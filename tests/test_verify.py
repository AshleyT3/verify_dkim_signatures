"""Per-file verification: verdicts, failure classification, byte handling."""
from __future__ import annotations

import email

import dkim
import pytest

from helpers import (
    BASE_HEADERS,
    double_signed,
    key_entry,
    sign_message,
    txt_record,
)
from verify_dkim_signatures import OurDKIM


def _db(public_key: str, domain: str = "example.com.", selector: str = "sel") -> dict:
    return {f"{domain}:{selector}": key_entry(domain, selector, public_key)}


class TestVerdicts:
    def test_valid_signature(self, keypair, make_verifier, eml):
        private, public = keypair
        verifier = make_verifier(_db(public))
        result = verifier.verify_email_file(eml(sign_message(private)))

        assert result["overall_status"] == "valid_dkim"
        detail = result["verification_details"][0]
        assert detail["valid"] is True
        assert detail["classification"] == "VALID"
        assert detail["body_hash_match"] is True
        assert result["arc"]["effective_status"] == "none"
        assert verifier.stats["valid_dkim"] == 1
        assert verifier.stats["cache_hits"] == 1

    def test_tampered_body_is_classified_as_altered(self, keypair, make_verifier, eml):
        private, public = keypair
        signed = sign_message(private)
        tampered = signed.replace(b"Hello world.", b"Hello there.")
        verifier = make_verifier(_db(public))

        result = verifier.verify_email_file(eml(tampered))

        assert result["overall_status"] == "invalid_dkim"
        detail = result["verification_details"][0]
        assert detail["valid"] is False
        assert detail["classification"] == "BODY_ALTERED"
        assert detail["body_hash_match"] is False
        assert detail["key_status"] == "present"
        assert "modified after signing" in detail["message"]

    def test_absent_key_is_not_reported_as_tampering(self, keypair, make_verifier, eml):
        private, _public = keypair
        verifier = make_verifier({})

        result = verifier.verify_email_file(eml(sign_message(private)))

        detail = result["verification_details"][0]
        assert result["overall_status"] == "invalid_dkim"
        assert detail["classification"] == "KEY_ABSENT"
        assert detail["body_hash_match"] is True
        assert verifier.stats["offline_no_domain"] == 1
        assert result["offline_failure_reason"] == "OFFLINE-NO-DOMAIN"

    def test_revoked_key_is_classified_as_revoked(self, keypair, make_verifier, eml):
        private, public = keypair
        entries = {"example.com.:sel": key_entry("example.com.", "sel", public, revoked=True)}
        verifier = make_verifier(entries)

        result = verifier.verify_email_file(eml(sign_message(private)))

        detail = result["verification_details"][0]
        assert detail["classification"] == "KEY_REVOKED"
        assert detail["key_status"] == "revoked"
        assert "revoked" in detail["message"]

    def test_missing_selector_in_known_domain(self, keypair, make_verifier, eml):
        private, public = keypair
        entries = {"example.com.:other": key_entry("example.com.", "other", public)}
        verifier = make_verifier(entries)

        result = verifier.verify_email_file(eml(sign_message(private)))

        detail = result["verification_details"][0]
        assert detail["classification"] == "KEY_ABSENT"
        assert verifier.stats["offline_no_key"] == 1
        assert result["offline_failure_reason"] == "OFFLINE-NO-KEY"

    def test_message_without_signature(self, make_verifier, eml):
        verifier = make_verifier({})
        result = verifier.verify_email_file(eml(BASE_HEADERS + b"\r\nBody only.\r\n"))

        assert result["overall_status"] == "no_dkim"
        assert result["dkim_signatures"] == []
        assert verifier.stats["no_dkim"] == 1

    def test_authentication_results_are_recorded(self, make_verifier, eml):
        data = (
            b"Authentication-Results: mx.example.net; dkim=pass header.d=example.com\r\n"
            + BASE_HEADERS
            + b"\r\nBody only.\r\n"
        )
        verifier = make_verifier({})
        result = verifier.verify_email_file(eml(data))

        assert result["overall_status"] == "no_dkim_signature"
        assert result["authentication_results"]
        assert "dkim=pass" in result["authentication_results"][0]

    def test_unreadable_file_is_reported_not_raised(self, make_verifier, tmp_path):
        verifier = make_verifier({})
        result = verifier.verify_email_file(tmp_path / "missing.eml")

        assert result["overall_status"] == "error"
        assert "missing.eml" in result["error"]
        assert verifier.stats["verification_errors"] == 1

    def test_non_email_file_counts_as_no_dkim(self, make_verifier, eml):
        verifier = make_verifier({})
        result = verifier.verify_email_file(eml(b"\x00\x01 not an email at all\n"))

        assert result["overall_status"] == "no_dkim"


class TestMultipleSignatures:
    def test_each_signature_is_verified(self, keypair, other_keypair, make_verifier, eml):
        private_one, public_one = keypair
        private_two, public_two = other_keypair
        entries = {}
        entries.update(_db(public_one, "example.com."))
        entries.update(_db(public_two, "example.org.", "sel2"))
        verifier = make_verifier(entries)

        result = verifier.verify_email_file(
            eml(double_signed(private_one, private_two))
        )

        assert result["overall_status"] == "valid_dkim"
        assert len(result["dkim_signatures"]) == 2
        assert len(result["verification_details"]) == 2
        assert [d["valid"] for d in result["verification_details"]] == [True, True]
        assert verifier.stats["multiple_signatures"] == 1

    def test_one_valid_one_unverifiable_signature(self, keypair, other_keypair, make_verifier, eml):
        private_one, public_one = keypair
        private_two, _public_two = other_keypair
        verifier = make_verifier(_db(public_one, "example.com."))

        result = verifier.verify_email_file(
            eml(double_signed(private_one, private_two))
        )

        # Signature order is the header order: the example.com signer is stacked
        # first, so index 0 is the one whose key is cached.
        assert result["overall_status"] == "valid_dkim"
        details = result["verification_details"]
        assert details[0]["domain"] == "example.com"
        assert details[0]["valid"] is True
        assert details[1]["domain"] == "example.org"
        assert details[1]["classification"] == "KEY_ABSENT"

    def test_malformed_signature_is_an_error_not_a_crash(self, make_verifier, eml):
        malformed = (
            b"DKIM-Signature: v=1; a=rsa-sha256; b=!!!notbase64; bh=AAAA; d=example.com;\r\n"
            b" h=from; s=sel\r\n" + BASE_HEADERS + b"\r\nBody.\r\n"
        )
        verifier = make_verifier({})
        result = verifier.verify_email_file(eml(malformed))

        assert result["overall_status"] == "invalid_dkim"
        detail = result["verification_details"][0]
        assert detail["valid"] is False
        assert detail["classification"] in ("MALFORMED_SIGNATURE", "VALIDATION_ERROR")


def _validate(sig):
    """Run the field validator on a parsed signature dict."""
    return OurDKIM(b"From: a@b\r\n\r\nbody\r\n").validate_signature_fields(sig)


class TestSignatureFieldValidation:
    def _sig(self, **overrides):
        sig = {
            b"v": b"1",
            b"a": b"rsa-sha256",
            b"b": b"AAAA",
            b"bh": b"AAAA",
            b"d": b"example.com",
            b"h": b"from",
            b"s": b"sel",
        }
        sig.update({key.encode() if isinstance(key, str) else key: value
                    for key, value in overrides.items()})
        return sig

    def test_rejects_bad_bh_even_when_b_is_fine(self):
        # Regression: the bh= branch used to re-validate sig[b'b'], so a bh=
        # of non-base64 characters passed validation and surfaced later as a
        # body-hash mismatch instead of a malformed signature.
        with pytest.raises(dkim.ValidationError):
            _validate(self._sig(bh=b"!!!!"))

    def test_rejects_bad_b(self):
        with pytest.raises(dkim.ValidationError):
            _validate(self._sig(b=b"!!!!"))

    def test_accepts_valid_fields(self):
        _validate(self._sig())

    def test_rejects_unknown_version(self):
        with pytest.raises(dkim.ValidationError):
            _validate(self._sig(v=b"2"))


class TestByteHandling:
    def test_latin1_body_survives_gmail_header_cleaning(self, keypair, make_verifier, eml):
        """Regression: cleaning decoded to str and dropped every non-UTF-8 byte.

        A Gmail-style export of a valid latin-1 message therefore failed with
        BODY_ALTERED even though dkimpy verified the raw bytes.
        """
        private, public = keypair
        body = "Caf\u00e9 latte.\r\n".encode("latin-1")
        headers = BASE_HEADERS + b"Content-Type: text/plain; charset=iso-8859-1\r\n"
        signed = sign_message(private, body=body, headers=headers)
        exported = b"Return-Path: <alice@example.com>\r\nDelivered-To: alice@example.com\r\n" + signed

        # The raw bytes verify; after cleaning they must still verify.
        assert dkim.verify(exported, dnsfunc=lambda *a, **kw: txt_record(public).encode())

        verifier = make_verifier(_db(public))
        result = verifier.verify_email_file(eml(exported))

        assert result["overall_status"] == "valid_dkim", result["verification_details"]
        assert result["structure_analysis"]["gmail_headers_removed"] is True
        assert result["structure_analysis"]["bytes_removed"] > 0

    def test_cleaning_is_byte_identical_for_ascii_mail(self, keypair, make_verifier):
        private, public = keypair
        signed = sign_message(private)
        exported = b"Return-Path: <alice@example.com>\r\nDelivered-To: alice@example.com\r\n" + signed
        verifier = make_verifier(_db(public))

        cleaned, was_cleaned = verifier.clean_gmail_export(exported)

        assert was_cleaned is True
        assert exported.endswith(cleaned)
        assert cleaned.startswith(b"Delivered-To:")

    def test_delivered_to_first_header_is_left_alone(self, keypair, make_verifier):
        verifier = make_verifier({}, verbose=False)
        data = b"Delivered-To: alice@example.com\r\n" + BASE_HEADERS + b"\r\nBody.\r\n"

        cleaned, was_cleaned = verifier.clean_gmail_export(data)

        assert was_cleaned is False
        assert cleaned == data

    def test_delivered_to_inside_the_body_is_not_a_header(self, make_verifier):
        verifier = make_verifier({})
        data = BASE_HEADERS + b"\r\nDelivered-To: forwarded@example.net\r\nrest of body\r\n"

        cleaned, was_cleaned = verifier.clean_gmail_export(data)

        assert was_cleaned is False
        assert cleaned == data

    @pytest.mark.parametrize(
        "signed_bytes,expected",
        [
            (b"a\r\nb\r\n", "CRLF"),
            (b"a\nb\n", "LF"),
            (b"a\r\nb\n", "mixed"),
        ],
    )
    def test_line_ending_detection(self, make_verifier, signed_bytes, expected):
        # Regression: "CRLF in data and LF in data" is true for every CRLF
        # message, so everything used to be reported as "mixed".
        verifier = make_verifier({})
        message = email.message_from_bytes(BASE_HEADERS + b"\r\n" + signed_bytes)

        analysis = verifier.analyze_email_structure(signed_bytes, signed_bytes, message)

        assert analysis["line_endings"] == expected

    def test_gmail_cleaning_removes_folded_header(self, keypair, make_verifier):
        verifier = make_verifier({})
        data = (
            b"Return-Path: <alice@example.com>\r\n"
            b"Delivered-To: alice@example.com\r\n"
            b"X-GM-LABELS: \\Important,\r\n more-labels\r\n" + BASE_HEADERS + b"\r\nBody.\r\n"
        )

        cleaned, was_cleaned = verifier.clean_gmail_export(data)

        assert was_cleaned is True
        assert cleaned.startswith(b"Delivered-To:")


class TestKeyLookupTolerance:
    def test_database_keyed_without_root_dot_still_verifies(self, keypair, make_verifier, eml):
        """A hand-written database may store example.com, not example.com."""
        private, public = keypair
        entries = {"example.com:sel": key_entry("example.com", "sel", public)}
        verifier = make_verifier(entries)

        result = verifier.verify_email_file(eml(sign_message(private)))

        assert result["overall_status"] == "valid_dkim"
        assert verifier.stats["cache_hits"] == 1

    def test_lookup_prefers_the_spelling_on_disk(self, make_verifier):
        entries = {"example.com:sel": key_entry("example.com", "sel", "AAAA")}
        verifier = make_verifier(entries)

        key, entry = verifier._database_entry("example.com.", "sel")

        assert key == "example.com:sel"
        assert entry is verifier.key_database["example.com:sel"]

    def test_missing_entry_returns_none(self, make_verifier):
        verifier = make_verifier({})

        assert verifier._database_entry("example.com.", "sel") == (None, None)
