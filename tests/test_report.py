"""Text report and JSON payload: numbers, ordering, and degenerate inputs."""
from __future__ import annotations

import json
from pathlib import Path

from helpers import key_entry, sign_message
from verify_dkim_signatures import JSON_SCHEMA_VERSION, _json_default


def _verifier_with_results(make_verifier, tmp_path, entries, emails):
    verifier = make_verifier(entries)
    paths = []
    for index, data in enumerate(emails):
        path = tmp_path / f"mail{index}.eml"
        path.write_bytes(data)
        paths.append(path)
    verifier.scan_paths(paths)
    return verifier


class TestTextReport:
    def test_summary_counts(self, keypair, make_verifier, tmp_path):
        private, public = keypair
        good = sign_message(private)
        bad = good.replace(b"Hello world.", b"Goodbye world.")
        verifier = _verifier_with_results(
            make_verifier, tmp_path, {"example.com.:sel": key_entry("example.com.", "sel", public)},
            [good, bad, b"From: c@d\r\n\r\nno signature\r\n"],
        )

        verifier.print_report()
        report = verifier.console.getvalue()

        assert "Total emails read/checked: 3" in report
        assert "Emails with valid DKIM signatures: 1" in report
        assert "Emails with invalid DKIM signatures: 1" in report
        assert "Emails without DKIM signatures: 1" in report
        assert "DKIM verified:                              1 / 3 (33.3%)" in report
        assert "DKIM failed:                                1 / 3 (33.3%)" in report

    def test_failure_breakdown_names_the_cause(self, keypair, make_verifier, tmp_path):
        private, _public = keypair
        verifier = _verifier_with_results(
            make_verifier, tmp_path, {}, [sign_message(private)]
        )

        verifier.print_report()
        report = verifier.console.getvalue()

        assert "DKIM FAILURE BREAKDOWN (by email)" in report
        assert "No public key in DNS for this selector" in report
        assert "NOT content tampering" in report

    def test_per_domain_statistics(self, keypair, make_verifier, tmp_path):
        private, public = keypair
        good = sign_message(private)
        bad = good.replace(b"Hello world.", b"Goodbye world.")
        verifier = _verifier_with_results(
            make_verifier, tmp_path, {"example.com.:sel": key_entry("example.com.", "sel", public)},
            [good, bad],
        )

        verifier.print_report()
        report = verifier.console.getvalue()

        assert "DKIM STATISTICS BY DOMAIN:" in report
        assert "example.com: 1/2 (50.0%)" in report

    def test_verbose_detail_includes_diagnosis(self, keypair, make_verifier, tmp_path):
        private, public = keypair
        bad = sign_message(private).replace(b"Hello world.", b"Goodbye world.")
        verifier = _verifier_with_results(
            make_verifier, tmp_path, {"example.com.:sel": key_entry("example.com.", "sel", public)},
            [bad],
        )
        verifier.verbose = True

        verifier.print_report()
        report = verifier.console.getvalue()

        assert "Cause: BODY_ALTERED" in report
        assert "Body integrity: ALTERED (body hash mismatch)" in report
        assert "Public key in DNS: present" in report

    def test_minimal_key_entry_does_not_break_the_report(self, keypair, make_verifier, tmp_path):
        """Regression: the key-database section indexed optional fields."""
        private, public = keypair
        minimal = {"example.com:sel": {
            "domain": "example.com", "selector": "sel",
            "key_data": f"v=DKIM1; k=rsa; p={public}",
        }}
        verifier = _verifier_with_results(make_verifier, tmp_path, minimal, [sign_message(private)])
        verifier.verbose = True

        verifier.print_report()
        report = verifier.console.getvalue()

        assert "KEY DATABASE DETAILS:" in report
        assert "Status: unknown" in report
        assert "Retrieved: (not recorded)" in report
        assert "DKIM verified:                              1 / 1 (100.0%)" in report

    def test_report_file_is_written_even_without_echo(self, keypair, make_verifier, tmp_path):
        private, public = keypair
        verifier = _verifier_with_results(
            make_verifier, tmp_path, {"example.com.:sel": key_entry("example.com.", "sel", public)},
            [sign_message(private)],
        )
        report_path = tmp_path / "report.txt"

        verifier.print_report(str(report_path), echo=False)

        assert "DKIM SIGNATURE VERIFICATION REPORT" not in verifier.console.getvalue()
        assert "DKIM SIGNATURE VERIFICATION REPORT" in report_path.read_text(encoding="utf-8")

    def test_echo_writes_to_the_console(self, keypair, make_verifier, tmp_path):
        private, public = keypair
        verifier = _verifier_with_results(
            make_verifier, tmp_path, {"example.com.:sel": key_entry("example.com.", "sel", public)},
            [sign_message(private)],
        )

        verifier.print_report()

        assert "OVERALL VERIFICATION SUMMARY" in verifier.console.getvalue()

    def test_empty_run_prints_no_summary(self, make_verifier):
        verifier = make_verifier({})

        verifier.print_report()

        report = verifier.console.getvalue()
        assert "Total emails read/checked: 0" in report
        assert "OVERALL VERIFICATION SUMMARY" not in report


class TestJsonReport:
    def test_schema_and_contents(self, keypair, make_verifier, tmp_path):
        private, public = keypair
        verifier = _verifier_with_results(
            make_verifier, tmp_path, {"example.com.:sel": key_entry("example.com.", "sel", public)},
            [sign_message(private)],
        )

        payload = verifier.json_report()

        assert payload["schema_version"] == JSON_SCHEMA_VERSION
        assert payload["stats"]["valid_dkim"] == 1
        assert payload["results"][0]["overall_status"] == "valid_dkim"
        assert payload["options"]["offline_only"] is True
        # The payload must survive json.dumps without a custom encoder.
        json.loads(json.dumps(payload, default=_json_default))

    def test_json_default_coerces_awkward_values(self):
        payload = {"blob": b"\xff\xfe", "tags": {"b", "a"}, "path": Path("x.eml")}

        encoded = json.loads(json.dumps(payload, default=_json_default))

        assert encoded["tags"] == ["a", "b"]
        assert encoded["path"] == "x.eml"
        assert isinstance(encoded["blob"], str)
