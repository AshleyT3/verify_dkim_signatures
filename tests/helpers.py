"""Helpers that build real, locally signed messages for the test suite."""
from __future__ import annotations

import base64

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE_HEADERS = (
    b"From: Alice <alice@example.com>\r\n"
    b"To: Bob <bob@example.net>\r\n"
    b"Subject: A signed message\r\n"
    b"Date: Mon, 02 Nov 2026 10:00:00 +0000\r\n"
    b"Message-ID: <abc123@example.com>\r\n"
    b"MIME-Version: 1.0\r\n"
)

SIGNED_HEADERS = [b"from", b"to", b"subject", b"date", b"message-id"]


def generate_keypair() -> tuple[bytes, str]:
    """Return (private key PEM, base64 DER public key) for a fresh RSA key."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    public_der = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, base64.b64encode(public_der).decode("ascii")


def txt_record(public_key_b64: str, revoked: bool = False) -> str:
    """The DNS TXT value a signer publishes (empty p= means revoked)."""
    return f"v=DKIM1; k=rsa; p={'' if revoked else public_key_b64}"


def sign_message(
    private_pem: bytes,
    domain: bytes = b"example.com",
    selector: bytes = b"sel",
    body: bytes = b"Hello world.\r\n",
    headers: bytes = BASE_HEADERS,
    canonicalize: tuple[bytes, bytes] = (b"relaxed", b"relaxed"),
) -> bytes:
    """Sign a message the way a real MTA would, canonicalized per RFC 6376."""
    message = headers + b"\r\n" + body
    signature = dkim.sign(
        message,
        selector,
        domain,
        private_pem,
        canonicalize=canonicalize,
        include_headers=SIGNED_HEADERS,
    )
    return signature + message


def key_entry(domain: str, selector: str, public_key_b64: str, revoked: bool = False) -> dict:
    """A key-database entry as this tool writes it."""
    record = txt_record(public_key_b64, revoked=revoked)
    parsed = {"v": "DKIM1", "k": "rsa", "p": "" if revoked else public_key_b64}
    return {
        "domain": domain,
        "selector": selector,
        "dns_query": f"{selector}._domainkey.{domain}",
        "key_data": record,
        "parsed_key": parsed,
        "retrieved": "2026-11-03T00:00:00+00:00",
        "status": "success",
        "used_by_files": [],
        "roles": ["dkim"],
    }

def signature_header(signed: bytes, base: bytes) -> bytes:
    """The DKIM-Signature header block a signer prepended to ``base``."""
    assert signed.endswith(base), "signature was not prepended to the given base"
    return signed[: len(signed) - len(base)]


def double_signed(private_one, private_two, body: bytes = b"Hello world.\r\n") -> bytes:
    """Two independent signers over the same base message.

    dkimpy's ``sign()`` drops any DKIM-Signature already on the message, so a
    second signature has to be computed over the same unsigned base and its
    header stacked on top — which is what an intermediary re-signing the
    original header set produces.
    """
    base = BASE_HEADERS + b"\r\n" + body
    first = sign_message(private_one, domain=b"example.com", selector=b"sel", body=body)
    second = sign_message(private_two, domain=b"example.org", selector=b"sel2", body=body)
    return signature_header(first, base) + signature_header(second, base) + base
