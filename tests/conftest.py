"""Fixtures for an entirely offline test run.

Every signed message is produced locally with dkimpy and a freshly generated
RSA key, and every verifier is pointed at a key database under tmp_path, so the
suite never touches the network and never depends on a real signer's key.
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from verify_dkim_signatures import DKIMVerifier  # noqa: E402

from helpers import generate_keypair  # noqa: E402


@pytest.fixture(scope="session")
def keypair() -> tuple[bytes, str]:
    return generate_keypair()


@pytest.fixture(scope="session")
def other_keypair() -> tuple[bytes, str]:
    return generate_keypair()


@pytest.fixture
def console() -> io.StringIO:
    return io.StringIO()


@pytest.fixture
def eml(tmp_path: Path):
    """Write bytes to a .eml file inside tmp_path and return the path."""

    def _write(data: bytes, name: str = "message.eml") -> Path:
        path = tmp_path / name
        path.write_bytes(data)
        return path

    return _write


@pytest.fixture
def make_verifier(tmp_path: Path, console: io.StringIO):
    """Build an offline DKIMVerifier with a key database under tmp_path."""

    def _make(entries: dict | None = None, **kwargs) -> DKIMVerifier:
        db_path = tmp_path / "key-database.json"
        if entries is not None:
            db_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")
        kwargs.setdefault("offline_only", True)
        return DKIMVerifier(
            key_database_file=str(db_path),
            console=console,
            **kwargs,
        )

    return _make
