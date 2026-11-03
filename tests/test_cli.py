"""End-to-end command line behaviour: routing, JSON, exit codes."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from helpers import key_entry, sign_message
from verify_dkim_signatures import VERSION, main

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def mailbox(tmp_path, monkeypatch, keypair):
    """A working directory holding a key database and one valid message."""
    private, public = keypair
    (tmp_path / "key-database.json").write_text(
        json.dumps({"example.com.:sel": key_entry("example.com.", "sel", public)}),
        encoding="utf-8",
    )
    (tmp_path / "mail.eml").write_bytes(sign_message(private))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_processes_a_directory_argument(mailbox, capsys):
    main([str(mailbox)])

    out = capsys.readouterr().out
    assert "Found 1 .eml files to process" in out
    assert "DKIM verified:                              1 / 1 (100.0%)" in out


def test_default_spec_is_eml_in_cwd(mailbox, capsys):
    main([])

    assert "DKIM verified:                              1 / 1 (100.0%)" in capsys.readouterr().out


def test_version_exits_zero(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])

    assert excinfo.value.code == 0
    assert VERSION in capsys.readouterr().out


def test_offline_only_and_overwrite_are_incompatible(mailbox):
    with pytest.raises(SystemExit) as excinfo:
        main(["--offline-only", "--overwrite-keys"])

    assert excinfo.value.code == 2


def test_replace_requires_attempt_fix(mailbox):
    with pytest.raises(SystemExit) as excinfo:
        main(["--replace"])

    assert excinfo.value.code == 2


def test_fail_under_passes_above_the_rate(mailbox, capsys):
    main(["--fail-under", "50"])

    assert "DKIM verified:" in capsys.readouterr().out


def test_fail_under_reports_shortfall(mailbox, capsys):
    (mailbox / "broken.eml").write_bytes(
        (mailbox / "mail.eml").read_bytes().replace(b"Hello world.", b"Goodbye world.")
    )

    with pytest.raises(SystemExit) as excinfo:
        main(["--fail-under", "90"])

    captured = capsys.readouterr()
    assert excinfo.value.code == 3
    assert "--fail-under 90" in captured.out + captured.err


def test_fail_under_with_no_files_exits_three(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as excinfo:
        main(["--fail-under", "50"])

    assert excinfo.value.code == 3


def test_fail_under_rejects_out_of_range(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as excinfo:
        main(["--fail-under", "101"])

    assert excinfo.value.code == 2


def test_json_to_stdout_leaves_stdout_parseable(mailbox, capsys):
    main(["--json", "-"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["schema_version"] == 1
    assert payload["stats"]["valid_dkim"] == 1
    assert "Found 1 .eml files" in captured.err
    assert "DKIM SIGNATURE VERIFICATION REPORT" not in captured.out


def test_json_to_file_and_report_to_file(mailbox, capsys):
    json_path = mailbox / "results.json"
    report_path = mailbox / "report.txt"

    main(["--json", str(json_path), "--output", str(report_path)])

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["results"][0]["file"] == "mail.eml"
    assert "DKIM SIGNATURE VERIFICATION REPORT" in report_path.read_text(encoding="utf-8")
    assert "JSON results saved to" in capsys.readouterr().out


def test_single_file_is_still_accepted(mailbox, capsys):
    main(["--single-file", "mail.eml"])

    assert "Found 1 .eml files" in capsys.readouterr().out


def test_unmatched_spec_warns_and_processes_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    main(["missing*.eml"])

    out = capsys.readouterr().out
    assert "No files matched 'missing*.eml'" in out
    assert "No .eml files to process." in out


def test_rename_sidecars_are_skipped(mailbox, capsys):
    (mailbox / "mail.fixed.eml").write_bytes((mailbox / "mail.eml").read_bytes())

    main([])

    assert "Found 1 .eml files" in capsys.readouterr().out


def test_include_fixed_picks_them_up(mailbox, capsys):
    (mailbox / "mail.fixed.eml").write_bytes((mailbox / "mail.eml").read_bytes())

    main(["--include-fixed"])

    assert "Found 2 .eml files" in capsys.readouterr().out


def test_missing_dependency_exits_with_guidance(tmp_path):
    """Regression: dkimpy missing used to raise a traceback, not advice."""
    stub_dir = tmp_path / "stubs"
    stub_dir.mkdir()
    (stub_dir / "dkim.py").write_text('raise ImportError("simulated missing dkimpy")\n')

    env = dict(os.environ)
    env["PYTHONPATH"] = str(stub_dir) + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "verify_dkim_signatures.py"), "--help"],
        capture_output=True, text=True, env=env, cwd=str(tmp_path),
    )

    assert result.returncode == 2
    assert "pip install dkimpy dnspython" in result.stderr


def test_delivered_to_prefix_still_verifies_end_to_end(mailbox, capsys):
    exported = b"Return-Path: <alice@example.com>\r\nDelivered-To: alice@example.com\r\n" + (
        mailbox / "mail.eml"
    ).read_bytes()
    (mailbox / "exported.eml").write_bytes(exported)

    main(["--json", "-"])

    payload = json.loads(capsys.readouterr().out)
    statuses = {r["file"]: r["overall_status"] for r in payload["results"]}
    assert statuses == {"mail.eml": "valid_dkim", "exported.eml": "valid_dkim"}
