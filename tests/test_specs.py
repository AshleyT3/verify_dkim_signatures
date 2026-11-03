"""Spec expansion: files, directories, globs, recursion, sidecar skipping."""
from __future__ import annotations

import pytest

from verify_dkim_signatures import expand_specs


@pytest.fixture
def mailbox(tmp_path):
    (tmp_path / "one.eml").write_bytes(b"a")
    (tmp_path / "two.eml").write_bytes(b"b")
    (tmp_path / "notes.txt").write_text("ignore me")
    nested = tmp_path / "archive"
    nested.mkdir()
    (nested / "deep.eml").write_bytes(b"c")
    fixed = tmp_path / "one.fixed.eml"
    fixed.write_bytes(b"d")
    return tmp_path


def names(paths):
    return [path.name for path in paths]


def test_literal_file_is_returned(mailbox):
    paths, warnings = expand_specs([str(mailbox / "two.eml")])

    assert names(paths) == ["two.eml"]
    assert warnings == []


def test_directory_yields_sorted_eml_files(mailbox):
    paths, warnings = expand_specs([str(mailbox)])

    assert names(paths) == ["one.eml", "two.eml"]
    assert warnings == []


def test_glob_pattern(mailbox):
    paths, _warnings = expand_specs([str(mailbox / "t*.eml")])

    assert names(paths) == ["two.eml"]


def test_unmatched_spec_warns(mailbox):
    paths, warnings = expand_specs([str(mailbox / "missing*.eml")])

    assert paths == []
    assert len(warnings) == 1
    assert "No files matched" in warnings[0]


def test_fixed_sidecars_are_skipped_by_glob(mailbox):
    paths, _warnings = expand_specs([str(mailbox / "*.eml")])

    assert "one.fixed.eml" not in names(paths)


def test_fixed_sidecar_named_explicitly_is_verified(mailbox):
    paths, _warnings = expand_specs([str(mailbox / "one.fixed.eml")])

    assert names(paths) == ["one.fixed.eml"]


def test_include_fixed_opt_in(mailbox):
    paths, _warnings = expand_specs([str(mailbox / "*.eml")], include_fixed=True)

    assert "one.fixed.eml" in names(paths)


def test_recursion_is_opt_in(mailbox):
    flat, _ = expand_specs([str(mailbox)])
    deep, _ = expand_specs([str(mailbox)], recurse=True)

    assert "deep.eml" not in names(flat)
    assert "deep.eml" in names(deep)


def test_duplicate_specs_are_collapsed(mailbox):
    paths, _warnings = expand_specs([str(mailbox), str(mailbox / "one.eml")])

    assert names(paths).count("one.eml") == 1


def test_empty_spec_list(mailbox):
    paths, warnings = expand_specs([])

    assert paths == []
    assert warnings == []


def test_non_eml_file_named_explicitly_is_accepted(mailbox):
    paths, _warnings = expand_specs([str(mailbox / "notes.txt")])

    assert names(paths) == ["notes.txt"]
