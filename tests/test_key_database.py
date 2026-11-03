"""Key cache: parsing, preservation, persistence and lookup tolerance."""
from __future__ import annotations

import json
from pathlib import Path

from helpers import key_entry, sign_message, txt_record
from verify_dkim_signatures import DKIMVerifier

RECORD = "v=DKIM1; k=rsa; p=QUJD"


def _db_path(verifier) -> Path:
    return Path(verifier.key_database_file)


class TestEntryHandling:
    def test_new_entry_records_fields(self, make_verifier):
        verifier = make_verifier({})

        verifier.add_key_to_database("example.com.", "sel", "sel._domainkey.example.com.",
                                     RECORD, "mail.eml")

        entry = verifier.key_database["example.com.:sel"]
        assert entry["parsed_key"]["p"] == "QUJD"
        assert entry["status"] == "success"
        assert entry["used_by_files"] == ["mail.eml"]
        assert entry["roles"] == ["dkim"]
        assert verifier.stats["keys_saved"] == 1
        assert verifier._db_dirty is True

    def test_blank_lookup_does_not_replace_a_known_key(self, make_verifier):
        verifier = make_verifier({"example.com.:sel": key_entry("example.com.", "sel", "QUJD")})

        verifier.add_key_to_database("example.com.", "sel", "q", "", "mail.eml", status="no_key")

        entry = verifier.key_database["example.com.:sel"]
        assert entry["key_data"] == txt_record("QUJD")
        assert entry["status"] == "success"

    def test_blank_placeholder_is_filled_by_a_later_lookup(self, make_verifier):
        verifier = make_verifier({"example.com.:sel": {
            "domain": "example.com.", "selector": "sel", "key_data": "",
            "parsed_key": {}, "status": "no_key", "used_by_files": [], "roles": [],
        }})

        verifier.add_key_to_database("example.com.", "sel", "q", RECORD, "mail.eml")

        assert verifier.key_database["example.com.:sel"]["key_data"] == RECORD

    def test_overwrite_requires_the_flag(self, make_verifier):
        verifier = make_verifier({"example.com.:sel": key_entry("example.com.", "sel", "OLD")})

        verifier.add_key_to_database("example.com.", "sel", "q", RECORD, "mail.eml")

        assert verifier.key_database["example.com.:sel"]["key_data"] == txt_record("OLD")

    def test_overwrite_flag_replaces_and_counts(self, make_verifier):
        verifier = make_verifier(
            {"example.com.:sel": key_entry("example.com.", "sel", "OLD")},
            overwrite_keys=True,
            offline_only=False,
        )

        verifier.add_key_to_database("example.com.", "sel", "q", RECORD, "mail.eml")

        assert verifier.key_database["example.com.:sel"]["key_data"] == RECORD
        assert verifier.stats["keys_overwritten"] == 1

    def test_roles_are_merged_not_replaced(self, make_verifier):
        verifier = make_verifier({"example.com.:sel": key_entry("example.com.", "sel", "QUJD")})

        verifier.add_key_to_database("example.com.", "sel", "q", txt_record("QUJD"),
                                     "arc.eml", role="arc")

        assert verifier.key_database["example.com.:sel"]["roles"] == ["dkim", "arc"]


class TestPersistence:
    def test_save_writes_file_and_rotates_backup(self, make_verifier):
        db_path = None
        verifier = make_verifier({})
        db_path = _db_path(verifier)
        db_path.write_text(json.dumps({"old.example.:k": {"domain": "old.example."}}), "utf-8")
        verifier.load_key_database()
        verifier.add_key_to_database("example.com.", "sel", "q", RECORD, "mail.eml")

        verifier.save_key_database()

        saved = json.loads(db_path.read_text(encoding="utf-8"))
        backup = json.loads(db_path.with_suffix(".json.bak").read_text(encoding="utf-8"))
        assert "example.com.:sel" in saved
        assert "old.example.:k" in backup
        assert "example.com.:sel" not in backup

    def test_clean_database_is_not_rewritten(self, make_verifier):
        verifier = make_verifier({"example.com.:sel": key_entry("example.com.", "sel", "QUJD")})
        db_path = _db_path(verifier)
        before = db_path.read_text(encoding="utf-8")

        verifier.save_key_database()

        assert db_path.read_text(encoding="utf-8") == before
        assert not db_path.with_suffix(".json.bak").exists()

    def test_save_is_atomic_and_leaves_no_temp_file(self, make_verifier):
        verifier = make_verifier({})
        verifier.add_key_to_database("example.com.", "sel", "q", RECORD, "mail.eml")

        verifier.save_key_database()

        db_path = _db_path(verifier)
        assert json.loads(db_path.read_text(encoding="utf-8"))
        assert not db_path.with_suffix(".json.tmp").exists()

    def test_round_trip_through_a_new_verifier(self, make_verifier):
        verifier = make_verifier({})
        verifier.add_key_to_database("example.com.", "sel", "q", RECORD, "mail.eml")
        verifier.save_key_database()

        reloaded = DKIMVerifier(key_database_file=str(_db_path(verifier)), offline_only=True)

        assert reloaded.key_database["example.com.:sel"]["key_data"] == RECORD
        assert reloaded.stats["keys_loaded"] == 1

    def test_invalid_json_is_ignored(self, make_verifier):
        verifier = make_verifier({})
        _db_path(verifier).write_text("{not json", encoding="utf-8")

        verifier.load_key_database()

        assert verifier.key_database == {}

    def test_json_that_is_not_an_object_is_ignored(self, make_verifier):
        verifier = make_verifier({})
        _db_path(verifier).write_text("[]", encoding="utf-8")

        verifier.load_key_database()

        assert verifier.key_database == {}


class TestLookupTolerance:
    def test_cache_hit_records_file_and_role(self, keypair, make_verifier, eml):
        private, public = keypair
        minimal = {"example.com.:sel": {
            "domain": "example.com.", "selector": "sel", "key_data": txt_record(public),
        }}
        verifier = make_verifier(minimal)
        path = eml(sign_message(private))

        result = verifier.verify_email_file(path)

        assert result["overall_status"] == "valid_dkim"
        entry = verifier.key_database["example.com.:sel"]
        assert entry["used_by_files"] == [path.name]
        assert entry["roles"] == ["dkim"]

    def test_dotless_entry_is_reused_not_duplicated(self, keypair, make_verifier, eml):
        private, public = keypair
        bare = {"example.com:sel": key_entry("example.com", "sel", public)}
        verifier = make_verifier(bare)

        verifier.verify_email_file(eml(sign_message(private)))

        assert list(verifier.key_database) == ["example.com:sel"]

    def test_offline_miss_categories(self, make_verifier):
        verifier = make_verifier({"example.com.:other": key_entry("example.com.", "other", "QUJD")})

        assert verifier._classify_offline_miss("example.com.", "sel") == "OFFLINE-NO-KEY"
        assert verifier._classify_offline_miss("unknown.example.", "sel") == "OFFLINE-NO-DOMAIN"
