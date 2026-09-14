"""Phase 7: the audit trail.

Every request and every result is recorded, refusals included, and the record
cannot be edited afterwards -- by the application or through the database.
"""

import json
import sqlite3

import pytest

from sentinelforge.response.audit import (
    REDACTED,
    AuditEvent,
    AuditLog,
    AuditRecord,
    scrub,
)
from sentinelforge.response.models import ActionType, ResponseAction
from sentinelforge.storage.sqlite import IncidentStore, ResponseStore


@pytest.fixture
def store(tmp_path):
    with ResponseStore(str(tmp_path / "response.db")) as opened:
        yield opened


@pytest.fixture
def action():
    return ResponseAction(
        action_id="ACTION-00001",
        action_type=ActionType.BLOCK_IP,
        target="203.0.113.50",
        incident_id="INC-000001",
        reason="brute force",
        requested_by="analyst",
    )


class TestRecording:
    def test_a_record_captures_every_audited_field(self, store, action):
        entry = AuditLog(store).record(AuditEvent.REQUESTED, action)
        stored = store.list_audit()[0]
        for field in (
            "audit_id", "timestamp", "action_id", "incident_id", "action_type", "target",
            "requested_by", "approved_by", "reason", "policy_decision", "dry_run",
            "execution_status", "result", "error", "rollback_available",
        ):
            assert field in stored
        assert stored["audit_id"] == entry.audit_id
        assert stored["target"] == "203.0.113.50"

    def test_audit_ids_are_sequential(self, store, action):
        log = AuditLog(store)
        first = log.record(AuditEvent.REQUESTED, action)
        second = log.record(AuditEvent.APPROVED, action)
        assert (first.audit_id, second.audit_id) == ("AUDIT-000001", "AUDIT-000002")

    def test_an_unknown_event_is_refused(self, store, action):
        with pytest.raises(ValueError, match="unknown audit event"):
            AuditLog(store).record("exfiltrated", action)

    def test_records_can_be_filtered_by_action_and_incident(self, store, action):
        other = ResponseAction(
            action_id="ACTION-00002", action_type=ActionType.KILL_PROCESS, target="4242",
            incident_id="INC-000002",
        )
        log = AuditLog(store)
        log.record(AuditEvent.REQUESTED, action)
        log.record(AuditEvent.REQUESTED, other)
        assert len(store.list_audit(action_id="ACTION-00001")) == 1
        assert len(store.list_audit(incident_id="INC-000002")) == 1

    def test_a_refusal_is_audited_too(self, store, action):
        AuditLog(store).record(AuditEvent.POLICY_DENIED, action, error="refused: loopback")
        assert store.list_audit()[0]["event"] == "policy_denied"
        assert "loopback" in store.list_audit()[0]["error"]


class TestAppendOnly:
    def test_the_database_refuses_an_update(self, store, action):
        AuditLog(store).record(AuditEvent.REQUESTED, action)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store.connect().execute("UPDATE response_audit SET event = 'nothing'")

    def test_the_database_refuses_a_delete(self, store, action):
        AuditLog(store).record(AuditEvent.REQUESTED, action)
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            store.connect().execute("DELETE FROM response_audit")

    def test_the_store_exposes_no_way_to_change_a_record(self):
        for name in dir(ResponseStore):
            assert not name.startswith(("update_audit", "delete_audit", "edit_audit"))


class TestHashChain:
    def test_an_untouched_trail_verifies(self, store, action):
        log = AuditLog(store)
        for event in (AuditEvent.REQUESTED, AuditEvent.APPROVED, AuditEvent.EXECUTED):
            log.record(event, action)
        result = store.verify_audit_chain()
        assert result["ok"] is True
        assert result["checked"] == 3

    def test_each_record_links_to_the_one_before_it(self, store, action):
        log = AuditLog(store)
        first = log.record(AuditEvent.REQUESTED, action)
        second = log.record(AuditEvent.APPROVED, action)
        assert second.previous_hash == first.entry_hash
        assert first.previous_hash is None

    def test_an_edited_record_breaks_the_chain(self, store, action):
        log = AuditLog(store)
        log.record(AuditEvent.REQUESTED, action)
        log.record(AuditEvent.APPROVED, action)
        # Only a direct file-level edit can do this; the triggers block the
        # ordinary path, so drop them first to simulate an attacker with write
        # access to the database file.
        store.connect().executescript(
            "DROP TRIGGER response_audit_no_update;"
            "UPDATE response_audit SET target = '10.0.0.1' WHERE sequence = 1;"
        )
        result = store.verify_audit_chain()
        assert result["ok"] is False
        assert result["broken_at"] == "AUDIT-000001"

    def test_a_deleted_record_breaks_the_chain(self, store, action):
        log = AuditLog(store)
        log.record(AuditEvent.REQUESTED, action)
        log.record(AuditEvent.APPROVED, action)
        store.connect().executescript(
            "DROP TRIGGER response_audit_no_delete;"
            "DELETE FROM response_audit WHERE sequence = 1;"
        )
        assert store.verify_audit_chain()["ok"] is False

    def test_an_empty_trail_verifies(self, store):
        assert store.verify_audit_chain()["ok"] is True

    def test_the_hash_is_stable_for_the_same_content(self):
        record = AuditRecord(audit_id="AUDIT-000001", event=AuditEvent.REQUESTED,
                             timestamp="2026-09-12T10:00:00Z", target="203.0.113.50")
        assert record.compute_hash(None) == record.compute_hash(None)
        assert record.compute_hash(None) != record.compute_hash("abc")


class TestNoSecrets:
    @pytest.mark.parametrize(
        "key", ["password", "api_key", "token", "authorization", "secret", "cookie"]
    )
    def test_credential_shaped_keys_are_redacted(self, key):
        assert scrub({key: "hunter2"})[key] == REDACTED

    def test_scrubbing_reaches_nested_structures(self):
        cleaned = scrub({"outer": [{"api_key": "x"}, {"safe": "y"}]})
        assert cleaned["outer"][0]["api_key"] == REDACTED
        assert cleaned["outer"][1]["safe"] == "y"

    def test_ordinary_result_data_survives(self):
        data = {"zone": "public", "rich_rule": "rule ...", "returncode": 0}
        assert scrub(data) == data

    def test_a_record_scrubs_on_the_way_out(self, store, action):
        AuditLog(store).record(
            AuditEvent.EXECUTED, action, result={"detail": "ok", "token": "secret-value"}
        )
        stored = json.dumps(store.list_audit()[0])
        assert "secret-value" not in stored
        assert REDACTED in stored


class TestSharedDatabase:
    def test_response_tables_live_beside_incidents(self, tmp_path):
        path = str(tmp_path / "sentinelforge.db")
        with ResponseStore(path) as store:
            store.save_action(
                ResponseAction(action_id="ACTION-00001", action_type=ActionType.BLOCK_IP,
                               target="203.0.113.50")
            )
        # The same file is a perfectly ordinary incident database.
        with IncidentStore(path) as incidents:
            assert incidents.count() == 0
        with ResponseStore(path) as store:
            assert store.action_count() == 1

    def test_actions_can_be_filtered(self, tmp_path):
        with ResponseStore(str(tmp_path / "x.db")) as store:
            store.save_action(ResponseAction(
                action_id="ACTION-00001", action_type=ActionType.BLOCK_IP,
                target="203.0.113.50", incident_id="INC-000001"))
            store.save_action(ResponseAction(
                action_id="ACTION-00002", action_type=ActionType.KILL_PROCESS,
                target="4242", incident_id="INC-000002", dry_run=True))
            assert len(store.list_actions(incident_id="INC-000001")) == 1
            assert len(store.list_actions(action_type="kill_process")) == 1
            assert len(store.list_actions(include_dry_run=False)) == 1
            assert store.next_action_number() == 3
            assert store.status_counts() == {"requested": 2}
