"""Tests for the SQLite incident store (temporary databases only)."""

import json
import sqlite3

import pytest

from conftest import at
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.models.incident import Incident, IncidentStatus
from sentinelforge.storage.sqlite import IncidentStore, default_database_path


@pytest.fixture
def store(tmp_path):
    with IncidentStore(str(tmp_path / "incidents.db")) as store:
        yield store


@pytest.fixture
def incident(compromise_alerts):
    return CorrelationEngine().run(compromise_alerts)[0]


class TestSchema:
    def test_database_file_is_created_with_directories(self, tmp_path):
        path = tmp_path / "nested" / "dir" / "incidents.db"
        with IncidentStore(str(path)) as store:
            assert store.count() == 0
        assert path.exists()

    def test_in_memory_store_works(self):
        with IncidentStore(":memory:") as store:
            store.save(Incident(incident_id="INC-000001", title="x"))
            assert store.count() == 1

    def test_default_path_is_under_the_user_data_directory(self, monkeypatch, tmp_path):
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert default_database_path() == str(tmp_path / "sentinelforge" / "incidents.db")

    def test_no_server_required(self, store):
        """It is just a file: sqlite3 from the standard library, nothing else."""
        assert isinstance(store.connect(), sqlite3.Connection)


class TestSaveAndLoad:
    def test_save_then_reload_preserves_everything(self, store, incident):
        store.save(incident)
        loaded = store.get(incident.incident_id)

        assert loaded is not None
        assert loaded.incident_id == incident.incident_id
        assert loaded.title == incident.title
        assert loaded.severity == incident.severity
        assert loaded.risk_score == incident.risk_score
        assert loaded.status == incident.status
        assert loaded.host == incident.host
        assert loaded.source_ips == incident.source_ips
        assert loaded.users == incident.users
        assert loaded.first_seen == incident.first_seen
        assert loaded.last_seen == incident.last_seen
        assert loaded.matched_chains == incident.matched_chains
        assert loaded.risk_explanation == incident.risk_explanation

    def test_alerts_and_their_evidence_survive(self, store, incident):
        store.save(incident)
        loaded = store.get(incident.incident_id)

        assert loaded.alert_count == incident.alert_count
        assert [a.alert_id for a in loaded.alerts] == [a.alert_id for a in incident.alerts]
        assert loaded.event_count == incident.event_count
        original_evidence = incident.alerts[0].evidence
        assert [e.to_dict() for e in loaded.alerts[0].evidence] == [
            e.to_dict() for e in original_evidence
        ]

    def test_timeline_survives(self, store, incident):
        store.save(incident)
        loaded = store.get(incident.incident_id)
        assert [entry.to_dict() for entry in loaded.timeline] == [
            entry.to_dict() for entry in incident.timeline
        ]

    def test_attack_chain_survives(self, store, incident):
        store.save(incident)
        loaded = store.get(incident.incident_id)
        assert loaded.attack_chain == incident.attack_chain

    def test_missing_incident_returns_none(self, store):
        assert store.get("INC-999999") is None

    def test_save_is_an_upsert(self, store, incident):
        store.save(incident)
        incident.risk_score = 42
        incident.title = "Updated title"
        store.save(incident)
        assert store.count() == 1
        assert store.get(incident.incident_id).risk_score == 42
        assert store.get(incident.incident_id).title == "Updated title"

    def test_save_all_returns_a_count(self, store):
        saved = store.save_all(
            [Incident(incident_id=f"INC-00000{i}", title=f"t{i}") for i in range(1, 4)]
        )
        assert saved == 3
        assert store.count() == 3

    def test_delete(self, store, incident):
        store.save(incident)
        assert store.delete(incident.incident_id) is True
        assert store.get(incident.incident_id) is None
        assert store.delete(incident.incident_id) is False


class TestQueries:
    def _incidents(self):
        return [
            Incident(
                incident_id="INC-000001",
                title="old critical",
                severity="critical",
                risk_score=95,
                last_seen=at(0),
                status=IncidentStatus.OPEN,
            ),
            Incident(
                incident_id="INC-000002",
                title="recent low",
                severity="low",
                risk_score=25,
                last_seen=at(600),
                status=IncidentStatus.RESOLVED,
            ),
            Incident(
                incident_id="INC-000003",
                title="recent high",
                severity="high",
                risk_score=80,
                last_seen=at(1200),
                status=IncidentStatus.INVESTIGATING,
            ),
        ]

    def test_list_is_most_recent_first(self, store):
        store.save_all(self._incidents())
        assert [i.incident_id for i in store.list_incidents()] == [
            "INC-000003",
            "INC-000002",
            "INC-000001",
        ]

    def test_list_filters_by_status(self, store):
        store.save_all(self._incidents())
        found = store.list_incidents(status=IncidentStatus.RESOLVED)
        assert [i.incident_id for i in found] == ["INC-000002"]

    def test_list_filters_by_minimum_severity(self, store):
        store.save_all(self._incidents())
        found = store.list_incidents(min_severity="high")
        assert {i.incident_id for i in found} == {"INC-000001", "INC-000003"}

    def test_list_respects_a_limit(self, store):
        store.save_all(self._incidents())
        assert len(store.list_incidents(limit=2)) == 2

    def test_active_incidents_respect_the_window(self, store):
        store.save_all(self._incidents())
        # INC-000003 is open/investigating and recent; INC-000001 is too old,
        # INC-000002 is resolved so it no longer takes alerts.
        active = store.active_incidents(at(1500), window_seconds=900)
        assert [i.incident_id for i in active] == ["INC-000003"]

    def test_active_incidents_with_no_reference_returns_nothing(self, store):
        store.save_all(self._incidents())
        assert store.active_incidents(None, 900) == []

    def test_next_incident_number(self, store):
        assert store.next_incident_number() == 1
        store.save(Incident(incident_id="INC-000007", title="x"))
        assert store.next_incident_number() == 8


class TestStatusTransitions:
    @pytest.mark.parametrize("status", IncidentStatus.ALL)
    def test_every_state_can_be_stored(self, store, incident, status):
        store.save(incident)
        assert store.update_status(incident.incident_id, status) is True
        assert store.get(incident.incident_id).status == status

    def test_unknown_state_is_rejected(self, store, incident):
        store.save(incident)
        with pytest.raises(ValueError, match="unknown incident status"):
            store.update_status(incident.incident_id, "banana")

    def test_updating_a_missing_incident_returns_false(self, store):
        assert store.update_status("INC-999999", IncidentStatus.RESOLVED) is False

    def test_status_change_does_not_disturb_the_alerts(self, store, incident):
        store.save(incident)
        store.update_status(incident.incident_id, IncidentStatus.CONTAINED)
        loaded = store.get(incident.incident_id)
        assert loaded.alert_count == incident.alert_count
        assert loaded.event_count == incident.event_count


class TestSafety:
    def test_queries_are_parameterized(self, store):
        """A hostile-looking id is data, not SQL."""
        nasty = "INC-000001'; DROP TABLE incidents; --"
        store.save(Incident(incident_id=nasty, title="x"))
        assert store.get(nasty) is not None
        assert store.count() == 1  # the table is still there

    def test_a_corrupt_row_is_skipped_not_fatal(self, store, caplog):
        store.save(Incident(incident_id="INC-000001", title="good"))
        store.connect().execute(
            "UPDATE incidents SET data = ? WHERE incident_id = ?",
            ("{not valid json", "INC-000001"),
        )
        store.connect().commit()
        assert store.get("INC-000001") is None
        assert store.list_incidents() == []

    def test_stored_data_is_the_incident_json(self, store, incident):
        store.save(incident)
        row = store.connect().execute("SELECT data FROM incidents").fetchone()
        assert json.loads(row["data"])["incident_id"] == incident.incident_id
