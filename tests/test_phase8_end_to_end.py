"""Phase 8: the complete end-to-end regression test.

One synthetic intrusion, walked through every phase of SentinelForge in order,
with each hand-off asserted::

    synthetic events -> normalization shape -> detection -> alerts
    -> correlation -> incident -> ATT&CK -> risk -> AI analysis
    -> storage -> dashboard API -> response request -> human approval
    -> mock containment -> verification -> audit

This is the project's primary regression test. If a change breaks the chain
anywhere, this is the file that says where.

It runs with **no root, no firewall, no process signal, no kernel probe, no
external network and no AI provider.** Those are not incidental: each one is
asserted, because a test that quietly needed any of them would stop being a
test of SentinelForge and start being a test of the machine.
"""

import json
import os

import pytest

from sentinelforge.ai.analyst import AISocAnalyst, AnalystConfig, attach_analysis
from sentinelforge.ai.cache import MemoryAnalysisCache
from sentinelforge.ai.client import LLMClient, LLMConfig
from sentinelforge.ai.providers.mock import MockProvider
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.models.event import EventType, Severity
from sentinelforge.models.incident import ENTRY_ALERT, ENTRY_EVENT
from sentinelforge.response.engine import ApprovalRequired, ResponseEngine
from sentinelforge.response.models import ActionStatus, ActionType
from sentinelforge.simulation.runner import SIMULATION_ACTOR, simulation_backends
from sentinelforge.simulation.scenarios import get_scenario
from sentinelforge.storage.sqlite import IncidentStore, ResponseStore

SCENARIO = get_scenario("full-attack")
ATTACKER = "203.0.113.10"
C2 = "198.51.100.9"


@pytest.fixture(scope="module")
def events():
    return SCENARIO.events()


@pytest.fixture(scope="module")
def alerts(events):
    return DetectionEngine().run(events)


@pytest.fixture(scope="module")
def incident(alerts):
    incidents = CorrelationEngine().run(alerts)
    assert len(incidents) == 1
    return incidents[0]


@pytest.fixture(scope="module")
def analysis(incident):
    analyst = AISocAnalyst(
        LLMClient(MockProvider(), LLMConfig(), sleep=lambda _: None),
        AnalystConfig(),
        cache=MemoryAnalysisCache(),
    )
    result = analyst.analyze(incident)
    attach_analysis(incident, result)
    return result


@pytest.fixture
def stored(tmp_path, incident, analysis):
    """The incident, round-tripped through a real SQLite database."""
    path = str(tmp_path / "incidents.db")
    with IncidentStore(path) as store:
        store.save(incident)
    return path


# -- 1. telemetry ----------------------------------------------------------
class TestStage1Telemetry:
    def test_the_scenario_produces_the_declared_events(self, events):
        assert len(events) == SCENARIO.expected.events == 12

    def test_the_events_span_every_source_the_platform_reads(self, events):
        assert {event.source for event in events} == {
            "systemd-journal", "ebpf-process", "ebpf-network"
        }

    def test_every_event_survives_a_json_round_trip(self, events):
        from sentinelforge.models.event import SecurityEvent

        for event in events:
            assert SecurityEvent.from_dict(json.loads(event.to_json())).to_dict() == (
                event.to_dict()
            )

    def test_the_telemetry_carries_the_sensor_metadata_rules_need(self, events):
        process_events = [e for e in events if e.event_type == EventType.PROCESS_START]
        network_events = [e for e in events if e.event_type == EventType.NETWORK_CONNECTION]
        assert all(e.pid and e.ppid and e.parent_process for e in process_events)
        assert all(e.dst_ip and e.dst_port and e.protocol for e in network_events)


# -- 2. detection ----------------------------------------------------------
class TestStage2Detection:
    def test_all_five_rules_fire(self, alerts):
        assert {alert.rule_id for alert in alerts} == SCENARIO.expected.rule_ids

    def test_each_alert_keeps_the_evidence_that_caused_it(self, alerts):
        for alert in alerts:
            assert alert.evidence
            assert alert.first_seen and alert.last_seen
            assert alert.first_seen <= alert.last_seen

    def test_each_alert_explains_its_score(self, alerts):
        for alert in alerts:
            assert alert.risk_explanation
            assert 0 <= alert.risk_score <= 100

    def test_the_compromise_alert_contains_both_the_failures_and_the_success(self, alerts):
        compromise = next(a for a in alerts if a.rule_id == "SSH_COMPROMISE_SUSPECTED")
        kinds = {event.event_type for event in compromise.evidence}
        assert EventType.AUTHENTICATION_FAILURE in kinds
        assert EventType.AUTHENTICATION_SUCCESS in kinds


# -- 3. correlation --------------------------------------------------------
class TestStage3Correlation:
    def test_five_alerts_become_one_incident(self, incident, alerts):
        assert incident.alert_count == len(alerts) == 5
        assert incident.incident_id == "INC-000001"

    def test_the_incident_records_both_adversary_addresses(self, incident):
        assert set(incident.source_ips) >= {ATTACKER, C2}

    def test_the_attack_chains_describe_the_sequence(self, incident):
        assert "AUTH_THEN_PROCESS_THEN_NETWORK" in incident.matched_chains
        assert "POSSIBLE_ACCOUNT_COMPROMISE" in incident.matched_chains

    def test_the_timeline_is_chronological_and_mixes_events_with_alerts(self, incident):
        keys = [entry.sort_key() for entry in incident.timeline]
        assert keys == sorted(keys)
        kinds = {entry.type for entry in incident.timeline}
        assert kinds == {ENTRY_EVENT, ENTRY_ALERT}

    def test_evidence_is_not_double_counted(self, incident):
        """One log line backs two alerts; the incident counts it once."""
        total = sum(alert.event_count for alert in incident.alerts)
        assert total == 14
        assert incident.event_count == 9

    def test_only_alerting_evidence_reaches_the_incident(self, incident, events):
        """A documented visibility property, asserted so it stays documented.

        An incident is built from its alerts' evidence. Telemetry that no rule
        matched -- the PAM session opening, the two intermediate process
        executions -- is therefore not part of it, even though the sensors saw
        it. That is why the process tree cannot show the full lineage, and it is
        pinned here so the limitation cannot change silently.
        """
        recorded = {
            (event.timestamp, event.event_type, event.message)
            for event in incident.unique_events()
        }
        omitted = [
            event for event in events
            if (event.timestamp, event.event_type, event.message) not in recorded
        ]
        assert len(omitted) == 3
        assert {event.event_type for event in omitted} == {
            EventType.SESSION_OPEN, EventType.PROCESS_START
        }

    def test_the_correlation_reasons_are_recorded(self, incident):
        reasons = " ".join(incident.correlation_reasons)
        assert "same host" in reasons
        assert "same source address" in reasons or "same account" in reasons


# -- 4. ATT&CK and risk ----------------------------------------------------
class TestStage4MitreAndRisk:
    def test_every_expected_technique_is_mapped(self, incident):
        found = set()
        for mapping in incident.attack_chain:
            found.add(mapping["technique_id"])
            if mapping.get("sub_technique_id"):
                found.add(mapping["sub_technique_id"])
        assert SCENARIO.expected.techniques <= found

    def test_no_technique_is_listed_twice(self, incident):
        keys = [
            (m["technique_id"], m.get("sub_technique_id")) for m in incident.attack_chain
        ]
        assert len(keys) == len(set(keys))

    def test_the_incident_is_critical_and_explains_why(self, incident):
        assert incident.severity == Severity.CRITICAL
        assert incident.risk_score == 100
        assert any("attack chain" in line for line in incident.risk_explanation)

    def test_the_score_is_not_the_sum_of_its_alerts(self, incident):
        """Two rules seeing the same thing must not inflate the score."""
        assert incident.risk_score < sum(alert.risk_score for alert in incident.alerts)


# -- 5. AI analysis --------------------------------------------------------
class TestStage5Analysis:
    def test_an_analysis_is_produced_offline(self, analysis):
        assert analysis.ok
        assert analysis.audit.is_mock
        assert analysis.audit.provider == "mock"

    def test_the_deterministic_verdict_is_preserved_beside_it(self, analysis, incident):
        assert analysis.deterministic_severity == incident.severity
        assert analysis.deterministic_score == incident.risk_score

    def test_the_analysis_separates_evidence_from_inference(self, analysis):
        assert analysis.key_evidence
        assert all(item.observation for item in analysis.key_evidence)
        assert analysis.false_positive_indicators
        assert analysis.investigation_steps

    def test_the_analysis_invents_no_attack_technique(self, analysis, incident):
        deterministic = set()
        for mapping in incident.attack_chain:
            deterministic.add(mapping["technique_id"])
            if mapping.get("sub_technique_id"):
                deterministic.add(mapping["sub_technique_id"])
        assert {item.technique_id for item in analysis.mitre_analysis} <= deterministic

    def test_the_analysis_sits_in_its_own_slot(self, incident, analysis):
        assert incident.ai_analysis is not None
        assert incident.ai_analysis["status"] == "ok"
        assert incident.severity == Severity.CRITICAL  # untouched


# -- 6. storage ------------------------------------------------------------
class TestStage6Storage:
    def test_the_incident_survives_the_database(self, stored, incident):
        with IncidentStore(stored) as store:
            reloaded = store.get(incident.incident_id)
        assert reloaded is not None
        assert reloaded.version == incident.version
        assert reloaded.alert_count == incident.alert_count
        assert reloaded.event_count == incident.event_count
        assert reloaded.ai_analysis == incident.ai_analysis

    def test_the_timeline_and_evidence_survive_too(self, stored, incident):
        with IncidentStore(stored) as store:
            reloaded = store.get(incident.incident_id)
        assert len(reloaded.timeline) == len(incident.timeline)
        assert [a.rule_id for a in reloaded.alerts] == [a.rule_id for a in incident.alerts]
        assert reloaded.alerts[0].evidence


# -- 7. dashboard ----------------------------------------------------------
class TestStage7Dashboard:
    @pytest.fixture
    def client(self, stored):
        pytest.importorskip("flask")
        from sentinelforge.bus import EventBus
        from sentinelforge.dashboard.app import create_app
        from sentinelforge.dashboard.state import DashboardConfig, DashboardContext

        bus = EventBus()
        context = DashboardContext(DashboardConfig(db_path=stored), bus=bus)
        app = create_app(context=context, start_monitors=False)
        app.config.update(TESTING=True)
        yield app.test_client()
        context.stop()
        bus.close()

    def test_the_api_serves_the_incident_the_engines_produced(self, client, incident):
        payload = client.get(f"/api/incidents/{incident.incident_id}").get_json()
        assert payload["severity"] == "critical"
        assert payload["risk_score"] == 100
        assert payload["alert_count"] == 5
        assert payload["version"] == incident.version

    def test_the_timeline_and_attack_chain_are_served(self, client, incident):
        timeline = client.get(f"/api/incidents/{incident.incident_id}/timeline").get_json()
        chain = client.get(f"/api/incidents/{incident.incident_id}/attack-chain").get_json()
        assert len(timeline["entries"]) == len(incident.timeline)
        assert chain["techniques"]
        assert "AUTH_THEN_PROCESS_THEN_NETWORK" in chain["matched_chains"]

    def test_the_process_tree_and_network_view_are_served(self, client, incident):
        tree = client.get(f"/api/incidents/{incident.incident_id}/process-tree").get_json()
        network = client.get(f"/api/incidents/{incident.incident_id}/network").get_json()
        assert tree["available"] is True
        assert tree["roots"]
        connections = network["connections"]
        assert connections
        assert connections[0]["destination_ip"] == C2
        assert connections[0]["destination_port"] == 443
        assert connections[0]["protocol"] == "tcp"
        assert connections[0]["pid"] == 4300

    def test_the_ai_reading_is_served_beside_the_deterministic_verdict(self, client, incident):
        payload = client.get(f"/api/incidents/{incident.incident_id}/ai").get_json()
        assert payload["available"] is True
        assert payload["deterministic_severity"] == "critical"
        assert payload["deterministic_score"] == 100

    def test_the_incident_page_renders(self, client, incident):
        response = client.get(f"/incidents/{incident.incident_id}")
        assert response.status_code == 200
        assert b"critical" in response.data.lower()

    def test_the_dashboard_adds_no_detection_of_its_own(self, client, incident):
        payload = client.get("/api/stats").get_json()
        assert payload["incidents"]["total"] == 1
        assert payload["incidents"]["by_severity"]["critical"] == 1


# -- 8. response -----------------------------------------------------------
class TestStage8Response:
    @pytest.fixture
    def engine(self, stored, events):
        return ResponseEngine(
            db_path=stored, backends=simulation_backends(events), actor=SIMULATION_ACTOR
        )

    def test_the_whole_lifecycle_runs_without_root(self, engine, incident):
        preview = engine.preview(
            ActionType.BLOCK_IP, ATTACKER, incident_id=incident.incident_id
        )
        assert preview["would_be_allowed"]

        action = engine.request(
            ActionType.BLOCK_IP,
            ATTACKER,
            incident_id=incident.incident_id,
            reason="end-to-end regression test",
        )
        assert action.status == ActionStatus.AWAITING_APPROVAL

        with pytest.raises(ApprovalRequired):
            engine.execute(action.action_id)

        approved = engine.approve(action.action_id, approved_by="analyst")
        assert approved.status == ActionStatus.APPROVED

        executed = engine.execute(action.action_id, executed_by="analyst")
        assert executed.status == ActionStatus.COMPLETED
        assert executed.verified is True
        assert executed.verification

        rolled_back = engine.rollback(executed.action_id, actor="analyst")
        assert rolled_back.status == ActionStatus.ROLLED_BACK
        assert engine.backends.firewall.rules == {}

    def test_a_process_from_the_telemetry_can_be_contained(self, engine, incident):
        action = engine.request(
            ActionType.KILL_PROCESS,
            "4300",
            incident_id=incident.incident_id,
            reason="end-to-end regression test",
        )
        engine.approve(action.action_id, approved_by="analyst")
        executed = engine.execute(action.action_id, executed_by="analyst")
        assert executed.status == ActionStatus.COMPLETED
        assert executed.verified is True
        assert 4300 in engine.backends.process.terminated
        # Terminating a process is not reversible, and is not offered as such.
        assert executed.rollback_available is False

    def test_the_incident_is_not_rewritten_by_a_response(self, engine, stored, incident):
        before = incident.version
        action = engine.request(
            ActionType.BLOCK_IP, C2, incident_id=incident.incident_id, reason="test"
        )
        engine.approve(action.action_id, approved_by="analyst")
        engine.execute(action.action_id, executed_by="analyst")
        with IncidentStore(stored) as store:
            assert store.get(incident.incident_id).version == before


# -- 9. audit --------------------------------------------------------------
class TestStage9Audit:
    def test_every_decision_is_recorded_and_the_chain_verifies(
        self, stored, events, incident
    ):
        engine = ResponseEngine(
            db_path=stored, backends=simulation_backends(events), actor=SIMULATION_ACTOR
        )
        action = engine.request(
            ActionType.BLOCK_IP, ATTACKER, incident_id=incident.incident_id, reason="audit"
        )
        engine.approve(action.action_id, approved_by="analyst")
        engine.execute(action.action_id, executed_by="analyst")

        records = engine.audit_records(action_id=action.action_id)
        assert {r["event"] for r in records} >= {
            "requested", "approved", "execution_started", "executed"
        }
        assert all(r["incident_id"] == incident.incident_id for r in records)
        assert engine.verify_audit()["ok"]

    def test_the_trail_cannot_be_rewritten(self, stored, events, incident):
        import sqlite3

        engine = ResponseEngine(
            db_path=stored, backends=simulation_backends(events), actor=SIMULATION_ACTOR
        )
        engine.request(
            ActionType.BLOCK_IP, ATTACKER, incident_id=incident.incident_id, reason="audit"
        )
        with ResponseStore(stored) as store:
            with pytest.raises(sqlite3.DatabaseError):
                store.connect().execute("DELETE FROM response_audit")


# -- 10. the properties the whole chain must keep --------------------------
class TestNoPrivilegeOrNetworkWasNeeded:
    def test_the_chain_ran_as_an_unprivileged_user(self):
        """If this suite needed root, it would be testing the machine, not the tool."""
        assert os.geteuid() != 0 or os.environ.get("SENTINELFORGE_ALLOW_ROOT_TESTS"), (
            "run the test suite as an ordinary user"
        )

    def test_no_real_containment_backend_was_constructed(self, events):
        backends = simulation_backends(events)
        assert type(backends.firewall).__name__.startswith("Mock")
        assert type(backends.process).__name__.startswith("Mock")
        assert type(backends.session).__name__.startswith("Mock")

    def test_the_ai_stage_used_the_offline_provider(self, analysis):
        assert analysis.audit.is_mock
        assert analysis.audit.model.startswith("sentinelforge-mock")

    def test_the_whole_chain_is_reproducible(self):
        """Run it twice from scratch; the incident fingerprint is identical."""
        first = CorrelationEngine().run(DetectionEngine().run(SCENARIO.events()))[0]
        second = CorrelationEngine().run(DetectionEngine().run(SCENARIO.events()))[0]
        assert first.version == second.version
        assert first.to_json() == second.to_json()
