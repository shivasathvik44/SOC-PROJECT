"""Phase 7: the whole pipeline, detection through containment.

One synthetic intrusion is pushed through every stage SentinelForge has:

    events -> detection -> alerts -> correlation -> incident -> AI analysis
           -> analyst request -> approval -> execution -> verification -> audit

Nothing is stubbed except the containment backends, which are in-memory: the
detection rules, the correlation engine, the incident store, the AI analyst
(offline mock provider), the response engine and the dashboard are all the real
ones.  The point is to show the seams hold -- especially the one between the AI
layer and the response layer, which does not exist.
"""

import pytest

from sentinelforge.ai.analyst import AISocAnalyst, AnalystConfig, attach_analysis
from sentinelforge.ai.cache import MemoryAnalysisCache
from sentinelforge.ai.client import LLMClient, LLMConfig
from sentinelforge.ai.providers.mock import MockProvider
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.dashboard.app import create_app
from sentinelforge.dashboard.state import DashboardConfig, DashboardContext
from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.response.engine import ResponseEngine
from sentinelforge.response.models import ActionStatus, ActionType
from sentinelforge.response.policy import PolicyConfig, ResponsePolicy
from sentinelforge.storage.sqlite import IncidentStore, ResponseStore


@pytest.fixture
def investigated_incident(tmp_path, attack_events):
    """A real incident, correlated from real alerts, with an AI analysis on it."""
    path = str(tmp_path / "sentinelforge.db")
    alerts = DetectionEngine().run(attack_events)
    incidents = CorrelationEngine().run(alerts)
    assert incidents, "the synthetic intrusion should correlate into an incident"
    incident = incidents[0]

    analyst = AISocAnalyst(
        LLMClient(MockProvider(), LLMConfig(), sleep=lambda _: None),
        AnalystConfig(),
        cache=MemoryAnalysisCache(),
    )
    attach_analysis(incident, analyst.analyze(incident))
    with IncidentStore(path) as store:
        store.save(incident)
    return path, incident


@pytest.fixture
def engine(investigated_incident, mock_backends):
    path, _ = investigated_incident
    return ResponseEngine(
        db_path=path,
        backends=mock_backends,
        policy=ResponsePolicy(PolicyConfig(cooldown_seconds=0)),
        actor="analyst",
    )


class TestFullFlow:
    def test_detection_to_containment(self, investigated_incident, engine, mock_backends):
        path, incident = investigated_incident
        source_ip = incident.source_ips[0]

        # 1. The AI has an opinion, and it is only an opinion.
        assert incident.ai_analysis
        assert engine.list_actions() == []

        # 2. The analyst previews. Nothing changes.
        preview = engine.preview(ActionType.BLOCK_IP, source_ip, ttl=900,
                                 incident_id=incident.incident_id)
        assert preview["would_be_allowed"]
        assert mock_backends.firewall.rules == {}

        # 3. The analyst requests. Still nothing changes.
        action = engine.request(
            ActionType.BLOCK_IP,
            source_ip,
            incident_id=incident.incident_id,
            reason="SSH brute force followed by a successful login",
            ttl=900,
        )
        assert action.status == ActionStatus.AWAITING_APPROVAL
        assert mock_backends.firewall.rules == {}

        # 4. The analyst approves. Still nothing changes.
        engine.approve(action.action_id, "analyst")
        assert mock_backends.firewall.rules == {}

        # 5. The analyst executes. Now, and only now, the system changes.
        executed = engine.execute(action.action_id)
        assert executed.status == ActionStatus.COMPLETED
        assert executed.verified is True
        assert source_ip in mock_backends.firewall.blocked_addresses()

        # 6. Every step is in the audit trail, in order, and it verifies.
        events = [record["event"] for record in reversed(engine.audit_records())]
        assert events == ["requested", "approved", "execution_started", "executed"]
        assert engine.verify_audit()["ok"] is True

        # 7. The containment is reversible, and reversing it is audited too.
        engine.rollback(action.action_id, "analyst", "confirmed benign after review")
        assert mock_backends.firewall.rules == {}
        assert engine.audit_records()[0]["event"] == "rolled_back"

    def test_the_incident_and_its_actions_share_one_database(self, investigated_incident, engine):
        path, incident = investigated_incident
        engine.request(ActionType.BLOCK_IP, incident.source_ips[0],
                       incident_id=incident.incident_id, reason="brute force")
        with IncidentStore(path) as store:
            assert store.get(incident.incident_id) is not None
        with ResponseStore(path) as store:
            assert store.action_count(incident.incident_id) == 1

    def test_the_incident_itself_is_never_rewritten_by_a_response(
        self, investigated_incident, engine
    ):
        """Phase 7 adds no second incident system; the Phase 3 record is untouched."""
        path, incident = investigated_incident
        before = incident.version
        action = engine.request(ActionType.BLOCK_IP, incident.source_ips[0],
                                incident_id=incident.incident_id, reason="brute force")
        engine.approve(action.action_id)
        engine.execute(action.action_id)
        with IncidentStore(path) as store:
            after = store.get(incident.incident_id)
        assert after.version == before
        assert after.status == incident.status
        assert after.ai_analysis == incident.ai_analysis

    def test_process_telemetry_becomes_a_containment_target(
        self, investigated_incident, engine, mock_backends
    ):
        """eBPF saw a PID; the analyst can act on it, through the same flow."""
        _path, incident = investigated_incident
        pids = [
            event.metadata.get("pid")
            for event in incident.unique_events()
            if (event.metadata or {}).get("pid")
        ]
        assert pids, "the eBPF telemetry in the fixture should carry a PID"
        pid = pids[0]
        mock_backends.process.add(pid, name="python3", command_line="python3 -c import socket")
        action = engine.request(ActionType.KILL_PROCESS, pid,
                                incident_id=incident.incident_id, reason="reverse shell")
        engine.approve(action.action_id)
        executed = engine.execute(action.action_id)
        assert executed.status == ActionStatus.COMPLETED
        assert executed.rollback_available is False
        assert mock_backends.process.terminated == [pid]


class TestAiBoundary:
    def test_an_ai_recommendation_never_becomes_an_action(
        self, investigated_incident, engine, mock_backends
    ):
        """Even a model shouting 'block this now' changes nothing by itself."""
        _path, incident = investigated_incident
        from sentinelforge.ai.schemas import AIIncidentAnalysis

        analysis = AIIncidentAnalysis.from_dict(incident.ai_analysis)
        assert analysis.recommended_actions  # the mock provider does recommend things
        assert engine.list_actions() == []
        assert mock_backends.firewall.rules == {}
        assert mock_backends.process.terminated == []

    def test_a_hostile_recommendation_is_stored_and_displayed_as_text(
        self, investigated_incident, mock_backends, dashboard_bus
    ):
        path, incident = investigated_incident
        incident.ai_analysis["recommended_actions"] = [
            {
                "action": "block_ip 203.0.113.50; rm -rf /",
                "priority": "critical",
                "reason": "<script>alert(1)</script>",
            }
        ]
        with IncidentStore(path) as store:
            store.save(incident)

        context = DashboardContext(DashboardConfig(db_path=path), bus=dashboard_bus)
        context._response_engine = ResponseEngine(
            db_path=path, backends=mock_backends,
            policy=ResponsePolicy(PolicyConfig(cooldown_seconds=0)),
        )
        app = create_app(context=context, start_monitors=False)
        try:
            markup = app.test_client().get(
                f"/incidents/{incident.incident_id}"
            ).get_data(as_text=True)
            assert "&lt;script&gt;alert(1)&lt;/script&gt;" in markup
            assert "<script>alert(1)</script>" not in markup
            assert "cannot start a response action" in markup
            # And nothing was requested by rendering the page.
            assert context.response_engine().list_actions() == []
            assert mock_backends.firewall.rules == {}
        finally:
            context.stop()


class TestDashboardFlow:
    def test_an_analyst_can_drive_the_whole_flow_from_the_api(
        self, investigated_incident, mock_backends, dashboard_bus
    ):
        path, incident = investigated_incident
        context = DashboardContext(DashboardConfig(db_path=path), bus=dashboard_bus)
        context._response_engine = ResponseEngine(
            db_path=path, backends=mock_backends,
            policy=ResponsePolicy(PolicyConfig(cooldown_seconds=0)), actor="analyst",
        )
        app = create_app(context=context, start_monitors=False)
        try:
            client = app.test_client()
            source_ip = incident.source_ips[0]

            created = client.post(
                "/api/response/request",
                json={
                    "action_type": "block_ip",
                    "target": source_ip,
                    "incident_id": incident.incident_id,
                    "reason": "brute force",
                    "ttl": 900,
                },
            )
            action_id = created.json["action"]["action_id"]
            assert created.json["action"]["status"] == "awaiting_approval"
            assert mock_backends.firewall.rules == {}

            assert client.post(f"/api/response/execute/{action_id}", json={}).status_code == 409
            client.post(f"/api/response/approve/{action_id}", json={"approved_by": "analyst"})
            executed = client.post(f"/api/response/execute/{action_id}", json={})
            assert executed.json["action"]["status"] == "completed"
            assert source_ip in mock_backends.firewall.blocked_addresses()

            # The incident page now shows the response history.
            markup = client.get(f"/incidents/{incident.incident_id}").get_data(as_text=True)
            assert action_id in markup
            assert "Response history" in markup

            # And the audit trail is complete and verifiable over HTTP.
            audit = client.get("/api/response/audit?verify=1").json
            assert audit["chain"]["ok"] is True
            assert {record["event"] for record in audit["items"]} >= {
                "requested", "approved", "executed"
            }
        finally:
            context.stop()

    def test_the_response_page_lists_actions_and_the_trail(
        self, investigated_incident, mock_backends, dashboard_bus
    ):
        path, incident = investigated_incident
        context = DashboardContext(DashboardConfig(db_path=path), bus=dashboard_bus)
        context._response_engine = ResponseEngine(
            db_path=path, backends=mock_backends,
            policy=ResponsePolicy(PolicyConfig(cooldown_seconds=0)), actor="analyst",
        )
        app = create_app(context=context, start_monitors=False)
        try:
            context.response_engine().request(
                ActionType.BLOCK_IP, incident.source_ips[0],
                incident_id=incident.incident_id, reason="brute force",
            )
            markup = app.test_client().get("/response").get_data(as_text=True)
            assert "ACTION-00001" in markup
            assert "AWAITING APPROVAL" in markup
            assert "append-only" in markup
        finally:
            context.stop()
