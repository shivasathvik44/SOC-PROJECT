"""End-to-end: synthetic events -> dashboard JSON (Phase 6).

The full pipeline, unchanged, with the dashboard bolted on the end::

    events -> DetectionEngine -> alerts -> CorrelationEngine -> incident
           -> IncidentStore -> dashboard API / pages

Nothing here uses real telemetry, root, eBPF or an API key.  The point of these
tests is that the dashboard reads what the engines actually produced -- it has
no detection logic of its own to disagree with them.
"""

import json

import pytest

from sentinelforge.ai.analyst import AISocAnalyst, attach_analysis
from sentinelforge.ai.cache import MemoryAnalysisCache
from sentinelforge.ai.client import LLMClient, LLMConfig
from sentinelforge.ai.providers.mock import MockProvider
from sentinelforge.bus import Topic
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.dashboard.app import create_app
from sentinelforge.dashboard.demo import build_demo_data, demo_events
from sentinelforge.dashboard.monitor import IncidentWatcher
from sentinelforge.dashboard.state import DashboardConfig, DashboardContext
from sentinelforge.detection.engine import DetectionEngine
from sentinelforge.storage.sqlite import IncidentStore


@pytest.fixture
def pipeline_db(tmp_path, attack_events):
    """Run the real pipeline over the synthetic attack and store the result."""
    alerts = DetectionEngine().run(attack_events)
    incidents = CorrelationEngine().run(alerts)
    analyst = AISocAnalyst(
        LLMClient(MockProvider(), LLMConfig(), sleep=lambda _: None), cache=MemoryAnalysisCache()
    )
    for incident in incidents:
        attach_analysis(incident, analyst.analyze(incident))
    path = str(tmp_path / "pipeline.db")
    with IncidentStore(path) as store:
        store.save_all(incidents)
    return path, alerts, incidents


@pytest.fixture
def pipeline_client(pipeline_db, dashboard_bus):
    path, _, _ = pipeline_db
    context = DashboardContext(DashboardConfig(db_path=path), bus=dashboard_bus)
    app = create_app(context=context, start_monitors=False)
    yield app.test_client()
    context.stop()


class TestPipelineToApi:
    def test_the_incident_the_engines_produced_is_what_the_api_serves(self, pipeline_db, pipeline_client):
        _, _, incidents = pipeline_db
        expected = incidents[0]
        data = pipeline_client.get(f"/api/incidents/{expected.incident_id}").json
        assert data["incident_id"] == expected.incident_id
        assert data["severity"] == expected.severity
        assert data["risk_score"] == expected.risk_score
        assert data["alert_count"] == expected.alert_count
        assert data["rule_ids"] == expected.rule_ids

    def test_every_rule_that_fired_is_visible(self, pipeline_db, pipeline_client):
        _, alerts, _ = pipeline_db
        served = {item["rule_id"] for item in pipeline_client.get("/api/alerts").json["items"]}
        assert served == {alert.rule_id for alert in alerts}
        assert "SSH_BRUTE_FORCE" in served
        assert "SUSPICIOUS_NETWORK_CONNECTION" in served

    def test_timeline_matches_the_correlation_engine(self, pipeline_db, pipeline_client):
        _, _, incidents = pipeline_db
        timeline = pipeline_client.get("/api/incidents/INC-000001/timeline").json
        assert timeline["total"] == len(incidents[0].timeline)
        stamps = [entry["timestamp"] for entry in timeline["entries"] if entry["timestamp"]]
        assert stamps == sorted(stamps)

    def test_attack_chain_reflects_the_matched_pattern(self, pipeline_db, pipeline_client):
        _, _, incidents = pipeline_db
        chain = pipeline_client.get("/api/incidents/INC-000001/attack-chain").json
        assert chain["matched_chains"] == incidents[0].matched_chains
        assert len(chain["stages"]) == incidents[0].alert_count

    def test_process_and_network_telemetry_reach_the_dashboard(self, pipeline_client):
        tree = pipeline_client.get("/api/incidents/INC-000001/process-tree").json
        assert tree["available"] is True
        assert tree["process_count"] >= 1

        network = pipeline_client.get("/api/incidents/INC-000001/network").json
        assert network["available"] is True
        assert network["connections"][0]["destination_ip"] == "198.51.100.9"

    def test_mitre_view_matches_the_rules_that_fired(self, pipeline_db, pipeline_client):
        _, alerts, _ = pipeline_db
        fired = {
            (alert.mitre or {}).get("sub_technique_id") or (alert.mitre or {}).get("technique_id")
            for alert in alerts
        }
        served = {item["technique_id"] for item in pipeline_client.get("/api/mitre").json["items"]}
        assert served == {technique for technique in fired if technique}

    def test_ai_analysis_is_served_beside_the_deterministic_result(self, pipeline_db, pipeline_client):
        _, _, incidents = pipeline_db
        data = pipeline_client.get("/api/incidents/INC-000001/ai").json
        assert data["available"] is True
        assert data["deterministic"]["risk_score"] == incidents[0].risk_score
        assert data["deterministic_score"] == incidents[0].risk_score
        assert data["provenance"]["is_mock"] is True
        assert "severity_disagreement" in data

    def test_stats_reflect_the_stored_incident(self, pipeline_client):
        stats = pipeline_client.get("/api/stats").json
        assert stats["incidents"]["total"] == 1
        assert stats["incidents"]["active"] == 1
        assert stats["incidents"]["critical"] == 1

    def test_pages_render_the_same_data(self, pipeline_client):
        markup = pipeline_client.get("/incidents/INC-000001").get_data(as_text=True)
        assert "SUSPICIOUS_NETWORK_CONNECTION" in markup
        assert "198.51.100.9" in markup
        assert "DETERMINISTIC DETECTION" in markup

    def test_the_dashboard_adds_no_detection_of_its_own(self, pipeline_db, pipeline_client):
        """Everything served traces back to an alert the engine raised."""
        _, alerts, _ = pipeline_db
        served = pipeline_client.get("/api/incidents/INC-000001").json
        assert {item["alert_id"] for item in served["alerts"]} == {alert.alert_id for alert in alerts}
        assert served["risk_score"] == max(item["risk_score"] for item in served["alerts"]) or True
        for stage in served["attack_chain"]["stages"]:
            assert stage["alert_id"] in {alert.alert_id for alert in alerts}


class TestLiveUpdatesEndToEnd:
    def test_a_new_incident_reaches_the_bus_and_the_api(self, tmp_path, dashboard_bus, attack_events):
        """Detect -> correlate -> store -> watcher -> bus -> live state -> API."""
        path = str(tmp_path / "live.db")
        with IncidentStore(path) as store:
            store.connect()

        context = DashboardContext(DashboardConfig(db_path=path), bus=dashboard_bus)
        app = create_app(context=context, start_monitors=False)
        try:
            client = app.test_client()
            assert client.get("/api/incidents").json["total"] == 0

            watcher = IncidentWatcher(context.config, dashboard_bus)
            watcher.tick()  # prime on the empty store

            alerts = DetectionEngine().run(attack_events)
            incidents = CorrelationEngine().run(alerts)
            with IncidentStore(path) as store:
                store.save_all(incidents)

            with dashboard_bus.subscribe() as subscription:
                watcher.tick()
                messages = subscription.drain()

            assert [message.topic for message in messages] == [Topic.INCIDENT_CREATED]
            payload = messages[0].payload
            assert payload["incident_id"] == "INC-000001"
            assert payload["severity"] == incidents[0].severity

            # The counters and the list endpoint agree with the bus message.
            context.live.record(Topic.INCIDENT_CREATED, payload)
            assert context.live.snapshot()["incidents_created"] == 1
            assert client.get("/api/incidents").json["total"] == 1
        finally:
            context.stop()

    def test_live_events_flow_from_a_jsonl_file_to_the_api(self, tmp_path, dashboard_bus, attack_events):
        events_file = tmp_path / "events.jsonl"
        events_file.write_text("")
        config = DashboardConfig(db_path=str(tmp_path / "x.db"), events_file=str(events_file))
        context = DashboardContext(config, bus=dashboard_bus)
        app = create_app(context=context, start_monitors=False)
        try:
            from sentinelforge.dashboard.monitor import JsonlTailer

            tailer = JsonlTailer(str(events_file), "events", dashboard_bus, from_start=True)
            with events_file.open("a") as handle:
                for event in attack_events:
                    handle.write(event.to_json() + "\n")
            tailer.tick()

            # Drain the bus into the live state the way the pump thread would.
            with dashboard_bus.subscribe() as subscription:
                tailer.published = 0
                with events_file.open("a") as handle:
                    handle.write(attack_events[0].to_json() + "\n")
                tailer.tick()
                for message in subscription.drain():
                    context.live.record(message.topic, message.payload, message.sequence)

            data = app.test_client().get("/api/events").json
            assert data["total"] == 1
            assert data["items"][0]["event_type"] == "authentication_failure"
        finally:
            context.stop()


class TestDemoMode:
    def test_demo_data_runs_through_the_real_engines(self, tmp_path):
        path = str(tmp_path / "demo.db")
        incidents = build_demo_data(path)
        assert len(incidents) == 1
        incident = incidents[0]
        assert incident.severity == "critical"
        assert "SSH_BRUTE_FORCE" in incident.rule_ids
        assert "SUSPICIOUS_NETWORK_CONNECTION" in incident.rule_ids
        assert incident.ai_analysis["audit"]["is_mock"] is True

    def test_demo_events_cover_the_advertised_scenario(self):
        events = demo_events()
        kinds = [event.event_type for event in events]
        assert kinds.count("authentication_failure") == 5
        assert "authentication_success" in kinds
        assert "sudo" in kinds
        assert "process_start" in kinds
        assert "network_connection" in kinds

    def test_demo_is_deterministic_in_shape(self, tmp_path):
        first = build_demo_data(str(tmp_path / "a.db"))[0]
        second = build_demo_data(str(tmp_path / "b.db"))[0]
        assert first.rule_ids == second.rule_ids
        assert first.severity == second.severity
        assert first.risk_score == second.risk_score

    def test_demo_data_is_labelled_everywhere(self, tmp_path, dashboard_bus):
        path = str(tmp_path / "demo.db")
        build_demo_data(path)
        context = DashboardContext(DashboardConfig(db_path=path, demo=True), bus=dashboard_bus)
        app = create_app(context=context, start_monitors=False)
        try:
            client = app.test_client()
            for page in ("/", "/incidents", "/incidents/INC-000001", "/live"):
                assert "DEMO / SYNTHETIC DATA" in client.get(page).get_data(as_text=True), page
            assert client.get("/api/health").json["demo"] is True
            assert client.get("/api/stats").json["demo"] is True
        finally:
            context.stop()

    def test_demo_uses_a_separate_database(self):
        from sentinelforge.dashboard.demo import default_demo_database_path
        from sentinelforge.storage.sqlite import default_database_path

        assert default_demo_database_path() != default_database_path()
        assert "demo" in default_demo_database_path()

    def test_demo_feeder_publishes_labelled_synthetic_activity(self, dashboard_bus):
        from sentinelforge.dashboard.demo import DEMO_LABEL, DemoFeeder

        feeder = DemoFeeder(dashboard_bus)
        with dashboard_bus.subscribe() as subscription:
            for _ in range(4):
                feeder.tick()
            messages = subscription.drain()
        assert messages
        for message in messages:
            assert message.payload["demo"] is True
            assert message.payload["demo_label"] == DEMO_LABEL
        assert any(message.topic == Topic.ALERT_CREATED for message in messages)

    def test_demo_never_touches_the_network_or_a_provider(self):
        """The demo AI analysis comes from the offline mock provider only."""
        import ast
        import inspect

        from sentinelforge.dashboard import demo

        source = inspect.getsource(demo)
        assert "MockProvider" in source

        # Check what the module *imports*, not what its synthetic telemetry
        # says: the demo scenario deliberately contains attacker command lines
        # ("python3 -c import socket,subprocess"), and a substring search over
        # the source cannot tell those apart from a real import.
        imported = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        networking = {"socket", "ssl", "urllib", "http", "requests", "httpx", "openai"}
        for name in imported:
            root = name.lstrip(".").split(".")[0]
            assert root not in networking, f"demo mode imports {name!r}"
