"""Tests for the rendered HTML pages (Phase 6).

These check that each view actually shows what an analyst needs -- not just
that it returns 200.  Rendering is server-side, so the assertions are on the
markup itself.
"""

import pytest

from conftest import make_alert, network_event, process_event
from sentinelforge.ai.analyst import AISocAnalyst, attach_analysis
from sentinelforge.ai.cache import MemoryAnalysisCache
from sentinelforge.ai.client import LLMClient, LLMConfig
from sentinelforge.ai.providers.mock import MockProvider
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.dashboard.app import create_app
from sentinelforge.dashboard.state import DashboardConfig, DashboardContext
from sentinelforge.storage.sqlite import IncidentStore


def body(client, path):
    response = client.get(path)
    assert response.status_code == 200, f"{path} -> {response.status_code}"
    return response.get_data(as_text=True)


@pytest.fixture
def rich_client(tmp_path, dashboard_bus, compromise_alerts):
    """An incident with process telemetry, network telemetry and an AI analysis."""
    alerts = list(compromise_alerts) + [
        make_alert("SUSPICIOUS_PROCESS_EXECUTION", 480, "ALT-000004", evidence=[process_event(480)]),
        make_alert("SUSPICIOUS_NETWORK_CONNECTION", 540, "ALT-000005", evidence=[network_event(540)]),
    ]
    incident = CorrelationEngine().run(alerts)[0]
    analyst = AISocAnalyst(
        LLMClient(MockProvider(), LLMConfig(), sleep=lambda _: None), cache=MemoryAnalysisCache()
    )
    attach_analysis(incident, analyst.analyze(incident))

    path = str(tmp_path / "rich.db")
    with IncidentStore(path) as store:
        store.save(incident)
    context = DashboardContext(DashboardConfig(db_path=path), bus=dashboard_bus)
    app = create_app(context=context, start_monitors=False)
    yield app.test_client()
    context.stop()


class TestNavigation:
    @pytest.mark.parametrize("path", ["/", "/alerts", "/incidents", "/live", "/mitre", "/sensors"])
    def test_every_page_renders_with_navigation(self, client, path):
        markup = body(client, path)
        assert "SENTINEL" in markup
        for link in ("/alerts", "/incidents", "/live", "/mitre", "/sensors"):
            assert f'href="{link}"' in markup

    def test_unknown_page_is_a_404_page_not_a_traceback(self, client):
        response = client.get("/nope")
        assert response.status_code == 404
        assert "not_found" in response.get_data(as_text=True)

    def test_malformed_incident_id_is_a_400_page(self, client):
        assert client.get("/incidents/not-an-id").status_code == 400

    def test_missing_incident_is_a_404_page(self, client):
        assert client.get("/incidents/INC-987654").status_code == 404


class TestOverview:
    def test_shows_the_key_counters(self, client):
        markup = body(client, "/")
        for element in ("stat-active", "stat-critical", "stat-high", "stat-eps", "stat-events"):
            assert f'id="{element}"' in markup
        assert "Active incidents" in markup

    def test_shows_recent_incidents_alerts_mitre_and_sensors(self, client):
        markup = body(client, "/")
        assert "INC-000001" in markup
        assert "SSH_BRUTE_FORCE" in markup
        assert "T1110.001" in markup
        assert "ebpf-process" in markup

    def test_has_a_live_feed_container(self, client):
        markup = body(client, "/")
        assert 'id="live-feed"' in markup
        assert "live.js" in markup

    def test_empty_deployment_explains_what_to_do(self, empty_db, dashboard_bus):
        context = DashboardContext(DashboardConfig(db_path=empty_db), bus=dashboard_bus)
        app = create_app(context=context, start_monitors=False)
        try:
            markup = body(app.test_client(), "/")
            assert "No incidents stored yet" in markup
            assert "sentinelforge detect" in markup
        finally:
            context.stop()


class TestIncidentDetail:
    def test_summary_facts(self, rich_client):
        markup = body(rich_client, "/incidents/INC-000001")
        assert "INC-000001" in markup
        # The title comes from the strongest attack chain the engine matched.
        assert "Possible Post-Compromise Command And Control" in markup
        assert "192.168.1.50" in markup
        assert "capslock" in markup
        assert "AUTH_THEN_PROCESS_THEN_NETWORK" in markup

    def test_all_investigation_sections_are_present(self, rich_client):
        markup = body(rich_client, "/incidents/INC-000001")
        for section in ('id="chain"', 'id="timeline"', 'id="process"', 'id="network"',
                        'id="mitre"', 'id="ai"', 'id="evidence"'):
            assert section in markup

    def test_attack_chain_shows_one_step_per_detection(self, rich_client):
        markup = body(rich_client, "/incidents/INC-000001")
        assert markup.count('class="chain-step') == 5
        assert "SSH_BRUTE_FORCE" in markup
        assert "SUSPICIOUS_NETWORK_CONNECTION" in markup

    def test_timeline_is_shown_with_context_columns(self, rich_client):
        markup = body(rich_client, "/incidents/INC-000001")
        assert "Timeline" in markup
        for column in ("Time", "Kind", "Process", "User", "IP", "Severity", "Evidence"):
            assert f"<th>{column}</th>" in markup

    def test_process_tree_marks_unobserved_parents(self, rich_client):
        markup = body(rich_client, "/incidents/INC-000001")
        assert "Process tree" in markup
        assert "not observed" in markup
        assert "Lineage is <strong>partial</strong>" in markup
        assert "never executed" in markup

    def test_network_section_shows_metadata_only(self, rich_client):
        markup = body(rich_client, "/incidents/INC-000001")
        assert "198.51.100.9" in markup
        assert "443" in markup
        assert "never captures packet payloads" in markup

    def test_deterministic_and_ai_verdicts_are_both_shown(self, rich_client):
        markup = body(rich_client, "/incidents/INC-000001")
        assert "DETERMINISTIC DETECTION" in markup
        assert "AI ANALYSIS" in markup
        assert "Source of truth" in markup
        assert "Advisory only" in markup

    def test_mock_ai_output_is_labelled(self, rich_client):
        markup = body(rich_client, "/incidents/INC-000001")
        assert "MOCK PROVIDER" in markup

    def test_ai_recommendations_are_marked_as_not_executed(self, rich_client):
        """Phase 7 gave the console a response layer; the AI still cannot use it."""
        markup = body(rich_client, "/incidents/INC-000001")
        assert "not executed" in markup
        assert "cannot start a response action" in markup

    def test_incident_without_ai_says_so(self, client):
        markup = body(client, "/incidents/INC-000001")
        assert "sentinelforge ai analyze" in markup

    def test_evidence_is_available_per_alert(self, rich_client):
        markup = body(rich_client, "/incidents/INC-000001")
        assert "Alerts and evidence" in markup
        assert "Failed password" in markup

    def test_missing_telemetry_is_explained(self, client):
        """An incident with no eBPF data must say so, not show an empty box."""
        markup = body(client, "/incidents/INC-000001")
        assert "no process telemetry in this incident" in markup
        assert "no network telemetry in this incident" in markup


class TestSeverityPresentation:
    def test_severity_is_not_conveyed_by_colour_alone(self, client):
        markup = body(client, "/incidents")
        assert "sev-text" in markup   # the word
        assert "sev-glyph" in markup  # the symbol
        assert "CRITICAL" in markup

    def test_risk_score_is_shown_as_a_number(self, client):
        assert 'class="risk-value"' in body(client, "/incidents")


class TestOtherPages:
    def test_alerts_page_lists_alerts_with_filters(self, client):
        markup = body(client, "/alerts")
        assert "SSH_BRUTE_FORCE" in markup
        assert 'name="severity"' in markup
        assert 'name="q"' in markup

    def test_mitre_page_explains_where_mappings_come_from(self, client):
        markup = body(client, "/mitre")
        assert "T1110.001" in markup
        assert "never assigns a technique of its own" in markup

    def test_sensors_page_shows_state_and_remedy(self, client):
        markup = body(client, "/sensors")
        assert "ebpf-process" in markup
        assert "ai-analyst" in markup
        assert "never presents telemetry it is not receiving" in markup

    def test_live_page_explains_how_events_arrive(self, client):
        markup = body(client, "/live")
        assert 'id="live-feed"' in markup
        assert "--watch-events" in markup
        assert 'id="live-pause"' in markup

    def test_demo_banner_only_appears_in_demo_mode(self, client, incident_db, dashboard_bus):
        assert "DEMO / SYNTHETIC DATA" not in body(client, "/")
        context = DashboardContext(
            DashboardConfig(db_path=incident_db, demo=True), bus=dashboard_bus
        )
        app = create_app(context=context, start_monitors=False)
        try:
            markup = body(app.test_client(), "/")
            assert "DEMO / SYNTHETIC DATA" in markup
            assert "not real telemetry" in markup
        finally:
            context.stop()
