"""Tests for the dashboard's read-only JSON API (Phase 6).

No test here needs root, real logs, eBPF, an API key, or a running server: the
app is exercised through Flask's test client against a temporary database.
"""

import json

import pytest

from conftest import make_alert
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.dashboard.serializers import API_VERSION
from sentinelforge.storage.sqlite import IncidentStore


class TestHealth:
    def test_health_reports_ok(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json
        assert data["status"] == "ok"
        assert data["api_version"] == API_VERSION
        assert data["database"]["incidents"] == 1
        assert data["demo"] is False

    def test_health_exposes_no_secret(self, client, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-must-not-appear")
        assert "sk-must-not-appear" not in json.dumps(client.get("/api/health").json)

    def test_health_on_an_empty_database(self, empty_db, dashboard_bus):
        from sentinelforge.dashboard.app import create_app
        from sentinelforge.dashboard.state import DashboardConfig, DashboardContext

        context = DashboardContext(DashboardConfig(db_path=empty_db), bus=dashboard_bus)
        app = create_app(context=context, start_monitors=False)
        try:
            data = app.test_client().get("/api/health").json
            assert data["status"] == "ok"
            assert data["database"]["incidents"] == 0
        finally:
            context.stop()


class TestStats:
    def test_counts_by_severity_and_status(self, client):
        data = client.get("/api/stats").json
        assert data["incidents"]["total"] == 1
        assert data["incidents"]["critical"] == 1
        assert data["incidents"]["active"] == 1
        assert data["incidents"]["by_status"]["open"] == 1
        assert set(data["incidents"]["by_severity"]) == {"info", "low", "medium", "high", "critical"}

    def test_live_counters_are_present(self, client):
        live = client.get("/api/stats").json["live"]
        for key in ("events_received", "alerts_created", "events_per_second", "buffer_size"):
            assert key in live


class TestIncidents:
    def test_list_is_paginated(self, client):
        data = client.get("/api/incidents").json
        assert data["total"] == 1
        assert data["count"] == 1
        assert data["limit"] == 50
        assert data["offset"] == 0
        assert data["has_more"] is False
        assert data["items"][0]["incident_id"] == "INC-000001"

    def test_limit_and_offset(self, tmp_path, dashboard_bus):
        from sentinelforge.dashboard.app import create_app
        from sentinelforge.dashboard.state import DashboardConfig, DashboardContext

        path = str(tmp_path / "many.db")
        with IncidentStore(path) as store:
            for index in range(1, 8):
                incident = CorrelationEngine().run(
                    [make_alert("SSH_BRUTE_FORCE", index * 3600, f"ALT-{index:06d}")],
                    start_number=index,
                )[0]
                store.save(incident)
        context = DashboardContext(DashboardConfig(db_path=path), bus=dashboard_bus)
        app = create_app(context=context, start_monitors=False)
        try:
            client = app.test_client()
            page = client.get("/api/incidents?limit=3").json
            assert page["count"] == 3
            assert page["total"] == 7
            assert page["has_more"] is True
            second = client.get("/api/incidents?limit=3&offset=3").json
            assert second["offset"] == 3
            assert {item["incident_id"] for item in page["items"]}.isdisjoint(
                {item["incident_id"] for item in second["items"]}
            )
            assert client.get("/api/incidents?limit=99999").json["limit"] == 500
        finally:
            context.stop()

    def test_detail_contains_every_section(self, client):
        data = client.get("/api/incidents/INC-000001").json
        for section in (
            "attack_chain", "mitre", "alerts", "timeline", "process_tree", "network", "ai_analysis"
        ):
            assert section in data
        assert data["incident_id"] == "INC-000001"

    def test_missing_incident_is_404(self, client):
        response = client.get("/api/incidents/INC-999999")
        assert response.status_code == 404
        assert response.json["error"]["code"] == "incident_not_found"

    def test_malformed_id_is_400(self, client):
        for bad in ("not-an-id", "INC-abc", "INC-000001'", "INC_000001", "1 OR 1=1", "%20"):
            response = client.get(f"/api/incidents/{bad}")
            assert response.status_code == 400, bad
            assert response.json["error"]["code"] == "invalid_incident_id"

    def test_path_traversal_never_reaches_a_handler(self, client):
        """A traversal attempt must not read a file or leak one."""
        for attempt in ("../../etc/passwd", "..%2f..%2fetc%2fpasswd", "INC-000001/../../../etc/passwd"):
            response = client.get(f"/api/incidents/{attempt}")
            assert response.status_code in (400, 404), attempt
            assert b"root:" not in response.data

    def test_sub_resources(self, client):
        timeline = client.get("/api/incidents/INC-000001/timeline").json
        assert timeline["entries"]
        assert timeline["total"] >= len(timeline["entries"])

        chain = client.get("/api/incidents/INC-000001/attack-chain").json
        assert chain["stages"]

        alerts = client.get("/api/incidents/INC-000001/alerts").json
        assert alerts["total"] == 3
        assert "evidence" not in alerts["items"][0]
        with_evidence = client.get("/api/incidents/INC-000001/alerts?evidence=1").json
        assert "evidence" in with_evidence["items"][0]

    def test_sub_resources_handle_missing_incidents(self, client):
        for suffix in ("timeline", "attack-chain", "process-tree", "network", "ai", "alerts"):
            assert client.get(f"/api/incidents/INC-424242/{suffix}").status_code == 404
            assert client.get(f"/api/incidents/bogus/{suffix}").status_code == 400

    def test_empty_telemetry_is_200_with_a_reason(self, client):
        """"No process telemetry" is an answer, not an error."""
        tree = client.get("/api/incidents/INC-000001/process-tree")
        assert tree.status_code == 200
        assert tree.json["available"] is False
        assert tree.json["reason"]

        network = client.get("/api/incidents/INC-000001/network")
        assert network.status_code == 200
        assert network.json["available"] is False

    def test_missing_ai_analysis_is_200_with_a_reason(self, client):
        response = client.get("/api/incidents/INC-000001/ai")
        assert response.status_code == 200
        assert response.json["available"] is False
        assert "ai analyze" in response.json["reason"]
        assert response.json["deterministic"]["risk_score"] > 0


class TestAlertsAndEvents:
    def test_alerts_come_from_stored_incidents(self, client):
        data = client.get("/api/alerts").json
        assert data["total"] == 3
        assert {item["rule_id"] for item in data["items"]} == {
            "SSH_BRUTE_FORCE", "SSH_COMPROMISE_SUSPECTED", "SUSPICIOUS_SUDO"
        }
        assert all(item["incident_id"] == "INC-000001" for item in data["items"])

    def test_alerts_are_newest_first(self, client):
        stamps = [item["timestamp"] for item in client.get("/api/alerts").json["items"]]
        assert stamps == sorted(stamps, reverse=True)

    def test_events_endpoint_serves_the_live_buffer(self, client, dashboard_context):
        from sentinelforge.bus import Topic
        from sentinelforge.dashboard.serializers import serialize_event
        from conftest import failed_ssh

        assert client.get("/api/events").json["items"] == []
        dashboard_context.live.record(Topic.EVENT_RECEIVED, serialize_event(failed_ssh(0)))
        data = client.get("/api/events").json
        assert data["total"] == 1
        assert data["items"][0]["event_type"] == "authentication_failure"
        assert "live buffer" in data["source"]

    def test_bad_query_parameters_are_400(self, client):
        assert client.get("/api/incidents?limit=abc").status_code == 400
        assert client.get("/api/incidents?severity=apocalyptic").status_code == 400
        assert client.get("/api/incidents?sort=nonsense").status_code == 400
        assert client.get("/api/alerts?since=not-a-timestamp").status_code == 400
        assert client.get("/api/incidents?offset=-5").status_code == 400
        body = client.get("/api/incidents?limit=abc").json
        assert body["error"]["code"] == "bad_request"
        assert body["error"]["status"] == 400


class TestMitreAndSensors:
    def test_mitre_aggregates_stored_incidents(self, client):
        data = client.get("/api/mitre").json
        assert data["total"] >= 1
        assert data["incident_count"] == 1
        ids = {item["technique_id"] for item in data["items"]}
        assert "T1110.001" in ids

    def test_mitre_can_be_scoped_to_one_incident(self, client):
        assert client.get("/api/mitre?incident_id=INC-000001").json["incident_count"] == 1
        assert client.get("/api/mitre?incident_id=INC-999999").status_code == 404
        assert client.get("/api/mitre?incident_id=nope").status_code == 400

    def test_sensors_report_availability_honestly(self, client):
        data = client.get("/api/sensors").json
        names = {item["name"] for item in data["items"]}
        assert {"journal", "file", "ebpf-process", "ebpf-network", "ai-analyst"} <= names
        for item in data["items"]:
            assert item["state"] in ("online", "offline", "configured", "not configured")
            if not item["available"]:
                assert item["reason"], f"{item['name']} is offline without a reason"

    def test_sensor_status_exposes_no_key(self, client, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-secret-not-for-the-browser")
        assert "sk-secret-not-for-the-browser" not in json.dumps(client.get("/api/sensors").json)


class TestApiIsReadOnly:
    @pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
    def test_write_methods_are_rejected(self, client, method):
        for path in ("/api/incidents", "/api/incidents/INC-000001", "/api/stats", "/api/sensors"):
            response = getattr(client, method)(path)
            assert response.status_code in (405, 404), f"{method} {path} was accepted"

    def test_only_the_response_api_declares_a_write_method(self, dashboard_app):
        """Phase 7 added containment; it did not loosen anything else.

        Before Phase 7 the whole API was GET-only.  It still is, apart from one
        blueprint: ``/api/response``, which is loopback-only, JSON-only and
        cannot execute anything a human has not approved in a separate call.
        No other part of the dashboard gained a write route with it.
        """
        writable = [
            rule.rule
            for rule in dashboard_app.url_map.iter_rules()
            if {"POST", "PUT", "PATCH", "DELETE"} & rule.methods
        ]
        assert writable, "the response API should expose write routes"
        for rule in writable:
            assert rule.startswith("/api/response/"), rule
        assert not any(
            {"PUT", "PATCH", "DELETE"} & rule.methods
            for rule in dashboard_app.url_map.iter_rules()
        )

    def test_unknown_api_path_is_json_404(self, client):
        response = client.get("/api/does-not-exist")
        assert response.status_code == 404
        assert response.json["error"]["code"] == "not_found"
