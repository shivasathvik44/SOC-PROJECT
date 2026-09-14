"""Tests for search, filtering, sorting and pagination (Phase 6).

Filtering happens server-side so the browser never receives an unbounded
dataset.  These tests cover both the JSON API and the HTML pages, because both
expose the same filters.
"""

import pytest

from conftest import failed_ssh, make_alert, sudo_event
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.dashboard.app import create_app
from sentinelforge.dashboard.state import DashboardConfig, DashboardContext
from sentinelforge.storage.sqlite import IncidentStore


@pytest.fixture
def varied_db(tmp_path):
    """Four incidents that differ in severity, status, host, IP and technique."""
    path = str(tmp_path / "varied.db")
    incidents = []

    brute = CorrelationEngine().run(
        [
            make_alert(
                "SSH_BRUTE_FORCE", 0, "ALT-000001", host="web-01", src_ip="203.0.113.7",
                user="root", evidence=[failed_ssh(0, src_ip="203.0.113.7")],
            )
        ],
        start_number=1,
    )
    incidents.extend(brute)

    sudo = CorrelationEngine().run(
        [
            make_alert(
                "SUSPICIOUS_SUDO", 7200, "ALT-000002", host="db-02", src_ip=None,
                user="capslock", evidence=[sudo_event(7200, "/usr/bin/curl http://198.51.100.9/x")],
            )
        ],
        start_number=2,
    )
    sudo[0].status = "investigating"
    incidents.extend(sudo)

    invalid = CorrelationEngine().run(
        [
            make_alert(
                "AUTH_INVALID_USER", 14400, "ALT-000003", host="web-01", src_ip="198.51.100.22",
                user="admin",
            )
        ],
        start_number=3,
    )
    invalid[0].status = "resolved"
    incidents.extend(invalid)

    compromise = CorrelationEngine().run(
        [
            make_alert(
                "SSH_COMPROMISE_SUSPECTED", 21600, "ALT-000004", host="db-02",
                src_ip="203.0.113.7", user="capslock",
            )
        ],
        start_number=4,
    )
    incidents.extend(compromise)

    with IncidentStore(path) as store:
        store.save_all(incidents)
    return path


@pytest.fixture
def varied_client(varied_db, dashboard_bus):
    context = DashboardContext(DashboardConfig(db_path=varied_db), bus=dashboard_bus)
    app = create_app(context=context, start_monitors=False)
    yield app.test_client()
    context.stop()


def ids(payload):
    return {item["incident_id"] for item in payload["items"]}


class TestIncidentFilters:
    def test_by_severity(self, varied_client):
        data = varied_client.get("/api/incidents?severity=critical").json
        assert data["total"] >= 1
        assert all(item["severity"] == "critical" for item in data["items"])

    def test_by_minimum_severity(self, varied_client):
        data = varied_client.get("/api/incidents?min_severity=high").json
        assert all(item["severity"] in ("high", "critical") for item in data["items"])
        assert data["total"] < varied_client.get("/api/incidents").json["total"]

    def test_by_status(self, varied_client):
        assert ids(varied_client.get("/api/incidents?status=investigating").json) == {"INC-000002"}
        assert ids(varied_client.get("/api/incidents?status=resolved").json) == {"INC-000003"}
        assert varied_client.get("/api/incidents?status=open").json["total"] == 2

    def test_by_host(self, varied_client):
        data = varied_client.get("/api/incidents?host=web-01").json
        assert ids(data) == {"INC-000001", "INC-000003"}

    def test_by_source_ip(self, varied_client):
        data = varied_client.get("/api/incidents?source_ip=203.0.113.7").json
        assert ids(data) == {"INC-000001", "INC-000004"}

    def test_by_user(self, varied_client):
        data = varied_client.get("/api/incidents?user=capslock").json
        assert ids(data) == {"INC-000002", "INC-000004"}

    def test_by_mitre_technique(self, varied_client):
        exact = varied_client.get("/api/incidents?technique=T1110.001").json
        assert ids(exact) == {"INC-000001", "INC-000003"}
        # A parent technique matches its sub-techniques.
        parent = varied_client.get("/api/incidents?technique=T1110").json
        assert ids(parent) >= ids(exact)
        assert varied_client.get("/api/incidents?technique=T9999").json["total"] == 0

    def test_by_minimum_risk(self, varied_client):
        data = varied_client.get("/api/incidents?min_risk=80").json
        assert all(item["risk_score"] >= 80 for item in data["items"])

    def test_free_text_search(self, varied_client):
        assert ids(varied_client.get("/api/incidents?q=db-02").json) == {"INC-000002", "INC-000004"}
        assert varied_client.get("/api/incidents?q=INC-000001").json["total"] == 1
        assert varied_client.get("/api/incidents?q=zzzz-no-match").json["total"] == 0

    def test_filters_combine(self, varied_client):
        data = varied_client.get("/api/incidents?host=db-02&status=investigating").json
        assert ids(data) == {"INC-000002"}

    def test_unknown_filter_value_is_rejected(self, varied_client):
        assert varied_client.get("/api/incidents?status=deleted").status_code == 400
        assert varied_client.get("/api/incidents?severity=catastrophic").status_code == 400

    def test_all_disables_a_filter(self, varied_client):
        assert varied_client.get("/api/incidents?severity=all").json["total"] == 4


class TestSorting:
    def test_by_risk_score(self, varied_client):
        scores = [item["risk_score"] for item in varied_client.get("/api/incidents?sort=risk_score").json["items"]]
        assert scores == sorted(scores, reverse=True)
        ascending = [
            item["risk_score"]
            for item in varied_client.get("/api/incidents?sort=risk_score&order=asc").json["items"]
        ]
        assert ascending == sorted(ascending)

    def test_by_severity_uses_the_defined_order(self, varied_client):
        from sentinelforge.models.event import Severity

        ranks = [
            Severity.rank(item["severity"])
            for item in varied_client.get("/api/incidents?sort=severity").json["items"]
        ]
        assert ranks == sorted(ranks, reverse=True)

    def test_by_time(self, varied_client):
        stamps = [item["last_seen"] for item in varied_client.get("/api/incidents?sort=last_seen").json["items"]]
        assert stamps == sorted(stamps, reverse=True)

    def test_by_id(self, varied_client):
        identifiers = [
            item["incident_id"]
            for item in varied_client.get("/api/incidents?sort=incident_id&order=asc").json["items"]
        ]
        assert identifiers == sorted(identifiers)


class TestAlertFilters:
    def test_by_severity_and_rule(self, varied_client):
        data = varied_client.get("/api/alerts?severity=high").json
        assert all(item["severity"] == "high" for item in data["items"])
        rule = varied_client.get("/api/alerts?rule=SSH_BRUTE_FORCE").json
        assert all(item["rule_id"] == "SSH_BRUTE_FORCE" for item in rule["items"])

    def test_by_host_and_source_ip(self, varied_client):
        assert all(
            item["host"] == "web-01" for item in varied_client.get("/api/alerts?host=web-01").json["items"]
        )
        assert all(
            item["source_ip"] == "203.0.113.7"
            for item in varied_client.get("/api/alerts?source_ip=203.0.113.7").json["items"]
        )

    def test_by_time_range(self, varied_client):
        everything = varied_client.get("/api/alerts").json["items"]
        pivot = sorted(item["timestamp"] for item in everything)[1]
        later = varied_client.get(f"/api/alerts?since={pivot}").json
        assert all(item["timestamp"] >= pivot for item in later["items"])
        earlier = varied_client.get(f"/api/alerts?until={pivot}").json
        assert all(item["timestamp"] <= pivot for item in earlier["items"])

    def test_free_text_search(self, varied_client):
        assert varied_client.get("/api/alerts?q=brute").json["total"] >= 1
        assert varied_client.get("/api/alerts?q=zzzz").json["total"] == 0

    def test_alert_scan_is_bounded(self, varied_db, dashboard_bus):
        """The alert view must never load the entire history."""
        config = DashboardConfig(db_path=varied_db, alert_scan_incidents=2)
        context = DashboardContext(config, bus=dashboard_bus)
        app = create_app(context=context, start_monitors=False)
        try:
            data = app.test_client().get("/api/alerts").json
            assert data["scanned_incidents"] == 2
        finally:
            context.stop()


class TestHtmlFilters:
    def test_incident_page_filters(self, varied_client):
        response = varied_client.get("/incidents?host=web-01")
        body = response.get_data(as_text=True)
        assert response.status_code == 200
        assert "INC-000001" in body
        assert "INC-000002" not in body

    def test_incident_page_technique_filter(self, varied_client):
        body = varied_client.get("/incidents?technique=T1110").get_data(as_text=True)
        assert "INC-000001" in body
        assert "INC-000004" not in body

    def test_alerts_page_filters(self, varied_client):
        body = varied_client.get("/alerts?rule=SSH_BRUTE_FORCE").get_data(as_text=True)
        assert "SSH_BRUTE_FORCE" in body
        assert "SUSPICIOUS_SUDO" not in body

    def test_invalid_html_filters_degrade_instead_of_failing(self, varied_client):
        """A hand-edited URL must not produce a 500."""
        for url in (
            "/incidents?severity=bogus",
            "/incidents?min_risk=abc",
            "/incidents?sort=drop%20table",
            "/incidents?page=-4",
            "/alerts?severity=bogus",
        ):
            assert varied_client.get(url).status_code == 200, url

    def test_pagination_bounds_the_page(self, varied_db, dashboard_bus, monkeypatch):
        import sentinelforge.dashboard.routes as routes

        monkeypatch.setattr(routes, "PAGE_SIZE", 2)
        context = DashboardContext(DashboardConfig(db_path=varied_db), bus=dashboard_bus)
        app = create_app(context=context, start_monitors=False)
        try:
            client = app.test_client()
            first = client.get("/incidents").get_data(as_text=True)
            second = client.get("/incidents?page=2").get_data(as_text=True)
            assert first.count('class="mono incident-link"') == 2
            assert first != second
        finally:
            context.stop()
