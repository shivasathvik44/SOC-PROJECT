"""Phase 7: the dashboard response API.

The first state-changing routes in SentinelForge.  These tests cover both what
they do and, at least as importantly, what they refuse: cross-origin requests,
form posts, unknown action types, execution without approval, and any use at
all when the dashboard is not on loopback.
"""

import pytest

from sentinelforge.bus import Topic
from sentinelforge.dashboard.app import create_app
from sentinelforge.dashboard.state import DashboardConfig, DashboardContext
from sentinelforge.response.engine import ResponseEngine
from sentinelforge.response.policy import PolicyConfig, ResponsePolicy


@pytest.fixture
def response_app(tmp_path, dashboard_bus, mock_backends, incident_db):
    """A dashboard whose response engine is wired to in-memory backends."""
    context = DashboardContext(DashboardConfig(db_path=incident_db), bus=dashboard_bus)
    context._response_engine = ResponseEngine(
        db_path=incident_db,
        backends=mock_backends,
        policy=ResponsePolicy(PolicyConfig(cooldown_seconds=0)),
        actor="analyst",
    )
    app = create_app(context=context, start_monitors=False)
    app.config.update(TESTING=True)
    yield app
    context.stop()


@pytest.fixture
def api(response_app):
    return response_app.test_client()


def request_block(api, target="203.0.113.50", **overrides):
    body = {
        "action_type": "block_ip",
        "target": target,
        "incident_id": "INC-000001",
        "reason": "brute force",
        "requested_by": "analyst",
        "ttl": 900,
    }
    body.update(overrides)
    response = api.post("/api/response/request", json=body)
    return response


class TestCapabilities:
    def test_capabilities_list_every_action(self, api):
        payload = api.get("/api/response/capabilities").json
        types = {entry["action_type"] for entry in payload["actions"]}
        assert types == {"block_ip", "unblock_ip", "kill_process",
                         "terminate_session", "isolate_host"}

    def test_the_guarantees_are_part_of_the_contract(self, api):
        payload = api.get("/api/response/capabilities").json
        assert payload["approval_required"] is True
        assert payload["automatic_execution"] is False
        assert payload["audit_logging"] is True


class TestPreview:
    def test_a_preview_records_nothing(self, api, mock_backends):
        payload = api.post(
            "/api/response/preview", json={"action_type": "block_ip", "target": "203.0.113.50"}
        ).json
        assert payload["would_be_allowed"] is True
        assert mock_backends.firewall.rules == {}
        assert api.get("/api/response/actions").json["count"] == 0

    def test_a_refused_preview_explains_why(self, api):
        payload = api.post(
            "/api/response/preview", json={"action_type": "block_ip", "target": "127.0.0.1"}
        ).json
        assert payload["would_be_allowed"] is False
        assert "loopback" in payload["policy"]["reason"]

    def test_a_malformed_target_is_a_400_naming_the_field(self, api):
        response = api.post(
            "/api/response/preview",
            json={"action_type": "block_ip", "target": "203.0.113.50; rm -rf /"},
        )
        assert response.status_code == 400
        assert response.json["error"]["field"] == "target"


class TestApprovalWorkflow:
    def test_a_request_is_recorded_awaiting_approval(self, api, mock_backends):
        response = request_block(api)
        assert response.status_code == 201
        assert response.json["action"]["status"] == "awaiting_approval"
        assert "approve" in response.json["next_step"]
        assert mock_backends.firewall.rules == {}

    def test_execution_before_approval_is_refused(self, api, mock_backends):
        action_id = request_block(api).json["action"]["action_id"]
        response = api.post(f"/api/response/execute/{action_id}", json={})
        assert response.status_code == 409
        assert response.json["error"]["code"] == "approval_required"
        assert mock_backends.firewall.rules == {}

    def test_approval_executes_nothing(self, api, mock_backends):
        action_id = request_block(api).json["action"]["action_id"]
        response = api.post(f"/api/response/approve/{action_id}", json={"approved_by": "analyst"})
        assert response.json["action"]["status"] == "approved"
        assert mock_backends.firewall.rules == {}

    def test_the_full_flow_completes_and_verifies(self, api, mock_backends):
        action_id = request_block(api).json["action"]["action_id"]
        api.post(f"/api/response/approve/{action_id}", json={})
        response = api.post(f"/api/response/execute/{action_id}", json={})
        assert response.status_code == 200
        assert response.json["action"]["status"] == "completed"
        assert response.json["action"]["verified"] is True
        assert "203.0.113.50" in mock_backends.firewall.blocked_addresses()

    def test_a_completed_block_can_be_rolled_back(self, api, mock_backends):
        action_id = request_block(api).json["action"]["action_id"]
        api.post(f"/api/response/approve/{action_id}", json={})
        api.post(f"/api/response/execute/{action_id}", json={})
        response = api.post(f"/api/response/rollback/{action_id}", json={})
        assert response.json["action"]["status"] == "rolled_back"
        assert mock_backends.firewall.rules == {}

    def test_a_rejected_action_cannot_be_executed(self, api):
        action_id = request_block(api).json["action"]["action_id"]
        api.post(f"/api/response/reject/{action_id}", json={"reason": "false positive"})
        assert api.post(f"/api/response/execute/{action_id}", json={}).status_code == 409

    def test_an_action_can_be_cancelled(self, api):
        action_id = request_block(api).json["action"]["action_id"]
        assert api.post(f"/api/response/cancel/{action_id}", json={}).json["action"]["status"] == (
            "cancelled"
        )

    def test_a_dry_run_makes_no_change(self, api, mock_backends):
        response = request_block(api, dry_run=True)
        assert response.json["action"]["status"] == "dry_run"
        assert response.json["next_step"] is None
        assert mock_backends.firewall.rules == {}


class TestRefusals:
    def test_a_policy_refusal_is_a_409_with_its_code(self, api):
        response = request_block(api, target="127.0.0.1")
        assert response.status_code == 409
        assert response.json["error"]["policy_code"] == "unsafe_target"
        assert response.json["action"]["status"] == "rejected"

    def test_a_duplicate_names_the_action_already_containing_the_target(self, api):
        action_id = request_block(api).json["action"]["action_id"]
        api.post(f"/api/response/approve/{action_id}", json={})
        api.post(f"/api/response/execute/{action_id}", json={})
        response = request_block(api)
        assert response.status_code == 409
        assert response.json["error"]["related_action_id"] == action_id

    @pytest.mark.parametrize(
        "action_type", ["rm_rf", "shell", "", None, "block_ip; rm -rf /", 7]
    )
    def test_unknown_action_types_are_refused(self, api, action_type):
        response = api.post(
            "/api/response/request", json={"action_type": action_type, "target": "203.0.113.50"}
        )
        assert response.status_code == 400

    def test_a_non_object_body_is_refused(self, api):
        assert api.post("/api/response/request", json=["block_ip"]).status_code == 400

    def test_an_unknown_action_id_is_a_404_or_409(self, api):
        assert api.get("/api/response/actions/ACTION-99999").status_code == 404
        assert api.post("/api/response/approve/ACTION-99999", json={}).status_code == 409

    def test_a_malformed_action_id_is_refused(self, api):
        assert api.post("/api/response/approve/..%2f..%2fetc", json={}).status_code in (400, 404)


class TestCsrfAndTransport:
    def test_a_form_post_is_refused(self, api):
        """An HTML form cannot send application/json cross-origin."""
        response = api.post("/api/response/request", data={"action_type": "block_ip"})
        assert response.status_code == 415

    @pytest.mark.parametrize(
        "origin", ["http://evil.example", "https://attacker.test", "http://192.0.2.1:8080"]
    )
    def test_cross_origin_requests_are_refused(self, api, origin):
        response = api.post("/api/response/request", json={}, headers={"Origin": origin})
        assert response.status_code == 403
        assert response.json["error"]["code"] == "cross_origin"

    def test_a_cross_origin_referer_is_refused(self, api):
        response = api.post(
            "/api/response/request", json={}, headers={"Referer": "http://evil.example/x"}
        )
        assert response.status_code == 403

    @pytest.mark.parametrize("origin", ["http://127.0.0.1:8080", "http://localhost:8080"])
    def test_a_same_origin_request_is_accepted(self, api, origin):
        response = request_block(api)
        assert response.status_code == 201

    def test_an_oversized_body_is_refused(self, api):
        response = api.post(
            "/api/response/request",
            data=b"x" * (32 * 1024),
            content_type="application/json",
        )
        assert response.status_code in (413, 400)

    def test_reads_do_not_require_a_json_body(self, api):
        assert api.get("/api/response/actions").status_code == 200


class TestNotOnLoopback:
    def test_every_response_route_is_refused_off_loopback(self, tmp_path, incident_db, dashboard_bus):
        context = DashboardContext(
            DashboardConfig(db_path=incident_db, host="0.0.0.0"), bus=dashboard_bus
        )
        app = create_app(context=context, start_monitors=False)
        try:
            client = app.test_client()
            for path, method in (
                ("/api/response/capabilities", "get"),
                ("/api/response/actions", "get"),
                ("/api/response/audit", "get"),
                ("/api/response/request", "post"),
                ("/api/response/preview", "post"),
                ("/api/response/execute/ACTION-00001", "post"),
            ):
                response = getattr(client, method)(path, json={})
                assert response.status_code == 403, path
                assert response.json["error"]["code"] == "response_disabled"
        finally:
            context.stop()

    def test_the_response_api_can_be_switched_off(self, incident_db, dashboard_bus):
        context = DashboardContext(
            DashboardConfig(db_path=incident_db, response_enabled=False), bus=dashboard_bus
        )
        app = create_app(context=context, start_monitors=False)
        try:
            response = app.test_client().get("/api/response/capabilities")
            assert response.status_code == 403
            assert "--no-response" in response.json["error"]["message"]
        finally:
            context.stop()

    def test_the_read_only_api_is_unaffected(self, incident_db, dashboard_bus):
        context = DashboardContext(
            DashboardConfig(db_path=incident_db, host="0.0.0.0"), bus=dashboard_bus
        )
        app = create_app(context=context, start_monitors=False)
        try:
            assert app.test_client().get("/api/incidents").status_code == 200
        finally:
            context.stop()


class TestReadEndpoints:
    def test_actions_can_be_filtered(self, api):
        request_block(api)
        request_block(api, target="198.51.100.25")
        payload = api.get("/api/response/actions?incident_id=INC-000001").json
        assert payload["count"] == 2
        assert api.get("/api/response/actions?status=completed").json["count"] == 0

    def test_an_invalid_filter_is_refused(self, api):
        assert api.get("/api/response/actions?status=nonsense").status_code == 400
        assert api.get("/api/response/actions?action_type=rm_rf").status_code == 400
        assert api.get("/api/response/actions?limit=abc").status_code == 400

    def test_one_action_comes_with_its_audit_trail(self, api):
        action_id = request_block(api).json["action"]["action_id"]
        payload = api.get(f"/api/response/actions/{action_id}").json
        assert payload["action"]["action_id"] == action_id
        assert payload["audit"][0]["event"] == "requested"

    def test_the_audit_trail_can_be_verified_over_http(self, api):
        request_block(api)
        payload = api.get("/api/response/audit?verify=1").json
        assert payload["chain"]["ok"] is True
        assert payload["items"][0]["entry_hash"]

    def test_audit_records_carry_no_secret(self, api):
        request_block(api)
        body = api.get("/api/response/audit").get_data(as_text=True)
        for marker in ("password", "api_key", "token"):
            assert marker not in body.lower()


class TestBusIntegration:
    def test_a_state_change_is_announced_on_the_bus(self, api, dashboard_bus):
        """A watching console sees containment happen, like any other event."""
        with dashboard_bus.subscribe(Topic.RESPONSE_ACTION) as subscription:
            request_block(api)
            messages = subscription.drain()
        assert messages
        assert messages[0].payload["action_type"] == "block_ip"
        assert messages[0].payload["status"] == "awaiting_approval"

    def test_a_preview_announces_nothing(self, api, dashboard_bus):
        with dashboard_bus.subscribe(Topic.RESPONSE_ACTION) as subscription:
            api.post(
                "/api/response/preview",
                json={"action_type": "block_ip", "target": "203.0.113.50"},
            )
            assert subscription.drain() == []
