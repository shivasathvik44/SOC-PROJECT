"""Phase 7: the policy engine.

Validation asks whether a target is well formed.  Policy asks whether
SentinelForge is willing to act on it -- and refuses the targets that would
break the host or strand the analyst.
"""

import pytest

from sentinelforge.response.models import ActionStatus, ActionType, ResponseAction
from sentinelforge.response.policy import (
    ALLOW,
    DENY_ALREADY_CONTAINED,
    DENY_BACKEND_UNAVAILABLE,
    DENY_COOLDOWN,
    DENY_DUPLICATE_PENDING,
    DENY_NOT_IMPLEMENTED,
    DENY_PROTECTED_TARGET,
    DENY_RATE_LIMIT,
    DENY_UNKNOWN_ACTION,
    DENY_UNSAFE_TARGET,
    PolicyConfig,
    ResponsePolicy,
)
from sentinelforge.response.backends.base import BackendStatus


@pytest.fixture
def policy():
    return ResponsePolicy(PolicyConfig(cooldown_seconds=0))


def completed_block(action_id="ACTION-00001", target="203.0.113.50", **overrides):
    fields = {
        "action_id": action_id,
        "action_type": ActionType.BLOCK_IP,
        "target": target,
        "status": ActionStatus.COMPLETED,
    }
    fields.update(overrides)
    return ResponseAction(**fields)


class TestDefaults:
    def test_approval_is_always_required(self, policy):
        decision = policy.evaluate(ActionType.BLOCK_IP, "203.0.113.50")
        assert decision.allowed
        assert decision.approval_required is True
        assert decision.code == ALLOW

    def test_block_ip_is_reported_as_reversible_and_privileged(self, policy):
        decision = policy.evaluate(ActionType.BLOCK_IP, "203.0.113.50")
        assert decision.reversible is True
        assert decision.requires_privilege is True

    def test_kill_process_is_reported_as_irreversible(self, policy):
        decision = policy.evaluate(ActionType.KILL_PROCESS, "4242", {"name": "nc"})
        assert decision.reversible is False

    def test_an_unknown_action_type_is_refused(self, policy):
        decision = policy.evaluate("rm_rf", "/")
        assert not decision.allowed
        assert decision.code == DENY_UNKNOWN_ACTION

    def test_a_decision_serializes_to_plain_data(self, policy):
        data = policy.evaluate(ActionType.BLOCK_IP, "203.0.113.50").to_dict()
        assert data["approval_required"] is True
        assert isinstance(data["warnings"], list)


class TestUnsafeAddresses:
    @pytest.mark.parametrize(
        "address",
        ["0.0.0.0", "::", "127.0.0.1", "::1", "255.255.255.255", "224.0.0.1", "ff02::1"],
    )
    def test_infrastructure_addresses_are_refused(self, policy, address):
        decision = policy.evaluate(ActionType.BLOCK_IP, address)
        assert not decision.allowed
        assert decision.code == DENY_UNSAFE_TARGET
        assert decision.overridable is False

    def test_this_hosts_own_address_is_refused(self, policy, monkeypatch):
        monkeypatch.setattr(
            "sentinelforge.response.validators.local_addresses",
            lambda: frozenset({"192.0.2.77"}),
        )
        decision = policy.evaluate(ActionType.BLOCK_IP, "192.0.2.77")
        assert not decision.allowed
        assert "belongs to this host" in decision.reason

    def test_the_default_gateway_is_refused(self, policy, monkeypatch):
        monkeypatch.setattr(
            "sentinelforge.response.validators.default_gateways",
            lambda: frozenset({"192.0.2.1"}),
        )
        decision = policy.evaluate(ActionType.BLOCK_IP, "192.0.2.1")
        assert not decision.allowed
        assert "gateway" in decision.reason

    def test_no_override_can_lift_an_unsafe_address_refusal(self, policy):
        decision = policy.evaluate(ActionType.BLOCK_IP, "127.0.0.1", override_protected=True)
        assert not decision.allowed

    def test_multicast_can_be_enabled_deliberately(self):
        policy = ResponsePolicy(PolicyConfig(allow_multicast_targets=True, cooldown_seconds=0))
        assert policy.evaluate(ActionType.BLOCK_IP, "224.0.0.1").allowed

    def test_a_malformed_address_is_refused(self, policy):
        decision = policy.evaluate(ActionType.BLOCK_IP, "203.0.113.50; rm -rf /")
        assert not decision.allowed
        assert decision.code == DENY_UNSAFE_TARGET

    def test_a_private_address_is_allowed_with_a_warning(self, policy):
        decision = policy.evaluate(ActionType.BLOCK_IP, "10.1.2.3")
        assert decision.allowed
        assert any("internal address" in warning for warning in decision.warnings)


class TestProcessTargets:
    def test_pid_1_is_never_a_target(self, policy):
        decision = policy.evaluate(ActionType.KILL_PROCESS, "1", {"name": "systemd"})
        assert not decision.allowed
        assert decision.overridable is False
        assert "init system" in decision.reason

    def test_the_running_process_is_never_a_target(self, policy):
        import os

        decision = policy.evaluate(ActionType.KILL_PROCESS, str(os.getpid()), {"name": "python"})
        assert not decision.allowed
        assert decision.overridable is False

    def test_a_kernel_thread_is_refused(self, policy):
        decision = policy.evaluate(
            ActionType.KILL_PROCESS, "42", {"name": "kworker", "kernel_thread": True}
        )
        assert not decision.allowed
        assert "kernel thread" in decision.reason

    @pytest.mark.parametrize("name", ["sshd", "systemd-journald", "firewalld", "NetworkManager"])
    def test_critical_daemons_are_protected(self, policy, name):
        decision = policy.evaluate(ActionType.KILL_PROCESS, "4242", {"name": name})
        assert not decision.allowed
        assert decision.code == DENY_PROTECTED_TARGET
        assert decision.overridable is True

    def test_sentinelforge_itself_is_protected(self, policy):
        decision = policy.evaluate(
            ActionType.KILL_PROCESS,
            "4242",
            {"name": "python3", "command_line": "python3 -m sentinelforge dashboard"},
        )
        assert not decision.allowed
        assert decision.code == DENY_PROTECTED_TARGET

    def test_an_explicit_override_lifts_a_protected_refusal_and_is_recorded(self, policy):
        decision = policy.evaluate(
            ActionType.KILL_PROCESS, "4242", {"name": "sshd"}, override_protected=True
        )
        assert decision.allowed
        assert any("PROTECTED TARGET OVERRIDE" in warning for warning in decision.warnings)

    def test_an_ordinary_process_is_allowed(self, policy):
        decision = policy.evaluate(
            ActionType.KILL_PROCESS, "4250", {"name": "nc", "uid": 1000}
        )
        assert decision.allowed

    def test_a_root_process_is_allowed_with_a_warning(self, policy):
        decision = policy.evaluate(ActionType.KILL_PROCESS, "4250", {"name": "nc", "uid": 0})
        assert decision.allowed
        assert any("root" in warning for warning in decision.warnings)


class TestSessionTargets:
    def test_the_analysts_own_session_is_refused(self, policy):
        decision = policy.evaluate(
            ActionType.TERMINATE_SESSION, "2", {"is_own_session": True}
        )
        assert not decision.allowed
        assert decision.overridable is False

    def test_a_logind_manager_session_is_refused(self, policy):
        decision = policy.evaluate(ActionType.TERMINATE_SESSION, "3", {"class": "manager"})
        assert not decision.allowed

    def test_a_user_session_is_allowed_with_an_irreversibility_warning(self, policy):
        decision = policy.evaluate(
            ActionType.TERMINATE_SESSION, "7", {"class": "user", "name": "intruder"}
        )
        assert decision.allowed
        assert any("cannot be undone" in warning for warning in decision.warnings)


class TestHostIsolation:
    def test_host_isolation_is_refused_as_not_implemented(self, policy):
        decision = policy.evaluate(ActionType.ISOLATE_HOST, "fedora")
        assert not decision.allowed
        assert decision.code == DENY_NOT_IMPLEMENTED
        assert "reversibly" in decision.reason

    def test_the_refusal_is_not_blamed_on_the_firewall(self, policy):
        status = BackendStatus(name="firewalld", available=False, reason="not running")
        decision = policy.evaluate(ActionType.ISOLATE_HOST, "fedora", backend_status=status)
        assert decision.code == DENY_NOT_IMPLEMENTED


class TestBackendAvailability:
    def test_an_unavailable_backend_refuses_the_action(self, policy):
        status = BackendStatus(name="unsupported", available=False, reason="no firewalld here")
        decision = policy.evaluate(ActionType.BLOCK_IP, "203.0.113.50", backend_status=status)
        assert not decision.allowed
        assert decision.code == DENY_BACKEND_UNAVAILABLE
        assert decision.reason == "no firewalld here"


class TestRateLimiting:
    def test_an_already_contained_target_is_refused(self, policy):
        decision = policy.evaluate(
            ActionType.BLOCK_IP, "203.0.113.50", existing_actions=[completed_block()]
        )
        assert not decision.allowed
        assert decision.code == DENY_ALREADY_CONTAINED
        assert decision.related_action_id == "ACTION-00001"

    def test_containment_by_a_dry_run_does_not_count(self, policy):
        decision = policy.evaluate(
            ActionType.BLOCK_IP,
            "203.0.113.50",
            existing_actions=[completed_block(dry_run=True)],
        )
        assert decision.allowed

    def test_a_different_target_is_unaffected(self, policy):
        decision = policy.evaluate(
            ActionType.BLOCK_IP, "198.51.100.25", existing_actions=[completed_block()]
        )
        assert decision.allowed

    def test_a_different_action_type_is_unaffected(self, policy):
        decision = policy.evaluate(
            ActionType.UNBLOCK_IP, "203.0.113.50", existing_actions=[completed_block()]
        )
        assert decision.allowed

    def test_too_many_pending_requests_are_refused(self):
        policy = ResponsePolicy(PolicyConfig(max_pending_per_target=2, cooldown_seconds=0))
        pending = [
            completed_block(f"ACTION-0000{index}", status=ActionStatus.AWAITING_APPROVAL)
            for index in (1, 2)
        ]
        decision = policy.evaluate(
            ActionType.BLOCK_IP, "203.0.113.50", existing_actions=pending
        )
        assert not decision.allowed
        assert decision.code == DENY_DUPLICATE_PENDING

    def test_a_runaway_number_of_actions_is_refused(self):
        policy = ResponsePolicy(PolicyConfig(max_actions_per_target=3, cooldown_seconds=0))
        history = [
            completed_block(f"ACTION-0000{index}", status=ActionStatus.ROLLED_BACK)
            for index in range(3)
        ]
        decision = policy.evaluate(
            ActionType.BLOCK_IP, "203.0.113.50", existing_actions=history
        )
        assert not decision.allowed
        assert decision.code == DENY_RATE_LIMIT

    def test_the_cooldown_refuses_an_immediate_repeat(self):
        policy = ResponsePolicy(PolicyConfig(cooldown_seconds=300))
        recent = completed_block(status=ActionStatus.ROLLED_BACK)
        decision = policy.evaluate(
            ActionType.BLOCK_IP, "203.0.113.50", existing_actions=[recent]
        )
        assert not decision.allowed
        assert decision.code == DENY_COOLDOWN
        assert decision.related_action_id == "ACTION-00001"

    def test_an_old_action_does_not_trigger_the_cooldown(self):
        policy = ResponsePolicy(PolicyConfig(cooldown_seconds=60))
        old = completed_block(
            status=ActionStatus.ROLLED_BACK, requested_at="2020-01-01T00:00:00Z"
        )
        assert policy.evaluate(
            ActionType.BLOCK_IP, "203.0.113.50", existing_actions=[old]
        ).allowed
