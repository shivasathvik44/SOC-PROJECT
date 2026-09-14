"""Phase 7: the response engine.

The lifecycle, and everything it refuses to skip.  Every test here runs against
mock backends (see ``conftest.no_real_containment``), so nothing touches the
host.
"""

import pytest

from sentinelforge.response.actions import ResponseBackends
from sentinelforge.response.backends.mock import (
    FAIL_BACKEND,
    FAIL_PERMISSION,
    FAIL_SURVIVES,
    FAIL_VERIFY,
    MockFirewallBackend,
)
from sentinelforge.response.engine import (
    ApprovalRequired,
    PolicyRefused,
    PrivilegeRequired,
    ResponseEngine,
    ResponseError,
)
from sentinelforge.response.models import ActionStatus, ActionType
from sentinelforge.response.policy import PolicyConfig, ResponsePolicy
from sentinelforge.response.validators import ValidationError


def block(engine, target="203.0.113.50", **kwargs):
    kwargs.setdefault("incident_id", "INC-000001")
    kwargs.setdefault("reason", "brute force")
    return engine.request(ActionType.BLOCK_IP, target, **kwargs)


def approved_block(engine, **kwargs):
    action = block(engine, **kwargs)
    engine.approve(action.action_id, "analyst")
    return action


class TestCapabilities:
    def test_every_action_type_is_reported(self, response_engine):
        capabilities = response_engine.capabilities()
        types = {entry["action_type"] for entry in capabilities["actions"]}
        assert types == set(ActionType.ALL)

    def test_the_guarantees_are_reported_and_never_negotiable(self, response_engine):
        capabilities = response_engine.capabilities()
        assert capabilities["approval_required"] is True
        assert capabilities["automatic_execution"] is False
        assert capabilities["dry_run_available"] is True
        assert capabilities["audit_logging"] is True

    def test_host_isolation_is_reported_unavailable(self, response_engine):
        entry = next(
            item for item in response_engine.capabilities()["actions"]
            if item["action_type"] == ActionType.ISOLATE_HOST
        )
        assert entry["available"] is False
        assert "Planned" in entry["reason"]


class TestPreview:
    def test_a_preview_changes_nothing_and_records_nothing(self, response_engine, mock_backends):
        result = response_engine.preview(ActionType.BLOCK_IP, "203.0.113.50", ttl=900)
        assert result["would_be_allowed"] is True
        assert mock_backends.firewall.rules == {}
        assert response_engine.list_actions() == []

    def test_a_preview_explains_the_effect_and_the_rollback(self, response_engine):
        preview = response_engine.preview(ActionType.BLOCK_IP, "203.0.113.50")["preview"]
        assert "drops packets" in preview["effect"] or "rich rule" in preview["effect"]
        assert preview["reversible"] is True

    def test_a_preview_of_a_refused_target_says_so(self, response_engine):
        result = response_engine.preview(ActionType.BLOCK_IP, "127.0.0.1")
        assert result["would_be_allowed"] is False
        assert "loopback" in result["policy"]["reason"]

    def test_an_unknown_action_type_is_refused(self, response_engine):
        with pytest.raises(ValidationError):
            response_engine.preview("rm_rf", "/")

    def test_a_kill_preview_names_the_process(self, response_engine):
        preview = response_engine.preview(ActionType.KILL_PROCESS, 4250)["preview"]
        assert "4250" in preview["description"]
        assert preview["reversible"] is False
        assert preview["target_detail"]["command_line"]


class TestRequest:
    def test_a_request_waits_for_approval_and_does_nothing(self, response_engine, mock_backends):
        action = block(response_engine)
        assert action.status == ActionStatus.AWAITING_APPROVAL
        assert mock_backends.firewall.rules == {}

    def test_a_request_records_who_asked_and_why(self, response_engine):
        action = block(response_engine, requested_by="capslock", reason="repeated failures")
        assert action.requested_by == "capslock"
        assert action.reason == "repeated failures"
        assert action.approved_by is None

    def test_a_request_records_the_policy_decision(self, response_engine):
        action = block(response_engine)
        assert action.policy_decision["allowed"] is True
        assert action.policy_decision["approval_required"] is True

    def test_a_request_captures_target_detail_before_anything_happens(self, response_engine):
        action = response_engine.request(ActionType.KILL_PROCESS, 4250, reason="reverse shell")
        assert action.target_detail["command_line"] == "python3 -c import socket,subprocess"
        assert action.target_detail["start_ticks"]

    def test_a_refused_request_raises_and_is_still_recorded(self, response_engine):
        with pytest.raises(PolicyRefused) as caught:
            block(response_engine, target="127.0.0.1")
        assert caught.value.action.status == ActionStatus.REJECTED
        stored = response_engine.get_action(caught.value.action.action_id)
        assert stored.status == ActionStatus.REJECTED
        assert "loopback" in stored.error

    def test_a_malformed_target_never_reaches_the_store(self, response_engine):
        with pytest.raises(ValidationError):
            block(response_engine, target="203.0.113.50; rm -rf /")
        assert response_engine.list_actions() == []

    def test_a_malformed_incident_id_is_refused(self, response_engine):
        with pytest.raises(ValidationError):
            block(response_engine, incident_id="../../etc/passwd")

    def test_action_ids_are_sequential(self, response_engine):
        first = block(response_engine)
        second = block(response_engine, target="198.51.100.25")
        assert (first.action_id, second.action_id) == ("ACTION-00001", "ACTION-00002")


class TestDryRun:
    def test_a_dry_run_reaches_no_backend(self, response_engine, mock_backends):
        action = block(response_engine, dry_run=True, ttl=900)
        assert action.status == ActionStatus.DRY_RUN
        assert mock_backends.firewall.rules == {}
        assert all(call[0] != "block_ip" for call in mock_backends.firewall.calls)

    def test_a_dry_run_carries_the_full_preview(self, response_engine):
        action = block(response_engine, dry_run=True, ttl=900)
        assert action.result["dry_run"] is True
        assert action.result["preview"]["effect"]
        assert action.result["note"] == "no system change was made"

    def test_a_dry_run_needs_no_approval_and_can_never_be_executed(self, response_engine):
        action = block(response_engine, dry_run=True)
        with pytest.raises(ResponseError, match="dry run"):
            response_engine.execute(action.action_id)

    def test_a_dry_run_does_not_contain_its_target(self, response_engine):
        block(response_engine, dry_run=True)
        assert response_engine.contained_targets() == {}

    def test_a_dry_run_of_a_process_does_not_terminate_it(self, response_engine, mock_backends):
        response_engine.request(ActionType.KILL_PROCESS, 4250, dry_run=True, reason="test")
        assert mock_backends.process.terminated == []
        assert mock_backends.process.get_process(4250) is not None


class TestApprovalIsMandatory:
    def test_execution_before_approval_is_refused(self, response_engine):
        action = block(response_engine)
        with pytest.raises(ApprovalRequired):
            response_engine.execute(action.action_id)

    def test_nothing_happens_when_execution_is_refused(self, response_engine, mock_backends):
        action = block(response_engine)
        with pytest.raises(ApprovalRequired):
            response_engine.execute(action.action_id)
        assert mock_backends.firewall.rules == {}
        assert response_engine.get_action(action.action_id).status == (
            ActionStatus.AWAITING_APPROVAL
        )

    def test_approval_alone_executes_nothing(self, response_engine, mock_backends):
        action = approved_block(response_engine)
        assert response_engine.get_action(action.action_id).status == ActionStatus.APPROVED
        assert mock_backends.firewall.rules == {}

    def test_approval_records_who_approved_and_when(self, response_engine):
        action = approved_block(response_engine)
        stored = response_engine.get_action(action.action_id)
        assert stored.approved_by == "analyst"
        assert stored.approved_at

    def test_a_rejected_action_can_never_be_executed(self, response_engine):
        action = block(response_engine)
        response_engine.reject(action.action_id, "analyst", "false positive")
        with pytest.raises(ResponseError):
            response_engine.execute(action.action_id)

    def test_a_cancelled_action_can_never_be_executed(self, response_engine):
        action = block(response_engine)
        response_engine.cancel(action.action_id, "analyst")
        with pytest.raises(ResponseError):
            response_engine.execute(action.action_id)

    def test_approving_twice_is_refused(self, response_engine):
        action = approved_block(response_engine)
        with pytest.raises(ResponseError, match="not awaiting approval"):
            response_engine.approve(action.action_id)

    def test_an_unknown_action_cannot_be_approved(self, response_engine):
        with pytest.raises(ResponseError, match="no such response action"):
            response_engine.approve("ACTION-99999")


class TestExecution:
    def test_an_approved_block_is_executed_and_verified(self, response_engine, mock_backends):
        action = approved_block(response_engine, ttl=900)
        executed = response_engine.execute(action.action_id)
        assert executed.status == ActionStatus.COMPLETED
        assert executed.verified is True
        assert "203.0.113.50" in mock_backends.firewall.blocked_addresses()

    def test_execution_records_timing_and_expiry(self, response_engine):
        action = approved_block(response_engine, ttl=900)
        executed = response_engine.execute(action.action_id)
        assert executed.started_at and executed.completed_at
        assert executed.expires_at

    def test_an_unverifiable_result_is_a_failure_not_a_success(self, tmp_path):
        """A zero exit code is never taken as proof."""
        firewall = MockFirewallBackend(fail=FAIL_VERIFY)
        engine = _engine(tmp_path, firewall=firewall)
        action = approved_block(engine)
        executed = engine.execute(action.action_id)
        assert executed.status == ActionStatus.FAILED
        assert executed.verified is False

    def test_a_permission_failure_is_reported_with_its_remedy(self, tmp_path):
        engine = _engine(tmp_path, firewall=MockFirewallBackend(fail=FAIL_PERMISSION))
        action = approved_block(engine)
        executed = engine.execute(action.action_id)
        assert executed.status == ActionStatus.FAILED
        assert "permission denied" in executed.error

    def test_a_backend_failure_is_reported_honestly(self, tmp_path):
        engine = _engine(tmp_path, firewall=MockFirewallBackend(fail=FAIL_BACKEND))
        action = approved_block(engine)
        assert engine.execute(action.action_id).status == ActionStatus.FAILED

    def test_a_process_that_survives_sigterm_is_a_failure(self, response_engine, mock_backends):
        mock_backends.process.fail = FAIL_SURVIVES
        action = response_engine.request(ActionType.KILL_PROCESS, 4250, reason="shell")
        response_engine.approve(action.action_id)
        executed = response_engine.execute(action.action_id)
        assert executed.status == ActionStatus.FAILED
        assert "SIGKILL" in executed.error

    def test_a_killed_process_is_verified_as_gone(self, response_engine, mock_backends):
        action = response_engine.request(ActionType.KILL_PROCESS, 4250, reason="shell")
        response_engine.approve(action.action_id)
        executed = response_engine.execute(action.action_id)
        assert executed.status == ActionStatus.COMPLETED
        assert executed.rollback_available is False
        assert mock_backends.process.terminated == [4250]

    def test_a_recycled_pid_is_not_terminated(self, response_engine, mock_backends):
        """Between approval and execution the PID became a different process."""
        action = response_engine.request(ActionType.KILL_PROCESS, 4250, reason="shell")
        response_engine.approve(action.action_id)
        mock_backends.process.processes.pop(4250)
        mock_backends.process.add(4250, name="innocent", start_ticks=999999)
        executed = response_engine.execute(action.action_id)
        assert executed.status == ActionStatus.FAILED
        assert "changed between approval and execution" in executed.error
        assert mock_backends.process.terminated == []

    def test_a_target_that_vanished_fails_cleanly(self, response_engine, mock_backends):
        action = response_engine.request(ActionType.KILL_PROCESS, 4250, reason="shell")
        response_engine.approve(action.action_id)
        mock_backends.process.processes.pop(4250)
        executed = response_engine.execute(action.action_id)
        assert executed.status == ActionStatus.FAILED
        assert "no longer valid" in executed.error

    def test_policy_is_re_evaluated_at_execution_time(self, response_engine, mock_backends):
        action = approved_block(response_engine)
        mock_backends.firewall.available = False
        executed = response_engine.execute(action.action_id)
        assert executed.status == ActionStatus.FAILED
        assert "policy refused execution" in executed.error

    def test_an_engine_without_execution_refuses_and_keeps_the_approval(self, tmp_path):
        engine = _engine(tmp_path, execution_enabled=False)
        action = approved_block(engine)
        with pytest.raises(PrivilegeRequired):
            engine.execute(action.action_id)
        assert engine.get_action(action.action_id).status == ActionStatus.APPROVED

    def test_executing_twice_is_refused(self, response_engine):
        action = approved_block(response_engine)
        response_engine.execute(action.action_id)
        with pytest.raises(ResponseError):
            response_engine.execute(action.action_id)


class TestRollback:
    def test_a_completed_block_can_be_undone(self, response_engine, mock_backends):
        action = approved_block(response_engine)
        response_engine.execute(action.action_id)
        rolled = response_engine.rollback(action.action_id, "analyst", "false positive")
        assert rolled.status == ActionStatus.ROLLED_BACK
        assert mock_backends.firewall.rules == {}
        assert response_engine.contained_targets() == {}

    def test_a_terminated_process_is_never_described_as_recoverable(self, response_engine):
        action = response_engine.request(ActionType.KILL_PROCESS, 4250, reason="shell")
        response_engine.approve(action.action_id)
        executed = response_engine.execute(action.action_id)
        assert executed.rollback_available is False
        with pytest.raises(ResponseError, match="not reversible"):
            response_engine.rollback(action.action_id)

    def test_an_unexecuted_action_cannot_be_rolled_back(self, response_engine):
        action = approved_block(response_engine)
        with pytest.raises(ResponseError, match="only a completed action"):
            response_engine.rollback(action.action_id)

    def test_a_failed_rollback_is_reported_and_leaves_the_block_in_place(self, tmp_path):
        firewall = MockFirewallBackend()
        engine = _engine(tmp_path, firewall=firewall)
        action = approved_block(engine)
        engine.execute(action.action_id)
        firewall.fail = FAIL_BACKEND
        with pytest.raises(ResponseError, match="rollback of"):
            engine.rollback(action.action_id)
        stored = engine.get_action(action.action_id)
        assert stored.status == ActionStatus.COMPLETED
        assert firewall.rules

    def test_rolling_back_twice_is_refused(self, response_engine):
        action = approved_block(response_engine)
        response_engine.execute(action.action_id)
        response_engine.rollback(action.action_id)
        with pytest.raises(ResponseError):
            response_engine.rollback(action.action_id)

    def test_unblock_is_available_as_an_action_of_its_own(self, response_engine, mock_backends):
        action = approved_block(response_engine)
        response_engine.execute(action.action_id)
        unblock = response_engine.request(
            ActionType.UNBLOCK_IP, "203.0.113.50", reason="cleared"
        )
        response_engine.approve(unblock.action_id)
        executed = response_engine.execute(unblock.action_id)
        assert executed.status == ActionStatus.COMPLETED
        assert mock_backends.firewall.rules == {}

    def test_unblocking_an_address_we_never_blocked_is_refused(self, response_engine):
        with pytest.raises(ValidationError, match="not blocked by SentinelForge"):
            response_engine.request(ActionType.UNBLOCK_IP, "198.51.100.25")


class TestTimeLimitedContainment:
    def test_a_lapsed_ttl_closes_the_action_without_touching_the_firewall(
        self, response_engine, mock_backends
    ):
        action = approved_block(response_engine, ttl=60)
        executed = response_engine.execute(action.action_id)
        # firewalld removed the rule itself when the timeout lapsed.
        mock_backends.firewall.rules.clear()
        stored = response_engine.get_action(executed.action_id)
        stored.expires_at = "2020-01-01T00:00:00Z"
        with response_engine.store() as store:
            store.save_action(stored)
        changed = response_engine.reconcile_expired()
        assert [item.action_id for item in changed] == [action.action_id]
        assert response_engine.get_action(action.action_id).status == ActionStatus.ROLLED_BACK
        assert mock_backends.firewall.calls[-1][0] != "unblock_ip"

    def test_a_block_still_installed_is_left_alone(self, response_engine):
        action = approved_block(response_engine, ttl=60)
        response_engine.execute(action.action_id)
        stored = response_engine.get_action(action.action_id)
        stored.expires_at = "2020-01-01T00:00:00Z"
        with response_engine.store() as store:
            store.save_action(stored)
        assert response_engine.reconcile_expired() == []
        assert response_engine.get_action(action.action_id).status == ActionStatus.COMPLETED

    def test_a_block_without_a_ttl_never_expires(self, response_engine):
        action = approved_block(response_engine)
        response_engine.execute(action.action_id)
        assert response_engine.reconcile_expired() == []


class TestHostIsolation:
    def test_it_is_refused_as_planned_only(self, response_engine):
        with pytest.raises(PolicyRefused) as caught:
            response_engine.request(ActionType.ISOLATE_HOST, "localhost")
        assert caught.value.decision.code == "not_implemented"

    def test_a_remote_host_can_never_be_targeted(self, response_engine):
        with pytest.raises(ValidationError, match="only ever target this host"):
            response_engine.request(ActionType.ISOLATE_HOST, "198.51.100.25")

    def test_its_preview_promises_nothing(self, response_engine):
        preview = response_engine.preview(ActionType.ISOLATE_HOST, "localhost")["preview"]
        assert preview["available"] is False
        assert preview["effect"].startswith("Nothing")


class TestIncidentLinkage:
    def test_actions_are_listed_per_incident(self, response_engine):
        block(response_engine, incident_id="INC-000001")
        block(response_engine, target="198.51.100.25", incident_id="INC-000002")
        assert len(response_engine.incident_actions("INC-000001")) == 1

    def test_an_action_can_stand_alone(self, response_engine):
        action = response_engine.request(ActionType.BLOCK_IP, "203.0.113.50")
        assert action.incident_id is None


def _engine(tmp_path, firewall=None, execution_enabled=True, **kwargs):
    """A second engine with its own database and backends."""
    from sentinelforge.response.backends.mock import MockProcessBackend, MockSessionBackend
    from sentinelforge.response.executor import ReadOnlyCommandRunner

    backends = ResponseBackends(
        firewall=firewall or MockFirewallBackend(),
        process=MockProcessBackend(),
        session=MockSessionBackend(),
        runner=ReadOnlyCommandRunner(),
    )
    return ResponseEngine(
        db_path=str(tmp_path / "other.db"),
        backends=backends,
        policy=ResponsePolicy(PolicyConfig(cooldown_seconds=0)),
        execution_enabled=execution_enabled,
        actor="analyst",
        **kwargs,
    )
