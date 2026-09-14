"""Phase 7: the response action model and its state machine.

The approval guarantee is a property of this state machine, so most of these
tests are about which transitions do *not* exist.
"""

import json

import pytest

from sentinelforge.response.models import (
    ActionOutcome,
    ActionPreview,
    ActionStatus,
    ActionType,
    InvalidTransition,
    ResponseAction,
    can_transition,
    format_action_id,
    format_audit_id,
)


def action(**overrides) -> ResponseAction:
    fields = {
        "action_id": "ACTION-00001",
        "action_type": ActionType.BLOCK_IP,
        "target": "203.0.113.50",
        "incident_id": "INC-000001",
    }
    fields.update(overrides)
    return ResponseAction(**fields)


class TestIds:
    def test_action_ids_are_sequential_and_padded(self):
        assert format_action_id(1) == "ACTION-00001"
        assert format_action_id(4242) == "ACTION-04242"

    def test_audit_ids_are_sequential_and_padded(self):
        assert format_audit_id(1) == "AUDIT-000001"


class TestVocabulary:
    def test_only_known_action_types_are_valid(self):
        assert ActionType.is_valid("block_ip")
        assert not ActionType.is_valid("rm_rf")
        assert not ActionType.is_valid("")

    def test_only_known_statuses_are_valid(self):
        assert ActionStatus.is_valid("awaiting_approval")
        assert not ActionStatus.is_valid("done")

    def test_an_unknown_status_falls_back_to_requested(self):
        assert action(status="whatever").status == ActionStatus.REQUESTED


class TestStateMachine:
    def test_a_new_action_starts_as_requested(self):
        assert action().status == ActionStatus.REQUESTED

    def test_execution_can_only_follow_approval(self):
        assert can_transition(ActionStatus.APPROVED, ActionStatus.EXECUTING)
        assert not can_transition(ActionStatus.AWAITING_APPROVAL, ActionStatus.EXECUTING)
        assert not can_transition(ActionStatus.REQUESTED, ActionStatus.EXECUTING)

    def test_transitioning_to_executing_without_approval_raises(self):
        item = action(status=ActionStatus.AWAITING_APPROVAL)
        with pytest.raises(InvalidTransition):
            item.transition(ActionStatus.EXECUTING)

    def test_a_rejected_action_is_final(self):
        item = action(status=ActionStatus.REJECTED)
        for status in ActionStatus.ALL:
            assert not item.can_transition_to(status)

    def test_a_completed_action_can_only_be_rolled_back(self):
        item = action(status=ActionStatus.COMPLETED)
        assert item.can_transition_to(ActionStatus.ROLLED_BACK)
        assert not item.can_transition_to(ActionStatus.EXECUTING)
        assert not item.can_transition_to(ActionStatus.COMPLETED)

    def test_a_dry_run_is_terminal(self):
        item = action(status=ActionStatus.DRY_RUN)
        for status in ActionStatus.ALL:
            assert not item.can_transition_to(status)

    def test_unknown_status_transitions_are_refused(self):
        with pytest.raises(InvalidTransition):
            action().transition("teleported")

    def test_the_happy_path_is_walkable(self):
        item = action()
        for status in (
            ActionStatus.AWAITING_APPROVAL,
            ActionStatus.APPROVED,
            ActionStatus.EXECUTING,
            ActionStatus.COMPLETED,
            ActionStatus.ROLLED_BACK,
        ):
            item.transition(status)
        assert item.status == ActionStatus.ROLLED_BACK


class TestContainment:
    def test_a_completed_block_holds_its_target(self):
        assert action(status=ActionStatus.COMPLETED).contains_target

    def test_a_dry_run_never_holds_a_target(self):
        assert not action(status=ActionStatus.COMPLETED, dry_run=True).contains_target

    def test_a_completed_kill_does_not_hold_a_pid(self):
        """A terminated process is over, not held -- the PID may be recycled."""
        item = action(action_type=ActionType.KILL_PROCESS, target="4242",
                      status=ActionStatus.COMPLETED)
        assert not item.contains_target

    def test_a_rolled_back_block_no_longer_holds_its_target(self):
        assert not action(status=ActionStatus.ROLLED_BACK).contains_target


class TestSerialization:
    def test_round_trip_preserves_every_field(self):
        item = action(
            status=ActionStatus.COMPLETED,
            reason="brute force",
            approved_by="analyst",
            ttl_seconds=900,
            verified=True,
            rollback_available=True,
            rollback_data={"rich_rule": "rule ..."},
            target_detail={"zone": "public"},
        )
        restored = ResponseAction.from_dict(json.loads(item.to_json()))
        assert restored.to_dict() == item.to_dict()

    def test_key_order_is_stable(self):
        keys = list(action().to_dict())
        assert keys[0] == "action_id"
        assert "rollback_available" in keys

    def test_summary_line_mentions_the_essentials(self):
        line = action(status=ActionStatus.AWAITING_APPROVAL).summary_line()
        assert "ACTION-00001" in line and "block_ip" in line and "203.0.113.50" in line
        assert "REAL" in line

    def test_a_dry_run_is_labelled_in_the_summary(self):
        assert "DRY-RUN" in action(dry_run=True).summary_line()


class TestPreviewAndOutcome:
    def test_a_preview_serializes_to_plain_data(self):
        preview = ActionPreview(
            action_type=ActionType.BLOCK_IP,
            target="203.0.113.50",
            description="Block",
            effect="Adds one rule",
            backend="firewalld",
            warnings=("careful",),
        )
        data = preview.to_dict()
        assert data["warnings"] == ["careful"]
        assert json.dumps(data)

    def test_an_outcome_reports_its_error(self):
        outcome = ActionOutcome(ok=False, detail="nope", error="permission denied")
        assert outcome.to_dict()["error"] == "permission denied"
