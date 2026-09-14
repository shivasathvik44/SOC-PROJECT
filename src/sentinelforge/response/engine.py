"""The response engine: request, approve, execute, verify, audit (Phase 7).

This is the only object that moves an action through its lifecycle, and it is
where the phase's central guarantee is implemented::

    AI recommends  ->  human approves  ->  engine validates  ->  executor acts
                                                             ->  result audited

Three things are worth knowing before reading the methods.

**Approval is structural, not procedural.**  :meth:`execute` does not check a
flag called ``approved``; it asks the action to transition from ``approved`` to
``executing``, and the state machine in :mod:`sentinelforge.response.models`
has no edge from ``awaiting_approval`` to ``executing``.  Skipping approval is
therefore not a policy someone could relax -- it is a transition that does not
exist.

**The target is re-checked at execution time.**  A request may sit in the queue
for minutes.  In that time a PID can be recycled onto an unrelated process and
an address can become this host's own.  So validation and policy run again
immediately before execution, against the system as it is now, not as it was
when the analyst clicked.

**Success means verified.**  Every execution ends with the handler re-reading
the system.  An action whose command exited zero but whose effect cannot be
confirmed is recorded as ``failed``, because a containment you cannot verify is
a containment you do not have.

Nothing here consumes AI output.  An analysis may *suggest* an action, and the
dashboard may show that suggestion, but the request that reaches this engine
always carries an operator label and an explicit human decision behind it.
"""

from __future__ import annotations

import logging

from ..models.event import format_timestamp, parse_timestamp, utc_now
from ..storage.sqlite import ResponseStore, default_database_path
from .actions import ResponseBackends, get_handler
from .audit import AuditEvent, AuditLog
from .models import ActionStatus, ActionType, ResponseAction, format_action_id
from .policy import PolicyConfig, ResponsePolicy
from .executor import is_root
from .validators import (
    ValidationError,
    validate_action_id,
    validate_action_type,
    validate_actor,
    validate_incident_id,
    validate_reason,
    validate_ttl,
)

LOGGER = logging.getLogger(__name__)

#: How many recent actions for a target the policy engine is shown.
POLICY_HISTORY_LIMIT = 50


class ResponseError(RuntimeError):
    """A response operation could not be carried out."""


class PolicyRefused(ResponseError):
    """The policy engine refused the request.

    Carries the recorded action (status ``rejected``) so the caller can show
    the analyst exactly what was refused and why.
    """

    def __init__(self, action: ResponseAction, decision) -> None:
        super().__init__(decision.reason)
        self.action = action
        self.decision = decision


class ApprovalRequired(ResponseError):
    """Execution was attempted on an action no human has approved."""


class PrivilegeRequired(ResponseError):
    """The action is approved but this process lacks the rights to run it.

    Deliberately *not* a failure of the action: the approval still stands, and
    the operator can re-run the execute step with the privileges the message
    names.  SentinelForge never escalates on its own behalf.
    """

    def __init__(self, message: str, action: ResponseAction) -> None:
        super().__init__(message)
        self.action = action


class ResponseEngine:
    """Runs the response lifecycle against one database and one set of backends.

    Args:
        db_path: The incident database; response actions live beside the
            incidents they belong to.  A fresh connection is opened per
            operation, so one engine is safe to share across the dashboard's
            request threads.
        backends: The containment mechanisms.  Defaults to whatever this host
            supports.  Tests pass mocks.
        policy: The policy engine.  Defaults to :class:`ResponsePolicy`.
        execution_enabled: When ``False`` the engine can validate, preview and
            dry-run, but its backends cannot change anything.
        actor: Default operator label when a caller does not supply one.
    """

    def __init__(
        self,
        db_path: str | None = None,
        backends: ResponseBackends | None = None,
        policy: ResponsePolicy | None = None,
        execution_enabled: bool = True,
        actor: str | None = None,
    ) -> None:
        self.db_path = db_path or default_database_path()
        self.execution_enabled = execution_enabled
        self.backends = backends or ResponseBackends.detect(execution_enabled=execution_enabled)
        self.policy = policy or ResponsePolicy(PolicyConfig())
        self.default_actor = actor

    # -- plumbing ----------------------------------------------------------
    def store(self) -> ResponseStore:
        """A fresh store for the calling thread.  Always used as a context manager."""
        return ResponseStore(self.db_path)

    def handler(self, action_type: str):
        return get_handler(action_type, self.backends)

    # -- capability --------------------------------------------------------
    def capabilities(self) -> dict:
        """What this host can actually do, action by action.

        The dashboard uses this to offer only the buttons that mean something,
        and the CLI to explain why an action is unavailable.  An action that
        cannot be carried out here is reported as unavailable with a reason and
        a remedy -- never hidden, and never offered and then failed.
        """
        actions = []
        for action_type in ActionType.ALL:
            handler = self.handler(action_type)
            status = handler.backend_status()
            actions.append(
                {
                    "action_type": action_type,
                    "label": handler.label,
                    "available": status.available,
                    "backend": status.name,
                    "reason": status.reason,
                    "remedy": status.remedy,
                    "reversible": handler.reversible,
                    "requires_privilege": handler.requires_privilege,
                    "privilege_satisfied": not handler.requires_privilege_here(),
                }
            )
        return {
            "actions": actions,
            "backends": self.backends.to_dict(),
            "execution_enabled": self.execution_enabled,
            "running_as_root": is_root(),
            "approval_required": True,
            "automatic_execution": False,
            "dry_run_available": True,
            "audit_logging": True,
        }

    # -- preview -----------------------------------------------------------
    def preview(
        self,
        action_type: str,
        target,
        ttl=None,
        incident_id: str | None = None,
        override_protected: bool = False,
    ) -> dict:
        """Describe what an action would do, and what policy thinks of it.

        Changes nothing, records nothing, and needs no approval: a preview is
        how an analyst decides whether to ask in the first place.
        """
        action_type = validate_action_type(action_type)
        incident_id = validate_incident_id(incident_id)
        ttl = validate_ttl(ttl)
        handler = self.handler(action_type)
        normalized, detail = handler.validate(target)
        preview = handler.preview(normalized, "ACTION-PREVIEW", ttl)
        with self.store() as store:
            existing = store.list_actions(target=normalized, limit=POLICY_HISTORY_LIMIT)
        decision = self.policy.evaluate(
            action_type,
            normalized,
            target_detail=detail,
            existing_actions=existing,
            override_protected=override_protected,
            backend_status=handler.backend_status(),
        )
        return {
            "action_type": action_type,
            "target": normalized,
            "incident_id": incident_id,
            "preview": preview.to_dict(),
            "policy": decision.to_dict(),
            "would_be_allowed": decision.allowed,
            "next_step": (
                "sentinelforge response request "
                f"{action_type.replace('_', '-')} {normalized}"
                if decision.allowed
                else None
            ),
        }

    # -- request -----------------------------------------------------------
    def request(
        self,
        action_type: str,
        target,
        incident_id: str | None = None,
        reason: str = "",
        requested_by: str | None = None,
        ttl=None,
        dry_run: bool = False,
        override_protected: bool = False,
    ) -> ResponseAction:
        """Record a request for containment.

        A real request lands in ``awaiting_approval``; nothing has happened to
        the system and nothing will until a human approves it.  A dry run is
        resolved here and then: it produces a full preview, is recorded with
        status ``dry_run``, and never reaches an executor.

        Raises:
            ValidationError: The target or a parameter is unusable.
            PolicyRefused: Policy said no.  The refusal is still recorded and
                audited -- a refused request is part of the investigation.
        """
        action_type = validate_action_type(action_type)
        incident_id = validate_incident_id(incident_id)
        reason = validate_reason(reason, required=self.policy.config.require_reason)
        requested_by = validate_actor(requested_by or self.default_actor, "requested_by")
        ttl = validate_ttl(ttl)

        handler = self.handler(action_type)
        normalized, detail = handler.validate(target)

        with self.store() as store:
            existing = store.list_actions(target=normalized, limit=POLICY_HISTORY_LIMIT)
            action_id = format_action_id(store.next_action_number())

            decision = self.policy.evaluate(
                action_type,
                normalized,
                target_detail=detail,
                existing_actions=existing,
                override_protected=override_protected,
                backend_status=handler.backend_status(),
            )
            action = ResponseAction(
                action_id=action_id,
                action_type=action_type,
                target=normalized,
                incident_id=incident_id,
                reason=reason,
                requested_by=requested_by,
                dry_run=bool(dry_run),
                ttl_seconds=ttl,
                target_detail=detail,
                policy_decision=decision.to_dict(),
                rollback_available=handler.reversible,
            )
            if override_protected:
                action.target_detail["protected_override"] = True
            audit = AuditLog(store)

            if not decision.allowed:
                action.status = ActionStatus.REJECTED
                action.error = decision.reason
                store.save_action(action)
                record = audit.record(
                    AuditEvent.POLICY_DENIED, action, error=decision.reason
                )
                action.audit_id = record.audit_id
                store.save_action(action)
                raise PolicyRefused(action, decision)

            if dry_run:
                # A dry run is resolved entirely from the preview: no backend
                # mutation method is called, and no approval is needed, because
                # nothing happens to the system.
                preview = handler.preview(normalized, action_id, ttl)
                action.status = ActionStatus.DRY_RUN
                action.result = {
                    "dry_run": True,
                    "preview": preview.to_dict(),
                    "note": "no system change was made",
                }
                action.verification = "dry run: nothing was executed and nothing was verified"
                action.completed_at = utc_now()
                store.save_action(action)
                record = audit.record(AuditEvent.DRY_RUN, action)
                action.audit_id = record.audit_id
                store.save_action(action)
                return action

            action.transition(ActionStatus.AWAITING_APPROVAL)
            store.save_action(action)
            record = audit.record(AuditEvent.REQUESTED, action)
            action.audit_id = record.audit_id
            store.save_action(action)
            return action

    # -- approval ----------------------------------------------------------
    def approve(
        self, action_id: str, approved_by: str | None = None, reason: str | None = None
    ) -> ResponseAction:
        """Record a human's approval.  Executes nothing.

        Approval and execution are separate calls on purpose: a single
        "approve and run" step is how an accidental click becomes an
        irreversible change.
        """
        action_id = validate_action_id(action_id)
        approved_by = validate_actor(approved_by or self.default_actor, "approved_by")
        with self.store() as store:
            action = self._load(store, action_id)
            if action.status != ActionStatus.AWAITING_APPROVAL:
                raise ResponseError(
                    f"{action_id} is {action.status}, not awaiting approval"
                )
            action.transition(ActionStatus.APPROVED)
            action.approved_by = approved_by
            action.approved_at = utc_now()
            if reason:
                action.reason = validate_reason(
                    f"{action.reason} | approval: {reason}" if action.reason else reason
                )
            store.save_action(action)
            AuditLog(store).record(AuditEvent.APPROVED, action)
            return action

    def reject(
        self, action_id: str, actor: str | None = None, reason: str = ""
    ) -> ResponseAction:
        """Refuse a pending action.  It can never be executed afterwards."""
        action_id = validate_action_id(action_id)
        actor = validate_actor(actor or self.default_actor, "approved_by")
        reason = validate_reason(reason)
        with self.store() as store:
            action = self._load(store, action_id)
            action.transition(ActionStatus.REJECTED)
            action.approved_by = actor
            action.error = reason or "rejected by an analyst"
            store.save_action(action)
            AuditLog(store).record(AuditEvent.REJECTED, action, error=action.error)
            return action

    def cancel(
        self, action_id: str, actor: str | None = None, reason: str = ""
    ) -> ResponseAction:
        """Withdraw a request that is no longer wanted."""
        action_id = validate_action_id(action_id)
        actor = validate_actor(actor or self.default_actor, "requested_by")
        with self.store() as store:
            action = self._load(store, action_id)
            action.transition(ActionStatus.CANCELLED)
            action.error = validate_reason(reason) or "cancelled by an analyst"
            store.save_action(action)
            AuditLog(store).record(AuditEvent.CANCELLED, action, error=action.error)
            return action

    # -- execution ---------------------------------------------------------
    def execute(self, action_id: str, executed_by: str | None = None) -> ResponseAction:
        """Carry out an approved action, verify it, and audit the result.

        Raises:
            ApprovalRequired: The action has not been approved by a human.
            PrivilegeRequired: The action is approved but this process cannot
                perform it; the approval stands and the operator is told what
                to re-run.
        """
        action_id = validate_action_id(action_id)
        with self.store() as store:
            action = self._load(store, action_id)
            audit = AuditLog(store)

            if action.dry_run:
                raise ResponseError(
                    f"{action_id} is a dry run: it records what would happen and can "
                    "never be executed. Request the action again without --dry-run."
                )
            if action.status != ActionStatus.APPROVED:
                if action.status in (ActionStatus.REQUESTED, ActionStatus.AWAITING_APPROVAL):
                    raise ApprovalRequired(
                        f"{action_id} has not been approved. A human must approve it "
                        f"first: sentinelforge response approve {action_id}"
                    )
                raise ResponseError(f"{action_id} is {action.status} and cannot be executed")

            handler = self.handler(action.action_type)

            # Re-validate against the system as it is *now*, not as it was when
            # the request was made.
            try:
                normalized, detail = handler.validate(action.target)
            except ValidationError as exc:
                return self._fail(
                    store, audit, action, f"the target is no longer valid: {exc}"
                )
            if normalized != action.target:  # pragma: no cover - defensive
                return self._fail(store, audit, action, "the target changed during approval")
            if self._target_changed(action, detail):
                return self._fail(
                    store,
                    audit,
                    action,
                    "the target changed between approval and execution (the process was "
                    "replaced by a different one with the same PID); request the action "
                    "again against the current target",
                )
            action.target_detail = {**action.target_detail, **detail}

            with self.store() as history_store:
                existing = [
                    other
                    for other in history_store.list_actions(
                        target=action.target, limit=POLICY_HISTORY_LIMIT
                    )
                    if other.action_id != action.action_id
                ]
            decision = self.policy.evaluate(
                action.action_type,
                action.target,
                target_detail=action.target_detail,
                existing_actions=existing,
                override_protected=bool(action.target_detail.get("protected_override")),
                backend_status=handler.backend_status(),
            )
            action.policy_decision = decision.to_dict()
            if not decision.allowed:
                return self._fail(
                    store, audit, action, f"policy refused execution: {decision.reason}"
                )

            if handler.requires_privilege_here():
                message = (
                    f"{handler.label} requires administrative privileges, and this "
                    "SentinelForge process does not have them. The approval stands: "
                    f"re-run the execute step with the necessary privileges, for example "
                    f"'sudo sentinelforge response execute {action_id}'. SentinelForge "
                    "never invokes sudo itself and never asks for a password."
                )
                audit.record(AuditEvent.FAILED, action, error=message)
                raise PrivilegeRequired(message, action)
            if not self.execution_enabled:
                message = (
                    "response execution is disabled in this SentinelForge process. "
                    f"Approve and execute {action_id} from the command line instead."
                )
                audit.record(AuditEvent.FAILED, action, error=message)
                raise PrivilegeRequired(message, action)

            action.transition(ActionStatus.EXECUTING)
            action.started_at = utc_now()
            if executed_by:
                action.approved_by = validate_actor(executed_by, "approved_by")
            store.save_action(action)
            audit.record(AuditEvent.EXECUTION_STARTED, action)

            try:
                outcome = handler.execute(action)
            except ValidationError as exc:
                return self._fail(store, audit, action, str(exc), transitioned=True)
            except Exception as exc:  # pragma: no cover - defensive
                LOGGER.exception("response action %s raised", action_id)
                return self._fail(
                    store, audit, action, f"the action raised an unexpected error: {exc}",
                    transitioned=True,
                )

            verified, verification = (False, "the action reported failure, so nothing "
                                             "was verified")
            if outcome.ok:
                verified, verification = handler.verify(action, outcome)

            action.result = outcome.to_dict()
            action.verified = verified
            action.verification = verification
            action.completed_at = utc_now()
            action.rollback_data = outcome.rollback_data or action.rollback_data
            action.rollback_available = bool(handler.reversible and action.rollback_data)
            if action.ttl_seconds and verified:
                action.expires_at = _expiry(action.completed_at, action.ttl_seconds)

            if outcome.ok and verified:
                action.transition(ActionStatus.COMPLETED)
                action.error = None
                store.save_action(action)
                audit.record(AuditEvent.EXECUTED, action)
            else:
                action.transition(ActionStatus.FAILED)
                action.error = outcome.error or verification
                store.save_action(action)
                audit.record(AuditEvent.FAILED, action, error=action.error)
            return action

    # -- rollback ----------------------------------------------------------
    def rollback(
        self, action_id: str, actor: str | None = None, reason: str = ""
    ) -> ResponseAction:
        """Undo a completed, reversible action.

        Raises:
            ResponseError: The action is not completed, or its type cannot be
                undone.  A terminated process is never described as
                recoverable.
        """
        action_id = validate_action_id(action_id)
        actor = validate_actor(actor or self.default_actor, "approved_by")
        with self.store() as store:
            action = self._load(store, action_id)
            audit = AuditLog(store)
            if action.status != ActionStatus.COMPLETED:
                raise ResponseError(
                    f"{action_id} is {action.status}; only a completed action can be "
                    "rolled back"
                )
            handler = self.handler(action.action_type)
            if not handler.reversible or not action.rollback_available:
                raise ResponseError(
                    f"{action.action_type} cannot be undone "
                    f"({handler.label} is not reversible)"
                )
            if handler.requires_privilege_here():
                message = (
                    f"undoing {action_id} requires administrative privileges. Re-run "
                    f"'sudo sentinelforge response rollback {action_id}'."
                )
                audit.record(AuditEvent.ROLLBACK_FAILED, action, error=message)
                raise PrivilegeRequired(message, action)

            outcome = handler.rollback(action)
            if not outcome.ok:
                action.error = outcome.error or "rollback failed"
                store.save_action(action)
                audit.record(
                    AuditEvent.ROLLBACK_FAILED, action, error=action.error,
                    result=outcome.to_dict(),
                )
                raise ResponseError(f"rollback of {action_id} failed: {action.error}")

            action.transition(ActionStatus.ROLLED_BACK)
            action.rolled_back_at = utc_now()
            action.approved_by = actor
            action.verification = outcome.detail
            action.error = None
            if reason:
                action.reason = validate_reason(f"{action.reason} | rollback: {reason}")
            store.save_action(action)
            audit.record(AuditEvent.ROLLED_BACK, action, result=outcome.to_dict())
            return action

    # -- TTL reconciliation ------------------------------------------------
    def reconcile_expired(self) -> list[ResponseAction]:
        """Notice blocks whose TTL has lapsed, by *reading* the firewall.

        SentinelForge does not run a timer that edits firewall state: the TTL
        is firewalld's own, and firewalld removes the rule.  This method only
        observes that it happened and closes the action, so the dashboard and
        the CLI stop reporting a containment that is no longer in force.

        Rules that are still installed are left exactly as they are.
        """
        changed: list[ResponseAction] = []
        now = parse_timestamp(utc_now())
        with self.store() as store:
            candidates = [
                action
                for action in store.list_actions(status=ActionStatus.COMPLETED)
                if action.action_type == ActionType.BLOCK_IP
                and action.expires_at
                and not action.dry_run
            ]
            audit = AuditLog(store)
            for action in candidates:
                expiry = parse_timestamp(action.expires_at)
                if expiry is None or now is None or expiry > now:
                    continue
                rule = (action.rollback_data or {}).get("rich_rule")
                zone = (action.rollback_data or {}).get("zone")
                if not rule:
                    continue
                if self.backends.firewall.get_rule_state(rule, zone) is not False:
                    continue  # still installed, or unknown: leave it alone
                action.transition(ActionStatus.ROLLED_BACK)
                action.rolled_back_at = utc_now()
                action.verification = (
                    "the TTL lapsed and the firewall removed the rule; containment has ended"
                )
                store.save_action(action)
                audit.record(
                    AuditEvent.ROLLED_BACK,
                    action,
                    result={"expired": True, "ttl_seconds": action.ttl_seconds},
                )
                changed.append(action)
        return changed

    # -- reads -------------------------------------------------------------
    def get_action(self, action_id: str) -> ResponseAction | None:
        with self.store() as store:
            return store.get_action(validate_action_id(action_id))

    def list_actions(self, **kwargs) -> list[ResponseAction]:
        with self.store() as store:
            return store.list_actions(**kwargs)

    def incident_actions(self, incident_id: str) -> list[ResponseAction]:
        """Every action recorded against one incident, newest first."""
        incident_id = validate_incident_id(incident_id, allow_none=False)
        with self.store() as store:
            return store.list_actions(incident_id=incident_id)

    def audit_records(
        self, action_id: str | None = None, incident_id: str | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        with self.store() as store:
            return store.list_audit(action_id=action_id, incident_id=incident_id, limit=limit)

    def verify_audit(self) -> dict:
        with self.store() as store:
            return store.verify_audit_chain()

    def contained_targets(self) -> dict[str, str]:
        """``target -> action_id`` for everything currently contained by us."""
        with self.store() as store:
            return {
                action.target: action.action_id
                for action in store.list_actions(status=ActionStatus.COMPLETED)
                if action.contains_target
            }

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _load(store: ResponseStore, action_id: str) -> ResponseAction:
        action = store.get_action(action_id)
        if action is None:
            raise ResponseError(f"no such response action: {action_id}")
        return action

    @staticmethod
    def _target_changed(action: ResponseAction, detail: dict) -> bool:
        """Whether the thing being targeted is still the thing that was approved.

        Only process identity is checked here, because it is the only target
        that can silently become a *different* thing under the same name: the
        kernel recycles PIDs.
        """
        if action.action_type != ActionType.KILL_PROCESS:
            return False
        approved = (action.target_detail or {}).get("start_ticks")
        current = detail.get("start_ticks")
        return approved is not None and current is not None and approved != current

    def _fail(
        self,
        store: ResponseStore,
        audit: AuditLog,
        action: ResponseAction,
        message: str,
        transitioned: bool = False,
    ) -> ResponseAction:
        """Record a failure honestly and return the action."""
        if not transitioned:
            action.transition(ActionStatus.EXECUTING)
            action.started_at = action.started_at or utc_now()
        action.transition(ActionStatus.FAILED)
        action.error = message
        action.verified = False
        action.completed_at = utc_now()
        store.save_action(action)
        audit.record(AuditEvent.FAILED, action, error=message)
        return action


def _expiry(completed_at: str | None, ttl_seconds: int) -> str | None:
    from datetime import timedelta

    moment = parse_timestamp(completed_at)
    if moment is None:  # pragma: no cover - completed_at is always set by now
        return None
    return format_timestamp(moment + timedelta(seconds=int(ttl_seconds)))
