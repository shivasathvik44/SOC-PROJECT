"""Response action model (Phase 7).

A :class:`ResponseAction` is the record of *one* containment decision: what an
analyst asked for, what the policy engine said about it, who approved it, what
the executor did, and whether it can be undone.  It is a record, not a
behaviour -- nothing in this module touches the firewall, a process, or a
shell.

Two rules shaped this dataclass:

1. **The target is structured data, never a command.**  ``target`` holds an IP
   address, a PID, or a session id -- a value that has already been through
   :mod:`sentinelforge.response.validators`.  There is no field anywhere in
   SentinelForge that carries a command line to be executed, because there is
   no code path that would execute one.
2. **No secrets.**  An action is written to a database and shown in a web page,
   so it carries no password, no token, and no API key.  ``requested_by`` and
   ``approved_by`` are operator labels, not credentials: they say who claims to
   have acted, and the audit trail keeps them for review.  On a single-user
   Fedora workstation that is exactly as much identity as there is to record --
   see the README's "Known limitations".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from ..models.event import utc_now

#: Action ids look like ``ACTION-00001``.
ACTION_ID_TEMPLATE = "ACTION-{:05d}"

#: Audit ids look like ``AUDIT-000001``.
AUDIT_ID_TEMPLATE = "AUDIT-{:06d}"


def format_action_id(number: int) -> str:
    """Format a sequential action number as ``ACTION-00001``."""
    return ACTION_ID_TEMPLATE.format(int(number))


def format_audit_id(number: int) -> str:
    """Format a sequential audit number as ``AUDIT-000001``."""
    return AUDIT_ID_TEMPLATE.format(int(number))


class ActionType:
    """The containment actions SentinelForge knows about.

    This tuple is the *whole* vocabulary: an action type that is not listed
    here is rejected at the edge (CLI argument choices, API validation), which
    is why neither interface needs to guess what a caller meant.
    """

    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    KILL_PROCESS = "kill_process"
    TERMINATE_SESSION = "terminate_session"
    ISOLATE_HOST = "isolate_host"

    ALL = (BLOCK_IP, UNBLOCK_IP, KILL_PROCESS, TERMINATE_SESSION, ISOLATE_HOST)

    @staticmethod
    def is_valid(action_type: str) -> bool:
        return action_type in ActionType.ALL


class ActionStatus:
    """Lifecycle of one response action.

    The only transitions the engine performs are listed in
    :data:`TRANSITIONS`.  Everything else -- most importantly
    ``awaiting_approval -> executing`` -- is refused, which is how "no
    execution without approval" becomes a property of the state machine rather
    than a comment in a handler.
    """

    REQUESTED = "requested"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"
    DRY_RUN = "dry_run"

    ALL = (
        REQUESTED,
        AWAITING_APPROVAL,
        APPROVED,
        REJECTED,
        EXECUTING,
        COMPLETED,
        FAILED,
        ROLLED_BACK,
        CANCELLED,
        DRY_RUN,
    )

    #: Statuses that still describe an in-flight request.
    PENDING = (REQUESTED, AWAITING_APPROVAL, APPROVED)
    #: Statuses where the action changed, or tried to change, the system.
    TERMINAL = (COMPLETED, FAILED, ROLLED_BACK, REJECTED, CANCELLED, DRY_RUN)
    #: Statuses that mean "this action is currently in force".
    CONTAINING = (COMPLETED,)

    @staticmethod
    def is_valid(status: str) -> bool:
        return status in ActionStatus.ALL


#: The complete set of legal status changes.  ``execute`` can only run from
#: ``approved``; there is deliberately no edge from ``awaiting_approval``.
TRANSITIONS: dict[str, tuple[str, ...]] = {
    ActionStatus.REQUESTED: (
        ActionStatus.AWAITING_APPROVAL,
        ActionStatus.REJECTED,
        ActionStatus.CANCELLED,
        ActionStatus.DRY_RUN,
    ),
    ActionStatus.AWAITING_APPROVAL: (
        ActionStatus.APPROVED,
        ActionStatus.REJECTED,
        ActionStatus.CANCELLED,
    ),
    ActionStatus.APPROVED: (
        ActionStatus.EXECUTING,
        ActionStatus.CANCELLED,
        ActionStatus.REJECTED,
    ),
    ActionStatus.EXECUTING: (ActionStatus.COMPLETED, ActionStatus.FAILED),
    ActionStatus.COMPLETED: (ActionStatus.ROLLED_BACK,),
    ActionStatus.FAILED: (),
    ActionStatus.REJECTED: (),
    ActionStatus.CANCELLED: (),
    ActionStatus.ROLLED_BACK: (),
    ActionStatus.DRY_RUN: (),
}


#: Action types whose effect *persists* after they complete, so the target
#: stays contained until someone undoes it.  A terminated process or session is
#: not in this set: it is over, not held -- which matters because policy refuses
#: a second action against an already-contained target, and a PID the kernel
#: later recycles onto a new process must remain a legal target.
ONGOING_CONTAINMENT_ACTIONS = frozenset({ActionType.BLOCK_IP})


def can_transition(current: str, target: str) -> bool:
    """Whether ``current -> target`` is a legal status change."""
    return target in TRANSITIONS.get(current, ())


#: JSON key order for a serialized action.
FIELD_ORDER = (
    "action_id",
    "incident_id",
    "action_type",
    "target",
    "target_detail",
    "status",
    "dry_run",
    "reason",
    "requested_by",
    "approved_by",
    "requested_at",
    "approved_at",
    "started_at",
    "completed_at",
    "ttl_seconds",
    "expires_at",
    "policy_decision",
    "result",
    "error",
    "verified",
    "verification",
    "rollback_available",
    "rollback_data",
    "rolled_back_at",
    "audit_id",
)


@dataclass
class ResponseAction:
    """One requested containment action and everything that happened to it.

    Attributes:
        action_id: Sequential id, e.g. ``ACTION-00001``.
        incident_id: The incident this action belongs to, or ``None`` for an
            action taken outside an investigation (the CLI allows that; the
            dashboard always supplies one).
        action_type: One of :class:`ActionType`.
        target: The validated target -- an IPv4/IPv6 address, a PID as a
            string, or a session id.  Never a command.
        target_detail: Read-only metadata collected *before* the action, so the
            audit trail records what was actually targeted (the process name and
            command line, the firewall zone, the session's user).  Command lines
            in here are data for a human to read; they are never executed.
        status: One of :class:`ActionStatus`.
        dry_run: Whether this action is a simulation.  A dry run never reaches
            an executor.
        reason: Why the analyst asked for this.  Free text from the operator.
        requested_by / approved_by: Operator labels (see the module docstring).
        ttl_seconds: Optional containment lifetime for reversible actions.
        expires_at: When a TTL-limited containment is due to lapse.
        policy_decision: The serialized :class:`~sentinelforge.response.policy.PolicyDecision`
            that allowed (or refused) this action.
        result: Structured outcome from the backend.  Plain JSON-safe data.
        verified: Whether post-execution verification confirmed the expected
            state.  ``None`` before execution.  An action is only ``completed``
            when this is true -- a zero exit code is not success.
        rollback_available: Whether this specific action can be undone.
        rollback_data: What the rollback needs (the exact rule SentinelForge
            created).  Never a command string.
        audit_id: The first audit record written for this action.
    """

    action_id: str
    action_type: str
    target: str
    incident_id: str | None = None
    status: str = ActionStatus.REQUESTED
    dry_run: bool = False
    reason: str = ""
    requested_by: str = "unknown"
    approved_by: str | None = None
    requested_at: str | None = None
    approved_at: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    ttl_seconds: int | None = None
    expires_at: str | None = None
    target_detail: dict = field(default_factory=dict)
    policy_decision: dict | None = None
    result: dict | None = None
    error: str | None = None
    verified: bool | None = None
    verification: str | None = None
    rollback_available: bool = False
    rollback_data: dict | None = None
    rolled_back_at: str | None = None
    audit_id: str | None = None

    def __post_init__(self) -> None:
        if not ActionStatus.is_valid(self.status):
            self.status = ActionStatus.REQUESTED
        if self.requested_at is None:
            self.requested_at = utc_now()

    # -- state machine -----------------------------------------------------
    def can_transition_to(self, status: str) -> bool:
        return can_transition(self.status, status)

    def transition(self, status: str) -> None:
        """Move to ``status``.  Raises :class:`InvalidTransition` if illegal."""
        if not ActionStatus.is_valid(status):
            raise InvalidTransition(f"unknown action status {status!r}")
        if not self.can_transition_to(status):
            raise InvalidTransition(
                f"{self.action_id}: cannot go from {self.status!r} to {status!r}"
            )
        self.status = status

    @property
    def is_pending(self) -> bool:
        return self.status in ActionStatus.PENDING

    @property
    def is_terminal(self) -> bool:
        return self.status in ActionStatus.TERMINAL

    @property
    def contains_target(self) -> bool:
        """Whether this action is *currently* holding its target contained.

        True only for containment that persists -- an installed firewall block.
        A completed ``kill_process`` is finished, not ongoing, so it never
        blocks a later request against the same PID.
        """
        return (
            self.status in ActionStatus.CONTAINING
            and not self.dry_run
            and self.action_type in ONGOING_CONTAINMENT_ACTIONS
        )

    # -- serialization -----------------------------------------------------
    def to_dict(self) -> dict:
        data = {
            "action_id": self.action_id,
            "incident_id": self.incident_id,
            "action_type": self.action_type,
            "target": self.target,
            "target_detail": dict(self.target_detail),
            "status": self.status,
            "dry_run": bool(self.dry_run),
            "reason": self.reason,
            "requested_by": self.requested_by,
            "approved_by": self.approved_by,
            "requested_at": self.requested_at,
            "approved_at": self.approved_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "ttl_seconds": self.ttl_seconds,
            "expires_at": self.expires_at,
            "policy_decision": self.policy_decision,
            "result": self.result,
            "error": self.error,
            "verified": self.verified,
            "verification": self.verification,
            "rollback_available": bool(self.rollback_available),
            "rollback_data": self.rollback_data,
            "rolled_back_at": self.rolled_back_at,
            "audit_id": self.audit_id,
        }
        return {key: data[key] for key in FIELD_ORDER}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def from_dict(cls, data: dict) -> "ResponseAction":
        return cls(
            action_id=data.get("action_id", ""),
            action_type=data.get("action_type", ""),
            target=data.get("target", ""),
            incident_id=data.get("incident_id"),
            status=data.get("status", ActionStatus.REQUESTED),
            dry_run=bool(data.get("dry_run", False)),
            reason=data.get("reason") or "",
            requested_by=data.get("requested_by") or "unknown",
            approved_by=data.get("approved_by"),
            requested_at=data.get("requested_at"),
            approved_at=data.get("approved_at"),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            ttl_seconds=data.get("ttl_seconds"),
            expires_at=data.get("expires_at"),
            target_detail=dict(data.get("target_detail") or {}),
            policy_decision=data.get("policy_decision") or None,
            result=data.get("result") or None,
            error=data.get("error"),
            verified=data.get("verified"),
            verification=data.get("verification"),
            rollback_available=bool(data.get("rollback_available", False)),
            rollback_data=data.get("rollback_data") or None,
            rolled_back_at=data.get("rolled_back_at"),
            audit_id=data.get("audit_id"),
        )

    def summary_line(self) -> str:
        """One-line description used by ``sentinelforge response list``."""
        incident = self.incident_id or "-"
        mode = "DRY-RUN" if self.dry_run else "REAL"
        return (
            f"{self.action_id:13}{self.action_type:19}{self.target:25.24}"
            f"{self.status:19}{mode:9}{incident:13}{self.requested_at or '-'}"
        )


class InvalidTransition(RuntimeError):
    """An action was asked to make an illegal status change.

    Raised, for example, when something tries to execute an action that has not
    been approved.  This is the last line of the approval guarantee: even a bug
    in a caller cannot skip the approval step without hitting this.
    """


@dataclass(frozen=True)
class ActionPreview:
    """What an action *would* do, rendered for a human before they approve it.

    A preview never touches the system beyond reading it: it resolves the
    target (does this PID exist? which firewall is running?) and describes the
    consequence.  Everything an analyst needs in order to consent is here.
    """

    action_type: str
    target: str
    description: str
    effect: str
    backend: str
    available: bool = True
    reversible: bool = False
    requires_privilege: bool = False
    privilege_hint: str | None = None
    ttl_seconds: int | None = None
    target_detail: dict = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    unavailable_reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "description": self.description,
            "effect": self.effect,
            "backend": self.backend,
            "available": self.available,
            "reversible": self.reversible,
            "requires_privilege": self.requires_privilege,
            "privilege_hint": self.privilege_hint,
            "ttl_seconds": self.ttl_seconds,
            "target_detail": dict(self.target_detail),
            "warnings": list(self.warnings),
            "unavailable_reason": self.unavailable_reason,
        }


@dataclass(frozen=True)
class ActionOutcome:
    """The result of asking a backend to do something.

    ``ok`` is set by *verification*, not by an exit code: see
    :meth:`sentinelforge.response.actions.ResponseActionHandler.verify`.
    """

    ok: bool
    detail: str
    data: dict = field(default_factory=dict)
    error: str | None = None
    rollback_data: dict | None = None

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "detail": self.detail,
            "data": dict(self.data),
            "error": self.error,
        }
