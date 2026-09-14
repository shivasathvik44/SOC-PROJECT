"""The response audit trail (Phase 7).

Every containment decision leaves a record here: the request, the policy
verdict, the approval or refusal, the execution attempt, the verification, and
any rollback.  A record is written *before* an action runs as well as after it,
so an execution that crashes the process still leaves evidence that it was
attempted.

Three properties this module is responsible for:

**Append-only.**  There is no update and no delete.  Records chain by hash:
each one is hashed together with the hash of the record before it, so editing
or removing history invalidates everything after it.  The database enforces the
same rule with triggers (see :mod:`sentinelforge.storage.sqlite`).  This is
tamper *evidence*: anyone who can rewrite the file can also recompute the
chain, but the realistic failure -- a row quietly edited or dropped -- becomes
visible instead of silent.

**Complete.**  A refused request is audited too.  "The analyst asked to block
the CEO's laptop and policy refused" is exactly the kind of thing an
investigation needs to be able to reconstruct.

**Free of secrets.**  Nothing here ever carries a password, an API key, a token
or an authorization header, and :func:`scrub` removes anything that looks like
one from backend output before it is stored -- a defence against a future
backend that becomes chattier than expected.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field

from ..models.event import utc_now
from .models import format_audit_id

LOGGER = logging.getLogger(__name__)


class AuditEvent:
    """What kind of thing happened to an action."""

    REQUESTED = "requested"
    POLICY_DENIED = "policy_denied"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    EXECUTION_STARTED = "execution_started"
    EXECUTED = "executed"
    FAILED = "failed"
    DRY_RUN = "dry_run"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"

    ALL = (
        REQUESTED,
        POLICY_DENIED,
        APPROVED,
        REJECTED,
        CANCELLED,
        EXECUTION_STARTED,
        EXECUTED,
        FAILED,
        DRY_RUN,
        ROLLED_BACK,
        ROLLBACK_FAILED,
    )


#: Keys whose values are never written to the audit trail, whatever a backend
#: puts in a result dictionary.
SECRET_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "credential",
        "credentials",
        "private_key",
        "session_key",
        "cookie",
    }
)

#: Value written in place of anything scrubbed.
REDACTED = "[redacted]"


def scrub(value, depth: int = 0):
    """Recursively drop anything that looks like a credential.

    Belt and braces: no current backend produces a secret, and the audit trail
    should keep that true if one ever starts.
    """
    if depth > 8:  # pragma: no cover - defensive against cyclic structures
        return REDACTED
    if isinstance(value, dict):
        return {
            key: (REDACTED if str(key).lower() in SECRET_KEYS else scrub(item, depth + 1))
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [scrub(item, depth + 1) for item in value]
    return value


@dataclass
class AuditRecord:
    """One entry in the response audit trail.

    Attributes:
        event: One of :class:`AuditEvent`.
        policy_decision: The serialized policy verdict that applied.
        execution_status: The action's status at the moment this was written.
        result: Structured backend output, scrubbed.
        entry_hash / previous_hash: Filled in by the store when the record is
            appended; see :meth:`compute_hash`.
    """

    audit_id: str
    event: str
    timestamp: str = field(default_factory=utc_now)
    action_id: str | None = None
    incident_id: str | None = None
    action_type: str | None = None
    target: str | None = None
    requested_by: str | None = None
    approved_by: str | None = None
    reason: str | None = None
    policy_decision: dict | None = None
    dry_run: bool = False
    execution_status: str | None = None
    result: dict | None = None
    error: str | None = None
    rollback_available: bool = False
    previous_hash: str | None = None
    entry_hash: str | None = None

    def to_dict(self) -> dict:
        """The record as stored.  Secrets are removed on the way out."""
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "event": self.event,
            "action_id": self.action_id,
            "incident_id": self.incident_id,
            "action_type": self.action_type,
            "target": self.target,
            "requested_by": self.requested_by,
            "approved_by": self.approved_by,
            "reason": self.reason,
            "policy_decision": scrub(self.policy_decision) if self.policy_decision else None,
            "dry_run": bool(self.dry_run),
            "execution_status": self.execution_status,
            "result": scrub(self.result) if self.result else None,
            "error": self.error,
            "rollback_available": bool(self.rollback_available),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AuditRecord":
        return cls(
            audit_id=data.get("audit_id", ""),
            event=data.get("event", ""),
            timestamp=data.get("timestamp") or utc_now(),
            action_id=data.get("action_id"),
            incident_id=data.get("incident_id"),
            action_type=data.get("action_type"),
            target=data.get("target"),
            requested_by=data.get("requested_by"),
            approved_by=data.get("approved_by"),
            reason=data.get("reason"),
            policy_decision=data.get("policy_decision"),
            dry_run=bool(data.get("dry_run", False)),
            execution_status=data.get("execution_status"),
            result=data.get("result"),
            error=data.get("error"),
            rollback_available=bool(data.get("rollback_available", False)),
            previous_hash=data.get("previous_hash"),
            entry_hash=data.get("entry_hash"),
        )

    def compute_hash(self, previous_hash: str | None) -> str:
        """SHA-256 over this record plus the hash of the one before it.

        Serialization is canonical (sorted keys, no whitespace) so the same
        record always hashes the same way, on any Python version.
        """
        material = json.dumps(
            {"previous": previous_hash or "", "entry": self.to_dict()},
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def summary_line(self) -> str:
        """One line for ``sentinelforge response audit``."""
        mode = "DRY-RUN" if self.dry_run else "REAL"
        who = self.approved_by or self.requested_by or "-"
        return (
            f"{self.timestamp} {self.audit_id} {self.event:18} "
            f"{(self.action_id or '-'):14} {(self.action_type or '-'):18} "
            f"{(self.target or '-'):24.24} {mode:8} {who}"
        )


class AuditLog:
    """Writes audit records for one response engine.

    A thin wrapper over the store: it allocates ids, fills in the fields that
    always come from the action, and refuses to write an unknown event kind.
    """

    def __init__(self, store) -> None:
        self.store = store

    def record(
        self,
        event: str,
        action=None,
        error: str | None = None,
        result: dict | None = None,
        **overrides,
    ) -> AuditRecord:
        """Append one record and return it (with its chain hashes filled in)."""
        if event not in AuditEvent.ALL:
            raise ValueError(f"unknown audit event {event!r}")
        entry = AuditRecord(
            audit_id=format_audit_id(self.store.next_audit_number()),
            event=event,
            action_id=getattr(action, "action_id", None),
            incident_id=getattr(action, "incident_id", None),
            action_type=getattr(action, "action_type", None),
            target=getattr(action, "target", None),
            requested_by=getattr(action, "requested_by", None),
            approved_by=getattr(action, "approved_by", None),
            reason=getattr(action, "reason", None),
            policy_decision=getattr(action, "policy_decision", None),
            dry_run=bool(getattr(action, "dry_run", False)),
            execution_status=getattr(action, "status", None),
            result=result if result is not None else getattr(action, "result", None),
            error=error if error is not None else getattr(action, "error", None),
            rollback_available=bool(getattr(action, "rollback_available", False)),
        )
        for key, value in overrides.items():
            setattr(entry, key, value)
        entry.previous_hash = self.store.last_audit_hash()
        entry.entry_hash = self.store.append_audit(entry)
        LOGGER.info(
            "response audit: %s %s %s target=%s",
            entry.audit_id,
            entry.event,
            entry.action_id or "-",
            entry.target or "-",
        )
        return entry

    def for_action(self, action_id: str, limit: int | None = None) -> list[dict]:
        return self.store.list_audit(action_id=action_id, limit=limit)

    def verify(self) -> dict:
        return self.store.verify_audit_chain()
