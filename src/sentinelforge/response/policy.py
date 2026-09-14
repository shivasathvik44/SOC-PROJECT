"""The response policy engine (Phase 7).

Validation asks "is this a usable target?".  Policy asks the harder question:
"is this something SentinelForge is willing to do?"  The two are separate
because ``0.0.0.0`` is a perfectly well-formed IP address and PID 1 is a
perfectly real process -- they are refused for what they *mean*, not for how
they are written.

The defaults, which no code path in this package changes on its own:

====================  =======
Human approval        required
Automatic execution   never
Dry-run               always available
Audit logging         always on
====================  =======

Two categories of refusal live here, and the difference matters:

* **Never allowed.**  Blocking the address the analyst is connected from,
  blocking the default gateway, killing PID 1 or a kernel thread.  These are
  refusals a flag cannot lift, because "the operator asked twice" is not a
  reason to disconnect a host from its own network mid-incident.
* **Protected, overridable.**  Terminating SentinelForge's own processes, or a
  well-known system daemon, is refused *by default* but can be allowed by an
  analyst who explicitly says so (``--override-protected`` on the CLI, an
  explicit field in the API).  The override is recorded on the action and in
  the audit trail; it is a documented decision, not a silent one.

Rate limiting lives here too: it is policy, not plumbing.  An address that is
already contained by one of our own rules does not get a second rule, and an
action repeated inside the cooldown window is refused with the id of the
action that already covers it.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from ..models.event import parse_timestamp, utc_now
from .models import ActionStatus, ActionType
from .validators import ValidationError, classify_ip, validate_pid, validate_session_id

#: Refusal codes.  Stable strings so an API client can branch on them without
#: parsing prose.
DENY_UNKNOWN_ACTION = "unknown_action_type"
DENY_ACTION_DISABLED = "action_disabled"
DENY_UNSAFE_TARGET = "unsafe_target"
DENY_PROTECTED_TARGET = "protected_target"
DENY_ALREADY_CONTAINED = "already_contained"
DENY_COOLDOWN = "cooldown"
DENY_RATE_LIMIT = "rate_limit"
DENY_DUPLICATE_PENDING = "duplicate_pending"
DENY_BACKEND_UNAVAILABLE = "backend_unavailable"
DENY_NOT_IMPLEMENTED = "not_implemented"
ALLOW = "allowed"

#: Processes SentinelForge refuses to terminate unless explicitly overridden.
#: Killing any of these breaks either the host's ability to be administered or
#: the analyst's ability to keep investigating.
PROTECTED_PROCESS_NAMES = frozenset(
    {
        "systemd",
        "systemd-journald",
        "systemd-logind",
        "systemd-udevd",
        "systemd-resolved",
        "init",
        "dbus-daemon",
        "dbus-broker",
        "polkitd",
        "firewalld",
        "NetworkManager",
        "sshd",
        "auditd",
        "sentinelforge",
    }
)

#: Actions that can be undone by a later action of the matching type.
REVERSIBLE_ACTIONS = frozenset({ActionType.BLOCK_IP})

#: Actions that need root to change anything.
PRIVILEGED_ACTIONS = frozenset(
    {ActionType.BLOCK_IP, ActionType.UNBLOCK_IP, ActionType.TERMINATE_SESSION,
     ActionType.ISOLATE_HOST}
)


@dataclass(frozen=True)
class PolicyDecision:
    """What the policy engine concluded about one request.

    Attributes:
        allowed: Whether the request may proceed to (human) approval.
        code: One of the stable ``DENY_*`` codes, or :data:`ALLOW`.
        reason: One line an analyst can act on.
        approval_required: Always ``True`` for a real action.  Present as a
            field rather than assumed so that the audit record states it.
        reversible: Whether a rollback exists for this action type.
        requires_privilege: Whether executing it needs root.
        warnings: Things the analyst should read before approving.
        overridable: Whether an explicit operator override could lift this
            refusal.  ``False`` for the refusals that no flag can lift.
        related_action_id: The action already covering this target, when the
            refusal was a duplicate or a cooldown.
    """

    allowed: bool
    code: str = ALLOW
    reason: str = ""
    approval_required: bool = True
    reversible: bool = False
    requires_privilege: bool = False
    warnings: tuple[str, ...] = ()
    overridable: bool = False
    related_action_id: str | None = None
    evaluated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "code": self.code,
            "reason": self.reason,
            "approval_required": self.approval_required,
            "reversible": self.reversible,
            "requires_privilege": self.requires_privilege,
            "warnings": list(self.warnings),
            "overridable": self.overridable,
            "related_action_id": self.related_action_id,
            "evaluated_at": self.evaluated_at,
        }

    def with_warning(self, warning: str) -> "PolicyDecision":
        return replace(self, warnings=(*self.warnings, warning))


@dataclass(frozen=True)
class PolicyConfig:
    """Tunable parts of the policy.  The safety-critical parts are not here.

    ``approval_required`` and ``allow_automatic_execution`` are deliberately
    absent as knobs: there is no supported configuration in which SentinelForge
    executes a containment action without a human approving it.

    Attributes:
        cooldown_seconds: How long after a request for the same target the next
            identical request is refused.
        max_actions_per_target: Most actions ever recorded against one target
            before further requests are refused as a likely loop.
        max_pending_per_target: Most simultaneously un-executed requests for
            one target.
        allow_multicast_targets: Off by default; multicast is infrastructure,
            not an attacker.
        allow_host_isolation: Off, and see :class:`HostIsolationAction` -- this
            phase ships the interface, not the capability.
        protected_process_names: Names refused unless overridden.
        require_reason: Whether a written justification is mandatory.
    """

    cooldown_seconds: int = 60
    max_actions_per_target: int = 10
    max_pending_per_target: int = 3
    allow_multicast_targets: bool = False
    allow_host_isolation: bool = False
    protected_process_names: frozenset[str] = PROTECTED_PROCESS_NAMES
    require_reason: bool = False
    default_block_ttl: int | None = 900


class ResponsePolicy:
    """Decides whether a requested action may proceed.

    The engine calls :meth:`evaluate` before an action is even recorded as
    awaiting approval, and again -- through the engine's own checks -- before
    execution, so an action that became unsafe while it sat in the queue (the
    target PID was recycled, the address became this host's own) does not slip
    through on a stale decision.
    """

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()

    # -- entry point -------------------------------------------------------
    def evaluate(
        self,
        action_type: str,
        target: str,
        target_detail: dict | None = None,
        existing_actions: list | None = None,
        override_protected: bool = False,
        backend_status=None,
    ) -> PolicyDecision:
        """Judge one request.

        Args:
            action_type: One of :class:`~sentinelforge.response.models.ActionType`.
            target: The already-validated target.
            target_detail: Facts gathered by the backend (process metadata,
                address classification, session properties).
            existing_actions: Actions already recorded for this target, newest
                first.  Used for duplicate, cooldown and rate-limit checks.
            override_protected: The analyst explicitly accepted the risk of a
                protected target.  Only lifts *overridable* refusals.
            backend_status: The relevant :class:`BackendStatus`, when known.
        """
        if not ActionType.is_valid(action_type):
            return PolicyDecision(
                allowed=False,
                code=DENY_UNKNOWN_ACTION,
                reason=f"unknown action type {action_type!r}",
            )

        base = PolicyDecision(
            allowed=True,
            reason="allowed, pending human approval",
            approval_required=True,
            reversible=action_type in REVERSIBLE_ACTIONS,
            requires_privilege=action_type in PRIVILEGED_ACTIONS,
        )

        if action_type == ActionType.ISOLATE_HOST:
            # Checked before backend availability so the refusal says what it
            # really is -- not implemented -- rather than blaming the firewall.
            return self._check_host_isolation(base, target, target_detail or {}, override_protected)

        if backend_status is not None and not getattr(backend_status, "available", False):
            return PolicyDecision(
                allowed=False,
                code=DENY_BACKEND_UNAVAILABLE,
                reason=getattr(backend_status, "reason", None)
                or f"no backend is available for {action_type}",
                reversible=base.reversible,
                requires_privilege=base.requires_privilege,
            )

        checker = {
            ActionType.BLOCK_IP: self._check_ip_target,
            ActionType.UNBLOCK_IP: self._check_unblock_target,
            ActionType.KILL_PROCESS: self._check_process_target,
            ActionType.TERMINATE_SESSION: self._check_session_target,
            ActionType.ISOLATE_HOST: self._check_host_isolation,
        }[action_type]
        decision = checker(base, target, target_detail or {}, override_protected)
        if not decision.allowed:
            return decision

        return self._check_rate_limits(decision, action_type, target, existing_actions or [])

    # -- per-action checks -------------------------------------------------
    def _check_ip_target(
        self, base: PolicyDecision, target: str, detail: dict, override: bool
    ) -> PolicyDecision:
        """Refuse addresses that are infrastructure rather than an adversary."""
        try:
            facts = classify_ip(target)
        except ValidationError as exc:
            return PolicyDecision(allowed=False, code=DENY_UNSAFE_TARGET, reason=str(exc))

        never = [
            (
                "is_unspecified",
                "0.0.0.0 and :: mean 'every address': blocking them would cut this "
                "host off from all network traffic",
            ),
            (
                "is_loopback",
                "loopback traffic is this host talking to itself; blocking it breaks "
                "local services, including this dashboard",
            ),
            (
                "is_broadcast",
                "255.255.255.255 is the local broadcast address, not an attacker",
            ),
            (
                "is_local_host_address",
                "this address belongs to this host: blocking it would disconnect the "
                "machine you are defending",
            ),
            (
                "is_default_gateway",
                "this address is this host's default gateway: blocking it would cut "
                "off all routed traffic, including your own access",
            ),
        ]
        for key, reason in never:
            if facts.get(key):
                return PolicyDecision(
                    allowed=False,
                    code=DENY_UNSAFE_TARGET,
                    reason=f"refusing to block {facts['address']}: {reason}",
                    reversible=base.reversible,
                    requires_privilege=base.requires_privilege,
                    overridable=False,
                )

        if facts.get("is_multicast") and not self.config.allow_multicast_targets:
            return PolicyDecision(
                allowed=False,
                code=DENY_UNSAFE_TARGET,
                reason=f"refusing to block {facts['address']}: multicast addresses "
                "carry service discovery and routing traffic, not a single attacker",
                reversible=base.reversible,
                requires_privilege=base.requires_privilege,
                overridable=False,
            )

        decision = base
        if facts.get("is_link_local"):
            decision = decision.with_warning(
                "this is a link-local address: it is only meaningful on the local "
                "segment and may be reassigned to a different device"
            )
        if facts.get("is_reserved"):
            decision = decision.with_warning(
                "this address is in a reserved range; confirm it is really the source "
                "of the activity before containing it"
            )
        if facts.get("is_private"):
            decision = decision.with_warning(
                "this is an internal address: blocking it will affect a device on your "
                "own network, not an anonymous outsider"
            )
        return decision

    def _check_unblock_target(
        self, base: PolicyDecision, target: str, detail: dict, override: bool
    ) -> PolicyDecision:
        """Removing a block is always safe; it only has to be a real address."""
        try:
            classify_ip(target)
        except ValidationError as exc:
            return PolicyDecision(allowed=False, code=DENY_UNSAFE_TARGET, reason=str(exc))
        return replace(
            base,
            reversible=False,
            reason="allowed, pending human approval (removes a SentinelForge block)",
        )

    def _check_process_target(
        self, base: PolicyDecision, target: str, detail: dict, override: bool
    ) -> PolicyDecision:
        """Refuse the processes that hold the system, or the investigation, up."""
        try:
            pid = validate_pid(target)
        except ValidationError as exc:
            return PolicyDecision(allowed=False, code=DENY_UNSAFE_TARGET, reason=str(exc))

        import os

        never = {
            1: "PID 1 is the init system: terminating it halts the host",
            os.getpid(): "that is the SentinelForge process handling this request",
        }
        parent = os.getppid()
        if parent > 1:
            never.setdefault(parent, "that is the parent of the SentinelForge process "
                                     "handling this request")
        if pid in never:
            return PolicyDecision(
                allowed=False,
                code=DENY_UNSAFE_TARGET,
                reason=f"refusing to terminate pid {pid}: {never[pid]}",
                requires_privilege=base.requires_privilege,
                overridable=False,
            )
        if detail.get("kernel_thread"):
            return PolicyDecision(
                allowed=False,
                code=DENY_UNSAFE_TARGET,
                reason=f"refusing to terminate pid {pid}: it is a kernel thread, not a "
                "user-space process",
                overridable=False,
            )

        name = (detail.get("name") or "").strip()
        command_line = detail.get("command_line") or ""
        protected_reason = None
        if name in self.config.protected_process_names:
            protected_reason = f"{name} is a critical system process"
        elif "sentinelforge" in command_line.lower() or "sentinelforge" in name.lower():
            protected_reason = "it is part of SentinelForge itself"

        if protected_reason:
            if not override:
                return PolicyDecision(
                    allowed=False,
                    code=DENY_PROTECTED_TARGET,
                    reason=f"refusing to terminate pid {pid}: {protected_reason}. If this "
                    "is genuinely what you intend, re-request the action with the "
                    "protected-target override and say why.",
                    requires_privilege=base.requires_privilege,
                    overridable=True,
                )
            base = base.with_warning(
                f"PROTECTED TARGET OVERRIDE: pid {pid} is protected because "
                f"{protected_reason}. The override was recorded on this action."
            )

        decision = base
        if detail.get("uid") == 0:
            decision = decision.with_warning(
                "this process runs as root; terminating it may affect system services"
            )
        return decision

    def _check_session_target(
        self, base: PolicyDecision, target: str, detail: dict, override: bool
    ) -> PolicyDecision:
        """Refuse the analyst's own session and logind's own machinery."""
        try:
            session_id = validate_session_id(target)
        except ValidationError as exc:
            return PolicyDecision(allowed=False, code=DENY_UNSAFE_TARGET, reason=str(exc))
        if detail.get("is_own_session"):
            return PolicyDecision(
                allowed=False,
                code=DENY_UNSAFE_TARGET,
                reason=f"refusing to terminate session {session_id}: it is the session "
                "this response is being run from",
                overridable=False,
            )
        if (detail.get("class") or "").lower() == "manager":
            return PolicyDecision(
                allowed=False,
                code=DENY_UNSAFE_TARGET,
                reason=f"refusing to terminate session {session_id}: it is a logind "
                "manager session, not a user login",
                overridable=False,
            )
        decision = base.with_warning(
            "ending a session cannot be undone: the user's processes in that session "
            "are terminated with it"
        )
        if detail.get("name") == "root":
            decision = decision.with_warning(
                "this is a root session; make sure another administrative path into "
                "this host is available before ending it"
            )
        return decision

    def _check_host_isolation(
        self, base: PolicyDecision, target: str, detail: dict, override: bool
    ) -> PolicyDecision:
        """Host-wide isolation is prepared, not enabled.  See the README."""
        if not self.config.allow_host_isolation:
            return PolicyDecision(
                allowed=False,
                code=DENY_NOT_IMPLEMENTED,
                reason="host isolation is planned and capability dependent: SentinelForge "
                "will not cut a host off the network until it can do so reversibly and "
                "without flushing firewall configuration it did not create",
                reversible=False,
                requires_privilege=True,
                overridable=False,
            )
        return base  # pragma: no cover - no supported configuration reaches this

    # -- rate limiting -----------------------------------------------------
    def _check_rate_limits(
        self, decision: PolicyDecision, action_type: str, target: str, existing: list
    ) -> PolicyDecision:
        """Refuse repeats: duplicates, cooldowns and runaway loops.

        This is what stops one address collecting five identical firewall
        rules because an analyst clicked twice and a browser retried once.
        """
        # Only actions that actually went somewhere count.  A request policy
        # refused, or one the analyst withdrew, never touched the system -- and
        # letting it start a cooldown would block the very next thing an
        # analyst does after a refusal, which is usually to re-request it
        # correctly (with an override, or against the right target).
        relevant = [
            action
            for action in existing
            if action.target == target
            and not action.dry_run
            and action.status not in (ActionStatus.REJECTED, ActionStatus.CANCELLED)
        ]
        same_type = [action for action in relevant if action.action_type == action_type]

        containing = [
            action
            for action in relevant
            if action.contains_target and _contains(action.action_type, action_type)
        ]
        if containing:
            first = containing[0]
            return PolicyDecision(
                allowed=False,
                code=DENY_ALREADY_CONTAINED,
                reason=f"target is already contained by {first.action_id}",
                reversible=decision.reversible,
                requires_privilege=decision.requires_privilege,
                related_action_id=first.action_id,
            )

        pending = [action for action in same_type if action.is_pending]
        if len(pending) >= self.config.max_pending_per_target:
            return PolicyDecision(
                allowed=False,
                code=DENY_DUPLICATE_PENDING,
                reason=f"{len(pending)} request(s) for this target are already waiting "
                f"for approval (see {pending[0].action_id})",
                reversible=decision.reversible,
                requires_privilege=decision.requires_privilege,
                related_action_id=pending[0].action_id,
            )

        if len(same_type) >= self.config.max_actions_per_target:
            return PolicyDecision(
                allowed=False,
                code=DENY_RATE_LIMIT,
                reason=f"{len(same_type)} {action_type} actions have already been recorded "
                f"for this target; refusing more without a human review of why they keep "
                "being needed",
                reversible=decision.reversible,
                requires_privilege=decision.requires_privilege,
            )

        recent = _most_recent(same_type)
        if recent is not None and self.config.cooldown_seconds > 0:
            age = _age_seconds(recent.requested_at)
            if age is not None and age < self.config.cooldown_seconds:
                return PolicyDecision(
                    allowed=False,
                    code=DENY_COOLDOWN,
                    reason=f"an identical action ({recent.action_id}) was requested "
                    f"{int(age)}s ago; the cooldown for this target is "
                    f"{self.config.cooldown_seconds}s",
                    reversible=decision.reversible,
                    requires_privilege=decision.requires_privilege,
                    related_action_id=recent.action_id,
                )
        return decision


def _contains(existing_type: str, requested_type: str) -> bool:
    """Whether an existing action of one type already contains a new request.

    Only same-type containment counts: a completed ``block_ip`` makes another
    ``block_ip`` redundant, but says nothing about a ``kill_process``.
    """
    return existing_type == requested_type


def _most_recent(actions: list):
    dated = [action for action in actions if action.requested_at]
    if not dated:
        return None
    return max(dated, key=lambda action: action.requested_at or "")


def _age_seconds(timestamp: str | None) -> float | None:
    moment = parse_timestamp(timestamp)
    now = parse_timestamp(utc_now())
    if moment is None or now is None:
        return None
    return (now - moment).total_seconds()
