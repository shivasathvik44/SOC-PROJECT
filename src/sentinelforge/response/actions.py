"""The containment actions themselves (Phase 7).

Every action follows the same five steps, and the engine drives them in that
order for all of them::

    validate()  ->  preview()  ->  execute()  ->  verify()  ->  (audit)

``validate`` turns an untrusted target into a typed value and gathers read-only
facts about it.  ``preview`` describes what would happen, in the words an
analyst needs in order to consent.  ``execute`` asks a backend to do exactly
that one thing.  ``verify`` re-reads the system and decides whether it worked --
never the exit code.  Auditing is the engine's job, so an action cannot forget
to do it.

Keeping all five behind one interface is what lets the CLI, the API and the
dashboard share a single code path: adding an action means writing a handler,
not another approval flow.

None of these classes takes a command, builds a command from a target, or has
any way to run one.  They ask a backend for a named operation with typed
arguments; the backend owns the (allowlisted, ``shell=False``) invocation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .backends.base import BackendStatus
from .backends.firewall import FirewallBackend, detect_firewall_backend
from .backends.process import DEFAULT_GRACE_SECONDS, ProcessBackend, LinuxProcessBackend
from .backends.session import SessionBackend, detect_session_backend
from .executor import CommandRunner, is_root
from .models import ActionOutcome, ActionPreview, ActionType
from .validators import (
    ValidationError,
    validate_ip,
    validate_pid,
    validate_session_id,
)

LOGGER = logging.getLogger(__name__)


@dataclass
class ResponseBackends:
    """The set of containment mechanisms one engine may use.

    Built by :meth:`detect` in production and handed mock backends in tests, so
    the engine's behaviour is identical either way.

    Args:
        execution_enabled: When ``False`` the backends are built around a
            read-only command runner: capability detection and previews still
            work, and nothing can change the system.
    """

    firewall: FirewallBackend
    process: ProcessBackend
    session: SessionBackend
    runner: CommandRunner

    @classmethod
    def detect(cls, execution_enabled: bool = True) -> "ResponseBackends":
        """Probe this host and build the backends it can actually support."""
        runner = CommandRunner(allow_mutation=execution_enabled)
        return cls(
            firewall=detect_firewall_backend(runner),
            process=LinuxProcessBackend(allow_mutation=execution_enabled),
            session=detect_session_backend(runner),
            runner=runner,
        )

    def statuses(self) -> dict[str, BackendStatus]:
        return {
            "firewall": self.firewall.status(),
            "process": self.process.status(),
            "session": self.session.status(),
        }

    def to_dict(self) -> dict:
        return {name: status.to_dict() for name, status in self.statuses().items()}


class ResponseActionHandler:
    """Base class: one containment action, from validation to verification."""

    action_type = ""
    #: Human-readable name used in previews and the dashboard.
    label = ""
    #: Whether a completed action of this type can be undone.
    reversible = False
    #: Whether executing it needs root.
    requires_privilege = True

    def __init__(self, backends: ResponseBackends) -> None:
        self.backends = backends

    # -- capability --------------------------------------------------------
    def backend_status(self) -> BackendStatus:  # pragma: no cover - abstract
        raise NotImplementedError

    def available(self) -> bool:
        return self.backend_status().available

    def requires_privilege_here(self) -> bool:
        """Whether running this action *on this host* needs rights we lack.

        Two facts combine.  The action class says whether the operation is
        privileged in principle; the backend says whether privileges are
        actually needed right now -- the firewalld backend reports ``False``
        once the process is root, and a mock backend reports ``False`` always.
        Asking both is what keeps the privilege check truthful instead of
        ceremonial.
        """
        if not self.requires_privilege:
            return False
        if not self.backend_status().requires_privilege:
            return False
        return not is_root()

    # -- the five steps ----------------------------------------------------
    def validate(self, target) -> tuple[str, dict]:  # pragma: no cover - abstract
        """Return ``(normalized_target, target_detail)`` or raise ValidationError."""
        raise NotImplementedError

    def preview(self, target, action_id: str = "ACTION-PREVIEW", ttl: int | None = None) -> ActionPreview:  # pragma: no cover - abstract
        raise NotImplementedError

    def execute(self, action) -> ActionOutcome:  # pragma: no cover - abstract
        raise NotImplementedError

    def verify(self, action, outcome: ActionOutcome) -> tuple[bool, str]:  # pragma: no cover - abstract
        """Re-read the system and decide whether the action really took effect."""
        raise NotImplementedError

    def rollback(self, action) -> ActionOutcome:
        """Undo a completed action.  Only reversible actions override this."""
        return ActionOutcome(
            ok=False,
            detail=f"{self.label} cannot be undone",
            error=f"{self.action_type} is not reversible",
        )

    # -- shared helpers ----------------------------------------------------
    def _privilege_hint(self) -> str | None:
        if not self.requires_privilege or is_root():
            return None
        return (
            f"{self.label} requires administrative privileges. Approve the action, then "
            "run the execute step with the necessary system privileges "
            "(for example: sudo sentinelforge response execute <ACTION-ID>). "
            "SentinelForge never invokes sudo itself and never asks for a password."
        )


class BlockIpAction(ResponseActionHandler):
    """Drop traffic from one source address at the host firewall.

    Reversible by construction: the rule SentinelForge installs is recorded
    verbatim on the action, and the rollback removes that exact rule.  With a
    TTL the firewall removes it on its own, so containment lapses safely even
    if nobody comes back to it.
    """

    action_type = ActionType.BLOCK_IP
    label = "Block IP"
    reversible = True
    requires_privilege = True

    def backend_status(self) -> BackendStatus:
        return self.backends.firewall.status()

    def validate(self, target) -> tuple[str, dict]:
        address = validate_ip(target)
        detail = self.backends.firewall.validate_target(address)
        blocked = self.backends.firewall.blocked_addresses()
        if str(address) in blocked:
            detail["already_blocked_by"] = blocked[str(address)]
        return str(address), detail

    def preview(self, target, action_id: str = "ACTION-PREVIEW", ttl: int | None = None) -> ActionPreview:
        address, detail = self.validate(target)
        status = self.backend_status()
        plan = self.backends.firewall.preview_block(address, action_id, ttl)
        duration = (
            f"{ttl} seconds, after which the firewall removes the rule itself"
            if ttl
            else "until it is rolled back, the firewall is reloaded, or the host reboots"
        )
        warnings = []
        if plan.get("already_blocked") or detail.get("already_blocked_by"):
            warnings.append(
                "this address is already blocked by a SentinelForge rule "
                f"({detail.get('already_blocked_by', 'an existing rule')})"
            )
        if not ttl:
            warnings.append(
                "no TTL was given: this block stays until someone removes it"
            )
        return ActionPreview(
            action_type=self.action_type,
            target=address,
            description=f"Block all traffic from {address} at the host firewall",
            effect=(
                f"Adds one firewalld rich rule to zone "
                f"{plan.get('zone') or 'unknown'} that drops packets from {address} "
                f"and logs them with the prefix sentinelforge-block-<action id>. "
                f"Duration: {duration}. No other rule is read, changed or removed."
            ),
            backend=status.name,
            available=status.available,
            reversible=True,
            requires_privilege=self.requires_privilege,
            privilege_hint=self._privilege_hint(),
            ttl_seconds=ttl,
            target_detail={**detail, **{k: plan[k] for k in ("rich_rule", "zone") if k in plan}},
            warnings=tuple(warnings),
            unavailable_reason=None if status.available else status.reason,
        )

    def execute(self, action) -> ActionOutcome:
        return self.backends.firewall.block_ip(
            action.target, action.action_id, action.ttl_seconds
        )

    def verify(self, action, outcome: ActionOutcome) -> tuple[bool, str]:
        """Confirm with the firewall that our exact rule is installed."""
        rule = (outcome.data or {}).get("rich_rule") or (outcome.rollback_data or {}).get(
            "rich_rule"
        )
        zone = (outcome.data or {}).get("zone") or (outcome.rollback_data or {}).get("zone")
        if not rule:
            return False, "no firewall rule was recorded, so nothing could be verified"
        state = self.backends.firewall.get_rule_state(rule, zone)
        if state is True:
            return True, f"the firewall reports the block rule as installed in zone {zone}"
        if state is False:
            return False, "the firewall does not report the block rule as installed"
        return False, "the firewall could not be asked whether the rule is installed"

    def rollback(self, action) -> ActionOutcome:
        if not action.rollback_data:
            return ActionOutcome(
                ok=False,
                detail="no rollback data was recorded for this action",
                error="this block cannot be undone automatically: SentinelForge does not "
                "know which rule it created",
            )
        return self.backends.firewall.unblock_ip(action.rollback_data)


class UnblockIpAction(ResponseActionHandler):
    """Remove a SentinelForge block, as a first-class action of its own.

    Distinct from :meth:`BlockIpAction.rollback` so that "undo the containment"
    can be requested, approved and audited like anything else -- including when
    the original action is not the one being undone (a lapsed TTL, an action
    recorded on a different incident).
    """

    action_type = ActionType.UNBLOCK_IP
    label = "Unblock IP"
    reversible = False
    requires_privilege = True

    def backend_status(self) -> BackendStatus:
        return self.backends.firewall.status()

    def validate(self, target) -> tuple[str, dict]:
        address = validate_ip(target)
        blocked = self.backends.firewall.blocked_addresses()
        if str(address) not in blocked:
            raise ValidationError(
                f"{address} is not blocked by SentinelForge, so there is nothing to "
                "remove. SentinelForge only removes rules it created.",
                "target",
            )
        detail = self.backends.firewall.validate_target(address)
        detail["blocked_by"] = blocked[str(address)]
        return str(address), detail

    def preview(self, target, action_id: str = "ACTION-PREVIEW", ttl: int | None = None) -> ActionPreview:
        address, detail = self.validate(target)
        status = self.backend_status()
        return ActionPreview(
            action_type=self.action_type,
            target=address,
            description=f"Remove the SentinelForge firewall block on {address}",
            effect=(
                f"Removes the rich rule created by {detail.get('blocked_by')} from zone "
                f"{detail.get('zone')}. Rules SentinelForge did not create are never "
                "touched. Traffic from this address will reach the host again."
            ),
            backend=status.name,
            available=status.available,
            reversible=False,
            requires_privilege=self.requires_privilege,
            privilege_hint=self._privilege_hint(),
            target_detail=detail,
            warnings=("the address will be able to reach this host again",),
            unavailable_reason=None if status.available else status.reason,
        )

    def execute(self, action) -> ActionOutcome:
        rollback_data = action.rollback_data
        if not rollback_data:
            rules = {
                rule["address"]: rule
                for rule in self.backends.firewall.managed_rules()
                if rule.get("address")
            }
            rollback_data = rules.get(action.target)
        if not rollback_data:
            return ActionOutcome(
                ok=False,
                detail=f"no SentinelForge block rule for {action.target} was found",
                error="nothing to remove: SentinelForge only removes rules it created",
            )
        return self.backends.firewall.unblock_ip(rollback_data)

    def verify(self, action, outcome: ActionOutcome) -> tuple[bool, str]:
        """Confirm the address is no longer blocked by any rule of ours."""
        if action.target in self.backends.firewall.blocked_addresses():
            return False, "the firewall still reports a SentinelForge block for this address"
        return True, "the firewall no longer reports a SentinelForge block for this address"


class KillProcessAction(ResponseActionHandler):
    """Terminate one local process with ``SIGTERM``.

    Irreversible, and reported as such everywhere.  The process metadata is
    captured before the signal so the audit trail describes what was killed.
    """

    action_type = ActionType.KILL_PROCESS
    label = "Kill process"
    reversible = False
    requires_privilege = False  # only when the process belongs to another user

    def backend_status(self) -> BackendStatus:
        return self.backends.process.status()

    def validate(self, target) -> tuple[str, dict]:
        pid = validate_pid(target)
        info = self.backends.process.validate_target(pid)
        return str(pid), info.to_dict()

    def preview(self, target, action_id: str = "ACTION-PREVIEW", ttl: int | None = None) -> ActionPreview:
        pid, detail = self.validate(target)
        status = self.backend_status()
        needs_root = detail.get("uid") not in (None, _current_uid()) and not is_root()
        warnings = [
            "terminating a process cannot be undone",
            "evidence in the process's memory is lost when it exits; capture what you "
            "need before containing it",
        ]
        if detail.get("uid") == 0:
            warnings.append("this process runs as root")
        return ActionPreview(
            action_type=self.action_type,
            target=pid,
            description=f"Terminate {detail.get('name') or 'process'} (pid {pid})",
            effect=(
                f"Sends SIGTERM to pid {pid} "
                f"({detail.get('executable') or detail.get('name') or 'unknown executable'}), "
                f"owned by {detail.get('username') or detail.get('uid')}, then waits "
                f"{DEFAULT_GRACE_SECONDS:g}s and checks whether it exited. "
                "SentinelForge never escalates to SIGKILL on its own, and never runs the "
                "process's command line."
            ),
            backend=status.name,
            available=status.available,
            reversible=False,
            requires_privilege=needs_root,
            privilege_hint=(
                "This process belongs to another user; terminating it requires root. "
                "Approve the action, then run the execute step with the necessary "
                "privileges. SentinelForge never invokes sudo itself."
            )
            if needs_root
            else None,
            target_detail=detail,
            warnings=tuple(warnings),
            unavailable_reason=None if status.available else status.reason,
        )

    def execute(self, action) -> ActionOutcome:
        return self.backends.process.terminate(validate_pid(action.target))

    def verify(self, action, outcome: ActionOutcome) -> tuple[bool, str]:
        """Confirm the process is gone -- and that it is the *same* process.

        The start time recorded at validation time is compared, so a recycled
        PID now belonging to an unrelated process is not mistaken for a
        survivor, and a *different* process is never reported as contained.
        """
        pid = validate_pid(action.target)
        start_ticks = (action.target_detail or {}).get("start_ticks")
        if self.backends.process.verify_terminated(pid, start_ticks):
            return True, f"pid {pid} is no longer running"
        return False, f"pid {pid} is still running"


class TerminateSessionAction(ResponseActionHandler):
    """End one systemd-logind session.

    Deliberately *not* "disable this user": no account is locked, no password
    is expired, and the user may log in again.  See
    :mod:`sentinelforge.response.backends.session`.
    """

    action_type = ActionType.TERMINATE_SESSION
    label = "Terminate session"
    reversible = False
    requires_privilege = True

    def backend_status(self) -> BackendStatus:
        return self.backends.session.status()

    def validate(self, target) -> tuple[str, dict]:
        session_id = validate_session_id(target)
        detail = self.backends.session.validate_target(session_id)
        return session_id, dict(detail)

    def preview(self, target, action_id: str = "ACTION-PREVIEW", ttl: int | None = None) -> ActionPreview:
        session_id, detail = self.validate(target)
        status = self.backend_status()
        where = detail.get("remotehost") or detail.get("tty") or detail.get("type") or "unknown"
        return ActionPreview(
            action_type=self.action_type,
            target=session_id,
            description=f"End session {session_id} for user {detail.get('name') or '?'}",
            effect=(
                f"Asks systemd-logind to terminate session {session_id} "
                f"({detail.get('class')}/{detail.get('type')}, from {where}). "
                "The processes in that session are terminated with it. The account is "
                "NOT locked or disabled: the user can log in again."
            ),
            backend=status.name,
            available=status.available,
            reversible=False,
            requires_privilege=self.requires_privilege,
            privilege_hint=self._privilege_hint(),
            target_detail=detail,
            warnings=(
                "ending a session cannot be undone",
                "unsaved work in that session is lost",
            ),
            unavailable_reason=None if status.available else status.reason,
        )

    def execute(self, action) -> ActionOutcome:
        return self.backends.session.terminate(validate_session_id(action.target))

    def verify(self, action, outcome: ActionOutcome) -> tuple[bool, str]:
        session_id = validate_session_id(action.target)
        if self.backends.session.verify_terminated(session_id):
            return True, f"logind no longer reports session {session_id} as active"
        return False, f"logind still reports session {session_id} as active"


class HostIsolationAction(ResponseActionHandler):
    """Host-wide network isolation -- **planned / capability dependent**.

    The interface exists so the capability can be reported, previewed and
    reasoned about; execution is refused in every supported configuration.

    The reason is specific rather than squeamish.  Isolating a Linux host
    safely means installing a policy that drops everything *except* the paths
    that keep the host reachable and reversible -- the analyst's own SSH
    session, the management network, DNS for the return path -- and then being
    able to restore the previous configuration exactly.  The naive
    implementation (flush the ruleset, install a default-drop policy) is
    precisely the destructive firewall operation this phase forbids: it
    discards configuration SentinelForge did not create, and it strands the
    responder outside the host they are responding to.  Until that can be done
    reversibly, the honest answer is a refusal with an explanation.
    """

    action_type = ActionType.ISOLATE_HOST
    label = "Isolate host"
    reversible = False
    requires_privilege = True

    #: Shown wherever this action is offered.
    STATUS_NOTE = (
        "Planned / capability dependent. SentinelForge will not isolate a host until it "
        "can do so reversibly, without discarding firewall configuration it did not "
        "create, and without stranding the responding analyst outside the host."
    )

    def backend_status(self) -> BackendStatus:
        firewall = self.backends.firewall.status()
        return BackendStatus(
            name=firewall.name,
            available=False,
            reason=self.STATUS_NOTE,
            remedy="Use targeted containment instead: block the source address, "
            "terminate the session, or disconnect the host by hand.",
            requires_privilege=True,
            details={
                "firewall_backend": firewall.name,
                "firewall_available": firewall.available,
                "planned": True,
            },
        )

    def validate(self, target) -> tuple[str, dict]:
        """Accept only this host as a target, and describe what is missing."""
        from ..collector.base import local_hostname

        host = local_hostname()
        if target not in (None, "", "localhost", host):
            raise ValidationError(
                "host isolation can only ever target this host; SentinelForge does not "
                "act on remote machines",
                "target",
            )
        return host, {
            "host": host,
            "capability": "planned",
            "firewall_backend": self.backends.firewall.status().name,
            "note": self.STATUS_NOTE,
        }

    def preview(self, target, action_id: str = "ACTION-PREVIEW", ttl: int | None = None) -> ActionPreview:
        host, detail = self.validate(target)
        status = self.backend_status()
        return ActionPreview(
            action_type=self.action_type,
            target=host,
            description=f"Isolate {host} from the network (not implemented)",
            effect=(
                "Nothing. This action is prepared but disabled: no rule is written, no "
                "interface is brought down, and nothing is flushed. " + self.STATUS_NOTE
            ),
            backend=status.name,
            available=False,
            reversible=False,
            requires_privilege=True,
            privilege_hint=None,
            target_detail=detail,
            warnings=("host isolation is not available in this phase",),
            unavailable_reason=self.STATUS_NOTE,
        )

    def execute(self, action) -> ActionOutcome:
        return ActionOutcome(ok=False, detail=self.STATUS_NOTE, error=self.STATUS_NOTE)

    def verify(self, action, outcome: ActionOutcome) -> tuple[bool, str]:
        return False, "host isolation is not implemented, so there is nothing to verify"


#: Every action the engine can run, by type.
ACTION_HANDLERS: dict[str, type] = {
    ActionType.BLOCK_IP: BlockIpAction,
    ActionType.UNBLOCK_IP: UnblockIpAction,
    ActionType.KILL_PROCESS: KillProcessAction,
    ActionType.TERMINATE_SESSION: TerminateSessionAction,
    ActionType.ISOLATE_HOST: HostIsolationAction,
}


def get_handler(action_type: str, backends: ResponseBackends) -> ResponseActionHandler:
    """Build the handler for ``action_type``.

    Raises:
        ValidationError: The type is not one SentinelForge implements.  This is
            the single place an unknown action type can enter the engine, which
            is why the CLI and the API can both rely on it.
    """
    handler_class = ACTION_HANDLERS.get(action_type)
    if handler_class is None:
        raise ValidationError(
            f"unknown action type {action_type!r} "
            f"(known: {', '.join(sorted(ACTION_HANDLERS))})",
            "action_type",
        )
    return handler_class(backends)


def _current_uid() -> int | None:
    import os

    try:
        return os.getuid()
    except AttributeError:  # pragma: no cover - non-POSIX
        return None
