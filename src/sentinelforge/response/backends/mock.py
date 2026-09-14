"""In-memory containment backends (Phase 7).

These exist so the response engine can be exercised end to end -- request,
approve, execute, verify, roll back, fail -- without a firewall rule ever being
written or a process ever being signalled.  The entire test suite runs against
them, which is why ``pytest`` on a developer's Fedora workstation cannot change
that workstation.

They are shipped in the package rather than in ``tests/`` for the same reason
:mod:`sentinelforge.ai.providers.mock` and :mod:`sentinelforge.sensors.mock`
are: a demonstrable, offline path through the system is a feature of the
product, not a fixture.  Demo mode uses them too, so the dashboard's response
panel can be clicked through on a machine with no privileges at all.

Failure injection is first class.  Real containment fails in specific ways --
permission denied, an unavailable backend, a process that ignores SIGTERM, a
rollback that cannot complete -- and each of those is reachable here, because
error handling that is never exercised is error handling that does not work.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import ActionOutcome
from ..validators import ValidationError, validate_ip, validate_pid, validate_session_id
from .base import BackendStatus
from .firewall import FirewallBackend, build_rich_rule, rule_action_id
from .process import DEFAULT_GRACE_SECONDS, ProcessBackend, ProcessInfo
from .session import SessionBackend

#: Injectable failure modes, shared by all three mock backends.
FAIL_NONE = None
FAIL_PERMISSION = "permission"
FAIL_BACKEND = "backend"
FAIL_VERIFY = "verify"
FAIL_SURVIVES = "survives"


@dataclass
class MockFirewallBackend(FirewallBackend):
    """A firewall that exists only in this dictionary.

    Attributes:
        rules: ``rich_rule -> zone`` for every block currently "installed".
        calls: Every operation performed, so a test can assert that a dry run
            really did nothing.
        fail: One of the ``FAIL_*`` constants, to simulate a specific failure.
    """

    name: str = "mock-firewall"
    zone_name: str = "mock-zone"
    available: bool = True
    unavailable_reason: str = "the mock firewall backend is switched off"
    fail: str | None = FAIL_NONE
    rules: dict[str, str] = field(default_factory=dict)
    calls: list[tuple] = field(default_factory=list)

    def status(self) -> BackendStatus:
        if not self.available:
            return BackendStatus(
                name=self.name,
                available=False,
                reason=self.unavailable_reason,
                remedy="This is a mock backend; enable it in the test setup.",
            )
        return BackendStatus(
            name=self.name,
            available=True,
            requires_privilege=False,
            details={"zone": self.zone_name, "mock": True},
        )

    def zone(self) -> str:
        return self.zone_name

    def validate_target(self, address) -> dict:
        parsed = validate_ip(address)
        return {
            "address": str(parsed),
            "family": f"ipv{parsed.version}",
            "zone": self.zone_name,
        }

    def preview_block(self, address, action_id: str, ttl: int | None = None) -> dict:
        target = self.validate_target(address)
        rule = build_rich_rule(address, action_id)
        self.calls.append(("preview_block", target["address"], ttl))
        return {
            "backend": self.name,
            "zone": self.zone_name,
            "family": target["family"],
            "address": target["address"],
            "rich_rule": rule,
            "ttl_seconds": ttl,
            "permanent": False,
            "command": ["firewall-cmd", "--zone", self.zone_name, "--add-rich-rule", rule],
            "already_blocked": rule in self.rules,
        }

    def get_rule_state(self, rich_rule: str, zone: str | None = None) -> bool | None:
        if self.fail == FAIL_VERIFY:
            return None
        return rich_rule in self.rules

    def managed_rules(self) -> list[dict]:
        return [
            {
                "zone": zone,
                "rich_rule": rule,
                "action_id": rule_action_id(rule),
                "address": _address_of(rule),
            }
            for rule, zone in self.rules.items()
        ]

    def blocked_addresses(self) -> dict[str, str]:
        return {
            rule["address"]: rule["action_id"]
            for rule in self.managed_rules()
            if rule.get("address")
        }

    def block_ip(self, address, action_id: str, ttl: int | None = None) -> ActionOutcome:
        target = self.validate_target(address)
        rule = build_rich_rule(address, action_id)
        self.calls.append(("block_ip", target["address"], action_id, ttl))
        if not self.available:
            return ActionOutcome(
                ok=False, detail=self.unavailable_reason, error=self.unavailable_reason
            )
        if self.fail == FAIL_PERMISSION:
            return ActionOutcome(
                ok=False,
                detail="not permitted to change the firewall",
                error="permission denied: firewall administration requires root. "
                "Re-run the approved action with the necessary privileges.",
            )
        if self.fail == FAIL_BACKEND:
            return ActionOutcome(
                ok=False, detail="the firewall refused the rule", error="mock backend failure"
            )
        if self.fail == FAIL_VERIFY:
            # Accepted, but the rule is not really there: the engine must catch
            # this rather than trusting the exit code.
            return ActionOutcome(
                ok=False,
                detail="the firewall accepted the command but the rule is not present",
                error="verification failed: the block rule could not be confirmed",
            )
        self.rules[rule] = self.zone_name
        return ActionOutcome(
            ok=True,
            detail=f"{target['address']} is blocked in zone {self.zone_name}",
            data={
                "zone": self.zone_name,
                "rich_rule": rule,
                "ttl_seconds": ttl,
                "permanent": False,
                "mock": True,
            },
            rollback_data={
                "backend": self.name,
                "zone": self.zone_name,
                "rich_rule": rule,
                "address": target["address"],
                "action_id": action_id,
            },
        )

    def unblock_ip(self, rollback_data: dict) -> ActionOutcome:
        rule = (rollback_data or {}).get("rich_rule")
        self.calls.append(("unblock_ip", rule))
        if not rule or not rule_action_id(rule):
            return ActionOutcome(
                ok=False,
                detail="refusing to remove a rule SentinelForge did not create",
                error="rollback data does not describe a SentinelForge block rule",
            )
        if self.fail == FAIL_PERMISSION:
            return ActionOutcome(
                ok=False,
                detail="not permitted to change the firewall",
                error="permission denied: firewall administration requires root",
            )
        if self.fail == FAIL_BACKEND:
            return ActionOutcome(
                ok=False, detail="the firewall refused the removal", error="mock rollback failure"
            )
        if rule not in self.rules:
            return ActionOutcome(
                ok=True,
                detail="the block rule was already gone",
                data={"rich_rule": rule, "already_absent": True},
            )
        zone = self.rules.pop(rule)
        return ActionOutcome(
            ok=True,
            detail=f"the block rule was removed from zone {zone}",
            data={"zone": zone, "rich_rule": rule, "mock": True},
        )


@dataclass
class MockProcessBackend(ProcessBackend):
    """A process table that exists only in this dictionary.

    Attributes:
        processes: ``pid -> ProcessInfo`` for the processes that "exist".
        terminated: PIDs this backend was asked to terminate.
    """

    name: str = "mock-process"
    available: bool = True
    fail: str | None = FAIL_NONE
    processes: dict[int, ProcessInfo] = field(default_factory=dict)
    terminated: list[int] = field(default_factory=list)
    calls: list[tuple] = field(default_factory=list)

    def add(self, pid: int, **overrides) -> ProcessInfo:
        """Register a synthetic process and return it."""
        fields = {
            "pid": pid,
            "ppid": 1,
            "name": "bash",
            "executable": "/usr/bin/bash",
            "command_line": "bash -i",
            "uid": 1000,
            "username": "analyst",
            "state": "S",
            "start_ticks": 1000 + pid,
            "start_time": "2026-09-12T10:30:00Z",
        }
        fields.update(overrides)
        info = ProcessInfo(**fields)
        self.processes[pid] = info
        return info

    def status(self) -> BackendStatus:
        if not self.available:
            return BackendStatus(
                name=self.name,
                available=False,
                reason="the mock process backend is switched off",
            )
        return BackendStatus(
            name=self.name, available=True, requires_privilege=False, details={"mock": True}
        )

    def get_process(self, pid: int) -> ProcessInfo | None:
        return self.processes.get(validate_pid(pid))

    def validate_target(self, pid) -> ProcessInfo:
        pid = validate_pid(pid)
        info = self.get_process(pid)
        if info is None:
            raise ValidationError(f"no process with PID {pid} is running", "target")
        return info

    def verify_terminated(self, pid: int, start_ticks: int | None = None) -> bool:
        pid = validate_pid(pid)
        info = self.processes.get(pid)
        if info is None:
            return True
        if start_ticks is not None and info.start_ticks != start_ticks:
            return True
        return info.state == "Z"

    def terminate(self, pid: int, grace_seconds: float = DEFAULT_GRACE_SECONDS) -> ActionOutcome:
        pid = validate_pid(pid)
        self.calls.append(("terminate", pid))
        info = self.processes.get(pid)
        if info is None:
            return ActionOutcome(
                ok=False,
                detail=f"no process with PID {pid} is running",
                error="the target process does not exist (it may already have exited)",
            )
        if self.fail == FAIL_PERMISSION:
            return ActionOutcome(
                ok=False,
                detail=f"not permitted to signal {info.describe()}",
                data={"process": info.to_dict()},
                error="permission denied: terminating a process owned by another user "
                "requires root. Re-run the approved action with the necessary privileges.",
            )
        if self.fail == FAIL_SURVIVES:
            return ActionOutcome(
                ok=False,
                detail=f"{info.describe()} is still running after SIGTERM",
                data={"process": info.to_dict(), "signal": "SIGTERM", "escalated": False},
                error="the process did not exit after SIGTERM. SentinelForge does not "
                "escalate to SIGKILL on its own.",
            )
        self.terminated.append(pid)
        self.processes.pop(pid, None)
        return ActionOutcome(
            ok=True,
            detail=f"{info.describe()} terminated after SIGTERM",
            data={"process": info.to_dict(), "signal": "SIGTERM", "escalated": False},
        )


@dataclass
class MockSessionBackend(SessionBackend):
    """A logind that exists only in this dictionary."""

    name: str = "mock-session"
    available: bool = True
    fail: str | None = FAIL_NONE
    sessions: dict[str, dict] = field(default_factory=dict)
    terminated: list[str] = field(default_factory=list)

    def add(self, session_id: str, **overrides) -> dict:
        session = {
            "id": session_id,
            "user": "1000",
            "name": "analyst",
            "state": "active",
            "type": "tty",
            "class": "user",
            "remote": "yes",
            "remotehost": "198.51.100.25",
            "is_own_session": False,
        }
        session.update(overrides)
        self.sessions[session_id] = session
        return session

    def status(self) -> BackendStatus:
        if not self.available:
            return BackendStatus(
                name=self.name,
                available=False,
                reason="the mock session backend is switched off",
            )
        return BackendStatus(
            name=self.name, available=True, requires_privilege=False, details={"mock": True}
        )

    def list_sessions(self) -> list[dict]:
        return list(self.sessions.values())

    def get_session(self, session_id: str) -> dict | None:
        return self.sessions.get(validate_session_id(session_id))

    def validate_target(self, session_id) -> dict:
        session_id = validate_session_id(session_id)
        session = self.get_session(session_id)
        if session is None:
            raise ValidationError(f"no session {session_id!r} is known to logind", "target")
        if session.get("is_own_session"):
            raise ValidationError(
                f"session {session_id} is this analyst's own session", "target"
            )
        return session

    def verify_terminated(self, session_id: str) -> bool:
        session = self.sessions.get(session_id)
        return session is None or session.get("state") in ("closing", "closed")

    def terminate(self, session_id: str) -> ActionOutcome:
        session = self.validate_target(session_id)
        if self.fail == FAIL_PERMISSION:
            return ActionOutcome(
                ok=False,
                detail="not permitted to terminate the session",
                error="permission denied: ending another user's session requires root",
            )
        if self.fail == FAIL_BACKEND:
            return ActionOutcome(
                ok=False, detail="logind refused the request", error="mock backend failure"
            )
        self.terminated.append(session["id"])
        self.sessions.pop(session["id"], None)
        return ActionOutcome(
            ok=True,
            detail=f"session {session['id']} ({session.get('name')}) was terminated",
            data={"session": session, "mock": True},
        )


def _address_of(rich_rule: str) -> str | None:
    import re

    match = re.search(r'source address="([^"]+)"', rich_rule or "")
    return match.group(1) if match else None
