"""What a scenario is, and what it expects (Phase 8).

A scenario has two halves that are deliberately kept apart:

* the **telemetry** it generates -- synthetic :class:`SecurityEvent` objects,
  shaped exactly the way Phase 1 normalization and the Phase 4 sensors produce
  them;
* the **expectation** -- what a security engineer says SentinelForge should
  make of that telemetry: which rules fire, which must *not* fire, how many
  incidents result, which ATT&CK techniques are mapped, what the risk band is,
  and which containment options the evidence should offer.

Keeping them apart is the whole point.  The generator knows nothing about the
detection rules, and the expectation is written against the *behaviour* a SOC
would want rather than against whatever the current implementation happens to
emit.  When the two disagree, the runner reports a failure -- it never adjusts
the expectation to match the observation.

Determinism: scenarios are built from a fixed base time
(:data:`BASE_TIME`) and fixed addresses drawn from the documentation ranges
reserved by RFC 5737 (``192.0.2.0/24``, ``198.51.100.0/24``, ``203.0.113.0/24``)
and RFC 3849 (``2001:db8::/32``).  Those addresses are routed nowhere, belong to
nobody, and can never be mistaken for a real host.  Re-running a scenario
therefore reproduces byte-identical events.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Sequence

from ..models.event import EventType, SecurityEvent, Severity, format_timestamp

#: Fixed reference time for every scenario, so runs are reproducible.
BASE_TIME = datetime(2026, 3, 17, 9, 0, 0, tzinfo=timezone.utc)

#: The host every scenario pretends to be running on.
SCENARIO_HOST = "fedora-lab"

# -- documentation addresses (RFC 5737 / RFC 3849): routed nowhere ----------
ATTACKER_IP = "203.0.113.10"
SECOND_ATTACKER_IP = "203.0.113.77"
C2_IP = "198.51.100.9"
SCAN_TARGET_IP = "198.51.100.40"
INTERNAL_IP = "10.10.0.15"
ADMIN_IP = "10.10.0.9"


class ScenarioKind:
    """Whether a scenario is meant to alert or meant to stay quiet.

    ``BENIGN`` scenarios are as important as ``ATTACK`` ones: they are how
    false positives are measured, and they are checked with the same machinery.
    """

    ATTACK = "attack"
    BENIGN = "benign"

    ALL = (ATTACK, BENIGN)


def scenario_time(offset_seconds: float, base: datetime | None = None) -> str:
    """Return a scenario timestamp ``offset_seconds`` after the base time."""
    return format_timestamp((base or BASE_TIME) + timedelta(seconds=offset_seconds))


@dataclass(frozen=True)
class Expectation:
    """What SentinelForge should make of a scenario's telemetry.

    Every field is compared literally by the runner; ``None`` means "this
    scenario does not make a claim about that", which is different from
    expecting zero.

    Attributes:
        events: Exact number of synthetic events the scenario generates.
        alerts: Exact number of alerts detection should raise.
        rule_ids: Rules that must fire.  All of them, or the check fails.
        forbidden_rule_ids: Rules that must **not** fire.  This is what makes a
            benign scenario a real test rather than a smoke test.
        incidents: Exact number of incidents correlation should produce.
        severity: Expected incident severity band, e.g. ``"critical"``.
        risk_range: Inclusive ``(low, high)`` bounds for the incident score.  A
            range rather than a number because scoring inputs (how many rules
            corroborate) are allowed to shift a few points without this being a
            regression; the band is narrow enough to catch a real change.
        techniques: ATT&CK ids that must appear on the incident's attack chain.
            Both parent techniques and sub-techniques count.
        attack_chains: Correlation chain ids that must match, e.g.
            ``"BRUTE_FORCE_THEN_SUCCESS"``.
        source_ips / users: Entities the incident must have recorded.
        response_options: Containment action types the incident's own evidence
            should offer an analyst (``block_ip``, ``kill_process``).
        process_tree_pids: PIDs that must appear in the reconstructed lineage.
        process_tree_missing_pids: PIDs the scenario's *telemetry* contains that
            the reconstructed lineage does **not** show, checked exactly.  The
            process tree is built from one incident's evidence plus the parents
            that evidence names, so a process the sensors observed but no rule
            alerted on never reaches it.  That is a real visibility gap, and
            pinning it here is how Phase 8 keeps it visible: the check fails
            both if the gap widens and if it silently closes, which forces the
            documented limitation to be revisited either way.
        network_destinations: ``"ip:port"`` pairs the network view must show.
        notes: Free text shown in reports; never asserted on.
    """

    events: int
    alerts: int
    incidents: int
    rule_ids: frozenset[str] = frozenset()
    forbidden_rule_ids: frozenset[str] = frozenset()
    severity: str | None = None
    risk_range: tuple[int, int] | None = None
    techniques: frozenset[str] = frozenset()
    attack_chains: frozenset[str] = frozenset()
    source_ips: frozenset[str] = frozenset()
    users: frozenset[str] = frozenset()
    response_options: frozenset[str] = frozenset()
    process_tree_pids: frozenset[int] = frozenset()
    process_tree_missing_pids: frozenset[int] | None = None
    network_destinations: frozenset[str] = frozenset()
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "events": self.events,
            "alerts": self.alerts,
            "incidents": self.incidents,
            "rule_ids": sorted(self.rule_ids),
            "forbidden_rule_ids": sorted(self.forbidden_rule_ids),
            "severity": self.severity,
            "risk_range": list(self.risk_range) if self.risk_range else None,
            "techniques": sorted(self.techniques),
            "attack_chains": sorted(self.attack_chains),
            "source_ips": sorted(self.source_ips),
            "users": sorted(self.users),
            "response_options": sorted(self.response_options),
            "process_tree_pids": sorted(self.process_tree_pids),
            "process_tree_missing_pids": (
                sorted(self.process_tree_missing_pids)
                if self.process_tree_missing_pids is not None
                else None
            ),
            "network_destinations": sorted(self.network_destinations),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class Scenario:
    """One reproducible synthetic scenario and its expected outcome.

    Attributes:
        scenario_id: CLI name, e.g. ``ssh-bruteforce``.
        name: Human-readable title.
        description: What the scenario represents, in one or two sentences.
        kind: :class:`ScenarioKind` -- an intrusion, or benign activity.
        mitre_techniques: The techniques the scenario is *about*.  Documented
            here for the coverage report; what is asserted lives in
            ``expected.techniques``.
        build: ``(base_time) -> list[SecurityEvent]``.  Must be pure and
            deterministic: same base time in, identical events out.
        expected: See :class:`Expectation`.
        containment_target: ``(action_type, target)`` the response stage should
            drive end to end, or ``None`` to skip response validation for this
            scenario.
    """

    scenario_id: str
    name: str
    description: str
    kind: str
    mitre_techniques: tuple[str, ...]
    build: Callable[[datetime], list[SecurityEvent]]
    expected: Expectation
    containment_target: tuple[str, str] | None = None
    tags: tuple[str, ...] = ()

    def events(self, base: datetime | None = None) -> list[SecurityEvent]:
        """Generate this scenario's telemetry."""
        return list(self.build(base or BASE_TIME))

    @property
    def is_attack(self) -> bool:
        return self.kind == ScenarioKind.ATTACK

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "kind": self.kind,
            "mitre_techniques": list(self.mitre_techniques),
            "expected": self.expected.to_dict(),
            "containment_target": (
                list(self.containment_target) if self.containment_target else None
            ),
            "tags": list(self.tags),
        }


# --------------------------------------------------------------------------
# Event builders.  These produce exactly the shapes Phase 1 normalization and
# the Phase 4 sensors produce, so the detection rules see nothing special about
# a simulated event.  No scenario builds an event by hand.
# --------------------------------------------------------------------------
def event(
    offset: float,
    base: datetime,
    *,
    event_type: str = EventType.UNKNOWN,
    severity: str = Severity.INFO,
    source: str = "systemd-journal",
    **fields,
) -> SecurityEvent:
    """A normalized event stamped at ``offset`` seconds after ``base``."""
    return SecurityEvent(
        timestamp=scenario_time(offset, base),
        host=fields.pop("host", SCENARIO_HOST),
        source=source,
        event_type=event_type,
        severity=severity,
        **fields,
    )


def ssh_failure(offset: float, base: datetime, src_ip: str, user: str) -> SecurityEvent:
    """A failed SSH password authentication, as sshd logs it."""
    message = f"Failed password for {user} from {src_ip} port 22 ssh2"
    return event(
        offset,
        base,
        event_type=EventType.AUTHENTICATION_FAILURE,
        severity=Severity.MEDIUM,
        process="sshd",
        user=user,
        src_ip=src_ip,
        message=message,
        raw=message,
    )


def ssh_invalid_user(offset: float, base: datetime, src_ip: str, user: str) -> SecurityEvent:
    """A failed SSH attempt for an account that does not exist on this host."""
    message = f"Failed password for invalid user {user} from {src_ip} port 22 ssh2"
    return event(
        offset,
        base,
        event_type=EventType.AUTHENTICATION_FAILURE,
        severity=Severity.HIGH,
        process="sshd",
        user=user,
        src_ip=src_ip,
        message=message,
        raw=message,
    )


def ssh_success(offset: float, base: datetime, src_ip: str, user: str) -> SecurityEvent:
    """A successful SSH password authentication."""
    message = f"Accepted password for {user} from {src_ip} port 22 ssh2"
    return event(
        offset,
        base,
        event_type=EventType.AUTHENTICATION_SUCCESS,
        severity=Severity.LOW,
        process="sshd",
        user=user,
        src_ip=src_ip,
        message=message,
        raw=message,
    )


def sudo_command(
    offset: float,
    base: datetime,
    command: str,
    user: str,
    target: str = "root",
    tty: str = "pts/0",
) -> SecurityEvent:
    """A sudo ``COMMAND=`` log line.

    The command text is data.  It is written into a log message, matched
    against regular expressions by the sudo rule, and never executed, expanded
    or passed to a shell by anything in SentinelForge.
    """
    message = (
        f"{user} : TTY={tty} ; PWD=/home/{user} ; USER={target} ; COMMAND={command}"
    )
    return event(
        offset,
        base,
        event_type=EventType.SUDO,
        severity=Severity.MEDIUM,
        process="sudo",
        user=user,
        message=message,
        raw=message,
    )


def process_start(
    offset: float,
    base: datetime,
    *,
    process: str,
    pid: int,
    ppid: int,
    parent: str,
    command_line: str,
    user: str,
    executable: str | None = None,
    uid: int = 1000,
) -> SecurityEvent:
    """A process-execution event in the shape the eBPF process sensor emits."""
    return event(
        offset,
        base,
        source="ebpf-process",
        event_type=EventType.PROCESS_START,
        severity=Severity.INFO,
        process=process,
        user=user,
        message=f"process {process} started by {parent}",
        metadata={
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "parent_process": parent,
            "executable": executable or f"/usr/bin/{process}",
            "command_line": command_line,
            "synthetic": True,
        },
    )


def network_connection(
    offset: float,
    base: datetime,
    *,
    process: str,
    pid: int,
    destination_ip: str,
    destination_port: int,
    user: str,
    source_ip: str = INTERNAL_IP,
    source_port: int = 54210,
    protocol: str = "tcp",
) -> SecurityEvent:
    """An outbound connection event in the shape the eBPF network sensor emits."""
    return event(
        offset,
        base,
        source="ebpf-network",
        event_type=EventType.NETWORK_CONNECTION,
        severity=Severity.INFO,
        process=process,
        user=user,
        src_ip=source_ip,
        message=f"{process} connected to {destination_ip}:{destination_port} ({protocol})",
        metadata={
            "pid": pid,
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol,
            "direction": "outbound",
            "process_name": process,
            "synthetic": True,
        },
    )


def session_open(offset: float, base: datetime, user: str, src_ip: str) -> SecurityEvent:
    """A PAM session opening after a successful login."""
    message = f"pam_unix(sshd:session): session opened for user {user}"
    return event(
        offset,
        base,
        event_type=EventType.SESSION_OPEN,
        severity=Severity.INFO,
        process="sshd",
        user=user,
        src_ip=src_ip,
        message=message,
        raw=message,
    )


def sorted_events(events: Sequence[SecurityEvent]) -> list[SecurityEvent]:
    """Return events in log order, which is how a collector would hand them over."""
    return sorted(events, key=lambda item: (item.timestamp or "", item.source))


#: Re-exported so scenario modules import one name.
__all__ = [
    "ADMIN_IP",
    "ATTACKER_IP",
    "BASE_TIME",
    "C2_IP",
    "Expectation",
    "INTERNAL_IP",
    "SCAN_TARGET_IP",
    "SCENARIO_HOST",
    "SECOND_ATTACKER_IP",
    "Scenario",
    "ScenarioKind",
    "event",
    "network_connection",
    "process_start",
    "scenario_time",
    "session_open",
    "sorted_events",
    "ssh_failure",
    "ssh_invalid_user",
    "ssh_success",
    "sudo_command",
]
