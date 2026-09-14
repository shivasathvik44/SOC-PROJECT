"""Detections that only become possible with eBPF telemetry (Phase 4).

Log files describe authentication.  They say nothing about *what ran*, so a web
server that spawns a shell, or a shell that dials out to the internet, is
invisible to Phase 1 sources.  These two rules read the process and network
metadata the eBPF sensors attach to normalized events.

Both are deliberately narrow.  There is no list of "bad command names" here:
the signal is the *relationship* -- which parent spawned an interpreter, and
which kind of process opened a connection -- which is far harder to rename
around than a binary name, and much less prone to false positives.

The rules read event metadata generically.  They contain no
``if event.source == "ebpf"`` check: any future sensor that fills in the same
fields gets the same detections for free.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from ...models.event import EventType, SecurityEvent, Severity
from ..mitre import mapping
from ..risk import RiskFactor
from ..rule import Detection, Rule, is_external_address

#: Interpreters that give an attacker an interactive foothold.
SHELLS: frozenset[str] = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "busybox", "ash"}
)
INTERPRETERS: frozenset[str] = frozenset(
    {"python", "python2", "python3", "perl", "ruby", "php", "lua", "node"}
)

#: Parents that have no legitimate reason to spawn an interactive shell.
#: Split by kind so the alert can say *why* the parent is unexpected.
DOWNLOAD_TOOLS: frozenset[str] = frozenset({"curl", "wget", "fetch", "aria2c"})
NETWORK_SERVICES: frozenset[str] = frozenset(
    {
        "nginx",
        "httpd",
        "apache2",
        "php-fpm",
        "lighttpd",
        "caddy",
        "tomcat",
        "postgres",
        "mysqld",
        "mariadbd",
        "redis-server",
        "memcached",
        "mongod",
        "vsftpd",
        "proftpd",
        "smbd",
        "named",
        "dovecot",
        "exim",
    }
)


def _basename(value: str | None) -> str | None:
    if not value:
        return None
    return value.rsplit("/", 1)[-1].strip() or None


def _is_shell(name: str | None) -> bool:
    return _basename(name) in SHELLS


def _is_interpreter(name: str | None) -> bool:
    base = _basename(name)
    return base in SHELLS or base in INTERPRETERS


class SuspiciousProcessExecutionRule(Rule):
    """An interactive shell spawned by a parent that should never spawn one.

    ``sshd -> bash`` is a login.  ``nginx -> bash`` or ``curl -> sh`` is the
    shape of a web shell or a download-and-run payload, and the parent/child
    pair is the whole signal.

    Args:
        shell_parents: Parent names that must not spawn shells.  Defaults to the
            download tools and network services above.
    """

    rule_id = "SUSPICIOUS_PROCESS_EXECUTION"
    name = "Shell Spawned By Unexpected Parent"
    description = "An interactive shell was started by a process that should not start one."
    severity = Severity.HIGH
    mitre = mapping("T1059.004")
    requires = ("parent_process",)

    def __init__(self, shell_parents: Iterable[str] | None = None) -> None:
        if shell_parents is None:
            self.download_parents = DOWNLOAD_TOOLS
            self.service_parents = NETWORK_SERVICES
        else:
            names = frozenset(shell_parents)
            self.download_parents = names & DOWNLOAD_TOOLS
            self.service_parents = names - DOWNLOAD_TOOLS
        self.shell_parents = self.download_parents | self.service_parents

    def evaluate(self, events: Sequence[SecurityEvent]) -> Iterable[Detection]:
        for event in events:
            if event.event_type != EventType.PROCESS_START:
                continue
            child = _basename(event.process) or _basename(event.executable)
            parent = _basename(event.parent_process)
            if not child or not parent:
                continue
            if not _is_shell(child) or parent not in self.shell_parents:
                continue
            yield self._detection(event, child, parent)

    def _detection(self, event: SecurityEvent, child: str, parent: str) -> Detection:
        if parent in self.download_parents:
            kind = "a download tool"
            factors = [
                RiskFactor(
                    10,
                    f"'{parent}' downloads remote content, so a shell started by it "
                    "suggests remote code was executed",
                )
            ]
        else:
            kind = "a network-facing service"
            factors = [
                RiskFactor(
                    10,
                    f"'{parent}' is a network-facing service, so a shell started by "
                    "it suggests remote command execution",
                )
            ]

        command = event.command_line or event.executable or child
        return Detection(
            dedup_key=f"{parent}->{child}",
            evidence=[event],
            description=(
                f"Shell '{child}' was spawned by {kind} ('{parent}'). Command: {command}"
            ),
            host=event.host,
            user=event.user,
            source_ip=event.src_ip,
            risk_factors=factors,
        )


class SuspiciousNetworkConnectionRule(Rule):
    """A shell or interpreter opening a connection to the internet.

    ``curl`` talking to the internet is its job.  ``bash`` or ``python`` doing
    it -- especially after something else spawned them -- is the shape of a
    reverse shell or a C2 callback.

    Args:
        allowed_ports: Destination ports that are too routine to report
            (nothing by default; tune per site).
    """

    rule_id = "SUSPICIOUS_NETWORK_CONNECTION"
    name = "Outbound Connection From A Shell"
    description = "An interactive shell or script interpreter connected to an external address."
    severity = Severity.MEDIUM
    mitre = mapping("T1071")
    requires = ("destination_ip",)

    def __init__(self, allowed_ports: Iterable[int] | None = None) -> None:
        self.allowed_ports = frozenset(allowed_ports or ())

    def unavailable_reason(self, events: Sequence[SecurityEvent]) -> str | None:
        if any(event.dst_ip for event in events):
            return None
        return (
            "requires network telemetry (destination_ip); start the eBPF network "
            "sensor with 'sentinelforge sensor start ebpf-network'"
        )

    def evaluate(self, events: Sequence[SecurityEvent]) -> Iterable[Detection]:
        for event in events:
            if event.event_type != EventType.NETWORK_CONNECTION:
                continue
            process = _basename(event.process)
            if not _is_interpreter(process):
                continue
            destination = event.dst_ip
            if not is_external_address(destination):
                continue
            port = event.dst_port
            if port is not None and int(port) in self.allowed_ports:
                continue
            yield self._detection(event, process, destination, port)

    def _detection(self, event, process, destination, port) -> Detection:
        factors = []
        if _basename(process) in SHELLS:
            factors.append(
                RiskFactor(
                    10,
                    f"'{process}' is an interactive shell, not a network client; an "
                    "outbound connection from it resembles a reverse shell",
                )
            )
        where = f"{destination}:{port}" if port else destination
        return Detection(
            dedup_key=f"{process}|{destination}",
            evidence=[event],
            description=(
                f"Interpreter '{process}' opened an outbound connection to {where}."
            ),
            host=event.host,
            user=event.user,
            source_ip=destination,
            risk_factors=factors,
        )
