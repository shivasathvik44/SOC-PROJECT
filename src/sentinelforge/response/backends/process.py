"""Process containment backend (Phase 7).

Terminating a process is the most irreversible thing SentinelForge can do, so
this backend is built around three habits:

**Read ``/proc`` directly.**  Metadata comes from the kernel's own filesystem,
not from parsing ``ps`` output.  That is faster, gives exact fields, and means
the only external program involved in killing a process is none at all -- the
signal goes through :func:`os.kill`.

**Record the target before touching it.**  The command line, executable, owner
and start time are captured *first* and stored on the action, so the audit
trail says what was actually killed even though the process no longer exists to
be asked.  A recorded command line is evidence for a human to read; nothing in
SentinelForge ever executes one.

**SIGTERM, then tell the truth.**  The process is asked to exit and given a
grace period.  If it is still alive afterwards, that is reported as a failed
containment.  There is no automatic escalation to ``SIGKILL``: escalating is a
second decision, and a second decision belongs to the analyst, who can request
a new action.

PID reuse is handled explicitly.  Linux recycles PIDs, so "did it die?" is
answered by comparing the process's *start time* with the one recorded before
the signal -- a PID that now belongs to a different, younger process counts as
terminated, and is never mistaken for a survivor that needs another signal.
"""

from __future__ import annotations

import errno
import logging
import os
import signal
import time
from dataclasses import dataclass, field

from ..models import ActionOutcome
from ..validators import ValidationError, validate_pid
from .base import BackendStatus

LOGGER = logging.getLogger(__name__)

#: Seconds to wait for a process to exit after SIGTERM before reporting that
#: it survived.  Long enough for an ordinary shutdown handler, short enough
#: that an analyst is not left staring at a spinner.
DEFAULT_GRACE_SECONDS = 5.0

#: How often to re-check while waiting.
POLL_INTERVAL = 0.15

#: Longest command line kept for the audit record.
MAX_CMDLINE = 2000


@dataclass(frozen=True)
class ProcessInfo:
    """A snapshot of one process, taken before anything is done to it.

    Attributes:
        start_ticks: The process's start time in clock ticks since boot
            (``/proc/<pid>/stat`` field 22).  Together with the PID this is a
            stable identity that survives nothing -- which is exactly the
            point: if it changes, the original process is gone.
        command_line: The process's argv, joined for display.  **Data, never a
            command.**  It is stored, rendered and audited; it is never run.
        kernel_thread: Kernel threads have no executable and cannot be
            meaningfully terminated by an analyst.
    """

    pid: int
    ppid: int | None = None
    name: str | None = None
    executable: str | None = None
    command_line: str | None = None
    uid: int | None = None
    username: str | None = None
    state: str | None = None
    start_ticks: int | None = None
    start_time: str | None = None
    kernel_thread: bool = False
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "executable": self.executable,
            "command_line": self.command_line,
            "uid": self.uid,
            "username": self.username,
            "state": self.state,
            "start_ticks": self.start_ticks,
            "start_time": self.start_time,
            "kernel_thread": self.kernel_thread,
        }

    def describe(self) -> str:
        """One line naming the process, for a confirmation prompt."""
        owner = self.username or (f"uid {self.uid}" if self.uid is not None else "unknown owner")
        return f"pid {self.pid} ({self.name or '?'}) owned by {owner}"


class ProcessBackend:
    """Interface every process backend implements."""

    name = "process"

    def status(self) -> BackendStatus:  # pragma: no cover - abstract
        raise NotImplementedError

    def get_process(self, pid: int) -> ProcessInfo | None:  # pragma: no cover - abstract
        raise NotImplementedError

    def validate_target(self, pid) -> ProcessInfo:  # pragma: no cover - abstract
        raise NotImplementedError

    def terminate(self, pid: int, grace_seconds: float = DEFAULT_GRACE_SECONDS) -> ActionOutcome:  # pragma: no cover - abstract
        raise NotImplementedError

    def verify_terminated(self, pid: int, start_ticks: int | None = None) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError


class LinuxProcessBackend(ProcessBackend):
    """Reads ``/proc`` and sends signals with :func:`os.kill`.

    Args:
        proc: Root of the proc filesystem.  Tests point this at a fixture
            directory so no real process is ever inspected or signalled.
        signal_sender: Injection point for :func:`os.kill`.  Tests replace it;
            production never does.
        allow_mutation: When ``False`` the backend can inspect processes but
            refuses to signal any, which is what a dashboard with response
            execution turned off runs with.
    """

    name = "linux-signals"

    def __init__(
        self,
        proc: str = "/proc",
        signal_sender=None,
        allow_mutation: bool = True,
        clock_ticks: int | None = None,
    ) -> None:
        self.proc = proc
        self.allow_mutation = allow_mutation
        self._send = signal_sender or os.kill
        self._ticks = clock_ticks or _clock_ticks()

    # -- availability ------------------------------------------------------
    def status(self) -> BackendStatus:
        if not os.path.isdir(self.proc):
            return BackendStatus(
                name=self.name,
                available=False,
                reason=f"{self.proc} is not present: this is not a Linux host",
                remedy="Process containment requires the Linux proc filesystem.",
            )
        return BackendStatus(
            name=self.name,
            available=True,
            requires_privilege=False,
            details={
                "signal": "SIGTERM (never escalated automatically)",
                "grace_seconds": DEFAULT_GRACE_SECONDS,
                "note": "terminating a process owned by another user requires root",
            },
        )

    # -- reads -------------------------------------------------------------
    def get_process(self, pid: int) -> ProcessInfo | None:
        """Snapshot one process, or ``None`` if it does not exist.

        Every field is read defensively: ``/proc`` entries vanish mid-read when
        a process exits, and that must produce "gone", never a traceback.
        """
        pid = validate_pid(pid)
        base = os.path.join(self.proc, str(pid))
        if not os.path.isdir(base):
            return None
        stat_fields = self._read_stat(base)
        status = self._read_status(base)
        command_line = self._read_cmdline(base)
        executable = None
        try:
            executable = os.readlink(os.path.join(base, "exe"))
        except OSError:
            # Kernel threads have no exe link; so do processes we may not
            # inspect.  Both are reported honestly rather than guessed at.
            executable = None
        uid = status.get("uid")
        start_ticks = stat_fields.get("start_ticks")
        return ProcessInfo(
            pid=pid,
            ppid=stat_fields.get("ppid"),
            name=status.get("name") or stat_fields.get("name"),
            executable=executable,
            command_line=command_line,
            uid=uid,
            username=_username(uid),
            state=stat_fields.get("state"),
            start_ticks=start_ticks,
            start_time=self._boot_relative_time(start_ticks),
            kernel_thread=executable is None and not command_line,
            details={"threads": status.get("threads")},
        )

    def validate_target(self, pid) -> ProcessInfo:
        """Resolve a PID to a live process.

        Raises:
            ValidationError: The PID is malformed or no such process exists.
        """
        pid = validate_pid(pid)
        info = self.get_process(pid)
        if info is None:
            raise ValidationError(f"no process with PID {pid} is running", "target")
        return info

    def verify_terminated(self, pid: int, start_ticks: int | None = None) -> bool:
        """Whether the process identified by ``pid``+``start_ticks`` is gone.

        Comparing the start time is what makes this safe against PID reuse: a
        recycled PID belongs to a different process, and a different process is
        not the one that was contained.
        """
        pid = validate_pid(pid)
        info = self.get_process(pid)
        if info is None:
            return True
        if start_ticks is not None and info.start_ticks != start_ticks:
            return True
        # A zombie has already exited; it lingers only until its parent reaps it.
        return info.state == "Z"

    # -- mutation ----------------------------------------------------------
    def terminate(self, pid: int, grace_seconds: float = DEFAULT_GRACE_SECONDS) -> ActionOutcome:
        """Send ``SIGTERM`` and report what happened.

        Never escalates.  A process that ignores the signal comes back as a
        failure with the reason, so the analyst decides what to do next.
        """
        pid = validate_pid(pid)
        info = self.get_process(pid)
        if info is None:
            return ActionOutcome(
                ok=False,
                detail=f"no process with PID {pid} is running",
                error="the target process does not exist (it may already have exited)",
            )
        if not self.allow_mutation:
            return ActionOutcome(
                ok=False,
                detail="this SentinelForge process is not permitted to signal processes",
                error="process termination is disabled in this process",
            )

        try:
            self._send(pid, signal.SIGTERM)
        except PermissionError:
            return ActionOutcome(
                ok=False,
                detail=f"not permitted to signal {info.describe()}",
                data={"process": info.to_dict()},
                error="permission denied: terminating a process owned by another user "
                "requires root. Re-run the approved action with the necessary "
                "privileges (for example: sudo sentinelforge response execute <ACTION-ID>).",
            )
        except ProcessLookupError:
            return ActionOutcome(
                ok=True,
                detail=f"pid {pid} had already exited",
                data={"process": info.to_dict(), "signal": "SIGTERM", "already_gone": True},
            )
        except OSError as exc:  # pragma: no cover - defensive
            return ActionOutcome(
                ok=False,
                detail=f"could not signal pid {pid}",
                data={"process": info.to_dict()},
                error=f"{errno.errorcode.get(exc.errno, exc.errno)}: {exc}",
            )

        deadline = time.monotonic() + max(0.0, grace_seconds)
        while True:
            if self.verify_terminated(pid, info.start_ticks):
                return ActionOutcome(
                    ok=True,
                    detail=f"{info.describe()} terminated after SIGTERM",
                    data={
                        "process": info.to_dict(),
                        "signal": "SIGTERM",
                        "escalated": False,
                    },
                )
            if time.monotonic() >= deadline:
                break
            time.sleep(POLL_INTERVAL)

        return ActionOutcome(
            ok=False,
            detail=f"{info.describe()} is still running {grace_seconds:g}s after SIGTERM",
            data={"process": info.to_dict(), "signal": "SIGTERM", "escalated": False},
            error=(
                "the process did not exit after SIGTERM. SentinelForge does not escalate "
                "to SIGKILL on its own: decide whether that is appropriate and, if it is, "
                "send it yourself."
            ),
        )

    # -- /proc parsing -----------------------------------------------------
    def _read_stat(self, base: str) -> dict:
        """Parse ``/proc/<pid>/stat``.

        The process name sits in parentheses and may itself contain spaces and
        parentheses, so the line is split at the *last* ``)`` rather than by
        whitespace -- the classic way to read this file correctly.
        """
        try:
            with open(os.path.join(base, "stat"), "r", encoding="utf-8", errors="replace") as fh:
                line = fh.read()
        except OSError:
            return {}
        end = line.rfind(")")
        if end == -1:
            return {}
        start = line.find("(")
        name = line[start + 1 : end] if start != -1 else None
        fields = line[end + 2 :].split()
        if len(fields) < 20:
            return {"name": name}
        try:
            return {
                "name": name,
                "state": fields[0],
                "ppid": int(fields[1]),
                "start_ticks": int(fields[19]),
            }
        except (ValueError, IndexError):  # pragma: no cover - malformed stat
            return {"name": name}

    def _read_status(self, base: str) -> dict:
        try:
            with open(os.path.join(base, "status"), "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except OSError:
            return {}
        status: dict = {}
        for line in lines:
            key, _, value = line.partition(":")
            value = value.strip()
            if key == "Name":
                status["name"] = value
            elif key == "Uid":
                parts = value.split()
                if parts and parts[0].isdigit():
                    status["uid"] = int(parts[0])
            elif key == "Threads" and value.isdigit():
                status["threads"] = int(value)
        return status

    def _read_cmdline(self, base: str) -> str | None:
        """Read argv as text.  Stored for a human to read; never executed."""
        try:
            with open(os.path.join(base, "cmdline"), "rb") as fh:
                raw = fh.read(MAX_CMDLINE * 2)
        except OSError:
            return None
        if not raw:
            return None
        text = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace")
        # An argv element can contain newlines and control characters; this
        # string is only ever displayed, so collapse it to one readable line.
        text = "".join(ch if ch.isprintable() else " " for ch in text)
        return " ".join(text.split())[:MAX_CMDLINE] or None

    def _boot_relative_time(self, start_ticks: int | None) -> str | None:
        """Turn ``start_ticks`` into a wall-clock timestamp, best effort."""
        if start_ticks is None:
            return None
        try:
            with open(os.path.join(self.proc, "uptime"), "r", encoding="utf-8") as fh:
                uptime = float(fh.read().split()[0])
        except (OSError, ValueError, IndexError):
            return None
        from datetime import datetime, timedelta, timezone

        from ...models.event import format_timestamp

        age = uptime - (start_ticks / self._ticks)
        if age < 0:  # pragma: no cover - clock skew
            return None
        return format_timestamp(datetime.now(timezone.utc) - timedelta(seconds=age))


def _clock_ticks() -> int:
    try:
        return int(os.sysconf("SC_CLK_TCK")) or 100
    except (ValueError, OSError, AttributeError):  # pragma: no cover - non-POSIX
        return 100


def _username(uid: int | None) -> str | None:
    if uid is None:
        return None
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):  # pragma: no cover - uid without a passwd entry
        return None
