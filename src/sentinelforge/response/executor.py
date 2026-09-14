"""The only place in SentinelForge that runs an external program (Phase 7).

Phases 1-6 execute exactly one external command -- ``journalctl`` -- to read
logs.  Phase 7 adds containment, which means running ``firewall-cmd`` and
``loginctl``.  Concentrating that in one module makes the security property
auditable in a single file rather than argued about across a package.

The rules, all enforced below rather than documented and hoped for:

* **Argument arrays only.**  :func:`run` takes a list.  There is no string
  form, no ``shell=True``, no ``os.system``, and no ``shlex`` anywhere in
  SentinelForge -- so shell metacharacters in an argument are not "escaped",
  they are simply never given to a shell that could interpret them.
* **A fixed executable allowlist.**  ``argv[0]`` is a logical name
  (``"firewall-cmd"``), not a path.  It is resolved against a hard-coded table
  of absolute paths, so ``$PATH`` cannot redirect it to an attacker's binary.
* **A scrubbed environment.**  The child gets a minimal, fixed environment.
* **No stdin, bounded output, mandatory timeout.**  A hung firewall backend
  fails the action; it does not hang the dashboard.
* **No privilege escalation.**  ``sudo``, ``pkexec`` and ``su`` are not on the
  allowlist and never will be: SentinelForge does not escalate on its own
  behalf and never asks for a password.  When an action needs root, it says so
  and stops.
* **Reads and writes are separated.**  Every call says whether it changes
  system state, and a runner built with ``allow_mutation=False`` refuses the
  ones that do.  That is what lets a dashboard process report firewall
  capability and render an accurate preview while being structurally unable to
  install a rule.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time
from dataclasses import dataclass, field

LOGGER = logging.getLogger(__name__)

#: Logical name -> the absolute paths it may resolve to, in order of
#: preference.  ``$PATH`` is deliberately not consulted.
ALLOWED_EXECUTABLES: dict[str, tuple[str, ...]] = {
    "firewall-cmd": ("/usr/bin/firewall-cmd", "/bin/firewall-cmd", "/usr/sbin/firewall-cmd"),
    "loginctl": ("/usr/bin/loginctl", "/bin/loginctl"),
}

#: Directories a resolved executable must live in.  A root-owned system
#: location; never a user-writable one.
ALLOWED_DIRECTORIES = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")

#: Environment handed to every child process.
SAFE_ENVIRONMENT = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LC_ALL": "C",
    "LANG": "C",
}

#: Default seconds before a command is killed.
DEFAULT_TIMEOUT = 15.0

#: Output beyond this is truncated: a response result is a record, not a log.
MAX_OUTPUT = 8000


class ExecutionError(RuntimeError):
    """A command could not be run at all (not: ran and failed)."""


@dataclass(frozen=True)
class CommandResult:
    """What one external command did.

    ``returncode == 0`` is *not* treated as success by any caller: actions
    verify the resulting system state instead (see
    :mod:`sentinelforge.response.actions`).  This dataclass only reports facts.
    """

    argv: tuple[str, ...]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_ms: int = 0

    @property
    def ok(self) -> bool:
        """Whether the command itself completed with a zero exit code."""
        return self.returncode == 0 and not self.timed_out

    @property
    def permission_denied(self) -> bool:
        """Whether the failure looks like a privilege problem.

        Recognised by text because that is what the tools give us: firewalld
        answers a polkit refusal on stderr with a non-specific exit code.
        """
        haystack = f"{self.stderr}\n{self.stdout}".lower()
        markers = (
            "authorization failed",
            "not authorized",
            "permission denied",
            "must be root",
            "access denied",
            "interactive authentication required",
            "operation not permitted",
        )
        return any(marker in haystack for marker in markers)

    def to_dict(self) -> dict:
        return {
            "command": list(self.argv),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "duration_ms": self.duration_ms,
        }

    def describe(self) -> str:
        """A short human-readable failure line."""
        if self.timed_out:
            return f"{self.argv[0]} timed out"
        detail = (self.stderr or self.stdout or "").strip().splitlines()
        return f"{self.argv[0]} exited {self.returncode}" + (f": {detail[0]}" if detail else "")


def resolve_executable(name: str) -> str | None:
    """Return the absolute path for an allowlisted logical name, or ``None``.

    ``$PATH`` is never consulted: the candidate paths come from
    :data:`ALLOWED_EXECUTABLES`, and each one must be a real, executable file
    in a system directory before it is accepted.
    """
    for candidate in ALLOWED_EXECUTABLES.get(name, ()):
        directory = os.path.dirname(candidate)
        if directory not in ALLOWED_DIRECTORIES:  # pragma: no cover - table is fixed
            continue
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _check_argument(value: object, position: int) -> str:
    """Reject anything that is not a plain, single-line string."""
    if not isinstance(value, str):
        raise ExecutionError(
            f"command argument {position} is {type(value).__name__}, not a string"
        )
    if "\x00" in value:
        raise ExecutionError(f"command argument {position} contains a NUL byte")
    if "\n" in value or "\r" in value:
        raise ExecutionError(f"command argument {position} contains a newline")
    return value


@dataclass
class CommandRunner:
    """Runs allowlisted commands with a fixed, safe invocation.

    Args:
        allow_mutation: When ``False``, calls marked ``mutating=True`` raise
            :class:`ExecutionError` instead of starting a process, while
            read-only queries still work.  This is how "this process may look
            but not touch" becomes a runtime property rather than an intention.
        timeout: Seconds before a command is killed.

    Attributes:
        calls: Every argv this runner actually ran, for tests and diagnostics.
    """

    allow_mutation: bool = True
    timeout: float = DEFAULT_TIMEOUT
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def available(self, name: str) -> bool:
        """Whether an allowlisted program exists on this host."""
        return resolve_executable(name) is not None

    def run(
        self, argv: list[str], timeout: float | None = None, mutating: bool = False
    ) -> CommandResult:
        """Run ``argv`` and return its :class:`CommandResult`.

        Args:
            argv: ``[logical_name, arg, arg, ...]``.  Every element must be a
                plain single-line string; the first must be an allowlisted
                logical name.
            mutating: Whether this call changes system state.  Set by the
                backend that builds the command -- the one place that knows --
                and refused outright when this runner may not mutate.

        Raises:
            ExecutionError: The command would change state in a runner that may
                not, the program is not allowlisted or not installed, or an
                argument is not a usable string.  A command that runs and
                *fails* is not an error here: it comes back as a
                :class:`CommandResult` with a non-zero exit code, so the caller
                can report it faithfully.
        """
        if not isinstance(argv, (list, tuple)) or not argv:
            raise ExecutionError("a command must be a non-empty list of arguments")
        name = _check_argument(argv[0], 0)
        arguments = [_check_argument(value, index + 1) for index, value in enumerate(argv[1:])]
        if name not in ALLOWED_EXECUTABLES:
            raise ExecutionError(
                f"{name!r} is not an allowlisted response command "
                f"(allowed: {', '.join(sorted(ALLOWED_EXECUTABLES))})"
            )
        if mutating and not self.allow_mutation:
            raise ExecutionError(
                "this SentinelForge process is not permitted to change system state "
                "(response execution is disabled here)"
            )
        path = resolve_executable(name)
        if path is None:
            raise ExecutionError(f"{name} is not installed on this host")

        command = [path, *arguments]
        self.calls.append(tuple(command))
        LOGGER.info("response executor running: %s", " ".join(command))
        started = time.monotonic()
        try:
            completed = subprocess.run(  # noqa: S603 - fixed path, list argv, no shell
                command,
                shell=False,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout or self.timeout,
                env=dict(SAFE_ENVIRONMENT),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                argv=tuple(command),
                returncode=-1,
                stdout=(exc.stdout or "")[:MAX_OUTPUT] if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "")[:MAX_OUTPUT] if isinstance(exc.stderr, str) else "",
                timed_out=True,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        except OSError as exc:
            raise ExecutionError(f"could not run {name}: {exc}") from exc
        return CommandResult(
            argv=tuple(command),
            returncode=completed.returncode,
            stdout=(completed.stdout or "")[:MAX_OUTPUT],
            stderr=(completed.stderr or "")[:MAX_OUTPUT],
            duration_ms=int((time.monotonic() - started) * 1000),
        )


class ReadOnlyCommandRunner(CommandRunner):
    """A runner that can query but never change anything.

    Used wherever a component must be able to *describe* what it would do
    without being able to do it: previews, dry runs, and any dashboard process
    started with response execution turned off.
    """

    def __init__(self) -> None:
        super().__init__(allow_mutation=False)


def is_root() -> bool:
    """Whether this process already has the privileges containment needs.

    SentinelForge never acquires them: it reports what is missing and leaves
    the decision -- and the ``sudo`` -- to the operator.
    """
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover - non-POSIX
        return False
