"""eBPF availability probing, privilege reporting and program loading.

Everything that can differ between machines is decided here, once, so the two
sensors stay small.  The rules this module follows:

* **Never escalate privileges.**  If eBPF needs root, say so and print the
  command for the *user* to run.  SentinelForge never calls ``sudo`` itself.
* **Never weaken the system.**  No sysctl changes, no SELinux changes, no sudo
  configuration, no kernel parameters.  We only look.
* **Never pretend.**  When eBPF is unavailable the sensor raises; nothing
  silently substitutes synthetic data.
"""

from __future__ import annotations

import glob
import os
import platform
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from ..base import SensorUnavailableError

#: Capability bits that allow loading BPF programs and attaching probes.
CAP_SYS_ADMIN = 21
CAP_PERFMON = 38
CAP_BPF = 39

#: BCC and the probes used here need a reasonably modern kernel.
MINIMUM_KERNEL = (4, 18)

INSTALL_HINT = (
    "Install the eBPF tooling (Fedora):\n"
    "    sudo dnf install bcc bcc-tools python3-bcc kernel-devel-$(uname -r)\n"
    "The Python bindings are packaged as 'python3-bcc' on current Fedora; if that\n"
    "name does not exist on your release, find it with:\n"
    "    dnf provides '*/site-packages/bcc/__init__.py'"
)

#: BCC ships as a distro package (it is not installable with pip), so a plain
#: virtualenv cannot see it.  That is the most common reason the import fails on
#: an otherwise perfectly capable Fedora machine.
VENV_HINT = (
    "BCC is installed system-wide at {path}, but this virtual environment cannot\n"
    "see it. BCC is a distro package and cannot be pip-installed, so either:\n"
    "    1. recreate the environment with access to system packages:\n"
    "         python3 -m venv --system-site-packages .venv\n"
    "         .venv/bin/pip install -e .\n"
    "    2. or run SentinelForge with the system interpreter:\n"
    "         sudo python3 -m sentinelforge.cli sensor start ebpf-process"
)


def system_bcc_path() -> str | None:
    """Find a system-wide BCC installation this interpreter cannot import."""
    patterns = (
        "/usr/lib/python3*/site-packages/bcc/__init__.py",
        "/usr/lib64/python3*/site-packages/bcc/__init__.py",
        "/usr/local/lib/python3*/site-packages/bcc/__init__.py",
    )
    for pattern in patterns:
        for match in sorted(glob.glob(pattern)):
            return os.path.dirname(match)
    return None


def in_virtualenv() -> bool:
    """True when running inside a virtual environment."""
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def _read(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read().strip()
    except OSError:
        return None


def kernel_version() -> tuple[int, ...]:
    """Return the running kernel version as a tuple, e.g. ``(6, 11, 3)``."""
    release = platform.release().split("-")[0]
    parts = []
    for piece in release.split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        if not digits:
            break
        parts.append(int(digits))
    return tuple(parts) or (0,)


def effective_capabilities() -> int:
    """Read this process's effective capability bitmask from ``/proc``."""
    status = _read("/proc/self/status") or ""
    for line in status.splitlines():
        if line.startswith("CapEff:"):
            try:
                return int(line.split()[1], 16)
            except (IndexError, ValueError):  # pragma: no cover - defensive
                return 0
    return 0


def has_bpf_privileges() -> bool:
    """True when this process may load BPF programs and attach probes."""
    if os.geteuid() == 0:
        return True
    caps = effective_capabilities()
    has_bpf = bool(caps & (1 << CAP_BPF)) and bool(caps & (1 << CAP_PERFMON))
    return has_bpf or bool(caps & (1 << CAP_SYS_ADMIN))


@lru_cache(maxsize=1)
def bcc_version() -> str | None:
    """Return the installed BCC version, or ``None`` when BCC is not importable."""
    try:
        import bcc  # noqa: F401  (import is the probe)
    except Exception:
        return None
    return getattr(bcc, "__version__", "unknown")


def privilege_remedy(command: str | None = None) -> str:
    """Explain, without doing anything, how to run a sensor with enough rights."""
    command = command or "sentinelforge sensor start ebpf-process"
    return (
        "eBPF needs elevated privileges on this system.\n"
        "Run the sensor yourself with, for example:\n"
        f"    sudo {command}\n"
        "\n"
        "Why: loading a BPF program and attaching it to kernel tracepoints requires\n"
        "root, or the CAP_BPF + CAP_PERFMON capabilities. That is a genuine privilege:\n"
        "a BPF program can read kernel memory, so only grant it to code you trust.\n"
        "SentinelForge will not call sudo for you, and will not change sysctl,\n"
        "SELinux or sudo configuration to make this easier."
    )


@dataclass
class EbpfSupport:
    """The result of probing this machine for eBPF support."""

    supported: bool
    reasons: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    remedy: str | None = None

    @property
    def reason(self) -> str | None:
        return "; ".join(self.reasons) if self.reasons else None

    def to_dict(self) -> dict:
        return {
            "supported": self.supported,
            "reasons": list(self.reasons),
            "details": dict(self.details),
        }


def check_ebpf_support(require_privileges: bool = True) -> EbpfSupport:
    """Probe kernel support, tooling and privileges.  Read-only; changes nothing.

    Args:
        require_privileges: Include the privilege check.  Pass ``False`` to ask
            "could this machine do eBPF at all, given the right rights?".
    """
    reasons: list[str] = []
    remedy: str | None = None

    version = kernel_version()
    btf = os.path.exists("/sys/kernel/btf/vmlinux")
    bpffs = os.path.isdir("/sys/fs/bpf")
    config = _read(f"/boot/config-{platform.release()}") or ""
    bpf_syscall = "CONFIG_BPF_SYSCALL=y" in config if config else None
    unprivileged = _read("/proc/sys/kernel/unprivileged_bpf_disabled")
    privileged = has_bpf_privileges()
    bcc = bcc_version()

    details = {
        "kernel": platform.release(),
        "kernel_version": ".".join(str(part) for part in version),
        "bcc_version": bcc,
        "btf": btf,
        "bpffs": bpffs,
        "config_bpf_syscall": bpf_syscall,
        "unprivileged_bpf_disabled": unprivileged,
        "euid": os.geteuid(),
        "has_bpf_privileges": privileged,
    }

    if bcc is None:
        system_bcc = system_bcc_path()
        if system_bcc and in_virtualenv():
            reasons.append(
                "the BCC Python bindings are installed system-wide but are not "
                "importable from this virtual environment"
            )
            remedy = VENV_HINT.format(path=system_bcc)
            details["system_bcc_path"] = system_bcc
        else:
            reasons.append("the BCC Python bindings (module 'bcc') are not installed")
            remedy = INSTALL_HINT
    if version < MINIMUM_KERNEL:
        reasons.append(
            f"kernel {details['kernel']} is older than the required "
            f"{'.'.join(str(part) for part in MINIMUM_KERNEL)}"
        )
    if bpf_syscall is False:
        reasons.append("this kernel was built without CONFIG_BPF_SYSCALL")
    if require_privileges and not privileged:
        reasons.append(
            "insufficient privileges: need root, or CAP_BPF and CAP_PERFMON"
            + (
                " (unprivileged BPF is disabled by sysctl "
                f"kernel.unprivileged_bpf_disabled={unprivileged})"
                if unprivileged and unprivileged != "0"
                else ""
            )
        )
        remedy = remedy or privilege_remedy()

    return EbpfSupport(
        supported=not reasons, reasons=reasons, details=details, remedy=remedy
    )


def require_ebpf(command: str | None = None) -> None:
    """Raise :class:`SensorUnavailableError` unless eBPF can actually run here."""
    support = check_ebpf_support()
    if support.supported:
        return
    remedy = support.remedy
    if remedy and command and "sentinelforge sensor start" in remedy:
        remedy = privilege_remedy(command)
    raise SensorUnavailableError(support.reason or "eBPF is unavailable", remedy)


def load_bpf(program: str, cflags: list[str] | None = None):
    """Compile and load a BPF program, mapping every failure to a clear error.

    Returns:
        The ``bcc.BPF`` object.

    Raises:
        SensorUnavailableError: tooling, kernel support or privileges missing,
            or the program failed to compile or load.
    """
    require_ebpf()
    try:
        from bcc import BPF
    except Exception as exc:  # pragma: no cover - covered by require_ebpf
        raise SensorUnavailableError(
            f"cannot import the BCC Python bindings: {exc}", INSTALL_HINT
        ) from exc

    try:
        return BPF(text=program, cflags=cflags or [])
    except PermissionError as exc:
        raise SensorUnavailableError(
            f"permission denied loading the BPF program: {exc}", privilege_remedy()
        ) from exc
    except Exception as exc:
        message = str(exc) or type(exc).__name__
        remedy = None
        lowered = message.lower()
        if "permission" in lowered or "operation not permitted" in lowered:
            remedy = privilege_remedy()
        elif "failed to compile" in lowered or "include" in lowered:
            remedy = (
                "The BPF program failed to compile. Kernel headers are usually missing:\n"
                "    sudo dnf install kernel-devel-$(uname -r) bcc-tools"
            )
        raise SensorUnavailableError(f"cannot load the BPF program: {message}", remedy) from exc


class BootClock:
    """Converts kernel monotonic timestamps (``bpf_ktime_get_ns``) to wall clock.

    The offset is sampled once when the sensor starts; that is accurate enough
    for event ordering and for correlating with log timestamps.
    """

    def __init__(self) -> None:
        self.sampled_at = datetime.now(timezone.utc)
        try:
            self.monotonic_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        except (AttributeError, OSError):  # pragma: no cover - non-Linux
            self.monotonic_ns = int(time.monotonic() * 1_000_000_000)

    def to_datetime(self, ktime_ns: int | None) -> datetime:
        """Map a kernel monotonic nanosecond stamp to a UTC datetime."""
        if not ktime_ns:
            return datetime.now(timezone.utc)
        delta_ns = int(ktime_ns) - self.monotonic_ns
        return self.sampled_at + timedelta(microseconds=delta_ns / 1000)
