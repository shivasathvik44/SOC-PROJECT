"""eBPF network-connection sensor.

Attaches to ``tcp_v4_connect`` / ``tcp_v6_connect`` and reports outbound TCP
connections with the process that made them -- the link between "a process ran"
and "something left this machine" that no auth log contains.

Deliberately limited:

* **Connection metadata only.**  Addresses, ports, protocol, PID, UID.
* **No payloads, ever.**  No packet capture, no deep packet inspection, no TLS
  interception.  The BPF programs below read socket fields and nothing else.
* **Connect events, not packets.**  One event per connection attempt, so the
  volume stays tiny compared with per-packet tracing.

Implementation note: this uses the ``sock:inet_sock_set_state`` tracepoint
rather than kprobes on ``tcp_v4_connect``.  The tracepoint carries the addresses
and ports as its own arguments, so the program needs no kernel struct headers --
which matters, because ``#include <net/sock.h>`` does not compile against
current Fedora kernel headers (``socket_lock_t`` has changed shape).  The cost
is that BCC must read ``/sys/kernel/tracing/events/...`` to build the argument
struct, so this program needs root even to compile; that is the same privilege
needed to attach it.  The decoder below is pure Python and is unit-tested
against synthetic records without any kernel involvement.
"""

from __future__ import annotations

import logging
import socket
from types import SimpleNamespace
from typing import Iterator

from ...models.event import EventType, SecurityEvent, Severity, format_timestamp
from ..base import Sensor, SensorStatus, SensorUnavailableError
from .loader import BootClock, check_ebpf_support, load_bpf, privilege_remedy
from .process import _int, _text, resolve_user

LOGGER = logging.getLogger(__name__)

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

#define AF_INET  2
#define AF_INET6 10

/* TCP state numbers from include/net/tcp_states.h */
#define TCP_SYN_SENT 2
#define TCP_CLOSE    7

#define IPPROTO_TCP 6

struct connect_event_t {
    u64 ts;
    u32 pid;
    u32 uid;
    u16 family;
    u16 sport;
    u16 dport;
    u8  saddr[16];
    u8  daddr[16];
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(connect_events);
BPF_PERCPU_ARRAY(scratch, struct connect_event_t, 1);

/*
 * sock:inet_sock_set_state fires on every TCP state change.  The transition
 * CLOSE -> SYN_SENT is exactly "this process is opening an outbound
 * connection", which keeps the event volume to one record per connection.
 */
TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    if (args->protocol != IPPROTO_TCP)
        return 0;
    if (args->oldstate != TCP_CLOSE || args->newstate != TCP_SYN_SENT)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
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

    u32 zero = 0;
    struct connect_event_t *data = scratch.lookup(&zero);
    if (data == 0)
        return 0;

    __builtin_memset(data->saddr, 0, sizeof(data->saddr));
    __builtin_memset(data->daddr, 0, sizeof(data->daddr));

    data->ts = bpf_ktime_get_ns();
    data->pid = pid;
    data->uid = uid;
    data->family = args->family;
    data->sport = args->sport;
    data->dport = args->dport;

    if (args->family == AF_INET) {
        __builtin_memcpy(data->saddr, args->saddr, 4);
        __builtin_memcpy(data->daddr, args->daddr, 4);
    } else {
        __builtin_memcpy(data->saddr, args->saddr_v6, 16);
        __builtin_memcpy(data->daddr, args->daddr_v6, 16);
    }

    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    connect_events.perf_submit(args, data, sizeof(*data));
    return 0;
}
"""

#: Address families as the tracepoint reports them.
AF_INET = 2
AF_INET6 = 10


def _packed(value, length: int) -> bytes | None:
    """Normalize an address field (bytes, ctypes array, or int) to raw bytes."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        packed = bytes(value)
    elif isinstance(value, int):
        try:
            packed = int(value).to_bytes(16, "little")
        except (OverflowError, ValueError):
            return None
    else:
        try:  # a ctypes u8 array
            packed = bytes(bytearray(value))
        except (TypeError, ValueError):
            return None
    return packed[:length] if len(packed) >= length else None


def format_ipv4(value) -> str | None:
    """Format a 4-byte address as a dotted quad."""
    packed = _packed(value, 4)
    if packed is None:
        return None
    try:
        return socket.inet_ntop(socket.AF_INET, packed)
    except (OSError, ValueError):
        return None


def format_ipv6(value) -> str | None:
    """Format a 16-byte address as a compressed IPv6 string."""
    packed = _packed(value, 16)
    if packed is None:
        return None
    try:
        return socket.inet_ntop(socket.AF_INET6, packed)
    except (OSError, ValueError):
        return None


def decode_network_event(
    raw,
    ip_version: int = 4,
    host: str = "unknown",
    source: str = "ebpf",
    clock: BootClock | None = None,
    user_lookup=None,
) -> SecurityEvent:
    """Turn one raw kernel connect record into a normalized event."""
    family = getattr(raw, "family", None)
    if family is not None:
        ip_version = 6 if int(family) == AF_INET6 else 4
    formatter = format_ipv4 if ip_version == 4 else format_ipv6
    destination = formatter(getattr(raw, "daddr", None))
    origin = formatter(getattr(raw, "saddr", None))
    dport = _int(getattr(raw, "dport", None))
    sport = _int(getattr(raw, "sport", None))
    process = _text(getattr(raw, "comm", None))

    uid = getattr(raw, "uid", None)
    user = user_lookup(uid) if (user_lookup is not None and uid is not None) else None

    timestamp = None
    if clock is not None:
        timestamp = format_timestamp(clock.to_datetime(getattr(raw, "ts", None)))

    metadata = {
        "pid": _int(getattr(raw, "pid", None)),
        "uid": _int(uid),
        "source_ip": origin,
        "source_port": sport,
        "destination_ip": destination,
        "destination_port": dport,
        "protocol": "tcp",
        "ip_version": ip_version,
        "direction": "outbound",
        "process_name": process,
    }

    target = f"{destination}:{dport}" if destination else "an unknown address"
    message = f"{process or 'a process'} connected to {target} (tcp)"
    event = SecurityEvent(
        host=host,
        source=source,
        event_type=EventType.NETWORK_CONNECTION,
        severity=Severity.INFO,
        user=user,
        src_ip=origin,
        process=process,
        message=message,
        raw=message,
        metadata={key: value for key, value in metadata.items() if value is not None},
    )
    if timestamp:
        event.timestamp = timestamp
    return event


class EbpfNetworkSensor(Sensor):
    """Reports outbound TCP connections with the process that opened them.

    Args:
        uid: Only report connections by this UID (kernel-side filter).
        poll_timeout_ms: Perf-buffer poll interval; also the stop latency.
    """

    name = "ebpf-network"
    description = "Outbound TCP connections with owning process, via eBPF"
    source = "ebpf"

    def __init__(
        self,
        uid: int | None = None,
        poll_timeout_ms: int = 200,
        host: str | None = None,
    ) -> None:
        super().__init__(host=host)
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
        import os

        flags = [f"-DSELF_PID={os.getpid()}"]
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
        self._bpf = load_bpf(BPF_PROGRAM, self.cflags())
        self._bpf["connect_events"].open_perf_buffer(
            self._handle_event, page_cnt=64, lost_cb=self._handle_lost
        )
        super().start()
        LOGGER.info("eBPF network sensor attached (sock:inet_sock_set_state)")

    def stop(self) -> None:
        super().stop()
        if self._bpf is not None:
            try:
                self._bpf.cleanup()
            except Exception as exc:  # pragma: no cover - best effort detach
                LOGGER.warning("error detaching eBPF network sensor: %s", exc)
            self._bpf = None
        self._queue.clear()

    def _handle_event(self, cpu, data, size) -> None:
        # Reading the perf record is fallible too; keep it inside the guard.
        try:
            raw = self._bpf["connect_events"].event(data)
            event = decode_network_event(
                raw,
                host=self.host,
                source=self.source,
                clock=self._clock,
                user_lookup=resolve_user,
            )
        except Exception as exc:  # a malformed record must not kill the sensor
            LOGGER.warning("skipping unreadable connect record: %s", exc)
            return
        self.events_seen += 1
        self._queue.append(event)

    def _handle_lost(self, count) -> None:
        self.events_dropped += int(count)
        LOGGER.warning("eBPF network sensor: kernel dropped %s event(s)", count)

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
    """Build a raw connect record stand-in for tests (no kernel required)."""
    record = SimpleNamespace(
        ts=0,
        pid=4101,
        uid=1000,
        family=AF_INET,
        saddr=socket.inet_aton("192.168.1.20") + b"\x00" * 12,
        daddr=socket.inet_aton("198.51.100.9") + b"\x00" * 12,
        sport=51234,
        dport=443,
        comm=b"curl\x00",
    )
    for key, value in overrides.items():
        setattr(record, key, value)
    return record
