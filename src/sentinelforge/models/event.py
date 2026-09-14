"""Normalized security event model.

Every log line collected by SentinelForge, regardless of where it came from,
ends up as a :class:`SecurityEvent`.  Keeping a single typed representation
means later phases (detection rules, correlation, AI enrichment) only ever
have to understand one shape of data.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


class Severity:
    """Allowed severity values.

    Plain string constants (rather than an ``enum``) keep the JSON output
    trivially serializable and easy to read for beginners.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    #: Ordered from least to most severe.  Order matters for --min-severity.
    ALL = (INFO, LOW, MEDIUM, HIGH, CRITICAL)

    @staticmethod
    def rank(severity: str) -> int:
        """Return the position of a severity in :attr:`ALL` (unknown -> 0)."""
        try:
            return Severity.ALL.index(severity)
        except ValueError:
            return 0

    @staticmethod
    def at_least(severity: str, minimum: str) -> bool:
        """Return ``True`` when ``severity`` is at least as severe as ``minimum``."""
        return Severity.rank(severity) >= Severity.rank(minimum)


class EventType:
    """Event classifications supported in Phase 1."""

    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHENTICATION_SUCCESS = "authentication_success"
    SUDO = "sudo"
    SSH_CONNECTION = "ssh_connection"
    PROCESS_START = "process_start"
    NETWORK_CONNECTION = "network_connection"
    SESSION_OPEN = "session_open"
    SESSION_CLOSE = "session_close"
    UNKNOWN = "unknown"

    ALL = (
        AUTHENTICATION_FAILURE,
        AUTHENTICATION_SUCCESS,
        SUDO,
        SSH_CONNECTION,
        PROCESS_START,
        NETWORK_CONNECTION,
        SESSION_OPEN,
        SESSION_CLOSE,
        UNKNOWN,
    )


# Field order used for JSON output, so every line of a .jsonl file looks the same.
FIELD_ORDER = (
    "timestamp",
    "host",
    "source",
    "event_type",
    "severity",
    "user",
    "src_ip",
    "process",
    "message",
    "raw",
    "metadata",
)

#: Fields omitted from serialized output when empty, for backwards compatibility.
OMIT_WHEN_EMPTY = ("metadata",)


def utc_now() -> str:
    """Return the current time as an RFC 3339 / ISO 8601 UTC string."""
    return format_timestamp(datetime.now(timezone.utc))


def format_timestamp(value: datetime) -> str:
    """Format a ``datetime`` as ``YYYY-MM-DDTHH:MM:SSZ`` in UTC.

    Naive datetimes are assumed to already be UTC; that is the safest
    assumption for log data of unknown origin and it never invents an offset.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_timestamp(value: str | None) -> datetime | None:
    """Parse an event timestamp back into an aware UTC ``datetime``.

    Detection rules need real datetimes to reason about time windows.  Returns
    ``None`` for missing or unparseable values so a single bad event can never
    break a rule.
    """
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _as_text(value: object) -> str:
    """Coerce an untrusted value to text without ever executing it."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return str(value)


@dataclass
class SecurityEvent:
    """A single normalized security-relevant event.

    Only ``timestamp``, ``host``, ``source``, ``event_type``, ``severity``,
    ``message`` and ``raw`` are always populated.  ``user``, ``src_ip`` and
    ``process`` stay ``None`` when the log line does not contain them -- we
    never invent values.
    """

    timestamp: str = field(default_factory=utc_now)
    host: str = "unknown"
    source: str = "unknown"
    event_type: str = EventType.UNKNOWN
    severity: str = Severity.INFO
    user: str | None = None
    src_ip: str | None = None
    process: str | None = None
    message: str = ""
    raw: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Defensive normalization: log data is untrusted input, so coerce the
        # required string fields instead of letting a weird value travel on.
        if self.event_type not in EventType.ALL:
            self.event_type = EventType.UNKNOWN
        if self.severity not in Severity.ALL:
            self.severity = Severity.INFO
        for name in ("host", "source", "message", "raw"):
            setattr(self, name, _as_text(getattr(self, name)))
        for name in ("user", "src_ip", "process"):
            value = getattr(self, name)
            if value is not None:
                setattr(self, name, _as_text(value) or None)
        if not isinstance(self.metadata, dict):
            self.metadata = {}

    def to_dict(self, include_empty: bool = True) -> dict:
        """Return the event as a plain dict with a stable key order.

        With ``include_empty=False`` the optional fields that are ``None`` are
        omitted entirely, which is handy for compact output.
        """
        data = asdict(self)
        ordered = {key: data[key] for key in FIELD_ORDER}
        for key in OMIT_WHEN_EMPTY:
            if not ordered.get(key):
                ordered.pop(key, None)
        if not include_empty:
            ordered = {k: v for k, v in ordered.items() if v is not None}
        return ordered

    def to_json(self, include_empty: bool = True) -> str:
        """Serialize the event to a single-line JSON string (one JSONL record)."""
        return json.dumps(
            self.to_dict(include_empty=include_empty),
            ensure_ascii=False,
            separators=(",", ":"),
        )

    # -- sensor metadata ---------------------------------------------------
    # Telemetry sensors (Phase 4) attach structured detail here.  Accessors
    # return None when a field was not available, so a rule can read
    # ``event.dst_port`` without knowing which sensor produced the event.
    def meta(self, key: str, default=None):
        """Read one metadata field, or ``default`` when the sensor had no value."""
        value = self.metadata.get(key, default) if isinstance(self.metadata, dict) else default
        return default if value is None else value

    @property
    def pid(self) -> int | None:
        return self.meta("pid")

    @property
    def ppid(self) -> int | None:
        return self.meta("ppid")

    @property
    def executable(self) -> str | None:
        return self.meta("executable")

    @property
    def parent_process(self) -> str | None:
        return self.meta("parent_process")

    @property
    def command_line(self) -> str | None:
        return self.meta("command_line")

    @property
    def dst_ip(self) -> str | None:
        return self.meta("destination_ip")

    @property
    def dst_port(self) -> int | None:
        return self.meta("destination_port")

    @property
    def protocol(self) -> str | None:
        return self.meta("protocol")

    @classmethod
    def from_dict(cls, data: dict) -> "SecurityEvent":
        """Rebuild an event from a dict, ignoring unknown keys."""
        known = {key: data[key] for key in FIELD_ORDER if key in data}
        return cls(**known)
