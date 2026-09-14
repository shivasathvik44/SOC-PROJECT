"""Raw (pre-normalization) log record.

Collectors do as little interpretation as possible: they read a log source and
emit :class:`RawRecord` objects.  The normalization pipeline is the only place
that decides what an event *means*.  That split keeps collectors simple and
lets new sources be added without touching the parsers.
"""

from __future__ import annotations

from dataclasses import dataclass


def _clean(value: object) -> str:
    """Coerce untrusted log data to a safe, single-line-ish string.

    Log content is attacker-influenced, so we only ever *sanitize* it -- NUL
    bytes are removed because they break downstream tooling.  The text itself
    is never interpreted, executed, or evaluated.
    """
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    elif not isinstance(value, str):
        value = str(value)
    return value.replace("\x00", "").strip()


@dataclass
class RawRecord:
    """One log line plus whatever metadata the source already knew.

    Attributes:
        message: The human-readable log text (journal ``MESSAGE`` field, or the
            part of a syslog line after ``process[pid]:``).
        raw: The original, unmodified line / JSON blob from the source.
        source: Short source identifier, e.g. ``systemd-journal`` or the file path.
        host: Hostname reported by the source, if any.
        process: Program name reported by the source, if any.
        timestamp: RFC 3339 UTC timestamp string, if the source provided one.
    """

    message: str = ""
    raw: str = ""
    source: str = "unknown"
    host: str | None = None
    process: str | None = None
    timestamp: str | None = None

    def __post_init__(self) -> None:
        self.message = _clean(self.message)
        self.raw = _clean(self.raw) or self.message
        self.source = _clean(self.source) or "unknown"
        self.host = _clean(self.host) or None
        self.process = _clean(self.process) or None
        self.timestamp = _clean(self.timestamp) or None
