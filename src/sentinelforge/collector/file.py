"""Plain-text log file collector for ``/var/log/secure`` and ``/var/log/auth.log``.

Which file exists depends on the distribution: Fedora/RHEL write
``/var/log/secure``, Debian/Ubuntu write ``/var/log/auth.log``, and a systemd
only box may have neither.  Nothing is assumed -- files are detected at runtime
and unreadable ones are skipped with a warning.

Files are only ever opened read-only.
"""

from __future__ import annotations

import logging
import os
import re
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Iterator, Sequence

from ..models.event import format_timestamp
from ..models.record import RawRecord
from .base import Collector

LOGGER = logging.getLogger(__name__)

#: Candidate auth log files, checked in order.
DEFAULT_LOG_PATHS: tuple[str, ...] = ("/var/log/secure", "/var/log/auth.log")

# "Sep 12 10:30:00 fedora sshd[1234]: Failed password for root from 10.0.0.1"
_BSD_SYSLOG = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\s\[\]:]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# "2026-09-12T10:30:00.123456+02:00 fedora sshd[1234]: Failed password ..."
_RFC3339_SYSLOG = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^\s\[\]:]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)


def _parse_bsd_timestamp(value: str, now: datetime | None = None) -> str | None:
    """Parse a year-less syslog timestamp, assuming local time.

    Syslog omits the year, so we assume the current one and fall back to the
    previous year when that would put the entry in the future (log rotation
    across New Year).
    """
    now = now or datetime.now()
    for year in (now.year, now.year - 1):
        try:
            candidate = datetime.strptime(f"{year} {value}", "%Y %b %d %H:%M:%S")
        except ValueError:
            continue  # e.g. "Feb 29" in a non-leap year -> try the previous year
        if candidate - now <= timedelta(days=1):
            return format_timestamp(candidate.astimezone().astimezone(timezone.utc))
    return None


def _parse_iso_timestamp(value: str) -> str | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.astimezone()
    return format_timestamp(parsed)


def parse_syslog_line(line: str, source: str = "logfile") -> RawRecord:
    """Parse one syslog line into a :class:`RawRecord`.

    Lines that do not match any known syslog layout are still returned, with the
    whole line as the message -- we never silently drop log data.
    """
    if not isinstance(line, str):
        line = str(line)
    stripped = line.rstrip("\n")

    for pattern, timestamp_parser in (
        (_RFC3339_SYSLOG, _parse_iso_timestamp),
        (_BSD_SYSLOG, _parse_bsd_timestamp),
    ):
        match = pattern.match(stripped)
        if match:
            return RawRecord(
                message=match.group("message"),
                raw=stripped,
                source=source,
                host=match.group("host"),
                process=match.group("process"),
                timestamp=timestamp_parser(match.group("ts")),
            )

    return RawRecord(message=stripped, raw=stripped, source=source)


def detect_log_files(candidates: Sequence[str] | None = None) -> list[str]:
    """Return the candidate log files that exist and are readable."""
    found: list[str] = []
    for path in candidates or DEFAULT_LOG_PATHS:
        try:
            if os.path.isfile(path) and os.access(path, os.R_OK):
                found.append(path)
            elif os.path.isfile(path):
                LOGGER.info("log file exists but is not readable: %s", path)
        except OSError as exc:  # pragma: no cover - defensive
            LOGGER.warning("cannot check %s: %s", path, exc)
    return found


def unreadable_log_files(candidates: Sequence[str] | None = None) -> list[str]:
    """Return candidate log files that exist but cannot be read by this user."""
    blocked: list[str] = []
    for path in candidates or DEFAULT_LOG_PATHS:
        try:
            if os.path.isfile(path) and not os.access(path, os.R_OK):
                blocked.append(path)
        except OSError:  # pragma: no cover - defensive
            continue
    return blocked


class FileCollector(Collector):
    """Read (and optionally tail) a single plain-text log file.

    Args:
        path: Path of the log file.
        follow: Keep watching the file for new lines after the initial read.
        limit: Only yield the last ``limit`` existing lines.
        poll_interval: Seconds between polls while following.
    """

    def __init__(
        self,
        path: str,
        follow: bool = False,
        limit: int | None = None,
        poll_interval: float = 1.0,
    ) -> None:
        self.path = path
        self.follow = follow
        self.limit = limit
        self.poll_interval = poll_interval

    @property
    def name(self) -> str:  # type: ignore[override]
        return self.path

    def exists(self) -> bool:
        """Return ``True`` when this specific file exists and is readable."""
        return bool(detect_log_files([self.path]))

    def collect(self) -> Iterator[RawRecord]:
        try:
            handle = open(self.path, "r", encoding="utf-8", errors="replace")
        except PermissionError:
            LOGGER.warning("permission denied reading %s (try sudo or group 'adm')", self.path)
            return
        except FileNotFoundError:
            LOGGER.warning("log file disappeared: %s", self.path)
            return
        except OSError as exc:
            LOGGER.error("cannot open %s: %s", self.path, exc)
            return

        with handle:
            yield from self._read_existing(handle)
            if self.follow:
                yield from self._tail(handle)

    def _read_existing(self, handle) -> Iterator[RawRecord]:
        try:
            lines = (line for line in handle if line.strip())
            if self.limit is not None and self.limit > 0:
                # Keep only the most recent N usable lines.
                lines = deque(lines, maxlen=self.limit)
            for line in lines:
                record = self.parse_line(line)
                if record is not None:
                    yield record
        except OSError as exc:  # pragma: no cover - e.g. file truncated mid-read
            LOGGER.warning("read error on %s: %s", self.path, exc)

    def _tail(self, handle) -> Iterator[RawRecord]:
        """Follow the file, surviving truncation and log rotation."""
        try:
            inode = os.fstat(handle.fileno()).st_ino
        except OSError:  # pragma: no cover - defensive
            inode = None
        while True:
            line = handle.readline()
            if line:
                record = self.parse_line(line)
                if record is not None:
                    yield record
                continue
            time.sleep(self.poll_interval)
            handle = self._maybe_reopen(handle, inode) or handle
            try:
                inode = os.fstat(handle.fileno()).st_ino
            except OSError:  # pragma: no cover - defensive
                pass

    def _maybe_reopen(self, handle, inode):
        """Reopen the file if it was rotated or truncated."""
        try:
            stat = os.stat(self.path)
        except OSError:
            return None
        rotated = inode is not None and stat.st_ino != inode
        truncated = stat.st_size < handle.tell()
        if not (rotated or truncated):
            return None
        LOGGER.info("reopening %s (rotated or truncated)", self.path)
        try:
            new_handle = open(self.path, "r", encoding="utf-8", errors="replace")
        except OSError as exc:
            LOGGER.warning("cannot reopen %s: %s", self.path, exc)
            return None
        handle.close()
        return new_handle

    def parse_line(self, line: str) -> RawRecord | None:
        """Parse one line, returning ``None`` for blank or unusable input."""
        line = line.rstrip("\n")
        if not line.strip():
            return None
        try:
            return parse_syslog_line(line, source=self.path)
        except Exception as exc:  # pragma: no cover - guardrail for odd input
            LOGGER.warning("skipping unparseable line in %s: %s", self.path, exc)
            return None


class FilesCollector(Collector):
    """Collect from every detected auth log file.

    In follow mode the files are polled round-robin so one quiet file never
    blocks another.
    """

    name = "logfile"

    def __init__(
        self,
        paths: Sequence[str] | None = None,
        follow: bool = False,
        limit: int | None = None,
        poll_interval: float = 1.0,
    ) -> None:
        self.paths = list(paths) if paths is not None else detect_log_files()
        self.follow = follow
        self.limit = limit
        self.poll_interval = poll_interval

    @classmethod
    def available(cls) -> bool:
        return bool(detect_log_files())

    def collect(self) -> Iterator[RawRecord]:
        if not self.paths:
            LOGGER.warning(
                "no readable auth log files found (looked for: %s)",
                ", ".join(DEFAULT_LOG_PATHS),
            )
            return

        collectors = [
            FileCollector(path, follow=False, limit=self.limit).collect()
            for path in self.paths
        ]
        for stream in collectors:
            yield from stream

        if self.follow:
            yield from self._follow_all()

    def _follow_all(self) -> Iterator[RawRecord]:
        followers = []
        for path in self.paths:
            collector = FileCollector(path, follow=True, poll_interval=0)
            try:
                handle = open(path, "r", encoding="utf-8", errors="replace")
            except OSError as exc:
                LOGGER.warning("cannot follow %s: %s", path, exc)
                continue
            handle.seek(0, os.SEEK_END)
            followers.append((collector, handle))

        try:
            while followers:
                produced = False
                for collector, handle in followers:
                    line = handle.readline()
                    while line:
                        record = collector.parse_line(line)
                        if record is not None:
                            produced = True
                            yield record
                        line = handle.readline()
                if not produced:
                    time.sleep(self.poll_interval or 1.0)
        finally:
            for _, handle in followers:
                try:
                    handle.close()
                except OSError:  # pragma: no cover
                    pass
