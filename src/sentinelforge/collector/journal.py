"""systemd journal collector.

Runs ``journalctl --output=json`` in a subprocess and parses the machine
readable output, one JSON object per line.  We never parse the human formatted
terminal output, and we never use ``shell=True``: the command is always an
argument list built from validated parameters.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Iterator

from ..models.event import format_timestamp
from ..models.record import RawRecord
from .base import Collector

LOGGER = logging.getLogger(__name__)

#: Journal fields we look at.  Everything else is preserved only inside ``raw``.
_PROCESS_FIELDS = ("SYSLOG_IDENTIFIER", "_COMM", "UNIT", "_SYSTEMD_UNIT")


def _decode_message(value: object) -> str:
    """Decode a journal ``MESSAGE`` field.

    journalctl emits non-UTF-8 messages as a JSON array of byte values, so both
    shapes have to be handled.
    """
    if isinstance(value, list):
        try:
            return bytes(bytearray(int(b) & 0xFF for b in value)).decode(
                "utf-8", errors="replace"
            )
        except (TypeError, ValueError):
            return ""
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return str(value)


def _decode_timestamp(entry: dict) -> str | None:
    """Convert ``__REALTIME_TIMESTAMP`` (microseconds since epoch) to ISO UTC."""
    value = entry.get("__REALTIME_TIMESTAMP") or entry.get("_SOURCE_REALTIME_TIMESTAMP")
    if value is None:
        return None
    try:
        seconds = int(value) / 1_000_000
        return format_timestamp(datetime.fromtimestamp(seconds, tz=timezone.utc))
    except (TypeError, ValueError, OSError, OverflowError):
        return None


class JournalCollector(Collector):
    """Collect events from the systemd journal via ``journalctl``.

    Args:
        since: Value passed to ``--since`` (e.g. ``"1 hour ago"``, ``"today"``).
        limit: Maximum number of recent entries to read (``-n``).
        follow: Stream new entries as they arrive (``-f``).
        unit: Restrict to a single systemd unit (``-u``).
        identifier: Restrict to a syslog identifier such as ``sshd`` (``-t``).
        raw_full: Keep the complete journal JSON entry in the event's ``raw``
            field instead of just the original log line.  Lossless but verbose.
        journalctl_path: Override for testing or unusual installations.
    """

    name = "systemd-journal"

    def __init__(
        self,
        since: str | None = "1 hour ago",
        limit: int | None = None,
        follow: bool = False,
        unit: str | None = None,
        identifier: str | None = None,
        raw_full: bool = False,
        journalctl_path: str | None = None,
    ) -> None:
        self.since = since
        self.limit = limit
        self.follow = follow
        self.unit = unit
        self.identifier = identifier
        self.raw_full = raw_full
        self.journalctl_path = journalctl_path or shutil.which("journalctl") or "journalctl"

    @classmethod
    def available(cls) -> bool:
        return shutil.which("journalctl") is not None

    def build_command(self) -> list[str]:
        """Build the ``journalctl`` argument list (never a shell string)."""
        cmd: list[str] = [self.journalctl_path, "--output=json", "--no-pager"]
        if self.limit is not None:
            cmd += ["-n", str(int(self.limit))]
        if self.since:
            cmd += ["--since", str(self.since)]
        if self.unit:
            cmd += ["-u", str(self.unit)]
        if self.identifier:
            cmd += ["-t", str(self.identifier)]
        if self.follow:
            cmd.append("-f")
        return cmd

    def _record_from_entry(self, entry: dict, raw_line: str) -> RawRecord | None:
        message = _decode_message(entry.get("MESSAGE"))
        if not message:
            return None
        process = None
        for key in _PROCESS_FIELDS:
            value = entry.get(key)
            if value:
                process = _decode_message(value)
                break
        if self.raw_full:
            raw = raw_line
        else:
            # SYSLOG_RAW is the untouched syslog line when there was one.
            raw = _decode_message(entry.get("SYSLOG_RAW")) or message
        return RawRecord(
            message=message,
            raw=raw,
            source=self.name,
            host=entry.get("_HOSTNAME"),
            process=process,
            timestamp=_decode_timestamp(entry),
        )

    def collect(self) -> Iterator[RawRecord]:
        """Yield records from journalctl.

        Errors (missing binary, permission denied, non-zero exit) are logged and
        end the stream instead of raising, so the CLI degrades gracefully.
        """
        cmd = self.build_command()
        LOGGER.debug("running: %s", " ".join(cmd))
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
        except FileNotFoundError:
            LOGGER.error("journalctl not found (looked for %s)", self.journalctl_path)
            return
        except PermissionError as exc:
            LOGGER.error("cannot execute journalctl: %s", exc)
            return
        except OSError as exc:  # pragma: no cover - defensive
            LOGGER.error("failed to start journalctl: %s", exc)
            return

        try:
            yield from self._read_stream(process)
        finally:
            self._shutdown(process)

    def _read_stream(self, process: "subprocess.Popen[str]") -> Iterator[RawRecord]:
        stdout = process.stdout
        if stdout is None:  # pragma: no cover - defensive
            return
        for line in stdout:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except (ValueError, TypeError):
                LOGGER.warning("skipping malformed journal entry (%d bytes)", len(line))
                continue
            if not isinstance(entry, dict):
                LOGGER.warning("skipping unexpected journal entry type: %s", type(entry).__name__)
                continue
            try:
                record = self._record_from_entry(entry, line)
            except Exception as exc:  # pragma: no cover - guardrail
                LOGGER.warning("skipping unreadable journal entry: %s", exc)
                continue
            if record is not None:
                yield record

    def _shutdown(self, process: "subprocess.Popen[str]") -> None:
        """Close pipes, stop a follow process, and report journalctl errors."""
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                process.kill()
        stderr = ""
        if process.stderr is not None:
            try:
                stderr = process.stderr.read() or ""
            except (ValueError, OSError):  # pragma: no cover - pipe already closed
                stderr = ""
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (ValueError, OSError):  # pragma: no cover
                    pass
        returncode = process.returncode
        if returncode not in (0, None) and not self.follow:
            message = stderr.strip() or f"journalctl exited with code {returncode}"
            if "permission" in message.lower() or returncode == 1:
                LOGGER.warning("journalctl reported a problem: %s", message)
            else:
                LOGGER.error("journalctl failed: %s", message)
        elif stderr.strip():
            LOGGER.warning("journalctl: %s", stderr.strip())


def journal_available() -> bool:
    """Convenience wrapper used by source auto-detection."""
    return JournalCollector.available()
