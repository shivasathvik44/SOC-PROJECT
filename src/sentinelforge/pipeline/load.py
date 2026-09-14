"""Read normalized events back from JSON Lines files.

``sentinelforge collect`` writes ``.jsonl``; ``sentinelforge detect`` reads it.
Malformed lines are reported and skipped -- a truncated or hand-edited file
must not stop a detection run.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import IO, Iterator

from ..models.alert import Alert
from ..models.event import SecurityEvent

LOGGER = logging.getLogger(__name__)


def events_from_lines(lines: Iterator[str], origin: str = "<input>") -> Iterator[SecurityEvent]:
    """Parse JSON Lines into events, skipping unusable lines."""
    for number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except ValueError as exc:
            LOGGER.warning("%s:%d: skipping malformed JSON (%s)", origin, number, exc)
            continue
        if not isinstance(data, dict):
            LOGGER.warning(
                "%s:%d: skipping %s, expected a JSON object", origin, number, type(data).__name__
            )
            continue
        try:
            yield SecurityEvent.from_dict(data)
        except Exception as exc:  # pragma: no cover - guardrail for odd input
            LOGGER.warning("%s:%d: skipping unreadable event (%s)", origin, number, exc)


def _load_json_objects(path: str) -> list[dict]:
    """Read a JSON Lines file (or stdin for ``-``) into dicts, skipping bad lines."""
    if path == "-":
        return list(_json_objects(iter(sys.stdin), "<stdin>"))
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return list(_json_objects(iter(handle), path))


def _json_objects(lines: Iterator[str], origin: str) -> Iterator[dict]:
    for number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except ValueError as exc:
            LOGGER.warning("%s:%d: skipping malformed JSON (%s)", origin, number, exc)
            continue
        if not isinstance(data, dict):
            LOGGER.warning(
                "%s:%d: skipping %s, expected a JSON object", origin, number, type(data).__name__
            )
            continue
        yield data


def load_alerts(path: str) -> list[Alert]:
    """Load alerts from an ``alerts.jsonl`` file, or from stdin when ``path`` is ``-``.

    Raises:
        OSError: if the file cannot be opened.
    """
    alerts = []
    for number, data in enumerate(_load_json_objects(path), start=1):
        try:
            alerts.append(Alert.from_dict(data))
        except Exception as exc:  # pragma: no cover - guardrail for odd input
            LOGGER.warning("%s:%d: skipping unreadable alert (%s)", path, number, exc)
    return alerts


def load_events(path: str) -> list[SecurityEvent]:
    """Load events from a ``.jsonl`` file, or from stdin when ``path`` is ``-``.

    Raises:
        OSError: if the file cannot be opened.
    """
    if path == "-":
        return list(events_from_lines(iter(sys.stdin), origin="<stdin>"))
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return list(events_from_lines(iter(handle), origin=path))


def write_jsonl(records: Iterator[str], stream: IO[str]) -> int:
    """Write pre-serialized JSON lines to a stream, returning the count."""
    count = 0
    for line in records:
        stream.write(line + "\n")
        count += 1
    return count
