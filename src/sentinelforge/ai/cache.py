"""Analysis cache keyed by incident *version* (Phase 5).

Re-analysing an unchanged incident costs money and returns the same reading, so
a completed analysis is reused.  The key is deliberately not the incident id:
an incident grows as correlation attaches new alerts, and an analysis of
``INC-000001`` as it was three alerts ago is not an analysis of what it is now.

The key therefore covers everything that could change the answer:

``incident_id`` + ``incident.version`` + provider + model + prompt version +
schema version.

Only successful analyses are cached.  A failure is a fact about the provider at
one moment, not about the incident, and caching one would hide a recovery.
"""

from __future__ import annotations

import abc
import hashlib
import json
import logging
import os
import re
import tempfile

LOGGER = logging.getLogger(__name__)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def default_cache_dir() -> str:
    """Cache location under the user's XDG cache directory."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(
        os.path.expanduser("~"), ".cache"
    )
    return os.path.join(base, "sentinelforge", "ai-analyses")


def cache_key(
    incident_id: str,
    incident_version: str,
    provider: str,
    model: str,
    prompt_version: str,
    schema_version: str,
) -> str:
    """Stable identifier for one analysis request.

    Doubles as the analysis id: two runs that would ask the same provider the
    same question about the same incident version share it.
    """
    material = "|".join(
        str(part or "")
        for part in (
            incident_id,
            incident_version,
            provider,
            model,
            prompt_version,
            schema_version,
        )
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"{_SAFE_NAME.sub('_', incident_id) or 'incident'}-{digest}"


class AnalysisCache(abc.ABC):
    """Stores serialized analyses by :func:`cache_key`."""

    @abc.abstractmethod
    def get(self, key: str) -> dict | None:
        """Return the stored analysis dict, or ``None``."""

    @abc.abstractmethod
    def put(self, key: str, analysis: dict) -> None:
        """Store one analysis.  Failures must not break an analysis run."""

    def clear(self) -> int:
        """Remove everything.  Returns how many entries were removed."""
        return 0


class MemoryAnalysisCache(AnalysisCache):
    """In-process cache; the default when no cache directory is wanted."""

    def __init__(self) -> None:
        self._entries: dict[str, dict] = {}

    def get(self, key: str) -> dict | None:
        entry = self._entries.get(key)
        return json.loads(json.dumps(entry)) if entry is not None else None

    def put(self, key: str, analysis: dict) -> None:
        self._entries[key] = json.loads(json.dumps(analysis))

    def clear(self) -> int:
        count = len(self._entries)
        self._entries.clear()
        return count


class NullAnalysisCache(AnalysisCache):
    """Caches nothing; used for ``--no-cache``."""

    def get(self, key: str) -> dict | None:
        return None

    def put(self, key: str, analysis: dict) -> None:
        return None


class FileAnalysisCache(AnalysisCache):
    """One JSON file per analysis, under a cache directory.

    A cache is an optimisation, so every filesystem error here is logged and
    swallowed: a broken cache degrades to "analyse again", never to a failure.
    """

    def __init__(self, directory: str | None = None) -> None:
        self.directory = directory or default_cache_dir()

    def _path(self, key: str) -> str:
        return os.path.join(self.directory, f"{_SAFE_NAME.sub('_', key)}.json")

    def get(self, key: str) -> dict | None:
        path = self._path(key)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as exc:
            LOGGER.warning("ignoring unreadable cache entry %s: %s", path, exc)
            return None
        return data if isinstance(data, dict) else None

    def put(self, key: str, analysis: dict) -> None:
        path = self._path(key)
        try:
            os.makedirs(self.directory, exist_ok=True)
            # Written via a temporary file so a crash cannot leave half a JSON
            # document that the next run would have to reject.
            handle = tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=self.directory, delete=False, suffix=".tmp"
            )
            with handle:
                json.dump(analysis, handle, ensure_ascii=False)
            os.replace(handle.name, path)
        except OSError as exc:
            LOGGER.warning("could not cache analysis at %s: %s", path, exc)

    def clear(self) -> int:
        removed = 0
        try:
            names = os.listdir(self.directory)
        except OSError:
            return 0
        for name in names:
            if not name.endswith(".json"):
                continue
            try:
                os.remove(os.path.join(self.directory, name))
                removed += 1
            except OSError as exc:  # pragma: no cover - permissions
                LOGGER.warning("could not remove cache entry %s: %s", name, exc)
        return removed
