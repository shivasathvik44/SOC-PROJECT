"""Collector interface shared by every log source.

A collector is deliberately dumb: it reads from somewhere and yields
:class:`~sentinelforge.models.record.RawRecord` objects.  It must never
interpret, execute or act on log content -- SentinelForge is read-only.

To add a source later (auditd, eBPF, a network appliance, ...), subclass
:class:`Collector` and implement :meth:`collect`.
"""

from __future__ import annotations

import abc
import logging
import socket
from typing import Iterator

from ..models.record import RawRecord

LOGGER = logging.getLogger(__name__)


class CollectorError(RuntimeError):
    """Raised for unrecoverable collector setup problems (never for bad log lines)."""


def local_hostname() -> str:
    """Best-effort local hostname, used when a source does not provide one."""
    try:
        return socket.gethostname() or "unknown"
    except OSError:  # pragma: no cover - extremely unlikely
        return "unknown"


class Collector(abc.ABC):
    """Base class for all log collectors."""

    #: Short identifier written into the ``source`` field of every event.
    name: str = "unknown"

    @classmethod
    def available(cls) -> bool:
        """Return ``True`` when this source can be used on the current system."""
        return True

    @abc.abstractmethod
    def collect(self) -> Iterator[RawRecord]:
        """Yield raw records.

        Implementations must not raise on malformed log lines; they should log
        a warning and keep going.
        """
        raise NotImplementedError

    def __iter__(self) -> Iterator[RawRecord]:
        return self.collect()
