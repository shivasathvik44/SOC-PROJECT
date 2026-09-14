"""Shared backend vocabulary for the response layer (Phase 7).

A *backend* is the narrow adapter between one response action and one system
mechanism: firewalld, ``kill(2)``, systemd-logind.  Every backend follows the
same shape, and that shape is what keeps the layer honest:

* it reports its own availability rather than being assumed to work
  (:class:`BackendStatus`, modelled on the Phase 4
  :class:`~sentinelforge.sensors.base.SensorStatus`);
* it exposes a *closed* set of operations -- block this address, terminate this
  PID -- and no general "run this" escape hatch;
* it never flushes, resets, disables or replaces anything it did not create.

When a mechanism is missing, the backend says so with a reason and a remedy the
operator can act on.  It never falls back to a cruder tool: an unavailable
containment action is a safe outcome, a surprising one is not.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class BackendStatus:
    """Whether a containment mechanism can be used here, and why not if it cannot.

    Attributes:
        name: Backend identifier, e.g. ``firewalld``.
        available: Whether the mechanism is present and usable for *reads*.
        reason: Why it is unavailable, in one line.
        remedy: What the operator can do about it.  Typically a command for
            *them* to run: SentinelForge never escalates on its own behalf.
        requires_privilege: Whether changing state through this backend needs
            root.  Reads may well work without it.
        details: Extra facts worth auditing (the firewalld zone, the kernel's
            signal semantics, the logind version).
    """

    name: str
    available: bool
    reason: str | None = None
    remedy: str | None = None
    requires_privilege: bool = True
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "available": self.available,
            "state": "available" if self.available else "unavailable",
            "reason": self.reason,
            "remedy": self.remedy,
            "requires_privilege": self.requires_privilege,
            "details": dict(self.details),
        }


class BackendError(RuntimeError):
    """A backend could not carry out an operation it was asked to attempt."""
