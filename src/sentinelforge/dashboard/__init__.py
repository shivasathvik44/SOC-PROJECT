"""Local SOC dashboard (Phase 6).

A read-only web view of what Phases 1-5 produced: incidents, their alerts,
timelines, attack chains, ATT&CK coverage, process lineage, network metadata
and AI analysis -- with live updates over Server-Sent Events.

It sits at the *end* of the pipeline::

    logs / eBPF -> events -> detection -> alerts -> correlation -> incidents
                -> AI analyst -> dashboard -> human analyst

and it deliberately contains none of the pipeline's logic.  No detection rule,
no correlation decision and no risk score is computed here; the dashboard reads
the incident store and the event bus, and shows what it finds.

Flask is an **optional** dependency (``pip install sentinelforge[dashboard]``),
so :func:`create_app` and :func:`run_dashboard` are resolved on first access
rather than at import time.  Importing a Flask-free part of this package --
:mod:`sentinelforge.dashboard.serializers`, which the CLI and the Phase 8
simulator both use -- must not fail on a standard-library-only install.
"""

from .state import DashboardConfig, DashboardContext

__all__ = ["DashboardConfig", "DashboardContext", "create_app", "run_dashboard"]

_LAZY = {"create_app": ".app", "run_dashboard": ".app"}


def __getattr__(name: str):
    """Import the Flask-dependent entry points only when they are asked for."""
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    return getattr(import_module(module_name, __name__), name)


def __dir__() -> list:  # pragma: no cover - interactive convenience
    return sorted(set(globals()) | set(__all__))
