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
"""

from .app import create_app, run_dashboard
from .state import DashboardConfig, DashboardContext

__all__ = ["DashboardConfig", "DashboardContext", "create_app", "run_dashboard"]
