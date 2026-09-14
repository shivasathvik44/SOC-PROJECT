"""HTML pages (Phase 6).

The pages are rendered server-side with Jinja2, whose autoescaping is on for
every ``.html`` template.  That is the primary XSS control in this dashboard:
a username, command line, log message or AI sentence reaches the DOM as text,
escaped on the way in, and there is no ``|safe`` anywhere near telemetry.

JavaScript is used only for things a server render cannot do -- the live
counters and the live event feed -- and it builds nodes with ``textContent``
rather than assembling HTML strings.  Keeping list rendering in Jinja means
there is exactly one rendering path per view to reason about.

These routes read; they never write.
"""

from __future__ import annotations

import logging
import sqlite3

from flask import Blueprint, abort, current_app, render_template, request

from ..models.event import Severity
from ..models.incident import IncidentStatus
from .api import INCIDENT_ID_PATTERN
from .serializers import (
    incident_alerts,
    mitre_breakdown,
    serialize_ai_analysis,
    serialize_attack_chain,
    serialize_audit_record,
    serialize_incident_summary,
    serialize_network,
    serialize_process_tree,
    serialize_response_capabilities,
    serialize_response_history,
    serialize_stats,
    serialize_timeline,
    sort_key,
    suggested_response_targets,
)

LOGGER = logging.getLogger(__name__)

pages = Blueprint("pages", __name__)

#: Rows shown per page in the HTML views.
PAGE_SIZE = 50


def context():
    return current_app.extensions["sentinelforge"]


def _incidents(limit: int | None = None):
    try:
        with context().store() as store:
            return store.list_incidents(limit=limit)
    except sqlite3.Error as exc:
        LOGGER.error("cannot read the incident store: %s", exc)
        return []


def _page_arg(name: str, default: int = 1) -> int:
    try:
        return max(1, int(request.args.get(name, default)))
    except (TypeError, ValueError):
        return default


@pages.app_context_processor
def _template_globals():
    """Values every template needs: severities, demo flag, navigation state."""
    ctx = context()
    return {
        "severities": list(Severity.ALL),
        "statuses": list(IncidentStatus.ALL),
        "demo_mode": ctx.config.demo,
        "nav_active": request.endpoint,
        "response_enabled": ctx.config.response_available()[0],
    }


def _response_context(incident_id: str | None = None) -> dict:
    """Everything the response panels need, or the reason there is nothing.

    A page never offers an action this host cannot carry out: when the response
    API is unavailable the panel explains why instead of rendering buttons that
    would fail.
    """
    ctx = context()
    available, reason = ctx.config.response_available()
    if not available:
        return {
            "available": False,
            "reason": reason,
            "capabilities": None,
            "history": serialize_response_history([]),
        }
    engine = ctx.response_engine()
    try:
        engine.reconcile_expired()
        actions = (
            engine.incident_actions(incident_id)
            if incident_id
            else engine.list_actions(limit=PAGE_SIZE)
        )
    except sqlite3.Error as exc:
        LOGGER.error("cannot read the response store: %s", exc)
        actions = []
    return {
        "available": True,
        "reason": None,
        "capabilities": serialize_response_capabilities(engine.capabilities()),
        "history": serialize_response_history(actions),
    }


@pages.get("/")
def overview():
    """SOC overview: counters, recent activity, ATT&CK coverage, sensors."""
    ctx = context()
    incidents = _incidents(limit=200)
    try:
        with ctx.store() as store:
            severity_counts = store.severity_counts()
            status_counts = store.status_counts()
            total = store.count()
    except sqlite3.Error:
        severity_counts, status_counts, total = {}, {}, 0

    summaries = [serialize_incident_summary(incident) for incident in incidents]
    recent_alerts: list[dict] = []
    for incident in incidents[:25]:
        recent_alerts.extend(incident_alerts(incident))
    recent_alerts.sort(key=lambda item: item.get("timestamp") or "", reverse=True)

    return render_template(
        "dashboard.html",
        stats=serialize_stats(
            severity_counts, status_counts, ctx.live.snapshot(), total, demo=ctx.config.demo
        ),
        incidents=sorted(summaries, key=lambda item: sort_key(item, "last_seen"), reverse=True)[:8],
        alerts=recent_alerts[:12],
        mitre=mitre_breakdown(incidents)[:10],
        sensors=ctx.sensor_snapshot(),
        ai_analyses=[item for item in summaries if item["has_ai_analysis"]][:5],
    )


@pages.get("/alerts")
def alerts():
    """Alert list with server-side filtering."""
    ctx = context()
    incidents = _incidents(limit=ctx.config.alert_scan_incidents)
    items: list[dict] = []
    for incident in incidents:
        items.extend(incident_alerts(incident))

    severity = request.args.get("severity") or ""
    rule_id = request.args.get("rule") or ""
    host = request.args.get("host") or ""
    source_ip = request.args.get("source_ip") or ""
    query = (request.args.get("q") or "").strip().lower()

    if severity in Severity.ALL:
        items = [item for item in items if item["severity"] == severity]
    if rule_id:
        items = [item for item in items if item["rule_id"] == rule_id]
    if host:
        items = [item for item in items if item["host"] == host]
    if source_ip:
        items = [item for item in items if item["source_ip"] == source_ip]
    if query:
        items = [
            item
            for item in items
            if query
            in " ".join(
                str(value or "").lower()
                for value in (
                    item["description"], item["name"], item["rule_id"],
                    item["user"], item["source_ip"], item["host"],
                )
            )
        ]

    items.sort(key=lambda item: item.get("timestamp") or "", reverse=True)
    page = _page_arg("page")
    start = (page - 1) * PAGE_SIZE
    return render_template(
        "alerts.html",
        alerts=items[start : start + PAGE_SIZE],
        total=len(items),
        page=page,
        page_size=PAGE_SIZE,
        rules=sorted({item["rule_id"] for item in items}),
        hosts=sorted({item["host"] for item in items if item["host"]}),
        filters={
            "severity": severity,
            "rule": rule_id,
            "host": host,
            "source_ip": source_ip,
            "q": request.args.get("q") or "",
        },
    )


@pages.get("/incidents")
def incidents():
    """Incident list with filtering and sorting."""
    items = [serialize_incident_summary(incident) for incident in _incidents()]

    severity = request.args.get("severity") or ""
    status = request.args.get("status") or ""
    host = request.args.get("host") or ""
    source_ip = request.args.get("source_ip") or ""
    technique = (request.args.get("technique") or "").upper()
    query = (request.args.get("q") or "").strip().lower()
    try:
        min_risk = int(request.args.get("min_risk") or 0)
    except ValueError:
        min_risk = 0

    if severity in Severity.ALL:
        items = [item for item in items if item["severity"] == severity]
    if status in IncidentStatus.ALL:
        items = [item for item in items if item["status"] == status]
    if host:
        items = [item for item in items if item["host"] == host]
    if source_ip:
        items = [item for item in items if source_ip in item["source_ips"]]
    if technique:
        items = [
            item
            for item in items
            if any(code.upper().startswith(technique) for code in item["techniques"])
        ]
    if min_risk:
        items = [item for item in items if item["risk_score"] >= min_risk]
    if query:
        items = [
            item
            for item in items
            if query
            in " ".join(
                str(value or "").lower()
                for value in (
                    item["title"], item["incident_id"], item["host"],
                    " ".join(item["source_ips"]), " ".join(item["users"]),
                    " ".join(item["rule_ids"]),
                )
            )
        ]

    sort_field = request.args.get("sort") or "last_seen"
    if sort_field not in ("last_seen", "first_seen", "severity", "risk_score", "incident_id", "status", "host"):
        sort_field = "last_seen"
    descending = (request.args.get("order") or "desc") != "asc"
    items.sort(key=lambda item: sort_key(item, sort_field), reverse=descending)

    page = _page_arg("page")
    start = (page - 1) * PAGE_SIZE
    return render_template(
        "incidents.html",
        incidents=items[start : start + PAGE_SIZE],
        total=len(items),
        page=page,
        page_size=PAGE_SIZE,
        hosts=sorted({item["host"] for item in items if item["host"]}),
        filters={
            "severity": severity,
            "status": status,
            "host": host,
            "source_ip": source_ip,
            "technique": request.args.get("technique") or "",
            "min_risk": min_risk or "",
            "q": request.args.get("q") or "",
            "sort": sort_field,
            "order": "asc" if not descending else "desc",
        },
    )


@pages.get("/incidents/<incident_id>")
def incident_detail(incident_id: str):
    """The investigation view for one incident."""
    if not INCIDENT_ID_PATTERN.match(incident_id or ""):
        abort(400)
    try:
        with context().store() as store:
            incident = store.get(incident_id)
    except sqlite3.Error as exc:
        LOGGER.error("cannot read the incident store: %s", exc)
        abort(503)
    if incident is None:
        abort(404)

    response = _response_context(incident_id)
    return render_template(
        "incident.html",
        incident=serialize_incident_summary(incident),
        raw=incident,
        response=response,
        response_targets=suggested_response_targets(incident),
        alerts=incident_alerts(incident, include_evidence=True),
        timeline=serialize_timeline(incident, limit=500),
        attack_chain=serialize_attack_chain(incident),
        mitre=mitre_breakdown([incident]),
        process_tree=serialize_process_tree(incident),
        network=serialize_network(incident),
        ai=serialize_ai_analysis(incident),
        risk_explanation=list(incident.risk_explanation),
        correlation_reasons=list(incident.correlation_reasons),
    )


@pages.get("/live")
def live():
    """The live activity console (SSE-driven)."""
    ctx = context()
    return render_template(
        "live.html",
        activity=ctx.live.recent_activity(100),
        counters=ctx.live.snapshot(),
        watching={
            "events_file": ctx.config.events_file,
            "alerts_file": ctx.config.alerts_file,
            "poll_interval": ctx.config.poll_interval,
        },
    )


@pages.get("/mitre")
def mitre():
    """ATT&CK coverage across every stored incident."""
    incidents = _incidents()
    return render_template(
        "mitre.html",
        techniques=mitre_breakdown(incidents),
        incident_count=len(incidents),
    )


@pages.get("/sensors")
def sensors():
    """Telemetry source and AI provider status."""
    ctx = context()
    return render_template(
        "sensors.html",
        sensors=ctx.sensor_snapshot(),
        monitors=ctx.monitors.describe() if ctx.monitors else [],
        config={
            "database": ctx.config.resolved_db_path(),
            "events_file": ctx.config.events_file,
            "alerts_file": ctx.config.alerts_file,
            "poll_interval": ctx.config.poll_interval,
            "bind": f"{ctx.config.host}:{ctx.config.port}",
            "demo": ctx.config.demo,
        },
    )


@pages.get("/response")
def response():
    """Every containment action taken here, and the audit trail behind them."""
    ctx = context()
    data = _response_context()
    records = []
    if data["available"]:
        try:
            records = [
                serialize_audit_record(record)
                for record in ctx.response_engine().audit_records(limit=200)
            ]
        except sqlite3.Error as exc:  # pragma: no cover - unreadable store
            LOGGER.error("cannot read the response audit trail: %s", exc)
    return render_template(
        "response.html",
        response=data,
        audit=records,
        chain=ctx.response_engine().verify_audit() if data["available"] else None,
    )
