"""Model -> JSON serializers for the dashboard (Phase 6).

Every byte the dashboard emits -- API response, SSE payload, template context --
comes through here.  Three reasons this is one module rather than scattered
``to_dict()`` calls:

1. **A stable wire format.** The Phase 1-5 models serialize themselves for
   *storage*; those shapes may grow. The dashboard needs a contract a browser
   can rely on, so it gets its own explicit one.
2. **Data minimization.** Raw log lines, sensor internals and provider metadata
   are not needed to investigate an incident and are dropped here.
3. **One place to reason about untrusted data.** Everything in a telemetry
   field -- usernames, command lines, log messages, AI prose -- is attacker
   influenceable. These functions never interpret it: they copy strings into
   JSON, which the templates autoescape and the JavaScript inserts with
   ``textContent``. Nothing is ever built into HTML by hand.

No internal Python objects are exposed; every function returns plain dicts,
lists, strings, numbers and booleans.
"""

from __future__ import annotations

from ..ai.schemas import AIIncidentAnalysis
from ..models.alert import Alert
from ..models.event import SecurityEvent, Severity, parse_timestamp
from ..models.incident import ENTRY_ALERT, Incident

#: Bumped when the dashboard's JSON contract changes incompatibly.
API_VERSION = "1.0"

#: Severity ordering, exported so the frontend never invents its own.
SEVERITY_ORDER = list(Severity.ALL)


def _text(value, limit: int = 2000) -> str | None:
    """Coerce a telemetry value to a bounded string, or ``None``.

    Bounded because a single log line can be megabytes long, and a dashboard
    that renders one is a dashboard that hangs.
    """
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def _int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------
def serialize_event(event: SecurityEvent) -> dict:
    """One normalized event.

    ``raw`` is deliberately omitted: ``message`` carries the security-relevant
    content, and the raw line adds bulk plus a second copy of the same
    untrusted text.
    """
    telemetry = {
        "pid": _int(event.pid),
        "ppid": _int(event.ppid),
        "uid": _int(event.meta("uid")),
        "executable": _text(event.executable, 512),
        "parent_process": _text(event.parent_process, 256),
        "command_line": _text(event.command_line, 1024),
        "source_ip": _text(event.meta("source_ip"), 64),
        "source_port": _int(event.meta("source_port")),
        "destination_ip": _text(event.dst_ip, 64),
        "destination_port": _int(event.dst_port),
        "protocol": _text(event.protocol, 16),
        "direction": _text(event.meta("direction"), 16),
    }
    return {
        "timestamp": event.timestamp,
        "host": _text(event.host, 256),
        "source": _text(event.source, 64),
        "event_type": event.event_type,
        "severity": event.severity,
        "user": _text(event.user, 256),
        "src_ip": _text(event.src_ip, 64),
        "process": _text(event.process, 256),
        "message": _text(event.message, 2000),
        "telemetry": {key: value for key, value in telemetry.items() if value is not None},
    }


# --------------------------------------------------------------------------
# MITRE ATT&CK
# --------------------------------------------------------------------------
def serialize_mitre(mapping: dict | None) -> dict | None:
    """One ATT&CK mapping, as produced by :mod:`sentinelforge.detection.mitre`.

    The dashboard never invents a mapping: if a rule did not map to a
    technique, this returns ``None`` and the UI says so.
    """
    if not mapping:
        return None
    technique_id = mapping.get("sub_technique_id") or mapping.get("technique_id")
    if not technique_id:
        return None
    return {
        "technique_id": technique_id,
        "technique": mapping.get("sub_technique") or mapping.get("technique") or "",
        "parent_technique_id": mapping.get("technique_id"),
        "parent_technique": mapping.get("technique"),
        "tactic": mapping.get("tactic"),
        "url": mapping.get("url"),
    }


def mitre_breakdown(incidents) -> list[dict]:
    """Aggregate ATT&CK coverage across incidents.

    Counts come from the alerts that actually fired, so the ATT&CK view is a
    picture of what was detected -- not a matrix of what could be.
    """
    techniques: dict[str, dict] = {}
    for incident in incidents:
        for alert in incident.alerts:
            mapping = serialize_mitre(alert.mitre)
            if not mapping:
                continue
            entry = techniques.setdefault(
                mapping["technique_id"],
                {
                    **mapping,
                    "alert_count": 0,
                    "incident_count": 0,
                    "incident_ids": [],
                    "rule_ids": [],
                    "highest_severity": Severity.INFO,
                    "first_seen": None,
                    "last_seen": None,
                },
            )
            entry["alert_count"] += 1
            if incident.incident_id not in entry["incident_ids"]:
                entry["incident_ids"].append(incident.incident_id)
                entry["incident_count"] += 1
            if alert.rule_id not in entry["rule_ids"]:
                entry["rule_ids"].append(alert.rule_id)
            if Severity.rank(alert.severity) > Severity.rank(entry["highest_severity"]):
                entry["highest_severity"] = alert.severity
            for key, compare in (("first_seen", min), ("last_seen", max)):
                stamp = alert.first_seen if key == "first_seen" else alert.last_seen
                stamp = stamp or alert.timestamp
                if stamp:
                    entry[key] = stamp if entry[key] is None else compare(entry[key], stamp)
    ordered = sorted(
        techniques.values(),
        key=lambda item: (-Severity.rank(item["highest_severity"]), -item["alert_count"], item["technique_id"]),
    )
    return ordered


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------
def serialize_alert(
    alert: Alert, incident_id: str | None = None, include_evidence: bool = False,
    max_evidence: int = 10,
) -> dict:
    """One alert.  Evidence is opt-in: alert lists do not need it."""
    data = {
        "alert_id": alert.alert_id,
        "incident_id": incident_id,
        "rule_id": alert.rule_id,
        "name": _text(alert.name, 256),
        "description": _text(alert.description, 1000),
        "severity": alert.severity,
        "risk_score": _int(alert.risk_score) or 0,
        "timestamp": alert.timestamp,
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "host": _text(alert.host, 256),
        "source_ip": _text(alert.source_ip, 64),
        "user": _text(alert.user, 256),
        "mitre": serialize_mitre(alert.mitre),
        "risk_explanation": [_text(line, 500) for line in alert.risk_explanation],
        "event_count": alert.event_count,
        "suppressed_duplicates": alert.suppressed_duplicates,
    }
    if include_evidence:
        data["evidence"] = [
            serialize_event(event) for event in alert.evidence[:max_evidence]
        ]
        data["evidence_truncated"] = len(alert.evidence) > max_evidence
    return data


def incident_alerts(incident: Incident, **kwargs) -> list[dict]:
    """Every alert of one incident, tagged with the incident it belongs to."""
    return [serialize_alert(alert, incident.incident_id, **kwargs) for alert in incident.alerts]


# --------------------------------------------------------------------------
# Incidents
# --------------------------------------------------------------------------
def serialize_incident_summary(incident: Incident) -> dict:
    """The row shape used by the incident list and the overview page."""
    return {
        "incident_id": incident.incident_id,
        "title": _text(incident.title, 300),
        "status": incident.status,
        "severity": incident.severity,
        "risk_score": _int(incident.risk_score) or 0,
        "first_seen": incident.first_seen,
        "last_seen": incident.last_seen,
        "host": _text(incident.host, 256),
        "source_ips": [_text(ip, 64) for ip in incident.source_ips],
        "users": [_text(user, 256) for user in incident.users],
        "alert_count": incident.alert_count,
        "event_count": incident.event_count,
        "rule_ids": list(incident.rule_ids),
        "matched_chains": list(incident.matched_chains),
        "techniques": [
            item["technique_id"]
            for item in (serialize_mitre(alert.mitre) for alert in incident.alerts)
            if item
        ],
        "version": incident.version,
        "has_ai_analysis": bool(incident.ai_analysis),
    }


def serialize_timeline(incident: Incident, limit: int | None = None) -> dict:
    """The incident timeline, enriched with the evidence behind each entry.

    The correlation engine produced these entries; this adds the process, user,
    address and ATT&CK context an analyst needs to scan them, by looking up the
    event or alert each entry came from.  Nothing new is inferred.
    """
    by_alert = {alert.alert_id: alert for alert in incident.alerts}
    events_by_key = {}
    for event in incident.unique_events():
        events_by_key.setdefault((event.timestamp, event.message), event)

    entries = []
    for entry in incident.timeline:
        alert = by_alert.get(entry.alert_id) if entry.alert_id else None
        event = events_by_key.get((entry.timestamp, entry.description))
        item = {
            "timestamp": entry.timestamp,
            "type": entry.type,
            "event": _text(entry.event, 200),
            "description": _text(entry.description, 1000),
            "severity": entry.severity or (alert.severity if alert else None),
            "alert_id": entry.alert_id,
            "source": None,
            "process": None,
            "user": None,
            "src_ip": None,
            "mitre": None,
            "evidence": None,
        }
        if entry.type == ENTRY_ALERT and alert is not None:
            item.update(
                {
                    "source": "detection",
                    "user": _text(alert.user, 256),
                    "src_ip": _text(alert.source_ip, 64),
                    "mitre": serialize_mitre(alert.mitre),
                    "rule_id": alert.rule_id,
                    "risk_score": _int(alert.risk_score) or 0,
                    "evidence": f"{alert.event_count} event(s)",
                }
            )
        elif event is not None:
            item.update(
                {
                    "source": _text(event.source, 64),
                    "process": _text(event.process, 256),
                    "user": _text(event.user, 256),
                    "src_ip": _text(event.src_ip, 64),
                    "evidence": _text(event.message, 1000),
                }
            )
            telemetry = serialize_event(event)["telemetry"]
            if telemetry:
                item["telemetry"] = telemetry
        entries.append(item)

    total = len(entries)
    if limit is not None and limit >= 0:
        entries = entries[:limit]
    return {
        "incident_id": incident.incident_id,
        "entries": entries,
        "total": total,
        "truncated": total > len(entries),
    }


def serialize_attack_chain(incident: Incident) -> dict:
    """The attack chain as a sequence of stages, for the visual chain view.

    Stages are the incident's own alerts in chronological order -- one step per
    detection that actually fired, carrying its ATT&CK mapping.  The dashboard
    draws arrows between them; it does not decide that they are connected. That
    decision was the correlation engine's, and ``matched_chains`` names the
    pattern it recognised.
    """
    stages = []
    for alert in incident.alerts:
        stages.append(
            {
                "alert_id": alert.alert_id,
                "rule_id": alert.rule_id,
                "label": _text(alert.name, 120),
                "severity": alert.severity,
                "timestamp": alert.timestamp,
                "mitre": serialize_mitre(alert.mitre),
                "description": _text(alert.description, 500),
            }
        )
    return {
        "incident_id": incident.incident_id,
        "matched_chains": list(incident.matched_chains),
        "correlation_reasons": [_text(reason, 500) for reason in incident.correlation_reasons],
        "stages": stages,
        "techniques": [
            item
            for item in (serialize_mitre(step) for step in incident.attack_chain)
            if item
        ],
    }


def serialize_incident_detail(incident: Incident, timeline_limit: int | None = 200) -> dict:
    """Everything the incident page needs, in one response."""
    data = serialize_incident_summary(incident)
    data.update(
        {
            "correlation_reasons": [
                _text(reason, 500) for reason in incident.correlation_reasons
            ],
            "risk_explanation": [_text(line, 500) for line in incident.risk_explanation],
            "attack_chain": serialize_attack_chain(incident),
            "mitre": mitre_breakdown([incident]),
            "alerts": incident_alerts(incident, include_evidence=True),
            "timeline": serialize_timeline(incident, limit=timeline_limit),
            "process_tree": serialize_process_tree(incident),
            "network": serialize_network(incident),
            "ai_analysis": serialize_ai_analysis(incident),
            "summary": _text(incident.summary, 2000),
        }
    )
    return data


# --------------------------------------------------------------------------
# Process lineage
# --------------------------------------------------------------------------
def serialize_process_tree(incident: Incident) -> dict:
    """Reconstruct process lineage from the incident's own telemetry.

    Built only from what the sensors recorded: pid, ppid, process name,
    executable, command line, user.  Two kinds of node can appear, and they are
    labelled differently on purpose:

    * ``observed: true`` -- a process SentinelForge saw execute, because an
      event for it is part of this incident's evidence;
    * ``observed: false`` -- a *parent* named by a child's own telemetry
      (``ppid`` + ``parent_process``, reported by the kernel) that was not
      itself part of the incident.  Showing it keeps the lineage readable;
      marking it keeps the display honest.

    Nothing beyond those two sources is drawn.  A process whose parent is
    entirely unknown becomes a root and ``incomplete`` is set, so the UI can say
    "this is where our visibility starts" rather than implying a full tree.

    Nothing here executes anything: a command line is a string that travels to
    the template and is escaped on the way in.
    """
    nodes: dict[int, dict] = {}
    order: list[int] = []

    def blank(pid: int | None, observed: bool) -> dict:
        return {
            "pid": pid,
            "ppid": None,
            "process": None,
            "executable": None,
            "parent_process": None,
            "command_line": None,
            "user": None,
            "timestamp": None,
            "event_type": None,
            "observed": observed,
            "parent_observed": False,
            "children": [],
        }

    for event in incident.unique_events():
        pid = _int(event.pid)
        if pid is None:
            continue
        node = nodes.get(pid)
        if node is None:
            node = blank(pid, observed=True)
            nodes[pid] = node
            order.append(pid)
        node["observed"] = True
        for key, value in (
            ("ppid", _int(event.ppid)),
            ("process", _text(event.process, 256)),
            ("executable", _text(event.executable, 512)),
            ("parent_process", _text(event.parent_process, 256)),
            ("command_line", _text(event.command_line, 1024)),
            ("user", _text(event.user, 256)),
            ("timestamp", event.timestamp),
            ("event_type", event.event_type),
        ):
            if node.get(key) is None and value is not None:
                node[key] = value

    # Add placeholders for parents the child's telemetry names but that were
    # never observed themselves.  Their pid and name come from the kernel's
    # record on the child; nothing is guessed.
    inferred: list[dict] = []
    for pid in list(order):
        node = nodes[pid]
        ppid = node["ppid"]
        if ppid is None or ppid in nodes:
            continue
        if not node["parent_process"]:
            continue
        parent = blank(ppid, observed=False)
        parent["process"] = node["parent_process"]
        nodes[ppid] = parent
        order.append(ppid)
        inferred.append({"pid": ppid, "process": parent["process"], "child_pid": pid})

    roots: list[dict] = []
    unknown_parents: list[dict] = []
    for pid in order:
        node = nodes[pid]
        parent = nodes.get(node["ppid"]) if node["ppid"] is not None else None
        if parent is not None and parent is not node:
            node["parent_observed"] = True
            parent["children"].append(node)
        else:
            roots.append(node)
            if node["ppid"] is not None:
                unknown_parents.append({"pid": pid, "ppid": node["ppid"]})

    def annotate(node: dict, level: int = 0) -> None:
        node["depth"] = level
        node["children"].sort(key=lambda child: (child["timestamp"] or "", child["pid"] or 0))
        for child in node["children"]:
            annotate(child, level + 1)

    roots.sort(key=lambda node: (node["timestamp"] or "", node["pid"] or 0))
    for root in roots:
        annotate(root)

    observed_count = sum(1 for node in nodes.values() if node["observed"])
    return {
        "incident_id": incident.incident_id,
        "available": bool(nodes),
        "roots": roots,
        "process_count": observed_count,
        "node_count": len(nodes),
        #: True when part of the lineage is missing: a parent named but never
        #: observed, or a parent not named at all.
        "incomplete": bool(inferred or unknown_parents),
        "inferred_parents": inferred,
        "unknown_parents": unknown_parents,
        "reason": None
        if nodes
        else "no process telemetry in this incident (needs the eBPF process sensor)",
    }


# --------------------------------------------------------------------------
# Network telemetry
# --------------------------------------------------------------------------
def serialize_network(incident: Incident) -> dict:
    """Connection metadata associated with the incident.

    Metadata only: addresses, ports, protocol, process, user, time.  There is
    no payload here because SentinelForge never captures one.
    """
    connections = []
    for event in incident.unique_events():
        destination = event.dst_ip
        if not destination:
            continue
        connections.append(
            {
                "timestamp": event.timestamp,
                "process": _text(event.process or event.meta("process_name"), 256),
                "pid": _int(event.pid),
                "user": _text(event.user, 256),
                "source_ip": _text(event.meta("source_ip") or event.src_ip, 64),
                "source_port": _int(event.meta("source_port")),
                "destination_ip": _text(destination, 64),
                "destination_port": _int(event.dst_port),
                "protocol": _text(event.protocol, 16),
                "direction": _text(event.meta("direction"), 16) or "outbound",
                "host": _text(event.host, 256),
            }
        )
    connections.sort(key=lambda item: item["timestamp"] or "")
    return {
        "incident_id": incident.incident_id,
        "available": bool(connections),
        "connections": connections,
        "connection_count": len(connections),
        "reason": None
        if connections
        else "no network telemetry in this incident (needs the eBPF network sensor)",
    }


# --------------------------------------------------------------------------
# AI analysis (Phase 5)
# --------------------------------------------------------------------------
def serialize_ai_analysis(incident: Incident) -> dict:
    """The stored AI analysis, next to the deterministic result.

    The two verdicts are returned side by side and the disagreement flag is
    explicit.  The dashboard displays both; it never lets the AI's opinion
    stand in for the deterministic severity or score.
    """
    deterministic = {
        "severity": incident.severity,
        "risk_score": _int(incident.risk_score) or 0,
        "rule_ids": list(incident.rule_ids),
        "matched_chains": list(incident.matched_chains),
    }
    if not incident.ai_analysis:
        return {
            "incident_id": incident.incident_id,
            "available": False,
            "status": None,
            "deterministic": deterministic,
            "reason": "no AI analysis yet - run: sentinelforge ai analyze "
            f"{incident.incident_id}",
        }

    analysis = AIIncidentAnalysis.from_dict(incident.ai_analysis)
    audit = analysis.audit
    payload = {
        "incident_id": incident.incident_id,
        "available": analysis.ok,
        "status": analysis.status,
        "deterministic": deterministic,
        "assessment": analysis.assessment,
        "confidence": analysis.confidence,
        "summary": _text(analysis.summary, 2000),
        "severity_assessment": analysis.severity_assessment,
        "attack_stage": analysis.attack_stage,
        "severity_disagreement": analysis.severity_disagreement,
        "deterministic_severity": analysis.deterministic_severity or incident.severity,
        "deterministic_score": analysis.deterministic_score
        if analysis.deterministic_score is not None
        else _int(incident.risk_score),
        "mitre_analysis": [item.to_dict() for item in analysis.mitre_analysis],
        "key_evidence": [item.to_dict() for item in analysis.key_evidence],
        "false_positive_indicators": list(analysis.false_positive_indicators),
        "investigation_steps": list(analysis.investigation_steps),
        "recommended_actions": [item.to_dict() for item in analysis.recommended_actions],
        "reasoning": _text(analysis.reasoning, 4000),
        "error": analysis.error,
        "provenance": {
            "provider": audit.provider,
            "model": audit.model,
            "is_mock": audit.is_mock,
            "prompt_version": audit.prompt_version,
            "schema_version": audit.schema_version,
            "incident_version": audit.incident_version,
            "analyzed_at": audit.analyzed_at,
            "cached": audit.cached,
            "attempts": audit.attempts,
            "truncated": list(audit.truncated),
        },
        "reason": None if analysis.ok else (analysis.error or "analysis failed"),
    }
    return payload


# --------------------------------------------------------------------------
# Sensors
# --------------------------------------------------------------------------
def serialize_sensor_status(status, description: str | None = None) -> dict:
    """One sensor's availability, as the Phase 4 registry reports it.

    An unavailable sensor is reported as unavailable with the reason the
    registry gave.  The dashboard never shows a sensor as online because it
    would look better.
    """
    return {
        "name": status.name,
        "available": bool(status.available),
        "state": "online" if status.available else "offline",
        "description": description,
        "reason": _text(status.reason, 500),
        "remedy": _text(status.remedy, 500),
    }


# --------------------------------------------------------------------------
# Response actions (Phase 7)
# --------------------------------------------------------------------------
def serialize_response_action(action) -> dict:
    """One containment action, as the dashboard sees it.

    Two fields deserve a note.  ``target`` is a value that was parsed before it
    was ever used (an address, a PID) -- it is displayed as text like any other
    telemetry, and the browser never sends it back as anything but a string.
    ``target_detail`` can carry a command line read from ``/proc``; that is
    evidence for a human to read, and it reaches the DOM through Jinja's
    autoescaping or ``textContent``, never as markup and never as a command.
    """
    data = action.to_dict()
    policy = data.get("policy_decision") or {}
    return {
        "action_id": data["action_id"],
        "incident_id": data["incident_id"],
        "action_type": data["action_type"],
        "target": _text(data["target"], 200),
        "status": data["status"],
        "dry_run": bool(data["dry_run"]),
        "reason": _text(data["reason"], 500),
        "requested_by": _text(data["requested_by"], 100),
        "approved_by": _text(data["approved_by"], 100),
        "requested_at": data["requested_at"],
        "approved_at": data["approved_at"],
        "started_at": data["started_at"],
        "completed_at": data["completed_at"],
        "ttl_seconds": _int(data["ttl_seconds"]),
        "expires_at": data["expires_at"],
        "verified": data["verified"],
        "verification": _text(data["verification"], 500),
        "error": _text(data["error"], 1000),
        "rollback_available": bool(data["rollback_available"]),
        "rolled_back_at": data["rolled_back_at"],
        "audit_id": data["audit_id"],
        "target_detail": {
            key: _text(value, 500) if isinstance(value, str) else value
            for key, value in (data.get("target_detail") or {}).items()
        },
        "policy": {
            "allowed": policy.get("allowed"),
            "code": policy.get("code"),
            "reason": _text(policy.get("reason"), 500),
            "approval_required": policy.get("approval_required", True),
            "reversible": policy.get("reversible", False),
            "requires_privilege": policy.get("requires_privilege", False),
            "warnings": [_text(item, 300) for item in policy.get("warnings") or []],
            "related_action_id": policy.get("related_action_id"),
        },
        "result": data.get("result"),
        "is_pending": data["status"] in ("requested", "awaiting_approval", "approved"),
        "awaiting_approval": data["status"] == "awaiting_approval",
        "approved_not_executed": data["status"] == "approved",
    }


def serialize_response_preview(preview: dict) -> dict:
    """A preview, trimmed for display.  Already plain data; bounded here."""
    return {
        "action_type": preview.get("action_type"),
        "target": _text(preview.get("target"), 200),
        "description": _text(preview.get("description"), 500),
        "effect": _text(preview.get("effect"), 1500),
        "backend": preview.get("backend"),
        "available": bool(preview.get("available")),
        "reversible": bool(preview.get("reversible")),
        "requires_privilege": bool(preview.get("requires_privilege")),
        "privilege_hint": _text(preview.get("privilege_hint"), 600),
        "ttl_seconds": _int(preview.get("ttl_seconds")),
        "warnings": [_text(item, 300) for item in preview.get("warnings") or []],
        "unavailable_reason": _text(preview.get("unavailable_reason"), 600),
        "target_detail": {
            key: _text(value, 500) if isinstance(value, str) else value
            for key, value in (preview.get("target_detail") or {}).items()
        },
    }


def serialize_audit_record(record: dict) -> dict:
    """One audit entry.  Carries its chain hashes so the trail is checkable."""
    return {
        "sequence": _int(record.get("sequence")),
        "audit_id": record.get("audit_id"),
        "timestamp": record.get("timestamp"),
        "event": record.get("event"),
        "action_id": record.get("action_id"),
        "incident_id": record.get("incident_id"),
        "action_type": record.get("action_type"),
        "target": _text(record.get("target"), 200),
        "requested_by": _text(record.get("requested_by"), 100),
        "approved_by": _text(record.get("approved_by"), 100),
        "reason": _text(record.get("reason"), 500),
        "dry_run": bool(record.get("dry_run")),
        "execution_status": record.get("execution_status"),
        "error": _text(record.get("error"), 1000),
        "rollback_available": bool(record.get("rollback_available")),
        "policy_decision": record.get("policy_decision"),
        "entry_hash": record.get("entry_hash"),
        "previous_hash": record.get("previous_hash"),
    }


def serialize_response_history(actions) -> dict:
    """The response history shown on an incident page.

    Counts are computed here rather than in the template so the same numbers
    reach the API and the HTML.
    """
    items = [serialize_response_action(action) for action in actions]
    return {
        "actions": items,
        "total": len(items),
        "pending": sum(1 for item in items if item["is_pending"]),
        "awaiting_approval": sum(1 for item in items if item["awaiting_approval"]),
        "completed": sum(1 for item in items if item["status"] == "completed"),
        "failed": sum(1 for item in items if item["status"] == "failed"),
        "dry_runs": sum(1 for item in items if item["dry_run"]),
    }


def serialize_response_capabilities(capabilities: dict) -> dict:
    """What the host supports, plus the guarantees that never change."""
    return {
        "actions": [
            {
                "action_type": entry["action_type"],
                "label": entry["label"],
                "available": bool(entry["available"]),
                "backend": entry["backend"],
                "reason": _text(entry.get("reason"), 600),
                "remedy": _text(entry.get("remedy"), 600),
                "reversible": bool(entry["reversible"]),
                "requires_privilege": bool(entry["requires_privilege"]),
                "privilege_satisfied": bool(entry["privilege_satisfied"]),
            }
            for entry in capabilities.get("actions", [])
        ],
        "backends": capabilities.get("backends", {}),
        "execution_enabled": bool(capabilities.get("execution_enabled")),
        "running_as_root": bool(capabilities.get("running_as_root")),
        "approval_required": True,
        "automatic_execution": False,
        "dry_run_available": True,
        "audit_logging": True,
        "api_version": API_VERSION,
    }


def suggested_response_targets(incident: Incident) -> dict:
    """Targets on this incident an analyst might want to contain.

    Derived from the incident's own evidence -- the source addresses the
    detection rules recorded, and the PIDs eBPF observed -- not from anything a
    model wrote.  They are *suggestions for a form*, not requests: each one
    still has to be previewed, requested, approved and executed.
    """
    addresses: list[str] = []
    for address in incident.source_ips:
        text = _text(address, 45)
        if text and text not in addresses:
            addresses.append(text)

    processes: list[dict] = []
    seen_pids: set[int] = set()
    for event in incident.unique_events():
        pid = _int((event.metadata or {}).get("pid"))
        if pid is None or pid in seen_pids:
            continue
        seen_pids.add(pid)
        processes.append(
            {
                "pid": pid,
                "process": _text(event.process, 120),
                "command_line": _text((event.metadata or {}).get("command_line"), 500),
                "user": _text(event.user, 100),
                "timestamp": event.timestamp,
            }
        )
    return {
        "source_ips": addresses,
        "processes": processes[:25],
        "note": "Suggested from this incident's own evidence. Every one of them still "
        "requires a preview, a request, a human approval and an execution step.",
    }


def serialize_stats(
    severity_counts: dict,
    status_counts: dict,
    live: dict,
    incident_total: int,
    demo: bool = False,
) -> dict:
    """The overview counters."""
    active = sum(
        count for status, count in status_counts.items() if status in ("open", "investigating")
    )
    return {
        "incidents": {
            "total": incident_total,
            "active": active,
            "by_severity": {severity: severity_counts.get(severity, 0) for severity in Severity.ALL},
            "by_status": dict(status_counts),
            "critical": severity_counts.get(Severity.CRITICAL, 0),
            "high": severity_counts.get(Severity.HIGH, 0),
        },
        "live": live,
        "demo": demo,
        "api_version": API_VERSION,
    }


def sort_key(item: dict, field: str):
    """Sort key for incident/alert dicts, used by the API's ``sort`` parameter."""
    if field == "severity":
        return (Severity.rank(item.get("severity", "")), item.get("risk_score", 0))
    if field == "risk_score":
        return _int(item.get("risk_score")) or 0
    if field in ("first_seen", "last_seen", "timestamp"):
        moment = parse_timestamp(item.get(field))
        return moment.timestamp() if moment else float("-inf")
    value = item.get(field)
    return (value is None, str(value) if value is not None else "")
