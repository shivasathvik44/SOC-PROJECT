"""The response API (Phase 7).

Phases 1-6 gave the dashboard a strictly read-only API, and said so: with no
state-changing route there was nothing to protect against CSRF.  Phase 7 adds
the first routes that can change the host, so the protection those routes do
not get for free is built explicitly here:

* **Loopback only.**  The blueprint refuses every request when the dashboard is
  not bound to 127.0.0.1, because this console has no authentication and an
  unauthenticated containment endpoint on a network interface is a remote
  control for the host.  ``--no-response`` turns it off entirely.
* **JSON only, and same-origin.**  A state-changing request must carry
  ``Content-Type: application/json``, which an HTML form cannot send
  cross-origin, and its ``Origin``/``Referer`` -- when the browser sends one --
  must be this dashboard.  Together those stop a page on another site from
  driving this API through a logged-in browser.
* **Structured input only.**  Every field is validated by
  :mod:`sentinelforge.response.validators` before it reaches the engine.  There
  is no field that accepts a command, and an unknown ``action_type`` is a 400.
* **Approval is still a separate call.**  ``/request`` records; ``/approve``
  approves; ``/execute`` executes.  The API cannot collapse them, because the
  engine's state machine has no edge that would let it.

The AI layer reaches none of this.  An analysis may suggest "block this
address", and the dashboard may render that suggestion, but the only thing that
can call these endpoints is a person clicking in a browser on this host.
"""

from __future__ import annotations

import logging
import sqlite3
from urllib.parse import urlparse

from flask import Blueprint, current_app, jsonify, request

from ..bus import Topic
from ..response.engine import (
    ApprovalRequired,
    PolicyRefused,
    PrivilegeRequired,
    ResponseError,
)
from ..response.models import ActionType
from ..response.validators import ValidationError
from .serializers import (
    API_VERSION,
    serialize_audit_record,
    serialize_response_action,
    serialize_response_capabilities,
    serialize_response_preview,
)

LOGGER = logging.getLogger(__name__)

response_api = Blueprint("response_api", __name__, url_prefix="/api/response")

#: Hard ceiling on any listing.
MAX_LIMIT = 500

#: Largest accepted request body.  A containment request is a handful of short
#: fields; anything larger is a mistake or an attack.
MAX_BODY_BYTES = 16 * 1024


def context():
    return current_app.extensions["sentinelforge"]


def error(status: int, code: str, message: str, **extra):
    payload = {"error": {"code": code, "message": message, "status": status}}
    payload["error"].update(extra)
    return jsonify(payload), status


@response_api.before_request
def _guard():
    """Refuse anything this process must not serve, before a route sees it."""
    ctx = context()
    available, reason = ctx.config.response_available()
    if not available:
        return error(403, "response_disabled", reason or "the response API is disabled")
    if request.method == "GET":
        return None
    return _guard_state_change()


def _guard_state_change():
    """CSRF and shape checks for the routes that can change the host."""
    if request.content_length and request.content_length > MAX_BODY_BYTES:
        return error(413, "body_too_large", "the request body is too large")
    if not request.is_json:
        return error(
            415,
            "json_required",
            "response requests must be sent as application/json. This also stops a "
            "cross-site HTML form from reaching these endpoints.",
        )
    origin = request.headers.get("Origin")
    if origin and not _same_origin(origin):
        return error(403, "cross_origin", "cross-origin response requests are refused")
    referer = request.headers.get("Referer")
    if not origin and referer and not _same_origin(referer):
        return error(403, "cross_origin", "cross-origin response requests are refused")
    return None


def _same_origin(value: str) -> bool:
    """Whether a URL points back at this dashboard.

    Compared by host, not by string: the browser may spell the origin with
    ``localhost`` where the server knows itself as ``127.0.0.1``, and both are
    this machine.
    """
    try:
        parsed = urlparse(value)
    except ValueError:  # pragma: no cover - urlparse is forgiving
        return False
    if not parsed.hostname:
        return False
    if parsed.hostname not in ("127.0.0.1", "::1", "localhost"):
        return False
    if parsed.port and parsed.port != context().config.port:
        return False
    return True


def _body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValidationError("the request body must be a JSON object", "body")
    return data


def _engine():
    return context().response_engine()


def _publish(action) -> None:
    """Announce a state change on the bus so the live console sees it."""
    ctx = context()
    payload = serialize_response_action(action)
    payload["demo"] = ctx.config.demo
    ctx.bus.publish(Topic.RESPONSE_ACTION, payload)


@response_api.errorhandler(ValidationError)
def _invalid(exc: ValidationError):
    return error(400, "invalid_request", str(exc), field=exc.field)


# --------------------------------------------------------------------------
# Reads
# --------------------------------------------------------------------------
@response_api.get("/capabilities")
def capabilities():
    """What this host can contain, and the guarantees that never change."""
    return jsonify(serialize_response_capabilities(_engine().capabilities()))


@response_api.get("/actions")
def actions():
    """Recorded actions, newest first, optionally filtered."""
    engine = _engine()
    incident_id = request.args.get("incident_id") or None
    status = request.args.get("status") or None
    action_type = request.args.get("action_type") or None
    if status is not None:
        from ..response.models import ActionStatus

        if not ActionStatus.is_valid(status):
            return error(400, "invalid_request", f"unknown status {status!r}")
    if action_type is not None and not ActionType.is_valid(action_type):
        return error(400, "invalid_request", f"unknown action type {action_type!r}")
    try:
        limit = min(MAX_LIMIT, max(1, int(request.args.get("limit", 100))))
    except ValueError:
        return error(400, "invalid_request", "limit must be an integer")
    try:
        engine.reconcile_expired()
        items = engine.list_actions(
            incident_id=incident_id, status=status, action_type=action_type, limit=limit
        )
    except sqlite3.Error as exc:
        return error(503, "store_unavailable", f"cannot read the response store: {exc}")
    return jsonify(
        {
            "items": [serialize_response_action(action) for action in items],
            "count": len(items),
            "api_version": API_VERSION,
        }
    )


@response_api.get("/actions/<action_id>")
def action_detail(action_id: str):
    """One action plus its own audit trail."""
    engine = _engine()
    action = engine.get_action(action_id)
    if action is None:
        return error(404, "not_found", f"no such response action: {action_id}")
    return jsonify(
        {
            "action": serialize_response_action(action),
            "audit": [
                serialize_audit_record(record)
                for record in engine.audit_records(action_id=action.action_id)
            ],
            "api_version": API_VERSION,
        }
    )


@response_api.get("/audit")
def audit():
    """The append-only audit trail, newest first."""
    engine = _engine()
    try:
        limit = min(MAX_LIMIT, max(1, int(request.args.get("limit", 100))))
    except ValueError:
        return error(400, "invalid_request", "limit must be an integer")
    records = engine.audit_records(
        action_id=request.args.get("action_id") or None,
        incident_id=request.args.get("incident_id") or None,
        limit=limit,
    )
    payload = {
        "items": [serialize_audit_record(record) for record in records],
        "count": len(records),
        "api_version": API_VERSION,
    }
    if request.args.get("verify") == "1":
        payload["chain"] = engine.verify_audit()
    return jsonify(payload)


# --------------------------------------------------------------------------
# Writes.  Each one is a separate, explicit step.
# --------------------------------------------------------------------------
@response_api.post("/preview")
def preview():
    """Describe what an action would do.  Records nothing, changes nothing."""
    body = _body()
    result = _engine().preview(
        body.get("action_type"),
        body.get("target"),
        ttl=body.get("ttl"),
        incident_id=body.get("incident_id"),
        override_protected=bool(body.get("override_protected")),
    )
    return jsonify(
        {
            "action_type": result["action_type"],
            "target": result["target"],
            "incident_id": result["incident_id"],
            "preview": serialize_response_preview(result["preview"]),
            "policy": result["policy"],
            "would_be_allowed": result["would_be_allowed"],
            "api_version": API_VERSION,
        }
    )


@response_api.post("/request")
def request_action():
    """Record a request.  Nothing is executed: a human must approve it first."""
    body = _body()
    try:
        action = _engine().request(
            body.get("action_type"),
            body.get("target"),
            incident_id=body.get("incident_id"),
            reason=body.get("reason") or "",
            requested_by=body.get("requested_by"),
            ttl=body.get("ttl"),
            dry_run=bool(body.get("dry_run")),
            override_protected=bool(body.get("override_protected")),
        )
    except PolicyRefused as exc:
        return (
            jsonify(
                {
                    "error": {
                        "code": "policy_refused",
                        "message": exc.decision.reason,
                        "status": 409,
                        "policy_code": exc.decision.code,
                        "related_action_id": exc.decision.related_action_id,
                    },
                    "action": serialize_response_action(exc.action),
                }
            ),
            409,
        )
    except ResponseError as exc:
        return error(400, "response_error", str(exc))
    _publish(action)
    return (
        jsonify(
            {
                "action": serialize_response_action(action),
                "next_step": None
                if action.dry_run
                else f"POST /api/response/approve/{action.action_id}",
                "api_version": API_VERSION,
            }
        ),
        201,
    )


@response_api.post("/approve/<action_id>")
def approve(action_id: str):
    """Record a human approval.  Still executes nothing."""
    body = _body()
    try:
        action = _engine().approve(
            action_id, approved_by=body.get("approved_by"), reason=body.get("reason")
        )
    except ResponseError as exc:
        return error(409, "cannot_approve", str(exc))
    _publish(action)
    return jsonify(
        {
            "action": serialize_response_action(action),
            "next_step": f"POST /api/response/execute/{action.action_id}",
            "api_version": API_VERSION,
        }
    )


@response_api.post("/reject/<action_id>")
def reject(action_id: str):
    """Refuse a pending action.  It can never be executed afterwards."""
    body = _body()
    try:
        action = _engine().reject(
            action_id, body.get("approved_by"), body.get("reason") or ""
        )
    except ResponseError as exc:
        return error(409, "cannot_reject", str(exc))
    _publish(action)
    return jsonify({"action": serialize_response_action(action), "api_version": API_VERSION})


@response_api.post("/execute/<action_id>")
def execute(action_id: str):
    """Carry out an approved action, verify it, and audit the result."""
    body = _body()
    try:
        action = _engine().execute(action_id, executed_by=body.get("executed_by"))
    except ApprovalRequired as exc:
        return error(409, "approval_required", str(exc))
    except PrivilegeRequired as exc:
        return error(
            409,
            "privilege_required",
            str(exc),
            action_id=action_id,
            approval_still_valid=True,
        )
    except ResponseError as exc:
        return error(409, "cannot_execute", str(exc))
    _publish(action)
    status = 200 if action.status == "completed" else 502
    return jsonify({"action": serialize_response_action(action), "api_version": API_VERSION}), status


@response_api.post("/rollback/<action_id>")
def rollback(action_id: str):
    """Undo a completed, reversible action."""
    body = _body()
    try:
        action = _engine().rollback(
            action_id, body.get("approved_by"), body.get("reason") or ""
        )
    except PrivilegeRequired as exc:
        return error(409, "privilege_required", str(exc), action_id=action_id)
    except ResponseError as exc:
        return error(409, "cannot_rollback", str(exc))
    _publish(action)
    return jsonify({"action": serialize_response_action(action), "api_version": API_VERSION})


@response_api.post("/cancel/<action_id>")
def cancel(action_id: str):
    """Withdraw a request that is no longer wanted."""
    body = _body()
    try:
        action = _engine().cancel(
            action_id, body.get("requested_by"), body.get("reason") or ""
        )
    except ResponseError as exc:
        return error(409, "cannot_cancel", str(exc))
    _publish(action)
    return jsonify({"action": serialize_response_action(action), "api_version": API_VERSION})
