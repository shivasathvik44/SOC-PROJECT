"""Flask application factory and local server (Phase 6).

The dashboard is the viewer for what the rest of SentinelForge produced.  It
contains no detection logic and no correlation logic -- it reads the incident
store, subscribes to the event bus, and renders.

Phase 7 adds the one thing it can *do*: drive the response engine on behalf of
an analyst.  That capability is fenced off rather than sprinkled around -- it
lives in one blueprint (:mod:`sentinelforge.dashboard.response_api`), it is
served on loopback only, it can be switched off entirely, and it still cannot
execute anything a human has not approved in a separate request.

Security posture, enforced here rather than left to documentation:

* binds to loopback by default, and says so loudly when told to do otherwise;
* debug mode is off unless explicitly requested (the Werkzeug debugger is a
  remote code execution console by design, which is why it must never be a
  default in security software);
* sends conservative response headers, including a Content-Security-Policy that
  forbids inline script -- so even a rendering mistake cannot become a working
  XSS;
* exposes exactly one group of state-changing routes, refuses them off
  loopback, and requires a JSON content type and a same-origin request for
  every one of them.
"""

from __future__ import annotations

import ipaddress
import logging

from flask import Flask, jsonify, render_template, request

from .api import api
from .events import stream
from .monitor import MonitorSet
from .response_api import response_api
from .routes import pages
from .state import DashboardConfig, DashboardContext

LOGGER = logging.getLogger(__name__)

#: No inline script, no external origins, no framing.  The dashboard loads its
#: own CSS and JS from /static and nothing else, so this can be strict.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def create_app(
    config: DashboardConfig | None = None,
    context: DashboardContext | None = None,
    start_monitors: bool = True,
) -> Flask:
    """Build the dashboard application.

    Args:
        config: Dashboard configuration; defaults are loopback + the standard
            incident database.
        context: An already-built :class:`DashboardContext` (tests inject one
            with a fixed bus and a temporary database).
        start_monitors: Start the background threads -- the live-state pump and
            the watchers.  Tests turn this off and feed the context directly,
            so no thread outlives a test and message counts stay deterministic.
    """
    context = context or DashboardContext(config or DashboardConfig())
    if config is not None and context.config is not config:  # pragma: no cover - defensive
        context.config = config

    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
        static_url_path="/static",
    )
    app.config.update(
        SENTINELFORGE_DEMO=context.config.demo,
        JSON_SORT_KEYS=False,
        #: Only relevant if a future phase adds a cookie; set now so it is not
        #: forgotten then.
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    app.extensions["sentinelforge"] = context

    if start_monitors:
        # Subscribing the live-state pump is itself starting a thread, so it
        # belongs behind the same switch: a test that drives a monitor by hand
        # must be the only thing folding messages into the live state.
        context.start()
        context.monitors = MonitorSet.for_context(context).start()
        if context.config.demo:
            from .demo import DemoFeeder

            feeder = DemoFeeder(context.bus)
            feeder.start()
            context.monitors.monitors.append(feeder)

    app.register_blueprint(api)
    app.register_blueprint(stream)
    app.register_blueprint(response_api)
    app.register_blueprint(pages)

    available, reason = context.config.response_available()
    if not available:
        LOGGER.info("response API not served: %s", reason)

    _register_error_handlers(app)
    _register_filters(app)

    @app.after_request
    def _security_headers(response):
        """Defence in depth for every response."""
        response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        # The dashboard needs none of these.
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
        )
        return response

    return app


def _wants_json() -> bool:
    return request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json"


def _register_error_handlers(app: Flask) -> None:
    """Same failure, two representations: JSON for the API, a page for a human."""

    def respond(status: int, code: str, message: str):
        if _wants_json():
            return jsonify({"error": {"code": code, "message": message, "status": status}}), status
        return render_template("error.html", status=status, code=code, message=message), status

    @app.errorhandler(400)
    def bad_request(exc):
        return respond(400, "bad_request", "That request could not be understood.")

    @app.errorhandler(404)
    def not_found(exc):
        return respond(404, "not_found", "No such page, incident or endpoint.")

    @app.errorhandler(503)
    def unavailable(exc):
        return respond(503, "store_unavailable", "The incident store could not be read.")

    @app.errorhandler(500)
    def server_error(exc):  # pragma: no cover - defensive
        LOGGER.exception("unhandled dashboard error")
        return respond(500, "internal_error", "The dashboard failed to render this view.")


def _register_filters(app: Flask) -> None:
    """Small presentation helpers.  They format; they never trust or execute."""

    @app.template_filter("short_time")
    def short_time(value):
        """``2026-09-13T00:11:42Z`` -> ``00:11:42``; anything odd passes through."""
        if not value or not isinstance(value, str):
            return "-"
        if "T" in value and len(value) >= 19:
            return value[11:19]
        return value

    @app.template_filter("short_date")
    def short_date(value):
        if not value or not isinstance(value, str) or "T" not in value:
            return "-"
        return value.replace("T", " ").replace("Z", "")

    @app.template_filter("severity_rank")
    def severity_rank(value):
        from ..models.event import Severity

        return Severity.rank(value or "")

    @app.template_filter("or_dash")
    def or_dash(value):
        if value is None or value == "" or value == []:
            return "-"
        if isinstance(value, (list, tuple)):
            return ", ".join(str(item) for item in value)
        return value


def run_dashboard(config: DashboardConfig) -> int:
    """Start the local server.  Returns a process exit code.

    Uses Flask's built-in server: this is a single-analyst, loopback-bound tool,
    and adding a production WSGI server would be a dependency with no user.
    Threading is on because Server-Sent Events hold a connection open per tab.
    """
    app = create_app(config)
    banner = _startup_banner(config)
    for line in banner:
        print(line, flush=True)
    try:
        app.run(
            host=config.host,
            port=config.port,
            debug=config.debug,
            threaded=True,
            use_reloader=False,  # the reloader would start a second monitor set
        )
    except OSError as exc:
        LOGGER.error("cannot listen on %s:%s: %s", config.host, config.port, exc)
        return 1
    except KeyboardInterrupt:  # pragma: no cover - interactive
        LOGGER.info("dashboard stopped")
    finally:
        context = app.extensions.get("sentinelforge")
        if context is not None:
            context.stop()
    return 0


def _startup_banner(config: DashboardConfig) -> list[str]:
    """What the analyst sees in the terminal, including any warning."""
    url = f"http://{config.host}:{config.port}"
    if ":" in config.host and not config.host.startswith("["):
        url = f"http://[{config.host}]:{config.port}"
    lines = [
        "",
        "SentinelForge SOC Dashboard",
        f"Listening on {url}",
        f"Incident database: {config.resolved_db_path()}",
    ]
    if config.events_file:
        lines.append(f"Following events:  {config.events_file}")
    if config.alerts_file:
        lines.append(f"Following alerts:  {config.alerts_file}")
    if config.demo:
        lines.extend(
            [
                "",
                "*** DEMO MODE - every incident, alert and event shown is SYNTHETIC ***",
                "*** Demo data lives in its own database and never mixes with real   ***",
                "*** telemetry.                                                      ***",
            ]
        )
    if not _is_loopback(config.host):
        lines.extend(
            [
                "",
                "!!! WARNING: binding to a non-loopback address.",
                "!!! The dashboard has NO authentication and exposes security data",
                "!!! (hostnames, usernames, command lines) to anyone who can reach it.",
                "!!! Put it behind an authenticating reverse proxy, or use an SSH",
                "!!! tunnel instead:  ssh -L 8080:127.0.0.1:8080 <host>",
            ]
        )
    if config.debug:
        lines.extend(
            [
                "",
                "!!! WARNING: debug mode is ON. The Werkzeug debugger can execute",
                "!!! arbitrary code. Development only - never on a monitored host.",
            ]
        )
    lines.extend(["", "Read-only: this dashboard never changes the system it monitors.", ""])
    return lines


def _is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False
