"""Server-Sent Events: the dashboard's real-time channel (Phase 6).

SSE rather than WebSockets, because the requirement is one-way: the server
tells the browser what happened, and the browser never pushes anything back.
That is a smaller attack surface, it is plain HTTP (no upgrade handshake, no
extra dependency, no async stack), and ``EventSource`` reconnects on its own.

Flow::

    monitors -> EventBus -> Subscription (bounded) -> this generator -> browser

The generator owns exactly one bounded :class:`~sentinelforge.bus.Subscription`.
If the client cannot keep up, its subscription drops the oldest messages and the
drop count is sent to it, so the UI can say "you missed some" instead of showing
a silently incomplete picture.  A slow browser can never slow the pipeline down.

Payloads are JSON and are inserted into the DOM with ``textContent`` on the
other side -- never as HTML.
"""

from __future__ import annotations

import json
import logging

from flask import Blueprint, Response, current_app, request, stream_with_context

from ..bus import Topic

LOGGER = logging.getLogger(__name__)

stream = Blueprint("stream", __name__, url_prefix="/api")

#: Seconds between keep-alive comments when nothing is happening.  Keeps proxies
#: and browsers from closing an idle connection.
KEEPALIVE_SECONDS = 15.0

#: How long a read waits before yielding control (also the shutdown latency).
POLL_SECONDS = 0.5


def _sse(data: str, event: str | None = None, identifier: int | None = None) -> str:
    """Format one SSE frame.

    Newlines inside the payload would break the protocol, so the payload is
    JSON (which escapes them).  The ``event:`` name is chosen by this module,
    never taken from telemetry.
    """
    lines = []
    if event:
        lines.append(f"event: {event}")
    if identifier is not None:
        lines.append(f"id: {identifier}")
    lines.append(f"data: {data}")
    return "\n".join(lines) + "\n\n"


def event_stream(context, topics=None, keepalive: float = KEEPALIVE_SECONDS):
    """Yield SSE frames for the life of one client connection."""
    subscription = context.bus.subscribe(topics)
    try:
        yield _sse(
            json.dumps(
                {
                    "message": "connected",
                    "demo": context.config.demo,
                    "topics": list(topics) if topics else list(Topic.ALL),
                }
            ),
            event="connected",
        )
        idle = 0.0
        reported_drops = 0
        while True:
            message = subscription.get(timeout=POLL_SECONDS)
            if message is None:
                idle += POLL_SECONDS
                if idle >= keepalive:
                    idle = 0.0
                    # A comment frame: ignored by EventSource, keeps the socket warm.
                    yield ": keepalive\n\n"
                continue
            idle = 0.0
            if subscription.dropped != reported_drops:
                reported_drops = subscription.dropped
                yield _sse(
                    json.dumps({"dropped": reported_drops}),
                    event="dropped",
                )
            yield _sse(
                json.dumps(message.to_dict(), ensure_ascii=False, default=str),
                event=message.topic,
                identifier=message.sequence,
            )
    except GeneratorExit:  # pragma: no cover - raised when the client disconnects
        raise
    finally:
        subscription.close()


@stream.get("/stream")
def sse_stream():
    """Live updates for the browser.

    Optional ``topics=alert_created,incident_created`` narrows the subscription
    server-side, so a page only receives what it will actually display.
    """
    context = current_app.extensions["sentinelforge"]
    requested = request.args.get("topics")
    topics = None
    if requested:
        topics = tuple(
            topic for topic in (name.strip() for name in requested.split(",")) if Topic.is_valid(topic)
        ) or None

    response = Response(
        stream_with_context(event_stream(context, topics)),
        mimetype="text/event-stream",
    )
    # Proxies and browsers must not buffer or cache a live stream.
    response.headers["Cache-Control"] = "no-cache, no-transform"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response
