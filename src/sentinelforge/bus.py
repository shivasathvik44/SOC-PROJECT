"""In-process publish/subscribe bus (Phase 6).

The pipeline stages do not know that a dashboard exists, and should not: a
detection rule that has to be aware of a web UI is a rule that will eventually
be changed for the UI's convenience.  This module is the seam between them.
A producer publishes a named message; whoever is listening receives a copy.

Deliberately small:

* in-process only -- no broker, no socket, no Kafka/Redis/RabbitMQ.  SentinelForge
  is a local Linux tool and this is a queue behind a lock;
* **non-blocking** -- publishing never waits for a subscriber.  A slow consumer
  (a browser tab on a saturated link) loses its oldest messages and its drop
  counter goes up; it can never stall the thread that produced the data;
* bounded -- every subscription has a maximum depth, so a forgotten subscriber
  cannot grow without limit;
* one-way -- a subscriber receives data.  There is no request, no reply, and no
  way for a listener to influence the producer.

Payloads are plain dicts that are already safe to serialize (see
:mod:`sentinelforge.dashboard.serializers`).  Nothing on this bus is executed,
and every string in it is treated as untrusted telemetry downstream.
"""

from __future__ import annotations

import itertools
import logging
import threading
from collections import deque
from dataclasses import dataclass
from typing import Iterator

from .models.event import utc_now

LOGGER = logging.getLogger(__name__)


class Topic:
    """Message topics published by SentinelForge.

    The names mirror the pipeline stages, so a subscriber can follow the story
    from raw telemetry to a finished incident without knowing which module
    produced any particular message.
    """

    EVENT_RECEIVED = "event_received"
    ALERT_CREATED = "alert_created"
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    AI_ANALYSIS_COMPLETED = "ai_analysis_completed"
    SENSOR_STATUS_CHANGED = "sensor_status_changed"
    #: A response action changed state (Phase 7).  Published by the response
    #: API after a human acted, so a watching console sees containment happen.
    #: Carrying it on the same bus is what keeps the live view one story.
    RESPONSE_ACTION = "response_action"
    #: Emitted by the bus itself, never by a pipeline stage.
    HEARTBEAT = "heartbeat"

    ALL = (
        EVENT_RECEIVED,
        ALERT_CREATED,
        INCIDENT_CREATED,
        INCIDENT_UPDATED,
        AI_ANALYSIS_COMPLETED,
        SENSOR_STATUS_CHANGED,
        RESPONSE_ACTION,
        HEARTBEAT,
    )

    @staticmethod
    def is_valid(topic: str) -> bool:
        return topic in Topic.ALL


#: Default depth of a subscription queue.  Roughly a screen-full of live
#: activity times a comfortable margin; a browser that falls this far behind is
#: better served by re-reading the API than by replaying stale messages.
DEFAULT_QUEUE_SIZE = 500


@dataclass(frozen=True)
class BusMessage:
    """One published message.

    Attributes:
        topic: One of :class:`Topic`.
        payload: Already-serialized data (plain JSON-safe types).
        sequence: Monotonic per-bus counter.  Lets a client tell "I missed
            some" apart from "nothing happened".
        timestamp: When the bus accepted the message (wall clock, UTC).
    """

    topic: str
    payload: dict
    sequence: int
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "topic": self.topic,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "payload": self.payload,
        }


class Subscription:
    """A bounded mailbox fed by an :class:`EventBus`.

    Use it as a context manager so it is always unsubscribed::

        with bus.subscribe() as messages:
            for message in messages.listen(timeout=1.0):
                ...

    Attributes:
        topics: Topics this subscription wants, or ``None`` for all of them.
        dropped: How many messages were discarded because the consumer was too
            slow.  Reported to the client rather than hidden -- a dashboard
            that silently skips alerts is worse than one that admits it.
    """

    def __init__(
        self,
        bus: "EventBus",
        topics: tuple[str, ...] | None = None,
        maxsize: int = DEFAULT_QUEUE_SIZE,
    ) -> None:
        self.bus = bus
        self.topics = tuple(topics) if topics else None
        self.maxsize = max(1, int(maxsize))
        self.dropped = 0
        self._messages: deque[BusMessage] = deque(maxlen=self.maxsize)
        self._condition = threading.Condition()
        self._closed = False

    # -- producer side -----------------------------------------------------
    def _offer(self, message: BusMessage) -> None:
        """Deliver one message.  Called by the bus, never by a consumer."""
        if self.topics is not None and message.topic not in self.topics:
            return
        with self._condition:
            if self._closed:
                return
            if len(self._messages) == self.maxsize:
                # deque(maxlen=...) evicts the oldest for us; count the loss.
                self.dropped += 1
            self._messages.append(message)
            self._condition.notify()

    # -- consumer side -----------------------------------------------------
    def get(self, timeout: float | None = None) -> BusMessage | None:
        """Return the next message, or ``None`` on timeout / after close."""
        with self._condition:
            if not self._messages and not self._closed:
                self._condition.wait(timeout)
            if self._messages:
                return self._messages.popleft()
            return None

    def drain(self) -> list[BusMessage]:
        """Take everything queued right now, without waiting."""
        with self._condition:
            messages = list(self._messages)
            self._messages.clear()
        return messages

    def listen(self, timeout: float | None = 1.0) -> Iterator[BusMessage]:
        """Yield messages until the subscription is closed.

        Yields nothing on a timeout, which gives the caller a chance to send a
        keep-alive and to notice that the client went away.
        """
        while not self._closed:
            message = self.get(timeout)
            if message is not None:
                yield message

    @property
    def pending(self) -> int:
        with self._condition:
            return len(self._messages)

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        """Unsubscribe and wake any waiting consumer."""
        with self._condition:
            self._closed = True
            self._condition.notify_all()
        self.bus.unsubscribe(self)

    def __enter__(self) -> "Subscription":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


class EventBus:
    """Fan-out of :class:`BusMessage` objects to live subscribers.

    There is no history and no replay: a subscriber sees what happens after it
    subscribes.  Anything durable belongs in the incident store, which is the
    system of record; the bus only carries "this just happened".
    """

    def __init__(self) -> None:
        self._subscribers: list[Subscription] = []
        self._lock = threading.Lock()
        self._sequence = itertools.count(1)
        self.published = 0

    def subscribe(
        self, topics: tuple[str, ...] | str | None = None, maxsize: int = DEFAULT_QUEUE_SIZE
    ) -> Subscription:
        """Create a subscription, optionally restricted to certain topics."""
        if isinstance(topics, str):
            topics = (topics,)
        subscription = Subscription(self, topics, maxsize)
        with self._lock:
            self._subscribers.append(subscription)
        return subscription

    def unsubscribe(self, subscription: Subscription) -> None:
        with self._lock:
            if subscription in self._subscribers:
                self._subscribers.remove(subscription)

    def publish(self, topic: str, payload: dict | None = None) -> BusMessage:
        """Publish one message.  Never blocks, never raises for a bad consumer.

        Args:
            topic: One of :class:`Topic`.  Unknown topics are accepted but
                logged, so a typo shows up instead of vanishing.
            payload: JSON-safe dict.  Serialization happens at the producer, so
                the bus never holds a live model object that another thread
                could mutate underneath a subscriber.
        """
        if not Topic.is_valid(topic):
            LOGGER.warning("publishing unknown topic %r", topic)
        message = BusMessage(
            topic=topic,
            payload=dict(payload or {}),
            sequence=next(self._sequence),
            timestamp=utc_now(),
        )
        with self._lock:
            subscribers = list(self._subscribers)
            self.published += 1
        for subscriber in subscribers:
            try:
                subscriber._offer(message)
            except Exception:  # pragma: no cover - a broken consumer is its own problem
                LOGGER.exception("subscriber rejected a message; dropping it")
        return message

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

    def close(self) -> None:
        """Close every subscription (used at shutdown and in tests)."""
        with self._lock:
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            subscriber.close()


#: Process-wide bus.  A dashboard subscribes to it; monitors publish to it.
_DEFAULT_BUS = EventBus()


def default_bus() -> EventBus:
    """Return the process-wide bus."""
    return _DEFAULT_BUS
