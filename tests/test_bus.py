"""Tests for the in-process event bus (Phase 6).

The bus is the seam that lets a dashboard watch the pipeline without the
pipeline knowing.  Its contract: deliver to live subscribers, never block a
publisher, never grow without bound, and never hide a drop.
"""

import threading

import pytest

from sentinelforge.bus import BusMessage, EventBus, Topic, default_bus


@pytest.fixture
def bus():
    bus = EventBus()
    yield bus
    bus.close()


class TestPublishSubscribe:
    def test_subscriber_receives_published_messages(self, bus):
        with bus.subscribe() as subscription:
            bus.publish(Topic.ALERT_CREATED, {"rule_id": "SSH_BRUTE_FORCE"})
            message = subscription.get(timeout=1.0)
        assert message.topic == Topic.ALERT_CREATED
        assert message.payload["rule_id"] == "SSH_BRUTE_FORCE"
        assert message.sequence == 1
        assert message.timestamp

    def test_every_subscriber_gets_a_copy(self, bus):
        with bus.subscribe() as first, bus.subscribe() as second:
            bus.publish(Topic.EVENT_RECEIVED, {"n": 1})
            assert first.get(timeout=1.0).payload["n"] == 1
            assert second.get(timeout=1.0).payload["n"] == 1

    def test_topic_filtering(self, bus):
        with bus.subscribe(topics=(Topic.INCIDENT_CREATED,)) as subscription:
            bus.publish(Topic.EVENT_RECEIVED, {"ignored": True})
            bus.publish(Topic.INCIDENT_CREATED, {"incident_id": "INC-000001"})
            message = subscription.get(timeout=1.0)
        assert message.topic == Topic.INCIDENT_CREATED
        assert message.payload["incident_id"] == "INC-000001"

    def test_a_single_topic_may_be_given_as_a_string(self, bus):
        with bus.subscribe(Topic.ALERT_CREATED) as subscription:
            bus.publish(Topic.EVENT_RECEIVED, {})
            bus.publish(Topic.ALERT_CREATED, {"x": 1})
            assert subscription.get(timeout=1.0).topic == Topic.ALERT_CREATED

    def test_sequence_numbers_are_monotonic(self, bus):
        with bus.subscribe() as subscription:
            for index in range(5):
                bus.publish(Topic.EVENT_RECEIVED, {"index": index})
            sequences = [message.sequence for message in subscription.drain()]
        assert sequences == sorted(sequences)
        assert len(set(sequences)) == 5

    def test_publishing_with_no_subscribers_is_harmless(self, bus):
        message = bus.publish(Topic.EVENT_RECEIVED, {"x": 1})
        assert isinstance(message, BusMessage)
        assert bus.published == 1

    def test_payload_is_copied_not_referenced(self, bus):
        payload = {"mutable": True}
        with bus.subscribe() as subscription:
            bus.publish(Topic.EVENT_RECEIVED, payload)
            payload["mutable"] = "changed after publishing"
            assert subscription.get(timeout=1.0).payload["mutable"] is True

    def test_unknown_topic_is_accepted_but_flagged(self, bus, caplog):
        with bus.subscribe() as subscription:
            bus.publish("not_a_real_topic", {})
            assert subscription.get(timeout=1.0).topic == "not_a_real_topic"
        assert any("unknown topic" in record.message for record in caplog.records)


class TestBoundedness:
    def test_a_slow_subscriber_drops_the_oldest_and_counts_it(self, bus):
        subscription = bus.subscribe(maxsize=5)
        for index in range(12):
            bus.publish(Topic.EVENT_RECEIVED, {"index": index})
        messages = subscription.drain()
        subscription.close()

        assert len(messages) == 5
        assert subscription.dropped == 7
        # The survivors are the most recent ones: live views want "now".
        assert [message.payload["index"] for message in messages] == [7, 8, 9, 10, 11]

    def test_a_stalled_subscriber_never_blocks_the_publisher(self, bus):
        """The pipeline must not be slowed down by a browser that stopped reading."""
        bus.subscribe(maxsize=1)  # never drained
        finished = threading.Event()

        def publish_many():
            for index in range(2000):
                bus.publish(Topic.EVENT_RECEIVED, {"index": index})
            finished.set()

        thread = threading.Thread(target=publish_many)
        thread.start()
        thread.join(timeout=5.0)
        assert finished.is_set(), "publishing blocked on a stalled subscriber"
        assert bus.published == 2000


class TestSubscriptionLifecycle:
    def test_unsubscribed_consumers_stop_receiving(self, bus):
        subscription = bus.subscribe()
        subscription.close()
        bus.publish(Topic.EVENT_RECEIVED, {"x": 1})
        assert subscription.get(timeout=0.1) is None
        assert bus.subscriber_count == 0

    def test_context_manager_unsubscribes(self, bus):
        with bus.subscribe():
            assert bus.subscriber_count == 1
        assert bus.subscriber_count == 0

    def test_get_returns_none_on_timeout(self, bus):
        with bus.subscribe() as subscription:
            assert subscription.get(timeout=0.05) is None

    def test_listen_yields_until_closed(self, bus):
        subscription = bus.subscribe()
        received = []

        def consume():
            for message in subscription.listen(timeout=0.1):
                received.append(message)

        thread = threading.Thread(target=consume, daemon=True)
        thread.start()
        bus.publish(Topic.ALERT_CREATED, {"x": 1})
        threading.Event().wait(0.3)
        subscription.close()
        thread.join(timeout=2.0)
        assert [message.payload["x"] for message in received] == [1]

    def test_close_is_idempotent(self, bus):
        subscription = bus.subscribe()
        subscription.close()
        subscription.close()
        assert subscription.closed

    def test_pending_reports_queue_depth(self, bus):
        with bus.subscribe() as subscription:
            bus.publish(Topic.EVENT_RECEIVED, {})
            bus.publish(Topic.EVENT_RECEIVED, {})
            assert subscription.pending == 2


class TestBusContract:
    def test_message_serializes_to_plain_json_types(self, bus):
        import json

        with bus.subscribe() as subscription:
            bus.publish(Topic.INCIDENT_CREATED, {"incident_id": "INC-000001", "risk_score": 94})
            message = subscription.get(timeout=1.0)
        decoded = json.loads(json.dumps(message.to_dict()))
        assert decoded["topic"] == Topic.INCIDENT_CREATED
        assert decoded["payload"]["risk_score"] == 94

    def test_topics_cover_the_pipeline_stages(self):
        for topic in (
            "event_received",
            "alert_created",
            "incident_created",
            "incident_updated",
            "ai_analysis_completed",
            "sensor_status_changed",
        ):
            assert Topic.is_valid(topic)

    def test_subscription_offers_no_way_to_talk_back(self, bus):
        """The bus is one-way: a consumer cannot influence a producer."""
        with bus.subscribe() as subscription:
            for forbidden in ("send", "publish", "reply", "request", "execute"):
                assert not hasattr(subscription, forbidden)

    def test_default_bus_is_shared(self):
        assert default_bus() is default_bus()
