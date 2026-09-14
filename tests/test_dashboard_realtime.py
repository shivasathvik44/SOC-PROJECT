"""Tests for real-time updates: monitors and the SSE stream (Phase 6).

The monitors are driven synchronously here (``tick()`` rather than ``start()``),
so no test depends on a thread waking up in time and no thread outlives a test.
"""

import json
import threading

import pytest

from conftest import failed_ssh, make_alert
from sentinelforge.bus import Topic
from sentinelforge.correlation.engine import CorrelationEngine
from sentinelforge.dashboard.events import event_stream
from sentinelforge.dashboard.monitor import IncidentWatcher, JsonlTailer, MonitorSet, SensorMonitor
from sentinelforge.dashboard.serializers import serialize_alert, serialize_event
from sentinelforge.dashboard.state import DashboardConfig, DashboardContext, LiveState
from sentinelforge.storage.sqlite import IncidentStore


@pytest.fixture
def watcher(dashboard_context):
    """A primed watcher: existing incidents are known, so only changes fire."""
    monitor = IncidentWatcher(dashboard_context.config, dashboard_context.bus)
    monitor.tick()  # priming pass
    return monitor


def save(db_path, incident):
    with IncidentStore(db_path) as store:
        store.save(incident)


class TestIncidentWatcher:
    def test_priming_does_not_replay_history(self, dashboard_context):
        """Opening the dashboard must not announce every old incident as new."""
        with dashboard_context.bus.subscribe() as subscription:
            monitor = IncidentWatcher(dashboard_context.config, dashboard_context.bus)
            monitor.tick()
            assert subscription.drain() == []

    def test_new_incident_is_published(self, dashboard_context, watcher, incident_db):
        incident = CorrelationEngine().run(
            [make_alert("PORT_SCAN", 9000, "ALT-000009")], start_number=2
        )[0]
        with dashboard_context.bus.subscribe() as subscription:
            save(incident_db, incident)
            watcher.tick()
            messages = subscription.drain()
        assert [message.topic for message in messages] == [Topic.INCIDENT_CREATED]
        assert messages[0].payload["incident_id"] == "INC-000002"
        assert messages[0].payload["severity"]
        assert messages[0].payload["risk_score"] >= 0

    def test_changed_incident_is_an_update_not_a_creation(self, dashboard_context, watcher, incident_db):
        with IncidentStore(incident_db) as store:
            incident = store.get("INC-000001")
            incident.status = "investigating"
            store.save(incident)
        with dashboard_context.bus.subscribe() as subscription:
            watcher.tick()
            messages = subscription.drain()
        assert [message.topic for message in messages] == [Topic.INCIDENT_UPDATED]
        assert messages[0].payload["status"] == "investigating"

    def test_nothing_is_published_when_nothing_changed(self, dashboard_context, watcher):
        with dashboard_context.bus.subscribe() as subscription:
            watcher.tick()
            watcher.tick()
            assert subscription.drain() == []

    def test_ai_analysis_is_announced_once(self, dashboard_context, watcher, incident_db):
        with IncidentStore(incident_db) as store:
            incident = store.get("INC-000001")
            incident.ai_analysis = {
                "status": "ok", "assessment": "likely_malicious", "confidence": 0.9,
                "severity_assessment": "critical", "severity_disagreement": False,
                "audit": {"provider": "mock", "is_mock": True},
            }
            store.save(incident)
        with dashboard_context.bus.subscribe() as subscription:
            watcher.tick()
            topics = [message.topic for message in subscription.drain()]
        assert Topic.AI_ANALYSIS_COMPLETED in topics

        # A later unrelated change must not re-announce the same analysis.
        with IncidentStore(incident_db) as store:
            incident = store.get("INC-000001")
            incident.status = "contained"
            store.save(incident)
        with dashboard_context.bus.subscribe() as subscription:
            watcher.tick()
            topics = [message.topic for message in subscription.drain()]
        assert Topic.AI_ANALYSIS_COMPLETED not in topics

    def test_a_missing_database_does_not_crash_the_watcher(self, tmp_path, dashboard_bus):
        config = DashboardConfig(db_path=str(tmp_path / "nested" / "missing.db"))
        monitor = IncidentWatcher(config, dashboard_bus)
        monitor.tick()
        monitor.tick()
        assert monitor.errors == 0

    def test_deleted_incidents_are_forgotten(self, dashboard_context, watcher, incident_db):
        with IncidentStore(incident_db) as store:
            store.delete("INC-000001")
        watcher.tick()
        assert "INC-000001" not in watcher._revisions


class TestJsonlTailer:
    def test_follows_only_new_lines_by_default(self, tmp_path, dashboard_bus):
        path = tmp_path / "events.jsonl"
        path.write_text(failed_ssh(0).to_json() + "\n")
        tailer = JsonlTailer(str(path), "events", dashboard_bus)
        tailer.tick()  # records the end of the file, publishes nothing

        with dashboard_bus.subscribe() as subscription:
            with path.open("a") as handle:
                handle.write(failed_ssh(60).to_json() + "\n")
            tailer.tick()
            messages = subscription.drain()
        assert len(messages) == 1
        assert messages[0].topic == Topic.EVENT_RECEIVED
        assert messages[0].payload["event_type"] == "authentication_failure"

    def test_from_start_reads_the_whole_file(self, tmp_path, dashboard_bus):
        path = tmp_path / "events.jsonl"
        path.write_text("\n".join(failed_ssh(index * 10).to_json() for index in range(3)) + "\n")
        tailer = JsonlTailer(str(path), "events", dashboard_bus, from_start=True)
        with dashboard_bus.subscribe() as subscription:
            tailer.tick()
            assert len(subscription.drain()) == 3

    def test_alerts_are_published_as_alerts(self, tmp_path, dashboard_bus):
        path = tmp_path / "alerts.jsonl"
        path.write_text(make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001").to_json() + "\n")
        tailer = JsonlTailer(str(path), "alerts", dashboard_bus, from_start=True)
        with dashboard_bus.subscribe() as subscription:
            tailer.tick()
            message = subscription.get(timeout=1.0)
        assert message.topic == Topic.ALERT_CREATED
        assert message.payload["rule_id"] == "SSH_BRUTE_FORCE"
        assert message.payload["mitre"]["technique_id"] == "T1110.001"

    def test_a_partial_line_is_not_published_until_complete(self, tmp_path, dashboard_bus):
        path = tmp_path / "events.jsonl"
        path.write_text("")
        tailer = JsonlTailer(str(path), "events", dashboard_bus, from_start=True)
        line = failed_ssh(0).to_json()
        with path.open("a") as handle:
            handle.write(line[:20])
        tailer.tick()
        assert tailer.published == 0
        with path.open("a") as handle:
            handle.write(line[20:] + "\n")
        tailer.tick()
        assert tailer.published == 1

    def test_malformed_lines_are_skipped_not_rendered(self, tmp_path, dashboard_bus):
        path = tmp_path / "events.jsonl"
        path.write_text('{"broken": \n[]\nnot json at all\n' + failed_ssh(0).to_json() + "\n")
        tailer = JsonlTailer(str(path), "events", dashboard_bus, from_start=True)
        tailer.tick()
        assert tailer.published == 1
        assert tailer.skipped >= 2

    def test_a_missing_file_is_waited_for(self, tmp_path, dashboard_bus):
        path = tmp_path / "not-yet.jsonl"
        tailer = JsonlTailer(str(path), "events", dashboard_bus)
        tailer.tick()
        path.write_text(failed_ssh(0).to_json() + "\n")
        tailer.tick()  # first sight of the file: start at its end
        with path.open("a") as handle:
            handle.write(failed_ssh(30).to_json() + "\n")
        tailer.tick()
        assert tailer.published == 1

    def test_truncation_restarts_the_offset(self, tmp_path, dashboard_bus):
        """A rotated or truncated file is re-read from the top, not skipped."""
        path = tmp_path / "events.jsonl"
        path.write_text("\n".join(failed_ssh(index * 10).to_json() for index in range(3)) + "\n")
        tailer = JsonlTailer(str(path), "events", dashboard_bus, from_start=True)
        tailer.tick()
        assert tailer.published == 3
        path.write_text(failed_ssh(99).to_json() + "\n")  # truncated: now shorter
        tailer.tick()
        assert tailer.published == 4

    def test_unknown_kind_is_rejected(self, tmp_path, dashboard_bus):
        with pytest.raises(ValueError):
            JsonlTailer(str(tmp_path / "x.jsonl"), "incidents", dashboard_bus)

    def test_a_reading_error_never_raises(self, tmp_path, dashboard_bus):
        tailer = JsonlTailer(str(tmp_path), "events", dashboard_bus, from_start=True)
        tailer.tick()  # a directory, not a file
        assert tailer.published == 0


class TestSensorMonitor:
    def test_publishes_only_on_change(self, dashboard_context):
        monitor = SensorMonitor(dashboard_context, dashboard_context.bus)
        with dashboard_context.bus.subscribe() as subscription:
            monitor.tick()  # first pass records the baseline
            assert subscription.drain() == []
            monitor.tick()
            assert subscription.drain() == []

        monitor._previous["ebpf-process"] = not monitor._previous["ebpf-process"]
        with dashboard_context.bus.subscribe() as subscription:
            monitor.tick()
            messages = subscription.drain()
        assert [message.topic for message in messages] == [Topic.SENSOR_STATUS_CHANGED]
        assert messages[0].payload["name"] == "ebpf-process"


class TestLiveState:
    def test_counts_and_buffers_by_topic(self, dashboard_bus):
        state = LiveState(dashboard_bus, buffer_size=10)
        state.record(Topic.EVENT_RECEIVED, serialize_event(failed_ssh(0)))
        state.record(Topic.ALERT_CREATED, serialize_alert(make_alert("SSH_BRUTE_FORCE", 0, "ALT-000001")))
        state.record(Topic.INCIDENT_CREATED, {"incident_id": "INC-000001"})
        state.record(Topic.AI_ANALYSIS_COMPLETED, {"incident_id": "INC-000001"})

        snapshot = state.snapshot()
        assert snapshot["events_received"] == 1
        assert snapshot["alerts_created"] == 1
        assert snapshot["incidents_created"] == 1
        assert snapshot["ai_analyses"] == 1
        assert len(state.recent_events()) == 1
        assert len(state.recent_alerts()) == 1
        assert len(state.recent_activity()) == 4

    def test_buffers_are_bounded(self, dashboard_bus):
        state = LiveState(dashboard_bus, buffer_size=5)
        for index in range(50):
            state.record(Topic.EVENT_RECEIVED, {"index": index})
        assert len(state.events) == 5
        assert state.counters["events_received"] == 50  # the count is not lost
        assert state.recent_events()[0]["payload"]["index"] == 49  # newest first

    def test_events_per_second_is_reported(self, dashboard_bus):
        state = LiveState(dashboard_bus)
        for _ in range(10):
            state.record(Topic.EVENT_RECEIVED, {})
        assert state.events_per_second() >= 0.0

    def test_the_pump_thread_drains_the_bus(self, dashboard_bus):
        state = LiveState(dashboard_bus, buffer_size=10).start()
        try:
            dashboard_bus.publish(Topic.EVENT_RECEIVED, serialize_event(failed_ssh(0)))
            deadline = threading.Event()
            for _ in range(50):
                if state.counters["events_received"]:
                    break
                deadline.wait(0.05)
            assert state.counters["events_received"] == 1
        finally:
            state.stop()

    def test_a_bad_payload_does_not_stop_recording(self, dashboard_bus):
        state = LiveState(dashboard_bus)
        state.record(Topic.EVENT_RECEIVED, {"weird": object()})
        state.record(Topic.EVENT_RECEIVED, {"ok": True})
        assert state.counters["events_received"] == 2


class TestServerSentEvents:
    def collect(self, context, count, publish, topics=None):
        """Run the SSE generator until ``count`` frames have been produced."""
        frames = []
        generator = event_stream(context, topics=topics, keepalive=0.05)
        frames.append(next(generator))  # the "connected" frame
        publish()
        while len(frames) < count + 1:
            frames.append(next(generator))
        generator.close()
        return frames

    def test_stream_starts_with_a_connected_frame(self, dashboard_context):
        generator = event_stream(dashboard_context, keepalive=0.05)
        frame = next(generator)
        generator.close()
        assert "event: connected" in frame
        assert '"message": "connected"' in frame

    def test_published_messages_become_sse_frames(self, dashboard_context):
        def publish():
            dashboard_context.bus.publish(Topic.ALERT_CREATED, {"rule_id": "SSH_BRUTE_FORCE"})

        frames = self.collect(dashboard_context, 1, publish)
        payload = frames[-1]
        assert payload.startswith("event: alert_created")
        assert "id: " in payload
        data_line = [line for line in payload.splitlines() if line.startswith("data: ")][0]
        decoded = json.loads(data_line[len("data: "):])
        assert decoded["payload"]["rule_id"] == "SSH_BRUTE_FORCE"
        assert decoded["topic"] == Topic.ALERT_CREATED

    def test_frames_are_newline_safe(self, dashboard_context):
        """A log line with newlines must not be able to forge an SSE frame."""
        def publish():
            dashboard_context.bus.publish(
                Topic.EVENT_RECEIVED,
                {"message": "line one\nevent: injected\ndata: {\"fake\": true}\n\n"},
            )

        frames = self.collect(dashboard_context, 1, publish)
        body = frames[-1]
        lines = body.rstrip("\n").split("\n")
        # Exactly one event line, one id line and one data line: the injected
        # newlines were JSON-escaped, so they cannot start a frame of their own.
        assert [line for line in lines if line.startswith("event: ")] == ["event: event_received"]
        assert len([line for line in lines if line.startswith("data: ")]) == 1
        assert body.count("\n\n") == 1
        assert "\nevent: injected" not in body

    def test_keepalive_is_sent_when_idle(self, dashboard_context):
        generator = event_stream(dashboard_context, keepalive=0.0)
        next(generator)
        assert next(generator).startswith(": keepalive")
        generator.close()

    def test_topic_filtering_is_applied_server_side(self, dashboard_context):
        def publish():
            dashboard_context.bus.publish(Topic.EVENT_RECEIVED, {"ignored": True})
            dashboard_context.bus.publish(Topic.INCIDENT_CREATED, {"incident_id": "INC-000001"})

        frames = self.collect(dashboard_context, 1, publish, topics=(Topic.INCIDENT_CREATED,))
        assert "incident_created" in frames[-1]
        assert "ignored" not in frames[-1]

    def test_closing_the_generator_unsubscribes(self, dashboard_context):
        generator = event_stream(dashboard_context, keepalive=0.05)
        next(generator)
        assert dashboard_context.bus.subscriber_count >= 1
        generator.close()
        assert dashboard_context.bus.subscriber_count == 0

    def test_stream_endpoint_sets_streaming_headers(self, client):
        response = client.get("/api/stream", buffered=False)
        try:
            assert response.status_code == 200
            assert response.mimetype == "text/event-stream"
            assert "no-cache" in response.headers["Cache-Control"]
            assert response.headers["X-Accel-Buffering"] == "no"
        finally:
            response.close()

    def test_stream_endpoint_rejects_unknown_topics_silently(self, dashboard_app):
        client = dashboard_app.test_client()
        response = client.get("/api/stream?topics=not_a_topic", buffered=False)
        try:
            assert response.status_code == 200
        finally:
            response.close()


class TestMonitorSet:
    def test_builds_the_monitors_the_configuration_asks_for(self, tmp_path, dashboard_bus):
        config = DashboardConfig(
            db_path=str(tmp_path / "x.db"),
            events_file=str(tmp_path / "events.jsonl"),
            alerts_file=str(tmp_path / "alerts.jsonl"),
        )
        context = DashboardContext(config, bus=dashboard_bus)
        try:
            monitors = MonitorSet.for_context(context)
            names = [monitor.name for monitor in monitors.monitors]
            assert any("incident-watcher" in name for name in names)
            assert any("sensor-monitor" in name for name in names)
            assert any("tail-events" in name for name in names)
            assert any("tail-alerts" in name for name in names)
        finally:
            context.stop()

    def test_without_files_only_the_store_and_sensors_are_watched(self, dashboard_context):
        monitors = MonitorSet.for_context(dashboard_context)
        assert len(monitors.monitors) == 2

    def test_start_and_stop_are_clean(self, dashboard_context):
        monitors = MonitorSet.for_context(dashboard_context).start()
        assert all(entry["alive"] for entry in monitors.describe())
        monitors.stop()
        assert not any(entry["alive"] for entry in monitors.describe())
