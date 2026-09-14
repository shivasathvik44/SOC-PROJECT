"""The detection engine: runs rules over events and turns findings into alerts.

Responsibilities kept *out* of the rules on purpose:

* loading and selecting rules,
* isolating failures so one broken rule or malformed event cannot stop a scan,
* risk scoring,
* alert id assignment,
* deduplication / cooldown.

The engine is read-only.  It reads events, it writes alerts, and it does
nothing else -- no blocking, no process control, no system changes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable, Sequence

from ..models.alert import Alert, format_alert_id
from ..models.event import SecurityEvent, Severity, parse_timestamp
from .risk import assess_risk
from .rule import Detection, Rule, time_span
from .rules import default_rules

LOGGER = logging.getLogger(__name__)


@dataclass
class EngineConfig:
    """Engine behaviour knobs.

    Attributes:
        dedup_window_seconds: Within this window, repeats of the same finding
            (same rule + same dedup key) fold into the first alert instead of
            creating new ones.  Set to 0 to disable deduplication.
        min_severity: Drop alerts below this severity from the result.
        max_evidence: Truncate the evidence *stored on the alert*.  ``None``
            (the default) keeps every triggering event, which is what the
            Phase 5 AI analyst will want.
    """

    dedup_window_seconds: int = 300
    min_severity: str | None = None
    max_evidence: int | None = None


@dataclass
class EngineStats:
    """What happened during a run, for the CLI summary and for tests."""

    events_received: int = 0
    events_processed: int = 0
    events_skipped: int = 0
    rules_run: int = 0
    rules_skipped: dict[str, str] = field(default_factory=dict)
    rule_errors: dict[str, str] = field(default_factory=dict)
    alerts_generated: int = 0
    alerts_suppressed: int = 0
    alerts_filtered: int = 0

    def to_dict(self) -> dict:
        return {
            "events_received": self.events_received,
            "events_processed": self.events_processed,
            "events_skipped": self.events_skipped,
            "rules_run": self.rules_run,
            "rules_skipped": dict(self.rules_skipped),
            "rule_errors": dict(self.rule_errors),
            "alerts_generated": self.alerts_generated,
            "alerts_suppressed": self.alerts_suppressed,
            "alerts_filtered": self.alerts_filtered,
        }


class DetectionEngine:
    """Runs a set of :class:`~sentinelforge.detection.rule.Rule` objects.

    Args:
        rules: Rules to run.  Defaults to every built-in rule.
        config: Behaviour knobs; see :class:`EngineConfig`.
    """

    def __init__(
        self, rules: Sequence[Rule] | None = None, config: EngineConfig | None = None
    ) -> None:
        self.rules: list[Rule] = list(rules) if rules is not None else default_rules()
        self.config = config or EngineConfig()
        self.stats = EngineStats()

    # -- public API --------------------------------------------------------
    def run(self, events: Iterable) -> list[Alert]:
        """Evaluate every enabled rule and return the resulting alerts.

        Args:
            events: Normalized events -- :class:`SecurityEvent` objects, or
                dicts as written by ``sentinelforge collect``.

        Returns:
            Alerts sorted chronologically, with sequential ids assigned.
        """
        self.stats = EngineStats()
        prepared = self._prepare(events)

        alerts: list[Alert] = []
        for rule in self.rules:
            alerts.extend(self._run_rule(rule, prepared))

        alerts.sort(key=lambda alert: (alert.timestamp or "", alert.rule_id, alert.name))

        kept: list[Alert] = []
        for alert in alerts:
            if self.config.min_severity and not Severity.at_least(
                alert.severity, self.config.min_severity
            ):
                self.stats.alerts_filtered += 1
                continue
            alert.alert_id = format_alert_id(len(kept) + 1)
            kept.append(alert)

        self.stats.alerts_generated = len(kept)
        return kept

    def rule_status(self, events: Sequence[SecurityEvent] | None = None) -> list[dict]:
        """Describe every loaded rule and whether it can run on these events."""
        events = list(events or [])
        status = []
        for rule in self.rules:
            entry = rule.to_dict()
            reason = None
            if not rule.enabled:
                reason = "disabled"
            try:
                reason = rule.unavailable_reason(events) or reason
            except Exception as exc:  # pragma: no cover - defensive
                reason = f"availability check failed: {exc}"
            entry["available"] = reason is None
            entry["unavailable_reason"] = reason
            status.append(entry)
        return status

    # -- internals ---------------------------------------------------------
    def _prepare(self, events: Iterable) -> list[SecurityEvent]:
        """Coerce input into events, dropping anything unusable.

        A malformed entry is counted and skipped; it never aborts the run.
        """
        prepared: list[SecurityEvent] = []
        for item in events:
            self.stats.events_received += 1
            try:
                if isinstance(item, SecurityEvent):
                    prepared.append(item)
                elif isinstance(item, dict):
                    prepared.append(SecurityEvent.from_dict(item))
                else:
                    raise TypeError(f"expected SecurityEvent or dict, got {type(item).__name__}")
            except Exception as exc:
                self.stats.events_skipped += 1
                LOGGER.warning("skipping malformed event: %s", exc)
                continue
        self.stats.events_processed = len(prepared)
        return prepared

    def _run_rule(self, rule: Rule, events: list[SecurityEvent]) -> list[Alert]:
        """Run one rule, converting its detections into deduplicated alerts."""
        try:
            reason = rule.unavailable_reason(events)
        except Exception as exc:  # pragma: no cover - defensive
            reason = f"availability check failed: {exc}"
        if not rule.enabled:
            # Prefer the concrete reason (missing telemetry) over a bare flag.
            reason = reason or "disabled by default"
        if reason:
            self.stats.rules_skipped[rule.rule_id] = reason
            LOGGER.info("skipping rule %s: %s", rule.rule_id, reason)
            return []

        try:
            detections = list(rule.evaluate(events))
        except Exception as exc:
            # One broken rule must not take the whole engine down.
            self.stats.rule_errors[rule.rule_id] = f"{type(exc).__name__}: {exc}"
            LOGGER.error("rule %s failed: %s", rule.rule_id, exc, exc_info=True)
            return []

        self.stats.rules_run += 1
        return self._deduplicate(rule, detections)

    def _deduplicate(self, rule: Rule, detections: Sequence[Detection]) -> list[Alert]:
        """Fold repeats of the same finding into the first alert.

        Two detections are "the same finding" when they share a rule and a
        dedup key (for example the same attacking IP).  While repeats keep
        arriving inside the cooldown window, the window rolls forward, so one
        long attack produces exactly one alert.
        """
        window = timedelta(seconds=max(0, self.config.dedup_window_seconds))
        alerts: list[Alert] = []
        last_by_key: dict[str, tuple[Alert, object]] = {}

        ordered = sorted(detections, key=lambda d: time_span(d.evidence)[1] or "")
        for detection in ordered:
            alert = self._build_alert(rule, detection)
            moment = parse_timestamp(alert.last_seen)
            key = detection.dedup_key

            previous = last_by_key.get(key)
            if (
                previous is not None
                and window
                and moment is not None
                and previous[1] is not None
                and moment - previous[1] <= window
            ):
                previous[0].suppressed_duplicates += 1
                self.stats.alerts_suppressed += 1
                # Roll the window forward so a continuing attack stays one alert.
                last_by_key[key] = (previous[0], moment)
                continue

            alerts.append(alert)
            last_by_key[key] = (alert, moment)
        return alerts

    def _build_alert(self, rule: Rule, detection: Detection) -> Alert:
        """Turn a detection into a scored, ATT&CK-mapped alert (no id yet)."""
        base_severity = detection.severity or rule.severity
        assessment = assess_risk(base_severity, detection.risk_factors)
        mitre = detection.mitre or rule.mitre
        first_seen, last_seen = time_span(detection.evidence)

        evidence = list(detection.evidence)
        if self.config.max_evidence is not None:
            evidence = evidence[: self.config.max_evidence]

        return Alert(
            alert_id="",  # assigned once all alerts are sorted
            rule_id=rule.rule_id,
            name=detection.name or rule.name,
            description=detection.description or rule.description,
            severity=assessment.severity,
            risk_score=assessment.score,
            timestamp=last_seen,
            host=detection.host,
            source_ip=detection.source_ip,
            user=detection.user,
            evidence=evidence,
            mitre=mitre.to_dict() if mitre else None,
            risk_explanation=assessment.explanation,
            first_seen=first_seen,
            last_seen=last_seen,
        )
