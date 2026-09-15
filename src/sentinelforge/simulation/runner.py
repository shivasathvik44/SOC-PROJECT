"""The scenario runner: simulate, detect, investigate, respond, verify (Phase 8).

The runner drives one scenario through the **real** SentinelForge pipeline and
records, stage by stage, whether what came out matches what the scenario said
should come out::

    scenario events
        -> DetectionEngine            (the real one, default rules)
        -> CorrelationEngine          (the real one, default config)
        -> AISocAnalyst               (offline mock provider)
        -> dashboard serializers      (the real ones)
        -> ResponseEngine             (the real one, in-memory backends)
        -> verification and audit

Two properties matter more than anything else here.

**Nothing is stubbed except the outside world.**  The detection rules, the
correlation logic, the risk scoring, the ATT&CK mapping, the AI schema
validation, the dashboard serializers and the response state machine are the
shipped implementations.  What is replaced is only what would otherwise touch
something real: the language model (the deterministic offline provider) and the
containment mechanisms (the in-memory mock backends, constructed directly here
rather than auto-detected, so this code cannot reach a firewall, a process or a
session even when run as root).

**The runner cannot declare success.**  Every verdict comes from a
:class:`~sentinelforge.simulation.results.Check` built by comparing an
observation against an expectation.  There is no branch in this module that
marks a stage as passing without a comparison, and a stage that raises is
recorded as a failure with the exception text, never swallowed.

Latency is measured with :func:`time.perf_counter` -- a monotonic clock -- and
kept strictly separate from the *event* timestamps, which are synthetic log
times and say nothing about how fast anything ran.
"""

from __future__ import annotations

import logging
import os
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Sequence

from ..ai.analyst import AISocAnalyst, AnalystConfig, attach_analysis
from ..ai.cache import MemoryAnalysisCache
from ..ai.client import LLMClient, LLMConfig
from ..ai.providers.mock import MockProvider
from ..correlation.engine import CorrelationConfig, CorrelationEngine
from ..detection.engine import DetectionEngine, EngineConfig
from ..models.incident import Incident
from ..response.actions import ResponseBackends
from ..response.backends.mock import (
    MockFirewallBackend,
    MockProcessBackend,
    MockSessionBackend,
)
from ..response.engine import ApprovalRequired, ResponseEngine, ResponseError
from ..response.executor import ReadOnlyCommandRunner
from ..response.models import ActionStatus, ActionType
from ..storage.sqlite import IncidentStore
from .results import (
    ScenarioResult,
    StageResult,
    contains_all,
    contains_none,
    equals,
    is_true,
    within,
)
from .scenario import BASE_TIME, Scenario
from .scenarios import all_scenarios, get_scenario

LOGGER = logging.getLogger(__name__)

# -- purple-team stage names (also the keys in a report) -------------------
STAGE_SIMULATION = "simulation"
STAGE_DETECTION = "detection"
STAGE_CORRELATION = "correlation"
STAGE_MITRE = "mitre"
STAGE_RISK = "risk"
STAGE_INVESTIGATION = "investigation"
STAGE_VISUALIZATION = "visualization"
STAGE_RESPONSE = "response"
STAGE_VERIFICATION = "verification"
STAGE_AUDIT = "audit"

STAGES = (
    STAGE_SIMULATION,
    STAGE_DETECTION,
    STAGE_CORRELATION,
    STAGE_MITRE,
    STAGE_RISK,
    STAGE_INVESTIGATION,
    STAGE_VISUALIZATION,
    STAGE_RESPONSE,
    STAGE_VERIFICATION,
    STAGE_AUDIT,
)

#: The operator label recorded on every simulated response action.  It names
#: the simulator, so an audit trail can never present one of these as a
#: decision a real analyst made.
SIMULATION_ACTOR = "phase8-simulator"

#: Stamped on every payload a simulation puts on the bus or into a file, so
#: synthetic activity can never be presented as real telemetry.
SIMULATION_LABEL = "SIMULATED / SYNTHETIC DATA"


@dataclass
class RunnerConfig:
    """What a run does, and how much of the platform it exercises.

    Attributes:
        base_time: Scenario base timestamp.  Fixed by default, which is what
            makes runs reproducible.
        analyze: Run the AI stage (offline mock provider).
        visualize: Run the dashboard serializers.
        respond: Drive the containment lifecycle against in-memory backends.
        persist: Round-trip the incident through a real SQLite store, so
            storage is validated too rather than assumed.
        delay: Seconds to pause between generated events, for a live
            demonstration.  ``0`` (the default) never sleeps.
        detection: Detection engine configuration; the defaults are the
            shipped ones, which is the point.
        correlation: Correlation engine configuration.
        publish: Optional callable invoked as ``publish(topic, payload)`` for
            each generated event and alert, so a running dashboard can show a
            simulation happening.  ``None`` publishes nothing.
    """

    base_time: datetime = BASE_TIME
    analyze: bool = True
    visualize: bool = True
    respond: bool = True
    persist: bool = True
    delay: float = 0.0
    detection: EngineConfig = field(default_factory=EngineConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    publish: object | None = None


def simulation_backends(events: Sequence = ()) -> ResponseBackends:
    """In-memory containment backends populated from a scenario's telemetry.

    Built by hand rather than through :meth:`ResponseBackends.detect`, which is
    the safety property that matters: there is no code path from a simulation
    to this host's firewall, process table or logind, regardless of privileges.

    Every PID the scenario's process telemetry mentions is registered, so a
    ``kill_process`` action has a real (synthetic) target to validate against
    instead of failing for an unrelated reason.
    """
    process = MockProcessBackend()
    seen: set[int] = set()
    for event in events:
        metadata = getattr(event, "metadata", None) or {}
        pid = metadata.get("pid")
        if not isinstance(pid, int) or pid in seen:
            continue
        seen.add(pid)
        process.add(
            pid,
            ppid=metadata.get("ppid") or 1,
            name=getattr(event, "process", None) or "unknown",
            executable=metadata.get("executable"),
            command_line=metadata.get("command_line"),
            username=getattr(event, "user", None) or "unknown",
            uid=metadata.get("uid", 1000),
        )
    session = MockSessionBackend()
    session.add("42", name="deploy", remotehost="203.0.113.10")
    return ResponseBackends(
        firewall=MockFirewallBackend(),
        process=process,
        session=session,
        runner=ReadOnlyCommandRunner(),
    )


@contextmanager
def _scratch_database(path: str | None = None):
    """A private SQLite file for one run, removed afterwards.

    A simulation must never write into the analyst's real incident database,
    so the default is a fresh temporary directory rather than
    :func:`~sentinelforge.storage.sqlite.default_database_path`.
    """
    if path is not None:
        yield path
        return
    directory = tempfile.mkdtemp(prefix="sentinelforge-sim-")
    try:
        yield os.path.join(directory, "simulation.db")
    finally:
        for name in os.listdir(directory):
            try:
                os.remove(os.path.join(directory, name))
            except OSError:  # pragma: no cover - best effort cleanup
                pass
        try:
            os.rmdir(directory)
        except OSError:  # pragma: no cover - best effort cleanup
            pass


class _Timer:
    """Monotonic stage timing, in milliseconds."""

    def __init__(self) -> None:
        self.timings: dict[str, float] = {}

    @contextmanager
    def measure(self, name: str):
        started = time.perf_counter()
        try:
            yield
        finally:
            self.timings[name] = (time.perf_counter() - started) * 1000.0


class ScenarioRunner:
    """Runs scenarios and reports expected versus observed, stage by stage.

    Args:
        config: See :class:`RunnerConfig`.  The defaults exercise the whole
            platform offline.
        db_path: Where the run's incidents and response actions are stored.
            ``None`` (the default) uses a temporary file that is deleted
            afterwards.
    """

    def __init__(self, config: RunnerConfig | None = None, db_path: str | None = None) -> None:
        self.config = config or RunnerConfig()
        self.db_path = db_path

    # -- public API --------------------------------------------------------
    def run(self, scenario: Scenario | str) -> ScenarioResult:
        """Run one scenario and return its result.  Never raises for a failure."""
        if isinstance(scenario, str):
            scenario = get_scenario(scenario)

        result = ScenarioResult(
            scenario_id=scenario.scenario_id,
            name=scenario.name,
            kind=scenario.kind,
            description=scenario.description,
            notes=scenario.expected.notes,
            mitre_techniques=tuple(scenario.mitre_techniques),
        )
        timer = _Timer()
        try:
            with _scratch_database(self.db_path) as db_path:
                self._run_stages(scenario, result, timer, db_path)
        except Exception as exc:  # pragma: no cover - defensive; a bug is a failure
            LOGGER.exception("scenario %s raised", scenario.scenario_id)
            result.error = f"{type(exc).__name__}: {exc}"
        result.timings = timer.timings
        return result

    def run_all(self, scenarios: Iterable[Scenario] | None = None) -> list[ScenarioResult]:
        """Run several scenarios, in order."""
        return [self.run(scenario) for scenario in (scenarios or all_scenarios())]

    # -- stages ------------------------------------------------------------
    def _run_stages(
        self, scenario: Scenario, result: ScenarioResult, timer: _Timer, db_path: str
    ) -> None:
        events = self._stage_simulation(scenario, result, timer)
        alerts = self._stage_detection(scenario, result, timer, events)
        incidents = self._stage_correlation(scenario, result, timer, alerts, db_path)

        incident = incidents[0] if incidents else None
        self._stage_mitre(scenario, result, incident)
        self._stage_risk(scenario, result, incident)
        self._stage_investigation(scenario, result, timer, incident, db_path)
        self._stage_visualization(scenario, result, timer, incident)
        self._stage_response(scenario, result, timer, incident, events, db_path)

    # -- 1. simulate -------------------------------------------------------
    def _stage_simulation(
        self, scenario: Scenario, result: ScenarioResult, timer: _Timer
    ) -> list:
        stage = result.stage(STAGE_SIMULATION)
        with timer.measure(STAGE_SIMULATION):
            events = scenario.events(self.config.base_time)
        result.events = events

        stage.add(equals("simulation.event_count", scenario.expected.events, len(events)))
        # Reproducibility is a property of the scenario, so it is checked, not
        # asserted in a comment: build it a second time and compare the JSON.
        replay = scenario.events(self.config.base_time)
        stage.add(
            equals(
                "simulation.deterministic",
                True,
                [event.to_json() for event in events] == [e.to_json() for e in replay],
                "rebuilding the scenario must produce identical events",
            )
        )
        stage.duration_ms = result.timings.get(STAGE_SIMULATION, 0.0)
        # Publishing and demonstration pacing happen *outside* the measured
        # region: a --delay of half a second must not appear as pipeline cost.
        self._publish_events(events)
        return events

    def _publish_events(self, events: Sequence) -> None:
        """Optionally announce generated events, for a live demonstration."""
        publish = self.config.publish
        if publish is None:
            return
        from ..bus import Topic
        from ..dashboard.serializers import serialize_event

        for index, event in enumerate(events):
            if self.config.delay and index:
                time.sleep(self.config.delay)
            payload = serialize_event(event)
            payload.update({"simulated": True, "simulation_label": SIMULATION_LABEL})
            publish(Topic.EVENT_RECEIVED, payload)

    # -- 2. detect ---------------------------------------------------------
    def _stage_detection(
        self, scenario: Scenario, result: ScenarioResult, timer: _Timer, events: Sequence
    ) -> list:
        stage = result.stage(STAGE_DETECTION)
        engine = DetectionEngine(config=self.config.detection)
        with timer.measure(STAGE_DETECTION):
            alerts = engine.run(events)
        result.alerts = alerts
        stage.duration_ms = result.timings.get(STAGE_DETECTION, 0.0)

        fired = sorted({alert.rule_id for alert in alerts})
        result.observed["rule_ids"] = fired
        result.observed["alert_count"] = len(alerts)

        stage.add(equals("detection.alert_count", scenario.expected.alerts, len(alerts)))
        if scenario.expected.rule_ids:
            stage.add(contains_all("detection.rules_fired", scenario.expected.rule_ids, fired))
        if scenario.expected.forbidden_rule_ids:
            stage.add(
                contains_none(
                    "detection.rules_silent", scenario.expected.forbidden_rule_ids, fired
                )
            )
        # A rule that crashed is not a rule that found nothing.
        stage.add(
            equals("detection.rule_errors", {}, dict(engine.stats.rule_errors))
        )
        stage.add(
            equals("detection.events_skipped", 0, engine.stats.events_skipped)
        )
        self._publish_alerts(alerts)
        return alerts

    def _publish_alerts(self, alerts: Sequence) -> None:
        publish = self.config.publish
        if publish is None:
            return
        from ..bus import Topic
        from ..dashboard.serializers import serialize_alert

        for alert in alerts:
            payload = serialize_alert(alert)
            payload.update({"simulated": True, "simulation_label": SIMULATION_LABEL})
            publish(Topic.ALERT_CREATED, payload)

    # -- 3. correlate ------------------------------------------------------
    def _stage_correlation(
        self,
        scenario: Scenario,
        result: ScenarioResult,
        timer: _Timer,
        alerts: Sequence,
        db_path: str,
    ) -> list:
        stage = result.stage(STAGE_CORRELATION)
        engine = CorrelationEngine(config=self.config.correlation)
        with timer.measure(STAGE_CORRELATION):
            incidents = engine.run(alerts)
        result.incidents = incidents
        stage.duration_ms = result.timings.get(STAGE_CORRELATION, 0.0)

        expected = scenario.expected
        result.observed["incident_count"] = len(incidents)
        stage.add(equals("correlation.incident_count", expected.incidents, len(incidents)))
        stage.add(equals("correlation.alerts_skipped", 0, engine.stats.alerts_skipped))

        if not incidents:
            if expected.incidents == 0:
                stage.add(
                    equals(
                        "correlation.no_incident_expected", 0, len(incidents),
                        "benign activity must not produce an incident",
                    )
                )
            return incidents

        incident = incidents[0]
        result.observed["incident_id"] = incident.incident_id
        result.observed["matched_chains"] = list(incident.matched_chains)
        result.observed["source_ips"] = list(incident.source_ips)
        result.observed["users"] = list(incident.users)

        stage.add(
            equals("correlation.alerts_in_incident", len(alerts), incident.alert_count,
                   "every alert from one scenario belongs to that scenario's incident")
        )
        if expected.source_ips:
            stage.add(
                contains_all("correlation.source_ips", expected.source_ips, incident.source_ips)
            )
        if expected.users:
            stage.add(contains_all("correlation.users", expected.users, incident.users))
        if expected.attack_chains:
            stage.add(
                contains_all(
                    "correlation.attack_chains", expected.attack_chains, incident.matched_chains
                )
            )
        stage.add(
            is_true(
                "correlation.timeline_built",
                bool(incident.timeline),
                "a non-empty chronological timeline",
            )
        )
        stage.add(
            is_true(
                "correlation.timeline_ordered",
                _is_ordered(incident),
                "entries in chronological order",
            )
        )

        if self.config.persist:
            self._check_persistence(stage, incident, db_path)
        return incidents

    def _check_persistence(self, stage: StageResult, incident: Incident, db_path: str) -> None:
        """Store and reload the incident: a round trip nothing may lose."""
        try:
            with IncidentStore(db_path) as store:
                store.save(incident)
                reloaded = store.get(incident.incident_id)
        except Exception as exc:  # pragma: no cover - storage failure is a failure
            stage.fail(f"persistence failed: {type(exc).__name__}: {exc}")
            return
        stage.add(
            equals(
                "correlation.storage_round_trip",
                incident.version,
                reloaded.version if reloaded else None,
                "the stored incident must be the incident that was correlated",
            )
        )

    # -- 4. ATT&CK ---------------------------------------------------------
    def _stage_mitre(
        self, scenario: Scenario, result: ScenarioResult, incident: Incident | None
    ) -> None:
        stage = result.stage(STAGE_MITRE)
        expected = scenario.expected.techniques
        if incident is None:
            stage.skip("no incident was produced, so there is no ATT&CK chain to check")
            return
        observed = incident_techniques(incident)
        result.observed["techniques"] = sorted(observed)
        if expected:
            stage.add(contains_all("mitre.techniques", expected, observed))
        stage.add(
            equals(
                "mitre.every_alert_mapped",
                incident.alert_count,
                sum(1 for alert in incident.alerts if alert.mitre),
                "every alert carries an ATT&CK mapping",
            )
        )
        stage.add(
            equals(
                "mitre.attack_chain_entries",
                len({(m.get("technique_id"), m.get("sub_technique_id")) for m in
                     (alert.mitre for alert in incident.alerts) if m}),
                len(incident.attack_chain),
                "the aggregated chain lists each technique exactly once",
            )
        )

    # -- 5. risk -----------------------------------------------------------
    def _stage_risk(
        self, scenario: Scenario, result: ScenarioResult, incident: Incident | None
    ) -> None:
        stage = result.stage(STAGE_RISK)
        expected = scenario.expected
        if incident is None:
            stage.skip("no incident was produced, so there is no risk score to check")
            return
        result.observed["severity"] = incident.severity
        result.observed["risk_score"] = incident.risk_score
        if expected.severity:
            stage.add(equals("risk.severity", expected.severity, incident.severity))
        if expected.risk_range:
            stage.add(within("risk.score", expected.risk_range, incident.risk_score))
        stage.add(
            is_true(
                "risk.explained",
                bool(incident.risk_explanation),
                "every point of the score accounted for",
            )
        )

    # -- 6. investigate (AI) ----------------------------------------------
    def _stage_investigation(
        self,
        scenario: Scenario,
        result: ScenarioResult,
        timer: _Timer,
        incident: Incident | None,
        db_path: str,
    ) -> None:
        stage = result.stage(STAGE_INVESTIGATION)
        if not self.config.analyze:
            stage.skip("AI analysis was disabled for this run")
            return
        if incident is None:
            stage.skip("no incident was produced, so there was nothing to analyze")
            return

        analyst = AISocAnalyst(
            LLMClient(MockProvider(), LLMConfig(), sleep=lambda _: None),
            AnalystConfig(),
            cache=MemoryAnalysisCache(),
        )
        with timer.measure(STAGE_INVESTIGATION):
            analysis = analyst.analyze(incident)
        stage.duration_ms = result.timings.get(STAGE_INVESTIGATION, 0.0)
        result.analysis = analysis

        stage.add(equals("ai.status", "ok", analysis.status, analysis.error or ""))
        if not analysis.ok:
            return
        attach_analysis(incident, analysis)
        result.observed["ai_assessment"] = analysis.assessment
        result.observed["ai_severity"] = analysis.severity_assessment
        result.observed["ai_confidence"] = analysis.confidence

        stage.add(within("ai.confidence", (0, 1), analysis.confidence))
        stage.add(is_true("ai.summary_present", bool(analysis.summary.strip())))
        stage.add(is_true("ai.evidence_present", bool(analysis.key_evidence)))
        stage.add(
            is_true("ai.investigation_steps_present", bool(analysis.investigation_steps))
        )
        stage.add(
            is_true(
                "ai.false_positive_indicators_present",
                bool(analysis.false_positive_indicators),
                "a Tier-1 reading must offer benign explanations too",
            )
        )
        # The deterministic verdict must survive the AI stage untouched, and
        # both verdicts must remain visible side by side.
        stage.add(
            equals(
                "ai.deterministic_severity_preserved",
                incident.severity,
                analysis.deterministic_severity,
            )
        )
        stage.add(
            equals(
                "ai.deterministic_score_preserved",
                incident.risk_score,
                analysis.deterministic_score,
            )
        )
        stage.add(
            is_true(
                "ai.labelled_as_mock",
                analysis.audit.is_mock,
                "offline provider output is labelled",
            )
        )
        # Any technique the model names must come from the deterministic chain;
        # an invented one would be the model adding evidence.
        deterministic = incident_techniques(incident)
        invented = sorted(
            {item.technique_id for item in analysis.mitre_analysis} - deterministic
        )
        stage.add(
            equals("ai.no_invented_techniques", [], invented,
                   "the model may interpret the mapped techniques, not add new ones")
        )
        if self.config.persist:
            try:
                with IncidentStore(db_path) as store:
                    store.save(incident)
                    reloaded = store.get(incident.incident_id)
                stage.add(
                    is_true(
                        "ai.analysis_persisted",
                        bool(reloaded and reloaded.ai_analysis),
                        "the analysis is stored beside the incident",
                    )
                )
            except Exception as exc:  # pragma: no cover - storage failure is a failure
                stage.fail(f"storing the analysis failed: {type(exc).__name__}: {exc}")

    # -- 7. visualize ------------------------------------------------------
    def _stage_visualization(
        self,
        scenario: Scenario,
        result: ScenarioResult,
        timer: _Timer,
        incident: Incident | None,
    ) -> None:
        stage = result.stage(STAGE_VISUALIZATION)
        if not self.config.visualize:
            stage.skip("dashboard serialization was disabled for this run")
            return
        if incident is None:
            stage.skip("no incident was produced, so there was nothing to render")
            return
        try:
            from ..dashboard.serializers import (
                serialize_ai_analysis,
                serialize_attack_chain,
                serialize_incident_detail,
                serialize_network,
                serialize_process_tree,
                serialize_timeline,
                suggested_response_targets,
            )
        except ImportError as exc:  # pragma: no cover - serializers are dependency-free
            stage.skip(f"dashboard serializers unavailable: {exc}")
            return

        expected = scenario.expected
        with timer.measure(STAGE_VISUALIZATION):
            detail = serialize_incident_detail(incident)
            timeline = serialize_timeline(incident)
            chain = serialize_attack_chain(incident)
            tree = serialize_process_tree(incident)
            network = serialize_network(incident)
            ai_view = serialize_ai_analysis(incident)
            targets = suggested_response_targets(incident)
        stage.duration_ms = result.timings.get(STAGE_VISUALIZATION, 0.0)

        stage.add(equals("dashboard.incident_id", incident.incident_id, detail.get("incident_id")))
        stage.add(
            equals("dashboard.timeline_entries", len(incident.timeline),
                   len(timeline.get("entries") or []))
        )
        stage.add(
            equals("dashboard.attack_chain_length", len(incident.attack_chain),
                   len(chain.get("techniques") or []))
        )

        pids = _tree_pids(tree)
        result.observed["process_tree_pids"] = sorted(pids)
        if expected.process_tree_pids:
            stage.add(contains_all("dashboard.process_tree", expected.process_tree_pids, pids))
        if expected.process_tree_missing_pids is not None:
            # The documented visibility gap, measured rather than assumed: a
            # process the sensors observed but no rule alerted on is not part
            # of the incident's evidence, so the lineage cannot show it.
            missing = telemetry_pids(result.events) - pids
            result.observed["process_tree_gap"] = sorted(missing)
            stage.add(
                equals(
                    "dashboard.process_tree_gap",
                    set(expected.process_tree_missing_pids),
                    missing,
                    "PIDs the telemetry contained that the incident-scoped tree omits",
                )
            )

        destinations = {
            f"{item.get('destination_ip')}:{item.get('destination_port')}"
            for item in (network.get("connections") or [])
        }
        result.observed["network_destinations"] = sorted(destinations)
        if expected.network_destinations:
            stage.add(
                contains_all(
                    "dashboard.network_destinations", expected.network_destinations, destinations
                )
            )
            stage.add(
                is_true(
                    "dashboard.network_fields_complete",
                    _network_fields_complete(network),
                    "pid, process, destination, port, protocol and timestamp all present",
                )
            )

        if self.config.analyze and incident.ai_analysis:
            stage.add(
                is_true(
                    "dashboard.ai_beside_deterministic",
                    bool(ai_view.get("available"))
                    and ai_view.get("deterministic_severity") == incident.severity,
                    "the AI reading is served next to the deterministic verdict",
                )
            )

        options = _response_options(targets)
        result.observed["response_options"] = sorted(options)
        stage.add(
            equals("dashboard.response_options", set(expected.response_options), options,
                   "containment options offered by this incident's own evidence")
        )

    # -- 8/9/10. respond, verify, audit ------------------------------------
    def _stage_response(
        self,
        scenario: Scenario,
        result: ScenarioResult,
        timer: _Timer,
        incident: Incident | None,
        events: Sequence,
        db_path: str,
    ) -> None:
        response = result.stage(STAGE_RESPONSE)
        verification = result.stage(STAGE_VERIFICATION)
        audit_stage = result.stage(STAGE_AUDIT)

        if not self.config.respond:
            for stage in (response, verification, audit_stage):
                stage.skip("response validation was disabled for this run")
            return
        if incident is None or scenario.containment_target is None:
            reason = (
                "no incident was produced" if incident is None
                else "this scenario declares no containment target"
            )
            for stage in (response, verification, audit_stage):
                stage.skip(reason)
            return

        action_type, target = scenario.containment_target
        engine = ResponseEngine(
            db_path=db_path,
            backends=simulation_backends(events),
            actor=SIMULATION_ACTOR,
        )
        try:
            self._drive_response(
                engine, response, verification, audit_stage, result, timer,
                incident, action_type, target,
            )
        except Exception as exc:
            LOGGER.exception("response validation raised")
            response.fail(f"{type(exc).__name__}: {exc}")

    def _drive_response(
        self,
        engine: ResponseEngine,
        response: StageResult,
        verification: StageResult,
        audit_stage: StageResult,
        result: ScenarioResult,
        timer: _Timer,
        incident: Incident,
        action_type: str,
        target: str,
    ) -> None:
        """Preview -> request -> (bypass refused) -> approve -> execute -> verify -> audit."""
        with timer.measure(STAGE_RESPONSE):
            preview = engine.preview(action_type, target, incident_id=incident.incident_id)
            response.add(
                is_true("response.preview_allowed", bool(preview.get("would_be_allowed")),
                        detail=str((preview.get("policy") or {}).get("reason", "")))
            )

            action = engine.request(
                action_type,
                target,
                incident_id=incident.incident_id,
                reason="Phase 8 purple-team validation against in-memory backends",
                requested_by=SIMULATION_ACTOR,
            )
            response.add(
                equals("response.requested", ActionStatus.AWAITING_APPROVAL, action.status)
            )

            # The central guarantee, exercised rather than asserted: executing
            # before a human approves must be refused.
            bypassed = False
            refusal = ""
            try:
                engine.execute(action.action_id)
                bypassed = True
            except ApprovalRequired as exc:
                refusal = str(exc)
            except ResponseError as exc:  # pragma: no cover - any refusal is a refusal
                refusal = str(exc)
            response.add(
                equals("response.execution_without_approval_refused", False, bypassed, refusal)
            )

            approved = engine.approve(action.action_id, approved_by=SIMULATION_ACTOR)
            response.add(equals("response.approved", ActionStatus.APPROVED, approved.status))

            executed = engine.execute(action.action_id, executed_by=SIMULATION_ACTOR)
        response.duration_ms = result.timings.get(STAGE_RESPONSE, 0.0)
        result.action = executed

        response.add(equals("response.executed", ActionStatus.COMPLETED, executed.status,
                            executed.error or ""))
        verification.add(
            is_true("verification.verified", bool(executed.verified), detail=executed.verification or "")
        )
        verification.add(
            is_true("verification.explained", bool(executed.verification),
                    "the engine says how it confirmed the effect")
        )

        # Rollback, where the action type has one.  A terminated process does
        # not, and claiming otherwise would be a lie about containment.
        if action_type == ActionType.BLOCK_IP:
            rolled_back = engine.rollback(executed.action_id, actor=SIMULATION_ACTOR)
            result.observed["rollback_status"] = rolled_back.status
            verification.add(
                equals("verification.rolled_back", ActionStatus.ROLLED_BACK, rolled_back.status)
            )
            verification.add(
                equals(
                    "verification.containment_removed",
                    {},
                    dict(engine.backends.firewall.rules),
                    "the rollback left no rule behind in the mock firewall",
                )
            )
        else:
            verification.add(
                equals(
                    "verification.rollback_offered", False, bool(executed.rollback_available),
                    "terminating a process is not reversible, and is not offered as such",
                )
            )

        records = engine.audit_records(action_id=executed.action_id)
        result.audit = records
        kinds = [record.get("event") for record in records]
        audit_stage.add(
            contains_all("audit.lifecycle_recorded", {"requested", "approved", "executed"}, kinds)
        )
        audit_stage.add(
            equals("audit.every_record_linked", len(records),
                   sum(1 for r in records if r.get("action_id") == executed.action_id))
        )
        chain = engine.verify_audit()
        audit_stage.add(
            is_true(
                "audit.hash_chain_intact",
                bool(chain.get("ok")),
                detail=str(chain.get("detail") or ""),
            )
        )
        audit_stage.add(
            equals("audit.records_checked", len(records), int(chain.get("checked") or 0),
                   "the verified chain covers every record this action wrote")
        )


# -- shared helpers --------------------------------------------------------
def incident_techniques(incident: Incident) -> set[str]:
    """Every ATT&CK id on an incident's aggregated chain, parents included."""
    found: set[str] = set()
    for mapping in incident.attack_chain:
        for key in ("technique_id", "sub_technique_id"):
            value = mapping.get(key)
            if value:
                found.add(value)
    return found


def _is_ordered(incident: Incident) -> bool:
    keys = [entry.sort_key() for entry in incident.timeline]
    return keys == sorted(keys)


def telemetry_pids(events: Sequence) -> set[int]:
    """Every PID the scenario's own telemetry mentions."""
    found: set[int] = set()
    for event in events:
        metadata = getattr(event, "metadata", None) or {}
        for key in ("pid", "ppid"):
            value = metadata.get(key)
            if isinstance(value, int):
                found.add(value)
    return found


def _tree_pids(tree: dict) -> set[int]:
    """Every PID in a serialized process tree, at any depth."""
    found: set[int] = set()

    def walk(nodes):
        for node in nodes or ():
            pid = node.get("pid")
            if isinstance(pid, int):
                found.add(pid)
            walk(node.get("children"))

    walk(tree.get("roots"))
    return found


def _network_fields_complete(network: dict) -> bool:
    """Whether every serialized connection kept the fields a SOC needs."""
    connections = network.get("connections") or []
    if not connections:
        return False
    required = ("pid", "process", "destination_ip", "destination_port", "protocol", "timestamp")
    return all(
        all(item.get(field) not in (None, "") for field in required) for item in connections
    )


def _response_options(targets: dict) -> set[str]:
    """Containment action types an incident's own evidence makes possible."""
    options: set[str] = set()
    if targets.get("source_ips"):
        options.add(ActionType.BLOCK_IP)
    if targets.get("processes"):
        options.add(ActionType.KILL_PROCESS)
    return options


def run_scenario(scenario: Scenario | str, config: RunnerConfig | None = None) -> ScenarioResult:
    """Convenience wrapper: run one scenario with the default configuration."""
    return ScenarioRunner(config).run(scenario)


def run_scenarios(
    scenarios: Iterable[Scenario] | None = None, config: RunnerConfig | None = None
) -> list[ScenarioResult]:
    """Convenience wrapper: run several scenarios with one runner."""
    return ScenarioRunner(config).run_all(scenarios)
