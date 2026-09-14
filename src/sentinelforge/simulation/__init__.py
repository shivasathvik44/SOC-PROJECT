"""Phase 8: attack simulation, purple-team validation and benchmarking.

This package answers one question about the rest of SentinelForge:

    can it reliably detect, correlate, investigate, visualize and safely
    respond to realistic security scenarios?

It answers it by *running* the pipeline, not by describing it.  A
:class:`~sentinelforge.simulation.scenario.Scenario` declares synthetic
telemetry and, separately, what the platform is expected to make of it.  The
:class:`~sentinelforge.simulation.runner.ScenarioRunner` feeds the telemetry
through the real detection, correlation, AI, dashboard and response code and
compares expected against observed, check by check.  Nothing in here decides
that a result is a pass: a check passes when the observation equals the
expectation, and fails otherwise.

**Safety.**  Every scenario is a list of in-memory
:class:`~sentinelforge.models.event.SecurityEvent` objects.  This package

* sends no network traffic and contacts no host, local or remote;
* starts no process, writes no file outside a caller-supplied directory, and
  loads no kernel program;
* never exploits anything, and contains no offensive tooling -- a "sudo
  command" in a scenario is a *string in a log message*, exactly as the
  detection rules see it;
* drives containment through the in-memory mock backends in
  :mod:`sentinelforge.response.backends.mock`, constructed directly rather than
  auto-detected, so a simulation cannot reach a real firewall, process or
  session even when run as root;
* uses addresses from the RFC 5737 / RFC 3849 documentation ranges, which are
  routed nowhere.

It lives in the installed package rather than in ``tests/`` for the same reason
the mock sensor, the mock AI provider and the mock containment backends do: a
demonstrable, offline path through the system is a feature of the product.  It
is also what lets ``sentinelforge simulate`` exist as a command.
"""

from .scenario import (
    BASE_TIME,
    Expectation,
    Scenario,
    ScenarioKind,
    scenario_time,
)
from .results import Check, ScenarioResult, StageResult, Verdict
from .runner import RunnerConfig, ScenarioRunner, run_scenario, run_scenarios
from .scenarios import (
    SCENARIOS,
    all_scenarios,
    attack_scenarios,
    benign_scenarios,
    get_scenario,
    scenario_ids,
)

__all__ = [
    "BASE_TIME",
    "Check",
    "Expectation",
    "RunnerConfig",
    "SCENARIOS",
    "Scenario",
    "ScenarioKind",
    "ScenarioResult",
    "ScenarioRunner",
    "StageResult",
    "Verdict",
    "all_scenarios",
    "attack_scenarios",
    "benign_scenarios",
    "get_scenario",
    "run_scenario",
    "run_scenarios",
    "scenario_ids",
    "scenario_time",
]
