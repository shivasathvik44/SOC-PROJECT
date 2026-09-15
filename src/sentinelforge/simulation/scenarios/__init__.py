"""The scenario registry (Phase 8).

Adding a scenario means writing a module here and listing it in
:data:`SCENARIOS`; the CLI, the runner and the coverage report pick it up
automatically.  Ids are the CLI spelling (``full-attack``), and they are stable:
a report from an earlier run refers to a scenario by this id.
"""

from __future__ import annotations

from ..scenario import Scenario, ScenarioKind
from .auth_probing import INVALID_USER, REMOTE_ROOT_LOGIN, REPEATED_FAILURES
from .benign import BENIGN_SCENARIOS
from .full_attack import SCENARIO as FULL_ATTACK
from .network_connection import SCENARIO as NETWORK_CONNECTION
from .port_scan import SCENARIO as PORT_SCAN
from .process_chain import SCENARIO as PROCESS_CHAIN
from .ssh_bruteforce import SCENARIO as SSH_BRUTEFORCE
from .ssh_compromise import SCENARIO as SSH_COMPROMISE
from .suspicious_sudo import SCENARIO as SUSPICIOUS_SUDO

#: Every scenario, attack ones first, in the order a report should show them.
SCENARIOS: tuple[Scenario, ...] = (
    SSH_BRUTEFORCE,
    SSH_COMPROMISE,
    INVALID_USER,
    REPEATED_FAILURES,
    REMOTE_ROOT_LOGIN,
    SUSPICIOUS_SUDO,
    PROCESS_CHAIN,
    NETWORK_CONNECTION,
    PORT_SCAN,
    FULL_ATTACK,
) + BENIGN_SCENARIOS

_BY_ID = {scenario.scenario_id: scenario for scenario in SCENARIOS}

if len(_BY_ID) != len(SCENARIOS):  # pragma: no cover - a duplicate id is a typo
    raise RuntimeError("two scenarios share an id")


def scenario_ids() -> list[str]:
    """Every scenario id, in registry order."""
    return [scenario.scenario_id for scenario in SCENARIOS]


def get_scenario(scenario_id: str) -> Scenario:
    """Look up one scenario by its CLI id.

    Raises:
        KeyError: with the list of valid ids, so a typo is self-correcting.
    """
    try:
        return _BY_ID[scenario_id]
    except KeyError:
        raise KeyError(
            f"unknown scenario {scenario_id!r}; available: {', '.join(scenario_ids())}"
        ) from None


def all_scenarios() -> list[Scenario]:
    return list(SCENARIOS)


def attack_scenarios() -> list[Scenario]:
    """Scenarios that are expected to alert."""
    return [s for s in SCENARIOS if s.kind == ScenarioKind.ATTACK]


def benign_scenarios() -> list[Scenario]:
    """Scenarios that are expected to stay silent (false-positive testing)."""
    return [s for s in SCENARIOS if s.kind == ScenarioKind.BENIGN]


__all__ = [
    "SCENARIOS",
    "all_scenarios",
    "attack_scenarios",
    "benign_scenarios",
    "get_scenario",
    "scenario_ids",
]
