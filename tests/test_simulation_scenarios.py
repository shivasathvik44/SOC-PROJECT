"""Phase 8: the scenario definitions themselves.

Before any scenario is trusted to validate SentinelForge, the scenarios have to
be trustworthy.  These tests check the properties the rest of Phase 8 assumes:

* **Safety.**  Every address a scenario uses is from a documentation range, and
  no scenario module can reach the network, a shell or the file system.
* **Determinism.**  Rebuilding a scenario produces byte-identical events.
* **Honesty.**  An expectation is *declared*, never derived from a run - a
  scenario that computed its own expectations would always pass.
* **Coverage.**  Every rule SentinelForge ships is exercised by some scenario,
  and every ATT&CK id a scenario claims is in the real catalogue.
"""

import ast
import ipaddress
import pathlib

import pytest

from sentinelforge.detection.mitre import TECHNIQUES
from sentinelforge.detection.rules import default_rules
from sentinelforge.models.event import EventType, SecurityEvent, parse_timestamp
from sentinelforge.simulation import scenario as scenario_module
from sentinelforge.simulation.scenario import BASE_TIME, ScenarioKind
from sentinelforge.simulation.scenarios import (
    SCENARIOS,
    all_scenarios,
    attack_scenarios,
    benign_scenarios,
    get_scenario,
    scenario_ids,
)

SCENARIO_PACKAGE = pathlib.Path(scenario_module.__file__).parent / "scenarios"

#: Ranges a scenario may use: RFC 5737 documentation, RFC 1918 private, and
#: loopback.  Anything else would name a host that might really exist.
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "2001:db8::/32",
    )
)


def _addresses(event: SecurityEvent) -> list[str]:
    found = [event.src_ip]
    for key in ("source_ip", "destination_ip"):
        found.append((event.metadata or {}).get(key))
    return [value for value in found if value]


@pytest.fixture(params=[s.scenario_id for s in SCENARIOS])
def scenario(request):
    return get_scenario(request.param)


class TestRegistry:
    def test_every_scenario_has_a_unique_id(self):
        ids = scenario_ids()
        assert len(ids) == len(set(ids))

    def test_ids_are_cli_spelled(self):
        for scenario_id in scenario_ids():
            assert scenario_id == scenario_id.lower()
            assert " " not in scenario_id and "_" not in scenario_id

    def test_the_six_required_scenarios_exist(self):
        """The scenarios Phase 8 is specified to provide."""
        for required in (
            "ssh-bruteforce",
            "ssh-compromise",
            "suspicious-sudo",
            "process-chain",
            "network-connection",
            "full-attack",
        ):
            assert get_scenario(required).kind == ScenarioKind.ATTACK

    def test_unknown_id_names_the_valid_ones(self):
        with pytest.raises(KeyError) as excinfo:
            get_scenario("no-such-scenario")
        assert "full-attack" in str(excinfo.value)

    def test_attack_and_benign_partition_the_registry(self):
        assert len(attack_scenarios()) + len(benign_scenarios()) == len(all_scenarios())
        assert benign_scenarios(), "false-positive testing needs benign scenarios"


class TestSafety:
    def test_only_documentation_or_private_addresses(self, scenario):
        for event in scenario.events():
            for address in _addresses(event):
                parsed = ipaddress.ip_address(address)
                assert any(parsed in network for network in ALLOWED_NETWORKS), (
                    f"{scenario.scenario_id} uses {address}, which is a routable "
                    "address that may belong to a real host"
                )

    def test_scenario_modules_import_nothing_dangerous(self):
        """A scenario is data.  It must not be able to reach the outside world."""
        forbidden = {"subprocess", "socket", "os", "shutil", "requests", "urllib", "http"}
        for path in sorted(SCENARIO_PACKAGE.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = {alias.name.split(".")[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom):
                    names = {(node.module or "").split(".")[0]}
                else:
                    continue
                assert not (names & forbidden), f"{path.name} imports {names & forbidden}"

    def test_scenario_modules_never_call_eval_or_exec(self):
        for path in sorted(SCENARIO_PACKAGE.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            called = {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            assert not (called & {"eval", "exec", "compile", "__import__"})

    def test_sudo_commands_are_only_ever_log_text(self):
        """A 'command' in a scenario lives inside a message and nowhere else."""
        for scenario in all_scenarios():
            for event in scenario.events():
                if event.event_type != EventType.SUDO:
                    continue
                assert "COMMAND=" in event.message
                # It is on the event as text, not as a structured invocation.
                assert "command" not in (event.metadata or {})


class TestDeterminism:
    def test_rebuilding_produces_identical_events(self, scenario):
        first = [event.to_json() for event in scenario.events()]
        second = [event.to_json() for event in scenario.events()]
        assert first == second

    def test_events_are_anchored_to_the_fixed_base_time(self, scenario):
        for event in scenario.events():
            moment = parse_timestamp(event.timestamp)
            assert moment is not None
            assert moment >= BASE_TIME

    def test_a_different_base_time_shifts_every_event(self, scenario):
        from datetime import timedelta

        shifted = scenario.events(BASE_TIME + timedelta(days=1))
        original = scenario.events()
        assert len(shifted) == len(original)
        for before, after in zip(original, shifted):
            assert parse_timestamp(after.timestamp) - parse_timestamp(
                before.timestamp
            ) == timedelta(days=1)

    def test_events_are_in_log_order(self, scenario):
        stamps = [event.timestamp for event in scenario.events()]
        assert stamps == sorted(stamps)


class TestExpectations:
    def test_the_declared_event_count_is_the_real_one(self, scenario):
        """The one expectation that can be checked without running anything."""
        assert scenario.expected.events == len(scenario.events())

    def test_expectations_are_literals_not_computed(self):
        """No scenario may derive its expectation from the pipeline.

        A scenario that ran the detection engine to decide what to expect would
        pass by construction.  The scenario modules therefore must not import
        the engines at all.
        """
        for path in sorted(SCENARIO_PACKAGE.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            for banned in ("DetectionEngine", "CorrelationEngine", "AISocAnalyst"):
                assert banned not in source, f"{path.name} references {banned}"

    def test_benign_scenarios_expect_silence(self):
        for scenario in benign_scenarios():
            assert scenario.expected.alerts == 0
            assert scenario.expected.incidents == 0
            assert scenario.expected.forbidden_rule_ids, (
                "a benign scenario must name the rules that may not fire"
            )

    def test_attack_scenarios_expect_something(self):
        for scenario in attack_scenarios():
            assert scenario.expected.alerts >= 1
            assert scenario.expected.rule_ids

    def test_declared_techniques_are_real_attack_ids(self, scenario):
        for technique in scenario.mitre_techniques:
            assert technique in TECHNIQUES
        for technique in scenario.expected.techniques:
            assert technique in TECHNIQUES

    def test_every_benign_scenario_forbids_every_shipped_rule(self):
        shipped = {rule.rule_id for rule in default_rules()}
        for scenario in benign_scenarios():
            assert scenario.expected.forbidden_rule_ids == shipped, (
                "a benign scenario must forbid every rule, so a new rule that "
                "misfires on ordinary activity is caught here"
            )


class TestCoverage:
    def test_every_shipped_rule_is_expected_by_some_scenario(self):
        shipped = {rule.rule_id for rule in default_rules()}
        expected = set()
        for scenario in attack_scenarios():
            expected |= scenario.expected.rule_ids
        assert shipped - expected == set(), (
            f"no scenario exercises: {sorted(shipped - expected)}"
        )

    def test_the_full_attack_scenario_covers_every_stage(self):
        full = get_scenario("full-attack")
        kinds = {event.event_type for event in full.events()}
        assert EventType.AUTHENTICATION_FAILURE in kinds
        assert EventType.AUTHENTICATION_SUCCESS in kinds
        assert EventType.SUDO in kinds
        assert EventType.PROCESS_START in kinds
        assert EventType.NETWORK_CONNECTION in kinds
        assert len(full.expected.rule_ids) == 5
