"""Tests for the central MITRE ATT&CK mapping."""

import re

import pytest

from sentinelforge.detection import mitre
from sentinelforge.detection.rules import default_rules

#: ATT&CK ids look like T1110 or T1110.001.
_ID_SHAPE = re.compile(r"^T\d{4}(\.\d{3})?$")


def test_technique_mapping_has_tactic_id_and_name():
    mapping = mitre.mapping("T1110")
    assert mapping.tactic == "Credential Access"
    assert mapping.technique_id == "T1110"
    assert mapping.technique == "Brute Force"
    assert mapping.sub_technique_id is None


def test_sub_technique_keeps_parent_and_sub():
    mapping = mitre.mapping("T1110.001")
    assert mapping.technique_id == "T1110"
    assert mapping.technique == "Brute Force"
    assert mapping.sub_technique_id == "T1110.001"
    assert mapping.sub_technique == "Password Guessing"


def test_mapping_serializes_for_alerts():
    data = mitre.mapping("T1548.003").to_dict()
    assert data == {
        "tactic": "Privilege Escalation",
        "technique_id": "T1548",
        "technique": "Abuse Elevation Control Mechanism",
        "sub_technique_id": "T1548.003",
        "sub_technique": "Sudo and Sudo Caching",
    }


def test_mapping_without_sub_technique_omits_those_keys():
    assert set(mitre.mapping("T1046").to_dict()) == {"tactic", "technique_id", "technique"}


def test_technique_url_points_at_attack_mitre_org():
    assert mitre.mapping("T1110.001").url == "https://attack.mitre.org/techniques/T1110/001/"
    assert mitre.mapping("T1046").url == "https://attack.mitre.org/techniques/T1046/"


def test_a_technique_with_several_tactics_can_pick_one():
    assert mitre.mapping("T1078").tactic == "Defense Evasion"  # primary
    assert mitre.mapping("T1078", mitre.Tactic.INITIAL_ACCESS).tactic == "Initial Access"


def test_invented_technique_ids_are_rejected():
    """Guards the "do not invent ATT&CK ids" requirement."""
    for bad in ("T9999", "T1110.999", "TXXXX", ""):
        with pytest.raises(mitre.UnknownTechniqueError):
            mitre.mapping(bad)


def test_tactic_not_listed_for_a_technique_is_rejected():
    with pytest.raises(mitre.UnknownTechniqueError):
        mitre.mapping("T1110", mitre.Tactic.EXECUTION)


def test_catalogue_entries_are_well_formed():
    for technique_id, technique in mitre.TECHNIQUES.items():
        assert _ID_SHAPE.match(technique_id), technique_id
        assert technique.technique_id == technique_id
        assert technique.name and technique.tactics
        if technique.parent_id:
            assert technique.parent_id in mitre.TECHNIQUES
            assert technique_id.startswith(technique.parent_id + ".")


def test_every_rule_maps_to_a_catalogued_technique():
    for rule in default_rules():
        assert rule.mitre is not None, rule.rule_id
        assert rule.mitre.technique_id in mitre.TECHNIQUES
        if rule.mitre.sub_technique_id:
            assert rule.mitre.sub_technique_id in mitre.TECHNIQUES


def test_known_rule_to_technique_assignments():
    by_id = {rule.rule_id: rule for rule in default_rules()}
    assert by_id["SSH_BRUTE_FORCE"].mitre.technique_id == "T1110"
    assert by_id["SSH_BRUTE_FORCE"].mitre.technique == "Brute Force"
    assert by_id["SSH_BRUTE_FORCE"].mitre.tactic == "Credential Access"
    assert by_id["SSH_COMPROMISE_SUSPECTED"].mitre.technique_id == "T1078"
    assert by_id["SUSPICIOUS_SUDO"].mitre.sub_technique_id == "T1548.003"
    assert by_id["PORT_SCAN"].mitre.technique_id == "T1046"
    assert by_id["PORT_SCAN"].mitre.technique == "Network Service Discovery"
