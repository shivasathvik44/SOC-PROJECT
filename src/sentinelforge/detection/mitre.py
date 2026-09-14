"""Central MITRE ATT&CK mapping.

Technique identifiers live here and nowhere else.  Rules ask for a technique by
id and get a validated :class:`MitreMapping` back, so a typo or an invented id
fails loudly at import time instead of silently producing a wrong alert.

All entries below are real ATT&CK Enterprise techniques.
Reference: https://attack.mitre.org/techniques/enterprise/
"""

from __future__ import annotations

from dataclasses import dataclass


class Tactic:
    """ATT&CK Enterprise tactics used by the rules in this project."""

    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    COMMAND_AND_CONTROL = "Command and Control"


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique or sub-technique as published by MITRE."""

    technique_id: str
    name: str
    #: Tactics this technique belongs to; the first one is treated as primary.
    tactics: tuple[str, ...]
    #: Parent technique id for sub-techniques (``T1110.001`` -> ``T1110``).
    parent_id: str | None = None

    @property
    def is_sub_technique(self) -> bool:
        return self.parent_id is not None


# --------------------------------------------------------------------------
# Technique catalogue.  Only techniques actually used by an implemented rule
# are listed -- we do not pre-populate the whole ATT&CK matrix.
# --------------------------------------------------------------------------
TECHNIQUES: dict[str, Technique] = {
    technique.technique_id: technique
    for technique in (
        Technique("T1110", "Brute Force", (Tactic.CREDENTIAL_ACCESS,)),
        Technique("T1110.001", "Password Guessing", (Tactic.CREDENTIAL_ACCESS,), "T1110"),
        Technique("T1110.003", "Password Spraying", (Tactic.CREDENTIAL_ACCESS,), "T1110"),
        Technique(
            "T1078",
            "Valid Accounts",
            (
                Tactic.DEFENSE_EVASION,
                Tactic.PERSISTENCE,
                Tactic.PRIVILEGE_ESCALATION,
                Tactic.INITIAL_ACCESS,
            ),
        ),
        Technique(
            "T1078.003",
            "Local Accounts",
            (
                Tactic.DEFENSE_EVASION,
                Tactic.PERSISTENCE,
                Tactic.PRIVILEGE_ESCALATION,
                Tactic.INITIAL_ACCESS,
            ),
            "T1078",
        ),
        Technique(
            "T1548",
            "Abuse Elevation Control Mechanism",
            (Tactic.PRIVILEGE_ESCALATION, Tactic.DEFENSE_EVASION),
        ),
        Technique(
            "T1548.003",
            "Sudo and Sudo Caching",
            (Tactic.PRIVILEGE_ESCALATION, Tactic.DEFENSE_EVASION),
            "T1548",
        ),
        Technique("T1059", "Command and Scripting Interpreter", (Tactic.EXECUTION,)),
        Technique("T1059.004", "Unix Shell", (Tactic.EXECUTION,), "T1059"),
        Technique("T1105", "Ingress Tool Transfer", (Tactic.COMMAND_AND_CONTROL,)),
        Technique("T1071", "Application Layer Protocol", (Tactic.COMMAND_AND_CONTROL,)),
        Technique("T1098", "Account Manipulation", (Tactic.PERSISTENCE,)),
        Technique("T1003", "OS Credential Dumping", (Tactic.CREDENTIAL_ACCESS,)),
        Technique(
            "T1003.008",
            "/etc/passwd and /etc/shadow",
            (Tactic.CREDENTIAL_ACCESS,),
            "T1003",
        ),
        Technique("T1070", "Indicator Removal", (Tactic.DEFENSE_EVASION,)),
        Technique(
            "T1070.002",
            "Clear Linux or Mac System Logs",
            (Tactic.DEFENSE_EVASION,),
            "T1070",
        ),
        Technique(
            "T1556",
            "Modify Authentication Process",
            (Tactic.CREDENTIAL_ACCESS, Tactic.DEFENSE_EVASION, Tactic.PERSISTENCE),
        ),
        Technique("T1562", "Impair Defenses", (Tactic.DEFENSE_EVASION,)),
        Technique("T1562.001", "Disable or Modify Tools", (Tactic.DEFENSE_EVASION,), "T1562"),
        Technique(
            "T1562.004", "Disable or Modify System Firewall", (Tactic.DEFENSE_EVASION,), "T1562"
        ),
        Technique("T1046", "Network Service Discovery", (Tactic.DISCOVERY,)),
    )
}


class UnknownTechniqueError(KeyError):
    """Raised when a rule references a technique id that is not in the catalogue."""


@dataclass(frozen=True)
class MitreMapping:
    """The ATT&CK context attached to a rule or alert.

    ``technique_id`` / ``technique`` always describe the parent technique; when
    a sub-technique was requested, ``sub_technique_id`` / ``sub_technique`` are
    filled in as well.
    """

    tactic: str
    technique_id: str
    technique: str
    sub_technique_id: str | None = None
    sub_technique: str | None = None

    def to_dict(self) -> dict:
        """Serialize for the ``mitre`` block of an alert."""
        data = {
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "technique": self.technique,
        }
        if self.sub_technique_id:
            data["sub_technique_id"] = self.sub_technique_id
            data["sub_technique"] = self.sub_technique
        return data

    @property
    def url(self) -> str:
        """Link to the technique page on attack.mitre.org."""
        ref = self.sub_technique_id or self.technique_id
        return "https://attack.mitre.org/techniques/" + ref.replace(".", "/") + "/"


def lookup(technique_id: str) -> Technique:
    """Return the catalogued technique, or raise :class:`UnknownTechniqueError`."""
    try:
        return TECHNIQUES[technique_id]
    except KeyError:
        raise UnknownTechniqueError(
            f"{technique_id!r} is not in the SentinelForge ATT&CK catalogue; "
            "add the official technique to mitre.TECHNIQUES instead of inventing an id"
        ) from None


def mapping(technique_id: str, tactic: str | None = None) -> MitreMapping:
    """Build a :class:`MitreMapping` for a technique or sub-technique id.

    Args:
        technique_id: e.g. ``"T1110"`` or ``"T1110.001"``.
        tactic: Pick a specific tactic for techniques that belong to several
            (``T1078`` spans four).  Defaults to the technique's primary tactic.

    Raises:
        UnknownTechniqueError: if the id -- or the requested tactic -- is not
            part of the catalogued ATT&CK data.
    """
    technique = lookup(technique_id)
    chosen = tactic or technique.tactics[0]
    if chosen not in technique.tactics:
        raise UnknownTechniqueError(
            f"tactic {chosen!r} is not listed for {technique_id} "
            f"(valid: {', '.join(technique.tactics)})"
        )

    if technique.is_sub_technique:
        parent = lookup(technique.parent_id)
        return MitreMapping(
            tactic=chosen,
            technique_id=parent.technique_id,
            technique=parent.name,
            sub_technique_id=technique.technique_id,
            sub_technique=technique.name,
        )
    return MitreMapping(
        tactic=chosen, technique_id=technique.technique_id, technique=technique.name
    )
