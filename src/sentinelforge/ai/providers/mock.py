"""Offline mock provider (Phase 5).

Runs with no API key, no network and no cost, and returns the *same* analysis
for the same incident every time.  That makes it the provider tests, CI, demos
and first-run users should use.

It is not a language model.  It reads the untrusted telemetry block out of the
prompt it was handed -- the same JSON a real provider would receive -- and
derives an analysis from a handful of deterministic rules over the incident's
own rule ids and score.  Everything it produces is labelled:
``is_mock`` is set on the response, the summary starts with ``[MOCK ANALYSIS]``,
and the CLI prints a banner.  Mock output must never be mistaken for a real
provider's opinion, so nothing here tries to sound like one.
"""

from __future__ import annotations

import json

from . import LLMProvider, ProviderResponse
from ..prompts import UNTRUSTED_BEGIN, UNTRUSTED_END
from ..schemas import Assessment, AttackStage, Priority, Relevance
from ...models.event import Severity

MOCK_MODEL = "sentinelforge-mock-analyst-1"

#: Marks every field a human might read, so mock output is self-identifying.
MOCK_PREFIX = "[MOCK ANALYSIS]"

#: rule id -> (evidence phrasing, what it may mean)
_RULE_EVIDENCE = {
    "SSH_BRUTE_FORCE": (
        "repeated failed SSH authentications from one source",
        "consistent with password guessing against this host",
    ),
    "AUTH_REPEATED_FAILURES": (
        "repeated authentication failures",
        "consistent with credential guessing; may also be a misconfigured client",
    ),
    "AUTH_INVALID_USER": (
        "authentication attempts for accounts that do not exist",
        "typical of automated scanning rather than a mistyped password",
    ),
    "SSH_COMPROMISE_SUSPECTED": (
        "a successful authentication following failed attempts from the same source",
        "consistent with a guessed or stolen credential being used successfully",
    ),
    "AUTH_ROOT_LOGIN_REMOTE": (
        "a remote privileged login",
        "worth verifying against the expected administration process",
    ),
    "SUSPICIOUS_SUDO": (
        "sudo used to run a command that fetches and executes remote content",
        "consistent with privilege escalation followed by payload execution",
    ),
    "SUSPICIOUS_PROCESS_EXECUTION": (
        "an interactive shell spawned by a process that does not normally spawn one",
        "consistent with a web shell or a download-and-run payload",
    ),
    "SUSPICIOUS_NETWORK_CONNECTION": (
        "an outbound connection opened by a shell or interpreter",
        "consistent with a reverse shell or command-and-control callback",
    ),
    "PORT_SCAN": (
        "connections to many distinct ports in a short window",
        "consistent with host or service discovery",
    ),
}

#: rule id -> investigation step, phrased for a Tier-1 analyst.
_RULE_STEPS = {
    "SSH_BRUTE_FORCE": "Identify the source address of the failed logins and confirm "
    "whether it is a known administration host.",
    "AUTH_INVALID_USER": "Check whether the targeted account names correspond to any "
    "real accounts on this host.",
    "AUTH_REPEATED_FAILURES": "Determine whether the failures come from a human, a "
    "service account, or an automated client.",
    "SSH_COMPROMISE_SUSPECTED": "Verify with the account owner whether the successful "
    "login was expected, and review the session's command history.",
    "AUTH_ROOT_LOGIN_REMOTE": "Confirm the privileged login against the change or "
    "maintenance record for this window.",
    "SUSPICIOUS_SUDO": "Review the full sudo command line and the file it retrieved, "
    "and check whether that command is part of a sanctioned task.",
    "SUSPICIOUS_PROCESS_EXECUTION": "Examine the process lineage around the shell and "
    "identify what the parent process was serving at that moment.",
    "SUSPICIOUS_NETWORK_CONNECTION": "Look up the destination address and determine "
    "whether the host has any legitimate reason to contact it.",
    "PORT_SCAN": "Establish whether a scanning or inventory tool was scheduled to run "
    "from this source.",
}


class MockProvider(LLMProvider):
    """Deterministic, offline, clearly-labelled analyst output.

    Args:
        model: Reported model name; kept configurable only so the audit trail
            can show which mock variant produced an analysis.
    """

    name = "mock"
    is_mock = True

    def __init__(self, model: str = MOCK_MODEL) -> None:
        self.model = model or MOCK_MODEL

    @classmethod
    def from_config(cls, config) -> "MockProvider":
        return cls(model=config.model or MOCK_MODEL)

    def describe(self) -> dict:
        return {
            "provider": self.name,
            "model": self.model,
            "is_mock": True,
            "api_key": "not required",
            "network": "never contacted",
        }

    def analyze(self, system_prompt: str, user_prompt: str) -> ProviderResponse:
        """Derive a deterministic analysis from the fenced telemetry block."""
        payload = _extract_untrusted(user_prompt)
        analysis = _analyze(payload)
        return ProviderResponse(
            text=json.dumps(analysis, ensure_ascii=False),
            provider=self.name,
            model=self.model,
            is_mock=True,
            usage={},
        )


def _extract_untrusted(user_prompt: str) -> dict:
    """Pull the untrusted telemetry JSON back out of the prompt.

    A real provider parses the prompt with a model; the mock parses it with
    ``json.loads``.  Either way it only ever sees what the sanitizer allowed
    into the prompt -- the mock has no privileged access to the incident.
    """
    start = user_prompt.find(UNTRUSTED_BEGIN)
    end = user_prompt.find(UNTRUSTED_END)
    if start == -1 or end == -1 or end < start:
        return {}
    block = user_prompt[start + len(UNTRUSTED_BEGIN) : end].strip()
    try:
        data = json.loads(block)
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def _rule_ids(payload: dict) -> list[str]:
    seen: list[str] = []
    for alert in payload.get("alerts") or []:
        rule_id = alert.get("rule_id")
        if rule_id and rule_id not in seen:
            seen.append(rule_id)
    return seen


def _looks_like_injection(payload: dict) -> bool:
    """Whether the telemetry contains text shaped like an instruction to a model.

    Reported as a finding, never acted on.  The mock uses a crude phrase list;
    that is enough to demonstrate the behaviour the real prompt asks for.
    """
    needles = (
        "ignore previous instruction",
        "ignore all previous",
        "disregard the above",
        "you are now",
        "system prompt",
        "reveal your",
        "new instructions",
    )
    blob = json.dumps(payload, ensure_ascii=False).lower()
    return any(needle in blob for needle in needles)


def _analyze(payload: dict) -> dict:
    """The mock's deterministic ruleset.  Same input -> same output, always."""
    rule_ids = _rule_ids(payload)
    score = int(payload.get("risk_score") or 0)
    severity = payload.get("severity") or Severity.MEDIUM
    incident_id = payload.get("incident_id") or ""
    truncated = payload.get("data_truncated") or []
    chains = [step for step in payload.get("attack_chain") or []]

    has_success = "SSH_COMPROMISE_SUSPECTED" in rule_ids or "AUTH_ROOT_LOGIN_REMOTE" in rule_ids
    has_failures = any(
        rule in rule_ids
        for rule in ("SSH_BRUTE_FORCE", "AUTH_INVALID_USER", "AUTH_REPEATED_FAILURES")
    )
    has_escalation = "SUSPICIOUS_SUDO" in rule_ids
    has_execution = "SUSPICIOUS_PROCESS_EXECUTION" in rule_ids
    has_network = "SUSPICIOUS_NETWORK_CONNECTION" in rule_ids

    # Assessment: driven by how much of an intrusion sequence is present.
    stages_present = sum((has_failures, has_success, has_escalation or has_execution, has_network))
    if stages_present >= 3 or (has_success and (has_escalation or has_execution)):
        assessment = Assessment.LIKELY_MALICIOUS
    elif stages_present >= 2 or score >= 70:
        assessment = Assessment.POSSIBLY_MALICIOUS
    elif rule_ids:
        assessment = Assessment.INCONCLUSIVE
    else:
        assessment = Assessment.INCONCLUSIVE

    if has_network or has_escalation or has_execution:
        stage = AttackStage.POST_COMPROMISE
    elif has_success:
        stage = AttackStage.INITIAL_ACCESS
    elif has_failures:
        stage = AttackStage.RECONNAISSANCE
    else:
        stage = AttackStage.UNKNOWN

    # Confidence: evidence-proportional, reduced when the view was partial.
    confidence = min(0.9, 0.35 + 0.15 * stages_present + min(score, 100) / 500)
    if truncated:
        confidence = max(0.1, confidence - 0.1)
    confidence = round(confidence, 2)

    key_evidence = []
    for rule_id in rule_ids:
        observation, significance = _RULE_EVIDENCE.get(
            rule_id, (f"rule {rule_id} matched", "reviewed as part of this incident")
        )
        key_evidence.append({"observation": observation, "significance": significance})

    injection = _looks_like_injection(payload)
    if injection:
        key_evidence.append(
            {
                "observation": "the telemetry contains text addressed to a language model "
                "(instruction-like phrasing inside log content)",
                "significance": "apparent prompt-injection attempt; treated as evidence and "
                "not acted on, and itself a sign of deliberate activity",
            }
        )

    steps = [_RULE_STEPS[rule_id] for rule_id in rule_ids if rule_id in _RULE_STEPS]
    if has_success:
        steps.append(
            "Review the commands executed during the session that followed the "
            "successful authentication."
        )
    if has_network:
        steps.append(
            "Review outbound connections from this host around the time of the incident."
        )
    if not steps:
        steps.append(
            "Review the alerts in this incident and confirm whether the activity was "
            "expected on this host."
        )

    false_positives = []
    sources = payload.get("source_ips") or []
    if any(_is_private(ip) for ip in sources):
        false_positives.append(
            "at least one source address is in private address space, so this may be "
            "internal administration activity - requires verification against the "
            "inventory of administration hosts"
        )
    if has_escalation:
        false_positives.append(
            "the sudo activity may correspond to a sanctioned administrative task - "
            "requires verification against the change record"
        )
    if has_failures and not has_success:
        false_positives.append(
            "repeated failures with no success are also consistent with a stale "
            "credential in an automated client - requires verification"
        )
    if not false_positives:
        false_positives.append(
            "no benign explanation is apparent from the telemetry alone; the activity "
            "still requires verification with the account owner"
        )

    actions = []
    if has_success:
        actions.append(
            {
                "action": "review_account_session",
                "priority": Priority.HIGH,
                "reason": "A successful authentication followed repeated failures from the "
                "same source.",
            }
        )
    if has_escalation or has_execution:
        actions.append(
            {
                "action": "review_privileged_command_history",
                "priority": Priority.HIGH,
                "reason": "Privileged or unexpected process activity followed the "
                "authentication.",
            }
        )
    if has_network:
        actions.append(
            {
                "action": "consider_host_isolation",
                "priority": Priority.HIGH,
                "reason": "Outbound activity from a shell or interpreter may indicate an "
                "active foothold; isolation is a decision for a human analyst.",
            }
        )
    actions.append(
        {
            "action": "confirm_with_account_owner",
            "priority": Priority.MEDIUM,
            "reason": "The account owner can rule the activity in or out faster than "
            "further log review.",
        }
    )

    mitre = []
    for step in chains:
        technique_id = step.get("sub_technique_id") or step.get("technique_id")
        if not technique_id:
            continue
        mitre.append(
            {
                "technique_id": technique_id,
                "technique": step.get("sub_technique") or step.get("technique") or "",
                "relevance": Relevance.OBSERVED,
                "rationale": "Mapped deterministically by the rule that fired; the AI layer "
                "did not introduce this technique.",
            }
        )

    sequence = " then ".join(
        part
        for part in (
            "failed authentications" if has_failures else "",
            "a successful authentication" if has_success else "",
            "privilege escalation" if has_escalation else "",
            "unexpected process execution" if has_execution else "",
            "outbound network activity" if has_network else "",
        )
        if part
    )
    summary = (
        f"{MOCK_PREFIX} {incident_id}: the incident contains "
        f"{sequence or 'activity from ' + str(len(rule_ids)) + ' detection rule(s)'}, "
        f"scored {score}/100 by the deterministic engine. "
        "This sequence is consistent with "
        + (
            "possible account compromise followed by post-compromise activity, "
            if assessment == Assessment.LIKELY_MALICIOUS
            else "suspicious activity that has not been confirmed, "
        )
        + "and requires verification by a human analyst."
    )

    reasoning = (
        f"{MOCK_PREFIX} This analysis was produced offline by SentinelForge's mock "
        "provider, not by a language model. It is derived deterministically from the "
        f"rule ids present ({', '.join(rule_ids) or 'none'}), the deterministic severity "
        f"'{severity}' and score {score}. Observed: the alerts and evidence listed above. "
        "Inferred: the ordering of those alerts is consistent with, but does not prove, "
        "the sequence described in the summary. "
        + (
            "Part of the incident data was truncated before analysis, so this reading is "
            "based on an incomplete view. "
            if truncated
            else ""
        )
        + "Every conclusion here requires verification by a human analyst."
    )

    return {
        "incident_id": incident_id,
        "assessment": assessment,
        "confidence": confidence,
        "summary": summary,
        "severity_assessment": severity if severity in Severity.ALL else Severity.MEDIUM,
        "attack_stage": stage,
        "mitre_analysis": mitre,
        "key_evidence": key_evidence,
        "false_positive_indicators": false_positives,
        "investigation_steps": steps,
        "recommended_actions": actions,
        "reasoning": reasoning,
    }


def _is_private(address: str) -> bool:
    """Rough private-range check; the mock only needs a hint, not a verdict."""
    text = str(address or "")
    if text.startswith(("10.", "192.168.", "127.", "169.254.", "fd", "fe80:")):
        return True
    if text.startswith("172."):
        parts = text.split(".")
        if len(parts) > 1 and parts[1].isdigit():
            return 16 <= int(parts[1]) <= 31
    return False
