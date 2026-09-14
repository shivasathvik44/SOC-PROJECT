"""Redaction and incident serialization for the AI layer (Phase 5).

Two jobs, both about what leaves the machine:

1. **Redaction** -- strip obvious secrets (passwords, tokens, authorization
   headers, private keys) out of text that would otherwise be sent to a
   third-party API, while keeping the things that make security evidence
   useful: IP addresses, usernames, process names, ports, file paths.

2. **Serialization** -- turn an :class:`~sentinelforge.models.incident.Incident`
   into a bounded payload split in two:

   * ``trusted`` -- values SentinelForge itself produced and an attacker cannot
     write into: incident id, counts, scores, rule ids, chain ids, technique
     ids, timestamps.
   * ``untrusted`` -- everything derived from observed data: log messages,
     command lines, hostnames, usernames, IP addresses, alert descriptions,
     correlation prose.  All of it is attacker-influenceable and is fenced off
     as data in the prompt (see :mod:`sentinelforge.ai.prompts`).

Limits of redaction
-------------------
Regexes match *shapes*, not secrets.  A password that looks like a word, a
token in a format not listed here, or a secret split across fields will pass
straight through.  Redaction reduces exposure; it does not guarantee that no
secret is sent.  The only guarantee available is not sending the data at all,
which is what ``--provider mock`` does.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..models.event import EventType, SecurityEvent
from ..models.incident import Incident

#: Field names that carry secrets when they appear as ``key=value``.
SECRET_KEYS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "access_key",
    "access-key",
    "auth_token",
    "auth-token",
    "private_key",
    "private-key",
    "credential",
    "credentials",
    "session_key",
)

_KEY_ALTERNATION = "|".join(re.escape(key) for key in SECRET_KEYS)


def _redaction(name: str) -> str:
    return f"[REDACTED:{name}]"


#: ``(name, pattern, replacement)``, applied in order.  Order matters: the
#: multi-line private key block must be removed before anything tries to
#: match inside it.
REDACTION_PATTERNS: tuple[tuple[str, re.Pattern, str], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        _redaction("private_key"),
    ),
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        _redaction("private_key"),
    ),
    (
        "authorization",
        re.compile(
            r"(?i)\b(authorization|proxy-authorization)\b\s*[:=]\s*"
            r"(?:bearer|basic|token|digest)?\s*\S+"
        ),
        r"\1: " + _redaction("authorization"),
    ),
    (
        "bearer_token",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
        "Bearer " + _redaction("bearer_token"),
    ),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}"),
        _redaction("jwt"),
    ),
    (
        "key_value",
        re.compile(rf"(?i)\b({_KEY_ALTERNATION})\b(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)"),
        lambda match: f"{match.group(1)}{match.group(2)}{_redaction('secret')}",
    ),
    (
        # ``--password secret`` -- the space-separated form the ``key=value``
        # pattern above cannot see.  Deliberately does not cover a bare ``-p``:
        # ``ssh -p 22`` is evidence, not a secret.
        "command_flag",
        re.compile(rf"(?i)(--?(?:{_KEY_ALTERNATION}))(\s+)(\"[^\"]*\"|'[^']*'|\S+)"),
        lambda match: f"{match.group(1)}{match.group(2)}{_redaction('secret')}",
    ),
    (
        "url_credentials",
        re.compile(r"\b([a-z][a-z0-9+.\-]*)://([^/\s:@]+):([^/\s@]+)@"),
        lambda match: f"{match.group(1)}://{match.group(2)}:{_redaction('url_password')}@",
    ),
    (
        "aws_access_key_id",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        _redaction("aws_access_key_id"),
    ),
    (
        "provider_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{16,}|xox[baprs]-[A-Za-z0-9-]{10,})"),
        _redaction("provider_token"),
    ),
)

#: Control characters have no business in telemetry text sent to a model; they
#: are the cheapest way to hide content from a human reviewing the prompt.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass
class Sanitizer:
    """Redacts secrets from text and nested structures, and counts what it hit.

    Args:
        max_chars: Hard cap per string field; longer values are cut and marked.
        markers: Literal strings that must never survive inside telemetry --
            the prompt's untrusted-data fences.  Neutralized so log content
            cannot forge the end of the untrusted block.
    """

    max_chars: int = 600
    markers: tuple[str, ...] = ()
    counts: dict = field(default_factory=dict)

    def text(self, value: object, max_chars: int | None = None) -> str:
        """Redact, de-fang and length-cap one string."""
        if value is None:
            return ""
        text = value if isinstance(value, str) else str(value)
        text = _CONTROL_CHARS.sub(" ", text)
        for name, pattern, replacement in REDACTION_PATTERNS:
            text, hits = pattern.subn(replacement, text)
            if hits:
                self.counts[name] = self.counts.get(name, 0) + hits
        for marker in self.markers:
            if marker and marker in text:
                # Telemetry that contains the prompt's own delimiter would let a
                # log line close the untrusted block early.  The literal is
                # replaced, and the substitution is itself reported: a log line
                # forging this marker is a finding, not noise.
                text = text.replace(marker, "[fence-marker-removed]")
                self.counts["fence_marker"] = self.counts.get("fence_marker", 0) + 1
        limit = self.max_chars if max_chars is None else max_chars
        if limit and len(text) > limit:
            text = text[: limit - 1].rstrip() + "…"
            self.counts["truncated_field"] = self.counts.get("truncated_field", 0) + 1
        return text

    def value(self, value: object, max_chars: int | None = None):
        """Redact recursively through dicts, lists, and scalars."""
        if isinstance(value, str):
            return self.text(value, max_chars)
        if isinstance(value, dict):
            return {str(key): self.value(item, max_chars) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.value(item, max_chars) for item in value]
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        return self.text(value, max_chars)

    @property
    def redaction_count(self) -> int:
        """How many secret-shaped values were replaced (excluding truncation)."""
        return sum(
            count
            for name, count in self.counts.items()
            if name not in ("truncated_field", "fence_marker")
        )


def redact(text: str) -> str:
    """Redact one string with default settings (convenience wrapper)."""
    return Sanitizer().text(text)


@dataclass(frozen=True)
class ContextLimits:
    """Bounds on what one incident may cost in prompt size.

    Every limit that actually bites is reported in
    :attr:`IncidentContext.truncated`, so the model -- and the human reading
    the analysis afterwards -- is told the view was partial.
    """

    max_alerts: int = 8
    max_evidence_per_alert: int = 5
    max_timeline_entries: int = 40
    max_process_events: int = 15
    max_network_events: int = 15
    max_correlation_reasons: int = 10
    max_field_chars: int = 600
    max_message_chars: int = 400
    #: Hard ceiling on the serialized untrusted payload, in characters.
    max_context_chars: int = 24000


@dataclass
class IncidentContext:
    """The bounded, minimized view of an incident that a provider may see."""

    incident_id: str
    incident_version: str
    trusted: dict
    untrusted: dict
    truncated: list[str] = field(default_factory=list)
    redactions: dict = field(default_factory=dict)

    def untrusted_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.untrusted, ensure_ascii=False, indent=indent, sort_keys=False)

    def trusted_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.trusted, ensure_ascii=False, indent=indent, sort_keys=False)


def _telemetry(event: SecurityEvent, sanitizer: Sanitizer, limits: ContextLimits) -> dict:
    """Sensor metadata worth showing an analyst, redacted and bounded."""
    fields = {
        "pid": event.pid,
        "ppid": event.ppid,
        "executable": event.executable,
        "parent_process": event.parent_process,
        "command_line": event.command_line,
        "destination_ip": event.dst_ip,
        "destination_port": event.dst_port,
        "protocol": event.protocol,
    }
    present = {key: value for key, value in fields.items() if value not in (None, "")}
    return {
        key: sanitizer.value(value, limits.max_message_chars) for key, value in present.items()
    }


def _event_view(event: SecurityEvent, sanitizer: Sanitizer, limits: ContextLimits) -> dict:
    """One evidence event, minimized.

    ``raw`` -- the original log line -- is deliberately dropped: ``message``
    already carries the security-relevant content, and the raw line adds
    surrounding context that was never part of the detection.
    """
    view = {
        "timestamp": event.timestamp,
        "event_type": event.event_type,
        "severity": event.severity,
        "source": sanitizer.text(event.source, 64),
        "host": sanitizer.text(event.host, 128),
        "user": sanitizer.text(event.user, 128) or None,
        "src_ip": sanitizer.text(event.src_ip, 64) or None,
        "process": sanitizer.text(event.process, 128) or None,
        "message": sanitizer.text(event.message, limits.max_message_chars),
    }
    telemetry = _telemetry(event, sanitizer, limits)
    if telemetry:
        view["telemetry"] = telemetry
    return {key: value for key, value in view.items() if value not in (None, "")}


def build_incident_context(
    incident: Incident,
    limits: ContextLimits | None = None,
    markers: tuple[str, ...] = (),
) -> IncidentContext:
    """Serialize an incident into trusted metadata + untrusted telemetry.

    Only data that is already part of the incident is included.  Nothing here
    reads the journal, the filesystem, or any event that did not end up as
    alert evidence: the AI sees the incident, not the host.
    """
    limits = limits or ContextLimits()
    sanitizer = Sanitizer(max_chars=limits.max_field_chars, markers=markers)
    truncated: list[str] = []

    alerts = incident.alerts[: limits.max_alerts]
    if len(incident.alerts) > len(alerts):
        truncated.append(
            f"alerts: showing {len(alerts)} of {len(incident.alerts)} (highest-priority first "
            "by incident order)"
        )

    alert_views = []
    for alert in alerts:
        evidence = alert.evidence[: limits.max_evidence_per_alert]
        if len(alert.evidence) > len(evidence):
            truncated.append(
                f"{alert.alert_id}: showing {len(evidence)} of {len(alert.evidence)} "
                "evidence events"
            )
        alert_views.append(
            {
                "alert_id": alert.alert_id,
                "rule_id": alert.rule_id,
                "name": sanitizer.text(alert.name, 128),
                "severity": alert.severity,
                "risk_score": alert.risk_score,
                "timestamp": alert.timestamp,
                "first_seen": alert.first_seen,
                "last_seen": alert.last_seen,
                "host": sanitizer.text(alert.host, 128) or None,
                "source_ip": sanitizer.text(alert.source_ip, 64) or None,
                "user": sanitizer.text(alert.user, 128) or None,
                "description": sanitizer.text(alert.description, limits.max_message_chars),
                "mitre": alert.mitre or {},
                "risk_explanation": [
                    sanitizer.text(line, limits.max_message_chars)
                    for line in alert.risk_explanation
                ],
                "event_count": alert.event_count,
                "suppressed_duplicates": alert.suppressed_duplicates,
                "evidence": [_event_view(event, sanitizer, limits) for event in evidence],
            }
        )

    timeline = incident.timeline[: limits.max_timeline_entries]
    if len(incident.timeline) > len(timeline):
        truncated.append(
            f"timeline: showing the first {len(timeline)} of {len(incident.timeline)} entries"
        )
    timeline_views = [
        {
            "timestamp": entry.timestamp,
            "type": entry.type,
            "event": sanitizer.text(entry.event, 128),
            "description": sanitizer.text(entry.description, limits.max_message_chars),
            **({"severity": entry.severity} if entry.severity else {}),
        }
        for entry in timeline
    ]

    # Sensor telemetry, pulled out of the evidence so an analyst (and the model)
    # can see process and network activity without walking every alert.
    events = incident.unique_events()
    process_events = [
        _event_view(event, sanitizer, limits)
        for event in events
        if event.event_type == EventType.PROCESS_START or event.parent_process
    ][: limits.max_process_events]
    network_events = [
        _event_view(event, sanitizer, limits)
        for event in events
        if event.event_type == EventType.NETWORK_CONNECTION or event.dst_ip
    ][: limits.max_network_events]

    reasons = incident.correlation_reasons[: limits.max_correlation_reasons]

    untrusted = {
        "incident_id": incident.incident_id,
        "title": sanitizer.text(incident.title, 200),
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "first_seen": incident.first_seen,
        "last_seen": incident.last_seen,
        "host": sanitizer.text(incident.host, 128) or None,
        "source_ips": [sanitizer.text(ip, 64) for ip in incident.source_ips],
        "users": [sanitizer.text(user, 128) for user in incident.users],
        "attack_chain": [sanitizer.value(step, 200) for step in incident.attack_chain],
        "correlation_reasons": [
            sanitizer.text(reason, limits.max_message_chars) for reason in reasons
        ],
        "risk_explanation": [
            sanitizer.text(line, limits.max_message_chars) for line in incident.risk_explanation
        ],
        "alerts": alert_views,
        "timeline": timeline_views,
        "process_telemetry": process_events,
        "network_telemetry": network_events,
    }

    # Last-resort size control.  Dropping whole sections (rather than cutting
    # the JSON mid-string) keeps the payload parseable and the loss explicit.
    for section, note in (
        ("timeline", "timeline omitted entirely to fit the context size limit"),
        ("process_telemetry", "process telemetry omitted to fit the context size limit"),
        ("network_telemetry", "network telemetry omitted to fit the context size limit"),
        ("alerts", "alert details omitted to fit the context size limit"),
    ):
        if len(json.dumps(untrusted, ensure_ascii=False)) <= limits.max_context_chars:
            break
        if untrusted.get(section):
            untrusted[section] = []
            truncated.append(note)

    untrusted["data_truncated"] = list(truncated)

    trusted = {
        "incident_id": incident.incident_id,
        "incident_version": incident.version,
        "deterministic_severity": incident.severity,
        "deterministic_risk_score": incident.risk_score,
        "alert_count": incident.alert_count,
        "unique_event_count": incident.event_count,
        "rule_ids": list(incident.rule_ids),
        "matched_attack_chains": list(incident.matched_chains),
        "attack_chain_technique_ids": [
            step.get("sub_technique_id") or step.get("technique_id")
            for step in incident.attack_chain
            if step.get("sub_technique_id") or step.get("technique_id")
        ],
        "first_seen": incident.first_seen,
        "last_seen": incident.last_seen,
        "data_truncated": list(truncated),
    }

    return IncidentContext(
        incident_id=incident.incident_id,
        incident_version=incident.version,
        trusted=trusted,
        untrusted=untrusted,
        truncated=truncated,
        redactions=dict(sanitizer.counts),
    )
