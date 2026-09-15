"""The correlation engine: alerts in, incidents out.

Correlation asks a narrow question about every new alert: *does this belong to
a story that is already being told?*  It answers with entities (host, source
address, account) plus time, never with "same machine" alone.

    alerts -> correlate (entity + time) -> incident
           -> attack chains -> risk -> timeline -> ATT&CK chain

Like everything else in SentinelForge this is read-only: it reads alerts and
produces incident objects.  It never touches the monitored system.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable, Sequence

from ..models.alert import Alert
from ..models.event import parse_timestamp
from ..models.incident import (
    ENTRY_ALERT,
    ENTRY_EVENT,
    Incident,
    IncidentStatus,
    TimelineEntry,
    format_incident_id,
)
from .chains import ATTACK_CHAINS, match_chains
from .scoring import score_incident

LOGGER = logging.getLogger(__name__)

#: Fifteen minutes, the default correlation window.
DEFAULT_WINDOW_SECONDS = 15 * 60


class CorrelationStrength:
    """How strongly an alert belongs to an incident."""

    STRONG = "strong"  # same host + same source address
    MEDIUM = "medium"  # same host + same account
    WEAK = "weak"  # same host only

    ALL = (WEAK, MEDIUM, STRONG)

    @staticmethod
    def rank(strength: str | None) -> int:
        try:
            return CorrelationStrength.ALL.index(strength)
        except ValueError:
            return -1


@dataclass(frozen=True)
class CorrelationMatch:
    """The verdict for one (alert, incident) pair."""

    strength: str | None
    reasons: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.strength is not None


NO_MATCH = CorrelationMatch(None)


@dataclass
class CorrelationConfig:
    """Correlation behaviour knobs.

    Attributes:
        window_seconds: An alert joins an incident only if it happened within
            this long after the incident's last activity.  Default 15 minutes.
        min_strength: Weakest correlation accepted.  ``"weak"`` (same host only)
            is not accepted unless it is configured explicitly.
        chain_upgrades_weak: When true, a same-host-only match is promoted to
            medium if the alerts are also related by attack-chain stage or by
            ATT&CK technique.  Off by default: on a busy host that would merge
            unrelated activity.
        include_events: Put the underlying evidence events on the timeline as
            well as the alerts.
    """

    window_seconds: int = DEFAULT_WINDOW_SECONDS
    min_strength: str = CorrelationStrength.MEDIUM
    chain_upgrades_weak: bool = False
    include_events: bool = True


@dataclass
class CorrelationStats:
    """What happened during a correlation run."""

    alerts_received: int = 0
    alerts_correlated: int = 0
    alerts_skipped: int = 0
    alerts_duplicate: int = 0
    incidents_created: int = 0
    incidents_updated: int = 0

    def to_dict(self) -> dict:
        return {
            "alerts_received": self.alerts_received,
            "alerts_correlated": self.alerts_correlated,
            "alerts_skipped": self.alerts_skipped,
            "alerts_duplicate": self.alerts_duplicate,
            "incidents_created": self.incidents_created,
            "incidents_updated": self.incidents_updated,
        }


def _alert_key(alert: Alert) -> tuple:
    """Identity of an alert by content, so re-running detection cannot duplicate it."""
    return (alert.rule_id, alert.timestamp, alert.source_ip, alert.user, alert.description)


def _techniques(alert: Alert) -> set[str]:
    mitre = alert.mitre or {}
    return {mitre.get("technique_id"), mitre.get("sub_technique_id")} - {None}


def _incident_techniques(incident: Incident) -> set[str]:
    """Every ATT&CK id already present in an incident, as one set."""
    found: set[str] = set()
    for alert in incident.alerts:
        found |= _techniques(alert)
    return found


class CorrelationEngine:
    """Groups related alerts into :class:`Incident` objects.

    Args:
        config: Behaviour knobs; see :class:`CorrelationConfig`.
    """

    def __init__(self, config: CorrelationConfig | None = None) -> None:
        self.config = config or CorrelationConfig()
        self.stats = CorrelationStats()
        # incident_id -> (alerts seen when built, technique union).  Correlating
        # one alert used to re-derive every other alert's ATT&CK ids, which made
        # a long-running incident quadratic in its own size; this memoizes the
        # derived set and rebuilds it whenever the incident grows.
        self._techniques_by_incident: dict[str, tuple[int, set[str]]] = {}

    def _technique_index(self, incident: Incident) -> set[str]:
        """The incident's ATT&CK ids, derived once and then extended in place.

        The cached entry records how many alerts it was built from.  While this
        engine is the only thing adding alerts (:meth:`_attach` keeps the entry
        in step) the union is never recomputed; an incident that arrived from
        somewhere else -- loaded from the database, or built by a caller -- is
        indexed once on first use.
        """
        cached = self._techniques_by_incident.get(incident.incident_id)
        if cached is not None and cached[0] == len(incident.alerts):
            return cached[1]
        techniques = _incident_techniques(incident)
        self._techniques_by_incident[incident.incident_id] = (
            len(incident.alerts),
            techniques,
        )
        return techniques

    # -- public API --------------------------------------------------------
    def run(
        self,
        alerts: Iterable,
        existing_incidents: Sequence[Incident] | None = None,
        start_number: int = 1,
    ) -> list[Incident]:
        """Correlate alerts into incidents.

        Args:
            alerts: :class:`Alert` objects, or dicts as written by
                ``sentinelforge detect``.
            existing_incidents: Incidents from a previous run (typically loaded
                from the database) that new alerts may extend instead of
                creating duplicates.
            start_number: First incident number to hand out.

        Returns:
            Every incident that was created or updated, in chronological order.
        """
        self.stats = CorrelationStats()
        self._techniques_by_incident = {}
        prepared = self._prepare(alerts)

        incidents: list[Incident] = list(existing_incidents or [])
        touched: dict[str, Incident] = {}
        seen_alerts: dict[str, set[tuple]] = {
            incident.incident_id: {_alert_key(a) for a in incident.alerts}
            for incident in incidents
        }
        # Alerts already stored in *any* incident, so re-running correlation over
        # the same alerts.jsonl updates nothing instead of duplicating it -- even
        # when the original incident has since gone inactive.
        known_alerts: set[tuple] = {key for keys in seen_alerts.values() for key in keys}
        next_number = max(start_number, self._next_number(incidents))

        for alert in prepared:
            key = _alert_key(alert)
            if key in known_alerts:
                self.stats.alerts_duplicate += 1
                continue

            incident, match = self._find_incident(alert, incidents)
            if incident is None:
                incident = Incident(
                    incident_id=format_incident_id(next_number),
                    title=alert.name or alert.rule_id,
                    status=IncidentStatus.OPEN,
                )
                next_number += 1
                incidents.append(incident)
                seen_alerts[incident.incident_id] = set()
                self.stats.incidents_created += 1
            elif incident.incident_id not in touched:
                self.stats.incidents_updated += 1

            seen_alerts[incident.incident_id].add(key)
            known_alerts.add(key)
            self._attach(incident, alert, match)
            self.stats.alerts_correlated += 1
            touched[incident.incident_id] = incident

        for incident in touched.values():
            self.finalize(incident)

        return sorted(touched.values(), key=lambda inc: (inc.first_seen or "", inc.incident_id))

    def correlate(self, alert: Alert, incident: Incident) -> CorrelationMatch:
        """Decide whether ``alert`` belongs to ``incident``, and why.

        Correlation needs the same host, a shared entity, and temporal
        proximity.  Shared rules and ATT&CK techniques are recorded as
        supporting reasons -- they describe *how* the alerts relate, and feed
        attack-chain detection, but they do not group alerts on their own.
        """
        if not incident.alerts:
            return NO_MATCH
        if incident.status not in IncidentStatus.ACTIVE:
            return NO_MATCH

        # -- host ---------------------------------------------------------
        if alert.host and incident.host and alert.host != incident.host:
            return NO_MATCH

        # -- time ---------------------------------------------------------
        window = timedelta(seconds=max(0, self.config.window_seconds))
        moment = parse_timestamp(alert.timestamp)
        last = parse_timestamp(incident.last_seen)
        if moment is not None and last is not None:
            gap = moment - last
            if gap > window or -gap > window:
                return NO_MATCH
            minutes = abs(gap.total_seconds()) / 60
            time_reason = f"within the correlation window ({minutes:.1f} min after previous activity)"
        else:
            time_reason = "timestamps unavailable; correlated on entities only"

        # -- entities ------------------------------------------------------
        reasons = []
        if alert.host and incident.host:
            reasons.append(f"same host '{alert.host}'")
        strength = CorrelationStrength.WEAK

        if alert.source_ip and alert.source_ip in incident.source_ips:
            strength = CorrelationStrength.STRONG
            reasons.append(f"same source address {alert.source_ip}")
        if alert.user and alert.user in incident.users:
            if strength != CorrelationStrength.STRONG:
                strength = CorrelationStrength.MEDIUM
            reasons.append(f"same account '{alert.user}'")

        # -- supporting signals --------------------------------------------
        # The union of the intersections with each existing alert is exactly
        # the intersection with the union, so this asks the same question as a
        # scan over ``incident.alerts`` -- in constant time instead of linear.
        shared = _techniques(alert) & self._technique_index(incident)
        if shared:
            reasons.append("shared ATT&CK technique " + ", ".join(sorted(shared)))
        chain_related = self._chain_related(alert, incident)
        if chain_related:
            reasons.append(f"rules form part of the '{chain_related}' attack chain")

        if (
            strength == CorrelationStrength.WEAK
            and self.config.chain_upgrades_weak
            and (chain_related or shared)
        ):
            strength = CorrelationStrength.MEDIUM
            reasons.append("weak host-only match promoted by a related attack chain")

        if CorrelationStrength.rank(strength) < CorrelationStrength.rank(self.config.min_strength):
            return NO_MATCH

        reasons.append(time_reason)
        return CorrelationMatch(strength, tuple(reasons))

    def finalize(self, incident: Incident) -> Incident:
        """Recompute everything derived from an incident's alerts."""
        incident.alerts.sort(key=lambda alert: (alert.timestamp or "", alert.alert_id))

        chains = match_chains(incident.alerts)
        incident.matched_chains = [chain.chain_id for chain, _ in chains]
        risk = score_incident(incident.alerts, [chain for chain, _ in chains])
        incident.risk_score = risk.score
        incident.severity = risk.severity
        incident.risk_explanation = risk.explanation

        if chains:
            incident.title = chains[0][0].title
        else:
            strongest = max(incident.alerts, key=lambda alert: alert.risk_score, default=None)
            if strongest is not None:
                incident.title = strongest.name or strongest.rule_id

        incident.attack_chain = self._attack_chain(incident)
        incident.timeline = self._timeline(incident)
        stamps = [alert.timestamp for alert in incident.alerts if alert.timestamp]
        first_evidence = [
            event.timestamp for event in incident.unique_events() if event.timestamp
        ]
        if stamps or first_evidence:
            incident.first_seen = min(stamps + first_evidence)
            incident.last_seen = max(stamps + first_evidence)
        return incident

    # -- internals ---------------------------------------------------------
    def _prepare(self, alerts: Iterable) -> list[Alert]:
        """Coerce input to alerts, chronologically; skip anything unusable."""
        prepared: list[Alert] = []
        for item in alerts:
            self.stats.alerts_received += 1
            try:
                if isinstance(item, Alert):
                    prepared.append(item)
                elif isinstance(item, dict):
                    prepared.append(Alert.from_dict(item))
                else:
                    raise TypeError(f"expected Alert or dict, got {type(item).__name__}")
            except Exception as exc:
                self.stats.alerts_skipped += 1
                LOGGER.warning("skipping malformed alert: %s", exc)
        prepared.sort(key=lambda alert: (alert.timestamp or "", alert.alert_id))
        return prepared

    @staticmethod
    def _next_number(incidents: Sequence[Incident]) -> int:
        """One past the highest existing incident number."""
        highest = 0
        for incident in incidents:
            digits = "".join(ch for ch in incident.incident_id if ch.isdigit())
            if digits:
                highest = max(highest, int(digits))
        return highest + 1

    def _find_incident(
        self, alert: Alert, incidents: Sequence[Incident]
    ) -> tuple[Incident | None, CorrelationMatch]:
        """Pick the best incident for this alert, strongest and most recent first."""
        best: tuple[Incident, CorrelationMatch] | None = None
        for incident in incidents:
            match = self.correlate(alert, incident)
            if not match:
                continue
            if best is None or (
                CorrelationStrength.rank(match.strength),
                incident.last_seen or "",
            ) > (
                CorrelationStrength.rank(best[1].strength),
                best[0].last_seen or "",
            ):
                best = (incident, match)
        return (best[0], best[1]) if best else (None, NO_MATCH)

    def _chain_related(self, alert: Alert, incident: Incident) -> str | None:
        """Return a chain id whose stages cover both this alert and an existing one."""
        for chain in ATTACK_CHAINS:
            stages_hit = {
                index
                for index, stage in enumerate(chain.stages)
                if stage.matches(alert)
            }
            if not stages_hit:
                continue
            for existing in incident.alerts:
                other = {
                    index
                    for index, stage in enumerate(chain.stages)
                    if stage.matches(existing)
                }
                if other and other != stages_hit:
                    return chain.chain_id
        return None

    def _attach(self, incident: Incident, alert: Alert, match: CorrelationMatch) -> None:
        """Add an alert to an incident and update its entities and time span.

        The time span has to be maintained *here*, not only in
        :meth:`finalize`: the correlation window for the next alert is measured
        against ``last_seen``, so it must be current while the run proceeds.
        """
        # Extend the technique index before the alert lands, so the cached
        # union stays in step with the alert count without a rescan.
        techniques = self._technique_index(incident) | _techniques(alert)
        incident.alerts.append(alert)
        self._techniques_by_incident[incident.incident_id] = (
            len(incident.alerts),
            techniques,
        )
        if alert.timestamp:
            if not incident.first_seen or alert.timestamp < incident.first_seen:
                incident.first_seen = alert.timestamp
            if not incident.last_seen or alert.timestamp > incident.last_seen:
                incident.last_seen = alert.timestamp
        if alert.host and not incident.host:
            incident.host = alert.host
        if alert.source_ip and alert.source_ip not in incident.source_ips:
            incident.source_ips.append(alert.source_ip)
        if alert.user and alert.user not in incident.users:
            incident.users.append(alert.user)
        for reason in match.reasons:
            if reason not in incident.correlation_reasons:
                incident.correlation_reasons.append(reason)

    @staticmethod
    def _attack_chain(incident: Incident) -> list[dict]:
        """Aggregate unique ATT&CK techniques in order of first appearance."""
        chain: list[dict] = []
        seen: set[tuple] = set()
        for alert in incident.alerts:
            mitre = alert.mitre
            if not mitre:
                continue
            key = (mitre.get("technique_id"), mitre.get("sub_technique_id"))
            if key in seen:
                continue
            seen.add(key)
            chain.append(dict(mitre))
        return chain

    def _timeline(self, incident: Incident) -> list[TimelineEntry]:
        """Build the chronological timeline from evidence events and alerts."""
        entries: list[TimelineEntry] = []

        if self.config.include_events:
            for event in incident.unique_events():
                entries.append(
                    TimelineEntry(
                        timestamp=event.timestamp,
                        type=ENTRY_EVENT,
                        event=event.event_type,
                        description=event.message or event.raw or "",
                    )
                )
        for alert in incident.alerts:
            entries.append(
                TimelineEntry(
                    timestamp=alert.timestamp,
                    type=ENTRY_ALERT,
                    event=alert.rule_id,
                    description=alert.description,
                    severity=alert.severity,
                    alert_id=alert.alert_id or None,
                )
            )

        unique: dict[tuple, TimelineEntry] = {}
        for entry in entries:
            unique.setdefault(
                (entry.timestamp, entry.type, entry.event, entry.description), entry
            )
        return sorted(unique.values(), key=lambda entry: entry.sort_key())
