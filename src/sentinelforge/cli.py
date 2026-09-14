"""Command line interface for SentinelForge.

The CLI is read-only by design: it collects logs, normalizes them, and writes
JSON Lines to stdout or a file.  It never modifies the system it monitors.

That holds for the AI commands too (Phase 5): ``ai analyze`` sends a bounded,
redacted view of one stored incident to a configured provider and writes the
returned analysis back onto that incident.  Nothing a model returns is executed.

Phase 7 adds the one exception, and confines it: ``sentinelforge response`` can
change the system, and every one of its commands is built so that a human
decides.  Requesting an action never performs it, approval and execution are
separate commands, ``--dry-run`` resolves entirely without touching anything,
and the target of a command is always a value (an address, a PID) that is
parsed before use -- never a command line.
"""

from __future__ import annotations

import argparse
import inspect
import logging
import os
import sqlite3
import time
import signal
import sys
from typing import Iterable, Iterator, Sequence, TextIO

from . import __version__
from .collector.base import local_hostname
from .collector.file import (
    DEFAULT_LOG_PATHS,
    FilesCollector,
    detect_log_files,
    unreadable_log_files,
)
from .collector.journal import JournalCollector
from .dashboard.state import DashboardConfig
from .correlation.engine import (
    DEFAULT_WINDOW_SECONDS,
    CorrelationConfig,
    CorrelationEngine,
    CorrelationStrength,
)
from .ai.analyst import AISocAnalyst, AnalystConfig, attach_analysis
from .ai.cache import FileAnalysisCache, NullAnalysisCache, default_cache_dir
from .ai.client import ENV_MODEL, ENV_PROVIDER, LLMClient, LLMConfig
from .ai.providers import ProviderError, available_providers
from .ai.prompts import FENCE_MARKERS, build_prompts
from .ai.sanitizer import ContextLimits, build_incident_context
from .ai.schemas import AIIncidentAnalysis
from .detection.engine import DetectionEngine, EngineConfig
from .detection.rules import default_rules
from .models.event import Severity
from .models.incident import ENTRY_ALERT, IncidentStatus
from .models.record import RawRecord
from .pipeline.load import load_alerts, load_events
from .pipeline.normalize import normalize_all
from .response.actions import ResponseBackends
from .response.engine import (
    ApprovalRequired,
    PolicyRefused,
    PrivilegeRequired,
    ResponseEngine,
    ResponseError,
)
from .response.models import ActionStatus, ActionType
from .response.validators import ValidationError as ResponseValidationError
from .sensors.base import SensorUnavailableError
from .sensors.ebpf.loader import check_ebpf_support
from .sensors.registry import SENSOR_NAMES, build_sensor, get_spec, sensor_statuses
from .storage.sqlite import IncidentStore, default_database_path

LOGGER = logging.getLogger("sentinelforge")

SOURCE_CHOICES = ("auto", "journal", "files", "all")
SEVERITY_CHOICES = Severity.ALL


def configure_logging(verbosity: int = 0, quiet: bool = False) -> None:
    """Send application logs to stderr so stdout stays pure JSONL."""
    level = logging.WARNING
    if quiet:
        level = logging.ERROR
    elif verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelforge",
        description=(
            "SentinelForge - Linux log collection, event normalization, "
            "threat detection and incident correlation."
        ),
    )
    parser.add_argument("--version", action="version", version=f"sentinelforge {__version__}")
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="increase log verbosity (-vv for debug)"
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="only log errors")

    subparsers = parser.add_subparsers(dest="command")

    collect = subparsers.add_parser("collect", help="collect and normalize log events")
    collect.add_argument(
        "--source",
        choices=SOURCE_CHOICES,
        default="auto",
        help="which log source to read (default: auto = journal if available, else files)",
    )
    collect.add_argument(
        "--follow", "-f", action="store_true", help="stream new events as they arrive"
    )
    collect.add_argument(
        "--output", "-o", metavar="FILE", help="write JSON Lines to FILE instead of stdout"
    )
    collect.add_argument(
        "--overwrite",
        action="store_true",
        help="truncate --output instead of appending to it",
    )
    collect.add_argument(
        "--limit", "-n", type=int, default=None, metavar="N", help="read at most N recent entries"
    )
    collect.add_argument(
        "--since",
        default="1 hour ago",
        help="journal time window passed to journalctl --since (default: '1 hour ago')",
    )
    collect.add_argument(
        "--unit", "-u", default=None, help="restrict journal collection to a systemd unit"
    )
    collect.add_argument(
        "--identifier",
        "-t",
        default=None,
        help="restrict journal collection to a syslog identifier (e.g. sshd)",
    )
    collect.add_argument(
        "--file",
        dest="files",
        action="append",
        default=None,
        metavar="PATH",
        help="explicit log file to read (repeatable); defaults to auto-detection",
    )
    collect.add_argument(
        "--event-type",
        dest="event_types",
        action="append",
        default=None,
        metavar="TYPE",
        help="only emit events of this type (repeatable)",
    )
    collect.add_argument(
        "--raw-full",
        action="store_true",
        help="keep the complete journal JSON entry in the 'raw' field (verbose)",
    )
    collect.add_argument(
        "--compact",
        action="store_true",
        help="omit fields that are null instead of writing them out",
    )

    subparsers.add_parser("sources", help="show which log sources are available")

    detect = subparsers.add_parser(
        "detect", help="run detection rules over collected events and emit alerts"
    )
    detect.add_argument(
        "events",
        metavar="EVENTS.jsonl",
        help="JSON Lines file written by 'sentinelforge collect' ('-' reads stdin)",
    )
    detect.add_argument(
        "--output", "-o", metavar="FILE", help="write alerts as JSON Lines to FILE"
    )
    detect.add_argument(
        "--overwrite", action="store_true", help="truncate --output instead of appending"
    )
    detect.add_argument(
        "--rule",
        dest="rules",
        action="append",
        default=None,
        metavar="RULE_ID",
        help="only run this rule (repeatable); see 'sentinelforge rules'",
    )
    detect.add_argument(
        "--exclude-rule",
        dest="excluded_rules",
        action="append",
        default=None,
        metavar="RULE_ID",
        help="skip this rule (repeatable)",
    )
    detect.add_argument(
        "--min-severity",
        choices=SEVERITY_CHOICES,
        default=None,
        help="only report alerts at this severity or above",
    )
    detect.add_argument(
        "--dedup-window",
        type=int,
        default=EngineConfig.dedup_window_seconds,
        metavar="SECONDS",
        help="fold repeats of the same finding within this window into one alert "
        f"(default: {EngineConfig.dedup_window_seconds}, 0 disables)",
    )
    detect.add_argument(
        "--threshold",
        type=int,
        default=None,
        metavar="N",
        help="override the failure threshold of the brute-force rules (default: 5)",
    )
    detect.add_argument(
        "--window",
        type=int,
        default=None,
        metavar="SECONDS",
        help="override the correlation window of the brute-force rules (default: 300)",
    )
    detect.add_argument(
        "--max-evidence",
        type=int,
        default=None,
        metavar="N",
        help="write at most N evidence events per alert (default: all of them)",
    )
    detect.add_argument(
        "--summary",
        action="store_true",
        help="print a human-readable summary to stderr instead of only JSON",
    )
    detect.add_argument(
        "--no-evidence",
        action="store_true",
        help="omit the evidence block from the JSON output",
    )

    subparsers.add_parser("rules", help="list the available detection rules")

    correlate = subparsers.add_parser(
        "correlate", help="correlate alerts into incidents"
    )
    correlate.add_argument(
        "alerts",
        metavar="ALERTS.jsonl",
        help="JSON Lines file written by 'sentinelforge detect' ('-' reads stdin)",
    )
    correlate.add_argument(
        "--output", "-o", metavar="FILE", help="write incidents as JSON Lines to FILE"
    )
    correlate.add_argument(
        "--overwrite", action="store_true", help="truncate --output instead of appending"
    )
    correlate.add_argument(
        "--window",
        type=float,
        default=DEFAULT_WINDOW_SECONDS / 60,
        metavar="MINUTES",
        help="correlation window in minutes (default: %(default)s)",
    )
    correlate.add_argument(
        "--min-strength",
        choices=CorrelationStrength.ALL,
        default=CorrelationStrength.MEDIUM,
        help="weakest correlation accepted; 'weak' means same host only "
        "(default: %(default)s)",
    )
    correlate.add_argument(
        "--chain-upgrades-weak",
        action="store_true",
        help="let a related attack chain promote a same-host-only match to medium",
    )
    correlate.add_argument(
        "--db",
        metavar="PATH",
        default=None,
        help=f"incident database (default: {default_database_path()})",
    )
    correlate.add_argument(
        "--no-save", action="store_true", help="do not write incidents to the database"
    )
    correlate.add_argument(
        "--no-events",
        action="store_true",
        help="keep only alerts on the timeline, not the underlying events",
    )
    correlate.add_argument(
        "--no-alerts", action="store_true", help="omit the alerts block from the JSON output"
    )
    correlate.add_argument(
        "--no-evidence",
        action="store_true",
        help="omit each alert's evidence from the JSON output",
    )
    correlate.add_argument(
        "--summary", action="store_true", help="print a readable run summary to stderr"
    )

    incident = subparsers.add_parser("incident", help="show one incident")
    incident.add_argument("incident_id", metavar="INC-000001", help="incident to display")
    incident.add_argument("--db", metavar="PATH", default=None, help="incident database")
    incident.add_argument(
        "--status",
        choices=IncidentStatus.ALL,
        default=None,
        help="set the incident's lifecycle status, then display it",
    )
    incident.add_argument("--json", action="store_true", help="print the raw incident JSON")
    incident.add_argument(
        "--max-timeline",
        type=int,
        default=40,
        metavar="N",
        help="show at most N timeline entries (0 = all; default: %(default)s)",
    )

    incidents = subparsers.add_parser("incidents", help="list stored incidents")
    incidents.add_argument("--db", metavar="PATH", default=None, help="incident database")
    incidents.add_argument(
        "--status", choices=IncidentStatus.ALL, default=None, help="only this status"
    )
    incidents.add_argument(
        "--min-severity", choices=SEVERITY_CHOICES, default=None, help="minimum severity"
    )
    incidents.add_argument(
        "--limit", type=int, default=None, metavar="N", help="show at most N incidents"
    )
    incidents.add_argument("--json", action="store_true", help="print raw incident JSON lines")

    sensor = subparsers.add_parser("sensor", help="telemetry sensors (eBPF and log sources)")
    sensor_commands = sensor.add_subparsers(dest="sensor_command")

    sensor_commands.add_parser("list", help="show available sensors")
    sensor_commands.add_parser("check", help="diagnose eBPF support on this machine")

    start = sensor_commands.add_parser("start", help="run a sensor and emit normalized events")
    start.add_argument("name", choices=SENSOR_NAMES, help="which sensor to run")
    start.add_argument(
        "--output", "-o", metavar="FILE", help="write JSON Lines to FILE instead of stdout"
    )
    start.add_argument(
        "--overwrite", action="store_true", help="truncate --output instead of appending"
    )
    start.add_argument(
        "--limit", "-n", type=int, default=None, metavar="N", help="stop after N events"
    )
    start.add_argument(
        "--duration",
        "-d",
        type=float,
        default=None,
        metavar="SECONDS",
        help="stop after this many seconds",
    )
    start.add_argument(
        "--no-args",
        action="store_true",
        help="do not capture command-line arguments (ebpf-process): they can contain "
        "secrets, and this compiles the capture out of the BPF program entirely",
    )
    start.add_argument(
        "--uid",
        type=int,
        default=None,
        metavar="UID",
        help="only report activity by this user id (filtered in the kernel)",
    )
    start.add_argument(
        "--compact", action="store_true", help="omit fields that are null"
    )

    bench = sensor_commands.add_parser(
        "bench", help="measure sensor throughput (events/second)"
    )
    bench.add_argument("name", choices=SENSOR_NAMES, default="mock", nargs="?")
    bench.add_argument(
        "--count", "-n", type=int, default=10000, metavar="N", help="events to measure"
    )

    ai = subparsers.add_parser(
        "ai", help="AI SOC analyst: explain a stored incident (never acts on it)"
    )
    ai_commands = ai.add_subparsers(dest="ai_command")

    analyze = ai_commands.add_parser(
        "analyze", help="analyze one stored incident with the configured LLM provider"
    )
    analyze.add_argument("incident_id", metavar="INC-000001", help="incident to analyze")
    analyze.add_argument("--db", metavar="PATH", default=None, help="incident database")
    analyze.add_argument(
        "--provider",
        choices=available_providers(),
        default=None,
        help=f"LLM provider (default: ${ENV_PROVIDER} or 'mock', which runs offline)",
    )
    analyze.add_argument(
        "--model",
        default=None,
        metavar="NAME",
        help=f"model id for the provider (default: ${ENV_MODEL})",
    )
    analyze.add_argument(
        "--output", "-o", metavar="FILE", help="write the analysis as JSON to FILE"
    )
    analyze.add_argument(
        "--json", action="store_true", help="print the analysis as JSON instead of a report"
    )
    analyze.add_argument(
        "--refresh",
        action="store_true",
        help="ignore any cached analysis for this incident version",
    )
    analyze.add_argument(
        "--no-cache", action="store_true", help="neither read nor write the analysis cache"
    )
    analyze.add_argument(
        "--cache-dir",
        metavar="PATH",
        default=None,
        help=f"analysis cache directory (default: {default_cache_dir()})",
    )
    analyze.add_argument(
        "--no-save",
        action="store_true",
        help="do not write the analysis back onto the stored incident",
    )
    analyze.add_argument(
        "--max-alerts",
        type=int,
        default=ContextLimits.max_alerts,
        metavar="N",
        help="send at most N alerts to the provider (default: %(default)s)",
    )
    analyze.add_argument(
        "--max-timeline",
        type=int,
        default=ContextLimits.max_timeline_entries,
        metavar="N",
        help="send at most N timeline entries (default: %(default)s)",
    )
    analyze.add_argument(
        "--show-prompt",
        action="store_true",
        help="print the exact prompts to stderr instead of calling a provider "
        "(review what would be sent; no request is made)",
    )

    ai_commands.add_parser(
        "providers", help="show the configured provider (never prints the API key)"
    )

    cache = ai_commands.add_parser("cache", help="inspect or clear the analysis cache")
    cache.add_argument("--clear", action="store_true", help="delete every cached analysis")
    cache.add_argument("--cache-dir", metavar="PATH", default=None, help="cache directory")

    dashboard = subparsers.add_parser(
        "dashboard", help="serve the local SOC dashboard (read-only web console)"
    )
    dashboard.add_argument(
        "--host",
        default=DashboardConfig.host,
        metavar="ADDRESS",
        help="bind address (default: %(default)s; the dashboard has no authentication, "
        "so anything else exposes security data to the network)",
    )
    dashboard.add_argument(
        "--port", type=int, default=DashboardConfig.port, metavar="PORT",
        help="listen port (default: %(default)s)",
    )
    dashboard.add_argument(
        "--db", metavar="PATH", default=None,
        help=f"incident database to read (default: {default_database_path()})",
    )
    dashboard.add_argument(
        "--watch-events", metavar="FILE", default=None,
        help="follow this JSON Lines file for live events "
        "(as written by 'sentinelforge collect -o')",
    )
    dashboard.add_argument(
        "--watch-alerts", metavar="FILE", default=None,
        help="follow this JSON Lines file for live alerts "
        "(as written by 'sentinelforge detect -o')",
    )
    dashboard.add_argument(
        "--poll-interval", type=float, default=DashboardConfig.poll_interval, metavar="SECONDS",
        help="how often to check the incident store for changes (default: %(default)s)",
    )
    dashboard.add_argument(
        "--live-buffer", type=int, default=DashboardConfig.live_buffer, metavar="N",
        help="how many live events/alerts to keep in memory (default: %(default)s)",
    )
    dashboard.add_argument(
        "--demo",
        action="store_true",
        help="serve synthetic demonstration data from a separate database; every page "
        "is labelled DEMO / SYNTHETIC DATA and no real telemetry is read",
    )
    dashboard.add_argument(
        "--debug",
        action="store_true",
        help="Flask debug mode: DEVELOPMENT ONLY. The debugger can execute arbitrary "
        "code, so never enable it on a monitored host",
    )
    dashboard.add_argument(
        "--no-response",
        action="store_true",
        help="serve the dashboard with the response API disabled entirely: containment "
        "can then only be performed from the command line",
    )

    _add_response_parser(subparsers)
    return parser


#: CLI spelling of each action type, e.g. ``block-ip`` for ``block_ip``.
ACTION_COMMANDS = {action_type.replace("_", "-"): action_type for action_type in ActionType.ALL}


def _add_response_parser(subparsers) -> None:
    """Build the ``sentinelforge response`` command tree (Phase 7).

    Deliberate shape: requesting an action and executing it are different
    commands, so nothing a single mistyped line can do is irreversible.
    """
    response = subparsers.add_parser(
        "response",
        help="containment actions (human-approved; never automatic)",
        description=(
            "Request, approve and execute containment actions. Every real action "
            "requires an explicit human approval step, is validated against policy, is "
            "verified after execution, and is written to an append-only audit trail. "
            "SentinelForge never escalates privileges and never executes anything that "
            "came from a log, a telemetry field or an AI answer."
        ),
    )
    response_commands = response.add_subparsers(dest="response_command")

    def _common(parser, target_help: str, metavar: str):
        parser.add_argument("target", metavar=metavar, help=target_help)
        parser.add_argument("--db", metavar="PATH", default=None, help="incident database")
        parser.add_argument(
            "--incident", metavar="INC-000001", default=None,
            help="incident this action belongs to",
        )
        parser.add_argument(
            "--reason", default="", metavar="TEXT",
            help="why this containment is being requested (recorded in the audit trail)",
        )
        parser.add_argument(
            "--by", dest="actor", default=None, metavar="NAME",
            help="operator label to record as the requester (default: the local user)",
        )
        parser.add_argument(
            "--dry-run", action="store_true",
            help="show exactly what would happen and record it; changes nothing",
        )
        parser.add_argument("--json", action="store_true", help="print JSON instead of a report")
        return parser

    listing = response_commands.add_parser("list", help="list response actions")
    listing.add_argument("--db", metavar="PATH", default=None, help="incident database")
    listing.add_argument("--incident", metavar="INC-000001", default=None, help="filter by incident")
    listing.add_argument(
        "--status", choices=ActionStatus.ALL, default=None, help="filter by status"
    )
    listing.add_argument(
        "--type", dest="action_type", choices=sorted(ACTION_COMMANDS), default=None,
        help="filter by action type",
    )
    listing.add_argument("--limit", type=int, default=50, metavar="N", help="most recent N")
    listing.add_argument("--json", action="store_true", help="print JSON")

    show = response_commands.add_parser("show", help="show one action in full")
    show.add_argument("action_id", metavar="ACTION-00001")
    show.add_argument("--db", metavar="PATH", default=None, help="incident database")
    show.add_argument("--json", action="store_true", help="print JSON")

    capabilities = response_commands.add_parser(
        "capabilities", help="which containment actions this host actually supports"
    )
    capabilities.add_argument("--db", metavar="PATH", default=None, help="incident database")
    capabilities.add_argument("--json", action="store_true", help="print JSON")

    preview = response_commands.add_parser(
        "preview", help="describe what an action would do (changes nothing)"
    )
    preview.add_argument("action", choices=sorted(ACTION_COMMANDS), metavar="ACTION")
    preview.add_argument("target", metavar="TARGET", help="IP address, PID or session id")
    preview.add_argument("--db", metavar="PATH", default=None, help="incident database")
    preview.add_argument("--ttl", type=int, default=None, metavar="SECONDS", help="block lifetime")
    preview.add_argument("--incident", metavar="INC-000001", default=None)
    preview.add_argument("--json", action="store_true", help="print JSON")

    block = _common(
        response_commands.add_parser(
            "block-ip", help="request a firewall block for one source address"
        ),
        "IPv4 or IPv6 address to block",
        "IP",
    )
    block.add_argument(
        "--ttl", type=int, default=None, metavar="SECONDS",
        help="remove the block automatically after this long (the firewall does it)",
    )

    _common(
        response_commands.add_parser(
            "unblock-ip", help="request removal of a SentinelForge firewall block"
        ),
        "address whose SentinelForge block should be removed",
        "IP",
    )

    kill = _common(
        response_commands.add_parser("kill-process", help="request termination of one process"),
        "PID of the process to terminate",
        "PID",
    )
    kill.add_argument(
        "--override-protected",
        action="store_true",
        help="accept the risk of targeting a protected process (system daemon or "
        "SentinelForge itself); the override is recorded on the action",
    )

    _common(
        response_commands.add_parser(
            "terminate-session", help="request termination of one login session"
        ),
        "systemd-logind session id",
        "SESSION",
    )

    isolate = _common(
        response_commands.add_parser(
            "isolate-host", help="host isolation (planned / capability dependent)"
        ),
        "this host (the only permitted target)",
        "HOST",
    )
    isolate.set_defaults(target="localhost")
    isolate.add_argument(
        "--ttl", type=int, default=None, metavar="SECONDS", help=argparse.SUPPRESS
    )

    approve = response_commands.add_parser("approve", help="approve a pending action")
    approve.add_argument("action_id", metavar="ACTION-00001")
    approve.add_argument("--db", metavar="PATH", default=None, help="incident database")
    approve.add_argument("--by", dest="actor", default=None, metavar="NAME", help="approver label")
    approve.add_argument("--reason", default="", metavar="TEXT", help="why it was approved")
    approve.add_argument("--json", action="store_true", help="print JSON")

    execute = response_commands.add_parser(
        "execute", help="execute an approved action (the only command that changes the system)"
    )
    execute.add_argument("action_id", metavar="ACTION-00001")
    execute.add_argument("--db", metavar="PATH", default=None, help="incident database")
    execute.add_argument("--by", dest="actor", default=None, metavar="NAME", help="operator label")
    execute.add_argument(
        "--yes", "-y", action="store_true", help="skip the interactive confirmation"
    )
    execute.add_argument("--json", action="store_true", help="print JSON")

    for name, help_text in (
        ("reject", "refuse a pending action"),
        ("cancel", "withdraw a pending action"),
        ("rollback", "undo a completed, reversible action"),
    ):
        parser = response_commands.add_parser(name, help=help_text)
        parser.add_argument("action_id", metavar="ACTION-00001")
        parser.add_argument("--db", metavar="PATH", default=None, help="incident database")
        parser.add_argument("--by", dest="actor", default=None, metavar="NAME")
        parser.add_argument("--reason", default="", metavar="TEXT")
        parser.add_argument("--json", action="store_true", help="print JSON")

    audit = response_commands.add_parser("audit", help="read the response audit trail")
    audit.add_argument("--db", metavar="PATH", default=None, help="incident database")
    audit.add_argument("--action", dest="action_id", default=None, metavar="ACTION-00001")
    audit.add_argument("--incident", default=None, metavar="INC-000001")
    audit.add_argument("--limit", type=int, default=50, metavar="N")
    audit.add_argument(
        "--verify", action="store_true", help="re-check the audit trail's hash chain"
    )
    audit.add_argument("--json", action="store_true", help="print JSON")


def _build_collectors(args: argparse.Namespace) -> list:
    """Instantiate the collectors selected on the command line."""
    journal_ok = JournalCollector.available()

    wanted = args.source
    if wanted == "auto":
        wanted = "journal" if journal_ok else "files"

    collectors = []
    if wanted in ("journal", "all"):
        if journal_ok:
            collectors.append(
                JournalCollector(
                    since=args.since,
                    limit=args.limit,
                    follow=args.follow,
                    unit=args.unit,
                    identifier=args.identifier,
                    raw_full=getattr(args, "raw_full", False),
                )
            )
        else:
            LOGGER.warning("journalctl is not available on this system")
    if wanted in ("files", "all"):
        # Only touch the filesystem when file collection was actually requested.
        detected_files = args.files if args.files else detect_log_files()
        if detected_files:
            collectors.append(
                FilesCollector(paths=detected_files, follow=args.follow, limit=args.limit)
            )
        else:
            LOGGER.warning(
                "no readable auth log files found (looked for: %s)",
                ", ".join(DEFAULT_LOG_PATHS),
            )
    return collectors


def _chain(collectors: Iterable) -> Iterator[RawRecord]:
    for collector in collectors:
        yield from collector.collect()


def _log_normalize_error(exc: Exception, record: object) -> None:
    LOGGER.warning("skipping record that could not be normalized: %s", exc)


def run_collect(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Run the ``collect`` command.  Returns a process exit code."""
    stdout = stdout or sys.stdout
    collectors = _build_collectors(args)
    if not collectors:
        LOGGER.error("no usable log sources; nothing to collect")
        return 1

    wanted_types = set(args.event_types) if args.event_types else None
    host = local_hostname()

    if args.output:
        mode = "w" if args.overwrite else "a"
        try:
            stream = open(args.output, mode, encoding="utf-8")
        except OSError as exc:
            LOGGER.error("cannot open output file %s: %s", args.output, exc)
            return 1
        close_stream = True
    else:
        stream = stdout
        close_stream = False

    count = 0
    try:
        events = normalize_all(
            _chain(collectors), host_default=host, on_error=_log_normalize_error
        )
        for event in events:
            if wanted_types and event.event_type not in wanted_types:
                continue
            stream.write(event.to_json(include_empty=not args.compact) + "\n")
            count += 1
            if args.follow:
                stream.flush()
    except KeyboardInterrupt:
        LOGGER.info("interrupted by user")
    except BrokenPipeError:  # e.g. piping into `head`
        return 0
    finally:
        try:
            stream.flush()
        except (OSError, ValueError):  # pragma: no cover
            pass
        if close_stream:
            stream.close()

    LOGGER.info("wrote %d event(s)", count)
    return 0


def run_sources(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Report which log sources this machine offers (read-only check)."""
    stdout = stdout or sys.stdout
    journal_ok = JournalCollector.available()
    files = detect_log_files()
    blocked = unreadable_log_files()
    stdout.write(f"systemd journal (journalctl): {'available' if journal_ok else 'not found'}\n")
    for path in files:
        stdout.write(f"log file: {path} (readable)\n")
    for path in blocked:
        stdout.write(f"log file: {path} (exists, permission denied - needs sudo or group 'adm')\n")
    if not files and not blocked:
        stdout.write("log file: none of " + ", ".join(DEFAULT_LOG_PATHS) + " present\n")
    return 0 if (journal_ok or files) else 1


def _select_rules(args: argparse.Namespace) -> tuple[list, list[str]]:
    """Build the rule list for this run, honouring --rule / --exclude-rule.

    Returns the selected rules and any rule ids the user named that do not exist.
    """
    rules = default_rules()

    # Threshold/window overrides apply to the rules that accept them.
    overrides = {}
    if getattr(args, "threshold", None) is not None:
        overrides["threshold"] = args.threshold
    if getattr(args, "window", None) is not None:
        overrides["window_seconds"] = args.window
    if overrides:
        # Only rebuild the rules that actually take these settings.
        rules = [
            type(rule)(**overrides) if _accepts(type(rule), overrides) else rule
            for rule in rules
        ]

    known = {rule.rule_id for rule in rules}
    unknown = [
        rule_id
        for rule_id in (args.rules or []) + (args.excluded_rules or [])
        if rule_id not in known
    ]

    if args.rules:
        wanted = set(args.rules)
        # An explicitly requested rule runs even if it is disabled by default.
        for rule in rules:
            if rule.rule_id in wanted:
                rule.enabled = True
        rules = [rule for rule in rules if rule.rule_id in wanted]
    if args.excluded_rules:
        rules = [rule for rule in rules if rule.rule_id not in set(args.excluded_rules)]
    return rules, unknown


def _accepts(rule_class: type, overrides: dict) -> bool:
    """Return True when a rule's __init__ takes all the given keyword names."""
    try:
        parameters = inspect.signature(rule_class.__init__).parameters
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return False
    return all(name in parameters for name in overrides)


def run_detect(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Run the ``detect`` command.  Returns a process exit code."""
    stdout = stdout or sys.stdout

    try:
        events = load_events(args.events)
    except OSError as exc:
        LOGGER.error("cannot read events from %s: %s", args.events, exc)
        return 1
    if not events:
        LOGGER.warning("no events loaded from %s", args.events)

    rules, unknown = _select_rules(args)
    for rule_id in unknown:
        LOGGER.warning("unknown rule id %r (see 'sentinelforge rules')", rule_id)
    if not rules:
        LOGGER.error("no rules selected; nothing to detect")
        return 1

    engine = DetectionEngine(
        rules=rules,
        config=EngineConfig(
            dedup_window_seconds=args.dedup_window,
            min_severity=args.min_severity,
        ),
    )
    alerts = engine.run(events)

    if args.output:
        mode = "w" if args.overwrite else "a"
        try:
            stream = open(args.output, mode, encoding="utf-8")
        except OSError as exc:
            LOGGER.error("cannot open output file %s: %s", args.output, exc)
            return 1
        close_stream = True
    else:
        stream = stdout
        close_stream = False

    try:
        for alert in alerts:
            stream.write(
                alert.to_json(
                    include_evidence=not args.no_evidence, max_evidence=args.max_evidence
                )
                + "\n"
            )
    except BrokenPipeError:  # pragma: no cover - e.g. piping into `head`
        return 0
    finally:
        try:
            stream.flush()
        except (OSError, ValueError):  # pragma: no cover
            pass
        if close_stream:
            stream.close()

    if args.summary:
        _print_detect_summary(engine, alerts, sys.stderr)
    stats = engine.stats
    LOGGER.info(
        "%d event(s), %d alert(s), %d suppressed duplicate(s)",
        stats.events_processed,
        stats.alerts_generated,
        stats.alerts_suppressed,
    )
    return 0


def _print_detect_summary(engine: DetectionEngine, alerts: list, stream: TextIO) -> None:
    """Write a short, human-readable run summary."""
    stats = engine.stats
    stream.write("\n--- SentinelForge detection summary ---\n")
    stream.write(
        f"events: {stats.events_processed} processed, {stats.events_skipped} skipped\n"
    )
    stream.write(
        f"alerts: {stats.alerts_generated} raised, "
        f"{stats.alerts_suppressed} duplicates suppressed, "
        f"{stats.alerts_filtered} below --min-severity\n"
    )

    by_severity: dict[str, int] = {}
    for alert in alerts:
        by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
    for severity in reversed(Severity.ALL):
        if by_severity.get(severity):
            stream.write(f"  {severity:8} {by_severity[severity]}\n")

    for rule_id, reason in stats.rules_skipped.items():
        stream.write(f"skipped rule {rule_id}: {reason}\n")
    for rule_id, error in stats.rule_errors.items():
        stream.write(f"rule {rule_id} FAILED: {error}\n")

    if alerts:
        stream.write("\n")
        for alert in alerts:
            stream.write(alert.summary() + "\n")


def run_rules(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """List the detection rules and their ATT&CK mappings."""
    stdout = stdout or sys.stdout
    engine = DetectionEngine()
    for entry in engine.rule_status():
        mitre = entry["mitre"] or {}
        technique = mitre.get("sub_technique_id") or mitre.get("technique_id", "-")
        name = mitre.get("sub_technique") or mitre.get("technique", "-")
        state = "enabled" if entry["available"] else f"UNAVAILABLE ({entry['unavailable_reason']})"
        stdout.write(f"{entry['rule_id']}\n")
        stdout.write(f"    {entry['name']} - severity {entry['severity']}\n")
        stdout.write(f"    ATT&CK: {technique} {name} ({mitre.get('tactic', '-')})\n")
        stdout.write(f"    status: {state}\n")
        stdout.write(f"    {entry['description']}\n")
    return 0


def run_correlate(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Run the ``correlate`` command.  Returns a process exit code."""
    stdout = stdout or sys.stdout

    try:
        alerts = load_alerts(args.alerts)
    except OSError as exc:
        LOGGER.error("cannot read alerts from %s: %s", args.alerts, exc)
        return 1
    if not alerts:
        LOGGER.warning("no alerts loaded from %s", args.alerts)

    window_seconds = int(max(0.0, args.window) * 60)
    engine = CorrelationEngine(
        CorrelationConfig(
            window_seconds=window_seconds,
            min_strength=args.min_strength,
            chain_upgrades_weak=args.chain_upgrades_weak,
            include_events=not args.no_events,
        )
    )

    store = None
    existing = []
    start_number = 1
    if not args.no_save:
        store = IncidentStore(args.db)
        try:
            store.connect()
            # Alerts may extend an incident that a previous run already opened.
            earliest = min((alert.timestamp for alert in alerts if alert.timestamp), default=None)
            existing = store.active_incidents(earliest, window_seconds)
            start_number = store.next_incident_number()
        except sqlite3.Error as exc:
            LOGGER.error("cannot open incident database %s: %s", store.path, exc)
            store.close()
            return 1

    incidents = engine.run(alerts, existing_incidents=existing, start_number=start_number)

    try:
        if store is not None:
            store.save_all(incidents)
    except sqlite3.Error as exc:
        LOGGER.error("cannot save incidents: %s", exc)
        return 1
    finally:
        if store is not None:
            store.close()

    if args.output:
        mode = "w" if args.overwrite else "a"
        try:
            stream = open(args.output, mode, encoding="utf-8")
        except OSError as exc:
            LOGGER.error("cannot open output file %s: %s", args.output, exc)
            return 1
        close_stream = True
    else:
        stream = stdout
        close_stream = False

    try:
        for incident in incidents:
            stream.write(
                incident.to_json(
                    include_alerts=not args.no_alerts,
                    include_evidence=not args.no_evidence,
                )
                + "\n"
            )
    except BrokenPipeError:  # pragma: no cover - e.g. piping into `head`
        return 0
    finally:
        try:
            stream.flush()
        except (OSError, ValueError):  # pragma: no cover
            pass
        if close_stream:
            stream.close()

    if args.summary:
        _print_correlate_summary(engine, incidents, sys.stderr)
    stats = engine.stats
    LOGGER.info(
        "%d alert(s) -> %d incident(s) (%d created, %d updated)",
        stats.alerts_correlated,
        len(incidents),
        stats.incidents_created,
        stats.incidents_updated,
    )
    return 0


def _print_correlate_summary(engine, incidents, stream: TextIO) -> None:
    """Write a short, human-readable correlation summary."""
    stats = engine.stats
    stream.write("\n--- SentinelForge correlation summary ---\n")
    stream.write(
        f"alerts: {stats.alerts_correlated} correlated, {stats.alerts_skipped} skipped, "
        f"{stats.alerts_duplicate} already in an incident\n"
    )
    stream.write(
        f"incidents: {stats.incidents_created} created, {stats.incidents_updated} updated\n"
    )
    for incident in incidents:
        stream.write(incident.summary_line() + "\n")


def render_incident(incident, max_timeline: int = 40) -> str:
    """Render one incident as a readable terminal report."""
    lines = [
        "=" * 72,
        f"{incident.incident_id}  {incident.title}",
        "=" * 72,
        f"status      : {incident.status}",
        f"severity    : {incident.severity.upper()}  (risk {incident.risk_score}/100)",
        f"host        : {incident.host or '-'}",
        f"source IPs  : {', '.join(incident.source_ips) or '-'}",
        f"users       : {', '.join(incident.users) or '-'}",
        f"first seen  : {incident.first_seen or '-'}",
        f"last seen   : {incident.last_seen or '-'}",
        f"alerts      : {incident.alert_count}   unique events: {incident.event_count}",
    ]
    if incident.matched_chains:
        lines.append(f"attack chain: {', '.join(incident.matched_chains)}")

    lines.append("")
    lines.append("Related alerts")
    lines.append("-" * 72)
    for alert in incident.alerts:
        lines.append(
            f"  {alert.timestamp or '-'}  {alert.severity.upper():8} "
            f"{alert.rule_id:24} {alert.description}"
        )

    lines.append("")
    lines.append("MITRE ATT&CK")
    lines.append("-" * 72)
    if incident.attack_chain:
        for step in incident.attack_chain:
            technique = step.get("sub_technique_id") or step.get("technique_id", "-")
            name = step.get("sub_technique") or step.get("technique", "-")
            lines.append(f"  {technique:12} {name} ({step.get('tactic', '-')})")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append("Why these alerts were correlated")
    lines.append("-" * 72)
    for reason in incident.correlation_reasons or ["(single alert)"]:
        lines.append(f"  - {reason}")

    lines.append("")
    lines.append("Risk score")
    lines.append("-" * 72)
    for line in incident.risk_explanation or ["(not scored)"]:
        lines.append(f"  {line}")

    lines.append("")
    lines.append("Timeline")
    lines.append("-" * 72)
    entries = incident.timeline
    shown = entries if max_timeline in (None, 0) else entries[:max_timeline]
    for entry in shown:
        marker = "ALERT" if entry.type == ENTRY_ALERT else "event"
        lines.append(f"  {entry.timestamp or '-'}  {marker:5}  {entry.event}")
        if entry.description:
            lines.append(f"                        {entry.description}")
    if len(entries) > len(shown):
        lines.append(f"  ... {len(entries) - len(shown)} more entries (use --max-timeline 0)")

    if incident.summary:
        lines.extend(["", "Summary", "-" * 72, f"  {incident.summary}"])
    if incident.ai_analysis:
        lines.extend(["", render_analysis(AIIncidentAnalysis.from_dict(incident.ai_analysis))])
    lines.append("")
    return "\n".join(lines)


def run_incident(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Show (and optionally re-status) one incident."""
    stdout = stdout or sys.stdout
    store = IncidentStore(args.db)
    try:
        store.connect()
        if args.status:
            try:
                changed = store.update_status(args.incident_id, args.status)
            except ValueError as exc:  # pragma: no cover - argparse validates first
                LOGGER.error("%s", exc)
                return 1
            if not changed:
                LOGGER.error("no such incident: %s", args.incident_id)
                return 1
            LOGGER.info("%s is now '%s'", args.incident_id, args.status)

        incident = store.get(args.incident_id)
        if incident is None:
            LOGGER.error("no such incident: %s (database: %s)", args.incident_id, store.path)
            return 1
        if args.json:
            stdout.write(incident.to_json() + "\n")
        else:
            stdout.write(render_incident(incident, args.max_timeline))
        return 0
    except sqlite3.Error as exc:
        LOGGER.error("database error: %s", exc)
        return 1
    finally:
        store.close()


def run_incidents(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """List stored incidents."""
    stdout = stdout or sys.stdout
    store = IncidentStore(args.db)
    try:
        store.connect()
        incidents = store.list_incidents(
            status=args.status, min_severity=args.min_severity, limit=args.limit
        )
    except sqlite3.Error as exc:
        LOGGER.error("database error: %s", exc)
        return 1
    finally:
        store.close()

    if not incidents:
        stdout.write("no incidents stored\n")
        return 0
    for incident in incidents:
        if args.json:
            stdout.write(incident.to_json() + "\n")
        else:
            stdout.write(incident.summary_line() + "\n")
    return 0


def run_sensor_list(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Show every sensor and whether it can run here."""
    stdout = stdout or sys.stdout
    stdout.write("Available sensors:\n\n")
    for status in sensor_statuses():
        spec = get_spec(status.name)
        state = "available" if status.available else "UNAVAILABLE"
        stdout.write(f"  {status.name:14} {state:12} {spec.description if spec else ''}\n")
        if not status.available and status.reason:
            stdout.write(f"  {'':14} reason: {status.reason}\n")
    stdout.write(
        "\nStart one with: sentinelforge sensor start <name>\n"
        "Diagnose eBPF with: sentinelforge sensor check\n"
    )
    return 0


def run_sensor_check(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Print eBPF support diagnostics.  Read-only: changes nothing."""
    stdout = stdout or sys.stdout
    support = check_ebpf_support()
    capability = check_ebpf_support(require_privileges=False)

    stdout.write("eBPF support check\n")
    stdout.write("=" * 60 + "\n")
    for key, value in support.details.items():
        stdout.write(f"  {key:28} {value}\n")
    stdout.write("\n")
    if support.supported:
        stdout.write("eBPF sensors can run in this process.\n")
        return 0

    stdout.write("eBPF sensors cannot run in this process:\n")
    for reason in support.reasons:
        stdout.write(f"  - {reason}\n")
    if capability.supported:
        stdout.write(
            "\nThe kernel and tooling are fine; only privileges are missing.\n"
        )
    if support.remedy:
        stdout.write("\n" + support.remedy + "\n")
    return 1


def _sensor_options(args: argparse.Namespace) -> dict:
    """Translate CLI flags into constructor arguments for the chosen sensor."""
    options: dict = {}
    if args.name == "ebpf-process":
        options["capture_args"] = not args.no_args
        if args.uid is not None:
            options["uid"] = args.uid
    elif args.name == "ebpf-network":
        if args.uid is not None:
            options["uid"] = args.uid
    elif args.name == "mock":
        # Follow forever unless the run is bounded, so --duration works.
        options["repeat"] = 0 if (args.limit is None and args.duration) else 1
    elif args.name in ("journal", "file"):
        options["follow"] = bool(args.duration) and args.limit is None
    return options


def run_sensor_start(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Run one sensor and write its normalized events as JSON Lines."""
    stdout = stdout or sys.stdout
    try:
        sensor = build_sensor(args.name, **_sensor_options(args))
    except KeyError as exc:  # pragma: no cover - argparse restricts the choices
        LOGGER.error("%s", exc)
        return 1

    try:
        sensor.start()
    except SensorUnavailableError as exc:
        # Never silently substitute synthetic data for a sensor the user asked for.
        LOGGER.error("cannot start sensor '%s': %s", args.name, exc.reason)
        if exc.remedy:
            sys.stderr.write("\n" + exc.remedy + "\n")
        return 1
    except Exception as exc:
        LOGGER.error("cannot start sensor '%s': %s", args.name, exc)
        return 1

    if args.output:
        mode = "w" if args.overwrite else "a"
        try:
            stream = open(args.output, mode, encoding="utf-8")
        except OSError as exc:
            LOGGER.error("cannot open output file %s: %s", args.output, exc)
            sensor.stop()
            return 1
        close_stream = True
    else:
        stream = stdout
        close_stream = False

    deadline = (time.monotonic() + args.duration) if args.duration else None
    count = 0
    try:
        for event in sensor.events():
            stream.write(event.to_json(include_empty=not args.compact) + "\n")
            stream.flush()
            count += 1
            if args.limit is not None and count >= args.limit:
                break
            if deadline is not None and time.monotonic() >= deadline:
                break
    except KeyboardInterrupt:
        LOGGER.info("interrupted by user")
    except SensorUnavailableError as exc:  # pragma: no cover - raised at start
        LOGGER.error("sensor stopped: %s", exc.reason)
        return 1
    except Exception as exc:
        LOGGER.error("sensor '%s' failed: %s", args.name, exc)
        return 1
    finally:
        sensor.stop()
        try:
            stream.flush()
        except (OSError, ValueError):  # pragma: no cover
            pass
        if close_stream:
            stream.close()

    dropped = getattr(sensor, "events_dropped", 0)
    if dropped:
        LOGGER.warning("kernel dropped %d event(s) - userspace could not keep up", dropped)
    LOGGER.info("sensor '%s' produced %d event(s)", args.name, count)
    return 0


def run_sensor_bench(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Measure how fast events flow from a sensor through normalization.

    This measures the *userspace* path (decode, normalize, serialize), which is
    what SentinelForge controls.  It says nothing about kernel-side overhead.
    """
    stdout = stdout or sys.stdout
    options = {"repeat": 0, "delay": 0.0} if args.name == "mock" else {}
    try:
        sensor = build_sensor(args.name, **options)
        sensor.start()
    except SensorUnavailableError as exc:
        LOGGER.error("cannot start sensor '%s': %s", args.name, exc.reason)
        if exc.remedy:
            sys.stderr.write("\n" + exc.remedy + "\n")
        return 1

    target = max(1, int(args.count))
    started = time.perf_counter()
    produced = 0
    serialized = 0
    try:
        for event in sensor.events():
            serialized += len(event.to_json())
            produced += 1
            if produced >= target:
                break
    finally:
        sensor.stop()
    elapsed = max(time.perf_counter() - started, 1e-9)

    stdout.write(f"sensor        : {args.name}\n")
    stdout.write(f"events        : {produced}\n")
    stdout.write(f"elapsed       : {elapsed:.3f} s\n")
    stdout.write(f"throughput    : {produced / elapsed:,.0f} events/second\n")
    stdout.write(f"per event     : {elapsed / produced * 1e6:.1f} microseconds\n")
    stdout.write(f"serialized    : {serialized / max(produced, 1):.0f} bytes/event\n")
    dropped = getattr(sensor, "events_dropped", 0)
    stdout.write(f"kernel drops  : {dropped}\n")
    stdout.write(
        "\nThis measures the userspace path only (decode -> normalize -> JSON).\n"
        "Kernel-side cost is bounded by the BPF programs, which copy a fixed-size\n"
        "record per event and filter by PID/UID in the kernel.\n"
    )
    return 0


def run_sensor(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Dispatch the ``sensor`` sub-commands."""
    command = getattr(args, "sensor_command", None)
    if command == "list":
        return run_sensor_list(args, stdout)
    if command == "check":
        return run_sensor_check(args, stdout)
    if command == "start":
        return run_sensor_start(args, stdout)
    if command == "bench":
        return run_sensor_bench(args, stdout)
    build_parser().parse_args(["sensor", "--help"])
    return 0


# --------------------------------------------------------------------------
# AI SOC analyst (Phase 5).  These commands read an incident and write an
# analysis; they never execute anything a model returns.
# --------------------------------------------------------------------------
def _wrap(text: str, width: int = 72, indent: str = "  ", hang: str | None = None) -> list[str]:
    """Wrap prose for the terminal report, keeping a hanging indent on bullets."""
    import textwrap

    if not text:
        return []
    return textwrap.wrap(
        text,
        width=width,
        initial_indent=indent,
        subsequent_indent=hang if hang is not None else indent,
    )


def render_analysis(analysis: AIIncidentAnalysis) -> str:
    """Render an AI analysis as a readable terminal report.

    Mock output is labelled at the top: a reader must never have to guess
    whether an opinion came from a provider or from the offline stub.
    """
    audit = analysis.audit
    lines = [
        "SentinelForge AI Analyst",
        "-" * 72,
    ]
    if audit.is_mock:
        lines.append("*** MOCK ANALYSIS - generated offline, not by a language model ***")
    if audit.cached:
        lines.append(f"(cached analysis for incident version {audit.incident_version})")

    lines.append(f"Incident: {analysis.incident_id}")

    if not analysis.ok:
        lines.extend(
            [
                "",
                "Analysis UNAVAILABLE.",
                f"  reason  : {analysis.error}",
                f"  provider: {audit.provider or '-'} ({audit.error_kind or 'error'})",
                "",
                "The incident itself is unaffected: detection, correlation and the",
                "stored incident do not depend on the AI layer.",
                "",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            "",
            f"Assessment: {analysis.assessment.replace('_', ' ').upper()}",
            f"Confidence: {analysis.confidence:.0%}",
            f"Attack stage: {analysis.attack_stage.replace('_', ' ')}",
            "",
            "Severity:",
            f"  Deterministic: {(analysis.deterministic_severity or '-').upper()} "
            f"({analysis.deterministic_score if analysis.deterministic_score is not None else '-'})",
            f"  AI assessment: {analysis.severity_assessment.upper()}",
        ]
    )
    if analysis.severity_disagreement:
        lines.append(
            "  NOTE: the AI disagrees with the deterministic severity. The "
            "deterministic score stands."
        )

    lines.extend(["", "Summary:"])
    lines.extend(_wrap(analysis.summary))

    if analysis.mitre_analysis:
        lines.extend(["", "MITRE ATT&CK:"])
        for item in analysis.mitre_analysis:
            lines.append(f"  {item.technique_id:12} {item.technique} [{item.relevance}]")
            lines.extend(_wrap(item.rationale, indent="      "))

    if analysis.key_evidence:
        lines.extend(["", "Key evidence (observed):"])
        for item in analysis.key_evidence:
            lines.extend(_wrap(f"- {item.observation}", indent="  ", hang="    "))
            if item.significance:
                lines.extend(_wrap(f"may indicate: {item.significance}", indent="      "))

    if analysis.false_positive_indicators:
        lines.extend(["", "Possible benign explanations (require verification):"])
        for item in analysis.false_positive_indicators:
            lines.extend(_wrap(f"- {item}", indent="  ", hang="    "))

    if analysis.investigation_steps:
        lines.extend(["", "Recommended investigation:"])
        for number, step in enumerate(analysis.investigation_steps, start=1):
            lines.extend(_wrap(f"{number}. {step}", indent="  ", hang="     "))

    if analysis.recommended_actions:
        lines.extend(["", "Recommended actions (for a human analyst - nothing is executed):"])
        for action in analysis.recommended_actions:
            lines.append(f"  [{action.priority:6}] {action.action}")
            lines.extend(_wrap(action.reason, indent="      "))

    if analysis.reasoning:
        lines.extend(["", "Reasoning:"])
        lines.extend(_wrap(analysis.reasoning))

    if audit.truncated:
        lines.extend(["", "Data the provider did NOT see:"])
        for note in audit.truncated:
            lines.extend(_wrap(f"- {note}", indent="  ", hang="    "))

    lines.extend(
        [
            "",
            "Provenance:",
            f"  provider      : {audit.provider}" + ("  (mock)" if audit.is_mock else ""),
            f"  model         : {audit.model or '-'}",
            f"  analysis id   : {audit.analysis_id}",
            f"  incident ver. : {audit.incident_version}",
            f"  prompt/schema : v{audit.prompt_version} / v{audit.schema_version}",
            f"  analyzed at   : {audit.analyzed_at or '-'}",
            f"  attempts      : {audit.attempts}",
        ]
    )
    if audit.redactions:
        redacted = ", ".join(f"{name}={count}" for name, count in sorted(audit.redactions.items()))
        lines.append(f"  redactions    : {redacted}")
    lines.append("")
    lines.append(
        "This is analyst assistance, not a verdict. The deterministic engine "
        "decided the detection;"
    )
    lines.append("a human decides the response.")
    lines.append("")
    return "\n".join(lines)


def _analyst_limits(args: argparse.Namespace) -> ContextLimits:
    """Context limits from the CLI flags (cost and privacy control)."""
    return ContextLimits(
        max_alerts=max(1, int(args.max_alerts)),
        max_timeline_entries=max(0, int(args.max_timeline)),
    )


def run_ai_analyze(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Analyze one stored incident.  Returns a process exit code."""
    stdout = stdout or sys.stdout

    store = IncidentStore(args.db)
    try:
        store.connect()
        incident = store.get(args.incident_id)
    except sqlite3.Error as exc:
        LOGGER.error("database error: %s", exc)
        store.close()
        return 1
    if incident is None:
        LOGGER.error("no such incident: %s (database: %s)", args.incident_id, store.path)
        store.close()
        return 1

    limits = _analyst_limits(args)

    if args.show_prompt:
        # Review mode: build exactly what would be sent, and send nothing.
        store.close()
        context = build_incident_context(incident, limits=limits, markers=FENCE_MARKERS)
        system_prompt, user_prompt = build_prompts(context)
        sys.stderr.write(system_prompt + "\n")
        sys.stderr.write(user_prompt + "\n")
        LOGGER.info("--show-prompt: no provider was contacted")
        return 0

    config = LLMConfig.from_env(provider=args.provider, model=args.model)
    try:
        client = LLMClient.from_config(config)
    except ProviderError as exc:
        LOGGER.error("cannot use provider %r: %s", config.provider, exc)
        if getattr(exc, "remedy", None):
            sys.stderr.write(exc.remedy + "\n")
        store.close()
        return 1

    if client.is_mock:
        LOGGER.info("using the offline mock provider; output is synthetic and labelled")

    cache = (
        NullAnalysisCache()
        if args.no_cache
        else FileAnalysisCache(args.cache_dir or default_cache_dir())
    )
    analyst = AISocAnalyst(
        client,
        AnalystConfig(limits=limits, use_cache=not args.no_cache),
        cache=cache,
    )
    analysis = analyst.analyze(incident, refresh=args.refresh)

    try:
        if analysis.ok and not args.no_save:
            attach_analysis(incident, analysis)
            store.save(incident)
    except sqlite3.Error as exc:
        LOGGER.error("cannot save the analysis onto %s: %s", incident.incident_id, exc)
    finally:
        store.close()

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(analysis.to_json(indent=2) + "\n")
        except OSError as exc:
            LOGGER.error("cannot write %s: %s", args.output, exc)
            return 1

    if args.json:
        stdout.write(analysis.to_json(indent=2) + "\n")
    else:
        stdout.write(render_analysis(analysis))

    if not analysis.ok:
        LOGGER.error("AI analysis unavailable: %s", analysis.error)
        return 1
    return 0


def run_ai_providers(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Report the AI configuration.  Never prints a key, only whether one exists."""
    stdout = stdout or sys.stdout
    config = LLMConfig.from_env()
    stdout.write("SentinelForge AI configuration\n")
    stdout.write("=" * 60 + "\n")
    for key, value in config.describe().items():
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        stdout.write(f"  {key:22} {value}\n")

    stdout.write("\nProvider status\n")
    stdout.write("-" * 60 + "\n")
    try:
        provider = LLMClient.from_config(config).provider
    except ProviderError as exc:
        stdout.write(f"  {config.provider}: unusable ({exc})\n")
        return 1
    for key, value in provider.describe().items():
        stdout.write(f"  {key:22} {value}\n")

    stdout.write(
        "\nConfigure with:\n"
        f"  export {ENV_PROVIDER}=openai\n"
        f"  export {ENV_MODEL}=<model your account can use>\n"
        "  export OPENAI_API_KEY=<key>        # never stored by SentinelForge\n"
        "\nRun offline with: sentinelforge ai analyze INC-000001 --provider mock\n"
    )
    return 0


def run_ai_cache(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Show or clear the analysis cache."""
    stdout = stdout or sys.stdout
    cache = FileAnalysisCache(args.cache_dir or default_cache_dir())
    if args.clear:
        removed = cache.clear()
        stdout.write(f"removed {removed} cached analysis file(s) from {cache.directory}\n")
        return 0
    try:
        entries = [name for name in os.listdir(cache.directory) if name.endswith(".json")]
    except OSError:
        entries = []
    stdout.write(f"cache directory: {cache.directory}\n")
    stdout.write(f"cached analyses: {len(entries)}\n")
    stdout.write(
        "\nEntries are keyed by incident id + incident version + provider + model +\n"
        "prompt version, so a changed incident is always analyzed again.\n"
    )
    return 0


def run_ai(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Dispatch the ``ai`` sub-commands."""
    command = getattr(args, "ai_command", None)
    if command == "analyze":
        return run_ai_analyze(args, stdout)
    if command == "providers":
        return run_ai_providers(args, stdout)
    if command == "cache":
        return run_ai_cache(args, stdout)
    build_parser().parse_args(["ai", "--help"])
    return 0


def run_dashboard_command(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Run the ``dashboard`` command.  Returns a process exit code.

    Demo mode deliberately points at its own database: synthetic incidents must
    never be written into, or read alongside, real telemetry.
    """
    from .dashboard.app import run_dashboard

    db_path = args.db
    if args.demo:
        from .dashboard.demo import build_demo_data, default_demo_database_path

        if db_path:
            LOGGER.warning(
                "--demo ignores --db (%s): demo data never shares a database with real "
                "telemetry",
                db_path,
            )
        db_path = default_demo_database_path()
        try:
            build_demo_data(db_path)
        except (OSError, sqlite3.Error) as exc:
            LOGGER.error("cannot prepare the demo database %s: %s", db_path, exc)
            return 1

    config = DashboardConfig(
        db_path=db_path,
        host=args.host,
        port=args.port,
        debug=args.debug,
        demo=args.demo,
        live_buffer=max(10, int(args.live_buffer)),
        events_file=args.watch_events,
        alerts_file=args.watch_alerts,
        poll_interval=max(0.2, float(args.poll_interval)),
        response_enabled=not args.no_response,
    )
    return run_dashboard(config)


# --------------------------------------------------------------------------
# Response and containment (Phase 7).  These are the only commands in
# SentinelForge that can change the host, and they are shaped so that a human
# decides: a request never executes, approval is its own command, execution is
# its own command, and --dry-run resolves without touching anything.
# --------------------------------------------------------------------------
#: Exit codes, so a script can tell a refusal apart from a crash.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_POLICY_REFUSED = 2
EXIT_PRIVILEGE_REQUIRED = 3


def _response_engine(args: argparse.Namespace) -> ResponseEngine:
    """Build an engine that talks to this host's real backends."""
    return ResponseEngine(
        db_path=getattr(args, "db", None),
        backends=ResponseBackends.detect(execution_enabled=True),
        actor=getattr(args, "actor", None),
    )


def _emit_json(payload, stream: TextIO) -> int:
    import json

    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str), file=stream)
    return EXIT_OK


def render_preview(preview: dict, policy: dict) -> str:
    """The block an analyst reads before deciding.

    Everything needed to consent, in the order the README's approval model
    lists it: what, on what, why it is allowed, what it costs, and whether it
    can be taken back.
    """
    lines = [
        "",
        "RESPONSE ACTION (preview - nothing has been done)",
        "-" * 68,
        f"Action:      {preview['action_type']}",
        f"Target:      {preview['target']}",
        f"Description: {preview['description']}",
        "",
        "Effect:",
    ]
    lines.extend(_wrap(preview["effect"], indent="  "))
    lines.extend(
        [
            "",
            f"Backend:     {preview['backend']}"
            + ("" if preview["available"] else "  [UNAVAILABLE]"),
            f"Duration:    {preview['ttl_seconds']} seconds"
            if preview.get("ttl_seconds")
            else "Duration:    until it is rolled back",
            f"Rollback:    {'available' if preview['reversible'] else 'NOT POSSIBLE'}",
            f"Privilege:   {'administrative privileges required' if preview['requires_privilege'] else 'no elevated privileges needed'}",
            f"Approval:    {'required' if policy.get('approval_required', True) else 'not required'}"
            " (a human must approve before anything runs)",
        ]
    )
    if preview.get("unavailable_reason"):
        lines.append("")
        lines.append("Unavailable:")
        lines.extend(_wrap(preview["unavailable_reason"], indent="  "))
    if preview.get("privilege_hint"):
        lines.append("")
        lines.extend(_wrap(preview["privilege_hint"], indent="  "))
    if preview.get("warnings"):
        lines.append("")
        lines.append("Warnings:")
        for warning in preview["warnings"]:
            lines.extend(_wrap(warning, indent="  - ", hang="    "))
    detail = preview.get("target_detail") or {}
    if detail:
        lines.append("")
        lines.append("Target detail (read from the system; never executed):")
        for key, value in detail.items():
            if value not in (None, "", {}, []):
                lines.append(f"  {key:20} {value}")
    lines.append("")
    lines.append(f"Policy:      {'ALLOWED' if policy.get('allowed') else 'REFUSED'}")
    lines.extend(_wrap(policy.get("reason") or "", indent="  "))
    lines.append("")
    return "\n".join(lines)


def render_action(action, audit: list | None = None) -> str:
    """The full record of one action, for ``response show``."""
    data = action.to_dict()
    lines = [
        "",
        f"{action.action_id}  {action.action_type}  ->  {action.target}",
        "-" * 68,
        f"Status:      {action.status.upper()}"
        + ("   [DRY RUN - nothing was changed]" if action.dry_run else ""),
        f"Incident:    {action.incident_id or '-'}",
        f"Requested:   {action.requested_at or '-'} by {action.requested_by}",
        f"Approved:    {action.approved_at or '-'}"
        + (f" by {action.approved_by}" if action.approved_by else " (not approved)"),
        f"Executed:    {action.started_at or '-'} -> {action.completed_at or '-'}",
        f"Verified:    {action.verified if action.verified is not None else 'not executed'}",
        f"Rollback:    {'available' if action.rollback_available else 'NOT POSSIBLE'}",
    ]
    if action.ttl_seconds:
        lines.append(f"TTL:         {action.ttl_seconds}s (expires {action.expires_at or '-'})")
    if action.reason:
        lines.append("")
        lines.append("Reason:")
        lines.extend(_wrap(action.reason, indent="  "))
    if action.verification:
        lines.append("")
        lines.append("Verification:")
        lines.extend(_wrap(action.verification, indent="  "))
    if action.error:
        lines.append("")
        lines.append("Error:")
        lines.extend(_wrap(action.error, indent="  "))
    decision = data.get("policy_decision") or {}
    if decision:
        lines.append("")
        lines.append(f"Policy:      {decision.get('code')} ({'allowed' if decision.get('allowed') else 'refused'})")
        lines.extend(_wrap(decision.get("reason") or "", indent="  "))
        for warning in decision.get("warnings") or []:
            lines.extend(_wrap(warning, indent="  ! ", hang="    "))
    detail = data.get("target_detail") or {}
    if detail:
        lines.append("")
        lines.append("Target detail (recorded before the action; never executed):")
        for key, value in detail.items():
            if value not in (None, "", {}, []):
                lines.append(f"  {key:20} {value}")
    if audit:
        lines.append("")
        lines.append("Audit trail:")
        for record in reversed(audit):
            lines.append(f"  {record['timestamp']}  {record['audit_id']}  {record['event']}")
    lines.append("")
    return "\n".join(lines)


def _next_step_hint(action) -> str:
    if action.status == ActionStatus.AWAITING_APPROVAL:
        return (
            f"Nothing has been done. To carry it out, a human must approve it first:\n"
            f"  sentinelforge response approve {action.action_id}\n"
            f"  sentinelforge response execute {action.action_id}"
        )
    if action.status == ActionStatus.APPROVED:
        return f"Approved. Run it with:\n  sentinelforge response execute {action.action_id}"
    if action.status == ActionStatus.DRY_RUN:
        return (
            "DRY RUN: no system change was made. Re-run without --dry-run to request "
            "the real action."
        )
    if action.status == ActionStatus.COMPLETED and action.rollback_available:
        return f"To undo it:\n  sentinelforge response rollback {action.action_id}"
    return ""


def run_response_request(args: argparse.Namespace, action_type: str, stdout=None) -> int:
    """Record a containment request (or resolve a dry run).  Executes nothing."""
    stream = stdout or sys.stdout
    engine = _response_engine(args)
    try:
        action = engine.request(
            action_type,
            args.target,
            incident_id=args.incident,
            reason=args.reason,
            requested_by=args.actor,
            ttl=getattr(args, "ttl", None),
            dry_run=args.dry_run,
            override_protected=getattr(args, "override_protected", False),
        )
    except ResponseValidationError as exc:
        LOGGER.error("%s: %s", exc.field, exc)
        return EXIT_ERROR
    except PolicyRefused as exc:
        if args.json:
            _emit_json(
                {"refused": True, "action": exc.action.to_dict(), "policy": exc.decision.to_dict()},
                stream,
            )
        else:
            print("", file=stream)
            print(f"REFUSED BY POLICY ({exc.decision.code})", file=stream)
            for line in _wrap(exc.decision.reason, indent="  "):
                print(line, file=stream)
            print("", file=stream)
            print(f"The refusal was recorded as {exc.action.action_id}.", file=stream)
        return EXIT_POLICY_REFUSED
    except ResponseError as exc:
        LOGGER.error("%s", exc)
        return EXIT_ERROR

    if args.json:
        return _emit_json(action.to_dict(), stream)
    if action.dry_run:
        preview = (action.result or {}).get("preview") or {}
        print(render_preview(preview, action.policy_decision or {}), file=stream)
        print("Mode:        DRY RUN", file=stream)
        print("No system change was made.", file=stream)
        print("", file=stream)
        print(f"Recorded as {action.action_id} for the audit trail.", file=stream)
        return EXIT_OK
    print(render_action(action), file=stream)
    print(_next_step_hint(action), file=stream)
    return EXIT_OK


def run_response_preview(args: argparse.Namespace, stdout=None) -> int:
    """Describe an action without recording or doing anything."""
    stream = stdout or sys.stdout
    engine = _response_engine(args)
    try:
        result = engine.preview(
            ACTION_COMMANDS[args.action],
            args.target,
            ttl=args.ttl,
            incident_id=args.incident,
        )
    except ResponseValidationError as exc:
        LOGGER.error("%s: %s", exc.field, exc)
        return EXIT_ERROR
    if args.json:
        return _emit_json(result, stream)
    print(render_preview(result["preview"], result["policy"]), file=stream)
    print("Mode:        PREVIEW - nothing was recorded and nothing was changed.", file=stream)
    if result["would_be_allowed"]:
        print("", file=stream)
        print(
            f"To request it:\n  sentinelforge response {args.action} {result['target']}",
            file=stream,
        )
    return EXIT_OK if result["would_be_allowed"] else EXIT_POLICY_REFUSED


def run_response_list(args: argparse.Namespace, stdout=None) -> int:
    stream = stdout or sys.stdout
    engine = _response_engine(args)
    engine.reconcile_expired()
    actions = engine.list_actions(
        incident_id=args.incident,
        status=args.status,
        action_type=ACTION_COMMANDS[args.action_type] if args.action_type else None,
        limit=max(1, args.limit),
    )
    if args.json:
        return _emit_json([action.to_dict() for action in actions], stream)
    if not actions:
        print("No response actions recorded.", file=stream)
        return EXIT_OK
    print(
        f"{'ACTION':13}{'TYPE':19}{'TARGET':25}{'STATUS':19}{'MODE':9}"
        f"{'INCIDENT':13}REQUESTED",
        file=stream,
    )
    for action in actions:
        print(action.summary_line(), file=stream)
    print("", file=stream)
    print(f"{len(actions)} action(s).", file=stream)
    return EXIT_OK


def run_response_show(args: argparse.Namespace, stdout=None) -> int:
    stream = stdout or sys.stdout
    engine = _response_engine(args)
    try:
        action = engine.get_action(args.action_id)
    except ResponseValidationError as exc:
        LOGGER.error("%s", exc)
        return EXIT_ERROR
    if action is None:
        LOGGER.error("no such response action: %s", args.action_id)
        return EXIT_ERROR
    audit = engine.audit_records(action_id=action.action_id)
    if args.json:
        return _emit_json({"action": action.to_dict(), "audit": audit}, stream)
    print(render_action(action, audit), file=stream)
    hint = _next_step_hint(action)
    if hint:
        print(hint, file=stream)
    return EXIT_OK


def run_response_capabilities(args: argparse.Namespace, stdout=None) -> int:
    """Report what this host can actually contain, and why not where it cannot."""
    stream = stdout or sys.stdout
    capabilities = _response_engine(args).capabilities()
    if args.json:
        return _emit_json(capabilities, stream)
    print("", file=stream)
    print("RESPONSE CAPABILITIES", file=stream)
    print("-" * 68, file=stream)
    for entry in capabilities["actions"]:
        state = "available" if entry["available"] else "UNAVAILABLE"
        print(
            f"  {entry['action_type']:18} {state:12} backend={entry['backend']:14} "
            f"rollback={'yes' if entry['reversible'] else 'no':3} "
            f"privileged={'yes' if entry['requires_privilege'] else 'no'}",
            file=stream,
        )
        if entry["reason"]:
            for line in _wrap(entry["reason"], indent="      "):
                print(line, file=stream)
        if entry["remedy"]:
            for line in _wrap(entry["remedy"], indent="      "):
                print(line, file=stream)
    print("", file=stream)
    print(f"  running as root:      {capabilities['running_as_root']}", file=stream)
    print(f"  approval required:    {capabilities['approval_required']}", file=stream)
    print(f"  automatic execution:  {capabilities['automatic_execution']}", file=stream)
    print(f"  dry run available:    {capabilities['dry_run_available']}", file=stream)
    print(f"  audit logging:        {capabilities['audit_logging']}", file=stream)
    print("", file=stream)
    return EXIT_OK


def run_response_approve(args: argparse.Namespace, stdout=None) -> int:
    stream = stdout or sys.stdout
    engine = _response_engine(args)
    try:
        action = engine.approve(args.action_id, approved_by=args.actor, reason=args.reason)
    except (ResponseError, ResponseValidationError) as exc:
        LOGGER.error("%s", exc)
        return EXIT_ERROR
    if args.json:
        return _emit_json(action.to_dict(), stream)
    print(f"{action.action_id} approved by {action.approved_by} at {action.approved_at}.", file=stream)
    print("Nothing has been executed yet.", file=stream)
    print(f"  sentinelforge response execute {action.action_id}", file=stream)
    return EXIT_OK


def run_response_execute(args: argparse.Namespace, stdout=None) -> int:
    """Execute an approved action.  The only CLI command that changes the host."""
    stream = stdout or sys.stdout
    engine = _response_engine(args)
    existing = None
    try:
        existing = engine.get_action(args.action_id)
    except ResponseValidationError as exc:
        LOGGER.error("%s", exc)
        return EXIT_ERROR
    if existing is None:
        LOGGER.error("no such response action: %s", args.action_id)
        return EXIT_ERROR

    if not args.yes and sys.stdin.isatty():
        print(render_action(existing), file=stream)
        answer = input(
            f"Execute {existing.action_id} ({existing.action_type} -> {existing.target})? "
            "Type 'yes' to proceed: "
        )
        if answer.strip().lower() != "yes":
            print("Not executed.", file=stream)
            return EXIT_OK

    try:
        action = engine.execute(args.action_id, executed_by=args.actor)
    except ApprovalRequired as exc:
        LOGGER.error("%s", exc)
        return EXIT_ERROR
    except PrivilegeRequired as exc:
        print("", file=stream)
        for line in _wrap(str(exc), indent="  "):
            print(line, file=stream)
        print("", file=stream)
        return EXIT_PRIVILEGE_REQUIRED
    except (ResponseError, ResponseValidationError) as exc:
        LOGGER.error("%s", exc)
        return EXIT_ERROR

    if args.json:
        return _emit_json(action.to_dict(), stream)
    print(render_action(action), file=stream)
    hint = _next_step_hint(action)
    if hint:
        print(hint, file=stream)
    return EXIT_OK if action.status == ActionStatus.COMPLETED else EXIT_ERROR


def run_response_decision(args: argparse.Namespace, command: str, stdout=None) -> int:
    """``reject``, ``cancel`` and ``rollback`` -- they share a shape."""
    stream = stdout or sys.stdout
    engine = _response_engine(args)
    method = {"reject": engine.reject, "cancel": engine.cancel, "rollback": engine.rollback}[command]
    try:
        action = method(args.action_id, args.actor, args.reason)
    except PrivilegeRequired as exc:
        print("", file=stream)
        for line in _wrap(str(exc), indent="  "):
            print(line, file=stream)
        return EXIT_PRIVILEGE_REQUIRED
    except (ResponseError, ResponseValidationError) as exc:
        LOGGER.error("%s", exc)
        return EXIT_ERROR
    if args.json:
        return _emit_json(action.to_dict(), stream)
    print(f"{action.action_id} is now {action.status.upper()}.", file=stream)
    if action.verification:
        for line in _wrap(action.verification, indent="  "):
            print(line, file=stream)
    return EXIT_OK


def run_response_audit(args: argparse.Namespace, stdout=None) -> int:
    """Read the append-only audit trail, optionally re-checking its hash chain."""
    stream = stdout or sys.stdout
    engine = _response_engine(args)
    if args.verify:
        result = engine.verify_audit()
        if args.json:
            return _emit_json(result, stream)
        print(
            f"Audit chain: {'OK' if result['ok'] else 'BROKEN'} "
            f"({result['checked']} record(s) checked)",
            file=stream,
        )
        print(f"  {result['detail']}", file=stream)
        return EXIT_OK if result["ok"] else EXIT_ERROR

    records = engine.audit_records(
        action_id=args.action_id, incident_id=args.incident, limit=max(1, args.limit)
    )
    if args.json:
        return _emit_json(records, stream)
    if not records:
        print("No audit records.", file=stream)
        return EXIT_OK
    print(
        f"{'TIMESTAMP':21}{'AUDIT':14}{'EVENT':19}{'ACTION':15}{'TYPE':19}"
        f"{'TARGET':25}{'MODE':9}WHO",
        file=stream,
    )
    for record in records:
        mode = "DRY-RUN" if record["dry_run"] else "REAL"
        who = record["approved_by"] or record["requested_by"] or "-"
        print(
            f"{record['timestamp']:21}{record['audit_id']:14}{record['event']:19}"
            f"{(record['action_id'] or '-'):15}{(record['action_type'] or '-'):19}"
            f"{(record['target'] or '-'):25.24}{mode:9}{who}",
            file=stream,
        )
    print("", file=stream)
    print(f"{len(records)} audit record(s). The trail is append-only.", file=stream)
    return EXIT_OK


def run_response(args: argparse.Namespace, stdout: TextIO | None = None) -> int:
    """Dispatch the ``response`` sub-commands."""
    command = getattr(args, "response_command", None)
    if command in ACTION_COMMANDS:
        return run_response_request(args, ACTION_COMMANDS[command], stdout)
    if command == "preview":
        return run_response_preview(args, stdout)
    if command == "list":
        return run_response_list(args, stdout)
    if command == "show":
        return run_response_show(args, stdout)
    if command == "capabilities":
        return run_response_capabilities(args, stdout)
    if command == "approve":
        return run_response_approve(args, stdout)
    if command == "execute":
        return run_response_execute(args, stdout)
    if command in ("reject", "cancel", "rollback"):
        return run_response_decision(args, command, stdout)
    if command == "audit":
        return run_response_audit(args, stdout)
    build_parser().parse_args(["response", "--help"])
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    # Restore default SIGPIPE behaviour so `... | head` does not traceback.
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except (AttributeError, ValueError):  # pragma: no cover - non-POSIX or non-main thread
        pass

    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose, args.quiet)

    if args.command == "collect":
        return run_collect(args)
    if args.command == "sources":
        return run_sources(args)
    if args.command == "detect":
        return run_detect(args)
    if args.command == "rules":
        return run_rules(args)
    if args.command == "correlate":
        return run_correlate(args)
    if args.command == "incident":
        return run_incident(args)
    if args.command == "incidents":
        return run_incidents(args)
    if args.command == "sensor":
        return run_sensor(args)
    if args.command == "ai":
        return run_ai(args)
    if args.command == "dashboard":
        return run_dashboard_command(args)
    if args.command == "response":
        return run_response(args)
    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
