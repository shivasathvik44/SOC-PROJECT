"""Tests for message classification and record normalization."""

import json

import pytest

from sentinelforge.models.event import EventType, SecurityEvent, Severity
from sentinelforge.models.record import RawRecord
from sentinelforge.pipeline.normalize import classify, normalize, normalize_all


# --------------------------------------------------------------------------
# authentication failure
# --------------------------------------------------------------------------
def test_failed_password_is_authentication_failure():
    result = classify("Failed password for root from 192.168.1.50 port 22 ssh2")
    assert result["event_type"] == EventType.AUTHENTICATION_FAILURE
    assert result["user"] == "root"
    assert result["src_ip"] == "192.168.1.50"
    assert result["process"] == "sshd"
    assert result["severity"] == Severity.MEDIUM


def test_failed_password_invalid_user_is_higher_severity():
    result = classify("Failed password for invalid user admin from 203.0.113.7 port 41122 ssh2")
    assert result["event_type"] == EventType.AUTHENTICATION_FAILURE
    assert result["user"] == "admin"
    assert result["src_ip"] == "203.0.113.7"
    assert result["severity"] == Severity.HIGH


def test_pam_authentication_failure_extracts_rhost_and_user():
    message = (
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
        "tty=ssh ruser= rhost=10.0.0.9  user=root"
    )
    result = classify(message)
    assert result["event_type"] == EventType.AUTHENTICATION_FAILURE
    assert result["user"] == "root"
    assert result["src_ip"] == "10.0.0.9"


def test_invalid_user_message():
    result = classify("Invalid user oracle from 198.51.100.22 port 5000")
    assert result["event_type"] == EventType.AUTHENTICATION_FAILURE
    assert result["user"] == "oracle"
    assert result["src_ip"] == "198.51.100.22"


# --------------------------------------------------------------------------
# authentication success
# --------------------------------------------------------------------------
def test_accepted_password_is_authentication_success():
    result = classify("Accepted password for capslock from 192.168.1.50 port 55622 ssh2")
    assert result["event_type"] == EventType.AUTHENTICATION_SUCCESS
    assert result["user"] == "capslock"
    assert result["src_ip"] == "192.168.1.50"
    assert result["severity"] == Severity.LOW


def test_accepted_publickey_is_authentication_success():
    result = classify("Accepted publickey for capslock from 10.1.2.3 port 40000 ssh2: RSA SHA256:x")
    assert result["event_type"] == EventType.AUTHENTICATION_SUCCESS
    assert result["user"] == "capslock"
    assert result["src_ip"] == "10.1.2.3"


# --------------------------------------------------------------------------
# sudo
# --------------------------------------------------------------------------
def test_sudo_command_line_is_parsed():
    message = "capslock : TTY=pts/0 ; PWD=/home/capslock ; USER=root ; COMMAND=/usr/bin/dnf update"
    result = classify(message)
    assert result["event_type"] == EventType.SUDO
    assert result["user"] == "capslock"
    assert result["process"] == "sudo"


def test_sudo_not_in_sudoers_is_high_severity():
    result = classify("mallory : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root")
    assert result["event_type"] == EventType.SUDO
    assert result["user"] == "mallory"
    assert result["severity"] == Severity.HIGH


# --------------------------------------------------------------------------
# sessions, ssh connections, process start
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "message,expected_type,expected_user",
    [
        (
            "pam_unix(sshd:session): session opened for user capslock(uid=1000) by (uid=0)",
            EventType.SESSION_OPEN,
            "capslock",
        ),
        (
            "pam_unix(sshd:session): session closed for user capslock",
            EventType.SESSION_CLOSE,
            "capslock",
        ),
    ],
)
def test_session_events(message, expected_type, expected_user):
    result = classify(message)
    assert result["event_type"] == expected_type
    assert result["user"] == expected_user


def test_ssh_connection_event():
    result = classify("Connection closed by 198.51.100.4 port 51234 [preauth]")
    assert result["event_type"] == EventType.SSH_CONNECTION
    assert result["src_ip"] == "198.51.100.4"


def test_process_start_event():
    result = classify("Started Session 42 of User capslock.")
    assert result["event_type"] == EventType.PROCESS_START
    assert result["process"] == "systemd"


# --------------------------------------------------------------------------
# unknown / malformed input
# --------------------------------------------------------------------------
@pytest.mark.parametrize("message", ["", "   ", None, 12345, "kernel: usb 1-2: new device"])
def test_unclassifiable_input_becomes_unknown(message):
    result = classify(message)
    assert result["event_type"] == EventType.UNKNOWN
    assert result["severity"] == Severity.INFO


def test_classify_never_raises_on_weird_input():
    weird = "\x00\x01 Failed password for ☃ from not-an-ip " + "A" * 5000
    result = classify(weird)
    assert result["event_type"] in EventType.ALL


def test_log_content_is_never_executed():
    """Command-looking log content must be treated as inert text."""
    message = "capslock : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/rm -rf / ; $(whoami)"
    event = normalize(RawRecord(message=message, source="test"))
    assert event.event_type == EventType.SUDO
    # The text survives verbatim; nothing is expanded or evaluated.
    assert "$(whoami)" in event.message
    assert "$(whoami)" in json.loads(event.to_json())["message"]


# --------------------------------------------------------------------------
# false positives seen on a real Fedora journal (regression tests)
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "message",
    [
        "Cannot change IRQ 175 affinity: Permission denied",
        ">>> Curl error (35): SSL connect error for https://mirrors.fedoraproject.org/",
        "Connection reset by peer",
        "curl: (56) Recv failure: Connection reset by peer",
        "the client disconnected from the bus",
        "Reached target initrd-usr-fs.target - Initrd /usr File System.",
    ],
)
def test_ordinary_system_noise_stays_unknown(message):
    assert classify(message)["event_type"] == EventType.UNKNOWN


def test_sudo_session_is_classified_as_sudo_not_session():
    result = classify("pam_unix(sudo:session): session opened for user root(uid=0) by capslock(uid=1000)")
    assert result["event_type"] == EventType.SUDO
    assert result["user"] == "root"


def test_ssh_connection_requires_an_address():
    assert classify("Connection closed by 10.0.0.5 port 22")["event_type"] == EventType.SSH_CONNECTION
    assert classify("Connection closed by peer")["event_type"] == EventType.UNKNOWN


# --------------------------------------------------------------------------
# normalization
# --------------------------------------------------------------------------
def test_normalize_builds_full_event():
    record = RawRecord(
        message="Failed password for root from 192.168.1.50 port 22 ssh2",
        raw="Sep 12 10:30:00 fedora sshd[1]: Failed password for root from 192.168.1.50 port 22 ssh2",
        source="systemd-journal",
        host="fedora",
        process="sshd",
        timestamp="2026-09-12T10:30:00Z",
    )
    event = normalize(record)
    assert isinstance(event, SecurityEvent)
    assert event.to_dict() == {
        "timestamp": "2026-09-12T10:30:00Z",
        "host": "fedora",
        "source": "systemd-journal",
        "event_type": "authentication_failure",
        "severity": "medium",
        "user": "root",
        "src_ip": "192.168.1.50",
        "process": "sshd",
        "message": "Failed password for root from 192.168.1.50 port 22 ssh2",
        "raw": record.raw,
    }


def test_normalize_preserves_original_message_as_raw():
    record = RawRecord(message="something odd", source="test")
    event = normalize(record)
    assert event.raw == "something odd"
    assert event.event_type == EventType.UNKNOWN


def test_normalize_uses_host_default_when_source_has_no_host():
    event = normalize(RawRecord(message="hi", source="test"), host_default="fedora")
    assert event.host == "fedora"


def test_normalize_all_skips_bad_records_without_crashing():
    records = [
        RawRecord(message="Accepted password for capslock from 10.0.0.1 port 1 ssh2"),
        object(),  # not a record at all
        RawRecord(message="Failed password for root from 10.0.0.2 port 1 ssh2"),
    ]
    errors = []
    events = list(normalize_all(records, on_error=lambda exc, rec: errors.append(exc)))
    assert [e.event_type for e in events] == [
        EventType.AUTHENTICATION_SUCCESS,
        EventType.AUTHENTICATION_FAILURE,
    ]
    assert len(errors) == 1
