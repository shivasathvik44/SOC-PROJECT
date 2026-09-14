"""Tests for the journal and file collectors.

None of these tests read the real system logs: the journal collector is driven
by a stub ``journalctl`` script and the file collector by temporary files.
"""

import json
import logging
import os
import stat
import subprocess

import pytest

from sentinelforge.cli import build_parser, run_collect, run_sources
from sentinelforge.collector.file import (
    DEFAULT_LOG_PATHS,
    FileCollector,
    FilesCollector,
    detect_log_files,
    parse_syslog_line,
    unreadable_log_files,
)
from sentinelforge.collector.journal import JournalCollector, _decode_message
from sentinelforge.models.event import EventType

SAMPLE_LINES = [
    "Sep 12 10:30:00 fedora sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2",
    "Sep 12 10:30:05 fedora sshd[1235]: Accepted password for capslock from 192.168.1.50 port 55622 ssh2",
    "Sep 12 10:30:10 fedora sudo[1300]: capslock : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/dnf",
    "this line is not syslog formatted at all",
    "",
]


def _write_stub_journalctl(tmp_path, body: str) -> str:
    """Create an executable stub that stands in for the real journalctl."""
    script = tmp_path / "journalctl"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(script)


# --------------------------------------------------------------------------
# journal collector
# --------------------------------------------------------------------------
def test_journal_command_is_argv_and_uses_json_output():
    collector = JournalCollector(since="today", limit=50, unit="sshd.service", identifier="sshd")
    cmd = collector.build_command()
    assert isinstance(cmd, list)  # never a shell string
    assert "--output=json" in cmd
    assert cmd[cmd.index("-n") + 1] == "50"
    assert cmd[cmd.index("--since") + 1] == "today"
    assert cmd[cmd.index("-u") + 1] == "sshd.service"
    assert "-f" not in cmd


def test_journal_command_adds_follow_flag():
    assert "-f" in JournalCollector(follow=True).build_command()


def test_journal_collect_parses_json_entries(tmp_path):
    entries = [
        {
            "__REALTIME_TIMESTAMP": "1789561800000000",
            "_HOSTNAME": "fedora",
            "SYSLOG_IDENTIFIER": "sshd",
            "MESSAGE": "Failed password for root from 192.168.1.50 port 22 ssh2",
        },
        {
            "__REALTIME_TIMESTAMP": "1789561805000000",
            "_HOSTNAME": "fedora",
            "SYSLOG_IDENTIFIER": "sudo",
            "MESSAGE": "capslock : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/dnf",
        },
    ]
    body = "".join(f"echo '{json.dumps(e)}'\n" for e in entries)
    path = _write_stub_journalctl(tmp_path, body)

    records = list(JournalCollector(journalctl_path=path).collect())
    assert len(records) == 2
    assert records[0].host == "fedora"
    assert records[0].process == "sshd"
    assert records[0].source == "systemd-journal"
    assert records[0].timestamp.endswith("Z")
    assert "Failed password" in records[0].message
    # By default ``raw`` holds the original log line, not the journal metadata.
    assert records[0].raw == records[0].message


def test_journal_raw_full_keeps_the_whole_entry(tmp_path):
    entry = {"MESSAGE": "Failed password for root from 10.0.0.1 port 22 ssh2", "_HOSTNAME": "fedora"}
    path = _write_stub_journalctl(tmp_path, f"echo '{json.dumps(entry)}'\n")

    records = list(JournalCollector(journalctl_path=path, raw_full=True).collect())
    assert json.loads(records[0].raw)["MESSAGE"] == records[0].message


def test_journal_prefers_syslog_raw_when_present(tmp_path):
    entry = {
        "MESSAGE": "Failed password for root from 10.0.0.1 port 22 ssh2",
        "SYSLOG_RAW": "<38>Sep 12 10:30:00 sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2",
    }
    path = _write_stub_journalctl(tmp_path, f"echo '{json.dumps(entry)}'\n")

    records = list(JournalCollector(journalctl_path=path).collect())
    assert records[0].raw.startswith("<38>Sep 12")


def test_journal_collect_skips_malformed_json_lines(tmp_path, caplog):
    good = json.dumps({"MESSAGE": "Accepted password for capslock from 10.0.0.1 port 1 ssh2"})
    body = f"echo 'not json at all'\necho '{good}'\necho '[1,2,3]'\necho '{{}}'\n"
    path = _write_stub_journalctl(tmp_path, body)

    records = list(JournalCollector(journalctl_path=path).collect())
    # Only the one valid entry with a MESSAGE survives; nothing raises.
    assert len(records) == 1
    assert "Accepted password" in records[0].message


def test_journal_collect_handles_journalctl_failure(tmp_path, caplog):
    path = _write_stub_journalctl(
        tmp_path, "echo 'Failed to open journal: Permission denied' >&2\nexit 1\n"
    )
    records = list(JournalCollector(journalctl_path=path).collect())
    assert records == []
    assert "Permission denied" in caplog.text


def test_journal_collect_handles_missing_binary(tmp_path, caplog):
    collector = JournalCollector(journalctl_path=str(tmp_path / "does-not-exist"))
    assert list(collector.collect()) == []
    assert "journalctl not found" in caplog.text


def test_journal_collect_handles_permission_error_on_exec(monkeypatch, caplog):
    def boom(*args, **kwargs):
        raise PermissionError("no exec for you")

    monkeypatch.setattr(subprocess, "Popen", boom)
    assert list(JournalCollector().collect()) == []
    assert "cannot execute journalctl" in caplog.text


def test_journal_decodes_byte_array_messages():
    # journalctl encodes non-UTF-8 messages as an array of byte values.
    assert _decode_message([104, 105]) == "hi"
    assert _decode_message(None) == ""


def test_journal_availability_is_a_lookup(monkeypatch):
    monkeypatch.setattr("sentinelforge.collector.journal.shutil.which", lambda name: None)
    assert JournalCollector.available() is False
    monkeypatch.setattr("sentinelforge.collector.journal.shutil.which", lambda name: "/usr/bin/journalctl")
    assert JournalCollector.available() is True


# --------------------------------------------------------------------------
# syslog line parsing
# --------------------------------------------------------------------------
def test_parse_bsd_syslog_line():
    record = parse_syslog_line(SAMPLE_LINES[0], source="/var/log/secure")
    assert record.host == "fedora"
    assert record.process == "sshd"
    assert record.message == "Failed password for root from 192.168.1.50 port 22 ssh2"
    assert record.timestamp.endswith("Z")
    assert record.raw == SAMPLE_LINES[0]


def test_parse_rfc3339_syslog_line():
    line = "2026-09-12T10:30:00.123456+00:00 fedora sshd[1234]: Accepted password for capslock from 10.0.0.5 port 22 ssh2"
    record = parse_syslog_line(line)
    assert record.timestamp == "2026-09-12T10:30:00Z"
    assert record.process == "sshd"


def test_parse_unstructured_line_keeps_everything():
    record = parse_syslog_line("this line is not syslog formatted at all")
    assert record.message == "this line is not syslog formatted at all"
    assert record.host is None
    assert record.process is None
    assert record.timestamp is None


def test_parse_malformed_lines_do_not_raise():
    for line in ["", "   ", "\x00\x00", "Sep 99 99:99:99 host proc: msg", 12345]:
        record = parse_syslog_line(line)
        assert record.raw is not None


# --------------------------------------------------------------------------
# source detection
# --------------------------------------------------------------------------
def test_detect_log_files_finds_only_existing_readable_files(tmp_path):
    present = tmp_path / "secure"
    present.write_text(SAMPLE_LINES[0] + "\n")
    missing = tmp_path / "auth.log"

    found = detect_log_files([str(present), str(missing)])
    assert found == [str(present)]


def test_detect_log_files_skips_unreadable_file(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    secret = tmp_path / "secure"
    secret.write_text("nope\n")
    secret.chmod(0o000)
    try:
        found = detect_log_files([str(secret)])
    finally:
        secret.chmod(0o600)
    if os.geteuid() == 0:
        pytest.skip("root can read everything")
    assert found == []
    assert "not readable" in caplog.text


def test_unreadable_log_files_reports_permission_blocked_paths(tmp_path):
    secret = tmp_path / "secure"
    secret.write_text("nope\n")
    secret.chmod(0o000)
    try:
        if os.geteuid() == 0:
            pytest.skip("root can read everything")
        assert unreadable_log_files([str(secret)]) == [str(secret)]
        assert unreadable_log_files([str(tmp_path / "absent")]) == []
    finally:
        secret.chmod(0o600)


def test_default_log_paths_cover_fedora_and_debian():
    assert "/var/log/secure" in DEFAULT_LOG_PATHS
    assert "/var/log/auth.log" in DEFAULT_LOG_PATHS


# --------------------------------------------------------------------------
# file collector
# --------------------------------------------------------------------------
def test_file_collector_reads_lines(tmp_path):
    log = tmp_path / "secure"
    log.write_text("\n".join(SAMPLE_LINES) + "\n")

    records = list(FileCollector(str(log)).collect())
    # Blank lines are dropped; the unstructured line is kept.
    assert len(records) == 4
    assert records[0].source == str(log)
    assert records[-1].message == "this line is not syslog formatted at all"


def test_file_collector_limit_returns_last_lines(tmp_path):
    log = tmp_path / "secure"
    log.write_text("\n".join(SAMPLE_LINES) + "\n")

    records = list(FileCollector(str(log), limit=2).collect())
    assert len(records) == 2
    assert records[-1].message == "this line is not syslog formatted at all"


def test_file_collector_follow_reads_appended_lines(tmp_path):
    """Follow mode keeps yielding after the existing content is consumed."""
    log = tmp_path / "secure"
    log.write_text(SAMPLE_LINES[0] + "\n")

    collector = FileCollector(str(log), follow=True, poll_interval=0.01)
    stream = collector.collect()

    first = next(stream)
    assert "Failed password" in first.message

    with open(log, "a") as handle:
        handle.write(SAMPLE_LINES[1] + "\n")
        handle.flush()

    second = next(stream)
    assert "Accepted password" in second.message
    stream.close()


def test_file_collector_handles_missing_file(tmp_path, caplog):
    records = list(FileCollector(str(tmp_path / "nope.log")).collect())
    assert records == []
    assert "disappeared" in caplog.text


def test_file_collector_handles_permission_denied(tmp_path, caplog):
    log = tmp_path / "secure"
    log.write_text("Sep 12 10:30:00 fedora sshd[1]: Failed password for root from 10.0.0.1\n")
    log.chmod(0o000)
    try:
        records = list(FileCollector(str(log)).collect())
    finally:
        log.chmod(0o600)
    if os.geteuid() == 0:
        pytest.skip("root can read everything")
    assert records == []
    assert "permission denied" in caplog.text.lower()


def test_files_collector_reads_every_detected_file(tmp_path):
    first = tmp_path / "secure"
    second = tmp_path / "auth.log"
    first.write_text(SAMPLE_LINES[0] + "\n")
    second.write_text(SAMPLE_LINES[1] + "\n")

    records = list(FilesCollector(paths=[str(first), str(second)]).collect())
    assert len(records) == 2
    assert {r.source for r in records} == {str(first), str(second)}


def test_files_collector_without_sources_warns_and_yields_nothing(caplog):
    assert list(FilesCollector(paths=[]).collect()) == []
    assert "no readable auth log files" in caplog.text


# --------------------------------------------------------------------------
# CLI wiring (still no real system logs involved)
# --------------------------------------------------------------------------
def test_cli_collect_writes_jsonl(tmp_path, capsys):
    log = tmp_path / "secure"
    log.write_text("\n".join(SAMPLE_LINES) + "\n")
    out = tmp_path / "events.jsonl"

    args = build_parser().parse_args(
        ["collect", "--source", "files", "--file", str(log), "--output", str(out)]
    )
    assert run_collect(args) == 0

    lines = out.read_text().strip().splitlines()
    assert len(lines) == 4
    events = [json.loads(line) for line in lines]
    assert events[0]["event_type"] == EventType.AUTHENTICATION_FAILURE
    assert events[0]["src_ip"] == "192.168.1.50"
    assert events[1]["event_type"] == EventType.AUTHENTICATION_SUCCESS
    assert events[2]["event_type"] == EventType.SUDO
    assert events[3]["event_type"] == EventType.UNKNOWN


def test_cli_collect_filters_by_event_type(tmp_path):
    log = tmp_path / "secure"
    log.write_text("\n".join(SAMPLE_LINES) + "\n")
    out = tmp_path / "events.jsonl"

    args = build_parser().parse_args(
        [
            "collect",
            "--source", "files",
            "--file", str(log),
            "--event-type", "authentication_failure",
            "--output", str(out),
        ]
    )
    assert run_collect(args) == 0
    events = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(events) == 1
    assert events[0]["user"] == "root"


def test_cli_collect_returns_error_without_sources(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr("sentinelforge.cli.JournalCollector.available", classmethod(lambda cls: False))
    monkeypatch.setattr("sentinelforge.cli.detect_log_files", lambda *a, **kw: [])
    args = build_parser().parse_args(["collect", "--source", "all"])
    assert run_collect(args) == 1
    assert "no usable log sources" in caplog.text


def test_cli_sources_reports_availability(capsys, monkeypatch):
    monkeypatch.setattr("sentinelforge.cli.JournalCollector.available", classmethod(lambda cls: True))
    monkeypatch.setattr("sentinelforge.cli.detect_log_files", lambda *a, **kw: ["/var/log/secure"])
    assert run_sources(build_parser().parse_args(["sources"])) == 0
    captured = capsys.readouterr().out
    assert "available" in captured
    assert "/var/log/secure" in captured
