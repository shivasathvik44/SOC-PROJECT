"""Scenario: outbound port scanning (Phase 8).

The eBPF network sensor traces ``connect()`` from *this* host, so ``PORT_SCAN``
detects this machine scanning something else -- the shape of a compromised host
enumerating its neighbours, not of an inbound scan.  (Inbound scanning needs
accept/drop telemetry, which SentinelForge does not collect; the gap is
recorded in ``FUTURE_CHAINS``.)

No packet is sent.  The scenario emits the connection *records* the sensor
would have produced.
"""

from __future__ import annotations

from datetime import datetime

from ..scenario import (
    Expectation,
    INTERNAL_IP,
    SCAN_TARGET_IP,
    Scenario,
    ScenarioKind,
    network_connection,
)

SCANNER_PID = 6000
SCANNER = "nmap"

#: Twelve distinct ports, two above the rule's threshold of ten, all inside its
#: sixty-second window.
SCANNED_PORTS = (21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 5432, 8080)
INTERVAL_SECONDS = 2


def build(base: datetime) -> list:
    return [
        network_connection(
            index * INTERVAL_SECONDS,
            base,
            process=SCANNER,
            pid=SCANNER_PID,
            destination_ip=SCAN_TARGET_IP,
            destination_port=port,
            user="root",
            source_ip=INTERNAL_IP,
            source_port=40000 + index,
        )
        for index, port in enumerate(SCANNED_PORTS)
    ]


SCENARIO = Scenario(
    scenario_id="port-scan",
    name="Outbound Port Scan",
    description=(
        f"'{SCANNER}' (pid {SCANNER_PID}) contacts {len(SCANNED_PORTS)} distinct ports on "
        f"{SCAN_TARGET_IP} in {(len(SCANNED_PORTS) - 1) * INTERVAL_SECONDS} seconds."
    ),
    kind=ScenarioKind.ATTACK,
    mitre_techniques=("T1046",),
    build=build,
    tags=("discovery", "ebpf", "network"),
    # The right containment here is the scanning process, not the address: the
    # source of these connections is this host itself.
    containment_target=("kill_process", str(SCANNER_PID)),
    expected=Expectation(
        events=len(SCANNED_PORTS),
        alerts=1,
        incidents=1,
        rule_ids=frozenset({"PORT_SCAN"}),
        # nmap is not an interpreter, so the reverse-shell rule must stay quiet:
        # the signal there is which process dialled out, not how many ports.
        forbidden_rule_ids=frozenset(
            {"SUSPICIOUS_NETWORK_CONNECTION", "SUSPICIOUS_PROCESS_EXECUTION"}
        ),
        severity="medium",
        risk_range=(45, 55),
        techniques=frozenset({"T1046"}),
        source_ips=frozenset({INTERNAL_IP}),
        # Deliberately empty, and a finding rather than a preference: the
        # connection events carry user='root', but PORT_SCAN's Detection does
        # not set a user the way SUSPICIOUS_NETWORK_CONNECTION does, so the
        # attribution is lost between the event and the incident. Pinning the
        # gap here keeps it in the report instead of quietly tolerating it.
        users=frozenset(),
        response_options=frozenset({"block_ip", "kill_process"}),
        process_tree_pids=frozenset({SCANNER_PID}),
        process_tree_missing_pids=frozenset(),
        network_destinations=frozenset(
            {f"{SCAN_TARGET_IP}:{port}" for port in SCANNED_PORTS}
        ),
        notes=(
            "The 'source address' on this incident is this host's own, because "
            "the sensor traces outbound connections. Blocking it would be the "
            "wrong response; terminating the scanning process is the right one. "
            "KNOWN GAP: the incident records no user even though the telemetry "
            "names one - PORT_SCAN does not populate Detection.user."
        ),
    ),
)
