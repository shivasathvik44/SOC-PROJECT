"""Tests for the eBPF network sensor (synthetic records only, no kernel)."""

import socket
from types import SimpleNamespace

import pytest

from sentinelforge.models.event import EventType
from sentinelforge.sensors.base import SensorUnavailableError
from sentinelforge.sensors.ebpf import loader
from sentinelforge.sensors.ebpf.network import (
    AF_INET,
    AF_INET6,
    BPF_PROGRAM,
    EbpfNetworkSensor,
    decode_network_event,
    format_ipv4,
    format_ipv6,
    synthetic_record,
)


class TestBpfProgram:
    def test_no_kernel_struct_headers_are_required(self):
        """net/sock.h does not compile on current Fedora kernels; avoid it."""
        assert "#include <net/sock.h>" not in BPF_PROGRAM
        assert "inet_sock_set_state" in BPF_PROGRAM

    def test_only_outbound_connection_attempts_are_reported(self):
        assert "TCP_CLOSE" in BPF_PROGRAM
        assert "TCP_SYN_SENT" in BPF_PROGRAM
        assert "IPPROTO_TCP" in BPF_PROGRAM

    def test_no_payload_capture(self):
        """Connection metadata only: never packet contents."""
        for forbidden in (
            "bpf_skb_load_bytes",
            "bpf_probe_write_user",
            "bpf_skb_store_bytes",
            "__sk_buff",
            "payload",
        ):
            assert forbidden not in BPF_PROGRAM

    def test_kernel_side_filters_exist(self):
        assert "SELF_PID" in BPF_PROGRAM
        assert "FILTER_UID" in BPF_PROGRAM
        assert "-DFILTER_UID=0" in EbpfNetworkSensor(uid=0).cflags()


class TestAddressFormatting:
    def test_ipv4_bytes(self):
        assert format_ipv4(socket.inet_aton("192.168.1.50")) == "192.168.1.50"

    def test_ipv6_bytes(self):
        packed = socket.inet_pton(socket.AF_INET6, "2001:db8::9")
        assert format_ipv6(packed) == "2001:db8::9"

    def test_ctypes_style_byte_arrays(self):
        assert format_ipv4([192, 168, 1, 50]) == "192.168.1.50"

    @pytest.mark.parametrize("value", [None, b"", b"\x01\x02", "nonsense", object()])
    def test_unusable_values_return_none(self, value):
        assert format_ipv4(value) is None
        assert format_ipv6(value) is None


class TestDecoder:
    def test_decodes_an_ipv4_connection(self):
        event = decode_network_event(synthetic_record(), host="fedora")

        assert event.event_type == EventType.NETWORK_CONNECTION
        assert event.source == "ebpf"
        assert event.process == "curl"
        assert event.dst_ip == "198.51.100.9"
        assert event.dst_port == 443
        assert event.protocol == "tcp"
        assert event.src_ip == "192.168.1.20"
        assert event.metadata["source_port"] == 51234
        assert event.metadata["direction"] == "outbound"
        assert event.pid == 4101

    def test_ip_version_follows_the_address_family(self):
        record = synthetic_record(
            family=AF_INET6,
            daddr=socket.inet_pton(socket.AF_INET6, "2001:db8::9"),
            saddr=socket.inet_pton(socket.AF_INET6, "fe80::1"),
        )
        event = decode_network_event(record)
        assert event.dst_ip == "2001:db8::9"
        assert event.metadata["ip_version"] == 6

    def test_missing_fields_become_none(self):
        event = decode_network_event(SimpleNamespace(family=AF_INET, comm=b"sh\x00"))
        assert event.process == "sh"
        assert event.dst_ip is None
        assert event.dst_port is None
        assert "destination_ip" not in event.metadata

    def test_empty_record_does_not_raise(self):
        event = decode_network_event(SimpleNamespace())
        assert event.event_type == EventType.NETWORK_CONNECTION
        assert event.to_json()

    def test_malformed_address_bytes_are_tolerated(self):
        event = decode_network_event(synthetic_record(daddr=b"\x01\x02"))
        assert event.dst_ip is None
        assert "an unknown address" in event.message

    def test_no_payload_field_is_ever_produced(self):
        event = decode_network_event(synthetic_record())
        assert set(event.metadata) <= {
            "pid",
            "uid",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "protocol",
            "ip_version",
            "direction",
            "process_name",
        }

    def test_user_lookup_is_optional(self):
        assert decode_network_event(synthetic_record()).user is None
        assert (
            decode_network_event(synthetic_record(), user_lookup=lambda uid: "capslock").user
            == "capslock"
        )

    def test_dst_port_is_readable_through_the_event_model(self):
        """This is the field the PORT_SCAN rule waited for since Phase 2."""
        event = decode_network_event(synthetic_record())
        assert getattr(event, "dst_port") == 443


class TestSensorLifecycle:
    def test_unavailable_ebpf_raises_with_a_remedy(self, monkeypatch):
        monkeypatch.setattr(
            "sentinelforge.sensors.ebpf.network.check_ebpf_support",
            lambda: loader.EbpfSupport(
                supported=False, reasons=["no privileges"], remedy="use sudo"
            ),
        )
        with pytest.raises(SensorUnavailableError) as exc:
            EbpfNetworkSensor().start()
        assert exc.value.remedy == "use sudo"

    def test_malformed_kernel_record_is_skipped(self, caplog):
        class Boom:
            def event(self, data):
                raise ValueError("truncated")

        sensor = EbpfNetworkSensor()
        sensor._bpf = {"connect_events": Boom()}
        sensor._handle_event(0, b"", 0)  # must not raise
        assert sensor.events_seen == 0
        assert "unreadable connect record" in caplog.text

    def test_dropped_events_are_counted(self):
        sensor = EbpfNetworkSensor()
        sensor._handle_lost(3)
        assert sensor.events_dropped == 3

    def test_stop_is_idempotent(self):
        sensor = EbpfNetworkSensor()
        sensor.stop()
        sensor.stop()
        assert sensor.running is False
