"""eBPF sensors (Phase 4)."""

from .loader import BootClock, EbpfSupport, check_ebpf_support, load_bpf, privilege_remedy
from .network import EbpfNetworkSensor, decode_network_event
from .process import EbpfProcessSensor, decode_process_event

__all__ = [
    "BootClock",
    "EbpfNetworkSensor",
    "EbpfProcessSensor",
    "EbpfSupport",
    "check_ebpf_support",
    "decode_network_event",
    "decode_process_event",
    "load_bpf",
    "privilege_remedy",
]
