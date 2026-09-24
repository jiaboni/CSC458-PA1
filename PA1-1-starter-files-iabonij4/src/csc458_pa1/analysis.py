from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from .pcap import read_pcap
from .protocols import (
    ETHERTYPE_IPV4,
    IPPROTO_ICMP,
    IPPROTO_UDP,
    EthernetFrame,
    ICMPMessage,
    IPv4Packet,
    PacketFormatError,
    UDPDatagram,
)


def analyze_traceroute_pcap(
    path: str | Path,
    source_ip: str,
    destination_ip: str,
    base_port: int = 33434,
    max_ttl: int = 30,
) -> list[list[str]]:
    """Reconstruct a UDP traceroute from an Ethernet PCAP.

    Packet parsing is STAFF-PROVIDED. Your task is only to select and correlate
    the relevant packets: identify supported ICMP errors, inspect the quoted
    IPv4/UDP probe, map its destination port back to the probe TTL, deduplicate
    responders, preserve missing hops, and stop when the destination is reached.

    Malformed or unrelated packets must be ignored rather than crashing the
    analysis.

    Args:
        path: Path to a classic PCAP file containing Ethernet frames.
        source_ip: IPv4 address of the host that sent the traceroute probes.
        destination_ip: IPv4 address of the traceroute destination.
        base_port: UDP destination port corresponding to a probe TTL of zero.
        max_ttl: Largest probe TTL to include in the analysis.

    Returns:
        A list indexed by probe TTL minus one. Each inner list contains the
        unique responder IPv4 addresses observed at that TTL, in capture
        order. Missing hops are represented by empty lists. Returns an empty
        list when no relevant responses are found.

    Examples:
        >>> capture = (
        ...     Path(__file__).resolve().parents[2]
        ...     / "pcaps"
        ...     / "traceroute_basic.pcap"
        ... )
        >>> analyze_traceroute_pcap(
        ...     capture, "192.0.2.10", "203.0.113.80", max_ttl=2
        ... )
        [['192.0.2.1'], ['198.51.100.1']]

    HINT: 
        Use the supplied parsers to:
        * ignore non-IPv4 and non-ICMP records;
        * accept only ICMP Time Exceeded (i.e., ICMP type=11 and ICMP code=0)
          and Port Unreachable (i.e., ICMP type=3 and ICMP code=3) addressed
          back to the expected source;
        * inspect the quoted IPv4/UDP probe and verify the expected
          source/destination pair;
        * map the quoted UDP destination port back to the original probe TTL;
        * Keep distinct responders at the same TTL; 
          Remove duplicate responders at the same TTL;
          Preserves capture order within each inner list;
        * keep an empty list for a missing hop;
        * stop when a Port Unreachable from the destination is observed.
    """
    # TODO: Part III (small PCAP-analysis task)
    raise NotImplementedError
