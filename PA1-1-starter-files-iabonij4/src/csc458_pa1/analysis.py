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
    route = []
    final_ttl = max_ttl

    for i in range(max_ttl):
        route.append([])

    for record in read_pcap(path):
        try:
            etherframe = EthernetFrame.parse(record.data)
        except PacketFormatError:
            continue
        
        if etherframe.ethertype == ETHERTYPE_IPV4:
            try:
                ipv4_packet = IPv4Packet.parse(etherframe.payload)
            except PacketFormatError:
                continue
        else:
            continue

        if ipv4_packet.protocol == IPPROTO_ICMP:
            try:
                icmp_message = ICMPMessage.parse(ipv4_packet.payload)
            except PacketFormatError:
                continue
        else:
            continue

        if (icmp_message.type == 11 and icmp_message.code == 0) or (icmp_message.type == 3 and icmp_message.code == 3):
            try:
                quoted_ipv4 = IPv4Packet.parse(icmp_message.payload, require_full=False)
            except PacketFormatError:
                continue
        
            if quoted_ipv4.protocol == IPPROTO_UDP:
                try:
                    quoted_udp = UDPDatagram.parse(quoted_ipv4.payload, require_full=False)
                except PacketFormatError:
                    continue
            else:
                continue

            if (
                ipv4_packet.dst == source_ip
                and quoted_ipv4.src == source_ip
                and quoted_ipv4.dst == destination_ip
            ):
                ttl = quoted_udp.dst_port - base_port
                if 0 <= ttl <= max_ttl:
                    if ipv4_packet.src not in route[ttl - 1]:
                        route[ttl - 1].append(ipv4_packet.src)
                    if icmp_message.type == 3 and icmp_message.code == 3:
                        final_ttl = ttl
            else:
                continue
        
    if not any(route):
        return []
    else: 
        return route[:final_ttl]


