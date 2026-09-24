from dataclasses import dataclass

from csc458_pa1.prefix_tools import canonical_prefix, prefix_contains, longest_prefix_match
from csc458_pa1.protocols import IPv4Packet
from csc458_pa1.router import Router


@dataclass
class RecordingInterface:
    sent: list

    def __init__(self):
        self.sent = []

    def send_datagram(self, datagram, next_hop_ip):
        self.sent.append((datagram, next_hop_ip))


def pkt(dst, ttl=8, payload=b"x"):
    return IPv4Packet.build("192.0.2.9", dst, payload, protocol=17, ttl=ttl)


def test_prefix_helpers_and_canonicalization():
    assert canonical_prefix("10.1.7.9/24") == "10.1.7.0/24"
    assert prefix_contains("10.1.0.0/16", "10.1.200.7")
    assert not prefix_contains("10.1.0.0/16", "10.2.0.1")
    assert prefix_contains("0.0.0.0/0", "203.0.113.99")


def test_longest_prefix_match_prefers_most_specific_route():
    prefixes = ["0.0.0.0/0", "10.0.0.0/8", "10.4.0.0/16", "10.4.32.0/20"]
    assert longest_prefix_match(prefixes, "10.4.35.7") == "10.4.32.0/20"
    assert longest_prefix_match(prefixes, "10.4.200.1") == "10.4.0.0/16"
    assert longest_prefix_match(prefixes, "8.8.8.8") == "0.0.0.0/0"


def test_router_direct_route_uses_destination_as_next_hop_and_decrements_ttl():
    i0, i1 = RecordingInterface(), RecordingInterface()
    r = Router([i0, i1])
    r.add_route("10.2.0.99", 16, None, 1)  # must canonicalize to 10.2.0.0/16
    d = pkt("10.2.7.8", ttl=5)
    r.receive_datagram(0, d)
    r.route()
    assert i0.sent == []
    assert len(i1.sent) == 1
    forwarded, next_hop = i1.sent[0]
    assert next_hop == "10.2.7.8"
    assert forwarded.dst == d.dst and forwarded.ttl == 4 and forwarded.payload == d.payload


def test_router_indirect_route_uses_configured_next_hop():
    i0, i1 = RecordingInterface(), RecordingInterface()
    r = Router([i0, i1])
    r.add_route("203.0.113.0", 24, "10.0.1.1", 1)
    r.receive_datagram(0, pkt("203.0.113.55"))
    r.route()
    assert len(i1.sent) == 1
    assert i1.sent[0][1] == "10.0.1.1"


def test_router_drops_no_route_and_expired_ttl():
    i0, i1 = RecordingInterface(), RecordingInterface()
    r = Router([i0, i1])
    r.add_route("10.0.0.0", 8, None, 1)
    r.receive_datagram(0, pkt("192.168.1.8", ttl=9))
    r.receive_datagram(0, pkt("10.7.8.9", ttl=1))
    r.route()
    assert i0.sent == [] and i1.sent == []


def test_router_uses_lpm_when_routes_overlap():
    ifaces = [RecordingInterface() for _ in range(3)]
    r = Router(ifaces)
    r.add_route("0.0.0.0", 0, "192.0.2.1", 0)
    r.add_route("10.0.0.0", 8, "192.0.2.2", 1)
    r.add_route("10.4.0.0", 16, "192.0.2.3", 2)
    r.receive_datagram(0, pkt("10.4.8.8"))
    r.route()
    assert len(ifaces[2].sent) == 1
    assert ifaces[2].sent[0][1] == "192.0.2.3"
