from csc458_pa1.network_interface import NetworkInterface
from csc458_pa1.protocols import (
    ARPMessage, ARP_REPLY, ARP_REQUEST, ETHERNET_BROADCAST,
    ETHERTYPE_ARP, ETHERTYPE_IPV4, EthernetFrame, IPv4Packet,
)

LOCAL_MAC = "02:00:00:00:00:10"
LOCAL_IP = "10.0.0.10"
ROUTER_MAC = "02:00:00:00:00:01"
ROUTER_IP = "10.0.0.1"


def datagram(src="192.0.2.10", dst="203.0.113.10", payload=b"hello", ttl=64):
    return IPv4Packet.build(src, dst, payload, protocol=17, ttl=ttl)


def arp_frame(src_mac, dst_mac, arp):
    return EthernetFrame(dst_mac, src_mac, ETHERTYPE_ARP, arp.to_bytes())


def test_typical_arp_resolution_and_release():
    iface = NetworkInterface(LOCAL_MAC, LOCAL_IP)
    d = datagram()
    iface.send_datagram(d, ROUTER_IP)

    request = iface.maybe_send()
    assert request is not None
    assert (request.src, request.dst, request.ethertype) == (
        LOCAL_MAC, ETHERNET_BROADCAST, ETHERTYPE_ARP
    )
    arp = ARPMessage.parse(request.payload)
    assert (arp.opcode, arp.sender_ip, arp.target_ip) == (ARP_REQUEST, LOCAL_IP, ROUTER_IP)
    assert iface.maybe_send() is None

    reply = ARPMessage.reply(ROUTER_MAC, ROUTER_IP, LOCAL_MAC, LOCAL_IP)
    assert iface.recv_frame(arp_frame(ROUTER_MAC, LOCAL_MAC, reply)) is None

    frame = iface.maybe_send()
    assert frame is not None
    assert (frame.src, frame.dst, frame.ethertype) == (LOCAL_MAC, ROUTER_MAC, ETHERTYPE_IPV4)
    got = IPv4Packet.parse(frame.payload)
    assert (got.src, got.dst, got.payload) == (d.src, d.dst, d.payload)
    assert iface.maybe_send() is None


def test_receives_ipv4_only_when_addressed_to_us():
    iface = NetworkInterface(LOCAL_MAC, LOCAL_IP)
    d = datagram("203.0.113.5", LOCAL_IP, b"reply")
    frame = EthernetFrame(LOCAL_MAC, ROUTER_MAC, ETHERTYPE_IPV4, d.to_bytes())
    got = iface.recv_frame(frame)
    assert got is not None and got.src == d.src and got.dst == d.dst and got.payload == b"reply"

    other = EthernetFrame("02:00:00:00:00:99", ROUTER_MAC, ETHERTYPE_IPV4, d.to_bytes())
    assert iface.recv_frame(other) is None


def test_learns_from_request_and_replies_when_target_is_us():
    iface = NetworkInterface(LOCAL_MAC, LOCAL_IP)
    remote_mac, remote_ip = "02:00:00:00:00:20", "10.0.0.20"
    request = ARPMessage.request(remote_mac, remote_ip, LOCAL_IP)
    assert iface.recv_frame(arp_frame(remote_mac, ETHERNET_BROADCAST, request)) is None

    reply_frame = iface.maybe_send()
    assert reply_frame is not None
    reply = ARPMessage.parse(reply_frame.payload)
    assert (reply.opcode, reply.sender_ip, reply.target_ip) == (ARP_REPLY, LOCAL_IP, remote_ip)
    assert (reply_frame.dst, reply.target_mac) == (remote_mac, remote_mac)

    # Receiving the request also taught us the sender's mapping.
    iface.send_datagram(datagram(dst="198.51.100.9"), remote_ip)
    ipv4 = iface.maybe_send()
    assert ipv4 is not None and ipv4.ethertype == ETHERTYPE_IPV4 and ipv4.dst == remote_mac


def test_request_suppression_and_pending_timeout():
    iface = NetworkInterface(LOCAL_MAC, LOCAL_IP)
    iface.send_datagram(datagram(payload=b"one"), ROUTER_IP)
    assert iface.maybe_send() is not None
    iface.send_datagram(datagram(payload=b"two"), ROUTER_IP)
    assert iface.maybe_send() is None
    iface.tick(4_999)
    iface.send_datagram(datagram(payload=b"three"), ROUTER_IP)
    assert iface.maybe_send() is None

    # At 5 seconds, unresolved state and its queued datagrams expire.
    iface.tick(1)
    iface.send_datagram(datagram(payload=b"fresh"), ROUTER_IP)
    assert ARPMessage.parse(iface.maybe_send().payload).opcode == ARP_REQUEST

    reply = ARPMessage.reply(ROUTER_MAC, ROUTER_IP, LOCAL_MAC, LOCAL_IP)
    iface.recv_frame(arp_frame(ROUTER_MAC, LOCAL_MAC, reply))
    sent = iface.maybe_send()
    assert sent is not None
    assert IPv4Packet.parse(sent.payload).payload == b"fresh"
    assert iface.maybe_send() is None


def test_arp_cache_expires_after_30_seconds():
    iface = NetworkInterface(LOCAL_MAC, LOCAL_IP)
    reply = ARPMessage.reply(ROUTER_MAC, ROUTER_IP, LOCAL_MAC, LOCAL_IP)
    iface.recv_frame(arp_frame(ROUTER_MAC, LOCAL_MAC, reply))
    iface.tick(29_999)
    iface.send_datagram(datagram(payload=b"cached"), ROUTER_IP)
    assert iface.maybe_send().ethertype == ETHERTYPE_IPV4

    iface.tick(1)
    iface.send_datagram(datagram(payload=b"expired"), ROUTER_IP)
    frame = iface.maybe_send()
    assert frame is not None and frame.ethertype == ETHERTYPE_ARP
    assert ARPMessage.parse(frame.payload).target_ip == ROUTER_IP
