# CSC458 PA1 Report

Name(s):
UTORid(s):

## Part I - Network Interface and ARP

1. A host has IP `10.0.0.10/24`, default gateway `10.0.0.1`, and wants to send an IPv4 datagram to `203.0.113.80`. Which IP address should be passed to `NetworkInterface.send_datagram()` as the next hop? Why is that address different from the datagram's destination IP?

The IP address passed into NetworkInterface.send_datagram() should be 10.0.0.1 because 203.0.113.80 is outside the /24 subnet so the next hop is a machine that resides in the same physical network. It is different because the  link layer requires the MAC address of the next hop to communicate with it. 

2. Why does the interface suppress repeated ARP requests for the same unresolved IP for 5 seconds? What problem would occur if every waiting datagram caused a fresh broadcast ARP request?

It suppresses repeated ARP requests because we append additional datagrams to that pending queue. It would broadcast to every machine in the physical network.

3. Why does an ARP cache entry expire even though a previously learned mapping may still appear valid?

An ARP cache entry expires because IP addresses aren’t permanently assigned to a computer. 

## Part II - IP Forwarding, Static Routing, and LPM

4. Suppose the routing table contains:

   - `0.0.0.0/0` via `192.0.2.1`
   - `10.0.0.0/8` via `192.0.2.2`
   - `10.4.0.0/16` via `192.0.2.3`
   - `10.4.32.0/20` directly connected

   Which route is selected for destination `10.4.35.7`? Explain why a router uses longest-prefix matching rather than simply the first matching route.

The route selected is 10.4.32.0/20. A route uses longest prefix matching because a more specific route can override an aggregate using longest-prefix matching

5. Explain the difference between a route with `next_hop=None` and a route with an explicit next-hop IP. Which IP address is handed to the outgoing `NetworkInterface` in each case?

When next_hop=None, then the  destination network is directly attached and an explicit next-hop IP is the next-hop IPv4 address. If next_hop is None, then the datagrams destination IP is handed otherwise the explicit next-hop IP is handed to the outgoing NetworkInterface.

6. Describe the complete forwarding path through your Part II and Part I code for a packet sent to a remote network: from routing-table lookup to the final Ethernet frame placed in the interface output queue.

First the router looks up the destination to choose the one with the largest prefix length and decrements the TTL then calls send_datagram() on the interface. Inside the interface, If the next-hop IP is cached, then we encapsulate the datagram in an Ethernet frame and queue it for transmission. If its unmapped then we broadcast one ARP request and queue the datagram while resolution is pending. Finally with the EthernetFrame created, it is appended to self._outgoing for physical transmission. 

## Part III - TTL, ICMP, and Traceroute

Use `pcaps/traceroute_integrated.pcap` and `pcaps/traceroute_messy.pcap`.

7. In Part II your simplified router silently drops a datagram whose TTL would reach zero. What does a real router normally send back, and how does traceroute use that message?

A real router normally sends back an ICMP Time Exceeded and traceroute exploits exactly this behavior by sending probes with values 1,2,3 and so on in an increasing manner. When router returns ICMP Time Exceeded message then traceroute gets the source IP address.

8. What is the difference between ICMP Time Exceeded (type 11/code 0) and ICMP Destination Unreachable / Port Unreachable (type 3/code 3) in the supplied UDP traceroute? Why does Port Unreachable signal that the destination has been reached?

ICMP Time Exceeded (type 11/code 0) is returned when decrementing TTL would produce zero. Port Unreachable (type 3/code 3) is returned when a probe finally reaches the destination but finds the selected UDP destination port normally has no listening application. It signals the destination has been reached because the destination returns ICMP Destination Unreachable / Port Unreachable. 

9. In `traceroute_integrated.pcap`, all outbound UDP probes have the same Ethernet destination MAC address even though the ICMP replies identify different routers along the path. Explain why.

All probes target Off-link (off-LAN) destination so routing resolve the next-hop router’s MAC address using ARP cache. While ordinary IP forwarding preserves the source and destination IP addresses, the ethernet destination MAC is always set to the next hop on that link. 

10. Run the supplied PCAP analysis and record the reconstructed hop list for `traceroute_integrated.pcap`. Then identify which ICMP source corresponds to each TTL.

11. `traceroute_messy.pcap` contains a missing hop. Give at least three realistic reasons why a traceroute hop may appear as `*` even though later routers respond.

A traceroute hop may appear as `*` even though later routers respond because of NATs,
firewalls, VPNs blocking the incoming UDP probe packets. Datagrams could be lost due to overflow and also because load balancing or route changes can expose different paths. 

12. The messy capture also contains duplicate, malformed, wrong-code, and unrelated traffic. Choose two such records and explain why they must not be treated as valid replies to the traceroute probe.

Messages with codes that are not (type 11/code 0) or (type 3/code 3) do not have a destination arrival or TTL expiration so we would get false routing hops through them. Also, ICMP messages whose quoted inner UDP port doesn't equal (base_port +t) belong in background traffic so if we accept them, then it will put an ICMP error with the probe.

13. Explain why an ICMP error must be matched using the quoted original IP/UDP headers rather than accepting any ICMP Time Exceeded message received by the host.

An ICMP error must be matched using the quoted original IP/UDP headers because ICMP error messages arrive asynchronously so inner destination IP and UDP destination port (base_port +t) are the only way to know an error is related to a specific probe and TTL step.