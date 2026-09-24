# CSC458 PA1 Report

Name(s):
UTORid(s):

## Part I - Network Interface and ARP

1. A host has IP `10.0.0.10/24`, default gateway `10.0.0.1`, and wants to send an IPv4 datagram to `203.0.113.80`. Which IP address should be passed to `NetworkInterface.send_datagram()` as the next hop? Why is that address different from the datagram's destination IP?

2. Why does the interface suppress repeated ARP requests for the same unresolved IP for 5 seconds? What problem would occur if every waiting datagram caused a fresh broadcast ARP request?

3. Why does an ARP cache entry expire even though a previously learned mapping may still appear valid?

## Part II - IP Forwarding, Static Routing, and LPM

4. Suppose the routing table contains:

   - `0.0.0.0/0` via `192.0.2.1`
   - `10.0.0.0/8` via `192.0.2.2`
   - `10.4.0.0/16` via `192.0.2.3`
   - `10.4.32.0/20` directly connected

   Which route is selected for destination `10.4.35.7`? Explain why a router uses longest-prefix matching rather than simply the first matching route.

5. Explain the difference between a route with `next_hop=None` and a route with an explicit next-hop IP. Which IP address is handed to the outgoing `NetworkInterface` in each case?

6. Describe the complete forwarding path through your Part II and Part I code for a packet sent to a remote network: from routing-table lookup to the final Ethernet frame placed in the interface output queue.

## Part III - TTL, ICMP, and Traceroute

Use `pcaps/traceroute_integrated.pcap` and `pcaps/traceroute_messy.pcap`.

7. In Part II your simplified router silently drops a datagram whose TTL would reach zero. What does a real router normally send back, and how does traceroute use that message?

8. What is the difference between ICMP Time Exceeded (type 11/code 0) and ICMP Destination Unreachable / Port Unreachable (type 3/code 3) in the supplied UDP traceroute? Why does Port Unreachable signal that the destination has been reached?

9. In `traceroute_integrated.pcap`, all outbound UDP probes have the same Ethernet destination MAC address even though the ICMP replies identify different routers along the path. Explain why.

10. Run the supplied PCAP analysis and record the reconstructed hop list for `traceroute_integrated.pcap`. Then identify which ICMP source corresponds to each TTL.

11. `traceroute_messy.pcap` contains a missing hop. Give at least three realistic reasons why a traceroute hop may appear as `*` even though later routers respond.

12. The messy capture also contains duplicate, malformed, wrong-code, and unrelated traffic. Choose two such records and explain why they must not be treated as valid replies to the traceroute probe.

13. Explain why an ICMP error must be matched using the quoted original IP/UDP headers rather than accepting any ICMP Time Exceeded message received by the host.
