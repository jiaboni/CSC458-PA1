# CSC458 PA1 - Building a Simple Router

This assignment has three connected parts:

1. **Network Interface + ARP (100 points)** - implement the Layer-2 network-interface behavior.
2. **IP Forwarding + Static Routing + LPM (100 points)** - implement the Layer-3 forwarding plane that calls the Part I interface.
3. **TTL, ICMP, and Traceroute (50 points)** - use supplied packet parsers and a small PCAP-analysis task to understand how TTL expiration and ICMP make traceroute possible.

## Environment

Use the official CSC458 Ubuntu 22.04 VM. The graded code uses Python 3.10+ and `pytest`; no extra Python package is required.

## Run public tests

```bash
python3 -m pytest -q
```

## Files students modify

- `src/csc458_pa1/network_interface.py`
- `src/csc458_pa1/prefix_tools.py`
- `src/csc458_pa1/router.py`
- `src/csc458_pa1/analysis.py`
- `report/answers_template.md`

Do **not** modify `protocols.py`, `pcap.py`, `io.py`, or `traceroute.py`.

## Optional live traceroute

After your deterministic tests pass, you may try the supplied live traceroute implementation from inside the course VM. Raw ICMP sockets normally require `sudo` and may be filtered by a VPN, firewall, NAT, or the destination network; live results are not correctness-graded.
