from pathlib import Path

from csc458_pa1.analysis import analyze_traceroute_pcap

PCAPS = Path(__file__).resolve().parents[1] / "pcaps"


def test_integrated_trace_from_pcap():
    # The first two records are an ARP request/reply. Part III should ignore them
    # and reconstruct the subsequent traceroute using the supplied parsers.
    assert analyze_traceroute_pcap(
        PCAPS / "traceroute_integrated.pcap",
        "192.0.2.10",
        "203.0.113.80",
    ) == [["192.0.2.1"], ["198.51.100.1"], ["203.0.113.1"], ["203.0.113.80"]]
