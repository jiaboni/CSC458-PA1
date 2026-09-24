from __future__ import annotations
import socket
from dataclasses import dataclass
from typing import Protocol

class ProbeIO(Protocol):
    """Abstraction used by run_traceroute, so tests need no privileged sockets."""
    def send_probe(self, destination: str, ttl: int, destination_port: int, payload: bytes) -> None: ...
    def receive(self, timeout: float) -> bytes | None: ...
    def close(self) -> None: ...

class SocketProbeIO:
    """Real UDP-probe/raw-ICMP implementation for Linux/macOS.

    Creating the receive socket normally requires root/CAP_NET_RAW. The
    protocol logic is deliberately kept outside this class so it can be tested
    deterministically with a fake ProbeIO.
    """
    def __init__(self):
        self._send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    def send_probe(self, destination: str, ttl: int, destination_port: int, payload: bytes) -> None:
        self._send.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        self._send.sendto(payload, (destination, destination_port))

    def receive(self, timeout: float) -> bytes | None:
        self._recv.settimeout(timeout)
        try:
            packet, _ = self._recv.recvfrom(65535)
            return packet
        except socket.timeout:
            return None

    def close(self) -> None:
        self._send.close(); self._recv.close()
