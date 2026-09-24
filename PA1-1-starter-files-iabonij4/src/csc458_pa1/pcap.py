from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import struct
from typing import Iterator

@dataclass(frozen=True)
class PcapRecord:
    timestamp: float
    captured_len: int
    original_len: int
    data: bytes

class PcapError(ValueError):
    pass

def read_pcap(path: str | Path) -> Iterator[PcapRecord]:
    """Read a classic PCAP file. Only Ethernet captures are accepted.

    This small reader is provided so that the assignment has no dependency on
    Scapy, dpkt, or libpcap. Students do not need to modify this file.
    """
    with open(path, 'rb') as f:
        gh = f.read(24)
        if len(gh) != 24:
            raise PcapError('truncated PCAP global header')
        magic = gh[:4]
        if magic == b'\xd4\xc3\xb2\xa1':
            endian, scale = '<', 1_000_000
        elif magic == b'\xa1\xb2\xc3\xd4':
            endian, scale = '>', 1_000_000
        elif magic == b'\x4d\x3c\xb2\xa1':
            endian, scale = '<', 1_000_000_000
        elif magic == b'\xa1\xb2\x3c\x4d':
            endian, scale = '>', 1_000_000_000
        else:
            raise PcapError('unsupported PCAP magic number')
        _, _, _, _, _, linktype = struct.unpack(endian + 'HHIIII', gh[4:])
        if linktype != 1:
            raise PcapError(f'expected Ethernet linktype 1, got {linktype}')
        while True:
            ph = f.read(16)
            if ph == b'':
                return
            if len(ph) != 16:
                raise PcapError('truncated PCAP packet header')
            ts_sec, ts_frac, caplen, origlen = struct.unpack(endian + 'IIII', ph)
            data = f.read(caplen)
            if len(data) != caplen:
                raise PcapError('truncated PCAP packet data')
            yield PcapRecord(ts_sec + ts_frac / scale, caplen, origlen, data)
