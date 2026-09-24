from __future__ import annotations

from dataclasses import dataclass
import socket
import struct

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERNET_BROADCAST = "ff:ff:ff:ff:ff:ff"
ARP_REQUEST = 1
ARP_REPLY = 2
IPPROTO_ICMP = 1
IPPROTO_UDP = 17


class PacketFormatError(ValueError):
    """Raised when a supplied frame/packet is malformed or unsupported."""


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _mac_bytes(text: str) -> bytes:
    parts = text.split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid MAC address: {text}")
    return bytes(int(p, 16) for p in parts)


def _ipv4(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def _ipv4_bytes(text: str) -> bytes:
    return socket.inet_aton(text)


def _checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


@dataclass(frozen=True)
class EthernetFrame:
    dst: str
    src: str
    ethertype: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes) -> "EthernetFrame":
        if len(data) < 14:
            raise PacketFormatError("truncated Ethernet header")
        dst, src, etype = struct.unpack("!6s6sH", data[:14])
        return cls(_mac(dst), _mac(src), etype, data[14:])

    def to_bytes(self) -> bytes:
        return struct.pack("!6s6sH", _mac_bytes(self.dst), _mac_bytes(self.src), self.ethertype) + self.payload


@dataclass(frozen=True)
class ARPMessage:
    hardware_type: int
    protocol_type: int
    hardware_len: int
    protocol_len: int
    opcode: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    @classmethod
    def parse(cls, data: bytes) -> "ARPMessage":
        if len(data) < 8:
            raise PacketFormatError("truncated ARP header")
        htype, ptype, hlen, plen, op = struct.unpack("!HHBBH", data[:8])
        if (htype, ptype, hlen, plen) != (1, ETHERTYPE_IPV4, 6, 4):
            raise PacketFormatError("only Ethernet/IPv4 ARP is supported")
        if op not in (ARP_REQUEST, ARP_REPLY):
            raise PacketFormatError("unsupported ARP opcode")
        need = 28
        if len(data) < need:
            raise PacketFormatError("truncated ARP message")
        sha = data[8:14]
        spa = data[14:18]
        tha = data[18:24]
        tpa = data[24:28]
        return cls(htype, ptype, hlen, plen, op, _mac(sha), _ipv4(spa), _mac(tha), _ipv4(tpa))

    @classmethod
    def request(cls, sender_mac: str, sender_ip: str, target_ip: str) -> "ARPMessage":
        return cls(1, ETHERTYPE_IPV4, 6, 4, ARP_REQUEST,
                   sender_mac, sender_ip, "00:00:00:00:00:00", target_ip)

    @classmethod
    def reply(cls, sender_mac: str, sender_ip: str,
              target_mac: str, target_ip: str) -> "ARPMessage":
        return cls(1, ETHERTYPE_IPV4, 6, 4, ARP_REPLY,
                   sender_mac, sender_ip, target_mac, target_ip)

    def to_bytes(self) -> bytes:
        return (
            struct.pack("!HHBBH", self.hardware_type, self.protocol_type,
                        self.hardware_len, self.protocol_len, self.opcode)
            + _mac_bytes(self.sender_mac)
            + _ipv4_bytes(self.sender_ip)
            + _mac_bytes(self.target_mac)
            + _ipv4_bytes(self.target_ip)
        )


@dataclass(frozen=True)
class IPv4Packet:
    version: int
    ihl_bytes: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    checksum: int
    src: str
    dst: str
    options: bytes
    payload: bytes

    @classmethod
    def parse(cls, data: bytes, require_full: bool = True) -> "IPv4Packet":
        if len(data) < 20:
            raise PacketFormatError("truncated IPv4 header")
        verihl = data[0]
        version = verihl >> 4
        ihl = (verihl & 0x0F) * 4
        if version != 4:
            raise PacketFormatError("not IPv4")
        if ihl < 20:
            raise PacketFormatError("invalid IPv4 IHL")
        if len(data) < ihl:
            raise PacketFormatError("truncated IPv4 header/options")
        _, _, total, ident, flfrag, ttl, proto, chk, src, dst = struct.unpack("!BBHHHBBH4s4s", data[:20])
        if total < ihl:
            raise PacketFormatError("invalid IPv4 total length")
        if require_full and len(data) < total:
            raise PacketFormatError("truncated IPv4 packet")
        flags = (flfrag >> 13) & 0x7
        frag = flfrag & 0x1FFF
        return cls(version, ihl, total, ident, flags, frag, ttl, proto, chk,
                   _ipv4(src), _ipv4(dst), data[20:ihl], data[ihl:min(total, len(data))])

    @classmethod
    def build(cls, src: str, dst: str, payload: bytes = b"hello", *,
              ttl: int = 64, protocol: int = IPPROTO_UDP,
              identification: int = 0, options: bytes = b"") -> "IPv4Packet":
        if len(options) % 4:
            raise ValueError("IPv4 options must have a length divisible by four")
        ihl = 20 + len(options)
        total = ihl + len(payload)
        pkt = cls(4, ihl, total, identification, 0, 0, ttl, protocol, 0,
                  src, dst, options, payload)
        raw = pkt.to_bytes()
        return cls.parse(raw)

    def to_bytes(self) -> bytes:
        if self.ihl_bytes != 20 + len(self.options) or self.ihl_bytes % 4:
            raise ValueError("inconsistent IPv4 IHL/options")
        total = self.ihl_bytes + len(self.payload)
        verihl = (4 << 4) | (self.ihl_bytes // 4)
        flfrag = ((self.flags & 0x7) << 13) | (self.fragment_offset & 0x1FFF)
        header0 = struct.pack(
            "!BBHHHBBH4s4s", verihl, 0, total, self.identification,
            flfrag, self.ttl, self.protocol, 0,
            _ipv4_bytes(self.src), _ipv4_bytes(self.dst)
        ) + self.options
        chk = _checksum16(header0)
        header = struct.pack(
            "!BBHHHBBH4s4s", verihl, 0, total, self.identification,
            flfrag, self.ttl, self.protocol, chk,
            _ipv4_bytes(self.src), _ipv4_bytes(self.dst)
        ) + self.options
        return header + self.payload


@dataclass(frozen=True)
class ICMPMessage:
    type: int
    code: int
    checksum: int
    rest: bytes
    payload: bytes

    @classmethod
    def parse(cls, data: bytes) -> "ICMPMessage":
        if len(data) < 8:
            raise PacketFormatError("truncated ICMP message")
        typ, code, chk = struct.unpack("!BBH", data[:4])
        return cls(typ, code, chk, data[4:8], data[8:])


@dataclass(frozen=True)
class UDPDatagram:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes, require_full: bool = True) -> "UDPDatagram":
        if len(data) < 8:
            raise PacketFormatError("truncated UDP header")
        sp, dp, length, chk = struct.unpack("!HHHH", data[:8])
        if length < 8:
            raise PacketFormatError("invalid UDP length")
        if require_full and len(data) < length:
            raise PacketFormatError("truncated UDP datagram")
        return cls(sp, dp, length, chk, data[8:min(length, len(data))])
