from __future__ import annotations
from dataclasses import dataclass
import socket, time
from .io import ProbeIO,SocketProbeIO
from .protocols import IPv4Packet,ICMPMessage,UDPDatagram,PacketFormatError
BASE_PORT=33434; MAX_TTL=30; PROBES_PER_TTL=3

@dataclass(frozen=True)
class TracerouteReply:
    responder:str
    reached_destination:bool

def parse_traceroute_reply(packet,destination_ip,destination_port):
    try:
        outer=IPv4Packet.parse(packet)
        if outer.protocol!=1: return None
        m=ICMPMessage.parse(outer.payload)
        if not ((m.type==11 and m.code==0) or (m.type==3 and m.code==3)): return None
        inner=IPv4Packet.parse(m.payload,require_full=False)
        if inner.protocol!=17 or inner.dst!=destination_ip: return None
        u=UDPDatagram.parse(inner.payload,require_full=False)
        if u.dst_port!=destination_port: return None
        reached=(m.type==3 and m.code==3 and outer.src==destination_ip)
        return TracerouteReply(outer.src,reached)
    except (PacketFormatError,ValueError):
        return None

def run_traceroute(destination_ip,io,max_ttl=MAX_TTL,probes_per_ttl=PROBES_PER_TTL,timeout=1.0,base_port=BASE_PORT):
    result=[]
    for ttl in range(1,max_ttl+1):
        port=base_port+ttl; responders=[]; reached=False
        for attempt in range(probes_per_ttl):
            io.send_probe(destination_ip,ttl,port,b'CSC458')
            deadline=time.monotonic()+timeout
            while True:
                remaining=deadline-time.monotonic()
                if remaining<=0: break
                packet=io.receive(remaining)
                if packet is None: break
                reply=parse_traceroute_reply(packet,destination_ip,port)
                if reply is None: continue
                if reply.responder not in responders: responders.append(reply.responder)
                reached |= reply.reached_destination
                break
        result.append(responders)
        if reached: break
    return result

def live_traceroute(host,**kwargs):
    destination_ip=socket.gethostbyname(host); io=SocketProbeIO()
    try: return run_traceroute(destination_ip,io,**kwargs)
    finally: io.close()
