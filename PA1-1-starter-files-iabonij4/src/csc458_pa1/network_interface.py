from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .protocols import (
    ARPMessage,
    ARP_REPLY,
    ARP_REQUEST,
    ETHERNET_BROADCAST,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    EthernetFrame,
    IPv4Packet,
    PacketFormatError,
)

ARP_CACHE_TTL_MS = 30_000
ARP_REQUEST_TTL_MS = 5_000


@dataclass
class _CacheEntry:
    mac: str
    learned_at_ms: int


@dataclass
class _PendingResolution:
    started_at_ms: int
    datagrams: list[IPv4Packet]


class NetworkInterface:
    """A simplified Ethernet/ARP network interface.

    The IP layer calls ``send_datagram()`` with an IPv4 datagram and the IP
    address of the next hop. The interface resolves that IP address to a MAC
    address using ARP and emits Ethernet frames.

    Note:
        You may add private helper methods and state to this class, but do not
        change the public method signatures.
    """

    def __init__(self, ethernet_address: str, ip_address: str):
        self.ethernet_address = ethernet_address.lower()
        self.ip_address = ip_address

        self._now_ms = 0
        self._arp_cache: dict[str, _CacheEntry] = {}
        self._pending: dict[str, _PendingResolution] = {}
        self._outgoing: deque[EthernetFrame] = deque()

    def send_datagram(self, datagram: IPv4Packet, next_hop_ip: str) -> None:
        """Queue an IPv4 datagram for transmission to the next hop.

        Args:
            datagram: The IPv4 datagram to transmit.
            next_hop_ip: The IP address of the datagram's next hop.

        Notes:
            Look up the next hop in the ARP cache and ignore expired entries.

            * If its MAC address is known, create an Ethernet frame with
              ``ethertype=ETHERTYPE_IPV4``, the appropriate source and
              destination MAC addresses, and
              ``payload=datagram.to_bytes()``. Add the frame to the outgoing
              queue.
            * If you do not know the MAC address of the next hop, you should try to
              find it. This is done by broadcasting an ARP request
              (i.e., ``ethertype=ETHERTYPE_ARP'') and asking who has that MAC address.
              Then you should wait for the response to that request. You should also
              queue this packet in a queue for pending frames so that you can prepare
              it for sending when you receive a reply. There is one extra thing that
              you need to consider here. If you have sent an ARP request for the same
              IP address in the last 5 seconds, you should NOT send a new ARP request.
              Instead, you should append this packet to queue that holds previous
              packets that are waiting for that IP address.
        """
        # TODO 1: Part I
        raise NotImplementedError

    def recv_frame(self, frame: EthernetFrame) -> IPv4Packet | None:
        """Process one incoming Ethernet frame.

        Args:
            frame: The incoming Ethernet frame.

        Returns:
            The parsed IPv4 packet when the frame contains a valid IPv4
            payload destined for this interface; otherwise, ``None``.

        Notes:
            Process the frame as follows:

            * Discard frames that are neither addressed to this interface nor
              broadcast to the network.
            * If this packet is destined to this machine and its payload is an IPv4
              packet, then try to parse the payload as an IPv4Packet. You can use
              ``IPv4Packet.parse()'' for that. If the parse was successful, it
              should be returned (so that the system can pass it to the higher IP
              layer in the network stack).
            * If this packet is destined to this machine and its payload is an ARP
              packet, process the ARP packet. To do this, it should first try to
              parse the payload as an ARPMessage. You can use ``ARPMessage.parse()''
              for this. If it could be parsed properly, then it should learn the
              mapping between the packet's Sender IP address and its MAC address and
              cache this in the ARP cache table. This information should be cached
              for 30 seconds. Furthermore, if it is an ARP request that asks for our
              IP address, reply back to it. To do this, you should create an ARP reply
              packet that is destined to the sender and contains proper information
              (including our IP and MAC address). You can use ``ARPMessage.reply()''
              for this. Then, package this ARP message in an Ethernet frame and place
              it in the ready-to-be-sent queue for outgoing frames.
        """
        # TODO 2: Part I
        raise NotImplementedError

    def maybe_send(self) -> EthernetFrame | None:
        """Return and remove the oldest frame awaiting transmission, if any.

        Returns:
            The oldest queued Ethernet frame, or ``None`` when the outgoing
            queue is empty.

        Note:
            Whenever the physical layer of the network is ready to send out a 
            packet, it will call this function to check if there is any packet
            ready to be sent. This is where you should check your ready-to-be-sent
            queue to see if there is any packet in it. If there any packet, you
            should remove the first packet waiting in the queue (the oldest packet)
            from it and return it. Otherwise, if there is no packet to be sent,
            simply return nothing.
            
            Note that there could be different Ethernet packets in the queue:
            datagrams that are passed by IP layer, ARP requests to learn the MAC
            address of a next hop, and ARP replies to requests that are sent to us
            about our IP addresses.
        """
        # TODO 3: Part I
        raise NotImplementedError

    def tick(self, ms_since_last_tick: int) -> None:
        """Advance time and expire stale ARP state.

        Args:
            ms_since_last_tick: The number of milliseconds elapsed since the
                previous call.

        Notes:
            This is the callback function that informs you about the passage of
            time. When this function is called, it means that ``ms_since_last_tick''
            milliseconds are passed from the last time that it was called.
            You should keep track of time and perform the following two tasks:
            * Expire any entry in ARP cache table that was learnt more than 30 
              seconds ago.
            * Remove the pending ARP reply wait for any next hop IP that was sent
              more than 5 seconds ago. Furthermore, you should also empty any packets
              waiting for that IP address from the queue.
        """
        # TODO 4: Part I
        raise NotImplementedError
