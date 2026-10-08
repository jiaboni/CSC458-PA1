from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from typing import Protocol
import ipaddress

from .prefix_tools import canonical_prefix, longest_prefix_match
from .protocols import IPv4Packet


class InterfaceLike(Protocol):
    def send_datagram(self, datagram: IPv4Packet, next_hop_ip: str) -> None: ...


@dataclass(frozen=True)
class RouteEntry:
    prefix: str
    next_hop: str | None
    interface_num: int


class Router:
    """A simplified IPv4 forwarding plane built on Part I NetworkInterfaces.

    Incoming IPv4 datagrams are queued with ``receive_datagram()``. Calling
    ``route()`` forwards all queued datagrams using static routes installed
    with ``add_route()``.

    The router decides which interface and IP next hop to use. The selected
    interface then performs ARP and Ethernet transmission using the Part I
    code.
    """

    def __init__(self, interfaces: list[InterfaceLike]):
        """Initialize a router with its network interfaces.

        Args:
            interfaces: Interfaces available for forwarding, indexed by their
                positions in this list.

        Examples:
            The router keeps its own list, so later changes to the supplied
            list do not alter its interfaces.

            >>> supplied = [None, None]
            >>> router = Router(supplied)
            >>> supplied.clear()
            >>> len(router.interfaces)
            2
            >>> router.routes
            ()
        """
        self.interfaces = list(interfaces)
        self._routes: dict[str, RouteEntry] = {}
        self._incoming: deque[tuple[int, IPv4Packet]] = deque()

    def add_route(
        self,
        route_prefix: str,
        prefix_length: int,
        next_hop: str | None,
        interface_num: int,
    ) -> None:
        """Install or replace one static route.

        Args:
            route_prefix: The IPv4 address identifying the destination
                network. Host bits are permitted.
            prefix_length: The network prefix length, from 0 through 32.
            next_hop: The next-hop IPv4 address, or ``None`` for a directly
                connected route.
            interface_num: The index of the outgoing interface.

        Raises:
            ValueError: If the prefix length, route prefix, or next-hop address
                is invalid.
            IndexError: If ``interface_num`` is not a valid interface index.

        Examples:
            Route prefixes are stored canonically. Adding another spelling of
            the same network replaces the existing entry.

            >>> router = Router([None, None])
            >>> router.add_route("10.2.0.99", 16, None, 1)
            >>> router.routes
            (RouteEntry(prefix='10.2.0.0/16', next_hop=None, interface_num=1),)
            >>> router.add_route("10.2.4.5", 16, "192.0.2.1", 0)
            >>> router.routes
            (RouteEntry(prefix='10.2.0.0/16', next_hop='192.0.2.1', interface_num=0),)

        Implementation notes:
            Validate both numeric indices before storing the route. Use a
            canonical CIDR string as the route-table key so equivalent route
            prefixes replace one another. Validate and normalize a configured
            next hop as IPv4. For a directly connected route, preserve
            ``next_hop`` as ``None``.

        Hint:
            Reuse ``canonical_prefix()`` for the route key. Python's
            standard-library ``ipaddress`` module can validate and normalize
            the optional next-hop address.
        """
        # TODO: Part II
        if prefix_length < 0 or prefix_length > 32:
            raise ValueError

        route_prefix += '/'
        route_prefix += str(prefix_length)
        try:
            cidr = canonical_prefix(route_prefix)
        except ValueError:
            raise ValueError

        if next_hop:
            try: #https://docs.python.org/3/library/ipaddress.html
                next_hop = str(ipaddress.IPv4Address(next_hop))
            except Exception:
                raise ValueError

        if interface_num < 0 or interface_num > len(self.interfaces):
            raise IndexError

        self._routes[cidr] = RouteEntry(cidr, next_hop, interface_num)


    def receive_datagram(self, interface_num: int, datagram: IPv4Packet) -> None:
        """Queue a datagram that arrived on a router interface.

        Args:
            interface_num: The index of the interface that received the
                datagram.
            datagram: The IPv4 datagram to queue for forwarding.

        Raises:
            IndexError: If ``interface_num`` is not a valid interface index.
        """
        if not 0 <= interface_num < len(self.interfaces):
            raise IndexError("invalid ingress interface")
        self._incoming.append((interface_num, datagram))

    def route(self) -> None:
        """Process and forward all queued datagrams.

        Examples:
            A directly connected route uses the packet's destination as its
            next hop. Forwarding decreases the TTL without modifying the
            original immutable packet.

            >>> from unittest.mock import Mock
            >>> ingress, egress = Mock(), Mock()
            >>> router = Router([ingress, egress])
            >>> router.add_route("10.2.0.99", 16, None, 1)
            >>> packet = IPv4Packet.build(
            ...     "192.0.2.9", "10.2.7.8", b"data", ttl=5
            ... )
            >>> router.receive_datagram(0, packet)
            >>> router.route()
            >>> forwarded, next_hop = egress.send_datagram.call_args.args
            >>> (forwarded.dst, forwarded.ttl, forwarded.payload, next_hop)
            ('10.2.7.8', 4, b'data', '10.2.7.8')
            >>> packet.ttl
            5

        Implementation notes:
            Process every queued datagram in FIFO order. For each datagram:

            * Find the route whose destination prefix is the longest match.
            * Drop the datagram if no route matches.
            * Otherwise, decrement its TTL, but drop it if the resulting TTL
              would be zero.
            * Select the route's outgoing interface.
            * Use the configured next hop, or the final destination for a
              directly connected route.
            * Pass the updated datagram and next hop to ``send_datagram()``.

        Hint:
            Use ``longest_prefix_match()`` for selection, ``popleft()`` for
            FIFO order, and the imported ``replace()`` function to create a
            packet with a lower TTL.
        """
        # TODO: Part II
        
        while self._incoming:
            interface_num, datagram = self._incoming.popleft()
            prefixes = longest_prefix_match(list(self._routes.keys()), datagram.dst)

            if prefixes and datagram.ttl > 1:
                #source: https://docs.python.org/3/library/dataclasses.html
                new_datagram = replace(datagram, ttl=datagram.ttl - 1)
                hop = datagram.dst
                if self._routes[prefixes].next_hop:
                    hop = self._routes[prefixes].next_hop
                interface_list = self._routes[prefixes].interface_num
                self.interfaces[interface_list].send_datagram(new_datagram, hop)


    @property
    def routes(self) -> tuple[RouteEntry, ...]:
        """Return a read-only snapshot of the installed routes."""
        return tuple(self._routes.values())
