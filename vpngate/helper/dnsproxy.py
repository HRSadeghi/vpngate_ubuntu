"""DNS proxy for routing-rule aware resolution (port of DNSProxy.swift).

A domain explicitly marked `.direct` is asked of the physical network's own resolver (never
the tunnel's), `.block` gets NXDOMAIN with no query sent anywhere, and everything else (the
default, `.proxy`) goes to the tunnel's own resolver — so nothing but `.direct` domains ever
reaches an ISP-controlled resolver. Every resolved address is also handed to NetConfig so the
matching route exists before the answer reaches the asking app.
"""

from __future__ import annotations

import asyncio
import socket

from ..core.routing import RoutingAction, RoutingConfig, RoutingMatcher
from . import dnsmessage
from .netconfig import NetConfig


class DNSUpstream:
    """A plain UDP DNS client: one query, one answer, no retries (the asker will retry)."""

    async def query(self, message: bytes, server: str, timeout_ms: int) -> bytes | None:
        """One-shot UDP DNS exchange with `server`."""
        loop = asyncio.get_running_loop()

        class Proto(asyncio.DatagramProtocol):
            def __init__(self) -> None:
                self.queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=1)
                self.transport = None

            def connection_made(self, transport: asyncio.DatagramTransport) -> None:
                self.transport = transport

            def datagram_received(self, data, addr) -> None:
                if not self.queue.full():
                    self.queue.put_nowait(data)

        try:
            infos = await loop.getaddrinfo(server, 53, family=socket.AF_INET, type=socket.SOCK_DGRAM)
        except Exception:
            return None
        if not infos:
            return None
        dest = infos[0][4]
        proto = Proto()
        try:
            transport, _ = await loop.create_datagram_endpoint(lambda: proto, remote_addr=dest)
        except Exception:
            return None
        try:
            transport.sendto(message)
            return await asyncio.wait_for(proto.queue.get(), timeout_ms / 1000.0)
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None
        finally:
            try:
                transport.close()
            except Exception:
                pass


class DNSProxy:
    class Settings:
        def __init__(self, listen_address: str = "127.0.0.1", port: int = 53, timeout_ms: int = 4000):
            self.listen_address = listen_address
            self.port = port
            self.timeout_ms = timeout_ms

    def __init__(self, net: NetConfig, upstream: DNSUpstream | None = None,
                 settings: "DNSProxy.Settings | None" = None,
                 block_ipv6: bool = False) -> None:
        self.net = net
        self.upstream = upstream or DNSUpstream()
        self.settings = settings or self.Settings()
        self.routing = RoutingConfig()
        # When IPv6 is blocked in the tunnel, AAAA answers must NOT reach apps: they would
        # pick v6 addresses and fail (the tunnel drops v6). Answer AAAA with NODATA so
        # everything falls back to IPv4 — the standard "block IPv6" DNS behaviour.
        self.block_ipv6 = block_ipv6
        self.tunnel_dns_servers: list[str] = []
        self.direct_dns_servers: list[str] = []
        self._transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.AbstractServer | None = None
        self._running = False

    @property
    def listen_address(self) -> str:
        return self.settings.listen_address

    @property
    def is_listening(self) -> bool:
        return self._running

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        proxy = self

        class Proto(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.DatagramTransport) -> None:
                self.transport = transport

            def datagram_received(self, data, addr) -> None:
                loop.create_task(proxy._serve_one(data, addr))

        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                Proto, local_addr=(self.settings.listen_address, self.settings.port))
        except OSError as e:
            raise RuntimeError(
                f"dns proxy bind {self.settings.listen_address}:{self.settings.port}: {e}") from None
        # TCP is not optional for a DNS server: systemd-resolved retries over TCP whenever a
        # UDP answer looks off (truncated, no OPT) and loops forever when nothing answers.
        try:
            self._tcp_server = await asyncio.start_server(
                self._serve_tcp, self.settings.listen_address, self.settings.port)
        except OSError as e:
            raise RuntimeError(
                f"dns proxy TCP bind {self.settings.listen_address}:{self.settings.port}: {e}") from None
        self._running = True

    def stop(self) -> None:
        self._running = False
        t = self._transport
        self._transport = None
        if t is not None:
            try:
                t.close()
            except Exception:
                pass
        srv = self._tcp_server
        self._tcp_server = None
        if srv is not None:
            try:
                srv.close()
            except Exception:
                pass

    async def _serve_tcp(self, reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter) -> None:
        """DNS over TCP (RFC 7766): 2-byte length prefix per message."""
        try:
            while self._running:
                hdr = await reader.readexactly(2)
                n = int.from_bytes(hdr, "big")
                if n == 0:
                    break
                message = await reader.readexactly(n)
                response = await self.handle(message)
                writer.write(len(response).to_bytes(2, "big") + response)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            pass
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _serve_one(self, query: bytes, addr) -> None:
        response = await self.handle(query)
        if self._transport is not None:
            self._transport.sendto(response, addr)

    async def handle(self, query: bytes) -> bytes:
        """The decision-and-forward logic for one query, with no socket involved."""
        # A query this helper cannot even parse the name of must never be guessed at: fail closed.
        name = dnsmessage.query_name(query)
        if name is None:
            return dnsmessage.servfail_response(query)
        rule = RoutingMatcher.match_domain(name, self.routing)
        if rule is not None and rule.action == RoutingAction.block:
            return dnsmessage.blocked_response(query)
        if self.block_ipv6 and dnsmessage.query_type(query) == 28:  # AAAA
            # NODATA (RCODE 0, zero answers): apps fall back to the A record.
            return dnsmessage.noerror_nodata_response(query)
        servers = self.direct_dns_servers if (rule is not None and rule.action == RoutingAction.direct) \
            else self.tunnel_dns_servers
        if not servers:
            return dnsmessage.servfail_response(query)
        qtype = dnsmessage.query_type(query)
        # Some upstream resolvers answer DO=1 (EDNS DNSSEC) queries with an empty section;
        # the same question without the DO bit gets the real records. Nothing here validates
        # DNSSEC, so the DO bit is simply not forwarded.
        response = await self.upstream.query(dnsmessage.strip_do_bit(query),
                                             servers[0], self.settings.timeout_ms)
        if response is not None and not dnsmessage.resolved_ipv4_addresses(response) \
                and qtype == 1 and dnsmessage.header(response) \
                and dnsmessage.header(response)[0] == 0:
            # Empty A answer: an EDNS-hostile middlebox. Retry as a plain-DNS query.
            response2 = await self.upstream.query(dnsmessage.strip_edns(query),
                                                  servers[0], self.settings.timeout_ms)
            if response2 is not None:
                response = response2
        if response is None:
            return dnsmessage.servfail_response(query)
        # Only for an address a rule explicitly decided on — the structural routes already do
        # the right thing for everything else.
        if rule is not None:
            for ip in dnsmessage.resolved_ipv4_addresses(response):
                self.net.apply_dynamic_rule(ip=ip, action=rule.action)
        return response