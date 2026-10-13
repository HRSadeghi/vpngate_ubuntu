"""Connectivity test of one relay with a real SoftEther handshake (port of ServerProbe.swift)."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from .pack import Pack, PackError
from .serverlist import VPNServer
from .stream import ByteStream, StreamError, TLSStream, protocol_error
from .ipcmessages import ProxySettings

# How many of a relay's ports are tried before giving up (Windows client's priority order).
MAX_PORTS = 3


@dataclass
class ProbeOutcome:
    state: str  # queued | testing | ok | failed
    port: int = 0
    connectMs: int = 0
    helloMs: int = 0
    build: int | None = None
    message: str = ""

    @property
    def is_ok(self) -> bool:
        return self.state == "ok"

    @staticmethod
    def sort_rank(o: "ProbeOutcome | None") -> int:
        """Ascending order = best first: working relays by connect time, then untested, then failed."""
        if o is None:
            return 2**63 - 2
        if o.state == "ok":
            return o.connectMs
        if o.state == "failed":
            return 2**63 - 1
        return 2**63 - 2


def ports_for(server: VPNServer) -> list[int]:
    out = list(server.prioritized_ssl_ports)
    if not out and server.connect_port is not None:
        out = [server.connect_port]
    if not out:
        out = [443]
    return out[:MAX_PORTS]


async def attempt(host: str, port: int, proxy: ProxySettings, timeout: float,
                  factory=None) -> ProbeOutcome:
    stream: ByteStream = (factory or (lambda h, p, px: TLSStream(h, p, px)))(host, port, proxy)

    async def handshake() -> ProbeOutcome:
        t0 = time.monotonic()

        def ms(since: float) -> int:
            return max(1, int((time.monotonic() - since) * 1000))

        try:
            await stream.start(timeout)
        except StreamError as e:
            raise protocol_error("No answer" if e.kind == "timeout" else e.message) from None
        connect_ms = ms(t0)
        # The plain marker is accepted by every SoftEther server, which is all that is needed
        # to make it say hello.
        body = b"VPNCONNECT"
        req = (f"POST /vpnsvc/connect.cgi HTTP/1.1\r\nHost: {host}\r\n"
               f"Content-Type: image/jpeg\r\nConnection: Keep-Alive\r\n"
               f"Content-Length: {len(body)}\r\n\r\n")
        try:
            await stream.send(req.encode() + body)
            head = await stream.recv_http_head()
            code = head.status_code or 0
            if code != 200:
                raise protocol_error(f"Not a VPN server (HTTP {code})")
            length = int(head.headers.get("content-length", "0") or 0)
            if not (0 < length < 1 << 20):
                raise protocol_error("Not a VPN server")
            pack = Pack.parse(await stream.recv(length))
            random = pack.data("random")
            if random is None or len(random) != 20:
                raise protocol_error("Not a SoftEther server")
            build = pack.int("build")
            return ProbeOutcome("ok", port=port, connectMs=connect_ms, helloMs=ms(t0),
                                build=build)
        except StreamError:
            raise protocol_error("Connected, but no VPN handshake") from None
        except PackError:
            raise protocol_error("Connected, but no VPN handshake") from None
        finally:
            stream.cancel()

    try:
        return await asyncio.wait_for(handshake(), timeout)
    except asyncio.TimeoutError:
        stream.cancel()
        return ProbeOutcome("failed", message=f"No answer in {int(timeout)} s")
    except StreamError as e:
        stream.cancel()
        return ProbeOutcome("failed", message=e.message)


async def run(host: str, ports: list[int], proxy: ProxySettings | None = None,
              timeout: float = 5, factory=None) -> ProbeOutcome:
    proxy = proxy or ProxySettings()
    last_error = "No port to test"
    for port in ports:
        outcome = await attempt(host, port, proxy, timeout, factory)
        if outcome.state == "ok":
            return outcome
        last_error = f"{outcome.message} (port {port})" if len(ports) > 1 else outcome.message
    return ProbeOutcome("failed", message=last_error)