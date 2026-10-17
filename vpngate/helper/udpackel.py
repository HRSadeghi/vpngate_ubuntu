"""SoftEther UDP Acceleration v2 (port of UdpAccel.swift), over an asyncio datagram socket.

Two-phase life cycle: `__init__` binds the local socket early (its port is advertised in the
login pack), and `configure` supplies the server's endpoint, cookies and key once the welcome
arrives. Sends run on the raw socket (thread-safe: send_frame is called from the TUN reader
thread); receives are event-driven through the loop's datagram endpoint.
"""

from __future__ import annotations

import asyncio
import os
import random
import socket
import time

from ..core.datphase import compress_frame, uncompress_frame
from ..core.udpackelpacket import (IV_SIZE, MIN_PACKET_SIZE, MIN_PLAINTEXT_SIZE,
                                   decode, encode, padding_size)
from .logutil import log


class UdpAccel:
    # UdpAccel.h: KEEPALIVE_INTERVAL_MIN/MAX/TIMEOUT (legacy) and the *_FAST variants.
    KEEP_ALIVE_INTERVAL_MS = (1000, 3000)        # rand() % (max - min) + min; maximum exclusive
    KEEP_ALIVE_INTERVAL_FAST_MS = (500, 1000)
    KEEP_ALIVE_TIMEOUT_MS = 9000
    KEEP_ALIVE_TIMEOUT_FAST_MS = 2100
    WINDOW_MS = 30_000
    # If the peer's echo of our own tick lags this far behind our last send, our outbound
    # datagrams are not arriving (inbound-only NAT path): stop sending data over UDP and let
    # TCP carry it, exactly like a download that freezes when the tunnel's ACKs vanish.
    # Healthy echo lag plateaus at the peer's keep-alive interval (~10 s) + RTT; a broken path
    # grows without bound, so 20 s separates the two cleanly without flapping.
    ECHO_LAG_MS = 20_000
    # How long packets must arrive without a gap before UDP carries data:
    # UDP_ACCELERATION_REQUIRE_CONTINUOUS (FirstStableReceiveTick + 10000 <= Now).
    STABLE_RECEIVE_MS = 10_000
    KEEP_ALIVE_MAX_SIZE = 1000
    DATA_MAX_SIZE = 1454 - 20 - 8
    MAX_INFLATED_SIZE = 4096

    def __init__(self, my_key_v2: bytes, clock=None) -> None:
        self.my_key_v2 = my_key_v2
        self.clock = clock or (lambda: int(time.monotonic_ns() // 1_000_000))
        self.your_key_v2 = b""
        self.my_cookie = 0
        self.your_cookie = 0
        self.dest: tuple[str, int] | None = None
        self.dest2: tuple[str, int] | None = None     # the TCP peer IP; keep-alives go there too while UDP is not usable
        self.use_compress = False
        self.plain_mode = False
        self.configured = False
        self.fast_disconnect = False

        self.next_iv = os.urandom(IV_SIZE)
        self._transport: asyncio.DatagramTransport | None = None
        self._socket: socket.socket | None = None
        self._started = False
        self._is_closed = False
        self.last_recv_tick = 0        # when the last valid packet arrived (local clock)
        self.last_recv_my_tick = 0     # highest of our own ticks the peer echoed back
        self.last_recv_your_tick = 0   # highest peer tick seen; echoed in everything we send
        self.last_sent_tick = 0        # our own clock value used in the last datagram we sent
        self.data_bytes_in = 0         # real data received over UDP — the data-plane proof
        self.first_stable_receive_tick = 0
        self._last_usable_logged: bool | None = None
        self._echo_lagged = False
        self._receive_gapped = False
        self._awaiting_data = False
        self._force_tcp = False
        self._keepalive_task: asyncio.Task | None = None

        self.on_frame = None
        self.on_byte_count = None

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.setblocking(False)
        try:
            self._socket.bind(("0.0.0.0", 0))
        except OSError:
            self._socket.close()
            self._socket = None
            self._is_closed = True

    @property
    def local_port(self) -> int:
        if self._socket is None:
            return 0
        try:
            return self._socket.getsockname()[1]
        except OSError:
            return 0

    @property
    def last_peer_tick(self) -> int:
        return self.last_recv_your_tick

    @property
    def is_socket_closed(self) -> bool:
        return self._is_closed or self._socket is None

    def configure(self, server_ip: str, server_port: int, my_cookie: int, your_cookie: int,
                  your_key_v2: bytes, fast_disconnect: bool, use_compress: bool = False,
                  plaintext: bool = False, secondary_ip: str | None = None) -> bool:
        """Supplies the server side. Fails (UDP stays off, TCP carries on) for a non-literal or
        unspecified address, port 0, or (unless plaintext) a key shorter than 32 bytes."""
        if (server_port == 0 or (not plaintext and len(your_key_v2) < 32)
                or not _valid_ipv4(server_ip) or _ipv4_value(server_ip) == 0):
            return False
        dest2 = None
        if secondary_ip is not None and _valid_ipv4(secondary_ip) and _ipv4_value(secondary_ip) != 0:
            dest2 = (secondary_ip, server_port)
        if self._is_closed:
            return False
        self.dest = (server_ip, server_port)
        self.dest2 = dest2
        self.use_compress = use_compress
        self.plain_mode = plaintext
        self.my_cookie = my_cookie
        self.your_cookie = your_cookie
        self.your_key_v2 = your_key_v2
        self.fast_disconnect = fast_disconnect
        self.configured = True
        return True

    @property
    def is_usable(self) -> bool:
        usable = self._usable_state
        if usable != self._last_usable_logged:
            self._last_usable_logged = usable
            reason = ("forced to TCP (the UDP data path collapsed)" if self._force_tcp
                      else ("echo lag (our datagrams are not arriving)" if self._echo_lagged
                            else ("no UDP data received yet" if self._awaiting_data
                                  else ("receive gap" if self._receive_gapped
                                        else "stable receive period"))))
            log("[udp]", f"acceleration {'USABLE' if usable else 'NOT usable'} ({reason})")
        return usable

    def force_tcp(self) -> None:
        """The UDP data path collapsed mid-session (heavy loss after some volume): keep
        the socket for keep-alives but never carry data on it again — TCP recovers where
        a lossy UDP stream cannot."""
        self._force_tcp = True

    @property
    def _usable_state(self) -> bool:
        self._echo_lagged = False
        self._receive_gapped = False
        self._awaiting_data = False
        if self._force_tcp:
            return False
        if self._is_closed or not self.configured or self.last_recv_tick == 0 \
                or self.first_stable_receive_tick == 0:
            self._receive_gapped = True
            return False
        now = self.clock()
        timeout = self.KEEP_ALIVE_TIMEOUT_FAST_MS if self.fast_disconnect else self.KEEP_ALIVE_TIMEOUT_MS
        if now < self.last_recv_tick or now - self.last_recv_tick > timeout:
            self.first_stable_receive_tick = 0
            self._receive_gapped = True
            return False
        # Keep-alives are tiny and routinely pass where large data datagrams are dropped
        # (DPI/MTU): a "stable receive period" of control packets proved nothing about the
        # data path and made the tunnel one-way (out over UDP, back over TCP). Only ever
        # accelerate after real data has actually arrived over UDP.
        if self.data_bytes_in == 0:
            self._awaiting_data = True
            return False
        # One-way breakage: both tick values come from OUR clock, so the lag needs no skew
        # correction. While the echo lags, our data is not arriving — TCP takes over.
        if self.last_sent_tick and self.last_sent_tick - self.last_recv_my_tick > self.ECHO_LAG_MS:
            self.first_stable_receive_tick = 0  # require a fresh stable period before reuse
            self._echo_lagged = True
            return False
        return now >= self.first_stable_receive_tick \
            and now - self.first_stable_receive_tick >= self.STABLE_RECEIVE_MS

    def start(self) -> None:
        if not self.configured or self._is_closed or self._started or self._socket is None:
            return
        self._started = True
        loop = asyncio.get_running_loop()
        accel = self

        class Proto(asyncio.DatagramProtocol):
            def connection_made(self, transport: asyncio.DatagramTransport) -> None:
                self.transport = transport

            def datagram_received(self, data, addr) -> None:
                if not accel._is_closed:
                    accel.handle_datagram(data, (addr[0], addr[1]))

        # Adopt the pre-bound socket: the advertised port is kept, receives become event-driven.
        async def adopt() -> None:
            try:
                self._transport, _protocol = await loop.create_datagram_endpoint(
                    Proto, sock=self._socket)
            except Exception:
                self._is_closed = True

        loop.create_task(adopt())
        self._keepalive_task = loop.create_task(self._keepalive_loop())

    def stop(self) -> None:
        if self._is_closed:
            return
        self._is_closed = True
        if self._transport is not None:
            try:
                self._transport.close()
            except Exception:
                pass
            self._transport = None
        # create_datagram_endpoint closed the socket with the transport.
        self._socket = None
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
            self._keepalive_task = None

    # MARK: send

    def send_frame(self, frame: bytes) -> bool:
        if not self.is_usable:
            return False
        if self.use_compress:
            # Session UseCompress: every block is zlib-compressed and flagged (Session.c:517).
            try:
                z = compress_frame(frame)
            except Exception:
                return False
            return self._send_packet(compressed=True, payload=z, max_size=self.DATA_MAX_SIZE)
        return self._send_packet(compressed=False, payload=frame, max_size=self.DATA_MAX_SIZE)

    def _send_packet(self, compressed: bool, payload: bytes, max_size: int) -> bool:
        # The whole encrypt+send runs under one synchronous block: the IV chain must never hand
        # the same nonce to two senders. socket.sendto is thread-safe (send_frame may be called
        # from the TUN reader thread).
        if self._is_closed or not self.configured or self._socket is None or self.dest is None:
            return False
        pad = padding_size(data_size=len(payload), max_size=max_size)
        try:
            my_tick = self.clock()
            packet, self.next_iv = encode(
                key32=self.my_key_v2, iv=self.next_iv, cookie=self.your_cookie,
                my_tick=my_tick, your_tick=self.last_recv_your_tick,
                compressed=compressed, payload=payload, padding_size=pad,
                plain_mode=self.plain_mode)
            self.last_sent_tick = my_tick
        except Exception:
            return False
        sent = self._send_datagram(packet, self.dest)
        # Keep-alive while UDP is not usable: the peer may sit behind a NAT, so also try the TCP
        # peer IP (UdpAccel.c:625-651).
        if not payload and self.dest2 is not None and self.dest2[0] != self.dest[0] and not self.is_usable:
            self._send_datagram(packet, (self.dest2[0], self.dest[1]))
        if sent and self.on_byte_count:
            self.on_byte_count(0, len(payload))
        return sent

    def _send_datagram(self, packet: bytes, dest: tuple[str, int]) -> bool:
        if self._socket is None:
            return False
        try:
            self._socket.sendto(packet, dest)
            return True
        except OSError:
            return False

    # MARK: receive

    def handle_datagram(self, raw: bytes, from_addr: tuple[str, int]) -> None:
        """Validates one received datagram (AEAD tag, cookie, tick window) and delivers its payload."""
        if self._is_closed or not self.configured:
            return
        min_size = MIN_PLAINTEXT_SIZE if self.plain_mode else MIN_PACKET_SIZE
        if len(raw) < min_size:
            return
        try:
            decoded = decode(packet=raw, key32=self.your_key_v2, plain_mode=self.plain_mode)
        except Exception:
            return
        if decoded.header.cookie != self.my_cookie:
            return
        h = decoded.header
        now = self.clock()
        timeout = self.KEEP_ALIVE_TIMEOUT_FAST_MS if self.fast_disconnect else self.KEEP_ALIVE_TIMEOUT_MS
        # Upstream drops a packet whose tick is a full window older than the newest peer tick seen.
        if h.my_tick < self.last_recv_your_tick and self.last_recv_your_tick - h.my_tick >= self.WINDOW_MS:
            return
        if self.last_recv_tick != 0 and now >= self.last_recv_tick \
                and now - self.last_recv_tick > timeout:
            self.first_stable_receive_tick = 0  # gap: stability restarts
        newest = h.my_tick > self.last_recv_your_tick
        self.last_recv_my_tick = max(self.last_recv_my_tick, h.your_tick)
        self.last_recv_your_tick = max(self.last_recv_your_tick, h.my_tick)
        if newest and self.dest is not None:
            # The peer (or its NAT mapping) moved: follow authenticated packets only.
            self.dest = (from_addr[0], self.dest[1])
        if self.last_recv_my_tick != 0 and now >= self.last_recv_my_tick \
                and now - self.last_recv_my_tick < self.WINDOW_MS:
            self.last_recv_tick = now
            if self.first_stable_receive_tick == 0:
                self.first_stable_receive_tick = now

        # Every non-empty payload is data; an empty one is a keep-alive. A nonzero flag means zlib.
        if not decoded.payload:
            return
        self.data_bytes_in += len(decoded.payload)
        if self.on_byte_count:
            self.on_byte_count(len(decoded.payload), 0)
        if h.compressed:
            try:
                frame = uncompress_frame(decoded.payload, max_len=self.MAX_INFLATED_SIZE)
            except Exception:
                return
            if not frame:
                return
            if self.on_frame:
                self.on_frame(frame)
        else:
            if self.on_frame:
                self.on_frame(decoded.payload)

    # MARK: keep-alive

    async def _keepalive_loop(self) -> None:
        while not self._is_closed:
            lo, hi = self.KEEP_ALIVE_INTERVAL_FAST_MS if self.fast_disconnect \
                else self.KEEP_ALIVE_INTERVAL_MS
            delay_ms = random.randrange(lo, hi)
            self._send_packet(compressed=False, payload=b"", max_size=self.KEEP_ALIVE_MAX_SIZE)
            await asyncio.sleep(delay_ms / 1000.0)


def _valid_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or int(p) > 255:
            return False
    return True


def _ipv4_value(s: str) -> int:
    a, b, c, d = (int(x) for x in s.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d