"""Byte stream under the SoftEther protocol (port of TLSStream.swift).

TLS runs on a blocking SSLSocket driven through the loop's executor, and HTTP CONNECT /
SOCKS5 proxy tunnels are built on plain blocking sockets the same way. One implementation,
identical behaviour on every Python version (an asyncio start_tls-based variant broke on
3.13's rewritten SSL internals). By default the TLS layer accepts the self-signed
certificates VPN Gate relays use; a ServerCertPolicy can pin the leaf certificate's
SHA-1/SHA-256 fingerprint or require system trust.
"""

from __future__ import annotations

import asyncio
import base64
import socket
import ssl
import struct

from .bytebuffer import ByteBuffer
from .certpin import ServerCertPolicy, ServerCertPolicyKind
from .httphead import HTTPHead, TERMINATOR, MAX_SIZE
from .packets import rd32
from .ipcmessages import ProxySettings


class StreamError(Exception):
    def __init__(self, message: str, kind: str = "protocol") -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind  # "closed" | "timeout" | "protocol"

    @property
    def description(self) -> str:
        return self.message


def closed_error() -> StreamError:
    return StreamError("Connection closed", "closed")


def timeout_error() -> StreamError:
    return StreamError("Timed out", "timeout")


def protocol_error(message: str) -> StreamError:
    return StreamError(message, "protocol")


class ByteStream:
    """Byte stream under the SoftEther protocol."""

    def __init__(self) -> None:
        self.buffer = ByteBuffer()
        self.remote_ipv4: str | None = None
        self._closed = False

    async def start(self, timeout: float = 15) -> None:
        raise NotImplementedError

    async def send(self, data: bytes) -> None:
        raise NotImplementedError

    async def read_chunk(self) -> bytes:
        """Reads whatever the transport has next (at least 1 byte) or raises."""
        raise NotImplementedError

    def cancel(self) -> None:
        self._closed = True

    async def recv(self, n: int) -> bytes:
        while self.buffer.count < n:
            self.buffer.append(await self.read_chunk())
        return self.buffer.take(n) or b""

    async def recv_u32(self) -> int:
        return rd32(await self.recv(4), 0)

    async def recv_http_head(self) -> HTTPHead:
        while True:
            head = self.buffer.take_up_to(TERMINATOR)
            if head is not None:
                return HTTPHead.parse(head)
            if self.buffer.count > MAX_SIZE:
                raise protocol_error("HTTP header too large")
            self.buffer.append(await self.read_chunk())


def _ssl_context(policy: ServerCertPolicy) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # SoftEther relays negotiate legacy suites (AES128-SHA); the distribution defaults reject them.
    ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    if policy.kind == ServerCertPolicyKind.systemTrust:
        return ctx  # default verification
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _is_ip(host: str) -> bool:
    if host.count(".") == 3 and all(p.isdigit() for p in host.split(".")):
        return True
    return ":" in host  # IPv6 literal


def _connect_socket(proxy: ProxySettings, host: str, port: int, timeout: float) -> socket.socket:
    """Opens the raw TCP connection — directly, or through an HTTP CONNECT / SOCKS5 tunnel.
    Blocking; runs on an executor thread."""
    if proxy.kind != ProxySettings.KIND_NONE and proxy.host:
        sock = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
        try:
            _handshake_proxy(sock, proxy, host, port)
        except Exception:
            sock.close()
            raise
        return sock
    return socket.create_connection((host, port), timeout=timeout)


def _handshake_proxy(sock: socket.socket, proxy: ProxySettings, host: str, port: int) -> None:
    if not (1 <= proxy.port <= 65535):
        raise StreamError("Invalid proxy port")
    if proxy.kind == ProxySettings.KIND_HTTP:
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        if proxy.username:
            creds = base64.b64encode(f"{proxy.username}:{proxy.password or ''}".encode()).decode()
            req += f"Proxy-Authorization: Basic {creds}\r\n"
        req += "\r\n"
        sock.sendall(req.encode())
        head = _recv_until(sock, b"\r\n\r\n")
        status = head.split(b"\r\n")[0].decode("latin-1", "replace")
        parts = status.split(" ")
        if len(parts) < 2 or parts[1] != "200":
            raise protocol_error(
                f"Connection to the proxy server failed (HTTP {parts[1] if len(parts) > 1 else status})")
        return
    if proxy.kind == ProxySettings.KIND_SOCKS5:
        sock.sendall(b"\x05\x02\x00\x02" if proxy.username else b"\x05\x01\x00")
        resp = _recv_exact(sock, 2)
        if resp[0] != 5:
            raise protocol_error("Connection to the proxy server failed (bad SOCKS version)")
        if resp[1] == 2:  # username/password auth (RFC 1929)
            u = proxy.username.encode()[:255]
            p = (proxy.password or "").encode()[:255]
            sock.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
            auth = _recv_exact(sock, 2)
            if auth[1] != 0:
                raise protocol_error("Failed to authenticate on the proxy server")
        elif resp[1] != 0:
            raise protocol_error("Connection to the proxy server failed (no acceptable auth)")
        addr = host.encode()[:255]
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + struct.pack(">H", port))
        reply = _recv_exact(sock, 4)
        if reply[1] != 0:
            raise protocol_error("Connection to the proxy server failed (SOCKS error)")
        if reply[3] == 1:
            _recv_exact(sock, 4 + 2)
        elif reply[3] == 4:
            _recv_exact(sock, 16 + 2)
        elif reply[3] == 3:
            ln = _recv_exact(sock, 1)[0]
            _recv_exact(sock, ln + 2)
        return
    raise protocol_error("Unsupported proxy type")


def _recv_until(sock: socket.socket, marker: bytes, limit: int = 65536) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise closed_error()
        data += chunk
        if len(data) > limit:
            raise protocol_error("Proxy response too large")
    return data


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise closed_error()
        data += chunk
    return data


def _describe_ssl_error(e: Exception) -> str:
    if isinstance(e, ssl.SSLCertVerificationError):
        return "Server certificate is not trusted"
    text = str(e)
    if "certificate verify failed" in text:
        return "Server certificate is not trusted: " + text
    return text


class TLSStream(ByteStream):
    def __init__(self, host: str, port: int, proxy: ProxySettings,
                 policy: ServerCertPolicy | None = None) -> None:
        super().__init__()
        self.host = host
        self.port = int(port)
        self.proxy = proxy
        self.policy = policy or ServerCertPolicy(ServerCertPolicyKind.acceptAny)
        # A server name with letters that is not an IP literal gets an SNI.
        self._use_sni = any(c.isalpha() for c in host) and "." in host and not _is_ip(host)
        self._ssl_sock: ssl.SSLSocket | None = None
        self._raw_sock: socket.socket | None = None
        # Data frames (pool.send) and keep-alives (broadcast) run on separate executor
        # threads; SSL writes must never interleave inside one socket.
        self._send_lock = asyncio.Lock()

    async def start(self, timeout: float = 15) -> None:
        # The deadline must bound the blocking connect/handshake too: the work runs on an
        # executor thread, and a cancelled await does NOT stop that thread — probes test
        # many servers concurrently and would pile up zombie threads on dead hosts.
        self._timeout = timeout
        try:
            await asyncio.wait_for(self._start(), timeout)
        except asyncio.TimeoutError:
            self.cancel()
            raise timeout_error()

    def _start_blocking(self) -> ssl.SSLSocket:
        connect_timeout = min(getattr(self, "_timeout", 15.0) or 15.0, 15.0)
        raw = _connect_socket(self.proxy, self.host, self.port, connect_timeout)
        # macOS parity (NWProtocolTCP.Options): small frames (the tunnel's ACKs) must not sit
        # in a Nagle delay during heavy transfers, and dead peers must surface via keep-alives.
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Large buffers for high-latency links: at 200ms RTT (Iran→Japan), the default
        # 16KB wmem/rcvbuf limits throughput to ~0.6 Mbps. 512KB allows ~20 Mbps.
        # These are the socket-level limits; the kernel auto-tunes up to tcp_rmem/wmem max.
        try:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 512 * 1024)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 512 * 1024)
        except OSError:
            pass
        # ACK small writes immediately on our side as well (Linux resets QUICKACK after a
        # while, but it shortens the worst stalls right after the handshake).
        try:
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        except OSError:
            pass
        # The TLS handshake honours the deadline as well.
        raw.settimeout(connect_timeout)
        self._raw_sock = raw
        ctx = _ssl_context(self.policy)
        server_name = self.host if self._use_sni else None
        try:
            ssl_sock = ctx.wrap_socket(raw, server_hostname=server_name)
        except ssl.SSLEOFError:
            # The server (or a middlebox) dropped the TCP connection mid-handshake —
            # SoftEther's own wording for this is ERR_CONNECT_FAILED.
            raise protocol_error(
                "Connection to the server has failed (TLS handshake was aborted)") from None
        except Exception as e:
            raise protocol_error(f"TLS handshake failed: {_describe_ssl_error(e)}") from None
        # Certificate pinning / system-trust rejection, with the presented leaf.
        if self.policy.kind in (ServerCertPolicyKind.pinned, ServerCertPolicyKind.systemTrust):
            der = None
            try:
                der = ssl_sock.getpeercert(binary_form=True)
            except Exception:
                pass
            why = self.policy.rejection(der)
            if why:
                ssl_sock.close()
                self._raw_sock = None
                raise protocol_error(why)
        ssl_sock.settimeout(None)  # cancel() closes the socket to unblock reads
        return ssl_sock

    async def _start(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            self._ssl_sock = await loop.run_in_executor(None, self._start_blocking)
        except StreamError:
            raise
        except (OSError, socket.gaierror) as e:
            raise protocol_error(_describe_os_error(e)) from None
        peer = self._ssl_sock.getpeername()
        if isinstance(peer, tuple) and len(peer) == 2 and isinstance(peer[0], str) \
                and peer[0].count(".") == 3:
            self.remote_ipv4 = peer[0]

    async def send(self, data: bytes) -> None:
        sock = self._ssl_sock
        if sock is None or self._closed:
            raise closed_error()
        loop = asyncio.get_running_loop()
        async with self._send_lock:
            if self._ssl_sock is not None and self._ssl_sock is not sock:
                raise closed_error()  # the stream was cancelled while we waited
            try:
                await loop.run_in_executor(None, sock.sendall, data)
            except ssl.SSLEOFError:
                # The server closed the connection without a TLS close_notify (volunteer
                # relays reap sessions): a plain disconnect, the session reconnects.
                raise closed_error() from None
            except (OSError, ssl.SSLError) as e:
                if self._closed:
                    raise closed_error() from None
                raise protocol_error(_describe_os_error(e)) from None

    async def read_chunk(self) -> bytes:
        sock = self._ssl_sock
        if sock is None or self._closed:
            raise closed_error()
        loop = asyncio.get_running_loop()
        try:
            chunk = await loop.run_in_executor(None, sock.recv, 65536)
        except (OSError, ssl.SSLError):
            if self._closed:
                raise closed_error() from None
            raise closed_error() from None
        if not chunk:
            raise closed_error()
        return chunk

    def cancel(self) -> None:
        self._closed = True
        ssl_sock = self._ssl_sock
        self._ssl_sock = None
        raw = self._raw_sock
        self._raw_sock = None
        for sock in (ssl_sock, raw):
            if sock is None:
                continue
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


def _describe_os_error(e: Exception) -> str:
    if isinstance(e, ssl.SSLEOFError):
        return "Connection closed"
    if isinstance(e, ConnectionRefusedError):
        return "Connection refused"
    if isinstance(e, socket.gaierror):
        return "Name or service not known"
    if isinstance(e, (TimeoutError, socket.timeout)):
        return "Timed out"
    if isinstance(e, ConnectionResetError):
        return "Connection reset"
    return str(e) or e.__class__.__name__