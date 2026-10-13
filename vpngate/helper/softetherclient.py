"""SoftEther SSL-VPN client with full protocol parity (port of SoftEtherClient.swift):
multi-TCP pool, compression, UDP acceleration v2, auth, cluster redirect.
Protocol reference: SoftEtherVPN src/Cedar/Protocol.c, Connection.c, UdpAccel.c."""

from __future__ import annotations

import asyncio
import os
import platform
import random
import socket
from dataclasses import dataclass

from ..core import validation
from ..core.certpin import ServerCertPolicy, ServerCertPolicyKind
from ..core.datphase import encode_keep_alive, encode_frames, MAX_BLOCK
from ..core.ipcmessages import ProxySettings
from ..core.pack import Pack
from ..core.packets import packIPString
from ..core.sha0 import hash as sha0
from ..core.softether_error import describe
from ..core.stream import ByteStream, StreamError, TLSStream, closed_error, protocol_error
from ..core.watermark import SOFT_ETHER_WATERMARK
from .connectionpool import ConnectionPool, SocketDirection
from .logutil import log
from .certauth import signer as cert_signer
from .hostuniqueid import HostUniqueId
from .udpackel import UdpAccel

DEFAULT_HUB_NAME = "VPNGATE"
DEFAULT_USER_NAME = "vpn"
CLIENT_VER = 444
CLIENT_BUILD = 9807
MAX_PENDING_FRAMES = 4096  # frames waiting for the TCP pool; beyond this they are dropped


class ClientAuth:
    ANONYMOUS = "anonymous"
    PLAIN_PASSWORD = "plain"
    HASHED_PASSWORD = "hashed"
    CERTIFICATE = "cert"
    TICKET = "ticket"


@dataclass
class Welcome:
    session_name: str
    connection_name: str
    timeout_ms: int = 30000
    message: bytes | None = None
    session_key: bytes | None = None
    max_connection: int = 1
    use_compress: bool = False
    use_encrypt: bool = True
    half_connection: bool = False
    qos: bool = False
    enable_udp_recovery: bool = False
    use_udp_acceleration: bool = False
    udp_accel_version: int = 1
    udp_server_ip: str | None = None
    udp_server_port: int | None = None
    udp_server_cookie: int | None = None
    udp_client_cookie: int | None = None
    udp_server_key: bytes | None = None
    udp_fast_disconnect: bool = False


def ascii_uppercased(s: str) -> str:
    """Upstream `Upper()` only maps a-z; Python's upper() would also change non-ASCII letters."""
    return "".join(chr(ord(c) - 32) if "a" <= c <= "z" else c for c in s)


def negotiated_max_connection(server: int, enable_udp_recovery: bool, client: int,
                              qos: bool, half: bool) -> int:
    """Session size per upstream (Protocol.c ClientConnectGetSessionKey)."""
    n = server
    if not enable_udp_recovery:
        n = min(n, client)
    n = max(1, min(n, 32))
    if qos:
        n = max(n, 4 if half else 2)
    return n


def valid_port(raw: int) -> int | None:
    return raw if 0 < raw < 65536 else None


def is_ipv6_flagged(w: Pack, name: str) -> bool:
    return (w.int(name + "@ipv6_bool") or 0) != 0


def redirect_host(w: Pack, fallback: str) -> str:
    """Redirect target from the pack's `Ip`: a hostname/IPv4 string, or SoftEther's pack integer."""
    if is_ipv6_flagged(w, "Ip"):
        raise protocol_error("Cluster redirect to an IPv6 address is not supported")
    ip_str = w.str("Ip")
    if ip_str:
        candidate = ip_str
    else:
        ip_int = w.int("Ip")
        if ip_int is None:
            return fallback
        candidate = packIPString(ip_int)
    if not validation.is_valid_host(candidate):
        raise protocol_error("Cluster redirect to an invalid host")
    return fallback if candidate == "0.0.0.0" else candidate


def resolve_udp_server_ip(advertised: str | None, tcp_host: str) -> str | None:
    """The UDP endpoint: the advertised IPv4 if it is a public literal, else the TCP peer."""
    if advertised and validation.is_ipv4_literal(advertised) and not validation.is_non_public_ipv4(advertised):
        return advertised
    return tcp_host if validation.is_ipv4_literal(tcp_host) else None


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


class SoftEtherClient:
    def __init__(self, host: str, port: int, hub_name: str = DEFAULT_HUB_NAME,
                 user_name: str = DEFAULT_USER_NAME, auth: str = ClientAuth.ANONYMOUS,
                 password: str | None = None, cert_der: bytes | None = None,
                 private_key_der: bytes | None = None, ticket: bytes | None = None,
                 proxy: ProxySettings | None = None, max_connections: int = 8,
                 use_compress: bool = False, use_udp_accel: bool = True,
                 disable_qos: bool = False, half_connection: bool = False,
                 unique_id: HostUniqueId | None = None,
                 server_cert_policy: ServerCertPolicy | None = None,
                 make_stream=None) -> None:
        self.host = host
        self.port = int(port)
        self.hub_name = hub_name
        self.user_name = user_name
        self.auth = auth
        self.password = password
        self.cert_der = cert_der
        self.private_key_der = private_key_der
        self.ticket = ticket
        self.proxy = proxy or ProxySettings()
        # Half connection needs separate send/receive sockets; request at least 4 (upstream's
        # own minimum, Protocol.c:6022).
        self.max_connections_config = max(4 if half_connection else 1, min(max_connections, 32))
        self.use_compress_config = use_compress
        self.use_udp_accel_config = use_udp_accel
        self.disable_qos = disable_qos
        self.half_connection_config = half_connection
        uid = unique_id or HostUniqueId.load()
        self.login_unique_id = uid.login_id
        self.node_unique_id = uid.node_id
        self.server_cert_policy = server_cert_policy or ServerCertPolicy(ServerCertPolicyKind.acceptAny)
        self._make_stream = make_stream or (
            lambda h, p, px: TLSStream(h, p, px, policy=self.server_cert_policy))

        self.welcome: Welcome | None = None
        self.plain_signature = False
        self.connected_ipv4: str | None = None

        self.pool = ConnectionPool()
        self.pool.on_frame = self._pool_frame
        self.pool.on_close = self._pool_closed
        self.pool.on_byte_count = self._pool_bytes

        self.udp_accel: UdpAccel | None = None
        self._replenish_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task | None = None
        self._replenish_interval = 1.0

        # The TUN reader thread calls send_frame(), so the outbound queue uses a threading lock
        # and the flush is handed to the session's event loop.
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None
        self._queue_lock = __import__("threading").Lock()
        self._pending: list[bytes] = []
        self._flushing = False
        self._closed = False
        self._dropped_frames = 0
        self._bytes_in = 0
        self._bytes_out = 0
        # Per-transport accounting: which path (UDP acceleration vs TCP pool) carries the data.
        self._in_tcp = 0
        self._in_udp = 0
        self._out_tcp = 0
        self._out_udp = 0
        self._last_path = ""

        self.on_frame = None       # callback(bytes)
        self.on_close = None       # callback(error | None)

    # MARK: stats

    @property
    def bytes_in(self) -> int:
        return self._bytes_in

    @property
    def bytes_out(self) -> int:
        return self._bytes_out

    def _add_in(self, n: int) -> None:
        self._bytes_in += n

    def _add_out(self, n: int) -> None:
        self._bytes_out += n

    @property
    def is_closed(self) -> bool:
        return self._closed

    @property
    def dropped_frames(self) -> int:
        return self._dropped_frames

    @property
    def pending_frame_count(self) -> int:
        return len(self._pending)

    @property
    def active_connection_count(self) -> int:
        return self.pool.active_count

    @property
    def udp_local_port(self) -> int:
        return self.udp_accel.local_port if self.udp_accel else 0

    @property
    def udp_accel_usable(self) -> bool:
        return self.udp_accel.is_usable if self.udp_accel else False

    @property
    def udp_accel_negotiated(self) -> bool:
        return self.udp_accel is not None

    def _pool_frame(self, frame: bytes) -> None:
        if self.on_frame:
            self.on_frame(frame)

    def _pool_closed(self, error) -> None:
        self.close(error)

    def _pool_bytes(self, bytes_in: int, bytes_out: int) -> None:
        if bytes_in > 0:
            self._add_in(bytes_in)
            self._in_tcp += bytes_in
        if bytes_out > 0:
            self._add_out(bytes_out)
            self._out_tcp += bytes_out

    def _udp_bytes(self, bytes_in: int, bytes_out: int) -> None:
        if bytes_in > 0:
            self._add_in(bytes_in)
            self._in_udp += bytes_in
        if bytes_out > 0:
            self._add_out(bytes_out)
            self._out_udp += bytes_out

    def stats(self) -> dict:
        """Snapshot for the periodic throughput log."""
        return {
            "in_tcp": self._in_tcp, "in_udp": self._in_udp,
            "out_tcp": self._out_tcp, "out_udp": self._out_udp,
            "in": self._bytes_in, "out": self._bytes_out,
            "sockets": self.pool.active_count,
            "udp_negotiated": self.udp_accel_negotiated,
            "udp_usable": self.udp_accel_usable,
            "path": self._last_path,
            "dropped": self._dropped_frames,
        }

    # MARK: handshake & cluster redirect

    async def connect(self, log) -> Welcome:
        current_host, current_port = self.host, self.port
        auth = self.auth
        redirect_count = 0
        while redirect_count < 5:
            welcome, redirect = await self._connect_once(current_host, current_port, auth, log)
            if redirect is not None:
                redirect_host_, redirect_port, ticket = redirect
                redirect_count += 1
                log(f"Cluster redirect ({redirect_count}/5) to {redirect_host_}:{redirect_port}")
                current_host, current_port = redirect_host_, redirect_port
                auth = ClientAuth.TICKET
                self.host, self.port = current_host, current_port
                self.auth = auth
                self.ticket = ticket
                continue
            if welcome is None:
                raise protocol_error("Connection closed without welcome or redirect")
            self.welcome = welcome
            log(f"Session {welcome.session_name} established (TCP max={welcome.max_connection}, "
                f"compress={welcome.use_compress}, UDP={welcome.use_udp_acceleration})")
            self._start_data_services(welcome)
            return welcome
        raise protocol_error(f"Too many cluster redirects ({redirect_count})")

    async def _connect_once(self, host: str, port: int, auth: str, log):
        active_stream = self._make_stream(host, port, self.proxy)
        temp_udp: UdpAccel | None = None
        handed_off = False
        try:
            try:
                await active_stream.start()
                if self._closed:
                    raise closed_error()
                log(f"TLS established with {host}:{port}")

                # 1. Signature upload
                try:
                    hello = await self._upload_signature(active_stream, self._signature_body(), host)
                except Exception as e:
                    log(f"Signature rejected ({e.message if isinstance(e, StreamError) else e}); retrying plain")
                    active_stream.cancel()
                    active_stream = self._make_stream(host, port, self.proxy)
                    await active_stream.start()
                    hello = await self._upload_signature(active_stream, b"VPNCONNECT", host)
                    self.plain_signature = True

                random = hello.data("random")
                if random is None or len(random) != 20:
                    raise protocol_error("Server hello missing random (not a SoftEther server?)")
                log(f"Server: {hello.str('hello') or '?'} v{hello.int('version') or 0} "
                    f"build {hello.int('build') or 0}")
                server_info = (hello.str("hello") or "", hello.int("version") or 0,
                               hello.int("build") or 0)

                # UDP acceleration: the socket is bound now so its port can be advertised.
                client_key_v1 = random_bytes(20)
                client_key_v2 = random_bytes(128)
                if self.use_udp_accel_config:
                    temp_udp = UdpAccel(my_key_v2=client_key_v2)

                # 2. Login
                login = self.login_pack(
                    random=random, auth=auth, host=host, port=port,
                    client_udp_port=temp_udp.local_port if temp_udp else 0,
                    client_key_v1=client_key_v1, client_key_v2=client_key_v2,
                    server_info=server_info)
                await active_stream.send(_http_post(
                    "/vpnsvc/vpn.cgi", "application/octet-stream",
                    _with_dummy(login).serialize(), host))
                w = await self._read_pack(active_stream)

                err = w.int("error")
                if err:
                    raise protocol_error(f"Server refused login: {describe(err)}")

                # Cluster redirect
                if (w.int("Redirect") or 0) != 0:
                    ticket = w.data("Ticket")
                    if ticket is None or len(ticket) != 20:
                        raise protocol_error("Cluster redirect missing 20-byte ticket")
                    rip = redirect_host(w, host)
                    redirect_port = port
                    # "Port" is a list: keep the port already in use if offered, else the first.
                    offered = w.ints("Port")
                    if offered:
                        chosen = port if port in offered else offered[0]
                        p = valid_port(chosen)
                        if p is None:
                            raise protocol_error(f"Cluster redirect to an invalid port ({chosen})")
                        redirect_port = p
                    return (None, (rip, redirect_port, ticket))

                # Parse Welcome packet.
                session_name = w.str("session_name") or ""
                connection_name = w.str("connection_name") or ""
                session_key = w.data("session_key")
                if not session_name or not session_key or len(session_key) != 20:
                    raise protocol_error("Malformed welcome from server (missing session_name, "
                                         "connection_name or session_key)")
                use_compress = (w.int("use_compress") or 0) != 0
                use_encrypt = (w.int("use_encrypt") or 0) != 0
                half_conn = (w.int("half_connection") or 0) != 0
                qos = (w.int("qos") or 0) != 0
                enable_udp_recovery = (w.int("enable_udp_recovery") or 0) != 0
                max_conn = negotiated_max_connection(
                    server=w.int("max_connection") or 1, enable_udp_recovery=enable_udp_recovery,
                    client=self.max_connections_config, qos=qos, half=half_conn)
                timeout_ms = max(w.int("timeout") or 30000, 500)
                message = w.data("Msg")

                # UDP acceleration fields. A bad value only disables UDP; TCP is unaffected.
                use_udp = (w.int("use_udp_acceleration") or 0) != 0
                udp_ver = w.int("udp_acceleration_version") or 1
                udp_server_port = valid_port(w.int("udp_acceleration_server_port") or 0)
                udp_server_cookie = w.int("udp_acceleration_server_cookie")
                udp_client_cookie = w.int("udp_acceleration_client_cookie")
                udp_key = w.data("udp_acceleration_server_key_v2")
                udp_fast_disconnect = (w.int("udp_accel_fast_disconnect_detect") or 0) != 0
                # Plaintext mode only when the server says so explicitly.
                udp_plaintext = (w.int("udp_acceleration_use_encryption") == 0
                                 if w.int("udp_acceleration_use_encryption") is not None else False)

                advertised_ip = w.str("udp_acceleration_server_ip")
                if not advertised_ip:
                    ip_int = w.int("udp_acceleration_server_ip")
                    if ip_int and not is_ipv6_flagged(w, "udp_acceleration_server_ip"):
                        advertised_ip = packIPString(ip_int)
                udp_server_ip = resolve_udp_server_ip(advertised_ip, host)

                if use_udp and temp_udp is not None:
                    secondary = host if (validation.is_ipv4_literal(host)
                                         and not validation.is_non_public_ipv4(host)) else None
                    s_port = udp_server_port
                    s_cookie = udp_server_cookie
                    c_cookie = udp_client_cookie
                    s_key = udp_key if udp_key is not None else (b"" if udp_plaintext else None)
                    ok = False
                    if (udp_ver == 2 and udp_server_ip and s_port and s_cookie
                            and c_cookie and s_key is not None):
                        ok = temp_udp.configure(
                            server_ip=udp_server_ip, server_port=s_port,
                            my_cookie=c_cookie & 0xFFFFFFFF, your_cookie=s_cookie & 0xFFFFFFFF,
                            your_key_v2=s_key, fast_disconnect=udp_fast_disconnect,
                            use_compress=use_compress, plaintext=udp_plaintext,
                            secondary_ip=secondary)
                    if ok:
                        temp_udp.on_frame = self._pool_frame
                        temp_udp.on_byte_count = self._udp_bytes
                        if self._install_udp(temp_udp):
                            temp_udp.start()
                            self.udp_accel = temp_udp
                        temp_udp = None
                    else:
                        log("UDP acceleration offered but unusable; using TCP only")

                welcome = Welcome(
                    session_name=session_name, connection_name=connection_name,
                    timeout_ms=timeout_ms, message=message, session_key=session_key,
                    max_connection=max_conn, use_compress=use_compress, use_encrypt=use_encrypt,
                    half_connection=half_conn, qos=qos, enable_udp_recovery=enable_udp_recovery,
                    use_udp_acceleration=use_udp, udp_accel_version=udp_ver,
                    udp_server_ip=udp_server_ip, udp_server_port=udp_server_port,
                    udp_server_cookie=udp_server_cookie, udp_client_cookie=udp_client_cookie,
                    udp_server_key=udp_key, udp_fast_disconnect=udp_fast_disconnect)

                # Add main stream to the pool. The primary connection is always client-to-server
                # when half connection is on (Protocol.c:4172-4176).
                handed_off = True
                with_sink = active_stream.remote_ipv4
                self._set_connected_ipv4(with_sink)
                self.pool.add(stream=active_stream, use_compress=use_compress, timeout_ms=timeout_ms,
                              direction=SocketDirection(SocketDirection.CLIENT_TO_SERVER)
                              if self.half_connection_config else SocketDirection())
                return (welcome, None)
            finally:
                if not handed_off:
                    active_stream.cancel()
                if temp_udp is not None:
                    temp_udp.stop()
        except Exception:
            # any failure above is propagated after the deferred cleanup above runs
            raise

    def _set_connected_ipv4(self, ip: str | None) -> None:
        self.connected_ipv4 = ip

    def _install_udp(self, udp: UdpAccel) -> bool:
        if self._closed:
            udp.stop()
            return False
        return True

    # MARK: welcome field helpers

    def _signature_body(self) -> bytes:
        """The watermark plus random padding, or the plain marker once the server refused it."""
        if self.plain_signature:
            return b"VPNCONNECT"
        return SOFT_ETHER_WATERMARK + random_bytes(random.randrange(0, 2000))

    async def _upload_signature(self, s: ByteStream, body: bytes, host: str) -> Pack:
        await s.send(_http_post("/vpnsvc/connect.cgi", "image/jpeg", body, host))
        return await self._read_pack(s)

    async def _read_pack(self, s: ByteStream) -> Pack:
        head = await s.recv_http_head()
        code = head.status_code or 0
        if code != 200:
            raise protocol_error(f"HTTP: {head.status}")
        try:
            length = int(head.headers.get("content-length", "0") or 0)
        except ValueError:
            length = 0
        if not (0 < length < 1 << 20):
            raise protocol_error("Bad response length")
        from ..core.pack import PackError
        try:
            return Pack.parse(await s.recv(length))
        except Exception as e:
            raise protocol_error("Bad pack from server") from e

    # MARK: login pack

    def login_pack(self, random: bytes | None = None, auth: str | None = None,
                   host: str | None = None, port: int | None = None,
                   client_udp_port: int = 0, client_key_v1: bytes | None = None,
                   client_key_v2: bytes | None = None,
                   server_info: tuple[str, int, int] = ("", 0, 0)) -> Pack:
        p = Pack()
        auth = auth if auth is not None else self.auth
        random = random if random is not None else bytes(20)
        client_key_v1 = client_key_v1 if client_key_v1 is not None else bytes(20)
        client_key_v2 = client_key_v2 if client_key_v2 is not None else bytes(128)
        host = host if host is not None else self.host
        port = port if port is not None else self.port

        p.add_str("method", "login")
        p.add_str("hubname", self.hub_name)
        p.add_str("username", self.user_name)

        # Authentication fields
        if auth == ClientAuth.ANONYMOUS:
            p.add_int("authtype", 0)
        elif auth == ClientAuth.HASHED_PASSWORD:
            p.add_int("authtype", 1)
            pw_data = (self.password or "").encode("utf-8") + ascii_uppercased(self.user_name).encode("utf-8")
            hashed = sha0(pw_data)
            secure = sha0(hashed + random)
            p.add_data("secure_password", secure)
        elif auth == ClientAuth.PLAIN_PASSWORD:
            p.add_int("authtype", 2)
            p.add_str("plain_password", self.password or "")
        elif auth == ClientAuth.CERTIFICATE:
            p.add_int("authtype", 3)
            p.add_data("cert", self.cert_der or b"")
            signature = cert_signer(self.private_key_der)(random)
            p.add_data("sign", signature)
        elif auth == ClientAuth.TICKET:
            p.add_int("authtype", 99)
            p.add_data("ticket", self.ticket or b"")

        p.add_str("client_str", "SoftEther VPN Client")
        p.add_int("client_ver", CLIENT_VER)
        p.add_int("client_build", CLIENT_BUILD)
        p.add_int("protocol", 0)  # TCP
        p.add_str("hello", "SoftEther VPN Client")
        p.add_int("version", CLIENT_VER)
        p.add_int("build", CLIENT_BUILD)
        p.add_int("client_id", 0)
        p.add_int("max_connection", self.max_connections_config)
        p.add_bool("use_encrypt", True)
        p.add_bool("use_compress", self.use_compress_config)
        p.add_bool("half_connection", self.half_connection_config)
        p.add_bool("require_bridge_routing_mode", False)
        p.add_bool("require_monitor_mode", False)
        p.add_bool("qos", not self.disable_qos)  # upstream: !DisableQoS
        p.add_bool("support_bulk_on_rudp", True)
        p.add_bool("support_hmac_on_bulk_of_rudp", True)
        p.add_bool("support_udp_recovery", True)
        p.add_data("unique_id", self.login_unique_id)

        # UDP Acceleration negotiation
        if self.use_udp_accel_config:
            p.add_bool("use_udp_acceleration", True)
            p.add_ipv4("udp_acceleration_client_ip", 0)
            p.add_int("udp_acceleration_client_port", client_udp_port)
            p.add_data("udp_acceleration_client_key", client_key_v1)
            p.add_data("udp_acceleration_client_key_v2", client_key_v2)
            p.add_bool("support_hmac_on_udp_acceleration", True)
            p.add_bool("support_udp_accel_fast_disconnect_detect", True)
            p.add_int("udp_acceleration_version", 2)
            p.add_int("udp_acceleration_max_version", 2)
        p.add_int("rudp_bulk_max_version", 2)

        # Node info
        p.add_str("ClientProductName", "SoftEther VPN Client")
        p.add_str("ServerProductName", server_info[0])
        p.add_str("ClientOsName", "Linux")
        p.add_str("ClientOsVer", platform.release())
        p.add_str("ClientOsProductId", "")
        p.add_str("ClientHostname", socket.gethostname())
        p.add_str("ServerHostname", host)
        p.add_str("ProxyHostname", "" if self.proxy.kind == ProxySettings.KIND_NONE else self.proxy.host)
        p.add_data("UniqueId", self.node_unique_id)
        p.add_int("ClientProductVer", CLIENT_VER)
        p.add_int("ClientProductBuild", CLIENT_BUILD)
        p.add_int("ServerProductVer", server_info[1])
        p.add_int("ServerProductBuild", server_info[2])
        p.add_int("ClientPort", 0)
        p.add_int("ServerPort2", port)
        p.add_int("ProxyPort", max(0, self.proxy.port))
        p.add_ipv4("ClientIpAddress", 0)
        p.add_ipv4("ServerIpAddress", 0)
        p.add_ipv4("ProxyIpAddress", 0)
        for name in ("ClientIpAddress6", "ServerIpAddress6", "ProxyIpAddress6"):
            p.add_data(name, bytes(16))
        return p

    # MARK: data services & multi-TCP

    @property
    def remote_ipv4(self) -> str | None:
        return None if self.proxy.kind != ProxySettings.KIND_NONE else self.connected_ipv4

    @property
    def bypass_hosts(self) -> list[str]:
        """Hosts that must stay reachable outside a full tunnel: the session host and the UDP endpoint."""
        out: list[str] = []
        if self.proxy.kind == ProxySettings.KIND_NONE:
            out.append(self.connected_ipv4 or self.host)
        if self.udp_accel is not None and self.welcome and self.welcome.udp_server_ip \
                and self.welcome.udp_server_ip not in out:
            out.append(self.welcome.udp_server_ip)
        return out

    def _start_data_services(self, welcome: Welcome) -> None:
        timeout_ms = welcome.timeout_ms
        use_compress = welcome.use_compress
        loop = asyncio.get_running_loop()

        async def keepalive():
            while True:
                lo = max(timeout_ms // 5, 1000)
                hi = max(timeout_ms // 2, lo + 1)
                await asyncio.sleep(random.randint(lo, hi) / 1000.0)
                junk = random_bytes(random.randrange(0, 512))
                packet = encode_keep_alive(junk)
                await self.pool.broadcast_keep_alive(packet)

        self._keepalive_task = loop.create_task(keepalive())

        if welcome.max_connection > 1 and welcome.session_key:
            self._replenish_task = loop.create_task(
                self._replenish_loop(target=welcome.max_connection,
                                     session_key=welcome.session_key,
                                     use_compress=use_compress, timeout_ms=timeout_ms))

    async def _replenish_loop(self, target: int, session_key: bytes, use_compress: bool,
                              timeout_ms: int) -> None:
        failures = 0
        while not self._closed:
            if self.pool.active_count >= target:
                await asyncio.sleep(self._replenish_interval)
                continue
            try:
                await self._open_additional_connection(session_key, use_compress, timeout_ms)
                failures = 0
            except asyncio.CancelledError:
                raise
            except Exception:
                if self._closed:
                    return
                failures += 1
                delay = min(self._replenish_interval * (2 ** min(failures - 1, 5)), 30)
                await asyncio.sleep(delay)

    async def _open_additional_connection(self, session_key: bytes, use_compress: bool,
                                          timeout_ms: int) -> None:
        if self._closed:
            return
        host, port = self.host, self.port
        s = self._make_stream(host, port, self.proxy)
        added = False
        try:
            await s.start()
            if self._closed:
                return
            # Signature: same upload as the first connection, then the hello is discarded.
            await self._upload_signature(s, self._signature_body(), host)

            p = Pack()
            p.add_str("method", "additional_connect")
            p.add_data("session_key", session_key)
            p.add_str("client_str", "SoftEther VPN Client")
            p.add_int("client_ver", CLIENT_VER)
            p.add_int("client_build", CLIENT_BUILD)
            await s.send(_http_post("/vpnsvc/vpn.cgi", "application/octet-stream",
                                    _with_dummy(p).serialize(), host))
            resp = await self._read_pack(s)
            err = resp.int("error")
            if err:
                raise protocol_error(f"Additional connection refused: {describe(err)}")
            # The reply's `direction` (0 both, 1 server->client, 2 client->server) is chosen by
            # the server, only when half connection was requested.
            direction = SocketDirection(resp.int("direction"))
            if self._closed:
                return
            added = True
            self.pool.add(stream=s, use_compress=use_compress, timeout_ms=timeout_ms,
                          direction=direction)
        finally:
            if not added:
                s.cancel()

    # MARK: send frame

    def send_frame(self, frame: bytes) -> None:
        if len(frame) > MAX_BLOCK or self._closed:
            return
        udp = self.udp_accel
        if udp is not None and udp.is_usable and udp.send_frame(frame):
            self._out_udp += len(frame)
            if self._last_path != "udp":
                self._last_path = "udp"
                log("[path]", "outbound data switched to UDP acceleration")
            return
        with self._queue_lock:
            if self._closed:
                return
            if len(self._pending) >= MAX_PENDING_FRAMES:
                self._dropped_frames += 1
                return
            self._pending.append(frame)
            if self._flushing or self._closed:
                return
            self._flushing = True
        self._schedule_flush()

    def _schedule_flush(self) -> None:
        """Runs the flusher on the session's event loop (send_frame may be called from any thread)."""
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            running = asyncio.get_running_loop() is loop
        except RuntimeError:
            running = False
        if running:
            loop.create_task(self._flush())
        else:
            asyncio.run_coroutine_threadsafe(self._flush(), loop)

    def _take_batch(self) -> list[bytes] | None:
        with self._queue_lock:
            frames = self._pending[:64]
            del self._pending[:len(frames)]
            if not frames:
                self._flushing = False
                return None
            return frames

    async def _flush(self) -> None:
        while True:
            frames = self._take_batch()
            if not frames:
                return
            use_compress = self.welcome.use_compress if self.welcome else False
            total = sum(len(f) for f in frames)
            try:
                encoded = encode_frames(frames, use_compress=use_compress)
                await self.pool.send(encoded, total)
                self._out_tcp += total
                if self._last_path != "tcp" and self.udp_accel is not None:
                    self._last_path = "tcp"
                    log("[path]", "outbound data switched back to the TCP pool")
            except Exception as e:
                self.close(e)
                return

    def close(self, error: Exception | None = None) -> None:
        with self._queue_lock:
            if self._closed:
                return
            self._closed = True
        for task in (self._keepalive_task, self._replenish_task):
            if task is not None:
                task.cancel()
        self._keepalive_task = None
        self._replenish_task = None
        if self.udp_accel is not None:
            self.udp_accel.stop()
            self.udp_accel = None
        self.pool.close(error)
        if self.on_close:
            self.on_close(error)


def _http_post(path: str, type_: str, body: bytes, host: str) -> bytes:
    head = (f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Type: {type_}\r\nConnection: Keep-Alive\r\n"
            f"Content-Length: {len(body)}\r\n\r\n")
    return head.encode() + body


def _with_dummy(p: Pack) -> Pack:
    """The pencore HttpClientSend appends to every pack."""
    p.add_data("pencore", random_bytes(random.randrange(0, 1000)))
    return p