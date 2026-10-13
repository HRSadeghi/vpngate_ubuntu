"""VPNGate.dat parsing, RSA verification, tunables and probes (port of VGDat.swift)."""

from __future__ import annotations

import hashlib
import struct
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .pack import Pack, PackError
from .packets import rd64
from .rc4 import RC4
from .serverlist import VPNServer, port_priority
from .sha0 import hash as sha0

API_CERTIFICATE_PEM = """-----BEGIN CERTIFICATE-----
MIIB/zCCAWgCAQAwDQYJKoZIhvcNAQEFBQAwSDEZMBcGA1UEAxQQdnBuZ2F0ZV9h
cGlfY2VydDEeMBwGA1UEChMVU29mdEV0aGVyIENvcnBvcmF0aW9uMQswCQYDVQQG
EwJKUDAeFw0xMzAxMTUwNjM4MTVaFw0zNzAxMDkwNjM4MTVaMEgxGTAXBgNVBAMU
EHZwbmdhdGVfYXBpX2NlcnQxHjAcBgNVBAoTFVNvZnRFdGhlciBDb3Jwb3JhdGlv
bjELMAkGA1UEBhMCSlAwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANKvJddX
AO7XIt+ZXBvzH10R/nlFV9RRG7nW0Kge6/FVVlfgYuninG/s9RF6rloWh4v7sotp
GUKFJ7jD76NAzkemvsNpcQfkddxZD/Nv6k3ZoWK1Z2Wm77UkhBiI34/Ez9uLPgiJ
rc10hwkeixpO2V5ewi0RvWEayq79xGS1jLpnAgMBAAEwDQYJKoZIhvcNAQEFBQAD
gYEAMKQNaIw5eusl1sOZ6BlcqVCXRAFG+/rF9ZFUHQzdu3hO2k1F08naMpoO9PIE
d8yEiIuOzeylfCReS34JclCWOz/IVVgk9gYNDKeGZpM17ZuXes1EkG4SrCDqUnaN
/gl7JR92FEfGHsyteExq/09Q7b1BfHCHSmXfKhoOBD/TlV4=
-----END CERTIFICATE-----
"""

# 36 hours in milliseconds (VG_ALLOW_TIME_DIFF from client_exe.c / VG.c).
ALLOW_TIME_DIFF_MS = 36 * 3600 * 1000
# Largest inflated `data` accepted (the real list is ~75 KB).
MAX_INFLATED_SIZE = 16 * 1024 * 1024


class VGDatError(Exception):
    pass


def _api_public_key():
    try:
        import warnings
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        # The historical certificate carries a non-positive serial (RFC 5280 violation):
        # silence the loader's deprecation warning, it parses fine today.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cert = x509.load_pem_x509_certificate(API_CERTIFICATE_PEM.encode())
        key = cert.public_key()
        if not isinstance(key, RSAPublicKey):
            return None
        return key.public_numbers().n, key.public_numbers().e
    except Exception:
        return None


class VGTunables:
    """The client's named tunables (client_exe.c FUN_0061b3f0 etc.).

    A verified VPNGate.dat may carry a `DynList`: an unencrypted nested Pack of name -> int64
    that overrides the defaults compiled into the client. A lookup returns the default when the
    name is absent or its value is 0, otherwise the value clamped to [default/5, default*50].
    """

    def __init__(self, dyn_list: bytes | None = None) -> None:
        self.values: dict[str, int] = {}
        if dyn_list:
            try:
                pack = Pack.parse(dyn_list)
            except PackError:
                return
            for e in pack.elements:
                if e.values and e.values[0].kind == "int64":
                    self.values[e.name.lower()] = int(e.values[0].value)

    def merge(self, newer: "VGTunables") -> None:
        self.values.update(newer.values)

    def value(self, name: str, default: int) -> int:
        v = self.values.get(name.lower())
        if not v:
            return default
        return min(max(v, default // 5), default * 50)

    def seconds(self, name: str, default_ms: int) -> float:
        return self.value(name, default_ms) / 1000.0


@dataclass
class VGDatFile:
    header_text: str
    soap_url: str
    timestamp: datetime
    timestamp_ms: int
    servers: list[VPNServer]
    raw_inner_pack: Pack
    is_signature_valid: bool
    is_fresh: bool
    tunables: VGTunables


def parse_inner_servers(inner_pack: Pack) -> list[VPNServer]:
    num_hosts_val = inner_pack.int("NumHosts")
    if num_hosts_val is None:
        return []
    ips = inner_pack.strs("IP")
    # NumHosts is attacker-influenced (signed, but a malicious relay can replay): never trust it past the arrays.
    count = min(int(num_hosts_val), len(ips))
    if count <= 0:
        return []

    fqdns = inner_pack.strs("Fqdn")
    host_names = inner_pack.strs("HostName")
    country_shorts = inner_pack.strs("CountryShort")
    country_fulls = inner_pack.strs("CountryFull")
    scores = inner_pack.int64s("Score")
    pings = inner_pack.ints("PingToJapan")
    speeds = inner_pack.int64s("SpeedToJapan")
    num_clients = inner_pack.ints("NumClients")
    uptimes = inner_pack.int64s("Uptime")
    ssl_ports_strs = inner_pack.strs("SslPorts")
    udp_ports = inner_pack.ints("UdpPort")
    openvpn_udp_strs = inner_pack.strs("OpenVpnUdpPorts")
    l2tps = inner_pack.ints("L2TP")
    oss = inner_pack.ints("Os")
    softs = inner_pack.strs("Soft")
    builds = inner_pack.ints("Build")
    owners = inner_pack.strs("Owner")
    abuses = inner_pack.strs("Abuse")
    messages = inner_pack.strs("Message")
    num_logins = inner_pack.int64s("NumLogin")
    logs = inner_pack.ints("Log")
    log_permanents = inner_pack.ints("LogPermanent")
    names = inner_pack.strs("Name")
    pings_google = inner_pack.ints("PingToGoogle")
    send_sizes = inner_pack.int64s("SendSize")
    recv_sizes = inner_pack.int64s("RecvSize")
    kernel_nats = inner_pack.ints("IsKernelModeNAT")

    servers: list[VPNServer] = []
    for i in range(count):
        ip = ips[i] if i < len(ips) else ""
        if not ip:
            continue

        fqdn = fqdns[i] if i < len(fqdns) else ""
        host_name = (host_names[i] if i < len(host_names) and host_names[i] else fqdn)
        country_short = country_shorts[i] if i < len(country_shorts) else ""
        country_long = country_fulls[i] if i < len(country_fulls) else ""
        score = int(min(scores[i], 2**63 - 1)) if i < len(scores) else 0
        ping = pings[i] if i < len(pings) else 0
        speed = int(min(speeds[i], 2**63 - 1)) if i < len(speeds) else 0
        sessions = num_clients[i] if i < len(num_clients) else 0
        uptime_ms = int(min(uptimes[i], 2**63 - 1)) if i < len(uptimes) else 0

        ssl_ports_str = ssl_ports_strs[i] if i < len(ssl_ports_strs) else ""
        ssl_ports = []
        for tok in ssl_ports_str.split():
            try:
                p = int(tok)
                if 0 < p < 65536:
                    ssl_ports.append(p)
            except ValueError:
                continue

        udp_port = None
        if i < len(udp_ports) and 0 < udp_ports[i] < 65536:
            udp_port = udp_ports[i]

        openvpn_str = openvpn_udp_strs[i] if i < len(openvpn_udp_strs) else ""
        openvpn_udp_ports = []
        for tok in openvpn_str.split():
            try:
                p = int(tok)
                if 0 < p < 65536:
                    openvpn_udp_ports.append(p)
            except ValueError:
                continue

        l2tp = bool(l2tps[i]) if i < len(l2tps) else False
        os_str = str(oss[i]) if i < len(oss) else None
        soft = softs[i] if i < len(softs) else None
        build = builds[i] if i < len(builds) else None
        owner = owners[i] if i < len(owners) else None
        abuse = abuses[i] if i < len(abuses) else None
        message = messages[i] if i < len(messages) else ""
        num_login = num_logins[i] if i < len(num_logins) else None

        ping_google = pings_google[i] if i < len(pings_google) else 0
        send_size = send_sizes[i] if i < len(send_sizes) else 0
        recv_size = recv_sizes[i] if i < len(recv_sizes) else 0
        traffic = int(min(send_size + recv_size, 2**63 - 1))

        is_log_permanent = bool(log_permanents[i]) if i < len(log_permanents) else False
        is_log2_weeks = bool(logs[i]) if i < len(logs) else False
        no_log = not is_log_permanent and not is_log2_weeks
        log_type = "Permanent" if is_log_permanent else ("2 Weeks" if is_log2_weeks else "No Log")

        first_port = port_priority(ssl_ports)[0] if port_priority(ssl_ports) else (udp_port or 443)

        servers.append(VPNServer(
            hostName=host_name, ip=ip, score=score, ping=ping, speed=speed,
            countryLong=country_long, countryShort=country_short,
            sessions=sessions, uptimeMs=uptime_ms,
            totalUsers=int(min(num_login, 2**63 - 1)) if num_login is not None else 0,
            totalTraffic=traffic, logType=log_type, operatorName=owner or "",
            message=message, listedPort=first_port, listedProto="tcp",
            fqdn=fqdn, sslPorts=ssl_ports, udpPort=udp_port,
            openvpnUdpPorts=openvpn_udp_ports, l2tp=l2tp, os=os_str, soft=soft,
            build=build, owner=owner, abuse=abuse, numLogin=num_login,
            noLog=no_log, logPermanent=is_log_permanent,
            name=names[i] if i < len(names) else None,
            pingToGoogle=ping_google, sendSize=send_size, recvSize=recv_size,
            isKernelModeNAT=bool(kernel_nats[i]) if i < len(kernel_nats) else False,
        ))
    return servers


def _decompress(data: bytes, expected_size: int) -> bytes:
    """Inflates a zlib stream (2-byte header, raw deflate, big-endian Adler-32) to exactly expected_size."""
    if expected_size <= 0 or expected_size > MAX_INFLATED_SIZE or len(data) < 6:
        raise VGDatError("Failed to decompress VPNGate.dat inner payload")
    # CMF/FLG: deflate, 32K window, no preset dictionary, header checksum multiple of 31.
    if (data[0] & 0x0F) != 8 or ((data[0] << 8) | data[1]) % 31 != 0 or (data[1] & 0x20) != 0:
        raise VGDatError("Failed to decompress VPNGate.dat inner payload")
    raw_deflate = data[2:-4]
    adler = int.from_bytes(data[-4:], "big")
    try:
        d = zlib.decompressobj(-15)
        out = d.decompress(raw_deflate, expected_size + 1)
        out += d.flush()
    except zlib.error:
        raise VGDatError("Failed to decompress VPNGate.dat inner payload")
    if len(out) != expected_size:
        raise VGDatError("Failed to decompress VPNGate.dat inner payload")
    if zlib.adler32(out) & 0xFFFFFFFF != adler:
        raise VGDatError("Failed to decompress VPNGate.dat inner payload")
    return out


def parse(data: bytes, now: float | None = None) -> VGDatFile:
    """Parses and always verifies a VPNGate.dat. `now` is only injectable for tests."""
    if now is None:
        now = time.time()
    if len(data) <= 0x104:
        raise VGDatError("Truncated VPNGate.dat file")

    # 1. Header (240 bytes)
    header_text = data[:0xF0].decode("utf-8", "replace")
    if not header_text.startswith("[VPNGate Data File]"):
        raise VGDatError("Invalid VPNGate.dat header")

    # 2. Seed (20 bytes)
    seed = data[0xF0:0x104]

    # 3. Body
    body = data[0x104:]
    key = hashlib.sha1(seed).digest()
    decrypted_body = RC4.cipher(key, body)

    # 4. Outer Pack
    try:
        outer = Pack.parse(decrypted_body)
    except PackError:
        raise VGDatError("Invalid Pack format in VPNGate.dat")

    outer_data = outer.data("data")
    data_size = outer.int("data_size")
    if data_size is None:
        v = outer.int64("data_size")
        data_size = v if v is not None else None
    sign = outer.data("sign")
    ts_data = outer.data("timestamp")
    if outer_data is None or data_size is None or sign is None or ts_data is None or len(ts_data) != 8:
        raise VGDatError("Invalid Pack format in VPNGate.dat")

    soap_url = outer.str("soap_url")
    if soap_url is None:
        raw = outer.data("soap_url")
        soap_url = raw.decode("utf-8", "replace") if raw else ""
    compressed = (outer.int("compressed") or 0) != 0

    ts_ms = rd64(ts_data, 0)
    timestamp = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)

    # 5. Signature verification (RSA PKCS#1 v1.5 SHA-1)
    sig_valid = False
    pub = _api_public_key()
    if pub is not None:
        signed_msg = ts_data + outer_data + struct.pack(">I", data_size)
        sig_valid = _verify_rsa_pkcs1_sha1(pub, signed_msg, sign)
    if not sig_valid:
        raise VGDatError("VPNGate.dat RSA signature verification failed")

    # 6. Decompress
    if compressed:
        uncompressed = _decompress(outer_data, int(data_size))
    else:
        uncompressed = outer_data

    # 7. Inner Pack
    try:
        inner = Pack.parse(uncompressed)
    except PackError:
        raise VGDatError("Invalid Pack format in VPNGate.dat")

    servers = parse_inner_servers(inner)
    now_ms = int(max(0, now) * 1000)
    diff_ms = abs(now_ms - ts_ms)
    is_fresh = diff_ms <= ALLOW_TIME_DIFF_MS
    dyn = inner.data("DynList")

    return VGDatFile(
        header_text=header_text, soap_url=soap_url, timestamp=timestamp,
        timestamp_ms=ts_ms, servers=servers, raw_inner_pack=inner,
        is_signature_valid=sig_valid, is_fresh=is_fresh,
        tunables=VGTunables(dyn) if dyn else VGTunables(),
    )


def _verify_rsa_pkcs1_sha1(pub: tuple[int, int], message: bytes, signature: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.exceptions import InvalidSignature
        key = RSAPublicNumbers(pub[1], pub[0]).public_key()
        key.verify(signature, message, padding.PKCS1v15(), hashes.SHA1())
        return True
    except Exception:
        return False


def generate_probe(timestamp_ms: int | None = None) -> bytes:
    """16-byte probe for HTTP GET /vgc_download_dat/:
    8 bytes big-endian timestamp + 8 bytes of SHA0(SHA0(SHA0(SHA1(ts))))[0..<8]."""
    if timestamp_ms is None:
        timestamp_ms = int(time.time() * 1000)
    ts_bytes = struct.pack(">Q", timestamp_ms)
    h1 = hashlib.sha1(ts_bytes).digest()
    s1 = sha0(h1)
    s2 = sha0(s1)
    s3 = sha0(s2)
    return ts_bytes + s3[:8]


def verify_probe(probe: bytes, allowed_diff_ms: int = ALLOW_TIME_DIFF_MS, now: float | None = None) -> bool:
    if len(probe) != 16:
        return False
    if now is None:
        now = time.time()
    ts_bytes = probe[:8]
    hash_bytes = probe[8:]
    ts_ms = rd64(ts_bytes, 0)
    now_ms = int(max(0, now) * 1000)
    if abs(now_ms - ts_ms) > allowed_diff_ms:
        return False
    h1 = hashlib.sha1(ts_bytes).digest()
    s3 = sha0(sha0(sha0(h1)))
    return s3[:8] == hash_bytes