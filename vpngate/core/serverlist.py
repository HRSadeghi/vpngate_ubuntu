"""VPN server model, CSV mirror parsing and list formatting (port of ServerList.swift)."""

from __future__ import annotations

import base64
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime

from .validation import is_ipv4_literal, is_valid_port

# The Windows client's port order (client_exe.c FUN_004117c0): only those the host offers,
# then the host's other ports in their original order.
PREFERRED_PORTS = [443, 992, 995, 465, 585, 993, 22]


def port_priority(ports: list[int]) -> list[int]:
    out = [p for p in PREFERRED_PORTS if p in ports]
    for p in ports:
        if p not in out:
            out.append(p)
    return out


@dataclass
class VPNServer:
    hostName: str
    ip: str
    score: int = 0
    ping: int = 0
    speed: int = 0            # bits per second
    countryLong: str = ""
    countryShort: str = ""
    sessions: int = 0
    uptimeMs: int = 0
    totalUsers: int = 0
    totalTraffic: int = 0     # bytes
    logType: str = ""
    operatorName: str = ""
    message: str = ""
    # Port from the server's OpenVPN config (tcp or udp); 0 if unknown.
    listedPort: int = 0
    listedProto: str = ""
    # Full parity fields from VPNGate.dat and Cedar
    fqdn: str = ""
    sslPorts: list[int] = field(default_factory=list)
    udpPort: int | None = None
    openvpnUdpPorts: list[int] = field(default_factory=list)
    l2tp: bool = False
    os: str | None = None
    soft: str | None = None
    build: int | None = None
    owner: str | None = None
    abuse: str | None = None
    numLogin: int | None = None
    noLog: bool = False
    logPermanent: bool = False
    name: str | None = None
    pingToGoogle: int = 0
    sendSize: int = 0
    recvSize: int = 0
    isKernelModeNAT: bool = False
    # Not stored or sent anywhere: the "Test from this Mac" result as a sort key.
    testRank: int = 0

    def __post_init__(self) -> None:
        if not self.hostName:
            self.hostName = self.fqdn
        if not self.fqdn:
            self.fqdn = self.hostName

    @property
    def id(self) -> str:
        """The DDNS host name is the only unique key: the same IP can appear on several ports."""
        return self.hostName

    @property
    def prioritized_ssl_ports(self) -> list[int]:
        return port_priority(self.sslPorts)

    @property
    def connect_port(self) -> int | None:
        """Port to try first: the first SSL port in priority order, then listedPort."""
        ports = self.prioritized_ssl_ports
        if ports and is_valid_port(ports[0]):
            return ports[0]
        return self.listedPort if is_valid_port(self.listedPort) else None

    @property
    def flag(self) -> str:
        base = 127397
        out = ""
        for ch in self.countryShort.upper():
            cp = base + ord(ch)
            if 0 <= cp <= 0x10FFFF:
                out += chr(cp)
        return out

    def to_json(self) -> dict:
        d = {
            "hostName": self.hostName, "ip": self.ip, "score": self.score, "ping": self.ping,
            "speed": self.speed, "countryLong": self.countryLong, "countryShort": self.countryShort,
            "sessions": self.sessions, "uptimeMs": self.uptimeMs, "totalUsers": self.totalUsers,
            "totalTraffic": self.totalTraffic, "logType": self.logType,
            "operatorName": self.operatorName, "message": self.message,
            "listedPort": self.listedPort, "listedProto": self.listedProto, "fqdn": self.fqdn,
            "sslPorts": self.sslPorts, "openVpnUdpPorts": self.openvpnUdpPorts,
            "l2tp": self.l2tp, "noLog": self.noLog, "logPermanent": self.logPermanent,
            "pingToGoogle": self.pingToGoogle, "sendSize": self.sendSize, "recvSize": self.recvSize,
            "isKernelModeNAT": self.isKernelModeNAT,
        }
        for key, val in (("udpPort", self.udpPort), ("os", self.os), ("soft", self.soft),
                         ("build", self.build), ("owner", self.owner), ("abuse", self.abuse),
                         ("numLogin", self.numLogin), ("name", self.name)):
            if val is not None:
                d[key] = val
        return d

    @classmethod
    def from_json(cls, d: dict) -> "VPNServer":
        raw_host = d.get("hostName", "") or ""
        raw_fqdn = d.get("fqdn", "") or ""
        s = cls(
            hostName=raw_host or raw_fqdn,
            ip=d.get("ip", "") or "",
            score=int(d.get("score", 0) or 0),
            ping=int(d.get("ping", 0) or 0),
            speed=int(d.get("speed", 0) or 0),
            countryLong=d.get("countryLong", "") or "",
            countryShort=d.get("countryShort", "") or "",
            sessions=int(d.get("sessions", 0) or 0),
            uptimeMs=int(d.get("uptimeMs", 0) or 0),
            totalUsers=int(d.get("totalUsers", 0) or 0),
            totalTraffic=int(d.get("totalTraffic", 0) or 0),
            logType=d.get("logType", "") or "",
            operatorName=d.get("operatorName", "") or "",
            message=d.get("message", "") or "",
            # `tcpPort` was written by the first app version, before ports/protocols were recorded.
            listedPort=int(d.get("listedPort", d.get("tcpPort", 0)) or 0),
            listedProto=d.get("listedProto", "") or "",
            fqdn=raw_fqdn or raw_host,
            sslPorts=[int(p) for p in d.get("sslPorts") or []],
            udpPort=int(d["udpPort"]) if d.get("udpPort") is not None else None,
            openvpnUdpPorts=[int(p) for p in d.get("openVpnUdpPorts") or []],
            l2tp=bool(d.get("l2tp", False)),
            os=d.get("os"), soft=d.get("soft"),
            build=int(d["build"]) if d.get("build") is not None else None,
            owner=d.get("owner"), abuse=d.get("abuse"),
            numLogin=int(d["numLogin"]) if d.get("numLogin") is not None else None,
            noLog=bool(d.get("noLog", False)),
            logPermanent=bool(d.get("logPermanent", False)),
            name=d.get("name"),
            pingToGoogle=int(d.get("pingToGoogle", 0) or 0),
            sendSize=int(d.get("sendSize", 0) or 0),
            recvSize=int(d.get("recvSize", 0) or 0),
            isKernelModeNAT=bool(d.get("isKernelModeNAT", False)),
        )
        return s


class ServerListError(Exception):
    pass


DEFAULT_URLS = ["https://www.vpngate.net/api/iphone/", "http://www.vpngate.net/api/iphone/"]


def fetch(mirror: str | None = None, timeout: int = 60) -> list[VPNServer]:
    last: Exception = ServerListError("bad response")
    urls = ([mirror] if mirror else []) + DEFAULT_URLS
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "VPNGateLinux/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            servers = parse_csv(data.decode("utf-8", "replace"))
            if servers:
                return servers
        except Exception as e:
            last = e
    raise last


def parse_csv(csv: str) -> list[VPNServer]:
    out: list[VPNServer] = []
    for raw in csv.splitlines():
        line = raw.strip()
        if line.startswith("*") or line.startswith("#") or not line:
            continue
        f = line.split(",")
        if len(f) < 15:
            continue
        # The config blob is always the last column; a stray comma in the message must not shift it.
        config = f[-1]
        message = ",".join(f[13:-1])
        if not is_ipv4_literal(f[1]):
            continue
        port, proto = 0, ""
        try:
            cfg = base64.b64decode(config).decode("utf-8", "replace")
            port, proto = openvpn_endpoint(cfg)
        except Exception:
            pass
        try:
            out.append(VPNServer(
                hostName=f[0], ip=f[1], score=_int_or(f[2]), ping=_int_or(f[3]),
                speed=_int_or(f[4]), countryLong=f[5], countryShort=f[6],
                sessions=_int_or(f[7]), uptimeMs=_int_or(f[8]), totalUsers=_int_or(f[9]),
                totalTraffic=_int_or(f[10]), logType=f[11], operatorName=f[12],
                message=message, listedPort=port, listedProto=proto))
        except Exception:
            continue
    return out


def _int_or(s: str) -> int:
    try:
        return int(s)
    except ValueError:
        return 0


def openvpn_endpoint(cfg: str) -> tuple[int, str]:
    """(port, "tcp"/"udp") from `proto` and `remote` lines; port 0 if absent or invalid."""
    proto = ""
    port = 0
    for l in cfg.splitlines():
        w = l.split()
        if not w:
            continue
        if w[0] == "proto" and len(w) > 1:
            proto = "tcp" if w[1].startswith("tcp") else "udp"
        if w[0] == "remote" and len(w) > 2:
            try:
                p = int(w[2])
                if is_valid_port(p):
                    port = p
            except ValueError:
                pass
    return port, proto


class ListFormat:
    """Text of the list table, following the Windows client (client_exe.c FUN_00525490)."""

    @staticmethod
    def uptime(ms: int) -> str:
        """Up to 1 h in minutes, up to 24 h in hours, beyond that in days."""
        ms = max(0, ms)

        def unit(n: int, word: str) -> str:
            return f"{n} {word}{'' if n == 1 else 's'}"

        if ms < 3_600_001:
            return unit(ms // 60_000, "min")
        if ms < 86_400_001:
            return unit(ms // 3_600_000, "hour")
        return unit(ms // 86_400_000, "day")

    @staticmethod
    def sessions(n: int) -> str:
        return f"{n} session{'' if n == 1 else 's'}"

    @staticmethod
    def logins(n: int) -> str:
        return f"{n:,} login{'' if n == 1 else 's'}"

    @staticmethod
    def logging(log_type: str) -> str:
        t = log_type.lower()
        if t.startswith("no"):
            return "No Logs"
        if "2" in t and "week" in t:
            return "2 Weeks"
        if t.startswith("perm"):
            return "Permanent"
        return log_type or "-"

    @staticmethod
    def pings(google: int, japan: int) -> str:
        def one(v: int) -> str:
            return "-" if v == 0 else f"{v} ms"
        return f"{one(google)}, {one(japan)}"

    @staticmethod
    def udp(port: int | None) -> str:
        return "-" if port is None else "UDP OK"

    @staticmethod
    def is_list_ok(timestamp: datetime, now: float | None = None) -> bool:
        """Within 24 h (inclusive) the list is OK, older it is "stale" (the UI uses 24 h)."""
        if now is None:
            now = time.time()
        ts = timestamp.timestamp() if isinstance(timestamp, datetime) else timestamp
        return abs(now - ts) * 1000 < 86_400_001