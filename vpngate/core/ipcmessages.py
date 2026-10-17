"""IPC message types shared by the helper and the app (port of IPCMessages.swift)."""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from enum import Enum

HELPER_SOCKET_PATH = "/var/run/vpngate-helper.sock"
# Bumped whenever the helper's behaviour or IPC changes; the app offers to reinstall an outdated helper.
HELPER_VERSION = 7


class ConnectionState(str, Enum):
    disconnected = "disconnected"
    connecting = "connecting"
    authenticating = "authenticating"
    dhcp = "dhcp"
    connected = "connected"
    reconnecting = "reconnecting"


@dataclass
class ProxySettings:
    KIND_NONE = "none"
    KIND_HTTP = "http"
    KIND_SOCKS5 = "socks5"

    kind: str = KIND_NONE
    host: str = ""
    port: int = 0
    username: str | None = None
    password: str | None = None

    def to_json(self) -> dict:
        d = {"kind": self.kind, "host": self.host, "port": self.port}
        if self.username is not None:
            d["username"] = self.username
        if self.password is not None:
            d["password"] = self.password
        return d

    @classmethod
    def from_json(cls, d: dict) -> "ProxySettings":
        return cls(
            kind=d.get("kind", cls.KIND_NONE) or cls.KIND_NONE,
            host=d.get("host", "") or "",
            port=int(d.get("port", 0) or 0),
            username=d.get("username"),
            password=d.get("password"),
        )


@dataclass
class ConnectConfig:
    """Full configuration for establishing a SoftEther session."""
    host: str
    ports: list[int] = field(default_factory=lambda: [443, 992, 5555, 1194])
    hubName: str = "VPNGATE"
    userName: str = "vpn"
    authType: str = "anonymous"        # anonymous, password, plain, cert, ticket
    password: str | None = None
    certDer: bytes | None = None
    # PKCS#1 RSAPrivateKey DER (PKCS#8 also accepted) for certificate auth; travels over the
    # uid-restricted IPC socket only and is never logged.
    privateKeyDer: bytes | None = None
    ticket: bytes | None = None
    proxy: ProxySettings = field(default_factory=ProxySettings)
    maxConnection: int = 1
    useCompress: bool = False
    useUdpAccel: bool = True
    # SoftEther "Disable QoS" (login qos = !disableQoS). The VPN Gate server-connect path sets it.
    disableQoS: bool = False
    # SoftEther half connection: separate TCP sockets for each direction; needs >= 4 connections.
    halfConnection: bool = False
    autoReconnect: bool = True
    reconnectInterval: float | None = None
    reconnectCount: int | None = None
    blockIPv6: bool = True
    checkServerCert: bool = False
    serverCertFingerprint: str | None = None
    mtu: int | None = None
    virtualMacAddress: str | None = None
    routing: dict | None = None

    def to_json(self) -> dict:
        d = {
            "host": self.host, "ports": self.ports, "hubName": self.hubName,
            "userName": self.userName, "authType": self.authType,
            "proxy": self.proxy.to_json(), "maxConnection": self.maxConnection,
            "useCompress": self.useCompress, "useUdpAccel": self.useUdpAccel,
            "disableQoS": self.disableQoS, "halfConnection": self.halfConnection,
            "autoReconnect": self.autoReconnect, "blockIPv6": self.blockIPv6,
            "checkServerCert": self.checkServerCert,
        }
        for key, val in (("password", self.password), ("serverCertFingerprint", self.serverCertFingerprint),
                         ("reconnectInterval", self.reconnectInterval), ("reconnectCount", self.reconnectCount),
                         ("mtu", self.mtu), ("virtualMacAddress", self.virtualMacAddress),
                         ("routing", self.routing)):
            if val is not None:
                d[key] = val
        for key, val in (("certDer", self.certDer), ("privateKeyDer", self.privateKeyDer),
                         ("ticket", self.ticket)):
            if val is not None:
                d[key] = bytes(val).hex()
        return d

    @classmethod
    def from_json(cls, d: dict) -> "ConnectConfig":
        cfg = cls(host=d["host"])
        if "ports" in d:
            cfg.ports = [int(p) for p in d["ports"]]
        for key in ("hubName", "userName", "authType", "password", "serverCertFingerprint",
                    "virtualMacAddress"):
            if key in d and d[key] is not None:
                setattr(cfg, key, d[key])
        for key in ("maxConnection", "reconnectCount", "mtu"):
            if key in d and d[key] is not None:
                setattr(cfg, key, int(d[key]))
        for key in ("useCompress", "useUdpAccel", "disableQoS", "halfConnection",
                    "autoReconnect", "blockIPv6", "checkServerCert"):
            if key in d and d[key] is not None:
                setattr(cfg, key, bool(d[key]))
        if "reconnectInterval" in d and d["reconnectInterval"] is not None:
            cfg.reconnectInterval = float(d["reconnectInterval"])
        if "proxy" in d and d["proxy"] is not None:
            cfg.proxy = ProxySettings.from_json(d["proxy"])
        for key in ("certDer", "privateKeyDer", "ticket"):
            if key in d and d[key] is not None:
                setattr(cfg, key, bytes.fromhex(d[key]))
        if "routing" in d and d["routing"] is not None:
            cfg.routing = d["routing"]
        return cfg


@dataclass
class HelperRequest:
    cmd: str  # connect | disconnect | status
    host: str | None = None
    port: int | None = None
    ports: list[int] | None = None
    proxy: ProxySettings | None = None
    autoReconnect: bool | None = None
    blockIPv6: bool | None = None
    routing: dict | None = None
    config: ConnectConfig | None = None
    bypassApps: list[str] | None = None
    bypassAppsEnabled: bool | None = None
    routing: dict | None = None

    def to_json(self) -> dict:
        d: dict = {"cmd": self.cmd}
        for key in ("host", "port", "autoReconnect", "blockIPv6", "routing"):
            v = getattr(self, key)
            if v is not None:
                d[key] = v
        if self.ports is not None:
            d["ports"] = self.ports
        if self.proxy is not None:
            d["proxy"] = self.proxy.to_json()
        if self.config is not None:
            d["config"] = self.config.to_json()
        return d

    @classmethod
    def from_json(cls, d: dict) -> "HelperRequest":
        r = cls(cmd=d["cmd"])
        for key in ("host", "autoReconnect", "blockIPv6", "routing"):
            if key in d and d[key] is not None:
                setattr(r, key, d[key])
        if "bypassApps" in d and d["bypassApps"] is not None:
            r.bypassApps = [str(a) for a in d["bypassApps"]]
        if "bypassAppsEnabled" in d and d["bypassAppsEnabled"] is not None:
            r.bypassAppsEnabled = bool(d["bypassAppsEnabled"])
        if "routing" in d and d["routing"] is not None:
            r.routing = d["routing"]
        if "port" in d and d["port"] is not None:
            r.port = int(d["port"])
        if "ports" in d and d["ports"] is not None:
            r.ports = [int(p) for p in d["ports"]]
        if "proxy" in d and d["proxy"] is not None:
            r.proxy = ProxySettings.from_json(d["proxy"])
        if "config" in d and d["config"] is not None:
            r.config = ConnectConfig.from_json(d["config"])
        return r


@dataclass
class HelperEvent:
    state: ConnectionState
    server: str | None = None
    virtualIP: str | None = None
    bytesIn: int = 0
    bytesOut: int = 0
    log: str | None = None
    error: str | None = None
    helperVersion: int | None = None

    def to_json(self) -> dict:
        d: dict = {"state": self.state.value}
        for key in ("server", "virtualIP", "log", "error"):
            v = getattr(self, key)
            if v is not None:
                d[key] = v
        if self.bytesIn:
            d["bytesIn"] = int(self.bytesIn)
        if self.bytesOut:
            d["bytesOut"] = int(self.bytesOut)
        if self.helperVersion is not None:
            d["helperVersion"] = self.helperVersion
        return d

    @classmethod
    def from_json(cls, d: dict) -> "HelperEvent":
        state = ConnectionState(d.get("state", "disconnected"))
        e = cls(state)
        for key in ("server", "virtualIP", "log", "error"):
            if key in d and d[key] is not None:
                setattr(e, key, d[key])
        if "bytesIn" in d:
            e.bytesIn = int(d["bytesIn"])
        if "bytesOut" in d:
            e.bytesOut = int(d["bytesOut"])
        if "helperVersion" in d and d["helperVersion"] is not None:
            e.helperVersion = int(d["helperVersion"])
        return e


def encode_line(obj) -> bytes:
    return (json.dumps(obj.to_json() if hasattr(obj, "to_json") else obj, separators=(",", ":")) + "\n").encode()


def decode_line(line: bytes, cls):
    return cls.from_json(json.loads(line.decode("utf-8")))