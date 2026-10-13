"""SoftEther VPN Client account configuration (port of ClientAccount.swift)."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from .ipcmessages import ConnectConfig, ProxySettings
from .routing import RoutingAction, RoutingConfig, RoutingRule, RoutingRuleType


class AccountAuthType:
    ANONYMOUS = "Anonymous"
    PASSWORD = "Standard Password (SHA-0)"
    PLAIN_PASSWORD = "Plain Password"
    CERTIFICATE = "User Certificate"

    ALL = [ANONYMOUS, PASSWORD, PLAIN_PASSWORD, CERTIFICATE]

    @staticmethod
    def wire_value(display: str) -> str:
        """The authType string carried in ConnectConfig (the helper's switch values)."""
        return {
            AccountAuthType.ANONYMOUS: "anonymous",
            AccountAuthType.PASSWORD: "password",
            AccountAuthType.PLAIN_PASSWORD: "plain",
            AccountAuthType.CERTIFICATE: "cert",
        }.get(display, "anonymous")


DEFAULT_PORTS = [443, 992, 5555, 1194]


def routing_config_to_json(cfg: RoutingConfig | None) -> dict | None:
    if cfg is None:
        return None
    out = {
        "rules": [
            {"id": r.id, "type": r.type.value, "value": r.value,
             "action": r.action.value, "enabled": r.enabled}
            for r in cfg.rules
        ],
        "defaultAction": cfg.default_action.value,
        "bypassPrivateNetworks": cfg.bypass_private_networks,
    }
    if cfg.bypass_apps_enabled or cfg.bypass_apps:
        out["bypassAppsEnabled"] = cfg.bypass_apps_enabled
        out["bypassApps"] = list(cfg.bypass_apps)
    return out


def routing_config_from_json(d: dict | None) -> RoutingConfig:
    if not d:
        return RoutingConfig()
    rules = []
    for r in d.get("rules", []):
        try:
            rules.append(RoutingRule(
                type=RoutingRuleType(r["type"]),
                value=r["value"],
                action=RoutingAction(r["action"]),
                enabled=bool(r.get("enabled", True)),
                id=r.get("id") or str(uuid.uuid4()),
            ))
        except (KeyError, ValueError):
            continue  # a bad record never fails the whole list
    try:
        default = RoutingAction(d.get("defaultAction", "proxy"))
    except ValueError:
        default = RoutingAction.proxy
    return RoutingConfig(rules=rules, default_action=default,
                         bypass_private_networks=bool(d.get("bypassPrivateNetworks", False)),
                         bypass_apps_enabled=bool(d.get("bypassAppsEnabled", False)),
                         bypass_apps=[str(a) for a in d.get("bypassApps") or []][:64])


@dataclass
class ClientAccount:
    """SoftEther VPN Client account configuration (Connection Setting)."""
    name: str
    host: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    portList: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    hub: str = "DEFAULT"
    username: str = ""
    authType: str = AccountAuthType.PASSWORD
    proxy: ProxySettings = field(default_factory=ProxySettings)
    checkServerCert: bool = False
    serverCertFingerprint: str | None = None
    maxConnection: int = 1
    # Splits send and receive onto separate TCP sockets. Stored for compatibility; the helper
    # requests at least 4 connections when this is on.
    halfConnection: bool = False
    compression: bool = False
    udpAcceleration: bool = True
    # "Disable QoS" of the SoftEther Client Manager; False (default) = QoS on.
    disableQoS: bool = False
    autoReconnect: bool = True
    reconnectInterval: float = 3.0
    reconnectCount: int = 8
    # "Virtual Network Adapter" MAC override ("aa:bb:cc:dd:ee:ff"); None uses a random one.
    virtualMacAddress: str | None = None
    # MTU override; None means automatic (the DHCP lease's option 26 wins).
    mtu: int | None = None
    # Per-account routing rules; None means "use the app's global rules".
    routing: RoutingConfig | None = None
    createdAt: float = field(default_factory=time.time)
    updatedAt: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.portList:
            self.portList = [443]
        self.maxConnection = max(1, min(int(self.maxConnection), 32))
        # The proxy password is a secret: it is kept in the keyring and never written to the file.
        self.proxy.password = None

    def to_json(self) -> dict:
        d = {
            "id": self.id, "name": self.name, "host": self.host, "portList": self.portList,
            "hub": self.hub, "username": self.username, "authType": self.authType,
            "proxy": self.proxy.to_json(), "checkServerCert": self.checkServerCert,
            "maxConnection": self.maxConnection, "halfConnection": self.halfConnection,
            "compression": self.compression, "udpAcceleration": self.udpAcceleration,
            "disableQoS": self.disableQoS, "autoReconnect": self.autoReconnect,
            "reconnectInterval": self.reconnectInterval, "reconnectCount": self.reconnectCount,
            "createdAt": self.createdAt, "updatedAt": self.updatedAt,
        }
        for key, val in (("serverCertFingerprint", self.serverCertFingerprint),
                         ("virtualMacAddress", self.virtualMacAddress), ("mtu", self.mtu)):
            if val is not None:
                d[key] = val
        if self.routing is not None:
            d["routing"] = routing_config_to_json(self.routing)
        return d

    @classmethod
    def from_json(cls, d: dict) -> "ClientAccount":
        acc = cls(
            name=d["name"], host=d["host"],
            id=d.get("id") or str(uuid.uuid4()),
            portList=[int(p) for p in d.get("portList") or DEFAULT_PORTS],
            hub=d.get("hub", "DEFAULT") or "DEFAULT",
            username=d.get("username", "") or "",
            authType=d.get("authType", AccountAuthType.PASSWORD) or AccountAuthType.PASSWORD,
            proxy=ProxySettings.from_json(d.get("proxy") or {}),
            checkServerCert=bool(d.get("checkServerCert", False)),
            maxConnection=int(d.get("maxConnection", 1) or 1),
            halfConnection=bool(d.get("halfConnection", False)),
            compression=bool(d.get("compression", False)),
            udpAcceleration=bool(d.get("udpAcceleration", True)),
            disableQoS=bool(d.get("disableQoS", False)),
            autoReconnect=bool(d.get("autoReconnect", True)),
            reconnectInterval=float(d.get("reconnectInterval", 3.0) or 3.0),
            reconnectCount=int(d.get("reconnectCount", 8) or 8),
            virtualMacAddress=d.get("virtualMacAddress"),
            mtu=int(d["mtu"]) if d.get("mtu") is not None else None,
            routing=routing_config_from_json(d.get("routing")),
            createdAt=float(d.get("createdAt", time.time()) or time.time()),
            updatedAt=float(d.get("updatedAt", time.time()) or time.time()),
        )
        acc.serverCertFingerprint = d.get("serverCertFingerprint")
        # An older file may still carry the invented `hideFromVpnGateList` key: ignored, never written.
        return acc

    def to_connect_config(
        self,
        password: str | None = None,
        cert_der: bytes | None = None,
        private_key_der: bytes | None = None,
        block_ipv6: bool = True,
        global_routing: RoutingConfig | None = None,
    ) -> ConnectConfig:
        """Converts this account into a ConnectConfig for IPC transmission to the helper."""
        return ConnectConfig(
            host=self.host,
            ports=list(self.portList),
            hubName=self.hub,
            userName=self.username,
            authType=AccountAuthType.wire_value(self.authType),
            password=password,
            certDer=cert_der,
            privateKeyDer=private_key_der,
            ticket=None,
            proxy=self.proxy,
            maxConnection=self.maxConnection,
            useCompress=self.compression,
            useUdpAccel=self.udpAcceleration,
            disableQoS=self.disableQoS,
            halfConnection=self.halfConnection,
            autoReconnect=self.autoReconnect,
            reconnectInterval=self.reconnectInterval,
            reconnectCount=self.reconnectCount,
            blockIPv6=block_ipv6,
            checkServerCert=self.checkServerCert,
            serverCertFingerprint=self.serverCertFingerprint,
            mtu=self.mtu,
            virtualMacAddress=self.virtualMacAddress,
            routing=(routing_config_to_json(self.routing) if self.routing is not None
                     else routing_config_to_json(global_routing)),
        )