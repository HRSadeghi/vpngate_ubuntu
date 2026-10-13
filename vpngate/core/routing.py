"""IPv4/IPv6 address and CIDR matching plus user routing rules (port of RoutingRule.swift)."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from enum import Enum


class RoutingAction(str, Enum):
    proxy = "proxy"
    direct = "direct"
    block = "block"

    @property
    def label(self) -> str:
        return {"proxy": "Proxy", "direct": "Direct", "block": "Block"}[self.value]


class RoutingRuleType(str, Enum):
    domainSuffix = "domainSuffix"
    domainFull = "domainFull"
    domainKeyword = "domainKeyword"
    domainRegex = "domainRegex"
    ip = "ip"
    cidr = "cidr"

    @property
    def is_domain(self) -> bool:
        return self in (RoutingRuleType.domainSuffix, RoutingRuleType.domainFull,
                        RoutingRuleType.domainKeyword, RoutingRuleType.domainRegex)

    @property
    def label(self) -> str:
        return {
            "domainSuffix": "Domain suffix",
            "domainFull": "Domain (exact)",
            "domainKeyword": "Domain keyword",
            "domainRegex": "Domain regex",
            "ip": "IP address",
            "cidr": "IP range (CIDR)",
        }[self.value]


def _is_plausible_domain(s: str) -> bool:
    return (bool(s) and len(s) <= 253 and s[0] != "." and s[-1] != "." and ".." not in s
            and all(c.isascii() and (c.isalpha() or c.isdigit() or c in "-.") for c in s))


def routing_rule_validation_error(rule_type: RoutingRuleType, value: str) -> str | None:
    """None when value is a well-formed instance of type; otherwise a short message for the editor."""
    v = value.strip()
    if not v:
        return "Value is required."
    if rule_type in (RoutingRuleType.domainSuffix, RoutingRuleType.domainFull):
        return None if _is_plausible_domain(v) else "Not a valid domain name."
    if rule_type == RoutingRuleType.domainKeyword:
        return None  # any substring is valid
    if rule_type == RoutingRuleType.domainRegex:
        try:
            re.compile(v)
            return None
        except re.error:
            return "Not a valid regular expression."
    if rule_type == RoutingRuleType.ip:
        try:
            CIDRMatcher(v)
            return None
        except ValueError:
            return "Not a valid IPv4 or IPv6 address."
    if rule_type == RoutingRuleType.cidr:
        if "/" not in v:
            return "A CIDR needs a /prefix, e.g. 10.0.0.0/8."
        try:
            CIDRMatcher(v)
            return None
        except ValueError:
            return "Not a valid CIDR range."
    return None


@dataclass
class RoutingRule:
    """One user-defined routing rule: traffic matching value (as type) gets action. First match wins."""
    type: RoutingRuleType
    value: str
    action: RoutingAction
    enabled: bool = True
    id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        self.value = self.value.strip()

    @property
    def validation_error(self) -> str | None:
        return routing_rule_validation_error(self.type, self.value)

    @property
    def is_valid(self) -> bool:
        return self.validation_error is None


PRIVATE_NETWORK_RANGES = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "100.64.0.0/10",
    "fc00::/7", "fe80::/10", "::1/128",
]


@dataclass
class RoutingConfig:
    """The user's complete routing configuration."""
    rules: list[RoutingRule] = field(default_factory=list)
    default_action: RoutingAction = RoutingAction.proxy
    bypass_private_networks: bool = False

    @property
    def is_empty(self) -> bool:
        """True when this config changes nothing (plain full-tunnel behaviour)."""
        return (not self.rules and not self.bypass_private_networks
                and self.default_action == RoutingAction.proxy)

    @property
    def effective_rules(self) -> list[RoutingRule]:
        """rules, with private-network ranges appended as low-priority .direct rules when enabled."""
        if not self.bypass_private_networks:
            return self.rules
        return self.rules + [RoutingRule(type=RoutingRuleType.cidr, value=r, action=RoutingAction.direct)
                             for r in PRIVATE_NETWORK_RANGES]


class CIDRMatcher:
    """A parsed IPv4/IPv6 address or CIDR range, compared as raw bytes so v4 and v6 share one implementation."""

    def __init__(self, text: str) -> None:
        parts = text.split("/", 1)
        if len(parts) > 2:
            raise ValueError("bad CIDR")
        addr = self._parse_address(parts[0])
        if addr is None:
            raise ValueError("bad address")
        self.bytes_ = addr
        if len(parts) == 2:
            try:
                p = int(parts[1])
            except ValueError:
                raise ValueError("bad prefix")
            if not 0 <= p <= len(addr) * 8:
                raise ValueError("bad prefix")
            self.prefix_length = p
        else:
            self.prefix_length = len(addr) * 8

    def contains(self, other: "CIDRMatcher") -> bool:
        """True when other (a bare address) falls inside this range."""
        if len(self.bytes_) != len(other.bytes_):
            return False
        remaining = self.prefix_length
        for i in range(len(self.bytes_)):
            if remaining <= 0:
                break
            bits = min(8, remaining)
            mask = 0xFF if bits == 8 else (0xFF << (8 - bits)) & 0xFF
            if (self.bytes_[i] & mask) != (other.bytes_[i] & mask):
                return False
            remaining -= bits
        return True

    @staticmethod
    def _parse_address(s: str) -> bytes | None:
        v4 = CIDRMatcher._parse_ipv4(s)
        if v4 is not None:
            return v4
        return CIDRMatcher._parse_ipv6(s)

    @staticmethod
    def _parse_ipv4(s: str) -> bytes | None:
        parts = s.split(".")
        if len(parts) != 4:
            return None
        out = []
        for p in parts:
            if not p or len(p) > 3 or not p.isdigit():
                return None
            v = int(p)
            if v > 255:
                return None
            out.append(v)
        return bytes(out)

    @staticmethod
    def _parse_ipv6(s: str) -> bytes | None:
        # Full and "::" compressed forms; no zone id, no embedded IPv4 (not needed for routing rules).
        if ":" not in s or not s:
            return None
        halves = s.split("::")
        if len(halves) > 2:
            return None

        def groups(part: str) -> list[int] | None:
            if part == "":
                return []
            out = []
            for g in part.split(":"):
                if not g or len(g) > 4:
                    return None
                try:
                    out.append(int(g, 16))
                except ValueError:
                    return None
            return out

        if len(halves) == 2:
            head = groups(halves[0])
            tail = groups(halves[1])
            if head is None or tail is None:
                return None
            if len(head) + len(tail) > 8:
                return None
            head = head + [0] * (8 - len(head) - len(tail))
        else:
            head = groups(s)
            if head is None or len(head) != 8:
                return None
            tail = []
        all_groups = head + tail
        if len(all_groups) != 8:
            return None
        out = bytearray()
        for g in all_groups:
            out.append((g >> 8) & 0xFF)
            out.append(g & 0xFF)
        return bytes(out)


class RoutingMatcher:
    """Matches a domain name or IP literal against a RoutingConfig, first rule wins."""

    @staticmethod
    def match_domain(domain: str, config: RoutingConfig) -> RoutingRule | None:
        d = domain.lower().strip(".")
        for rule in config.effective_rules:
            if not rule.enabled or not rule.type.is_domain:
                continue
            if rule.type == RoutingRuleType.domainFull:
                if d == rule.value.lower():
                    return rule
            elif rule.type == RoutingRuleType.domainSuffix:
                suf = rule.value.lower()
                if d == suf or d.endswith("." + suf):
                    return rule
            elif rule.type == RoutingRuleType.domainKeyword:
                if rule.value.lower() in d:
                    return rule
            elif rule.type == RoutingRuleType.domainRegex:
                try:
                    if re.search(rule.value, d, re.IGNORECASE):
                        return rule
                except re.error:
                    continue
        return None

    @staticmethod
    def match_ip(ip: str, config: RoutingConfig) -> RoutingRule | None:
        try:
            target = CIDRMatcher(ip)
        except ValueError:
            return None
        for rule in config.effective_rules:
            if not rule.enabled or rule.type.is_domain:
                continue
            try:
                m = CIDRMatcher(rule.value)
            except ValueError:
                continue
            if m.contains(target):
                return rule
        return None

    @staticmethod
    def action(domain: str | None = None, ip: str | None = None,
               config: RoutingConfig | None = None) -> RoutingAction:
        config = config or RoutingConfig()
        if domain is not None:
            rule = RoutingMatcher.match_domain(domain, config)
            if rule:
                return rule.action
        if ip is not None:
            rule = RoutingMatcher.match_ip(ip, config)
            if rule:
                return rule.action
        return config.default_action