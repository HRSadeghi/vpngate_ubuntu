"""Validation for values that end up in privileged command lines or sockets (port of InputValidation.swift)."""

from __future__ import annotations

from .routing import CIDRMatcher


def is_valid_port(p: int | None) -> bool:
    return p is not None and 1 <= p <= 65535


def is_ipv4_literal(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p or len(p) > 3 or not p.isascii() or not p.isdigit():
            return False
        try:
            if int(p) > 255:
                return False
        except ValueError:
            return False
    return True


def is_valid_host(s: str) -> bool:
    """IPv4 literal or RFC 1123 hostname. Never starts with '-' (would be parsed as an option)."""
    if not s or len(s) > 253:
        return False
    if is_ipv4_literal(s):
        return True
    if all(c.isdigit() or c == "." for c in s):
        return False  # malformed dotted number, not a hostname
    if s[0] in "-." or s[-1] in ".-":
        return False
    return (all(c.isascii() and (c.isalpha() or c.isdigit() or c in "-.") for c in s)
            and ".." not in s)


def is_local_address(s: str) -> bool:
    """Loopback (127/8) and link-local (169.254/16) hosts must never get a bypass route."""
    if not is_ipv4_literal(s):
        return s.lower() == "localhost"
    o = [int(x) for x in s.split(".")]
    return o[0] == 127 or (o[0] == 169 and o[1] == 254) or o[0] == 0


def is_non_public_ipv4(s: str) -> bool:
    """Unspecified, loopback, link-local and RFC 1918 IPv4 literals."""
    if not is_ipv4_literal(s):
        return False
    o = [int(x) for x in s.split(".")]
    return (o[0] == 0 or o[0] == 10 or o[0] == 127 or (o[0] == 169 and o[1] == 254)
            or (o[0] == 172 and 16 <= o[1] <= 31) or (o[0] == 192 and o[1] == 168))


def normalized_fingerprint(s: str) -> str | None:
    """SHA-1 (40) or SHA-256 (64) hex digits, ':' ' ' '-' separators allowed → bare lowercase hex."""
    hexdigits = "".join(c for c in s if not c.isspace() and c not in ":").lower()
    if len(hexdigits) not in (40, 64):
        return None
    if not all(c.isascii() and (c.isdigit() or c in "abcdef") for c in hexdigits):
        return None
    return hexdigits


def parse_mac_address(s: str) -> bytes | None:
    """A MAC address: 6 hex byte pairs, ':' or '-' separated."""
    parts = [p for p in s.replace(":", "-").split("-") if p != "" or False]
    # Swift splits on both separators (empty parts dropped).
    parts = [p for p in s.replace("-", ":").split(":") if p != ""]
    if len(parts) != 6:
        return None
    try:
        return bytes(int(p, 16) for p in parts)
    except ValueError:
        return None


def is_valid_identity_field(s: str) -> bool:
    """hub and user names travel in the SoftEther handshake: at most 255 bytes, no NUL."""
    raw = s.encode("utf-8")
    return len(raw) <= 255 and b"\x00" not in raw


def is_ip_literal(s: str) -> bool:
    """A bare IPv4 or IPv6 address literal (no "/prefix")."""
    if "/" in s:
        return False
    try:
        return CIDRMatcher(s) is not None
    except ValueError:
        return False