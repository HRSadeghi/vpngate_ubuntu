"""Server certificate pinning (port of CertPin.swift): SHA-1/SHA-256 fingerprint of the DER leaf."""

from __future__ import annotations

import hashlib
from enum import Enum
from dataclasses import dataclass


def _parse_hex(text: str) -> bytes | None:
    hexdigits = "".join(c for c in text if not c.isspace() and c != ":")
    if len(hexdigits) not in (40, 64) or not all(c in "0123456789abcdefABCDEF" for c in hexdigits):
        return None
    try:
        return bytes.fromhex(hexdigits)
    except ValueError:
        return None


@dataclass(frozen=True)
class CertPin:
    digest: bytes

    def __init__(self, text: str):
        digest = _parse_hex(text)
        if digest is None:
            raise ValueError("not a SHA-1/SHA-256 hex fingerprint")
        object.__setattr__(self, "digest", digest)

    def matches(self, cert_der: bytes) -> bool:
        if len(self.digest) == 20:
            actual = hashlib.sha1(cert_der).digest()
        else:
            actual = hashlib.sha256(cert_der).digest()
        return actual == self.digest


class ServerCertPolicyKind(Enum):
    acceptAny = "acceptAny"        # VPN Gate relays: self-signed, unverified
    pinned = "pinned"
    invalidPin = "invalidPin"      # a fingerprint is configured but unparseable: fail closed
    systemTrust = "systemTrust"    # "verify server certificate" without a pin


class ServerCertPolicy:
    def __init__(self, kind: ServerCertPolicyKind, pin: CertPin | None = None) -> None:
        self.kind = kind
        self.pin = pin

    @classmethod
    def from_config(cls, check_server_cert: bool, fingerprint: str | None) -> "ServerCertPolicy":
        fp = (fingerprint or "").strip()
        if fp:
            try:
                return cls(ServerCertPolicyKind.pinned, CertPin(fp))
            except ValueError:
                return cls(ServerCertPolicyKind.invalidPin)
        return cls(ServerCertPolicyKind.systemTrust if check_server_cert else ServerCertPolicyKind.acceptAny)

    def rejection(self, leaf_der: bytes | None) -> str | None:
        """None when the presented leaf is acceptable, otherwise the reason it is not."""
        if self.kind in (ServerCertPolicyKind.acceptAny, ServerCertPolicyKind.systemTrust):
            return None
        if self.kind == ServerCertPolicyKind.invalidPin:
            return "Server certificate fingerprint is not a valid SHA-1/SHA-256 hex string"
        if leaf_der is None:
            return "Server presented no certificate to match the pinned fingerprint"
        assert self.pin is not None
        if self.pin.matches(leaf_der):
            return None
        return "Server certificate does not match the pinned fingerprint"