"""A random install-wide identifier kept in a root-only file (port of HostUniqueId.swift).

Deliberately not derived from the hostname or any hardware identifier.
"""

from __future__ import annotations

import hashlib
import os
import secrets

DEFAULT_PATH = "/var/lib/vpngate/helper.uid"


class HostUniqueId:
    def __init__(self, key: bytes) -> None:
        self.key = key

    @classmethod
    def load(cls, path: str = DEFAULT_PATH, random=None) -> "HostUniqueId":
        """Reads `path`; creates it with 32 random bytes (mode 0600) when missing or malformed."""
        random = random or (lambda n: secrets.token_bytes(n))
        try:
            with open(path, "rb") as f:
                d = f.read()
            if len(d) == 32:
                return cls(d)
        except OSError:
            pass
        fresh = random(32)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(fresh)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            os.chmod(path, 0o600)
        except OSError:
            pass
        return cls(fresh)

    @property
    def login_id(self) -> bytes:
        """20-byte login `unique_id` (SHA-1 sized, like the stock client's machine hash)."""
        return hashlib.sha1(b"login" + self.key).digest()

    @property
    def node_id(self) -> bytes:
        """16-byte NodeInfo `UniqueId` (the stock client sends its random Cedar->UniqueId)."""
        return hashlib.sha256(b"node" + self.key).digest()[:16]


_SHARED: HostUniqueId | None = None


def shared() -> HostUniqueId:
    """Process-wide instance; falls back to a per-process random value when the file cannot be written."""
    global _SHARED
    if _SHARED is None:
        _SHARED = HostUniqueId.load()
    return _SHARED