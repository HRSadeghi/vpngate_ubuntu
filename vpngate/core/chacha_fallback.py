"""Pure-Python ChaCha20-Poly1305 (RFC 8439) fallback.

Used only when the `cryptography` package is unavailable or too old to provide
ChaCha20Poly1305; correctness is verified against the RFC's own test vectors in tests.
"""

from __future__ import annotations

import struct

_P1305_MOD = (1 << 130) - 5


def _rotl(v: int, n: int) -> int:
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def _chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    constants = b"expand 32-byte k"
    state = list(struct.unpack("<4I", constants)) + list(struct.unpack("<8I", key)) \
        + [counter & 0xFFFFFFFF] + list(struct.unpack("<3I", nonce))
    x = state[:]

    def qr(a: int, b: int, c: int, d: int) -> None:
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl(x[d] ^ x[a], 16)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl(x[b] ^ x[c], 12)
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl(x[d] ^ x[a], 8)
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl(x[b] ^ x[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)

    return struct.pack("<16I", *[(a + b) & 0xFFFFFFFF for a, b in zip(x, state)])


def _poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    return _chacha_block(key, 0, nonce)[:32]


def _pad16(data: bytes) -> bytes:
    """Zero-pads to the next 16-byte boundary (no padding when already aligned)."""
    rem = len(data) % 16
    return b"\x00" * (16 - rem) if rem else b""


def _poly1305(mac_key: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(mac_key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(mac_key[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % _P1305_MOD
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


class PureChaCha20Poly1305:
    """RFC 8439 AEAD with a 12-byte nonce."""

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("key must be 32 bytes")
        self.key = key

    def _mac_data(self, aad: bytes, ciphertext: bytes) -> bytes:
        # aad || pad16(aad) || ciphertext || pad16(ciphertext) || len(aad) || len(ct) (LE64 each)
        return (aad + _pad16(aad) + ciphertext + _pad16(ciphertext)
                + len(aad).to_bytes(8, "little") + len(ciphertext).to_bytes(8, "little"))

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
        if len(nonce) != 12:
            raise ValueError("nonce must be 12 bytes")
        ciphertext = self._xor_stream(nonce, plaintext, counter=1)
        mac_key = _poly1305_key_gen(self.key, nonce)
        tag = _poly1305(mac_key, self._mac_data(aad, ciphertext))
        return ciphertext + tag

    def decrypt(self, nonce: bytes, data: bytes, aad: bytes = b"") -> bytes:
        if len(data) < 16:
            raise ValueError("ciphertext too short")
        ciphertext, tag = data[:-16], data[-16:]
        mac_key = _poly1305_key_gen(self.key, nonce)
        expected = _poly1305(mac_key, self._mac_data(aad, ciphertext))
        if not _bytes_eq(expected, tag):
            raise ValueError("authentication failed")
        return self._xor_stream(nonce, ciphertext, counter=1)

    def _xor_stream(self, nonce: bytes, data: bytes, counter: int) -> bytes:
        out = bytearray()
        for i in range(0, len(data), 64):
            keystream = _chacha_block(self.key, counter + i // 64, nonce)
            out += bytes(a ^ b for a, b in zip(data[i:i + 64], keystream))
        return bytes(out)


def _bytes_eq(a: bytes, b: bytes) -> bool:
    return len(a) == len(b) and all(x == y for x, y in zip(a, b))