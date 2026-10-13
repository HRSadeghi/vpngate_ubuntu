"""SHA-0 cryptographic hash function (FIPS PUB 180, 1993) — port of SHA0.swift.

SoftEther uses SHA-0 for authtype 1 (secure password) authentication and internal
probe signatures. Unlike SHA-1, SHA-0 does NOT rotate left by 1 during message
schedule expansion.
"""

from __future__ import annotations

import struct

MASK32 = 0xFFFFFFFF


def _rotl(v: int, n: int) -> int:
    return ((v << n) | (v >> (32 - n))) & MASK32


def hash(data: bytes) -> bytes:
    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0

    bit_count = len(data) * 8
    padded = bytearray(data)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0)
    padded += struct.pack(">Q", bit_count)

    w = [0] * 80
    for c in range(len(padded) // 64):
        offset = c * 64
        for i in range(16):
            w[i] = struct.unpack_from(">I", padded, offset + i * 4)[0]
        # SHA-0 message schedule: no 1-bit rotate!
        for i in range(16, 80):
            w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]

        a, b, cc, d, e = h0, h1, h2, h3, h4
        for i in range(80):
            if i < 20:
                f = (b & cc) | (~b & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ cc ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & cc) | (b & d) | (cc & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ cc ^ d
                k = 0xCA62C1D6
            temp = (_rotl(a, 5) + f + e + k + w[i]) & MASK32
            e = d
            d = cc
            cc = _rotl(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & MASK32
        h1 = (h1 + b) & MASK32
        h2 = (h2 + cc) & MASK32
        h3 = (h3 + d) & MASK32
        h4 = (h4 + e) & MASK32

    return struct.pack(">5I", h0, h1, h2, h3, h4)


digest_length = 20