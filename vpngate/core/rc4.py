"""RC4 (ARC4) stream cipher (port of RC4.swift).

SoftEther uses RC4 for VPNGate.dat body decryption (key = SHA1(seed)) and
legacy password hashing/scrambling.
"""

from __future__ import annotations


class RC4:
    def __init__(self, key: bytes) -> None:
        self._s = list(range(256))
        self._i = 0
        self._j = 0
        if not key:
            return
        j = 0
        s = self._s
        klen = len(key)
        for i in range(256):
            j = (j + s[i] + key[i % klen]) & 0xFF
            s[i], s[j] = s[j], s[i]

    def process(self, data: bytes) -> bytes:
        """Process (encrypt/decrypt) data and return the result."""
        out = bytearray(data)
        s = self._s
        i = self._i
        j = self._j
        for idx in range(len(out)):
            i = (i + 1) & 0xFF
            j = (j + s[i]) & 0xFF
            s[i], s[j] = s[j], s[i]
            out[idx] ^= s[(s[i] + s[j]) & 0xFF]
        self._i = i
        self._j = j
        return bytes(out)

    @staticmethod
    def cipher(key: bytes, data: bytes) -> bytes:
        return RC4(key).process(data)