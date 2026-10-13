"""UDP acceleration v2 packet framing and ChaCha20-Poly1305 encryption (port of UdpAccelPacket.swift).

Reference: SoftEther src/Cedar/UdpAccel.c (Version 2.0).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .packets import rd32, rd64
from .stream import StreamError, protocol_error

IV_SIZE = 12
MAC_SIZE = 16
MIN_PLAINTEXT_SIZE = 4 + 8 + 8 + 2 + 1   # 23 bytes (Cookie + MyTick + YourTick + Size + Flag)
MIN_PACKET_SIZE = IV_SIZE + MIN_PLAINTEXT_SIZE + MAC_SIZE  # 51 bytes
MAX_PADDING = 31                          # upstream pads rand() % MIN(room, 32)


def _aead(key: bytes):
    """The best ChaCha20Poly1305 implementation available."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        return ChaCha20Poly1305(key[:32])
    except Exception:
        from .chacha_fallback import PureChaCha20Poly1305
        return PureChaCha20Poly1305(key[:32])


@dataclass
class UdpAccelHeader:
    cookie: int
    my_tick: int
    your_tick: int
    size: int
    # The flag byte is upstream's COMPRESS flag (UdpAccel.c:353, :914): nonzero means zlib-compressed.
    compressed: bool


@dataclass
class UdpAccelDecodedPacket:
    header: UdpAccelHeader
    payload: bytes


def padding_size(data_size: int, max_size: int, random=None) -> int:
    """Padding length (UdpAccel.c:535-540): zero when the packet already reaches max_size,
    else rand() % min(max_size - current, 32)."""
    if random is None:
        random = lambda bound: int.from_bytes(os.urandom(4), "little") % max(bound, 1)
    current = MIN_PACKET_SIZE + data_size
    if current >= max_size:
        return 0
    return random(min(max_size - current, 32))


def encode(key32: bytes, iv: bytes, cookie: int, my_tick: int, your_tick: int,
           compressed: bool, payload: bytes, padding_size: int = 0,
           plain_mode: bool = False) -> tuple[bytes, bytes]:
    """Encrypts and encodes a UDP acceleration v2 packet. Returns (packet, next_iv)."""
    if not plain_mode:
        if len(key32) < 32:
            raise protocol_error(f"Invalid ChaCha20-Poly1305 key size ({len(key32)} < 32)")
        if len(iv) != IV_SIZE:
            raise protocol_error(f"Invalid IV size ({len(iv)} != {IV_SIZE})")

    plaintext = bytearray()
    # 1. Cookie (4 bytes BE)
    plaintext += cookie.to_bytes(4, "big")
    # 2. My Tick (8 bytes BE) — 0 becomes 1 (upstream never sends tick 0)
    plaintext += ((my_tick if my_tick != 0 else 1)).to_bytes(8, "big")
    # 3. Your Tick (8 bytes BE)
    plaintext += your_tick.to_bytes(8, "big")
    # 4. Size (2 bytes BE)
    plaintext += min(len(payload), 0xFFFF).to_bytes(2, "big")
    # 5. Flag (1 byte)
    plaintext.append(1 if compressed else 0)
    # 6. Data
    plaintext += payload
    # 7. Padding (0..31 bytes; upstream never pads in plaintext mode)
    if padding_size > 0 and not plain_mode:
        plaintext += bytes(min(padding_size, 32))

    # Plaintext mode (udp_acceleration_use_encryption == false): no IV, no AEAD, no MAC.
    if plain_mode:
        return bytes(plaintext), iv

    aead = _aead(key32)
    sealed = aead.encrypt(bytes(iv), bytes(plaintext), None)
    ciphertext = sealed[:-MAC_SIZE]
    tag = sealed[-MAC_SIZE:]

    # Wire format: IV (12 B) + Ciphertext + Tag (16 B)
    packet = bytes(iv) + ciphertext + tag
    # Next IV: last 12 bytes of ciphertext (before tag), or the original nonce
    next_iv = ciphertext[-IV_SIZE:] if len(ciphertext) >= IV_SIZE else bytes(iv)
    return packet, next_iv


def decode(packet: bytes, key32: bytes, plain_mode: bool = False) -> UdpAccelDecodedPacket:
    """Decrypts and decodes a received UDP acceleration v2 packet."""
    if plain_mode:
        plain = packet
    else:
        plain = _decrypt(packet, key32)
    return _parse(plain)


def _decrypt(packet: bytes, key32: bytes) -> bytes:
    if len(packet) < MIN_PACKET_SIZE:
        raise protocol_error(f"UDP packet too short ({len(packet)} < {MIN_PACKET_SIZE})")
    if len(key32) < 32:
        raise protocol_error(f"Invalid ChaCha20-Poly1305 key size ({len(key32)} < 32)")

    iv = packet[:IV_SIZE]
    ciphertext_and_tag = packet[IV_SIZE:]
    if len(ciphertext_and_tag) < MAC_SIZE:
        raise protocol_error("UDP packet missing MAC")
    ciphertext = ciphertext_and_tag[:-MAC_SIZE]
    tag = ciphertext_and_tag[-MAC_SIZE:]

    aead = _aead(key32)
    try:
        return aead.decrypt(iv, ciphertext + tag, None)
    except Exception:
        raise protocol_error("UDP acceleration packet failed authentication")


def _parse(plain: bytes) -> UdpAccelDecodedPacket:
    if len(plain) < MIN_PLAINTEXT_SIZE:
        raise protocol_error(f"Decrypted UDP packet too short ({len(plain)})")

    cookie = rd32(plain, 0)
    my_tick = rd64(plain, 4)
    your_tick = rd64(plain, 12)
    size = (plain[20] << 8) | plain[21]
    compressed = plain[22] != 0

    data_offset = 23
    data_len = size
    if len(plain) < data_offset + data_len:
        raise protocol_error(f"Truncated UDP payload ({len(plain)} < {data_offset + data_len})")

    payload = plain[data_offset:data_offset + data_len]
    return UdpAccelDecodedPacket(
        UdpAccelHeader(cookie, my_tick, your_tick, size, compressed), payload)


__all__ = ["StreamError", "protocol_error", "UdpAccelHeader", "UdpAccelDecodedPacket",
           "padding_size", "encode", "decode", "IV_SIZE", "MAC_SIZE",
           "MIN_PLAINTEXT_SIZE", "MIN_PACKET_SIZE", "MAX_PADDING"]