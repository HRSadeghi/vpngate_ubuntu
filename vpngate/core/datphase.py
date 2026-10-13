"""Post-login data-phase framing and zlib compression (port of DataPhase.swift).

Wire format after login (SoftEther Connection.c): u32 n then n × (u32 size + frame),
or the keep-alive marker 0xFFFFFFFF, u32 len, len junk bytes. Big-endian.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass

from .packets import be32, rd32
from .bytebuffer import ByteBuffer

MAX_BLOCK = 3200
MAX_BLOCKS_PER_BATCH = 4095
KEEP_ALIVE_MAGIC = 0xFFFFFFFF
MAX_KEEP_ALIVE = 4095


class DataPhaseError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class DataPhaseItem:
    kind: str            # "frame" | "keepAlive"
    payload: bytes = b""


def compress_frame(frame: bytes) -> bytes:
    """Compress an individual Ethernet frame with zlib (deflate)."""
    return zlib.compress(frame)


def uncompress_frame(data: bytes, max_len: int = 4096) -> bytes:
    """Decompress a zlib-compressed Ethernet frame."""
    d = zlib.decompressobj()
    try:
        out = d.decompress(data, max_len)
        if d.unconsumed_tail or d.unused_data:
            raise DataPhaseError("Zlib block decompression failed")
        return out
    except zlib.error:
        raise DataPhaseError("Zlib block decompression failed")


def encode(frames: list[bytes]) -> bytes:
    out = bytearray(be32(len(frames)))
    for f in frames:
        out += be32(len(f))
        out += f
    return bytes(out)


def encode_frames(frames: list[bytes], use_compress: bool = False) -> bytes:
    if not use_compress:
        return encode(frames)
    return encode([compress_frame(f) for f in frames])


def encode_keep_alive(junk: bytes) -> bytes:
    return be32(KEEP_ALIVE_MAGIC) + be32(len(junk)) + junk


class DataPhaseDecoder:
    """Incremental decoder: feed it whatever chunks the socket returns."""

    def __init__(self, use_compress: bool = False) -> None:
        self.use_compress = use_compress
        self._buf = ByteBuffer()
        self._state = "header"
        self._remaining = 0
        self._block_size = 0
        self._keep_alive_len = 0

    def _u32(self) -> int | None:
        b = self._buf.take(4)
        if b is None:
            return None
        return rd32(b, 0)

    def feed(self, chunk: bytes) -> list[DataPhaseItem]:
        self._buf.append(chunk)
        out: list[DataPhaseItem] = []
        while True:
            if self._state == "header":
                n = self._u32()
                if n is None:
                    return out
                if n == KEEP_ALIVE_MAGIC:
                    self._state = "keepAliveLength"
                elif n == 0:
                    continue
                elif n > MAX_BLOCKS_PER_BATCH:
                    raise DataPhaseError(f"Bad block count ({n})")
                else:
                    self._state = "blockSize"
                    self._remaining = n
            elif self._state == "keepAliveLength":
                n = self._u32()
                if n is None:
                    return out
                if n > MAX_KEEP_ALIVE:
                    raise DataPhaseError(f"Bad keep-alive length ({n})")
                self._state = "keepAliveBody"
                self._keep_alive_len = n
            elif self._state == "keepAliveBody":
                if self._buf.take(self._keep_alive_len) is None:
                    return out
                out.append(DataPhaseItem("keepAlive"))
                self._state = "header"
            elif self._state == "blockSize":
                n = self._u32()
                if n is None:
                    return out
                if n > MAX_BLOCK:
                    raise DataPhaseError(f"Oversized block ({n} bytes)")
                self._block_size = n
                self._state = "blockBody"
            elif self._state == "blockBody":
                raw = self._buf.take(self._block_size)
                if raw is None:
                    return out
                if self.use_compress:
                    out.append(DataPhaseItem("frame", uncompress_frame(raw)))
                else:
                    out.append(DataPhaseItem("frame", raw))
                if self._remaining > 1:
                    self._remaining -= 1
                    self._state = "blockSize"
                else:
                    self._state = "header"