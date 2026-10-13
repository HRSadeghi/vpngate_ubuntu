"""Growable FIFO byte buffer with O(1) amortised consumption (port of ByteBuffer.swift)."""

from __future__ import annotations


class ByteBuffer:
    def __init__(self) -> None:
        self._storage = bytearray()
        self._head = 0

    @property
    def count(self) -> int:
        return len(self._storage) - self._head

    def append(self, data: bytes) -> None:
        self._storage += data

    def take(self, n: int) -> bytes | None:
        """Removes and returns exactly n bytes, or None if fewer are buffered."""
        if n < 0 or self.count < n:
            return None
        out = bytes(self._storage[self._head:self._head + n])
        self._head += n
        self._compact_if_needed()
        return out

    def take_all(self) -> bytes:
        return self.take(self.count) or b""

    def take_up_to(self, marker: bytes) -> bytes | None:
        """Removes everything up to and including marker; returns the bytes before it."""
        if not marker or self.count < len(marker):
            return None
        idx = self._storage.find(marker, self._head)
        if idx < 0:
            return None
        out = bytes(self._storage[self._head:idx])
        self._head = idx + len(marker)
        self._compact_if_needed()
        return out

    def _compact_if_needed(self) -> None:
        if self._head == len(self._storage):
            self._storage = bytearray()
            self._head = 0
        elif self._head > 1 << 16 and self._head * 2 > len(self._storage):
            self._storage = self._storage[self._head:]
            self._head = 0