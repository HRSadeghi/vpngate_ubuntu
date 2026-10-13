"""Minimal HTTP head parsing (port of HTTPHead.swift)."""

from __future__ import annotations

TERMINATOR = b"\r\n\r\n"
MAX_SIZE = 16384


class HTTPHead:
    def __init__(self, status: str, headers: dict[str, str]) -> None:
        self.status = status
        self.headers = headers  # names lowercased

    @property
    def status_code(self) -> int | None:
        parts = self.status.split(" ")
        if len(parts) >= 2:
            try:
                return int(parts[1])
            except ValueError:
                return None
        return None

    @classmethod
    def parse(cls, head: bytes) -> "HTTPHead":
        lines = head.decode("utf-8", "replace").split("\r\n")
        status = lines.pop(0) if lines else ""
        headers: dict[str, str] = {}
        for l in lines:
            i = l.find(":")
            if i >= 0:
                headers[l[:i].lower()] = l[i + 1:].strip()
        return cls(status, headers)