"""Connection history, kept locally (port of ConnectionLog.swift)."""

from __future__ import annotations

import json
import os
import time
import uuid

from .events import Event
from .paths import support_file


class ConnectionLogEntry:
    def __init__(self, server_name: str, server_ip: str, connected_at: float | None = None,
                 disconnected_at: float | None = None, duration_seconds: float | None = None,
                 bytes_in: int = 0, bytes_out: int = 0, error: str | None = None,
                 id: str | None = None) -> None:
        self.id = id or str(uuid.uuid4())
        self.serverName = server_name
        self.serverIP = server_ip
        self.connectedAt = connected_at if connected_at is not None else time.time()
        self.disconnectedAt = disconnected_at
        self.durationSeconds = duration_seconds
        self.bytesIn = bytes_in
        self.bytesOut = bytes_out
        self.error = error

    def to_json(self) -> dict:
        d = {
            "id": self.id, "serverName": self.serverName, "serverIP": self.serverIP,
            "connectedAt": self.connectedAt, "bytesIn": self.bytesIn, "bytesOut": self.bytesOut,
        }
        for key, val in (("disconnectedAt", self.disconnectedAt),
                         ("durationSeconds", self.durationSeconds), ("error", self.error)):
            if val is not None:
                d[key] = val
        return d

    @classmethod
    def from_json(cls, d: dict) -> "ConnectionLogEntry":
        return cls(
            server_name=d.get("serverName", ""), server_ip=d.get("serverIP", ""),
            connected_at=d.get("connectedAt"),
            disconnected_at=d.get("disconnectedAt"),
            duration_seconds=d.get("durationSeconds"),
            bytes_in=int(d.get("bytesIn", 0) or 0),
            bytes_out=int(d.get("bytesOut", 0) or 0),
            error=d.get("error"), id=d.get("id"),
        )


class ConnectionLogStore:
    def __init__(self, file_url: str | None = None) -> None:
        self.fileURL = file_url or support_file("connection_history.json")
        self.entries: list[ConnectionLogEntry] = []
        self.changed = Event()
        self.load()

    def _notify(self) -> None:
        self.changed.emit()

    def load(self) -> None:
        try:
            with open(self.fileURL) as f:
                records = json.load(f)
            self.entries = [ConnectionLogEntry.from_json(r) for r in records]
        except (OSError, ValueError):
            self.entries = []
        self._notify()

    def save(self) -> None:
        try:
            tmp = self.fileURL + ".tmp"
            with open(tmp, "w") as f:
                json.dump([e.to_json() for e in self.entries], f)
            os.replace(tmp, self.fileURL)
        except OSError:
            pass

    def record_start(self, server_name: str, server_ip: str) -> str:
        entry = ConnectionLogEntry(server_name=server_name, server_ip=server_ip)
        self.entries.insert(0, entry)
        if len(self.entries) > 100:
            del self.entries[100:]
        self.save()
        self._notify()
        return entry.id

    def record_end(self, id: str, bytes_in: int, bytes_out: int, error: str | None) -> None:
        for idx, entry in enumerate(self.entries):
            if entry.id == id:
                now = time.time()
                entry.disconnectedAt = now
                entry.durationSeconds = now - entry.connectedAt
                entry.bytesIn = bytes_in
                entry.bytesOut = bytes_out
                entry.error = error
                self.save()
                self._notify()
                return

    def clear(self) -> None:
        self.entries = []
        self.save()
        self._notify()