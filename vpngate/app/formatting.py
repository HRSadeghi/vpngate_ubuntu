"""Formatting helpers and connection-state presentation (port of Formatting.swift)."""

from __future__ import annotations

import time

from ..core.ipcmessages import ConnectionState


def speed(bps: int) -> str:
    return f"{bps / 1_000_000:.1f} Mbps"


def bytes_fmt(n: int) -> str:
    """Binary byte count like macOS ByteCountFormatter (.binary)."""
    n = float(n)
    for unit in ("bytes", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024 or unit == "PB":
            if unit == "bytes":
                return f"{int(n)} bytes"
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def traffic(n: int) -> str:
    """Decimal byte count like macOS ByteCountFormatter (.decimal)."""
    n = float(n)
    for unit in ("bytes", "kB", "MB", "GB", "TB", "PB"):
        if n < 1000 or unit == "PB":
            if unit == "bytes":
                return f"{int(n)} bytes"
            return f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} PB"


def duration(since: float | None) -> str:
    if since is None:
        return ""
    s = max(0, int(time.time() - since))
    return f"{s // 3600}:{s % 3600 // 60:02d}:{s % 60:02d}"


def duration_seconds(seconds: float) -> str:
    s = max(0, int(seconds))
    return f"{s // 3600}:{s % 3600 // 60:02d}:{s % 60:02d}"


def state_title(state: ConnectionState) -> str:
    return {
        ConnectionState.disconnected: "Disconnected",
        ConnectionState.connecting: "Connecting…",
        ConnectionState.authenticating: "Authenticating…",
        ConnectionState.dhcp: "Getting address…",
        ConnectionState.connected: "Connected",
        ConnectionState.reconnecting: "Reconnecting…",
    }[state]


STATE_SYMBOL = {
    ConnectionState.connected: "lock.shield.fill",
    ConnectionState.disconnected: "lock.open",
}
