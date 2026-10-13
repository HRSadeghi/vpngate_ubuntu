"""Timestamped log lines for the helper (goes to the systemd log file)."""

from __future__ import annotations

import time


def stamp() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(tag: str, message: str) -> None:
    print(f"[{stamp()}] {tag} {message}", flush=True)