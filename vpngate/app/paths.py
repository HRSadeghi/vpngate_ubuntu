"""Where the app keeps its files (port of AppPaths.swift)."""

from __future__ import annotations

import os

# VPNGATE_SUPPORT_DIR points a run (screenshots, demos, tests) at a scratch folder instead
# of the real data.
SUPPORT_DIR_ENV = "VPNGATE_SUPPORT_DIR"


def support_directory() -> str:
    override = os.environ.get(SUPPORT_DIR_ENV, "")
    if override:
        return override
    return os.path.expanduser("~/.local/share/vpngate")


def support_file(name: str) -> str:
    d = support_directory()
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)


def cache_file(name: str) -> str:
    override = os.environ.get(SUPPORT_DIR_ENV, "")
    if override:
        return os.path.join(override, name)
    d = os.path.expanduser("~/.cache/vpngate")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)
