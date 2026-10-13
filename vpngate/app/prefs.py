"""App preferences (the UserDefaults equivalent), persisted as JSON."""

from __future__ import annotations

import json
import os
import threading

from .paths import support_file

DEFAULTS: dict = {
    "hasAgreedToDisclaimer": False,
    "favorites": [],
    "autoReconnect": True,
    "proxyKind": "none",
    "proxyHost": "",
    "proxyPort": 0,
    "proxyUsername": "",
    "blockIPv6": True,
    "routingConfig": None,
    "listFetchedAt": None,
    "lastServerID": None,
    "maxLogWeeks": -1,
    "mirrorURL": "",
    "launchAtLogin": False,
    "telemetryOptIn": False,
    "telemetryHostKey": "",
    "alternativeMode": False,
    "lastGoodRelay": None,
}


class Prefs:
    """A small thread-safe key-value store backed by a JSON file."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path or support_file("preferences.json")
        self._lock = threading.Lock()
        self._values: dict = dict(DEFAULTS)
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path) as f:
                stored = json.load(f)
            if isinstance(stored, dict):
                self._values.update(stored)
        except (OSError, ValueError):
            pass

    def _save(self) -> None:
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._values, f)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def get(self, key: str, default=None):
        with self._lock:
            return self._values.get(key, DEFAULTS.get(key, default))

    def set(self, key: str, value) -> None:
        with self._lock:
            self._values[key] = value
            self._save()

    def remove(self, key: str) -> None:
        with self._lock:
            self._values.pop(key, None)
            self._save()