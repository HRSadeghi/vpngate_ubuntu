"""Opt-in diagnostic upload (port of VGStatistics.swift) — OFF by default; nothing is sent or
scheduled until the user turns it on. The Windows client does NOT send this for an ordinary
client; the payload is this app's own."""

from __future__ import annotations

import random
import time
import urllib.request
import uuid

from ..core.pack import Pack
from .events import Event


SEND_INTERVAL = 600.0   # 10 minutes
RETRY_INTERVAL = 60.0   # 1 minute
OPT_IN_KEY = "telemetryOptIn"
HOST_KEY_KEY = "telemetryHostKey"


class VGStatistics:
    def __init__(self, prefs=None, start_if_enabled: bool = True) -> None:
        self.prefs = prefs
        self.is_enabled = bool(prefs.get(OPT_IN_KEY)) if prefs else False
        self.last_sent_at: float | None = None
        self.last_status: str | None = None
        self.changed = Event()
        self._endpoint_override: str | None = None
        self._timer = None
        self._loop = None
        if self.is_enabled and start_if_enabled:
            self.start()

    def _notify(self) -> None:
        self.changed.emit()

    @property
    def is_scheduled(self) -> bool:
        return self._timer is not None

    def set_enabled(self, value: bool) -> None:
        self.is_enabled = value
        if self.prefs:
            self.prefs.set(OPT_IN_KEY, value)
        if value:
            self.start()
        else:
            self.stop()
        self._notify()

    @property
    def host_key(self) -> str:
        if self.prefs:
            k = self.prefs.get(HOST_KEY_KEY)
            if k:
                return k
        return self.reset_host_key()

    def reset_host_key(self) -> str:
        """Random per-install identifier (not derived from the machine)."""
        k = uuid.uuid4().hex
        if self.prefs:
            self.prefs.set(HOST_KEY_KEY, k)
        return k

    @staticmethod
    def payload_description() -> list[str]:
        p = make_telemetry_pack("<random per-install ID>")
        return [f"HostKey: {p.str('HostKey')}", f"Build: {p.int('Build')}",
                f"ClientVer: {p.int('ClientVer')}", f"ClientBuild: {p.int('ClientBuild')}",
                f"ClientOsName: {p.str('ClientOsName')}", f"IsClient: {p.int('IsClient')}"]

    def start(self) -> None:
        self.stop()
        if not self.is_enabled:
            return
        self._schedule(5.0)  # first upload shortly after the user turned it on

    def stop(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _schedule(self, interval: float) -> None:
        self.stop()
        if not self.is_enabled:
            return
        import threading
        self._timer = threading.Timer(interval, self._fire)
        self._timer.daemon = True
        self._timer.start()

    def _fire(self) -> None:
        self._timer = None
        self.send_statistics()

    @staticmethod
    def telemetry_url(host_key: str, base_url: str | None = None) -> str:
        if base_url:
            return base_url
        # x%c.x%c are the hex digits at index 2 and 3 of the key (client_exe.c:12530-12535).
        chars = list(host_key)
        c0 = chars[2] if len(chars) > 2 else "0"
        c1 = chars[3] if len(chars) > 3 else "0"
        rand = random.getrandbits(64)
        return f"https://x{c0}.x{c1}.statistics.api.vpngate2.jp/api/statistics/?rand={rand}"

    def send_statistics(self, override_url: str | None = None) -> bool:
        if not self.is_enabled:
            return False
        host_key = self.host_key
        target = override_url or self._endpoint_override or self.telemetry_url(host_key)
        pack = make_telemetry_pack(host_key)
        body = pack.serialize()
        req = urllib.request.Request(
            target, data=body, method="POST",
            headers={"Content-Type": "application/octet-stream",
                     "User-Agent": "VPNGateLinux (opt-in diagnostics)"})
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                ok = resp.status == 200
        except urllib.error.HTTPError as e:
            ok = False
            self.last_status = f"Server error response ({e.code})"
        except Exception as e:
            ok = False
            self.last_status = f"Error: {e}"
        if ok:
            self.last_sent_at = time.time()
            self.last_status = "Successfully uploaded statistics"
            self._schedule(SEND_INTERVAL)
        else:
            if "Server error" not in (self.last_status or "") and "Error:" not in (self.last_status or ""):
                self.last_status = "Server error response"
            self._schedule(RETRY_INTERVAL)
        self._notify()
        return ok


def make_telemetry_pack(host_key: str) -> Pack:
    p = Pack()
    p.add_str("HostKey", host_key)
    p.add_int("Build", 9807)
    p.add_int("ClientVer", 444)
    p.add_int("ClientBuild", 9807)
    p.add_str("ClientOsName", "Linux")
    p.add_int("IsClient", 1)
    return p