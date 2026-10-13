"""Talks to the privileged helper over its Unix socket (port of HelperClient.swift).

The blocking socket lives on a reader thread; events are delivered through callbacks that the
GUI marshals onto its own main loop.
"""

from __future__ import annotations

import json
import socket
import threading

from ..core.ipcmessages import HELPER_SOCKET_PATH, HelperEvent, HelperRequest


class HelperClient:
    def __init__(self, path: str = HELPER_SOCKET_PATH) -> None:
        self.path = path
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self.on_event = None      # callback(HelperEvent)
        self.on_disconnect = None  # callback()

    @property
    def is_connected(self) -> bool:
        with self._lock:
            return self._sock is not None

    def connect(self) -> bool:
        with self._lock:
            if self._sock is not None:
                return True
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(self.path)
            except OSError:
                try:
                    s.close()
                except Exception:
                    pass
                return False
            self._sock = s
        t = threading.Thread(target=self._read_loop, args=(s,), daemon=True,
                             name="vpngate-helper-reader")
        t.start()
        return True

    def _read_loop(self, s: socket.socket) -> None:
        buf = b""
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        event = HelperEvent.from_json(json.loads(line.decode("utf-8")))
                    except Exception:
                        continue
                    if self.on_event:
                        self.on_event(event)
        except OSError:
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass
            with self._lock:
                if self._sock is s:
                    self._sock = None
            if self.on_disconnect:
                self.on_disconnect()

    def send(self, request: HelperRequest) -> None:
        if not self.connect():
            return
        with self._lock:
            s = self._sock
        if s is None:
            return
        try:
            data = (json.dumps(request.to_json(), separators=(",", ":")) + "\n").encode()
            s.sendall(data)
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            s = self._sock
            self._sock = None
        if s is not None:
            try:
                s.close()
            except OSError:
                pass