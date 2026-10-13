"""Linux TUN device (port of Utun.swift) — /dev/net/tun with TUNSETIFF, IFF_TUN | IFF_NO_PI.

On Linux the tunnel carries bare IP packets (no 4-byte address-family header like macOS utun),
so a single write() path covers both IPv4 and IPv6 and the reader forwards whatever it reads.
"""

from __future__ import annotations

import fcntl
import os
import select
import struct
import threading

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
TUN_PATH = "/dev/net/tun"


class TunError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class TunDevice:
    """A Linux TUN interface with a dedicated reader thread."""

    def __init__(self, name_hint: str = "") -> None:
        self.name = ""
        self.on_packet = None            # callback(bytes) for IP packets from the kernel
        self.forward_ipv6 = False        # v6 is always forwarded on Linux (single stream)
        self._fd = -1
        self._wake_r = -1
        self._wake_w = -1
        self._reading = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        try:
            self._fd = os.open(TUN_PATH, os.O_RDWR)
        except OSError as e:
            raise TunError(f"open {TUN_PATH} (need root and the tun kernel module): {e}") from None

        ifr = struct.pack("16sH", name_hint.encode()[:15], IFF_TUN | IFF_NO_PI)
        try:
            result = fcntl.ioctl(self._fd, TUNSETIFF, ifr)
        except OSError as e:
            os.close(self._fd)
            self._fd = -1
            raise TunError(f"TUNSETIFF (need root): {e}") from None
        ifname = struct.unpack("16sH", result)[0]
        self.name = ifname.split(b"\x00")[0].decode()
        os.set_blocking(self._fd, False)

        self._wake_r, self._wake_w = os.pipe()

    def start_reading(self) -> None:
        with self._lock:
            if self._fd < 0 or self._reading:
                return
            self._reading = True
            fd = self._fd
            self._thread = threading.Thread(target=self._read_loop, args=(fd,), daemon=True,
                                            name=f"vpngate-tun-{self.name}")
        self._thread.start()

    def _read_loop(self, fd: int) -> None:
        while True:
            try:
                fds = select.poll()
                fds.register(fd, select.POLLIN)
                fds.register(self._wake_r, select.POLLIN)
                events = fds.poll(-1)
            except (OSError, ValueError):
                break
            stop = False
            readable = False
            for f, rev in events:
                if f == self._wake_r:
                    stop = True
                elif rev & select.POLLIN:
                    readable = True
            if stop:
                break
            if not readable:
                continue
            try:
                data = os.read(fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                break
            if not data:
                break
            cb = self.on_packet
            if cb:
                cb(data)

    def write(self, packet: bytes) -> None:
        """Writes an IP packet (v4 or v6) into the tunnel."""
        with self._lock:
            fd = self._fd
        if fd < 0:
            return
        try:
            os.write(fd, packet)
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            was_reading = self._reading
            self._reading = False
            fd = self._fd
            self._fd = -1
        if was_reading:
            try:
                os.write(self._wake_w, b"\x01")
            except OSError:
                pass
            t = self._thread
            if t is not None:
                t.join(timeout=2)
        try:
            os.close(self._wake_r)
        except OSError:
            pass
        try:
            os.close(self._wake_w)
        except OSError:
            pass
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass