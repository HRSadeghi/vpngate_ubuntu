"""Newline-delimited JSON over a Unix socket, restricted to allowed users (port of IPCServer.swift).

Linux uses SO_PEERCRED (the equivalent of macOS getpeereid) to learn the connecting uid.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import struct

from ..core import validation
from ..core.ipcmessages import (ConnectionState, HelperEvent, HelperRequest, HELPER_VERSION,
                                decode_line, encode_line)
from .certauth import MAX_CERT_BYTES, MAX_KEY_BYTES
from .session import VPNSession

MAX_QUEUED = 256
STALL_TIMEOUT_MS = 2000


def console_uid() -> int | None:
    """uid of the user logged in at the console: the newest non-root /run/user/<uid> directory."""
    best: tuple[float, int] | None = None
    try:
        for entry in os.listdir("/run/user"):
            if not entry.isdigit():
                continue
            uid = int(entry)
            if uid == 0:
                continue
            try:
                mtime = os.stat(f"/run/user/{entry}").st_mtime
            except OSError:
                continue
            if best is None or mtime > best[0]:
                best = (mtime, uid)
    except OSError:
        return None
    return best[1] if best else None


def peer_uid(fd: int) -> int | None:
    """SO_PEERCRED gives pid, uid, gid on Linux (like getpeereid on macOS)."""
    try:
        creds = fd.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                              struct.calcsize("3i"))
        _, uid, _gid = struct.unpack("3i", creds)
        return uid
    except OSError:
        return None


class IPCServer:
    def __init__(self, path: str, allowed_uid: int | None, session: VPNSession,
                 console_uid_fn=console_uid) -> None:
        self.path = path
        self.allowed_uid = allowed_uid
        self.console_uid_fn = console_uid_fn
        self.session = session
        self._clients: set = set()
        self._server: asyncio.AbstractServer | None = None
        session.emit = self._broadcast

    def is_allowed(self, uid: int) -> bool:
        """root, the explicitly configured user, or whoever is logged in at the console."""
        if uid == 0 or uid == self.allowed_uid:
            return True
        c = self.console_uid_fn()
        return c is not None and c == uid and c != 0

    async def start(self) -> None:
        try:
            os.unlink(self.path)
        except OSError:
            pass

        async def client_connected(reader: asyncio.StreamReader,
                                   writer: asyncio.StreamWriter) -> None:
            fd = writer.get_extra_info("socket")
            uid = peer_uid(fd) if fd is not None else None
            if uid is None or not self.is_allowed(uid):
                writer.close()
                return
            client = _IPCClient(reader, writer)
            self._clients.add(client)
            try:
                self._send(client, self.session.snapshot)
                await client.serve(self._handle)
            finally:
                self._clients.discard(client)

        self._server = await asyncio.start_unix_server(client_connected, path=self.path)
        # The socket is connectable by any user and clients are authenticated by uid in accept(),
        # like macOS (the console user is not known at install time); root-only when --uid is set.
        os.chmod(self.path, 0o600 if self.allowed_uid is not None else 0o666)

    def _broadcast(self, event: HelperEvent) -> None:
        for c in list(self._clients):
            self._send(c, event)

    def _send(self, client: "_IPCClient", event: HelperEvent) -> None:
        client.send(encode_line(event))

    async def _handle(self, request: HelperRequest, client: "_IPCClient") -> None:
        if request.cmd == "connect":
            problem = self.validate(request)
            if problem is not None:
                e = self.session.snapshot
                e.log = None
                e.error = f"Rejected connect request: {problem}"
                self._send(client, e)
                return
            if request.config is not None:
                self.session.connect_config(request.config)
            else:
                from ..core.ipcmessages import ProxySettings
                self.session.connect_host(
                    host=request.host or "",
                    port=request.port,
                    proxy=request.proxy or ProxySettings(),
                    auto_reconnect=request.autoReconnect if request.autoReconnect is not None else True,
                    block_ipv6=request.blockIPv6 if request.blockIPv6 is not None else True,
                    routing=request.routing, ports=request.ports)
        elif request.cmd == "disconnect":
            self.session.disconnect()
        else:
            self._send(client, self.session.snapshot)

    # MARK: validation

    @staticmethod
    def validate(r: HelperRequest) -> str | None:
        """Everything that reaches `ip`/the network stack from here must pass validation first."""
        from ..core.clientaccount import routing_config_from_json
        host = r.config.host if (r.config is not None and r.config.host) else r.host
        if not host or not validation.is_valid_host(host):
            return "invalid host"
        if r.port is not None and not validation.is_valid_port(r.port):
            return "invalid port"
        config = r.config
        if config is not None:
            for p in config.ports:
                if not validation.is_valid_port(p):
                    return f"invalid port {p}"
            if config.certDer is not None and len(config.certDer) > MAX_CERT_BYTES:
                return "certificate too large"
            if config.privateKeyDer is not None and len(config.privateKeyDer) > MAX_KEY_BYTES:
                return "private key too large"
            if config.ticket is not None and len(config.ticket) > 1024:
                return "ticket too large"
            if not validation.is_valid_identity_field(config.hubName):
                return "invalid hub name"
            if not validation.is_valid_identity_field(config.userName):
                return "invalid user name"
        p = (config.proxy if config is not None else None) or r.proxy
        if p is not None and p.kind != "none":
            if not validation.is_valid_host(p.host):
                return "invalid proxy host"
            if not validation.is_valid_port(p.port):
                return "invalid proxy port"
        routing_json = (config.routing if config is not None else None) or r.routing
        if routing_json is not None:
            routing = routing_config_from_json(routing_json)
            for rule in routing.rules:
                if rule.validation_error is not None:
                    return f'routing rule "{rule.value}": {rule.validation_error}'
        return None

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None
        for c in list(self._clients):
            c.close()
        self._clients.clear()
        try:
            os.unlink(self.path)
        except OSError:
            pass


class _IPCClient:
    """One connected app. A client that stops reading can never stall the VPN session."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer
        self._closed = False
        self._outbox: list[bytes] = []
        self._draining = False

    def send(self, data: bytes) -> None:
        if self._closed:
            return
        self._outbox.append(data)
        if len(self._outbox) > MAX_QUEUED:
            self._outbox.pop(0)  # events are state snapshots: newest wins
        if not self._draining:
            self._draining = True
            asyncio.get_event_loop().create_task(self._drain())

    async def _drain(self) -> None:
        try:
            while self._outbox:
                d = self._outbox.pop(0)
                try:
                    self.writer.write(d)
                    await asyncio.wait_for(self.writer.drain(), STALL_TIMEOUT_MS / 1000.0)
                except Exception:
                    self.close()
                    return
        finally:
            self._draining = False

    async def serve(self, handler) -> None:
        """Reads newline-delimited requests until the client goes away."""
        buf = b""
        try:
            while not self._closed:
                try:
                    chunk = await asyncio.wait_for(self.reader.read(4096), 500)
                except asyncio.TimeoutError:
                    continue
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 1 << 20:
                    break  # runaway line: drop the client
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        req = decode_line(line, HelperRequest)
                    except Exception:
                        continue
                    await handler(req, self)
        except Exception:
            pass
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._outbox.clear()
        try:
            self.writer.close()
        except Exception:
            pass