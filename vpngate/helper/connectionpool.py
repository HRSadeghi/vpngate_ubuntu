"""Multiple TCP connections for one SoftEther session (port of ConnectionPool.swift)."""

from __future__ import annotations

import asyncio
import time

from ..core.datphase import DataPhaseDecoder, DataPhaseItem
from ..core.stream import ByteStream, StreamError, closed_error, protocol_error
from .logutil import log


class SocketDirection:
    """Which way a half-connection socket may carry application data (Connection.c's
    IsSendDirection / IsRecvDirection, from the client's point of view)."""

    BOTH = 0
    SERVER_TO_CLIENT = 1
    CLIENT_TO_SERVER = 2

    def __init__(self, wire_value: int | None = None) -> None:
        # The server's `direction` field on an additional_connect reply (0 both, 1 server->client,
        # 2 client->server, Protocol.c:5257); anything else (absent) is .both.
        if wire_value == 1:
            self.value = self.SERVER_TO_CLIENT
        elif wire_value == 2:
            self.value = self.CLIENT_TO_SERVER
        else:
            self.value = self.BOTH

    @property
    def can_send(self) -> bool:
        return self.value in (self.BOTH, self.CLIENT_TO_SERVER)

    @property
    def can_receive(self) -> bool:
        return self.value in (self.BOTH, self.SERVER_TO_CLIENT)


class ConnectionPool:
    def __init__(self) -> None:
        self.on_frame = None      # callback(bytes)
        self.on_close = None      # callback(error | None)
        self.on_byte_count = None # callback(bytes_in, bytes_out)
        self._sockets: dict[int, dict] = {}
        self._next_id = 1
        self._is_closed = False
        self._lock = asyncio.Lock()

    @property
    def active_count(self) -> int:
        return len(self._sockets)

    def add(self, stream: ByteStream, use_compress: bool, timeout_ms: int,
            direction: SocketDirection | None = None) -> None:
        """Adds an established socket to the pool and starts reading frames from it."""
        if self._is_closed:
            stream.cancel()
            return
        direction = direction or SocketDirection()
        sid = self._next_id
        self._next_id += 1
        entry = {
            "id": sid,
            "stream": stream,
            "direction": direction,
            "bytes_out": 0,
            "reader_task": None,
        }

        last_rx = [time.monotonic()]

        async def reader():
            decoder = DataPhaseDecoder(use_compress=use_compress)
            chunk = stream.buffer.take_all()
            try:
                while True:
                    for item in decoder.feed(chunk):
                        if item.kind == "frame":
                            if self.on_byte_count:
                                self.on_byte_count(len(item.payload), 0)
                            if self.on_frame:
                                self.on_frame(item.payload)
                    chunk = await stream.read_chunk()
                    last_rx[0] = time.monotonic()
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self._remove(sid, e)

        async def watchdog():
            # Send-only sockets never receive: silence there is correct, not a stall.
            if not direction.can_receive:
                return
            poll_s = max(timeout_ms / 2, 50) / 1000.0
            try:
                while True:
                    await asyncio.sleep(poll_s)
                    if time.monotonic() - last_rx[0] >= timeout_ms / 1000.0:
                        self._remove(sid, protocol_error(f"Read idle timeout ({timeout_ms} ms)"))
                        return
            except asyncio.CancelledError:
                pass

        async def supervisor():
            await reader()
            wt.cancel()

        entry["reader_task"] = asyncio.get_event_loop().create_task(supervisor())
        wt = asyncio.get_event_loop().create_task(watchdog())
        self._sockets[sid] = entry
        log("[pool]", f"socket {sid} added (compress={use_compress}, "
                      f"timeout={timeout_ms}ms, {len(self._sockets)} active)")

    async def send(self, data: bytes, byte_count: int) -> None:
        """Selects the least-loaded socket eligible to send and sends the data."""
        async with self._lock:
            if self._is_closed or not self._sockets:
                raise closed_error()
            eligible = [e for e in self._sockets.values() if e["direction"].can_send]
            if not eligible:
                raise closed_error()
            chosen = min(eligible, key=lambda e: e["bytes_out"])
            chosen["bytes_out"] += byte_count
            stream = chosen["stream"]
        await stream.send(data)
        if self.on_byte_count:
            self.on_byte_count(0, byte_count)

    async def broadcast_keep_alive(self, data: bytes) -> None:
        """Broadcasts a keep-alive packet to every socket eligible to send."""
        async with self._lock:
            if self._is_closed:
                return
            streams = [e["stream"] for e in self._sockets.values() if e["direction"].can_send]
        for s in streams:
            try:
                await s.send(data)
            except Exception:
                pass

    def _remove(self, sid: int, error: Exception | None) -> None:
        entry = self._sockets.pop(sid, None)
        if entry is None:
            return
        reason = error.message if isinstance(error, StreamError) else str(error)
        log("[pool]", f"socket {sid} removed ({reason}); {len(self._sockets)} left")
        task = entry["reader_task"]
        if task is not None:
            task.cancel()
        entry["stream"].cancel()
        if not self._sockets and not self._is_closed:
            self.close(error)

    def close(self, error: Exception | None = None) -> None:
        if self._is_closed:
            return
        self._is_closed = True
        entries = list(self._sockets.values())
        self._sockets.clear()
        for e in entries:
            task = e["reader_task"]
            if task is not None:
                task.cancel()
            e["stream"].cancel()
        if self.on_close:
            self.on_close(error)