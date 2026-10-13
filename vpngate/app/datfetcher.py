"""Fetches and syncs VPNGate.dat from the HTTP API and peer-to-peer from relays
(port of VGDatFetcher.swift).

Reference: SoftEther Windows Client / VPN Gate Plugin FUN_00411140 (scheduler), FUN_00414230
(HTTP API), FUN_00411a00 / FUN_00411f20 / FUN_00412960 (relay download), FUN_00413140."""

from __future__ import annotations

import asyncio
import os
import random
import time
import urllib.request
from dataclasses import dataclass
from enum import Enum

from ..core.serverlist import VPNServer, fetch as csv_fetch
from ..core.stream import ByteStream, StreamError, TLSStream, protocol_error
from ..core.vgdat import VGDatError, VGDatFile, VGTunables, generate_probe, parse
from .paths import cache_file


class ListSource(str, Enum):
    bundle = "Built-in"
    cache = "Cached"
    relaySync = "Relay P2P"
    httpApi = "HTTP API"
    csv = "CSV Mirror"


class SyncOutcome(Enum):
    synced = "synced"              # VGC_HTTP_POLL_INTERVAL_OK
    relaysFailed = "relaysFailed"  # VGC_UDP_POLL_INTERVAL_ERROR
    noRelays = "noRelays"          # VGC_HTTP_POLL_INTERVAL_ERROR


@dataclass
class ServerFetchResult:
    servers: list[VPNServer]
    source: ListSource
    timestamp: float | None = None
    isFresh: bool = True
    outcome: SyncOutcome = SyncOutcome.synced


@dataclass
class RelayTarget:
    ip: str
    port: int


class HTTPGetError(Exception):
    pass


def http_get(url: str, connect_timeout: float, data_timeout: float, max_bytes: int,
             proxy: ProxyLike | None = None) -> bytes:
    """Plain HTTP GET for the project's list API. 200 only, body capped (runs in a thread)."""
    handlers: list = []
    if proxy is not None and proxy.kind == "http" and proxy.host:
        proxy_url = "http://"
        if proxy.username:
            import urllib.parse
            creds = urllib.parse.quote(proxy.username, safe="")
            if proxy.password:
                creds += ":" + urllib.parse.quote(proxy.password, safe="")
            proxy_url += f"{creds}@"
        proxy_url += f"{proxy.host}:{proxy.port}"
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers={"User-Agent": "VPNGateLinux/1.0"})
    try:
        with opener.open(req, timeout=max(connect_timeout, data_timeout)) as resp:
            if resp.status != 200:
                raise HTTPGetError(f"HTTP status {resp.status}")
            length = resp.headers.get("Content-Length")
            if length and int(length) > max_bytes:
                raise HTTPGetError("HTTP body too large")
            body = b""
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                body += chunk
                if len(body) > max_bytes:
                    raise HTTPGetError("HTTP body too large")
            return body
    except HTTPGetError:
        raise
    except urllib.error.HTTPError as e:
        raise HTTPGetError(f"HTTP status {e.code}") from None
    except Exception as e:
        raise HTTPGetError(str(e) or e.__class__.__name__) from None


from ..core.ipcmessages import ProxySettings as ProxyLike  # noqa: E402


class VGDatFetcher:
    # Defaults of the client's tunables in milliseconds; a verified list's DynList can override
    # each within [default/5, default*50].
    HTTP_POLL_OK_MS = 3_600_000          # VGC_HTTP_POLL_INTERVAL_OK
    HTTP_POLL_ERROR_MS = 600_000         # VGC_HTTP_POLL_INTERVAL_ERROR
    UDP_POLL_ERROR_MS = 600_000          # VGC_UDP_POLL_INTERVAL_ERROR
    TCP_TARGET_HOSTS = 12                # VGC_NUM_TCP_TARGET_HOSTS
    TCP_CONNECT_MS = 1_000               # VGC_TCP_POLL_CONNECT_TIMEOUT
    TCP_SSL_MS = 5_000                   # VGC_TCP_POLL_SSL_TIMEOUT
    DATA_MS = 60_000                     # VGC_HTTP_DATA_TIMEOUT
    HTTP_CONNECT_MS = 7_000              # VGC_HTTP_CONNECT_TIMEOUT
    HTTP_MAX_BYTES = 32 * 1024 * 1024    # 0x2000000, client_exe.c:9040
    TRAILER_TIMEOUT = 10.0               # ack/junk/final-byte exchange, client_exe.c:8338
    LAST_GOOD_KEY = "lastGoodRelay"

    def __init__(self, prefs=None, cache_url: str | None = None, bundle_urls: list[str] | None = None,
                 now=None, alternative_mode: bool = False, api_digits: tuple[str, str] | None = None,
                 make_stream=None) -> None:
        self.prefs = prefs
        self.cache_url = cache_url or cache_file("VPNGate.dat")
        self.bundle_urls = bundle_urls or []
        self.now = now or time.time
        self.timeout_scale = 1.0
        self.alternative_mode = alternative_mode
        hexdigits = "0123456789abcdef"
        self.api_digits = api_digits or (random.choice(hexdigits), random.choice(hexdigits))
        self._tunables = VGTunables()
        self._tunable_lock = asyncio.Lock()
        self._make_stream = make_stream or (lambda h, p, px: TLSStream(h, p, px))

    # MARK: tunables (DynList)

    @property
    def tunables(self) -> VGTunables:
        return self._tunables

    def adopt(self, file: VGDatFile) -> None:
        """Takes over the tunables of a verified list, like the original does for every list."""
        self._tunables.merge(file.tunables)

    def _ms(self, name: str, default: int) -> float:
        return self._tunables.seconds(name, default_ms=default) * self.timeout_scale

    def next_poll_delay(self, outcome: SyncOutcome, random_value: int | None = None) -> float:
        """Next poll = now + Rand % interval, uniformly random in [0, interval)."""
        if outcome == SyncOutcome.synced:
            interval = self._tunables.value("VGC_HTTP_POLL_INTERVAL_OK", self.HTTP_POLL_OK_MS)
        elif outcome == SyncOutcome.relaysFailed:
            interval = self._tunables.value("VGC_UDP_POLL_INTERVAL_ERROR", self.UDP_POLL_ERROR_MS)
        else:
            interval = self._tunables.value("VGC_HTTP_POLL_INTERVAL_ERROR", self.HTTP_POLL_ERROR_MS)
        if random_value is None:
            random_value = random.getrandbits(64)
        return (random_value % interval) / 1000.0

    # MARK: cached / bundled lists

    @staticmethod
    def cached_dat_url() -> str:
        return cache_file("VPNGate.dat")

    def load_cached(self) -> VGDatFile | None:
        try:
            with open(self.cache_url, "rb") as f:
                data = f.read()
        except OSError:
            return None
        try:
            return parse(data, now=self.now())
        except VGDatError:
            return None

    def load_bundle_dat(self) -> VGDatFile | None:
        for url in self.bundle_urls:
            try:
                with open(url, "rb") as f:
                    data = f.read()
                return parse(data, now=self.now())
            except (OSError, VGDatError):
                continue
        return None

    def _save_cached(self, data: bytes, existing: VGDatFile | None, new: VGDatFile) -> None:
        """Never let an older (but validly signed) list overwrite a newer one."""
        if existing is not None and existing.timestamp_ms >= new.timestamp_ms:
            return
        try:
            os.makedirs(os.path.dirname(self.cache_url), exist_ok=True)
            tmp = self.cache_url + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, self.cache_url)
        except OSError:
            pass

    # MARK: HTTP API

    def api_url(self, https: bool, session_id: int | None = None) -> str:
        if session_id is None:
            session_id = random.getrandbits(64)
        return (f"{'https' if https else 'http'}://x{self.api_digits[0]}.x{self.api_digits[1]}"
                f".client.api.vpngate2.jp/api/?session_id={session_id}")

    async def fetch_from_http_api(self, proxy: ProxyLike | None = None) -> VGDatFile:
        """Asks the project's API for the list; only a verified, fresh reply is used. Plain http
        first, then (alternative mode only) https, as the original does."""
        last: Exception = protocol_error("HTTP API unavailable")
        urls = [self.api_url(https=False)]
        if self.alternative_mode:
            urls.append(self.api_url(https=True))
        for url in urls:
            try:
                body = await asyncio.get_running_loop().run_in_executor(
                    None, lambda u=url: http_get(
                        u, self._ms("VGC_HTTP_CONNECT_TIMEOUT", self.HTTP_CONNECT_MS),
                        self._ms("VGC_HTTP_DATA_TIMEOUT", self.DATA_MS),
                        self.HTTP_MAX_BYTES,
                        proxy if (proxy is not None and proxy.kind == "http") else None))
                return await asyncio.get_running_loop().run_in_executor(None, self._accept, body)
            except Exception as e:
                last = e
        raise last

    def _accept(self, payload: bytes) -> VGDatFile:
        """Verifies a downloaded list, adopts its tunables, and keeps it when fresh."""
        dat_file = parse(payload, now=self.now())  # RSA signature
        self.adopt(dat_file)                       # the original applies DynList before the age check
        if not dat_file.is_fresh:
            raise protocol_error(f"Served a stale VPNGate.dat ({dat_file.timestamp})")
        self._save_cached(payload, self.load_cached(), dat_file)
        return dat_file

    # MARK: peer-to-peer relay fetch

    @staticmethod
    def select_targets(servers: list[VPNServer], limit: int,
                       shuffle=None) -> list[RelayTarget]:
        """Relay choice of FUN_00411a00: pass 1 takes hosts offering 443, pass 2 the rest with
        SSL ports on their first priority port; each pass admits at most limit + 1 hosts."""
        shuffle = shuffle or (lambda lst: random.sample(lst, len(lst)))
        shuffled = shuffle(list(servers))
        cap = limit + 1
        targets = [RelayTarget(s.ip, 443) for s in shuffled if 443 in s.sslPorts][:cap]
        targets += [RelayTarget(s.ip, s.prioritized_ssl_ports[0])
                    for s in shuffled if 443 not in s.sslPorts and s.sslPorts][:cap]
        if not targets:
            targets = [RelayTarget(s.ip, s.connect_port or 443) for s in shuffled[:limit]]
        return targets

    def get_last_good_relay(self) -> RelayTarget | None:
        if self.prefs is None:
            return None
        s = self.prefs.get(self.LAST_GOOD_KEY)
        if not s or ":" not in s:
            return None
        ip, _, port = s.rpartition(":")
        try:
            return RelayTarget(ip, int(port))
        except ValueError:
            return None

    def set_last_good_relay(self, target: RelayTarget | None) -> None:
        if self.prefs is None:
            return
        self.prefs.set(self.LAST_GOOD_KEY,
                       f"{target.ip}:{target.port}" if target is not None else None)

    async def fetch_from_relays(self, candidates: list[VPNServer],
                                proxy: ProxyLike | None = None) -> VGDatFile:
        """Asks the last-good relay, then up to 13 hosts with port 443 and 13 others."""
        limit = self._tunables.value("VGC_NUM_TCP_TARGET_HOSTS", self.TCP_TARGET_HOSTS)
        targets = self.select_targets(candidates, int(limit))
        last_good = self.get_last_good_relay()
        if last_good is not None:
            targets = [t for t in targets if (t.ip, t.port) != (last_good.ip, last_good.port)]
            targets.insert(0, last_good)
        if not targets:
            raise protocol_error("No target relay hosts available")

        last_error: Exception = protocol_error("All relay hosts failed")
        for target in targets:
            try:
                file = await self.download_from_host(host=target.ip, port=target.port, proxy=proxy)
                self.set_last_good_relay(target)
                return file
            except asyncio.CancelledError:
                raise
            except Exception as e:
                last_error = e
                if last_good is not None and (target.ip, target.port) == (last_good.ip, last_good.port):
                    self.set_last_good_relay(None)  # the original forgets a cached relay that failed
        raise last_error

    async def download_from_host(self, host: str, port: int,
                                 proxy: ProxyLike | None = None) -> VGDatFile:
        """Single host download (GET /vgc_download_dat/ + probe + ack). A list older than
        VG_ALLOW_TIME_DIFF is discarded so the next relay is tried, like the original."""
        stream: ByteStream = self._make_stream(host, port, proxy or ProxyLike())

        async def guarded(seconds: float, op):
            try:
                return await asyncio.wait_for(op(), seconds)
            except asyncio.TimeoutError:
                stream.cancel()
                raise protocol_error("Timed out") from None

        connect_s = (self._ms("VGC_TCP_POLL_CONNECT_TIMEOUT", self.TCP_CONNECT_MS)
                     + self._ms("VGC_TCP_POLL_SSL_TIMEOUT", self.TCP_SSL_MS))
        try:
            await guarded(connect_s, lambda: stream.start())

            async def download() -> bytes:
                req_head = b"GET /vgc_download_dat/ HTTP/1.1\r\nHOST: vpngate\r\n\r\n"
                req = req_head + generate_probe(timestamp_ms=int(max(0, self.now()) * 1000))
                await stream.send(req)
                # 4-byte big-endian payload length, then the payload
                length = await stream.recv_u32()
                if not (0 < length <= 32 * 1024 * 1024):
                    raise protocol_error(f"Invalid download_dat payload length: {length}")
                return await stream.recv(length)

            payload = await guarded(self._ms("VGC_HTTP_DATA_TIMEOUT", self.DATA_MS), download)

            # Ack (17 bytes, first = 1), 512 bytes of padding, then a best-effort 1-byte reply.
            async def trailer():
                ack = bytearray(17)
                ack[0] = 1
                await stream.send(bytes(ack))
                await stream.send(os.urandom(512))
            try:
                await guarded(self.TRAILER_TIMEOUT, trailer)
            except StreamError:
                pass
            try:
                await guarded(self.TRAILER_TIMEOUT, lambda: stream.recv(1))
            except Exception:
                pass

            return await asyncio.get_running_loop().run_in_executor(None, self._accept, payload)
        finally:
            stream.cancel()

    # MARK: sync pipeline

    async def sync(self, current_servers: list[VPNServer], proxy: ProxyLike | None = None,
                   mirror: str | None = None) -> ServerFetchResult:
        """Full fallback pipeline: HTTP API → P2P relays → cached/bundled .dat → CSV mirror."""
        loop = asyncio.get_running_loop()
        if (proxy is None or proxy.kind == "none") and True:
            try:
                dat = await self.fetch_from_http_api(proxy)
                return ServerFetchResult(servers=dat.servers, source=ListSource.httpApi,
                                         timestamp=dat.timestamp.timestamp(), isFresh=dat.is_fresh)
            except Exception:
                pass
        outcome = SyncOutcome.noRelays
        if current_servers:
            outcome = SyncOutcome.relaysFailed
            try:
                dat = await self.fetch_from_relays(current_servers, proxy)
                return ServerFetchResult(servers=dat.servers, source=ListSource.relaySync,
                                         timestamp=dat.timestamp.timestamp(), isFresh=dat.is_fresh)
            except asyncio.CancelledError:
                raise
            except Exception:
                pass

        stored: list[tuple[VGDatFile, ListSource]] = []
        cached = self.load_cached()
        if cached is not None:
            stored.append((cached, ListSource.cache))
        bundled = self.load_bundle_dat()
        if bundled is not None:
            stored.append((bundled, ListSource.bundle))
        if stored:
            best = max(stored, key=lambda pair: pair[0].timestamp_ms)
            self.adopt(best[0])
            return ServerFetchResult(servers=best[0].servers, source=best[1],
                                     timestamp=best[0].timestamp.timestamp(),
                                     isFresh=best[0].is_fresh, outcome=outcome)

        try:
            csv_servers = await loop.run_in_executor(None, csv_fetch, mirror)
            if csv_servers:
                return ServerFetchResult(servers=csv_servers, source=ListSource.csv,
                                         timestamp=None, isFresh=True, outcome=outcome)
        except Exception:
            pass

        return ServerFetchResult(servers=current_servers, source=ListSource.cache,
                                 timestamp=None, isFresh=False, outcome=outcome)
