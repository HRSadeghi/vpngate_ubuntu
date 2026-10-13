"""The app's central state (port of AppModel.swift).

The macOS model drove SwiftUI with @Published; here views register an `on_change` callback that
the GTK layer invokes on its own main loop. Background work (list sync, probes, helper polling)
runs on a private asyncio loop in a worker thread; UI-affecting callbacks are marshalled with
`dispatch` (GLib.idle_add in the UI).
"""

from __future__ import annotations

import asyncio
import os
import threading
import time

from ..core.clientaccount import routing_config_from_json, routing_config_to_json
from ..core.ipcmessages import (ConnectConfig, ConnectionState, HelperEvent,
                                HelperRequest, ProxySettings)
from ..core.serverlist import VPNServer
from ..core.serverprobe import ProbeOutcome, ports_for, run as probe_run
from ..core.stream import TLSStream
from ..core.validation import is_ipv4_literal
from .accountmanager import AccountManager
from .events import Event
from .connectionlog import ConnectionLogStore
from .datfetcher import ListSource, ServerFetchResult, SyncOutcome, VGDatFetcher
from .helperclient import HelperClient
from .helperinstaller import is_installed
from .keyring import get as keyring_get
from .paths import cache_file
from .prefs import Prefs
from .statistics import VGStatistics

# Wait between reconnect attempts of a VPN Gate connection: the stock account's RetryInterval
# 0xF (client_exe.c:27590s).
RECONNECT_INTERVAL = 15.0
HELPER_ANSWER_TIMEOUT = 8.0
LOG_LIMIT = 300


class SetupPrompt:
    INSTALL = "install"
    UPDATE = "update"


class AppModel:
    def __init__(self, socket_path: str | None = None, prefs: Prefs | None = None,
                 auto_start: bool = True, open_installer=None, account_manager: AccountManager | None = None,
                 connection_log: ConnectionLogStore | None = None, dat_fetcher: VGDatFetcher | None = None,
                 reconnect_delay: float = RECONNECT_INTERVAL) -> None:
        self.prefs = prefs or Prefs()
        self.helper = HelperClient(socket_path or _socket_path())
        self.dat_fetcher = dat_fetcher or VGDatFetcher(
            prefs=self.prefs,
            bundle_urls=_bundle_urls(),
            alternative_mode=bool(self.prefs.get("alternativeMode")))
        self.reconnect_delay = reconnect_delay
        self.persists_server_cache = auto_start
        self.open_installer = open_installer or _default_open_installer
        self.account_manager = account_manager or AccountManager()
        self.connection_log = connection_log or ConnectionLogStore()
        self.statistics = VGStatistics(self.prefs, start_if_enabled=auto_start)

        # Published state
        self.servers: list[VPNServer] = []
        self.loading = False
        self.load_error: str | None = None
        self.event = HelperEvent(ConnectionState.disconnected)
        self.helper_is_running = False
        self.helper_is_installed = is_installed()
        self.log_lines: list[str] = []
        self.probes: dict[str, ProbeOutcome] = {}
        self.connected_at: float | None = None
        self.notice: str | None = None
        self.setup_prompt: str | None = None
        self.waiting_for_installer = False
        self._pending_server: VPNServer | None = None
        self.favorites: set[str] = set(self.prefs.get("favorites") or [])
        self.list_source: ListSource = ListSource.bundle
        self.list_timestamp: float | None = None
        self.list_fetched_at: float | None = self.prefs.get("listFetchedAt")
        self.list_is_fresh = True
        self.active_account = None
        self.last_server_id: str | None = self.prefs.get("lastServerID")
        self.has_agreed_to_disclaimer = bool(self.prefs.get("hasAgreedToDisclaimer"))
        self.showing_disclaimer = False
        self._pending_after_agreement = None
        self.reconnect_attempts = 0
        self.scheduled_poll_delay: float | None = None

        # UI hook (marshalled onto the GTK loop by the UI layer); multiple listeners allowed.
        self.changed = Event()
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_loop, daemon=True,
                                             name="vpngate-app-async")
        self._loop_thread.start()

        self._wanted_server: VPNServer | None = None
        self._relay_queue: list[VPNServer] = []
        self._current_relay_id: str | None = None
        self._last_failed_id: str | None = None
        self._reconnect_task: asyncio.Task | None = None
        self._history_entry: str | None = None
        self._history_bytes = (0, 0)
        self._last_event_at = 0.0
        self._probe_generation = 0

        self.helper.on_event = lambda e: self._dispatch(self._handle_event, e)
        self.helper.on_disconnect = lambda: self._dispatch(self._handle_helper_gone)

        self.account_manager.changed.connect(lambda: self._dispatch(self._changed))
        self.connection_log.changed.connect(lambda: self._dispatch(self._changed))

        if auto_start:
            cached = self.dat_fetcher.load_cached()
            if cached is not None:
                self.dat_fetcher.adopt(cached)
                self.servers = cached.servers
                self.list_source = ListSource.cache
                self.list_timestamp = cached.timestamp.timestamp()
                self.list_is_fresh = cached.is_fresh
            else:
                bundled = self.dat_fetcher.load_bundle_dat()
                if bundled is not None:
                    self.dat_fetcher.adopt(bundled)
                    self.servers = bundled.servers
                    self.list_source = ListSource.bundle
                    self.list_timestamp = bundled.timestamp.timestamp()
                    self.list_is_fresh = bundled.is_fresh
            self._migrate_favorites()

        if auto_start:
            self._schedule_repeating(2.0, self.poll_helper)
            self._dispatch(self.poll_helper)
            self._dispatch(self.refresh)

    # MARK: plumbing

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        # The TLS streams block on executor threads (connect/handshake/send/recv); the
        # interpreter default (min(32, cpu+4)) starves under 8 concurrent probes.
        from concurrent.futures import ThreadPoolExecutor
        self._loop.set_default_executor(ThreadPoolExecutor(
            max_workers=32, thread_name_prefix="vpngate-app-io"))
        self._loop.run_forever()

    def _async(self, coro_fn, *args) -> asyncio.Task:
        return asyncio.run_coroutine_threadsafe(coro_fn(*args), self._loop)

    def _schedule_repeating(self, interval: float, fn) -> None:
        def tick():
            if fn():
                t = threading.Timer(interval, tick)
                t.daemon = True
                t.start()
        t = threading.Timer(interval, tick)
        t.daemon = True
        t.start()

    def _dispatch(self, fn, *args) -> None:
        """Runs `fn` synchronously (models are plain thread-locked by the UI dispatch)."""
        try:
            fn(*args)
        except Exception:
            import traceback
            traceback.print_exc()

    def _changed(self) -> None:
        self.changed.emit()

    # MARK: helper

    def poll_helper(self) -> bool:
        self.helper_is_installed = is_installed()
        if not self.helper.is_connected:
            self.helper_is_running = self.helper.connect()
        self._resume_after_setup()
        self._changed()
        return True  # keep the timer

    def begin_setup(self) -> None:
        self.setup_prompt = None
        if self.open_installer():
            self.waiting_for_installer = True
            self.notice = "Finish the installer, then VPN Gate connects automatically."
        else:
            self._pending_server = None
            self.notice = ("Helper not found. Install it with: sudo scripts/install-helper.sh "
                           "(or reinstall VPN Gate).")
        self._changed()

    def cancel_setup(self) -> None:
        self.setup_prompt = None
        self._pending_server = None
        self._changed()

    def _resume_after_setup(self) -> None:
        if not (self.waiting_for_installer or self._pending_server is not None):
            return
        if not self.helper_is_running or self.helper_outdated:
            return
        self.waiting_for_installer = False
        if self.notice and self.notice.startswith("Finish the installer"):
            self.notice = None
        if self._pending_server is not None:
            s = self._pending_server
            self._pending_server = None
            self.connect(s)

    def uninstall_helper(self) -> None:
        def work():
            try:
                from .helperinstaller import uninstall
                uninstall()
            except Exception as e:
                self.notice = f"Uninstall failed: {e}"
            self.helper_is_running = False
            self.poll_helper()
        threading.Thread(target=work, daemon=True).start()

    @property
    def helper_outdated(self) -> bool:
        return (self.helper_is_running and self._last_event_at > 0
                and (self.event.helperVersion or 0) < _helper_version())

    def _handle_event(self, e: HelperEvent) -> None:
        self._last_event_at = time.time()
        self.helper_is_running = True
        if e.log:
            self.append_log(e.log)
        if e.error:
            self.append_log(f"Error: {e.error}")
            self.notice = e.error
        if e.state == ConnectionState.connected and self.connected_at is None:
            self.connected_at = time.time()
            self.notice = None
        if e.state != ConnectionState.connected:
            self.connected_at = None
        self._track_history(e)
        self.event = e
        # Relay stall (the helper's 60 s no-data detector): the helper keeps the dead session
        # up, so rotate to the next relay ourselves — disconnect, then the reconnect loop
        # picks the next candidate.
        if (e.state == ConnectionState.connected and e.log
                and e.log.startswith("The relay stopped sending data")
                and self._wanted_server is not None and self.active_account is None
                and self.prefs.get("autoReconnect", True)
                and self._reconnect_task is None):
            self.append_log("Switching to another relay…")
            self.helper.send(HelperRequest(cmd="disconnect"))
            self.reconnect_attempts += 1
            self._last_failed_id = self._current_relay_id
            self._rotate_and_schedule(e.log)
            return
        self._consider_reconnect(e)
        self._changed()

    def _handle_helper_gone(self) -> None:
        self.helper_is_running = False
        self._cancel_reconnect()
        self._end_history(None)
        self.event = HelperEvent(ConnectionState.disconnected)
        self._changed()

    # MARK: reconnect (VPN Gate connections)

    def _relay_candidates(self) -> list[VPNServer]:
        """Relay failover queue: the wanted server first, then the best others (probed ones by
        their test rank, otherwise by score). Volatile relays die mid-session; rotating keeps
        the user online without manual babysitting."""
        wanted = self._wanted_server
        pool = [s for s in self._visible_servers_list()
                if s.id != (wanted.id if wanted else None)]
        pool.sort(key=lambda s: (ProbeOutcome.sort_rank(self.probes.get(s.id)), -s.score))
        return ([wanted] if wanted is not None else []) + pool[:6]

    def _visible_servers_list(self) -> list[VPNServer]:
        return self.servers

    def _next_relay(self) -> VPNServer | None:
        """Pops the next candidate from the failover queue, skipping the relay that just
        failed; refills from the server list when the queue runs dry."""
        while self._relay_queue:
            candidate = self._relay_queue.pop(0)
            if candidate.id != self._last_failed_id \
                    and candidate.ip in {s.ip for s in self.servers}:
                return candidate
        self._relay_queue = [c for c in self._relay_candidates()
                             if c.id != self._last_failed_id]
        while self._relay_queue:
            candidate = self._relay_queue.pop(0)
            if candidate.ip in {s.ip for s in self.servers}:
                return candidate
        return None

    def _consider_reconnect(self, e: HelperEvent) -> None:
        if e.state == ConnectionState.connected:
            self.reconnect_attempts = 0
            return
        if not (e.state == ConnectionState.disconnected and e.error is not None
                and self.prefs.get("autoReconnect", True) and self._wanted_server is not None
                and self.active_account is None and self._reconnect_task is None):
            return
        self.reconnect_attempts += 1
        self._last_failed_id = self._current_relay_id
        self._rotate_and_schedule(e.error)

    def _rotate_and_schedule(self, error: str | None) -> None:
        """Picks the next relay from the failover queue and schedules the reconnect."""
        server = self._next_relay() or self._wanted_server
        if server is None:
            return
        self.append_log(f"Reconnecting to {server.hostName} in "
                        f"{int(-(-self.reconnect_delay // 1))} s "
                        f"(attempt {self.reconnect_attempts})")
        waiting = HelperEvent(ConnectionState.reconnecting)
        waiting.server = server.ip
        waiting.error = error
        self.event = waiting
        self._changed()

        async def wait_and_retry():
            await asyncio.sleep(self.reconnect_delay)
            if self._wanted_server is None:
                return
            if (not self.prefs.get("autoReconnect", True)
                    or self.event.state != ConnectionState.reconnecting
                    or not self.helper_is_running):
                if self.event.state == ConnectionState.reconnecting:
                    self.event = HelperEvent(ConnectionState.disconnected)
                    self._changed()
                return
            self._send_connect(server)

        self._reconnect_task = self._async(wait_and_retry)

    def _cancel_reconnect(self) -> None:
        if self._reconnect_task is not None:
            self._reconnect_task.cancel()
            self._reconnect_task = None

    # MARK: connection history

    def _track_history(self, e: HelperEvent) -> None:
        if e.state == ConnectionState.connected:
            self._history_bytes = (e.bytesIn, e.bytesOut)
            if self._history_entry is None:
                name = self._connected_server_name(e)
                self._history_entry = self.connection_log.record_start(
                    server_name=name, server_ip=e.server or "")
        else:
            self._end_history(e.error)

    def _end_history(self, error: str | None) -> None:
        if self._history_entry is None:
            return
        id_ = self._history_entry
        self._history_entry = None
        self.connection_log.record_end(id=id_, bytes_in=self._history_bytes[0],
                                       bytes_out=self._history_bytes[1], error=error)
        self._history_bytes = (0, 0)

    def _connected_server_name(self, e: HelperEvent) -> str:
        if self.active_account is not None and self.active_account.host == e.server:
            return self.active_account.name
        for s in self.servers:
            if s.ip == e.server:
                return s.hostName
        return e.server or "unknown"

    # MARK: disclaimer

    def require_agreement(self, action) -> bool:
        if self.has_agreed_to_disclaimer:
            return True
        self._pending_after_agreement = action
        self.showing_disclaimer = True
        self._changed()
        return False

    def agree_to_disclaimer(self) -> None:
        self.has_agreed_to_disclaimer = True
        self.prefs.set("hasAgreedToDisclaimer", True)
        self.showing_disclaimer = False
        resume = self._pending_after_agreement
        self._pending_after_agreement = None
        self._changed()
        if resume is not None:
            resume()

    def decline_disclaimer(self) -> None:
        self._pending_after_agreement = None
        self.showing_disclaimer = False
        self._changed()

    def append_log(self, line: str) -> None:
        self.log_lines.append(line)
        if len(self.log_lines) > LOG_LIMIT:
            del self.log_lines[:len(self.log_lines) - LOG_LIMIT]

    # MARK: connect

    @property
    def current_proxy(self) -> ProxySettings:
        p = ProxySettings()
        p.kind = self.prefs.get("proxyKind", "none")
        p.host = self.prefs.get("proxyHost", "")
        p.port = int(self.prefs.get("proxyPort", 0) or 0)
        username = self.prefs.get("proxyUsername", "")
        if p.kind != ProxySettings.KIND_NONE and username:
            p.username = username
            p.password = keyring_get("proxy")
        return p

    @property
    def last_server(self) -> VPNServer | None:
        for s in self.servers:
            if s.id == self.last_server_id:
                return s
        return None

    @property
    def is_connected(self) -> bool:
        return self.event.state == ConnectionState.connected

    def connect(self, s: VPNServer) -> None:
        if not self.require_agreement(lambda: self.connect(s)):
            return
        self.poll_helper()
        if not self.helper_is_running:
            self._pending_server = s
            self.setup_prompt = SetupPrompt.INSTALL
            self._changed()
            return
        if self.helper_outdated:
            self._pending_server = s
            self.setup_prompt = SetupPrompt.UPDATE
            self._changed()
            return
        self.notice = None
        self._cancel_reconnect()
        self._wanted_server = s
        self.reconnect_attempts = 0
        self._send_connect(s)

    def _send_connect(self, s: VPNServer) -> None:
        # The VPN Gate client's own account: hub VPNGATE, anonymous, QoS off, one TCP
        # connection — unless the user raised "TCP connections" (a parallel-flow defense
        # against per-connection throttling; the server caps it in the welcome anyway).
        try:
            max_conn = max(1, min(int(self.prefs.get("vgateMaxConnections", 1) or 1), 32))
        except (TypeError, ValueError):
            max_conn = 1
        cfg = ConnectConfig(
            host=s.ip,
            ports=list(s.prioritized_ssl_ports) or [443],
            hubName="VPNGATE",
            userName="vpn",
            authType="anonymous",
            proxy=self.current_proxy,
            maxConnection=max_conn,
            disableQoS=True,
            autoReconnect=False,
            blockIPv6=bool(self.prefs.get("blockIPv6", True)),
            routing=(routing_config_to_json(self.routing_config)
                     if not self.routing_config.is_empty else None),
        )
        r = HelperRequest(cmd="connect", config=cfg)
        self.last_server_id = s.id
        self._current_relay_id = s.id  # failover tracking
        self.prefs.set("lastServerID", s.id)
        sent_at = time.time()
        self.helper.send(r)
        self.event.state = ConnectionState.connecting
        self.event.server = s.ip
        self._changed()

        def timeout_watch():
            if self._last_event_at < sent_at and self.event.state == ConnectionState.connecting:
                self.event = HelperEvent(ConnectionState.disconnected)
                self.notice = ("The helper is not responding. Open Settings and choose "
                               "“Reinstall helper…”.")
                self.append_log(f"No answer from the helper within {int(HELPER_ANSWER_TIMEOUT)} s")
                self._changed()
        t = threading.Timer(HELPER_ANSWER_TIMEOUT, timeout_watch)
        t.daemon = True
        t.start()

    def connect_account(self, account) -> None:
        if not self.require_agreement(lambda: self.connect_account(account)):
            return
        self.poll_helper()
        if not self.helper_is_running:
            self.setup_prompt = SetupPrompt.INSTALL
            self._changed()
            return
        if self.helper_outdated:
            self.setup_prompt = SetupPrompt.UPDATE
            self._changed()
            return
        self.notice = None
        self._cancel_reconnect()
        self._wanted_server = None
        pw = self.account_manager.password(account)
        cert = self.account_manager.certificate(account)
        key = self.account_manager.private_key(account)
        if account.authType == "User Certificate" and (cert is None or key is None):
            self.notice = (f"“{account.name}” needs a certificate and RSA private key. "
                           f"Open its properties and import them.")
            self._changed()
            return
        acc = account
        if acc.proxy.kind != ProxySettings.KIND_NONE and acc.proxy.password is None:
            acc.proxy.password = self.account_manager.proxy_password(account)
        global_routing = self.routing_config
        cfg = acc.to_connect_config(
            password=pw, cert_der=cert, private_key_der=key,
            block_ipv6=bool(self.prefs.get("blockIPv6", True)),
            global_routing=None if global_routing.is_empty else global_routing)
        r = HelperRequest(cmd="connect")
        r.config = cfg
        self.active_account = account
        self.last_server_id = account.name
        self.prefs.set("lastServerID", account.name)
        sent_at = time.time()
        self.helper.send(r)
        self.event.state = ConnectionState.connecting
        self.event.server = account.host
        self._changed()

        def timeout_watch():
            if self._last_event_at < sent_at and self.event.state == ConnectionState.connecting:
                self.event = HelperEvent(ConnectionState.disconnected)
                self.notice = ("The helper is not responding. Open Settings and choose "
                               "“Reinstall helper…”.")
                self.append_log(f"No answer from the helper within {int(HELPER_ANSWER_TIMEOUT)} s")
                self._changed()
        t = threading.Timer(HELPER_ANSWER_TIMEOUT, timeout_watch)
        t.daemon = True
        t.start()

    def disconnect(self) -> None:
        waiting = self._reconnect_task is not None
        self._cancel_reconnect()
        self._wanted_server = None
        self.helper.send(HelperRequest(cmd="disconnect"))
        if waiting:
            self.event = HelperEvent(ConnectionState.disconnected)
            self._changed()

    def reconnect(self) -> None:
        s = self.last_server
        if s is not None:
            self.connect(s)  # the helper tears the old session down before starting the new one

    @property
    def connected_server(self) -> VPNServer | None:
        for s in self.servers:
            if s.id == self.last_server_id and s.ip == self.event.server:
                return s
        for s in self.servers:
            if s.ip == self.event.server:
                return s
        return None

    # MARK: server list

    @property
    def routing_config(self):
        return routing_config_from_json(self.prefs.get("routingConfig"))

    def set_routing_config(self, config) -> None:
        self.prefs.set("routingConfig", routing_config_to_json(config))
        self._changed()
        # Live-apply app bypass while connected (no reconnect needed).
        if self.is_connected:
            r = HelperRequest(cmd="setBypassApps",
                              bypassApps=config.bypass_apps,
                              bypassAppsEnabled=config.bypass_apps_enabled)
            self.helper.send(r)

    def refresh(self) -> bool:
        if self.loading:
            return False
        self.loading = True
        self.load_error = None
        self._changed()
        mirror = self.prefs.get("mirrorURL") or None
        proxy = self.current_proxy

        async def work() -> ServerFetchResult:
            return await self.dat_fetcher.sync(self.servers, proxy, mirror)

        def done(task):
            try:
                res = task.result()
            except Exception:
                res = None
            self._refresh_done(res)
        self._async(work).add_done_callback(done)
        return False  # not a repeating timer tick

    def _refresh_done(self, res: ServerFetchResult | None) -> None:
        if res is not None and res.servers:
            self.servers = res.servers
            self.list_source = res.source
            self.list_timestamp = res.timestamp
            self.list_is_fresh = res.isFresh
            if res.source not in (ListSource.cache, ListSource.bundle):
                self.list_fetched_at = time.time()
                if self.persists_server_cache:
                    self.prefs.set("listFetchedAt", self.list_fetched_at)
            self._migrate_favorites()
            if self.persists_server_cache:
                self._save_cache(res.servers)
        elif not self.servers:
            self.load_error = "Failed to load servers"
        self.loading = False
        self._changed()
        self._schedule_next_poll(SyncOutcome.noRelays if (res is None or not res.servers)
                                 else res.outcome)

    def _schedule_next_poll(self, outcome: SyncOutcome) -> None:
        interval = self.dat_fetcher.next_poll_delay(outcome)
        self.scheduled_poll_delay = interval
        t = threading.Timer(interval, lambda: self._dispatch(self.refresh))
        t.daemon = True
        t.start()

    def toggle_favorite(self, s: VPNServer) -> None:
        if s.id in self.favorites:
            self.favorites.discard(s.id)
        else:
            self.favorites.add(s.id)
        self.prefs.set("favorites", sorted(self.favorites))
        self._changed()

    def _migrate_favorites(self) -> None:
        """Favorites used to be keyed by IP; they are keyed by host name now."""
        legacy = {f for f in self.favorites if is_ipv4_literal(f)}
        if not legacy or not self.servers:
            return
        migrated = self.favorites - legacy
        for ip in legacy:
            for s in self.servers:
                if s.ip == ip:
                    migrated.add(s.id)
        self.favorites = migrated
        self.prefs.set("favorites", sorted(self.favorites))

    # MARK: connectivity tests ("Test Connection")

    def measure(self, servers: list[VPNServer]) -> None:
        """Tests every given server with a real SoftEther handshake, a few at a time."""
        self._probe_generation += 1
        generation = self._probe_generation
        targets = list(servers)
        for s in targets:
            self.probes[s.id] = ProbeOutcome("queued")
        self._changed()
        proxy = self.current_proxy

        async def work():
            queue: asyncio.Queue = asyncio.Queue()
            for s in targets:
                queue.put_nowait(s)
            semaphore = asyncio.Semaphore(8)

            async def one(s: VPNServer):
                async with semaphore:
                    if generation != self._probe_generation:
                        return
                    self.probes[s.id] = ProbeOutcome("testing")
                    self._changed()
                    outcome = await probe_run(s.ip, ports_for(s), proxy, 5.0,
                                              factory=lambda h, p, px: TLSStream(h, p, px))
                    if generation != self._probe_generation:
                        return
                    self.probes[s.id] = outcome
                    self._changed()

            await asyncio.gather(*(one(s) for s in targets))
            if generation != self._probe_generation:
                return
            for s in targets:
                if self.probes.get(s.id) is not None and self.probes[s.id].state in ("queued", "testing"):
                    self.probes[s.id] = ProbeOutcome("failed", message="Test did not finish")
            self._changed()

        self._async(work)

    # MARK: cache

    @staticmethod
    def _cache_url() -> str:
        return cache_file("servers.json")

    def _save_cache(self, servers: list[VPNServer]) -> None:
        try:
            import json
            with open(self._cache_url(), "w") as f:
                json.dump([s.to_json() for s in servers], f)
        except OSError:
            pass

    def load_cache(self) -> list[VPNServer]:
        try:
            import json
            with open(self._cache_url()) as f:
                records = json.load(f)
            return [VPNServer.from_json(r) for r in records]
        except (OSError, ValueError):
            return []


def _socket_path() -> str:
    from ..core.ipcmessages import HELPER_SOCKET_PATH
    return HELPER_SOCKET_PATH


def _helper_version() -> int:
    from ..core.ipcmessages import HELPER_VERSION
    return HELPER_VERSION


def _bundle_urls() -> list[str]:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(here, "assets", "VPNGate.dat"),
        "/usr/local/share/vpngate/VPNGate.dat",
        "/usr/share/vpngate/VPNGate.dat",
    ]
    return [c for c in candidates if os.path.exists(c)]


def _default_open_installer() -> bool:
    """The Linux equivalent of opening the .pkg: run the privileged installer script once."""
    script = "/usr/local/share/vpngate/install-helper.sh"
    if not os.path.exists(script):
        script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "..", "scripts", "install-helper.sh")
        script = os.path.abspath(script)
    if not os.path.exists(script):
        return False
    import shutil
    import subprocess
    for tool in ("pkexec", "sudo"):
        path = shutil.which(tool)
        if path:
            r = subprocess.run([path, "/bin/sh", script], capture_output=True, text=True)
            return r.returncode == 0
    return False