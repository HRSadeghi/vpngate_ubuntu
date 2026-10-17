"""Owns one VPN connection: SoftEther session + bridge + tun + routes (port of Session.swift).

Every connect()/disconnect() bumps a generation number. Work started for an older generation
never publishes state and never keeps resources.
"""

from __future__ import annotations

from collections import deque

import asyncio
import time

from ..core import validation
from ..core.certpin import ServerCertPolicy
from ..core.clientaccount import routing_config_from_json
from ..core.ipcmessages import (ConnectConfig, ConnectionState, HelperEvent, HELPER_VERSION,
                                ProxySettings)
from ..core.packets import ip_string
from ..core.stream import StreamError, closed_error, protocol_error
from .bridge import BridgeTiming, EthernetBridge
from .dnsproxy import DNSProxy
from .netconfig import NetConfig
from .softetherclient import ClientAuth, SoftEtherClient
from .tun import TunDevice


class SessionTiming:
    def __init__(self) -> None:
        self.reconnect_delay = 3.0
        self.max_attempts = 8
        self.min_renew_seconds = 60.0
        self.bridge = BridgeTiming()


class ThrottleDetector:
    """A relay that was fast and then collapsed to a trickle while the app is still
    demanding traffic — VPN Gate relays cap sessions after some volume. The old stall
    detector never fires here: trickling bytes keep counting as 'progress'."""
    WINDOW = 20.0          # seconds of history to judge
    DEMAND_BYTES = 25_000  # the app is really trying (above keep-alive noise)
    DEAD_IN_BYTES = 10_000
    MIN_PEAK_BPS = 15_000  # the session must have been decent before (~120 kbps)
    FLOOR_BPS = 6_000

    def __init__(self) -> None:
        self.samples: deque[tuple[float, int, int]] = deque()
        self.peak_bps = 0.0
        self.stage = 0

    def observe(self, now: float, bytes_in: int, bytes_out: int) -> str | None:
        """None | 'fallback' (first collapse: leave UDP) | 'throttle' (still dead: rotate)."""
        self.samples.append((now, bytes_in, bytes_out))
        while self.samples and now - self.samples[0][0] > self.WINDOW + 10:
            self.samples.popleft()
        if len(self.samples) >= 2:
            t0, i0, o0 = self.samples[0]
            dt = now - t0
            if dt >= 5:
                rate = ((bytes_in - i0) + (bytes_out - o0)) / dt
                if rate > self.peak_bps:
                    self.peak_bps = rate
        old = None
        for s in self.samples:
            if now - s[0] >= self.WINDOW:
                old = s
        if old is None:
            return None
        t0, i0, o0 = old
        d_in = bytes_in - i0
        d_out = bytes_out - o0
        rate = (d_in + d_out) / max(now - t0, 1.0)
        if (self.peak_bps >= self.MIN_PEAK_BPS and d_out >= self.DEMAND_BYTES
                and d_in < self.DEAD_IN_BYTES
                and rate < max(self.peak_bps / 10, self.FLOOR_BPS)):
            self.stage += 1
            return "fallback" if self.stage == 1 else "throttle"
        if rate >= max(self.peak_bps / 4, self.FLOOR_BPS):
            self.stage = 0
        return None


class Resources:
    """Everything one connection attempt owns. Released exactly once by VPNSession.release."""

    def __init__(self, gen: int) -> None:
        self.gen = gen
        self.link_down = asyncio.Event()
        self.close_error: Exception | None = None
        self.client: SoftEtherClient | None = None
        self.tun: TunDevice | None = None
        self.net: NetConfig | None = None
        self.dns_proxy: DNSProxy | None = None
        self.bridge: EthernetBridge | None = None
        self.renew_task: asyncio.Task | None = None
        self.counter_task: asyncio.Task | None = None
        self.bypass_task: asyncio.Task | None = None
        self.tasks: list[asyncio.Task] = []

    def cancel_tasks(self) -> None:
        for t in (self.counter_task, self.renew_task, self.bypass_task):
            if t is not None:
                t.cancel()


class VPNSession:
    def __init__(self, timing: SessionTiming | None = None) -> None:
        self.timing = timing or SessionTiming()
        self._lock = asyncio.Lock()
        self._generation = 0
        self._active_runs = 0
        self._run_task: asyncio.Task | None = None
        self._current = HelperEvent(ConnectionState.disconnected)
        self._current.helperVersion = HELPER_VERSION
        self._res: Resources | None = None
        self.emit = None  # callback(HelperEvent)
        # Seams for tests (the Swift SessionDependencies): overridden in tests to inject doubles.
        self._make_tun = lambda: TunDevice()
        self._make_net = lambda: NetConfig()
        self._tunnel_alive = self._default_tunnel_alive

    @property
    def snapshot(self) -> HelperEvent:
        return self._current

    async def wait_until_idle(self, timeout: float) -> bool:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            async with self._lock:
                if self._active_runs == 0:
                    return True
            await asyncio.sleep(0.02)
        return False

    def _is_current(self, gen: int) -> bool:
        return self._generation == gen

    def _set(self, gen: int, state: ConnectionState, server: str | None = None,
             ip: str | None = None, log: str | None = None, error: str | None = None) -> None:
        """Publishes a state change; ignored if gen has been superseded."""
        if not self._is_current(gen):
            return
        self._publish(state, server, ip, log, error)

    def _publish(self, state: ConnectionState, server: str | None, ip: str | None,
                 log: str | None, error: str | None) -> None:
        self._current.state = state
        if state == ConnectionState.disconnected:
            self._current.server = None
            self._current.virtualIP = None
        if server is not None:
            self._current.server = server
        if ip is not None:
            self._current.virtualIP = ip
        self._current.log = log
        self._current.error = error
        self._current.helperVersion = HELPER_VERSION
        if state == ConnectionState.disconnected and (error or log):
            # Daemon mode has no UI attached: the systemd log needs the reason.
            import time as _t
            print(f"[{_t.strftime('%Y-%m-%d %H:%M:%S')}] [session] disconnected: "
                  f"{log or error}", flush=True)
        if self.emit is not None:
            self.emit(self._current)

    # MARK: control

    def connect_config(self, config: ConnectConfig) -> None:
        self._generation += 1
        gen = self._generation
        old = self._res
        self._res = None
        old_task = self._run_task
        self._active_runs += 1
        if old_task is not None:
            old_task.cancel()
        if old is not None:
            self._release(old)
        self._run_task = asyncio.get_running_loop().create_task(self._run(gen, config))

    def connect_host(self, host: str, port: int | None, proxy: ProxySettings,
                     auto_reconnect: bool, block_ipv6: bool,
                     routing: dict | None = None, ports: list[int] | None = None) -> None:
        port_list = list(ports) if ports else []
        if port is not None and port not in port_list:
            port_list.insert(0, port)
        cfg = ConnectConfig(
            host=host,
            ports=port_list or [443, 992, 5555, 1194],
            hubName="VPNGATE",
            userName="vpn",
            authType="anonymous",
            proxy=proxy,
            maxConnection=1,      # the VPN Gate client's own account (client_exe.c:27590)
            disableQoS=True,      # ... and DisableQoS=1 (client_exe.c:27598)
            autoReconnect=auto_reconnect,
            blockIPv6=block_ipv6,
            routing=routing,
        )
        self.connect_config(cfg)

    def set_routing_live(self, routing_json: dict | None) -> None:
        """Live-apply routing rules while connected: update the DNS proxy's routing (domain
        rules) and add routes for IP/CIDR rules immediately — no reconnect needed."""
        if self._res is None:
            return
        from ..core.clientaccount import routing_config_from_json
        routing = routing_config_from_json(routing_json)
        net = self._res.net
        dns_proxy = self._res.dns_proxy
        try:
            if dns_proxy is not None:
                dns_proxy.routing = routing
            # Apply IP/CIDR rules as routes (domain rules are handled by the DNS proxy).
            if net is not None:
                for rule in routing.effective_rules:
                    if rule.enabled and not rule.type.is_domain:
                        net.apply_dynamic_rule(rule.value, rule.action)
            from .logutil import log
            log("[routing]", f"live update: {len(routing.rules)} rule(s), "
                             f"default={routing.default_action.value}")
        except Exception as e:
            from .logutil import log
            log("[routing]", f"live apply failed: {e}")

    def set_bypass_apps(self, apps: list[str], enabled: bool) -> None:
        """Live-apply the bypass list while connected (no reconnect needed)."""
        if self._res is None or self._res.net is None:
            return
        try:
            self._res.net.update_bypass_apps(apps, enabled)
        except Exception as e:
            from .logutil import log
            log("[bypass]", f"live apply failed: {e}")

    def disconnect(self) -> None:
        self._generation += 1
        old = self._res
        self._res = None
        task = self._run_task
        self._run_task = None
        if task is not None:
            task.cancel()
        if old is not None:
            self._release(old)
        self._publish(ConnectionState.disconnected, None, None, None, None)

    # MARK: run loop

    async def _run(self, gen: int, config: ConnectConfig) -> None:
        attempt = 0
        try:
            while self._is_current(gen) and not asyncio.current_task().cancelled():
                self._set(gen, ConnectionState.connecting if attempt == 0
                          else ConnectionState.reconnecting, server=config.host)
                r = Resources(gen)
                async with self._lock:
                    if self._generation != gen:
                        return
                    self._res = r

                failure: Exception | None = None
                try:
                    await self._establish(r, config)
                    attempt = 0
                    await r.link_down.wait()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    failure = e
                if failure is None and r.close_error is not None:
                    failure = r.close_error

                async with self._lock:
                    if self._res is r:
                        self._res = None
                self._release(r)
                if not self._is_current(gen) or asyncio.current_task().cancelled():
                    return

                if failure is not None and not isinstance(failure, asyncio.CancelledError):
                    if not config.autoReconnect:
                        self._set(gen, ConnectionState.disconnected, error=str(failure))
                        return
                elif not config.autoReconnect:
                    self._set(gen, ConnectionState.disconnected, error="Connection lost")
                    return
                max_attempts = config.reconnectCount if config.reconnectCount is not None \
                    else self.timing.max_attempts
                reconnect_delay = config.reconnectInterval if config.reconnectInterval is not None \
                    else self.timing.reconnect_delay
                if attempt >= max_attempts:
                    self._set(gen, ConnectionState.disconnected, error="Gave up reconnecting")
                    return
                attempt += 1
                self._set(gen, ConnectionState.reconnecting, server=config.host,
                          log=f"Reconnecting in {int(-(-reconnect_delay // 1))}s (attempt {attempt})",
                          error=str(failure) if failure is not None else None)
                try:
                    await asyncio.sleep(reconnect_delay)
                except asyncio.CancelledError:
                    raise
        except asyncio.CancelledError:
            pass
        finally:
            self._active_runs -= 1

    def _make_transport(self, config: ConnectConfig, port: int) -> SoftEtherClient:
        auth = config.authType.lower()
        password = config.password
        cert = config.certDer
        key = config.privateKeyDer
        if auth in ("standard password (sha-0)", "password"):
            auth_kind, pw = ClientAuth.HASHED_PASSWORD, password or ""
        elif auth in ("plain password", "plain"):
            auth_kind, pw = ClientAuth.PLAIN_PASSWORD, password or ""
        elif auth in ("user certificate", "cert"):
            auth_kind, pw = ClientAuth.CERTIFICATE, None
        elif auth == "ticket":
            auth_kind, pw = ClientAuth.TICKET, None
        else:
            auth_kind, pw = ClientAuth.ANONYMOUS, None
        return SoftEtherClient(
            host=config.host, port=port, hub_name=config.hubName, user_name=config.userName,
            auth=auth_kind, password=pw, cert_der=cert,
            private_key_der=key, ticket=config.ticket, proxy=config.proxy,
            max_connections=config.maxConnection, use_compress=config.useCompress,
            use_udp_accel=config.useUdpAccel, disable_qos=config.disableQoS,
            half_connection=config.halfConnection,
            server_cert_policy=ServerCertPolicy.from_config(config.checkServerCert,
                                                            config.serverCertFingerprint))

    async def _establish(self, r: Resources, config: ConnectConfig) -> None:
        gen = r.gen
        loop = asyncio.get_running_loop()
        ports: list[int] = []
        for p in config.ports:
            if validation.is_valid_port(p) and p not in ports:
                ports.append(p)
        for p in (443, 992, 5555, 1194):
            if validation.is_valid_port(p) and p not in ports:
                ports.append(p)

        client: SoftEtherClient | None = None
        last_error: Exception = closed_error()
        for port in ports:
            if not self._is_current(gen):
                raise asyncio.CancelledError()
            c = self._make_transport(config, port)
            # Registered before connecting so that a disconnect() during the handshake can reach it.
            r.client = c
            try:
                self._set(gen, ConnectionState.authenticating, server=config.host,
                          log=f"Connecting to {config.host}:{port}")
                # A server that accepts TLS but then stalls must not hang the session forever
                # (the macOS streams rely on NWConnection's own deadlines).
                await asyncio.wait_for(c.connect(lambda m, g=gen: self._set(
                    g, ConnectionState.authenticating, log=m)), timeout=45.0)
                if not self._is_current(gen):
                    raise asyncio.CancelledError()
                client = c
                break
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                err = protocol_error("No answer in 45 s (server did not finish the VPN handshake)")
                c.close(err)
                if r.client is c:
                    r.client = None
                last_error = err
                if not self._is_current(gen):
                    raise asyncio.CancelledError() from None
                self._set(gen, ConnectionState.connecting, log=f"Port {port} failed: {err.message}")
            except Exception as e:
                c.close(e)
                if r.client is c:
                    r.client = None
                last_error = e
                if not self._is_current(gen):
                    raise asyncio.CancelledError() from None
                self._set(gen, ConnectionState.connecting,
                          log=f"Port {port} failed: {_err_text(e)}")
        if client is None:
            raise last_error

        tun = self._make_tun()
        r.tun = tun
        bridge = EthernetBridge(timing=self.timing.bridge,
                                fixed_mac=_parse_mac(config.virtualMacAddress))
        bridge.handle_ipv6 = not config.blockIPv6
        r.bridge = bridge
        bridge.send_frame = client.send_frame
        bridge.deliver_ipv4 = tun.write
        bridge.deliver_ipv6 = getattr(tun, "write6", tun.write)

        def lease_changed(_l):
            if client is not None:
                client.close(protocol_error("DHCP address changed"))
        bridge.on_lease_changed = lease_changed

        def lease_lost():
            if client is not None:
                client.close(protocol_error("DHCP lease lost"))
        bridge.on_lease_lost = lease_lost

        client.on_frame = bridge.from_hub
        tun.on_packet = bridge.from_host

        def client_closed(err, r=r):
            # Remember why the link went down so the session reports the real reason
            # instead of a bare "Connection lost".
            r.close_error = err
            if err is not None and config.autoReconnect and self._is_current(gen):
                self._set(gen, ConnectionState.reconnecting, log=f"Link closed: {_err_text(err)}")
            r.link_down.set()
        client.on_close = client_closed

        self._set(gen, ConnectionState.dhcp, log=f"Requesting address on {tun.name}")
        lease = await bridge.acquire_lease()
        if not self._is_current(gen):
            raise asyncio.CancelledError()
        bridge.gratuitous_arp()
        net = self._make_net()
        r.net = net
        # The address the TLS connection really went to, not a second lookup of the name.
        if config.proxy.kind != ProxySettings.KIND_NONE:
            primary_bypass = config.proxy.host
        elif validation.is_ipv4_literal(config.host):
            primary_bypass = config.host
        else:
            primary_bypass = client.remote_ipv4 or config.host
        # Domain rules need a resolver of our own: IP/CIDR rules alone are handled by
        # routes. blockIPv6 needs one too — without the proxy nothing swallows AAAA answers
        # and every app tries the blocked v6 first and hangs.
        routing = routing_config_from_json(config.routing)
        needs_dns_proxy = config.blockIPv6 or any(rule.enabled and rule.type.is_domain
                                                 for rule in routing.effective_rules)
        dns_proxy: DNSProxy | None = None
        if needs_dns_proxy:
            try:
                dns_proxy = DNSProxy(net, block_ipv6=config.blockIPv6)
                dns_proxy.routing = routing
                await dns_proxy.start()
                r.dns_proxy = dns_proxy
            except Exception as e:
                from .logutil import log
                log("[dns]", f"proxy start failed (using the tunnel's resolver directly): {e}")
                dns_proxy = None
        net.apply(iface=tun.name, lease=lease, bypass_host=primary_bypass,
                  block_ipv6=config.blockIPv6, mtu_override=config.mtu,
                  routing=routing,
                  dns_proxy_address=dns_proxy.listen_address if dns_proxy else None,
                  capture=False)
        try:
            net.setup_app_bypass(routing, net.original_route)
        except Exception as e:
            from .logutil import log
            log("[bypass]", f"setup failed (VPN continues without bypass): {e}")
        if dns_proxy is not None:
            dns_proxy.tunnel_dns_servers = [ip_string(d) for d in lease.dns]
            dns_proxy.direct_dns_servers = net.direct_dns_servers()
        # After a cluster redirect the data flows to another host, and UDP acceleration to its
        # own endpoint: both need their own route around the tunnel.
        for h in client.bypass_hosts:
            if h != primary_bypass:
                net.add_bypass(h)
        # IPv6 (only when not blocked): put the SLAAC address on the tun once a router advertises.
        if not config.blockIPv6:
            def on_v6_address(address, prefix_length):
                if self._is_current(gen):
                    net.configure_ipv6(address, prefix_length)
            bridge.start_ipv6(on_v6_address)
        tun.start_reading()

        # A relay that accepts the session but carries no data must never blackhole the
        # machine: prove the tunnel works BEFORE the default routes are captured. The
        # probe is a TCP handshake through the tunnel — without it the dead relay would
        # take the whole box offline (and every reconnect attempt would too).
        if not await self._tunnel_alive(net, captured=False):
            raise RuntimeError("the relay accepted the session but is not carrying any "
                               "traffic (connection test failed)")
        net.enable_capture()

        self._set(gen, ConnectionState.connected, ip=ip_string(lease.ip),
                  log=f"Connected via {tun.name}, gateway {ip_string(lease.router)}")

        async def counter():
            # 1 s events for the UI, 5 s throughput lines for the log file, and a liveness
            # watchdog: when the relay stops carrying traffic the capture routes are pulled
            # (fail-open) so the machine keeps working while another relay is picked.
            from .logutil import log
            last_sample = (client.bytes_in, client.bytes_out)
            since_sample = time.monotonic()
            last_in = client.bytes_in
            last_progress = time.monotonic()
            fail_opened = False
            stall_warned = False
            probing = False
            misses = 0
            last_probe = 0.0
            throttle = ThrottleDetector()
            while True:
                await asyncio.sleep(1)
                if not self._is_current(gen):
                    return
                now = time.monotonic()
                verdict = throttle.observe(now, client.bytes_in, client.bytes_out)
                if verdict == "fallback":
                    accel = getattr(client, "udp_accel", None)
                    if accel is not None:
                        accel.force_tcp()
                    log("[session]", "throughput collapsed — leaving the UDP path "
                                     "(it degrades after some volume on this network)")
                elif verdict == "throttle":
                    total_mb = (client.bytes_in + client.bytes_out) / 1e6
                    log("[session]", f"relay is throttling this session "
                                     f"(peak {throttle.peak_bps * 8 / 1e6:.2f}Mbps, "
                                     f"{total_mb:.1f}MB moved) — switching to another server")
                    self._current.log = ("The relay is throttling this session (the speed "
                                         "collapsed after a while). Picking another server…")
                    self._current.helperVersion = HELPER_VERSION
                    if self.emit is not None:
                        self.emit(self._current)
                    self._current.log = None
                if client.bytes_in > last_in:
                    last_in = client.bytes_in
                    last_progress = now
                    misses = 0
                    if fail_opened:
                        fail_opened = False
                        stall_warned = False
                        try:
                            net.fail_close()
                            log("[route]", "traffic is flowing again — capture routes restored")
                        except Exception as e:
                            log("[route]", f"recapture failed: {e}")
                elif not probing and now - last_progress >= 10 and now - last_probe >= 5:
                    # Quiet does not mean dead (an idle tunnel is healthy): ask the tunnel
                    # directly. Two misses in a row mean the relay is gone or capping.
                    probing = True
                    last_probe = now
                    try:
                        alive = await self._tunnel_alive(net, captured=True)
                    finally:
                        probing = False
                    if alive:
                        last_progress = time.monotonic()
                        misses = 0
                    else:
                        misses += 1
                        if misses >= 2 and not fail_opened:
                            fail_opened = True
                            stall_warned = True
                            try:
                                net.fail_open()
                            except Exception as e:
                                log("[route]", f"fail-open failed: {e}")
                            log("[session]", "the relay is not carrying data — traffic is "
                                             "going direct while another server is picked")
                            self._current.log = ("The relay stopped sending data (it may be "
                                                 "capping this session). Reconnect or pick "
                                                 "another server.")
                            self._current.helperVersion = HELPER_VERSION
                            if self.emit is not None:
                                self.emit(self._current)
                            self._current.log = None
                self._current.bytesIn = client.bytes_in
                self._current.bytesOut = client.bytes_out
                self._current.log = None
                self._current.error = None
                self._current.helperVersion = HELPER_VERSION
                if self.emit is not None:
                    self.emit(self._current)
                now = time.monotonic()
                if now - since_sample >= 5:
                    (last_in, last_out) = last_sample
                    d_in = client.bytes_in - last_in
                    d_out = client.bytes_out - last_out
                    last_sample = (client.bytes_in, client.bytes_out)
                    since_sample = now
                    st = client.stats()
                    log("[throughput]",
                        f"in={d_in * 8 / 5 / 1e6:.2f}Mbps out={d_out * 8 / 5 / 1e6:.2f}Mbps "
                        f"totals in={st['in']} out={st['out']} "
                        f"in_tcp={st['in_tcp']} in_udp={st['in_udp']} "
                        f"out_tcp={st['out_tcp']} out_udp={st['out_udp']} "
                        f"path={st['path'] or '-'} sockets={st['sockets']} "
                        f"udp={'usable' if st['udp_usable'] else ('negotiated' if st['udp_negotiated'] else 'off')} "
                        f"dropped={st['dropped']}")

        async def renew():
            wait = max(lease.seconds / 2.0, self.timing.min_renew_seconds)
            while True:
                await asyncio.sleep(wait)
                await bridge.renew()

        r.counter_task = loop.create_task(counter())
        r.renew_task = loop.create_task(renew())
        if net.state is not None and net.state.app_bypass:
            r.bypass_task = loop.create_task(net.rescan_loop())

    async def _default_tunnel_alive(self, net, captured: bool) -> bool:
        """True when a TCP handshake through the tunnel completes. Before capture
        (`captured=False`) temporary host routes push the probe into the tunnel; after
        capture the default routes already do. Any one target answering is enough."""
        targets = (("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443))
        if not captured:
            for host, _port in targets:
                net.add_probe_host(host)
        try:
            async def one(host: str, port: int) -> bool:
                try:
                    _reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), 3.0)
                    try:
                        writer.close()
                    except Exception:
                        pass
                    return True
                except Exception:
                    return False
            return any(await asyncio.gather(*[one(h, p) for h, p in targets]))
        finally:
            if not captured:
                for host, _port in targets:
                    net.remove_probe_host(host)

    def _release(self, r: Resources) -> None:
        """Stops traffic first, then removes routes, then closes the tun. Safe more than once."""
        r.cancel_tasks()
        if r.client is not None:
            r.client.on_close = None
            r.client.close()
        r.link_down.set()
        if r.dns_proxy is not None:
            r.dns_proxy.stop()
            r.dns_proxy = None
        if r.net is not None:
            try:
                r.net.teardown()
            except Exception as e:
                print("[net] teardown failed:", e)
            r.net = None
        if r.tun is not None:
            r.tun.close()
            r.tun = None
        r.client = None
        r.bridge = None


def _err_text(e: Exception) -> str:
    if isinstance(e, StreamError):
        return e.message
    return str(e) or e.__class__.__name__


def _parse_mac(text: str | None) -> bytes | None:
    if not text:
        return None
    from ..core.validation import parse_mac_address
    return parse_mac_address(text)