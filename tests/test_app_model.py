"""App model wiring: prefs, disclaimer gate, event fan-out, favorites migration (no network)."""

import asyncio
import os
import tempfile
import time
import unittest

os.environ["VPNGATE_SUPPORT_DIR"] = tempfile.mkdtemp()

from vpngate.app.events import Event  # noqa: E402
from vpngate.app.model import AppModel  # noqa: E402
from vpngate.app.prefs import Prefs  # noqa: E402
from vpngate.core.ipcmessages import ConnectionState, HelperEvent  # noqa: E402
from vpngate.core.serverlist import VPNServer  # noqa: E402


class EventTests(unittest.TestCase):
    def test_multiple_listeners_and_unsubscribe(self):
        event = Event()
        hits = []
        off = event.connect(lambda: hits.append("a"))
        event.connect(lambda: hits.append("b"))
        event.emit()
        off()
        event.emit()
        self.assertEqual(hits, ["a", "b", "b"])

    def test_listener_error_does_not_break_others(self):
        event = Event()
        hits = []

        def boom():
            raise RuntimeError("boom")
        event.connect(boom)
        event.connect(lambda: hits.append("ok"))
        event.emit()
        self.assertEqual(hits, ["ok"])


class PrefsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["VPNGATE_SUPPORT_DIR"] = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_defaults_and_persistence(self):
        path = os.path.join(os.environ["VPNGATE_SUPPORT_DIR"], "prefs.json")
        prefs = Prefs(path)
        self.assertTrue(prefs.get("blockIPv6", True))
        self.assertEqual(prefs.get("maxLogWeeks"), -1)
        prefs.set("mirrorURL", "http://mirror.example/api")
        prefs2 = Prefs(path)
        self.assertEqual(prefs2.get("mirrorURL"), "http://mirror.example/api")

    def test_corrupt_file_falls_back_to_defaults(self):
        path = os.path.join(os.environ["VPNGATE_SUPPORT_DIR"], "bad.json")
        with open(path, "w") as f:
            f.write("{not json")
        prefs = Prefs(path)
        self.assertFalse(prefs.get("hasAgreedToDisclaimer"))
        prefs.set("mirrorURL", "x")  # still writable
        self.assertEqual(Prefs(path).get("mirrorURL"), "x")


class AppModelWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        # Fresh support dir per test: prefs, accounts and history never leak between tests.
        self._tmp = tempfile.TemporaryDirectory()
        os.environ["VPNGATE_SUPPORT_DIR"] = self._tmp.name

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _model(self, **kwargs) -> AppModel:
        defaults = dict(auto_start=False, reconnect_delay=0.05)
        defaults.update(kwargs)
        return AppModel(**defaults)

    def test_disclaimer_gates_connection(self):
        model = self._model()
        gated = []

        def action():
            gated.append(True)
        self.assertFalse(model.require_agreement(action))  # parked until agreement
        self.assertEqual(gated, [])
        self.assertTrue(model.showing_disclaimer)
        model.agree_to_disclaimer()
        self.assertEqual(gated, [True])
        self.assertTrue(model.has_agreed_to_disclaimer)
        self.assertTrue(model.require_agreement(action))  # now passes immediately

    def test_helper_event_updates_state_and_log(self):
        model = self._model()
        model._handle_event(HelperEvent(ConnectionState.connected, server="1.2.3.4",
                                        virtualIP="10.0.0.2", log="Connected"))
        self.assertEqual(model.event.state, ConnectionState.connected)
        self.assertEqual(model.event.virtualIP, "10.0.0.2")
        self.assertIn("Connected", model.log_lines)
        self.assertIsNotNone(model.connected_at)

        model._handle_event(HelperEvent(ConnectionState.disconnected, error="link lost"))
        self.assertEqual(model.event.state, ConnectionState.disconnected)
        self.assertIsNone(model.connected_at)
        self.assertIsNotNone(model.connection_log.entries)  # history started and ended

    def test_change_event_fires_for_ui(self):
        model = self._model()
        hits = []
        off = model.changed.connect(lambda: hits.append(1))
        model._handle_event(HelperEvent(ConnectionState.connecting, server="5.6.7.8"))
        self.assertEqual(hits, [1])
        off()
        model._handle_event(HelperEvent(ConnectionState.disconnected))
        self.assertEqual(hits, [1])

    def test_favorites_migration_from_ip(self):
        model = self._model()
        s = VPNServer(hostName="srv.example.com", ip="10.0.0.9")
        model.servers = [s]
        model.favorites = {"10.0.0.9"}
        model._migrate_favorites()
        self.assertEqual(model.favorites, {"srv.example.com"})

    def test_toggle_favorite_persists(self):
        model = self._model()
        s = VPNServer(hostName="srv.example.com", ip="10.0.0.9")
        model.toggle_favorite(s)
        self.assertIn(s.id, model.favorites)
        model.toggle_favorite(s)
        self.assertNotIn(s.id, model.favorites)

    def test_pressing_connect_builds_and_sends_the_request(self):
        """Regression: _send_connect used an unimported ConnectConfig — the button silently
        did nothing (the GTK callback swallowed the NameError)."""
        model = self._model()
        sent: list = []
        model.helper.send = sent.append      # capture instead of the socket
        model.helper.connect = lambda: True  # never touch the real helper socket
        model.helper_is_running = True       # past the setup prompts
        s = VPNServer(hostName="srv.example.com", ip="5.6.7.8", sslPorts=[443, 992], score=10)
        model.connect(s)  # disclaimer path: first call parks, agree, second sends
        model.agree_to_disclaimer()
        self.assertEqual(len(sent), 1)
        request = sent[0]
        self.assertEqual(request.cmd, "connect")
        self.assertIsNotNone(request.config, "the VPN-Gate connect must carry a full config")
        cfg = request.config
        self.assertEqual(cfg.host, "5.6.7.8")
        self.assertEqual(cfg.hubName, "VPNGATE")
        self.assertEqual(cfg.userName, "vpn")
        self.assertEqual(cfg.authType, "anonymous")
        self.assertTrue(cfg.disableQoS)
        self.assertFalse(cfg.autoReconnect)
        self.assertEqual(cfg.ports, [443, 992])
        self.assertEqual(cfg.maxConnection, 1)

    def test_reconnect_rotates_to_next_relay(self):
        """Relays die constantly; the reconnect loop must rotate through candidates instead of
        hammering the same dead server forever."""
        model = self._model()
        sent: list = []
        model.helper.send = sent.append
        model.helper.connect = lambda: True
        model.helper_is_running = True
        model.has_agreed_to_disclaimer = True
        first = VPNServer(hostName="dead.example.com", ip="9.9.9.9", sslPorts=[443], score=5000)
        second = VPNServer(hostName="alt.example.com", ip="8.8.8.8", sslPorts=[443], score=4000)
        model.servers = [first, second]
        model.connect(first)  # builds the failover queue [first, second]
        self.assertEqual(sent[0].config.host, "9.9.9.9")
        # the helper reports the connection dropped → next attempt rotates to the alt relay
        model._handle_event(HelperEvent(ConnectionState.disconnected, error="Connection closed"))
        time.sleep(0.3)  # let the app loop run the scheduled reconnect
        self.assertEqual(sent[-1].config.host, "8.8.8.8")

    def test_relay_stall_switches_to_next_relay(self):
        """When the helper's 60 s no-data detector fires, the app disconnects the starved
        session and immediately rotates to the next candidate relay."""
        model = self._model()
        sent: list = []
        model.helper.send = sent.append
        model.helper.connect = lambda: True
        model.helper_is_running = True
        model.has_agreed_to_disclaimer = True
        first = VPNServer(hostName="capped.example.com", ip="9.9.9.9", sslPorts=[443], score=5000)
        second = VPNServer(hostName="alt.example.com", ip="8.8.8.8", sslPorts=[443], score=4000)
        model.servers = [first, second]
        model.connect(first)
        self.assertEqual(sent[0].config.host, "9.9.9.9")
        model._handle_event(HelperEvent(ConnectionState.connected, server="9.9.9.9",
                                        virtualIP="10.0.0.2", bytesIn=100, bytesOut=100))
        # the helper's stall detector fires while still "connected"
        model._handle_event(HelperEvent(
            ConnectionState.connected, server="9.9.9.9", bytesIn=100, bytesOut=100,
            log="The relay stopped sending data (it may be capping this session). "
                "Reconnect or pick another server."))
        time.sleep(0.3)  # let the app loop run the scheduled reconnect
        self.assertTrue(any(r.cmd == "disconnect" for r in sent))
        self.assertEqual(sent[-1].config.host, "8.8.8.8")

    def test_remove_bypass_app_updates_ui(self):
        """Regression: the Remove button removed from the data but never rebuilt the rows."""
        from vpngate.app.ui.routing import RoutingRulesEditor
        from vpngate.core.routing import RoutingConfig
        cfg = RoutingConfig(bypass_apps_enabled=True,
                            bypass_apps=["Telegram", "chrome"])
        changes = []
        editor = RoutingRulesEditor(cfg, lambda c: changes.append(c), parent_window=None)
        editor._reload_bypass_rows()
        rows_before = len(editor._bypass_rows_box.get_children())
        self.assertEqual(rows_before, 2)
        editor._remove_bypass_app("Telegram")
        rows_after = len(editor._bypass_rows_box.get_children())
        self.assertEqual(rows_after, 1)  # UI rebuilt — Telegram's row is gone
        self.assertEqual(cfg.bypass_apps, ["chrome"])

    def test_bypass_setup_failure_does_not_block_vpn(self):
        """Regression: an exception in setup_app_bypass must never prevent the VPN from
        connecting — it should log and continue without bypass."""
        import subprocess as sp
        import tempfile
        from vpngate.helper.session import VPNSession, SessionTiming
        from vpngate.core.ipcmessages import ConnectConfig, ConnectionState

        # The session code wraps setup_app_bypass in try/except — verify by inspecting
        # that _establish survives a net whose setup_app_bypass raises.
        session = VPNSession(timing=SessionTiming())

        class ExplodingNet:
            def __init__(self):
                self.applied = None
                self.torn_down = False
                self.original_route = ("192.168.1.1", "eth0")
                self.state = None
            def apply(self, **kw):
                self.applied = kw
            def setup_app_bypass(self, *args):
                raise RuntimeError("cgroup permission denied")
            def enable_capture(self):
                pass
            def fail_open(self):
                pass
            def fail_close(self):
                pass
            def add_probe_host(self, host):
                pass
            def remove_probe_host(self, host):
                pass
            def add_bypass(self, host):
                pass
            def configure_ipv6(self, a, p):
                pass
            def apply_dynamic_rule(self, ip, action):
                pass
            def direct_dns_servers(self):
                return []
            def teardown(self):
                self.torn_down = True

        class FakeClient:
            def __init__(self):
                self.closed = False
                self.on_frame = None
                self.on_close = None
                self.remote_ipv4 = "203.0.113.7"
                self.hub = None
            def send_frame(self, frame):
                if self.hub:
                    self.hub.on_frame(frame)
            async def connect(self, log):
                class W:
                    session_name = "SID-test"
                    connection_name = "CN"
                    timeout_ms = 30000
                    session_key = b"\x01" * 20
                    max_connection = 1
                    use_compress = False
                    udp_server_ip = None
                return W()
            @property
            def bypass_hosts(self):
                return [self.remote_ipv4]
            @property
            def bytes_in(self):
                return 0
            @property
            def bytes_out(self):
                return 0
            def close(self, error=None):
                self.closed = True
                if self.on_close:
                    cb, self.on_close = self.on_close, None
                    cb(error)

        class FakeDNSProxy:
            def __init__(self, *a, **kw):
                self.routing = None
                self.tunnel_dnsservers = []
                self.direct_dnsservers = []
                self.listen_address = "127.0.0.1"
                self.block_ipv6 = kw.get("block_ipv6", False)
            async def start(self):
                pass
            def stop(self):
                pass
            def rescan_loop(self, interval=3):
                async def _loop():
                    pass
                return _loop()

        class FakeHub:
            """Answers DHCP like the real hub (the bridge needs a lease to reach connected)."""
            def __init__(self, client):
                self.client = client
                self.lease_ip = 0x0A080002
            def on_frame(self, frame):
                from vpngate.core.packets import (DHCPMessage, DHCPType, Ethernet, IPv4,
                                                   UDP, broadcastMAC, rd16, rd32)
                if len(frame) < 14 or rd16(frame, 12) != 0x0800:
                    return
                ip = IPv4.parse(frame[14:])
                if ip is None or ip[0] != 17:
                    return
                udp = UDP.parse(ip[3])
                if udp is None or udp[1] != 67:
                    return
                raw = bytearray(udp[2])
                if len(raw) < 240 or raw[0] != 2:
                    raw[0] = 2
                msg = DHCPMessage.parse(bytes(raw))
                if msg is None:
                    return
                reply = DHCPMessage(DHCPType.ack if msg.type == DHCPType.request
                                    else DHCPType.offer, msg.xid,
                                    b"\x5e\x00\x99\x88\x77\x66")
                reply.yiaddr = self.lease_ip
                reply.serverID = 0x0A080001
                reply.router = 0x0A080001
                reply.subnetMask = 0xFFFFFF00
                reply.dns = [0x08080808]
                reply.leaseSeconds = 3600
                rraw = bytearray(reply.encode())
                rraw[0] = 2
                rraw[16:20] = self.lease_ip.to_bytes(4, "big")
                udp_out = UDP.datagram(src=0, dst=0xFFFFFFFF, sport=67, dport=68,
                                        payload=bytes(rraw))
                ip_out = IPv4.packet(proto=17, src=0, dst=0xFFFFFFFF, payload=udp_out)
                self.client.on_frame(Ethernet.frame(
                    dst=broadcastMAC, src=b"\x5e\x00\x99\x88\x77\x66",
                    ethertype=0x0800, payload=ip_out))

        class FakeTun:
            def __init__(self):
                self.name = "faketun0"
                self.on_packet = None
                self.closed = False
            def start_reading(self):
                pass
            def write(self, p):
                pass
            def close(self):
                self.closed = True

        async def scenario():
            hub = FakeHub(None)
            client = FakeClient()
            client.hub = hub
            hub.client = client
            net = ExplodingNet()
            session._make_transport = lambda cfg, port: client
            session._make_tun = lambda: FakeTun()
            session._make_net = lambda: net

            async def fake_alive(net, captured=True):
                return True
            session._tunnel_alive = fake_alive
            # Avoid binding to the real port 53 (the helper owns it)
            import vpngate.helper.session as sess_mod
            orig_dns = sess_mod.DNSProxy
            sess_mod.DNSProxy = FakeDNSProxy
            try:
                session.connect_config(ConnectConfig(
                    host="test.example.com", ports=[443], hubName="VPNGATE",
                    userName="vpn", authType="anonymous",
                    maxConnection=1, disableQoS=True, autoReconnect=False, blockIPv6=True))
                for _ in range(300):
                    if session.snapshot.state == ConnectionState.connected:
                        break
                    await asyncio.sleep(0.01)
                self.assertEqual(session.snapshot.state, ConnectionState.connected,
                                 "VPN must connect even when bypass setup explodes")
            finally:
                sess_mod.DNSProxy = orig_dns

        asyncio.run(scenario())

    def test_routing_live_apply_pushes_to_helper(self):
        """Regression: routing rules must take effect immediately (no reconnect)."""
        model = self._model()
        sent: list = []
        model.helper.send = sent.append
        model.helper.connect = lambda: True
        model.helper_is_running = True
        model.has_agreed_to_disclaimer = True
        # simulate connected state
        from vpngate.core.ipcmessages import ConnectionState, HelperEvent
        model._handle_event(HelperEvent(ConnectionState.connected, server="1.2.3.4",
                                        virtualIP="10.0.0.2", bytesIn=1, bytesOut=1))
        from vpngate.core.routing import RoutingConfig, RoutingRule, RoutingRuleType, RoutingAction
        cfg = RoutingConfig(rules=[RoutingRule(
            type=RoutingRuleType.domainSuffix, value="example.com",
            action=RoutingAction.direct)])
        model.set_routing_config(cfg)
        # a setRouting IPC message must have been sent
        assert any(r.cmd == "setRouting" for r in sent),             f"setRouting not sent: {[r.cmd for r in sent]}"
        # the routing config should contain the rule
        msg = next(r for r in sent if r.cmd == "setRouting")
        assert msg.routing is not None
        assert len(msg.routing.get("rules", [])) == 1
        assert msg.routing["rules"][0]["value"] == "example.com"

    def test_max_connection_preference_is_applied(self):
        model = self._model()
        sent: list = []
        model.helper.send = sent.append
        model.helper.connect = lambda: True
        model.helper_is_running = True
        model.prefs.set("vgateMaxConnections", 4)
        model.has_agreed_to_disclaimer = True
        s = VPNServer(hostName="srv.example.com", ip="5.6.7.8", sslPorts=[443], score=10)
        model.connect(s)
        self.assertEqual(sent[0].config.maxConnection, 4)

    def test_current_proxy_from_prefs_and_keyring(self):
        from vpngate.app import keyring
        model = self._model()
        model.prefs.set("proxyKind", "http")
        model.prefs.set("proxyHost", "proxy.example.com")
        model.prefs.set("proxyPort", 8080)
        model.prefs.set("proxyUsername", "u")
        keyring.set("proxy", "p")
        proxy = model.current_proxy
        self.assertEqual(proxy.kind, "http")
        self.assertEqual(proxy.host, "proxy.example.com")
        self.assertEqual(proxy.port, 8080)
        self.assertEqual(proxy.username, "u")
        self.assertEqual(proxy.password, "p")
        keyring.delete("proxy")


if __name__ == "__main__":
    unittest.main()