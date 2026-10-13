"""App model wiring: prefs, disclaimer gate, event fan-out, favorites migration (no network)."""

import os
import tempfile
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
        model.helper.send = sent.append  # capture instead of the socket
        model.helper_is_running = True   # past the setup prompts
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

    def test_max_connection_preference_is_applied(self):
        model = self._model()
        sent: list = []
        model.helper.send = sent.append
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