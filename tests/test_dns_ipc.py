"""DNS message parsing/writing and IPC validation + JSON round trips."""

import json
import unittest

from vpngate.core.clientaccount import routing_config_to_json
from vpngate.core.ipcmessages import (ConnectionState, ConnectConfig, HelperEvent, HelperRequest,
                                      ProxySettings, decode_line, encode_line)
from vpngate.core.routing import RoutingAction, RoutingConfig, RoutingRule, RoutingRuleType
from vpngate.helper import dnsmessage
from vpngate.helper.ipcserver import IPCServer, console_uid, peer_uid


def query_for(name: str) -> bytes:
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + b"\x00\x01\x00\x01"


class DNSMessageTests(unittest.TestCase):
    def test_query_name(self):
        self.assertEqual(dnsmessage.query_name(query_for("example.com")), "example.com")
        self.assertEqual(dnsmessage.query_name(query_for("a.b.c.example.com")),
                         "a.b.c.example.com")
        self.assertIsNone(dnsmessage.query_name(b""))
        self.assertIsNone(dnsmessage.query_name(b"\x00" * 11))

    def test_resolved_ipv4(self):
        q = query_for("example.com")
        resp = (q[:2] + b"\x81\x80" + b"\x00\x01\x00\x02\x00\x00\x00\x00" + q[12:]
                + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04"
                + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x05\x06\x07\x08")
        self.assertEqual(dnsmessage.resolved_ipv4_addresses(resp), ["1.2.3.4", "5.6.7.8"])
        # A CNAME answer (type 5) is skipped.
        resp2 = (q[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:]
                 + b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c\x00\x09\x03www\xc0\x0c")
        self.assertEqual(dnsmessage.resolved_ipv4_addresses(resp2), [])

    def test_blocked_response(self):
        q = query_for("ads.example.com")
        resp = dnsmessage.blocked_response(q)
        self.assertEqual(resp[3] & 0xF, 3)      # NXDOMAIN
        self.assertTrue(resp[2] & 0x80)         # QR set
        self.assertEqual(resp[:2], q[:2])       # id echoed
        self.assertEqual(len(resp), 12 + len(q) - 12)

    def test_servfail_response(self):
        q = query_for("example.com")
        resp = dnsmessage.servfail_response(q)
        self.assertEqual(resp[3] & 0xF, 2)
        self.assertEqual(resp[4:6], b"\x00\x01")  # question count preserved

    def test_short_query(self):
        self.assertEqual(dnsmessage.servfail_response(b"\x01"), b"\x01")
        self.assertIsNone(dnsmessage.query_name(b"\x12\x34\x01\x00"))


class IPCValidationTests(unittest.TestCase):
    def test_connect_host_validation(self):
        self.assertEqual(IPCServer.validate(HelperRequest(cmd="connect")), "invalid host")
        r = HelperRequest(cmd="connect", host="-x")
        self.assertEqual(IPCServer.validate(r), "invalid host")
        r = HelperRequest(cmd="connect", host="vpn.example.com", port=99999)
        self.assertEqual(IPCServer.validate(r), "invalid port")
        r = HelperRequest(cmd="connect", host="vpn.example.com", port=443)
        self.assertIsNone(IPCServer.validate(r))

    def test_connect_config_validation(self):
        cfg = ConnectConfig(host="vpn.example.com", ports=[443, 0])
        self.assertEqual(IPCServer.validate(HelperRequest(cmd="connect", config=cfg)),
                         "invalid port 0")
        cfg = ConnectConfig(host="vpn.example.com", hubName="a" * 300)
        self.assertEqual(IPCServer.validate(HelperRequest(cmd="connect", config=cfg)),
                         "invalid hub name")
        cfg = ConnectConfig(host="vpn.example.com", proxy=ProxySettings(kind="socks5",
                                                                       host="127.0.0.1", port=1))
        # loopback proxy host is a valid host; port 1 valid
        self.assertIsNone(IPCServer.validate(HelperRequest(cmd="connect", config=cfg)))
        cfg = ConnectConfig(host="vpn.example.com", proxy=ProxySettings(kind="http",
                                                                       host="", port=8080))
        self.assertEqual(IPCServer.validate(HelperRequest(cmd="connect", config=cfg)),
                         "invalid proxy host")

    def test_oversized_secrets(self):
        cfg = ConnectConfig(host="vpn.example.com")
        cfg.certDer = b"x" * (16 * 1024 + 1)
        self.assertEqual(IPCServer.validate(HelperRequest(cmd="connect", config=cfg)),
                         "certificate too large")
        cfg = ConnectConfig(host="vpn.example.com")
        cfg.privateKeyDer = b"x" * (16 * 1024 + 1)
        self.assertEqual(IPCServer.validate(HelperRequest(cmd="connect", config=cfg)),
                         "private key too large")
        cfg = ConnectConfig(host="vpn.example.com")
        cfg.ticket = b"x" * 1025
        self.assertEqual(IPCServer.validate(HelperRequest(cmd="connect", config=cfg)),
                         "ticket too large")

    def test_routing_rules_validated(self):
        cfg = ConnectConfig(host="vpn.example.com", ports=[443], routing={
            "rules": [{"type": "domainRegex", "value": "([", "action": "proxy", "enabled": True}]}
        )
        problem = IPCServer.validate(HelperRequest(cmd="connect", config=cfg))
        self.assertIsNotNone(problem)
        self.assertIn("routing rule", problem)
        cfg = ConnectConfig(host="vpn.example.com", ports=[443], routing={
            "rules": [{"type": "domainSuffix", "value": "example.com", "action": "direct",
                       "enabled": True}]}
        )
        self.assertIsNone(IPCServer.validate(HelperRequest(cmd="connect", config=cfg)))


class LineCodecTests(unittest.TestCase):
    def test_request_round_trip_with_secrets(self):
        cfg = ConnectConfig(host="vpn.example.com", hubName="HUB", userName="u",
                            authType="cert", certDer=b"\x01\x02", privateKeyDer=b"\x03\x04")
        req = HelperRequest(cmd="connect", config=cfg)
        line = encode_line(req)
        decoded = decode_line(line.split(b"\n")[0], HelperRequest)
        self.assertEqual(decoded.cmd, "connect")
        self.assertEqual(decoded.config.certDer, b"\x01\x02")
        self.assertEqual(decoded.config.privateKeyDer, b"\x03\x04")
        self.assertEqual(decoded.config.hubName, "HUB")

    def test_event_round_trip(self):
        e = HelperEvent(ConnectionState.connected, server="1.2.3.4", virtualIP="10.0.0.2",
                        bytesIn=123, bytesOut=456, log="Connected", helperVersion=7)
        decoded = HelperEvent.from_json(json.loads(encode_line(e)))
        self.assertEqual(decoded.state, ConnectionState.connected)
        self.assertEqual(decoded.virtualIP, "10.0.0.2")
        self.assertEqual(decoded.bytesIn, 123)
        self.assertEqual(decoded.helperVersion, 7)

    def test_tolerant_event_decode(self):
        e = HelperEvent.from_json({"state": "connected"})
        self.assertEqual(e.state, ConnectionState.connected)
        self.assertEqual(e.bytesIn, 0)
        with self.assertRaises(ValueError):
            HelperEvent.from_json({"state": "nope"})


class ConsoleUidTests(unittest.TestCase):
    def test_console_uid_never_root(self):
        uid = console_uid()
        if uid is not None:
            self.assertNotEqual(uid, 0)

    def test_peer_uid_on_plain_socket(self):
        # A non-socket fd raises or returns None; just exercise the function.
        import socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            uid = peer_uid(s)
        except Exception:
            uid = None
        s.close()


class RoutingJsonTests(unittest.TestCase):
    def test_round_trip(self):
        cfg = RoutingConfig(rules=[
            RoutingRule(type=RoutingRuleType.domainSuffix, value="example.com",
                        action=RoutingAction.direct),
        ], default_action=RoutingAction.proxy, bypass_private_networks=True)
        decoded = IPCServer._routing_json_round_trip(cfg) if hasattr(IPCServer, "_routing_json_round_trip") else None
        from vpngate.core.clientaccount import routing_config_from_json
        decoded = routing_config_from_json(routing_config_to_json(cfg))
        self.assertEqual(len(decoded.rules), 1)
        self.assertEqual(decoded.rules[0].value, "example.com")
        self.assertEqual(decoded.default_action, RoutingAction.proxy)
        self.assertTrue(decoded.bypass_private_networks)

    def test_bad_records_skipped(self):
        from vpngate.core.clientaccount import routing_config_from_json
        cfg = routing_config_from_json({"rules": [
            {"type": "domainSuffix", "value": "ok.com", "action": "direct", "enabled": True},
            {"type": "bogus", "value": "x", "action": "proxy"},
        ]})
        self.assertEqual(len(cfg.rules), 1)
        self.assertEqual(cfg.rules[0].value, "ok.com")


if __name__ == "__main__":
    unittest.main()
