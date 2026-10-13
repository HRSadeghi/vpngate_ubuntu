"""Behaviour tests: helper IPC over a real Unix socket, DNS proxy decisions, helper client."""

import asyncio
import json
import os
import socket
import tempfile
import threading
import unittest

from vpngate.core.ipcmessages import (ConnectionState, HelperEvent, HelperRequest, ProxySettings,
                                      decode_line, encode_line)
from vpngate.core.routing import RoutingAction, RoutingConfig, RoutingRule, RoutingRuleType
from vpngate.app.helperclient import HelperClient
from vpngate.helper.dnsproxy import DNSProxy
from vpngate.helper.netconfig import NetConfig
from vpngate.helper import dnsmessage


class FakeDNSServer:
    """Answers every A query with a fixed address (in the event loop)."""

    def __init__(self) -> None:
        self.queries: list[bytes] = []

    async def query(self, message: bytes, server: str, timeout_ms: int) -> bytes | None:
        self.queries.append((message, server))
        q = message
        # Echo the question, one A record 9.9.9.9.
        return (q[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:]
                + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x09\x09\x09\x09")


class RecordingNet(NetConfig):
    def __init__(self) -> None:
        self.dynamic: list[tuple[str, RoutingAction]] = []

    def apply_dynamic_rule(self, ip: str, action: RoutingAction) -> None:
        self.dynamic.append((ip, action))


class DNSProxyTests(unittest.TestCase):
    def _config(self, **kwargs) -> RoutingConfig:
        return RoutingConfig(**kwargs)

    def test_proxy_domains_go_to_tunnel_resolver(self):
        async def run():
            net = RecordingNet()
            upstream = FakeDNSServer()
            proxy = DNSProxy(net, upstream)
            proxy.routing = self._config()
            proxy.tunnel_dns_servers = ["10.8.0.1"]
            proxy.direct_dns_servers = ["192.168.1.1"]
            q = query_bytes("example.com")
            resp = await proxy.handle(q)
            self.assertIsNotNone(resp)
            self.assertEqual(upstream.queries[0][1], "10.8.0.1")  # tunnel resolver
            self.assertEqual(dnsmessage.resolved_ipv4_addresses(resp), ["9.9.9.9"])
            self.assertEqual(net.dynamic, [])  # no explicit rule: no dynamic route
        asyncio.run(run())

    def test_direct_domains_go_to_physical_resolver(self):
        async def run():
            net = RecordingNet()
            upstream = FakeDNSServer()
            proxy = DNSProxy(net, upstream)
            proxy.routing = self._config(rules=[
                RoutingRule(type=RoutingRuleType.domainSuffix, value="example.com",
                            action=RoutingAction.direct)])
            proxy.tunnel_dns_servers = ["10.8.0.1"]
            proxy.direct_dns_servers = ["192.168.1.1"]
            resp = await proxy.handle(query_bytes("www.example.com"))
            self.assertEqual(upstream.queries[0][1], "192.168.1.1")  # never the tunnel's
            # The resolved address is routed the way the rule asked.
            self.assertEqual(net.dynamic, [("9.9.9.9", RoutingAction.direct)])

    def test_blocked_domain_gets_nxdomain_without_query(self):
        async def run():
            net = RecordingNet()
            upstream = FakeDNSServer()
            proxy = DNSProxy(net, upstream)
            proxy.routing = self._config(rules=[
                RoutingRule(type=RoutingRuleType.domainKeyword, value="ads",
                            action=RoutingAction.block)])
            proxy.tunnel_dns_servers = ["10.8.0.1"]
            resp = await proxy.handle(query_bytes("ads.example.com"))
            self.assertEqual(upstream.queries, [])  # nothing sent anywhere
            self.assertEqual(resp[3] & 0xF, 3)

    def test_unparseable_query_fails_closed(self):
        async def run():
            proxy = DNSProxy(RecordingNet(), FakeDNSServer())
            resp = await proxy.handle(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            self.assertEqual(resp[3] & 0xF, 2)  # SERVFAIL, never a guess

    def test_no_resolver_fails_closed(self):
        async def run():
            proxy = DNSProxy(RecordingNet(), FakeDNSServer())
            proxy.tunnel_dns_servers = []
            resp = await proxy.handle(query_bytes("example.com"))
            self.assertEqual(resp[3] & 0xF, 2)


def query_bytes(name: str) -> bytes:
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + b"\x00\x01\x00\x01"


class HelperIPCWireTests(unittest.TestCase):
    """A real Unix-socket round trip of HelperRequest/HelperEvent JSON lines."""

    def test_round_trip_over_socketpair(self):
        async def run():
            a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            cfg_req = HelperRequest(cmd="connect", host="vpn.example.com", port=443,
                                    proxy=ProxySettings(kind="socks5", host="127.0.0.1", port=1080),
                                    autoReconnect=False, blockIPv6=True)
            line = encode_line(cfg_req)
            a.sendall(line)
            data = b""
            while not data.endswith(b"\n"):
                data += b.recv(4096)
            decoded = decode_line(data.strip(), HelperRequest)
            self.assertEqual(decoded.cmd, "connect")
            self.assertEqual(decoded.host, "vpn.example.com")
            self.assertEqual(decoded.proxy.kind, "socks5")
            self.assertFalse(decoded.autoReconnect)

            event = HelperEvent(ConnectionState.connected, server="1.2.3.4", virtualIP="10.0.0.2",
                                bytesIn=1, helperVersion=7)
            b.sendall(encode_line(event))
            data = b""
            while not data.endswith(b"\n"):
                data += a.recv(4096)
            e = decode_line(data.strip(), HelperEvent)
            self.assertEqual(e.state, ConnectionState.connected)
            self.assertEqual(e.virtualIP, "10.0.0.2")
            a.close()
            b.close()
        asyncio.run(run())


class HelperClientTests(unittest.TestCase):
    def test_connects_sends_receives(self):
        tmp = tempfile.TemporaryDirectory()
        path = os.path.join(tmp.name, "helper.sock")
        events: list[HelperEvent] = []
        got_request = threading.Event()

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(path)
        server.listen(1)

        def serve():
            conn, _ = server.accept()
            buf = b""
            while not got_request.is_set():
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    req = json.loads(line.decode())
                    got_request.set()
                    conn.sendall((json.dumps({"state": "connected", "server": req.get("host")})
                                  + "\n").encode())
            conn.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        client = HelperClient(path)
        client.on_event = events.append
        self.assertFalse(client.is_connected)
        self.assertTrue(client.connect())
        self.assertTrue(client.connect())  # idempotent
        client.send(HelperRequest(cmd="status", host="vpn.example.com"))
        self.assertTrue(got_request.wait(2))
        import time
        end = time.time() + 2
        while not events and time.time() < end:
            time.sleep(0.01)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].state, ConnectionState.connected)
        self.assertEqual(events[0].server, "vpn.example.com")
        client.close()
        server.close()
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()