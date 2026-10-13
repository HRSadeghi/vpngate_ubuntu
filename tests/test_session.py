"""Session state machine against a fake SoftEther transport + fake hub (no network, no root).

The fake client answers the bridge's DHCP exchange like the macOS suite's fake hub, and the
net/dns layers are replaced with recording doubles, so establish() runs end to end.
"""

import asyncio
import unittest

from vpngate.core.ipcmessages import ConnectConfig, ConnectionState, HelperEvent, ProxySettings
from vpngate.core.packets import (DHCPMessage, DHCPType, Ethernet, IPv4, UDP, broadcastMAC,
                                  ip_string, rd16)
from vpngate.helper.session import SessionTiming, VPNSession


class FakeTun:
    last = None

    def __init__(self) -> None:
        self.name = "faketun0"
        self.on_packet = None
        self.written: list[bytes] = []
        self.closed = False
        FakeTun.last = self

    def start_reading(self) -> None:
        pass

    def write(self, packet: bytes) -> None:
        self.written.append(packet)

    def write6(self, packet: bytes) -> None:
        self.written.append(packet)

    def close(self) -> None:
        self.closed = True


class RecordingNet:
    def __init__(self) -> None:
        self.applied = None
        self.bypasses: list[str] = []
        self.torn_down = False

    def apply(self, iface, lease, bypass_host, block_ipv6=True, mtu_override=None,
              routing=None, dns_proxy_address=None) -> None:
        self.applied = (iface, lease, bypass_host)

    def add_bypass(self, host: str) -> None:
        self.bypasses.append(host)

    def configure_ipv6(self, address, prefix_length) -> None:
        pass

    def apply_dynamic_rule(self, ip, action) -> None:
        pass

    def direct_dns_servers(self):
        return ["192.168.1.1"]

    def teardown(self) -> None:
        self.torn_down = True


class FakeHub:
    """Answers DHCP discover/request over the recorded send_frame path."""

    def __init__(self, client) -> None:
        self.client = client
        self.lease_ip = 0x0A080002

    def on_frame(self, frame: bytes) -> None:
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
            raw[0] = 2  # requests are op 1; parse() accepts replies — read the request anyway
        msg = DHCPMessage.parse(bytes(raw))
        if msg is None:
            return
        reply = DHCPMessage(DHCPType.offer if msg.type == DHCPType.discover else DHCPType.ack,
                            msg.xid, b"\x5e\x00\x99\x88\x77\x66")
        reply.yiaddr = self.lease_ip
        reply.serverID = 0x0A080001
        reply.router = 0x0A080001
        reply.subnetMask = 0xFFFFFF00
        reply.dns = [0x08080808]
        reply.leaseSeconds = 3600
        raw = bytearray(reply.encode())
        raw[0] = 2                     # boot reply; encode() writes a client request
        raw[16:20] = self.lease_ip.to_bytes(4, "big")  # yiaddr (requests leave it zero)
        udp_out = UDP.datagram(src=0, dst=0xFFFFFFFF, sport=67, dport=68, payload=bytes(raw))
        ip_out = IPv4.packet(proto=17, src=0, dst=0xFFFFFFFF, payload=udp_out)
        self.client.deliver_frame(Ethernet.frame(dst=broadcastMAC,
                                                 src=b"\x5e\x00\x99\x88\x77\x66",
                                                 ethertype=0x0800, payload=ip_out))


class FakeClient:
    def __init__(self, hub: FakeHub) -> None:
        self.hub = hub
        self.closed = False
        self.close_error = None
        self.on_frame = None
        self.on_close = None
        self.remote_ipv4 = "203.0.113.7"

    def deliver_frame(self, frame: bytes) -> None:
        if self.on_frame:
            self.on_frame(frame)

    def send_frame(self, frame: bytes) -> None:
        self.hub.on_frame(frame)

    async def connect(self, log) -> object:
        class FakeWelcome:
            session_name = "SID-something"
            connection_name = "CN"
            timeout_ms = 30000
            session_key = b"\x01" * 20
            max_connection = 1
            use_compress = False
            udp_server_ip = None
        log("TLS established")
        return FakeWelcome()

    @property
    def bypass_hosts(self):
        return [self.remote_ipv4]

    @property
    def bytes_in(self):
        return 0

    @property
    def bytes_out(self):
        return 0

    def close(self, error=None) -> None:
        self.closed = True
        self.close_error = error
        if self.on_close:
            cb, self.on_close = self.on_close, None
            cb(error)


class SessionTests(unittest.TestCase):
    def _config(self, **kwargs) -> ConnectConfig:
        defaults = dict(host="vpn.example.com", ports=[443], hubName="VPNGATE", userName="vpn",
                        authType="anonymous", proxy=ProxySettings(), maxConnection=1,
                        useUdpAccel=False, disableQoS=True, autoReconnect=False,
                        blockIPv6=True)
        defaults.update(kwargs)
        return ConnectConfig(**defaults)

    def _run(self, coro):
        return asyncio.run(coro)

    def test_connect_disconnect_lifecycle(self):
        async def scenario():
            session = VPNSession(timing=SessionTiming())
            events: list[HelperEvent] = []
            session.emit = events.append

            hub = FakeHub(None)
            client = FakeClient(hub)
            hub.client = client
            net = RecordingNet()

            session._make_transport = lambda config, port: client
            tun = FakeTun()
            session._make_tun = lambda: tun  # type: ignore
            session._make_net = lambda: net  # type: ignore

            session.connect_config(self._config())
            # Wait until connected.
            for _ in range(300):
                if session.snapshot.state == ConnectionState.connected:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(session.snapshot.state, ConnectionState.connected)
            self.assertEqual(session.snapshot.virtualIP, ip_string(hub.lease_ip))
            self.assertEqual(tun.name, "faketun0")
            self.assertEqual(net.applied[2], client.remote_ipv4)
            self.assertTrue(any(e.state == ConnectionState.connected for e in events))

            session.disconnect()
            for _ in range(300):
                if session.snapshot.state == ConnectionState.disconnected and net.torn_down:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(session.snapshot.state, ConnectionState.disconnected)
            self.assertTrue(client.closed)
            self.assertTrue(net.torn_down)
            self.assertTrue(tun.closed)
        self._run(scenario())

    def test_close_reason_is_reported(self):
        async def scenario():
            from vpngate.core.stream import closed_error
            session = VPNSession(timing=SessionTiming())
            hub = FakeHub(None)
            client = FakeClient(hub)
            hub.client = client
            session._make_transport = lambda config, port: client
            session._make_tun = lambda: FakeTun()
            session._make_net = lambda: RecordingNet()
            session.connect_config(self._config())
            for _ in range(300):
                if session.snapshot.state == ConnectionState.connected:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(session.snapshot.state, ConnectionState.connected)
            # The server (or watchdog) closes the link: the session must report the real reason.
            client.on_close(closed_error())
            for _ in range(300):
                if session.snapshot.state == ConnectionState.disconnected:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(session.snapshot.state, ConnectionState.disconnected)
            self.assertEqual(session.snapshot.error, "Connection closed")
        self._run(scenario())

    def test_failed_connect_reports_disconnected_without_reconnect(self):
        async def scenario():
            session = VPNSession(timing=SessionTiming())
            session.emit = lambda e: None

            class FailingClient:
                closed = False

                def __init__(self) -> None:
                    self.on_frame = None
                    self.on_close = None
                    self.remote_ipv4 = None

                def send_frame(self, frame):
                    pass

                async def connect(self, log):
                    raise ConnectionError("refused")

                @property
                def bypass_hosts(self):
                    return []

                @property
                def bytes_in(self):
                    return 0

                @property
                def bytes_out(self):
                    return 0

                def close(self, error=None):
                    self.closed = True

            failing = FailingClient()
            session._make_transport = lambda config, port: failing
            session._make_tun = lambda: FakeTun()  # type: ignore
            session._make_net = lambda: RecordingNet()  # type: ignore

            session.connect_config(self._config(autoReconnect=False, ports=[443]))
            for _ in range(400):
                if session.snapshot.error is not None:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(session.snapshot.state, ConnectionState.disconnected)
            self.assertIsNotNone(session.snapshot.error)
            self.assertIn("refused", session.snapshot.error)
        self._run(scenario())


if __name__ == "__main__":
    unittest.main()