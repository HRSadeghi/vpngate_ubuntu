"""Server list CSV parsing, list formatting, filtering."""

import os
import unittest
from datetime import datetime, timezone

from vpngate.core.serverfilter import ServerFilter
from vpngate.core.serverlist import ListFormat, VPNServer, openvpn_endpoint, parse_csv, port_priority

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures_vpngate_snapshot.csv")


class ServerListTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(FIXTURE, encoding="utf-8") as f:
            cls.csv = f.read()
        cls.servers = parse_csv(cls.csv)

    def test_parses_fixture(self):
        self.assertTrue(self.servers)
        for s in self.servers:
            self.assertNotIn("#", s.hostName)
            self.assertTrue(s.ip.count(".") == 3)

    def test_openvpn_endpoint_extracted(self):
        with_ports = [s for s in self.servers if s.listedPort]
        self.assertTrue(with_ports)
        s = with_ports[0]
        self.assertIn(s.listedProto, ("tcp", "udp"))
        self.assertTrue(1 <= s.listedPort <= 65535)

    def test_skips_comment_lines(self):
        for line in self.csv.splitlines():
            if line.startswith("#") or line.startswith("*"):
                self.assertFalse(any(s.hostName in line and s.ip in line for s in self.servers)
                                 and line.startswith("#"))

    def test_id_is_hostname(self):
        s = self.servers[0]
        self.assertEqual(s.id, s.hostName)

    def test_flag(self):
        s = VPNServer(hostName="h", ip="1.2.3.4", countryShort="US")
        self.assertEqual(s.flag, "\U0001F1FA\U0001F1F8")

    def test_connect_port(self):
        s = VPNServer(hostName="h", ip="1.2.3.4", sslPorts=[995, 443], listedPort=1194)
        self.assertEqual(s.connect_port, 443)
        s2 = VPNServer(hostName="h", ip="1.2.3.4", listedPort=0)
        self.assertIsNone(s2.connect_port)

    def test_json_round_trip(self):
        s = self.servers[0]
        s2 = VPNServer.from_json(s.to_json())
        self.assertEqual(s2.id, s.id)
        self.assertEqual(s2.ip, s.ip)
        self.assertEqual(s2.sslPorts, s.sslPorts)
        self.assertEqual(s2.udpPort, s.udpPort)

    def test_tolerates_old_cache_with_tcp_port(self):
        s = VPNServer.from_json({"hostName": "h", "ip": "1.2.3.4", "tcpPort": 5555})
        self.assertEqual(s.listedPort, 5555)


class PortPriorityTests(unittest.TestCase):
    def test_order(self):
        self.assertEqual(port_priority([22, 992, 443]), [443, 992, 22])
        self.assertEqual(port_priority([1194, 5555]), [1194, 5555])
        self.assertEqual(port_priority([]), [])


class OpenVPNEndpointTests(unittest.TestCase):
    def test_tcp(self):
        cfg = "client\ndev tun\nproto tcp\nremote 1.2.3.4 443\n"
        self.assertEqual(openvpn_endpoint(cfg), (443, "tcp"))

    def test_udp(self):
        cfg = "proto udp\nremote vpn.example.com 1194\n"
        self.assertEqual(openvpn_endpoint(cfg), (1194, "udp"))

    def test_missing(self):
        self.assertEqual(openvpn_endpoint("client\ndev tun\n"), (0, ""))


class ListFormatTests(unittest.TestCase):
    def test_uptime(self):
        self.assertEqual(ListFormat.uptime(0), "0 mins")
        self.assertEqual(ListFormat.uptime(59 * 60000), "59 mins")
        self.assertEqual(ListFormat.uptime(60 * 60000), "60 mins")  # < 3,600,001 ms → minutes
        self.assertEqual(ListFormat.uptime(61 * 60000), "1 hour")
        self.assertEqual(ListFormat.uptime(90 * 60000), "1 hour")
        self.assertEqual(ListFormat.uptime(25 * 3600000), "1 day")
        self.assertEqual(ListFormat.uptime(3 * 86400000), "3 days")
        self.assertEqual(ListFormat.uptime(-5), "0 mins")

    def test_sessions(self):
        self.assertEqual(ListFormat.sessions(1), "1 session")
        self.assertEqual(ListFormat.sessions(5), "5 sessions")

    def test_logins(self):
        self.assertEqual(ListFormat.logins(1), "1 login")
        self.assertEqual(ListFormat.logins(12345), "12,345 logins")

    def test_logging(self):
        self.assertEqual(ListFormat.logging("No Logs"), "No Logs")
        self.assertEqual(ListFormat.logging("2 Weeks"), "2 Weeks")
        self.assertEqual(ListFormat.logging("Permanent"), "Permanent")
        self.assertEqual(ListFormat.logging("weird"), "weird")
        self.assertEqual(ListFormat.logging(""), "-")

    def test_pings(self):
        self.assertEqual(ListFormat.pings(12, 0), "12 ms, -")
        self.assertEqual(ListFormat.pings(0, 30), "-, 30 ms")

    def test_udp(self):
        self.assertEqual(ListFormat.udp(None), "-")
        self.assertEqual(ListFormat.udp(1194), "UDP OK")

    def test_is_list_ok(self):
        now = datetime.now(timezone.utc).timestamp()
        self.assertTrue(ListFormat.is_list_ok(datetime.fromtimestamp(now - 3600)))
        self.assertFalse(ListFormat.is_list_ok(datetime.fromtimestamp(now - 25 * 3600)))


class ServerFilterTests(unittest.TestCase):
    def servers(self):
        return [
            VPNServer(hostName="a.example.com", ip="10.0.0.1", countryLong="Japan",
                      operatorName="Taro", logType="2 Weeks", score=100),
            VPNServer(hostName="b.example.com", ip="10.0.0.2", countryLong="USA",
                      operatorName="Bob", logType="no", score=50),
            VPNServer(hostName="c.example.com", ip="10.0.0.3", countryLong="Japan",
                      operatorName="Hanako", logType="Permanent", score=10),
        ]

    def test_search(self):
        f = ServerFilter()
        f.search = "taro"
        out = f.apply(self.servers())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].hostName, "a.example.com")

    def test_search_matches_ip(self):
        f = ServerFilter()
        f.search = "10.0.0.2"
        self.assertEqual(len(f.apply(self.servers())), 1)

    def test_country(self):
        f = ServerFilter()
        f.country = "Japan"
        self.assertEqual(len(f.apply(self.servers())), 2)

    def test_favorites(self):
        f = ServerFilter()
        f.favorites_only = True
        f.favorites = {"b.example.com"}
        self.assertEqual([s.hostName for s in f.apply(self.servers())], ["b.example.com"])

    def test_max_log_weeks(self):
        f = ServerFilter()
        f.max_log_weeks = 2
        out = f.apply(self.servers())
        self.assertEqual([s.hostName for s in out], ["a.example.com", "b.example.com"])

    def test_unknown_retention_hidden(self):
        f = ServerFilter()
        f.max_log_weeks = 0
        out = f.apply([VPNServer(hostName="x", ip="1.1.1.1", logType="weird")])
        self.assertEqual(out, [])

    def test_log_weeks_parsing(self):
        self.assertEqual(ServerFilter.log_weeks("no"), 0)
        self.assertEqual(ServerFilter.log_weeks("none"), 0)
        self.assertEqual(ServerFilter.log_weeks("0"), 0)
        self.assertEqual(ServerFilter.log_weeks("2weeks"), 2)
        self.assertEqual(ServerFilter.log_weeks("3days"), 1)
        self.assertEqual(ServerFilter.log_weeks("1month"), 5)
        self.assertEqual(ServerFilter.log_weeks("3months"), 13)
        self.assertEqual(ServerFilter.log_weeks("1year"), 52)
        self.assertIsNone(ServerFilter.log_weeks("garbage"))


if __name__ == "__main__":
    unittest.main()
