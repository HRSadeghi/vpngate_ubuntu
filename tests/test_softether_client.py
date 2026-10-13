"""SoftEther client helpers: login pack, redirect, max connections, watermark."""

import unittest

from vpngate.core.ipcmessages import ProxySettings
from vpngate.core.pack import Pack
from vpngate.core.packets import packIPString
from vpngate.core.stream import StreamError
from vpngate.core.watermark import SOFT_ETHER_WATERMARK
from vpngate.helper.hostuniqueid import HostUniqueId
from vpngate.helper.softetherclient import (ClientAuth, SoftEtherClient, ascii_uppercased,
                                            negotiated_max_connection, redirect_host,
                                            resolve_udp_server_ip, valid_port)


def make_client(**kwargs) -> SoftEtherClient:
    defaults = dict(host="vpn.example.com", port=443, unique_id=HostUniqueId(b"\x01" * 32),
                    proxy=ProxySettings())
    defaults.update(kwargs)
    return SoftEtherClient(**defaults)


class NegotiatedMaxConnectionTests(unittest.TestCase):
    def test_capped_by_client(self):
        self.assertEqual(negotiated_max_connection(8, False, 1, False, False), 1)
        self.assertEqual(negotiated_max_connection(8, True, 1, False, False), 8)  # udp recovery

    def test_clamped(self):
        self.assertEqual(negotiated_max_connection(0, False, 8, False, False), 1)
        self.assertEqual(negotiated_max_connection(99, False, 99, False, False), 32)

    def test_qos_minimums(self):
        self.assertEqual(negotiated_max_connection(1, False, 8, True, False), 2)
        self.assertEqual(negotiated_max_connection(1, False, 8, True, True), 4)


class LoginPackTests(unittest.TestCase):
    def test_anonymous_login_pack(self):
        client = make_client(hub_name="VPNGATE", user_name="vpn")
        pack = client.login_pack(random=bytes(20), auth=ClientAuth.ANONYMOUS,
                                 host="vpn.example.com", port=443,
                                 server_info=("SoftEther VPN Server", 444, 9807))
        self.assertEqual(pack.str("method"), "login")
        self.assertEqual(pack.str("hubname"), "VPNGATE")
        self.assertEqual(pack.str("username"), "vpn")
        self.assertEqual(pack.int("authtype"), 0)
        self.assertEqual(pack.int("client_ver"), 444)
        self.assertEqual(pack.int("client_build"), 9807)
        self.assertEqual(pack.int("max_connection"), 8)  # the client default
        self.assertEqual(pack.int("use_encrypt"), 1)
        self.assertEqual(pack.int("qos"), 1)  # QoS on by default
        self.assertEqual(pack.str("ClientOsName"), "Linux")
        self.assertEqual(pack.data("unique_id"),
                         HostUniqueId(b"\x01" * 32).login_id)
        self.assertEqual(pack.int("ServerPort2"), 443)
        self.assertEqual(pack.data("ClientIpAddress6"), bytes(16))

    def test_vpngate_path_disables_qos(self):
        # The session's connect_host builds the config with disableQoS; the login pack honours it.
        client = make_client()
        client.disable_qos = True
        pack = client.login_pack()
        self.assertEqual(pack.int("qos"), 0)

    def test_hashed_password(self):
        from vpngate.core.sha0 import hash as sha0
        client = make_client(auth=ClientAuth.HASHED_PASSWORD, password="pw")
        random = b"\x05" * 20
        pack = client.login_pack(random=random, auth=ClientAuth.HASHED_PASSWORD)
        self.assertEqual(pack.int("authtype"), 1)
        pw_data = b"pw" + b"VPN"  # ascii_uppercased("vpn")
        hashed = sha0(pw_data)
        expected = sha0(hashed + random)
        self.assertEqual(pack.data("secure_password"), expected)

    def test_plain_password(self):
        client = make_client(auth=ClientAuth.PLAIN_PASSWORD, password="plain")
        pack = client.login_pack(auth=ClientAuth.PLAIN_PASSWORD)
        self.assertEqual(pack.int("authtype"), 2)
        self.assertEqual(pack.str("plain_password"), "plain")

    def test_ticket(self):
        client = make_client(auth=ClientAuth.TICKET, ticket=b"\x07" * 20)
        pack = client.login_pack(auth=ClientAuth.TICKET)
        self.assertEqual(pack.int("authtype"), 99)
        self.assertEqual(pack.data("ticket"), b"\x07" * 20)

    def test_udp_negotiation_fields(self):
        client = make_client(use_udp_accel=True)
        pack = client.login_pack(client_udp_port=51234, client_key_v1=b"\x01" * 20,
                                 client_key_v2=b"\x02" * 128)
        self.assertEqual(pack.int("use_udp_acceleration"), 1)
        self.assertEqual(pack.int("udp_acceleration_client_port"), 51234)
        self.assertEqual(pack.data("udp_acceleration_client_key"), b"\x01" * 20)
        self.assertEqual(pack.data("udp_acceleration_client_key_v2"), b"\x02" * 128)
        self.assertEqual(pack.int("udp_acceleration_version"), 2)
        self.assertEqual(pack.int("udp_acceleration_max_version"), 2)

    def test_no_udp_fields_when_disabled(self):
        client = make_client(use_udp_accel=False)
        pack = client.login_pack()
        self.assertIsNone(pack.value("use_udp_acceleration"))

    def test_ascii_uppercased(self):
        # Only a-z are mapped; non-ASCII letters stay untouched (the hash depends on it).
        self.assertEqual(ascii_uppercased("vpn"), "VPN")
        self.assertEqual(ascii_uppercased("ça"), "çA")
        self.assertEqual(ascii_uppercased("a-b9"), "A-B9")


class RedirectTests(unittest.TestCase):
    def test_string_ip(self):
        w = Pack()
        w.add_str("Ip", "9.9.9.9")
        self.assertEqual(redirect_host(w, "5.6.7.8"), "9.9.9.9")

    def test_zero_ip_falls_back(self):
        w = Pack()
        w.add_str("Ip", "0.0.0.0")
        self.assertEqual(redirect_host(w, "5.6.7.8"), "5.6.7.8")

    def test_pack_integer_ip(self):
        w = Pack()
        w.add_int("Ip", 0x09090909)
        self.assertEqual(redirect_host(w, "5.6.7.8"), packIPString(0x09090909))

    def test_absent_falls_back(self):
        self.assertEqual(redirect_host(Pack(), "5.6.7.8"), "5.6.7.8")

    def test_invalid_host_rejected(self):
        w = Pack()
        w.add_str("Ip", "-x")
        with self.assertRaises(StreamError):
            redirect_host(w, "5.6.7.8")

    def test_ipv6_rejected(self):
        w = Pack()
        w.add_str("Ip", "2001:db8::1")
        w.add_bool("Ip@ipv6_bool", True)
        with self.assertRaises(StreamError):
            redirect_host(w, "5.6.7.8")


class ResolveUdpServerIPTests(unittest.TestCase):
    def test_public_advertised(self):
        self.assertEqual(resolve_udp_server_ip("9.9.9.9", "5.6.7.8"), "9.9.9.9")

    def test_private_advertised_uses_tcp_host(self):
        self.assertEqual(resolve_udp_server_ip("10.0.0.1", "5.6.7.8"), "5.6.7.8")

    def test_none(self):
        self.assertIsNone(resolve_udp_server_ip(None, "example.com"))
        self.assertEqual(resolve_udp_server_ip("1.2.3.4", "example.com"), "1.2.3.4")  # public literal


class ValidPortTests(unittest.TestCase):
    def test(self):
        self.assertEqual(valid_port(443), 443)
        self.assertIsNone(valid_port(0))
        self.assertIsNone(valid_port(65536))


class WatermarkTests(unittest.TestCase):
    def test_gif_magic(self):
        self.assertTrue(SOFT_ETHER_WATERMARK.startswith(b"GIF8"))
        self.assertGreater(len(SOFT_ETHER_WATERMARK), 1000)


if __name__ == "__main__":
    unittest.main()
