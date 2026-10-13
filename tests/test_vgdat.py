"""VPNGate.dat parsing against the real bundled file, probes, tunables."""

import os
import time
import unittest

from vpngate.core.pack import Pack
from vpngate.core.vgdat import (ALLOW_TIME_DIFF_MS, VGDatError, VGTunables, generate_probe,
                                parse, verify_probe)

ASSET = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "assets", "VPNGate.dat")


class VGDatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(ASSET, "rb") as f:
            cls.data = f.read()

    def test_parses_real_file_with_valid_signature(self):
        file = parse(self.data)
        self.assertTrue(file.is_signature_valid)
        self.assertTrue(file.servers, "the bundled list has servers")
        self.assertTrue(file.header_text.startswith("[VPNGate Data File]"))

    def test_server_fields(self):
        file = parse(self.data)
        s = file.servers[0]
        self.assertTrue(s.ip)
        self.assertTrue(s.hostName)
        self.assertIsInstance(s.score, int)
        self.assertIsInstance(s.uptimeMs, int)
        self.assertIn(s.logType, ("Permanent", "2 Weeks", "No Log"))
        for server in file.servers[:10]:
            self.assertGreater(len(server.ip.split(".")), 1)

    def test_port_priority(self):
        file = parse(self.data)
        for s in file.servers[:20]:
            if s.sslPorts:
                # 443 first when offered
                if 443 in s.sslPorts:
                    self.assertEqual(s.prioritized_ssl_ports[0], 443)
                self.assertEqual(sorted(s.prioritized_ssl_ports), sorted(s.sslPorts))

    def test_rejects_corrupted(self):
        bad = bytearray(self.data)
        bad[len(bad) // 2] ^= 0xFF  # flip a body byte: RC4/Pack/RSA must catch it
        with self.assertRaises(VGDatError):
            parse(bytes(bad))

    def test_rejects_truncated(self):
        with self.assertRaises(VGDatError):
            parse(self.data[:10])

    def test_rejects_wrong_header(self):
        bad = b"X" + self.data[1:]
        with self.assertRaises(VGDatError):
            parse(bad)

    def test_freshness_window(self):
        file = parse(self.data, now=time.time())
        ts = file.timestamp_ms / 1000.0
        fresh = parse(self.data, now=ts + (ALLOW_TIME_DIFF_MS / 1000.0))
        self.assertTrue(fresh.is_fresh)
        stale = parse(self.data, now=ts + (ALLOW_TIME_DIFF_MS / 1000.0) + 61)
        self.assertFalse(stale.is_fresh)

    def test_bundled_list_tunables(self):
        file = parse(self.data)
        # The shipped list sets VGC_HTTP_POLL_INTERVAL_OK to 2 h.
        self.assertEqual(file.tunables.value("VGC_HTTP_POLL_INTERVAL_OK", 3_600_000), 7_200_000)


class TunablesTests(unittest.TestCase):
    def test_clamped(self):
        pack = Pack()
        pack.add_int64("vgc_http_poll_interval_ok", 100)
        t = VGTunables(pack.serialize())
        # below default/5 → clamped up to default/5
        self.assertEqual(t.value("VGC_HTTP_POLL_INTERVAL_OK", 3_600_000), 3_600_000 // 5)
        pack2 = Pack()
        pack2.add_int64("vgc_http_poll_interval_ok", 10 ** 12)
        t2 = VGTunables(pack2.serialize())
        # above default*50 → clamped down
        self.assertEqual(t2.value("VGC_HTTP_POLL_INTERVAL_OK", 3_600_000), 3_600_000 * 50)

    def test_zero_means_unset(self):
        pack = Pack()
        pack.add_int64("vgc_http_poll_interval_ok", 0)
        t = VGTunables(pack.serialize())
        self.assertEqual(t.value("VGC_HTTP_POLL_INTERVAL_OK", 3_600_000), 3_600_000)

    def test_case_insensitive_and_missing(self):
        pack = Pack()
        pack.add_int64("VGC_Num_TCP_Target_Hosts", 7)
        t = VGTunables(pack.serialize())
        self.assertEqual(t.value("vgc_num_tcp_target_hosts", 12), 7)
        self.assertEqual(t.value("absent", 5), 5)

    def test_non_int64_skipped(self):
        pack = Pack()
        pack.add_str("vgc_x", "text")
        t = VGTunables(pack.serialize())
        self.assertEqual(t.value("vgc_x", 9), 9)

    def test_unparseable_is_empty(self):
        self.assertEqual(VGTunables(b"not a pack").values, {})


class ProbeTests(unittest.TestCase):
    def test_round_trip(self):
        ts = int(time.time() * 1000)
        probe = generate_probe(ts)
        self.assertEqual(len(probe), 16)
        self.assertTrue(verify_probe(probe, now=ts / 1000.0))

    def test_rejects_stale(self):
        old = int(time.time() * 1000) - 37 * 3600 * 1000
        self.assertFalse(verify_probe(generate_probe(old)))

    def test_rejects_wrong_length(self):
        self.assertFalse(verify_probe(b"\x00" * 8))

    def test_rejects_tampered(self):
        probe = bytearray(generate_probe())
        probe[15] ^= 0xFF
        self.assertFalse(verify_probe(bytes(probe)))


if __name__ == "__main__":
    unittest.main()
