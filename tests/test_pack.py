"""SoftEther Pack serialize/parse."""

import unittest

from vpngate.core.pack import Pack, PackBadName, PackBadType, PackTruncated


class PackTests(unittest.TestCase):
    def test_round_trip(self):
        p = Pack()
        p.add_str("method", "login")
        p.add_int("authtype", 0)
        p.add_bool("use_encrypt", True)
        p.add_data("unique_id", bytes(range(20)))
        p.add_uni("note", "héllo")
        p.add_int64("big", 2 ** 40 + 7)
        p.add_ints("Port", [443, 992, 5555])
        p.add_ipv4("Ip", 0x01020304)
        q = Pack.parse(p.serialize())
        self.assertEqual(q.str("method"), "login")
        self.assertEqual(q.int("authtype"), 0)
        self.assertEqual(q.int("use_encrypt"), 1)
        self.assertEqual(q.data("unique_id"), bytes(range(20)))
        self.assertEqual(q.str("note"), "héllo")
        self.assertEqual(q.int64("big"), 2 ** 40 + 7)
        self.assertEqual(q.ints("Port"), [443, 992, 5555])
        self.assertEqual(q.int("Ip"), 0x01020304)
        self.assertEqual(q.int("Ip@ipv6_bool"), 0)
        self.assertEqual(q.data("Ip@ipv6_array"), bytes(16))

    def test_case_insensitive_replace_and_lookup(self):
        p = Pack()
        p.add_str("Method", "login")
        p.add_str("method", "additional_connect")
        self.assertEqual(len(p.elements), 1)
        self.assertEqual(p.str("METHOD"), "additional_connect")

    def test_truncated(self):
        p = Pack()
        p.add_int("n", 5)
        blob = p.serialize()
        with self.assertRaises(PackTruncated):
            Pack.parse(blob[:3])
        with self.assertRaises(PackTruncated):
            Pack.parse(blob[:-2])

    def test_bad_name(self):
        with self.assertRaises(PackBadName):
            Pack.parse(b"\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00")

    def test_bad_type(self):
        # one element, type 9
        blob = (1).to_bytes(4, "big") + (2).to_bytes(4, "big") + b"n" \
            + (9).to_bytes(4, "big") + (1).to_bytes(4, "big") + (1).to_bytes(4, "big")
        with self.assertRaises(PackBadType):
            Pack.parse(blob)

    def test_empty(self):
        q = Pack.parse(Pack().serialize())
        self.assertEqual(q.elements, [])


if __name__ == "__main__":
    unittest.main()
