"""Ethernet/IP/ARP/DHCP/UDP/IPv6 packet builders and parsers."""

import unittest

from vpngate.core.packets import (ARPPacket, DHCPMessage, DHCPType, Ethernet, ICMPv6, IPv4, IPv6,
                                  UDP, be16, be32, broadcastMAC, checksum, ip_string, packIPString,
                                  packIPValue, rd16, rd32, rd64)


class PrimitivesTests(unittest.TestCase):
    def test_be_rd_round_trip(self):
        self.assertEqual(be16(0x1234), b"\x12\x34")
        self.assertEqual(be32(0x12345678), b"\x124Vx")
        b = be32(0x11223344) + b"\x55\x66"
        self.assertEqual(rd16(b, 0), 0x1122)
        self.assertEqual(rd32(b, 0), 0x11223344)
        self.assertEqual(rd64(be32(0) + be32(0x1234), 0), 0x1234)

    def test_checksum(self):
        self.assertEqual(checksum(b""), 0xFFFF)
        # RFC 1071 example: 00 01 f2 03 f4 f5 f6 f7 -> 220d
        self.assertEqual(checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220D)

    def test_ip_string(self):
        self.assertEqual(ip_string(0x7F000001), "127.0.0.1")

    def test_pack_ip_string(self):
        # The pack integer is the little-endian reading: first octet is the LOW byte.
        self.assertEqual(packIPString(0x0A000001), "1.0.0.10")
        # Inverse of packIPString's reading for the dotted literal.
        self.assertEqual(packIPValue(bytes([10, 0, 0, 1])), 0x0100000A)
        self.assertEqual(packIPString(packIPValue(bytes([10, 0, 0, 1]))), "10.0.0.1")
        # Round trip with PackAddIp semantics
        p = 0x5E0102F3
        parts = packIPString(p)
        self.assertEqual(parts, "243.2.1.94")


class EthernetTests(unittest.TestCase):
    def test_frame(self):
        f = Ethernet.frame(b"\x01" * 6, b"\x02" * 6, 0x0800, b"payload")
        self.assertEqual(f[:6], b"\x01" * 6)
        self.assertEqual(f[6:12], b"\x02" * 6)
        self.assertEqual(rd16(f, 12), 0x0800)
        self.assertEqual(f[14:], b"payload")


class ARPTests(unittest.TestCase):
    def test_round_trip(self):
        a = ARPPacket(1, b"\x5e" * 6, 0x0A000001, bytes(6), 0x0A0000FE)
        parsed = ARPPacket.parse(a.encode())
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.op, 1)
        self.assertEqual(parsed.senderMAC, b"\x5e" * 6)
        self.assertEqual(parsed.senderIP, 0x0A000001)
        self.assertEqual(parsed.targetIP, 0x0A0000FE)

    def test_rejects_garbage(self):
        self.assertIsNone(ARPPacket.parse(b"\x00" * 10))
        self.assertIsNone(ARPPacket.parse(bytes(28)))  # htype 0


class IPv4Tests(unittest.TestCase):
    def test_parse_round_trip(self):
        payload = bytes(8)
        pkt = IPv4.packet(proto=17, src=0x01020304, dst=0x05060708, payload=payload)
        parsed = IPv4.parse(pkt)
        self.assertIsNotNone(parsed)
        proto, src, dst, pl = parsed
        self.assertEqual(proto, 17)
        self.assertEqual(src, 0x01020304)
        self.assertEqual(dst, 0x05060708)
        self.assertEqual(pl, payload)

    def test_header_checksum_valid(self):
        pkt = IPv4.packet(proto=6, src=1, dst=2, payload=b"")
        self.assertEqual(checksum(pkt[:20]), 0)

    def test_rejects_short(self):
        self.assertIsNone(IPv4.parse(b"\x45" * 10))


class DHCPTests(unittest.TestCase):
    def test_encode_offer(self):
        # encode() writes a client request (op 1); parse() accepts server replies (op 2),
        # so the reply is built by patching the encoded request the way the hub would.
        m = DHCPMessage(DHCPType.offer, 0x1234, b"\x01\x02\x03\x04\x05\x06")
        m.serverID = 0x0A000001
        raw = bytearray(m.encode())
        raw[0] = 2
        raw[16:20] = be32(0x0A000001)  # yiaddr
        options = bytes([53, 1, DHCPType.offer.value])
        options += bytes([1, 4]) + be32(0xFFFFFF00)        # subnet mask
        options += bytes([3, 4]) + be32(0x0A0000FE)        # router
        options += bytes([6, 4]) + be32(0x08080808)        # dns
        options += bytes([54, 4]) + be32(0x0A000001)       # server id
        options += bytes([51, 4]) + be32(3600)             # lease seconds
        options += bytes([26, 2]) + be16(1400)             # mtu
        options += bytes([255])
        raw[240:240 + len(m.encode()) - 240] = options
        parsed = DHCPMessage.parse(bytes(raw))
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.type, DHCPType.offer)
        self.assertEqual(parsed.xid, 0x1234)
        self.assertEqual(parsed.mac, b"\x01\x02\x03\x04\x05\x06")
        self.assertEqual(parsed.yiaddr, 0x0A000001)
        self.assertEqual(parsed.serverID, 0x0A000001)
        self.assertEqual(parsed.subnetMask, 0xFFFFFF00)
        self.assertEqual(parsed.router, 0x0A0000FE)
        self.assertEqual(parsed.dns, [0x08080808])
        self.assertEqual(parsed.mtu, 1400)
        self.assertEqual(parsed.leaseSeconds, 3600)

    def test_discover_encode_parses(self):
        m = DHCPMessage(DHCPType.discover, 7, b"\xaa" * 6)
        m.requestedIP = 0x01020304
        m.serverID = 0x0A000001
        parsed = DHCPMessage.parse(m.encode())  # op 1: parse() rejects it
        self.assertIsNone(parsed)
        raw = bytearray(m.encode())
        raw[0] = 2
        parsed2 = DHCPMessage.parse(bytes(raw))
        self.assertIsNotNone(parsed2)
        self.assertEqual(parsed2.type, DHCPType.discover)
        self.assertEqual(parsed2.xid, 7)
        self.assertEqual(parsed2.serverID, 0x0A000001)
        # requested-ip (option 50) is written but never read back (Swift parity)

    def test_bogus_mtu_ignored(self):
        m = DHCPMessage(DHCPType.ack, 1, b"\x00" * 6)
        raw = bytearray(m.encode())
        # append option 26 with value 9000
        raw += bytes([26, 2]) + be16(9000) + bytes([255])
        raw[0] = 2
        parsed = DHCPMessage.parse(bytes(raw))
        self.assertIsNotNone(parsed)
        self.assertIsNone(parsed.mtu)

    def test_rejects_non_bootreply(self):
        self.assertIsNone(DHCPMessage.parse(bytes(240)))


class UDPTests(unittest.TestCase):
    def test_round_trip(self):
        d = UDP.datagram(src=0, dst=0xFFFFFFFF, sport=68, dport=67, payload=b"\x01\x02\x03")
        parsed = UDP.parse(d)
        self.assertIsNotNone(parsed)
        sport, dport, payload = parsed
        self.assertEqual((sport, dport), (68, 67))
        self.assertEqual(payload, b"\x01\x02\x03")
        # With the checksum in place the pseudo-header sum cancels to zero.
        pseudo = be32(0) + be32(0xFFFFFFFF) + bytes([0, 17]) + be16(len(d))
        self.assertEqual(checksum(pseudo + d), 0)


class IPv6Tests(unittest.TestCase):
    def test_link_local(self):
        ll = IPv6.link_local(b"\x5e\x00\x01\x02\x03\x04")
        self.assertEqual(ll[:8], bytes([0xFE, 0x80, 0, 0, 0, 0, 0, 0]))
        self.assertEqual(ll[8], 0x5C)  # 0x5E ^ 0x02 (universal/local bit flipped)
        self.assertEqual(ll[9:11], b"\x00\x01")
        self.assertEqual(ll[11:13], b"\xff\xfe")
        self.assertEqual(ll[13:], b"\x02\x03\x04")
        self.assertTrue(IPv6.is_link_local(ll))

    def test_slaac(self):
        prefix = bytes([0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0]) + bytes(8)
        addr = IPv6.slaac(prefix, b"\x5e\x00\x01\x02\x03\x04")
        self.assertEqual(addr[:8], prefix[:8])
        self.assertEqual(addr[8:], IPv6.link_local(b"\x5e\x00\x01\x02\x03\x04")[8:])

    def test_string(self):
        addr = bytes([0x20, 0x01] + [0] * 12 + [0, 0x01])
        self.assertEqual(IPv6.string(addr), "2001:0:0:0:0:0:0:1")

    def test_multicast_mapping(self):
        dst = bytes([0xFF, 0x02] + [0] * 9 + [0x01, 0xFF, 0xAA, 0xBB, 0xCC])
        self.assertEqual(IPv6.solicited_node_multicast(dst)[11:13], b"\x01\xff")
        self.assertEqual(IPv6.multicast_mac(dst), b"\x33\x33" + dst[12:])

    def test_ndp_hop_limit(self):
        src = IPv6.link_local(b"\x5e" * 6)
        dst = IPv6.solicited_node_multicast(src)
        icmp = ICMPv6.neighbor_solicitation(src, b"\x5e" * 6, src, dst)
        pkt = IPv6.ndp_packet(src, dst, icmp)
        self.assertEqual(pkt[6], 58)
        self.assertEqual(pkt[7], 255)
        parsed = IPv6.parse(pkt)
        self.assertEqual(parsed[3], icmp)

    def test_icmpv6_checksum_round_trip(self):
        src = IPv6.link_local(b"\x5e" * 6)
        dst = bytes([0xFF, 0x02] + [0] * 13 + [2])  # all-routers ff02::2
        rs = ICMPv6.router_solicitation(b"\x5e" * 6, src)
        self.assertTrue(ICMPv6.is_checksum_valid(src, dst, rs))
        broken = bytearray(rs)
        broken[8] ^= 0xFF
        self.assertFalse(ICMPv6.is_checksum_valid(src, dst, bytes(broken)))

    def test_na_flags(self):
        target = IPv6.link_local(b"\x5e" * 6)
        na = ICMPv6.neighbor_advertisement(target, b"\x5e" * 6, target, target, solicited=True)
        self.assertEqual(na[4], 0x60)
        na_unsolicited = ICMPv6.neighbor_advertisement(target, b"\x5e" * 6, target, target,
                                                       solicited=False)
        self.assertEqual(na_unsolicited[4], 0x20)


if __name__ == "__main__":
    unittest.main()
