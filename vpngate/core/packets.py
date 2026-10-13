"""Ethernet / IP / ARP / DHCP / UDP / IPv6+NDP packet builders and parsers (port of Packets.swift)."""

from __future__ import annotations

import enum
import struct

MAC = bytes


def checksum(b: bytes) -> int:
    total = 0
    i = 0
    n = len(b)
    while i + 1 < n:
        total += (b[i] << 8) | b[i + 1]
        i += 2
    if i < n:
        total += b[i] << 8
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def be16(v: int) -> bytes:
    return bytes([(v >> 8) & 0xFF, v & 0xFF])


def be32(v: int) -> bytes:
    return bytes([(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF])


def rd16(b: bytes, o: int) -> int:
    return (b[o] << 8) | b[o + 1]


def rd32(b: bytes, o: int) -> int:
    return (b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]


def rd64(b: bytes, o: int) -> int:
    v = 0
    for i in range(8):
        v = (v << 8) | b[o + i]
    return v


broadcastMAC: MAC = b"\xff" * 6


def ip_string(ip: int) -> str:
    return ".".join(str(x) for x in be32(ip))


def ip_string_bytes(ip: bytes) -> str:
    return ".".join(str(x) for x in ip[:4])


def packIPString(v: int) -> str:
    """IPv4 as SoftEther's `PackAddIp` carries it in a pack integer (the redirect `Ip` and
    `udp_acceleration_server_ip`): the integer is always the little-endian reading and the first
    octet is the LOW byte. (Not the network-order reading `ip_string` uses for DHCP/ARP fields.)"""
    return ".".join(str(x) for x in
                    (v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF))


def packIPValue(ip: bytes) -> int:
    """Inverse of `packIPString`'s integer reading for a dotted IPv4 literal."""
    return (ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0]


def ipv4_from_string(s: str) -> int | None:
    parts = s.split(".")
    if len(parts) != 4:
        return None
    try:
        vals = [int(p) for p in parts]
    except ValueError:
        return None
    if any(p < 0 or p > 255 for p in vals) or any(len(p) == 0 or len(p) > 3 for p in parts):
        return None
    return (vals[0] << 24) | (vals[1] << 16) | (vals[2] << 8) | vals[3]


def ipv4_bytes_from_string(s: str) -> bytes | None:
    v = ipv4_from_string(s)
    return be32(v) if v is not None else None


class Ethernet:
    @staticmethod
    def frame(dst: MAC, src: MAC, ethertype: int, payload: bytes) -> bytes:
        return dst + src + be16(ethertype) + payload


class ARPPacket:
    def __init__(self, op: int, senderMAC: MAC, senderIP: int, targetMAC: MAC, targetIP: int) -> None:
        self.op = op
        self.senderMAC = senderMAC
        self.senderIP = senderIP
        self.targetMAC = targetMAC
        self.targetIP = targetIP

    def encode(self) -> bytes:
        return (bytes([0, 1, 8, 0, 6, 4]) + be16(self.op) + self.senderMAC + be32(self.senderIP)
                + self.targetMAC + be32(self.targetIP))

    @classmethod
    def parse(cls, p: bytes) -> "ARPPacket | None":
        if len(p) < 28 or rd16(p, 0) != 1 or rd16(p, 2) != 0x0800:
            return None
        return cls(rd16(p, 6), p[8:14], rd32(p, 14), p[18:24], rd32(p, 24))


class IPv4:
    @staticmethod
    def packet(proto: int, src: int, dst: int, payload: bytes) -> bytes:
        h = bytearray(bytes([0x45, 0]) + be16(20 + len(payload)) + bytes([0, 0, 0, 0, 64, proto, 0, 0])
                      + be32(src) + be32(dst))
        c = checksum(bytes(h))
        h[10] = c >> 8
        h[11] = c & 0xFF
        return bytes(h) + payload

    @staticmethod
    def parse(p: bytes) -> tuple[int, int, int, bytes] | None:
        """Returns (protocol, src, dst, payload) for a well-formed IPv4 packet."""
        if len(p) < 20 or (p[0] >> 4) != 4:
            return None
        ihl = (p[0] & 0xF) * 4
        total = min(rd16(p, 2), len(p))
        if ihl < 20 or total < ihl:
            return None
        return p[9], rd32(p, 12), rd32(p, 16), p[ihl:total]


class DHCPType(enum.Enum):
    discover = 1
    offer = 2
    request = 3
    ack = 5
    nak = 6


class DHCPMessage:
    def __init__(self, type: DHCPType, xid: int, mac: MAC) -> None:
        self.type = type
        self.xid = xid
        self.mac = mac
        self.yiaddr = 0
        self.ciaddr = 0
        self.serverID: int | None = None
        self.requestedIP: int | None = None
        self.subnetMask: int | None = None
        self.router: int | None = None
        self.dns: list[int] = []
        self.leaseSeconds: int | None = None
        self.mtu: int | None = None

    def encode(self) -> bytes:
        b = bytearray(bytes([1, 1, 6, 0]) + be32(self.xid) + bytes([0, 0, 0x80, 0]))  # broadcast flag
        b += be32(self.ciaddr) + bytes(12)                                            # ciaddr, then yiaddr siaddr giaddr
        b += self.mac + bytes(10)
        b += bytes(192)                                                               # sname + file
        b += bytes([99, 130, 83, 99])
        b += bytes([53, 1, self.type.value])
        if self.requestedIP is not None:
            b += bytes([50, 4]) + be32(self.requestedIP)
        if self.serverID is not None:
            b += bytes([54, 4]) + be32(self.serverID)
        b += bytes([55, 5, 1, 3, 6, 51, 26])                                          # parameter list incl. option 26 (MTU)
        b += bytes([255])
        return bytes(b)

    @classmethod
    def parse(cls, p: bytes) -> "DHCPMessage | None":
        if len(p) < 240 or p[0] != 2 or rd32(p, 236) != 0x63825363:
            return None
        xid = rd32(p, 4)
        yiaddr = rd32(p, 16)
        mac = p[28:34]
        t: DHCPType | None = None
        m = cls(DHCPType.discover, xid, mac)
        m.yiaddr = yiaddr
        i = 240
        while i < len(p):
            c = p[i]
            if c == 255:
                break
            if c == 0:
                i += 1
                continue
            if i + 1 >= len(p):
                break
            l = p[i + 1]
            s = i + 2
            if s + l > len(p):
                break
            if c == 53 and l == 1:
                try:
                    t = DHCPType(p[s])
                except ValueError:
                    t = None
            elif c == 54 and l == 4:
                m.serverID = rd32(p, s)
            elif c == 1 and l == 4:
                m.subnetMask = rd32(p, s)
            elif c == 3 and l >= 4:
                m.router = rd32(p, s)
            elif c == 6 and l >= 4:
                m.dns = [rd32(p, s + k) for k in range(0, l - 3, 4)]
            elif c == 51 and l == 4:
                m.leaseSeconds = rd32(p, s)
            elif c == 26 and l == 2:
                # An MTU outside 576...1500 is bogus (or would exceed what the 1500-byte hub frames can carry): ignore it.
                mm = rd16(p, s)
                if 576 <= mm <= 1500:
                    m.mtu = mm
            i = s + l
        if t is None:
            return None
        m.type = t
        return m


class UDP:
    @staticmethod
    def datagram(src: int, dst: int, sport: int, dport: int, payload: bytes) -> bytes:
        u = bytearray(be16(sport) + be16(dport) + be16(8 + len(payload)) + bytes([0, 0]) + payload)
        pseudo = be32(src) + be32(dst) + bytes([0, 17]) + be16(len(u))
        c = checksum(pseudo + bytes(u))
        if c == 0:
            c = 0xFFFF
        u[6] = c >> 8
        u[7] = c & 0xFF
        return bytes(u)

    @staticmethod
    def parse(p: bytes) -> tuple[int, int, bytes] | None:
        if len(p) < 8:
            return None
        length = min(rd16(p, 4), len(p))
        if length < 8:
            return None
        return rd16(p, 0), rd16(p, 2), p[8:length]


class IPv6:
    @staticmethod
    def header(src: bytes, dst: bytes, next_header: int, payload_len: int, hop_limit: int = 64) -> bytes:
        # Version (6) + Traffic Class (0) + Flow Label (0)
        return bytes([0x60, 0x00, 0x00, 0x00]) + be16(payload_len) + bytes([next_header, hop_limit]) + src + dst

    @staticmethod
    def parse(p: bytes) -> tuple[int, bytes, bytes, bytes] | None:
        if len(p) < 40 or (p[0] >> 4) != 6:
            return None
        payload_len = min(rd16(p, 4), len(p) - 40)
        return p[6], p[8:24], p[24:40], p[40:40 + payload_len]

    @staticmethod
    def link_local(mac: MAC) -> bytes:
        """EUI-64 link-local address generation from 48-bit MAC: fe80::(mac with bit 1 flipped)"""
        if len(mac) != 6:
            return bytes(16)
        return bytes([0xFE, 0x80, 0, 0, 0, 0, 0, 0, mac[0] ^ 0x02, mac[1], mac[2], 0xFF, 0xFE, mac[3], mac[4], mac[5]])

    @staticmethod
    def is_link_local(ip: bytes) -> bool:
        """fe80::/10"""
        return len(ip) == 16 and ip[0] == 0xFE and (ip[1] & 0xC0) == 0x80

    @staticmethod
    def slaac(prefix: bytes, mac: MAC) -> bytes:
        """SLAAC address: /64 prefix + modified EUI-64 interface identifier (RFC 4862 §5.5.3)."""
        if len(prefix) < 8 or len(mac) != 6:
            return bytes(16)
        return prefix[:8] + IPv6.link_local(mac)[8:]

    @staticmethod
    def string(ip: bytes) -> str:
        """Uncompressed colon-hex text (2001:db8:0:0:...), which inet_pton/ifconfig accept."""
        if len(ip) != 16:
            return ""
        return ":".join(format(rd16(ip, i), "x") for i in range(0, 16, 2))

    @staticmethod
    def ndp_packet(src: bytes, dst: bytes, icmp: bytes) -> bytes:
        """Neighbour Discovery messages must leave with hop limit 255 (RFC 4861 §6.1.1)."""
        return IPv6.header(src, dst, 58, len(icmp), hop_limit=255) + icmp

    @staticmethod
    def solicited_node_multicast(ip: bytes) -> bytes:
        """ff02::1:ffXX:XXXX"""
        if len(ip) != 16:
            return bytes(16)
        return bytes([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, ip[13], ip[14], ip[15]])

    @staticmethod
    def multicast_mac(ip: bytes) -> MAC:
        """33:33:XX:XX:XX:XX"""
        if len(ip) != 16:
            return bytes([0x33, 0x33, 0, 0, 0, 0])
        return bytes([0x33, 0x33, ip[12], ip[13], ip[14], ip[15]])


class ICMPv6:
    @staticmethod
    def checksum(src: bytes, dst: bytes, icmp_payload: bytes) -> int:
        pseudo = src + dst + bytes([0, 0]) + be16(len(icmp_payload)) + bytes([0, 0, 0, 58])
        return checksum(pseudo + icmp_payload)

    @staticmethod
    def is_checksum_valid(src: bytes, dst: bytes, icmp: bytes) -> bool:
        return len(icmp) >= 4 and ICMPv6.checksum(src, dst, icmp) == 0

    @staticmethod
    def _set_checksum(icmp: bytearray, src: bytes, dst: bytes) -> bytes:
        c = ICMPv6.checksum(src, dst, bytes(icmp))
        icmp[2] = c >> 8
        icmp[3] = c & 0xFF
        return bytes(icmp)

    @staticmethod
    def router_solicitation(srcMAC: MAC, srcIP: bytes) -> bytes:
        icmp = bytearray(bytes([133, 0, 0, 0, 0, 0, 0, 0]) + bytes([1, 1]) + srcMAC)
        dst_ip = bytes([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])  # all-routers
        return ICMPv6._set_checksum(icmp, srcIP, dst_ip)

    @staticmethod
    def neighbor_solicitation(targetIP: bytes, srcMAC: MAC, srcIP: bytes, dstIP: bytes) -> bytes:
        icmp = bytearray(bytes([135, 0, 0, 0, 0, 0, 0, 0]) + targetIP)
        if any(srcIP):  # the source link-layer option is left out for the unspecified source (DAD)
            icmp += bytes([1, 1]) + srcMAC
        return ICMPv6._set_checksum(icmp, srcIP, dstIP)

    @staticmethod
    def neighbor_advertisement(targetIP: bytes, targetMAC: MAC, srcIP: bytes, dstIP: bytes,
                               solicited: bool = True) -> bytes:
        # Flags: Solicited (0x40) | Override (0x20), 3 reserved bytes.
        icmp = bytearray(bytes([136, 0, 0, 0, 0x60 if solicited else 0x20, 0, 0, 0]) + targetIP)
        icmp += bytes([2, 1]) + targetMAC  # Option 2: Target Link-Layer Address
        return ICMPv6._set_checksum(icmp, srcIP, dstIP)