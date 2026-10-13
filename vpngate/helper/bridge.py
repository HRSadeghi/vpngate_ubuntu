"""Userspace L2 stack: lets an L3 tun device talk to SoftEther's L2 virtual hub (port of
EthernetBridge.swift). Implements a DHCP client, ARP responder/resolver, IPv6 NDP and framing."""

from __future__ import annotations

import asyncio
import random
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..core.packets import (ARPPacket, DHCPMessage, DHCPType, Ethernet, ICMPv6, IPv4, IPv6,
                            UDP, be32, broadcastMAC, ip_string, rd16, rd32)
from ..core.stream import StreamError, protocol_error


@dataclass
class Lease:
    ip: int
    mask: int
    router: int
    dns: list[int] = field(default_factory=list)
    seconds: int = 0
    serverID: int = 0
    mtu: int | None = None


@dataclass
class BridgeTiming:
    dhcp_timeout: float = 4
    dhcp_retries: int = 6
    arp_ttl: float = 60          # ARP cache entries older than this are re-resolved
    arp_retry_interval: float = 1
    arp_queue_max_age: float = 3
    arp_max_queued: int = 64
    rs_interval: float = 4       # Router Solicitations repeat (interval doubling) until an RA
    rs_max_interval: float = 64
    rs_retries: int = 8


@dataclass
class _ARPEntry:
    mac: bytes
    at: float


@dataclass
class _V6Prefix:
    prefix: bytes
    on_link: bool
    autonomous: bool
    valid_until: float


@dataclass
class _V6Router:
    address: bytes
    until: float


@dataclass
class _Pending:
    packets: list = field(default_factory=list)   # list[(pkt, at)]
    last_request: float | None = None


class EthernetBridge:
    def __init__(self, timing: BridgeTiming | None = None, fixed_mac: bytes | None = None) -> None:
        self.timing = timing or BridgeTiming()
        m = bytearray(random.randbytes(6))
        m[0] = 0x5E
        m[1] = 0x00 | (m[1] & 0xFE)   # locally-administered-style prefix like SoftEther (5E:xx), unicast
        self.mac = bytes(fixed_mac) if fixed_mac else bytes(m)
        self.lease: Lease | None = None
        self.arp_cache: dict[int, _ARPEntry] = {}
        self.waiting: dict[int, _Pending] = {}
        self.last_dhcp: DHCPMessage | None = None
        self._xid = random.randint(1, 0xFFFFFFFF)
        self.send_frame = None        # to hub
        self.deliver_ipv4 = None      # to tun
        self.deliver_ipv6 = None      # to tun
        self.on_lease_changed = None  # renew returned different parameters
        self.on_lease_lost = None     # renew got no answer or a NAK
        self.handle_ipv6 = True
        self._v6_prefix: _V6Prefix | None = None
        self._v6_router: _V6Router | None = None
        self._ra_seen = False
        self._announced_v6: bytes | None = None
        self._on_ipv6_address = None
        self._nd6_cache: dict[bytes, _ARPEntry] = {}
        self._waiting6: dict[bytes, _Pending] = {}
        self._ipv6_task: asyncio.Task | None = None
        # from_hub runs on the loop, from_host on the TUN reader thread: shared state is locked
        # (the Swift original guards the same fields with an NSLock).
        self._lock = threading.RLock()

    # MARK: DHCP

    def _new_xid(self) -> int:
        with self._lock:
            self._xid = random.randint(1, 0xFFFFFFFF)
            self.last_dhcp = None
            return self._xid

    async def acquire_lease(self) -> Lease:
        for _ in range(self.timing.dhcp_retries):
            x = self._new_xid()
            self._send_dhcp(DHCPMessage(DHCPType.discover, x, self.mac))
            offer = await self._wait_dhcp([DHCPType.offer], self.timing.dhcp_timeout)
            if offer is None:
                continue
            req = DHCPMessage(DHCPType.request, x, self.mac)
            req.requestedIP = offer.yiaddr
            req.serverID = offer.serverID
            self.last_dhcp = None
            self._send_dhcp(req)
            reply = await self._wait_dhcp([DHCPType.ack, DHCPType.nak], self.timing.dhcp_timeout)
            if reply is None:
                continue
            if reply.type == DHCPType.nak:
                continue  # start over immediately
            lease = Lease(
                ip=reply.yiaddr,
                mask=reply.subnetMask if reply.subnetMask is not None else 0xFFFFFF00,
                router=reply.router if reply.router is not None else (offer.router or 0),
                dns=reply.dns or offer.dns,
                seconds=reply.leaseSeconds if reply.leaseSeconds is not None else 3600,
                serverID=(reply.serverID if reply.serverID is not None else (offer.serverID or 0)),
                mtu=reply.mtu if reply.mtu is not None else offer.mtu,
            )
            with self._lock:
                self.lease = lease
            return lease
        raise protocol_error("DHCP failed: no lease from the VPN server")

    async def renew(self) -> None:
        """Renews the current lease (RFC 2131 §4.3.2 RENEWING: ciaddr set, no requested-ip/server-id)."""
        with self._lock:
            l = self.lease
        if l is None:
            return
        x = self._new_xid()
        req = DHCPMessage(DHCPType.request, x, self.mac)
        req.ciaddr = l.ip
        self._send_dhcp(req)
        reply = await self._wait_dhcp([DHCPType.ack, DHCPType.nak], self.timing.dhcp_timeout)
        if reply is None or reply.type != DHCPType.ack:
            cb = self.on_lease_lost
            if cb:
                cb()
            return
        n = Lease(ip=reply.yiaddr, mask=l.mask, router=l.router, dns=l.dns,
                  seconds=l.seconds, serverID=l.serverID, mtu=l.mtu)
        n.mask = reply.subnetMask if reply.subnetMask is not None else l.mask
        n.router = reply.router if reply.router is not None else l.router
        n.seconds = reply.leaseSeconds if reply.leaseSeconds is not None else l.seconds
        if reply.dns:
            n.dns = reply.dns
        changed = n.ip != l.ip or n.router != l.router or n.mask != l.mask
        with self._lock:
            self.lease = n
        if changed and self.on_lease_changed:
            self.on_lease_changed(n)

    async def _wait_dhcp(self, types: list[DHCPType], seconds: float) -> DHCPMessage | None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            m = self.last_dhcp
            if m is not None and m.type in types:
                return m
            await asyncio.sleep(0.01)
        return None

    def _send_dhcp(self, m: DHCPMessage) -> None:
        udp = UDP.datagram(src=m.ciaddr, dst=0xFFFFFFFF, sport=68, dport=67, payload=m.encode())
        ip = IPv4.packet(proto=17, src=m.ciaddr, dst=0xFFFFFFFF, payload=udp)
        if self.send_frame:
            self.send_frame(Ethernet.frame(dst=broadcastMAC, src=self.mac, ethertype=0x0800, payload=ip))

    # MARK: hub -> host

    def from_hub(self, f: bytes) -> None:
        if len(f) < 14:
            return
        dst = f[0:6]
        ethertype = rd16(f, 12)
        payload = f[14:]
        for_us = dst == self.mac or dst == broadcastMAC or (dst[0] & 1) == 1
        if ethertype == 0x0806:
            a = ARPPacket.parse(payload)
            if a is None:
                return
            t = time.monotonic()
            queued: list = []
            with self._lock:
                if a.senderIP != 0:
                    self.arp_cache[a.senderIP] = _ARPEntry(a.senderMAC, t)
                    pending = self.waiting.pop(a.senderIP, None)
                    queued = pending.packets if pending else []
                my_ip = self.lease.ip if self.lease else None
            if a.op == 1 and my_ip is not None and a.targetIP == my_ip:
                r = ARPPacket(2, self.mac, my_ip, a.senderMAC, a.senderIP)
                if self.send_frame:
                    self.send_frame(Ethernet.frame(dst=a.senderMAC, src=self.mac,
                                                   ethertype=0x0806, payload=r.encode()))
            # Flush in order, but never send packets that have been waiting too long.
            for q, at in queued:
                if t - at <= self.timing.arp_queue_max_age:
                    self.from_host(q)
        elif ethertype == 0x0800:
            if not for_us:
                return
            ip = IPv4.parse(payload)
            if ip is None:
                return
            proto, _src, _dst, ip_payload = ip
            if proto == 17:
                u = UDP.parse(ip_payload)
                if u is not None and u[1] == 68:
                    m = DHCPMessage.parse(u[2])
                    if m is not None:
                        with self._lock:
                            if m.xid == self._xid:
                                self.last_dhcp = m
                        return
            with self._lock:
                have_lease = self.lease is not None
            if have_lease and self.deliver_ipv4:
                self.deliver_ipv4(payload)
        elif ethertype == 0x86DD:
            if not self.handle_ipv6 or not for_us:
                return
            v6 = IPv6.parse(payload)
            if v6 is None:
                return
            next_header, src, dst_ip, icmp = v6
            if next_header == 58 and len(icmp) >= 4 and 133 <= icmp[0] <= 137:
                # Neighbour Discovery is answered here, never handed to the kernel (which would
                # otherwise act on RAs and configure the tun a second time).
                self._handle_ndp(v6, payload[7], f[6:12])
                return
            if self.deliver_ipv6:
                self.deliver_ipv6(payload)

    # MARK: host -> hub

    def from_host(self, pkt: bytes) -> None:
        if not pkt:
            return
        version = pkt[0] >> 4
        if version == 6:
            self._from_host_ipv6(pkt)
            return
        with self._lock:
            l = self.lease
        if l is None or len(pkt) < 20:
            return
        t = time.monotonic()
        dst = rd32(pkt, 16)
        next_hop = dst
        on_link = (dst & l.mask) == (l.ip & l.mask)
        if not on_link:
            next_hop = l.router
        is_broadcast = (dst == 0xFFFFFFFF or (on_link and (dst | (~l.mask & 0xFFFFFFFF)) == dst)
                        or (dst >> 28) == 0xE)
        target: bytes | None
        send_request = False
        with self._lock:
            if is_broadcast:
                target = broadcastMAC
            else:
                e = self.arp_cache.get(next_hop)
                if e is not None and t - e.at <= self.timing.arp_ttl:
                    target = e.mac
                else:
                    self.arp_cache.pop(next_hop, None)
                    target = None
            if target is None:
                p = self.waiting.get(next_hop) or _Pending()
                p.packets = [(q, at) for q, at in p.packets
                             if t - at <= self.timing.arp_queue_max_age]
                if len(p.packets) < self.timing.arp_max_queued:
                    p.packets.append((pkt, t))
                if p.last_request is None or t - p.last_request >= self.timing.arp_retry_interval:
                    p.last_request = t
                    send_request = True
                self.waiting[next_hop] = p

        if target is not None:
            if self.send_frame:
                self.send_frame(Ethernet.frame(dst=target, src=self.mac, ethertype=0x0800, payload=pkt))
        elif send_request:
            req = ARPPacket(1, self.mac, l.ip, bytes(6), next_hop)
            if self.send_frame:
                self.send_frame(Ethernet.frame(dst=broadcastMAC, src=self.mac, ethertype=0x0806,
                                               payload=req.encode()))

    def _from_host_ipv6(self, pkt: bytes) -> None:
        if not self.handle_ipv6 or len(pkt) < 40:
            return
        v6 = IPv6.parse(pkt)
        if v6 is None:
            return
        _nh, _src, dst, _payload = v6
        if dst[0] == 0xFF:  # multicast
            if self.send_frame:
                self.send_frame(Ethernet.frame(dst=IPv6.multicast_mac(dst), src=self.mac,
                                               ethertype=0x86DD, payload=pkt))
            return
        t = time.monotonic()
        # Link-local and on-link destinations are resolved directly; everything else goes to the router.
        next_hop = dst
        target: bytes | None = None
        send_request = False
        with self._lock:
            on_link = IPv6.is_link_local(dst) or (
                self._v6_prefix is not None and self._v6_prefix.on_link
                and t < self._v6_prefix.valid_until
                and dst[0:8] == self._v6_prefix.prefix[0:8])
            if not on_link:
                r = self._v6_router
                if r is None or t >= r.until:
                    return  # no IPv6 router: nothing to send to
                next_hop = r.address
            e = self._nd6_cache.get(next_hop)
            if e is not None and t - e.at <= self.timing.arp_ttl:
                target = e.mac
            else:
                self._nd6_cache.pop(next_hop, None)
            if target is None:
                if next_hop not in self._waiting6 and len(self._waiting6) >= self.timing.arp_max_queued:
                    return
                p = self._waiting6.get(next_hop) or _Pending()
                p.packets = [(q, at) for q, at in p.packets
                             if t - at <= self.timing.arp_queue_max_age]
                if len(p.packets) < self.timing.arp_max_queued:
                    p.packets.append((pkt, t))
                if p.last_request is None or t - p.last_request >= self.timing.arp_retry_interval:
                    p.last_request = t
                    send_request = True
                self._waiting6[next_hop] = p

        if target is not None:
            if self.send_frame:
                self.send_frame(Ethernet.frame(dst=target, src=self.mac, ethertype=0x86DD, payload=pkt))
        elif send_request:
            src_ip = IPv6.link_local(self.mac)
            dst_ip = IPv6.solicited_node_multicast(next_hop)
            ns = ICMPv6.neighbor_solicitation(next_hop, self.mac, src_ip, dst_ip)
            if self.send_frame:
                self.send_frame(Ethernet.frame(
                    dst=IPv6.multicast_mac(dst_ip), src=self.mac, ethertype=0x86DD,
                    payload=IPv6.ndp_packet(src_ip, dst_ip, ns)))

    # MARK: IPv6 neighbour discovery

    def start_ipv6(self, on_address) -> None:
        """Reports the SLAAC address (once, as soon as an RA provides a usable prefix) and sends
        Router Solicitations with backoff until some router answers."""
        if not self.handle_ipv6:
            return
        self._on_ipv6_address = on_address
        if self._announced_v6 is not None:
            on_address(self._announced_v6, 64)
        self._ipv6_task = asyncio.get_running_loop().create_task(self._solicit_loop())

    async def _solicit_loop(self) -> None:
        wait = self.timing.rs_interval
        for _ in range(self.timing.rs_retries):
            if not self._solicit_router_if_needed():
                return
            await asyncio.sleep(wait)
            wait = min(wait * 2, self.timing.rs_max_interval)

    def _solicit_router_if_needed(self) -> bool:
        with self._lock:
            seen = self._ra_seen
        if seen or not self.handle_ipv6:
            return False
        src = IPv6.link_local(self.mac)
        all_routers = bytes([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2])
        rs = ICMPv6.router_solicitation(self.mac, src)
        if self.send_frame:
            self.send_frame(Ethernet.frame(dst=IPv6.multicast_mac(all_routers), src=self.mac,
                                           ethertype=0x86DD,
                                           payload=IPv6.ndp_packet(src, all_routers, rs)))
        return True

    def _slaac_address(self, t: float) -> bytes | None:
        p = self._v6_prefix
        if p is None or not p.autonomous or t >= p.valid_until:
            return None
        return IPv6.slaac(p.prefix, self.mac)

    def _learn6(self, ip: bytes, m: bytes, t: float) -> list:
        self._nd6_cache[ip] = _ARPEntry(m, t)
        pending = self._waiting6.pop(ip, None)
        return pending.packets if pending else []

    def _flush6(self, queued: list, t: float) -> None:
        for q, at in queued:
            if t - at <= self.timing.arp_queue_max_age:
                self._from_host_ipv6(q)

    def _ndp_option(self, icmp: bytes, start: int, opt_type: int) -> bytes | None:
        """Option of `type` (RFC 4861 §4.6) in an NDP message whose options start at `start`."""
        i = start
        while i + 8 <= len(icmp):
            ln = icmp[i + 1] * 8
            if ln == 0 or i + ln > len(icmp):
                return None
            if icmp[i] == opt_type:
                return icmp[i + 2:i + ln]
            i += ln
        return None

    def _handle_ndp(self, v6, hop_limit: int, srcMAC: bytes) -> None:
        _nh, src, dst, icmp = v6
        # RFC 4861 §7.1/§6.1: hop limit 255 (never forwarded by a router), code 0, valid checksum.
        if hop_limit != 255 or icmp[1] != 0 or not ICMPv6.is_checksum_valid(src, dst, icmp):
            return
        t = time.monotonic()
        if icmp[0] == 135 and len(icmp) >= 24:      # Neighbor Solicitation
            target = icmp[8:24]
            if target[0] == 0xFF:
                return
            probe = all(b == 0 for b in src)         # DAD probe from ::
            if dst != IPv6.solicited_node_multicast(target) and not (not probe and dst == target):
                return
            slla = None if probe else self._ndp_option(icmp, 24, 1)
            own = [IPv6.link_local(self.mac)]
            with self._lock:
                queued = []
                if slla is not None and len(slla) == 6:
                    queued = self._learn6(src, slla, t)
                slaac = self._slaac_address(t)
                if slaac is not None:
                    own.append(slaac)
            self._flush6(queued, t)
            if target not in own:
                return
            # Answer from the solicited address to the asker's own MAC; a DAD probe has no one to
            # unicast to, so the answer goes to all nodes with S clear.
            all_nodes = bytes([0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
            dst_ip = all_nodes if probe else src
            na = ICMPv6.neighbor_advertisement(target, self.mac, target, dst_ip, solicited=not probe)
            out_dst = IPv6.multicast_mac(all_nodes) if probe else srcMAC
            if self.send_frame:
                self.send_frame(Ethernet.frame(dst=out_dst, src=self.mac, ethertype=0x86DD,
                                               payload=IPv6.ndp_packet(target, dst_ip, na)))
        elif icmp[0] == 136 and len(icmp) >= 24:    # Neighbor Advertisement
            target = icmp[8:24]
            if target[0] == 0xFF:
                return
            tlla = self._ndp_option(icmp, 24, 2)
            m = tlla if tlla is not None and len(tlla) == 6 else srcMAC
            # Only resolutions we asked for (or refreshes of known entries) are accepted.
            with self._lock:
                if target in self._waiting6 or target in self._nd6_cache:
                    queued = self._learn6(target, m, t)
                else:
                    queued = []
            self._flush6(queued, t)
        elif icmp[0] == 134 and len(icmp) >= 16:    # Router Advertisement
            if not IPv6.is_link_local(src):
                return
            self._handle_router_advertisement(src, icmp, srcMAC, t)

    def _handle_router_advertisement(self, router: bytes, icmp: bytes, srcMAC: bytes, t: float) -> None:
        def until(seconds: int) -> float:
            return t + seconds if seconds != 0xFFFFFFFF else float("inf")

        router_lifetime = rd16(icmp, 6)
        slla = self._ndp_option(icmp, 16, 1)
        candidate: _V6Prefix | None = None
        i = 16
        while i + 8 <= len(icmp):
            ln = icmp[i + 1] * 8
            if ln == 0 or i + ln > len(icmp):
                break
            if icmp[i] == 3 and ln >= 32 and candidate is None and icmp[i + 2] == 64:
                # Prefix Information, /64 only
                flags = icmp[i + 3]
                valid = rd32(icmp, i + 4)
                preferred = rd32(icmp, i + 8)
                prefix = icmp[i + 16:i + 32]
                # RFC 4862 §5.5.3: preferred must not exceed valid; link-local prefixes are ignored.
                if (valid > 0 and preferred <= valid and not IPv6.is_link_local(prefix)
                        and prefix[0] != 0xFF and flags & 0xC0 != 0):
                    candidate = _V6Prefix(prefix, flags & 0x80 != 0, flags & 0x40 != 0, until(valid))
            i += ln
        with self._lock:
            self._ra_seen = True
            queued: list = []
            if router_lifetime == 0:
                if self._v6_router is not None and self._v6_router.address == router:
                    self._v6_router = None
            else:
                self._v6_router = _V6Router(router, until(router_lifetime))
                m = slla if slla is not None and len(slla) == 6 else srcMAC
                queued = self._learn6(router, m, t)
            # One prefix per link: later RAs refresh it; a different prefix replaces it after expiry.
            if candidate is not None:
                cur = self._v6_prefix
                if cur is None or cur.prefix[0:8] == candidate.prefix[0:8] or t >= cur.valid_until:
                    self._v6_prefix = candidate
            announce = None
            a = self._slaac_address(t)
            if a is not None and self._announced_v6 != a:
                self._announced_v6 = a
                announce = (a, self._on_ipv6_address)
        self._flush6(queued, t)
        if announce is not None and announce[1] is not None:
            announce[1](announce[0], 64)

    def gratuitous_arp(self) -> None:
        """Announce ourselves so the hub learns our MAC/IP."""
        l = self.lease
        if l is None:
            return
        a = ARPPacket(1, self.mac, l.ip, bytes(6), l.ip)
        if self.send_frame:
            self.send_frame(Ethernet.frame(dst=broadcastMAC, src=self.mac, ethertype=0x0806,
                                           payload=a.encode()))

    # Read-only introspection used by the session
    @property
    def ipv6_prefix(self) -> bytes | None:
        return self._v6_prefix.prefix if self._v6_prefix else None

    @property
    def router_ipv6(self) -> bytes | None:
        return self._v6_router.address if self._v6_router else None

    @property
    def ipv6_address(self) -> bytes | None:
        return self._slaac_address(time.monotonic())