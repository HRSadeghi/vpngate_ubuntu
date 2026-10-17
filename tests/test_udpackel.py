"""UDP acceleration: the data plane must be proven before it carries data.

Keep-alives are tiny and routinely pass where large data datagrams are dropped (DPI/MTU);
a "stable receive period" of control packets proves nothing. Acceleration starts only
after real data has arrived over UDP, and one-way-broken paths fall back to TCP.
"""

import unittest

from vpngate.helper.udpackel import UdpAccel
from vpngate.core.udpackelpacket import encode


def make_accel(clock):
    accel = UdpAccel(my_key_v2=bytes(range(32)), clock=clock)
    assert accel.configure(server_ip="9.9.9.9", server_port=5555, my_cookie=0x11111111,
                           your_cookie=0x22222222, your_key_v2=bytes(range(64, 96)),
                           fast_disconnect=False)
    # No start(): the receive loop and keep-alive task are not needed here — the tests
    # drive handle_datagram and the send path directly.
    return accel


def stabilise(accel, clock, server_key, echo_tick_source):
    """Client sends a keep-alive, then the peer sends 12 s of echoing keep-alives — the
    first of which carries a real data payload (the data-plane proof)."""
    accel._send_packet(compressed=False, payload=b"", max_size=1000)
    for i in range(12):
        packet, _ = encode(server_key, bytes(range(12)), cookie=0x11111111,
                           my_tick=clock(), your_tick=echo_tick_source(),
                           compressed=False, payload=b"data" if i == 0 else b"")
        accel.handle_datagram(packet, ("9.9.9.9", 5555))
        clock.advance(1000)


def run_broken_seconds(accel, clock, server_key, frozen_echo, seconds=30):
    """The keep-alive task keeps sending (as in real operation) while none of our datagrams
    reach the peer: the peer's echo stays frozen while our last-sent tick keeps advancing."""
    for _ in range(seconds):
        accel._send_packet(compressed=False, payload=b"", max_size=1000)
        packet, _ = encode(server_key, bytes(range(12)), cookie=0x11111111,
                           my_tick=clock(), your_tick=frozen_echo,
                           compressed=False, payload=b"")
        accel.handle_datagram(packet, ("9.9.9.9", 5555))
        clock.advance(1000)


class FakeClock:
    def __init__(self) -> None:
        self.ms = 1_000_000

    def __call__(self) -> int:
        return self.ms

    def advance(self, ms: int) -> None:
        self.ms += ms


class OneWayPathTests(unittest.TestCase):
    def test_keepalives_alone_are_not_usable(self):
        """Regression: control packets alone made the tunnel one-way (out over UDP, back
        over TCP) while the log claimed USABLE — large data datagrams were being dropped."""
        clock = FakeClock()
        accel = make_accel(clock)
        self.assertFalse(accel.is_usable)

        # The peer sends keep-alives for > 10 s (stable receive), echoing OUR latest tick.
        accel._send_packet(compressed=False, payload=b"", max_size=1000)
        for _ in range(12):
            packet, _ = encode(bytes(range(64, 96)), bytes(range(12)), cookie=0x11111111,
                               my_tick=clock(), your_tick=accel.last_sent_tick,
                               compressed=False, payload=b"")
            accel.handle_datagram(packet, ("9.9.9.9", 5555))
            clock.advance(1000)
        self.assertFalse(accel.is_usable,
                         "keep-alives alone must never enable the UDP data path")
        self.assertEqual(accel.data_bytes_in, 0)

    def test_usable_when_data_and_echo_keep_up(self):
        clock = FakeClock()
        accel = make_accel(clock)
        self.assertFalse(accel.is_usable)

        # The peer sends data + keep-alives for > 10 s, echoing OUR latest tick.
        stabilise(accel, clock, bytes(range(64, 96)), lambda: accel.last_sent_tick)
        self.assertGreater(accel.data_bytes_in, 0)
        self.assertTrue(accel.is_usable)

    def test_one_way_broken_falls_back_to_tcp(self):
        clock = FakeClock()
        accel = make_accel(clock)
        server_key = bytes(range(64, 96))

        # Stabilise with echoing keep-alives.
        stabilise(accel, clock, server_key, lambda: accel.last_sent_tick)
        self.assertTrue(accel.is_usable)

        # We start sending data (the tunnel's outbound frames).
        self.assertTrue(accel.send_frame(b"ethernet frame" * 10))
        sent_tick = accel.last_sent_tick
        self.assertGreater(sent_tick, 0)

        # Our datagrams never reach the peer: it keeps sending (we receive, stability holds)
        # but its echo of our tick stays frozen while our sends keep advancing the lag.
        run_broken_seconds(accel, clock, server_key, sent_tick - 5_000)

        self.assertFalse(accel.is_usable,
                         "one-way path must not be considered usable")

    def test_recovers_when_path_heals(self):
        clock = FakeClock()
        accel = make_accel(clock)
        server_key = bytes(range(64, 96))
        stabilise(accel, clock, server_key, lambda: accel.last_sent_tick)
        self.assertTrue(accel.send_frame(b"data"))
        frozen_echo = accel.last_recv_my_tick  # nothing of ours arrives after this
        run_broken_seconds(accel, clock, server_key, frozen_echo)
        self.assertFalse(accel.is_usable)

        # The path heals: the peer's echo catches up to our (frozen) last send and a fresh
        # stable period passes; the keep-alive task has resumed probing both ways.
        last = accel.last_sent_tick
        for _ in range(25):
            accel._send_packet(compressed=False, payload=b"", max_size=1000)
            last = accel.last_sent_tick
            packet, _ = encode(server_key, bytes(range(12)), cookie=0x11111111,
                               my_tick=clock(), your_tick=last,
                               compressed=False, payload=b"")
            accel.handle_datagram(packet, ("9.9.9.9", 5555))
            clock.advance(1000)
        self.assertTrue(accel.is_usable, "healed path must become usable again")

    def test_data_falls_back_to_tcp_immediately_on_break(self):
        clock = FakeClock()
        accel = make_accel(clock)
        server_key = bytes(range(64, 96))
        stabilise(accel, clock, server_key, lambda: accel.last_sent_tick)
        self.assertTrue(accel.send_frame(b"first frame"))
        frozen_echo = accel.last_recv_my_tick
        run_broken_seconds(accel, clock, server_key, frozen_echo)
        # While broken, send_frame must refuse (caller then queues the frame for TCP).
        self.assertFalse(accel.send_frame(b"frame that must ride tcp"))

    def test_keepalives_alone_do_not_trip_the_guard(self):
        """During idle periods only tiny keep-alives flow; the echo naturally lags by the
        keep-alive interval, which must not disable UDP once the data plane is proven."""
        clock = FakeClock()
        accel = make_accel(clock)
        server_key = bytes(range(64, 96))
        stabilise(accel, clock, server_key, lambda: accel.last_sent_tick)
        self.assertTrue(accel.is_usable)
        accel._send_packet(compressed=False, payload=b"", max_size=1000)
        self.assertTrue(accel.last_sent_tick - accel.last_recv_my_tick <= accel.ECHO_LAG_MS)
        self.assertTrue(accel.is_usable)


if __name__ == "__main__":
    unittest.main()