"""Data-phase framing, HTTP head, byte buffer."""

import unittest

from vpngate.core.bytebuffer import ByteBuffer
from vpngate.core.datphase import (DataPhaseDecoder, DataPhaseError, encode_frames,
                                   encode_keep_alive)
from vpngate.core.httphead import HTTPHead


class ByteBufferTests(unittest.TestCase):
    def test_take(self):
        buf = ByteBuffer()
        buf.append(b"hello world")
        self.assertEqual(buf.take(5), b"hello")
        self.assertEqual(buf.count, 6)
        self.assertIsNone(buf.take(100))
        self.assertEqual(buf.take_all(), b" world")

    def test_take_up_to(self):
        buf = ByteBuffer()
        buf.append(b"GET / HTTP/1.1\r\n\r\nrest")
        head = buf.take_up_to(b"\r\n\r\n")
        self.assertEqual(head, b"GET / HTTP/1.1")
        self.assertEqual(buf.take_all(), b"rest")
        self.assertIsNone(ByteBuffer().take_up_to(b"\r\n\r\n"))

    def test_incremental(self):
        buf = ByteBuffer()
        buf.append(b"abc")
        buf.append(b"def")
        self.assertEqual(buf.take(6), b"abcdef")


class DataPhaseTests(unittest.TestCase):
    def test_encode_parse_round_trip(self):
        frames = [b"a" * 10, b"b" * 20, bytes(range(256))]
        decoder = DataPhaseDecoder()
        items = decoder.feed(encode_frames(frames))
        self.assertEqual([i.payload for i in items if i.kind == "frame"], frames)

    def test_chunked_feed(self):
        frames = [b"x" * 3000, b"y" * 100]
        blob = encode_frames(frames)
        decoder = DataPhaseDecoder()
        out = []
        for i in range(0, len(blob), 3):
            out += decoder.feed(blob[i:i + 3])
        self.assertEqual([i.payload for i in out if i.kind == "frame"], frames)

    def test_keep_alive(self):
        decoder = DataPhaseDecoder()
        items = decoder.feed(encode_keep_alive(b"junk" * 10))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].kind, "keepAlive")

    def test_empty_batch_is_skipped(self):
        decoder = DataPhaseDecoder()
        self.assertEqual(decoder.feed(b"\x00\x00\x00\x00"), [])

    def test_compressed_round_trip(self):
        frame = b"z" * 2000
        decoder = DataPhaseDecoder(use_compress=True)
        items = decoder.feed(encode_frames([frame], use_compress=True))
        self.assertEqual(items[0].payload, frame)

    def test_bad_block_count(self):
        decoder = DataPhaseDecoder()
        with self.assertRaises(DataPhaseError):
            decoder.feed((4096).to_bytes(4, "big"))

    def test_oversized_block(self):
        decoder = DataPhaseDecoder()
        decoder.feed((1).to_bytes(4, "big"))
        with self.assertRaises(DataPhaseError):
            decoder.feed((3201).to_bytes(4, "big"))

    def test_bad_keep_alive(self):
        decoder = DataPhaseDecoder()
        decoder.feed(b"\xff\xff\xff\xff")
        with self.assertRaises(DataPhaseError):
            decoder.feed((4096).to_bytes(4, "big"))

    def test_partial_keeps_state(self):
        decoder = DataPhaseDecoder()
        blob = encode_frames([b"hello"])
        self.assertEqual(decoder.feed(blob[:2]), [])
        items = decoder.feed(blob[2:])
        self.assertEqual(items[0].payload, b"hello")


class HTTPHeadTests(unittest.TestCase):
    def test_parse(self):
        head = HTTPHead.parse(b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\nX-Weird: spaced\r\n")
        self.assertEqual(head.status_code, 200)
        self.assertEqual(head.headers["content-length"], "42")
        self.assertEqual(head.headers["x-weird"], "spaced")

    def test_status_code_optional(self):
        self.assertIsNone(HTTPHead.parse(b"garbage\r\n").status_code)
        self.assertEqual(HTTPHead.parse(b"HTTP/1.1 404 Not Found\r\n\r\n").status_code, 404)


if __name__ == "__main__":
    unittest.main()
