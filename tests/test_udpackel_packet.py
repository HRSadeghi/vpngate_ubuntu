"""UDP acceleration packet encoding/decoding, including the pure-Python ChaCha fallback."""

import os
import unittest

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from vpngate.core.chacha_fallback import PureChaCha20Poly1305
from vpngate.core.stream import StreamError
from vpngate.core.udpackelpacket import (IV_SIZE, MAC_SIZE, MIN_PACKET_SIZE, decode, encode,
                                         padding_size)


class ChaChaFallbackTests(unittest.TestCase):
    def test_rfc8439_vector(self):
        # RFC 8439 §2.8.2 test vector
        key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = ("Ladies and Gentlemen of the class of '99: If I could offer you "
                     "only one tip for the future, sunscreen would be it.").encode()
        expected_ct = bytes.fromhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116")[:114]  # 114-byte plaintext
        expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
        sealed = PureChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
        self.assertEqual(sealed, expected_ct + expected_tag)
        # And against the reference implementation
        self.assertEqual(sealed, ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad))


class UdpAccelPacketTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.iv = bytes.fromhex("00112233445566778899aabb")

    def test_round_trip(self):
        payload = b"hello frame data" * 3
        packet, next_iv = encode(self.key, self.iv, cookie=0x1234, my_tick=42, your_tick=7,
                                 compressed=False, payload=payload)
        self.assertEqual(len(packet), IV_SIZE + 23 + len(payload) + MAC_SIZE)
        decoded = decode(packet, self.key)
        self.assertEqual(decoded.payload, payload)
        self.assertEqual(decoded.header.cookie, 0x1234)
        self.assertEqual(decoded.header.my_tick, 42)
        self.assertEqual(decoded.header.your_tick, 7)
        self.assertFalse(decoded.header.compressed)
        # Next IV is the last 12 bytes of ciphertext (before the tag).
        self.assertEqual(next_iv, packet[-(MAC_SIZE + IV_SIZE):-MAC_SIZE])

    def test_compressed_flag(self):
        packet, _ = encode(self.key, self.iv, 1, 1, 1, compressed=True, payload=b"data")
        self.assertTrue(decode(packet, self.key).header.compressed)

    def test_tick_zero_becomes_one(self):
        packet, _ = encode(self.key, self.iv, 1, 0, 0, False, b"")
        self.assertEqual(decode(packet, self.key).header.my_tick, 1)

    def test_plain_mode(self):
        packet, next_iv = encode(self.key, self.iv, 5, 6, 7, False, b"plain", plain_mode=True)
        self.assertEqual(packet[:4], (5).to_bytes(4, "big"))
        decoded = decode(packet, b"", plain_mode=True)
        self.assertEqual(decoded.payload, b"plain")
        self.assertEqual(next_iv, self.iv)

    def test_tamper_rejected(self):
        packet, _ = encode(self.key, self.iv, 1, 1, 1, False, b"secret")
        bad = bytearray(packet)
        bad[-1] ^= 0xFF
        with self.assertRaises(StreamError):
            decode(bytes(bad), self.key)

    def test_wrong_key_rejected(self):
        packet, _ = encode(self.key, self.iv, 1, 1, 1, False, b"secret")
        with self.assertRaises(StreamError):
            decode(packet, bytes(range(32, 64)))

    def test_too_short_rejected(self):
        with self.assertRaises(StreamError):
            decode(b"\x00" * 10, self.key)

    def test_padding_bounds(self):
        # Packet smaller than maxSize gets random padding below 32.
        pad = padding_size(data_size=10, max_size=2000, random=lambda n: n - 1)
        self.assertTrue(0 <= pad < 32)
        # Packet already at maxSize: no padding.
        self.assertEqual(padding_size(data_size=2000, max_size=2000, random=lambda n: 5), 0)


if __name__ == "__main__":
    unittest.main()
