"""SHA-0 and RC4 against standard vectors."""

import unittest

from vpngate.core.rc4 import RC4
from vpngate.core.sha0 import hash as sha0


class SHA0Tests(unittest.TestCase):
    def test_standard_vector(self):
        # FIPS PUB 180 SHA-0 vector: "abc" -> 0164b8a914cd2a5e74c4f7ff082c4d97f1edf880
        self.assertEqual(sha0(b"abc").hex(), "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880")

    def test_digest_length(self):
        self.assertEqual(len(sha0(b"")), 20)

    def test_differs_from_sha1(self):
        import hashlib
        self.assertNotEqual(sha0(b"abc"), hashlib.sha1(b"abc").digest())

    def test_long_input(self):
        data = b"x" * 1000
        self.assertEqual(len(sha0(data)), 20)
        # Deterministic
        self.assertEqual(sha0(data), sha0(data))


class RC4Tests(unittest.TestCase):
    def test_standard_vector(self):
        # RC4 key "Key", plaintext "Plaintext" -> BBF316E8D940AF0AD3
        self.assertEqual(RC4.cipher(b"Key", b"Plaintext").hex(), "bbf316e8d940af0ad3")

    def test_symmetric(self):
        data = bytes(range(256))
        self.assertEqual(RC4.cipher(b"secret", RC4.cipher(b"secret", data)), data)

    def test_stream_keystate(self):
        rc4 = RC4(b"key")
        a = rc4.process(b"AAAA")
        b = rc4.process(b"BBBB")
        self.assertNotEqual(RC4.cipher(b"key", b"BBBB"), b)


if __name__ == "__main__":
    unittest.main()
