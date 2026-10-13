"""Certificate pinning and error tables."""

import hashlib
import os
import unittest

from vpngate.core.certpin import CertPin, ServerCertPolicy, ServerCertPolicyKind
from vpngate.core.softether_error import describe, info


class CertPinTests(unittest.TestCase):
    def test_sha1(self):
        der = os.urandom(32)
        pin = CertPin(hashlib.sha1(der).hexdigest())
        self.assertTrue(pin.matches(der))
        self.assertFalse(pin.matches(b"other"))

    def test_sha256_with_separators(self):
        der = os.urandom(32)
        digest = hashlib.sha256(der).hexdigest()
        formatted = ":".join(digest[i:i + 2] for i in range(0, 64, 2))
        self.assertTrue(CertPin(formatted.upper()).matches(der))

    def test_invalid(self):
        with self.assertRaises(ValueError):
            CertPin("nothex")
        with self.assertRaises(ValueError):
            CertPin("AB" * 10)  # neither 40 nor 64

    def test_policy_from_config(self):
        der = os.urandom(32)
        pin = ServerCertPolicy.from_config(False, hashlib.sha1(der).hexdigest())
        self.assertEqual(pin.kind, ServerCertPolicyKind.pinned)
        self.assertIsNone(pin.rejection(der))
        self.assertEqual(pin.rejection(b"other"), "Server certificate does not match the pinned "
                                                  "fingerprint")
        self.assertEqual(ServerCertPolicy.from_config(False, None).kind,
                         ServerCertPolicyKind.acceptAny)
        self.assertEqual(ServerCertPolicy.from_config(True, None).kind,
                         ServerCertPolicyKind.systemTrust)
        bad = ServerCertPolicy.from_config(False, "zz")
        self.assertEqual(bad.kind, ServerCertPolicyKind.invalidPin)
        self.assertIsNotNone(bad.rejection(der))
        self.assertIsNone(ServerCertPolicy.from_config(True, None).rejection(der))
        pinned = ServerCertPolicy.from_config(False, hashlib.sha1(der).hexdigest())
        self.assertEqual(pinned.rejection(None),
                         "Server presented no certificate to match the pinned fingerprint")


class SoftEtherErrorTests(unittest.TestCase):
    def test_known(self):
        self.assertEqual(describe(9), "ERR_AUTH_FAILED (9): Authentication failure")
        self.assertEqual(describe(15), "ERR_TOO_MANY_CONNECTION (15): Too many connections")
        entry = info(9)
        self.assertEqual(entry, ("ERR_AUTH_FAILED", "Authentication failure"))

    def test_zero_is_no_error(self):
        self.assertIsNone(info(0))

    def test_unknown(self):
        self.assertEqual(describe(999), "ERR_999 (999): Unknown server error")


if __name__ == "__main__":
    unittest.main()
