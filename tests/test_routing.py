"""Input validation and routing rules."""

import unittest

from vpngate.core.routing import (CIDRMatcher, RoutingAction, RoutingConfig, RoutingMatcher,
                                  RoutingRule, RoutingRuleType, routing_rule_validation_error)
from vpngate.core.validation import (is_ip_literal, is_ipv4_literal, is_local_address,
                                     is_non_public_ipv4, is_valid_host, is_valid_identity_field,
                                     is_valid_port, normalized_fingerprint, parse_mac_address)


class ValidationTests(unittest.TestCase):
    def test_ports(self):
        self.assertTrue(is_valid_port(1) and is_valid_port(65535))
        self.assertFalse(is_valid_port(0))
        self.assertFalse(is_valid_port(65536))
        self.assertFalse(is_valid_port(None))

    def test_ipv4_literal(self):
        self.assertTrue(is_ipv4_literal("1.2.3.4"))
        self.assertTrue(is_ipv4_literal("255.255.255.255"))
        self.assertFalse(is_ipv4_literal("1.2.3"))
        self.assertFalse(is_ipv4_literal("256.1.1.1"))
        self.assertFalse(is_ipv4_literal("1.2.3.4.5"))
        self.assertFalse(is_ipv4_literal("a.b.c.d"))
        self.assertFalse(is_ipv4_literal("1..2.3"))

    def test_host(self):
        self.assertTrue(is_valid_host("vpn.example.com"))
        self.assertTrue(is_valid_host("1.2.3.4"))
        self.assertFalse(is_valid_host(""))
        self.assertFalse(is_valid_host("-leading-dash"))
        self.assertFalse(is_valid_host("1.2.3"))           # malformed dotted number
        self.assertFalse(is_valid_host("trailing."))
        self.assertFalse(is_valid_host("a..b"))
        self.assertFalse(is_valid_host("x" * 254))

    def test_local_and_non_public(self):
        self.assertTrue(is_local_address("127.0.0.1"))
        self.assertTrue(is_local_address("169.254.1.1"))
        self.assertTrue(is_local_address("localhost"))
        self.assertFalse(is_local_address("8.8.8.8"))
        for ip in ("0.0.0.0", "10.0.0.1", "127.4.4.4", "169.254.9.9", "172.16.0.1", "172.31.255.1",
                   "192.168.1.1"):
            self.assertTrue(is_non_public_ipv4(ip), ip)
        for ip in ("8.8.8.8", "172.32.0.1", "192.169.0.1"):
            self.assertFalse(is_non_public_ipv4(ip), ip)

    def test_fingerprint(self):
        fp = "AB" * 20
        self.assertIsNone(normalized_fingerprint("ab:cd:12"))  # neither 40 nor 64 hex digits
        self.assertEqual(normalized_fingerprint(fp.upper()), fp.lower())
        self.assertIsNone(normalized_fingerprint("a b-c"))  # too short even after cleaning
        self.assertIsNone(normalized_fingerprint("AB:CD"))
        self.assertIsNone(normalized_fingerprint("ZZ" * 20))

    def test_mac(self):
        self.assertEqual(parse_mac_address("00:AC:DE:12:34:56"), bytes([0, 0xAC, 0xDE, 0x12, 0x34, 0x56]))
        self.assertEqual(parse_mac_address("aa-bb-cc-dd-ee-ff"), b"\xaa\xbb\xcc\xdd\xee\xff")
        self.assertIsNone(parse_mac_address("00:11:22:33:44"))
        self.assertIsNone(parse_mac_address("zz:11:22:33:44:55"))

    def test_identity_field(self):
        self.assertTrue(is_valid_identity_field("VPNGATE"))
        self.assertTrue(is_valid_identity_field("ü" * 100))
        self.assertFalse(is_valid_identity_field("a\x00b"))
        self.assertFalse(is_valid_identity_field("x" * 256))

    def test_ip_literal(self):
        self.assertTrue(is_ip_literal("1.2.3.4"))
        self.assertTrue(is_ip_literal("::1"))
        self.assertTrue(is_ip_literal("2001:db8::1"))
        self.assertFalse(is_ip_literal("1.2.3.4/24"))
        self.assertFalse(is_ip_literal("example.com"))


class CIDRTests(unittest.TestCase):
    def test_v4(self):
        m = CIDRMatcher("10.0.0.0/8")
        self.assertTrue(m.contains(CIDRMatcher("10.255.255.255")))
        self.assertFalse(m.contains(CIDRMatcher("11.0.0.1")))
        self.assertEqual(CIDRMatcher("1.2.3.4").prefix_length, 32)

    def test_v6(self):
        m = CIDRMatcher("2001:db8::/32")
        self.assertTrue(m.contains(CIDRMatcher("2001:db8::1")))
        self.assertTrue(m.contains(CIDRMatcher("2001:db8:ffff::ffff")))
        self.assertFalse(m.contains(CIDRMatcher("2001:db9::1")))
        self.assertTrue(CIDRMatcher("fe80::/10").contains(CIDRMatcher("fe80::1")))
        self.assertFalse(CIDRMatcher("fe80::/10").contains(CIDRMatcher("fec0::1")))

    def test_compressed_forms(self):
        self.assertEqual(CIDRMatcher("::1").bytes_, bytes(15) + b"\x01")
        self.assertEqual(CIDRMatcher("2001:db8::1").bytes_,
                         bytes.fromhex("20010db8") + bytes(10) + b"\x00\x01")
        self.assertEqual(CIDRMatcher("dead:beef::ab:cd").bytes_[:8],
                         bytes.fromhex("deadbeef00000000"))

    def test_invalid(self):
        for bad in ("", "abc", "1.2.3.4.5", "1.2.3.4/33", "10.0.0.0/x", "::/::", "1.2.3:4",
                    "1.2.3.4/8/8", "12345::"):
            with self.assertRaises(ValueError, msg=bad):
                CIDRMatcher(bad)


class RoutingTests(unittest.TestCase):
    def rule(self, rtype, value, action=RoutingAction.proxy, enabled=True):
        return RoutingRule(type=rtype, value=value, action=action, enabled=enabled)

    def test_domain_rules(self):
        cfg = RoutingConfig(rules=[
            self.rule(RoutingRuleType.domainSuffix, "example.com", RoutingAction.direct),
            self.rule(RoutingRuleType.domainFull, "exact.org", RoutingAction.block),
            self.rule(RoutingRuleType.domainKeyword, "ads", RoutingAction.block),
            self.rule(RoutingRuleType.domainRegex, r"^cn\..*\.net$", RoutingAction.direct),
        ])
        self.assertEqual(RoutingMatcher.match_domain("www.example.com", cfg).action,
                         RoutingAction.direct)
        self.assertEqual(RoutingMatcher.match_domain("example.com", cfg).action,
                         RoutingAction.direct)  # suffix matches the bare domain
        self.assertIsNone(RoutingMatcher.match_domain("notexample.com", cfg))
        self.assertEqual(RoutingMatcher.match_domain("exact.org", cfg).action, RoutingAction.block)
        self.assertEqual(RoutingMatcher.match_domain("ads.example.net", cfg).action, RoutingAction.block)
        self.assertEqual(RoutingMatcher.match_domain("cn.news.net", cfg).action, RoutingAction.direct)
        self.assertIsNone(RoutingMatcher.match_domain("unrelated.org", cfg))

    def test_first_match_wins(self):
        cfg = RoutingConfig(rules=[
            self.rule(RoutingRuleType.domainKeyword, "bad", RoutingAction.block),
            self.rule(RoutingRuleType.domainSuffix, "good.bad", RoutingAction.direct),
        ])
        # "good.bad" contains "bad": the first rule wins.
        self.assertEqual(RoutingMatcher.match_domain("good.bad", cfg).action, RoutingAction.block)

    def test_disabled_rules_skipped(self):
        cfg = RoutingConfig(rules=[
            self.rule(RoutingRuleType.domainSuffix, "example.com", RoutingAction.block, enabled=False),
        ])
        self.assertIsNone(RoutingMatcher.match_domain("example.com", cfg))

    def test_ip_rules(self):
        cfg = RoutingConfig(rules=[
            self.rule(RoutingRuleType.cidr, "10.0.0.0/8", RoutingAction.direct),
            self.rule(RoutingRuleType.ip, "192.168.1.1", RoutingAction.block),
        ])
        self.assertEqual(RoutingMatcher.match_ip("10.1.2.3", cfg).action, RoutingAction.direct)
        self.assertEqual(RoutingMatcher.match_ip("192.168.1.1", cfg).action, RoutingAction.block)
        self.assertIsNone(RoutingMatcher.match_ip("8.8.8.8", cfg))

    def test_private_ranges_appended_last(self):
        cfg = RoutingConfig(rules=[
            self.rule(RoutingRuleType.cidr, "192.168.4.0/24", RoutingAction.block),
        ], bypass_private_networks=True)
        # The explicit user rule wins over the appended direct range.
        self.assertEqual(RoutingMatcher.match_ip("192.168.4.9", cfg).action, RoutingAction.block)
        self.assertEqual(RoutingMatcher.match_ip("192.168.5.9", cfg).action, RoutingAction.direct)
        self.assertEqual(len(cfg.effective_rules), 1 + 9)

    def test_action_fallback(self):
        cfg = RoutingConfig(default_action=RoutingAction.proxy)
        self.assertEqual(RoutingMatcher.action(domain="x.org", ip="1.2.3.4", config=cfg),
                         RoutingAction.proxy)
        direct_cfg = RoutingConfig(default_action=RoutingAction.direct)
        self.assertEqual(RoutingMatcher.action(config=direct_cfg), RoutingAction.direct)

    def test_validation(self):
        self.assertIsNone(routing_rule_validation_error(RoutingRuleType.domainSuffix, "example.com"))
        self.assertIsNotNone(routing_rule_validation_error(RoutingRuleType.domainSuffix, ""))
        self.assertIsNone(routing_rule_validation_error(RoutingRuleType.domainSuffix, "-bad"))
        self.assertIsNotNone(routing_rule_validation_error(RoutingRuleType.domainSuffix, ".bad"))
        self.assertIsNotNone(routing_rule_validation_error(RoutingRuleType.domainSuffix, "bad..name"))
        self.assertIsNotNone(routing_rule_validation_error(RoutingRuleType.domainSuffix, "not valid!"))
        self.assertIsNone(routing_rule_validation_error(RoutingRuleType.domainKeyword, "anything"))
        self.assertIsNone(routing_rule_validation_error(RoutingRuleType.domainRegex, "^a.*b$"))
        self.assertIsNotNone(routing_rule_validation_error(RoutingRuleType.domainRegex, "(["))
        self.assertIsNone(routing_rule_validation_error(RoutingRuleType.ip, "203.0.113.5"))
        self.assertIsNotNone(routing_rule_validation_error(RoutingRuleType.ip, "nope"))
        self.assertIsNone(routing_rule_validation_error(RoutingRuleType.cidr, "10.0.0.0/8"))
        self.assertIsNotNone(routing_rule_validation_error(RoutingRuleType.cidr, "10.0.0.0"))
        self.assertIsNotNone(routing_rule_validation_error(RoutingRuleType.cidr, "10.0.0.0/99"))

    def test_is_empty(self):
        self.assertTrue(RoutingConfig().is_empty)
        self.assertFalse(RoutingConfig(rules=[self.rule(RoutingRuleType.ip, "1.2.3.4")]).is_empty)
        self.assertFalse(RoutingConfig(bypass_private_networks=True).is_empty)
        self.assertFalse(RoutingConfig(default_action=RoutingAction.direct).is_empty)


if __name__ == "__main__":
    unittest.main()
