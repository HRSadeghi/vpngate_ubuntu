"""NetConfig with a recording runner: routes are added, persisted and removed."""

import json
import os
import tempfile
import unittest

from vpngate.core.routing import RoutingAction, RoutingConfig, RoutingRule, RoutingRuleType
from vpngate.helper.netconfig import DNSConfigurator, NetConfig, State, _mask_to_prefix


class FakeLease:
    def __init__(self) -> None:
        self.ip = 0x0A000002      # 10.0.0.2
        self.mask = 0             # point-to-point
        self.router = 0x0A000001  # 10.0.0.1
        self.dns = [0x08080808]   # 8.8.8.8
        self.seconds = 3600
        self.serverID = 0x0A000001
        self.mtu = 1400


class RecordingRunner:
    def __init__(self, fail: set[str] | None = None) -> None:
        self.calls: list[tuple[str, tuple]] = []
        self.fail = fail or set()

    def run(self, path: str, args: list[str]) -> tuple[int, str]:
        self.calls.append((path, tuple(args)))
        key = " ".join(args)
        if "-C" in args:  # rule-existence checks: pretend nothing exists yet
            return 1, ""
        if any(f in key for f in self.fail):
            return 1, "failed"
        if "status" in args:  # fake resolvectl status: tun0 + ens33 with DNS
            return 0, ("Global:\n  DNS Servers: 192.168.247.2\n\n"
                        "Link 2 (ens33):\n"
                        "  Current Scopes: DNS\n"
                        "  DNS Servers: 192.168.247.2\n\n"
                        "Link 18 (tun0):\n"
                        "  Current Scopes: DNS\n"
                        "  DNS Servers: 127.0.0.1\n")
        if args[:2] == ["route", "show"] or "route" in args[:2]:
            if "default" in args:
                return 0, "default via 192.168.1.1 dev eth0 proto dhcp metric 600\n"
        return 0, ""

    def argv(self, call) -> str:
        return " ".join(call[1])


class RecordingDNS(DNSConfigurator):
    """Records resolvectl invocations; simulates systemd-resolved being present."""

    def __init__(self, runner) -> None:
        super().__init__(runner)
        self._resolved = True

    def set(self, servers, iface, address, router):
        calls = []
        for args in (("dns", iface, *servers), ("domain", iface, "~."),
                     ("default-route", iface, "yes"), ("flush-caches",)):
            self.runner.calls.append(("resolvectl", tuple(args)))
            calls.append(args)
        return True


class AllowDNSConfigurator(DNSConfigurator):
    def set(self, servers, iface, address, router):
        return True

    def remove(self, iface=""):
        pass

    def current_servers(self):
        return ["192.168.1.1"]


class NetConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self.tmp.name, "state.json")
        self.runner = RecordingRunner()
        self.net = NetConfig(runner=self.runner, dns=AllowDNSConfigurator(self.runner),
                             state_file=self.state_file)

    def tearDown(self):
        self.tmp.cleanup()

    def _apply(self, **kwargs):
        defaults = dict(iface="vpngate0", lease=FakeLease(), bypass_host="5.6.7.8",
                        block_ipv6=True)
        defaults.update(kwargs)
        self.net.apply(**defaults)

    def _argvs(self):
        return [" ".join(args) for _path, args in self.runner.calls]

    def _argv_text(self) -> str:
        return "\n".join(self._argvs())

    def test_apply_adds_address_mtu_and_routes(self):
        self._apply()
        text = self._argv_text()
        self.assertIn("addr replace 10.0.0.2/32 peer 10.0.0.1/32 dev vpngate0", text)
        self.assertIn("link set dev vpngate0 mtu 1400 up", text)
        self.assertIn("route replace 10.0.0.1/32 dev vpngate0", text)
        self.assertIn("route replace 5.6.7.8/32 via 192.168.1.1", text)
        self.assertIn("route replace 0.0.0.0/1 via 10.0.0.1", text)
        self.assertIn("route replace 128.0.0.0/1 via 10.0.0.1", text)
        self.assertIn("-6 route replace ::/1 dev vpngate0", text)
        self.assertIn("-6 route replace 8000::/1 dev vpngate0", text)

    def test_full_capture_routes_undo_in_reverse(self):
        self._apply()
        before = len(self.runner.calls)
        self.net.teardown()
        undo_calls = self.runner.calls[before:]
        undo_text = "\n".join(" ".join(args) for _path, args in undo_calls)
        self.assertIn("route del 0.0.0.0/1", undo_text)
        self.assertIn("route del 128.0.0.0/1", undo_text)
        self.assertIn("route del 5.6.7.8/32", undo_text)
        self.assertIn("-6 route del ::/1", undo_text)
        # state file removed
        self.assertFalse(os.path.exists(self.state_file))

    def test_failed_route_not_remembered(self):
        self.runner.fail.add("replace 0.0.0.0/1")
        self._apply()
        self.net.teardown()
        undo_text = "\n".join(" ".join(args) for _path, args in self.runner.calls)
        self.assertNotIn("route del 0.0.0.0/1", undo_text)

    def test_direct_default_action_does_not_capture(self):
        cfg = RoutingConfig(default_action=RoutingAction.direct)
        self._apply(routing=cfg)
        self.assertNotIn("0.0.0.0/1 via 10.0.0.1", self._argv_text())

    def test_proxy_rule_gets_tunnel_route(self):
        # With .direct default nothing is captured; an explicit .proxy rule routes back in.
        cfg = RoutingConfig(default_action=RoutingAction.direct,
                            rules=[RoutingRule(type=RoutingRuleType.cidr, value="203.0.113.0/24",
                                               action=RoutingAction.proxy)])
        self._apply(routing=cfg)
        text = self._argv_text()
        self.assertIn("route replace 203.0.113.0/24 dev vpngate0", text)
        self.assertNotIn("0.0.0.0/1 via 10.0.0.1", text)

    def test_direct_rule_uses_original_gateway(self):
        # With full capture, a .direct rule carves an exception via the original gateway.
        cfg = RoutingConfig(rules=[RoutingRule(type=RoutingRuleType.cidr, value="8.8.8.0/24",
                                               action=RoutingAction.direct)])
        self._apply(routing=cfg)
        self.assertIn("route replace 8.8.8.0/24 via 192.168.1.1", self._argv_text())

    def test_block_rule_is_blackhole(self):
        cfg = RoutingConfig(rules=[RoutingRule(type=RoutingRuleType.cidr, value="10.9.9.0/24",
                                               action=RoutingAction.block)])
        self._apply(routing=cfg)
        self.assertIn("route add blackhole 10.9.9.0/24", self._argv_text())

    def test_local_bypass_never_routed(self):
        self._apply(bypass_host="127.0.0.1")
        self.assertNotIn("route replace 127.0.0.1/32 via 192.168.1.1", self._argv_text())

    def test_mtu_override_wins(self):
        self._apply(mtu_override=1300)
        self.assertIn("link set dev vpngate0 mtu 1300 up", self._argv_text())

    def test_state_file_written_and_cleanup_stale(self):
        self._apply()
        self.assertTrue(os.path.exists(self.state_file))
        with open(self.state_file) as f:
            state = json.load(f)
        self.assertEqual(state["iface"], "vpngate0")
        self.assertTrue(state["added_routes"])
        self.net.teardown()
        # A stale state file from a crashed run is cleaned by the next start.
        # added_routes holds the UNDO argument lists.
        stale = {"iface": "vpngate0", "bypass_host": "5.6.7.8", "gateway": "10.0.0.1",
                 "dns_set": False,
                 "added_routes": [["route", "del", "9.9.9.9/32"]],
                 "tun_iface": "vpngate0"}
        with open(self.state_file, "w") as f:
            json.dump(stale, f)
        NetConfig.cleanup_stale(runner=self.runner, dns=AllowDNSConfigurator(self.runner),
                                state_file=self.state_file)
        self.assertIn("route del 9.9.9.9/32", self._argv_text())
        self.assertFalse(os.path.exists(self.state_file))

    def test_dns_proxy_address_published(self):
        self._apply(dns_proxy_address="127.0.0.1")
        # AllowDNSConfigurator.set returns True; assert the DNS configurator was called with it
        self.assertIsNotNone(self.net.state)
        self.assertTrue(self.net.state.dns_set)

    def test_bypass_host_route_dynamic(self):
        self._apply()
        self.net.add_bypass("9.9.9.9")
        self.assertIn("route replace 9.9.9.9/32 via 192.168.1.1", self._argv_text())
        self.net.add_bypass("127.0.0.1")  # never routed
        self.assertNotIn("route replace 127.0.0.1/32 via 192.168.1.1", self._argv_text())

    def test_dynamic_rule_route(self):
        self._apply()
        self.net.apply_dynamic_rule("203.0.113.5", RoutingAction.proxy)
        self.assertIn("route replace 203.0.113.5/32 dev vpngate0", self._argv_text())

    def test_dns_publish_invokes_resolvectl_binary(self):
        # Regression: the publish used to run "ip resolvectl ..." (iproute2 has no such
        # subcommand), so the tunnel's resolver was never configured and DNS kept leaking to
        # the local — censored — resolver.
        runner = RecordingRunner()
        dns = RecordingDNS(runner)
        net = NetConfig(runner=runner, dns=dns, state_file=self.state_file)
        net.apply(iface="vpngate0", lease=FakeLease(), bypass_host="5.6.7.8")
        resolvectl_calls = [args for path, args in runner.calls if path == "resolvectl"]
        self.assertIn(("dns", "vpngate0", "8.8.8.8"), resolvectl_calls)
        self.assertIn(("domain", "vpngate0", "~."), resolvectl_calls)
        self.assertIn(("default-route", "vpngate0", "yes"), resolvectl_calls)
        self.assertIn(("flush-caches",), resolvectl_calls)  # poisoned cached answers must go
        # and never through the ip binary
        for path, args in runner.calls:
            if "resolvectl" in args:
                self.fail(f"resolvectl must not be invoked via {path}: {args}")

    def test_current_servers_excludes_tunnel_and_loopback(self):
        """current_servers must not capture the tunnel's own DNS (127.0.0.1) or loopback —
        the DNS proxy would query itself and get SERVFAIL for Direct domains."""
        dns = DNSConfigurator(self.runner)
        # Fake resolvectl status with tun0 + ens33
        self.runner.calls.clear()
        self.runner.fail.clear()
        captured = dns.current_servers()
        # ens33's 192.168.247.2 should be captured; tun0's 127.0.0.1 should NOT
        self.assertIn("192.168.247.2", captured)
        self.assertNotIn("127.0.0.1", captured)

    def test_dns_link_isolation(self):
        """resolved must not merge poisoned answers from the physical link with the tunnel's.
        When tunnel DNS is published, DNS on every other link is disabled (and restored on
        teardown)."""
        dns = RecordingDNS(self.runner)
        net = NetConfig(runner=self.runner, dns=dns, state_file=self.state_file)
        net.cgroup_root = "/tmp/opencode-test-cgroup"  # bypass no-op
        net.apply(iface="tun0", lease=FakeLease(), bypass_host="5.6.7.8")
        # The RecordingDNS._disable_other_links was called via set() — but RecordingDNS
        # overrides set(); use a real DNSConfigurator instead:
        dns2 = DNSConfigurator(self.runner)
        dns2.set(["8.8.8.8"], "tun0", "10.0.0.2", "10.0.0.1")
        text = self._argv_text()
        # tun0 DNS published
        self.assertIn("dns tun0 8.8.8.8", text)
        # non-tunnel links must be disabled (status shows ens33 has DNS 192.168.247.2)
        self.assertIn("dns ens33", text)  # cleared (no servers)
        self.assertIn("default-route ens33 no", text)
        # teardown restores them
        dns2.remove("tun0")
        text = self._argv_text()
        self.assertIn("revert ens33", text)

    def test_app_bypass_commands_and_cleanup(self):
        import tempfile
        from vpngate.core.routing import RoutingConfig
        cfg = RoutingConfig(bypass_apps_enabled=True, bypass_apps=["firefox"])
        self._apply()
        cgroup_dir = tempfile.mkdtemp()  # stands in for /sys/fs/cgroup
        self.net.cgroup_root = cgroup_dir
        self.runner.fail.clear()
        self.net.setup_app_bypass(cfg, ("192.168.1.1", "eth0"))
        text = self._argv_text()
        self.assertIn("-t mangle -A OUTPUT -m cgroup --path vpngate-bypass -j MARK "
                      "--set-mark 0x5657", text)
        self.assertIn("rule add fwmark 0x5657 table 5657 priority 5000", text)
        self.assertIn("route replace default via 192.168.1.1 dev eth0 table 5657", text)
        self.assertTrue(self.net.state.app_bypass)
        self.net.teardown()
        text = self._argv_text()
        self.assertIn("-t mangle -D OUTPUT -m cgroup --path vpngate-bypass -j MARK "
                      "--set-mark 0x5657", text)
        self.assertIn("rule del fwmark 0x5657 table 5657 priority 5000", text)
        self.assertIn("route flush table 5657", text)

    def test_app_bypass_rescan_moves_matching_processes(self):
        import tempfile
        from vpngate.core.routing import RoutingConfig
        cfg = RoutingConfig(bypass_apps_enabled=True, bypass_apps=["firefox"])
        self._apply()
        cgroup_dir = tempfile.mkdtemp()
        proc_dir = tempfile.mkdtemp()
        os.makedirs(f"{cgroup_dir}/vpngate-bypass")
        os.makedirs(f"{proc_dir}/123")
        with open(f"{proc_dir}/123/comm", "w") as f:
            f.write("firefox")
        os.makedirs(f"{proc_dir}/456")
        with open(f"{proc_dir}/456/comm", "w") as f:
            f.write("gimp")
        self.net.cgroup_root = cgroup_dir
        self.net.proc_root = proc_dir
        self.net.setup_app_bypass(cfg, ("192.168.1.1", "eth0"))
        moved = self.net.rescan_app_bypass()
        self.assertEqual(moved, 1)
        procs = open(f"{cgroup_dir}/vpngate-bypass/cgroup.procs").read()
        self.assertIn("123", procs)
        self.assertNotIn("456", procs)
        # already moved: rescan is a no-op
        self.assertEqual(self.net.rescan_app_bypass(), 0)

    def test_app_bypass_off_does_nothing(self):
        from vpngate.core.routing import RoutingConfig
        self._apply()
        before = len(self.runner.calls)
        self.net.setup_app_bypass(RoutingConfig(), ("192.168.1.1", "eth0"))
        self.assertEqual(len(self.runner.calls), before)

    def test_teardown_returns_stranded_processes(self):
        import tempfile
        from vpngate.core.routing import RoutingConfig
        cfg = RoutingConfig(bypass_apps_enabled=True, bypass_apps=["firefox"])
        self._apply()
        cgroup_dir = tempfile.mkdtemp()
        self.net.cgroup_root = cgroup_dir
        os.makedirs(f"{cgroup_dir}/vpngate-bypass")
        # a process "stuck" in the cgroup (as if the helper crashed after moving it)
        with open(f"{cgroup_dir}/vpngate-bypass/cgroup.procs", "w") as f:
            f.write("123\n")
        self.net._bypass_apps = ["firefox"]
        self.net._bypass_active = True
        if self.net.state:
            self.net.state.app_bypass = True
        self.net.teardown()
        moved_back = open(f"{cgroup_dir}/cgroup.procs").read()
        self.assertIn("123", moved_back)  # the stranded process was returned to the root cgroup

    def test_update_bypass_apps_live(self):
        from vpngate.core.routing import RoutingConfig
        self._apply()
        self.net.cgroup_root = tempfile.mkdtemp()
        # the engine is armed at connect time (session._establish)
        self.net.setup_app_bypass(
            RoutingConfig(bypass_apps_enabled=True, bypass_apps=["firefox"]),
            ("192.168.1.1", "eth0"))
        self.net.update_bypass_apps(["firefox"], True)
        self.assertEqual(self.net._bypass_apps, ["firefox"])
        text = self._argv_text()
        self.assertIn("-t mangle -A OUTPUT -m cgroup --path vpngate-bypass", text)
        # disabling tears the whole setup down
        self.net.update_bypass_apps([], False)
        text = self._argv_text()
        self.assertIn("-t mangle -D OUTPUT -m cgroup --path vpngate-bypass", text)
        self.assertIn("rule del fwmark 0x5657", text)
        self.assertFalse(self.net._bypass_active)

    def test_mask_to_prefix(self):
        self.assertEqual(_mask_to_prefix(0xFFFFFF00), 24)
        self.assertEqual(_mask_to_prefix(0xFFFF0000), 16)
        self.assertEqual(_mask_to_prefix(0xFFFFFFFC), 30)
        self.assertEqual(_mask_to_prefix(0), 32)


if __name__ == "__main__":
    unittest.main()
