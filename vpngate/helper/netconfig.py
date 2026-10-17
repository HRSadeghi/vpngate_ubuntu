"""Interface address, routes and DNS for the tunnel (port of NetConfig.swift).

macOS used /sbin/route, /sbin/ifconfig and configd. On Ubuntu this uses iproute2 (`ip`)
and DNS is published through systemd-resolved (`resolvectl`) when it runs, with a plain
/etc/resolv.conf rewrite as the fallback. State is persisted so a crashed helper can clean up.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import time

CGROUP_PATH = "/sys/fs/cgroup/vpngate-bypass"
BYPASS_MARK = "0x5657"
BYPASS_TABLE = "5657"


def _log(tag: str, message: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {tag} {message}", flush=True)
from dataclasses import dataclass

from ..core import validation
from ..core.routing import RoutingAction, RoutingConfig

DEFAULT_STATE_FILE = "/var/run/vpngate-helper.state"
IP = "/usr/sbin/ip" if os.path.exists("/usr/sbin/ip") else "/usr/sbin/ip"


def _ip_path() -> str:
    return shutil.which("ip") or "/usr/sbin/ip"


@dataclass
class State:
    iface: str
    bypass_host: str
    gateway: str
    dns_set: bool = False
    app_bypass: bool = False
    # `ip` argument lists that undo each route we really added, in the order they were added.
    # None in state files written by older versions (then everything is removed best-effort).
    added_routes: list[list[str]] | None = None
    # Fallback DNS rewrite support (no systemd-resolved): the original resolv.conf text.
    resolv_conf_backup: str | None = None
    tun_iface: str = ""


class CommandRunner:
    def run(self, path: str, args: list[str]) -> tuple[int, str]:
        try:
            proc = subprocess.run([path, *args], capture_output=True, text=True, timeout=15)
            return proc.returncode, proc.stdout + proc.stderr
        except Exception as e:
            return -1, str(e)


class DNSConfigurator:
    """Publishes the tunnel's resolver while connected (systemd-resolved or /etc/resolv.conf)."""

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self.runner = runner or CommandRunner()
        self._resolv_backup: str | None = None
        self._wrote_resolv_conf = False
        self._disabled_links: list[str] = []

    @staticmethod
    def _has_resolved() -> bool:
        if not (shutil.which("resolvectl") and os.path.isdir("/run/systemd/resolve")):
            return False
        # Only trust resolvectl when the system actually uses systemd-resolved: with a
        # static /etc/resolv.conf, per-link DNS configures nothing apps ever ask. In that
        # case fall through to the plain resolv.conf rewrite.
        try:
            target = os.path.realpath("/etc/resolv.conf")
        except OSError:
            return False
        return target.startswith("/run/systemd/resolve/")

    def set(self, servers: list[str], iface: str, address: str, router: str) -> bool:
        if self._has_resolved():
            resolvectl = shutil.which("resolvectl")
            r = self.runner.run(resolvectl, ["dns", iface, *servers])
            ok1 = r[0] == 0
            r = self.runner.run(resolvectl, ["domain", iface, "~."])
            ok2 = r[0] == 0
            self.runner.run(resolvectl, ["default-route", iface, "yes"])
            # Disable DNS on every OTHER link so resolved cannot merge poisoned/censored
            # answers from the physical network with the tunnel's answers. Without this,
            # resolved queries both links and the browser gets a union of real + poisoned
            # records (the AAAA leak that made YouTube unreachable).
            self._disable_other_links(iface, resolvectl)
            self.runner.run(resolvectl, ["flush-caches"])
            ok = ok1 and ok2
            if not ok:
                _log("[dns]", "publishing resolver through resolvectl failed: " + r[1].strip())
            return ok
        # Fallback: rewrite /etc/resolv.conf directly (original kept for restore).
        try:
            if os.path.exists("/etc/resolv.conf") and self._resolv_backup is None:
                with open("/etc/resolv.conf", "r") as f:
                    self._resolv_backup = f.read()
            with open("/etc/resolv.conf", "w") as f:
                f.write("".join(f"nameserver {s}\n" for s in servers))
            self._wrote_resolv_conf = True
            return True
        except OSError as e:
            _log("[dns]", f"writing /etc/resolv.conf failed: {e}")
            return False

    def _disable_other_links(self, tunnel_iface: str, resolvectl: str) -> None:
        """Clear DNS on every non-tunnel link so resolved cannot merge poisoned answers."""
        self._disabled_links = []
        rc, out = self.runner.run(resolvectl, ["status"])
        if rc != 0:
            return
        current_link = ""
        for line in out.splitlines():
            t = line.strip()
            if t.startswith("Link "):
                # "Link 2 (ens33):" → "ens33"
                name = t.split("(", 1)[1].split(")", 1)[0] if "(" in t else ""
                current_link = name
            elif t.startswith("DNS Servers:") and current_link and current_link != tunnel_iface:
                self._disabled_links.append(current_link)
        for link in self._disabled_links:
            self.runner.run(resolvectl, ["dns", link])  # clear DNS servers on that link
            self.runner.run(resolvectl, ["default-route", link, "no"])
            _log("[dns]", f"disabled DNS on physical link {link} (prevents leak)")

    def remove(self, iface: str = "") -> None:
        if self._has_resolved():
            resolvectl = shutil.which("resolvectl")
            # Restore the tunnel link and every link we disabled during set().
            # Always run both — even if the set() side missed, the user must not be left
            # with no DNS after disconnecting.
            if iface:
                self.runner.run(resolvectl, ["revert", iface])
            for link in self._disabled_links:
                self.runner.run(resolvectl, ["revert", link])
                self.runner.run(resolvectl, ["default-route", link, "yes"])
                _log("[dns]", f"restored DNS on physical link {link}")
            if not self._disabled_links:
                # Even if we never recorded the disabled links, try restoring the
                # physical interface from the current default route.
                rc, out = self.runner.run(_ip_path(), ["route", "show", "default"])
                if rc == 0 and "dev" in out:
                    toks = out.split()
                    for i, t in enumerate(toks):
                        if t == "dev" and i + 1 < len(toks):
                            self.runner.run(resolvectl, ["revert", toks[i + 1]])
                            self.runner.run(resolvectl, ["default-route", toks[i + 1], "yes"])
                            _log("[dns]", f"restored DNS on default link {toks[i + 1]}")
                            break
            self.runner.run(resolvectl, ["flush-caches"])
            self._disabled_links = []
            return
        # Fallback: restore the resolv.conf we overwrote.
        if self._wrote_resolv_conf and self._resolv_backup is not None:
            try:
                with open("/etc/resolv.conf", "w") as f:
                    f.write(self._resolv_backup)
            except OSError:
                pass
            self._wrote_resolv_conf = False
        if self._wrote_resolv_conf and self._resolv_backup is not None:
            try:
                with open("/etc/resolv.conf", "w") as f:
                    f.write(self._resolv_backup)
            except OSError:
                pass
            self._wrote_resolv_conf = False

    def current_servers(self) -> list[str]:
        """The resolver(s) in effect right before the tunnel's are published (the physical
        network's own DNS). Excludes the tunnel interface and loopback addresses (127.x)."""
        out: list[str] = []
        # systemd-resolved: ask it directly for per-link DNS (skips the 127.0.0.53 stub).
        if self._has_resolved():
            rc, text = self.runner.run("resolvectl", ["status"])
            if rc == 0:
                current_link = ""
                for line in text.splitlines():
                    t = line.strip()
                    if t.startswith("Link ") and "(" in t:
                        name = t.split("(", 1)[1].split(")", 1)[0] if "(" in t else ""
                        current_link = name
                    elif t.startswith("DNS Servers:") or t.startswith("Current DNS Server:"):
                        for tok in t.split(":", 1)[1].split():
                            tok = tok.strip(",()")
                            # Skip the tunnel's own DNS and loopback addresses
                            if current_link.startswith(("tun", "vpngate")):
                                continue
                            if validation.is_ipv4_literal(tok) and not validation.is_local_address(tok):
                                out.append(tok)
        if not out:
            try:
                with open("/etc/resolv.conf") as f:
                    for line in f:
                        t = line.strip()
                        if t.startswith("nameserver "):
                            server = t.split()[1]
                            if validation.is_ipv4_literal(server):
                                out.append(server)
            except OSError:
                pass
        # Deduplicate, keep order.
        seen: set[str] = set()
        unique = [s for s in out if not (s in seen or seen.add(s))]
        return unique


class NetConfig:
    """State is persisted so a crashed helper can clean up (only routes it added)."""

    def __init__(self, runner: CommandRunner | None = None, dns: DNSConfigurator | None = None,
                 state_file: str = DEFAULT_STATE_FILE) -> None:
        self.runner = runner or CommandRunner()
        self.dns = dns or DNSConfigurator(self.runner)
        self.state_file = state_file
        self.state: State | None = None
        self.proc_root = "/proc"          # patchable for tests
        self.cgroup_root = "/sys/fs/cgroup"  # patchable for tests
        self._bypass_moved: set[int] = set()
        self._bypass_apps: list[str] = []
        self._bypass_active = False
        self._app_bypass_config: RoutingConfig | None = None
        self.original_route: tuple[str | None, str] | None = None
        self.routing = RoutingConfig()
        self.tunnel_gateway: str | None = None
        self.captured_physical_dns: list[str] = []
        # Capture bookkeeping (fail-open support): the publish arguments for the resolver,
        # the undo lists of the default-capture routes, and whether capture is installed.
        self._publish: tuple[list[str], str, str, str] | None = None
        self._capture_undo: list[list[str]] = []
        self._capture_enabled = False

    # MARK: routes

    def _add_route(self, add_args: list[str], undo_args: list[str]) -> None:
        """Adds a route; remembers how to delete it only if `ip route add` succeeded."""
        r = self.runner.run(_ip_path(), add_args)
        if r[0] == 0:
            if self.state and self.state.added_routes is not None:
                self.state.added_routes.append(undo_args)
                self._save()
        else:
            _log("[route]", f"add {' '.join(add_args[1:])} failed ({r[0]}): {r[1].strip()}")

    def _add_bypass_route(self, host: str, via: tuple[str | None, str]) -> None:
        gw, iface = via
        if gw:
            self._add_route(["route", "replace", host + "/32", "via", gw],
                            ["route", "del", host + "/32"])
        else:
            self._add_route(["route", "replace", host + "/32", "dev", iface],
                            ["route", "del", host + "/32"])

    def _add_rule_route(self, value: str, action: RoutingAction, iface: str, gw: str,
                        orig: tuple[str | None, str] | None) -> None:
        """Adds an explicit route for one IP/CIDR routing rule. Uses `replace` so a
        route left by a previous session is overwritten instead of failing with "File exists"."""
        is_v6 = ":" in value
        prefix = "-6" if is_v6 else "-4"
        target = value if "/" in value else value + ("/128" if is_v6 else "/32")
        args = [prefix, "route", "replace", target]
        undo = ["route", "del", target]
        if action == RoutingAction.direct:
            if orig is None:
                return
            o_gw, o_iface = orig
            if o_gw and not is_v6:
                self._add_route(args + ["via", o_gw], undo)
            else:
                self._add_route(args + ["dev", o_iface], undo)
        elif action == RoutingAction.proxy:
            self._add_route(args + ["dev", iface], undo)
        elif action == RoutingAction.block:
            self._add_route([prefix, "route", "add", "blackhole", target], undo)

    # MARK: apply / teardown

    def apply(self, iface: str, lease, bypass_host: str, block_ipv6: bool = True,
              mtu_override: int | None = None, routing: RoutingConfig | None = None,
              dns_proxy_address: str | None = None, capture: bool = True) -> None:
        """`lease` is the bridge's Lease (ip/mask/router/dns/seconds/mtu as ints).

        `capture=False` defers the default-capture routes and the resolver publish to
        enable_capture(): a relay must prove it carries traffic before the machine's
        default routes are taken over."""
        from ..core.packets import ip_string
        ip = ip_string(lease.ip)
        gw = ip_string(lease.router)
        orig = self.default_route()
        self.original_route = orig
        self.tunnel_gateway = gw
        self.routing = routing or RoutingConfig()
        self.state = State(iface=iface, bypass_host=bypass_host, gateway=gw,
                           added_routes=[], tun_iface=iface)
        self._save()

        # The account's own MTU setting wins when valid; otherwise the DHCP lease's option 26.
        def valid_mtu(v):
            return v if v is not None and 576 <= v <= 1500 else None

        mtu_val = valid_mtu(mtu_override) or valid_mtu(lease.mtu) or 1400
        # Point-to-point /32 like the macOS port (and OpenVPN): the DHCP mask only steers the
        # bridge's on-link decisions, it never becomes an interface route.
        self.runner.run(_ip_path(), ["addr", "replace", f"{ip}/32", "peer", f"{gw}/32", "dev", iface])
        self.runner.run(_ip_path(), ["link", "set", "dev", iface, "mtu", str(mtu_val), "up"])
        # `replace`: reconnecting to a subnet whose gateway route survived the previous
        # teardown must not fail ("File exists") and lose the undo bookkeeping.
        self._add_route(["route", "replace", gw + "/32", "dev", iface], ["route", "del", gw + "/32"])

        # Keep the tunnel's own transport outside the tunnel (never for loopback/link-local proxies).
        if not validation.is_local_address(bypass_host) and orig:
            self._add_bypass_route(bypass_host, orig)

        if self.routing.default_action == RoutingAction.direct:
            # Nothing is captured: unmatched traffic keeps going the way it always did.
            for rule in self.routing.effective_rules:
                if rule.enabled and not rule.type.is_domain and rule.action != RoutingAction.direct:
                    self._add_rule_route(rule.value, rule.action, iface, gw, orig)
        else:
            for rule in self.routing.effective_rules:
                if rule.enabled and not rule.type.is_domain and rule.action != RoutingAction.proxy:
                    self._add_rule_route(rule.value, rule.action, iface, gw, orig)

        # ALWAYS capture the physical DNS before the resolver is switched over — a `.direct`
        # domain rule added later (live-apply) needs these to resolve through the physical
        # network. Previously this was gated on `routing.is_empty` which left direct_dnsservers
        # empty when the user connected without rules and added them later.
        self.captured_physical_dns = [s for s in self.dns.current_servers()
                                      if validation.is_ipv4_literal(s)]
        for server in self.captured_physical_dns:
            if not validation.is_local_address(server) and orig:
                self._add_bypass_route(server, orig)

        if lease.dns:
            published = [dns_proxy_address] if dns_proxy_address else [ip_string(d) for d in lease.dns]
            self._publish = (published, iface, ip, gw)
        self._capture_enabled = False
        self._capture_undo = []
        if capture:
            self.enable_capture()

    def direct_dns_servers(self) -> list[str]:
        return self.captured_physical_dns

    # MARK: capture / fail-open

    def enable_capture(self) -> None:
        """Installs the default-capture routes and publishes the tunnel's resolver. Called
        once the tunnel has proved it carries traffic — and again after a fail-open."""
        if self.state is None or self._capture_enabled or self.tunnel_gateway is None:
            return
        iface, gw = self.state.iface, self.tunnel_gateway
        before = len(self.state.added_routes or [])
        if self.routing.default_action != RoutingAction.direct:
            self._add_route(["route", "replace", "0.0.0.0/1", "via", gw], ["route", "del", "0.0.0.0/1"])
            self._add_route(["route", "replace", "128.0.0.0/1", "via", gw], ["route", "del", "128.0.0.0/1"])
        # Both halves of the IPv6 space point at the tunnel either way, so native v6 never leaks.
        self._add_route(["-6", "route", "replace", "::/1", "dev", iface], ["-6", "route", "del", "::/1"])
        self._add_route(["-6", "route", "replace", "8000::/1", "dev", iface], ["-6", "route", "del", "8000::/1"])
        added = (self.state.added_routes or [])[before:]
        self._capture_undo = [list(u) for u in added]
        if self._publish is not None:
            published, p_iface, ip, p_gw = self._publish
            if self.dns.set(published, p_iface, ip, p_gw):
                self.state.dns_set = True
                self._save()
        self._capture_enabled = True

    def fail_open(self) -> None:
        """The relay stopped carrying traffic: stop blackholing the machine. The default
        routes are removed and DNS goes back to the physical network while the session
        stays up — traffic fails open to the real network instead of dying behind a dead
        tunnel. enable_capture() puts the capture back if the tunnel recovers."""
        if self.state is None or not self._capture_enabled:
            return
        if self.state.dns_set:
            self.dns.remove(self.state.iface)
            self.state.dns_set = False
        for undo in self._capture_undo:
            self.runner.run(_ip_path(), undo)
        if self.state.added_routes is not None:
            drop = {tuple(u) for u in self._capture_undo}
            self.state.added_routes = [u for u in self.state.added_routes
                                       if tuple(u) not in drop]
        self._capture_undo = []
        self._capture_enabled = False
        self._save()
        _log("[route]", "fail-open: capture routes removed, traffic goes direct "
                        "(the relay is not carrying data)")

    def fail_close(self) -> None:
        """Traffic is flowing again after a fail-open: re-capture the default routes."""
        self.enable_capture()

    def add_probe_host(self, host: str) -> None:
        """Routes one probe target into the tunnel temporarily (pre-capture liveness
        check). Not recorded in the state file: the kernel drops the route with the
        device when the tunnel goes away."""
        if self.state is None or not validation.is_ipv4_literal(host):
            return
        self.runner.run(_ip_path(), ["route", "replace", host + "/32", "dev", self.state.iface])

    def remove_probe_host(self, host: str) -> None:
        if self.state is None:
            return
        self.runner.run(_ip_path(), ["route", "del", host + "/32"])

    def apply_dynamic_rule(self, ip: str, action: RoutingAction) -> None:
        """Routes one resolved address (from the DNS proxy) the way a domain rule asked for."""
        if self.state is None or self.tunnel_gateway is None or not validation.is_ip_literal(ip):
            return
        self._add_rule_route(ip, action, self.state.iface, self.tunnel_gateway, self.original_route)

    def add_bypass(self, host: str) -> None:
        """Adds a host route around the tunnel for a further peer (redirect/UDP endpoint)."""
        if (self.state is None or not validation.is_ipv4_literal(host)
                or validation.is_local_address(host) or host == self.state.bypass_host
                or self.original_route is None):
            return
        self._add_bypass_route(host, self.original_route)

    def configure_ipv6(self, address: bytes, prefix_length: int) -> None:
        """Puts the SLAAC address learned from a Router Advertisement on the tunnel interface."""
        from ..core.packets import IPv6
        if (self.state is None or len(address) != 16 or not 1 <= prefix_length <= 128
                or not any(address) or address[0] == 0xFF or IPv6.is_link_local(address)):
            return
        r = self.runner.run(_ip_path(), ["-6", "addr", "add",
                                         f"{IPv6.string(address)}/{prefix_length}",
                                         "dev", self.state.iface])
        if r[0] != 0:
            _log("[ip]", f"-6 addr add {IPv6.string(address)} failed ({r[0]}): {r[1].strip()}")

    def teardown(self) -> None:
        self._teardown_app_bypass()
        self._cleanup(self.state, self.runner, self.dns)
        self.state = None
        self.original_route = None
        self.tunnel_gateway = None
        self.captured_physical_dns = []
        self.routing = RoutingConfig()
        self._publish = None
        self._capture_undo = []
        self._capture_enabled = False
        try:
            os.remove(self.state_file)
        except OSError:
            pass

    @staticmethod
    def cleanup_stale(runner: CommandRunner | None = None, dns: DNSConfigurator | None = None,
                      state_file: str = DEFAULT_STATE_FILE) -> None:
        """Remove leftovers from a previous run that did not shut down cleanly."""
        runner = runner or CommandRunner()
        dns = dns or DNSConfigurator(runner)
        try:
            with open(state_file) as f:
                st = State(**json.load(f))
        except (OSError, ValueError, TypeError):
            return
        NetConfig._cleanup(st, runner, dns)
        if getattr(st, "app_bypass", False):
            NetConfig._cleanup_app_bypass_stale(runner)
        try:
            os.remove(state_file)
        except OSError:
            pass

    @staticmethod
    def _cleanup_app_bypass_stale(runner: CommandRunner) -> None:
        ipt = shutil.which("iptables")
        ip6t = shutil.which("ip6tables")
        spec = ["-m", "cgroup", "--path", "vpngate-bypass", "-j", "MARK",
                "--set-mark", BYPASS_MARK]
        if ipt:
            runner.run(ipt, ["-t", "mangle", "-D", "OUTPUT", *spec])
        if ip6t:
            runner.run(ip6t, ["-t", "mangle", "-D", "OUTPUT", *spec])
        runner.run(_ip_path(), ["rule", "del", "fwmark", BYPASS_MARK,
                                "table", BYPASS_TABLE, "priority", "5000"])
        runner.run(_ip_path(), ["route", "flush", "table", BYPASS_TABLE])
        try:
            os.rmdir(CGROUP_PATH)
        except OSError:
            pass

    @staticmethod
    def _cleanup(st: State | None, runner: CommandRunner, dns: DNSConfigurator) -> None:
        if st is None:
            return
        if st.added_routes:
            for undo in reversed(st.added_routes):
                runner.run(_ip_path(), undo)
        else:  # state written by an older version: remove what it would have added
            runner.run(_ip_path(), ["route", "del", "0.0.0.0/1"])
            runner.run(_ip_path(), ["route", "del", "128.0.0.0/1"])
            runner.run(_ip_path(), ["route", "del", st.gateway + "/32"])
            if not validation.is_local_address(st.bypass_host):
                runner.run(_ip_path(), ["route", "del", st.bypass_host + "/32"])
        if st.dns_set:
            dns.remove(st.tun_iface or st.iface)

    def _save(self) -> None:
        if self.state is None:
            return
        try:
            with open(self.state_file, "w") as f:
                json.dump({
                    "iface": self.state.iface,
                    "bypass_host": self.state.bypass_host,
                    "gateway": self.state.gateway,
                    "dns_set": self.state.dns_set,
                    "added_routes": self.state.added_routes,
                    "resolv_conf_backup": self.state.resolv_conf_backup,
                    "tun_iface": self.state.tun_iface,
                    "app_bypass": self.state.app_bypass,
                }, f)
        except OSError:
            pass

    # MARK: application bypass (split tunneling by app)
    #
    # Selected applications keep their normal internet while the VPN is connected: a cgroup
    # v2 group collects the apps' processes, an iptables cgroup match marks their packets,
    # and an fwmark policy rule routes marked packets over the original default gateway —
    # ahead of the 0.0.0.0/1+128.0.0.0/1 tunnel capture. Only NEW connections of a moved
    # process are affected (the socket's cgroup is fixed at creation).

    def setup_app_bypass(self, routing: RoutingConfig | None,
                         orig: tuple[str | None, str] | None) -> None:
        """Enables or clears app bypass according to `routing`; safe to call repeatedly."""
        enabled = bool(routing and routing.bypass_apps_enabled and routing.bypass_apps)
        if not enabled:
            self._teardown_app_bypass()
            return
        ipt = shutil.which("iptables")
        ip6t = shutil.which("ip6tables")
        if not ipt or orig is None:
            _log("[bypass]", "iptables or the original route is unavailable; app bypass off")
            self._teardown_app_bypass()
            return
        cgroup = os.path.join(self.cgroup_root, "vpngate-bypass")
        if not os.path.isdir(self.cgroup_root):
            _log("[bypass]", "no cgroup filesystem; app bypass off")
            self._teardown_app_bypass()
            return
        try:
            os.makedirs(cgroup, exist_ok=True)
        except OSError as e:
            _log("[bypass]", f"cannot create {cgroup}: {e}")
            return

        self._app_bypass_config = routing
        self._bypass_apps = [a.strip() for a in routing.bypass_apps if a.strip()]
        spec = ["-m", "cgroup", "--path", "vpngate-bypass", "-j", "MARK",
                "--set-mark", BYPASS_MARK]
        # v4
        if self.runner.run(ipt, ["-t", "mangle", "-C", "OUTPUT", *spec])[0] != 0:
            self.runner.run(ipt, ["-t", "mangle", "-A", "OUTPUT", *spec])
        # v6 (only when the physical network has IPv6; otherwise v6 stays blocked anyway)
        if ip6t and self.default_route6() is not None:
            if self.runner.run(ip6t, ["-t", "mangle", "-C", "OUTPUT", *spec])[0] != 0:
                self.runner.run(ip6t, ["-t", "mangle", "-A", "OUTPUT", *spec])

        rules_now = self.runner.run(_ip_path(), ["rule", "show"])[1]
        if f"fwmark {BYPASS_MARK}" not in rules_now:
            self.runner.run(_ip_path(), ["rule", "add", "fwmark", BYPASS_MARK,
                                         "table", BYPASS_TABLE, "priority", "5000"])
        # Mirror the original default route (and its connected route) into the bypass table.
        o_gw, o_iface = orig
        if o_gw:
            self.runner.run(_ip_path(), ["route", "replace", "default", "via", o_gw,
                                         "dev", o_iface, "table", BYPASS_TABLE])
        else:
            self.runner.run(_ip_path(), ["route", "replace", "default", "dev", o_iface,
                                         "table", BYPASS_TABLE])
        rc, out = self.runner.run(_ip_path(), ["route", "show", "dev", o_iface])
        for line in out.splitlines():
            t = line.strip()
            if t.startswith("default") or "scope link" not in t:
                continue
            self.runner.run(_ip_path(), ["route", "replace", *t.split(), "table", BYPASS_TABLE])
            break

        self.rescan_app_bypass()
        self._bypass_active = True
        if self.state is not None:
            self.state.app_bypass = True
            self._save()

    def default_route6(self) -> tuple[str | None, str] | None:
        rc, out = self.runner.run(_ip_path(), ["-6", "route", "show", "default"])
        if rc != 0 or not out.strip():
            return None
        gw = iface = None
        toks = out.split()
        for i, tok in enumerate(toks):
            if tok == "via" and i + 1 < len(toks):
                gw = toks[i + 1]
            if tok == "dev" and i + 1 < len(toks):
                iface = toks[i + 1]
        return (gw, iface) if iface else None

    def _bypass_matches(self, comm: str, exe: str) -> bool:
        low = comm.lower()
        for app in self._bypass_apps:
            a = app.lower()
            base = a.rsplit("/", 1)[-1]
            if low == a.rsplit("/", 1)[-1] or low == base or (exe and exe.lower() == a) \
                    or (exe and exe.lower().rsplit("/", 1)[-1] == base):
                return True
        return False

    def update_bypass_apps(self, apps: list[str], enabled: bool) -> None:
        """Live update of the bypass list (the user edited it while connected): re-runs the
        whole setup/teardown with the new list, no reconnect needed."""
        clean = [a.strip() for a in apps if a.strip()][:64]
        if self._app_bypass_config is None:
            return
        cfg = RoutingConfig(bypass_apps_enabled=enabled, bypass_apps=clean,
                            default_action=self._app_bypass_config.default_action,
                            bypass_private_networks=self._app_bypass_config.bypass_private_networks)
        self.setup_app_bypass(cfg, self.original_route)
        _log("[bypass]", f"live update: {len(clean)} app(s), "
                         f"{'enabled' if enabled and clean else 'disabled'}")

    def rescan_app_bypass(self) -> int:
        """Moves processes of bypassed apps into the cgroup; returns the number newly moved.
        Cheap enough to run every few seconds for the whole /proc."""
        if not self.state or not self.state.app_bypass or not self._bypass_apps:
            return 0
        cgroup = os.path.join(self.cgroup_root, "vpngate-bypass")
        if not os.path.isdir(cgroup):
            return 0
        moved = 0
        moved_names: list[str] = []
        try:
            entries = os.listdir(self.proc_root)
        except OSError:
            return 0
        for entry in entries:
            if not entry.isdigit():
                continue
            pid = int(entry)
            if pid in self._bypass_moved:
                continue
            try:
                with open(f"{self.proc_root}/{entry}/comm", "rb") as f:
                    comm = f.read().decode("utf-8", "replace").strip()
                try:
                    exe = os.readlink(f"{self.proc_root}/{entry}/exe")
                except OSError:
                    exe = ""
            except OSError:
                continue
            if not comm or not self._bypass_matches(comm, exe):
                continue
            try:
                with open(f"{cgroup}/cgroup.procs", "ab") as f:
                    f.write(f"{pid}\n".encode())
                self._bypass_moved.add(pid)
                moved += 1
                moved_names.append(f"{comm} (pid {pid})")
            except OSError:
                continue
        if moved:
            _log("[bypass]", f"moved {moved} process(es): {', '.join(moved_names[:6])}")
        return moved

    def _teardown_app_bypass(self) -> None:
        if not self._bypass_active:
            self._bypass_apps = []
            self._bypass_moved = set()
            return
        self._bypass_active = False
        ipt = shutil.which("iptables")
        ip6t = shutil.which("ip6tables")
        spec = ["-m", "cgroup", "--path", "vpngate-bypass", "-j", "MARK",
                "--set-mark", BYPASS_MARK]
        if ipt:
            self.runner.run(ipt, ["-t", "mangle", "-D", "OUTPUT", *spec])
        if ip6t:
            self.runner.run(ip6t, ["-t", "mangle", "-D", "OUTPUT", *spec])
        self.runner.run(_ip_path(), ["rule", "del", "fwmark", BYPASS_MARK,
                                     "table", BYPASS_TABLE, "priority", "5000"])
        self.runner.run(_ip_path(), ["route", "flush", "table", BYPASS_TABLE])
        # Move any stranded processes back to the root cgroup so nothing stays classified
        # (and the cgroup can be removed).
        procs_file = os.path.join(self.cgroup_root, "vpngate-bypass", "cgroup.procs")
        try:
            with open(procs_file) as f:
                stranded = [p for p in f.read().split() if p.strip()]
            root_procs = os.path.join(self.cgroup_root, "cgroup.procs")
            for pid in stranded:
                try:
                    with open(root_procs, "ab") as rf:
                        rf.write(f"{pid}\n".encode())
                except OSError:
                    continue
            if stranded:
                _log("[bypass]", f"returned {len(stranded)} process(es) to the root cgroup")
        except OSError:
            pass
        try:
            os.rmdir(os.path.join(self.cgroup_root, "vpngate-bypass"))
        except OSError as e:
            _log("[bypass]", f"could not remove the bypass cgroup: {e}")
        self._bypass_apps = []
        self._bypass_moved = set()
        if self.state is not None and getattr(self.state, "app_bypass", False):
            self.state.app_bypass = False
            self._save()

    def rescan_loop(self, interval: float = 3.0):
        async def _loop():
            while True:
                await asyncio.sleep(interval)
                try:
                    self.rescan_app_bypass()
                except Exception as e:  # never kill the session over the bypass scan
                    _log("[bypass]", f"rescan failed: {e}")
        return _loop()

    def default_route(self) -> tuple[str | None, str] | None:
        """(gateway, iface) of the current default route; gateway None when on-link."""
        rc, out = self.runner.run(_ip_path(), ["route", "show", "default"])
        if rc != 0:
            return None
        gw = iface = None
        toks = out.split()
        for i, tok in enumerate(toks):
            if tok == "via" and i + 1 < len(toks):
                gw = toks[i + 1]
            if tok == "dev" and i + 1 < len(toks):
                iface = toks[i + 1]
        if iface is None:
            return None
        if gw is not None and not validation.is_ipv4_literal(gw):
            gw = None
        return gw, iface


def _mask_to_prefix(mask: int) -> int:
    """DHCP netmask integer → prefix length (255.255.255.0 → 24); 0 → 32 (point-to-point)."""
    if mask == 0:
        return 32
    bits = 0
    for i in range(24, -8, -8):
        byte = (mask >> i) & 0xFF
        if byte == 0xFF:
            bits += 8
        else:
            for b in range(7, -1, -1):
                if byte & (1 << b):
                    bits += 1
                else:
                    return bits
    return bits or 32