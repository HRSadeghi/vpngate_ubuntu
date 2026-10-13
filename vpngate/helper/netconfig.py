"""Interface address, routes and DNS for the tunnel (port of NetConfig.swift).

macOS used /sbin/route, /sbin/ifconfig and configd. On Ubuntu this uses iproute2 (`ip`)
and DNS is published through systemd-resolved (`resolvectl`) when it runs, with a plain
/etc/resolv.conf rewrite as the fallback. State is persisted so a crashed helper can clean up.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time


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

    @staticmethod
    def _has_resolved() -> bool:
        return bool(shutil.which("resolvectl")) and os.path.isdir("/run/systemd/resolve")

    def set(self, servers: list[str], iface: str, address: str, router: str) -> bool:
        if self._has_resolved():
            resolvectl = shutil.which("resolvectl")
            r = self.runner.run(resolvectl, ["dns", iface, *servers])
            ok1 = r[0] == 0
            r = self.runner.run(resolvectl, ["domain", iface, "~."])
            ok2 = r[0] == 0
            self.runner.run(resolvectl, ["default-route", iface, "yes"])
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

    def remove(self, iface: str = "") -> None:
        if self._has_resolved() and iface:
            resolvectl = shutil.which("resolvectl")
            self.runner.run(resolvectl, ["revert", iface])
            return
        if self._wrote_resolv_conf and self._resolv_backup is not None:
            try:
                with open("/etc/resolv.conf", "w") as f:
                    f.write(self._resolv_backup)
            except OSError:
                pass
            self._wrote_resolv_conf = False

    def current_servers(self) -> list[str]:
        """The resolver(s) in effect right before the tunnel's are published (the physical network's own DNS)."""
        out: list[str] = []
        # systemd-resolved: ask it directly for per-link DNS (skips the 127.0.0.53 stub).
        if self._has_resolved():
            rc, text = self.runner.run("resolvectl", ["status"])
            if rc == 0:
                for line in text.splitlines():
                    t = line.strip()
                    if t.startswith("DNS Servers:") or t.startswith("Current DNS Server:"):
                        for tok in t.split(":", 1)[1].split():
                            tok = tok.strip(",()")
                            if validation.is_ipv4_literal(tok):
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
        self.original_route: tuple[str | None, str] | None = None
        self.routing = RoutingConfig()
        self.tunnel_gateway: str | None = None
        self.captured_physical_dns: list[str] = []

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
        """Adds an explicit route for one IP/CIDR routing rule."""
        is_v6 = ":" in value
        prefix = "-6" if is_v6 else "-4"
        target = value if "/" in value else value + ("/128" if is_v6 else "/32")
        args = [prefix, "route", "add", target]
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
              dns_proxy_address: str | None = None) -> None:
        """`lease` is the bridge's Lease (ip/mask/router/dns/seconds/mtu as ints)."""
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
            self._add_route(["route", "replace", "0.0.0.0/1", "via", gw], ["route", "del", "0.0.0.0/1"])
            self._add_route(["route", "replace", "128.0.0.0/1", "via", gw], ["route", "del", "128.0.0.0/1"])
            for rule in self.routing.effective_rules:
                if rule.enabled and not rule.type.is_domain and rule.action != RoutingAction.proxy:
                    self._add_rule_route(rule.value, rule.action, iface, gw, orig)

        # Both halves of the IPv6 space point at the tunnel either way, so native IPv6 never leaks.
        self._add_route(["-6", "route", "replace", "::/1", "dev", iface], ["-6", "route", "del", "::/1"])
        self._add_route(["-6", "route", "replace", "8000::/1", "dev", iface], ["-6", "route", "del", "8000::/1"])

        # Captured before the resolver is switched over, so a `.direct` domain rule can still be
        # resolved by the physical network's own DNS once the DNS proxy is listening.
        if not self.routing.is_empty:
            self.captured_physical_dns = [s for s in self.dns.current_servers()
                                          if validation.is_ipv4_literal(s)]
            for server in self.captured_physical_dns:
                if not validation.is_local_address(server) and orig:
                    self._add_bypass_route(server, orig)

        if lease.dns:
            published = [dns_proxy_address] if dns_proxy_address else [ip_string(d) for d in lease.dns]
            if self.dns.set(published, iface, ip, gw):
                self.state.dns_set = True
                self._save()

    def direct_dns_servers(self) -> list[str]:
        return self.captured_physical_dns

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
        self._cleanup(self.state, self.runner, self.dns)
        self.state = None
        self.original_route = None
        self.tunnel_gateway = None
        self.captured_physical_dns = []
        self.routing = RoutingConfig()
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
        try:
            os.remove(state_file)
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
                }, f)
        except OSError:
            pass

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