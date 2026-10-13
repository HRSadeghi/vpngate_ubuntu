"""vpngate-helper entrypoint (port of the Swift main.swift).

Usage:
  vpngate-helper --daemon [--uid <uid>]        run as the systemd service, serve the app over a
                                               Unix socket (without --uid: whoever is logged in
                                               at the console may connect)
  vpngate-helper --connect <host> [--port N]   connect once in the foreground (debugging; sudo)
  vpngate-helper --probe <host> [--port N]     handshake + DHCP only, no tun/routes (no root)
      [--watch-udp [N]]                        keep the session open N s (default 20) afterwards,
                                               polling whether UDP acceleration became usable
  vpngate-helper --version
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from vpngate.core import validation
from vpngate.core.ipcmessages import HELPER_SOCKET_PATH, HELPER_VERSION, ConnectionState, ProxySettings
from vpngate.core.packets import ip_string
from vpngate.core.stream import StreamError
from vpngate.helper.bridge import EthernetBridge
from vpngate.helper.ipcserver import IPCServer, console_uid
from vpngate.helper.netconfig import NetConfig
from vpngate.helper.session import VPNSession
from vpngate.helper.softetherclient import SoftEtherClient
from vpngate.helper.tun import TunDevice


def parse_probe_args(argv: list[str]) -> tuple[str, int] | None:
    if "--probe" not in argv:
        return None
    i = argv.index("--probe")
    if i + 1 >= len(argv):
        return None
    port = 443
    if "--port" in argv:
        pi = argv.index("--port")
        if pi + 1 < len(argv):
            try:
                p = int(argv[pi + 1])
            except ValueError:
                p = -1
            if not validation.is_valid_port(p):
                return None
            port = p
    return argv[i + 1], port


def parse_watch_udp_seconds(argv: list[str]) -> int | None:
    if "--watch-udp" not in argv:
        return None
    i = argv.index("--watch-udp")
    if i + 1 >= len(argv):
        return 20
    try:
        n = int(argv[i + 1])
    except ValueError:
        return 20
    if n <= 0:
        return 20
    return min(n, 300)


def _use_large_executor() -> None:
    """The TLS streams block on executor threads (recv/sendall). With up to 32 pooled sockets
    the interpreter default (min(32, cpu+4)) can starve receives on busy machines."""
    from concurrent.futures import ThreadPoolExecutor
    loop = asyncio.get_running_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=32, thread_name_prefix="vpngate-io"))


async def probe_mode(host: str, port: int, watch_seconds: int | None) -> int:
    _use_large_executor()
    """--probe <host> [--port N]: handshake + DHCP only, no tun/routes, so it runs without root."""
    client = SoftEtherClient(host=host, port=port, proxy=ProxySettings())
    bridge = EthernetBridge()
    bridge.send_frame = client.send_frame
    client.on_frame = bridge.from_hub

    def log(m: str) -> None:
        print(f"  {m}", flush=True)

    try:
        w = await client.connect(log)
        print(f"OK session {w.session_name} timeout {w.timeout_ms}ms", flush=True)
        lease = await bridge.acquire_lease()
        print(f"OK lease ip {ip_string(lease.ip)} mask {ip_string(lease.mask)} "
              f"gw {ip_string(lease.router)} dns {[ip_string(d) for d in lease.dns]} "
              f"{lease.seconds}s", flush=True)
        if watch_seconds is not None:
            print(f"  UDP negotiated: {client.udp_accel_negotiated} — watching for {watch_seconds}s "
                  f"(needs ~10s stable receive before it carries data)", flush=True)
            became_usable_at = None
            for elapsed in range(1, watch_seconds + 1):
                await asyncio.sleep(1)
                if client.udp_accel_usable and became_usable_at is None:
                    became_usable_at = elapsed
                    print(f"  UDP became usable after {elapsed}s", flush=True)
            if became_usable_at is not None:
                print(f"OK udp usable after {became_usable_at}s "
                      f"(still usable: {client.udp_accel_usable})", flush=True)
            elif client.udp_accel_negotiated:
                print(f"FAIL udp negotiated by the server but never became usable in "
                      f"{watch_seconds}s (likely blocked/dropped on this network; TCP fallback is "
                      f"what carries traffic instead)", flush=True)
            else:
                print("OK udp not negotiated by this server; nothing to watch (TCP only)", flush=True)
        client.close(None)
        return 0
    except StreamError as e:
        print(f"FAIL {e.message}", flush=True)
        return 1
    except Exception as e:
        print(f"FAIL {e}", flush=True)
        return 1


async def connect_mode(host: str, port: int | None, allow_ipv6: bool) -> int:
    """Foreground tunnel for debugging (needs root); Ctrl-C restores routes/DNS."""
    _use_large_executor()
    session = VPNSession()

    def emit(e) -> None:
        if e.log:
            print(f"[{e.state.value}] {e.log}", flush=True)
        if e.error:
            print(f"[error] {e.error}", flush=True)
        if e.state == ConnectionState.connected and e.bytesIn == 0 and e.bytesOut == 0:
            print(f"[connected] virtual IP {e.virtualIP or '?'}", flush=True)

    session.emit = emit
    if not validation.is_valid_host(host):
        print("invalid host", flush=True)
        return 2
    session.connect_host(host=host, port=port, proxy=ProxySettings(), auto_reconnect=False,
                         block_ipv6=not allow_ipv6)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    session.disconnect()
    # Give the run task a moment to tear everything down.
    await session.wait_until_idle(timeout=5)
    return 0


async def daemon_mode(socket_path: str, fixed_uid: int | None) -> int:
    _use_large_executor()
    NetConfig.cleanup_stale()
    session = VPNSession()
    server = IPCServer(path=socket_path, allowed_uid=fixed_uid, session=session,
                       console_uid_fn=(lambda: None) if fixed_uid is not None else console_uid)
    await server.start()
    print(f"vpngate-helper listening on {socket_path}", flush=True)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    done: list[int] = []

    def request_shutdown() -> None:
        if not stop.is_set():
            stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, request_shutdown)
    # Signal handlers may not take locks or spawn processes: do the cleanup on the loop.
    shutdown_task = loop.create_task(_shutdown_when_signalled(stop, session, server, socket_path, done))
    await stop.wait()
    shutdown_task.cancel()
    return done[0] if done else 0


async def _shutdown_when_signalled(stop: asyncio.Event, session: VPNSession, server: IPCServer,
                                   socket_path: str, done: list[int]) -> None:
    await stop.wait()
    session.disconnect()
    await session.wait_until_idle(timeout=5)
    await server.stop()
    try:
        os.unlink(socket_path)
    except OSError:
        pass
    done.append(0)


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
    argv = list(argv if argv is not None else sys.argv[1:])
    if "--version" in argv:
        print(HELPER_VERSION)
        return 0

    probe = parse_probe_args(argv)
    if probe is not None:
        host, port = probe
        watch = parse_watch_udp_seconds(argv)
        return asyncio.run(probe_mode(host, port, watch))

    parser = argparse.ArgumentParser(prog="vpngate-helper", add_help=False)
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--connect")
    parser.add_argument("--port", type=int)
    parser.add_argument("--socket")
    parser.add_argument("--uid", type=int)
    parser.add_argument("--allow-ipv6", action="store_true")
    args, _unknown = parser.parse_known_args(argv)

    socket_path = args.socket or HELPER_SOCKET_PATH

    if args.connect:
        # Only creating the tunnel needs root; the daemon itself starts anywhere.
        if os.getuid() != 0:
            sys.stderr.write("vpngate-helper must run as root (use sudo)\n")
            return 1
        return asyncio.run(connect_mode(args.connect, args.port, args.allow_ipv6))
    if args.daemon:
        return asyncio.run(daemon_mode(socket_path, args.uid))
    print("usage: vpngate-helper --daemon --uid <uid> | --connect <host> [--port N]")
    return 2


if __name__ == "__main__":
    sys.exit(main())