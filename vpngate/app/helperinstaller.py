"""Helper installation (systemd) and launch-at-login (autostart) for the Ubuntu port
(ports of HelperInstaller.swift and LoginItem.swift)."""

from __future__ import annotations

import os
import shutil
import subprocess

from ..core.ipcmessages import HELPER_SOCKET_PATH

HELPER_LABEL = "vpngate-helper"
HELPER_INSTALLED_PATH = "/usr/local/bin/vpngate-helper"
SERVICE_PATH = f"/etc/systemd/system/{HELPER_LABEL}.service"

SERVICE_UNIT = f"""\
[Unit]
Description=VPN Gate privileged helper
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={HELPER_INSTALLED_PATH} --daemon
Restart=always
RestartSec=2
StandardOutput=append:/var/log/vpngate-helper.log
StandardError=append:/var/log/vpngate-helper.log

[Install]
WantedBy=multi-user.target
"""


def is_installed() -> bool:
    return os.path.exists(SERVICE_PATH) or os.path.exists(HELPER_INSTALLED_PATH)


def helper_running() -> bool:
    """True when the systemd service is active (or a helper is listening on the socket)."""
    systemctl = shutil.which("systemctl")
    if systemctl:
        r = subprocess.run([systemctl, "is-active", "--quiet", HELPER_LABEL],
                           capture_output=True)
        if r.returncode == 0:
            return True
    import socket as s
    try:
        test = s.socket(s.AF_UNIX, s.SOCK_STREAM)
        test.connect(HELPER_SOCKET_PATH)
        test.close()
        return True
    except OSError:
        return False


def shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _run_admin(script: str) -> None:
    """Runs a shell script with administrator rights (pkexec on Ubuntu, sudo as fallback)."""
    for tool in ("pkexec", "sudo"):
        path = shutil.which(tool)
        if not path:
            continue
        r = subprocess.run([path, "/bin/sh", "-c", script], capture_output=True, text=True)
        if r.returncode == 0:
            return
        raise OSError(r.stderr.strip() or "Installation cancelled")
    raise OSError("Neither pkexec nor sudo is available")


def install_helper() -> None:
    """Installs the helper launcher, the Python package, the bundled list and the systemd
    service (asks for the password once)."""
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    script = f"""
set -e
install -d -m 755 /usr/local/bin /usr/local/lib/vpngate /usr/local/share/vpngate
install -m 755 {shell_quote(os.path.join(here, "bin", "vpngate-helper"))} {shell_quote(HELPER_INSTALLED_PATH)}
rm -rf /usr/local/lib/vpngate/vpngate
cp -R {shell_quote(os.path.join(here, "vpngate"))} /usr/local/lib/vpngate/vpngate
find /usr/local/lib/vpngate/vpngate -name '__pycache__' -type d -exec rm -rf {{}} + 2>/dev/null || true
install -m 644 {shell_quote(os.path.join(here, "assets", "VPNGate.dat"))} /usr/local/share/vpngate/VPNGate.dat
install -m 644 {shell_quote(os.path.join(here, "assets", "AppIcon-256.png"))} /usr/local/share/vpngate/AppIcon-256.png
cat > {shell_quote(SERVICE_PATH)} <<'UNIT'
{SERVICE_UNIT}UNIT
chmod 700 /var/lib/vpngate 2>/dev/null || mkdir -p /var/lib/vpngate && chmod 700 /var/lib/vpngate
systemctl daemon-reload
systemctl enable {HELPER_LABEL}.service 2>/dev/null || true
systemctl restart {HELPER_LABEL}.service
"""
    _run_admin(script)


def uninstall() -> None:
    """Stops and removes the helper service and its files."""
    script = f"""
systemctl disable --now {HELPER_LABEL}.service 2>/dev/null || true
rm -f {shell_quote(SERVICE_PATH)} {shell_quote(HELPER_INSTALLED_PATH)} {shell_quote(HELPER_SOCKET_PATH)}
systemctl daemon-reload 2>/dev/null || true
"""
    _run_admin(script)


# MARK: launch at login (autostart .desktop, the Linux LoginItem equivalent)

AUTOSTART_DIR = os.path.expanduser("~/.config/autostart")


def autostart_path() -> str:
    return os.path.join(AUTOSTART_DIR, "vpngate.desktop")


def login_item_status() -> str:
    if os.path.exists(autostart_path()):
        return "enabled"
    return "notRegistered"


def register_login_item(app_command: str) -> None:
    os.makedirs(AUTOSTART_DIR, exist_ok=True)
    desktop = f"""\
[Desktop Entry]
Type=Application
Name=VPN Gate
Exec={app_command}
X-GNOME-Autostart-enabled=true
NoDisplay=false
"""
    with open(autostart_path(), "w") as f:
        f.write(desktop)


def unregister_login_item() -> None:
    try:
        os.remove(autostart_path())
    except FileNotFoundError:
        pass