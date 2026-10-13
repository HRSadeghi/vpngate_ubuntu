#!/bin/sh
# Installs the privileged helper (the LaunchDaemon equivalent) as a systemd service:
# the launcher -> /usr/local/bin, the Python package -> /usr/local/lib/vpngate,
# assets -> /usr/local/share/vpngate. Run once; the app offers to run it again if the
# helper is missing or outdated.
set -e

HERE=$(cd "$(dirname "$0")/.." && pwd)

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
elif command -v pkexec >/dev/null 2>&1; then
  SUDO="pkexec"
elif command -v sudo >/dev/null 2>&1; then
  SUDO="sudo"
else
  echo "need root (pkexec or sudo)" >&2
  exit 1
fi

$SUDO sh -c "
set -e
install -d -m 755 /usr/local/bin /usr/local/lib/vpngate /usr/local/share/vpngate
install -m 755 '$HERE/bin/vpngate-helper' /usr/local/bin/vpngate-helper
rm -rf /usr/local/lib/vpngate/vpngate
cp -R '$HERE/vpngate' /usr/local/lib/vpngate/vpngate
find /usr/local/lib/vpngate/vpngate -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
install -m 644 '$HERE/assets/VPNGate.dat' /usr/local/share/vpngate/VPNGate.dat
install -m 644 '$HERE/assets/AppIcon-256.png' /usr/local/share/vpngate/AppIcon-256.png
install -m 644 '$HERE/packaging/vpngate-helper.service' /etc/systemd/system/vpngate-helper.service
mkdir -p /var/lib/vpngate && chmod 700 /var/lib/vpngate
systemctl daemon-reload
systemctl enable vpngate-helper.service 2>/dev/null || true
systemctl restart vpngate-helper.service
"

echo "vpngate-helper installed and started (systemctl status vpngate-helper)"
