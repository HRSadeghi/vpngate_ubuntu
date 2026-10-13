#!/bin/sh
# Removes the helper service and its files.
set -e
if [ "$(id -u)" -eq 0 ]; then SUDO=""; elif command -v pkexec >/dev/null 2>&1; then SUDO="pkexec"; else SUDO="sudo"; fi

$SUDO sh -c "
systemctl disable --now vpngate-helper.service 2>/dev/null || true
rm -f /etc/systemd/system/vpngate-helper.service /usr/local/bin/vpngate-helper /var/run/vpngate-helper.sock
rm -rf /usr/local/lib/vpngate/vpngate
systemctl daemon-reload 2>/dev/null || true
"
echo "vpngate-helper removed"
