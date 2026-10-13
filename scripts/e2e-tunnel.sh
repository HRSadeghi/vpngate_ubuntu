#!/bin/sh
# Real-tunnel end-to-end check (port of e2e-tunnel.sh): sudo required.
# Usage: sudo scripts/e2e-tunnel.sh <server-ip> [port]
set -e
cd "$(dirname "$0")/.."
IP=${1:?usage: e2e-tunnel.sh <server-ip> [port]}
PORT=${2:-443}
echo "== Foreground tunnel to $IP:$PORT (Ctrl-C restores routes/DNS) =="
python3 bin/vpngate-helper --connect "$IP" --port "$PORT"
