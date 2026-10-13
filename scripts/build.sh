#!/bin/sh
# Checks that everything compiles and the core protocol pieces import cleanly.
cd "$(dirname "$0")/.."
set -e
python3 -m compileall -q vpngate bin
python3 -W ignore - <<'EOF'
from vpngate.core.vgdat import parse
data = open("assets/VPNGate.dat", "rb").read()
f = parse(data)
print(f"bundled VPNGate.dat: {len(f.servers)} servers, signature valid")
EOF
echo "build check OK"
