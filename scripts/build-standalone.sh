#!/usr/bin/env bash
# Builds standalone executables into dist/ — no Python needed on the target machine.
#
#   dist/vpngate          the GTK app (Python + GTK/PyGObject bundled)
#   dist/vpngate-helper   the privileged service (run as root; still installed via
#                         scripts/install-helper.sh or a Windows/Linux service)
#
# Requirements (build host only): /usr/bin/python3 with GTK 3 bindings and
#   /usr/bin/python3 -m pip install --user pyinstaller pyinstaller-hooks-contrib
#
# Sizes (Ubuntu 22.04): helper ~8 MB, app ~106 MB (GTK + typelibs bundled).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-/usr/bin/python3}"
DIST="$ROOT/dist"
WORK="$ROOT/build/pyi"

"$PY" -c "import PyInstaller" 2>/dev/null || {
    echo "PyInstaller is missing. Install it with:" >&2
    echo "  $PY -m pip install --user pyinstaller pyinstaller-hooks-contrib" >&2
    exit 1
}
"$PY" -c "import gi; gi.require_version('Gtk', '3.0')" 2>/dev/null || {
    echo "GTK 3 Python bindings are missing: sudo apt install python3-gi gir1.2-gtk-3.0" >&2
    exit 1
}

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"

echo "== vpngate-helper (root service) =="
"$PY" -m PyInstaller --noconfirm --clean --onefile \
    --name vpngate-helper \
    --distpath "$DIST" --workpath "$WORK/helper" \
    --paths "$ROOT" \
    "$ROOT/vpngate/helper/__main__.py"

echo "== vpngate (GTK app) =="
"$PY" -m PyInstaller --noconfirm --clean --onefile --windowed \
    --name vpngate \
    --distpath "$DIST" --workpath "$WORK/app" \
    --paths "$ROOT" \
    --hidden-import cairo \
    --hidden-import gi.repository.GObject \
    --hidden-import gi.repository.GLib \
    --hidden-import gi.repository.Gio \
    --hidden-import gi.repository.Gdk \
    --hidden-import gi.repository.Gtk \
    --hidden-import gi.repository.Pango \
    --hidden-import gi.repository.GdkPixbuf \
    "$ROOT/bin/vpngate"

echo
echo "done:"
ls -lh "$DIST/vpngate" "$DIST/vpngate-helper"
echo
echo "smoke-test with:  $DIST/vpngate-helper --version && $DIST/vpngate"
