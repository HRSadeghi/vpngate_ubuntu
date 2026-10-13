#!/bin/sh
# Runs the test suite (no network, no root), like scripts/test.sh in the macOS project.
cd "$(dirname "$0")/.."
exec python3 -m unittest discover -s tests -v "$@"
