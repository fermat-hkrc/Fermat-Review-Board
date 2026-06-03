#!/bin/bash
# Build script for OH-2026-DEVAUTH-PTR-001 PoC (standalone)
#
# This PoC is standalone — it simulates the vulnerable IPC callback stub
# without requiring the full device_auth source tree.
#
# Usage: ./build.sh

set -e
DIR="$(dirname "$0")"

echo "[*] Compiling standalone PoC ..."
gcc -g -O0 "$DIR/poc.c" -o "$DIR/poc_devauth_ptr_001"

echo "[*] Running PoC ..."
"$DIR/poc_devauth_ptr_001"
echo "[*] Done (exit=$?)"
