#!/bin/bash
# Build script for OH-2026-DEVAUTH-PTR-001 PoC 
#
# This PoC extracts and simulates the vulnerable IPC callback stub
# without requiring the full device_auth source tree.
#
# Usage: ./build.sh

set -e
DIR="$(dirname "$0")"

echo "[*] Compiling PoC ..."
clang -g -O0 "$DIR/poc.c" -o "$DIR/poc_devauth_ptr_001"

echo "[*] Running PoC ..."
"$DIR/poc_devauth_ptr_001"
echo "[*] Done (exit=$?)"
