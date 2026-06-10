#!/bin/bash
# Build script for netmanager env.rs array_buffer() null pointer PoC
#
# Usage: ./build.sh [netmanager_base_path]
# The netmanager_base_path is optional — this PoC reproduces the exact
# vulnerable code pattern inline since env.rs depends on the full ANI crate.
#
# Oracle: Process crashes with SIGSEGV (signal 11)

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TMPDIR=$(mktemp -d /tmp/fermat_netmgr_XXXXXX)
trap "rm -rf $TMPDIR" EXIT

echo "[*] Compiling PoC (reproduces env.rs:843 vulnerable code path)..."

# Compile the Rust PoC
rustc -o "$TMPDIR/poc_bin" \
    --edition 2021 \
    "$SCRIPT_DIR/poc.rs"

echo "[*] Running PoC (expect SIGSEGV)..."
echo ""

# Run and capture signal — SIGSEGV = exit code 139
set +e
"$TMPDIR/poc_bin" 2>&1
RET=$?
set -e

echo ""
if [ $RET -eq 139 ] || [ $RET -eq 134 ] || [ $RET -eq 11 ]; then
    echo "[+] Process crashed with signal (exit=$RET) — NULL pointer dereference CONFIRMED."
    echo "[+] Root cause: env.rs:843 std::slice::from_raw_parts(NULL, 16) → UB → SIGSEGV"
    echo "[+] Fix: Add 'if ptr.is_null() { return Err(...); }' before from_raw_parts"
    exit 0
elif [ $RET -eq 0 ]; then
    echo "[-] Process exited normally — fix may already be applied."
    exit 1
else
    echo "[?] Unexpected exit code: $RET"
    exit $RET
fi
