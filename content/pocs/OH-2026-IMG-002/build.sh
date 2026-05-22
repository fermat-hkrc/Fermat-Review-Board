#!/bin/bash
# Build script for OH-2026-IMG-002 PoC (target-compile)
#
# Usage: ./build.sh <multimedia_image_framework_path>

set -e
TARGET="${1:?Usage: $0 <multimedia_image_framework_path>}"

SRCDIR="$TARGET/plugins/common/libs/image/libpngplugin/src"
INCDIR="$TARGET/plugins/common/libs/image/libpngplugin/include"
STUBDIR="$(dirname "$0")/stubs"
TMPDIR=$(mktemp -d /tmp/fermat_img002_XXXXXX)
trap "rm -rf $TMPDIR" EXIT

echo "[*] Compiling real png_ninepatch_res.cpp ..."
g++ -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$INCDIR" \
    -I "$STUBDIR" \
    "$SRCDIR/png_ninepatch_res.cpp" \
    -o "$TMPDIR/png_ninepatch_res.o"

echo "[*] Compiling test driver ..."
g++ -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$INCDIR" \
    -I "$STUBDIR" \
    "$(dirname "$0")/poc.cpp" \
    -o "$TMPDIR/poc.o"

echo "[*] Linking ..."
g++ -O0 -fsanitize=address -fno-omit-frame-pointer \
    -o "$TMPDIR/poc_bin" \
    "$TMPDIR/png_ninepatch_res.o" \
    "$TMPDIR/poc.o" \
    -lstdc++

echo "[*] Running PoC ..."
"$TMPDIR/poc_bin" 2>&1
echo "[*] Done (exit=$?)"
