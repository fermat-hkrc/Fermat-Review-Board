#!/bin/bash
# Build script for OH-2026-IMG-001 PoC (target-compile)
#
# Usage: ./build.sh <multimedia_image_framework_path>

set -e
TARGET="${1:?Usage: $0 <multimedia_image_framework_path>}"

SRCDIR="$TARGET/plugins/common/libs/image/libextplugin/src/jpeg_yuv_decoder"
INCDIR="$TARGET/plugins/common/libs/image/libextplugin/include/jpeg_yuv_decoder"
STUBDIR="$(dirname "$0")/stubs"
TMPDIR=$(mktemp -d /tmp/fermat_img001_XXXXXX)
trap "rm -rf $TMPDIR" EXIT

echo "[*] Compiling real jpeg_yuvdata_converter.cpp ..."
clang++ -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$INCDIR" \
    -I "$STUBDIR" \
    "$SRCDIR/jpeg_yuvdata_converter.cpp" \
    -o "$TMPDIR/jpeg_yuvdata_converter.o"

echo "[*] Compiling real yuv_helper.cpp ..."
clang++ -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$INCDIR" \
    -I "$STUBDIR" \
    "$SRCDIR/yuv_helper.cpp" \
    -o "$TMPDIR/yuv_helper.o"

echo "[*] Compiling test driver ..."
clang++ -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$INCDIR" \
    -I "$STUBDIR" \
    "$(dirname "$0")/poc.cpp" \
    -o "$TMPDIR/poc.o"

echo "[*] Linking ..."
clang++ -O0 -fsanitize=address -fno-omit-frame-pointer \
    -o "$TMPDIR/poc_bin" \
    "$TMPDIR/jpeg_yuvdata_converter.o" \
    "$TMPDIR/yuv_helper.o" \
    "$TMPDIR/poc.o" \
    -ldl -lstdc++

echo "[*] Running PoC ..."
"$TMPDIR/poc_bin" 2>&1
echo "[*] Done (exit=$?)"
