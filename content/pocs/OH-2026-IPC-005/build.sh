#!/bin/bash
# Build script for OH-2026-IPC-005 PoC (target-compile)
#
# Usage: ./build.sh <sensors_sensor_lite_path> <toolkit-stubs-path>

set -e
TARGET="${1:?Usage: $0 <sensors_sensor_lite_path> <toolkit-stubs-path>}"
STUBS="${2:?Missing toolkit-stubs-path}"

TMPDIR=$(mktemp -d /tmp/fermat_ipc005_XXXXXX)
trap "rm -rf $TMPDIR" EXIT

echo "[*] Compiling real sensor_agent_proxy.c ..."
gcc -c -Dstatic= -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$TARGET/interfaces/kits/native/include" \
    -I "$TARGET/frameworks/include" \
    -I "$TARGET/services/include" \
    -I "$STUBS" \
    "$TARGET/frameworks/src/sensor_agent_proxy.c" \
    -o "$TMPDIR/sensor_agent_proxy.o"

echo "[*] Compiling stubs ..."
gcc -c -fsanitize=address -fno-omit-frame-pointer -O0 \
    -I "$STUBS" "$STUBS/ohos_stubs.c" -o "$TMPDIR/ohos_stubs.o"
gcc -c -fsanitize=address -fno-omit-frame-pointer -O0 \
    -I "$STUBS" "$STUBS/cJSON.c" -o "$TMPDIR/cJSON.o"

echo "[*] Compiling memcpy_s stub ..."
echo '#include <string.h>
int memcpy_s(void *d, size_t ds, const void *s, size_t n) {
    if (!d || !s || n > ds) return 1;
    memcpy(d, s, n); return 0;
}' | gcc -c -O0 -x c - -o "$TMPDIR/memcpy_s.o"

echo "[*] Compiling test driver ..."
gcc -c -Dstatic= -fsanitize=address -fno-omit-frame-pointer -O0 -g \
    -I "$TARGET/interfaces/kits/native/include" \
    -I "$TARGET/frameworks/include" \
    -I "$TARGET/services/include" \
    -I "$STUBS" \
    "$(dirname "$0")/poc.c" \
    -o "$TMPDIR/poc.o"

echo "[*] Linking ..."
g++ -O0 -fsanitize=address -fno-omit-frame-pointer \
    -o "$TMPDIR/poc_bin" \
    "$TMPDIR/sensor_agent_proxy.o" \
    "$TMPDIR/cJSON.o" \
    "$TMPDIR/ohos_stubs.o" \
    "$TMPDIR/memcpy_s.o" \
    "$TMPDIR/poc.o" \
    -lpthread -lstdc++

echo "[*] Running PoC ..."
"$TMPDIR/poc_bin"
echo "[*] Done (exit=$?)"
