#!/bin/bash
# Build script for OH-2026-IPC-008 PoC
#
# Target: OpenHarmony bundle_framework_lite BundleManagerService
# Vuln:   HandleGetBundleInfosByIndex unchecked index → OOB/nullptr crash
#
# Prerequisites:
#   - OpenHarmony LiteOS-A SDK with cross-compilation toolchain
#   - Or: host clang with stubs for local ASan verification
#
# Usage:
#   Cross-compile for device: ./build.sh device <OH_SDK_PATH>
#   Local ASan verification:  ./build.sh local <toolkit-stubs-path>

set -e
MODE="${1:-local}"
TOOLKIT="${2:?Usage: $0 <device|local> <sdk-or-stubs-path>}"

TMPDIR=$(mktemp -d /tmp/fermat_ipc008_XXXXXX)
trap "rm -rf $TMPDIR" EXIT

if [ "$MODE" = "device" ]; then
    echo "[*] Cross-compiling for OpenHarmony LiteOS-A target ..."
    arm-linux-ohos-clang "$(dirname "$0")/poc.c" -o "$TMPDIR/poc_bms_crash" \
        -I"${TOOLKIT}/sysroot/usr/include" \
        -lsamgr_proxy -lipc_single -lbundle_lite

    echo "[*] Binary: $TMPDIR/poc_bms_crash"
    echo "[*] Deploy: hdc file send $TMPDIR/poc_bms_crash /tmp/"
    echo "[*]         hdc shell chmod +x /tmp/poc_bms_crash"
    echo "[*]         hdc shell /tmp/poc_bms_crash"

elif [ "$MODE" = "local" ]; then
    STUBS="$TOOLKIT"
    echo "[*] Compiling with stubs for local ASan verification ..."

    echo "[*] Compiling OHOS IPC/SAMGR stubs ..."
    clang -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
        -I "$STUBS" "$STUBS/ohos_stubs.c" -o "$TMPDIR/ohos_stubs.o"

    echo "[*] Compiling PoC driver ..."
    clang -c -fsanitize=address -fno-omit-frame-pointer -O0 -g \
        -I "$STUBS" \
        "$(dirname "$0")/poc.c" \
        -o "$TMPDIR/poc.o"

    echo "[*] Linking ..."
    clang++ -O0 -fsanitize=address -fno-omit-frame-pointer \
        -o "$TMPDIR/poc_bin" \
        "$TMPDIR/ohos_stubs.o" \
        "$TMPDIR/poc.o" \
        -lpthread

    echo "[*] Running PoC ..."
    "$TMPDIR/poc_bin"
    echo "[*] Done (exit=$?)"
fi
