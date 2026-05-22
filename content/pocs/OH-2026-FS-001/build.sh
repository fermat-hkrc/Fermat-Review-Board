#!/bin/bash
# Build script for OH-2026-FS-001 PoC
# Requires: gn, ninja, clang with ASan, ~/data/ohos-build-toolkit/

set -e

TOOLKIT=~/data/ohos-build-toolkit
BUILD_DIR=/tmp/cfg_policy_build

if [ ! -d "$BUILD_DIR" ]; then
    python3 "$TOOLKIT/setup_build.py" \
        --source ~/data/test-repos/customization_config_policy \
        --output "$BUILD_DIR"
    cp -r /tmp/ohos_build_prod/third_party "$BUILD_DIR/" 2>/dev/null || true
fi

cd "$BUILD_DIR"
gn gen out/default
ninja -C out/default

echo ""
echo "Run: $BUILD_DIR/out/default/obj/test/cfg_policy_poc"
