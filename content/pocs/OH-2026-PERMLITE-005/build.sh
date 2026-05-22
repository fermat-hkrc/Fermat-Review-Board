#!/bin/bash
# Build script for OH-2026-PERMLITE-005 PoC
# Requires: gn, ninja, clang with ASan support, ~/data/ohos-build-toolkit/
#
# Prerequisites:
#   1. OHOS repos at ~/data/openharmony-data/repos/
#   2. Permission lite source at ~/data/test-repos/permission_lite/
#   3. Build toolkit at ~/data/ohos-build-toolkit/

set -e

TOOLKIT=~/data/ohos-build-toolkit
BUILD_DIR=/tmp/ohos_build_prod

# Step 1: Setup build root (if not already done)
if [ ! -d "$BUILD_DIR" ]; then
    python3 "$TOOLKIT/setup_build.py" \
        --source ~/data/test-repos/permission_lite \
        --output "$BUILD_DIR"
fi

# Step 2: Copy PoC driver and build files
cp poc.c "$BUILD_DIR/test/server_test_driver.c"
cp build_test_gn.txt "$BUILD_DIR/test/BUILD.gn"

# Step 3: Build
cd "$BUILD_DIR"
gn gen out/default
ninja -C out/default

echo ""
echo "Build complete. Run with:"
echo "  $BUILD_DIR/out/default/obj/test/server_poc"
