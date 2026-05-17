#!/bin/bash
set -e

TOOLKIT=~/data/ohos-build-toolkit
BUILD_DIR=/tmp/castengine_build

if [ ! -d "$BUILD_DIR" ]; then
    python3 "$TOOLKIT/setup_build.py" \
        --source ~/data/test-repos/castengine_wifi_display \
        --output "$BUILD_DIR"
    # Copy third_party from existing build
    cp -r /tmp/ohos_build_prod/third_party "$BUILD_DIR/" 2>/dev/null || true
    # Copy updated C++ configs
    cp "$TOOLKIT/custom_build/configs/BUILD.gn" "$BUILD_DIR/custom_build/configs/BUILD.gn"
fi

cd "$BUILD_DIR"
gn gen out/default
ninja -C out/default

echo ""
echo "Run: $BUILD_DIR/out/default/obj/test/data_buffer_poc"
