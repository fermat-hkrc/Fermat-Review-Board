#!/usr/bin/env bash
set -eu

TARGET=/home/cupcup/data/openharmony-data/repos/communication_dhcp
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD"

COMMON=(
  -std=c++17 -DOHOS_ARCH_LITE -include memory -include vector -include mutex -include atomic
  -I"$ROOT/stubs"
  -I"$TARGET/frameworks/native/include"
  -I"$TARGET/frameworks/native/interfaces"
  -I"$TARGET/frameworks/native/src"
  -I"$TARGET/interfaces"
  -I"$TARGET/interfaces/inner_api"
  -I"$TARGET/interfaces/inner_api/include"
  -I"$TARGET/interfaces/kits/c"
  -I"$TARGET/services"
  -I"$TARGET/services/dhcp_client/include"
  -I"$TARGET/services/utils/include"
)

clang++ "${COMMON[@]}" -c "$TARGET/frameworks/native/src/dhcp_client_proxy_lite.cpp" -o "$BUILD/proxy.o"
clang++ "${COMMON[@]}" -c "$TARGET/services/dhcp_client/src/dhcp_client_stub_lite.cpp" -o "$BUILD/stub.o"
clang++ "${COMMON[@]}" -c "$ROOT/callback_shim.cpp" -o "$BUILD/callback_shim.o"
clang++ "${COMMON[@]}" -c "$ROOT/driver.cpp" -o "$BUILD/driver.o"
clang++ "$BUILD/proxy.o" "$BUILD/stub.o" "$BUILD/callback_shim.o" "$BUILD/driver.o" -o "$BUILD/dhcp_client_lite_wire"
"$BUILD/dhcp_client_lite_wire"
