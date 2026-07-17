#!/usr/bin/env bash
set -eu

TARGET=/home/cupcup/data/openharmony-data/repos/communication_dhcp
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD"

COMMON=(
  -std=c++17 -O1 -g -include algorithm -include mutex -include atomic -include memory
  -I"$ROOT/stubs"
  -I"$TARGET/frameworks/native/include"
  -I"$TARGET/frameworks/native/interfaces"
  -I"$TARGET/frameworks/native/src"
  -I"$TARGET/interfaces"
  -I"$TARGET/interfaces/inner_api"
  -I"$TARGET/interfaces/inner_api/include"
  -I"$TARGET/interfaces/kits/c"
  -I"$TARGET/services"
  -I"$TARGET/services/dhcp_server/include"
)

clang++ "${COMMON[@]}" -c "$TARGET/services/dhcp_server/src/dhcp_server_callback_proxy.cpp" -o "$BUILD/proxy.o"
clang++ "${COMMON[@]}" -c "$TARGET/frameworks/native/src/dhcp_server_callback_stub.cpp" -o "$BUILD/stub.o"
clang++ "${COMMON[@]}" -c "$ROOT/driver.cpp" -o "$BUILD/driver.o"
clang++ "$BUILD/proxy.o" "$BUILD/stub.o" "$BUILD/driver.o" -o "$BUILD/dhcp_server_callback_wire"
"$BUILD/dhcp_server_callback_wire"
