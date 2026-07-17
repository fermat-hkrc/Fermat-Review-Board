#!/usr/bin/env bash
set -eu

TARGET=/home/cupcup/data/openharmony-data/repos/communication_dhcp
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD"

COMMON=(
  -std=c++17 -O1 -g -include vector -include mutex
  -I"$ROOT/stubs"
  -I"$TARGET/services/dhcp_client/include"
  -I"$TARGET/services/utils/include"
  -I"$TARGET/frameworks/native/include"
  -I"$TARGET/interfaces"
  -I"$TARGET/interfaces/inner_api"
  -I"$TARGET/interfaces/inner_api/include"
  -I"$TARGET/interfaces/kits/c"
  -I"$TARGET/services"
)

clang++ "${COMMON[@]}" -c "$TARGET/services/dhcp_client/src/dhcp_result_store_manager.cpp" -o "$BUILD/store.o"
clang++ "${COMMON[@]}" -c "$ROOT/driver.cpp" -o "$BUILD/driver.o"
clang++ "$BUILD/store.o" "$BUILD/driver.o" -Wl,--wrap=fwrite -o "$BUILD/dhcp_cache_write_loss"
"$BUILD/dhcp_cache_write_loss"
