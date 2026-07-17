#!/usr/bin/env bash
set -eu

TARGET=/home/cupcup/data/openharmony-data/repos/communication_dhcp
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD"

COMMON_FLAGS=(
  -std=c++17 -include vector -O0 -g
  -I"$ROOT/stubs"
  -I"$TARGET/services/dhcp_server/include"
  -I"$TARGET/interfaces/inner_api/include"
)

clang++ "${COMMON_FLAGS[@]}" -c "$TARGET/services/dhcp_server/src/address_utils.cpp" -o "$BUILD/address_utils.o"
clang++ "${COMMON_FLAGS[@]}" -c "$ROOT/driver.cpp" -o "$BUILD/driver.o"
clang++ "$BUILD/address_utils.o" "$BUILD/driver.o" -o "$BUILD/dhcp_network_order"
"$BUILD/dhcp_network_order"
