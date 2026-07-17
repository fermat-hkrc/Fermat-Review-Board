#!/usr/bin/env bash
set -eu

TARGET=/home/cupcup/data/openharmony-data/repos/communication_dhcp
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD"

COMMON_FLAGS=(
  -std=c++17 -DOHOS_ARCH_LITE -include vector
  -O0 -g -fno-omit-frame-pointer
  -I"$ROOT/stubs"
  -I"$TARGET/services"
  -I"$TARGET/services/dhcp_client/include"
  -I"$TARGET/interfaces/inner_api/include"
  -I"$TARGET/interfaces/kits/c"
)

clang++ "${COMMON_FLAGS[@]}" -c "$TARGET/services/dhcp_client/src/dhcp_options.cpp" -o "$BUILD/dhcp_options.o"
clang++ "${COMMON_FLAGS[@]}" -c "$ROOT/driver.cpp" -o "$BUILD/driver.o"
clang++ "$BUILD/dhcp_options.o" "$BUILD/driver.o" -o "$BUILD/dhcp_option_overload"
"$BUILD/dhcp_option_overload"
