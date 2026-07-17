#!/usr/bin/env bash
set -eu

TARGET=/home/cupcup/data/openharmony-data/repos/communication_dhcp
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD"

COMMON=(
  -std=c++17 -O1 -g -ffunction-sections -fdata-sections -include vector
  -I"$ROOT/stubs"
  -I"$TARGET/services"
  -I"$TARGET/services/dhcp_server/include"
  -I"$TARGET/services/dhcp_client/include"
  -I"$TARGET/services/utils/include"
  -I"$TARGET/interfaces/inner_api/include"
)

clang++ "${COMMON[@]}" -c "$TARGET/services/dhcp_server/src/dhcp_s_server.cpp" -o "$BUILD/server.o"
clang++ "${COMMON[@]}" -c "$TARGET/services/dhcp_server/src/dhcp_option.cpp" -o "$BUILD/option.o"
clang++ "${COMMON[@]}" -c "$ROOT/driver.cpp" -o "$BUILD/driver.o"
clang++ -Wl,--gc-sections "$BUILD/server.o" "$BUILD/option.o" "$BUILD/driver.o" -o "$BUILD/dhcp_hostname_stale"
"$BUILD/dhcp_hostname_stale"
