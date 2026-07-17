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

clang++ "${COMMON[@]}" -c "$ROOT/harness.cpp" -o "$BUILD/harness.o"
clang++ "${COMMON[@]}" -c "$ROOT/driver.cpp" -o "$BUILD/driver.o"
clang++ -Wl,--gc-sections -Wl,--wrap=sendto "$BUILD/harness.o" "$BUILD/driver.o" -o "$BUILD/dhcp_send_failure"
"$BUILD/dhcp_send_failure"
