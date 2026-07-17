#!/usr/bin/env bash
set -eu

TARGET=/home/cupcup/data/openharmony-data/repos/communication_dhcp
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD"

COMMON_FLAGS=(
  -std=c++17 -DOHOS_ARCH_LITE -include vector -include mutex -include algorithm
  -fsanitize=memory -fsanitize-memory-track-origins=2
  -fPIE -fno-omit-frame-pointer -O1 -g
  -I"$ROOT/stubs"
  -I"$TARGET/services"
  -I"$TARGET/frameworks/native/include"
  -I"$TARGET/frameworks/native/interfaces"
  -I"$TARGET/interfaces"
  -I"$TARGET/interfaces/inner_api"
  -I"$TARGET/interfaces/inner_api/include"
  -I"$TARGET/interfaces/kits/c"
  -I"$TARGET/services/dhcp_client/include"
  -I"$TARGET/services/dhcp_server/include"
  -I"$TARGET/services/utils/include"
)

clang++ "${COMMON_FLAGS[@]}" -c "$TARGET/frameworks/native/src/dhcp_event.cpp" -o "$BUILD/dhcp_event.o"
clang++ "${COMMON_FLAGS[@]}" -c "$ROOT/driver.cpp" -o "$BUILD/driver.o"
clang++ -fsanitize=memory -fsanitize-memory-track-origins=2 -pie \
  "$BUILD/dhcp_event.o" "$BUILD/driver.o" -o "$BUILD/dhcp_event_uninitialized"

"$BUILD/dhcp_event_uninitialized"
