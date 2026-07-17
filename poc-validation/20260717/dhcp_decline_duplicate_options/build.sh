#!/usr/bin/env bash
set -eu

TARGET=/home/cupcup/data/openharmony-data/repos/communication_dhcp
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD"

COMMON=(
  -std=c++17 -DOHOS_ARCH_LITE -O1 -g -ffunction-sections -fdata-sections
  -include cinttypes -include functional -include vector -include memory -include mutex -include atomic -include algorithm
  -DVENDOR_NAME_PREFIX=\"OpenHarmony\" -DDEFAULT_IPV4_DNS_PRI=\"1.1.1.1\" -DDEFAULT_IPV4_DNS_SEC=\"8.8.8.8\"
  -I"$ROOT/stubs"
  -I"$TARGET/services"
  -I"$TARGET/services/dhcp_client/include"
  -I"$TARGET/services/dhcp_server/include"
  -I"$TARGET/services/utils/include"
  -I"$TARGET/interfaces/inner_api/include"
  -I"$TARGET/interfaces/kits/c"
)

clang++ "${COMMON[@]}" -c "$ROOT/harness.cpp" -o "$BUILD/harness.o"
clang++ "${COMMON[@]}" -c "$TARGET/services/dhcp_client/src/dhcp_options.cpp" -o "$BUILD/options.o"
clang++ "${COMMON[@]}" -c "$ROOT/driver.cpp" -o "$BUILD/driver.o"
clang++ -Wl,--gc-sections "$BUILD/harness.o" "$BUILD/options.o" "$BUILD/driver.o" -o "$BUILD/dhcp_decline_duplicate_options"
"$BUILD/dhcp_decline_duplicate_options"
