#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
dashboard_root="$(cd "$root/../../.." && pwd)"
target="${COMMUNICATION_DHCP_ROOT:-}"
if [[ -z "$target" || ! -d "$target" ]]; then
  printf 'Set COMMUNICATION_DHCP_ROOT to the target checkout.\n' >&2
  exit 2
fi
test_root="$dashboard_root/poc-validation/20260717/dhcp_decline_duplicate_options"
build="$test_root/build"
mkdir -p "$build"

common=(
  -std=c++17 -DOHOS_ARCH_LITE -O1 -g -ffunction-sections -fdata-sections
  -include cinttypes -include functional -include vector -include memory -include mutex -include atomic -include algorithm
  '-DVENDOR_NAME_PREFIX="OpenHarmony"' '-DDEFAULT_IPV4_DNS_PRI="1.1.1.1"' '-DDEFAULT_IPV4_DNS_SEC="8.8.8.8"'
  -I"$test_root/stubs"
  -I"$target/services"
  -I"$target/services/dhcp_client/include"
  -I"$target/services/dhcp_client/src"
  -I"$target/services/dhcp_server/include"
  -I"$target/services/utils/include"
  -I"$target/interfaces/inner_api/include"
  -I"$target/interfaces/kits/c"
)

clang++ "${common[@]}" -c "$root/harness.cpp" -o "$build/harness.o"
clang++ "${common[@]}" -c "$target/services/dhcp_client/src/dhcp_options.cpp" -o "$build/options.o"
clang++ "${common[@]}" -c "$root/driver.cpp" -o "$build/driver.o"
clang++ -Wl,--gc-sections "$build/harness.o" "$build/options.o" "$build/driver.o" -o "$build/dhcp_decline_duplicate_options"
"$build/dhcp_decline_duplicate_options"
