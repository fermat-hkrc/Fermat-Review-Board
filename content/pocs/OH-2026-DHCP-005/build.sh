#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
dashboard_root="$(cd "$root/../../.." && pwd)"
target="${COMMUNICATION_DHCP_ROOT:-}"
if [[ -z "$target" || ! -d "$target" ]]; then
  printf 'Set COMMUNICATION_DHCP_ROOT to the target checkout.\n' >&2
  exit 2
fi
test_root="$dashboard_root/poc-validation/20260717/dhcp_network_order"
build="$test_root/build"
mkdir -p "$build"

common=(
  -std=c++17 -include vector -O0 -g
  -I"$test_root/stubs"
  -I"$target/services/dhcp_server/include"
  -I"$target/interfaces/inner_api/include"
)

clang++ "${common[@]}" -c "$target/services/dhcp_server/src/address_utils.cpp" -o "$build/address_utils.o"
clang++ "${common[@]}" -c "$root/driver.cpp" -o "$build/driver.o"
clang++ "$build/address_utils.o" "$build/driver.o" -o "$build/dhcp_network_order"
"$build/dhcp_network_order"
