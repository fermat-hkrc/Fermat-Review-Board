#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
dashboard_root="$(cd "$root/../../.." && pwd)"
target="${COMMUNICATION_DHCP_ROOT:-}"
if [[ -z "$target" || ! -d "$target" ]]; then
  printf 'Set COMMUNICATION_DHCP_ROOT to the target checkout.\n' >&2
  exit 2
fi
test_root="$dashboard_root/poc-validation/20260717/dhcp_send_failure"
build="$test_root/build"
mkdir -p "$build"

common=(
  -std=c++17 -O1 -g -ffunction-sections -fdata-sections -include vector
  -I"$test_root/stubs"
  -I"$target/services"
  -I"$target/services/dhcp_server/include"
  -I"$target/services/dhcp_server/src"
  -I"$target/services/dhcp_client/include"
  -I"$target/services/utils/include"
  -I"$target/interfaces/inner_api/include"
)

clang++ "${common[@]}" -c "$root/harness.cpp" -o "$build/harness.o"
clang++ "${common[@]}" -c "$root/driver.cpp" -o "$build/driver.o"
clang++ -Wl,--gc-sections -Wl,--wrap=sendto "$build/harness.o" "$build/driver.o" -o "$build/dhcp_send_failure"
"$build/dhcp_send_failure"
