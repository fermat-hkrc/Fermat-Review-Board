#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
dashboard_root="$(cd "$root/../../.." && pwd)"
target="${COMMUNICATION_DHCP_ROOT:-}"
if [[ -z "$target" || ! -d "$target" ]]; then
  printf 'Set COMMUNICATION_DHCP_ROOT to the target checkout.\n' >&2
  exit 2
fi
test_root="$dashboard_root/poc-validation/20260717/dhcp_cache_write_loss"
build="$test_root/build"
mkdir -p "$build"

common=(
  -std=c++17 -O1 -g -include vector -include mutex
  -I"$test_root/stubs"
  -I"$target/services/dhcp_client/include"
  -I"$target/services/utils/include"
  -I"$target/frameworks/native/include"
  -I"$target/interfaces"
  -I"$target/interfaces/inner_api"
  -I"$target/interfaces/inner_api/include"
  -I"$target/interfaces/kits/c"
  -I"$target/services"
)

clang++ "${common[@]}" -c "$target/services/dhcp_client/src/dhcp_result_store_manager.cpp" -o "$build/store.o"
clang++ "${common[@]}" -c "$root/driver.cpp" -o "$build/driver.o"
clang++ "$build/store.o" "$build/driver.o" -Wl,--wrap=fwrite -o "$build/dhcp_cache_write_loss"
"$build/dhcp_cache_write_loss"
