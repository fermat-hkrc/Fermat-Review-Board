#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
dashboard_root="$(cd "$root/../../.." && pwd)"
target="${COMMUNICATION_DHCP_ROOT:-}"
if [[ -z "$target" || ! -d "$target" ]]; then
  printf 'Set COMMUNICATION_DHCP_ROOT to the target checkout.\n' >&2
  exit 2
fi
test_root="$dashboard_root/poc-validation/20260717/dhcp_option_overload"
build="$test_root/build"
mkdir -p "$build"

common=(
  -std=c++17 -DOHOS_ARCH_LITE -include vector -O0 -g -fno-omit-frame-pointer
  -I"$test_root/stubs"
  -I"$target/services"
  -I"$target/services/dhcp_client/include"
  -I"$target/interfaces/inner_api/include"
  -I"$target/interfaces/kits/c"
)

clang++ "${common[@]}" -c "$target/services/dhcp_client/src/dhcp_options.cpp" -o "$build/dhcp_options.o"
clang++ "${common[@]}" -c "$root/driver.cpp" -o "$build/driver.o"
clang++ "$build/dhcp_options.o" "$build/driver.o" -o "$build/dhcp_option_overload"
"$build/dhcp_option_overload"
