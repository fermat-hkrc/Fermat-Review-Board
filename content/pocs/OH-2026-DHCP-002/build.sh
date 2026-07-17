#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
dashboard_root="$(cd "$root/../../.." && pwd)"
target="${COMMUNICATION_DHCP_ROOT:-}"
if [[ -z "$target" || ! -d "$target" ]]; then
  printf 'Set COMMUNICATION_DHCP_ROOT to the target checkout.\n' >&2
  exit 2
fi
test_root="$dashboard_root/poc-validation/20260717/dhcp_server_callback_wire"
build="$test_root/build"
mkdir -p "$build"

common=(
  -std=c++17 -O1 -g -include algorithm -include mutex -include atomic -include memory
  -I"$test_root/stubs"
  -I"$target/frameworks/native/include"
  -I"$target/frameworks/native/interfaces"
  -I"$target/frameworks/native/src"
  -I"$target/interfaces"
  -I"$target/interfaces/inner_api"
  -I"$target/interfaces/inner_api/include"
  -I"$target/interfaces/kits/c"
  -I"$target/services"
  -I"$target/services/dhcp_server/include"
)

clang++ "${common[@]}" -c "$target/services/dhcp_server/src/dhcp_server_callback_proxy.cpp" -o "$build/proxy.o"
clang++ "${common[@]}" -c "$target/frameworks/native/src/dhcp_server_callback_stub.cpp" -o "$build/stub.o"
clang++ "${common[@]}" -c "$root/driver.cpp" -o "$build/driver.o"
clang++ "$build/proxy.o" "$build/stub.o" "$build/driver.o" -o "$build/dhcp_server_callback_wire"
"$build/dhcp_server_callback_wire"
