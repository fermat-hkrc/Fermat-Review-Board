#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
dashboard_root="$(cd "$root/../../.." && pwd)"
target="${COMMUNICATION_DHCP_ROOT:-}"
if [[ -z "$target" || ! -d "$target" ]]; then
  printf 'Set COMMUNICATION_DHCP_ROOT to the target checkout.\n' >&2
  exit 2
fi
test_root="$dashboard_root/poc-validation/20260717/dhcp_client_lite_wire"
build="$test_root/build"
mkdir -p "$build"

common=(
  -std=c++17 -DOHOS_ARCH_LITE -include memory -include vector -include mutex -include atomic
  -I"$test_root/stubs"
  -I"$target/frameworks/native/include"
  -I"$target/frameworks/native/interfaces"
  -I"$target/frameworks/native/src"
  -I"$target/interfaces"
  -I"$target/interfaces/inner_api"
  -I"$target/interfaces/inner_api/include"
  -I"$target/interfaces/kits/c"
  -I"$target/services"
  -I"$target/services/dhcp_client/include"
  -I"$target/services/utils/include"
)

clang++ "${common[@]}" -c "$target/frameworks/native/src/dhcp_client_proxy_lite.cpp" -o "$build/proxy.o"
clang++ "${common[@]}" -c "$target/services/dhcp_client/src/dhcp_client_stub_lite.cpp" -o "$build/stub.o"
# The shim intentionally binds to the real callback-stub declaration.  Keep
# the source directory before the reduced test header only for this unit.
callback_common=(
  -std=c++17 -DOHOS_ARCH_LITE -include memory -include vector -include mutex -include atomic
  -I"$target/frameworks/native/src"
  -I"$test_root/stubs"
  -I"$target/frameworks/native/include"
  -I"$target/frameworks/native/interfaces"
  -I"$target/interfaces"
  -I"$target/interfaces/inner_api"
  -I"$target/interfaces/inner_api/include"
  -I"$target/interfaces/kits/c"
  -I"$target/services"
  -I"$target/services/dhcp_client/include"
  -I"$target/services/utils/include"
)
clang++ "${callback_common[@]}" -c "$root/callback_shim.cpp" -o "$build/callback_shim.o"
clang++ "${common[@]}" -c "$root/driver.cpp" -o "$build/driver.o"
clang++ "$build/proxy.o" "$build/stub.o" "$build/callback_shim.o" "$build/driver.o" -o "$build/dhcp_client_lite_wire"
"$build/dhcp_client_lite_wire"
