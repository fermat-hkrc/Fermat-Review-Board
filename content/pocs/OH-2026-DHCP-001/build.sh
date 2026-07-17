#!/usr/bin/env bash
set -euo pipefail

# Fixed automatic-variable initialization makes the missing initialization
# deterministic; it does not replace the production callback implementation.
root="$(cd "$(dirname "$0")" && pwd)"
dashboard_root="$(cd "$root/../../.." && pwd)"
target="${COMMUNICATION_DHCP_ROOT:-}"
if [[ -z "$target" || ! -d "$target" ]]; then
  printf 'Set COMMUNICATION_DHCP_ROOT to the target checkout.\n' >&2
  exit 2
fi
test_root="$dashboard_root/poc-validation/20260717/dhcp_event_uninitialized"
build="$test_root/build-pattern"
mkdir -p "$build"

common=(
  -std=c++17 -DOHOS_ARCH_LITE -include vector -include mutex -include algorithm
  -ftrivial-auto-var-init=pattern -fPIE -fno-omit-frame-pointer -O1 -g
  -I"$test_root/stubs"
  -I"$target/services"
  -I"$target/frameworks/native/include"
  -I"$target/frameworks/native/interfaces"
  -I"$target/interfaces"
  -I"$target/interfaces/inner_api"
  -I"$target/interfaces/inner_api/include"
  -I"$target/interfaces/kits/c"
  -I"$target/services/dhcp_client/include"
  -I"$target/services/dhcp_server/include"
  -I"$target/services/utils/include"
)

clang++ "${common[@]}" -c "$target/frameworks/native/src/dhcp_event.cpp" -o "$build/dhcp_event.o"
clang++ "${common[@]}" -c "$root/driver.cpp" -o "$build/driver.o"
clang++ -pie "$build/dhcp_event.o" "$build/driver.o" -o "$build/dhcp_event_pattern"
"$build/dhcp_event_pattern"
