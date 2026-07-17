#!/usr/bin/env bash
set -euo pipefail

# This is a compile-time reproduction.  FERMAT_MESA_ROOT can point at a local
# fermat-MESA checkout that provides the same compatibility headers.
root="$(cd "$(dirname "$0")" && pwd)"
dashboard_root="$(cd "$root/../../.." && pwd)"
target="${COMMUNICATION_DHCP_ROOT:-}"
mesa_root="${FERMAT_MESA_ROOT:-}"
if [[ -z "$target" || ! -d "$target" ]]; then
  printf 'Set COMMUNICATION_DHCP_ROOT to the target checkout.\n' >&2
  exit 2
fi
if [[ -z "$mesa_root" || ! -d "$mesa_root" ]]; then
  printf 'Set FERMAT_MESA_ROOT to the fermat-MESA checkout.\n' >&2
  exit 2
fi
mesa="$mesa_root"
test_root="$dashboard_root/poc-validation/20260717/dhcp_lite_build"
event_stubs="$dashboard_root/poc-validation/20260717/dhcp_event_uninitialized/stubs"
build="$test_root/build"
mkdir -p "$build"

common=(
  clang++ -fsyntax-only -ferror-limit=0 -std=c++17 -DOHOS_ARCH_LITE -DUSING_DHCP_VECTOR=1
  -include vector -include mutex -include algorithm -include memory -include atomic
  -include posix_compat.h -include ohos_compat.h
  -I"$event_stubs"
  -I"$mesa/core/analysis/universal_stubs/tier0_builtin"
  -I"$mesa/core/verification/ohos_toolkit/stubs"
  -I"$target/frameworks/native/c_adapter/inc"
  -I"$target/frameworks/native/include"
  -I"$target/frameworks/native/interfaces"
  -I"$target/frameworks/native/src"
  -I"$target/interfaces"
  -I"$target/interfaces/inner_api"
  -I"$target/interfaces/inner_api/include"
  -I"$target/interfaces/kits/c"
  -I"$target/services"
  -I"$target/services/dhcp_client/include"
  -I"$target/services/dhcp_server/include"
  -I"$target/services/utils/include"
  -I"${COMMONLIBRARY_C_UTILS_ROOT:-$(dirname "$target")/commonlibrary_c_utils}/base/include"
  -I"${COMMUNICATION_IPC_ROOT:-$(dirname "$target")/communication_ipc}/interfaces/innerkits/c/ipc/include"
)

status=0
for source in \
  "$target/frameworks/native/src/dhcp_server_impl.cpp" \
  "$target/frameworks/native/src/dhcp_server_callback_stub_lite.cpp" \
  "$target/frameworks/native/src/dhcp_server_proxy_lite.cpp"; do
  name="$(basename "$source" .cpp)"
  if "${common[@]}" "$source" >"$build/$name.out" 2>&1; then
    printf '%s: unexpectedly compiled\n' "$name"
    status=1
  else
    printf '%s: rejected by compiler\n' "$name"
  fi
done

if ! rg -q 'clientProxy' "$build/dhcp_server_impl.out"; then
  status=1
fi
if ! rg -q 'GetRawDataSize' "$build/dhcp_server_callback_stub_lite.out"; then
  status=1
fi
if ! rg -q "undeclared identifier 'state'" "$build/dhcp_server_callback_stub_lite.out"; then
  status=1
fi
if ! rg -q 'WifiScanProxy' "$build/dhcp_server_proxy_lite.out"; then
  status=1
fi
if ! rg -q 'mRemoteDied' "$build/dhcp_server_proxy_lite.out"; then
  status=1
fi
rg -n "clientProxy|GetRawDataSize|use of undeclared identifier 'state'|WifiScanProxy|mRemoteDied" "$build"/*.out || true
exit "$status"
