#!/usr/bin/env bash
set -u

TARGET=/home/cupcup/data/openharmony-data/repos/communication_dhcp
MESA=/home/cupcup/code/fermat-MESA/dist/cli_build.dist
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD"

COMMON=(
  clang++ -fsyntax-only -ferror-limit=0 -std=c++17 -DOHOS_ARCH_LITE -DUSING_DHCP_VECTOR=1
  -include vector -include mutex -include algorithm -include memory -include atomic
  -include posix_compat.h -include ohos_compat.h
  -I"$ROOT/../dhcp_event_uninitialized/stubs"
  -I"$MESA/core/analysis/universal_stubs/tier0_builtin"
  -I"$MESA/core/verification/ohos_toolkit/stubs"
  -I"$TARGET/frameworks/native/c_adapter/inc"
  -I"$TARGET/frameworks/native/include"
  -I"$TARGET/frameworks/native/interfaces"
  -I"$TARGET/frameworks/native/src"
  -I"$TARGET/interfaces"
  -I"$TARGET/interfaces/inner_api"
  -I"$TARGET/interfaces/inner_api/include"
  -I"$TARGET/interfaces/kits/c"
  -I"$TARGET/services"
  -I"$TARGET/services/dhcp_client/include"
  -I"$TARGET/services/dhcp_server/include"
  -I"$TARGET/services/utils/include"
  -I/home/cupcup/data/openharmony-data/repos/commonlibrary_c_utils/base/include
  -I/home/cupcup/data/openharmony-data/repos/communication_ipc/interfaces/innerkits/c/ipc/include
)

status=0
for source in \
  "$TARGET/frameworks/native/src/dhcp_server_impl.cpp" \
  "$TARGET/frameworks/native/src/dhcp_server_callback_stub_lite.cpp" \
  "$TARGET/frameworks/native/src/dhcp_server_proxy_lite.cpp"; do
  name="$(basename "$source" .cpp)"
  if "${COMMON[@]}" "$source" >"$BUILD/$name.out" 2>&1; then
    printf '%s: unexpectedly compiled\n' "$name"
    status=1
  else
    printf '%s: rejected by compiler\n' "$name"
  fi
done

rg -n "clientProxy|GetRawDataSize|use of undeclared identifier 'state'|WifiScanProxy|mRemoteDied" "$BUILD"/*.out
exit "$status"
