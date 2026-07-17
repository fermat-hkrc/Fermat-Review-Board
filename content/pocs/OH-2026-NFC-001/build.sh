#!/usr/bin/env bash
set -euo pipefail

# Override COMMUNICATION_NFC_TAG_ROOT when the target checkout lives elsewhere.
root="$(cd "$(dirname "$0")" && pwd)"
dashboard_root="$(cd "$root/../../.." && pwd)"
target="${COMMUNICATION_NFC_TAG_ROOT:-}"
if [[ -z "$target" || ! -d "$target" ]]; then
  printf 'Set COMMUNICATION_NFC_TAG_ROOT to the target checkout.\n' >&2
  exit 2
fi
test_root="$dashboard_root/poc-validation/20260717/nfc_write_reply_mismatch"
build="$test_root/build"
mkdir -p "$build"

common=(
  -std=c++17 -O1 -g
  -I"$test_root/stubs"
  -I"$target/services/include"
  -I"$target/interfaces/inner_api/include"
)

clang++ "${common[@]}" -c "$target/services/src/nfc_tag_stub.cpp" -o "$build/stub.o"
clang++ "${common[@]}" -c "$target/interfaces/inner_api/src/nfc_tag_proxy.cpp" -o "$build/proxy.o"
clang++ "${common[@]}" -c "$root/driver.cpp" -o "$build/driver.o"
clang++ "$build/stub.o" "$build/proxy.o" "$build/driver.o" -o "$build/nfc_write_reply_mismatch"
"$build/nfc_write_reply_mismatch"
