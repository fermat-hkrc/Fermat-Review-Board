#!/usr/bin/env bash
set -eu

TARGET=/home/cupcup/data/openharmony-data/repos/communication_connected_nfc_tag
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD"

COMMON=(
  -std=c++17 -O1 -g
  -I"$ROOT/stubs"
  -I"$TARGET/services/include"
  -I"$TARGET/interfaces/inner_api/include"
)

clang++ "${COMMON[@]}" -c "$TARGET/services/src/nfc_tag_stub.cpp" -o "$BUILD/stub.o"
clang++ "${COMMON[@]}" -c "$TARGET/interfaces/inner_api/src/nfc_tag_proxy.cpp" -o "$BUILD/proxy.o"
clang++ "${COMMON[@]}" -c "$ROOT/driver.cpp" -o "$BUILD/driver.o"
clang++ "$BUILD/stub.o" "$BUILD/proxy.o" "$BUILD/driver.o" -o "$BUILD/nfc_write_reply_mismatch"
"$BUILD/nfc_write_reply_mismatch"
