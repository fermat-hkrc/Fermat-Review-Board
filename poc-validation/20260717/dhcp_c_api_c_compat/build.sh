#!/usr/bin/env bash
set -eu

TARGET=/home/cupcup/data/openharmony-data/repos/communication_dhcp
ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
mkdir -p "$BUILD"

if clang -std=c11 -Wall -Werror -fsyntax-only \
  -I"$TARGET/interfaces/kits/c" "$ROOT/driver.c" >"$BUILD/diagnostics.txt" 2>&1; then
  echo "unexpected: public C header compiled as C"
  exit 1
fi

grep -E 'expected parameter declarator|unknown type name|expected' "$BUILD/diagnostics.txt"
