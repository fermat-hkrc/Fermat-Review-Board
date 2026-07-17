#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
dashboard_root="$(cd "$root/../../.." && pwd)"
target="${COMMUNICATION_DHCP_ROOT:-}"
if [[ -z "$target" || ! -d "$target" ]]; then
  printf 'Set COMMUNICATION_DHCP_ROOT to the target checkout.\n' >&2
  exit 2
fi
build="$dashboard_root/poc-validation/20260717/dhcp_c_api_c_compat/build"
mkdir -p "$build"

if clang -std=c11 -Wall -Werror -fsyntax-only \
  -I"$target/interfaces/kits/c" "$root/driver.c" >"$build/diagnostics.txt" 2>&1; then
  echo "unexpected: public C header compiled as C"
  exit 1
fi

rg 'expected parameter declarator|unknown type name|expected' "$build/diagnostics.txt"
