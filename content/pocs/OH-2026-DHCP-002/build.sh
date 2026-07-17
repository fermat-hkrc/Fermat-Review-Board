#!/usr/bin/env bash
set -eu

dashboard_root="$(cd "$(dirname "$0")/../../.." && pwd)"
exec "$dashboard_root/poc-validation/20260717/dhcp_server_callback_wire/build.sh"
