#!/usr/bin/env bash
set -eu

dashboard_root="$(cd "$(dirname "$0")/../../.." && pwd)"
exec "$dashboard_root/poc-validation/20260717/dhcp_decline_duplicate_options/build.sh"
