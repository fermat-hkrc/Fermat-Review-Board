#!/usr/bin/env bash
set -eu

dashboard_root="$(cd "$(dirname "$0")/../../.." && pwd)"
exec "$dashboard_root/poc-validation/20260717/dhcp_event_uninitialized/run-pattern.sh"
