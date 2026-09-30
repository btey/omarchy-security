#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Runs plugins/security_hub/tests/e2e/shell.qml in a private Quickshell
# instance against tools/mock-securityd.py, then tests/e2e/modes.qml once
# for each firewall mode other than ufw, each against its own mock. Needs a
# Wayland session and Omarchy's shell modules (qs.Commons, qs.Ui) at
# $OMARCHY_SHELL.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
omarchy_shell=${OMARCHY_SHELL:-${OMARCHY_PATH:-/usr/share/omarchy}/shell}
work=$(mktemp -d)
# AF_UNIX paths are limited to 108 bytes, so keep the socket short.
sock_dir=$(mktemp -d /tmp/osh-e2e.XXXXXX)
sock=$sock_dir/securityd.sock
mock_pid=""

stop_mock() {
  [[ -n $mock_pid ]] && kill "$mock_pid" 2>/dev/null && wait "$mock_pid" 2>/dev/null
  mock_pid=""
}

cleanup() {
  stop_mock
  rm -rf -- "$work" "$sock_dir"
}
trap cleanup EXIT

ln -s "$omarchy_shell/Commons" "$work/Commons"
ln -s "$omarchy_shell/Ui" "$work/Ui"
ln -s "$repo/plugins/security_hub" "$work/hub"

# run QML SECS [mock args...]: runs tests/e2e/QML as the shell, for at most
# SECS, against a fresh mock.
run() {
  local qml=$1 secs=$2 status=0
  shift 2
  cp "$repo/plugins/security_hub/tests/e2e/$qml" "$work/shell.qml"
  python3 "$repo/tools/mock-securityd.py" --socket "$sock" "$@" &
  mock_pid=$!
  for _ in $(seq 50); do [[ -S $sock ]] && break; sleep 0.1; done
  # The hub remembers when alerts were seen under XDG_STATE_HOME; keep the
  # test's writes out of the user's.
  OMARCHY_SECURITYD_SOCKET=$sock XDG_STATE_HOME=$work/state timeout "$secs" quickshell -p "$work" >"$work/log" 2>&1 || status=$?
  grep -E 'E2E|ERROR' "$work/log" || true
  stop_mock
  return "$status"
}

# Alerts every second, so the badge step does not wait for the default 15 s,
# and prompts that time out in 3 s, not 30.
run shell.qml 30 --alert-every 1 --prompt-timeout 3
for mode in standalone both none unknown; do
  export E2E_MODE=$mode
  run modes.qml 15 --alert-every 0.3 --mode "$mode"
done
