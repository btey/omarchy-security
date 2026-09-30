#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Runs plugins/security_hub/tests/e2e/shell.qml in a private Quickshell
# instance against tools/mock-securityd.py. Needs a Wayland session and
# Omarchy's shell modules (qs.Commons, qs.Ui) at $OMARCHY_SHELL.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
omarchy_shell=${OMARCHY_SHELL:-${OMARCHY_PATH:-/usr/share/omarchy}/shell}
work=$(mktemp -d)
# AF_UNIX paths are limited to 108 bytes, so keep the socket short.
sock_dir=$(mktemp -d /tmp/osh-e2e.XXXXXX)
sock=$sock_dir/securityd.sock
mock_pid=""

cleanup() {
  [[ -n $mock_pid ]] && kill "$mock_pid" 2>/dev/null && wait "$mock_pid" 2>/dev/null
  rm -rf -- "$work" "$sock_dir"
}
trap cleanup EXIT

ln -s "$omarchy_shell/Commons" "$work/Commons"
ln -s "$omarchy_shell/Ui" "$work/Ui"
ln -s "$repo/plugins/security_hub" "$work/hub"
cp "$repo/plugins/security_hub/tests/e2e/shell.qml" "$work/shell.qml"

# Alerts every second, so the badge step does not wait for the default 15 s.
python3 "$repo/tools/mock-securityd.py" --socket "$sock" --alert-every 1 &
mock_pid=$!
for _ in $(seq 50); do [[ -S $sock ]] && break; sleep 0.1; done

status=0
# The hub remembers when alerts were seen under XDG_STATE_HOME; keep the
# test's writes out of the user's.
OMARCHY_SECURITYD_SOCKET=$sock XDG_STATE_HOME=$work/state timeout 30 quickshell -p "$work" >"$work/log" 2>&1 || status=$?
grep -E 'E2E|ERROR' "$work/log" || true
exit "$status"
