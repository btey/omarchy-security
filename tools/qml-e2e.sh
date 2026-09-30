#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Runs plugins/security_hub/tests/e2e/shell.qml in a private Quickshell
# instance against tools/mock-securityd.py, then tests/e2e/modes.qml once
# for each firewall mode other than ufw, each against its own mock, then
# tests/e2e/themes.qml, which applies every theme in $OMARCHY_PATH/themes
# live under a throwaway HOME. Needs a Wayland session and Omarchy's shell
# modules (qs.Commons, qs.Ui) at $OMARCHY_SHELL.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
omarchy_path=${OMARCHY_PATH:-/usr/share/omarchy}
omarchy_shell=${OMARCHY_SHELL:-$omarchy_path/shell}
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
  OMARCHY_SECURITYD_SOCKET=$sock XDG_STATE_HOME=$work/state HOME=${shell_home:-$HOME} \
    timeout "$secs" quickshell -p "$work" >"$work/log" 2>&1 || status=$?
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
unset E2E_MODE

# qs.Commons reads the theme from $HOME/.local/state/omarchy/current/theme,
# so the theme test gets a HOME of its own, which tools/theme-apply.sh
# fills the way `omarchy theme set` does. It starts on the last theme, so
# the first switch changes something.
themes=("$omarchy_path"/themes/*/ "$repo/plugins/security_hub/tests/e2e/themes/bare-palette")
shell_home=$work/home
# As on an install, ~/.config/omarchy is there (without a shell.toml), so
# qs.Commons can watch for one.
mkdir -p "$shell_home/.config/omarchy"
HOME=$shell_home OMARCHY_PATH=$omarchy_path "$repo/tools/theme-apply.sh" "${themes[-2]}" >/dev/null
export E2E_THEME_APPLY=$repo/tools/theme-apply.sh
E2E_THEMES=$(IFS=:; echo "${themes[*]}")
export E2E_THEMES
run themes.qml 120 --alert-every 1 --prompt-timeout 3
