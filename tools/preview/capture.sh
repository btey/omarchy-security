#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Screenshots of the hub for the marketplace preview, into
# tools/preview/shots/: the hub on each tab, and the connection prompt and
# threat alert on their own. Runs the plugin's QML in a private Quickshell
# inside a nested Hyprland (a window on the current desktop for a few
# seconds), against tools/mock-securityd.py's canned data, so nothing from
# this machine shows. The theme is THEME (default tokyo-night), applied
# under a throwaway HOME as `omarchy theme set` does; the output has scale
# 2, so the shots are sharp at twice their size. Needs a Wayland session,
# Hyprland, Quickshell, grim, ImageMagick and Omarchy's shell modules.
set -euo pipefail

repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
omarchy_path=${OMARCHY_PATH:-/usr/share/omarchy}
omarchy_shell=${OMARCHY_SHELL:-$omarchy_path/shell}
theme=${THEME:-tokyo-night}
shots=$repo/tools/preview/shots
work=$(mktemp -d)
sock_dir=$(mktemp -d /tmp/osh-cap.XXXXXX)
mock_pid="" hypr_pid=""

cleanup() {
  [[ -n $hypr_pid ]] && kill "$hypr_pid" 2>/dev/null
  [[ -n $mock_pid ]] && kill "$mock_pid" 2>/dev/null
  wait 2>/dev/null || true
  rm -rf -- "$work" "$sock_dir"
}
trap cleanup EXIT

mkdir -p "$work/shell" "$work/out" "$work/home/.config/omarchy" "$shots"
ln -s "$omarchy_shell/Commons" "$work/shell/Commons"
ln -s "$omarchy_shell/Ui" "$work/shell/Ui"
ln -s "$repo/plugins/security_hub" "$work/shell/hub"
cp "$repo/tools/preview/capture.qml" "$work/shell/shell.qml"
HOME=$work/home OMARCHY_PATH=$omarchy_path "$repo/tools/theme-apply.sh" "$omarchy_path/themes/$theme/" >/dev/null

version=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$repo/plugins/security_hub/manifest.json")
# Standalone, so the Network tab shows the hub's own firewall, and prompts
# that wait long enough to be photographed.
# The mock puts HOME and USER into its paths; keep this machine's out.
HOME=/home/user USER=user python3 "$repo/tools/mock-securityd.py" --socket "$sock_dir/securityd.sock" --mode standalone \
  --daemon-version "$version" --all-active --prompt-timeout 600 --alert-every 2 &
mock_pid=$!
for _ in $(seq 50); do [[ -S $sock_dir/securityd.sock ]] && break; sleep 0.1; done

bg=$(sed -n 's/^background *= *"#\([0-9a-fA-F]*\)".*/\1/p' "$work/home/.local/state/omarchy/current/theme/colors.toml")
cat >"$work/hyprland.lua" <<EOF
-- The nested window's own output takes whatever size the desktop gives
-- it, so the shell goes on a headless output of a set size instead.
hl.monitor({ output = "CAP", mode = "2000x2000", position = "0x0", scale = 2 })
hl.monitor({ output = "WAYLAND-1", disabled = true })
hl.config({
  misc = { disable_hyprland_logo = true, disable_splash_rendering = true,
           disable_scale_notification = true, background_color = "rgb(${bg:-000000})" },
  animations = { enabled = false },
  cursor = { inactive_timeout = 1 },
})
hl.on("hyprland.start", function()
  hl.exec_cmd("hyprctl output create headless CAP >/dev/null; sleep 1; quickshell -p $work/shell > $work/log 2>&1; touch $work/done")
end)
EOF

HOME=$work/home XDG_STATE_HOME=$work/state CAPTURE_OUT=$work/out \
  OMARCHY_SECURITYD_SOCKET=$sock_dir/securityd.sock \
  start-hyprland -- -c "$work/hyprland.lua" >"$work/hyprland.log" 2>&1 &
hypr_pid=$!
for _ in $(seq 600); do [[ -e $work/done ]] && break; sleep 0.1; done
grep -E 'CAPTURE|ERROR' "$work/log" || true
# CAPTURE_KEEP=DIR keeps the full screenshots, to see what was cropped.
[[ -n ${CAPTURE_KEEP:-} ]] && cp -r "$work/out/." "$CAPTURE_KEEP/"
grep -q 'CAPTURE osd' "$work/log" || { echo "capture did not finish" >&2; exit 1; }

python3 "$repo/tools/preview/crop.py" "$work/out" "$shots" 2
