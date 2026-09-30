#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
#   tools/theme-apply.sh THEME_DIR [SHELL_DIR]
#
# What `omarchy theme set` does to the shell, for tests/e2e/themes.qml
# (plan task 4.2), under a throwaway HOME: stages THEME_DIR into
# $HOME/.local/state/omarchy/current/next-theme, generates shell.toml and
# the other templates with Omarchy's own omarchy-theme-set-templates, swaps
# it in as the current theme, and, given SHELL_DIR, pushes colors.toml and
# shell.toml to the Quickshell instance running that config with
# `shell applyTheme`, the IPC call omarchy-theme-set makes. It leaves out
# what omarchy-theme-set does to the rest of the session (terminals,
# Hyprland, the background, hooks), so it never touches the user's desktop.
#
# Then prints Omarchy's resolved palette for the theme (omarchy-theme-color
# --all), which the test checks the hub against.
set -euo pipefail

theme=${1:?usage: theme-apply.sh THEME_DIR [SHELL_DIR]}
shell_dir=${2:-}

# The one thing that must never happen is the user's own theme being
# replaced.
if [[ ${HOME:-} == "$(getent passwd "$(id -u)" | cut -d: -f6)" ]]; then
  echo "theme-apply.sh: HOME is the real home; run it under a throwaway HOME" >&2
  exit 2
fi

state=$HOME/.local/state/omarchy/current
next=$state/next-theme
current=$state/theme

rm -rf -- "$next"
mkdir -p "$next"
# Backgrounds are the background's business, not the shell's.
for entry in "$theme"/*; do
  [[ -e $entry && $(basename -- "$entry") != backgrounds ]] && cp -r -- "$entry" "$next/"
done
if [[ ! -f $next/colors.toml && -f $next/alacritty.toml ]]; then
  omarchy-theme-colors-from-alacritty "$next"
fi
omarchy-theme-set-templates

rm -rf -- "$current"
mv -- "$next" "$current"
basename -- "$theme" >"$state/theme.name"

if [[ -n $shell_dir ]]; then
  colors=$([[ -f $current/colors.toml ]] && base64 -w 0 "$current/colors.toml" || true)
  shell=$([[ -f $current/shell.toml ]] && base64 -w 0 "$current/shell.toml" || true)
  timeout 5 qs ipc -p "$shell_dir" call shell applyTheme "$colors" "$shell" >/dev/null
fi

if [[ -f $current/colors.toml ]]; then
  omarchy-theme-color --file "$current/colors.toml" --all
fi
