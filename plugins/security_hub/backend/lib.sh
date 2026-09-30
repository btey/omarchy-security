# SPDX-License-Identifier: MIT
#
# Shared by install.sh and uninstall.sh (plan task 5.3, §5.22); sourced,
# not run. The OMSEC_* variables replace commands and URLs for
# tools/test_backend_scripts.py only.

REPO_URL=https://github.com/btey/omarchy-security
SUDO=${OMSEC_SUDO-sudo}
SYSTEMCTL=${OMSEC_SYSTEMCTL-systemctl}
PACMAN=${OMSEC_PACMAN-pacman}
DESTDIR=${DESTDIR-}
PLUGIN_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ASSUME_YES=0

say() { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die() {
  printf '%s: %s\n' "${0##*/}" "$*" >&2
  exit 1
}

# Runs a command as root: through sudo, or as is when OMSEC_SUDO is empty.
as_root() {
  if [[ -n $SUDO ]]; then $SUDO "$@"; else "$@"; fi
}

confirm() {
  (( ASSUME_YES )) && return 0
  [[ -t 0 ]] || die "refusing to continue without confirmation; pass --yes"
  local answer
  read -r -p "$1 [y/N] " answer
  [[ $answer == [yY] || $answer == [yY][eE][sS] ]]
}

# The plugin's version, from its manifest; the backend is installed at it.
plugin_version() {
  sed -n 's/^ *"version": *"\([^"]*\)".*/\1/p' "$PLUGIN_DIR/manifest.json" | head -n 1
}

# The hub is installed by root, but belongs to the user who runs it.
refuse_root() {
  (( EUID != 0 )) || die "run this as your own user, not as root; it asks for sudo when it needs it"
}

# An install from the Arch package (plan task 5.4) is pacman's to update
# and remove.
refuse_package() {
  local bin owner
  bin=$(command -v omarchy-securityd) || return 0
  owner=$($PACMAN -Qqo "$bin" 2>/dev/null) || return 0
  die "$bin belongs to the package '$owner'; update or remove it with pacman instead"
}
