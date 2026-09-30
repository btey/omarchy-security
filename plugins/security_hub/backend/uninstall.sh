#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Removes the Security Hub backend that install.sh (or `sudo make
# install`) put in place (plan task 5.3, §5.22): the README's "Removing
# the Security Hub", steps 1 and 3.
#
#   ~/.config/omarchy/plugins/security-hub/backend/uninstall.sh [--purge]
#
# The firewall goes back to ufw first. The plugin, USBGuard and its policy
# stay; --purge also deletes the hub's state and configuration.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat <<EOF
Usage: ${0##*/} [--purge] [--yes]

Removes the Security Hub backend and hands the firewall back to ufw.

  --purge   also delete /var/lib/omarchy-security, ~/.config/omarchy-security
            and ~/.local/state/omarchy-security
  --yes     do not ask first
EOF
}

PURGE=0
while (( $# > 0 )); do
  case "$1" in
  --purge) PURGE=1 ;;
  --yes | -y) ASSUME_YES=1 ;;
  -h | --help)
    usage
    exit 0
    ;;
  *) die "unknown option: $1 (see --help)" ;;
  esac
  shift
done

refuse_root
refuse_package

# What `make uninstall` removes (PREFIX=/usr); tools/test_backend_scripts.py
# checks this against the Makefile.
FILES=(
  /usr/bin/omarchy-securityd
  /usr/bin/omarchy-secctl
  /usr/lib/omarchy-security/omarchy-securityd-helper
  /usr/lib/omarchy-security/exec-monitor.bpf.o
  /usr/lib/systemd/user/omarchy-securityd.service
  /usr/lib/systemd/system/omarchy-securityd-helper.service
  /usr/lib/systemd/system/omarchy-security-firewall.service
  /usr/share/polkit-1/actions/org.omarchy.security.policy
  /usr/share/polkit-1/rules.d/50-omarchy-security.rules
  /usr/share/doc/omarchy-security/config.example.toml
)
DIRS=(/usr/lib/omarchy-security /usr/share/doc/omarchy-security)
STATE=$DESTDIR/var/lib/omarchy-security
CONFIG=${XDG_CONFIG_HOME:-$HOME/.config}/omarchy-security
USER_STATE=${XDG_STATE_HOME:-$HOME/.local/state}/omarchy-security

say "Removing the Security Hub backend"
note "the firewall goes back to ufw, then the services stop and the files go"
if (( PURGE )); then
  note "and the hub's state and configuration: $STATE $CONFIG $USER_STATE"
else
  note "your rules and configuration stay (--purge deletes them)"
fi
confirm "Continue?" || die "cancelled"
[[ -z $SUDO ]] || $SUDO -v

if [[ -z $DESTDIR ]]; then
  say "Stopping the services"
  $SYSTEMCTL --user disable --now omarchy-securityd.service 2>/dev/null || true
  as_root $SYSTEMCTL disable --now omarchy-securityd-helper.service omarchy-security-firewall.service 2>/dev/null || true
fi

# The helper is stopped, so nothing loads its policy again. In standalone
# mode the hub turned ufw off: turn it back on before the hub's table goes,
# so the machine is never without a firewall.
say "Handing the firewall back to ufw"
mode=$(as_root cat "$STATE/mode" 2>/dev/null || true)
mode=${mode//[[:space:]]/}
if [[ $mode == standalone ]]; then
  if command -v ufw >/dev/null; then
    as_root ufw --force enable
  else
    note "ufw is not installed; the machine keeps only the rules nftables has from elsewhere"
  fi
fi
as_root nft delete table inet omarchy_sec 2>/dev/null || true
as_root rm -f "$STATE/mode" "$STATE/firewall.nft"

say "Removing the files"
paths=()
for f in "${FILES[@]}"; do paths+=("$DESTDIR$f"); done
as_root rm -f "${paths[@]}"
for d in "${DIRS[@]}"; do as_root rmdir "$DESTDIR$d" 2>/dev/null || true; done

if [[ -z $DESTDIR ]]; then
  as_root $SYSTEMCTL daemon-reload
  $SYSTEMCTL --user daemon-reload
fi

if (( PURGE )); then
  say "Deleting the hub's state and configuration"
  as_root rm -rf "$STATE"
  rm -rf "$CONFIG" "$USER_STATE"
fi

say "Security Hub backend removed"
note "To remove the plugin too: omarchy plugin remove security-hub"
note "USBGuard, if you set it up, is still running with your policy."
