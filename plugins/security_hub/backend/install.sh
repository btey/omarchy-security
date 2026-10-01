#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Installs the Security Hub backend (the daemon, the root helper, the eBPF
# monitor, their units and polkit files) at this plugin's version (plan
# task 5.3, §5.22). The hub's "Install backend" button runs it in a
# terminal; it can also be run by hand:
#
#   ~/.config/omarchy/plugins/security-hub/backend/install.sh [--from-source]
#
# By default it downloads the release's prebuilt tarball and checks it
# against the release's SHA256SUMS. --from-source builds the same tag from
# source instead. It never enables USBGuard, never runs ufw and never
# changes the firewall mode.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat <<EOF
Usage: ${0##*/} [--from-source] [--version X.Y.Z] [--yes]

Installs the Security Hub backend at the plugin's version ($(plugin_version)).

  --from-source   build the release's source instead of using its binaries
  --version V     install version V instead of the plugin's
  --yes           do not ask; this also installs the optional packages
EOF
}

FROM_SOURCE=0
VERSION=$(plugin_version)
while (( $# > 0 )); do
  case "$1" in
  --from-source) FROM_SOURCE=1 ;;
  --version)
    [[ $# -ge 2 ]] || die "--version needs a value"
    VERSION=$2
    shift
    ;;
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
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "not a version: '$VERSION'"

ARCH=$(uname -m)
if (( ! FROM_SOURCE )) && [[ $ARCH != x86_64 ]]; then
  die "releases have binaries for x86_64 only, and this is $ARCH; run it again with --from-source"
fi

RELEASE_BASE=${OMSEC_RELEASE_BASE:-$REPO_URL/releases/download/v$VERSION}
SOURCE_URL=${OMSEC_SOURCE_URL:-$REPO_URL/archive/refs/tags/v$VERSION.tar.gz}
TARBALL=omarchy-security-hub-$VERSION-$ARCH.tar.gz

# The README's step 1. The core needs polkit and nftables; without any of
# the others, the daemon reports that module unavailable and keeps going.
REQUIRED=(polkit nftables make)
OPTIONAL=(bubblewrap usbguard pcsclite ccid libfido2 udisks2 cryptsetup fuse3 gocryptfs pinentry gnupg)
# bpf-linker from pacman is built against the system LLVM, so it never
# needs rebuilding after an LLVM upgrade.
BUILD=(base-devel llvm clang bpf-linker)

missing() { $PACMAN -T "$@" 2>/dev/null || true; }

need_required=$(missing "${REQUIRED[@]}")
need_optional=$(missing "${OPTIONAL[@]}")
need_build=""
if (( FROM_SOURCE )); then
  # pacman's rust links the system LLVM, as its bpf-linker does, so with it
  # the build needs nothing from outside the repositories (the BPF target
  # takes the nightly features through RUSTC_BOOTSTRAP). A rustup install
  # is used as it is: it and pacman's rust conflict.
  if command -v rustup >/dev/null; then
    RUST=rustup
    command -v cargo >/dev/null || die "rustup has no default toolchain; run: rustup default stable"
  else
    RUST=system
    command -v cargo >/dev/null || BUILD+=(rust)
    BUILD+=(rust-src)
  fi
  need_build=$(missing "${BUILD[@]}")
fi

say "Security Hub backend $VERSION"
if (( FROM_SOURCE )); then
  note "from source: $SOURCE_URL"
else
  note "prebuilt: $RELEASE_BASE/$TARBALL"
fi
[[ -z $need_required ]] || note "required packages to install: $(echo $need_required)"
[[ -z $need_build ]] || note "build packages to install: $(echo $need_build)"
[[ -z $need_optional ]] || note "optional packages not installed: $(echo $need_optional)"
if [[ -z $DESTDIR ]]; then
  note "then: sudo make install, and enable omarchy-securityd-helper, omarchy-security-firewall"
  note "and your omarchy-securityd service. USBGuard and the firewall mode are left as they are."
else
  note "then: make install DESTDIR=$DESTDIR (no services)"
fi
confirm "Continue?" || die "cancelled"

if [[ -n $SUDO ]] && [[ -z $DESTDIR ]]; then
  # One password prompt, up front, rather than in the middle of the build.
  $SUDO -v
fi

packages=()
[[ -z $need_required ]] || packages+=($need_required)
[[ -z $need_build ]] || packages+=($need_build)
if [[ -n $need_optional ]]; then
  if confirm "Also install the optional packages ($(echo $need_optional))?"; then
    packages+=($need_optional)
  else
    note "skipped; the modules that need them will say they are unavailable"
  fi
fi
if (( ${#packages[@]} > 0 )); then
  say "Installing packages: ${packages[*]}"
  as_root $PACMAN -S --needed --noconfirm "${packages[@]}"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() {
  local url=$1 out=$2 proto=()
  [[ $url != https://* ]] || proto=(--proto =https --proto-redir =https --tlsv1.2)
  curl -fL --retry 2 --silent --show-error "${proto[@]}" -o "$out" "$url" ||
    die "could not download $url"
}

if (( FROM_SOURCE )); then
  say "Downloading the source of v$VERSION"
  fetch "$SOURCE_URL" "$work/source.tar.gz"
  mkdir "$work/src"
  tar -xzf "$work/source.tar.gz" -C "$work/src" --strip-components=1
  tree=$work/src
  [[ -f $tree/Makefile && -f $tree/Cargo.toml ]] || die "the source archive has no Makefile or Cargo.toml"

  say "Building the daemon and the helper (this takes a few minutes)"
  make -C "$tree" release
  # With rustup, the nightly on the system's LLVM, from the Makefile (1.1.0
  # and older only have the crate's pin). mise and others export
  # RUSTUP_TOOLCHAIN, which would override that pin. RUSTC_BOOTSTRAP is for
  # pacman's rust, and for a Makefile from before it set it itself.
  ebpf_env=(-u RUSTUP_TOOLCHAIN)
  ebpf_ready=1
  if [[ $RUST == system ]]; then
    ebpf_env+=(RUSTC_BOOTSTRAP=1)
  else
    pin=$(make -s -C "$tree" ebpf-toolchain 2>/dev/null) ||
      pin=$(sed -n 's/^channel = "\(.*\)"/\1/p' "$tree/crates/omarchy-security-ebpf/rust-toolchain.toml")
    if ! rustup toolchain list 2>/dev/null | grep -q "^$pin"; then
      ebpf_ready=0
      note "not building the eBPF exec monitor: with rustup it needs $pin:"
      note "  rustup toolchain install $pin --component rust-src"
    fi
  fi
  if ! command -v bpf-linker >/dev/null; then
    ebpf_ready=0
    note "not building the eBPF exec monitor: it needs bpf-linker (sudo pacman -S bpf-linker)"
  fi
  if (( ebpf_ready )); then
    say "Building the eBPF exec monitor"
    # Without it the daemon still works, so a failure here is not fatal.
    env "${ebpf_env[@]}" make -C "$tree" ebpf ||
      note "the eBPF exec monitor did not build; the threat module scans /proc instead (degraded)."
  else
    note "Without it the threat module scans /proc instead (degraded)."
  fi
else
  say "Downloading $TARBALL"
  fetch "$RELEASE_BASE/$TARBALL" "$work/$TARBALL"
  fetch "$RELEASE_BASE/SHA256SUMS" "$work/SHA256SUMS"
  # Only the line for this tarball: a SHA256SUMS that does not list it
  # must fail, not pass with nothing checked.
  grep -E "^[0-9a-f]{64}  $TARBALL\$" "$work/SHA256SUMS" > "$work/check" ||
    die "SHA256SUMS does not list $TARBALL"
  (cd "$work" && sha256sum --check --quiet check) || die "$TARBALL does not match SHA256SUMS"
  note "checksum OK"
  tar -xzf "$work/$TARBALL" -C "$work"
  tree=$work/omarchy-security-hub-$VERSION
  [[ -f $tree/Makefile ]] || die "$TARBALL has no omarchy-security-hub-$VERSION/Makefile"
fi

say "Installing"
if [[ -n $DESTDIR ]]; then
  make -C "$tree" install DESTDIR="$DESTDIR"
  say "Installed into $DESTDIR; services not enabled"
  exit 0
fi
as_root make -C "$tree" install

say "Enabling the services"
as_root $SYSTEMCTL daemon-reload
as_root $SYSTEMCTL enable omarchy-securityd-helper.service omarchy-security-firewall.service
# Restart rather than start, so an update replaces the running binaries.
as_root $SYSTEMCTL restart omarchy-securityd-helper.service
if [[ -z $(missing pcsclite) ]]; then
  as_root $SYSTEMCTL enable --now pcscd.socket
fi
$SYSTEMCTL --user daemon-reload
$SYSTEMCTL --user enable omarchy-securityd.service
$SYSTEMCTL --user restart omarchy-securityd.service

say "Security Hub backend $VERSION installed"
note "The hub connects within a few seconds. Check it with: omarchy-secctl call GET_STATUS"
note "USB control needs USBGuard set up first; do not just enable it, since without a"
note "policy it blocks every device: $REPO_URL#setting-up-usbguard"
