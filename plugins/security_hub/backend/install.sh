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
# What it installs is pinned by backend/release.lock, which `make dist`
# writes into the plugin when it packages a release: the prebuilt
# tarball's SHA-256 and the commit it was built from. By default it
# downloads that tarball from the release and refuses it unless it has
# that digest, before unpacking it. --from-source fetches that commit with
# git and builds it instead. The release's own SHA256SUMS is not used: it
# could be replaced along with the tarball. It never enables USBGuard,
# never runs ufw and never changes the firewall mode.

set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

usage() {
  cat <<EOF
Usage: ${0##*/} [--from-source] [--yes]

Installs the Security Hub backend at the plugin's version ($(plugin_version)),
as pinned by backend/release.lock.

  --from-source   build the release's source commit instead of using its binaries
  --yes           do not ask; this also installs the optional packages
EOF
}

FROM_SOURCE=0
while (( $# > 0 )); do
  case "$1" in
  --from-source) FROM_SOURCE=1 ;;
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

LOCK=$PLUGIN_DIR/backend/release.lock
[[ -f $LOCK ]] || die "$LOCK is missing: this plugin was not packaged by make dist (a source checkout?); install the backend from the checkout, as its README says"
# Read, never sourced; each field is checked before it is used.
lock_field() { awk -v k="$1" '$1 == k { print $2; exit }' "$LOCK"; }
VERSION=$(lock_field version)
COMMIT=$(lock_field commit)
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "release.lock has no valid version"
[[ $VERSION == "$(plugin_version)" ]] || die "release.lock is for $VERSION, but the plugin is $(plugin_version)"
[[ $COMMIT =~ ^[0-9a-f]{40}$ ]] || die "release.lock has no valid commit"

ARCH=$(uname -m)
if (( ! FROM_SOURCE )) && [[ $ARCH != x86_64 ]]; then
  die "releases have binaries for x86_64 only, and this is $ARCH; run it again with --from-source"
fi

RELEASE_BASE=${OMSEC_RELEASE_BASE:-$REPO_URL/releases/download/v$VERSION}
SOURCE_REPO=${OMSEC_SOURCE_REPO:-$REPO_URL}
TARBALL=omarchy-security-hub-$VERSION-$ARCH.tar.gz
DIGEST=$(awk -v t="$TARBALL" '$1 == "sha256" && $3 == t { print $2; exit }' "$LOCK")
if (( ! FROM_SOURCE )); then
  [[ $DIGEST =~ ^[0-9a-f]{64}$ ]] || die "release.lock has no SHA-256 for $TARBALL"
fi

# The README's step 1. The core needs polkit and nftables; without any of
# the others, the daemon reports that module unavailable and keeps going.
REQUIRED=(polkit nftables make)
OPTIONAL=(bubblewrap usbguard pcsclite ccid libfido2 udisks2 cryptsetup fuse3 gocryptfs pinentry gnupg)
# bpf-linker from pacman is built against the system LLVM, so it never
# needs rebuilding after an LLVM upgrade.
BUILD=(git base-devel llvm clang bpf-linker)

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
  note "from source: $SOURCE_REPO, commit $COMMIT"
else
  note "prebuilt: $RELEASE_BASE/$TARBALL"
  note "sha256 (from release.lock): $DIGEST"
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
  say "Fetching commit $COMMIT (v$VERSION)"
  # The commit, not the tag, which could be moved: git checks every object
  # it fetches against its hash, so the tree is the one the commit names.
  git_proto=()
  [[ $SOURCE_REPO != https://* ]] || git_proto=(-c protocol.allow=never -c protocol.https.allow=always)
  tree=$work/src
  git init -q "$tree"
  git "${git_proto[@]}" -C "$tree" fetch -q --depth 1 "$SOURCE_REPO" "$COMMIT" ||
    die "could not fetch commit $COMMIT from $SOURCE_REPO"
  git -C "$tree" -c advice.detachedHead=false checkout -q FETCH_HEAD
  [[ $(git -C "$tree" rev-parse HEAD) == "$COMMIT" ]] || die "fetched $(git -C "$tree" rev-parse HEAD), not $COMMIT"
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
  # Against the digest in release.lock, before anything is unpacked.
  printf '%s  %s\n' "$DIGEST" "$TARBALL" > "$work/check"
  (cd "$work" && sha256sum --check --quiet --strict check) ||
    die "$TARBALL does not have the SHA-256 in release.lock; not installing it"
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
