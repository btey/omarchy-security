<!-- SPDX-License-Identifier: MIT -->

# Changelog

The daemon, the helper, the eBPF monitor and the plugin share one version.
The IPC protocol (`docs/ipc-protocol.md`) and the helper protocol have
their own version numbers, which the daemon reports in `HELLO`.

## Unreleased

- `make ebpf` picks the nightly that matches the system LLVM:
  `nightly-2026-08-01` on LLVM 22, which Omarchy's stable mirror still
  ships, and `nightly-2026-09-30` on LLVM 23. Before, a source build on
  Omarchy failed in `bpf-linker` with "Invalid record". It also names the
  toolchain explicitly, so a `RUSTUP_TOOLCHAIN` from mise no longer
  overrides it. `make -s ebpf-toolchain` prints the nightly it will use.
- `backend/install.sh --from-source` uses that nightly, and goes on
  without the eBPF monitor when only that build fails.

## 1.1.0 (2026-10-01)

The plugin installs its own backend, and has a repository of its own.

### Plugin

* **Installs its own backend.** While the daemon isn't reachable, the hub
  shows a card instead of its tabs:
  * If the backend isn't installed, **Install backend** opens a terminal
    running the plugin's `backend/install.sh`.
  * If it's installed but stopped, **Start** starts the user service.
  * If it's running but not answering, the card shows the error.
  * Once connected, a line above the tabs says when the backend is older
    than the plugin (with **Update backend**) or newer.
* `backend/install.sh` installs the backend at the plugin's version. It
  installs the missing packages (asking about the optional ones), then
  downloads the release tarball and checks it against the release's
  `SHA256SUMS`, or builds the tagged source with `--from-source`. Then it
  runs `sudo make install` and enables the services. It never enables
  USBGuard, runs `ufw`, or changes the firewall mode.
* `backend/uninstall.sh` hands the firewall back to `ufw`, stops the
  services and deletes the files. With `--purge`, it deletes the hub's
  state and configuration too.
* The plugin has a README of its own.

### Release files

* On each tag, CI also publishes the plugin to
  `btey/omarchy-security-hub-plugin`, at the repository's root as
  `omarchy plugin add` needs. It's the same files as
  `security-hub-<version>.tar.gz`.

## 1.0.0 (2026-09-30)

The first release.

### Daemon and helper

* `omarchy-securityd`, a user service, serves the shell over a Unix socket
  (`docs/ipc-protocol.md`). `omarchy-securityd-helper`, a system service,
  does the few things that need root, and checks each request with polkit.
* **Threats:** an eBPF exec monitor (`sched_process_exec`) flags programs
  run from writable places. It can kill or isolate them, and falls back to
  scanning `/proc` without the monitor. Executable files dropped in
  `/tmp`, `/var/tmp` and `/dev/shm` are reported as well.
* **USB:** devices are answered through USBGuard over D-Bus (approve,
  save permanently, block, reject). The hub never enables USBGuard itself.
* **Security keys:** FIDO2, PC/SC and OpenPGP cards are listed, with touch
  prompts for FIDO2, SSH and GnuPG.
* **Firewall:** Omarchy's `ufw` stays in charge by default (`ufw` mode),
  with its rules shown read-only. The `standalone` mode replaces it with
  the hub's own nftables policy (default-deny inbound, Docker
  protection), loaded again at boot. Also: per-program outbound rules and
  connection prompts (NFQUEUE), blocked-traffic alerts, desktop
  notifications, and temporary allows and blocks.
* **Vaults:** gocryptfs and LUKS (through udisks2) vaults, with the
  passphrase read from `pinentry`, and a panic mode that unmounts them all.
* **Sandbox:** programs can be launched in bubblewrap, with or without
  network.
* **Hardening:** an audit of the system's security posture.
* **Configuration:** `~/.config/omarchy-security/config.toml`, reloaded on
  `SIGHUP` (`docs/configuration.md`). `omarchy-secctl` is a command-line
  client.
* **Checking an install:** `make system-check` runs an end-to-end check
  of the installed hub, announcing and undoing each test action.

### Plugin

* A bar shield that follows the firewall mode, with a badge for unseen
  alerts.
* A tabbed hub: Overview, Threats, USB, Security keys, Network, Vaults
  and Hardening. The threat alert, USB, touch and connection prompts
  appear as overlays.
* Colours and borders come from the active Omarchy theme, and follow a
  theme switch.

### Release files

* `omarchy-security-hub-1.0.0-x86_64.tar.gz` holds the binaries, the eBPF
  object, the units, the polkit files, the CLI and the plugin. Unpack it
  and run `sudo make install` and `make plugin-install`, as in the
  README's Installation section, skipping the build.
* `security-hub-1.0.0.tar.gz` holds only the plugin, to unpack into
  `~/.config/omarchy/plugins`.
* The binaries are built on Arch Linux (x86_64) and need a kernel with
  BTF for the eBPF monitor.

### Known limitations

* The end-to-end pass (plan task 4.4) ran on one machine without a USB
  stick, a security key or a second device, so these are not checked end
  to end yet: USBGuard with a new stick, the FIDO2 and GnuPG touch
  prompts, and the checks from a second device (blocked-traffic alerts, a
  temporary inbound allow, a published Docker port).
* There is no Arch package yet (plan task 5.4).
