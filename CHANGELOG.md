<!-- SPDX-License-Identifier: MIT -->

# Changelog

The daemon, the helper, the eBPF monitor and the plugin share one version.
The IPC protocol (`docs/ipc-protocol.md`) and the helper protocol have
their own version numbers, which the daemon reports in `HELLO`.

## 1.1.5 (2026-10-01)

- gocryptfs vaults mount and unmount when the daemon runs as its systemd
  service. They failed with "fusermount3: mount failed: Operation not
  permitted": the unit's `NoNewPrivileges=yes` reaches every program the
  daemon starts, and `fusermount3` is setuid. The user's systemd manager
  now starts gocryptfs (as a transient service per mount, which also
  outlives a daemon restart) and `fusermount3`, so the daemon keeps its
  hardening. The passphrase reaches gocryptfs through a private FIFO in
  `$XDG_RUNTIME_DIR` instead of a pipe; it is still never stored.

## 1.1.4 (2026-10-01)

- The Vaults tab can add and remove vaults, so setting one up no longer
  means editing `config.toml` by hand. **Add vault** takes a name, the
  backend, an existing gocryptfs folder or LUKS disk or image, and for
  gocryptfs where to open it. **Remove** (a second click, on a locked
  vault) takes it out again and keeps its encrypted files.
- **Add vault** can also create a new gocryptfs vault, from a name alone:
  the daemon makes the folder with `gocryptfs -init` and asks for the new
  passphrase twice with pinentry (one window with `SETREPEAT`, else two).
  New IPC method `VAULT_CREATE`; the passphrase never crosses the socket.
- New IPC methods `VAULT_ADD` and `VAULT_REMOVE`, and a `VAULT_REMOVED`
  event, which also comes when a vault leaves the configuration through a
  hand edit and a reload. The daemon edits the file in place: it keeps
  comments and layout, checks the result before writing, replaces the file
  atomically, and follows a symlink rather than replacing it. Before, a
  hub kept showing a vault removed by hand until it reconnected.

## 1.1.3 (2026-10-01)

- The shield in the bar takes the same slot as the tray, network and audio
  icons beside it, instead of the narrower one of the center's status
  items. The alert badge stays on the shield's corner.

## 1.1.2 (2026-10-01)

- The hub opens below the bar instead of over it. Like Omarchy's
  notifications, it clears a top or right bar by the bar's size, and
  takes no room for a hidden bar.
- The hub has a close button in its header. Esc still closes it, while the
  hub has the keyboard.

## 1.1.1 (2026-10-01)

Building needs nothing outside Omarchy's repositories, and the release
binaries are built from them.

- `make ebpf` builds with pacman's `rust`, `rust-src` and `bpf-linker`
  when there is no rustup. Those packages all link the system LLVM, so
  they always match, and `RUSTC_BOOTSTRAP=1` gives the BPF target its one
  nightly feature. `make lint`, `make fmt`, `make test-fuzz` and
  `make clean` no longer need rustup's `cargo +stable`.
- With rustup, `make ebpf` picks the nightly that matches the system LLVM:
  `nightly-2026-08-01` on LLVM 22, which Omarchy's stable mirror still
  ships, and `nightly-2026-09-30` on LLVM 23. Before, a source build on
  Omarchy failed in `bpf-linker` with "Invalid record". It names the
  toolchain, so a `RUSTUP_TOOLCHAIN` from mise no longer overrides it,
  and it prefers pacman's `bpf-linker`. `make -s ebpf-toolchain` prints
  the choice.
- `backend/install.sh --from-source` installs `rust`, `rust-src` and
  `bpf-linker` with pacman when there is no rustup. It goes on without the
  eBPF monitor when only that build fails.
- CI builds and tests on Omarchy's package mirror, with those packages,
  so the release binaries need nothing newer than Omarchy has.

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
