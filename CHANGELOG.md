<!-- SPDX-License-Identifier: MIT -->

# Changelog

The daemon, the helper, the eBPF monitor and the plugin share one version.
The IPC protocol (`docs/ipc-protocol.md`) and the helper protocol have
their own version numbers, which the daemon reports in `HELLO`.

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

* The end-to-end pass on a fresh install (plan task 4.4) has not been
  done yet. Each part has been tested live on one machine.
* There is no Arch package yet (plan task 5.4).
