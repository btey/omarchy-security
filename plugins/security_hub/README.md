<!-- SPDX-License-Identifier: MIT -->

# Security Hub for Omarchy

A bar shield and a tabbed panel for `omarchy-shell`. It covers threat alerts
for programs run from writable places, USB devices through USBGuard,
security-key touch prompts, a firewall that works with Omarchy's `ufw`, and
per-program connection rules. It also has encrypted vaults, a sandbox
launcher and a hardening audit.

This is the plugin, the part the shell loads. The work is done by a
backend, `omarchy-securityd` and its root helper, which the plugin can
install for you. The source, the documentation and the issue tracker are
in [btey/omarchy-security](https://github.com/btey/omarchy-security).
This repository is published from there on each release; don't send
changes here.

## Install

```sh
omarchy plugin add https://github.com/btey/omarchy-security-hub-plugin
omarchy plugin enable security-hub
```

The shield appears on the right of the bar. Click it: until the backend is
installed, the hub shows **Install backend**. That opens a terminal that
runs `backend/install.sh`, which:

1. lists what it will do and asks you to confirm;
2. installs the missing packages with pacman, asking first about the
   optional ones (USBGuard, smart cards, FIDO2, vaults, sandbox);
3. downloads the release that matches this plugin's version, and checks it
   against the release's `SHA256SUMS`;
4. installs it with `sudo make install` and enables the services
   (`omarchy-securityd-helper`, `omarchy-security-firewall` and your
   `omarchy-securityd`).

It asks for your password once, in the terminal. It never enables USBGuard,
never runs `ufw` and never changes the firewall mode, so Omarchy's firewall
stays in charge until you switch it in the Network tab.

You can also run it yourself:

```sh
~/.config/omarchy/plugins/security-hub/backend/install.sh
```

With `--from-source` it builds the same release from source instead,
with packages from Omarchy's repositories only: it installs `rust`,
`rust-src` and `bpf-linker` with pacman when Rust is missing. If you use
`rustup`, it uses that, and builds the eBPF monitor only when the nightly
it names is installed. Without the eBPF monitor the daemon still works,
and the threat module scans `/proc` instead. `--help` lists the other
options. Prebuilt binaries are for x86_64, built from Omarchy's packages
too.

## USBGuard

USB control needs USBGuard, set up with a policy first. Don't just enable
the service: without a policy, it blocks every device, including your
keyboard. Follow
[Setting up USBGuard](https://github.com/btey/omarchy-security#setting-up-usbguard).

## Update

```sh
omarchy plugin update security-hub
```

After an update, the hub says when the backend is older than the plugin.
**Update backend** runs the installer again for the new version.

The shell reloads a plugin when its files change, but Omarchy 4.0.4 can
keep showing the hub it had already loaded. If the hub looks unchanged
after an update, restart the shell:

```sh
omarchy-restart-shell
```

## Remove

```sh
~/.config/omarchy/plugins/security-hub/backend/uninstall.sh
omarchy plugin remove security-hub
```

The uninstaller first hands the firewall back to `ufw` (turning it on
again if the hub had turned it off). Then it stops the services and deletes
the files. Your rules and configuration stay, unless you pass `--purge`.
USBGuard and its policy stay too.

## Licence

The plugin, and its installer, are MIT (`LICENSE`). The backend it
installs is GPL-3.0-or-later, with its eBPF monitor under GPL-2.0-only; see
the main repository's Licensing section.
