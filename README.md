<!-- SPDX-License-Identifier: MIT -->

# Omarchy Security Hub

A security control centre for Omarchy 4 (Hyprland + QuickShell). It has two
parts:

* **`omarchy-securityd`**: a Rust daemon, run as a systemd user service,
  that talks to eBPF, USBGuard, udev/PC/SC, nftables, and the system
  hardening state.
* **`plugins/security_hub`**: an `omarchy-shell` plugin with a bar
  indicator and a panel. It reaches the daemon over a Unix socket.

The design is in [`omarchy_4_security_hub_technical_plan_English.md`](omarchy_4_security_hub_technical_plan_English.md).
The wire contract is in [`docs/ipc-protocol.md`](docs/ipc-protocol.md).

## Status

Phases 1 (base architecture) and 2 (backend daemon) are complete. The
QuickShell views are Phase 3, which has started with the theme provider
(3.1) and the bar widget (3.2).

| Task | Where |
|---|---|
| 1.1–1.4 Repository, build, protocol, plugin template | `LICENSE`, `Cargo.toml`, `docs/ipc-protocol.md`, `plugins/security_hub/` |
| 2.1 Unix socket server | `crates/omarchy-securityd/src/server.rs` |
| 2.2 eBPF exec monitor and response | `crates/omarchy-security-ebpf`, `crates/omarchy-security-helper/src/exec.rs`, `crates/omarchy-securityd/src/threat.rs` |
| 2.3 USBGuard over D-Bus | `crates/omarchy-securityd/src/usbguard.rs` |
| 2.4 Security tokens and touch prompts | `crates/omarchy-securityd/src/token.rs` |
| 2.5 nftables rules and bubblewrap sandbox | `crates/omarchy-securityd/src/firewall.rs`, `crates/omarchy-security-helper/src/firewall.rs`, `crates/omarchy-securityd/src/sandbox.rs` |
| 2.6 Posture audit | `crates/omarchy-securityd/src/posture.rs` |
| 2.7 systemd units and polkit | `dist/` |
| 2.8 Live install and privileged validation, CLI client | `tools/secctl.py`; results below |
| 2.9 USBGuard setup and validation against the real service | results below |
| 2.10 Daemon configuration file, reloaded on `SIGHUP` | `crates/omarchy-securityd/src/config.rs`, [`docs/configuration.md`](docs/configuration.md), `dist/config.example.toml` |
| 2.11 Encrypted vaults (gocryptfs, and LUKS through udisks2), passphrase from `pinentry` | `crates/omarchy-securityd/src/vault.rs`, `udisks.rs`, `pinentry.rs` |
| 2.12 Vault panic mode, with a keybinding (below) | `crates/omarchy-securityd/src/vault.rs`, `holders.rs` |
| 2.13 Connection interception (NFQUEUE) in the helper | `crates/omarchy-security-helper/src/connections.rs`, `nfqueue.rs`, `sockdiag.rs` |
| 2.14 Executable-scoped rules and connection prompts (`FIREWALL_DECIDE`) | `crates/omarchy-securityd/src/firewall.rs` |
| 2.15 Touch prompts for OpenPGP cards (gpg) | `crates/omarchy-securityd/src/gpg.rs` |
| 2.16 Executable file drops in `/tmp`, `/var/tmp` and `/dev/shm` (inotify) | `crates/omarchy-securityd/src/drops.rs` |
| 2.17 `ufw` detection, firewall mode, read-only `ufw` rules | `crates/omarchy-securityd/src/ufw.rs`, `crates/omarchy-security-helper/src/firewall.rs` |
| 2.18 Standalone baseline policy (default-deny inbound, Docker protection) and its boot copy | `crates/omarchy-security-helper/src/firewall.rs`, `dist/systemd/system/omarchy-security-firewall.service` |
| 2.19 Turning `ufw` off and on from the hub (`FIREWALL_SET_MODE`), importing `ufw`'s rules | `crates/omarchy-security-helper/src/firewall.rs`, `crates/omarchy-securityd/src/firewall.rs`, `dist/polkit/` |
| 2.20 Blocked-traffic alerts from the kernel log, desktop notifications with actions | `crates/omarchy-securityd/src/alerts.rs`, `notify.rs`, `firewall.rs` |
| 2.21 Temporary allow and block in both modes (`FIREWALL_TEMP_*`) | `crates/omarchy-securityd/src/firewall.rs`, `crates/omarchy-security-helper/src/firewall.rs` |
| 3.1 Theme provider: colours and borders from the active Omarchy theme | `plugins/security_hub/services/ThemeProvider.qml`, `Palette.js` |
| 3.2 Bar widget: shield that follows the firewall mode, badge with unseen alerts | `plugins/security_hub/StatusBarIndicator.qml`, `services/Indicator.js`, `services/SecurityIPC.qml` |

Not built yet:

* The firewall views (3.6, 3.10). `FIREWALL_SET_MODE`, the alerts and
  temporary decisions work over the protocol and from the daemon's
  desktop notifications, but the panel has no switch or alert list yet;
  an install stays in `ufw` mode until the user switches. See
  [docs/security.md](docs/security.md) for how to get back to stock
  Omarchy from a TTY.

### Live validation (task 2.8)

Run on 2026-09-26 on the development machine (Omarchy, kernel 7.2.5,
sudo 1.9.17), with `make release ebpf && sudo make install`, both units
enabled, and USBGuard not yet enabled. Every check in the plan's §5.2 passed:

| Check | Result |
|---|---|
| eBPF attach | The helper logged `exec monitor attached` under the unit's hardening as shipped, and `threat` became `active`. No directive had to be relaxed. |
| Exec detection | `/tmp/x a b` was reported with the right pid, ppid and argv, origin `tmp`. An exec from a `memfd_create` fd was reported as `/memfd:evil`, origin `memfd`. |
| Cross-user response | A `/tmp/s2 300` run as `nobody` (uid 65534) was quarantined (state `T`), resumed (`S`) and killed (gone) through the helper. |
| Firewall | Blocking outbound TCP to `1.1.1.1/32` port 443 made `curl https://1.1.1.1` time out, and the rule showed in `nft list table inet omarchy_sec` with a matching drop counter. `ufw status verbose` was the same before and after, and all 65 `ufw` chains stayed in the ruleset. Removing the rule restored access. |
| Polkit | As a wheel member in the Hyprland session, no firewall or signal request asked for a password. The helper logged `authorized=true` for each. |
| Reconnect | With our table deleted and the helper restarted, the daemon reconnected within a second, re-applied the saved rule, and `threat` went back to `active`. |
| Degraded | With the helper stopped, `threat` went to `degraded`, `firewall` to `unavailable`, and the daemon kept running. It recovered when the helper came back. |
| Footprint | At idle, the daemon used 4.8 MB and the helper 7.8 MB (`MemoryCurrent`), both at 0.0% CPU. |

No bugs turned up. One quirk of the test itself: when a process that
`sudo -u` started is stopped, sudo also stops its own process group. So
quarantining a process started from a script with `sudo -u nobody …`
suspends the script too. Start the target with `setsid` in scripted
checks (4.4).

### USBGuard validation (task 2.9)

Run on 2026-09-26, after generating `/etc/usbguard/rules.conf` with every
needed device plugged in. The only change from Arch's
`usbguard-daemon.conf` is `IPCAllowedGroups=wheel`. The other settings the
plan's §5.3 asks for are the packaged defaults. Every check passed:

| Check | Result |
|---|---|
| Status | `GET_STATUS` shows `usbguard` `active`, listing the 6 allowed devices. |
| New device | A USB stick not in the policy produced `USB_DEVICE_PRESENTED` with `rule: block`, and did not mount. |
| Allow | `USBGUARD_SET_POLICY` `allow` mounted it, and `usbguard list-rules` gained no rule. |
| Reject | `reject` produced `USB_DEVICE_REMOVED`, and the device left `lsblk`. |
| Permanent | `allow` with `permanent: true` added an `allow id 0951:1666 serial … hash …` rule. After unplugging it and plugging it back in, USBGuard allowed the stick by itself and it mounted. |
| Resync | Restarting `usbguard-dbus`, then `usbguard` (which renumbers devices), left the daemon with the same 7 devices as `usbguard list-devices`, with no duplicates. |
| Polkit | No password was asked for. The daemon calls `usbguard-dbus` without interactive authorization, so a call polkit had not allowed outright would have failed. |

One bug turned up and is fixed: `usbguard-dbus` takes `org.usbguard1` on
the bus before it has connected to `usbguard-daemon`. When the two units
start together, the daemon's first `listDevices` failed with `NoServer`,
and the module stayed `unavailable` until the daemon restarted. It now
retries with backoff (0.5 s, doubling to 30 s) while the name has an owner.
After the fix, each restart above recovered within about 4 s.

Two things for the Phase 3 views. A device that a permanent rule allows
still arrives as `USB_DEVICE_PRESENTED` with `rule: block`, followed at once
by `USB_DEVICE_POLICY_CHANGED` to `allow`, because that is the order
USBGuard reports them in. The USB prompt should wait briefly before asking,
rather than flash. Also, `usbguard-dbus` reports no product name for
devices without a string descriptor. The daemon falls back to
`USB device vvvv:pppp`.

To recover if USBGuard ever blocks something you need, run
`sudo systemctl disable --now usbguard` from a TTY or over ssh.

### How privileges are split

`omarchy-securityd` runs as the desktop user and needs no privileges.
USBGuard, sysfs, `/proc`, hidraw, and `bwrap` are all reachable as that
user. Three things need root, and `omarchy-securityd-helper` does them. It
is a system service that runs as root with only `CAP_BPF`, `CAP_PERFMON`,
`CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, and `CAP_KILL`:

* It loads the eBPF exec monitor and streams suspicious executions.
* It replaces `table inet omarchy_sec`.
* It signals processes that it reported itself.

It checks each request with polkit (`org.omarchy.security.*`) against the
connecting process. `dist/polkit/50-omarchy-security.rules` lets wheel
members in a local session do this without a password.

Every module works without the helper, with less function. The threat
module scans `/proc` for the user's own processes and reports itself
`degraded`. The firewall module is `unavailable`.

## Layout

```
Cargo.toml                    workspace (edition 2024, stable toolchain)
crates/
  omarchy-securityd/          user daemon: socket server + modules   GPL-3.0-or-later
  omarchy-security-helper/    privileged helper (system service)     GPL-3.0-or-later
  omarchy-security-proto/     IPC types, helper protocol, /proc      GPL-3.0-or-later
  omarchy-security-ebpf/      eBPF exec monitor (nightly, bpf target) GPL-2.0-only
dist/
  systemd/user/               omarchy-securityd.service
  systemd/system/             omarchy-securityd-helper.service
  polkit/                     actions (.policy) and rules
docs/ipc-protocol.md          protocol v1 spec         MIT
plugins/security_hub/         omarchy-shell plugin     MIT
  manifest.json               kinds: service, bar-widget, panel
  qmldir
  SecurityHub.qml             panel entry point
  StatusBarIndicator.qml      bar widget entry point
  services/SecurityIPC.qml    service entry point: socket client singleton
  services/Protocol.js        framing, message classification, constants
  services/ThemeProvider.qml  singleton: colours and borders from the theme
  services/Palette.js         colors.toml reader, state -> colour roles
  services/Indicator.js       bar widget state: firewall mode, alert badge
  components/                 module views (Phase 3)
  tests/                      node unit tests, Quickshell e2e harness
tools/
  mock-securityd.py           protocol v1 stand-in for UI work
  secctl.py                   CLI client: one call, or watch events as NDJSON
                              (installed as omarchy-secctl)
  qml-e2e.sh                  runs the plugin against the mock in Quickshell
```

The plan's `plugins/security_hub/` tree is kept. The one addition is
`manifest.json`, which omarchy-shell needs to load the plugin. The plugin
is split along omarchy-shell's plugin kinds: a single **service**
(`SecurityIPC.qml`) owns the socket, and the **bar widget** and the
**panel** both reach it through `shell.serviceFor("security-hub")`.
Views take their colours and borders from the `ThemeProvider` singleton
(`import "services"`), never from hex values of their own. It passes
through `qs.Commons` `Color` and `Style` (popup surface with its
transparency, accent, border colour and width, Hyprland's rounding) and
adds `danger`, `warning` and `success`, which `Color` does not have:
`danger` is the theme's `urgent`, and the other two are the theme's
`yellow` and `green` from `colors.toml` (`color3`/`color2` in older
themes). It re-reads `colors.toml` on every `omarchy theme set`. A theme
or the user can pin any of the three in `shell.toml`:

```toml
[security-hub]
warning = "#e0af68"   # a hex colour, or a role: accent, urgent, foreground, muted
```

Spacing and typography still come from `Style` directly.

The **bar widget** is a shield in the bar foreground while the firewall
mode is `ufw` or `standalone`, in `warning` when both firewalls enforce,
in `danger` when neither does, and dimmed when the mode is unknown or the
daemon is not connected. A badge counts the blocked-traffic alerts with
packets since the user last opened the hub (muted alerts are left out),
and the tooltip gives the mode and the count. Clicking opens the hub with
`{"tab": "network"}`, which clears the badge. The time of that last look
is kept in `$XDG_STATE_HOME/omarchy-security/shell-seen.json`, so a shell
restart does not bring the badge back.

## Development

Requirements: a Rust stable toolchain (1.85 or newer), Node 20 or newer for
the JS tests, Python 3.11 or newer for the mock, and Quickshell for the e2e
test. If Rust is not installed system-wide, prefix the commands with
`mise exec rust@stable --`.

```sh
make build        # cargo build --workspace
make test         # Rust unit + integration tests, JS protocol tests
make lint         # rustfmt check, clippy -D warnings, qmllint (advisory)
make test-e2e     # plugin QML in a private Quickshell vs. the mock daemon
make run          # run omarchy-securityd with RUST_LOG=debug
make mock         # run the mock daemon on the real socket path
make ebpf         # build the eBPF exec monitor (see below)
```

Some tests use tools from the system when they are present, and skip
themselves when they are not:

* `dbus-daemon`: a private bus with a fake USBGuard.
* `nft` in an unprivileged user namespace (`unshare -rn`): applies the
  rendered rulesets for real.
* `bwrap`: runs a real sandbox.

No test needs root.

### The eBPF exec monitor

`crates/omarchy-security-ebpf` builds for `bpfel-unknown-none`, which needs
nightly Rust with `rust-src`, and `bpf-linker`:

```sh
rustup toolchain install nightly-2026-08-01 --component rust-src
cargo install bpf-linker
make ebpf
```

`bpf-linker` links against the system LLVM (22 on Arch today). It cannot
read bitcode from a newer LLVM, so the crate's `rust-toolchain.toml` pins
the last nightly on LLVM 22. When Arch moves to LLVM 23, raise the pin and
reinstall `bpf-linker`.

## Installation

```sh
make release ebpf                 # as your user
sudo make install                 # PREFIX=/usr by default; DESTDIR is honoured
sudo systemctl enable --now omarchy-securityd-helper.service
sudo systemctl enable omarchy-security-firewall.service
systemctl --user enable --now omarchy-securityd.service
```

`omarchy-security-firewall.service` loads the helper's boot copy
(`/var/lib/omarchy-security/firewall.nft`) before the network comes up, so
the hub's `standalone` policy protects the machine before login. In `ufw`
mode, the default, the file only removes the hub's table and `ufw` protects
the machine as before. The unit does nothing until the helper has written
the file.

Optional system packages:

* `usbguard`, with `usbguard-dbus.service` running, for the USBGuard module.
* `nftables` for the firewall.
* `bubblewrap` for the sandbox.
* `gocryptfs` and `fuse3` for gocryptfs vaults, `udisks2` for LUKS vaults
  ([`docs/configuration.md`](docs/configuration.md)).

Tokens need the usual udev `uaccess` rules for FIDO devices (shipped with
`libfido2`) before touch prompts can be read. OpenPGP card prompts need
`gnupg` (`gpg-connect-agent`) with `pcsclite` and `ccid`, and card keys
known to gpg-agent (stubs in `~/.gnupg/private-keys-v1.d`).

`sudo make uninstall` removes everything `install` put in place.

### Vault panic keybinding

Panic mode (`VAULT_PANIC`) stops every process using a mounted vault,
flushes and unmounts the vaults, and locks the LUKS ones. It never asks
anything, and it runs in the daemon, so it works while the shell is
frozen. `make install` puts the CLI client (`tools/secctl.py`) in place
as `omarchy-secctl`. To bind panic mode to `SUPER CTRL ALT + P`, add this
to `~/.config/hypr/bindings.lua`:

```lua
o.bind("SUPER + CTRL + ALT + P", "Vault panic", "omarchy-secctl call VAULT_PANIC")
```

The compositor and the shell (`Hyprland`, `quickshell`, `omarchy-shell`)
are never stopped. A vault they hold is detached lazily and reported in
`failed`, since they keep access to the files they have open.

### Trying the plugin in your shell

```sh
make run &                                    # or `make mock &` for canned data
make plugin-link                              # symlink into ~/.config/omarchy/plugins/security-hub
omarchy plugin enable security-hub            # adds the bar widget (right section)
omarchy-shell shell toggle security-hub '{}'  # open or close the panel
```

`make plugin-unlink` removes the symlink. Plugins run unsandboxed inside
`omarchy-shell`, so read the code before you enable one.

## Licensing

The daemon and protocol crates are GPL-3.0-or-later. The QuickShell plugin,
the protocol specification, and the tooling are MIT, so other clients may
implement the protocol under any license. See [`LICENSE`](LICENSE). Every
source file carries an `SPDX-License-Identifier`.
