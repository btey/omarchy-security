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

Phases 1 (base architecture), 2 (backend daemon) and 3 (QuickShell
views) are complete: the theme provider (3.1), the bar widget (3.2), the
USBGuard panel (3.3), the threat alert OSD (3.4), the security-key touch
prompt (3.5), the firewall rules, connection prompt and hardening audit
views (3.6), the vault panel (3.7), the security-key list and sandbox
launcher (3.8), the tabbed hub that holds them (3.9), and the mode-aware
Network tab (3.10). Phase 4 (testing and documentation) has the
footprint check (4.1), the live theme-switching test (4.2), the
installation manual and usage guide below (4.3), and the security review
of the privilege boundary with fuzz targets for the parsers (4.5), and
the end-to-end pass on a real install (4.4), apart from the checks that
need a USB stick, a security key or a second device. Phase 5 has the CI
(5.1) and the first release,
[v1.0.0](https://github.com/btey/omarchy-security/releases/tag/v1.0.0)
(5.2). The plugin's own repository,
[btey/omarchy-security-hub-plugin](https://github.com/btey/omarchy-security-hub-plugin),
with its backend installer, is published from v1.1.0 on (5.3). From
[v1.1.1](https://github.com/btey/omarchy-security/releases/tag/v1.1.1) on,
the release binaries are built from Omarchy's package mirror, and a build
from source needs only Omarchy's packages.

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
| 3.3 USBGuard panel: connected devices with Approve, Save permanent, Block and Reject | `plugins/security_hub/components/USBGuardPanel.qml`, `services/Usb.js`, `services/SecurityIPC.qml` |
| 3.4 Threat alert OSD: suspicious executions with Kill process, Isolate and It's safe | `plugins/security_hub/components/ThreatAlertOSD.qml`, `services/Threat.js`, `services/SecurityIPC.qml` |
| 3.5 Touch prompt: a security key waiting for a touch (FIDO2, SSH, GnuPG) | `plugins/security_hub/components/YubiKeyPrompt.qml`, `services/Touch.js`, `services/SecurityIPC.qml` |
| 3.6 Firewall rules (list, add, remove), connection prompt (Allow/Block × Once/This process/Always), hardening audit | `plugins/security_hub/components/NetworkSnitch.qml`, `components/ConnectionPrompt.qml`, `components/HardeningSem.qml`, `services/Network.js`, `services/Posture.js`, `services/SecurityIPC.qml` |
| 3.7 Vault panel: vaults with Mount and Unmount, and Panic with a second click | `plugins/security_hub/components/VaultPanel.qml`, `services/Vault.js`, `services/SecurityIPC.qml` |
| 3.8 Security keys and their capabilities; sandbox launcher (program, optional file, network toggle) | `plugins/security_hub/components/TokenPanel.qml`, `components/SandboxLauncher.qml`, `services/Token.js`, `services/Sandbox.js`, `services/SecurityIPC.qml` |
| 3.9 Tabbed hub: Overview (module states, recent alerts), Threats, USB, Security keys, Network, Vaults, Hardening | `plugins/security_hub/SecurityHub.qml`, `components/HubView.qml`, `components/Overview.qml`, `components/ThreatList.qml`, `components/qmldir`, `services/Hub.js` |
| 3.10 Network tab by firewall mode: banner and switch, UFW's rules, hub rules, blocked traffic, temporary decisions; plugin IPC target | `plugins/security_hub/components/NetworkSnitch.qml`, `components/FirewallModeBanner.qml`, `components/UfwRules.qml`, `components/HubRules.qml`, `components/FirewallAlerts.qml`, `components/TempDecisions.qml`, `services/Network.js`, `services/SecurityIPC.qml` |
| 4.1 Footprint check: CPU and memory of the daemon and the helper, idle and under load | `tools/footprint.py` (`make footprint`), `tools/test_footprint.py` |
| 4.2 Live theme switching: every view through every shipped theme, the way `omarchy theme set` applies it | `plugins/security_hub/tests/e2e/themes.qml`, `tools/theme-apply.sh`, `tools/qml-e2e.sh` (`make test-e2e`) |
| 4.3 Installation manual, dependencies, USBGuard, vaults, firewall modes, removal | this README, from [Installation](#installation) on |
| 4.4 End-to-end check of an installed hub, run on this machine in both firewall modes and across a reboot | `tools/system_check.py` (`make system-check`), `tools/test_system_check.py` |
| 4.5 Security review of the privilege boundary, fuzz targets for the parsers of untrusted input | [`docs/security.md`](docs/security.md), `fuzz/` (`make fuzz`, `make test-fuzz`) |
| 5.1 CI: eBPF, lint, every test (none skipped), release binaries, in an Arch container | `.github/workflows/ci.yml`, `make qml-check` |
| 5.2 Release tarballs (binaries, and the plugin alone), published on a `v*` tag | `make dist`, `make plugin-install`, [`CHANGELOG.md`](CHANGELOG.md), `.github/workflows/ci.yml` |
| 5.3 (in progress) Plugin repository published by CI, the backend installer and uninstaller in the plugin, the hub's card for a missing or older backend | `plugins/security_hub/backend/`, `plugins/security_hub/README.md`, `components/BackendSetup.qml`, `services/Backend.js`, `.github/workflows/ci.yml` (`plugin-repo`), `tools/test_backend_scripts.py` |

An install stays in `ufw` mode until the user switches in the Network
tab. See [docs/security.md](docs/security.md) for how to get back to
stock Omarchy from a TTY.

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
CHANGELOG.md                  one version for the crates, eBPF crate and plugin
crates/
  omarchy-securityd/          user daemon: socket server + modules   GPL-3.0-or-later
  omarchy-security-helper/    privileged helper (system service)     GPL-3.0-or-later
  omarchy-security-proto/     IPC types, helper protocol, /proc      GPL-3.0-or-later
  omarchy-security-ebpf/      eBPF exec monitor (nightly, bpf target) GPL-2.0-only
fuzz/                         cargo fuzz targets (nightly), seeds/, checks in src/lib.rs
.github/workflows/ci.yml      CI: make ebpf lint test release dist in archlinux; on v* tags,
                              the release and the plugin repository
dist/
  systemd/user/               omarchy-securityd.service
  systemd/system/             omarchy-securityd-helper.service
  polkit/                     actions (.policy) and rules
docs/ipc-protocol.md          protocol v1 spec         MIT
docs/configuration.md         the daemon's config.toml
docs/security.md              what the hub promises, the 4.5 review
plugins/security_hub/         omarchy-shell plugin     MIT
  manifest.json               kinds: service, bar-widget, panel
  README.md                   the plugin repository's README: install, update, remove
  qmldir
  backend/install.sh          installs the backend at the plugin's version (5.3)
  backend/uninstall.sh        removes it, handing the firewall back to ufw first
  backend/lib.sh              what the two share
  SecurityHub.qml             panel entry point
  StatusBarIndicator.qml      bar widget entry point
  services/SecurityIPC.qml    service entry point: socket client singleton
  services/Protocol.js        framing, message classification, constants
  services/ThemeProvider.qml  singleton: colours and borders from the theme
  services/Palette.js         colors.toml reader, state -> colour roles
  services/Indicator.js       bar widget state: firewall mode, alert badge
  services/Usb.js             USB device list, actions and labels
  services/Threat.js          threat alert list, responses and labels
  services/Touch.js           tokens and touch requests, prompt texts
  services/Network.js         firewall rules and form, held connections, modes,
                              UFW's rules, durations, temporary decisions
  services/Posture.js         hardening audit: order, status roles, summaries
  services/Vault.js           vault list, error texts, panic summary
  services/Token.js           security-key labels, capabilities, last touch
  services/Sandbox.js         sandbox form checks, launches, error texts
  services/Hub.js             hub tabs, what waits in each, alert history
  services/Backend.js         the backend probe, versions, what the setup card says
  components/                 module views (Phase 3)
  components/qmldir           every view, as the directory's import
  components/HubView.qml      the tab row and the view of the tab selected
  components/BackendSetup.qml  Install or Start while there is no daemon; version warnings
  components/Overview.qml     module states and the latest alerts
  components/ThreatList.qml   threat alerts of this session, with answers
  components/USBGuardPanel.qml  USB devices and their policy
  components/ThreatAlertOSD.qml  on-screen card for suspicious executions
  components/YubiKeyPrompt.qml   prompt while a security key waits for a touch
  components/NetworkSnitch.qml   the Network tab, by firewall mode
  components/FirewallModeBanner.qml  which firewall runs, and the switch dialog
  components/UfwRules.qml        UFW's rules, read-only, and the hub's temporary ones
  components/HubRules.qml        the hub's firewall rules, with Add and Remove
  components/FirewallAlerts.qml  blocked traffic, with Allow, Block and Mute
  components/TempDecisions.qml   temporary decisions, with countdowns and Revoke
  components/ConnectionPrompt.qml  card for an outbound connection held for an answer
  components/HardeningSem.qml    hardening audit as a traffic light
  components/VaultPanel.qml      encrypted vaults with Mount, Unmount and Panic
  components/TokenPanel.qml      security keys plugged in and what they can do
  components/SandboxLauncher.qml  runs a program in the bubblewrap sandbox
  tests/                      node unit tests, Quickshell e2e harness
tools/
  mock-securityd.py           protocol v1 stand-in for UI work
  secctl.py                   CLI client: one call, or watch events as NDJSON
                              (installed as omarchy-secctl)
  footprint.py                CPU and memory of the running daemon and helper
  system_check.py             end-to-end check of the installed hub (4.4)
  test_backend_scripts.py     the plugin's installer and uninstaller, against a fake release
  qml-e2e.sh                  runs the plugin against the mock in Quickshell,
                              then the Network tab in each firewall mode,
                              then every theme applied live
  theme-apply.sh              what `omarchy theme set` does to the shell,
                              under a throwaway HOME, for the theme test
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
they are the theme's `red`, `yellow` and `green` from `colors.toml`
(`color1`/`color3`/`color2` in older themes), with muted fallbacks for a
theme that has none. It re-reads `colors.toml` on every `omarchy theme
set`. A theme
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
packets since the user last looked at the Network tab (muted alerts are
left out), and the tooltip gives the mode and the count. Clicking opens
the hub on the Network tab, which clears the badge and keeps it clear
while it is on screen. The time of that last look
is kept in `$XDG_STATE_HOME/omarchy-security/shell-seen.json`, so a shell
restart does not bring the badge back.

The **hub** has seven tabs: **Overview**, **Threats**, **USB**,
**Security keys**, **Network**, **Vaults** and **Hardening**. A tab with
something waiting shows a count or a dot: open threat alerts, blocked USB
devices, a key waiting for a touch, held connections and new blocked
traffic, or an audit with a warning or a failure. The Overview lists the
state of each daemon module and the eight latest alerts (suspicious
programs and blocked traffic together); a row opens its tab. The Threats
tab lists every threat alert of this session with its answers, so an
alert put off with Later on the card is answered there (a second click
sends it), and holds the sandbox launcher below. The hub opens on the tab
its payload names (`omarchy-shell shell toggle security-hub
'{"tab": "usb"}'`; module ids such as `usbguard` work too), or where it
was left. With no text field focused, Left / Right (or h / l) and 1–7
switch tabs. Views stay loaded while their tab is hidden, so a
half-filled form is still there on return.

The **USBGuard panel** (the USB tab) lists every device USBGuard knows about, with its
vendor:product id, serial, interface classes and rule. A blocked device
offers **Approve** (until it is unplugged), **Save permanent** (a rule in
`/etc/usbguard/rules.conf`) and **Reject**; an allowed one offers
**Block** and **Reject**, and **Save permanent** after an Approve from
the panel. Devices found allowed get no Save permanent: the daemon cannot
say whether their allow already comes from a rule, and after
`usbguard generate-policy` it normally does. Reject asks for a second
click, since a rejected device only comes back when it is plugged in
again. An allowed hub has no buttons, because blocking it cuts off every
device behind it (the laptop's root hubs carry the keyboard). A device
that can type as a keyboard as well as something else is flagged, most
strongly when it is also storage, the usual shape of a keystroke-injection
("BadUSB") stick. Rows stay in the order USBGuard saw the devices, so a
device that changes state never moves another's buttons under the
pointer.

The **threat alert OSD** is a card at the top centre of the screen for
each program the daemon reports running from `/tmp`, `/var/tmp`,
`/dev/shm` or memory. It shows the program, its command line, its PID,
parent and user, and how long before the run the file was written.
**Kill process** ends it with `SIGKILL`, **Isolate** pauses it
(`SIGSTOP`, undone by **Resume**), **It's safe** dismisses the alert, and
**Later** hides it for this session while the alert stays open. Kill never
sends `SIGTERM`: the daemon counts the alert as killed as soon as the
signal is sent, so a program that ignored it would keep running unwatched,
and a paused one would not act on it at all. Alerts are shown one at a
time, oldest first, and a new one never replaces the card being read.
The buttons wait 0.8 s after a card appears, so a click meant for the
window below cannot answer it, and the card never takes the keyboard.
The service loads the OSD, so it appears whether or not the hub is open.

The **touch prompt** appears at the bottom centre of the screen, above the
volume OSD, while a security key waits for a touch: a FIDO2 sign-in
(browser, `sudo` with `pam_u2f`), SSH with a security key, or GnuPG with
an OpenPGP card. It names the key and what is probably asking, counts the
seconds, and warns not to touch the key for a request you did not start.
Nothing on it can be clicked and it never takes the keyboard: the touch is
the answer, and the app that asked (a terminal, a browser, pinentry) keeps
the middle of the screen. Once the daemon reports the outcome, the prompt
says so briefly (touched, timed out, cancelled, or the key was unplugged).
A request that was already waiting when the shell connected is not shown,
since the daemon has no call to list them.

The **Network tab** follows the firewall mode. A banner at the top says
which firewall protects the machine: UFW (its rules are shown read-only,
and the hub cannot open what UFW blocks), the Security Hub firewall, both
(a warning: traffic must pass both), none (critical), or unknown while
the privileged helper is not running. It offers the switch that fits:
**Use Security Hub firewall instead**, **Hand back to UFW**, or both
choices. The switch opens a dialog that lists what will change, which of
UFW's rules will be imported and which cannot be (a dry run of
`FIREWALL_SET_MODE`), the Docker note, that the password is asked for,
and the recovery command; it is sent on a second click, and the result
says what was imported.

Below it, in `ufw` mode, come **UFW's rules** (from `/etc/ufw/user.rules`,
with its built-in rules folded away) and the temporary UFW rules the hub
added, each with a countdown and **Revoke**. Then come the **hub's own
rules** (in `firewall.json`), with **Remove** (a second click confirms)
and an **Add rule** form: Block or Allow, outbound or inbound, an address
or prefix, optionally TCP or UDP and a port, and, for outbound rules, one
program by its full path. In `ufw` mode only rules for one program are
enforced by the hub, so the others are folded into "inactive while UFW is
on". In `standalone` mode the fixed baseline the policy always allows is
listed first. The form refuses an inbound allow while UFW is on, because
UFW decides inbound traffic and the daemon would refuse it too, and warns
that one asks for the password otherwise.

**Blocked traffic** lists the alerts newest first, with the count, the
interface and when the last packet came. **Allow** and **Block** add a
temporary decision for the duration picked above the list (5 min, 1 h or
8 h, from `temp_durations_secs`), for the alert's protocol, port and
remote host, or any source for an inbound alert with **Any source**. An
inbound Allow carries a lock: it asks for the password. **Mute** keeps
blocking and stops the desktop notifications for that kind of packet.
The packets listed were already dropped, and in `ufw` mode the list is a
sample, since UFW logs only about three blocked packets a minute. Last,
**Temporary decisions** lists what is allowed or blocked for now, where
(a UFW rule or the hub's table), how long it has left, and **Revoke**.

The **connection prompt** is a card at the top centre, below the threat
card when both are up, for each new outbound connection the firewall
holds while `[firewall] prompt = true` (off by default). It names the
program, the address and port (with the service for well-known ports) and
the PID, and counts down to the daemon's timeout verdict. **Allow** or
**Block** apply **Once**, for **This process** until it exits, or
**Always**, which saves a rule for the program, address and port. It
follows the threat card's rules: one prompt at a time, oldest first, the
buttons wait 0.8 s, and the card never takes the keyboard. A prompt that
another client answers, or that times out, says so briefly and makes way
for the next one.

The **vaults** section lists the vaults from the daemon's configuration,
each locked or open (with its mount point), with **Mount** or
**Unmount**. The hub never asks for a passphrase: Mount makes the daemon
open pinentry, and the row says "Waiting for the passphrase…" until it
is done; that can take minutes, so the hub waits up to 10 min for the
answer. An Unmount that fails because the vault is in use says so and
points to Panic. **Panic** needs a second click within 4 s. It stops the
programs using the vaults (their unsaved work is lost), unmounts and locks
every vault, closes a passphrase prompt that is open, and then says what
it did, including a vault that was still busy and was only detached
lazily. A vault mounted or unmounted outside the hub shows the change too.

The **security keys** section lists the keys and smart card readers
plugged in, with their kind, USB id and serial, and what each can do
(FIDO2, PIV, OpenPGP, OTP; hover for what that means). While a key waits
for a touch its row says so, and for ten minutes after, how the last
request ended. It is read only.

The **sandbox** section runs a program with bubblewrap: the system
read-only, an empty home, `/tmp` and `/run` (so no D-Bus or other
system sockets), no network unless **Network** is
switched on, and optionally one file bound read-write at its own path and
passed to the program, so an untrusted PDF can be opened with
`/usr/bin/zathura` without the viewer seeing anything else. Paths must be
absolute (`~/` works); the daemon checks that they exist, refuses a file
that is a symbolic link, and says why it refused one. The last five launches can be put back in the form with
**Use again**.

The **hardening** section shows the posture audit as a traffic light: the
worst status of the checks (mandatory access control, ptrace scope, the
docker group, swap encryption), then each check with the daemon's summary
and advice. **Check now** runs the checks again; the daemon also re-runs
them every 30 s and sends changes.

### Footprint (task 4.1)

`make footprint` (`tools/footprint.py`) measures the installed services'
systemd cgroups, so the daemon's `journalctl` child counts too: 60 s with
nothing asked of them, then 30 s while one client sends 20 read-only
requests a second and receives the events of every topic but `firewall`
(a `firewall` subscriber would make the daemon hold outbound connections
while prompting is on). It passes when the idle CPU mean is under 2% of
one core and the memory peak is under 40 MB. Memory is counted without
the page cache: the daemon's `MemoryCurrent` is mostly the journal files
`journalctl` reads, which the kernel reclaims under pressure. It is
read-only and exits 1 on a FAIL.

Run on 2026-09-29 on the development machine, with every module active,
UFW mode and three blocked-traffic alerts held:

| Check | Daemon | Helper |
|---|---|---|
| Idle CPU (60 s mean, busiest second) | 0.02%, 0.59% | 0.05%, 0.61% |
| CPU at 20 requests/s | 0.24% | 0.04% |
| CPU at 500 requests/s | 3.8% | 0.03% |
| Memory without page cache (peak) | 3.7 MB | 4.8 MB |
| `MemoryCurrent` (peak) | 26.9 MB | 7.8 MB |

Every request was answered. Not measured here: a burst of suspicious
executions, which would put threat cards on the screen; 4.4 covers
execs on a disposable install.

### Theme switching (task 4.2)

`make test-e2e` ends with `tests/e2e/themes.qml`, which builds every view
of the plugin (the hub and its panel, the bar widget, the threat card and
the two prompts) against the mock and applies each theme in
`$OMARCHY_PATH/themes`, plus one with no red, yellow or green, while they
are loaded. `tools/theme-apply.sh` does what `omarchy theme set` does to
the shell, under a throwaway HOME: it stages the theme, generates its
`shell.toml` with Omarchy's own `omarchy-theme-set-templates`, swaps it in
and sends `shell applyTheme` over IPC to the test's Quickshell instance.
It leaves out the rest of the session (terminals, Hyprland, the
background), so the desktop's theme never changes. After each theme:

* `ThemeProvider` holds the theme's colours as Omarchy's resolver
  (`omarchy-theme-color`) reads them, or its fallbacks where there are
  none.
* Every colour on every item (about 1,450) is one the theme explains: a
  palette, `Color` or `ThemeProvider` colour at any alpha, or one darkened
  or lightened the way `qs.Ui` does it.

Once all have been applied, no item kept one colour through every theme,
applying the first theme again gives every item its first colours back,
and a `[security-hub]` pin in `~/.config/omarchy/shell.toml` takes effect
live and survives a theme switch. Colours bound to `Color` change within
the IPC call; `danger`, `warning` and `success` follow when `colors.toml`
has been read again, about 120 ms later.

The test found two bugs, both fixed. The bar badge's count was always
black: `ThemeProvider.onAccent` never held its value, since QML treats
names of `on` and a capital specially and this object also has an
`accent` (it is now `accentText`). And in a theme with no red,
`danger` kept the red of the theme applied before, because `Color` keeps
its old `urgent` (it now falls back to a fixed muted red, like `warning`
and `success`).

## Development

Requirements: a Rust stable toolchain (1.85 or newer), Node 20 or newer for
the JS tests, Python 3.11 or newer for the mock, and Quickshell for the e2e
test. If Rust is not installed system-wide, prefix the commands with
`mise exec rust@stable --`.

```sh
make build        # cargo build --workspace
make test         # Rust unit + integration tests, JS and Python tool tests,
                  # fuzz seeds replayed on stable
make lint         # rustfmt check, clippy -D warnings, qml-check, qmllint (advisory)
make qml-check    # every plugin .qml and .js parses (qmlformat)
make test-e2e     # plugin QML in a private Quickshell vs. the mock daemon
make run          # run omarchy-securityd with RUST_LOG=debug
make mock         # run the mock daemon on the real socket path
make ebpf         # build the eBPF exec monitor (see below)
make footprint    # CPU and memory of the installed daemon and helper
make system-check # end-to-end check of the installed hub (sudo, interactive)
make fuzz         # fuzz each parser for FUZZ_SECS (60) s; needs cargo-fuzz
make dist         # release tarballs in target/dist, after `make release ebpf`
```

`make fuzz` needs `cargo install cargo-fuzz` and the eBPF crate's nightly
(below). The daemon and the helper are each a library plus a small
`main.rs`, so the fuzz targets in `fuzz/` can call their parsers;
[`docs/security.md`](docs/security.md) lists what each target checks.

Some tests use tools from the system when they are present, and skip
themselves when they are not:

* `dbus-daemon`: a private bus with a fake USBGuard.
* `nft` in an unprivileged user namespace (`unshare -rn`): applies the
  rendered rulesets for real.
* `bwrap`: runs a real sandbox.

No test needs root.

CI (`.github/workflows/ci.yml`) runs on every push to `main` and every pull
request, in an `archlinux` container switched to Omarchy's package mirror
(`stable-mirror.omarchy.org`, which trails Arch's). It builds with that
mirror's `rust`, `rust-src` and `bpf-linker` and no rustup, so the release
binaries need nothing newer than an Omarchy machine has, glibc included,
and the build is the one an Omarchy user does from source. It warns when
the mirror's LLVM has no rustup nightly listed in the Makefile. It
installs every tool above plus `gocryptfs`,
runs the tests as an unprivileged user in a privileged container, with
Omarchy's tagged source (`OMARCHY_REF`) for the themes and `qs.*`, and fails
if any test skips itself. It then runs `make dist` and uploads the
tarballs as a build artifact.

To release, set the new version in `Cargo.toml`,
`crates/omarchy-security-ebpf/Cargo.toml` and
`plugins/security_hub/manifest.json`, add its section to `CHANGELOG.md`
(`make version-check` checks all four), and push a tag `v<version>`. CI
then publishes the tarballs and `SHA256SUMS` as a GitHub release, with
the CHANGELOG section as its notes. Then it commits the plugin tarball's
files to [btey/omarchy-security-hub-plugin](https://github.com/btey/omarchy-security-hub-plugin),
the repository `omarchy plugin add` installs from, and tags it the same
way. It pushes with a deploy key for that repository, in the secret
`PLUGIN_REPO_DEPLOY_KEY`. Without that secret, the step is skipped. To see the skips locally:
`make test RUST_TEST_ARGS=--nocapture 2>&1 | grep -E '; skipping$'`.

To try the plugin in your own shell without installing the daemon, run
the mock or a development build on the real socket path, then link the
plugin (step 5 of [Installation](#installation)):

```sh
make mock &                                   # canned data; or `make run &` for the real daemon
make plugin-link && omarchy plugin enable security-hub
omarchy-shell shell toggle security-hub '{}'  # open or close the panel
```

### The eBPF exec monitor

`crates/omarchy-security-ebpf` builds for `bpfel-unknown-none`, which needs
`rust-src` and a nightly cargo feature (`build-std`), and `bpf-linker`.
`bpf-linker` links against the system LLVM and cannot read bitcode from a
newer LLVM, so rustc has to be on the same LLVM major. There are two ways:

* **pacman's Rust** (what CI and the plugin's installer use without
  rustup). Arch's, and so Omarchy's, `rust` and `bpf-linker` both link the
  system LLVM, so they always match, and `make ebpf` passes
  `RUSTC_BOOTSTRAP=1` for the nightly feature:

  ```sh
  sudo pacman -S --needed rust rust-src bpf-linker
  make ebpf
  ```

* **rustup** (`rustup` conflicts with pacman's `rust`). `make ebpf` uses
  the nightly on the system's LLVM, from `llvm-config`:
  `nightly-2026-08-01` on LLVM 22, which Omarchy's stable mirror still
  ships, and `nightly-2026-09-30` on LLVM 23, which Arch has had since
  2026-10-01 (the crate's `rust-toolchain.toml` pin).
  `make -s ebpf-toolchain` prints it:

  ```sh
  sudo pacman -S --needed bpf-linker
  rustup toolchain install "$(make -s ebpf-toolchain)" --component rust-src
  make ebpf
  ```

  pacman's `bpf-linker` is used over one from `cargo install`, which an
  LLVM upgrade leaves behind (`cargo install --force bpf-linker` rebuilds
  it). When LLVM 24 arrives, add a line for it to the Makefile and raise
  the pin; CI warns when Omarchy's LLVM has no line.

`make ebpf EBPF_RUST=system` or `EBPF_RUST=rustup` picks one by hand.

## Installation

The shortest way is the plugin. It has an installer for the rest:

```sh
omarchy plugin add https://github.com/btey/omarchy-security-hub-plugin
omarchy plugin enable security-hub
```

Then click the shield. Until the backend is there, the hub shows
**Install backend**. It opens a terminal running the plugin's
`backend/install.sh`, which does steps 1, 3 and 4 below for the plugin's
version:
* It installs the missing packages, asking first about the optional ones.
* It downloads the release tarball and checks it against the release's
  `SHA256SUMS`. With `--from-source`, it builds the tagged source instead.
* It runs `sudo make install` and enables the services.

It asks for the password once. It never enables USBGuard, runs `ufw`, or
changes the firewall mode. `backend/uninstall.sh` undoes it, as in
[Removing the Security Hub](#removing-the-security-hub), steps 1 and 3.
The plugin's [README](plugins/security_hub/README.md) has the details.

The steps below do the same by hand: `make install`, either from this
checkout after building it, or from a release tarball with the build done
(see [From a release](#from-a-release)). There is no Arch package yet.
Every step that needs root is marked with `sudo`; the build itself runs
as your user.

### 1. Packages

```sh
sudo pacman -S --needed base-devel llvm clang polkit nftables bubblewrap \
  usbguard pcsclite ccid libfido2 udisks2 cryptsetup fuse3 gocryptfs pinentry gnupg
sudo systemctl enable --now pcscd.socket
```

| Package | Needed for | Without it |
|---|---|---|
| `polkit` | the helper's authorization of every privileged request | the helper refuses everything |
| `nftables` | the firewall, and the boot copy (`nft -f`) | the firewall module is unavailable |
| `bubblewrap` | the sandbox launcher | `SANDBOX_RUN` fails |
| `usbguard` | the USB module (set it up as in [Setting up USBGuard](#setting-up-usbguard)) | the USB module is unavailable |
| `pcsclite`, `ccid` | smart cards and OpenPGP cards | those keys are not listed |
| `libfido2` | the udev `uaccess` rules that let the daemon read FIDO2 keys | no FIDO2 touch prompts |
| `gnupg` | touch prompts for OpenPGP card keys (`gpg-connect-agent`) | no GnuPG touch prompts |
| `gocryptfs`, `fuse3` | gocryptfs vaults | those vaults fail to mount |
| `udisks2`, `cryptsetup` | LUKS vaults | those vaults fail to mount |
| `pinentry` | vault passphrases | no vault can be mounted |
| `ufw` | the `ufw` firewall mode (Omarchy installs and enables it) | only `standalone` mode |

Only `polkit` and `nftables` matter for the core; the daemon reports each
missing piece as its module being `unavailable` and keeps running.

**Do not enable `usbguard` yet.** Started without a policy, it blocks
every USB device, including the keyboard.

`pcscd.socket` starts the smart-card daemon on demand. OpenPGP card
prompts also need the card's keys known to gpg-agent (stubs in
`~/.gnupg/private-keys-v1.d`, which `gpg --card-status` creates).

### 2. Toolchains

The daemon and helper need Rust stable, 1.85 or newer. Omarchy's
packages are enough for everything, the eBPF monitor included:

```sh
sudo pacman -S --needed rust rust-src bpf-linker
```

With `rustup` (or `mise`) instead, install `bpf-linker` with pacman as
above, and the nightly the eBPF crate needs:
`rustup toolchain install "$(make -s ebpf-toolchain)" --component rust-src`.
The eBPF exec monitor is written with
[`aya-ebpf`](https://crates.io/crates/aya-ebpf) (the crate formerly named
`aya-bpf`; cargo fetches it) and the helper loads it with `aya`.

The eBPF monitor is optional. Without it the threat module scans `/proc`
for your own programs every 2 s and reports itself `degraded`;
[The eBPF exec monitor](#the-ebpf-exec-monitor) says how the toolchain
matches the system LLVM. The kernel needs BTF (`CONFIG_DEBUG_INFO_BTF=y`, as Arch's and
Omarchy's kernels have).

### 3. Build and install

```sh
make release ebpf                 # as your user; drop `ebpf` to skip the monitor
sudo make install                 # PREFIX=/usr by default; DESTDIR is honoured
```

This installs `/usr/bin/omarchy-securityd`, the helper and the eBPF
object in `/usr/lib/omarchy-security/`, the CLI client as
`/usr/bin/omarchy-secctl`, the three systemd units, the polkit action and
rules, and `config.example.toml` in `/usr/share/doc/omarchy-security/`.

### From a release

Instead of steps 2 and 3, download
`omarchy-security-hub-<version>-x86_64.tar.gz` and `SHA256SUMS` from the
[releases](https://github.com/btey/omarchy-security/releases). The
binaries are built on Arch Linux:

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf omarchy-security-hub-<version>-x86_64.tar.gz
cd omarchy-security-hub-<version>
sudo make install
```

In step 5, use `make plugin-install` (from the same directory) instead of
`make plugin-link`: it copies the plugin into
`~/.config/omarchy/plugins/security-hub`, and run again it replaces the
older copy. `security-hub-<version>.tar.gz` holds only the plugin:
`tar -xzf security-hub-<version>.tar.gz -C ~/.config/omarchy/plugins`.
To remove a release install, run `sudo make uninstall` from the same
directory, and delete the plugin's folder instead of `make plugin-unlink`.

### 4. Enable the services

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now omarchy-securityd-helper.service
sudo systemctl enable omarchy-security-firewall.service
systemctl --user daemon-reload
systemctl --user enable --now omarchy-securityd.service
```

* **`omarchy-securityd-helper`** (system) does the three things that need
  root, as described in [How privileges are split](#how-privileges-are-split).
* **`omarchy-security-firewall`** (system, runs at boot) loads the
  helper's boot copy (`/var/lib/omarchy-security/firewall.nft`) before the
  network comes up, so the hub's `standalone` policy protects the machine
  before login. In `ufw` mode, the default, the file only removes the
  hub's table and `ufw` protects the machine as before. It does nothing
  until the helper has written the file.
* **`omarchy-securityd`** (user) is the daemon the shell talks to. It
  starts with the graphical session.

The polkit rules let a member of `wheel` in the active local session do
everyday things without a password (block a program, answer a USB
device, kill a flagged process). Turning `ufw` off or on, and every
inbound allow, asks for the administrator password, and polkit keeps it
for a few minutes.

### 5. Add the plugin to the shell

```sh
make plugin-link                  # symlink into ~/.config/omarchy/plugins/security-hub
omarchy plugin enable security-hub
```

The symlink points at this checkout, so keep it where it is (a
`git pull` and `omarchy-shell shell rescanPlugins` update the plugin).
Enabling adds the shield to the right of the bar. Plugins run unsandboxed
inside `omarchy-shell`, so read the code before you enable one.

### 6. Check it

```sh
omarchy-secctl call GET_STATUS
```

Every module should be `active`, except `usbguard`, which is
`unavailable` until USBGuard is set up. The threat module is `degraded`
without the eBPF object or the helper, and `firewall` is `unavailable`
without the helper. Why a
module is not active is in its `detail`, and in the logs:

```sh
journalctl --user -u omarchy-securityd -b
journalctl -u omarchy-securityd-helper -b
```

Click the shield, or run `omarchy-shell security-hub toggle overview`, to
open the hub.

## Setting up USBGuard

USBGuard blocks any USB device not in its policy. Generate the policy
from the devices you use, **with every one of them plugged in**: keyboard,
mouse, dock, webcam, security keys, and anything behind the dock.

```sh
sudo sh -c 'usbguard generate-policy > /etc/usbguard/rules.conf'
sudo chmod 600 /etc/usbguard/rules.conf
sudoedit /etc/usbguard/usbguard-daemon.conf   # confirm the values below
sudo systemctl enable --now usbguard.service usbguard-dbus.service
```

Settings to confirm in `usbguard-daemon.conf` (on Arch only
`IPCAllowedGroups` differs from the packaged file):

| Setting | Why |
|---|---|
| `RuleFile=/etc/usbguard/rules.conf` | the policy generated above, where Save permanent adds rules |
| `ImplicitPolicyTarget=block` | a device no rule matches is blocked, and waits in the hub |
| `PresentDevicePolicy=apply-policy` | devices already plugged in at start are judged by the policy |
| `InsertedDevicePolicy=apply-policy` | so are new ones |
| `IPCAllowedUsers=root` | `usbguard-dbus`, which the daemon talks to, runs as root |
| `IPCAllowedGroups=wheel` | the `usbguard` command, as your user |

Then `omarchy-secctl call GET_STATUS` shows `usbguard` `active`, and a
new device shows up blocked in the hub's USB tab with **Approve**,
**Save permanent** and **Reject**.

Things to know:

* Generating the policy first is what keeps you from being locked out.
  The LUKS passphrase at boot is typed before USBGuard starts, so it is
  never at risk.
* A device plugged into another port, or behind a different dock, is a
  new device to USBGuard: it arrives blocked and has to be approved.
* **To recover** if USBGuard blocks something you need, from a TTY
  (`CTRL ALT F3` with a keyboard that still works) or over ssh:

  ```sh
  sudo systemctl disable --now usbguard.service usbguard-dbus.service
  ```

  USBGuard leaves the USB controllers' default at "not authorized" when it
  stops (unless `RestoreControllerDeviceState=true`), so a device plugged
  in afterwards may stay blocked until the next boot. To authorize one by
  hand: `echo 1 | sudo tee /sys/bus/usb/devices/<port>/authorized`, with
  `<port>` from `usbguard list-devices` or `lsusb -t` (such as `1-2`).

## Vaults

Vaults are listed in the daemon's configuration,
`~/.config/omarchy-security/config.toml`, which
[`docs/configuration.md`](docs/configuration.md) describes key by key. A
sample with every key is installed as
`/usr/share/doc/omarchy-security/config.example.toml`.

Create the vault first. For gocryptfs, a cipher directory:

```sh
mkdir -p ~/Vaults/work.enc && gocryptfs -init ~/Vaults/work.enc
```

For LUKS, an image file with a filesystem you own (a LUKS partition or
USB disk works the same way, with its device as `source`):

```sh
truncate -s 2G ~/Vaults/backup.img
sudo cryptsetup luksFormat ~/Vaults/backup.img
sudo cryptsetup open ~/Vaults/backup.img backup
sudo mkfs.ext4 -E root_owner=$(id -u):$(id -g) /dev/mapper/backup
sudo cryptsetup close backup
```

Then describe it and reload the daemon:

```toml
[[vault]]
id = "work"                    # a-z, 0-9 and -, unique
name = "Work documents"
backend = "gocryptfs"
source = "~/Vaults/work.enc"
mount_point = "~/Vaults/work"  # created if missing

[[vault]]
id = "backup"
name = "Backup disk"
backend = "luks"
source = "~/Vaults/backup.img" # udisks2 picks the mount point, under /run/media/$USER
```

```sh
systemctl --user reload omarchy-securityd
```

An invalid file is logged (`journalctl --user -u omarchy-securityd`) and
ignored: the daemon keeps the configuration it had. Passphrases are never
stored. **Mount** in the hub makes the daemon open `pinentry`, and the
passphrase is kept only for as long as the mount takes. **Panic** stops
every program using a vault, then unmounts and locks them all; it is also
bound to a key below.

The same file holds the firewall settings: connection prompts
(`[firewall] prompt`, off by default) and the blocked-traffic alerts
(`[firewall.alerts]`).

## The firewall modes

Omarchy protects the machine with `ufw` (inbound denied by default, with
LocalSend and Docker's DNS allowed). The hub never turns it off on its
own. The firewall is in one of two modes, shown in the Network tab's
banner and by the colour of the shield:

* **`ufw`** (after install, and until you switch): `ufw` protects the
  machine and its rules are shown read-only. The hub's table holds only
  what works alongside `ufw`: blocks for single programs, outbound
  connection prompts, and temporary decisions. An inbound temporary allow
  becomes a `ufw` rule the hub removes when it expires. Hub rules that
  `ufw` would override are kept but not loaded ("inactive while UFW is
  on").
* **`standalone`**: `ufw` is off and the hub's own policy protects the
  machine. It is the same as Omarchy's `ufw` setup (inbound denied except
  established traffic, loopback, ICMP, DHCP, mDNS and SSDP; outbound
  allowed; published Docker ports reachable only from private networks),
  plus the hub's rules, which are editable here. It is loaded at boot,
  before login, by `omarchy-security-firewall.service`.

Two more states are never chosen by the hub. **Both** (a warning) means
`ufw` was enabled again while in `standalone` mode, for example by an
Omarchy update: both firewalls enforce, which is safe but confusing, and
the banner offers to keep one. **None** (critical) means neither enforces.
**Unknown** means the helper is not running, so the hub cannot tell.

**Switching** is done with **Use Security Hub firewall instead** or
**Hand back to UFW** in the Network tab. The dialog lists what will change
and which of `ufw`'s rules will be imported and which cannot be (the
first switch to `standalone` imports every rule it can express, such as
LocalSend's), and asks for the administrator password. The order makes
sure the machine is never without a firewall:

* **To `standalone`:** the hub's policy is loaded and checked, written to
  the boot copy and `/var/lib/omarchy-security/mode`, and only then is
  `ufw disable` run. If that fails, both stay on (mode `both`).
* **To `ufw`:** `ufw --force enable` is run and its rules checked, and
  only then is the hub's policy removed. If `ufw` fails to come up, the
  hub's policy stays.

The same switch works from a terminal (the password prompt still comes
from the shell's polkit agent):

```sh
omarchy-secctl call FIREWALL_SET_MODE '{"mode": "ufw"}'
omarchy-secctl call FIREWALL_GET_MODE
```

[`docs/security.md`](docs/security.md) lists what the firewall promises,
and the recovery command below returns the machine to stock Omarchy from a
TTY.

## Keybindings

Add these to `~/.config/hypr/bindings.lua` (neither key is taken in stock
Omarchy):

```lua
o.bind("SUPER + CTRL + ALT + S", "Security Hub", "omarchy-shell security-hub toggle overview")
o.bind("SUPER + CTRL + ALT + P", "Vault panic", "omarchy-secctl call VAULT_PANIC")
```

`omarchy-shell security-hub open <tab>` (and `toggle <tab>`, `close`)
opens the hub on a tab: `overview`, `threats`, `usb`, `tokens`, `network`,
`vaults`, `hardening` or a module id, or `""` for the tab it was left on.
The daemon's notifications use it to open the Network tab.

Panic mode (`VAULT_PANIC`) stops every process using a mounted vault,
flushes and unmounts the vaults, and locks the LUKS ones. It never asks
anything, and it runs in the daemon, so the key works while the shell is
frozen. The compositor and the shell (`Hyprland`, `quickshell`,
`omarchy-shell`) are never stopped. A vault they hold is detached lazily
and reported in `failed`, since they keep access to the files they have
open.

## Removing the Security Hub

Undo the steps in this order. The first one matters most: in `standalone`
mode `ufw` is off, and the hub's table is what protects the machine.

1. **Hand the firewall back to `ufw`**: **Hand back to UFW** in the
   Network tab, or `omarchy-secctl call FIREWALL_SET_MODE '{"mode":
   "ufw"}'`. Check that `omarchy-secctl call FIREWALL_GET_MODE` says
   `"mode": "ufw"` and `sudo ufw status` says `active`. If the daemon or
   helper is not working, from a TTY or over ssh:

   ```sh
   sudo ufw --force enable && sudo nft delete table inet omarchy_sec && \
     sudo rm -f /var/lib/omarchy-security/firewall.nft /var/lib/omarchy-security/mode
   ```

   The mode file matters: while it says `standalone`, the helper loads its
   policy again at its next start. This command alone also returns the
   machine to stock Omarchy's firewall without uninstalling anything.
2. **Remove the plugin:**

   ```sh
   omarchy plugin disable security-hub
   make plugin-unlink
   ```
3. **Stop the services and uninstall:**

   ```sh
   systemctl --user disable --now omarchy-securityd.service
   sudo systemctl disable --now omarchy-securityd-helper.service omarchy-security-firewall.service
   sudo nft delete table inet omarchy_sec     # the table stays after the helper stops
   sudo make uninstall
   sudo systemctl daemon-reload && systemctl --user daemon-reload
   ```
4. **USBGuard**, if you set it up only for the hub:
   `sudo systemctl disable --now usbguard.service usbguard-dbus.service`
   (see the note on devices plugged in afterwards in
   [Setting up USBGuard](#setting-up-usbguard)). Your policy stays in
   `/etc/usbguard/rules.conf`.
5. **State**, if you want it gone too: the helper's in
   `/var/lib/omarchy-security` (`sudo rm -r`), and yours in
   `~/.config/omarchy-security` (the configuration) and
   `~/.local/state/omarchy-security` (the hub's rules, and when you last
   looked at the Network tab). Remove the keybindings from
   `~/.config/hypr/bindings.lua`.

Vaults are not touched: unmount them first, and the encrypted data stays
where `source` says.

## Licensing

The daemon and protocol crates are GPL-3.0-or-later. The QuickShell plugin,
the protocol specification, and the tooling are MIT, so other clients may
implement the protocol under any license. See [`LICENSE`](LICENSE). Every
source file carries an `SPDX-License-Identifier`.
