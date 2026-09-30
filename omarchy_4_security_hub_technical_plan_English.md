# Omarchy 4 Security Hub: Technical Specifications and Implementation Plan



This document details the architecture, component specifications, and step-by-step implementation plan for the development of the **Security Hub** in **Omarchy 4** (Hyprland + QuickShell).

The project is divided into a decoupled architecture: a high-performance **Rust Backend Daemon** with controlled privileges and a **QuickShell Frontend Interface (QML/JS)** for real-time control from the compositor.

---

## 1. Overall System Architecture



The communication flow follows the **asynchronous IPC pattern (D-Bus / Unix Domain Socket)** using JSON/Protobuf message passing, ensuring that shell interface performance is not affected by system inspection operations.

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                          QuickShell Frontend (QML)                                │
│  ┌──────────────────┬──────────────────┬──────────────┬─────────────┬──────────┐  │
│  │ Threat Monitor   │ Credential/HSM   │ Network FW   │ Hardening   │ USBGuard │  │
│  │ (eBPF Alerts)    │ (YubiKey OSD)    │ (OpenSnitch) │ Audit Checklist │ Control│  │
│  └─────────┬────────┴────────┬─────────┴──────┬───────┴──────┬──────┴────┬─────┘  │
│            │                 │                │              │           │        │
│            └─────────────────┼────────────────┼──────────────┼───────────┘        │
│                              │ Theme Provider (Omarchy Color Palette/Style)       │
└──────────────────────────────┼────────────────────────────────────────────────────┘
                               │ IPC (Unix Socket / Private D-Bus)
┌──────────────────────────────┴────────────────────────────────────────────────────┐
│                    `omarchy-securityd` (Rust Daemon)                              │
│  ┌──────────────────┬──────────────────┬──────────────┬─────────────┬──────────┐  │
│  │ Module: eBPF     │ Module: PC/SC    │ Module:      │ Module:     │ Module:  │  │
│  │ (aya-rs / exec)  │ & FIDO2 (udev)   │ nftables     │ Sys-Audit   │ USBGuard │  │
│  └─────────┬────────┴────────┬─────────┴──────┬───────┴──────┬──────┴────┬─────┘  │
└────────────┼─────────────────┼────────────────┼──────────────┼───────────┘        │
             │                 │                │              │           │        │
┌────────────▼─────────────────▼────────────────▼──────────────▼───────────▼────────┐
│                            Linux Kernel & Daemons                                 │
│   [eBPF tracepoints]    [USB / Smartcard]   [nftables]    [Sys-State]   [USBGuard] │
└───────────────────────────────────────────────────────────────────────────────────┘

```

---

## 2. Technical Detail of Backend Components (`omarchy-securityd`)



The `omarchy-securityd` service is developed in **Rust** using `tokio` as an asynchronous runtime. It runs as a systemd user service (`systemctl --user`), invoking a helper with limited Linux capabilities (`CAP_NET_ADMIN`, `CAP_BPF`, `CAP_SYS_PTRACE`) to avoid running the entire daemon as `root`.

### 2.1 Module 1: Threat Detection and Response (eBPF & Inotify)



* **Rust Library:** `aya` (for native loading and management of eBPF programs in Rust).


* **Mechanism:**

* Attaches an eBPF probe to the `sys_enter_execve` tracepoint.


* Filters binary executions in `/tmp`, `/var/tmp`, `/dev/shm`, or anonymous memory descriptors (`memfd_create`).


* Emits a real-time event with the `PID`, `PPID`, `UID`, `binary_path`, and executed arguments to the IPC socket.




* **Active Response:** Exposes the IPC methods `KillProcess(pid: u32, signal: u32)` and `QuarantineProcess(pid: u32)` (sends `SIGSTOP`).



### 2.2 Module 2: Credentials and HSM / Cryptography Modules



* **Mechanisms:**

* **PC/SC & USB Monitoring:** Uses `libudev-sys` to detect insertion and removal of security tokens (YubiKey, SoloKeys).


* **FIDO2 / SSH Prompt Interception:** Listens for requests by monitoring events in the `pcscd` API or reading `ssh-agent` / `gpg-agent` traces via local sockets.




* **Encrypted Volume Control:**

* Integrates direct calls to `cryptsetup` (via `libcryptsetup-rs`) or `gocryptfs` to mount/unmount secure containers.


* **Panic Mode (*Emergency Unmount*):** Closes open file descriptors, unmounts encrypted folders, and forces a buffer flush (`sync`).





### 2.3 Module 3: Network Security and Isolation (Firewall & Sandbox)



* **`nftables` Controller:**

* Interacts with the native `mnl` / `nftables` library to manage a dedicated table in netfilter: `table inet omarchy_sec`.


* Maintains dynamic sets of blocked or authorized IPs and ports per process.




* **Sandbox Invoker (Bubblewrap Wrapper):**

* Provides a dynamic `bwrap` profile generator.


* Constructs the isolation command:


```bash
bwrap --unshare-all --share-net --ro-bind / / --tmpfs /tmp --tmpfs /home/$USER \
      --bind $TARGET_FILE $TARGET_FILE --proc /proc --dev /dev $EXECUTABLE

```





### 2.4 Module 4: Security Posture and Audit (System Audit)



* **Configuration Evaluator:** A background state analyzer that evaluates every 30 seconds:


* Reads `/sys/fs/selinux/enforce` or `/sys/kernel/security/apparmor/profiles`.


* Checks `sysctl kernel.yama.ptrace_scope` (must be `>= 1`).


* Checks the `/etc/group` file to validate if the current user belongs to the `docker` group (critical risk alert).


* Checks `/proc/swaps` to ensure swap areas are encrypted.





### 2.5 Module 5: USBGuard Device Management



* **Mechanisms:**

* Connects via D-Bus to `org.isis.USBGuard` (or native USBGuard IPC socket).


* Listens for `presenceChanged` and `devicePolicyChanged` signals.


* Queries the current list of connected devices and their policies (`listDevices`).




* **IPC-Exposed Actions:**

* `AuthorizeUSBDevice(id: u32, permanent: bool)`: Allows peripheral connection (optionally saves rule in `/etc/usbguard/rules.conf`).


* `BlockUSBDevice(id: u32)`: Instantly blocks or rejects the USB peripheral.


* `RejectUSBDevice(id: u32)`: Removes logical access to the USB port.





---

## 3. QuickShell Interface Specification & Visual Integration (UI)



### 3.1 Thematic Consistency with Omarchy



Any visual component generated by the plugin (bar widgets, floating panels, modals, and OSDs) **must strictly use Omarchy's global style variables**.

* **Style Injection:** Binds to the Omarchy color/style module (via `Omarchy.Theme` or the global config import in QuickShell).


* **Properties to Synchronize:**

* `background`: Background color of panels (respecting user-configured transparency/blur).


* `foreground` / `text`: Main text color.


* `accent`: Accent color for buttons, switches, and status charts.


* `danger` / `warning` / `success`: Semantic colors to indicate threats (blocked process, rejected USB, hardening OK).


* `border.radius` / `border.color`: Borders and radii adapted to the user's theme.





### 3.2 Plugin Structure (`plugins/security_hub/`)



```
plugins/security_hub/
├── qmldir
├── SecurityHub.qml           # Main panel (Popup / Window overlay)
├── StatusBarIndicator.qml    # Omarchy status bar widget
├── components/
│   ├── ThreatAlertOSD.qml    # eBPF pop-up notification
│   ├── YubiKeyPrompt.qml     # Modal overlay for physical presence
│   ├── NetworkSnitch.qml     # Firewall pop-up selector
│   ├── HardeningSem.qml      # Security audit status indicator
│   └── USBGuardPanel.qml     # Visual management of USB devices
└── services/
    ├── SecurityIPC.qml       # WebSocket / Unix Domain Socket client
    └── ThemeProvider.qml     # Dynamic binding to Omarchy color scheme

```

### 3.3 IPC Communication Protocol (JSON-RPC Example)



#### Event: USB Device Blocked by USBGuard (`Daemon -> Shell`)



```json
{
  "event": "USB_DEVICE_PRESENTED",
  "payload": {
    "device_id": 14,
    "name": "Mass Storage Device",
    "vendor_id": "0951",
    "product_id": "1666",
    "serial": "00187D0F2E3B",
    "rule": "block",
    "interface_class": "08"
  }
}

```

#### Action: Manual USB Approval by User (`Shell -> Daemon`)



```json
{
  "action": "USBGUARD_SET_POLICY",
  "payload": {
    "device_id": 14,
    "target": "allow",
    "permanent": true
  }
}

```

---

## 4. Full Task Breakdown (Development Checklist)



**How to use this checklist (for people and agent sessions).** Tasks are in dependency order. Before starting a phase, finish every unchecked task in the earlier phases (for example, 1.5 comes before any Phase 3 work). Tasks marked **[needs the user: sudo]** change the system. An agent session has no passwordless `sudo`: it must print the exact commands for the user to run, then check the result itself without root. Every task numbered 1.5 or later has a full specification in **§5**. The wire contract is `docs/ipc-protocol.md`. Update it in the same change as any code that alters the protocol, and add new methods, events and fields only in the additive ways that its §7 allows.



### Phase 1: Base Architecture and Development Environment



* [x] **1.1** Create Git repository structure and configure licenses (`GPL-3.0` / `MIT`).


* [x] **1.2** Set up Rust build environment for `omarchy-securityd` (`Cargo.toml`, dependencies `tokio`, `serde`, `aya`, `zbus`).


* [x] **1.3** Define IPC protocol specification (JSON-RPC messages over Unix Domain Socket).


* [x] **1.4** Create base plugin template in QuickShell (`qmldir`, `SecurityHub.qml`).


* [x] **1.5** **[needs the user: sudo]** Install the system packages that the build, the test suite and every module need (`usbguard`, `nftables`, `bubblewrap`, `pcsclite`/`ccid`, `libfido2`, `udisks2`/`cryptsetup`, `gocryptfs`/`fuse3`, `pinentry`), plus the eBPF toolchain. Install `usbguard` but **do not enable it** yet (see 2.9). Spec: §5.1.



### Phase 2: Backend Daemon Development (`omarchy-securityd`)



* [x] **2.1** Implement Unix Domain Socket server in Rust for IPC client management.


* [x] **2.2** Implement **eBPF Module** (`aya-rs`) to capture executions in `/tmp` and suspicious directories.


* [x] **2.3** Implement **USBGuard Module** via D-Bus/IPC integration (`USBGuard` API) to list, authorize, and reject devices.


* [x] **2.4** Implement **HSM/YubiKey Module** listening for `udev` events and security touch prompts.


* [x] **2.5** Implement **Network Module** integrating dynamic rules into `nftables`.


* [x] **2.6** Implement **Posture Audit Module** (checking SELinux/AppArmor, `docker` groups, `ptrace`).


* [x] **2.7** Write Systemd service file (`omarchy-securityd.service`) and Polkit rules for execution without unnecessary elevated privileges.


* [x] **2.8** **[needs the user: sudo]** Install the daemon, helper, eBPF object, units and polkit files on the live system. Validate the privileged paths that no unprivileged test covers: that the eBPF monitor attaches under the unit's hardening, that the real nft table works alongside Omarchy's `ufw`, cross-user signalling, and password-less polkit for wheel. Add the small CLI client `tools/secctl.py` that this task and later ones use to drive the socket. Spec: §5.2.


* [x] **2.9** **[needs the user: sudo]** Configure and enable USBGuard safely (generate the allow-list first, then enable `usbguard` and `usbguard-dbus`). Validate the USBGuard module against the real service, including `permanent: true`. Spec: §5.3.


* [x] **2.10** Add the daemon configuration file (`$XDG_CONFIG_HOME/omarchy-security/config.toml`), which vault definitions and firewall-prompt settings need. Spec: §5.4.


* [x] **2.11** Implement the **Encrypted Vault Module** (plan §2.2): `VAULT_LIST`, `VAULT_MOUNT` and `VAULT_UNMOUNT` for LUKS containers (through udisks2) and `gocryptfs`. The passphrase comes from `pinentry` and never crosses the client socket. Spec: §5.5.


* [x] **2.12** Implement **Panic Mode** (`VAULT_PANIC`, plan §2.2). It stops processes holding files open in the vaults, flushes buffers, unmounts and locks every vault, and can be run from a keybinding even when the shell is unresponsive. Spec: §5.6.


* [x] **2.13** Implement connection interception in the privileged helper (NFQUEUE on new outbound connections from the desktop user). It maps each connection to a process and executable, which the "per process" sets of plan §2.3 and the OpenSnitch-style prompts need. Spec: §5.7.


* [x] **2.14** Implement executable-scoped firewall rules and interactive prompts in the daemon: `executable` in `FirewallRuleSpec`, `FIREWALL_CONNECTION_PROMPT`, `FIREWALL_DECIDE` with `once`/`process`/`always`. Both return `NOT_IMPLEMENTED` today. Spec: §5.8.


* [x] **2.15** Detect touch prompts for OpenPGP cards (source `gpg`, from gpg-agent/scdaemon), so the YubiKey prompt also covers GPG signing and decryption (plan §2.2). Spec: §5.9.


* [x] **2.16** Add the **Inotify** half of Module 1 (plan §2.1 title): report executable files dropped into `/tmp`, `/var/tmp` or `/dev/shm` before they run. Low priority. Spec: §5.10. Tasks 2.17–2.21 do not depend on it.


* [x] **2.17** Detect `ufw` and the firewall mode (`ufw`, `standalone`, `both`, `none`, `unknown`), and serve `ufw`'s rules read-only (`FIREWALL_GET_MODE`, `FIREWALL_UFW_RULES`, `FIREWALL_MODE_CHANGED`). Needs 2.8. Spec: §5.15, §5.16.


* [x] **2.18** Add the standalone baseline policy (default-deny inbound, matching what Omarchy's `ufw` allows, including Docker protection) and the boot copy of the ruleset with `omarchy-security-firewall.service`, so the machine is protected before login when `ufw` is off. Needs 2.17. Spec: §5.17.


* [x] **2.19** Let the user turn `ufw` off and on from the hub (`FIREWALL_SET_MODE`), in an order that never leaves the machine without a firewall, with the new polkit action `org.omarchy.security.firewall.mode` (password, kept). Validating it on the live system is **[needs the user: sudo]**. Needs 2.18. Spec: §5.18.


* [x] **2.20** Report blocked traffic from `ufw` and from our baseline (kernel log), filtered, grouped and rate-limited, as `FIREWALL_ALERT` events and as `omarchy-shell` desktop notifications with actions (the "Allow for 1 h" action is wired up in 2.21). Needs 2.17 and 2.10. Spec: §5.19.


* [x] **2.21** Add temporary allow and block decisions that work in both modes (`FIREWALL_TEMP_*`): kernel-expiring sets in our table, or tagged, self-expiring `ufw` rules for inbound allows while `ufw` is on. Needs 2.19 and 2.20. Spec: §5.20. Validating the `ufw` backend and the notifications on the live system is **[needs the user: sudo]** (reinstall the helper); see the As built note in §5.20.



### Phase 3: Visual Integration and QuickShell Theme



Views are developed against `tools/mock-securityd.py`. Extend the mock in the same change whenever a view needs a method or event that it does not simulate yet. Each view must also be checked once against the real daemon (after 2.8 and 2.9).



* [x] **3.1** Create `ThemeProvider.qml` to dynamically consume colors and styles from the current Omarchy theme. **As built (2026-09-29).** `plugins/security_hub/services/ThemeProvider.qml`, a singleton declared in the new `services/qmldir` (which must also list `SecurityIPC`). It passes `qs.Commons` through as bindings: `background`/`foreground`/`text` from the popup surface (so `popups.background-alpha` applies), `accent`, `muted`, `border.radius` (Hyprland rounding), `border.color`, `border.width`, and `barForeground(bar)` for bar widgets, which follows the bar's transparency. `Color` has no warning or success colour, so `danger` is `Color.urgent` and `warning`/`success` are `yellow`/`green` (else `color3`/`color2`) read from the theme's `colors.toml` by `services/Palette.js`. Every shipped theme defines both. `omarchy theme set` pushes the theme over IPC instead of changing the file in place, so the file is re-read whenever `Color.shellValues` is reassigned, which every theme apply does after the new file is in place. A `[security-hub]` section in `shell.toml` pins any of the three. `Palette.js` also maps module states and posture statuses to these roles. `SecurityHub.qml` and `StatusBarIndicator.qml` now use it (active modules show `success` instead of `accent`, degraded ones `warning`). Tests: `tests/palette.test.js` (parser, fallbacks, every theme in `/usr/share/omarchy/themes`, role maps) and a `theme` step in `tests/e2e/shell.qml`.


* [x] **3.2** Design and implement `StatusBarIndicator.qml` widget for the main Omarchy bar. It also shows the firewall mode and a badge with unseen firewall alerts (§5.21). **As built (2026-09-29).** The shield's colour follows the mode as §5.21 says (`ThemeProvider.barRoleColor`): bar foreground for `ufw`/`standalone`, `warning` for `both`, `danger` for `none`, dimmed for `unknown`, before the first answer, and while the daemon is not connected. The tooltip names the mode and the count. The state lives in the service, so every bar on every monitor and the panel share it: `SecurityIPC` calls `FIREWALL_GET_MODE` and `FIREWALL_ALERT_LIST` after `SUBSCRIBE`, follows `FIREWALL_MODE_CHANGED` and `FIREWALL_ALERT`, and clears both on disconnect (a failed `FIREWALL_GET_MODE` counts as `unknown`). "Unseen" means an alert with a packet (`last_seen`) after the user last opened the hub, not muted (`muted_until` in the future), so an alert that was seen counts again when more of its packets are blocked; the badge shows 1–9, then `9+`. `markAlertsSeen()` stores that time in `$XDG_STATE_HOME/omarchy-security/shell-seen.json`, so a shell restart does not bring the badge back. Clicking toggles the hub with `{"tab": "network"}`; `SecurityHub.open()` keeps `tab` for 3.9 and clears the badge. **For 3.10:** once the Network tab has the alert list, only showing that tab should call `markAlertsSeen()`. The rules are in `services/Indicator.js` (`mergeAlert`, `unseenCount`, `badgeText`, `modeRole`, `summarize`). The mock gains `--alert-every SECS`. Tests: `tests/indicator.test.js`, and the e2e steps `firewallMode`, `badge` and `seen` (the widget is given a stand-in bar host; the runner now sets `XDG_STATE_HOME` to its work directory). Checked once against the real daemon: mode `ufw`, three real alerts, badge `3`.


* [x] **3.3** Design and implement `USBGuardPanel.qml` visual panel (list of connected USB devices, "Approve", "Reject", "Save Permanent" buttons). **As built (2026-09-29).** `components/USBGuardPanel.qml`, shown in the hub card below the module list (in a scroll area) until 3.9 gives it the USB tab. The device list lives in `SecurityIPC` (`usbDevices`, `usbListError`, `setUsbPolicy()`): `USBGUARD_LIST_DEVICES` after `SUBSCRIBE`, then `USB_DEVICE_PRESENTED`/`POLICY_CHANGED`/`REMOVED`, and a new listing when the module comes back to `active` (the daemon resyncs silently after `usbguard-dbus` restarts); a `reject` answer never re-adds a device its `USB_DEVICE_REMOVED` already took away. Rows show name, `vendor:product · serial`, interface classes and the rule (`success`/`warning`/`danger`), and stay in `device_id` order so that nothing moves under the pointer. A blocked device offers Approve (`allow`, until unplugged), Save permanent (`allow`, `permanent: true`) and Reject; an allowed one Block and Reject. Save permanent is offered for an allowed device only after this shell's own Approve (the `temporary` mark): the daemon reports `permanent: false` for every change it did not make, including a saved rule USBGuard applies at plug-in, and devices allowed at startup normally come from `generate-policy` rules. Reject needs a second click within 4 s. An allowed hub (class `09`) gets no buttons, because blocking the root hub cuts off the keyboard; the real daemon lists both xHCI root hubs. A device with a keyboard interface plus others is flagged, more strongly with storage (keystroke-injection sticks). Failures are shown under the device (`PERMISSION_DENIED`, `NOT_FOUND`, `BACKEND_ERROR` with `data.detail`); `MODULE_UNAVAILABLE`, `NOT_IMPLEMENTED` and a stopped USBGuard are stated in place of the list. Rules in `services/Usb.js`. The mock now starts with three devices (receiver and camera allowed, a stick blocked), plugs in storage-that-types after `SUBSCRIBE` (SIGUSR1 unplugs and replugs it), removes a rejected device, and lets a saved one back in on replug. Tests: `tests/usb.test.js`, and e2e steps `usbList`, `usbConfirm`, `usbReject`, `usbSave` (Block → Approve → Save permanent through the panel). Checked against the real daemon (read-only: 7 devices, the blocked headset with its HID note, root hubs without buttons); no policy was changed on the real system.


* [x] **3.4** Design and implement threat OSD modal (`ThreatAlertOSD.qml`) with response actions ("Kill Process", "Isolate"). **As built (2026-09-29).** `components/ThreatAlertOSD.qml`, a card at the top centre of the screen, below the bar, on a full-screen click-through layer surface (like the shell's OSD and notifications) that never takes keyboard focus. The shell loads panels only when summoned, so `SecurityIPC` (the service, always loaded) loads the OSD by URL (`components/` imports `services/`, so a static import would be circular) and only when the shell has injected `shell`, which keeps tests windowless. The alert list lives in `SecurityIPC` (`threatAlerts`, `respondToThreat()`): `THREAT_LIST_ALERTS` after `SUBSCRIBE`, then `THREAT_EXEC_DETECTED` and `THREAT_ALERT_RESOLVED`; the daemon announces only final states, so Isolate and Resume are recorded from their answers, and a `STALE_TARGET` answer resolves the alert as `exited` at once. It keeps the last 50 alerts, dropping resolved ones first, and on disconnect keeps only resolved ones (a restarted daemon has none). The card shows the program, path, command line (shell-quoted), PID/parent/user, and the time from `dropped_at` to the run. Open alerts offer **Kill process**, **Isolate** (the plan's QuarantineProcess, `SIGSTOP`) and **It's safe** (dismiss); isolated ones **Kill process** and **Resume**. Kill always sends `SIGKILL`: the daemon resolves the alert as `killed` once the signal is sent, so an ignored `SIGTERM` would leave the program running and no longer watched, and a stopped process does not act on `SIGTERM` until resumed. **Later** hides an alert until the shell restarts; it stays open in the daemon (for the Threats tab of 3.7). One alert is shown at a time, oldest first, with a count of the others; a new alert never replaces the card on screen. Buttons are disabled for 0.8 s after a card appears. An alert resolved while shown (by the user or by the program exiting) shows the outcome for 5 s, longer while hovered. Rules in `services/Threat.js`. The mock's `threat` module is now `degraded` with three canned alerts after `SUBSCRIBE` (a `/tmp` drop with `dropped_at`, a memfd program, and a `/dev/shm` script whose process has exited, so responses to it fail with `STALE_TARGET`); SIGALRM reports another. Tests: `tests/threat.test.js`, and e2e steps `threatArmed`, `threatIsolate`, `threatLater`, `threatKill`, `threatStale`. Checked against the real daemon (eBPF monitor active) with a copy of `sleep` run from `/tmp`: the card showed it, Isolate stopped it (state `T`), Kill ended it with `SIGKILL`, and the card reported "Killed".


* [x] **3.5** Design and implement `YubiKeyPrompt.qml` component for physical presence authentication alerts. **As built (2026-09-29).** `components/YubiKeyPrompt.qml`, loaded by `SecurityIPC` like the threat OSD, so it shows while the hub is closed. It is not modal: the touch is the answer, so the prompt is visual only, on a full-screen layer surface with an empty input region (like the shell's OSD) that never takes keyboard focus, and it sits at the bottom centre above the volume OSD, leaving the middle of the screen to the app that asked (terminal, browser, pinentry). `SecurityIPC` keeps `tokens` (`TOKEN_LIST` after `SUBSCRIBE`, then `TOKEN_INSERTED`/`TOKEN_REMOVED`) and `touchRequests` (`TOKEN_TOUCH_REQUESTED`/`COMPLETED`, stamped with this shell's clock), and clears both on disconnect, since request ids start over with the daemon. While a key waits, the prompt shows "Touch your YubiKey" (the token's kind; "security keys" when several keys wait), the daemon's description, a hint at what is probably asking (FIDO2: a browser, `sudo` with `pam_u2f`, or another app; SSH; GnuPG, including SSH through gpg-agent), the seconds waited, and "Didn't start this? Don't touch the key." Afterwards it shows the outcome for a moment: touched 1.2 s, cancelled 2.5 s, timed out 5 s. The daemon's hidraw monitor stops without `TOKEN_TOUCH_COMPLETED` when a key is unplugged mid-request, so `TOKEN_REMOVED` ends that key's requests as "Key removed". A request with no outcome after 60 s is no longer shown (FIDO2 requests end within 3 s of the last keepalive, gpg ones after 15 s, so this only covers a lost event). There is no call to list requests already waiting, so one that started before the shell connected is not shown. Rules in `services/Touch.js`. The mock's `token` module is now `degraded` ("mock data") with one YubiKey; after `SUBSCRIBE` it plays a FIDO2 request that is touched, a gpg one that times out, and an SSH one ended by unplugging the key (then plugged back in); SIGPROF starts a FIDO2 request touched after 8 s. Tests: `tests/touch.test.js`, and e2e steps `touchWaiting`, `touchTouched`, `touchTimedOut`, `touchRemoved`, `touchCleared`. Checked against the real daemon only without a key (token module `active`, `TOKEN_LIST` empty, nothing shown); **not checked with a real key yet**, since none was plugged in.


* [x] **3.6** Design and implement `NetworkSnitch.qml` visual module and the audit status indicator view (`HardeningSem.qml`). `NetworkSnitch` has two parts. Its rule list (list/add/remove) can be built now. Its connection prompt (Allow/Block × Once/This process/Always, with a countdown to `expires_at`) needs 2.14. It is mode-aware: see 3.10. **As built (2026-09-29).** Three components. (1) `components/NetworkSnitch.qml`, the first part: the hub's saved rules (`FIREWALL_LIST_RULES`) with Remove (a second click confirms) and an Add rule form (Block/Allow, outbound/inbound, address or prefix, Any/TCP/UDP and a port, and for outbound rules one program by absolute path). The form checks what the daemon would refuse before sending: a bad address or prefix, a port without TCP or UDP, a program on an inbound rule or without a full path, and an inbound allow while `ufw` or `both` (`MODE_CONFLICT`). It warns that an inbound allow asks for the password, and that a rule without a program is saved but not enforced in `ufw` mode. A rule with `loaded: false` says why. No event announces rule changes, so `SecurityIPC` reads the list after the handshake, after each add or remove, after an `always` decision, on `FIREWALL_MODE_CHANGED`, and when the hub opens. Mode awareness beyond that (banner, switch, `ufw` rules, alerts, temporary decisions) stays with 3.10. (2) `components/ConnectionPrompt.qml`, the second part, as the overlay named in §5.21: `SecurityIPC` keeps `connectionPrompts` from `FIREWALL_CONNECTION_PROMPT`/`_RESOLVED` and loads the card, so it shows while the hub is closed. The card names the program, the address and port (with the service for well-known ports) and the PID, and counts down to `expires_at`. It offers Once / This process / Always and Allow / Block, then `FIREWALL_DECIDE`. It follows the threat card's rules: one prompt at a time, oldest first, a new prompt never replaces the one on screen, buttons armed after 0.8 s, input region on the card only, no keyboard focus. It sits at the top centre, below the threat card when both are up (`ThreatAlertOSD.cardHeight`). A resolved prompt shows how it ended (for example "Allowed always", "Blocked: no answer in time", "answered elsewhere") for 1.5 s, or 4 s after a timeout, and stays with a Close button when the decision returned an error. One more than 5 s past `expires_at` with no `RESOLVED` is dropped. As with touch requests, prompts sent before the shell connected are not shown; the daemon answers held connections itself. (3) `components/HardeningSem.qml`: the `PostureReport` (`POSTURE_GET_REPORT`, then `POSTURE_CHANGED`) as a traffic light with the worst status, one row per check (summary and the daemon's advice), "Checked N min ago" and Check now (`POSTURE_REFRESH`). The Phase 1 hub card is wider (380) and scrolls its three sections (USB, firewall rules, hardening) together until 3.9. Rules in `services/Network.js` and `services/Posture.js`. Mock: two seeded rules (an outbound block, not enforced in `ufw` mode, and an allow for `/usr/bin/curl`); after `SUBSCRIBE` to `firewall`, a git and a firefox connection are held; `--prompt-timeout` (the e2e harness uses 3 s); `always` skips an identical rule as the daemon does; `POSTURE_REFRESH` updates `evaluated_at`; the posture checks use the daemon's wording. Tests: `tests/network.test.js`, `tests/posture.test.js`, and e2e steps `rulesListed`, `ruleForm`, `ruleAdded`, `ruleRemoved`, `promptQueued`, `promptAlways`, `promptTimeout`, `postureShown`, `postureRefresh`. Checked against the real daemon (read-only): mode `ufw`, the six rules imported in 2.19 listed as not enforced while UFW is on, the audit with one warning (no LSM enforcing), and Check now. **Not checked live:** the connection prompt, because `[firewall] prompt` is off in this configuration; and adding or removing a rule, because the checks against the real daemon were read-only.


* [x] **3.7** Design and implement `components/VaultPanel.qml`: the vault list with mount state, Mount/Unmount, and a Panic button that asks for confirmation. Needs 2.11 and 2.12. Spec: §5.11. **As built (2026-09-29).** `components/VaultPanel.qml`, shown in the Phase 1 hub card between the firewall rules and the hardening audit until 3.9 gives it the Vaults tab. The list lives in `SecurityIPC` (`vaults`, `vaultsError`): `VAULT_LIST` after `SUBSCRIBE`, when the hub opens (a reloaded configuration sends no event), and when the `vault` module's state changes; then `VAULT_STATE_CHANGED`, so a vault mounted or unmounted outside the hub shows too. Rows keep the daemon's (the configuration's) order and show the name, backend (gocryptfs or LUKS), and "Locked" or "Open at <mount point>" (home shortened to `~`). **Mount** / **Unmount** send `VAULT_MOUNT` / `VAULT_UNMOUNT`; the view never asks for a passphrase, and while the daemon's pinentry is open the row says "Waiting for the passphrase…". The mounts in progress are kept in `SecurityIPC` (`vaultOps`), so they survive the hub closing, and one vault gets one call at a time. `SecurityIPC.request()` takes an optional timeout: 10 min for a mount (up to three pinentry tries of 120 s, then gocryptfs), 2 min for an unmount and for panic, instead of the usual 10 s. Failures are shown under the vault: a cancelled prompt as "Cancelled." (muted, or "Cancelled by Panic."), three wrong passphrases, polkit refusals, and a busy unmount as "Still in use. Close the programs using it, or use Panic."; an error is dropped once the vault's state has changed since. **Panic** (`VAULT_PANIC`) is offered while a vault is open or a mount waits for its passphrase, and needs a second click within 4 s, with a warning that programs using the vaults are stopped. Its result is summed up under the list ("Panic locked 2 vaults."), with a line for each vault detached lazily and each in `failed` with its reason. `MODULE_UNAVAILABLE`, `NOT_IMPLEMENTED`, an unavailable module (with its detail) and an empty configuration (with where to add a `[[vault]]`) are stated in place of the list; a `degraded` module's detail is shown above it. Rules in `services/Vault.js`. The mock's `vault` module is now `active` with three vaults ("notes" and "backup" locked, "work" open and busy); `VAULT_MOUNT` is answered after `--passphrase-delay` (1 s) without holding up other requests, the first mount of "backup" is cancelled, unmounting "work" fails as busy, `VAULT_PANIC` cancels waiting mounts and unmounts everything ("work" lazily), and SIGVTALRM mounts or unmounts "notes" outside the hub. The e2e step `notImplemented` now probes `SANDBOX_RUN`, since the mock implements `VAULT_PANIC`. Tests: `tests/vault.test.js`, and e2e steps `vaultsListed`, `vaultMounted`, `vaultUnmounted`, `vaultBusy`, `vaultCancelled`, `vaultPanic` (Panic sent while a mount waits, which ends as "Cancelled by Panic."). Checked against the real daemon (read-only): module `active` with "no vaults configured", and the panel shows the setup hint with no Panic button. **Not checked live:** mounting, unmounting and panic on a real vault, since none is configured on this machine and a mount needs the passphrase typed into pinentry. The same option now gives an inbound allow in `FIREWALL_ADD_RULE` (3.6), which waits for the polkit password, 2 min (`passwordTimeoutMs`); **for 3.10**, the mode switch and a temporary inbound allow need it too.


* [x] **3.8** Design and implement `components/TokenPanel.qml` (connected tokens and their capabilities, from `TOKEN_LIST` and `TOKEN_*` events) and `components/SandboxLauncher.qml` (pick an executable and an optional target file, toggle network, then `SANDBOX_RUN`). No view in the plan's tree covers either module. Spec: §5.11. **As built (2026-09-29).** Two views, shown in the Phase 1 hub card after the vaults until 3.9 gives them the Tokens tab and a place of their own. (1) `components/TokenPanel.qml`: the tokens `SecurityIPC` already kept for the touch prompt (3.5), now with `tokensError` from `TOKEN_LIST` and a new listing when the `token` module's state changes. Each row shows the name, the kind ("YubiKey", "FIDO2 key", "Smart card reader", …), `vendor:product · serial`, and the capabilities as chips (FIDO2, PIV, OpenPGP, OTP, with a tooltip on what each is for). The key's touch requests give it a line: "SSH is waiting for a touch" (the icon turns amber), or, for ten minutes after, how the last one ended (touched, not touched in time, cancelled, or unplugged while it waited). A key with neither FIDO2 nor OpenPGP says that its touches are not shown; a smart card reader lists no capabilities but does not say so, since a card in it gets GnuPG prompts under the reader's id. Read only. (2) `components/SandboxLauncher.qml`: a program path, an optional file, and a Network toggle (off by default, with a warning when on), then `SANDBOX_RUN`. The file is sent as `target_file` and also as the only argument, since the daemon binds it but does not pass it. The client checks only that the paths are absolute (with `~/` expanded), have no line break and do not end in `/`; the daemon's refusals are shown as "Not started: <reason>". A successful run says "Started (PID n)", and `SecurityIPC.sandboxRuns` keeps the last five launches of this shell (the daemon does not list them), with **Use again** to put one back in the form. It keeps them across a daemon restart, since the sandboxes survive it too. `MODULE_UNAVAILABLE`, `NOT_IMPLEMENTED` and an unavailable module (with its detail, such as "bwrap (bubblewrap) is not installed") are stated in place of the form. **Not done:** a file picker. The shell has no file dialog that works from a layer-shell panel, so both paths are typed. Rules in `services/Token.js` and `services/Sandbox.js`. The mock adds a smart card reader to the YubiKey, and its `sandbox` module is now `active`: `SANDBOX_RUN` checks the params as the daemon does, with the same messages, and answers with a made-up pid without running anything. The e2e step `notImplemented` now probes `MOCK_NOT_IMPLEMENTED`, since the mock implements every protocol method. Tests: `tests/token.test.js`, `tests/sandbox.test.js`, and e2e steps `tokensListed`, `tokenWaiting`, `sandboxForm`, `sandboxRejected`, `sandboxStarted`, `sandboxReuse`. Checked against the real daemon: `token` and `sandbox` `active`, no key plugged in (the panel says so), a missing `target_file` refused with the same message as the mock's, and one real `SANDBOX_RUN` of `/usr/bin/true` without network, which returned a pid.


* [x] **3.9** Replace the Phase 1 module list in `SecurityHub.qml` with a tabbed hub (Overview, Threats, USB, Tokens, Network, Vaults, Hardening). The Overview shows alert history and module states. Add every new file to `qmldir`. Spec: §5.11. **As built (2026-09-29).** `SecurityHub.qml` keeps the window, the title and the connection line; the hub itself is `components/HubView.qml`, so the e2e test drives it without a window. The tab row has icon buttons with the tab's name as tooltip (seven labels do not fit in the 380 px card); the Tokens tab is labelled "Security keys". A tab with something waiting shows a count or a dot: open or isolated threat alerts (`danger`), blocked USB devices, keys waiting for a touch, held connections (`danger`) plus unseen blocked traffic on Network, and a `warn`/`fail` audit on Hardening. Every view stays loaded while its tab is hidden (the layout skips it), so a half-filled rule or sandbox form, or a Panic waiting for its second click, survives a tab switch. (1) `components/Overview.qml`: the seven modules with their state ("All 7 modules active" or "5 of 7 …"), and the eight latest alerts of this session, threat alerts (by `detected_at`) and blocked traffic (by `last_seen`) merged newest first; every row opens its tab. (2) `components/ThreatList.qml`, new, for the Threats tab: every threat alert of this session, newest first, with program, origin, command line, process line and drop time, and the OSD's answers for the open and isolated ones. A new alert moves the rows below it, so an answer is sent only on a second click on the same alert within 4 s. An alert put off with Later on the card is answered here. The daemon lists only open alerts, so a resolved one raised before the shell connected is not shown. The sandbox launcher sits below the list, as the one module without a tab of its own. The other tabs hold the views of 3.3 and 3.6–3.8 unchanged. `open(payload)` takes a tab id or a module id (`usbguard`, `firewall`, `posture`, `sandbox`, …); without one, or with an unknown one, the hub opens on the tab it was left on. Left / Right (or h / l) and 1–7 switch tabs while no text field has the keyboard. `markAlertsSeen()` still runs on every open; **for 3.10**, as noted in 3.2, only showing the Network tab's alert list should call it. `components/qmldir` now lists every view (it replaces the directory's implicit import); the overlays are still loaded by URL. Rules in `services/Hub.js` (`TABS`, `tabFor`, `tabFromPayload`, `neighbour`, `attention`, `history`, `firewallTitle`, `firewallDetail`, `modulesSummary`); `Threat.js` gains `newestFirst` and `listEmptyText`. Tests: `tests/hub.test.js` (including a check that every `.qml` in `components/` and `services/` is in its `qmldir`), a new case in `tests/threat.test.js`, and e2e steps `hubTabs`, `hubAttention`, `hubOverview`, `hubThreatAnswered` (the alert put off in `threatLater` dismissed from the list with two clicks). Checked visually against the mock (every tab), and against the real daemon read-only: all seven modules active, three real blocked-traffic alerts in the Overview, the blocked headset counted on the USB tab, and the audit warning as a dot.


* [x] **3.10** Make the Network tab mode-aware: the `ufw` banner and conflict warnings, the mode switch with confirmation, `ufw`'s rules read-only in `ufw` mode and the hub's rules editable in `standalone` mode, the alert list, and temporary Allow/Block/Mute with countdowns and Revoke, in both modes. Add the plugin IPC handler that notification actions use to open the hub. Needs 2.17–2.21 (use the mock before that). Spec: §5.21. **As built (2026-09-29).** `components/NetworkSnitch.qml` is now the whole Network tab and shows, as `Network.sections(mode)` says: (1) `FirewallModeBanner.qml`, the banner in §5.21's words for each mode, with the daemon's `detail` and "before.rules has local changes" under it, and the switch buttons (none in `unknown`). A switch opens a dialog: what will change, what will be imported from UFW and what cannot be, the Docker note, the password, and the recovery command from `docs/security.md` (selectable). It is sent on a second click within 4 s, and afterwards says "Switched to …" and what was imported. Errors: a refused password ("Not switched: …") and `BACKEND_ERROR`'s message, which says which firewalls enforce. (2) `UfwRules.qml`, in `ufw` and `both` (and `unknown` while `ufw.conf` says enabled): UFW's rules read-only ("Allow in UDP port 53 from 172.16.0.0/12 to 172.17.0.1", with its comment), its built-in rules folded, and the hub's temporary UFW rules marked "Added by the hub · 58 min left" with Revoke. (3) `HubRules.qml`, the rule list and form from 3.6 (moved out of `NetworkSnitch.qml`), editable in every mode; in `ufw` mode the rules UFW makes inactive are folded into "inactive while UFW is on (N)", and in `standalone` and `both` the baseline (`Network.BASELINE`, from `docs/ipc-protocol.md` §4.6) is listed as fixed rows first. (4) `FirewallAlerts.qml`: the alerts newest first (15, then "and N older"), with a duration picker above the list, then per alert Allow and Block (`FIREWALL_TEMP_ADD` with `Protocol.specFromAlert`, only for TCP and UDP with a port, not `forward`), Any source for an inbound one, and Mute (`FIREWALL_ALERT_MUTE`, the same duration). An inbound Allow has a lock icon and waits up to 2 min for the password. A row with a decision in force says "Allowed, 58 min left". The list says the packets were already dropped and, in UFW mode, that UFW logs a sample; the journal-access detail replaces it when alerts are off. No second click here: every action is temporary and can be revoked. (5) `TempDecisions.qml`: the decisions in force, soonest to expire first, with backend ("UFW rule" / "Security Hub table"), a countdown, and Revoke (a second click, since the list reorders as decisions expire). `SecurityIPC` keeps `firewallInfo` (the whole `FirewallMode`), `ufwRules`, `tempDecisions` and `tempDurations`, reads them after the handshake and when the hub opens, follows `FIREWALL_TEMP_CHANGED` (and reads UFW's rules again then and on `FIREWALL_MODE_CHANGED`), and adds `previewFirewallMode`, `setFirewallMode`, `addTemp`, `removeTemp` and `muteAlert`. **The badge** is cleared only while the hub is open on the Network tab (`HubView.shown`), and kept clear as alerts arrive; `SecurityHub.open()` no longer clears it. **Plugin IPC:** the service registers the target `security-hub` with `open(tab)`, `toggle(tab)` and `close()` (`omarchy-shell security-hub open network`, the call the daemon's notification action already makes), which summon the panel with `{"tab": …}`; `""` opens the tab it was left on. The README gives a keybinding. **Two additive daemon changes**, for what the UI needs and could not read: `FIREWALL_SET_MODE` takes `dry_run: true`, which answers with the current mode and the `imported` (with `rule_id` 0) and `not_imported` the switch would give, without the helper or a password; and `FIREWALL_TEMP_LIST` returns `durations_secs` (`[firewall.alerts] temp_durations_secs`), which closes the point left open in 2.21. Against an older daemon the dialog says the imported rules are listed after the switch, and the durations fall back to 5 min, 1 h and 8 h. Temporary decision ids are milliseconds, beyond QML's 32-bit `int`, so the views keep them as `real`. Protocol: `docs/ipc-protocol.md` §4.6, `docs/configuration.md`; tests `firewall::tests::switches_the_mode_and_imports_ufw_rules_once` (the dry run changes nothing) and `temporary_decisions_follow_the_mode` (durations), wire-format `set_mode_matches_spec` and `temporary_decisions_match_spec`. Mock: `--mode ufw|standalone|both|none|unknown` (in `unknown` a switch fails with `BACKEND_ERROR` and temporary decisions with `MODE_CONFLICT`), the dry run, a UFW port-range rule that cannot be imported, `durations_secs`, and the first inbound allow refused with `PERMISSION_DENIED` as a dismissed password prompt. Tests: new cases in `tests/network.test.js`; e2e steps `networkUfw`, `allowRefused`, `allowAsUfwRule`, `blockedAsTable`, `alertMuted`, `tempRevoked`, `modePreview`, `modeSwitched`, `modeBack`, `hubIpc` (the test calls `qs ipc … call security-hub open network` on itself) and `hubSeen`; and `tests/e2e/modes.qml`, which `tools/qml-e2e.sh` runs once per other mode against its own mock (banner, lists, and one path each: back to UFW from `standalone`, `MODE_CONFLICT` for an inbound allow in `both` and for a block in `none`, and a failed switch in `unknown`). Checked visually against the mock in every mode, and against the real daemon read-only: mode `ufw`, UFW's six rules and eight built-in ones, the six imported hub rules folded as inactive, three real blocked-traffic alerts, and the switch dialog with the fallback text (the installed daemon predates `dry_run`); nothing was switched or allowed. **Needs the user to validate live:** after `make release && sudo make install` and `systemctl --user restart omarchy-securityd.service`, the dialog should list the import (LocalSend and the Docker DNS rules, or nothing if they were imported in 2.19), and the notification's "Open Security Hub" should open the Network tab.



### Phase 4: Testing, Validation, and Documentation



* [x] **4.1** Perform integration testing for low impact on memory/CPU consumption (< 2% CPU, < 40MB RAM daemon). **As built (2026-09-29).** `tools/footprint.py` (`make footprint`, stdlib Python, reusing `secctl.Client`) samples the systemd cgroups of `omarchy-securityd.service` (user) and `omarchy-securityd-helper.service` (system) once a second from `cpu.stat` and `memory.current`/`memory.stat`, so the daemon's `journalctl -k -f` child counts too. It measures 60 s idle (`--idle`), then 30 s (`--load`) while one client sends 20 (`--rate`) read-only requests a second in turn (`GET_STATUS`, the `*_LIST*` calls, `FIREWALL_GET_MODE`, `FIREWALL_UFW_RULES`, `POSTURE_GET_REPORT`) and drains the events of every topic but `firewall`: a `firewall` subscriber makes the daemon hold outbound connections while `[firewall] prompt` is on. **How it judges:** CPU is cgroup CPU time over wall time, as `top` shows it (100% is one core), and the 2% limit applies to the idle mean. Memory is `memory.current` less the reclaimable page cache (`active_file` + `inactive_file`), because §5.2's `MemoryCurrent` is here mostly the journal files `journalctl` reads (24 of 27 MB); the 40 MB limit applies to the peak over both windows, and `MemoryCurrent` is printed too. The load window is reported (INFO), not judged, and FAILs if the daemon stops answering. It exits 1 on any FAIL, so 4.4's `tools/system-check.sh` can run it. Unit tests for the pure parts (`parse_keyed`, `unreclaimable`, `cpu_percent`, `summarize`, `verdicts`, the load list being read-only) in `tools/test_footprint.py`, now part of `make test` (`make test-py`). **Result on the development machine** (every module active, UFW mode): daemon idle 0.02% CPU (busiest second 0.59%), 0.24% at 20 requests/s and 3.8% at 500 requests/s, 3.7 MB without page cache (`MemoryCurrent` 26.9 MB); helper idle 0.05%, 4.8 MB (7.8 MB); every request answered. Not measured: a burst of suspicious executions, which would put threat cards on the user's screen; 4.4 covers execs on a disposable install.


* [x] **4.2** Test real-time theme switching in Omarchy to verify dynamic UI adaptation. **As built (2026-09-29).** `plugins/security_hub/tests/e2e/themes.qml`, the last run of `tools/qml-e2e.sh` (`make test-e2e`), under a throwaway HOME (qs.Commons reads the theme from `$HOME/.local/state/omarchy/current/theme`) against the mock, started with `--prompt-timeout 3` and begun once the mock's scripted touches and held connections are over. It builds every view (HubView and the SecurityHub panel, the bar widget with a stand-in bar whose foreground is `Color.bar.text`, ThreatAlertOSD, YubiKeyPrompt, ConnectionPrompt, windows unmapped) and applies each theme in `$OMARCHY_PATH/themes` (22) plus a fixture with no red, yellow or green (`tests/e2e/themes/bare-palette`). `tools/theme-apply.sh THEME_DIR SHELL_DIR` is what `omarchy-theme-set` does to the shell: it stages the theme (without `backgrounds/`), runs Omarchy's `omarchy-theme-set-templates` for `shell.toml`, swaps it in, sends `shell applyTheme <colors b64> <shell b64>` with `qs ipc -p`, and prints `omarchy-theme-color --all`; it skips the terminals, Hyprland, background and hooks, and refuses to run with the real HOME. The test's `shell` IPC target has the body of the one in `$OMARCHY_PATH/shell/shell.qml`. **Checks, per theme:** ThemeProvider's `danger`/`warning`/`success` are the theme's `red`/`yellow`/`green` as `omarchy-theme-color` resolves them, or the fallbacks; `background`, `foreground`, `accent`, `muted`, `border.color`, `accentText` and `barForeground` equal their `Color` sources and `border.radius` is `Style.cornerRadius`; then, 400 ms later (qs.Ui Button fades its colour over 120 ms), every `color`, drawn `border.color` and `placeholderTextColor` on every item under the views (about 1,450, walking `children`, `data`, `contentItem` and Loader items) is explained by the theme: its rgb is in the palette, `Color.shellValues`, `Color` and its surfaces, or ThemeProvider, at any alpha, or one of these through `Qt.darker`/`Qt.lighter` with the factors qs.Ui uses. qs.Ui's hidden debug outlines (`debugBounds`) are exempt. **At the end:** no item kept the same colour through every theme; the first theme applied again gives every item its first colours back; `[security-hub] danger = "#123456"` and `success = "accent"` written to `~/.config/omarchy/shell.toml` take effect live, survive a theme switch, and go when the file is emptied. The semantic colours follow within about 120 ms of the IPC call (the `colors.toml` re-read); the rest change within it. Planting a hard-coded colour or a colour assigned once instead of bound fails the first theme, naming the item. **Bugs it found, fixed:** `ThemeProvider.onAccent` always read as black (QML treats `on` + capital names specially, and the singleton also has `accent`), so the bar badge's count was black in every theme; it is `accentText` now. In a theme with no `red`/`color1`, `danger` fell back to `Color.urgent`, which qs.Commons does not reset, so it kept the previous theme's red; it now falls back to `fallbackDanger` (`#a55555`, Color's start-up `urgent`), like `warning` and `success`. Also checked by eye: the opened panel captured with `grabToImage` under tokyo-night, catppuccin-latte, white, retro-82, gruvbox and the fixture. Not done: switching the theme of the user's own desktop, which restarts terminals and reloads Hyprland; a manual check there is `omarchy theme set <name>` with the hub open.


* [x] **4.3** Write installation manual, dependency setup (`usbguard`, `nftables`, `aya-bpf`), and usage guide in `README.md`. It must cover the packages from §5.1, the USBGuard procedure and recovery from §5.3, the vault configuration from §5.4, the firewall modes and what switching does (§5.15), and how to get out of the hub (uninstall, disabling USBGuard, and handing the firewall back to `ufw` with the recovery command in §5.18). **As built (2026-09-29).** `README.md` from "Installation" on: (1) packages, one `pacman` line and a table of what each is for and what happens without it (only `polkit` and `nftables` matter for the core; `usbguard` is installed, not enabled); (2) toolchains: Rust stable, and for the eBPF monitor `aya-ebpf` (the crate once named `aya-bpf`, fetched by cargo) with the pinned nightly and `bpf-linker`, and what the threat module does without it; (3) build and install, and what lands where; (4) the three units and what each does, and which actions ask for the password; (5) the plugin (`make plugin-link`, `omarchy plugin enable`); (6) `omarchy-secctl call GET_STATUS` and the logs. Then "Setting up USBGuard" (§5.3's procedure, the six settings with the reason for each, the safety notes, and recovery: `systemctl disable --now` from a TTY or ssh, and that USBGuard leaves the controllers' default at unauthorized when it stops, so a device plugged in afterwards may stay blocked until reboot, with the `authorized` sysfs write); "Vaults" (creating a gocryptfs and a LUKS vault, the `[[vault]]` tables, reload, pinentry, Panic); "The firewall modes" (`ufw` and `standalone`, the states the hub never chooses, what a switch does in which order, the CLI call); "Keybindings" in Omarchy 4's `bindings.lua` form; and "Removing the Security Hub" in order: hand the firewall back to `ufw` first (in the hub, with `omarchy-secctl`, or §5.18's recovery command with the mode file), then the plugin, the units (and `nft delete table`, since the table stays after the helper stops), `make uninstall`, USBGuard, and the state directories. The development-only "Trying the plugin" note moved to Development. **Fixed on the way:** the README's hub keybinding used the old `bindings.conf` syntax and `SUPER ALT + S`, which Omarchy 4 binds to "Move window to scratchpad"; both bindings are now `o.bind(...)` lines on `SUPER CTRL ALT + S` and `+ P`, which are free.


* [ ] **4.4** **[needs the user: sudo]** Run a full end-to-end pass on a real Omarchy install, or on a disposable VM of one, covering every module, including those added in 2.11–2.21, and the firewall in both modes. Turn §5.2's manual checks into `tools/system-check.sh`, which is read-only and prints PASS/FAIL per check, so the pass can be repeated after every release. Spec: §5.12.


* [x] **4.5** Review the security of the privilege boundary and add fuzz tests for the parsers that read untrusted input, including the kernel-log and `ufw` tuple parsers. Spec: §5.13. **As built (2026-09-30).** The findings are in `docs/security.md` ("Review of the privilege boundary"): what was fixed, what holds, and what is accepted. **Fixed, each with a test:** (1) the sandbox bound `/` read-only, which leaves every socket in `/run` connectable, and polkit sees a sandboxed program as the daemon's user and session, so it could reach the helper (remove rules, take the connection prompts) and the system bus (USBGuard, udisks2) without a password; `/run` is now a tmpfs (`/run/systemd/resolve` bound back with `share_net`) and the sandbox runs with `--cap-drop ALL`; (2) a symlinked `target_file` was bound read-write under the link's name, and is now refused; (3) the helper asked for `firewall.mode` only for an inbound temporary allow it did not hold, ignoring `expires_at`, so a later expiry kept it open without the password; a later expiry now counts as new, and temporary decisions are capped at 24 hours (`MAX_TEMP_MS`) in the table and in `ufw`; (4) the inbound check ran before the firewall lock, so `apply` and `set_temp` now take `inbound_authorized` and check again under the lock; (5) polkit is now asked in one place, before any handler runs, through the exhaustive `required_action` (no wildcard arm), so a new op cannot skip it; `hello` and `connection_unsubscribe` are the two that need no action; (6) a refused `exec_subscribe` set the subscribed flag first, so a second one answered success without polkit; (7) the helper spawned a task per request without a limit, so it now allows 32 in flight per connection and the unit has `MemoryHigh=48M`/`MemoryMax=96M`; (8) `threat.monitor` was `YES` for wheel over SSH too, and now needs `subject.local`; (9) the helper swept expired `ufw` temporary rules and restored the standalone table only after reaching polkit, and now does both first. Accepted and written down: signals reach other users' flagged processes, which is the point of the threat card; the PID-reuse windows, which pidfds and a start time from eBPF would close; the LUKS passphrase copy in the D-Bus message; one connection subscriber per machine; abstract sockets reachable with `share_net`. **Fuzzing:** `fuzz/`, a `cargo fuzz` workspace on the eBPF crate's nightly, excluded from the main workspace. To give it access to the parsers, `omarchy-securityd` and `omarchy-security-helper` are now a library (`src/lib.rs`, the modules) plus `main.rs`; `server::read_frame` and `token::relevant_uevent` became `pub`. The eight targets are `rpc_frame`, `helper_request`, `usbguard_rule`, `token`, `exec_event`, `packet`, `kernel_log` and `ufw_tuple`, covering every parser §5.13 lists. Their checks live in `fuzz/src/lib.rs` and go beyond not crashing: frames equal the input's lines and an error response is one line; a rendered `nft` script holds only fixed strings, allowed characters, balanced braces and one line per rule; a `ufw` argv holds no option or quote; a USBGuard-escaped serial and name round-trip; touch edges alternate; tuples imported from `user.rules` render safely. `fuzz/tests/seeds.rs` replays `fuzz/seeds` (real lines, rules and packets from the unit tests) on stable as `make test-fuzz`, now part of `make test`; `make fuzz` runs each target for `FUZZ_SECS` (60 s) with `cargo +$(FUZZ_TOOLCHAIN) fuzz` (named explicitly, because a `RUSTUP_TOOLCHAIN` in the environment overrides `fuzz/rust-toolchain.toml`), and `make lint` covers the crate. **Found by the fuzz checks:** USBGuard escapes each byte of a UTF-8 name as `\xHH`, and the rule tokenizer turned each byte into a `char`, so "Café" showed as "CafÃ©"; it now decodes to bytes and then UTF-8 (test `parses_interface_sets_escapes_and_empty_names`). Run on 2026-09-30, 2 minutes per target, from about 93 thousand runs (`rpc_frame`) to 78 million (`packet`): no crash, no failed check. **Needs the user to validate live**, after `make release && sudo make install`, `sudo systemctl daemon-reload && sudo systemctl restart omarchy-securityd-helper` and `systemctl --user restart omarchy-securityd`: the Security Hub still works as before (exec alerts, firewall changes without a password, an inbound allow asking for it), and a sandbox still opens a file (`/run` is now hidden).



### Phase 5: Release and Distribution



* [ ] **5.1** Set up GitHub Actions (CI/CD) for automated Rust binary compilation and QML syntax validation. Run it in an `archlinux` container so the eBPF build finds the same LLVM major version as the pinned nightly (see `crates/omarchy-security-ebpf/rust-toolchain.toml`). Build `make ebpf`, run `make lint test`, and keep the tests that skip themselves when a tool is missing running, by installing `dbus`, `nftables`, `bubblewrap` and `util-linux` in the container.


* [ ] **5.2** Publish first semantic Release (`v1.0.0`) on GitHub with compiled binaries and plugin packaging.


* [ ] **5.3** Submit or publish the plugin to the Omarchy community plugin index / catalog.


* [ ] **5.4** Write an Arch `PKGBUILD` (AUR `omarchy-security-hub`) with the dependencies from §5.1. Its install script must never enable or start `usbguard` on its own, and never switch the firewall mode or touch `ufw`. Spec: §5.14.



---

## 5. Specifications for Open Tasks



These sections hold the details a later session needs to carry out each task in §4 without redoing the research. Where the original design in §1–§3 has since changed, the note "As built" in §5.0 is the reference.



### 5.0 As built: where Phase 2 departed from §2



* **Exec hook.** The monitor attaches to `sched:sched_process_exec`, not `sys_enter_execve`: it fires only after an exec succeeds, when the new image is known. A root helper, `omarchy-securityd-helper`, loads it (system unit, `CAP_BPF CAP_PERFMON CAP_SYS_PTRACE CAP_NET_ADMIN CAP_KILL`). It checks every request with polkit (`org.omarchy.security.*`). The user daemon has no privileges.
* **USBGuard.** The D-Bus name is `org.usbguard1` (path `/org/usbguard1/Devices`, interface `org.usbguard.Devices1`), not `org.isis.USBGuard`. `usbguard-dbus` owns that name before it has reached `usbguard-daemon`, so the module retries a failed `listDevices` with backoff while the name has an owner (found in 2.9).
* **Tokens.** Tokens are detected from sysfs plus the kernel uevent netlink socket, not `libudev-sys`. FIDO2 touch prompts come from CTAPHID `KEEPALIVE` (status `UPNEEDED`) read on hidraw.
* **nftables.** The helper replaces the whole `table inet omarchy_sec` atomically with `nft -f -`, not through libmnl. The table stays in the kernel when the helper stops.
* **Sandbox.** The `bwrap` profile also mounts a tmpfs over `$XDG_RUNTIME_DIR` (only the Wayland socket is bound back), adds `--new-session`, and binds the executable read-only. Each sandbox runs in its own `systemd-run --user --scope`.
* **eBPF toolchain.** The eBPF crate is a separate workspace pinned to `nightly-2026-08-01`, the last nightly on LLVM 22, because `bpf-linker` links the system LLVM. Move the pin when Arch moves to LLVM 23.
* **Omarchy firewall.** Omarchy already enables `ufw` (default deny inbound, see `/usr/share/omarchy/install/config/firewall.sh`). Our table does not replace it. A packet must pass both, so our `allow` rules cannot open a port that `ufw` blocks. Tasks 2.17–2.21 turn this into explicit firewall modes (`ufw` or `standalone`), let the user switch between them, and add alerts and temporary decisions; see §5.15.



### 5.1 (Task 1.5) System dependencies



Run on the development machine (Arch/Omarchy):

```bash
sudo pacman -S --needed base-devel llvm clang python nodejs quickshell qt6-declarative \
  dbus util-linux nftables bubblewrap polkit \
  usbguard pcsclite ccid libfido2 udisks2 cryptsetup fuse3 gocryptfs pinentry gnupg openssh \
  yubikey-manager
sudo systemctl enable --now pcscd.socket
# eBPF toolchain (as the user, not root):
rustup toolchain install nightly-2026-08-01 --component rust-src
cargo install bpf-linker
```

| Package | Needed by |
|---|---|
| `nftables`, `util-linux` (`unshare`), `dbus` (`dbus-daemon`), `bubblewrap` | Tests that skip themselves when the tool is missing: they apply real rulesets in `unshare -rn`, run a fake USBGuard on a private bus, and start a real sandbox. Also needed at runtime. |
| `llvm`, `clang`, `bpf-linker`, pinned nightly | `make ebpf`. `bpf-linker` must be built against the same LLVM major version as the nightly. |
| `usbguard` | Module 5, and the real-service checks in 2.9. **Install only.** Enabling it before a policy exists blocks every USB device, including the keyboard. |
| `pcsclite`, `ccid` | Smart-card and OpenPGP card tokens (2.15). |
| `libfido2` | udev `uaccess` rules for FIDO hidraw nodes, needed to read touch prompts. |
| `udisks2`, `cryptsetup`, `fuse3`, `gocryptfs`, `pinentry` | Vaults (2.11). |
| `nodejs` (≥ 20, or through mise), `python` (≥ 3.11), `quickshell`, `qt6-declarative` | JS tests, the mock daemon, the QML e2e harness and `qmllint`. |
| `yubikey-manager` | Optional: manual token testing (`ykman`). |

Once the user has run it, the agent checks without root:

* `pacman -Q usbguard ccid gocryptfs udisks2 pinentry` reports every package.
* `unshare -rn nft list ruleset` and `bwrap --ro-bind / / true` both succeed.
* `systemctl is-enabled usbguard` prints `disabled`.
* `make lint test` passes, and no test reports itself skipped for a missing tool.

State of the development machine on 2026-09-26 (task 1.5 done): every package above is installed, `nodejs` 26 comes from mise, `pcscd.socket` is enabled and `usbguard` is installed but disabled. `make lint test` passes with no test skipped. The kernel has `CONFIG_DEBUG_INFO_BTF=y` and `CONFIG_BPF_LSM=y`, and lockdown is `none`.



### 5.2 (Task 2.8) Live install and privileged validation



1. Write `tools/secctl.py` (MIT, Python stdlib only). It connects to `$XDG_RUNTIME_DIR/omarchy-security/securityd.sock` (or `$OMARCHY_SECURITYD_SOCKET`), sends `HELLO`, then either one call (`secctl.py call GET_STATUS`, `secctl.py call FIREWALL_ADD_RULE '{"verdict":"block",...}'`) or `secctl.py watch threat usbguard ...`, which subscribes and prints events as NDJSON. The later tasks and `tools/system-check.sh` (4.4) use it. Take the socket path and framing from `docs/ipc-protocol.md` §1, not from memory.
2. The user runs:
   ```bash
   make release ebpf && sudo make install
   sudo systemctl daemon-reload && sudo systemctl enable --now omarchy-securityd-helper.service
   systemctl --user daemon-reload && systemctl --user enable --now omarchy-securityd.service
   ```
3. Checks. Each needs root or a second user only where noted:

   | Check | Pass when |
   |---|---|
   | eBPF attach | `journalctl -u omarchy-securityd-helper -b` shows `exec monitor attached`, and `GET_STATUS` shows `threat` `active`, not `degraded`. If the unit's hardening blocks the load, relax the one directive that blocks it and explain the reason in a comment in the unit. Never add capabilities beyond the five listed. |
   | Exec detection | `cp /usr/bin/true /tmp/x && /tmp/x a b` raises `THREAT_EXEC_DETECTED` with the right pid, ppid and argv. A memfd exec is reported with origin `memfd`. |
   | Cross-user response | The user runs `sudo -u nobody sh -c 'cp /usr/bin/sleep /tmp/s2; /tmp/s2 300'`. Quarantine, resume and kill all work through the helper, and the process is stopped, continued and then gone. |
   | Firewall | `FIREWALL_ADD_RULE` blocking outbound TCP to `1.1.1.1/32` port `443` makes `curl -m5 https://1.1.1.1` fail. `sudo nft list table inet omarchy_sec` shows the rule. `sudo ufw status` is unchanged, and `ufw`'s chains are still in `nft list ruleset`. Removing the rule restores access. |
   | Polkit | As a wheel member in the active Hyprland session, none of the above asks for a password. If it does, the session is not counted as `active`, so fix `dist/polkit/50-omarchy-security.rules` rather than widening the defaults in the `.policy` file. |
   | Reconnect | `sudo systemctl restart omarchy-securityd-helper`: the daemon reconnects, re-applies the saved rules, and `threat` goes back to `active`. |
   | Degraded | Stopping the helper sets `threat` to `degraded` and `firewall` to `unavailable`, and the daemon keeps running. |
   | Footprint | `systemctl --user show omarchy-securityd -p MemoryCurrent` stays under 40 MB, and under 2% CPU at idle (`top -p`). Do the same for the helper. |
4. Record the results in the README's Status section, and fix any bug found here before starting Phase 3.
5. After 2.18 exists, the install also enables the boot unit: `sudo systemctl enable omarchy-security-firewall.service`. Repeat the Firewall and Polkit checks once in each mode after 2.19 (§5.12). `org.omarchy.security.firewall.mode` is expected to ask for the password once and then keep it for a few minutes.



### 5.3 (Task 2.9) USBGuard setup and validation



The user runs, with every device they need plugged in (keyboard, mouse, dock, webcam and so on):

```bash
sudo pacman -S --needed usbguard
sudo sh -c 'usbguard generate-policy > /etc/usbguard/rules.conf'
sudo chmod 600 /etc/usbguard/rules.conf
sudoedit /etc/usbguard/usbguard-daemon.conf   # confirm the values below
sudo systemctl enable --now usbguard.service usbguard-dbus.service
```

Settings to confirm in `usbguard-daemon.conf`:

* `RuleFile=/etc/usbguard/rules.conf`
* `ImplicitPolicyTarget=block`
* `PresentDevicePolicy=apply-policy`
* `InsertedDevicePolicy=apply-policy`
* `IPCAllowedUsers=root` (`usbguard-dbus` runs as root)
* `IPCAllowedGroups=wheel` (the `usbguard` CLI as the user)

Safety notes. They also go into the README (task 4.3):

* Generating the policy first is what stops the user being locked out. Keyboard input needed at boot (the LUKS passphrase) is read before `usbguard` starts.
* To recover from a TTY or over ssh: `sudo systemctl disable --now usbguard`.
* A device plugged into a different port or dock later is a new device, so it arrives blocked and must be approved in the hub.

Checks:

* `GET_STATUS` shows `usbguard` `active`.
* A new USB stick produces `USB_DEVICE_PRESENTED` with `target: block`.
* `USBGUARD_SET_POLICY` with `allow` authorizes it (it mounts), and the rule is not in `sudo usbguard list-rules`.
* With `allow` and `permanent: true`, the rule appears in the list and survives unplugging the device and plugging it back in.
* With `reject`, the device disappears (`USB_DEVICE_REMOVED`).
* `sudo systemctl restart usbguard-dbus` makes the daemon resynchronize, with no duplicate devices.
* No polkit password is asked for, because `50-omarchy-security.rules` grants `org.usbguard.*` to local active wheel members.



### 5.4 (Task 2.10) Daemon configuration



* The file is `$XDG_CONFIG_HOME/omarchy-security/config.toml` (default `~/.config/omarchy-security/config.toml`). A missing file means defaults. Parse it with `toml` + `serde` and `deny_unknown_fields`. An invalid file makes the daemon log the error and keep its previous configuration (or the defaults at startup). It must never crash.
* Reload it on `SIGHUP`. Add `ExecReload=kill -HUP $MAINPID` to the user unit.
* Initial schema:
  ```toml
  [[vault]]
  id = "work"                    # vault_id on the wire; [a-z0-9-]+, unique
  name = "Work documents"
  backend = "gocryptfs"          # or "luks"
  source = "~/Vaults/work.enc"   # gocryptfs cipher dir, or LUKS image file / block device
  mount_point = "~/Vaults/work"  # gocryptfs only; udisks2 chooses the LUKS mount point

  [firewall]
  prompt = false                 # enable interactive prompts (2.14)
  prompt_timeout_secs = 30
  timeout_verdict = "block"      # verdict when nobody answers

  [firewall.alerts]              # 2.20, §5.19
  notify = true                  # desktop notifications for blocked traffic
  window_secs = 600              # group repeats of the same alert
  max_notifications_per_minute = 3
  ignore_multicast = true        # 224.0.0.0/4, ff00::/8, 255.255.255.255, IGMP
  ignore = []                    # e.g. [{protocol = "udp", port = 137}]
  temp_durations_secs = [300, 3600, 28800]   # choices offered for temporary decisions (2.21)
  ```
* Document every key in a new file, `docs/configuration.md` (MIT). Add a sample file, `dist/config.example.toml`.
* **As built (2026-09-26).** `crates/omarchy-securityd/src/config.rs`. `--config <PATH>` overrides the path. Validation beyond the schema: paths must be absolute or start with `~/` (expanded at load); `mount_point` is required for `gocryptfs` and rejected for `luks`, and is unique; `prompt_timeout_secs` 5–300, `window_secs` 10–86 400, `max_notifications_per_minute` 1–60, `temp_durations_secs` non-empty and each 60–86 400 (the `FIREWALL_TEMP_ADD` range); an `ignore` entry takes `protocol` (`tcp`/`udp`/`icmp`/`icmpv6`/`igmp`), `port` (local) and `address` (remote IP or CIDR), and needs at least one. Modules read it through `Settings::current()` and watch `Settings::subscribe()`, which fires only when a reload changes the value.



### 5.5 (Task 2.11) Encrypted vaults



* This runs entirely in the user daemon, with no new helper operations and no new capabilities.
* **gocryptfs.** To mount, run `gocryptfs -passfile /dev/stdin -- <source> <mount_point>` and write the passphrase to its stdin. Never pass it in argv or the environment. To unmount, run `fusermount3 -u <mount_point>`.
* **LUKS through udisks2.** Use zbus on the system bus with `org.freedesktop.UDisks2`.
  * To mount an image file: call `Manager.LoopSetup(fd, {})`, then `Encrypted.Unlock(passphrase, {})` on the loop device, then `Filesystem.Mount({})` on the cleartext device. Report the path it returns as `mount_point`.
  * To unmount: `Filesystem.Unmount`, then `Encrypted.Lock`, then `Loop.Delete`.
  * The udisks2 polkit defaults already allow `encrypted-unlock`, `loop-setup` and `filesystem-mount` for an active local session. Check this in 2.8's environment.
* **Passphrase.** Spawn `pinentry` (Omarchy has `pinentry-qt`/`-gnome3`) and speak Assuan to it: `SETTITLE`, `SETDESC`, `SETPROMPT`, `GETPIN`, and decode the `%XX` escapes in the `D` line. Keep the passphrase in a `zeroize::Zeroizing` buffer and drop it straight after use. A cancelled pinentry makes the call fail with a new error, `CANCELLED` (-32008, additive under protocol §7). Replace the "polkit or `systemd-ask-password`" wording in `docs/ipc-protocol.md` §4.5 with this mechanism.
* **State.** Derive `mounted` from `/proc/self/mountinfo`. Watch it with `poll(POLLPRI)` so that a vault unmounted outside the hub still emits `VAULT_STATE_CHANGED`. Set the module to `active` once the configuration has loaded, and to `unavailable` with a detail when `gocryptfs` or udisks2 is missing for a configured backend.
* **Tests.** Test gocryptfs for real when `gocryptfs` and `/dev/fuse` are available, and skip otherwise. Create the cipher dir with `gocryptfs -init` in a tempdir. Test LUKS against a fake `org.freedesktop.UDisks2` on a private `dbus-daemon`, following the pattern of the USBGuard tests in `crates/omarchy-securityd/src/usbguard.rs`. For pinentry, use a fake script given through a configurable path.
* **As built (2026-09-26).** `crates/omarchy-securityd/src/vault.rs`, `udisks.rs` and `pinentry.rs`. A wrong passphrase is asked again (pinentry's `SETERROR`) up to three attempts, then fails with `PERMISSION_DENIED`; gocryptfs signals it with exit code 12, udisks2 with cryptsetup's `EPERM` message. When the daemon runs under systemd, gocryptfs is started through `systemd-run --user --scope`, so a daemon restart does not kill mounted vaults. `mounted` for gocryptfs comes from `fuse.gocryptfs` entries in mountinfo; for LUKS from udisks2's object tree (the loop device whose `BackingFile` is the image, or the block device by number, then the cleartext device whose `CryptoBackingDevice` points at it), re-read whenever mountinfo changes. A failed LUKS mount locks and deletes whatever it set up. The module is `degraded` when only some configured backends are usable. `VAULT_PANIC` still returns `NOT_IMPLEMENTED` (2.12).



### 5.6 (Task 2.12) Panic mode



* `VAULT_PANIC` does the following, in order, for every mounted vault:
  1. Find the user's processes that use the mount: an open fd, `cwd`, `root`, or an `mmap` under the mount point, taken from `/proc/*/fd`, `cwd`, `root` and `maps`.
  2. Send them `SIGTERM`, wait up to 2 s, then send `SIGKILL`. Never signal the daemon itself, or the compositor or shell (`Hyprland`, `quickshell`/`omarchy-shell`). If one of those holds the vault, report it in `failed` instead.
  3. Call `syncfs` on the mount.
  4. Unmount and lock (see §5.5). For gocryptfs, fall back to a lazy unmount with `fusermount3 -uz`, and report that it was lazy.
  5. Finish with a global `sync()`.
* The call returns `{unmounted, failed}` as the protocol specifies, and emits `VAULT_STATE_CHANGED` for each vault.
* **Reachable without the UI.** `secctl.py call VAULT_PANIC` works, and the README documents a Hyprland keybinding for it. Make the panic path its own function with no pinentry or other prompt anywhere in it.
* **Tests.** Use a gocryptfs vault in which a child process keeps a file open. Check that panic kills the child and unmounts the vault, and that the daemon survives.
* **As built (2026-09-26).** `Vaults::panic` in `crates/omarchy-securityd/src/vault.rs`, and `crates/omarchy-securityd/src/holders.rs` for finding and stopping processes. Holders are this user's processes other than the daemon, matched by path prefix on the `cwd`/`root`/`fd` link targets and the `maps` paths, so the scan never touches the mount itself; the `starttime` from `stat` guards against PID reuse. `Hyprland`, `quickshell` (and its `.quickshell-wrapped` wrapper), `qs` and `omarchy-shell` are protected by `comm` or executable name. Every holder of every vault gets `SIGTERM` at once, then `SIGKILL` after 2 s. `syncfs` and the final `sync()` run on blocking threads with timeouts (2 s, 10 s), so a stuck FUSE mount cannot hang the call. LUKS falls back to udisks2's `Unmount` with `force` (a lazy unmount) as gocryptfs does to `fusermount3 -uz`. The result gained an additive `lazy` field (protocol §7) listing the vaults in `unmounted` that were only detached lazily; a vault held by a protected process is detached lazily as well but reported in `failed`. Panic also closes an open passphrase prompt (its `VAULT_MOUNT` fails with `CANCELLED`), and waits up to 2 s for a mount already past its prompt, so that vault is unmounted too. The README documents the keybinding (`SUPER CTRL ALT + P` through `tools/secctl.py`).



### 5.7 (Task 2.13) Connection interception in the helper



* **Mechanism.** Use NFQUEUE, as OpenSnitch does. An eBPF LSM `socket_connect` program cannot wait for a user's decision, so it cannot drive prompts.
  * While prompts or executable rules are active, the helper adds this to the output chain of `table inet omarchy_sec`, after the static allow/block rules:

    ```
    oif "lo" accept
    meta skuid <daemon uid> ct state new queue num <N> bypass
    ```
  * `bypass` fails open if the helper is not reading the queue. Document this choice, or make it configurable.
  * Only new outbound connections of the desktop user are queued. Inbound prompts are out of scope; inbound traffic is handled by alerts and temporary decisions (§5.19, §5.20).
  * The queue rule works the same in both firewall modes (§5.15), because `ufw` allows outgoing traffic on Omarchy. It goes after the temporary decisions and static rules, and it is never written to the boot copy (§5.17).
* **Per packet.**
  1. Parse the IPv4/IPv6 and TCP/UDP headers.
  2. Find the socket inode with `NETLINK_SOCK_DIAG` (inet_diag), then find the pid by matching `socket:[inode]` in `/proc/*/fd`. Cache the result, keyed on pid and start time.
  3. Read the executable from `/proc/<pid>/exe`.
  4. Evaluate the executable-scoped rules the daemon sent. If one matches, set the verdict at once. If none does, send the connection to the daemon and hold the packet until it answers or `prompt_timeout_secs` expires, then apply `timeout_verdict`.
* **Crates.** Candidates are `nfq` (a pure Rust nfnetlink_queue client) and `netlink-packet-sock-diag`. Check that they are maintained before adopting one. `CAP_NET_ADMIN` is enough; add no new capability.
* **Helper protocol.** Bump `HELPER_PROTOCOL_VERSION` to 2, since both ends ship together.
  * `FirewallApply` also carries the executable-scoped rules.
  * New op `ConnectionSubscribe`.
  * New message `Connection {request_id, pid, start_time, uid, executable, protocol, address, port}`.
  * New op `ConnectionVerdict {request_id, verdict, remember: none|process}`.
  * Authorize `ConnectionSubscribe` with the polkit action `org.omarchy.security.firewall.manage`.
  * When the daemon disconnects, remove the queue rule, so connections are not held with nobody to answer.
* **Tests.** Test in `unshare -rn` (the namespace owner holds `CAP_NET_ADMIN`). For the test, render the ruleset with a flag that queues loopback traffic, open a UDP/TCP connection from the test process, and check the lookup of pid and exe and both verdict paths, including the timeout.
* **As built (2026-09-26).** `crates/omarchy-security-helper/src/connections.rs` (the queue thread and verdict logic), `nfqueue.rs`, `sockdiag.rs`, `packet.rs` and `netlink.rs`. Neither candidate crate was adopted: `nfq` has had no release since 2022, and the few fixed netlink structures are written out by hand over nix's safe socket calls (no `unsafe`), so they are easy to fuzz later. The queue is number 7433 (`--queue-num`, `--no-connections`), bound with `NFQA_CFG_F_FAIL_OPEN`; the rule is `meta skuid <uid> meta l4proto { tcp, udp } ct state new queue num 7433 bypass`, after `oif "lo" accept`, and it is present only while a client subscribes or executable rules are applied (it is taken out when the last subscriber disconnects and when the helper stops). Interception fails open on purpose, which is documented in the module: `bypass`, a full queue, and a packet whose process cannot be found (the socket already closed, or a kernel socket) are all accepted; static rules still apply. The socket is found by dumping `sock_diag` for the local port and scoring candidates (connected over unconnected, IPv4-mapped IPv6 sockets included), then `socket:[inode]` in `/proc/*/fd` of processes of that uid, cached by inode and by (pid, start time). A `remember: process` verdict is keyed on (pid, start time, protocol, address, port) and pruned when the process exits; decided flows keep their verdict for 30 s so TCP SYN retransmissions do not prompt again. `connection_verdict` is accepted only from the connection that received the record. `connection_subscribe` takes `timeout_secs` (1–3600) and `timeout_verdict`. `HelperHello` gained `connections`/`connections_detail`. On the daemon side, `HelperClient::connections()` relays the records to the prompts of 2.14 (§5.8). The namespaced end-to-end test is `connections::tests::intercepts_connections_in_a_namespace`, which re-runs the test binary under `unshare -rn` with `--queue-loopback`-style rendering.



### 5.8 (Task 2.14) Executable-scoped rules and prompts in the daemon



* **Executable rules.** Accept `executable` in `FirewallRuleSpec` (an absolute path, compared with `/proc/<pid>/exe` after stripping ` (deleted)`). Match on the path, not the inode, so that package upgrades keep the rules. Persist the rules in `firewall.json` as today, and remove the `NOT_IMPLEMENTED` check.
* **Prompts.** When `[firewall] prompt = true` and at least one client subscribes to the `firewall` topic, the daemon subscribes to the helper's connections.
  * For each connection it emits `FIREWALL_CONNECTION_PROMPT` with `expires_at`.
  * Pending prompts for the same executable, address, port and protocol are merged into one.
* **`FIREWALL_DECIDE`.** The first decision wins.
  * `once` applies to this connection only.
  * `process` applies until the process exits. Keep it in memory, keyed on pid and start time.
  * `always` saves an executable-scoped rule. It works in both firewall modes, because it is outbound (§5.15).
  * Add the event `FIREWALL_CONNECTION_RESOLVED {request_id, verdict, decided_by: "user" | "timeout"}` (additive under §7), so that other clients close their prompt.
* **Documentation.** Update `docs/ipc-protocol.md` §4.6 and §5, `tools/mock-securityd.py`, and `plugins/security_hub/services/Protocol.js` constants.
* **As built (2026-09-26).** `crates/omarchy-securityd/src/firewall.rs`. Executable rules must be absolute paths and `outbound` (`INVALID_PARAMS` otherwise). When the helper's hello says it cannot intercept (`connections: false`), adding one fails with `MODULE_UNAVAILABLE`, and saved ones stay listed and saved but are left out of `FirewallApply`, with the module `degraded`, so the static rules keep applying. The hub counts subscribers per topic (`Hub::listeners`). The daemon subscribes while `prompt` is on, a client listens to `firewall`, and the helper intercepts, and it sends the new helper op `connection_unsubscribe` when any of these stops; changing the timeout settings re-subscribes. The helper holds each connection for `prompt_timeout_secs` + 5 s, and the daemon applies `timeout_verdict` itself at `expires_at`, so the helper's timeout only matters if the daemon never answers. Merged prompts carry the helper request ids of every connection they cover (the first one's `pid` is shown), and a decision answers all of them. `process` is forwarded as `remember: process`, which the helper keys on each connection's pid and start time. `always` answers with `remember: none`, then adds the rule (single address, port, protocol), skipping it if an identical rule exists. Prompts that are still pending when prompting stops or the helper connection changes resolve with `decided_by: "timeout"`. A decision never answers request ids from an earlier helper connection. A refused `connection_subscribe` is logged and retried only when an input changes. The new event is `FIREWALL_CONNECTION_RESOLVED`, with a new `DecidedBy` type. The mock sends a prompt on `SIGUSR2`.



### 5.9 (Task 2.15) OpenPGP card (gpg) touch prompts



* **Background.** A card waiting for touch sends nothing the host can see over PC/SC. The prior art is `yubikey-touch-detector` (github.com/maximbaz/yubikey-touch-detector). Read its current GPG detector before implementing: it uses an inotify trigger on gpg's files plus a probe that times out while the card waits. Reproduce the approach; do not copy the code without checking the license, since that project is ISC-licensed.
* **Trigger.** Watch `$GNUPGHOME` (default `~/.gnupg`) for `IN_OPEN` on `pubring.kbx`, and the gpg-agent sockets under `$XDG_RUNTIME_DIR/gnupg/`.
* **Probe.** Send a short query to scdaemon through `gpg-connect-agent --no-autostart`, with a timeout of about 400 ms. A timeout while a gpg operation is running means the card is waiting for touch.
* **Events.** Emit `TOKEN_TOUCH_REQUESTED` with `source: "gpg"` and the `token_id` of the OpenPGP-capable token present. Emit `TOKEN_TOUCH_COMPLETED` when the probe answers again (`touched`) or after 15 s (`timed_out`).
* **Scope.** Generic PC/SC (PIV) prompts cannot be detected reliably. Keep `pcsc` reserved and say so in `docs/ipc-protocol.md` §4.4.
* **Tests.** Test the state machine with a fake probe command, and the trigger with a temporary `GNUPGHOME`.
* **As built (2026-09-28).** `crates/omarchy-securityd/src/gpg.rs`, wired into `token.rs`. Upstream replaced the inotify-and-probe detector on 2026-09-20 with a transparent proxy on the gpg-agent socket. We kept inotify-and-probe on purpose. The proxy renames the user's agent socket, and gpg stays broken if the proxy dies. The approach was reimplemented from its description; no code was copied. Two changes from the spec above: (1) The trigger is `IN_OPEN` on the card-key stubs in `$GNUPGHOME/private-keys-v1.d` (files containing `shadowed-private-key`), not `pubring.kbx`. gpg-agent opens the stub for every private-key operation, including SSH through gpg-agent. Every `gpg` command opens `pubring.kbx`, including `--list-keys`. (2) The sockets are not watched, because connecting to a socket raises no inotify event. One directory watch follows new and removed stubs. The events from our own stub rereads are drained. When the directory is missing, the daemon checks again every 30 s. The probe is `gpg-connect-agent --no-autostart "SCD SERIALNO" /bye`. It runs 200 ms after the trigger and is killed on timeout. If it has not answered after 400 ms while a `pinentry` of the user is running, the wait is PIN entry, not a touch. The 400 ms window then restarts when the pinentry closes. Prompts are only probed while a token with `openpgp` (or else a `smartcard` reader) is present, and they carry its `token_id`. When the probe cannot run or inotify is unavailable, the token module reports `degraded`. Tests: `gpg::tests::probe_state_machine` (fake `sh` probes and a fake `/proc` with pinentry), `gpg::tests::triggers_on_card_stub_opens`, and `token::tests::gpg_card_touch_prompt`. **Not validated on hardware yet.** No OpenPGP card was available, so it is still unchecked that `SCD SERIALNO` really waits behind a pending touch on a YubiKey.



### 5.10 (Task 2.16) Inotify drop detection



* Watch `/tmp`, `/var/tmp` and `/dev/shm` without recursion, plus each new first-level directory for a bounded time, with `IN_CLOSE_WRITE | IN_ATTRIB | IN_MOVED_TO`.
* Report a regular file that is executable by its owner and starts with the ELF magic or `#!` as `THREAT_FILE_DROPPED {path, uid, size, detected_at}` on the `threat` topic. This is additive under §7.
* Rate-limit the events. Ignore files owned by other users unless the helper is active.
* When the same path is later executed, the `ThreatAlert` gains `dropped_at?`, an optional field, so the UI can show the time between the drop and the execution.
* Confirm the value of this task with the project owner before building it. The eBPF exec monitor already catches the execution itself.
* **As built (2026-09-28).** Built at the project owner's request. `crates/omarchy-securityd/src/drops.rs`, wired into `threat.rs`. The watcher also takes `IN_CREATE` on the three roots to see new first-level directories. It watches each one for 5 min, at most 128 at a time, and examines the files already in it when the watch is added. Files are checked with `lstat` first, so FIFOs and device nodes are never opened, and then opened with `O_NOFOLLOW \| O_NONBLOCK`. Each version of a file (device, inode, mtime and size, not ctime) is reported once, so a write followed by `chmod +x` gives one event. Rate limit: a burst of 10, then one every 3 s, with the suppressed count logged. "Helper active" means the helper is connected; other users' files are then reported if this user can read them. `THREAT_FILE_DROPPED` carries no `alert_id` and is not kept for `THREAT_LIST_ALERTS`. The last 1024 dropped paths are remembered for `dropped_at`. If inotify or every root fails, the `threat` module keeps its state and its `detail` names the problem. The gpg trigger's inotify wrapper moved to `inotify.rs`, which both use. Tests: `drops::tests::{examines_only_executable_programs, rate_limit_allows_a_burst_then_refills, reports_drops_in_roots_and_new_subdirectories, fails_without_any_root}`, `threat::tests::{a_dropped_file_is_reported_and_its_run_carries_dropped_at, other_users_drops_need_the_helper}`, and a wire-format test.



### 5.11 (Tasks 3.7–3.9) Additional views



* Every new view takes the theme from `ThemeProvider.qml` (3.1). It reaches the daemon only through the `SecurityIPC.qml` service, via `shell.serviceFor("security-hub")`, and handles `MODULE_UNAVAILABLE` and `NOT_IMPLEMENTED` with a stated empty state, not an error.
* `VaultPanel` never asks for a passphrase itself: the daemon's pinentry does. The Panic button needs a two-step confirmation, which is a hold or a second click.
* `SandboxLauncher` validates absolute paths on the client, but relies on the daemon's checks.
* Add the new views to `tests/e2e/shell.qml`, and give each one a mock scenario.



### 5.12 (Task 4.4) End-to-end system check



* `tools/system-check.sh` is read-only, apart from the explicit test actions it announces. It runs as the user, and uses `sudo -n` only for checks that need root, reporting them as SKIP if `sudo` is unavailable.
* It covers:
  * everything in §5.2 and §5.3;
  * vault mount, unmount and panic, with a throwaway gocryptfs vault it creates in a temporary directory;
  * an executable-scoped block rule and a prompt that times out;
  * a gpg touch prompt (manual step, which the script announces);
  * the firewall in both modes (§5.15–§5.20): the mode reported matches `sudo nft list ruleset`; switching to `standalone` and back leaves no moment without an input `drop` policy (poll `nft -j list ruleset` every 100 ms during the switch); after a reboot in `standalone` mode, the table is loaded before login; LocalSend still works after the import; a published Docker port is not reachable from another host; a TCP SYN from another host to a closed port raises one `FIREWALL_ALERT` and one notification; a temporary inbound allow works in each mode and disappears on its own (in `ufw` mode, from `sudo ufw status`); a mode of `both` is reported after an outside `sudo ufw enable`; `nftables.service` is not enabled with a `flush ruleset` config;
  * the footprint limits of task 4.1.
* It exits non-zero on any FAIL. It is not run by `make test`; `make system-check` runs it.



### 5.13 (Task 4.5) Security review and fuzzing



* **Review, and write down the findings in `docs/security.md`:**
  * The helper socket is mode `0666`. Check that polkit is consulted for every operation, including `hello`/`exec_subscribe`, and that the subject is the peer's pid and start time, not the uid.
  * Signals must be limited to processes the helper itself reported. Check the start-time recheck.
  * nft script rendering must stay injection-safe: addresses are parsed into typed values, and no string from a client is copied into the script verbatim.
  * The sandbox profile must not escape to the runtime dir, the D-Bus sockets, or `/proc/1`.
  * A vault passphrase must never appear in logs or `argv`, or anywhere in memory after use.
  * The daemon socket permissions and the `SO_PEERCRED` check.
  * The `ufw` calls: argv built only from typed values, no shell, cleared environment; tagged temporary rules always expire (sweep at startup and after a reboot); a mode switch never leaves the machine with no firewall, including on every failure branch; every inbound allow and every mode change needs `org.omarchy.security.firewall.mode`.
  * The boot copy `/var/lib/omarchy-security/firewall.nft` is root-owned, `0600`, written atomically, and never contains temporary decisions or the NFQUEUE rule.
* **Fuzzing.** Add `cargo fuzz` targets, which need nightly, so keep them in their own workspace, as the eBPF crate is. Targets:
  * NDJSON framing and JSON-RPC parsing (`server.rs`);
  * the USBGuard rule parser (`usbguard.rs`);
  * uevent parsing and CTAPHID frames (`token.rs`);
  * eBPF event parsing (`omarchy-security-helper/src/exec.rs`);
  * packet parsing (2.13);
  * kernel-log block lines (2.20) and `ufw` tuples (2.17).



### 5.14 (Task 5.4) Arch package



* `depends`: `glibc`, `systemd`, `polkit`, `nftables`, `bubblewrap`.
* `optdepends`:
  * `usbguard`: USB device control;
  * `pcsclite` and `ccid`: smart cards;
  * `libfido2`: FIDO2 touch prompts;
  * `udisks2` and `cryptsetup`: LUKS vaults;
  * `gocryptfs` and `fuse3`: gocryptfs vaults;
  * `pinentry`: vault passphrases;
  * `gnupg`: gpg touch prompts;
  * `ufw`: the `ufw` firewall mode (installed by Omarchy).
* `makedepends`: `rustup`, `llvm`, `clang`, `bpf-linker`.
* `package()` calls `make install DESTDIR="$pkgdir"`. It installs `omarchy-security-firewall.service` (§5.17) and creates `/var/lib/omarchy-security` (`0700`) through a `tmpfiles.d` entry.
* The `.install` script prints the enable commands from §5.2 and the USBGuard procedure from §5.3. It never runs `systemctl enable` on `usbguard`, never runs `ufw`, and never changes the firewall mode: a fresh install stays in `ufw` mode.
* The plugin is installed to `/usr/share/omarchy-security/plugin`, and the user links or enables it through Omarchy's plugin mechanism. It is not written into `$HOME` from `package()`.



### 5.15 UFW coexistence and firewall modes (overview for tasks 2.17–2.21 and 3.10)



The owner's requirements (2026-09-25):

* The UI tells the user that `ufw` is running and can conflict with the hub's rules.
* The UI can turn `ufw` off and on.
* With `ufw` on, the UI only shows the rules `ufw` enforces; with `ufw` off, the user manages the hub's own nftables rules.
* The user is told about blocked traffic, in a way that fits Omarchy, and can allow or block temporarily in both cases.

**Kernel facts that constrain the design.** Every base chain on a hook sees every packet, whichever table it lives in. `drop` is final everywhere. `accept` only ends the evaluation of the chain that issued it; the packet still goes through `ufw`'s chains. So:

* A hub `allow` can never override a `ufw` block. With `ufw` on, an inbound temporary allow must be a `ufw` rule (§5.20).
* A hub `block` always works, in both modes.
* Outbound traffic is allowed by `ufw` on Omarchy (`DEFAULT_OUTPUT_POLICY="ACCEPT"` in `/etc/default/ufw`), so outbound prompts (2.13/2.14) and outbound temporary allows work in our table in both modes. If the user changed that default to `DROP`, treat outbound allows like inbound ones (use the `ufw` backend).

**Facts about this machine (2026-09-25).** `ufw` 0.36.2 on `iptables` 1.8.13 (nf_tables backend, so `ufw`'s chains appear in `nft list ruleset` as tables `ip filter` / `ip6 filter`). `ufw-docker` is installed and its block is in `/etc/ufw/after.rules`. `ENABLED=yes`, `LOGLEVEL=low`. The user rules (from `/usr/share/omarchy/install/config/firewall.sh`) are LocalSend `53317/tcp+udp` and two Docker DNS rules. `/etc/ufw/ufw.conf`, `/etc/default/ufw`, `/etc/ufw/user.rules` and `user6.rules` are world-readable (0644); `before.init`/`after.init` are not. `nftables.service` is disabled. The kernel log had 239 `[UFW BLOCK]` lines in 24 h, nearly all IGMP (`PROTO=2`) to `224.0.0.251` from the Wi-Fi network.

**Omarchy desktop facts.** Omarchy 4 has no mako and no Waybar: `omarchy-shell` (Quickshell) is the bar and the `org.freedesktop.Notifications` server (`GetServerInformation` → `quickshell`; capabilities include `actions`, `persistence`, `body-markup`). Its notification service keeps a history under `$XDG_STATE_HOME`, supports do-not-disturb (`omarchy-toggle-notification-silencing`, `SUPER+CTRL+,`), lets DND bypass only the app name `omarchy-action` or critical `notify-send`, and has keybindings to invoke the last notification (`SUPER+ALT+,`) and open the history (`SUPER+SHIFT+ALT+,`). The shell has its own polkit agent plugin, so `auth_admin_keep` prompts work in the session.

**Modes.** The daemon reports one of these as `FirewallMode.mode`:

| Mode | `ufw` | Our table holds | Saved hub rules (`firewall.json`) | Rules view in the UI |
|---|---|---|---|---|
| `ufw` (default on Omarchy) | active | only the NFQUEUE rule (2.13), executable rules (2.14), temporary decisions (2.21). Chains `policy accept`. | kept, **not loaded** (`loaded: false`) | `ufw`'s rules, read-only |
| `standalone` | inactive | the full policy: baseline (§5.17), saved rules, executable rules, temporary decisions. Input chain `policy drop`. | loaded | hub rules, editable |
| `both` (conflict) | active | the standalone policy | loaded | warning banner, and both rule lists |
| `none` (unprotected) | inactive | no standalone policy | not loaded | critical banner |
| `unknown` | cannot tell (helper down) | — | — | banner explaining that the state is unknown |

`both` and `none` are never chosen by the hub. They appear when someone runs `ufw enable`/`ufw disable` outside the hub, or when an Omarchy update re-runs its firewall setup. The daemon does not repair them on its own: it reports them, notifies once (§5.19), and the UI offers the two fixes ("Use UFW" / "Use Security Hub firewall"). `both` is safe (stricter, only confusing). `none` is urgent.

**Where the state lives.**

* The desired mode is system state, not user state, because it must hold before login: `/var/lib/omarchy-security/mode` (`ufw` or `standalone`), written by the helper.
* The rendered persistent ruleset is `/var/lib/omarchy-security/firewall.nft` (root, 0600), loaded at boot (§5.17).
* The daemon keeps owning the rule list in `$XDG_STATE_HOME/omarchy-security/firewall.json`, as today.

**Protocol additions (all additive under protocol §7; update `docs/ipc-protocol.md` §4.6, §5 and §6, `tools/mock-securityd.py` and `plugins/security_hub/services/Protocol.js` in the same change):**

| Method | Params | Result |
|---|---|---|
| `FIREWALL_GET_MODE` | — | `FirewallMode {mode, ufw: {installed, enabled_in_conf, chains_loaded, default_input, default_output, logging}, table_loaded, docker_protection: "ufw-docker" \| "omarchy" \| "none", detail?}` |
| `FIREWALL_SET_MODE` | `{mode: "ufw" \| "standalone", import_ufw_rules?: bool}` | `FirewallMode` |
| `FIREWALL_UFW_RULES` | — | `{rules: UfwRule[], builtin: string[], source: "user.rules"}` |
| `FIREWALL_ALERT_LIST` | `{limit?}` | `{alerts: FirewallAlert[]}` |
| `FIREWALL_ALERT_MUTE` | `{alert_id, duration_secs}` | `{}` |
| `FIREWALL_TEMP_ADD` | `{spec: FirewallRuleSpec, verdict, duration_secs, alert_id?}` | `TempDecision` |
| `FIREWALL_TEMP_LIST` | — | `{decisions: TempDecision[]}` |
| `FIREWALL_TEMP_REMOVE` | `{temp_id}` | `{}` |

* `FirewallRule` gains `loaded: bool`.
* `UfwRule {action: "allow"|"deny"|"reject"|"limit", direction: "in"|"out", protocol, port?, src, dst, iface?, comment?, ipv6: bool, temp_id?, expires_at?}` (the last two only for rules the hub added, §5.20).
* `FirewallAlert {alert_id, source: "ufw"|"omarchy", direction: "inbound"|"outbound"|"forward", protocol, src, dst, dst_port?, iface, count, first_seen, last_seen, muted_until?}`.
* `TempDecision {temp_id, spec, verdict, backend: "table"|"ufw", created_at, expires_at}`.
* Events on topic `firewall`: `FIREWALL_MODE_CHANGED {FirewallMode}`, `FIREWALL_ALERT {FirewallAlert}` (emitted when an alert is created and again when its count changes, at most once per 5 s per alert), `FIREWALL_TEMP_CHANGED {decisions}`.
* New error `MODE_CONFLICT` (-32009): the call cannot work in the current mode (for example `FIREWALL_ADD_RULE` with an inbound `allow` while in `ufw` mode). The message says what to do instead. `FIREWALL_ADD_RULE`/`REMOVE_RULE` still work in `ufw` mode (they edit the saved list, reported as `loaded: false`) except when the rule would be misleading, which is only an inbound `allow`.
* `GET_STATUS`: the `firewall` module's `detail` states the mode.

**Helper protocol.** These tasks add helper ops (listed in §5.17–§5.20). Bump `HELPER_PROTOCOL_VERSION` once per release that changes it (2.13 already bumps it to 2; if these ship in the same release, they share version 2).

**Polkit.** Add the action `org.omarchy.security.firewall.mode` (defaults `auth_admin`). In `50-omarchy-security.rules`, a wheel member in a local active session gets `polkit.Result.AUTH_ADMIN_KEEP` for it, not `YES`. It covers everything that weakens or replaces a firewall: `FIREWALL_SET_MODE`, and every temporary or permanent **inbound allow** in either mode. Temporary blocks, mutes and outbound decisions stay under `org.omarchy.security.firewall.manage` (no password). Document the reason in the rules file: these are the changes that expose the machine to the network.



### 5.16 (Task 2.17) UFW detection and the read-only rules view



* **Detection, unprivileged part (daemon).** Parse `/etc/ufw/ufw.conf` (`ENABLED`, `LOGLEVEL`) and `/etc/default/ufw` (`DEFAULT_INPUT_POLICY`, `DEFAULT_OUTPUT_POLICY`, `DEFAULT_FORWARD_POLICY`). Watch both files and `/etc/ufw/user*.rules` with inotify on their directory (the files are replaced by rename). `installed` is whether `/usr/bin/ufw` exists. `docker_protection` is `ufw-docker` when `after.rules` contains the `BEGIN UFW AND DOCKER` marker.
* **Detection, privileged part (helper op `FirewallInspect`).** Returns whether `ufw`'s chains are loaded (the chain `ufw-user-input` exists in `ip filter`; check with `nft -j list chains ip`) and whether our table is loaded and in which mode (the helper stamps the mode into the table as a comment: `table inet omarchy_sec { comment "mode=standalone"; ... }`). Do not use the `ufw.service` unit state: it is `oneshot` with `RemainAfterExit`, so it stays `active` after `ufw disable`. Authorize with `org.omarchy.security.firewall.manage`. Poll it every 30 s and after every inotify change or mode switch; emit `FIREWALL_MODE_CHANGED` only on change.
* **Mode derivation.** `ufw` active = `enabled_in_conf` and `chains_loaded`. Combine with the table's mode stamp using the table in §5.15. With the helper down, report `unknown` and fill in the unprivileged fields only.
* **Rules view (`FIREWALL_UFW_RULES`).** Parse the `### tuple ###` lines of `/etc/ufw/user.rules` and `user6.rules` (no root needed). Format: `### tuple ### <action> <proto> <dport> <dst> <sport> <src> <direction>[_<iface>] [comment=<hex>]`, where `any` means no constraint and the comment is hex-encoded UTF-8 (for example `616c6c6f772d646f636b65722d646e73` = `allow-docker-dns`). Return `builtin` as a fixed, documented list of what `before.rules`/`after.rules` do on a stock install (established traffic, loopback, ICMP, DHCP client, mDNS, UPnP, and the ufw-docker block when present). `FirewallInspect` also reports `before_rules_modified`: the helper compares `/etc/ufw/before.rules` and `before6.rules` with the packaged copies in `/usr/share/ufw/iptables/` (mode 0640, so the daemon cannot). When they differ, the UI adds "`before.rules` has local changes" to the summary. `after.rules` is expected to differ because of ufw-docker. Do not call `ufw status` (needs root and is slow).
* **Tests.** Unit tests for the tuple parser with the four real tuples above, IPv6 tuples, interfaces (`in_wlan0`), and malformed lines (skipped, not fatal). Mode-derivation tests over every combination. A test with a temporary `/etc/ufw`-like directory given through a configurable root path.
* **As built (2026-09-28).** `crates/omarchy-securityd/src/ufw.rs` (files, tuple parser, mode derivation, inotify watch on `/etc/ufw` and `/etc/default`), wired into `firewall.rs`; helper op `firewall_inspect` in `crates/omarchy-security-helper/src/firewall.rs` (`nft -j list tables` / `list chains`, and the `before.rules` comparison), authorized non-interactively with `org.omarchy.security.firewall.manage`. It shares helper protocol version 2 with 2.13. `FIREWALL_GET_MODE` and `FIREWALL_UFW_RULES` work while the module is unavailable. `UfwState` also carries `default_forward` and `before_rules_modified`, and `UfwRule` also carries `src_port`. The tuple parser takes the application form (`<dapp> <sapp>` before the direction) and logging actions (`allow_log`), and skips routed (`route:`) rules. `builtin` is empty when `ufw` is not installed. Deferred to 2.18/2.19, where they first mean something: `FirewallRule.loaded` and `MODE_CONFLICT`. `docs/ipc-protocol.md` §4.6 and §5, `tools/mock-securityd.py` (SIGHUP toggles `ufw`/`none`) and `Protocol.js` (`FIREWALL_MODES`, `firewallModeLabel`) are updated. Tests: `ufw::tests::{parses_the_omarchy_tuples, parses_ipv6_interfaces_apps_and_logging, skips_malformed_and_routed_lines, derives_every_mode, reads_an_etc_ufw_tree, notices_files_replaced_by_rename}`, `firewall::tests::{tracks_the_mode_and_serves_ufw_rules, the_mode_is_unknown_without_the_helper}`, helper `firewall::tests::{reads_the_table_mode_and_ufw_chains, compares_before_rules_with_the_packaged_copies, inspects_a_live_ruleset}`, and the wire-format tests `firewall_mode_matches_spec` and `ufw_rules_match_spec`. Checked against this machine's `/etc/ufw` (all six tuples parsed, ufw-docker detected). **Validated live (2026-09-28)** with the protocol-2 helper installed: `FIREWALL_GET_MODE` reports `ufw` with `chains_loaded: true`, `docker_protection: ufw-docker` and `before_rules_modified: false`, and the 30 s inspect is authorized without a prompt.



### 5.17 (Task 2.18) Standalone baseline policy and boot persistence



* **Why.** Our table is applied only when the user daemon connects (after login), and its chains are `policy accept`. If `ufw` is turned off, the machine must still be protected at boot and before login, as `ufw` protects it today.
* **Boot copy.** Every successful `FirewallApply` in the helper also writes the persistent part of the rendered script (atomically: temp file, `fsync`, rename) to `/var/lib/omarchy-security/firewall.nft`. The persistent part is: in `standalone` mode, the baseline plus saved rules plus executable rules; in `ufw` mode, nothing (the file then only deletes the table). It never contains temporary decisions or the NFQUEUE rule, because no one is there to answer at boot.
* **Boot unit.** Add `dist/systemd/system/omarchy-security-firewall.service`:
  ```ini
  [Unit]
  Description=Security Hub firewall (boot copy)
  DefaultDependencies=no
  After=local-fs.target
  Before=network-pre.target shutdown.target
  Wants=network-pre.target
  Conflicts=shutdown.target
  ConditionPathExists=/var/lib/omarchy-security/firewall.nft

  [Service]
  Type=oneshot
  RemainAfterExit=yes
  ExecStart=/usr/bin/nft -f /var/lib/omarchy-security/firewall.nft

  [Install]
  WantedBy=sysinit.target
  ```
  `make install` installs it, and 2.8's instructions enable it. It must not be ordered after the helper.
* **Baseline** (rendered by the helper when the mode is `standalone`; mirrors what Omarchy's `ufw` setup allows today, so switching changes nothing the user relies on):
  ```
  chain input {
      type filter hook input priority filter; policy drop;
      <temporary decisions, §5.20>
      ct state established,related accept
      ct state invalid drop
      iif "lo" accept
      meta l4proto icmp icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept
      meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
      udp sport 67 udp dport 68 accept
      udp sport 547 udp dport 546 accept
      ip daddr 224.0.0.251 udp dport 5353 accept
      ip6 daddr ff02::fb udp dport 5353 accept
      <saved inbound rules>
      limit rate 5/second burst 20 packets log prefix "[OMSEC BLOCK] " level info
  }
  chain forward {
      type filter hook forward priority filter; policy accept;
      <Docker protection, below>
  }
  chain output {
      type filter hook output priority filter; policy accept;
      <temporary decisions>, <saved outbound rules>, <executable rules / NFQUEUE, 2.13>
  }
  ```
  Leave `forward` `policy accept`: Docker's own `iptables` chains already set their policy, and a `drop` here would break container networking and libvirt.
* **Docker protection.** With `ufw-docker`, published container ports are reachable only from private networks. Reproduce that: read the `ufw-docker` block in `/etc/ufw/after.rules` on the machine and translate its intent to `forward` rules (new connections that Docker DNAT-ed to a container, `ct status dnat`, from a source outside `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16` are dropped and logged). Write a test that renders it, and check it for real in 4.4 with `docker run -p 8080:80 nginx` and a connection from another host.
* **Importing UFW's rules.** On the first switch to `standalone` (and whenever `import_ufw_rules: true` is passed), the daemon converts every `ufw` user tuple it can express into a saved hub rule (`allow in` tuples become inbound `allow` rules with the same protocol, port and source; `deny`/`reject` become `block`; `limit` becomes `allow` plus a note, because rate limiting is out of scope) and returns the list for the UI to show before confirming. Tuples it cannot express are listed and not imported. On this machine that imports LocalSend and the Docker DNS rules.
* **Coexistence checks.** `nftables.service` with the stock `/etc/nftables.conf` starts with `flush ruleset`, which would remove `ufw`'s tables and ours on every start or reload. The daemon reports `detail` "nftables.service is enabled and flushes the ruleset" when it is enabled, and 4.4 fails on it. `firewalld` must not be active either (it is not installed on Omarchy); report it the same way.
* **Tests.** Render tests for both modes (golden files). In `unshare -rn`: apply the standalone script, then check with `nft -j list ruleset` that the input policy is `drop`, a TCP connection to an unlisted port on a veth peer is dropped, one to an imported port is accepted, and the boot copy equals the persistent part of the applied script.
* **As built (2026-09-28).** Rendering, the mode file, the boot copy and `restore` are in `crates/omarchy-security-helper/src/firewall.rs`; `loaded`, `MODE_CONFLICT`, the coexistence checks and the importer are in `crates/omarchy-securityd/src/firewall.rs` and `ufw.rs`. How it differs from the spec above: (1) the baseline also accepts SSDP (`ip daddr 239.255.255.250 udp dport 1900`), because `ufw`'s `before.rules` allow UPnP. (2) The helper keeps the rules it last applied in `/var/lib/omarchy-security/rules.json`. At startup in `standalone` mode it re-applies them and rewrites the boot copy before any daemon connects, so a stale boot copy is replaced. The helper unit gets `StateDirectory=omarchy-security` (0700). (3) The boot copy is rewritten only when it changes, so a new queue rule does not rewrite it. A failed write does not fail the apply: the table is loaded anyway. The failure goes into `FirewallInspection.boot_copy_error` and the mode's `detail`. (4) The Docker forward rules also accept established traffic, `docker0`-to-`docker0` traffic and private sources before the logged drop. The drop matches only `ct status dnat`, so libvirt and VPN routing are not touched. They log with `[OMSEC DOCKER BLOCK] `. (5) Every rule is rendered in both modes, even though `ufw` mode writes none of them, so a bad saved rule fails at once and not later at the switch. (6) `nftables.service` is reported only when `/etc/nftables.conf` contains `flush ruleset`, or cannot be read. (7) `ufw::import` is written and tested, but nothing calls it until `FIREWALL_SET_MODE` (2.19); likewise, nothing writes the mode file before 2.19, so installs stay in `ufw` mode. `MODE_CONFLICT` (inbound allow while `ufw` or `both`) and `loaded` are in `docs/ipc-protocol.md` §4.6 and §6, `Protocol.js` and `tools/mock-securityd.py`. Tests: helper `firewall::tests::{renders_the_standalone_policy, ufw_mode_keeps_only_the_queue, the_boot_copy_never_queues, a_bad_rule_fails_the_render, nft_accepts_the_rendered_ruleset, enforces_the_standalone_policy, persists_the_mode_rules_and_boot_copy}` (golden files in `crates/omarchy-security-helper/testdata/`; the veth test is `testdata/standalone-netns.sh`), and daemon `firewall::tests::rules_follow_the_mode` and `ufw::tests::{imports_the_omarchy_rules, imports_what_a_hub_rule_can_express, notices_a_flushing_nftables_conf, reports_services_that_undo_the_ruleset}`. **Validated live (2026-09-28):** the installed helper loads `mode=ufw` from its state directory, and an inbound allow fails with `MODE_CONFLICT` while `ufw` is active. **Validated live with 2.19 (2026-09-28):** the standalone table and the boot unit loading it before login. **Not validated live yet:** the Docker rules. The Docker check with a second host belongs to 4.4.



### 5.18 (Task 2.19) Switching modes (turn UFW off and on)



* **Helper op `FirewallSetMode {mode, rules}`.** It runs the whole switch under the helper's firewall lock, so no other apply can interleave. It needs `org.omarchy.security.firewall.mode`. It calls `ufw` through `std::process::Command` (absolute path `/usr/bin/ufw`, cleared environment plus `PATH=/usr/bin:/usr/sbin`, `LC_ALL=C`), never through a shell.
* **To `standalone`** (never leave a window with no firewall):
  1. Render and apply the standalone table (baseline plus `rules`), and verify with `nft -j list table inet omarchy_sec` that the input chain has policy `drop` and the mode stamp says `standalone`.
  2. Write the boot copy and `/var/lib/omarchy-security/mode`.
  3. Run `ufw disable` (sets `ENABLED=no` and unloads its chains; leave `ufw.service` enabled, since with `ENABLED=no` it loads nothing).
  4. Verify that `ufw`'s chains are gone. If step 3 or 4 fails, stay with both enforcing (mode `both`) and return the error; never roll back step 1 in that case, because that would leave `ufw` in an unknown state with no hub policy.
* **To `ufw`:**
  1. Run `ufw --force enable`, and verify its chains are loaded.
  2. Only then re-render our table without the standalone policy, write the boot copy, and write the mode file.
  3. If step 1 fails, keep `standalone` and return the error.
* **Afterwards** the daemon emits `FIREWALL_MODE_CHANGED` and re-applies temporary decisions through the backend that the new mode requires (§5.20).
* **Omarchy updates.** An Omarchy update may run `ufw enable` again. The inotify watch on `ufw.conf` and the 30 s inspect catch it; the result is mode `both`, and the UI offers the choice. Record in `docs/security.md` that the hub never fights `ufw` on its own.
* **Recovery** (for the README, 4.3): from a TTY or ssh, `sudo ufw --force enable && sudo nft delete table inet omarchy_sec && sudo rm /var/lib/omarchy-security/firewall.nft` returns the machine to stock Omarchy.
* **Tests.** Put `ufw` behind a configurable path, and test the ordering and every failure branch with a fake `ufw` script that records its calls and can be told to fail. Real `ufw` is exercised only in 4.4.
* **As built (2026-09-28).** The switch is `Firewall::set_mode` in `crates/omarchy-security-helper/src/firewall.rs` (helper op `firewall_set_mode`, which returns the `FirewallInspection` after the switch) and `Firewall::set_mode` in `crates/omarchy-securityd/src/firewall.rs`. How it differs from the spec above: (1) To `standalone`: if the check in step 1 fails, the helper restores the table it had, since `ufw` has not been touched yet. A failed boot copy or mode-file write also stops before `ufw disable`, so both stay enforcing. (2) To `ufw`: the rules are rendered before `ufw` is touched, so a bad saved rule fails with nothing changed. A failed mode-file write after the switch is only logged, because `ufw` and the boot copy already agree. (3) `import_ufw_rules` is optional: absent means "only on the first switch to `standalone`", which the daemon records in `ufw-imported` next to `firewall.json`; `false` skips that. The import is committed only if the switch succeeds, and rules that are already saved are not added again. (4) The result is `FirewallMode` plus `imported: [{rule, from, notes?}]` and `not_imported: [{from, reason}]` (`SetModeResult`), both absent when empty, so the UI can show what was imported after the switch. (5) A failure makes the daemon re-inspect at once, so `FIREWALL_GET_MODE` reports `both` right after the error. (6) The recovery command also has to remove `/var/lib/omarchy-security/mode`: while it says `standalone`, the helper loads the table again at its next start (`docs/security.md`). Re-applying temporary decisions after a switch waits for 2.21. The polkit action is in `dist/polkit/org.omarchy.security.policy` (`auth_admin`) and `50-omarchy-security.rules` (`AUTH_ADMIN_KEEP` for a wheel member in an active local session). `docs/security.md` is started with the firewall promises (the hub never fights `ufw` on its own). `docs/ipc-protocol.md` §4.6, `tools/mock-securityd.py` (`FIREWALL_SET_MODE` without a password) and `Protocol.js` (`SETTABLE_FIREWALL_MODES`) are updated. Tests: helper `firewall::tests::{switches_modes_without_a_gap, a_failed_ufw_disable_leaves_both_enforcing, ufw_is_not_touched_before_the_table_is_safe, a_failed_ufw_enable_keeps_the_hub_firewall, only_a_new_inbound_allow_in_standalone_opens_inbound, checks_the_loaded_standalone_table}` (fake `ufw` script in a user namespace) and `server::tests::requires_hello_and_authorization`, daemon `firewall::tests::switches_the_mode_and_imports_ufw_rules_once`, and the wire-format test `set_mode_matches_spec`. (7) The helper unit opens `/etc/ufw` and `/run/ufw.lock` for writing (`ReadWritePaths=`, and an `ExecStartPre=+touch` so the lock exists), because `ProtectSystem=strict` made `ufw disable` fail with "`/etc/ufw/ufw.conf` is not writable". Nothing else `ufw` touches needs it: its temporary files go to the private `/tmp` and are copied into place, `sysctl -p` writes `/proc/sys`, `IPT_MODULES` is empty, and the nf_tables `iptables` takes no xtables lock. **Validated live (2026-09-28), failure branch only:** before that unit fix, the switch to `standalone` failed at `ufw disable`, `FIREWALL_GET_MODE` then reported `both` (our table loaded next to `ufw`), and switching back to `ufw` removed the standalone table. **Validated live (2026-09-28), with the unit fix installed:** the switch to `standalone` imported six rules (LocalSend on UDP and TCP 53317 for IPv4 and IPv6, and the two ufw-docker DNS rules, each with the local-address note) and reported `standalone` with `docker_protection: omarchy`. `ufw status` then said `inactive`, and `nft list table inet omarchy_sec` showed `comment "mode=standalone"`, `policy drop` and the imported rules after the baseline. The switch back reported `ufw` with its chains loaded, and our table was removed. Polkit asked for the password on the first switch and kept it for the next one. After a reboot in `standalone` mode, `omarchy-security-firewall.service` had loaded the table (`mode=standalone`) before login, which also validates that part of 2.18.



### 5.19 (Task 2.20) Blocked-traffic alerts and desktop notifications



* **Sources.** Both `ufw` and our baseline log through the kernel log with the same `key=value` format (`IN= OUT= MAC= SRC= DST= LEN= ... PROTO= SPT= DPT=`). The daemon runs `journalctl -k -f -n 0 -o json --output-fields=MESSAGE,__REALTIME_TIMESTAMP` and keeps lines whose `MESSAGE` starts with `[UFW BLOCK] `, `[UFW LIMIT BLOCK] ` or `[OMSEC BLOCK] `. Wheel members can read the system journal (checked on this machine); without access, the alerts part of the module is `degraded` with a detail, and nothing else fails. Restart `journalctl` with backoff if it exits.
* **What `ufw` does not log.** With `LOGLEVEL=low`, `ufw` logs blocked packets rate-limited to 3 per minute and does not log everything its default policy drops. Say in the UI that alerts in `ufw` mode are a sample. The hub never changes `ufw`'s log level.
* **Parsing.** Direction: `IN` set and `OUT` empty is `inbound`; `OUT` set and `IN` empty is `outbound`; both set is `forward`. Parse addresses with `std::net`, never by string matching. Fuzz the parser (4.5).
* **Noise filter** (configurable, §5.4 `[firewall.alerts]`): ignore multicast and broadcast destinations (`224.0.0.0/4`, `ff00::/8`, `255.255.255.255`) and IGMP (`PROTO=2`) by default. On this machine that removes nearly all 239 lines a day.
* **Aggregation.** Key: source, direction, protocol, remote address, local port. Within `window_secs` (default 600) repeats only increase `count` and `last_seen`. Keep at most 500 alerts in memory, newest first.
* **Desktop notifications.** The daemon sends them itself over the session bus (`org.freedesktop.Notifications.Notify`, zbus), with app name `Omarchy Security`, urgency `normal`, and these actions:
  * `default`: open the hub on the Network tab (through `omarchy-shell` IPC or the plugin's IPC handler, which 3.10 adds);
  * `allow`: "Allow for 1 h" (becomes `FIREWALL_TEMP_ADD`; the polkit prompt appears for an inbound allow);
  * `mute`: "Keep blocking, stop telling me" (`FIREWALL_ALERT_MUTE`, 8 h).

  Listen for `ActionInvoked` and `NotificationClosed`. At most one notification per alert key per window; use `replaces_id` to update it. At most `max_notifications_per_minute` (default 3) in total; beyond that, send one summary notification ("N more connections blocked") that opens the hub. Never use the app name `omarchy-action` or urgency `critical` except for the `none` mode warning, so the user's DND setting is respected; `omarchy-shell` still keeps the notification in its history, and the bar widget (3.2) shows the unread count.
* **Mode warnings.** A change to `both` sends one normal notification; a change to `none` sends one critical notification ("Firewall is off"), with actions "Use UFW" and "Use Security Hub firewall".
* **Held outbound connections are not notifications.** The prompt for an outbound connection held by NFQUEUE (2.13/2.14) is the overlay from 3.6/3.10, because a notification cannot be relied on to be answered before `expires_at`.
* **Semantics to show in the UI.** A blocked packet in an alert was already dropped. "Allow" applies to later packets that match, for the chosen duration.
* **Tests.** Parser tests over real log lines (the IGMP lines above, a TCP SYN to a closed port, an IPv6 line, a `forward` line from Docker). Aggregation and rate-limit tests with a fake clock. Notifications against a fake `org.freedesktop.Notifications` on a private session bus that records calls and can emit `ActionInvoked`.
* **As built (2026-09-29).** `crates/omarchy-securityd/src/alerts.rs` (parser, noise filter, grouping, the `journalctl` follower), `notify.rs` (the rate limit as a pure `Policy`, and the zbus client) and the glue in `firewall.rs` (`start_alerts`, `follow_alerts`, `follow_actions`); `main.rs` connects to the session bus and starts them. How it differs from the spec above: (1) `[OMSEC DOCKER BLOCK] ` lines are read too, as `forward` alerts from source `omarchy`. (2) The grouping key uses the destination port for every direction (for an outbound packet the source port is ephemeral); `[firewall.alerts] ignore` still matches the local port as §5.4 defines it. The window runs from an alert's first packet, so a long stream gives one alert (and at most one notification) per window. Packet times come from the journal's `__REALTIME_TIMESTAMP`. (3) `FIREWALL_ALERT` is also sent when an alert is muted. Mutes apply to the kind of packet, so later alerts of that kind start muted. (4) A notification is updated through `replaces_id` when its count changes (on the same 5 s throttle as the event) until the user closes it; updates do not count against `max_notifications_per_minute`. The summary is replaced as its count grows and starts over a minute after it was first sent. The "Allow for 1 h" action is offered only for TCP and UDP alerts with a port that are not `forward`. A failed action (other than a refused password) is reported in a notification. (5) The `default` action runs `$OMARCHY_PATH/bin/omarchy-shell -q security-hub open network` (`AlertsEnv::open_hub`); the plugin's IPC target `security-hub` with method `open` is for 3.10 to add, and until then the call does nothing. (6) Mode warnings are sent even with `notify = false`; `unknown` sends none, and the warning is closed (`CloseNotification`) once the mode is `ufw` or `standalone` again. (7) Without read access to the kernel log (`journalctl` prints "insufficient permissions" or "not seeing messages"), the module is `degraded` with "blocked-traffic alerts are off: …"; `journalctl` is restarted with backoff (1 s doubling to 60 s) whenever it exits. (8) Alerts need no helper, so `FIREWALL_ALERT_LIST` and `FIREWALL_ALERT_MUTE` work while the module is unavailable. Protocol: `docs/ipc-protocol.md` §4.6 and §5, `tools/mock-securityd.py` (a canned alert every 15 s), `Protocol.js` (`FirewallEvent.ALERT`, `specFromAlert`, `needsPassword`). Tests: `alerts::tests::{parses_real_log_lines, reads_journal_json, filters_noise, groups_repeats_within_the_window, keeps_at_most_500, mutes_a_kind_of_packet, follows_and_restarts_journalctl}`, `notify::tests::{limits_new_notifications_per_minute, describes_alerts, notifies_and_routes_actions}`, `firewall::tests::alerts_are_grouped_notified_and_acted_on` (fake `journalctl`, fake notification server, and the "Allow" action ending in a temporary `ufw` allow), and the wire-format test `firewall_alerts_match_spec`. Run once against the real journal as the desktop user (wheel): the follower starts, and the module is not degraded. **Not validated live yet:** a notification from a real blocked packet, and its actions, which need the new helper installed.



### 5.20 (Task 2.21) Temporary allow and block in both modes



* **Backend choice**, by the daemon, for `FIREWALL_TEMP_ADD`:

  | Mode | Verdict | Direction | Backend |
  |---|---|---|---|
  | `ufw` or `both` | block | any | `table` |
  | `ufw` or `both` | allow | outbound | `table`, or `ufw` if `DEFAULT_OUTPUT_POLICY` is not `ACCEPT` |
  | `ufw` or `both` | allow | inbound | `ufw` |
  | `standalone` | any | any | `table` |
  | `none`, `unknown` | any | any | fails with `MODE_CONFLICT` |

  `duration_secs` is 60 to 86 400. The UI offers 5 min, 1 h and 8 h (configurable).
* **`table` backend.** Render temporary decisions as named sets with kernel timeouts, so they expire even if the daemon and helper die:
  ```
  set tmp_allow_in_v4 { type ipv4_addr . inet_proto . inet_service; flags timeout; }
  set tmp_block_in_v4 { type ipv4_addr . inet_proto . inet_service; flags timeout; }
  ```
  (one set per verdict, direction and family; use `flags interval, timeout` where the spec has a CIDR). They sit at the top of their chains, before `ct state established,related accept`, so a temporary block also cuts an existing connection. Blocks come before allows. Because the helper replaces the whole table, every render includes the live elements with their remaining time (`elements = { 203.0.113.7 . tcp . 22 timeout 3542s }`). The daemon keeps the list in memory with `expires_at`, drops expired entries, and re-sends them on reconnect. Temporary decisions do not survive a reboot, and the boot copy never contains them.
* **`ufw` backend** (helper op `UfwTempRule {op: add|delete, temp_id, spec, verdict, created_at, expires_at}`, polkit `org.omarchy.security.firewall.mode` for an allow, `firewall.manage` for a delete):
  * Build the argv from typed values only: `ufw prepend allow in [on <iface>] proto <tcp|udp> from <cidr|any> to any port <port> comment 'omarchy-security:tmp:<temp_id>:<created_unix>:<expires_unix>'`. `prepend` exists since `ufw` 0.36 (0.36.2 is installed) and works when the list is empty, unlike `insert 1`. Use `ufw insert 1 ...` only if a future `ufw` drops `prepend`.
  * Delete with `ufw delete allow ...` and the same arguments, not by rule number (numbers shift when others edit the list).
  * **Expiry.** The helper sweeps every 30 s and at startup: it parses the tuples in `user.rules`/`user6.rules`, decodes the comment, and deletes every tagged rule whose `expires_unix` has passed, or whose `created_unix` is before the current boot (from `btime` in `/proc/stat`). The expiry is in the rule itself, so a crash cannot leave an allow in place forever. `FIREWALL_UFW_RULES` shows these rules with `temp_id` and `expires_at`.
  * `ufw` takes about a second per call. Run it off the async runtime (`spawn_blocking`) and serialize the calls.
* **From alerts and prompts.** A notification's `allow` action and the alert list's buttons build the spec from the alert: for an inbound alert, protocol and local port, and the remote address as a single host. The UI can widen it to "any source" in the alert list, never in the notification.
* **Permanent decisions.** In `ufw` mode the hub does not add permanent `ufw` rules (the owner asked for `ufw`'s rules to be shown, not edited). "Always" for an inbound allow fails with `MODE_CONFLICT`, and the UI explains the choice: use `ufw allow` yourself, or switch to the Security Hub firewall. Permanent outbound rules and executable rules (2.14) keep working in our table in both modes.
* **Tests.** Backend selection over every row of the table. In `unshare -rn`: a set element with a 2 s timeout blocks, then expires without any call. The `ufw` argv builder with a fake `ufw` (recorded argv, including a rejected CIDR and a port out of range). The sweep with a fake `user.rules` containing expired, live, pre-boot and untagged rules.
* **As built (2026-09-29).** Daemon: `temp_backend`, `temp_add`/`temp_list`/`temp_remove`, `rebalance_temps` and the expiry loop `follow_temps` in `crates/omarchy-securityd/src/firewall.rs`. Helper: `render_with`, `set_temp`, `ufw_temp`, `ufw_temp_args` and `sweep_ufw` in `crates/omarchy-security-helper/src/firewall.rs`, the ops in `server.rs`, and the 30 s sweep in `main.rs` (only when `/usr/bin/ufw` exists). The tuple parser moved to `omarchy_security_proto::ufw`, shared by both, with the tag helpers and `temp_decision`. How it differs from the spec above: (1) The verdict is part of `spec` (a `FirewallRuleSpec` has one); `FIREWALL_TEMP_ADD` is `{spec, duration_secs, alert_id?}` and a separate `verdict` is an unknown field. `TempDecision` has no top-level `verdict` for the same reason, and carries `alert_id?`. `spec` may not have an `executable`, and a `port` needs a `protocol` (port 0 is refused). (2) Each decision is its own named set (`tmp_<temp_id>`) with one element, and its own rule (comment `omarchy:tmp:<temp_id>`), instead of one set per verdict, direction and family: nft refuses overlapping intervals in one set, and two decisions may overlap. `flags interval` is set only for a prefix. A decision with less than a second left is not rendered. In `ufw` mode the decisions alone keep the table. (3) Helper ops `firewall_temp_set {decisions}` (replaces the table decisions; polkit `firewall.manage`, plus `firewall.mode` for a new inbound allow) and `ufw_temp {change: add|delete, decision}` (`firewall.mode` for adding any allow, `firewall.manage` otherwise); `firewall_inspect` also returns `temp`. They share helper protocol version 2. The helper now answers a request it cannot parse (such as an op an older helper does not know) with the request's `id`, so the daemon gets an error at once instead of a timeout. (4) The ufw argv also supports outbound (`prepend allow out from any to <addr>`), blocks (`deny`), and no port or no protocol; the address is the masked prefix. `ufw` calls are serialized with a lock in the helper (mode switches included) and run on the async runtime with the existing 60 s timeout. (5) A new decision for the same spec replaces the earlier one. (6) Takeover after a daemon restart: the daemon reads the tagged rules from `user.rules` at startup and the helper's table decisions from each `firewall_inspect`; `temp_id`s start at the current time in ms, so they do not collide. After a helper restart the daemon re-sends the table decisions. (7) After a mode switch, decisions are moved to the backend the new mode needs (an inbound allow becomes a `ufw` rule when `ufw` comes back, and a table element when it goes); a move that fails is logged and the decision stays where it was. Protocol: `docs/ipc-protocol.md` §4.6 and §5, `docs/security.md`, `tools/mock-securityd.py`, `Protocol.js`. Tests: helper `firewall::tests::{renders_temporary_decisions, nft_accepts_temporary_sets, temporary_decisions_expire_in_the_kernel, temporary_decisions_survive_other_changes, builds_ufw_argv_from_typed_values, ufw_temp_rules_are_added_and_swept}` (golden files `testdata/standalone-temp.nft` and `ufw-temp.nft`; the expiry test connects over loopback in `unshare -rn` while a 2 s block lasts and after it) and `server::tests::requires_hello_and_authorization`; daemon `firewall::tests::{temp_backend_follows_the_mode, builds_specs_from_alerts, temporary_decisions_follow_the_mode, takes_over_decisions_a_previous_daemon_left}`; proto `ufw::tests::reads_temporary_rules_back`; wire-format `temporary_decisions_match_spec`. **Open for 3.10:** clients cannot read `temp_durations_secs` yet; the UI needs it served (for example as a field of `FIREWALL_TEMP_LIST`). **Needs the user (sudo) to validate live:** `make release && sudo make install && sudo systemctl restart omarchy-securityd-helper.service`, then `systemctl --user restart omarchy-securityd.service`, and with `ufw` active: `tools/secctl.py call FIREWALL_TEMP_ADD '{"spec":{"verdict":"allow","direction":"inbound","address":"<another host>","port":22,"protocol":"tcp"},"duration_secs":60}'` should ask for the password and add a rule to `sudo ufw status numbered` with the `omarchy-security:tmp:` comment, which is gone about a minute later; the same with `"verdict":"block"` should add `set tmp_<id>` to `sudo nft list table inet omarchy_sec` without a password.



### 5.21 (Task 3.10) Firewall UI: mode, rules, alerts and decisions



* **Where things appear, in the Omarchy way:**
  * **Bar** (`StatusBarIndicator.qml`, 3.2): a shield whose state follows the mode (normal for `ufw` and `standalone`, warning for `both`, critical for `none`, dim for `unknown`), and a badge with the number of unseen alerts. Clicking it opens the hub on the Network tab.
  * **Desktop notifications**: sent by the daemon (§5.19), shown by `omarchy-shell`, so they follow the user's DND setting and stay in its history.
  * **Overlay** (`components/ConnectionPrompt.qml`): only for outbound connections held by NFQUEUE (3.6 second part), with the countdown to `expires_at`.
  * **Hub, Network tab** (`NetworkSnitch.qml`, 3.6): everything below.
* **Mode banner**, always at the top of the Network tab:
  * `ufw`: "UFW is active. It filters every packet alongside the Security Hub, and the hub cannot open ports UFW blocks. The rules below are UFW's and are read-only here. Temporary allow and block still work." Button: "Use Security Hub firewall instead".
  * `standalone`: "The Security Hub firewall protects this machine. UFW is off." Button: "Hand back to UFW".
  * `both`: warning: "UFW and the Security Hub firewall are both enforcing. Traffic must pass both." Buttons: "Use UFW", "Use Security Hub firewall".
  * `none`: critical: "No firewall is active." Same two buttons.
  * `unknown`: "Cannot read the firewall state: the privileged helper is not running."
* **Mode switch dialog.** It lists what will change, the `ufw` rules that will be imported and those that cannot be (§5.17), the Docker note, that a password is needed, and the recovery command from §5.18. The switch needs a second confirmation (a hold or a second click, as for Panic in 3.7).
* **Rules section.** In `ufw` mode: the `ufw` rules table (read-only; hub-added temporary rules marked with a countdown and a "Revoke" button), the built-in summary, and the saved hub rules in a collapsed "Inactive while UFW is on" group. In `standalone` mode: the editable hub rule list (3.6 first part), plus the baseline shown as fixed rows. In `both`: both lists.
* **Alerts section.** `FIREWALL_ALERT` rows (direction, remote address, port, count, last seen), newest first, with "Allow for…" and "Block for…" (durations from the configuration), and "Mute". Mark buttons that will ask for a password. In `ufw` mode, a note that UFW alerts are a sample (§5.19).
* **Temporary decisions section.** `FIREWALL_TEMP_LIST` with the backend, a countdown and "Revoke".
* **Plugin IPC.** Add an IPC handler to the plugin so the daemon's notification action (and a keybinding) can open the hub on a tab: `omarchy-shell` plugin IPC, following the pattern in `/usr/share/omarchy/shell/plugins/README.md`.
* **Mock.** `tools/mock-securityd.py` gains a scenario per mode, a stream of alerts, and the `MODE_CONFLICT` and `PERMISSION_DENIED` paths. Add the view states to `tests/e2e/shell.qml`.


---

Aquí tienes la traducción completa al inglés en el mismo formato Markdown:

```markdown
# Omarchy 4 Security Hub: Technical Specifications and Implementation Plan

This document details the architecture, component specifications, and step-by-step implementation plan for the development of the **Security Hub** in **Omarchy 4** (Hyprland + QuickShell).

The project is divided into a decoupled architecture: a high-performance **Rust Backend Daemon** with controlled privileges and a **QuickShell Frontend Interface (QML/JS)** for real-time control from the compositor.

---

## 1. Overall System Architecture

The communication flow follows the **asynchronous IPC pattern (D-Bus / Unix Domain Socket)** using JSON/Protobuf message passing, ensuring that shell interface performance is not affected by system inspection operations.


```

┌───────────────────────────────────────────────────────────────────────────────────┐
│                          QuickShell Frontend (QML)                                │
│  ┌──────────────────┬──────────────────┬──────────────┬─────────────┬──────────┐  │
│  │ Threat Monitor   │ Credential/HSM   │ Network FW   │ Hardening   │ USBGuard │  │
│  │ (eBPF Alerts)    │ (YubiKey OSD)    │ (OpenSnitch) │ Audit Checklist │ Control│  │
│  └─────────┬────────┴────────┬─────────┴──────┬───────┴──────┬──────┴────┬─────┘  │
│            │                 │                │              │           │        │
│            └─────────────────┼────────────────┼──────────────┼───────────┘        │
│                              │ Theme Provider (Omarchy Color Palette/Style)       │
└──────────────────────────────┼────────────────────────────────────────────────────┘
│ IPC (Unix Socket / Private D-Bus)
┌──────────────────────────────┴────────────────────────────────────────────────────┐
│                    `omarchy-securityd` (Rust Daemon)                              │
│  ┌──────────────────┬──────────────────┬──────────────┬─────────────┬──────────┐  │
│  │ Module: eBPF     │ Module: PC/SC    │ Module:      │ Module:     │ Module:  │  │
│  │ (aya-rs / exec)  │ & FIDO2 (udev)   │ nftables     │ Sys-Audit   │ USBGuard │  │
│  └─────────┬────────┴────────┬─────────┴──────┬───────┴──────┬──────┴────┬─────┘  │
└────────────┼─────────────────┼────────────────┼──────────────┼───────────┘        │
│                 │                │              │           │        │
┌────────────▼─────────────────▼────────────────▼──────────────▼───────────▼────────┐
│                            Linux Kernel & Daemons                                 │
│   [eBPF tracepoints]    [USB / Smartcard]   [nftables]    [Sys-State]   [USBGuard] │
└───────────────────────────────────────────────────────────────────────────────────┘

```

---

## 2. Technical Detail of Backend Components (`omarchy-securityd`)

The `omarchy-securityd` service is developed in **Rust** using `tokio` as an asynchronous runtime. It runs as a systemd user service (`systemctl --user`), invoking a helper with limited Linux capabilities (`CAP_NET_ADMIN`, `CAP_BPF`, `CAP_SYS_PTRACE`) to avoid running the entire daemon as `root`.

### 2.1 Module 1: Threat Detection and Response (eBPF & Inotify)

* **Rust Library:** `aya` (for native loading and management of eBPF programs in Rust).
* **Mechanism:**
  * Attaches an eBPF probe to the `sys_enter_execve` tracepoint.
  * Filters binary executions in `/tmp`, `/var/tmp`, `/dev/shm`, or anonymous memory descriptors (`memfd_create`).
  * Emits a real-time event with the `PID`, `PPID`, `UID`, `binary_path`, and executed arguments to the IPC socket.
* **Active Response:** Exposes the IPC methods `KillProcess(pid: u32, signal: u32)` and `QuarantineProcess(pid: u32)` (sends `SIGSTOP`).

### 2.2 Module 2: Credentials and HSM / Cryptography Modules

* **Mechanisms:**
  * **PC/SC & USB Monitoring:** Uses `libudev-sys` to detect insertion and removal of security tokens (YubiKey, SoloKeys).
  * **FIDO2 / SSH Prompt Interception:** Listens for requests by monitoring events in the `pcscd` API or reading `ssh-agent` / `gpg-agent` traces via local sockets.
* **Encrypted Volume Control:**
  * Integrates direct calls to `cryptsetup` (via `libcryptsetup-rs`) or `gocryptfs` to mount/unmount secure containers.
  * **Panic Mode (*Emergency Unmount*):** Closes open file descriptors, unmounts encrypted folders, and forces a buffer flush (`sync`).

### 2.3 Module 3: Network Security and Isolation (Firewall & Sandbox)

* **`nftables` Controller:**
  * Interacts with the native `mnl` / `nftables` library to manage a dedicated table in netfilter: `table inet omarchy_sec`.
  * Maintains dynamic sets of blocked or authorized IPs and ports per process.
* **Sandbox Invoker (Bubblewrap Wrapper):**
  * Provides a dynamic `bwrap` profile generator.
  * Constructs the isolation command:
    ```bash
    bwrap --unshare-all --share-net --ro-bind / / --tmpfs /tmp --tmpfs /home/$USER \
          --bind $TARGET_FILE $TARGET_FILE --proc /proc --dev /dev $EXECUTABLE
    ```

### 2.4 Module 4: Security Posture and Audit (System Audit)

* **Configuration Evaluator:** A background state analyzer that evaluates every 30 seconds:
  * Reads `/sys/fs/selinux/enforce` or `/sys/kernel/security/apparmor/profiles`.
  * Checks `sysctl kernel.yama.ptrace_scope` (must be `>= 1`).
  * Checks the `/etc/group` file to validate if the current user belongs to the `docker` group (critical risk alert).
  * Checks `/proc/swaps` to ensure swap areas are encrypted.

### 2.5 Module 5: USBGuard Device Management

* **Mechanisms:**
  * Connects via D-Bus to `org.isis.USBGuard` (or native USBGuard IPC socket).
  * Listens for `presenceChanged` and `devicePolicyChanged` signals.
  * Queries the current list of connected devices and their policies (`listDevices`).
* **IPC-Exposed Actions:**
  * `AuthorizeUSBDevice(id: u32, permanent: bool)`: Allows peripheral connection (optionally saves rule in `/etc/usbguard/rules.conf`).
  * `BlockUSBDevice(id: u32)`: Instantly blocks or rejects the USB peripheral.
  * `RejectUSBDevice(id: u32)`: Removes logical access to the USB port.

---

## 3. QuickShell Interface Specification & Visual Integration (UI)

### 3.1 Thematic Consistency with Omarchy

Any visual component generated by the plugin (bar widgets, floating panels, modals, and OSDs) **must strictly use Omarchy's global style variables**.

* **Style Injection:** Binds to the Omarchy color/style module (via `Omarchy.Theme` or the global config import in QuickShell).
* **Properties to Synchronize:**
  * `background`: Background color of panels (respecting user-configured transparency/blur).
  * `foreground` / `text`: Main text color.
  * `accent`: Accent color for buttons, switches, and status charts.
  * `danger` / `warning` / `success`: Semantic colors to indicate threats (blocked process, rejected USB, hardening OK).
  * `border.radius` / `border.color`: Borders and radii adapted to the user's theme.

### 3.2 Plugin Structure (`plugins/security_hub/`)


```

plugins/security_hub/
├── qmldir
├── SecurityHub.qml           # Main panel (Popup / Window overlay)
├── StatusBarIndicator.qml    # Omarchy status bar widget
├── components/
│   ├── ThreatAlertOSD.qml    # eBPF pop-up notification
│   ├── YubiKeyPrompt.qml     # Modal overlay for physical presence
│   ├── NetworkSnitch.qml     # Firewall pop-up selector
│   ├── HardeningSem.qml      # Security audit status indicator
│   └── USBGuardPanel.qml     # Visual management of USB devices
└── services/
├── SecurityIPC.qml       # WebSocket / Unix Domain Socket client
└── ThemeProvider.qml     # Dynamic binding to Omarchy color scheme

```

### 3.3 IPC Communication Protocol (JSON-RPC Example)

#### Event: USB Device Blocked by USBGuard (`Daemon -> Shell`)
```json
{
  "event": "USB_DEVICE_PRESENTED",
  "payload": {
    "device_id": 14,
    "name": "Mass Storage Device",
    "vendor_id": "0951",
    "product_id": "1666",
    "serial": "00187D0F2E3B",
    "rule": "block",
    "interface_class": "08"
  }
}

```

#### Action: Manual USB Approval by User (`Shell -> Daemon`)

```json
{
  "action": "USBGUARD_SET_POLICY",
  "payload": {
    "device_id": 14,
    "target": "allow",
    "permanent": true
  }
}

```

---

## 4. Full Task Breakdown (Development Checklist)

Compact copy. The full checklist, the ordering rules and the task specifications (§5) are in the first copy of this document.


### Phase 1: Base Architecture and Development Environment

* [x] **1.1** Create Git repository structure and configure licenses (`GPL-3.0` / `MIT`).
* [x] **1.2** Set up Rust build environment for `omarchy-securityd` (`Cargo.toml`, dependencies `tokio`, `serde`, `aya`, `zbus`).
* [x] **1.3** Define IPC protocol specification (JSON-RPC messages over Unix Domain Socket).
* [x] **1.4** Create base plugin template in QuickShell (`qmldir`, `SecurityHub.qml`).
* [x] **1.5** **[needs the user: sudo]** Install the system packages that the build, the test suite and every module need (`usbguard`, `nftables`, `bubblewrap`, `pcsclite`/`ccid`, `libfido2`, `udisks2`/`cryptsetup`, `gocryptfs`/`fuse3`, `pinentry`), plus the eBPF toolchain. Install `usbguard` but **do not enable it** yet (see 2.9). Spec: §5.1.

### Phase 2: Backend Daemon Development (`omarchy-securityd`)

* [x] **2.1** Implement Unix Domain Socket server in Rust for IPC client management.
* [x] **2.2** Implement **eBPF Module** (`aya-rs`) to capture executions in `/tmp` and suspicious directories.
* [x] **2.3** Implement **USBGuard Module** via D-Bus/IPC integration (`USBGuard` API) to list, authorize, and reject devices.
* [x] **2.4** Implement **HSM/YubiKey Module** listening for `udev` events and security touch prompts.
* [x] **2.5** Implement **Network Module** integrating dynamic rules into `nftables`.
* [x] **2.6** Implement **Posture Audit Module** (checking SELinux/AppArmor, `docker` groups, `ptrace`).
* [x] **2.7** Write Systemd service file (`omarchy-securityd.service`) and Polkit rules for execution without unnecessary elevated privileges.
* [x] **2.8** **[needs the user: sudo]** Install the daemon, helper, eBPF object, units and polkit files on the live system. Validate the privileged paths that no unprivileged test covers: that the eBPF monitor attaches under the unit's hardening, that the real nft table works alongside Omarchy's `ufw`, cross-user signalling, and password-less polkit for wheel. Add the small CLI client `tools/secctl.py` that this task and later ones use to drive the socket. Spec: §5.2.
* [x] **2.9** **[needs the user: sudo]** Configure and enable USBGuard safely (generate the allow-list first, then enable `usbguard` and `usbguard-dbus`). Validate the USBGuard module against the real service, including `permanent: true`. Spec: §5.3.
* [x] **2.10** Add the daemon configuration file (`$XDG_CONFIG_HOME/omarchy-security/config.toml`), which vault definitions and firewall-prompt settings need. Spec: §5.4.
* [x] **2.11** Implement the **Encrypted Vault Module** (plan §2.2): `VAULT_LIST`, `VAULT_MOUNT` and `VAULT_UNMOUNT` for LUKS containers (through udisks2) and `gocryptfs`. The passphrase comes from `pinentry` and never crosses the client socket. Spec: §5.5.
* [x] **2.12** Implement **Panic Mode** (`VAULT_PANIC`, plan §2.2). It stops processes holding files open in the vaults, flushes buffers, unmounts and locks every vault, and can be run from a keybinding even when the shell is unresponsive. Spec: §5.6.
* [x] **2.13** Implement connection interception in the privileged helper (NFQUEUE on new outbound connections from the desktop user). It maps each connection to a process and executable, which the "per process" sets of plan §2.3 and the OpenSnitch-style prompts need. Spec: §5.7.
* [x] **2.14** Implement executable-scoped firewall rules and interactive prompts in the daemon: `executable` in `FirewallRuleSpec`, `FIREWALL_CONNECTION_PROMPT`, `FIREWALL_DECIDE` with `once`/`process`/`always`. Both return `NOT_IMPLEMENTED` today. Spec: §5.8.
* [x] **2.15** Detect touch prompts for OpenPGP cards (source `gpg`, from gpg-agent/scdaemon), so the YubiKey prompt also covers GPG signing and decryption (plan §2.2). Spec: §5.9.
* [x] **2.16** Add the **Inotify** half of Module 1 (plan §2.1 title): report executable files dropped into `/tmp`, `/var/tmp` or `/dev/shm` before they run. Low priority. Spec: §5.10. Tasks 2.17–2.21 do not depend on it.
* [x] **2.17** Detect `ufw` and the firewall mode (`ufw`, `standalone`, `both`, `none`, `unknown`), and serve `ufw`'s rules read-only (`FIREWALL_GET_MODE`, `FIREWALL_UFW_RULES`, `FIREWALL_MODE_CHANGED`). Needs 2.8. Spec: §5.15, §5.16.
* [x] **2.18** Add the standalone baseline policy (default-deny inbound, matching what Omarchy's `ufw` allows, including Docker protection) and the boot copy of the ruleset with `omarchy-security-firewall.service`, so the machine is protected before login when `ufw` is off. Needs 2.17. Spec: §5.17.
* [x] **2.19** Let the user turn `ufw` off and on from the hub (`FIREWALL_SET_MODE`), in an order that never leaves the machine without a firewall, with the new polkit action `org.omarchy.security.firewall.mode` (password, kept). Validating it on the live system is **[needs the user: sudo]**. Needs 2.18. Spec: §5.18.
* [x] **2.20** Report blocked traffic from `ufw` and from our baseline (kernel log), filtered, grouped and rate-limited, as `FIREWALL_ALERT` events and as `omarchy-shell` desktop notifications with actions (the "Allow for 1 h" action is wired up in 2.21). Needs 2.17 and 2.10. Spec: §5.19.
* [x] **2.21** Add temporary allow and block decisions that work in both modes (`FIREWALL_TEMP_*`): kernel-expiring sets in our table, or tagged, self-expiring `ufw` rules for inbound allows while `ufw` is on. Needs 2.19 and 2.20. Spec: §5.20.

### Phase 3: Visual Integration and QuickShell Theme

* [x] **3.1** Create `ThemeProvider.qml` to dynamically consume colors and styles from the current Omarchy theme.
* [x] **3.2** Design and implement `StatusBarIndicator.qml` widget for the main Omarchy bar. It also shows the firewall mode and a badge with unseen firewall alerts (§5.21).
* [x] **3.3** Design and implement `USBGuardPanel.qml` visual panel (list of connected USB devices, "Approve", "Reject", "Save Permanent" buttons).
* [x] **3.4** Design and implement threat OSD modal (`ThreatAlertOSD.qml`) with response actions ("Kill Process", "Isolate").
* [x] **3.5** Design and implement `YubiKeyPrompt.qml` component for physical presence authentication alerts.
* [x] **3.6** Design and implement `NetworkSnitch.qml` visual module and the audit status indicator view (`HardeningSem.qml`). `NetworkSnitch` has two parts. Its rule list (list/add/remove) can be built now. Its connection prompt (Allow/Block × Once/This process/Always, with a countdown to `expires_at`) needs 2.14. It is mode-aware: see 3.10.
* [x] **3.7** Design and implement `components/VaultPanel.qml`: the vault list with mount state, Mount/Unmount, and a Panic button that asks for confirmation. Needs 2.11 and 2.12. Spec: §5.11.
* [x] **3.8** Design and implement `components/TokenPanel.qml` (connected tokens and their capabilities, from `TOKEN_LIST` and `TOKEN_*` events) and `components/SandboxLauncher.qml` (pick an executable and an optional target file, toggle network, then `SANDBOX_RUN`). No view in the plan's tree covers either module. Spec: §5.11.
* [x] **3.9** Replace the Phase 1 module list in `SecurityHub.qml` with a tabbed hub (Overview, Threats, USB, Tokens, Network, Vaults, Hardening). The Overview shows alert history and module states. Add every new file to `qmldir`. Spec: §5.11.
* [x] **3.10** Make the Network tab mode-aware: the `ufw` banner and conflict warnings, the mode switch with confirmation, `ufw`'s rules read-only in `ufw` mode and the hub's rules editable in `standalone` mode, the alert list, and temporary Allow/Block/Mute with countdowns and Revoke, in both modes. Add the plugin IPC handler that notification actions use to open the hub. Needs 2.17–2.21 (use the mock before that). Spec: §5.21.

### Phase 4: Testing, Validation, and Documentation

* [x] **4.1** Perform integration testing for low impact on memory/CPU consumption (< 2% CPU, < 40MB RAM daemon).
* [x] **4.2** Test real-time theme switching in Omarchy to verify dynamic UI adaptation.
* [x] **4.3** Write installation manual, dependency setup (`usbguard`, `nftables`, `aya-bpf`), and usage guide in `README.md`. It must cover the packages from §5.1, the USBGuard procedure and recovery from §5.3, the vault configuration from §5.4, the firewall modes and what switching does (§5.15), and how to get out of the hub (uninstall, disabling USBGuard, and handing the firewall back to `ufw` with the recovery command in §5.18).
* [ ] **4.4** **[needs the user: sudo]** Run a full end-to-end pass on a real Omarchy install, or on a disposable VM of one, covering every module, including those added in 2.11–2.21, and the firewall in both modes. Turn §5.2's manual checks into `tools/system-check.sh`, which is read-only and prints PASS/FAIL per check, so the pass can be repeated after every release. Spec: §5.12.
* [x] **4.5** Review the security of the privilege boundary and add fuzz tests for the parsers that read untrusted input, including the kernel-log and `ufw` tuple parsers. Spec: §5.13.

### Phase 5: Release and Distribution

* [ ] **5.1** Set up GitHub Actions (CI/CD) for automated Rust binary compilation and QML syntax validation. Run it in an `archlinux` container so the eBPF build finds the same LLVM major version as the pinned nightly (see `crates/omarchy-security-ebpf/rust-toolchain.toml`). Build `make ebpf`, run `make lint test`, and keep the tests that skip themselves when a tool is missing running, by installing `dbus`, `nftables`, `bubblewrap` and `util-linux` in the container.
* [ ] **5.2** Publish first semantic Release (`v1.0.0`) on GitHub with compiled binaries and plugin packaging.
* [ ] **5.3** Submit or publish the plugin to the Omarchy community plugin index / catalog.
* [ ] **5.4** Write an Arch `PKGBUILD` (AUR `omarchy-security-hub`) with the dependencies from §5.1. Its install script must never enable or start `usbguard` on its own, and never switch the firewall mode or touch `ufw`. Spec: §5.14.

```