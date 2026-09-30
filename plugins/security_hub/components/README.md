Module views, added in Phase 3:

- `ThreatAlertOSD.qml` (3.4, built): suspicious-execution card with Kill
  process / Isolate / Resume / It's safe / Later. Its rules are in
  `../services/Threat.js`; the alert list lives in `SecurityIPC`, which
  also loads this component, so it shows while the hub is closed.
- `YubiKeyPrompt.qml` (3.5, built): prompt while a security key waits for
  a touch, visual only (no clicks, no keyboard). Its rules are in
  `../services/Touch.js`; tokens and touch requests live in `SecurityIPC`,
  which also loads this component.
- `NetworkSnitch.qml` (3.6 and 3.10, built): the Network tab, by firewall
  mode: the views below, shown as the mode needs (`Network.sections`).
- `FirewallModeBanner.qml` (3.10, built): which firewall protects the
  machine, and the switch dialog (dry-run import list, Docker note,
  password, recovery command; a second click sends).
- `UfwRules.qml` (3.10, built): UFW's rules, read-only, its built-in
  rules folded, and the hub's temporary UFW rules with countdown and Revoke.
- `HubRules.qml` (3.6, built; 3.10 folds inactive rules and adds the
  baseline): the hub's saved firewall rules, with Remove and an Add rule form.
- `FirewallAlerts.qml` (3.10, built): blocked traffic with Allow / Block for
  a picked duration, Any source, and Mute.
- `TempDecisions.qml` (3.10, built): temporary decisions with backend,
  countdown and Revoke (a second click).

  The Network views' rules are in `../services/Network.js`; the rules,
  UFW's rules, alerts, decisions and mode live in `SecurityIPC`.
- `ConnectionPrompt.qml` (3.6, built): card for an outbound connection the
  firewall holds, Allow / Block × Once / This process / Always, with a
  countdown. Its rules are in `../services/Network.js`; the prompts live in
  `SecurityIPC`, which also loads this component.
- `HardeningSem.qml` (3.6, built): the posture audit as a traffic light,
  with Check now. Its rules are in `../services/Posture.js`; the report
  lives in `SecurityIPC`.
- `USBGuardPanel.qml` (3.3, built): USB devices with Approve / Save permanent /
  Block / Reject. Its rules are in `../services/Usb.js`; the device list
  lives in `SecurityIPC`.
- `VaultPanel.qml` (3.7, built): encrypted vaults with Mount / Unmount and
  Panic (second click). The daemon asks for passphrases with pinentry; this
  view never does. Its rules are in `../services/Vault.js`; the vault list
  and the mounts in progress live in `SecurityIPC`.
- `TokenPanel.qml` (3.8, built): security keys plugged in, with their kind,
  USB id, serial and capabilities, and how the last touch request went.
  Read only. Its rules are in `../services/Token.js`; the tokens and touch
  requests live in `SecurityIPC`.
- `SandboxLauncher.qml` (3.8, built): a program, an optional file for it
  to open, and a network toggle, then `SANDBOX_RUN`. Paths are checked
  for being absolute here, and for everything else by the daemon. Its
  rules are in `../services/Sandbox.js`; the launches live in `SecurityIPC`.
- `HubView.qml` (3.9, built): the tabbed hub SecurityHub.qml puts in its
  window: a row of tabs with a count or dot where something waits, and
  the view of the tab selected. Every view stays loaded while hidden. Its
  rules are in `../services/Hub.js`.
- `Overview.qml` (3.9, built): module states and the latest threat and
  blocked-traffic alerts, each row opening its tab.
- `ThreatList.qml` (3.9, built): the Threats tab, every threat alert of
  this session newest first, with the OSD's answers (a second click
  sends). Its rules are in `../services/Threat.js`.

`qmldir` lists every view: it replaces the directory's implicit import,
so a view left out of it cannot be found (`tests/hub.test.js` checks).
