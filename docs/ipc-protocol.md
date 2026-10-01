<!-- SPDX-License-Identifier: MIT -->

# Security Hub IPC protocol, version 1

This is the contract between `omarchy-securityd` and its clients, chiefly
the QuickShell plugin in `plugins/security_hub/`. The Rust types in
`crates/omarchy-security-proto` implement this document. Its tests
(`tests/wire_format.rs`) check the examples below.

## 1. Transport

| Property   | Value |
|------------|-------|
| Socket     | Unix domain stream socket at `$XDG_RUNTIME_DIR/omarchy-security/securityd.sock` |
| Override   | `$OMARCHY_SECURITYD_SOCKET`, or `omarchy-securityd --socket PATH` |
| Framing    | NDJSON: one compact JSON object per line, terminated by `\n` (UTF-8) |
| Max frame  | 65 536 bytes, not counting the newline. A longer line closes the connection. |
| Envelope   | [JSON-RPC 2.0](https://www.jsonrpc.org/specification), with no batches and no client notifications |

The daemon creates the socket directory with mode `0700` and the socket
with mode `0600`. It checks every connection's `SO_PEERCRED` and drops any
peer whose UID is not the daemon's own. The daemon runs as a systemd user
service. The privileged helper it drives never listens on this socket.

NDJSON was chosen over length-prefixed frames because QuickShell's `Socket`
and `SplitParser` read it natively, and `socat` can debug it by hand:

```sh
socat - UNIX-CONNECT:$XDG_RUNTIME_DIR/omarchy-security/securityd.sock
{"jsonrpc":"2.0","id":1,"method":"HELLO","params":{"protocol_version":1,"client":"socat"}}
```

## 2. Message shapes

The technical plan's `{"action": …, "payload": …}` and
`{"event": …, "payload": …}` examples map to JSON-RPC as follows.

**Request** (client → daemon). `action` becomes `method` and `payload`
becomes `params`. `id` is required, and an integer that increases for each
request is recommended:

```json
{"jsonrpc":"2.0","id":7,"method":"USBGUARD_SET_POLICY","params":{"device_id":14,"target":"allow","permanent":true}}
```

**Response** (daemon → client). Each response carries exactly one of
`result` or `error`, and its `id` matches the request's. `id` is `null`
only when the request's id could not be read.

```json
{"jsonrpc":"2.0","id":7,"result":{"device_id":14,"name":"Mass Storage Device","vendor_id":"0951","product_id":"1666","serial":"00187D0F2E3B","rule":"allow","interface_class":"08"}}
{"jsonrpc":"2.0","id":8,"error":{"code":-32003,"message":"no USB device with id 99"}}
```

**Event** (daemon → client). An event is a JSON-RPC notification with no
`id`. `event` becomes `method` and `payload` becomes `params`:

```json
{"jsonrpc":"2.0","method":"USB_DEVICE_PRESENTED","params":{"device_id":14,"name":"Mass Storage Device","vendor_id":"0951","product_id":"1666","serial":"00187D0F2E3B","rule":"block","interface_class":"08"}}
```

A client tells the three apart by their members. A message with `id` and
`result` or `error` is a response. A message with `method` and no `id` is
an event.

**Conventions**

* Names: methods and events are `UPPER_SNAKE_CASE`, and fields and enum
  values are `snake_case`.
* Timestamps: Unix epoch milliseconds (`u64`).
* `params` rules: a method without params accepts `params` omitted, `null`,
  or `{}`. A method's params must be an object, never an array. Unknown
  param fields are rejected with `INVALID_PARAMS`.
* Clients ignore unknown fields in results and events, so a daemon can add
  fields without bumping the protocol version.
* Daemon-issued ids (`alert_id`, `rule_id`, `request_id`) are valid only
  for the life of the daemon process. After reconnecting, a client lists
  them again.

## 3. Session lifecycle

1. The client connects and sends `HELLO`. Any other method sent before
   `HELLO` fails with `HANDSHAKE_REQUIRED`.
2. The daemon answers with its protocol version and module states. A client
   that asks for a version the daemon does not speak receives
   `UNSUPPORTED_PROTOCOL_VERSION`, and the connection stays open so the
   client can report the mismatch.
3. The client sends `SUBSCRIBE` with the topics it wants. No events flow
   until it does, so one-shot tools such as CLI queries stay quiet.
4. Requests may be pipelined. Responses can arrive out of order and
   interleaved with events, so clients correlate them by `id`. The daemon
   serves at most 32 requests per connection at once and reads the rest
   as those finish.
5. After a disconnect, the client reconnects with backoff and restarts at
   step 1. The daemon disconnects a client that falls more than 256
   events behind, rather than dropping events silently.

## 4. Methods

In the tables below, *params* and *result* name the types in
`omarchy-security-proto`, where every field is documented. `—` means no
params, and `{}` means an empty result object.

### 4.1 Session

| Method | Params | Result |
|---|---|---|
| `HELLO` | `{protocol_version: u32, client: string}` | `{protocol_version, daemon_version, modules: ModuleStatus[]}` |
| `PING` | — | `{}` |
| `GET_STATUS` | — | `{protocol_version, daemon_version, uptime_secs, modules: ModuleStatus[]}` |
| `SUBSCRIBE` | `{topics: Topic[]}` | `{topics: Topic[]}` |

`SUBSCRIBE` replaces the connection's topic set rather than adding to it.
Topics: `system`, `threat`, `usbguard`, `token`, `vault`, `firewall`,
`posture`.

A `ModuleStatus` is `{module, state, detail?}`. `module` is one of
`threat`, `usbguard`, `token`, `vault`, `firewall`, `sandbox`, `posture`.
`state` is one of `active`, `degraded`, `unavailable`, `not_implemented`.
A method whose module is not `active` or `degraded` fails with
`MODULE_UNAVAILABLE` or `NOT_IMPLEMENTED`.

### 4.2 Threat detection (eBPF)

| Method | Params | Result |
|---|---|---|
| `THREAT_LIST_ALERTS` | — | `{alerts: ThreatAlert[]}` |
| `THREAT_KILL_PROCESS` | `{alert_id, pid, signal: 15 \| 9}` | `ThreatAlert` |
| `THREAT_QUARANTINE_PROCESS` | `{alert_id, pid}` | `ThreatAlert` (sends `SIGSTOP`) |
| `THREAT_RESUME_PROCESS` | `{alert_id, pid}` | `ThreatAlert` (sends `SIGCONT`) |
| `THREAT_DISMISS_ALERT` | `{alert_id, pid}` | `ThreatAlert` |

`ThreatAlert` fields: `alert_id`, `pid`, `ppid`, `uid`, `start_time`,
`binary_path`, `argv`, `origin` (`tmp`, `var_tmp`, `dev_shm`, or `memfd`),
`detected_at`, `state` (`open`, `quarantined`, `killed`, `dismissed`,
or `exited`), and `dropped_at?`: the `detected_at` of the
`THREAT_FILE_DROPPED` event for the same path, when there was one.

The plan's `KillProcess(pid, signal)` and `QuarantineProcess(pid)` are
narrowed on purpose, so that this socket is not a general `kill(2)` proxy:

* The daemon acts only on a process it reported. The caller must pass the
  `alert_id` together with its `pid`.
* Before signalling, the daemon compares the live process's start time
  (`/proc/<pid>/stat`, field 22) with the alert's `start_time`. If the PID
  now belongs to another process, the call fails with `STALE_TARGET`.
* Only `SIGTERM` (15) and `SIGKILL` (9) are accepted. Any other signal is
  rejected with `INVALID_PARAMS` while the params are parsed.
* A call that does not fit the alert's state fails with `INVALID_PARAMS`.
  Quarantine and dismiss need an `open` alert, and resume needs a
  `quarantined` one. Kill works on either.
* If the process has exited, the call fails with `STALE_TARGET`, and the
  alert resolves as `exited`.
* The daemon signals the user's own processes itself. Signalling another
  user's process goes through the privileged helper. When the helper is
  not running, or polkit refuses the request, the call fails with
  `PERMISSION_DENIED`.

The module is `active` when the privileged helper's eBPF monitor feeds
it. Without the helper it is `degraded`: it scans `/proc` every 2 s and
sees only this user's processes, and it misses scripts and very
short-lived programs.

Independently of either source, the daemon watches `/tmp`, `/var/tmp` and
`/dev/shm` with inotify, without recursion. Each directory created
directly in them is also watched, for 5 minutes (at most 128 at a time).
A regular file that its owner may execute and that starts with the ELF
magic or `#!` raises `THREAT_FILE_DROPPED {path, uid, size, detected_at}`
when it is written, made executable, or moved in. It is reported once per
content version, since a later chmod or rename does not repeat it. This
is not an alert: it has no `alert_id` and needs no response, because the
execution, if it comes, raises its own `THREAT_EXEC_DETECTED`. Files owned
by other users are reported only while the privileged helper is
connected, and only if this user can read them. At most 10 are reported
at once, then one every 3 s; the rest are logged as a count. If inotify
is unavailable, the module's `detail` says so and its state is unchanged.

### 4.3 USBGuard

| Method | Params | Result |
|---|---|---|
| `USBGUARD_LIST_DEVICES` | — | `{devices: UsbDevice[]}` |
| `USBGUARD_SET_POLICY` | `{device_id: u32, target: "allow" \| "block" \| "reject", permanent?: bool}` | `UsbDevice` |

This one method stands in for the plan's `AuthorizeUSBDevice`,
`BlockUSBDevice`, and `RejectUSBDevice`, as in the plan's own JSON example.
`permanent` defaults to `false`. When set, it appends a rule to
`/etc/usbguard/rules.conf`, which USBGuard does through its own
`applyDevicePolicy(…, permanent)` call.

The daemon talks to `usbguard-dbus` (bus name `org.usbguard1`, interface
`org.usbguard.Devices1`) on the system bus. The module is `unavailable`
while that service is not running. `usbguard-dbus` checks polkit, so a
refused policy change fails with `PERMISSION_DENIED`.

`UsbDevice` fields: `device_id`, `name`, `vendor_id`, `product_id`,
`serial`, `rule`, `interface_class`, and `interfaces?`. `vendor_id` and
`product_id` are four lowercase hex digits. `interface_class` is the first
interface's class as two hex digits, and `interfaces` lists every
interface's class when the device has more than one.

### 4.4 Tokens (PC/SC, FIDO2)

| Method | Params | Result |
|---|---|---|
| `TOKEN_LIST` | — | `{tokens: SecurityToken[]}` |

`SecurityToken` fields: `token_id`, `kind` (`yubikey`, `solokey`,
`nitrokey`, `fido2`, or `smartcard`), `name`, `vendor_id`, `product_id`,
`serial?`, and `capabilities` (a list drawn from `fido2`, `piv`, `openpgp`,
and `otp`).

Touch prompts for FIDO2 authenticators have `source` set to `fido2`, or to
`ssh` when an `ssh-sk-helper` of the user is running. The daemon reads the
authenticator's `KEEPALIVE` reports from hidraw and never takes part in the
request itself.

OpenPGP card prompts have `source` set to `gpg` and the `token_id` of the
OpenPGP-capable token present (or else of a smartcard reader). A card
waiting for a touch shows nothing to the host, so these are inferred: when
gpg-agent opens the stub of a card key (in `$GNUPGHOME/private-keys-v1.d`),
the daemon sends a short query to scdaemon, and a query that has not
answered after 400 ms is waiting behind a touch. `TOKEN_TOUCH_COMPLETED`
follows with `touched` when the query answers, or `timed_out` after 15 s;
`cancelled` is never sent for `gpg`. Waits while a `pinentry` of the user is
open are taken as PIN entry, not a touch. This covers gpg signing and
decryption and SSH through gpg-agent. Without a token present, nothing is
probed.

`pcsc` is reserved: other PC/SC prompts (such as PIV) cannot be detected
reliably, and the daemon does not send it.

### 4.5 Encrypted vaults

| Method | Params | Result |
|---|---|---|
| `VAULT_LIST` | — | `{vaults: Vault[]}` |
| `VAULT_MOUNT` | `{vault_id}` | `Vault` |
| `VAULT_UNMOUNT` | `{vault_id}` | `Vault` |
| `VAULT_PANIC` | — | `{unmounted: string[], lazy: string[], failed: [{vault_id, reason}]}` |
| `VAULT_ADD` | `{vault_id, name, backend, source, mount_point?}` | `Vault` |
| `VAULT_REMOVE` | `{vault_id}` | `{}` |
| `VAULT_CREATE` | `{vault_id, name, source, mount_point}` | `Vault` |

`Vault` fields: `vault_id`, `name`, `backend` (`gocryptfs` or `luks`),
`mount_point`, and `mounted`. For a LUKS vault, udisks2 chooses the mount
point each time, so `mount_point` is empty while the vault is not mounted.

Vaults are defined in the daemon configuration
([`configuration.md`](configuration.md)), and clients refer to them only by
`vault_id`.

* `VAULT_ADD` appends a `[[vault]]` table to the configuration file and
  reloads it; its params are that table's keys, with `id` spelled
  `vault_id`. The file keeps its comments and layout, and is replaced
  atomically (a symlink is followed, not replaced). A vault the
  configuration would reject (a bad or duplicate id, a missing or shared
  `mount_point`, a relative path) fails with `INVALID_PARAMS`, and so does
  a `source` that is not there: a gocryptfs `source` must be a directory
  with a `gocryptfs.conf` (made by `gocryptfs -init`), and a LUKS image
  file must exist; a path under `/dev` may be absent, as an unplugged disk
  is. If the file is invalid already, nothing is written and the call
  fails with `BACKEND_ERROR`. `VAULT_STATE_CHANGED` announces the new vault.
* `VAULT_REMOVE` deletes the vault's table from the file and reloads it.
  The encrypted data is not touched. A mounted vault is refused with
  `BACKEND_ERROR` (unmount it first), and so is any call while a mount or
  unmount is in progress. `VAULT_REMOVED` announces it, as it does when a
  vault leaves the configuration because the file was edited and reloaded.
* Neither method needs the vault backends, so both work while the module
  is `unavailable`.
* `VAULT_CREATE` makes a new, empty gocryptfs vault and adds it as
  `VAULT_ADD` would (`backend` is always `gocryptfs`). `source` is the
  cipher directory to create: it must not exist (it is made, with its
  parents, mode 0700) or be empty. The configuration change and `source`
  are checked first, failing with `INVALID_PARAMS` before any prompt;
  `MODULE_UNAVAILABLE` if `gocryptfs` is not installed. The daemon then
  asks for the new passphrase with pinentry, typed twice: pinentry checks
  the two itself when it supports `SETREPEAT`, else a second prompt asks
  again. An empty passphrase, or one with a line break, is asked for again,
  as is a mismatch, up to three times in all, after which the call fails
  with `INVALID_PARAMS`. Cancelling a prompt fails with `CANCELLED`, and
  `VAULT_PANIC` closes it like a mount's. The passphrase goes only to
  `gocryptfs -init` on its stdin; gocryptfs prints no master key without a
  terminal. If the vault cannot be added to the configuration in the end,
  the files `-init` made are removed again. The new vault is not mounted.

* Passphrases never cross this socket. For `VAULT_MOUNT`, the daemon runs
  `pinentry` in the user's session and reads the passphrase from it. It
  then passes the passphrase to gocryptfs on its stdin, or to udisks2's
  `Encrypted.Unlock`. A wrong passphrase makes pinentry ask again, up to
  three times in all, after which the call fails with `PERMISSION_DENIED`.
  If the user cancels the prompt, the call fails with `CANCELLED`.
* `VAULT_MOUNT` on a mounted vault, and `VAULT_UNMOUNT` on one that is not
  mounted, return the vault as it is. `VAULT_UNMOUNT` on a LUKS vault also
  locks it and deletes the loop device the daemon set up for an image file.
* `mounted` is read from the system, not remembered. A vault mounted or
  unmounted outside the hub still sends `VAULT_STATE_CHANGED`.
* The `vault` module is `unavailable` when no configured backend can be
  used (`gocryptfs` or `fusermount3` is missing, or udisks2 is not on the
  system bus), and `degraded` when only some of them can. A call on a vault
  whose backend is missing fails with `MODULE_UNAVAILABLE`. Other failures
  are `BACKEND_ERROR`, or `PERMISSION_DENIED` when polkit refuses a udisks2
  action.
* `VAULT_PANIC` is the emergency unmount, and never prompts. For every
  mounted vault it stops this user's processes that use it (an open file,
  a memory mapping, the working or root directory): `SIGTERM`, then
  `SIGKILL` after 2 s. It then flushes the filesystem, unmounts it (and
  locks and detaches a LUKS vault), and ends with a global `sync`. A
  passphrase prompt that is open is closed, and its `VAULT_MOUNT` fails
  with `CANCELLED`. A vault still busy after the processes are stopped is
  unmounted lazily and listed in both `unmounted` and `lazy`: a process the
  daemon cannot see, such as one in another mount namespace, may keep
  using files it has open. The compositor and the shell (`Hyprland`,
  `quickshell`, `omarchy-shell`) are never signalled. A vault they use is
  unmounted lazily too, but reported in `failed`, whose `reason` names
  them. `VAULT_STATE_CHANGED` is sent for each vault that changed.

### 4.6 Firewall (nftables)

| Method | Params | Result |
|---|---|---|
| `FIREWALL_LIST_RULES` | — | `{rules: FirewallRule[]}` |
| `FIREWALL_ADD_RULE` | `FirewallRuleSpec` | `FirewallRule` |
| `FIREWALL_REMOVE_RULE` | `{rule_id}` | `{}` |
| `FIREWALL_DECIDE` | `{request_id, verdict: "allow" \| "block", scope: "once" \| "process" \| "always"}` | `{}` |
| `FIREWALL_GET_MODE` | — | `FirewallMode` |
| `FIREWALL_SET_MODE` | `{mode: "ufw" \| "standalone", import_ufw_rules?: bool, dry_run?: bool}` | `FirewallMode` plus `imported?`, `not_imported?` |
| `FIREWALL_UFW_RULES` | — | `{rules: UfwRule[], builtin: string[], source: "user.rules"}` |
| `FIREWALL_ALERT_LIST` | `{limit?}` | `{alerts: FirewallAlert[]}` |
| `FIREWALL_ALERT_MUTE` | `{alert_id, duration_secs}` | `{}` |
| `FIREWALL_TEMP_ADD` | `{spec: FirewallRuleSpec, duration_secs, alert_id?}` | `TempDecision` |
| `FIREWALL_TEMP_LIST` | — | `{decisions: TempDecision[], durations_secs: number[]}` |
| `FIREWALL_TEMP_REMOVE` | `{temp_id}` | `{}` |

`FirewallRuleSpec` fields: `verdict`, `direction` (`inbound` or
`outbound`), `address` (an IP or CIDR prefix), `port?`, `protocol?` (`tcp`
or `udp`), and `executable?`. A `FirewallRule` is the spec plus its
`rule_id` and `loaded`, which says whether the rule is enforced now (see
the firewall mode below). Every rule lives in `table inet omarchy_sec`,
and the daemon never touches other tables.

* The daemon saves the rules in
  `$XDG_STATE_HOME/omarchy-security/firewall.json` and applies them as a
  whole through the privileged helper. A change is kept only once it has
  been applied. If polkit refuses it, the call fails with
  `PERMISSION_DENIED` and the rules stay as they were.
* Within a direction, `allow` rules are matched before `block` rules. An
  allow rule therefore makes an exception to a broader block. It does not
  override a `drop` in another nftables table.
* `executable` (an absolute path) scopes a rule to one program. Such a
  rule must be `outbound`. It is compared with the process's
  `/proc/<pid>/exe` (without a ` (deleted)` suffix), by path and not by
  inode, so a package upgrade keeps it. nftables cannot match a process,
  so these rules are not written to the table: the privileged helper holds
  each new outbound connection of the desktop user and checks them. If the
  helper cannot intercept connections, adding one fails with
  `MODULE_UNAVAILABLE`, saved ones are listed but not enforced, and the
  module reports `degraded`.
* Interception fails open. A connection whose process cannot be found (the
  socket already closed), or that arrives while the helper is not reading
  its queue, is allowed; the other rules still apply.

**Connection prompts.** While `[firewall] prompt = true`
([configuration](configuration.md)) and at least one client is subscribed
to the `firewall` topic, each new outbound connection that no executable
rule decides is held, and the daemon sends `FIREWALL_CONNECTION_PROMPT`.
Held connections with the same `executable`, `address`, `port` and
`protocol` share one prompt; `pid` is that of the first.

* `FIREWALL_DECIDE` answers a prompt. The first decision wins; a later
  one, or one after `expires_at`, fails with `NOT_FOUND`. Every client
  then gets `FIREWALL_CONNECTION_RESOLVED` and should close the prompt.
* `scope`: `once` applies to the held connections only. `process` also
  applies to later connections of the same process (pid and start time) to
  the same address, port and protocol, until it exits; it is kept in
  memory. `always` also adds an executable-scoped rule (outbound, the
  prompt's address, port and protocol), as `FIREWALL_ADD_RULE` would; the
  call fails as that would, for example with `PERMISSION_DENIED`, but the
  held connections are answered either way.
* If nobody answers by `expires_at`, or prompting stops (the last
  `firewall` subscriber leaves, the setting is turned off, or the helper
  goes away), the held connections get `timeout_verdict` and the prompt
  resolves with `decided_by: "timeout"`.

**Firewall mode.** Omarchy enables `ufw`, whose chains live in other
tables. A packet must pass both, so a hub `allow` cannot open what `ufw`
blocks, while a hub `block` always applies. `FIREWALL_GET_MODE` reports
which firewall protects the machine:

| `mode` | Meaning |
|---|---|
| `ufw` | `ufw` is active; our table holds only what adds to it. The default on Omarchy. |
| `standalone` | `ufw` is inactive and our table holds the full policy. |
| `both` | Both are active: safe, but confusing. Only happens when `ufw` is enabled outside the hub. |
| `none` | Neither is active: the machine is unprotected. |
| `unknown` | The privileged helper cannot be asked, so what is loaded is unknown. |

`FirewallMode` fields: `mode`, `ufw`, `table_loaded?`, `docker_protection`
(`ufw-docker`, `omarchy`, or `none`), and `detail?`, which explains an odd
state (for example `ufw` enabled in `ufw.conf` but its chains not loaded).
`ufw` is `{installed, enabled_in_conf, chains_loaded?, default_input?,
default_output?, default_forward?, logging?, before_rules_modified?}`: the
policies are lowercased (`drop`, `accept`, `reject`), `logging` is
`LOGLEVEL`, and `before_rules_modified` says that `/etc/ufw/before.rules`
or `before6.rules` differ from the packaged copies. The fields marked `?`
that come from the kernel (`chains_loaded`, `table_loaded`,
`before_rules_modified`) are absent in `unknown` mode.

* `ufw` is active when `ENABLED=yes` in `/etc/ufw/ufw.conf` and its chain
  `ufw-user-input` is loaded in `ip filter`. The state of `ufw.service`
  says nothing: it stays `active` after `ufw disable`. The standalone
  policy is recognised by the `mode=standalone` comment on our table.
* The daemon re-checks every 30 s, when `ufw`'s files change, and when the
  helper connects or goes away, and sends `FIREWALL_MODE_CHANGED` only
  when the result differs. The `firewall` module's `detail` starts with
  the mode in words.
* Both methods work while the `firewall` module is unavailable: the mode
  is then `unknown`, and the `ufw` rules need no helper.

**Rules in each mode.** In `standalone` (and `both`) mode our table holds
the full policy: the input chain drops by default after a baseline that
mirrors Omarchy's `ufw` setup (established traffic, loopback, the usual
ICMP and ICMPv6 types, DHCP and DHCPv6 replies, mDNS, and SSDP), then the
saved inbound rules, then a rate-limited log rule with the prefix
`[OMSEC BLOCK] `. The forward chain accepts by default but drops new
connections from outside the private ranges to ports Docker publishes, as
ufw-docker does. The output chain accepts by default. In `ufw` mode the
saved rules without an `executable` are kept, listed with
`loaded: false`, and not written to the table, because `ufw` decides.
Rules with an `executable` are `loaded` whenever the helper intercepts
connections, in every mode.

* `FIREWALL_ADD_RULE` with an inbound `allow` fails with `MODE_CONFLICT`
  while `ufw` is active (modes `ufw` and `both`): it could not open
  anything `ufw` blocks. `data.mode` names the mode. Every other rule can
  be added in every mode.
* The helper also writes the enforced part of the table (never the
  connection queue or temporary decisions) to
  `/var/lib/omarchy-security/firewall.nft`, which
  `omarchy-security-firewall.service` loads at boot. When it cannot, the
  `firewall` module's `detail` says so.
* The `detail` also names a service that would undo the ruleset:
  `nftables.service` enabled with a configuration that runs
  `flush ruleset` (the stock one does), or an active `firewalld`.

**Switching modes.** `FIREWALL_SET_MODE` turns `ufw` off (`standalone`)
or on (`ufw`) together with our table. It always asks for the
administrator password (polkit `org.omarchy.security.firewall.mode`, kept
for a few minutes); so does `FIREWALL_ADD_RULE` with an inbound `allow`.
The order never leaves the machine without a firewall:

* To `standalone`: the helper loads and checks the full policy while
  `ufw` still runs, writes the boot copy, and only then runs
  `ufw disable`. If `ufw` cannot be turned off, both stay enforcing.
* To `ufw`: the helper runs `ufw --force enable` and checks its chains,
  and only then removes the standalone policy from our table. If `ufw`
  cannot be turned on, the standalone policy stays.
* A failure returns `BACKEND_ERROR` whose message says which firewalls
  are enforcing; the daemon re-checks the mode, and a change in it sends
  `FIREWALL_MODE_CHANGED` as usual. `PERMISSION_DENIED` means polkit
  refused and nothing changed.
* On success the result is the new `FirewallMode`, and
  `FIREWALL_MODE_CHANGED` follows when the mode changed.
* The hub never switches on its own. An update that runs `ufw enable`
  while in `standalone` mode gives mode `both`, and the choice is the
  user's.

Importing `ufw`'s rules: on the first switch to `standalone`, or on any
switch to it with `import_ufw_rules: true`, the daemon saves `ufw`'s user
rules as hub rules where a hub rule can express them (`import_ufw_rules:
false` skips the first import). `allow` stays `allow`, `limit` becomes
`allow`, and `deny` and `reject` become `block`; a rule that is already
saved is not added again. The imported rules are committed only if the
switch succeeds. The result lists them in `imported`, each as `{rule:
FirewallRule, from: UfwRule, notes?}`, where `notes` says what the hub rule
does differently (no rate limiting, no local address). `not_imported`
lists `{from: UfwRule, reason}` for rules with an interface, a source
port, a port range or list, or another protocol. Both are absent when
empty.

`dry_run: true` switches nothing, saves nothing and asks for no password:
the result is the current `FirewallMode` with the `imported` and
`not_imported` the same call without `dry_run` would give (each imported
`rule` with `rule_id` 0 and `loaded` as after the switch), so the UI can
show them before asking.

`FIREWALL_UFW_RULES` returns `ufw`'s own rules, read-only, from the
`### tuple ###` lines of `/etc/ufw/user.rules` and `user6.rules`; `ufw
status` is never called. `UfwRule` fields: `action` (`allow`, `deny`,
`reject`, or `limit`), `direction` (`in` or `out`), `protocol` (`tcp`,
`udp`, `any`, ...), `port?` and `src_port?` (a port, `a:b` range, or
comma list), `src` and `dst` (an address, prefix, or `any`), `iface?`,
`comment?`, `ipv6`, and, on the temporary rules the hub added (see below),
`temp_id?` and `expires_at?`. Routed rules and lines that cannot be parsed
are left out. `builtin` describes, in words, what `before.rules` and
`after.rules` allow on a stock install, including the ufw-docker block
when it is present; it is empty when `ufw` is not installed.

**Blocked-traffic alerts.** The daemon follows the kernel log
(`journalctl -k`) for the packets `ufw` (`[UFW BLOCK]`, `[UFW LIMIT
BLOCK]`) and the standalone policy (`[OMSEC BLOCK]`, `[OMSEC DOCKER
BLOCK]`) logged as dropped. `FirewallAlert` fields: `alert_id`, `source`
(`ufw` or `omarchy`), `direction` (`inbound`, `outbound`, or `forward`,
for traffic routed to a container), `protocol` (`tcp`, `udp`, `icmp`,
`icmpv6`, `igmp`, or as logged), `src`, `dst`, `dst_port?`, `iface`,
`count`, `first_seen`, `last_seen`, and `muted_until?`.

* A blocked packet in an alert was already dropped. Packets of the same
  kind (source, direction, protocol, remote address, destination port)
  within `window_secs` of an alert's first packet only raise its `count`
  and `last_seen`. The daemon keeps the newest 500; `FIREWALL_ALERT_LIST`
  returns them newest first. Alerts live in memory only.
* The noise filter drops multicast and broadcast destinations and IGMP,
  and whatever `[firewall.alerts] ignore` lists
  ([configuration](configuration.md)).
* With `LOGLEVEL=low`, `ufw` logs a rate-limited sample (about 3 per
  minute) and nothing its default policy drops without a log rule, so in
  `ufw` mode the alerts are a sample. The hub never changes `ufw`'s log
  level.
* Alerts need to read the system journal, which wheel members can. If the
  daemon cannot, the `firewall` module is `degraded` with a detail that
  says so, and nothing else changes. They do not need the helper, so both
  alert methods work while the module is unavailable.
* `FIREWALL_ALERT_MUTE` (`duration_secs` 60 to 86 400) stops desktop
  notifications for the alert's kind of packet, including later alerts of
  that kind, until `muted_until`. Traffic stays blocked and alerts are
  still recorded and sent.
* The daemon also sends desktop notifications itself (app name
  `Omarchy Security`, urgency `normal`, so the user's do-not-disturb
  setting applies): one per alert, updated as the count grows, and at
  most `max_notifications_per_minute` new ones, beyond which one summary
  counts the rest. Their actions are "Open Security Hub", "Allow for 1 h"
  (a `FIREWALL_TEMP_ADD` built as below; offered only for TCP and UDP
  with a port) and "Keep blocking, stop telling me" (an 8 h mute). A
  change to mode `both` sends one notification, and to `none` one
  critical notification, each with "Use UFW" and "Use Security Hub
  firewall"; it is withdrawn once a firewall is chosen again.

**Temporary decisions.** `FIREWALL_TEMP_ADD` allows or blocks traffic for
`duration_secs` (60 to 86 400) in either mode. `spec` is a
`FirewallRuleSpec` with its `verdict`; it may not have an `executable`, and
a `port` needs a `protocol`. `TempDecision` fields: `temp_id` (unique
across daemon restarts), `spec`, `backend`, `created_at`, `expires_at`,
and `alert_id?` (passed through, to link the decision to the alert it
came from). Each change sends `FIREWALL_TEMP_CHANGED` with every decision.
`FIREWALL_TEMP_LIST` also returns `durations_secs`, the durations the UI
should offer (`[firewall.alerts] temp_durations_secs` in the
[configuration](configuration.md)); the event does not carry it.

| Mode | Verdict | Direction | `backend` |
|---|---|---|---|
| `ufw` or `both` | `block` | any | `table` |
| `ufw` or `both` | `allow` | `outbound` | `table`, or `ufw` if `ufw`'s default outbound policy is not `accept` |
| `ufw` or `both` | `allow` | `inbound` | `ufw` |
| `standalone` | any | any | `table` |
| `none`, `unknown` | any | any | fails with `MODE_CONFLICT` |

* `table`: an element with a kernel timeout in a set of our table, whose
  rule comes first in its chain (blocks before allows, before replies to
  established connections are accepted), so a temporary block also cuts
  an open connection. It expires even if the daemon and the helper stop.
* `ufw`: a `ufw` rule added with `ufw prepend`, whose comment is
  `omarchy-security:tmp:<temp_id>:<created_unix>:<expires_unix>`. The
  helper deletes it once it expires (it checks every 30 s and at startup)
  and deletes those from an earlier boot. `FIREWALL_UFW_RULES` shows it
  with `temp_id` and `expires_at`. A permanent inbound allow is still
  refused in `ufw` mode (`MODE_CONFLICT` above): the hub adds only these
  temporary rules to `ufw`.
* Every inbound allow, temporary or not, asks for the administrator
  password (`org.omarchy.security.firewall.mode`); temporary blocks,
  outbound decisions, mutes and removals do not.
* A new decision for the same `spec` replaces the earlier one.
  `FIREWALL_TEMP_REMOVE` ends one early; an unknown or expired `temp_id`
  is `NOT_FOUND`.
* Temporary decisions never survive a reboot and are never in the boot
  copy. A restarted daemon takes over the ones still in force. After a
  mode switch, each is moved to the backend the new mode needs, so an
  inbound allow keeps working.

### 4.7 Sandbox (bubblewrap)

| Method | Params | Result |
|---|---|---|
| `SANDBOX_RUN` | `{executable, args?, target_file?, share_net?}` | `{pid}` |

The daemon runs `bwrap` as the calling user, never through the privileged
helper, with the profile from the technical plan (§2.3). It passes
`--share-net` only when `share_net` is `true`, which is not the default.
`executable` and `target_file` must be absolute paths to existing regular
files, and `executable` must be executable. `target_file` must not be a
symbolic link: it is bound read-write, and the sandbox would get the file
the link points to under the link's name.

The profile adds these to the plan's:

* `--new-session`.
* A read-only bind of the executable itself, so a program under `$HOME`
  or `/tmp` still runs.
* A tmpfs over `$XDG_RUNTIME_DIR`, with only the Wayland socket bound
  back. Without it the sandboxed program could reach this socket or the
  systemd user bus, and through either start something outside the
  sandbox.
* A tmpfs over `/run`, for the same reason: the system bus, the
  privileged helper's socket and pcscd are there, and a read-only bind
  does not stop a program connecting to a socket. With `share_net`,
  `/run/systemd/resolve` is bound back read-only for DNS.
* `--cap-drop ALL`.

Under systemd, each sandbox runs in its own transient user scope, so it
survives a daemon restart. The returned `pid` is the `bwrap` process.

### 4.8 Posture audit

| Method | Params | Result |
|---|---|---|
| `POSTURE_GET_REPORT` | — | `PostureReport` |
| `POSTURE_REFRESH` | — | `PostureReport` |

A `PostureReport` is `{overall, evaluated_at, checks: PostureCheck[]}`, and
a `PostureCheck` is `{check_id, status, summary, detail?}`. `check_id` is
one of `lsm`, `ptrace_scope`, `docker_group`, or `swap_encryption`.
`status` is one of `pass`, `unknown`, `warn`, or `fail`, listed from best
to worst, and `overall` is the worst status among the checks.

## 5. Events

| Event | Topic | Params |
|---|---|---|
| `MODULE_STATE_CHANGED` | `system` | `ModuleStatus` |
| `THREAT_EXEC_DETECTED` | `threat` | `ThreatAlert` |
| `THREAT_ALERT_RESOLVED` | `threat` | `{alert_id, state}` |
| `THREAT_FILE_DROPPED` | `threat` | `{path, uid, size, detected_at}` |
| `USB_DEVICE_PRESENTED` | `usbguard` | `UsbDevice` |
| `USB_DEVICE_POLICY_CHANGED` | `usbguard` | `{device_id, target, permanent}` |
| `USB_DEVICE_REMOVED` | `usbguard` | `{device_id}` |
| `TOKEN_INSERTED` | `token` | `SecurityToken` |
| `TOKEN_REMOVED` | `token` | `{token_id}` |
| `TOKEN_TOUCH_REQUESTED` | `token` | `{request_id, token_id?, source: ssh \| gpg \| fido2 \| pcsc, description}` |
| `TOKEN_TOUCH_COMPLETED` | `token` | `{request_id, outcome: touched \| timed_out \| cancelled}` |
| `VAULT_STATE_CHANGED` | `vault` | `Vault` |
| `VAULT_REMOVED` | `vault` | `{vault_id}` |
| `FIREWALL_CONNECTION_PROMPT` | `firewall` | `{request_id, pid, executable, protocol, address, port, expires_at}` |
| `FIREWALL_CONNECTION_RESOLVED` | `firewall` | `{request_id, verdict, decided_by: user \| timeout}` |
| `FIREWALL_MODE_CHANGED` | `firewall` | `FirewallMode` |
| `FIREWALL_ALERT` | `firewall` | `FirewallAlert` |
| `FIREWALL_TEMP_CHANGED` | `firewall` | `{decisions: TempDecision[]}` |
| `POSTURE_CHANGED` | `posture` | `PostureReport` |

The daemon emits `POSTURE_CHANGED` only when a 30 s evaluation differs from
the previous one. If `FIREWALL_DECIDE` does not arrive by `expires_at`, the
held connection gets the configured `timeout_verdict` (`block` by default)
and `FIREWALL_CONNECTION_RESOLVED` follows with `decided_by: "timeout"`.
`FIREWALL_ALERT` is sent when an alert is created, when it is muted, and
when its count changes, at most once per 5 s per alert.

## 6. Errors

| Code | Name | Meaning |
|---|---|---|
| -32700 | `PARSE_ERROR` | The frame is not valid JSON. |
| -32600 | `INVALID_REQUEST` | Not a JSON-RPC 2.0 request: wrong `jsonrpc`, missing `id` or `method`, or a batch. |
| -32601 | `METHOD_NOT_FOUND` | Unknown method. |
| -32602 | `INVALID_PARAMS` | Params are not an object, a field is missing or has the wrong type, a field is unknown, or a value is disallowed. |
| -32603 | `INTERNAL_ERROR` | A bug in the daemon. |
| -32000 | `HANDSHAKE_REQUIRED` | A method was called before `HELLO`. |
| -32001 | `UNSUPPORTED_PROTOCOL_VERSION` | `HELLO.protocol_version` is not supported. `data.supported` lists the versions that are. |
| -32002 | `MODULE_UNAVAILABLE` | The module is disabled or its dependency is missing. `data.module` names the module. |
| -32003 | `NOT_FOUND` | Unknown alert, device, token, vault, rule, or request id. |
| -32004 | `PERMISSION_DENIED` | Refused by policy, or by polkit for a helper action. |
| -32005 | `STALE_TARGET` | The PID or device no longer matches what was reported. |
| -32006 | `BACKEND_ERROR` | The kernel, USBGuard, cryptsetup, or nftables rejected the action. `data.detail` gives the reason. |
| -32007 | `NOT_IMPLEMENTED` | The method is specified but not built into this daemon yet. |
| -32008 | `CANCELLED` | The user cancelled a prompt the call needed, such as a vault's passphrase prompt. |
| -32009 | `MODE_CONFLICT` | The call cannot work in the current firewall mode, such as an inbound allow while `ufw` is active. The message says what to do instead; `data.mode` names the mode. |

## 7. Versioning

`PROTOCOL_VERSION` is `1`. The version stays the same when new optional
result or event fields are added, and when new methods, events, topics, or
enum values are added. Clients must treat an unknown event or enum value as
something to ignore, not as an error. Removing or renaming anything,
changing a field's type, or making a param required bumps the version.
