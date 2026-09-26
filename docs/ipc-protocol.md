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
`detected_at`, and `state` (`open`, `quarantined`, `killed`, `dismissed`,
or `exited`).

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

Touch prompts are detected only for FIDO2 authenticators so far, with
`source` set to `fido2`, or to `ssh` when an `ssh-sk-helper` of the user is
running. The daemon reads the authenticator's `KEEPALIVE` reports from
hidraw and never takes part in the request itself. It cannot yet detect
OpenPGP card (`gpg`) or PC/SC prompts.

### 4.5 Encrypted vaults

| Method | Params | Result |
|---|---|---|
| `VAULT_LIST` | — | `{vaults: Vault[]}` |
| `VAULT_MOUNT` | `{vault_id}` | `Vault` |
| `VAULT_UNMOUNT` | `{vault_id}` | `Vault` |
| `VAULT_PANIC` | — | `{unmounted: string[], lazy: string[], failed: [{vault_id, reason}]}` |

`Vault` fields: `vault_id`, `name`, `backend` (`gocryptfs` or `luks`),
`mount_point`, and `mounted`. For a LUKS vault, udisks2 chooses the mount
point each time, so `mount_point` is empty while the vault is not mounted.

Vaults are defined in the daemon configuration
([`configuration.md`](configuration.md)), and clients refer to them only by
`vault_id`.

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

`FirewallRuleSpec` fields: `verdict`, `direction` (`inbound` or
`outbound`), `address` (an IP or CIDR prefix), `port?`, `protocol?` (`tcp`
or `udp`), and `executable?`. A `FirewallRule` is the spec plus its
`rule_id`. Every rule lives in `table inet omarchy_sec`, and the daemon
never touches other tables.

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

### 4.7 Sandbox (bubblewrap)

| Method | Params | Result |
|---|---|---|
| `SANDBOX_RUN` | `{executable, args?, target_file?, share_net?}` | `{pid}` |

The daemon runs `bwrap` as the calling user, never through the privileged
helper, with the profile from the technical plan (§2.3). It passes
`--share-net` only when `share_net` is `true`, which is not the default.
`executable` and `target_file` must be absolute paths to existing regular
files, and `executable` must be executable.

The profile adds three things to the plan's:

* `--new-session`.
* A read-only bind of the executable itself, so a program under `$HOME`
  or `/tmp` still runs.
* A tmpfs over `$XDG_RUNTIME_DIR`, with only the Wayland socket bound
  back. Without it the sandboxed program could reach this socket or the
  systemd user bus, and through either start something outside the
  sandbox.

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
| `USB_DEVICE_PRESENTED` | `usbguard` | `UsbDevice` |
| `USB_DEVICE_POLICY_CHANGED` | `usbguard` | `{device_id, target, permanent}` |
| `USB_DEVICE_REMOVED` | `usbguard` | `{device_id}` |
| `TOKEN_INSERTED` | `token` | `SecurityToken` |
| `TOKEN_REMOVED` | `token` | `{token_id}` |
| `TOKEN_TOUCH_REQUESTED` | `token` | `{request_id, token_id?, source: ssh \| gpg \| fido2 \| pcsc, description}` |
| `TOKEN_TOUCH_COMPLETED` | `token` | `{request_id, outcome: touched \| timed_out \| cancelled}` |
| `VAULT_STATE_CHANGED` | `vault` | `Vault` |
| `FIREWALL_CONNECTION_PROMPT` | `firewall` | `{request_id, pid, executable, protocol, address, port, expires_at}` |
| `FIREWALL_CONNECTION_RESOLVED` | `firewall` | `{request_id, verdict, decided_by: user \| timeout}` |
| `POSTURE_CHANGED` | `posture` | `PostureReport` |

The daemon emits `POSTURE_CHANGED` only when a 30 s evaluation differs from
the previous one. If `FIREWALL_DECIDE` does not arrive by `expires_at`, the
held connection gets the configured `timeout_verdict` (`block` by default)
and `FIREWALL_CONNECTION_RESOLVED` follows with `decided_by: "timeout"`.

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

## 7. Versioning

`PROTOCOL_VERSION` is `1`. The version stays the same when new optional
result or event fields are added, and when new methods, events, topics, or
enum values are added. Clients must treat an unknown event or enum value as
something to ignore, not as an error. Removing or renaming anything,
changing a field's type, or making a param required bumps the version.
