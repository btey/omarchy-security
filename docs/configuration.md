<!-- SPDX-License-Identifier: MIT -->

# Daemon configuration

`omarchy-securityd` reads `$XDG_CONFIG_HOME/omarchy-security/config.toml`
(by default `~/.config/omarchy-security/config.toml`), or the file given
with `--config <PATH>`. A sample with every key is in
[`dist/config.example.toml`](../dist/config.example.toml).

* **Missing file.** Every key has a default, so no file means the defaults.
* **Reload.** `systemctl --user reload omarchy-securityd` (or `SIGHUP`)
  reads the file again. Modules pick up the new values without a restart.
* **Errors.** Unknown keys, wrong types and out-of-range values make the
  whole file invalid. The daemon logs the reason
  (`journalctl --user -u omarchy-securityd`) and keeps the configuration it
  had, which at startup is the defaults. It never exits over the file.
* **Paths.** Paths must be absolute or start with `~/`, which is expanded
  to `$HOME`.

## `[[vault]]`: encrypted vaults

One table per vault. Clients see vaults only through `VAULT_LIST` and refer
to them by `id` (`vault_id` on the wire, [`ipc-protocol.md`](ipc-protocol.md)
§4.5). Passphrases are never stored here: the daemon asks for them with
`pinentry` when a vault is mounted.

A gocryptfs vault needs `gocryptfs` and `fuse3`. Create its cipher
directory first with `gocryptfs -init <source>`. The mount point is created
(mode 0700) if it does not exist. A LUKS vault needs `udisks2`. udisks2's
polkit defaults let the active local session set up the loop device,
unlock it and mount it without a password.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `id` | string | yes | 1–64 characters of `a-z`, `0-9` and `-`, unique among vaults. |
| `name` | string | yes | Name shown in the hub. Not empty. |
| `backend` | `"gocryptfs"` or `"luks"` | yes | How the vault is encrypted. |
| `source` | path | yes | For `gocryptfs`, the cipher directory. For `luks`, a LUKS image file or block device. |
| `mount_point` | path | `gocryptfs` only | Where the cleartext view is mounted. Must differ from `source` and from every other vault's. Not allowed for `luks`: udisks2 chooses the mount point (under `/run/media/$USER`). |

## `[firewall]`: connection prompts

| Key | Type | Default | Meaning |
|---|---|---|---|
| `prompt` | bool | `false` | Hold new outbound connections that no rule decides, and ask the user (`FIREWALL_CONNECTION_PROMPT`). Only while a client is subscribed to the `firewall` topic, and only if the privileged helper can intercept connections. |
| `prompt_timeout_secs` | integer, 5–300 | `30` | How long a held connection waits for `FIREWALL_DECIDE`. |
| `timeout_verdict` | `"allow"` or `"block"` | `"block"` | Applied when nobody answers in time. |

## `[firewall.alerts]`: blocked-traffic alerts

Alerts come from the kernel log of `ufw` and of the hub's baseline policy.
They are always sent to subscribed clients as `FIREWALL_ALERT`; these keys
filter them and control desktop notifications.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `notify` | bool | `true` | Send desktop notifications for alerts. The warnings that both firewalls, or neither, are active are sent either way. |
| `window_secs` | integer, 10–86 400 | `600` | Packets of the same kind (source, direction, protocol, remote address, destination port) within this long of an alert's first packet are grouped into it, with a count. |
| `max_notifications_per_minute` | integer, 1–60 | `3` | Beyond this, one summary notification is sent instead. |
| `ignore_multicast` | bool | `true` | Drop alerts for multicast and broadcast destinations (`224.0.0.0/4`, `ff00::/8`, `255.255.255.255`) and for IGMP. |
| `ignore` | array of tables | `[]` | Drop alerts that match an entry; see below. |
| `temp_durations_secs` | array of integers, each 60–86 400 | `[300, 3600, 28800]` | The durations offered for temporary allow and block decisions (and mutes) in the hub's Network tab, served in `FIREWALL_TEMP_LIST`. Not empty. |

Each `ignore` entry matches when every key it sets matches, and needs at
least one of them:

| Key | Type | Matches |
|---|---|---|
| `protocol` | `"tcp"`, `"udp"`, `"icmp"`, `"icmpv6"` or `"igmp"` | The packet's protocol. |
| `port` | integer, 0–65 535 | The local port: the destination of an inbound packet, the source of an outbound one. |
| `address` | IP or CIDR prefix | The remote address. |

```toml
[firewall.alerts]
ignore = [
  { protocol = "udp", port = 137 },          # NetBIOS name service
  { address = "192.168.1.0/24", port = 5353 },
]
```
