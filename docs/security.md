# Security notes

What the Security Hub promises about its own behaviour, and why, and
what the security review of the privilege boundary (task 4.5) found.

## Firewall

* **The hub never fights `ufw` on its own.** Only `FIREWALL_SET_MODE`,
  which the user starts and polkit guards with the administrator password
  (`org.omarchy.security.firewall.mode`), turns `ufw` off or on. If
  something else enables `ufw` again while the hub is in `standalone`
  mode, for example an Omarchy update that runs `ufw enable`, the daemon
  reports mode `both` and leaves it: both firewalls enforce, which is
  safe, and the user chooses which to keep.
* **A mode switch never leaves the machine without a firewall.** Turning
  `ufw` off happens only after the standalone policy is loaded, checked
  and written to the boot copy; turning it on happens before the
  standalone policy is removed. A failure part-way leaves both enforcing.
* **Changes that expose the machine need the password.** Turning `ufw` off
  or on and every inbound allow need `org.omarchy.security.firewall.mode`,
  which asks even a local wheel member (`auth_admin_keep`). Blocks and
  outbound rules stay under `org.omarchy.security.firewall.manage`, which
  does not ask. "Every inbound allow" includes temporary ones, in the
  table and in `ufw`, and any temporary `ufw` allow.
* **Temporary exceptions cannot outlive their time.** A temporary
  decision in our table is a set element with a kernel timeout; one in
  `ufw` carries its expiry in its comment, and the helper deletes it once
  expired, at startup, every 30 s, and when it is from an earlier boot.
  Neither needs the daemon to be running, and neither is in the boot
  copy. The hub adds no permanent `ufw` rules.
* **Notifications cannot open the firewall silently.** "Allow for 1 h" in
  a desktop notification is an ordinary `FIREWALL_TEMP_ADD`, so an inbound
  allow still asks for the password. The alert only fills in the
  protocol, the port and the one remote host.
* **`ufw` is run without a shell**: `/usr/bin/ufw` with a fixed argv, a
  cleared environment plus `PATH=/usr/bin:/usr/sbin` and `LC_ALL=C`.

Recovery, from a TTY or ssh, back to stock Omarchy:

```sh
sudo ufw --force enable && sudo nft delete table inet omarchy_sec && \
  sudo rm -f /var/lib/omarchy-security/firewall.nft /var/lib/omarchy-security/mode
```

The mode file matters: while it says `standalone`, the helper loads the
standalone table again at its next start.

## Review of the privilege boundary (task 4.5, 2026-09-29)

The boundary is between the desktop user and root: the root helper
(`omarchy-securityd-helper`, socket `/run/omarchy-security/helper.sock`,
mode 0666) and what it does for its clients. A second boundary is the
sandbox, between a sandboxed program and the user. Each point of the
plan's §5.13 was checked in the code; what was wrong is fixed, with a
test, and what is accepted is said here.

### Fixed

* **The sandbox could reach the system bus and the helper.** `bwrap`
  bound `/` read-only, but a read-only mount does not stop `connect()` on
  a socket, and `/run` holds the system bus, the helper's socket and
  pcscd. polkit sees a sandboxed program as the desktop user in the same
  session as the daemon, so it could have removed the firewall rules,
  answered connection prompts, allowed a USB device through USBGuard or
  mounted a disk through udisks2, all without a password. `/run` is now an
  empty tmpfs in the sandbox (`systemd/resolve` is bound back when the
  network is shared, for DNS), and the sandbox drops every capability.
  Test: `sandbox::tests::sandbox_hides_the_session` lists `/run` inside a
  real sandbox.
* **A symlinked target file gave write access to what it points to.**
  `doc.pdf -> ../.bashrc` was bound read-write under the name `doc.pdf`.
  `SANDBOX_RUN` now refuses a `target_file` that is a symbolic link.
* **A temporary inbound allow could be extended without the password.**
  The helper asked for `org.omarchy.security.firewall.mode` only for an
  inbound allow it did not hold yet, comparing the id and the rule but not
  the expiry, so resending one with a later `expires_at` kept it open for
  as long as the client liked under the passwordless
  `firewall.manage`. A later expiry now counts as a new allow, and no
  temporary decision may last more than 24 hours (the longest
  `temp_durations_secs`), in the table or in `ufw`.
* **The inbound check raced the change.** Whether a request opens the
  machine was decided before the firewall lock was taken, so the mode or
  the loaded rules could change before the rules were applied. The helper
  now checks again under the lock and refuses a request that has come to
  need the password without having asked for it.
* **Authorization was per handler.** Each handler called polkit itself,
  so a new operation could have been added without it. Every request now
  goes through one exhaustive `required_action` (no wildcard arm) before
  it runs; the handlers only ask for more, for an inbound or `ufw` allow.
  `hello` and `connection_unsubscribe` are the two that need nothing: one
  says what the helper can do, the other gives up what the connection
  itself holds.
* **A refused `exec_subscribe` was remembered as subscribed**, so a second
  one answered success without asking polkit (no records were sent). The
  flag is now set only once the stream starts.
* **Any local user could make the helper hold unbounded memory**, one task
  per request, each waiting on polkit. A connection now has at most 32
  requests in flight, and the unit has `MemoryMax=96M`.
* **Watching executions was allowed to any wheel member, over SSH too.**
  The records carry other users' programs and paths the helper reads with
  `CAP_SYS_PTRACE`. `org.omarchy.security.threat.monitor` now needs a
  local session, like the other actions.
* **The `ufw` sweep depended on polkit.** The helper swept expired
  temporary `ufw` rules only once it had reached polkit, and it exits when
  it cannot. It now restores the standalone table and sweeps `ufw` first.

### Holds

* **polkit subject.** `unix-process` with the peer's pid, its start time
  from `/proc/<pid>/stat` and the uid from `SO_PEERCRED`. When polkit
  cannot be asked the answer is no; without the system bus at startup the
  helper does not run.
* **Signals.** Only to a (pid, start time) the exec monitor reported,
  checked against `/proc` again just before the signal; pid 0 and 1 and
  anything else are refused.
* **nft scripts.** No string from a client reaches the script: addresses
  are parsed into `IpAddr` and printed back, ports are integers, protocol
  and verdict are enums, set names and comments are built from integer
  ids, and executable rules are matched in the helper, never rendered.
  The `helper_request` fuzz target checks this on every script it renders.
* **`ufw` calls.** `/usr/bin/ufw` without a shell, a cleared environment
  plus `PATH` and `LC_ALL=C`, and an argv of those same typed values; the
  comment tag is integers. A tag read back from `user.rules` is parsed to
  integers and the rule rebuilt from typed values before it is deleted.
  The `ufw_tuple` fuzz target checks both.
* **Mode switches.** Every failure branch leaves at least one firewall
  enforcing (see Firewall above). Every mode change and every inbound
  allow, temporary or not, table or `ufw`, needs
  `org.omarchy.security.firewall.mode`.
* **Boot copy.** `/var/lib/omarchy-security/firewall.nft`, `rules.json`
  and `mode` are written by root into a 0700 directory, each through a
  temporary file created 0600, fsync, rename and fsync of the directory.
  The boot copy is rendered without the NFQUEUE rule and without
  temporary decisions.
* **Sandbox.** `--unshare-all --new-session`, a fresh `/proc` in its own
  PID namespace (so `/proc/1` is bwrap's), and `$HOME`, `/tmp`, `/run` and
  `$XDG_RUNTIME_DIR` as tmpfs, with only the Wayland socket bound back.
* **Vault passphrases.** Read from pinentry into `Zeroizing` buffers of a
  fixed capacity (never reallocated, so never copied behind our back),
  passed to gocryptfs on stdin (`-passfile /dev/stdin`), never in argv,
  never logged, and dropped after use.
* **Daemon socket.** Its directory is created 0700 and the socket 0600;
  a peer of another uid (`SO_PEERCRED`) is disconnected; only `HELLO` is
  answered before the handshake; a frame is at most 64 KiB, and a
  connection has at most 32 requests in flight.
* **Untrusted text on screen.** Every text the hub shows from a device,
  a process or the network is set as plain text, and the daemon escapes
  `&`, `<` and `>` in notification bodies (the server supports markup).

### Accepted

* **Signals reach other users' processes.** `threat.respond` lets any
  process of the desktop user stop or kill a flagged process of any user,
  root included; that is what the threat card is for, and only programs
  run from `/tmp`, `/var/tmp`, `/dev/shm` or memory are flagged.
* **PID reuse.** The start time of a reported process is read from
  `/proc` after the exec event, and a peer's after it connects; a pid
  reused in between names another process. pidfds (`SO_PEERPIDFD`,
  `pidfd_send_signal`) and a start time from the eBPF program would close
  both windows.
* **The LUKS passphrase** is copied into the D-Bus message to udisks2,
  which zbus does not zeroize.
* **One connection subscriber per machine.** A second
  `connection_subscribe` (another user's daemon) replaces the first, and
  the queue then follows the new uid.
* **With the network shared**, the sandbox is in the host network
  namespace, so abstract Unix sockets are reachable, XWayland's among
  them. Share the network only with programs that need it.

### Fuzzing

`fuzz/` is a `cargo fuzz` workspace (nightly, like the eBPF crate) with a
target for each parser that reads untrusted input:

| Target | Parser | Input from |
|---|---|---|
| `rpc_frame` | NDJSON framing and JSON-RPC (`omarchy-securityd` `server.rs`, proto `rpc.rs`) | any process of the user |
| `helper_request` | helper requests, and the `nft` script and `ufw` argv made from them | any local user |
| `usbguard_rule` | USBGuard device rules (`usbguard.rs`) | a USB device's descriptors |
| `token` | uevents and CTAPHID reports (`token.rs`) | the kernel, a security key |
| `exec_event` | eBPF ring buffer records and the tracepoint format (`exec.rs`) | the kernel |
| `packet` | IP, TCP and UDP headers from the NFQUEUE (`packet.rs`) | the network |
| `kernel_log` | blocked-packet log lines and `journalctl` JSON (`alerts.rs`) | the network |
| `ufw_tuple` | `### tuple ###` lines, the rules imported from them, the tags of temporary rules | `/etc/ufw/user.rules` |

Each checks more than not crashing: frames match the input's lines and
an error response is one line; a rendered `nft` script holds only fixed
text, numbers and addresses, one line per rule; a `ufw` argv holds no
option and no quote; a name USBGuard escaped comes back unchanged; touch
prompts start and end in turn. `make test-fuzz` replays `fuzz/seeds`
(real lines and packets from the tests) through the same checks on
stable, as part of `make test`; `make fuzz` fuzzes each target for
`FUZZ_SECS` (60) seconds.

Run on 2026-09-30 for 2 minutes per target, from about 93 thousand runs
(`rpc_frame`, whose inputs reach 64 KiB) to 78 million (`packet`), with
no crash and no check failed. The seed replay found one bug before that,
fixed: USBGuard writes each byte of a UTF-8
name as `\xHH`, and the rule parser turned each byte into a character,
so "Café" showed as "CafÃ©".

## End-to-end pass (task 4.4)

`tools/system_check.py` (`make system-check`) checks an installed hub on
a real machine. What it found:

* **Rules scoped to a program, and connection prompts, were never
  applied.** To find which process owns an intercepted connection, the
  helper listed `/proc/<pid>/fd` of the user's processes. The kernel checks
  only file permissions on that directory (0500, owned by the process's
  user), and the unit grants no `CAP_DAC_READ_SEARCH`, so every listing
  failed. Each connection then counted as one whose process could not be
  found, and interception let it through, as it is meant to fail open.
  The tests had not seen it: they run the helper as the user whose
  processes it reads. The helper now reads `/proc/<pid>/fdinfo`, which
  the kernel opens to `CAP_SYS_PTRACE`, and matches the socket's `ino`
  on the sockfs mount (`mnt_id`), so the unit keeps its five
  capabilities.

## The plugin's backend installer (task 5.3)

A plugin installed with `omarchy plugin add` can install the backend with
`backend/install.sh`, from the hub's **Install backend** button or by hand.
Its trust model is the plugin's own:

* **Who is trusted.** The plugin already runs unsandboxed in
  `omarchy-shell`, and `omarchy plugin add` warns about that. The
  installer adds no new party: it downloads only from this project's GitHub
  releases (`curl --proto =https`, redirects also HTTPS only).
* **What the checksum proves.** The tarball is checked against the same
  release's `SHA256SUMS`. That catches a corrupted or truncated download,
  and a tarball swapped for another release's. It is no defence against
  someone who can publish releases here, just as `omarchy plugin update`
  is no defence against someone who can push to the plugin repository. A
  `SHA256SUMS` that doesn't list the tarball fails the install, rather than
  passing with nothing checked.
* **Root.** The script refuses to run as root. It runs `sudo` for the
  install and the system units only, after showing what it will do and
  asking. The button starts it in a visible terminal, where sudo asks for
  the password; nothing in the shell runs as root, and nothing runs without
  a click. **Start** runs only `systemctl --user`.
* **What it leaves alone.** It never enables USBGuard (without a policy,
  that blocks the keyboard), never runs `ufw`, and never changes the
  firewall mode. It refuses to replace an install that pacman owns.
* **Removal is safe for the firewall.** `uninstall.sh` stops the helper
  first, so nothing loads the hub's policy again. If the mode was
  `standalone` (the hub had turned `ufw` off), it turns `ufw` back on
  before deleting the hub's table, so the machine always has a firewall.
