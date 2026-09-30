# Security notes

What the Security Hub promises about its own behaviour, and why. The
security review (task 4.5) adds its findings here.

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
