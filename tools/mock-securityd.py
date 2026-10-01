#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stand-in for omarchy-securityd that speaks protocol v1 with canned data.

Lets the QuickShell plugin be developed before the daemon's modules exist.
It listens on the same socket path the plugin resolves, so run the real
daemon or this, not both.

    tools/mock-securityd.py [--socket PATH] [--alert-every SECS] [--prompt-timeout SECS]
                            [--passphrase-delay SECS] [--mode MODE]

Three USB devices are connected from the start. A few seconds after a
client subscribes, a flash drive that also registers a keyboard is plugged
in (USB_DEVICE_PRESENTED); each SIGUSR1 unplugs it or plugs it back in.
USBGUARD_SET_POLICY with "reject" removes a device (USB_DEVICE_REMOVED), and
"allow" with permanent: true lets it in whenever it is plugged in again, as
USBGuard does.

Firewall: two saved rules to start with, an outbound block (not enforced
while ufw is on) and an allow for /usr/bin/curl (enforced in every mode).
Shortly after a client subscribes to "firewall", git and firefox each make a
held connection (FIREWALL_CONNECTION_PROMPT); each SIGUSR2 sends another one,
from curl. FIREWALL_DECIDE answers a prompt ("always" saves a rule for the
program, unless an identical one exists), and an unanswered one is blocked
after PROMPT_TIMEOUT_SECS (or --prompt-timeout). The firewall starts in
--mode (ufw, standalone, both, none or unknown; default ufw); in unknown the
helper counts as stopped, so switching and temporary decisions fail. Each
SIGHUP switches the mode between "ufw" and "none" and sends
FIREWALL_MODE_CHANGED. FIREWALL_SET_MODE switches at once, without a
password; with dry_run it only says what it would import (UFW's port range
rule cannot be). Every ALERT_EVERY_SECS (or --alert-every) a canned blocked
packet is recorded and sent as FIREWALL_ALERT (repeats are grouped, as the
daemon does). FIREWALL_TEMP_* keep temporary decisions in memory, choose
the backend from the mode, and send FIREWALL_TEMP_CHANGED; they expire on
time. The first inbound allow fails with PERMISSION_DENIED, as if the
password prompt were dismissed; MODE_CONFLICT comes as from the daemon.

Threat alerts: shortly after a client subscribes, three suspicious
executions are reported (THREAT_EXEC_DETECTED): a dropped binary in /tmp, a
program run from memory, and a script in /dev/shm; each SIGALRM reports the
next canned one again. The /dev/shm one
has already exited, so a response to it fails with STALE_TARGET and resolves
it. Kill, Isolate (quarantine), Resume and Dismiss follow the daemon's state
rules; no process is signalled.

Security tokens: a YubiKey and a smart card reader are plugged in from the
start (TOKEN_LIST). Shortly
after a client subscribes, three touch requests play out: a FIDO2 sign-in
that is touched, a GnuPG one that times out (in 1 s, not the daemon's 15 s),
and an SSH one ended by unplugging the key (TOKEN_REMOVED, which the daemon
sends without TOKEN_TOUCH_COMPLETED), after which the key is plugged back
in. Each SIGPROF starts a FIDO2 request that is touched after 8 s.

Vaults: "notes" (gocryptfs) and "backup" (LUKS) are locked, "work"
(gocryptfs) is open and in use. VAULT_MOUNT stands for the pinentry wait
with PASSPHRASE_SECS (or --passphrase-delay) before it answers; the first
mount of "backup" is cancelled, as if the prompt were closed, and later
ones succeed. VAULT_UNMOUNT of "work" fails because it is busy. VAULT_PANIC
cancels mounts still waiting for a passphrase, unmounts every open vault
("work" lazily) and sends VAULT_STATE_CHANGED for each. Each SIGVTALRM
mounts or unmounts "notes" as if done outside the hub. VAULT_ADD checks
its params as the configuration does (id, name, backend, paths, a
mount_point for gocryptfs only and not shared), but not that the source
exists; VAULT_REMOVE refuses a mounted vault. Neither writes a file.
VAULT_CREATE checks the same, then waits PASSPHRASE_SECS for the "new
passphrase" before adding the vault; a source with "cancel" in it is
cancelled there, and VAULT_PANIC cancels one still waiting.

Sandbox: SANDBOX_RUN checks its params as the daemon does (absolute paths
to existing regular files, an executable program, no unknown fields) and
answers with a made-up pid; nothing is run.

Any other method is answered with NOT_IMPLEMENTED (the e2e harness probes
MOCK_NOT_IMPLEMENTED for that).
"""

import argparse
import asyncio
import json
import os
import re
import signal
import sys
import time

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 64 * 1024

MODULES = [
    {"module": "threat", "state": "degraded", "detail": "mock data"},
    {"module": "usbguard", "state": "active"},
    {"module": "token", "state": "degraded", "detail": "mock data"},
    {"module": "vault", "state": "active"},
    {"module": "firewall", "state": "active"},
    {"module": "sandbox", "state": "active"},
    {"module": "posture", "state": "degraded", "detail": "mock data"},
]

DEVICES = {
    2: {
        "device_id": 2,
        "name": "USB Receiver",
        "vendor_id": "046d",
        "product_id": "c52b",
        "serial": "",
        "rule": "allow",
        "interface_class": "03",
        "interfaces": ["03", "03", "03"],
    },
    5: {
        "device_id": 5,
        "name": "Integrated Camera",
        "vendor_id": "04f2",
        "product_id": "b6dd",
        "serial": "0001",
        "rule": "allow",
        "interface_class": "0e",
        "interfaces": ["0e", "0e"],
    },
    14: {
        "device_id": 14,
        "name": "Mass Storage Device",
        "vendor_id": "0951",
        "product_id": "1666",
        "serial": "00187D0F2E3B",
        "rule": "block",
        "interface_class": "08",
    },
}

# Plugged in after SUBSCRIBE and by SIGUSR1: storage that can also type.
DRIVE = {
    "device_id": 21,
    "name": "Flash Drive",
    "vendor_id": "1234",
    "product_id": "5678",
    "serial": "AA00112233",
    "rule": "block",
    "interface_class": "08",
    "interfaces": ["08", "03"],
}
# (vendor_id, product_id, serial) with a permanent allow rule.
SAVED_DEVICES = set()

# Worded as the daemon words them (crates/omarchy-securityd/src/posture.rs).
POSTURE = {
    "overall": "fail",
    "evaluated_at": 0,
    "checks": [
        {"check_id": "lsm", "status": "warn",
         "summary": "No mandatory access control (SELinux or AppArmor) is active",
         "detail": "Active LSMs: capability, landlock, lockdown, yama, bpf"},
        {"check_id": "ptrace_scope", "status": "pass", "summary": "ptrace_scope = 1 (parents only)"},
        {"check_id": "docker_group", "status": "fail",
         "summary": f"{os.environ.get('USER', 'user')} is in the docker group",
         "detail": "Members of docker can start a privileged container and become root. "
                   "Prefer rootless Docker or Podman."},
        {"check_id": "swap_encryption", "status": "pass", "summary": "All swap is encrypted or in RAM",
         "detail": "/dev/zram0: zram (RAM only)"},
    ],
}

# Seeded in main(): add_rule() reads FIREWALL_MODE.
RULES = {}
PROMPTS = {}
prompt_script = {"running": False}

FIREWALL_MODE = {
    "mode": "ufw",
    "ufw": {
        "installed": True,
        "enabled_in_conf": True,
        "chains_loaded": True,
        "default_input": "drop",
        "default_output": "accept",
        "default_forward": "drop",
        "logging": "low",
        "before_rules_modified": False,
    },
    "table_loaded": True,
    "docker_protection": "ufw-docker",
}

UFW_RULES = {
    "rules": [
        {"action": "allow", "direction": "in", "protocol": "udp", "port": "53317",
         "src": "any", "dst": "any", "ipv6": False},
        {"action": "allow", "direction": "in", "protocol": "tcp", "port": "53317",
         "src": "any", "dst": "any", "ipv6": False},
        {"action": "allow", "direction": "in", "protocol": "udp", "port": "53",
         "src": "172.16.0.0/12", "dst": "172.17.0.1", "comment": "allow-docker-dns", "ipv6": False},
        {"action": "allow", "direction": "in", "protocol": "tcp", "port": "1714:1764",
         "src": "192.168.1.0/24", "dst": "any", "comment": "kdeconnect", "ipv6": False},
    ],
    "builtin": [
        "Replies to established connections are allowed",
        "Loopback traffic is allowed",
        "ufw-docker: published Docker ports are reachable from private networks only",
    ],
    "source": "user.rules",
}

PROMPT_TIMEOUT_SECS = 30
PASSPHRASE_SECS = 1.0
ALERT_EVERY_SECS = 15
next_id = {"rule": 1, "prompt": 1, "alert": 1, "threat": 1, "touch": 1, "temp": int(time.time() * 1000)}
ALERTS = []  # newest first

# Canned suspicious executions, reported in turn. "gone": the process has
# exited by the time a response comes.
EXECS = [
    {"pid": 48211, "ppid": 48190, "uid": 1000, "binary_path": "/tmp/.cache-x/update",
     "argv": ["/tmp/.cache-x/update", "--connect", "203.0.113.9:4444", "--quiet"],
     "origin": "tmp", "dropped_ms": 2300},
    {"pid": 48305, "ppid": 1, "uid": 1000, "binary_path": "memfd:payload (deleted)",
     "argv": ["[kworker/0:1]"], "origin": "memfd"},
    {"pid": 48377, "ppid": 48190, "uid": 1000, "binary_path": "/dev/shm/run.sh",
     "argv": ["/bin/sh", "/dev/shm/run.sh", "it's here"], "origin": "dev_shm", "gone": True},
]
THREATS = {}  # alert_id -> ThreatAlert, open or quarantined

YUBIKEY = {
    "token_id": "usb-3-2-7",
    "kind": "yubikey",
    "name": "YubiKey OTP+FIDO+CCID",
    "vendor_id": "1050",
    "product_id": "0407",
    "serial": "23456789",
    "capabilities": ["fido2", "piv", "openpgp", "otp"],
}
READER = {
    "token_id": "usb-1-4-3",
    "kind": "smartcard",
    "name": "AU9540 Smartcard Reader",
    "vendor_id": "058f",
    "product_id": "9540",
    "capabilities": [],
}
TOKENS = {READER["token_id"]: READER, YUBIKEY["token_id"]: YUBIKEY}
touch_script = {"running": False}
threat_gone = set()
TEMPS = {}
BLOCKED = [
    {"source": "ufw", "direction": "inbound", "protocol": "tcp", "src": "192.168.1.23",
     "dst": "192.168.1.10", "dst_port": 22, "iface": "wlan0"},
    {"source": "ufw", "direction": "inbound", "protocol": "udp", "src": "192.168.1.40",
     "dst": "192.168.1.10", "dst_port": 5000, "iface": "wlan0"},
    {"source": "ufw", "direction": "inbound", "protocol": "icmp", "src": "203.0.113.9",
     "dst": "192.168.1.10", "iface": "wlan0"},
]
ufw_imported = {"done": False}
# The first inbound allow is refused, as if the password prompt were closed.
password_script = {"refused": False}
TEMP_DURATIONS = [300, 3600, 28800]

HOME = os.environ.get("HOME", "/home/user")
USER = os.environ.get("USER", "user")
VAULTS = {v["vault_id"]: v for v in [
    {"vault_id": "notes", "name": "Notes", "backend": "gocryptfs", "mount_point": f"{HOME}/Vaults/notes",
     "mounted": False},
    {"vault_id": "work", "name": "Work documents", "backend": "gocryptfs", "mount_point": f"{HOME}/Vaults/work",
     "mounted": True},
    {"vault_id": "backup", "name": "Backup disk", "backend": "luks", "mount_point": "", "mounted": False},
]}
VAULT_BUSY = {"work"}
vault_script = {"backup_cancelled": False}
MOUNTING = {}  # vault_id -> Event set by VAULT_PANIC while the passphrase is asked for

TOPICS = {"system", "threat", "usbguard", "token", "vault", "firewall", "posture"}


def error(code, message):
    return {"code": code, "message": message}


class Client:
    def __init__(self, writer):
        self.writer = writer
        self.hello = False
        self.topics = set()

    def send(self, message):
        self.writer.write((json.dumps(message, separators=(",", ":")) + "\n").encode())

    def event(self, topic, name, params):
        if topic in self.topics:
            self.send({"jsonrpc": "2.0", "method": name, "params": params})


clients = set()


def usb_key(device):
    return (device["vendor_id"], device["product_id"], device["serial"])


def usb_plug_in():
    if DRIVE["device_id"] in DEVICES:
        return
    device = {**DRIVE, "rule": "allow" if usb_key(DRIVE) in SAVED_DEVICES else "block"}
    DEVICES[device["device_id"]] = device
    broadcast("usbguard", "USB_DEVICE_PRESENTED", device)


def usb_remove(device_id):
    if DEVICES.pop(device_id, None) is not None:
        broadcast("usbguard", "USB_DEVICE_REMOVED", {"device_id": device_id})


def usb_toggle_drive():
    if DRIVE["device_id"] in DEVICES:
        usb_remove(DRIVE["device_id"])
    else:
        usb_plug_in()


def threat_exec(tick=[0]):
    spec = EXECS[tick[0] % len(EXECS)]
    tick[0] += 1
    now = now_ms()
    alert = {"alert_id": next_id["threat"], "pid": spec["pid"] + tick[0], "ppid": spec["ppid"],
             "uid": spec["uid"], "start_time": 123456 + tick[0], "binary_path": spec["binary_path"],
             "argv": spec["argv"], "origin": spec["origin"], "detected_at": now, "state": "open"}
    if "dropped_ms" in spec:
        alert["dropped_at"] = now - spec["dropped_ms"]
    next_id["threat"] += 1
    THREATS[alert["alert_id"]] = alert
    if spec.get("gone"):
        threat_gone.add(alert["alert_id"])
    broadcast("threat", "THREAT_EXEC_DETECTED", alert)


def threat_resolve(alert_id, state):
    alert = THREATS.pop(alert_id, None)
    if alert is None:
        return None
    broadcast("threat", "THREAT_ALERT_RESOLVED", {"alert_id": alert_id, "state": state})
    return {**alert, "state": state}


def threat_act(method, params):
    """The daemon's rules (docs/ipc-protocol.md §4.2), without signals."""
    if method == "THREAT_KILL_PROCESS" and params.get("signal") not in (9, 15):
        return None, error(-32602, "invalid params: signal must be 15 or 9")
    alert = THREATS.get(params.get("alert_id"))
    if alert is None:
        return None, error(-32003, f"no open alert with id {params.get('alert_id')}")
    if alert["pid"] != params.get("pid"):
        return None, error(-32003, f"alert {alert['alert_id']} is not about pid {params.get('pid')}")
    need = {"THREAT_QUARANTINE_PROCESS": "open", "THREAT_DISMISS_ALERT": "open",
            "THREAT_RESUME_PROCESS": "quarantined"}.get(method)
    if need and alert["state"] != need:
        return None, error(-32602, f"alert {alert['alert_id']} is {alert['state']}")
    if method == "THREAT_DISMISS_ALERT":
        return threat_resolve(alert["alert_id"], "dismissed"), None
    if alert["alert_id"] in threat_gone:
        threat_resolve(alert["alert_id"], "exited")
        return None, error(-32005, f"process {alert['pid']} has exited")
    if method == "THREAT_KILL_PROCESS":
        return threat_resolve(alert["alert_id"], "killed"), None
    alert["state"] = "quarantined" if method == "THREAT_QUARANTINE_PROCESS" else "open"
    return dict(alert), None


def touch_request(source):
    """TOKEN_TOUCH_REQUESTED as the daemon words it; returns the request_id."""
    request_id = next_id["touch"]
    next_id["touch"] += 1
    name = YUBIKEY["name"]
    description = {"ssh": f"SSH is waiting for a touch on {name}",
                   "gpg": f"GnuPG is waiting for a touch on {name}"}.get(source, f"{name} is waiting for a touch")
    broadcast("token", "TOKEN_TOUCH_REQUESTED", {"request_id": request_id, "token_id": YUBIKEY["token_id"],
                                                 "source": source, "description": description})
    return request_id


def touch_complete(request_id, outcome):
    broadcast("token", "TOKEN_TOUCH_COMPLETED", {"request_id": request_id, "outcome": outcome})


def token_unplug():
    if TOKENS.pop(YUBIKEY["token_id"], None) is not None:
        broadcast("token", "TOKEN_REMOVED", {"token_id": YUBIKEY["token_id"]})


def token_plug_in():
    if YUBIKEY["token_id"] not in TOKENS:
        TOKENS[YUBIKEY["token_id"]] = YUBIKEY
        broadcast("token", "TOKEN_INSERTED", YUBIKEY)


async def touch_sequence():
    """Touched, timed out, then ended by unplugging the key."""
    touch_script["running"] = True
    try:
        await asyncio.sleep(1)
        request_id = touch_request("fido2")
        await asyncio.sleep(1)
        touch_complete(request_id, "touched")
        await asyncio.sleep(0.5)
        request_id = touch_request("gpg")
        await asyncio.sleep(1)
        touch_complete(request_id, "timed_out")
        await asyncio.sleep(0.5)
        touch_request("ssh")
        await asyncio.sleep(1)
        token_unplug()
        await asyncio.sleep(0.5)
        token_plug_in()
    finally:
        touch_script["running"] = False


def touch_later():
    """SIGPROF: a FIDO2 request that is touched after 8 s."""
    token_plug_in()
    request_id = touch_request("fido2")
    asyncio.get_running_loop().call_later(8, touch_complete, request_id, "touched")


def broadcast(topic, name, params):
    for client in list(clients):
        client.event(topic, name, params)


def resolve_prompt(request_id, verdict, decided_by):
    if PROMPTS.pop(request_id, None) is None:
        return False
    broadcast("firewall", "FIREWALL_CONNECTION_RESOLVED",
              {"request_id": request_id, "verdict": verdict, "decided_by": decided_by})
    return True


def apply_mode(mode):
    """Sets FIREWALL_MODE as the daemon reports `mode`."""
    ufw_on = mode in ("ufw", "both")
    FIREWALL_MODE["mode"] = mode
    FIREWALL_MODE.pop("detail", None)
    FIREWALL_MODE["ufw"]["enabled_in_conf"] = ufw_on or mode == "unknown"
    if mode == "unknown":
        # Only what the daemon reads itself.
        FIREWALL_MODE["ufw"].pop("chains_loaded", None)
        FIREWALL_MODE["ufw"].pop("before_rules_modified", None)
        FIREWALL_MODE.pop("table_loaded", None)
        FIREWALL_MODE["docker_protection"] = "ufw-docker"
        FIREWALL_MODE["detail"] = "cannot reach the privileged helper"
    else:
        FIREWALL_MODE["ufw"]["chains_loaded"] = ufw_on
        FIREWALL_MODE["ufw"]["before_rules_modified"] = False
        FIREWALL_MODE["table_loaded"] = mode != "none"
        FIREWALL_MODE["docker_protection"] = "ufw-docker" if mode == "ufw" else "none" if mode == "none" else "omarchy"
    for rule in RULES.values():
        rule["loaded"] = "executable" in rule or mode in ("standalone", "both")


def toggle_firewall_mode():
    """What `sudo ufw disable` / `enable` outside the hub looks like."""
    apply_mode("none" if FIREWALL_MODE["mode"] == "ufw" else "ufw")
    broadcast("firewall", "FIREWALL_MODE_CHANGED", FIREWALL_MODE)


def refuse_first_password(spec):
    """PERMISSION_DENIED for the first inbound allow, then nothing."""
    if spec.get("verdict") == "allow" and spec.get("direction") == "inbound" and "executable" not in spec \
            and not password_script["refused"]:
        password_script["refused"] = True
        return error(-32004, "not authorized: the password prompt was dismissed")
    return None


def connection_prompt(executable="/usr/bin/curl", address="192.0.2.1", port=443, pid=4242):
    request_id = next_id["prompt"]
    next_id["prompt"] += 1
    prompt = {
        "request_id": request_id,
        "pid": pid,
        "executable": executable,
        "protocol": "tcp",
        "address": address,
        "port": port,
        "expires_at": int(time.time() * 1000) + PROMPT_TIMEOUT_SECS * 1000,
    }
    PROMPTS[request_id] = prompt
    broadcast("firewall", "FIREWALL_CONNECTION_PROMPT", prompt)
    asyncio.get_running_loop().call_later(
        PROMPT_TIMEOUT_SECS, resolve_prompt, request_id, "block", "timeout")


async def prompt_sequence():
    """A git push over SSH, then firefox, each held for an answer."""
    prompt_script["running"] = True
    try:
        await asyncio.sleep(1)
        connection_prompt("/usr/bin/git", "140.82.112.3", 22, 51022)
        await asyncio.sleep(0.3)
        connection_prompt("/usr/lib/firefox/firefox", "203.0.113.50", 443, 3310)
        await asyncio.sleep(PROMPT_TIMEOUT_SECS + 1)
    finally:
        prompt_script["running"] = False


def now_ms():
    return int(time.time() * 1000)


def record_alert(tick=[0]):
    """One canned blocked packet, grouped with an alert of the same kind
    from the last 600 s."""
    packet = BLOCKED[tick[0] % len(BLOCKED)]
    tick[0] += 1
    now = now_ms()
    for alert in ALERTS:
        same = all(alert.get(k) == packet.get(k) for k in ("source", "direction", "protocol", "src", "dst_port"))
        if same and now - alert["first_seen"] < 600_000:
            alert["count"] += 1
            alert["last_seen"] = now
            broadcast("firewall", "FIREWALL_ALERT", alert)
            return
    alert = {"alert_id": next_id["alert"], **packet, "count": 1, "first_seen": now, "last_seen": now}
    next_id["alert"] += 1
    ALERTS.insert(0, alert)
    del ALERTS[500:]
    broadcast("firewall", "FIREWALL_ALERT", alert)


async def alert_stream(every):
    while True:
        await asyncio.sleep(every)
        record_alert()


def temp_backend(spec):
    mode = FIREWALL_MODE["mode"]
    if mode in ("none", "unknown"):
        return None
    if mode in ("ufw", "both") and spec["verdict"] == "allow" and spec["direction"] == "inbound":
        return "ufw"
    return "table"


def temps_changed():
    broadcast("firewall", "FIREWALL_TEMP_CHANGED", {"decisions": list(TEMPS.values())})


def expire_temp(temp_id):
    if TEMPS.pop(temp_id, None) is not None:
        temps_changed()


def temp_add(params):
    spec, secs = params.get("spec"), params.get("duration_secs")
    if not isinstance(spec, dict) or spec.get("verdict") not in ("allow", "block") \
            or spec.get("direction") not in ("inbound", "outbound") or not isinstance(spec.get("address"), str) \
            or "executable" in spec or ("port" in spec and "protocol" not in spec):
        return None, error(-32602, "invalid params: spec")
    if not isinstance(secs, int) or not 60 <= secs <= 86400:
        return None, error(-32602, "invalid params: duration_secs must be 60-86400")
    backend = temp_backend(spec)
    if backend is None:
        return None, {**error(-32009, "no firewall is active; turn one on first"),
                      "data": {"mode": FIREWALL_MODE["mode"]}}
    refused = refuse_first_password(spec)
    if refused:
        return None, refused
    for old in [t for t in TEMPS.values() if t["spec"] == spec]:
        TEMPS.pop(old["temp_id"])
    now = now_ms()
    decision = {"temp_id": next_id["temp"], "spec": spec, "backend": backend,
                "created_at": now, "expires_at": now + secs * 1000}
    if "alert_id" in params:
        decision["alert_id"] = params["alert_id"]
    next_id["temp"] += 1
    TEMPS[decision["temp_id"]] = decision
    asyncio.get_running_loop().call_later(secs, expire_temp, decision["temp_id"])
    temps_changed()
    return decision, None


def add_rule(spec):
    # Like the daemon: in ufw mode only executable rules are enforced.
    loaded = "executable" in spec or FIREWALL_MODE["mode"] in ("standalone", "both")
    rule = {"rule_id": next_id["rule"], **spec, "loaded": loaded}
    next_id["rule"] += 1
    RULES[rule["rule_id"]] = rule
    return rule


def set_mode(params):
    """FIREWALL_SET_MODE: switches at once; the first switch to standalone
    imports UFW_RULES as the daemon would. `dry_run` changes nothing."""
    mode = params.get("mode")
    if mode not in ("ufw", "standalone") or set(params) - {"mode", "import_ufw_rules", "dry_run"}:
        return None, error(-32602, "invalid params: mode")
    dry = params.get("dry_run") is True
    if FIREWALL_MODE["mode"] == "unknown" and not dry:
        return None, error(-32006, "the privileged helper is not running")
    imported, not_imported = [], []
    want = params.get("import_ufw_rules")
    importing = mode == "standalone" and (want or (want is None and not ufw_imported["done"]))
    if importing:
        for rule in UFW_RULES["rules"]:
            if not rule["port"].isdigit():
                not_imported.append({"from": rule, "reason": "port ranges and lists cannot be expressed"})
                continue
            spec = {"verdict": "allow", "direction": "inbound", "address": rule["src"]
                    if rule["src"] != "any" else "0.0.0.0/0", "port": int(rule["port"]),
                    "protocol": rule["protocol"]}
            if any({k: r.get(k) for k in spec} == spec for r in RULES.values()):
                continue
            notes = [] if rule["dst"] == "any" else [
                f"not limited to the local address {rule['dst']}: hub rules match the remote address only"]
            new = {"rule_id": 0, **spec, "loaded": True} if dry else add_rule(spec)
            imported.append({"rule": new, "from": rule, "notes": notes})
    result = dict(FIREWALL_MODE)
    if imported:
        result["imported"] = imported
    if not_imported:
        result["not_imported"] = not_imported
    if dry:
        return result, None
    if importing:
        ufw_imported["done"] = True
    apply_mode(mode)
    for decision in TEMPS.values():
        decision["backend"] = temp_backend(decision["spec"]) or decision["backend"]
    if TEMPS:
        temps_changed()
    broadcast("firewall", "FIREWALL_MODE_CHANGED", FIREWALL_MODE)
    return {**result, **FIREWALL_MODE}, None


class Deferred:
    """A reply that comes later; `coro` returns (result, error)."""

    def __init__(self, coro):
        self.coro = coro


def vault_changed(vault):
    broadcast("vault", "VAULT_STATE_CHANGED", dict(vault))


def vault_set(vault, mounted):
    vault["mounted"] = mounted
    if vault["backend"] == "luks":
        vault["mount_point"] = f"/run/media/{USER}/{vault['vault_id']}" if mounted else ""
    vault_changed(vault)


async def vault_mount(vault, panicked):
    """Stands for pinentry: the user types the passphrase."""
    vault_id = vault["vault_id"]
    try:
        await asyncio.wait_for(panicked.wait(), PASSPHRASE_SECS)
        return None, error(-32008, "panic mode ran while the passphrase was asked for")
    except asyncio.TimeoutError:
        pass
    finally:
        MOUNTING.pop(vault_id, None)
    if vault_id == "backup" and not vault_script["backup_cancelled"]:
        vault_script["backup_cancelled"] = True
        return None, error(-32008, "passphrase prompt was cancelled")
    if not vault["mounted"]:
        vault_set(vault, True)
    return dict(vault), None


def vault_unmount(vault):
    if not vault["mounted"]:
        return dict(vault), None
    if vault["vault_id"] in VAULT_BUSY:
        detail = (f"fusermount3 -u failed: fusermount3: failed to unmount {vault['mount_point']}: "
                  "Device or resource busy")
        return None, {**error(-32006, detail), "data": {"detail": detail}}
    vault_set(vault, False)
    return dict(vault), None


def vault_panic():
    for panicked in list(MOUNTING.values()):
        panicked.set()
    unmounted, lazy = [], []
    for vault in VAULTS.values():
        if vault["mounted"]:
            unmounted.append(vault["vault_id"])
            if vault["vault_id"] in VAULT_BUSY:
                lazy.append(vault["vault_id"])
            vault_set(vault, False)
    return {"unmounted": unmounted, "lazy": lazy, "failed": []}


VAULT_ID = re.compile(r"[a-z0-9-]{1,64}")


def vault_check(params, keys):
    """The checks VAULT_ADD and VAULT_CREATE share: the new vault, or an error."""
    unknown = set(params) - keys
    if unknown:
        return None, error(-32602, f"invalid params: unknown field `{sorted(unknown)[0]}`")
    vault_id, backend, mount_point = params.get("vault_id"), params.get("backend"), params.get("mount_point")
    if not isinstance(vault_id, str) or not VAULT_ID.fullmatch(vault_id):
        return None, error(-32602, f"invalid params: vault id '{vault_id}' must be 1 to 64 characters of a-z, 0-9 and -")
    if vault_id in VAULTS:
        return None, error(-32602, f"invalid params: vault id '{vault_id}' is defined twice")
    if not str(params.get("name") or "").strip():
        return None, error(-32602, f"invalid params: vault '{vault_id}': name is empty")
    if backend not in ("gocryptfs", "luks"):
        return None, error(-32602, f"invalid params: unknown variant `{backend}`")
    for key in ("source", "mount_point"):
        path = params.get(key)
        if path is not None and not (isinstance(path, str) and (path.startswith("/") or path.startswith("~/"))):
            return None, error(-32602, f"invalid params: vault '{vault_id}': {key} {path} must be absolute or start with ~/")
    if backend == "gocryptfs" and mount_point is None:
        return None, error(-32602, f"invalid params: vault '{vault_id}': a gocryptfs vault needs mount_point")
    if backend == "luks" and mount_point is not None:
        return None, error(-32602, f"invalid params: vault '{vault_id}': mount_point is for gocryptfs only; udisks2 chooses it for luks")
    def expand(path):
        return HOME + path[1:] if path and path.startswith("~/") else path or ""
    if backend == "gocryptfs" and any(v["mount_point"] == expand(mount_point) for v in VAULTS.values()):
        return None, error(-32602, f"invalid params: vault '{vault_id}': mount_point {expand(mount_point)} is used by another vault")
    return {"vault_id": vault_id, "name": params["name"], "backend": backend,
            "mount_point": expand(mount_point), "mounted": False}, None


def vault_add(params):
    """The daemon's VAULT_ADD, without the file or the source check."""
    vault, err = vault_check(params, {"vault_id", "name", "backend", "source", "mount_point"})
    if err:
        return None, err
    VAULTS[vault["vault_id"]] = vault
    vault_changed(vault)
    return dict(vault), None


def vault_create_start(params):
    """VAULT_CREATE up to the passphrase prompt; the rest is deferred."""
    if "backend" in params:
        return None, error(-32602, "invalid params: unknown field `backend`")
    if not isinstance(params.get("mount_point"), str):
        return None, error(-32602, "invalid params: missing field `mount_point`")
    vault, err = vault_check({**params, "backend": "gocryptfs"},
                             {"vault_id", "name", "backend", "source", "mount_point"})
    if err:
        return None, err
    if vault["vault_id"] in MOUNTING:
        return None, error(-32602, f"invalid params: vault id '{vault['vault_id']}' is defined twice")
    panicked = MOUNTING.setdefault(vault["vault_id"], asyncio.Event())
    return Deferred(vault_create(vault, params["source"], panicked)), None


async def vault_create(vault, source, panicked):
    """Stands for the new passphrase's prompt, then `gocryptfs -init`."""
    try:
        await asyncio.wait_for(panicked.wait(), PASSPHRASE_SECS)
        return None, error(-32008, "panic mode ran while the passphrase was asked for")
    except asyncio.TimeoutError:
        pass
    finally:
        MOUNTING.pop(vault["vault_id"], None)
    if "cancel" in source:
        return None, error(-32008, "passphrase prompt was cancelled")
    VAULTS[vault["vault_id"]] = vault
    vault_changed(vault)
    return dict(vault), None


def vault_remove(params):
    vault = VAULTS.get(params.get("vault_id"))
    if vault is None:
        return None, error(-32003, f"no vault with id '{params.get('vault_id')}'")
    if vault["mounted"]:
        message = f"vault '{vault['vault_id']}' is mounted; unmount it first"
        return None, {**error(-32006, message), "data": {"detail": message}}
    del VAULTS[vault["vault_id"]]
    broadcast("vault", "VAULT_REMOVED", {"vault_id": vault["vault_id"]})
    return {}, None


sandbox_pids = {"next": 52000}


def sandbox_file(what, path):
    """The daemon's existing_file(): an error message, or None."""
    if not isinstance(path, str) or not path.startswith("/"):
        return f"invalid params: {what} must be an absolute path"
    try:
        real = os.path.realpath(path, strict=True)
    except OSError as e:
        return f"invalid params: {what} {path}: {e.strerror} (os error {e.errno})"
    if not os.path.isfile(real):
        return f"invalid params: {what} {path} is not a regular file"
    return None


def sandbox_run(params):
    unknown = set(params) - {"executable", "args", "target_file", "share_net"}
    if unknown:
        return None, error(-32602, f"invalid params: unknown field `{sorted(unknown)[0]}`")
    args = params.get("args", [])
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args) \
            or not isinstance(params.get("share_net", False), bool):
        return None, error(-32602, "invalid params: args and share_net")
    executable = params.get("executable")
    problem = sandbox_file("executable", executable)
    if problem is None and not os.access(os.path.realpath(executable), os.X_OK):
        problem = f"invalid params: {executable} is not executable"
    if problem is None and params.get("target_file") is not None:
        problem = sandbox_file("target_file", params["target_file"])
    if problem:
        return None, error(-32602, problem)
    sandbox_pids["next"] += 1
    return {"pid": sandbox_pids["next"]}, None


def vault_toggle_outside():
    vault = VAULTS["notes"]
    vault_set(vault, not vault["mounted"])


def handle(client, method, params):
    """Returns (result, error); exactly one is None."""
    if method != "HELLO" and not client.hello:
        return None, error(-32000, "send HELLO first")
    if method == "HELLO":
        if params.get("protocol_version") != PROTOCOL_VERSION:
            return None, {**error(-32001, "unsupported protocol version"), "data": {"supported": [1]}}
        client.hello = True
        return {"protocol_version": 1, "daemon_version": "0.0.0-mock", "modules": MODULES}, None
    if method == "PING":
        return {}, None
    if method == "GET_STATUS":
        return {"protocol_version": 1, "daemon_version": "0.0.0-mock", "uptime_secs": 0, "modules": MODULES}, None
    if method == "SUBSCRIBE":
        topics = params.get("topics")
        if not isinstance(topics, list) or not set(topics) <= TOPICS:
            return None, error(-32602, "invalid params: topics")
        client.topics = set(topics)
        if "usbguard" in client.topics:
            asyncio.get_running_loop().call_later(3, usb_plug_in)
        if "threat" in client.topics and not THREATS:
            asyncio.get_running_loop().call_later(1, threat_exec)
            asyncio.get_running_loop().call_later(1.5, threat_exec)
            asyncio.get_running_loop().call_later(2, threat_exec)
        if "firewall" in client.topics and not prompt_script["running"]:
            prompt_script["task"] = asyncio.get_running_loop().create_task(prompt_sequence())
        if "token" in client.topics and not touch_script["running"]:
            # Keep a reference: the loop holds tasks only weakly.
            touch_script["task"] = asyncio.get_running_loop().create_task(touch_sequence())
        return {"topics": topics}, None
    if method == "USBGUARD_LIST_DEVICES":
        return {"devices": list(DEVICES.values())}, None
    if method == "USBGUARD_SET_POLICY":
        device = DEVICES.get(params.get("device_id"))
        if device is None:
            return None, error(-32003, "no USB device with that id")
        if params.get("target") not in ("allow", "block", "reject"):
            return None, error(-32602, "invalid params: target")
        device["rule"] = params["target"]
        permanent = bool(params.get("permanent", False))
        if permanent and device["rule"] == "allow":
            SAVED_DEVICES.add(usb_key(device))
        elif permanent:
            SAVED_DEVICES.discard(usb_key(device))
        broadcast("usbguard", "USB_DEVICE_POLICY_CHANGED",
                  {"device_id": device["device_id"], "target": device["rule"], "permanent": permanent})
        if device["rule"] == "reject":
            usb_remove(device["device_id"])
        return dict(device), None
    if method == "TOKEN_LIST":
        return {"tokens": list(TOKENS.values())}, None
    if method == "THREAT_LIST_ALERTS":
        return {"alerts": list(THREATS.values())}, None
    if method in ("THREAT_KILL_PROCESS", "THREAT_QUARANTINE_PROCESS", "THREAT_RESUME_PROCESS",
                  "THREAT_DISMISS_ALERT"):
        return threat_act(method, params)
    if method == "FIREWALL_LIST_RULES":
        return {"rules": list(RULES.values())}, None
    if method == "FIREWALL_ADD_RULE":
        if params.get("verdict") not in ("allow", "block") or params.get("direction") not in ("inbound", "outbound") \
                or not isinstance(params.get("address"), str):
            return None, error(-32602, "invalid params: rule")
        if params["verdict"] == "allow" and params["direction"] == "inbound" and "executable" not in params \
                and FIREWALL_MODE["mode"] in ("ufw", "both"):
            return None, {**error(-32009, "ufw is active and decides inbound traffic, so this allow "
                                          "would have no effect"),
                          "data": {"mode": FIREWALL_MODE["mode"]}}
        refused = refuse_first_password(params)
        if refused:
            return None, refused
        return add_rule(params), None
    if method == "FIREWALL_REMOVE_RULE":
        if RULES.pop(params.get("rule_id"), None) is None:
            return None, error(-32003, "no firewall rule with that id")
        return {}, None
    if method == "FIREWALL_DECIDE":
        verdict, scope = params.get("verdict"), params.get("scope")
        if verdict not in ("allow", "block") or scope not in ("once", "process", "always"):
            return None, error(-32602, "invalid params: verdict or scope")
        prompt = PROMPTS.get(params.get("request_id"))
        if prompt is None or not resolve_prompt(prompt["request_id"], verdict, "user"):
            return None, error(-32003, "no pending connection prompt with that id")
        if scope == "always":
            spec = {"verdict": verdict, "direction": "outbound", "address": prompt["address"],
                    "port": prompt["port"], "protocol": prompt["protocol"],
                    "executable": prompt["executable"]}
            if not any({k: r.get(k) for k in spec} == spec for r in RULES.values()):
                add_rule(spec)
        return {}, None
    if method == "FIREWALL_GET_MODE":
        return FIREWALL_MODE, None
    if method == "FIREWALL_SET_MODE":
        return set_mode(params)
    if method == "FIREWALL_UFW_RULES":
        rules = [r for r in UFW_RULES["rules"]]
        for t in TEMPS.values():
            if t["backend"] == "ufw":
                spec = t["spec"]
                rule = {"action": "allow", "direction": "in", "protocol": spec.get("protocol", "any"),
                        "src": spec["address"], "dst": "any", "ipv6": ":" in spec["address"],
                        "comment": f"omarchy-security:tmp:{t['temp_id']}:{t['created_at'] // 1000}:{t['expires_at'] // 1000}",
                        "temp_id": t["temp_id"], "expires_at": t["expires_at"]}
                if "port" in spec:
                    rule["port"] = str(spec["port"])
                rules.insert(0, rule)
        return {**UFW_RULES, "rules": rules}, None
    if method == "FIREWALL_ALERT_LIST":
        limit = params.get("limit")
        return {"alerts": ALERTS[:limit] if isinstance(limit, int) else ALERTS}, None
    if method == "FIREWALL_ALERT_MUTE":
        secs = params.get("duration_secs")
        if not isinstance(secs, int) or not 60 <= secs <= 86400:
            return None, error(-32602, "invalid params: duration_secs must be 60-86400")
        alert = next((a for a in ALERTS if a["alert_id"] == params.get("alert_id")), None)
        if alert is None:
            return None, error(-32003, "no firewall alert with that id")
        alert["muted_until"] = now_ms() + secs * 1000
        broadcast("firewall", "FIREWALL_ALERT", alert)
        return {}, None
    if method == "FIREWALL_TEMP_ADD":
        return temp_add(params)
    if method == "FIREWALL_TEMP_LIST":
        return {"decisions": list(TEMPS.values()), "durations_secs": TEMP_DURATIONS}, None
    if method == "FIREWALL_TEMP_REMOVE":
        if TEMPS.pop(params.get("temp_id"), None) is None:
            return None, error(-32003, "no temporary decision with that id")
        temps_changed()
        return {}, None
    if method in ("VAULT_MOUNT", "VAULT_UNMOUNT"):
        vault = VAULTS.get(params.get("vault_id"))
        if vault is None:
            return None, error(-32003, f"no vault with id '{params.get('vault_id')}'")
        if method == "VAULT_UNMOUNT":
            return vault_unmount(vault)
        if vault["mounted"]:
            return dict(vault), None
        # Registered now, so that a VAULT_PANIC right behind it cancels it.
        panicked = MOUNTING.setdefault(vault["vault_id"], asyncio.Event())
        return Deferred(vault_mount(vault, panicked)), None
    if method == "VAULT_LIST":
        return {"vaults": [dict(v) for v in VAULTS.values()]}, None
    if method == "VAULT_PANIC":
        return vault_panic(), None
    if method == "VAULT_ADD":
        return vault_add(params)
    if method == "VAULT_REMOVE":
        return vault_remove(params)
    if method == "VAULT_CREATE":
        return vault_create_start(params)
    if method == "SANDBOX_RUN":
        return sandbox_run(params)
    if method == "POSTURE_GET_REPORT":
        return POSTURE, None
    if method == "POSTURE_REFRESH":
        POSTURE["evaluated_at"] = now_ms()
        return POSTURE, None
    return None, error(-32007, f"{method} is not implemented by the mock")


deferred = set()


async def reply_later(client, request_id, coro):
    result, err = await coro
    reply = {"jsonrpc": "2.0", "id": request_id}
    reply["error" if err else "result"] = err or result
    if client in clients:
        client.send(reply)


async def serve(reader, writer):
    client = Client(writer)
    clients.add(client)
    try:
        while True:
            try:
                line = await reader.readuntil(b"\n")
            except asyncio.LimitOverrunError:
                break
            except (asyncio.IncompleteReadError, ConnectionResetError):
                break
            try:
                msg = json.loads(line)
            except ValueError as e:
                client.send({"jsonrpc": "2.0", "id": None, "error": error(-32700, f"parse error: {e}")})
                continue
            if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "id" not in msg or "method" not in msg:
                client.send({"jsonrpc": "2.0", "id": msg.get("id") if isinstance(msg, dict) else None,
                             "error": error(-32600, "invalid request")})
                continue
            result, err = handle(client, msg["method"], msg.get("params") or {})
            if isinstance(result, Deferred):
                # Answered later; other requests go on meanwhile, as with
                # the daemon. The loop holds tasks only weakly.
                task = asyncio.get_running_loop().create_task(reply_later(client, msg["id"], result.coro))
                deferred.add(task)
                task.add_done_callback(deferred.discard)
                continue
            reply = {"jsonrpc": "2.0", "id": msg["id"]}
            reply["error" if err else "result"] = err or result
            client.send(reply)
            await writer.drain()
    finally:
        clients.discard(client)
        writer.close()


async def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    default = os.environ.get("OMARCHY_SECURITYD_SOCKET") or (
        os.path.join(os.environ["XDG_RUNTIME_DIR"], "omarchy-security", "securityd.sock")
        if os.environ.get("XDG_RUNTIME_DIR") else None)
    parser.add_argument("--socket", default=default)
    parser.add_argument("--alert-every", type=float, default=ALERT_EVERY_SECS, metavar="SECS",
                        help="seconds between canned blocked packets (default %(default)s)")
    parser.add_argument("--prompt-timeout", type=float, default=PROMPT_TIMEOUT_SECS, metavar="SECS",
                        help="seconds before an unanswered connection prompt is blocked (default %(default)s)")
    parser.add_argument("--passphrase-delay", type=float, default=PASSPHRASE_SECS, metavar="SECS",
                        help="seconds VAULT_MOUNT waits, standing for pinentry (default %(default)s)")
    parser.add_argument("--mode", default="ufw", choices=["ufw", "standalone", "both", "none", "unknown"],
                        help="the firewall mode to start in (default %(default)s)")
    args = parser.parse_args()
    globals()["PROMPT_TIMEOUT_SECS"] = args.prompt_timeout
    globals()["PASSPHRASE_SECS"] = args.passphrase_delay
    POSTURE["evaluated_at"] = now_ms()
    add_rule({"verdict": "block", "direction": "outbound", "address": "198.51.100.0/24"})
    add_rule({"verdict": "allow", "direction": "outbound", "address": "192.0.2.1", "port": 443,
              "protocol": "tcp", "executable": "/usr/bin/curl"})
    apply_mode(args.mode)
    if not args.socket:
        sys.exit("XDG_RUNTIME_DIR is not set; pass --socket")

    os.makedirs(os.path.dirname(args.socket), mode=0o700, exist_ok=True)
    if os.path.exists(args.socket):
        os.unlink(args.socket)
    old_umask = os.umask(0o177)
    try:
        server = await asyncio.start_unix_server(serve, path=args.socket, limit=MAX_FRAME_BYTES + 1)
    finally:
        os.umask(old_umask)

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGUSR1, usb_toggle_drive)
    loop.add_signal_handler(signal.SIGUSR2, connection_prompt)
    loop.add_signal_handler(signal.SIGHUP, toggle_firewall_mode)
    loop.add_signal_handler(signal.SIGALRM, threat_exec)
    loop.add_signal_handler(signal.SIGPROF, touch_later)
    loop.add_signal_handler(signal.SIGVTALRM, vault_toggle_outside)
    alerts = asyncio.create_task(alert_stream(args.alert_every))
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    print(f"mock-securityd listening on {args.socket}", file=sys.stderr)
    async with server:
        await stop.wait()
    alerts.cancel()
    # Python 3.13+ removes the socket file when the server closes.
    if os.path.exists(args.socket):
        os.unlink(args.socket)


if __name__ == "__main__":
    asyncio.run(main())
