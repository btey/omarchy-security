#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stand-in for omarchy-securityd that speaks protocol v1 with canned data.

Lets the QuickShell plugin be developed before the daemon's modules exist.
It listens on the same socket path the plugin resolves, so run the real
daemon or this, not both.

    tools/mock-securityd.py [--socket PATH]

Every connected, subscribed client gets a USB_DEVICE_PRESENTED event a few
seconds after subscribing, and again on each SIGUSR1. Each SIGUSR2 sends a
FIREWALL_CONNECTION_PROMPT, which FIREWALL_DECIDE answers and which
otherwise times out after PROMPT_TIMEOUT_SECS. Each SIGHUP switches the
firewall mode between "ufw" and "none" and sends FIREWALL_MODE_CHANGED;
FIREWALL_SET_MODE switches at once, without a password. Every
ALERT_EVERY_SECS a canned blocked packet is recorded and sent as
FIREWALL_ALERT (repeats are grouped, as the daemon does). FIREWALL_TEMP_*
keep temporary decisions in memory, choose the backend from the mode, and
send FIREWALL_TEMP_CHANGED; they expire on time.
"""

import argparse
import asyncio
import json
import os
import signal
import sys
import time

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 64 * 1024

MODULES = [
    {"module": "threat", "state": "not_implemented"},
    {"module": "usbguard", "state": "active"},
    {"module": "token", "state": "not_implemented"},
    {"module": "vault", "state": "not_implemented"},
    {"module": "firewall", "state": "active"},
    {"module": "sandbox", "state": "not_implemented"},
    {"module": "posture", "state": "degraded", "detail": "mock data"},
]

DEVICES = {
    14: {
        "device_id": 14,
        "name": "Mass Storage Device",
        "vendor_id": "0951",
        "product_id": "1666",
        "serial": "00187D0F2E3B",
        "rule": "block",
        "interface_class": "08",
    }
}

POSTURE = {
    "overall": "warn",
    "evaluated_at": 0,
    "checks": [
        {"check_id": "lsm", "status": "warn", "summary": "No LSM enforcing (mock)"},
        {"check_id": "ptrace_scope", "status": "pass", "summary": "ptrace_scope = 1"},
        {"check_id": "docker_group", "status": "pass", "summary": "Not in docker group"},
        {"check_id": "swap_encryption", "status": "unknown", "summary": "No swap"},
    ],
}

RULES = {}
PROMPTS = {}

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
    ],
    "builtin": [
        "Replies to established connections are allowed",
        "Loopback traffic is allowed",
        "ufw-docker: published Docker ports are reachable from private networks only",
    ],
    "source": "user.rules",
}

PROMPT_TIMEOUT_SECS = 30
ALERT_EVERY_SECS = 15
next_id = {"rule": 1, "prompt": 1, "alert": 1, "temp": int(time.time() * 1000)}
ALERTS = []  # newest first
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


def usb_presented():
    for client in list(clients):
        client.event("usbguard", "USB_DEVICE_PRESENTED", DEVICES[14])


def broadcast(topic, name, params):
    for client in list(clients):
        client.event(topic, name, params)


def resolve_prompt(request_id, verdict, decided_by):
    if PROMPTS.pop(request_id, None) is None:
        return False
    broadcast("firewall", "FIREWALL_CONNECTION_RESOLVED",
              {"request_id": request_id, "verdict": verdict, "decided_by": decided_by})
    return True


def toggle_firewall_mode():
    """What `sudo ufw disable` / `enable` outside the hub looks like."""
    on = FIREWALL_MODE["mode"] != "ufw"
    FIREWALL_MODE["mode"] = "ufw" if on else "none"
    FIREWALL_MODE["ufw"]["enabled_in_conf"] = on
    FIREWALL_MODE["ufw"]["chains_loaded"] = on
    FIREWALL_MODE["docker_protection"] = "ufw-docker" if on else "none"
    broadcast("firewall", "FIREWALL_MODE_CHANGED", FIREWALL_MODE)


def connection_prompt():
    request_id = next_id["prompt"]
    next_id["prompt"] += 1
    prompt = {
        "request_id": request_id,
        "pid": 4242,
        "executable": "/usr/bin/curl",
        "protocol": "tcp",
        "address": "192.0.2.1",
        "port": 443,
        "expires_at": int(time.time() * 1000) + PROMPT_TIMEOUT_SECS * 1000,
    }
    PROMPTS[request_id] = prompt
    broadcast("firewall", "FIREWALL_CONNECTION_PROMPT", prompt)
    asyncio.get_running_loop().call_later(
        PROMPT_TIMEOUT_SECS, resolve_prompt, request_id, "block", "timeout")


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


async def alert_stream():
    while True:
        await asyncio.sleep(ALERT_EVERY_SECS)
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
    imports UFW_RULES as the daemon would."""
    mode = params.get("mode")
    if mode not in ("ufw", "standalone"):
        return None, error(-32602, "invalid params: mode")
    imported = []
    want = params.get("import_ufw_rules")
    if mode == "standalone" and (want or (want is None and not ufw_imported["done"])):
        ufw_imported["done"] = True
        for rule in UFW_RULES["rules"]:
            spec = {"verdict": "allow", "direction": "inbound", "address": rule["src"]
                    if rule["src"] != "any" else "0.0.0.0/0", "port": int(rule["port"]),
                    "protocol": rule["protocol"]}
            if any({k: r.get(k) for k in spec} == spec for r in RULES.values()):
                continue
            notes = [] if rule["dst"] == "any" else [
                f"not limited to the local address {rule['dst']}: hub rules match the remote address only"]
            imported.append({"rule": add_rule(spec), "from": rule, "notes": notes})
    on = mode == "ufw"
    FIREWALL_MODE["mode"] = mode
    FIREWALL_MODE["ufw"]["enabled_in_conf"] = on
    FIREWALL_MODE["ufw"]["chains_loaded"] = on
    FIREWALL_MODE["table_loaded"] = True
    FIREWALL_MODE["docker_protection"] = "ufw-docker" if on else "omarchy"
    for rule in RULES.values():
        rule["loaded"] = "executable" in rule or not on
    for decision in TEMPS.values():
        decision["backend"] = temp_backend(decision["spec"]) or decision["backend"]
    if TEMPS:
        temps_changed()
    broadcast("firewall", "FIREWALL_MODE_CHANGED", FIREWALL_MODE)
    result = dict(FIREWALL_MODE)
    if imported:
        result["imported"] = imported
    return result, None


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
            asyncio.get_running_loop().call_later(3, usb_presented)
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
        for other in list(clients):
            other.event("usbguard", "USB_DEVICE_POLICY_CHANGED",
                        {"device_id": device["device_id"], "target": device["rule"], "permanent": permanent})
        return device, None
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
            add_rule({"verdict": verdict, "direction": "outbound", "address": prompt["address"],
                      "port": prompt["port"], "protocol": prompt["protocol"],
                      "executable": prompt["executable"]})
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
        return {"decisions": list(TEMPS.values())}, None
    if method == "FIREWALL_TEMP_REMOVE":
        if TEMPS.pop(params.get("temp_id"), None) is None:
            return None, error(-32003, "no temporary decision with that id")
        temps_changed()
        return {}, None
    if method in ("POSTURE_GET_REPORT", "POSTURE_REFRESH"):
        return POSTURE, None
    return None, error(-32007, f"{method} is not implemented by the mock")


async def serve(reader, writer):
    client = Client(writer)
    clients.add(client)
    try:
        while True:
            try:
                line = await reader.readuntil(b"\n")
            except asyncio.LimitOverrunError:
                break
            except asyncio.IncompleteReadError:
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
    args = parser.parse_args()
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
    loop.add_signal_handler(signal.SIGUSR1, usb_presented)
    loop.add_signal_handler(signal.SIGUSR2, connection_prompt)
    loop.add_signal_handler(signal.SIGHUP, toggle_firewall_mode)
    alerts = asyncio.create_task(alert_stream())
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
