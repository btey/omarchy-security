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
otherwise times out after PROMPT_TIMEOUT_SECS.
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
PROMPT_TIMEOUT_SECS = 30
next_id = {"rule": 1, "prompt": 1}

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


def add_rule(spec):
    rule = {"rule_id": next_id["rule"], **spec}
    next_id["rule"] += 1
    RULES[rule["rule_id"]] = rule
    return rule


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
    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    print(f"mock-securityd listening on {args.socket}", file=sys.stderr)
    async with server:
        await stop.wait()
    # Python 3.13+ removes the socket file when the server closes.
    if os.path.exists(args.socket):
        os.unlink(args.socket)


if __name__ == "__main__":
    asyncio.run(main())
