#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Command-line client for omarchy-securityd (protocol v1, docs/ipc-protocol.md).

  tools/secctl.py [--socket PATH] call METHOD [PARAMS_JSON]
  tools/secctl.py [--socket PATH] watch [--count N] [--timeout SECS] TOPIC...

`call` prints the result as one JSON line. A JSON-RPC error goes to stderr
and exits 1. `watch` subscribes to the topics and prints each event as one
NDJSON line, `{"method": ..., "params": ...}`, until interrupted, until N
events have arrived, or until SECS pass with no event (exit 2 if none came).
"""

import argparse
import json
import os
import socket
import sys

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 64 * 1024


class RpcError(Exception):
    def __init__(self, error):
        super().__init__(error.get("message", "error"))
        self.error = error


class Client:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.buf = b""
        self.next_id = 1
        self.events = []

    def send(self, method, params=None):
        request = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            request["params"] = params
        self.next_id += 1
        line = json.dumps(request, separators=(",", ":")).encode()
        if len(line) > MAX_FRAME_BYTES:
            raise ValueError(f"request is {len(line)} bytes; the limit is {MAX_FRAME_BYTES}")
        self.sock.sendall(line + b"\n")
        return request["id"]

    def read(self):
        """Returns the next message, or None when the daemon closes the socket."""
        while b"\n" not in self.buf:
            if len(self.buf) > MAX_FRAME_BYTES:
                raise ValueError("daemon sent an oversized frame")
            chunk = self.sock.recv(65536)
            if not chunk:
                return None
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line)

    def call(self, method, params=None):
        """Sends one request and waits for its response. Events that arrive
        in the meantime are kept for the next `event()`."""
        want = self.send(method, params)
        while True:
            message = self.read()
            if message is None:
                raise ConnectionError("daemon closed the connection")
            if "id" not in message:
                self.events.append(message)
            elif message["id"] == want:
                if "error" in message:
                    raise RpcError(message["error"])
                return message.get("result")

    def event(self):
        if self.events:
            return self.events.pop(0)
        while True:
            message = self.read()
            if message is None or "id" not in message:
                return message


def default_socket():
    if os.environ.get("OMARCHY_SECURITYD_SOCKET"):
        return os.environ["OMARCHY_SECURITYD_SOCKET"]
    if os.environ.get("XDG_RUNTIME_DIR"):
        return os.path.join(os.environ["XDG_RUNTIME_DIR"], "omarchy-security", "securityd.sock")
    return None


def dump(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--socket", default=default_socket())
    commands = parser.add_subparsers(dest="command", required=True)
    call = commands.add_parser("call", help="send one request and print its result")
    call.add_argument("method")
    call.add_argument("params", nargs="?", help="params as a JSON object")
    watch = commands.add_parser("watch", help="subscribe and print events as NDJSON")
    watch.add_argument("--count", type=int, help="exit after this many events")
    watch.add_argument("--timeout", type=float, help="exit after this many seconds without an event")
    watch.add_argument("topics", nargs="+")
    args = parser.parse_args()

    if not args.socket:
        sys.exit("XDG_RUNTIME_DIR is not set; pass --socket")
    params = None
    if args.command == "call" and args.params is not None:
        try:
            params = json.loads(args.params)
        except json.JSONDecodeError as e:
            sys.exit(f"params are not JSON: {e}")
        if not isinstance(params, dict):
            sys.exit("params must be a JSON object")

    try:
        client = Client(args.socket)
    except OSError as e:
        sys.exit(f"cannot connect to {args.socket}: {e.strerror or e}")

    try:
        client.call("HELLO", {"protocol_version": PROTOCOL_VERSION, "client": "secctl"})
        if args.command == "call":
            dump(client.call(args.method.upper(), params))
            return 0
        client.call("SUBSCRIBE", {"topics": args.topics})
        client.sock.settimeout(args.timeout)
        seen = 0
        while args.count is None or seen < args.count:
            try:
                message = client.event()
            except TimeoutError:
                return 0 if seen else 2
            if message is None:
                sys.exit("daemon closed the connection")
            dump({"method": message.get("method"), "params": message.get("params")})
            seen += 1
        return 0
    except RpcError as e:
        print(json.dumps(e.error, separators=(",", ":")), file=sys.stderr)
        return 1
    except (ConnectionError, ValueError) as e:
        sys.exit(str(e))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
