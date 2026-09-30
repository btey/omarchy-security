#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Run by firewall::tests::enforces_the_standalone_policy inside
# `unshare -rn`: applies $SCRIPT (the standalone table, allowing inbound
# TCP 53317) and connects to this namespace from a peer namespace over a
# veth pair. Prints one "name=result" line per check.
set -eu

ip link set lo up
unshare -n sleep 30 &
peer=$!
# Wait until the child has its own network namespace.
while [ "$(readlink /proc/$peer/ns/net)" = "$(readlink /proc/self/ns/net)" ]; do
	sleep 0.01
done
in_peer() { nsenter -t "$peer" -n "$@"; }

ip link add veth0 type veth peer name veth1 netns "$peer"
ip addr add 10.99.0.1/24 dev veth0
ip link set veth0 up
in_peer ip link set lo up
in_peer ip addr add 10.99.0.2/24 dev veth1
in_peer ip link set veth1 up

printf '%s' "$SCRIPT" | "$NFT" -f -

python3 -c '
import socket, threading, time
for port in (53317, 8080):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen()
    threading.Thread(target=lambda s=s: [s.accept()[0].close() for _ in iter(int, 1)], daemon=True).start()
time.sleep(20)
' &
listener=$!
sleep 0.3

connect() {
	in_peer python3 -c '
import socket, sys
try:
    socket.create_connection(("10.99.0.1", int(sys.argv[1])), timeout=1).close()
    print("accepted")
except OSError:
    print("dropped")
' "$1"
}
echo "listed=$(connect 53317)"
echo "unlisted=$(connect 8080)"
echo "loopback=$(python3 -c '
import socket
socket.create_connection(("127.0.0.1", 8080), timeout=1).close()
print("accepted")
')"
if "$NFT" -j list chain inet omarchy_sec input | grep -q '"policy": "drop"'; then
	echo "policy=drop"
else
	echo "policy=other"
fi

kill "$listener" "$peer" 2>/dev/null || true
