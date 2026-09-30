#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Checks the footprint of the running daemon and helper (plan task 4.1).

  tools/footprint.py [--idle SECS] [--load SECS] [--rate N] [--cpu-limit PCT]
                     [--memory-limit MB] [--json]

Read-only. It samples the systemd cgroups of omarchy-securityd.service
(user) and omarchy-securityd-helper.service (system) once a second, so a
child such as the daemon's `journalctl` counts too: first for --idle
seconds (default 60) with nothing asked of them, then for --load seconds
(default 30) while one client sends --rate read-only requests a second
(default 20) and receives the events of every topic but `firewall`
(a `firewall` subscriber makes the daemon hold outbound connections for an
answer when prompting is on).

  * CPU is the cgroup's CPU time over wall time, as `top` shows it (100%
    is one core). The limit (--cpu-limit, 2%) applies to the idle mean.
  * Memory is what the cgroup cannot give back: memory.current less its
    page cache (active_file and inactive_file), which the kernel reclaims
    under pressure. `journalctl` reading the journal fills the daemon's
    cache, so MemoryCurrent alone overstates it; both are printed. The
    limit (--memory-limit, 40 MB) applies to the peak over both windows.

Prints one PASS / FAIL / INFO line per check and exits 1 on any FAIL.
"""

import argparse
import json
import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secctl  # noqa: E402

UNITS = [
    {"name": "daemon", "unit": "omarchy-securityd.service", "user": True},
    {"name": "helper", "unit": "omarchy-securityd-helper.service", "user": False},
]

# Read-only calls: none changes state, asks for a password, or runs checks.
LOAD_METHODS = [
    "GET_STATUS", "FIREWALL_GET_MODE", "FIREWALL_LIST_RULES", "FIREWALL_ALERT_LIST",
    "FIREWALL_UFW_RULES", "FIREWALL_TEMP_LIST", "USBGUARD_LIST_DEVICES", "TOKEN_LIST",
    "THREAT_LIST_ALERTS", "VAULT_LIST", "POSTURE_GET_REPORT",
]
LOAD_TOPICS = ["system", "threat", "usbguard", "token", "vault", "posture"]

CGROUP_ROOT = "/sys/fs/cgroup"
MB = 1024 * 1024


def parse_keyed(text):
    """`key value` lines (cpu.stat, memory.stat) as a dict of ints."""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            out[parts[0]] = int(parts[1])
    return out


def unreclaimable(current, memory_stat):
    """memory.current less the page cache the kernel can reclaim."""
    cache = memory_stat.get("active_file", 0) + memory_stat.get("inactive_file", 0)
    return max(0, current - cache)


def cpu_percent(usage_usec_before, usage_usec_after, wall_before, wall_after):
    """CPU time over wall time, in percent of one core."""
    wall = wall_after - wall_before
    if wall <= 0:
        return 0.0
    return (usage_usec_after - usage_usec_before) / 1e6 / wall * 100


def summarize(samples):
    """Samples of {t, usage_usec, current, resident} → mean and max CPU, peak memory."""
    if len(samples) < 2:
        return None
    rates = [cpu_percent(a["usage_usec"], b["usage_usec"], a["t"], b["t"]) for a, b in zip(samples, samples[1:])]
    first, last = samples[0], samples[-1]
    return {
        "cpu_mean": cpu_percent(first["usage_usec"], last["usage_usec"], first["t"], last["t"]),
        "cpu_max": max(rates),
        "resident_peak": max(s["resident"] for s in samples),
        "current_peak": max(s["current"] for s in samples),
    }


def verdicts(results, cpu_limit, memory_limit):
    """PASS / FAIL / INFO lines from {unit name: {idle, load}} summaries."""
    lines = []
    for name, phases in results.items():
        idle, load = phases.get("idle"), phases.get("load")
        if phases.get("error"):
            lines.append(("FAIL", f"{name}: {phases['error']}"))
            continue
        if idle:
            ok = idle["cpu_mean"] < cpu_limit
            lines.append(("PASS" if ok else "FAIL",
                          f"{name} idle CPU {idle['cpu_mean']:.2f}% (peak second {idle['cpu_max']:.2f}%), "
                          f"limit {cpu_limit:g}%"))
        if load:
            lines.append(("INFO", f"{name} CPU under load {load['cpu_mean']:.2f}% "
                                  f"(peak second {load['cpu_max']:.2f}%)"))
        peaks = [p for p in (idle, load) if p]
        if peaks:
            resident = max(p["resident_peak"] for p in peaks)
            current = max(p["current_peak"] for p in peaks)
            ok = resident < memory_limit * MB
            lines.append(("PASS" if ok else "FAIL",
                          f"{name} memory {resident / MB:.1f} MB without page cache "
                          f"(MemoryCurrent up to {current / MB:.1f} MB), limit {memory_limit:g} MB"))
    return lines


def control_group(unit):
    """The unit's cgroup directory, or an error string."""
    cmd = ["systemctl"] + (["--user"] if unit["user"] else []) + [
        "show", unit["unit"], "-p", "ActiveState", "-p", "ControlGroup"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=True).stdout
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"cannot ask systemd about {unit['unit']}: {e}"
    props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    if props.get("ActiveState") != "active":
        return None, f"{unit['unit']} is {props.get('ActiveState') or 'unknown'}, not active"
    path = CGROUP_ROOT + props.get("ControlGroup", "")
    if not props.get("ControlGroup") or not os.path.isdir(path):
        return None, f"no cgroup for {unit['unit']}"
    return path, None


def sample(path):
    with open(os.path.join(path, "cpu.stat")) as f:
        usage = parse_keyed(f.read())["usage_usec"]
    with open(os.path.join(path, "memory.current")) as f:
        current = int(f.read())
    with open(os.path.join(path, "memory.stat")) as f:
        stat = parse_keyed(f.read())
    return {"t": time.monotonic(), "usage_usec": usage, "current": current,
            "resident": unreclaimable(current, stat)}


def watch(paths, seconds, stop=None):
    """Samples every cgroup once a second for `seconds`."""
    samples = {name: [] for name in paths}
    end = time.monotonic() + seconds
    while True:
        for name, path in paths.items():
            try:
                samples[name].append(sample(path))
            except (OSError, KeyError, ValueError):
                pass  # the unit stopped; the summary says so
        if time.monotonic() >= end or (stop and stop.is_set()):
            return samples
        time.sleep(1)


class Load(threading.Thread):
    """One client: `rate` read-only requests a second, events drained."""

    def __init__(self, path, rate):
        super().__init__(daemon=True)
        self.path, self.rate = path, rate
        self.stop = threading.Event()
        self.sent = self.answered = self.failed = self.events = 0
        self.error = None

    def run(self):
        try:
            client = secctl.Client(self.path)
            client.call("HELLO", {"protocol_version": secctl.PROTOCOL_VERSION, "client": "footprint"})
            client.call("SUBSCRIBE", {"topics": LOAD_TOPICS})
            gap = 1 / self.rate
            due = time.monotonic()
            i = 0
            while not self.stop.is_set():
                method = LOAD_METHODS[i % len(LOAD_METHODS)]
                i += 1
                self.sent += 1
                try:
                    client.call(method, {})
                    self.answered += 1
                except secctl.RpcError:
                    # A module that is unavailable here still answered.
                    self.failed += 1
                self.events += len(client.events)
                client.events.clear()
                due += gap
                time.sleep(max(0, due - time.monotonic()))
        except (OSError, ConnectionError, ValueError) as e:
            self.error = str(e)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--idle", type=float, default=60, metavar="SECS")
    parser.add_argument("--load", type=float, default=30, metavar="SECS")
    parser.add_argument("--rate", type=float, default=20, metavar="N", help="requests a second under load")
    parser.add_argument("--cpu-limit", type=float, default=2.0, metavar="PCT")
    parser.add_argument("--memory-limit", type=float, default=40.0, metavar="MB")
    parser.add_argument("--socket", default=secctl.default_socket())
    parser.add_argument("--json", action="store_true", help="print the measurements as JSON too")
    args = parser.parse_args()

    results, paths = {}, {}
    for unit in UNITS:
        path, error = control_group(unit)
        if error:
            results[unit["name"]] = {"error": error}
        else:
            paths[unit["name"]] = path
            results[unit["name"]] = {}

    print(f"Sampling {', '.join(paths) or 'nothing'}: {args.idle:g} s idle", flush=True)
    for name, samples in watch(paths, args.idle).items():
        results[name]["idle"] = summarize(samples)

    load = None
    if args.load > 0 and "daemon" in paths and args.socket:
        print(f"Then {args.load:g} s at {args.rate:g} requests a second", flush=True)
        load = Load(args.socket, args.rate)
        load.start()
        for name, samples in watch(paths, args.load).items():
            results[name]["load"] = summarize(samples)
        load.stop.set()
        load.join(timeout=5)

    for name in paths:
        if not results[name].get("idle"):
            results[name]["error"] = "stopped while it was sampled"

    lines = verdicts(results, args.cpu_limit, args.memory_limit)
    if load:
        if load.error or load.answered + load.failed == 0:
            lines.append(("FAIL", f"load client: {load.error or 'no answers'}"))
        else:
            lines.append(("INFO", f"load: {load.answered + load.failed} of {load.sent} requests answered "
                                  f"({load.failed} with an error), {load.events} events"))
    for verdict, text in lines:
        print(f"{verdict:4} {text}")
    if args.json:
        print(json.dumps(results, indent=2))
    return 1 if any(v == "FAIL" for v, _ in lines) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
