#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""End-to-end check of an installed Security Hub (plan task 4.4, §5.12).

  tools/system_check.py [--only SECTION,...] [--skip SECTION,...]
                        [--other-host IP] [--no-manual] [--stay-standalone]

Run it as the desktop user in the Hyprland session, with the daemon and
the helper installed and running, starting in `ufw` mode. It prints one
PASS / FAIL / SKIP / INFO line per check and exits 1 on any FAIL.

It changes nothing that it does not announce first, and undoes each test
action (a rule, a temporary decision, a mode switch, a USB rule, the
config change for prompts) before it moves on. Checks that need root use
`sudo -n` and are SKIP without it: the script runs `sudo -v` once at the
start when it has a terminal. Manual steps (plugging a USB stick, touching
a key, commands on another host) wait for Enter; with --no-manual, or
without a terminal, they are SKIP.

Sections, in the order they run:

  boot        after a reboot in standalone mode: the boot copy was loaded
              before the network and before login; then back to ufw
  install     versions, units, module states, eBPF monitor attached
  threat      a file dropped and run from /tmp, a memfd exec
  cross-user  quarantine, resume and kill of a process of `nobody`
  firewall    a block rule, a temporary block, a program-scoped block
  prompt      a connection prompt that times out
  vault       mount, unmount and panic of a throwaway gocryptfs vault, in
              a private daemon (a fake pinentry answers)
  usb         a new USB stick through USBGuard, and a usbguard-dbus restart
  token       FIDO2 touch prompt (ssh-keygen), GnuPG touch prompt
  modes       mode vs the ruleset, both switches with the ruleset polled
              every 100 ms, `both` mode, and in each mode: blocked-traffic
              alert, temporary inbound allow and Docker from another host,
              LocalSend
  footprint   tools/footprint.py (task 4.1)
  polkit      which actions asked for a password

--stay-standalone ends the modes section in standalone mode, for the
reboot check: reboot, then run `make system-check ARGS="--only boot"`.
"""

import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import secctl  # noqa: E402

REPO = HERE.parent
SECTIONS = ["boot", "install", "threat", "cross-user", "firewall", "prompt", "vault",
            "usb", "token", "modes", "footprint", "polkit"]
# An address outside the local network, reachable over HTTPS by IP.
TEST_ADDR = "1.1.1.1"
TEST_SPEC = {"verdict": "block", "direction": "outbound", "address": f"{TEST_ADDR}/32",
             "port": 443, "protocol": "tcp"}
TABLE = ["inet", "omarchy_sec"]


class Skip(Exception):
    pass


class Fail(Exception):
    pass


# ---------------------------------------------------------------- output

RESULTS = []


def report(status, name, detail=""):
    RESULTS.append((status, name))
    print(f"{status:<5} {name}" + (f": {detail}" if detail else ""), flush=True)


def expect(ok, name, detail=""):
    report("PASS" if ok else "FAIL", name, detail)
    return ok


class Ui:
    def __init__(self, manual):
        self.manual = manual and sys.stdin.isatty()

    @staticmethod
    def say(text):
        print(f"\n==> {text}", flush=True)

    def enter(self, text):
        """A manual step: waits for Enter, or skips the check."""
        if not self.manual:
            raise Skip("manual step (run without --no-manual, in a terminal)")
        self.say(text)
        input("    press Enter when done ")

    def ask(self, question):
        if not self.manual:
            raise Skip("manual step (run without --no-manual, in a terminal)")
        while True:
            answer = input(f"\n==> {question} [y/n] ").strip().lower()
            if answer in ("y", "yes", "n", "no"):
                return answer.startswith("y")


# ------------------------------------------------------------ processes

def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


class Root:
    """`sudo -n`, refreshed before each use so a long run keeps it."""

    def available(self):
        return run(["sudo", "-n", "-v"]).returncode == 0

    def run(self, argv, **kw):
        if not self.available():
            raise Skip("needs sudo (run `sudo -v` first)")
        return run(["sudo", "-n", *argv], **kw)

    def ok(self, argv):
        r = self.run(argv)
        if r.returncode != 0:
            raise Fail(f"`sudo {' '.join(argv)}` failed: {(r.stderr or r.stdout).strip()}")
        return r.stdout


def curl_ok(timeout=5):
    return run(["curl", "-sS", "-m", str(timeout), "-o", "/dev/null",
                f"https://{TEST_ADDR}"]).returncode == 0


def tcp_ok(address, port, timeout=5):
    try:
        socket.create_connection((address, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def free_port():
    """A TCP port nothing listens on."""
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def proc_state(pid):
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    return stat.rsplit(")", 1)[1].split()[0]


def wait_until(predicate, timeout, step=0.2):
    deadline = time.monotonic() + timeout
    while True:
        if predicate():
            return True
        if time.monotonic() > deadline:
            return False
        time.sleep(step)


def unit_props(unit, user=False):
    out = run(["systemctl", *(["--user"] if user else []), "show", unit,
               "--property=ActiveState,Result,ExecMainStatus,ActiveEnterTimestampMonotonic,"
               "UnitFileState"]).stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


# --------------------------------------------------------------- daemon

class Daemon:
    def __init__(self, path):
        try:
            self.client = secctl.Client(path)
        except OSError as e:
            raise Fail(f"cannot connect to {path}: {e.strerror or e}") from e
        self.hello = self.call("HELLO", {"protocol_version": secctl.PROTOCOL_VERSION,
                                         "client": "system-check"})

    def call(self, method, params=None):
        self.client.sock.settimeout(None)
        try:
            return self.client.call(method, params)
        except secctl.RpcError as e:
            raise Fail(f"{method}: {e.error.get('message')} {e.error.get('data', '')}".strip()) from e

    def call_raw(self, method, params=None):
        """Like call, but lets RpcError through."""
        self.client.sock.settimeout(None)
        return self.client.call(method, params)

    def subscribe(self, *topics):
        self.call("SUBSCRIBE", {"topics": list(topics)})
        self.client.events.clear()

    def events(self, secs):
        """Yields (method, params) of each event for up to secs seconds."""
        deadline = time.monotonic() + secs
        while (left := deadline - time.monotonic()) > 0:
            self.client.sock.settimeout(left)
            try:
                message = self.client.event()
            except (TimeoutError, socket.timeout):
                return
            if message is None:
                raise Fail("the daemon closed the connection")
            yield message.get("method"), message.get("params") or {}

    def wait(self, method, predicate=lambda p: True, timeout=30):
        for m, params in self.events(timeout):
            if m == method and predicate(params):
                return params
        return None

    def collect(self, method, predicate, secs):
        return [p for m, p in self.events(secs) if m == method and predicate(p)]

    def close(self):
        self.client.sock.close()


def module_state(status, module):
    for m in status["modules"]:
        if m["module"] == module:
            return m["state"], m.get("detail", "")
    return None, ""


def require_module(daemon, module):
    state, detail = module_state(daemon.call("GET_STATUS"), module)
    if state not in ("active", "degraded"):
        raise Skip(f"the {module} module is {state}" + (f" ({detail})" if detail else ""))


# ------------------------------------------------------------- nftables

def ruleset(root):
    return json.loads(root.ok(["nft", "-j", "list", "ruleset"]))["nftables"]


def objects(rs, kind):
    return [o[kind] for o in rs if kind in o]


def input_drop_families(rs):
    """Families with a base input chain whose policy is drop."""
    return {c["family"] for c in objects(rs, "chain")
            if c.get("hook") == "input" and c.get("policy") == "drop"}


def protected(families, need_ip6=True):
    return "inet" in families or ("ip" in families and ("ip6" in families or not need_ip6))


def nft_mode(rs):
    """The firewall mode the ruleset shows, as the helper derives it."""
    ufw = any(c["family"] == "ip" and c["table"] == "filter" and c["name"] == "ufw-user-input"
              for c in objects(rs, "chain"))
    standalone = any(t["family"] == "inet" and t["name"] == "omarchy_sec"
                     and t.get("comment") == "mode=standalone" for t in objects(rs, "table"))
    return {(True, False): "ufw", (False, True): "standalone",
            (True, True): "both", (False, False): "none"}[(ufw, standalone)]


def our_table(root):
    r = root.run(["nft", "list", "table", *TABLE])
    return r.stdout if r.returncode == 0 else ""


def ufw_status(root):
    if not shutil.which("ufw"):
        return None
    return root.ok(["ufw", "status", "verbose"])


def check_mode(daemon, root, expected):
    mode = daemon.call("FIREWALL_GET_MODE")["mode"]
    actual = nft_mode(ruleset(root))
    return expect(mode == actual == expected, f"mode {expected}: the daemon and the ruleset agree",
                  f"daemon says {mode}, ruleset shows {actual}")


class Poller(threading.Thread):
    """Samples the ruleset every 100 ms and notes whether input is dropped."""

    def __init__(self, need_ip6):
        super().__init__(daemon=True)
        self.need_ip6 = need_ip6
        self.samples = []
        self.errors = 0
        self.halt = threading.Event()

    def run(self):
        while not self.halt.is_set():
            start = time.monotonic()
            r = run(["sudo", "-n", "nft", "-j", "list", "ruleset"])
            if r.returncode == 0:
                families = input_drop_families(json.loads(r.stdout)["nftables"])
                self.samples.append((start, protected(families, self.need_ip6), sorted(families)))
            else:
                self.errors += 1
            self.halt.wait(max(0.0, 0.1 - (time.monotonic() - start)))


def switch_mode(ctx, target):
    """FIREWALL_SET_MODE with the ruleset polled throughout."""
    families = input_drop_families(ruleset(ctx.root))
    need_ip6 = protected(families, True)
    if not protected(families, need_ip6=False):
        raise Fail(f"no input chain drops by default before the switch ({sorted(families)})")
    if not need_ip6:
        report("INFO", "no IPv6 input chain drops by default; checking IPv4 only")
    ctx.ui.say(f"Switching the firewall to {target}. polkit asks for the administrator password.")
    poller = Poller(need_ip6)
    poller.start()
    time.sleep(0.5)
    try:
        result = ctx.daemon.call("FIREWALL_SET_MODE", {"mode": target})
    finally:
        time.sleep(1.5)
        poller.halt.set()
        poller.join()
    gaps = [s for s in poller.samples if not s[1]]
    expect(result["mode"] == target, f"switch to {target}", f"result mode {result['mode']}")
    expect(poller.samples and not gaps and not poller.errors,
           f"input dropped by default throughout the switch to {target}",
           f"{len(poller.samples)} samples, {len(gaps)} without"
           + (f" (first: {gaps[0][2]})" if gaps else "")
           + (f", {poller.errors} failed" if poller.errors else ""))
    return result


# -------------------------------------------------------------- context

class Context:
    def __init__(self, args):
        self.args = args
        self.ui = Ui(not args.no_manual)
        self.root = Root()
        self.socket = secctl.default_socket()
        self.daemon = None
        self.other = args.other_host
        self.password_asked = []

    def connect(self):
        if self.daemon is None:
            self.daemon = Daemon(self.socket)
        return self.daemon

    def other_host(self):
        """The other host's address, and ours on the way to it."""
        if not self.other:
            if not self.ui.manual:
                raise Skip("needs another host (--other-host IP)")
            while True:
                answer = input("\n==> IP address of another device on this network: ").strip()
                try:
                    ipaddress.ip_address(answer)
                    self.other = answer
                    break
                except ValueError:
                    print("    not an IP address")
        route = json.loads(run(["ip", "-j", "route", "get", self.other]).stdout or "[{}]")
        mine = route[0].get("prefsrc")
        if not mine:
            raise Fail(f"no route to {self.other}")
        return self.other, mine


# ------------------------------------------------------------- sections

def section_boot(ctx):
    d = ctx.connect()
    mode = d.call("FIREWALL_GET_MODE")["mode"]
    if mode != "standalone":
        raise Skip(f"mode is {mode}; run the modes section with --stay-standalone, reboot, "
                   "then run this")
    unit = unit_props("omarchy-security-firewall.service")
    expect(unit.get("ActiveState") == "active" and unit.get("ExecMainStatus") == "0",
           "the boot copy was loaded", f"{unit.get('ActiveState')}, exit {unit.get('ExecMainStatus')}")
    loaded = int(unit.get("ActiveEnterTimestampMonotonic") or 0)
    net = int(unit_props("network-pre.target").get("ActiveEnterTimestampMonotonic") or 0)
    login = int(unit_props(f"user@{os.getuid()}.service").get("ActiveEnterTimestampMonotonic") or 0)
    expect(0 < loaded <= net and loaded < login, "before the network and before login",
           f"loaded at {loaded / 1e6:.1f} s, network-pre at {net / 1e6:.1f} s, "
           f"login at {login / 1e6:.1f} s")
    check_mode(d, ctx.root, "standalone")
    if ctx.ui.ask("Hand the firewall back to ufw now?"):
        switch_mode(ctx, "ufw")
        check_mode(d, ctx.root, "ufw")


def section_install(ctx):
    d = ctx.connect()
    status = d.call("GET_STATUS")
    cargo = REPO / "Cargo.toml"
    if cargo.exists():
        version = tomllib.loads(cargo.read_text())["workspace"]["package"]["version"]
        expect(status["daemon_version"] == version, "the installed daemon is this checkout's version",
               f"{status['daemon_version']}, checkout {version}")
    else:
        report("INFO", "daemon version", status["daemon_version"])
    helper = unit_props("omarchy-securityd-helper.service")
    expect(helper.get("UnitFileState") == "enabled" and helper.get("ActiveState") == "active",
           "omarchy-securityd-helper is enabled and running",
           f"{helper.get('UnitFileState')}, {helper.get('ActiveState')}")
    boot = unit_props("omarchy-security-firewall.service")
    expect(boot.get("UnitFileState") == "enabled", "omarchy-security-firewall is enabled",
           boot.get("UnitFileState", ""))
    user = unit_props("omarchy-securityd.service", user=True)
    expect(user.get("UnitFileState") == "enabled" and user.get("ActiveState") == "active",
           "omarchy-securityd (user) is enabled and running",
           f"{user.get('UnitFileState')}, {user.get('ActiveState')}")
    for m in status["modules"]:
        name = f"module {m['module']} is active"
        if m["state"] == "active":
            report("PASS", name, m.get("detail", ""))
        elif m["module"] == "usbguard" and m["state"] == "unavailable":
            report("INFO", f"module usbguard is unavailable ({m.get('detail', 'not set up')})")
        else:
            report("FAIL", name, f"{m['state']}: {m.get('detail', '')}")
    log = run(["journalctl", "-b", "-u", "omarchy-securityd-helper", "--no-pager", "-o", "cat",
               "-g", "exec monitor attached"])
    expect("exec monitor attached" in log.stdout, "the helper attached the eBPF exec monitor this boot",
           "" if log.returncode in (0, 1) else log.stderr.strip())


def section_threat(ctx):
    d = ctx.connect()
    require_module(d, "threat")
    state, _ = module_state(d.call("GET_STATUS"), "threat")
    ctx.ui.say("Running programs from /tmp and from a memfd; the hub shows threat alerts for them.")
    d.subscribe("threat")
    tmp = Path(tempfile.mkdtemp(prefix="omsec-check-", dir="/tmp"))
    try:
        exe = tmp / "x"
        shutil.copy2("/usr/bin/true", exe)
        drop = d.wait("THREAT_FILE_DROPPED", lambda p: p["path"] == str(exe), timeout=10)
        expect(drop is not None, "THREAT_FILE_DROPPED for a program copied to /tmp")
        proc = subprocess.Popen([str(exe), "a", "b"])
        proc.wait()
        alert = d.wait("THREAT_EXEC_DETECTED", lambda p: p["pid"] == proc.pid, timeout=10)
        if expect(alert is not None, "THREAT_EXEC_DETECTED when it runs", f"pid {proc.pid}"):
            expect(alert["ppid"] == os.getpid() and alert["argv"] == [str(exe), "a", "b"]
                   and alert["origin"] == "tmp", "the alert has the right ppid, argv and origin",
                   f"ppid {alert['ppid']}, argv {alert['argv']}, origin {alert['origin']}")
            expect("dropped_at" in alert, "the alert links to the drop (dropped_at)")
        if state != "active":
            report("SKIP", "memfd exec", "the threat module is degraded (no eBPF monitor)")
            return
        fd = os.memfd_create("omsec-check", 0)
        os.write(fd, Path("/usr/bin/true").read_bytes())
        pid = os.fork()
        if pid == 0:
            try:
                os.execve(fd, ["omsec-memfd"], dict(os.environ))
            finally:
                os._exit(127)
        os.waitpid(pid, 0)
        os.close(fd)
        alert = d.wait("THREAT_EXEC_DETECTED", lambda p: p["pid"] == pid, timeout=10)
        expect(alert is not None and alert["origin"] == "memfd", "a memfd exec is reported as memfd",
               "no alert" if alert is None else f"origin {alert['origin']}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def section_cross_user(ctx):
    d = ctx.connect()
    require_module(d, "threat")
    if ctx.root.run(["-u", "nobody", "true"]).returncode != 0:
        raise Skip("`sudo -u nobody` is not allowed")
    path = f"/tmp/omsec-check-s2-{os.getpid()}"
    ctx.ui.say(f"Running {path} as nobody, then quarantining, resuming and killing it through the hub.")
    d.subscribe("threat")
    # Detached with `setsid -f`, so sudo returns at once: when its own child
    # stops, sudo stops its process group too, and that is this script's.
    ctx.root.ok(["-u", "nobody", "setsid", "-f", "sh", "-c",
                 f"cp /usr/bin/sleep {path} && exec {path} 300 </dev/null >/dev/null 2>&1"])
    try:
        alert = d.wait("THREAT_EXEC_DETECTED", lambda p: p["binary_path"] == path, timeout=15)
        if not expect(alert is not None, "a process of nobody is reported"):
            return
        target = {"alert_id": alert["alert_id"], "pid": alert["pid"]}
        pid = alert["pid"]
        d.call("THREAT_QUARANTINE_PROCESS", target)
        expect(wait_until(lambda: proc_state(pid) == "T", 3), "quarantine stops it", f"state {proc_state(pid)}")
        d.call("THREAT_RESUME_PROCESS", target)
        expect(wait_until(lambda: proc_state(pid) in ("S", "R"), 3), "resume continues it",
               f"state {proc_state(pid)}")
        d.call("THREAT_KILL_PROCESS", {**target, "signal": 9})
        expect(wait_until(lambda: proc_state(pid) in (None, "Z"), 3), "kill ends it")
    finally:
        ctx.root.run(["-u", "nobody", "pkill", "-KILL", "-f", path])
        ctx.root.run(["-u", "nobody", "rm", "-f", path])


def block_checks(ctx, mode):
    """A block rule and a temporary block of TEST_ADDR:443 in this mode."""
    d, root = ctx.connect(), ctx.root
    if not curl_ok():
        raise Skip(f"https://{TEST_ADDR} is not reachable from here")
    have_root = root.available()
    if not have_root:
        report("INFO", f"{mode} mode: no sudo, so the ruleset and `ufw status` are not checked")
    ufw_before = ufw_status(root) if have_root else None
    rule = d.call("FIREWALL_ADD_RULE", TEST_SPEC)
    try:
        if mode == "ufw":
            expect(not rule["loaded"], "ufw mode: a hub block rule is saved, not loaded (ufw decides)")
        else:
            expect(rule["loaded"], f"{mode} mode: a hub block rule is loaded")
            expect(not curl_ok(), f"{mode} mode: the rule blocks https://{TEST_ADDR}")
            if have_root:
                expect(TEST_ADDR in our_table(root), f"{mode} mode: the rule is in table inet omarchy_sec")
    finally:
        d.call("FIREWALL_REMOVE_RULE", {"rule_id": rule["rule_id"]})
    if mode != "ufw":
        expect(curl_ok(), f"{mode} mode: removing the rule restores access")
    temp = d.call("FIREWALL_TEMP_ADD", {"spec": TEST_SPEC, "duration_secs": 60})
    try:
        expect(temp["backend"] == "table", f"{mode} mode: a temporary block goes to our table",
               temp["backend"])
        expect(not curl_ok(), f"{mode} mode: the temporary block stops https://{TEST_ADDR}")
        if have_root:
            expect(f"tmp_{temp['temp_id']}" in our_table(root), f"{mode} mode: its set is in our table")
    finally:
        d.call("FIREWALL_TEMP_REMOVE", {"temp_id": temp["temp_id"]})
    expect(curl_ok(), f"{mode} mode: removing the temporary block restores access")
    if ufw_before is not None:
        expect(ufw_status(root) == ufw_before, f"{mode} mode: `ufw status` is unchanged")
    if mode == "ufw" and have_root:
        expect(nft_mode(ruleset(root)) == "ufw", "ufw mode: ufw's chains are still loaded")


def section_firewall(ctx):
    d = ctx.connect()
    require_module(d, "firewall")
    mode = d.call("FIREWALL_GET_MODE")["mode"]
    if mode not in ("ufw", "standalone"):
        raise Fail(f"the firewall mode is {mode}")
    ctx.ui.say(f"Blocking https://{TEST_ADDR} for a few seconds with hub rules.")
    block_checks(ctx, mode)
    curl = os.path.realpath(shutil.which("curl") or "/usr/bin/curl")
    rule = d.call("FIREWALL_ADD_RULE", {**TEST_SPEC, "executable": curl})
    try:
        expect(rule["loaded"], "a program-scoped rule is enforced (connection interception)")
        expect(not curl_ok(), f"it blocks {curl}")
        expect(tcp_ok(TEST_ADDR, 443), "and not another program (python)")
    finally:
        d.call("FIREWALL_REMOVE_RULE", {"rule_id": rule["rule_id"]})
    expect(curl_ok(), "removing it restores access")


def config_path():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "omarchy-security" / "config.toml"


def section_prompt(ctx):
    d = ctx.connect()
    require_module(d, "firewall")
    cfg = config_path()
    original = cfg.read_bytes() if cfg.exists() else None
    firewall = tomllib.loads(original.decode()).get("firewall", {}) if original else {}
    changed = False
    if firewall.get("prompt"):
        timeout = firewall.get("prompt_timeout_secs", 30)
    elif firewall:
        raise Skip(f"{cfg} has a [firewall] table without `prompt = true`; set it (and "
                   "prompt_timeout_secs = 5) for this check")
    else:
        if not ctx.ui.ask(f"Turn connection prompts on for about 10 s? This appends a [firewall] "
                          f"table to {cfg} and restores the file afterwards. While it is on, new "
                          "connections of every program wait for an answer (5 s at most)."):
            raise Skip("declined")
        timeout = 5
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_bytes((original or b"") + b"\n[firewall]\nprompt = true\nprompt_timeout_secs = 5\n")
        changed = True
    verdict = firewall.get("timeout_verdict", "block")
    try:
        if changed:
            run(["systemctl", "--user", "reload", "omarchy-securityd.service"])
            time.sleep(1)
        ctx.ui.say("A connection prompt for curl appears in the hub. Do not answer it.")
        d.subscribe("firewall")
        curl = os.path.realpath(shutil.which("curl") or "/usr/bin/curl")
        proc = subprocess.Popen(["curl", "-sS", "-m", str(timeout + 10), "-o", "/dev/null",
                                 f"https://{TEST_ADDR}"], stderr=subprocess.DEVNULL)
        prompt = d.wait("FIREWALL_CONNECTION_PROMPT",
                        lambda p: p["executable"] == curl and p["address"] == TEST_ADDR
                        and p["port"] == 443, timeout=10)
        if expect(prompt is not None, "a new connection of curl is held with a prompt"):
            done = d.wait("FIREWALL_CONNECTION_RESOLVED",
                          lambda p: p["request_id"] == prompt["request_id"], timeout=timeout + 10)
            expect(done is not None and done["decided_by"] == "timeout" and done["verdict"] == verdict,
                   f"unanswered, it resolves by timeout with {verdict}", str(done))
        rc = proc.wait(timeout=timeout + 20)
        if prompt is not None and verdict == "block":
            expect(rc != 0, "and curl's connection is refused")
    finally:
        if changed:
            if original is None:
                cfg.unlink()
            else:
                cfg.write_bytes(original)
            run(["systemctl", "--user", "reload", "omarchy-securityd.service"])


FAKE_PINENTRY = """#!/bin/sh
echo "OK Pleased to meet you"
while read -r cmd rest; do
  case "$cmd" in
    GETPIN) echo "D $(cat '{passfile}')"; echo OK ;;
    BYE) echo OK; exit 0 ;;
    *) echo OK ;;
  esac
done
"""


def mounted(path):
    return any(line.split()[4] == str(path) for line in Path("/proc/self/mountinfo").read_text().splitlines())


def section_vault(ctx):
    for tool in ("gocryptfs", "fusermount3"):
        if not shutil.which(tool):
            raise Skip(f"{tool} is not installed")
    daemon_bin = shutil.which("omarchy-securityd")
    if not daemon_bin:
        raise Skip("omarchy-securityd is not installed")
    ctx.ui.say("Creating a throwaway gocryptfs vault and a private daemon for it (no helper).")
    tmp = Path(tempfile.mkdtemp(prefix="omsec-vault-"))
    cipher, plain, bindir = tmp / "cipher", tmp / "plain", tmp / "bin"
    for p in (cipher, bindir, tmp / "state"):
        p.mkdir()
    passfile = tmp / "pass"
    passfile.write_text(secrets.token_hex(16))
    pinentry = bindir / "pinentry"
    pinentry.write_text(FAKE_PINENTRY.format(passfile=passfile))
    pinentry.chmod(0o755)
    r = run(["gocryptfs", "-init", "-q", "-passfile", str(passfile), str(cipher)])
    if r.returncode != 0:
        raise Fail(f"gocryptfs -init: {r.stderr.strip()}")
    cfg = tmp / "config.toml"
    cfg.write_text(f'[[vault]]\nid = "check"\nname = "System check"\nbackend = "gocryptfs"\n'
                   f'source = "{cipher}"\nmount_point = "{plain}"\n\n'
                   "[firewall.alerts]\nnotify = false\n")
    sock = tmp / "securityd.sock"
    env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
           "XDG_STATE_HOME": str(tmp / "state"), "RUST_LOG": "warn"}
    log = open(tmp / "daemon.log", "w")
    server = subprocess.Popen([daemon_bin, "--config", str(cfg), "--socket", str(sock),
                               "--helper-socket", str(tmp / "no-helper.sock")],
                              env=env, stdout=log, stderr=log)
    sleeper = None
    try:
        if not wait_until(sock.exists, 10):
            raise Fail("the private daemon did not start (see its log)")
        v = Daemon(str(sock))
        vaults = v.call("VAULT_LIST")["vaults"]
        expect([x["vault_id"] for x in vaults] == ["check"], "the configured vault is listed")
        vault = v.call("VAULT_MOUNT", {"vault_id": "check"})
        expect(vault["mounted"] and mounted(plain), "VAULT_MOUNT mounts it (passphrase from pinentry)")
        (plain / "secret.txt").write_text("hello")
        names = [p.name for p in cipher.rglob("*")]
        expect("secret.txt" not in names and len(names) > 2, "what is written is stored encrypted")
        vault = v.call("VAULT_UNMOUNT", {"vault_id": "check"})
        expect(not vault["mounted"] and not mounted(plain), "VAULT_UNMOUNT unmounts it")
        v.call("VAULT_MOUNT", {"vault_id": "check"})
        sleeper = subprocess.Popen(["sleep", "300"], cwd=plain)
        result = v.call("VAULT_PANIC")
        expect("check" in result["unmounted"] and not result["failed"] and not mounted(plain),
               "VAULT_PANIC unmounts it", json.dumps(result))
        expect(wait_until(lambda: sleeper.poll() is not None, 5), "and stops the process using it")
        v.close()
    finally:
        if sleeper and sleeper.poll() is None:
            sleeper.kill()
        server.send_signal(signal.SIGTERM)
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        log.close()
        if mounted(plain):
            run(["fusermount3", "-u", str(plain)])
        failed = server.returncode not in (0, -signal.SIGTERM)
        if failed or any(s == "FAIL" for s, _ in RESULTS[-8:]):
            report("INFO", "private daemon log", (tmp / "daemon.log").read_text().strip()[-2000:])
        shutil.rmtree(tmp, ignore_errors=True)


def usbguard_rules(root):
    r = run(["usbguard", "list-rules"])
    if r.returncode != 0:
        r = root.run(["usbguard", "list-rules"])
    if r.returncode != 0:
        raise Fail(f"usbguard list-rules: {r.stderr.strip()}")
    return {int(m.group(1)): m.group(2) for m in re.finditer(r"^\s*(\d+): (.*)$", r.stdout, re.M)}


def section_usb(ctx):
    d = ctx.connect()
    state, detail = module_state(d.call("GET_STATUS"), "usbguard")
    if state != "active":
        raise Skip(f"USBGuard is {state} ({detail}); set it up as in the README first")
    root = ctx.root
    rules = usbguard_rules(root)
    d.subscribe("usbguard")
    ctx.ui.enter("Plug in a USB stick that has not been used on this machine. Leave the prompt "
                 "in the hub unanswered.")
    dev = d.wait("USB_DEVICE_PRESENTED", timeout=30)
    if not expect(dev is not None, "USB_DEVICE_PRESENTED for the new stick"):
        return
    expect(dev["rule"] == "block", "it arrives blocked", dev["rule"])
    d.call("USBGUARD_SET_POLICY", {"device_id": dev["device_id"], "target": "allow"})
    changed = d.wait("USB_DEVICE_POLICY_CHANGED", lambda p: p["device_id"] == dev["device_id"], 10)
    expect(changed is not None and changed["target"] == "allow", "allow authorizes it")
    expect(usbguard_rules(root) == rules, "a one-time allow adds no rule")
    d.call("USBGUARD_SET_POLICY", {"device_id": dev["device_id"], "target": "allow", "permanent": True})
    added = {k: v for k, v in usbguard_rules(root).items() if k not in rules}
    again = None
    expect(len(added) == 1, "a permanent allow adds one rule", "; ".join(added.values()))
    try:
        ctx.ui.enter("Unplug the stick and plug it back in.")
        again = d.wait("USB_DEVICE_PRESENTED", timeout=30)
        expect(again is not None and again["rule"] == "allow", "with the permanent rule it comes back allowed",
               "" if again is None else again["rule"])
    finally:
        for rule_id in added:
            ctx.ui.say(f"Removing the test rule {rule_id} from USBGuard's policy.")
            r = run(["usbguard", "remove-rule", str(rule_id)])
            if r.returncode != 0:
                root.run(["usbguard", "remove-rule", str(rule_id)])
    expect(usbguard_rules(root) == rules, "the policy is back as it was")
    if again is not None:
        d.call("USBGUARD_SET_POLICY", {"device_id": again["device_id"], "target": "reject"})
        gone = d.wait("USB_DEVICE_REMOVED", lambda p: p["device_id"] == again["device_id"], 10)
        expect(gone is not None, "reject removes it (USB_DEVICE_REMOVED)")
    before = d.call("USBGUARD_LIST_DEVICES")["devices"]
    ctx.ui.say("Restarting usbguard-dbus.")
    ctx.root.ok(["systemctl", "restart", "usbguard-dbus.service"])
    time.sleep(2)
    wait_until(lambda: module_state(d.call("GET_STATUS"), "usbguard")[0] == "active", 15, step=1)
    after = d.call("USBGUARD_LIST_DEVICES")["devices"]
    ids = [x["device_id"] for x in after]
    expect(len(ids) == len(set(ids)) and len(after) == len(before),
           "after a usbguard-dbus restart the devices are listed again, once each",
           f"{len(before)} before, {len(after)} after")
    ctx.ui.say("Unplug the stick; it is blocked until you allow it in the hub.")


def section_token(ctx):
    d = ctx.connect()
    require_module(d, "token")
    tokens = d.call("TOKEN_LIST")["tokens"]
    report("INFO", "security keys", ", ".join(f"{t['name']} {t['capabilities']}" for t in tokens) or "none")
    fido = [t for t in tokens if "fido2" in t["capabilities"]]
    if not fido:
        report("SKIP", "FIDO2 touch prompt", "no FIDO2 key plugged in")
    elif not shutil.which("ssh-keygen"):
        report("SKIP", "FIDO2 touch prompt", "ssh-keygen is not installed")
    elif ctx.ui.manual:
        ctx.ui.say("ssh-keygen makes a throwaway, non-resident FIDO2 key (nothing is stored on the "
                   "key). Touch the key when it blinks; enter its PIN if asked.")
        d.subscribe("token")
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.Popen(["ssh-keygen", "-q", "-t", "ed25519-sk", "-N", "",
                                     "-f", f"{tmp}/key", "-C", "omsec-check"])
            asked = d.wait("TOKEN_TOUCH_REQUESTED", timeout=60)
            if expect(asked is not None, "a touch prompt appears", "" if asked is None else asked["source"]):
                done = d.wait("TOKEN_TOUCH_COMPLETED",
                              lambda p: p["request_id"] == asked["request_id"], timeout=60)
                expect(done is not None and done["outcome"] == "touched", "and completes when touched",
                       str(done))
            try:
                proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()
    else:
        report("SKIP", "FIDO2 touch prompt", "manual step")
    if not any("openpgp" in t["capabilities"] for t in tokens):
        report("SKIP", "GnuPG touch prompt", "no OpenPGP card plugged in")
        return
    ctx.ui.enter("In another terminal, sign with a key on the card (touch it when it blinks):\n"
                 "    echo test | gpg --clearsign > /dev/null\n    Press Enter here first.")
    d.subscribe("token")
    asked = d.wait("TOKEN_TOUCH_REQUESTED", lambda p: p["source"] == "gpg", timeout=120)
    if expect(asked is not None, "a GnuPG touch prompt appears"):
        done = d.wait("TOKEN_TOUCH_COMPLETED", lambda p: p["request_id"] == asked["request_id"], 30)
        expect(done is not None and done["outcome"] == "touched", "and completes when touched", str(done))


# ---- modes: the checks that need another host

def alert_check(ctx, mode):
    d = ctx.connect()
    other, mine = ctx.other_host()
    port = free_port()
    d.subscribe("firewall")
    ctx.ui.enter(f"On {other}, run:  nc -vz -w3 {mine} {port}\n"
                 f"    (or open http://{mine}:{port} in its browser). It should fail.")
    alerts = d.collect("FIREWALL_ALERT", lambda p: p.get("dst_port") == port and p["src"] == other, 15)
    ids = {a["alert_id"] for a in alerts}
    detail = f"{len(ids)} alerts"
    if mode == "ufw" and not ids:
        detail += " (ufw logs only a sample at LOGLEVEL=low)"
    expect(len(ids) == 1, f"{mode} mode: a blocked connection from {other} raises one FIREWALL_ALERT",
           detail)
    if ids:
        expect(ctx.ui.ask("Did exactly one desktop notification appear for it?"),
               f"{mode} mode: one notification for it")


def temp_allow_check(ctx, mode):
    d, root = ctx.connect(), ctx.root
    other, mine = ctx.other_host()
    port = free_port()
    tmp = Path(tempfile.mkdtemp(prefix="omsec-http-"))
    log_path = tmp / "http.log"
    log = open(log_path, "w")
    server = subprocess.Popen([sys.executable, "-m", "http.server", str(port), "--bind", "0.0.0.0",
                               "--directory", str(tmp)], stdout=log, stderr=log)
    url = f"http://{mine}:{port}/"

    def hits():
        return sum(line.startswith(other + " ") for line in log_path.read_text().splitlines())

    temp = None
    try:
        ctx.ui.enter(f"On {other}, run:  curl -m5 {url}\n    It should time out.")
        time.sleep(1)
        expect(hits() == 0, f"{mode} mode: port {port} is closed to {other}")
        ctx.ui.say("Adding a 60 s inbound allow; polkit asks for the administrator password.")
        ctx.password_asked.append("temporary inbound allow")
        temp = d.call("FIREWALL_TEMP_ADD", {"spec": {"verdict": "allow", "direction": "inbound",
                                                     "address": other, "port": port, "protocol": "tcp"},
                                            "duration_secs": 60})
        backend = "ufw" if mode == "ufw" else "table"
        expect(temp["backend"] == backend, f"{mode} mode: a temporary inbound allow goes to {backend}",
               temp["backend"])
        tag = f"omarchy-security:tmp:{temp['temp_id']}"
        if mode == "ufw":
            expect(tag in ufw_status(root), "it is in `ufw status`")
        ctx.ui.enter(f"Run the same curl on {other} again. It should get a directory listing.")
        time.sleep(1)
        expect(hits() >= 1, f"{mode} mode: the temporary allow lets {other} in")
        ctx.ui.say("Waiting for the allow to expire (up to 2 minutes).")
        left = temp["expires_at"] / 1000 - time.time()
        time.sleep(max(0, left) + 2)
        expect(wait_until(lambda: all(x["temp_id"] != temp["temp_id"]
                                      for x in d.call("FIREWALL_TEMP_LIST")["decisions"]), 10),
               f"{mode} mode: it expires on its own")
        if mode == "ufw":
            expect(wait_until(lambda: tag not in ufw_status(root), 45, step=3),
                   "and is gone from `ufw status`")
        before = hits()
        ctx.ui.enter(f"Run the curl on {other} once more. It should time out again.")
        time.sleep(1)
        expect(hits() == before, f"{mode} mode: {other} is shut out again")
    finally:
        if temp is not None:
            try:
                d.call_raw("FIREWALL_TEMP_REMOVE", {"temp_id": temp["temp_id"]})
            except secctl.RpcError:
                pass
        server.terminate()
        server.wait(timeout=10)
        log.close()
        shutil.rmtree(tmp, ignore_errors=True)


def docker_check(ctx, mode):
    root = ctx.root
    if not shutil.which("docker"):
        raise Skip("docker is not installed")
    if unit_props("docker.service").get("ActiveState") != "active":
        raise Skip("docker is not running (sudo systemctl start docker)")
    other, mine = ctx.other_host()
    port = free_port()
    name = f"omsec-check-{os.getpid()}"
    ctx.ui.say(f"Publishing port {port} from a busybox container (pulls busybox if needed).")
    root.ok(["docker", "run", "-d", "--rm", "--name", name, "-p", f"{port}:8080", "busybox",
             "httpd", "-f", "-vv", "-p", "8080"])
    try:
        ctx.ui.enter(f"On {other}, run:  curl -m5 http://{mine}:{port}/\n    It should time out.")
        time.sleep(1)
        logs = root.run(["docker", "logs", name])
        reached = other in (logs.stdout + logs.stderr)
        expect(not reached and ctx.ui.ask("Did the curl time out (no 404 page)?"),
               f"{mode} mode: a published Docker port is closed to {other}")
    finally:
        root.run(["docker", "stop", "-t", "1", name])


def other_host_checks(ctx, mode):
    for check in (alert_check, temp_allow_check, docker_check):
        try:
            check(ctx, mode)
        except Skip as e:
            report("SKIP", f"{mode} mode: {check.__name__.replace('_', ' ')}", str(e))
        except Fail as e:
            report("FAIL", f"{mode} mode: {check.__name__.replace('_', ' ')}", str(e))


def section_modes(ctx):
    d, root = ctx.connect(), ctx.root
    require_module(d, "firewall")
    mode = d.call("FIREWALL_GET_MODE")["mode"]
    if mode != "ufw":
        raise Skip(f"start in ufw mode (it is {mode}); after a reboot test run --only boot")
    root.run(["true"])
    check_mode(d, root, "ufw")
    nft_enabled = run(["systemctl", "is-enabled", "nftables.service"]).stdout.strip() == "enabled"
    conf = Path("/etc/nftables.conf")
    flushes = conf.exists() and "flush ruleset" in conf.read_text(errors="replace")
    expect(not (nft_enabled and flushes), "nftables.service is not enabled with a `flush ruleset` config",
           f"enabled: {nft_enabled}, flush ruleset: {flushes}")
    expect(unit_props("firewalld.service").get("ActiveState") != "active", "firewalld is not running")
    block_checks(ctx, "ufw")
    other_host_checks(ctx, "ufw")

    preview = d.call("FIREWALL_SET_MODE", {"mode": "standalone", "dry_run": True})
    report("INFO", "switching imports ufw's rules",
           f"{len(preview.get('imported', []))} imported, {len(preview.get('not_imported', []))} not")
    ctx.ui.say("Keep a way back in (a TTY or ssh). If anything goes wrong:\n"
               "    sudo ufw --force enable && sudo nft delete table inet omarchy_sec && \\\n"
               "      sudo rm -f /var/lib/omarchy-security/firewall.nft /var/lib/omarchy-security/mode")
    ctx.password_asked.append("mode switch")
    switch_mode(ctx, "standalone")
    try:
        check_mode(d, root, "standalone")
        expect(Path("/var/lib/omarchy-security/firewall.nft").exists() or
               root.run(["test", "-s", "/var/lib/omarchy-security/firewall.nft"]).returncode == 0,
               "the boot copy is written")
        block_checks(ctx, "standalone")
        other_host_checks(ctx, "standalone")
        try:
            expect(ctx.ui.ask("Send a file to this machine with LocalSend from another device. "
                              "Did it arrive?"), "standalone mode: LocalSend works after the import")
        except Skip as e:
            report("SKIP", "standalone mode: LocalSend", str(e))
        if ctx.args.stay_standalone:
            ctx.ui.say("Staying in standalone mode. Reboot, log in, and run:\n"
                       "    make system-check ARGS=\"--only boot\"")
            return
        ctx.ui.say("Turning ufw on outside the hub (`sudo ufw --force enable`), as an update might.")
        d.subscribe("firewall")
        root.ok(["ufw", "--force", "enable"])
        changed = d.wait("FIREWALL_MODE_CHANGED", lambda p: p["mode"] == "both", timeout=40)
        expect(changed is not None, "the daemon reports mode both")
        check_mode(d, root, "both")
    finally:
        if not ctx.args.stay_standalone:
            switch_mode(ctx, "ufw")
            check_mode(d, root, "ufw")


def section_footprint(ctx):
    ctx.ui.say("Measuring the daemon and the helper for 90 s (tools/footprint.py). Leave the "
               "machine idle.")
    r = run([sys.executable, str(HERE / "footprint.py")])
    for line in r.stdout.splitlines():
        status, _, rest = line.partition(" ")
        if status in ("PASS", "FAIL", "INFO", "SKIP"):
            report(status, "footprint " + rest.strip())
    if r.returncode not in (0, 1):
        raise Fail(f"footprint.py: {r.stderr.strip()}")


def section_polkit(ctx):
    expected = ", ".join(sorted(set(ctx.password_asked))) or "nothing"
    expect(not ctx.ui.ask(f"Did polkit ask for a password for anything other than: {expected}?"),
           "no password for everyday actions (polkit rules)")


# ----------------------------------------------------------------- main

def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog="\n".join(__doc__.splitlines()[2:]))
    parser.add_argument("--only", help="comma-separated sections to run")
    parser.add_argument("--skip", default="", help="comma-separated sections to leave out")
    parser.add_argument("--other-host", help="IP of another device on the network")
    parser.add_argument("--no-manual", action="store_true", help="SKIP the checks that need a person")
    parser.add_argument("--stay-standalone", action="store_true",
                        help="end the modes section in standalone mode, for the reboot check")
    args = parser.parse_args()
    chosen = args.only.split(",") if args.only else list(SECTIONS)
    skipped = set(filter(None, args.skip.split(",")))
    unknown = (set(chosen) | skipped) - set(SECTIONS)
    if unknown:
        parser.error(f"unknown sections: {', '.join(sorted(unknown))} (known: {', '.join(SECTIONS)})")
    ctx = Context(args)
    if not ctx.root.available() and sys.stdin.isatty():
        Ui.say("Some checks need root; sudo asks for your password once.")
        subprocess.run(["sudo", "-v"])
    for name in SECTIONS:
        if name not in chosen or name in skipped:
            continue
        print(f"\n--- {name}", flush=True)
        try:
            globals()["section_" + name.replace("-", "_")](ctx)
        except Skip as e:
            report("SKIP", name, str(e))
        except Fail as e:
            report("FAIL", name, str(e))
        except (OSError, subprocess.SubprocessError, KeyError, ValueError) as e:
            report("FAIL", name, f"{type(e).__name__}: {e}")
    counts = {s: sum(1 for r, _ in RESULTS if r == s) for s in ("PASS", "FAIL", "SKIP")}
    print(f"\n{counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped", flush=True)
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
