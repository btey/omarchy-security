// SPDX-License-Identifier: MIT
//
// Rules for the hub without a backend (components/BackendSetup.qml, plan
// task 5.3, §5.22): what the probe found, what to say about it, and the
// commands the buttons run. A plugin install brings only the QML; the
// daemon, the helper and their units come from backend/install.sh, which
// the Install button runs in a terminal. Free of QML so it can be tested
// with plain node.
.pragma library

// Exit codes of PROBE.
var PROBE_MISSING = 10
var PROBE_STOPPED = 11

// Is omarchy-securityd installed, and is its user unit running?
var PROBE = ["sh", "-c",
  "command -v omarchy-securityd >/dev/null 2>&1 || exit " + PROBE_MISSING + "; " +
  "systemctl --user is-active --quiet omarchy-securityd.service || exit " + PROBE_STOPPED]

var TERMINAL = "omarchy-launch-floating-terminal-with-presentation"
var START = ["systemctl", "--user", "enable", "--now", "omarchy-securityd.service"]

// [major, minor, patch] of "1.2.3" (a "-pre" or "+build" suffix is
// ignored), or null.
function parseVersion(text) {
  var m = /^v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/.exec(String(text || "").trim())
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null
}

// -1, 0 or 1 as `a` is older than, the same as or newer than `b`; null
// when either is not a version.
function compareVersions(a, b) {
  var x = parseVersion(a), y = parseVersion(b)
  if (!x || !y) return null
  for (var i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1
  return 0
}

// What the hub shows about the backend:
//   "ok"          connected, at the plugin's version (or one not comparable)
//   "older"       connected to a daemon older than the plugin
//   "newer"       connected to a daemon newer than the plugin
//   "checking"    not connected, and the probe has not answered yet
//   "missing"     omarchy-securityd is not installed
//   "stopped"     installed, but its user unit is not running
//   "unreachable" running, but the socket or HELLO fails
// `probeExit` is PROBE's exit code, or null before it has run.
function state(ready, daemonVersion, pluginVersion, probeExit) {
  if (ready) {
    var order = compareVersions(daemonVersion, pluginVersion)
    return order === -1 ? "older" : order === 1 ? "newer" : "ok"
  }
  if (probeExit === null || probeExit === undefined) return "checking"
  if (probeExit === PROBE_MISSING) return "missing"
  if (probeExit === PROBE_STOPPED) return "stopped"
  return "unreachable"
}

// Whether the hub shows the setup card instead of its tabs.
function blocksHub(kind) {
  return kind === "missing" || kind === "stopped" || kind === "unreachable" || kind === "checking"
}

// {title, body, action, actionHint, manual} for the card, or for the line
// above the tabs when the versions differ. `action` is "install", "start"
// or "" (no button); `manual` is a command to run by hand, or "".
function message(kind, ctx) {
  var c = ctx || {}
  var script = c.scriptPath || "backend/install.sh"
  switch (kind) {
  case "missing":
    return {
      title: "The backend is not installed",
      body: "The Security Hub shows what omarchy-securityd sees, and the plugin alone does not "
        + "include it. The installer downloads release " + (c.pluginVersion || "") + ", checks it "
        + "against the release's checksums, and installs the daemon and its root helper. "
        + "It asks for your password in a terminal, and leaves USBGuard and the firewall mode as they are.",
      action: "install",
      actionHint: "Opens a terminal that runs " + script,
      manual: script + " --from-source"
    }
  case "stopped":
    return {
      title: "omarchy-securityd is not running",
      body: "The backend is installed, but its user service is stopped. If it keeps stopping, "
        + "its log says why.",
      action: "start",
      actionHint: "systemctl --user enable --now omarchy-securityd.service",
      manual: "journalctl --user -u omarchy-securityd -b"
    }
  case "unreachable":
    return {
      title: "omarchy-securityd is not answering",
      body: c.lastError || "The service is running, but the hub cannot talk to it yet.",
      action: "",
      actionHint: "",
      manual: "journalctl --user -u omarchy-securityd -b"
    }
  case "checking":
    return { title: "Connecting to omarchy-securityd…", body: "", action: "", actionHint: "", manual: "" }
  case "older":
    return {
      title: "Backend " + (c.daemonVersion || "") + " is older than the plugin (" + (c.pluginVersion || "") + ")",
      body: "",
      action: "install",
      actionHint: "Opens a terminal that installs backend " + (c.pluginVersion || ""),
      manual: ""
    }
  case "newer":
    return {
      title: "The plugin (" + (c.pluginVersion || "") + ") is older than the backend (" + (c.daemonVersion || "") + ")",
      body: "",
      action: "",
      actionHint: "",
      manual: "omarchy plugin update security-hub"
    }
  }
  return null
}

// The local path of a file:// URL (Qt.resolvedUrl), or "" for another.
function localPath(url) {
  var text = String(url || "")
  if (text.indexOf("file://") !== 0) return ""
  return decodeURIComponent(text.slice("file://".length))
}

// `text` as one word for sh.
function shellQuote(text) {
  return "'" + String(text).replace(/'/g, "'\\''") + "'"
}

// The argv that opens Omarchy's floating terminal running `scriptPath`
// with `args`. The launcher joins its arguments into a bash command, so
// the path is quoted for it.
function terminalCommand(scriptPath, args) {
  var words = [shellQuote(scriptPath)]
  var extra = args || []
  for (var i = 0; i < extra.length; i++) words.push(shellQuote(extra[i]))
  return [TERMINAL, words.join(" ")]
}

if (typeof module !== "undefined") module.exports = {
  PROBE: PROBE, PROBE_MISSING: PROBE_MISSING, PROBE_STOPPED: PROBE_STOPPED, TERMINAL: TERMINAL,
  START: START, parseVersion: parseVersion, compareVersions: compareVersions, state: state,
  blocksHub: blocksHub, message: message, localPath: localPath, shellQuote: shellQuote,
  terminalCommand: terminalCommand
}
