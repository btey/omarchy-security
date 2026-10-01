// SPDX-License-Identifier: MIT
//
// Rules for the plugin's own update check (services/SecurityIPC.qml). A
// plugin added with `omarchy plugin add` is a git checkout, and
// `omarchy plugin update` fast-forwards it from its origin, where CI tags
// each version `vX.Y.Z` once its release is out. So the check asks that
// origin for its tags (`git ls-remote`, which sends no data about this
// machine and needs no API), and a tag newer than the manifest's version
// is an update. It runs a few minutes after the shell starts, then at
// most once a day, and says so once per version: a notification that
// updates when clicked, and a line in the hub until the plugin is updated.
// Nothing updates without a click, and the bar widget's "Check for
// updates" setting turns it off. Free of QML so it can be tested with
// plain node.
.pragma library

// After the shell starts, so a boot's network is up and the check does not
// compete with the shell's own start.
var FIRST_DELAY_MS = 2 * 60 * 1000
// How often a running shell looks whether a check is due, and how long a
// successful one lasts.
var POLL_MS = 60 * 60 * 1000
var CHECK_EVERY_MS = 24 * 60 * 60 * 1000

var TERMINAL = "omarchy-launch-floating-terminal-with-presentation"

// The tags of the checkout's origin, without asking for a password (an ssh
// origin needs an agent, an https one nothing), for at most 30 s.
function lsRemote(pluginDir) {
  return ["env", "GIT_TERMINAL_PROMPT=0", "GIT_SSH_COMMAND=ssh -oBatchMode=yes",
    "timeout", "30", "git", "-C", pluginDir, "ls-remote", "--tags", "--refs", "origin", "v*"]
}

// [major, minor, patch] of "1.2.3" or "v1.2.3", or null. Unlike
// Backend.parseVersion, a pre-release such as "1.3.0-rc1" is not a version
// here, so it is never offered.
function parseVersion(text) {
  var m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(String(text || "").trim())
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

// The newest "X.Y.Z" among `git ls-remote --tags` lines
// ("<sha>\trefs/tags/vX.Y.Z"), or "" when there is none.
function latestTag(output) {
  var best = ""
  var lines = String(output || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var m = /\trefs\/tags\/v(\d+\.\d+\.\d+)$/.exec(lines[i].trim().replace(/\s+/, "\t"))
    if (m && (best === "" || compareVersions(m[1], best) === 1)) best = m[1]
  }
  return best
}

// The version to offer: `latest` when it is newer than `current`, else "".
function available(current, latest) {
  return compareVersions(latest, current) === 1 ? String(latest) : ""
}

// Where the check remembers when it last ran and what it said, so a shell
// restart neither asks again within the day nor repeats a notification.
function statePath(env) {
  var state = env("XDG_STATE_HOME") || (env("HOME") ? env("HOME") + "/.local/state" : "")
  return state ? state + "/omarchy-security/plugin-update.json" : ""
}

// {checkedAt, latest, notified} from the state file; zeros and "" for
// anything missing or unreadable.
function parseState(raw) {
  var state = { checkedAt: 0, latest: "", notified: "" }
  try {
    var value = JSON.parse(raw)
    if (typeof value.checked_at === "number" && value.checked_at > 0) state.checkedAt = value.checked_at
    if (parseVersion(value.latest)) state.latest = String(value.latest)
    if (parseVersion(value.notified)) state.notified = String(value.notified)
  } catch (e) {}
  return state
}

function stateText(state) {
  return JSON.stringify({ checked_at: state.checkedAt, latest: state.latest, notified: state.notified }) + "\n"
}

// Whether a check is due at `now` (ms): never checked, a day since the
// last one, or a clock that went back.
function isDue(state, now) {
  var last = state ? state.checkedAt : 0
  return !last || now - last >= CHECK_EVERY_MS || now < last
}

// Whether `version` (from available()) still needs its notification.
function shouldNotify(state, version) {
  return version !== "" && (!state || state.notified !== version)
}

// The command the Update button runs: `omarchy plugin update` in a
// terminal, where it shows the changes and asks before it applies them.
// The hub then offers the matching backend, as for any version apart.
function updateCommand(pluginId) {
  return [TERMINAL, "omarchy plugin update " + pluginId]
}

// Omarchy's own sender: the shell's notifications have no action buttons,
// and a click on one runs its --exec command, which also survives a shell
// restart (a libnotify action needs its sender still running).
function notifyCommand(pluginId, current, version) {
  return ["omarchy-notification-send", "--app-name", "Omarchy Security", "-u", "normal", "-i", "software-update-available",
    "Security Hub " + version + " is available",
    "You have " + current + ". Click to run omarchy plugin update " + pluginId + " in a terminal.",
    "--exec"].concat(updateCommand(pluginId))
}

if (typeof module !== "undefined") module.exports = {
  FIRST_DELAY_MS: FIRST_DELAY_MS, POLL_MS: POLL_MS, CHECK_EVERY_MS: CHECK_EVERY_MS, TERMINAL: TERMINAL,
  lsRemote: lsRemote, parseVersion: parseVersion, compareVersions: compareVersions, latestTag: latestTag,
  available: available, statePath: statePath, parseState: parseState, stateText: stateText, isDue: isDue,
  shouldNotify: shouldNotify, updateCommand: updateCommand, notifyCommand: notifyCommand
}
