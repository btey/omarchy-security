// SPDX-License-Identifier: MIT
//
// Rules for the threat alert OSD (plan task 3.4, docs/ipc-protocol.md §4.2):
// the alert list SecurityIPC keeps from THREAT_LIST_ALERTS and the
// THREAT_EXEC_DETECTED / THREAT_ALERT_RESOLVED events, which alerts wait for
// an answer, the actions each one offers, and the text the OSD shows. Free
// of QML so it can be tested with plain node.
.pragma library

// Alerts kept for the session, newest last. Open ones are never dropped for
// room; resolved ones go first.
var MAX_ALERTS = 50

// States that still need an answer.
function isPending(alert) {
  return !!alert && (alert.state === "open" || alert.state === "quarantined")
}

// `alerts` with `alert` added or, when its alert_id is already there,
// replaced. The list stays in alert_id order, the order the daemon raised
// them.
function upsertAlert(alerts, alert) {
  if (!alert || typeof alert.alert_id !== "number") return alerts
  var next = []
  var placed = false
  for (var i = 0; i < alerts.length; i++) {
    var a = alerts[i]
    if (a.alert_id === alert.alert_id) {
      next.push(alert)
      placed = true
      continue
    }
    if (!placed && a.alert_id > alert.alert_id) {
      next.push(alert)
      placed = true
    }
    next.push(a)
  }
  if (!placed) next.push(alert)
  return trim(next)
}

function trim(alerts) {
  var extra = alerts.length - MAX_ALERTS
  if (extra <= 0) return alerts
  var next = []
  for (var i = 0; i < alerts.length; i++) {
    if (extra > 0 && !isPending(alerts[i])) {
      extra--
      continue
    }
    next.push(alerts[i])
  }
  return next
}

function findAlert(alerts, alertId) {
  for (var i = 0; i < alerts.length; i++)
    if (alerts[i].alert_id === alertId) return alerts[i]
  return null
}

// THREAT_ALERT_RESOLVED `{alert_id, state}`. An alert this list does not
// have is left alone: it was raised before this shell connected and is not
// open any more, so there is nothing to show.
function resolveAlert(alerts, change) {
  if (!change || typeof change.alert_id !== "number") return alerts
  var old = findAlert(alerts, change.alert_id)
  if (!old || old.state === change.state) return alerts
  var copy = {}
  for (var key in old) copy[key] = old[key]
  copy.state = change.state
  return upsertAlert(alerts, copy)
}

// A THREAT_LIST_ALERTS answer names every alert still open. One this list
// thinks pending but the listing leaves out was resolved while this shell
// was away (the daemon only lists open ones); it is dropped rather than
// guessed at.
function replaceAlerts(old, listed) {
  var next = []
  for (var i = 0; i < old.length; i++)
    if (!isPending(old[i])) next.push(old[i])
  for (var j = 0; j < listed.length; j++) next = upsertAlert(next, listed[j])
  return next
}

// Alerts that wait for an answer, oldest first, leaving out the ones the
// user put off with Later (`later`: alert_id → true).
function queue(alerts, later) {
  var out = []
  for (var i = 0; i < alerts.length; i++)
    if (isPending(alerts[i]) && !(later && later[alerts[i].alert_id])) out.push(alerts[i])
  return out
}

var ORIGINS = {
  tmp: "/tmp",
  var_tmp: "/var/tmp",
  dev_shm: "/dev/shm",
  memfd: "memory"
}

function originLabel(origin) {
  return ORIGINS[origin] || String(origin || "an unusual place")
}

function title(alert) {
  if (!alert) return ""
  if (alert.origin === "memfd") return "Program started from memory"
  return "Program started from " + originLabel(alert.origin)
}

// Why the daemon raised it, in one line.
function reason(alert) {
  if (!alert) return ""
  if (alert.origin === "memfd")
    return "It has no file on disk (memfd), which is how some malware hides."
  return "Programs rarely run from a temporary folder; downloaded payloads often do."
}

function basename(path) {
  var s = String(path || "")
  var cut = s.lastIndexOf("/")
  return cut >= 0 && cut < s.length - 1 ? s.slice(cut + 1) : s
}

function programName(alert) {
  if (!alert) return ""
  return basename(alert.binary_path) || (alert.argv && alert.argv.length ? basename(alert.argv[0]) : "unknown")
}

// argv as a shell would read it back, cut at `max` characters.
function commandLine(argv, max) {
  if (!argv || argv.length === 0) return ""
  var limit = max || 240
  var parts = []
  for (var i = 0; i < argv.length; i++) {
    var arg = String(argv[i])
    parts.push(arg !== "" && /^[A-Za-z0-9_@%+=:,.\/-]+$/.test(arg) ? arg : "'" + arg.replace(/'/g, "'\\''") + "'")
  }
  var line = parts.join(" ")
  return line.length > limit ? line.slice(0, limit - 1) + "…" : line
}

// "PID 4242 · parent 4100 · user 1000"
function processLine(alert) {
  if (!alert) return ""
  return "PID " + alert.pid + " · parent " + alert.ppid + " · user " + alert.uid
}

function durationText(ms) {
  var s = Math.max(0, Math.round(ms / 1000))
  if (s < 1) return "less than a second"
  if (s < 60) return s + (s === 1 ? " second" : " seconds")
  var m = Math.round(s / 60)
  if (m < 60) return m + (m === 1 ? " minute" : " minutes")
  var h = Math.round(m / 60)
  return h + (h === 1 ? " hour" : " hours")
}

// "Written to /tmp 3 seconds before it ran", when a THREAT_FILE_DROPPED
// preceded it.
function droppedLine(alert) {
  if (!alert || typeof alert.dropped_at !== "number") return ""
  return "Written to " + originLabel(alert.origin) + " " + durationText(alert.detected_at - alert.dropped_at) + " before it ran"
}

function stateLabel(state) {
  switch (state) {
  case "open": return "Running"
  case "quarantined": return "Isolated (paused)"
  case "killed": return "Killed"
  case "exited": return "Exited"
  case "dismissed": return "Dismissed"
  default: return "Unknown"
  }
}

// ThemeProvider.role name for an alert's state.
function stateRole(state) {
  switch (state) {
  case "open": return "danger"
  case "quarantined": return "warning"
  case "killed": return "success"
  default: return "muted"
  }
}

// Response buttons. Each is {id, label, hint, method, signal?}. Kill always
// sends SIGKILL: the daemon marks the alert killed as soon as the signal is
// sent, so a SIGTERM the program ignores would leave it running under a
// "Killed" label and no longer watched; and a paused program would not act
// on SIGTERM before it is resumed. Isolate is the plan's QuarantineProcess:
// SIGSTOP, undone by Resume.
var ACTIONS = {
  kill: { id: "kill", label: "Kill process", method: "THREAT_KILL_PROCESS", signal: 9,
    hint: "End it now (SIGKILL). Anything unsaved in it is lost." },
  isolate: { id: "isolate", label: "Isolate", method: "THREAT_QUARANTINE_PROCESS",
    hint: "Pause it (SIGSTOP) so it can do nothing until you decide" },
  resume: { id: "resume", label: "Resume", method: "THREAT_RESUME_PROCESS",
    hint: "Let it run again (SIGCONT)" },
  dismiss: { id: "dismiss", label: "It's safe", method: "THREAT_DISMISS_ALERT",
    hint: "Close the alert and leave the program running" }
}

function actionsFor(alert) {
  if (!alert) return []
  switch (alert.state) {
  case "open": return [ACTIONS.kill, ACTIONS.isolate, ACTIONS.dismiss]
  case "quarantined": return [ACTIONS.kill, ACTIONS.resume]
  default: return []
  }
}

// Params for an action's request.
function actionParams(alert, action) {
  var params = { alert_id: alert.alert_id, pid: alert.pid }
  if (action.signal !== undefined) params.signal = action.signal
  return params
}

// What the OSD says once an alert is no longer pending.
function outcomeText(state) {
  switch (state) {
  case "killed": return "The program was killed."
  case "exited": return "The program has exited."
  case "dismissed": return "Dismissed. The program keeps running."
  default: return ""
  }
}

// Error codes, as in Protocol.ErrorCode (kept here so this file stands alone).
var INVALID_PARAMS = -32602
var MODULE_UNAVAILABLE = -32002
var NOT_FOUND = -32003
var PERMISSION_DENIED = -32004
var STALE_TARGET = -32005

// A failed response, for the line under the buttons.
function actionErrorText(error) {
  if (!error) return ""
  switch (error.code) {
  case STALE_TARGET: return "The program has already exited."
  case NOT_FOUND: return "This alert is no longer open."
  case PERMISSION_DENIED:
    return "Not allowed: the program belongs to another user, and the privileged helper is not running or polkit refused."
  case MODULE_UNAVAILABLE: return "The threat monitor is not running."
  case INVALID_PARAMS: return "Not possible now: " + (error.message || "the alert changed")
  default: return error.message || "The response failed."
  }
}

// The hub's Threats tab: every alert of this session, newest first.
function newestFirst(alerts) {
  return (alerts || []).slice().sort(function(a, b) { return b.alert_id - a.alert_id })
}

// Text for a Threats tab with no alert to list, or "".
function listEmptyText(ready, moduleState, moduleDetail, alerts) {
  if (!ready) return "Not connected to omarchy-securityd"
  if (moduleState === "not_implemented") return "Programs are not watched by this daemon"
  if (moduleState === "unavailable")
    return "Programs are not watched" + (moduleDetail ? ": " + moduleDetail : "")
  if (!alerts || alerts.length === 0)
    return "No program has started from a temporary folder or from memory since the hub connected."
  return ""
}

if (typeof module !== "undefined") module.exports = {
  MAX_ALERTS: MAX_ALERTS, isPending: isPending, upsertAlert: upsertAlert, findAlert: findAlert,
  resolveAlert: resolveAlert, replaceAlerts: replaceAlerts, queue: queue, originLabel: originLabel,
  title: title, reason: reason, programName: programName, commandLine: commandLine,
  processLine: processLine, durationText: durationText, droppedLine: droppedLine,
  stateLabel: stateLabel, stateRole: stateRole, ACTIONS: ACTIONS, actionsFor: actionsFor,
  actionParams: actionParams, outcomeText: outcomeText, actionErrorText: actionErrorText,
  newestFirst: newestFirst, listEmptyText: listEmptyText
}
