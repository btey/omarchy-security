// SPDX-License-Identifier: MIT
//
// What the bar widget shows (plan §5.21): the shield's state, which
// follows the firewall mode, and the badge with the number of unseen
// blocked-traffic alerts. SecurityIPC keeps the data; this file holds the
// rules, free of QML so they can be tested with plain node.
.pragma library

// The daemon keeps its newest 500 alerts; the shell keeps the same.
var MAX_ALERTS = 500

// `alerts` with `alert` added or, when its alert_id is already there,
// replaced (the daemon re-sends an alert when its count grows or it is
// muted). Newest first, as FIREWALL_ALERT_LIST returns them.
function mergeAlert(alerts, alert) {
  if (!alert || alert.alert_id === undefined) return alerts
  var next = []
  var replaced = false
  for (var i = 0; i < alerts.length; i++) {
    if (alerts[i].alert_id === alert.alert_id) { next.push(alert); replaced = true }
    else next.push(alerts[i])
  }
  if (!replaced) next.unshift(alert)
  return next.length > MAX_ALERTS ? next.slice(0, MAX_ALERTS) : next
}

// Alerts with a packet after `seenAt` (ms), not counting muted ones: the
// user asked not to be told about those. An alert that was seen counts
// again when more of its packets are blocked.
function unseenCount(alerts, seenAt, now) {
  var n = 0
  for (var i = 0; i < alerts.length; i++) {
    var a = alerts[i]
    if (!(a.last_seen > seenAt)) continue
    if (a.muted_until !== undefined && a.muted_until !== null && a.muted_until > now) continue
    n++
  }
  return n
}

// "" hides the badge.
function badgeText(count) {
  if (!(count > 0)) return ""
  return count > 9 ? "9+" : String(count)
}

// Shield state for a firewall mode: "normal" for the two modes the hub
// chooses, "warning" for the conflict, "danger" when nothing protects the
// machine, "dim" when the mode cannot be read (or is not known yet).
function modeRole(mode) {
  switch (mode) {
  case "ufw": case "standalone": return "normal"
  case "both": return "warning"
  case "none": return "danger"
  default: return "dim"
  }
}

// {role, badge, tooltip} for the bar widget. `status`:
//   ready     - HELLO done
//   mode      - FirewallMode.mode, "" before the first answer
//   modeLabel - the mode's display name (Protocol.firewallModeLabel)
//   unseen    - unseenCount(...)
function summarize(status) {
  if (!status || !status.ready)
    return { role: "dim", badge: "", tooltip: "Security Hub · daemon not connected" }
  var lines = ["Security Hub"]
  if (!status.mode) lines.push("Firewall: reading state…")
  else if (status.mode === "unknown") lines.push("Firewall: state unknown (privileged helper not running)")
  else lines.push("Firewall: " + status.modeLabel)
  if (status.unseen > 0)
    lines.push(status.unseen + (status.unseen === 1 ? " new blocked connection" : " new blocked connections"))
  return { role: modeRole(status.mode), badge: badgeText(status.unseen), tooltip: lines.join("\n") }
}

// Where the shell remembers when the user last looked at the alerts, so a
// shell restart does not bring back a badge that was already cleared.
function seenStatePath(env) {
  var state = env("XDG_STATE_HOME") || (env("HOME") ? env("HOME") + "/.local/state" : "")
  return state ? state + "/omarchy-security/shell-seen.json" : ""
}

// The file's `alerts_seen_at`, or 0 when it is missing or unreadable.
function parseSeenState(raw) {
  try {
    var value = JSON.parse(raw).alerts_seen_at
    return typeof value === "number" && value > 0 ? value : 0
  } catch (e) {
    return 0
  }
}

if (typeof module !== "undefined") module.exports = {
  MAX_ALERTS: MAX_ALERTS, mergeAlert: mergeAlert, unseenCount: unseenCount,
  badgeText: badgeText, modeRole: modeRole, summarize: summarize,
  seenStatePath: seenStatePath, parseSeenState: parseSeenState
}
