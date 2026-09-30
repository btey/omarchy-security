// SPDX-License-Identifier: MIT
//
// Rules for the hardening audit view (HardeningSem.qml, plan task 3.6,
// docs/ipc-protocol.md §4.8): the PostureReport from POSTURE_GET_REPORT,
// POSTURE_REFRESH and POSTURE_CHANGED, drawn as a traffic light. Free of
// QML so it can be tested with plain node.
.pragma library

// Best to worst, as the protocol lists them.
var STATUSES = ["pass", "unknown", "warn", "fail"]

// The checks the daemon runs, in display order.
var CHECKS = [
  { id: "lsm", label: "Mandatory access control" },
  { id: "ptrace_scope", label: "Process tracing (ptrace)" },
  { id: "docker_group", label: "Docker group" },
  { id: "swap_encryption", label: "Swap encryption" }
]

function checkLabel(checkId) {
  for (var i = 0; i < CHECKS.length; i++) if (CHECKS[i].id === checkId) return CHECKS[i].label
  return checkId
}

function rank(status) {
  var i = STATUSES.indexOf(status)
  return i < 0 ? 1 : i
}

// The report's checks in CHECKS order; a check this shell does not know
// goes last, in the daemon's order.
function sortedChecks(report) {
  if (!report || !Array.isArray(report.checks)) return []
  var order = function(c) {
    for (var i = 0; i < CHECKS.length; i++) if (CHECKS[i].id === c.check_id) return i
    return CHECKS.length
  }
  return report.checks.map(function(c, i) { return { c: c, i: i } })
    .sort(function(a, b) { return order(a.c) - order(b.c) || a.i - b.i })
    .map(function(x) { return x.c })
}

// The worst status among the checks, which is what `overall` says; worked
// out again in case a check is newer than the field.
function overall(report) {
  var checks = sortedChecks(report)
  if (checks.length === 0) return report && report.overall ? report.overall : "unknown"
  var worst = "pass"
  for (var i = 0; i < checks.length; i++) if (rank(checks[i].status) > rank(worst)) worst = checks[i].status
  return worst
}

function statusRole(status) {
  switch (status) {
  case "pass": return "success"
  case "warn": return "warning"
  case "fail": return "danger"
  default: return "muted"
  }
}

function statusLabel(status) {
  switch (status) {
  case "pass": return "Pass"
  case "warn": return "Warning"
  case "fail": return "Fail"
  default: return "Unknown"
  }
}

// nf-md-check_circle, alert, close_circle, help_circle
function statusIcon(status) {
  switch (status) {
  case "pass": return "\u{F05E0}"
  case "warn": return "\u{F0026}"
  case "fail": return "\u{F0159}"
  default: return "\u{F02D7}"
  }
}

function count(report, status) {
  return sortedChecks(report).filter(function(c) { return c.status === status }).length
}

// One line for the section header.
function summaryText(report) {
  var checks = sortedChecks(report)
  if (checks.length === 0) return ""
  var fails = count(report, "fail")
  var warns = count(report, "warn")
  if (fails === 0 && warns === 0) {
    var unknown = count(report, "unknown")
    return unknown === 0 ? "All " + checks.length + " checks pass"
      : unknown + (unknown === 1 ? " check" : " checks") + " could not be run"
  }
  var parts = []
  if (fails > 0) parts.push(fails + (fails === 1 ? " problem" : " problems"))
  if (warns > 0) parts.push(warns + (warns === 1 ? " warning" : " warnings"))
  return parts.join(", ")
}

// "Checked just now", "Checked 3 min ago". `evaluated_at` is ms.
function checkedText(report, now) {
  if (!report || !report.evaluated_at) return ""
  var secs = Math.max(0, Math.floor((now - report.evaluated_at) / 1000))
  if (secs < 60) return "Checked just now"
  var mins = Math.floor(secs / 60)
  if (mins < 60) return "Checked " + mins + " min ago"
  var hours = Math.floor(mins / 60)
  return "Checked " + hours + (hours === 1 ? " hour ago" : " hours ago")
}

// Text for a view with no report to draw, or "".
function emptyText(ready, moduleState, error, report) {
  if (!ready) return "Not connected to omarchy-securityd"
  if (moduleState === "unavailable" || moduleState === "not_implemented") return "The hardening audit is not available"
  if (error) return "Could not read the audit: " + (error.message || "unknown error")
  if (!report) return "Loading…"
  if (sortedChecks(report).length === 0) return "The audit has no checks to report"
  return ""
}

if (typeof module !== "undefined") module.exports = {
  STATUSES: STATUSES, CHECKS: CHECKS, checkLabel: checkLabel, rank: rank, sortedChecks: sortedChecks,
  overall: overall, statusRole: statusRole, statusLabel: statusLabel, statusIcon: statusIcon,
  count: count, summaryText: summaryText, checkedText: checkedText, emptyText: emptyText
}
