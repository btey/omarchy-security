// SPDX-License-Identifier: MIT
//
// Rules for the tabbed hub (SecurityHub.qml and HubView.qml, plan task
// 3.9, §5.11): the tabs, which one a caller's payload opens, what needs
// attention in each, and the Overview's alert history, which merges the
// threat alerts and the blocked-traffic alerts SecurityIPC keeps. Free of
// QML so it can be tested with plain node.
.pragma library

// In display order. `module` is the daemon module the tab is about.
var TABS = [
  { id: "overview", label: "Overview", icon: "\u{F056E}", module: "" },       // nf-md-view_dashboard
  { id: "threats", label: "Threats", icon: "\u{F0026}", module: "threat" },   // nf-md-alert
  { id: "usb", label: "USB", icon: "\u{F0553}", module: "usbguard" },         // nf-md-usb
  { id: "tokens", label: "Security keys", icon: "\u{F0306}", module: "token" }, // nf-md-key
  { id: "network", label: "Network", icon: "\u{F059F}", module: "firewall" }, // nf-md-web
  { id: "vaults", label: "Vaults", icon: "\u{F033E}", module: "vault" },      // nf-md-lock
  { id: "hardening", label: "Hardening", icon: "\u{F0565}", module: "posture" } // nf-md-shield_check
]

// Other names a caller may use: the daemon's module ids, and the plan's.
var ALIASES = {
  threat: "threats", usbguard: "usb", token: "tokens", keys: "tokens", yubikey: "tokens",
  firewall: "network", vault: "vaults", posture: "hardening", sandbox: "threats"
}

function tabIndex(id) {
  for (var i = 0; i < TABS.length; i++) if (TABS[i].id === id) return i
  return -1
}

// The tab `name` means, or "" when it names none.
function tabFor(name) {
  var key = String(name || "").toLowerCase()
  if (tabIndex(key) >= 0) return key
  return ALIASES[key] || ""
}

// The tab to show for `open(payloadJson)`: the payload's `tab` when it
// names one, else `current` (a bare open comes back to where the user was).
function tabFromPayload(payloadJson, current) {
  var payload = {}
  try { payload = JSON.parse(payloadJson || "{}") || {} } catch (e) {}
  var tab = typeof payload.tab === "string" ? tabFor(payload.tab) : ""
  return tab || current || "overview"
}

// The tab `delta` steps from `id`, wrapping.
function neighbour(id, delta) {
  var i = tabIndex(id)
  if (i < 0) return TABS[0].id
  var n = TABS.length
  return TABS[((i + delta) % n + n) % n].id
}

// What each tab has waiting, as tab id -> {count, role}. A count of 0
// draws a dot. `state` holds the lists SecurityIPC keeps:
//   threatAlerts, usbDevices, touchRequests, heldConnections (the number
//   of Network.pendingPrompts), unseenAlerts (a number), and posture
//   (Posture.overall, or "")
function attention(state) {
  var s = state || {}
  var out = {}
  var pending = 0
  var threats = s.threatAlerts || []
  for (var i = 0; i < threats.length; i++)
    if (threats[i].state === "open" || threats[i].state === "quarantined") pending++
  if (pending > 0) out.threats = { count: pending, role: "danger" }

  var blocked = 0
  var devices = s.usbDevices || []
  for (var j = 0; j < devices.length; j++) if (devices[j].rule === "block") blocked++
  if (blocked > 0) out.usb = { count: blocked, role: "warning" }

  var touches = 0
  var requests = s.touchRequests || []
  for (var k = 0; k < requests.length; k++) if (!requests[k].outcome) touches++
  if (touches > 0) out.tokens = { count: touches, role: "warning" }

  var held = s.heldConnections > 0 ? s.heldConnections : 0
  var network = held + (s.unseenAlerts > 0 ? s.unseenAlerts : 0)
  if (network > 0) out.network = { count: network, role: held > 0 ? "danger" : "warning" }

  if (s.posture === "fail") out.hardening = { count: 0, role: "danger" }
  else if (s.posture === "warn") out.hardening = { count: 0, role: "warning" }
  return out
}

// "3", "9+", or "" for a dot.
function countText(count) {
  if (!(count > 0)) return ""
  return count > 9 ? "9+" : String(count)
}

// Entries in the Overview's history, most recent first, at most `max`:
// {key, kind: "threat" | "firewall", tab, time, alert}. A threat alert
// counts from when it was raised, a blocked-traffic alert from its last
// packet, so a stream of packets keeps its alert near the top.
function history(threatAlerts, firewallAlerts, max) {
  var out = []
  var threats = threatAlerts || []
  for (var i = 0; i < threats.length; i++)
    out.push({ key: "threat:" + threats[i].alert_id, kind: "threat", tab: "threats",
      time: threats[i].detected_at || 0, alert: threats[i] })
  var blocked = firewallAlerts || []
  for (var j = 0; j < blocked.length; j++)
    out.push({ key: "firewall:" + blocked[j].alert_id, kind: "firewall", tab: "network",
      time: blocked[j].last_seen || blocked[j].first_seen || 0, alert: blocked[j] })
  out.sort(function(a, b) { return b.time - a.time || (a.key < b.key ? -1 : a.key > b.key ? 1 : 0) })
  return out.slice(0, max || 8)
}

// "Blocked TCP from 203.0.113.9 to port 22" for a FirewallAlert; the port
// is the one on this machine, or the remote one for outbound traffic.
function firewallTitle(alert) {
  if (!alert) return ""
  var proto = alert.protocol ? String(alert.protocol).toUpperCase() : "traffic"
  var hasPort = alert.dst_port !== undefined && alert.dst_port !== null
  if (alert.direction === "outbound")
    return "Blocked " + proto + " to " + (alert.dst || "?") + (hasPort ? " port " + alert.dst_port : "")
  var line = "Blocked " + proto + " from " + (alert.src || "?")
  if (alert.direction === "forward") return line + " to a container" + (hasPort ? ", port " + alert.dst_port : "")
  return line + (hasPort ? " to port " + alert.dst_port : "")
}

// "12 packets · wlan0 · muted", under the title.
function firewallDetail(alert, now) {
  if (!alert) return ""
  var parts = [alert.count === 1 ? "1 packet" : (alert.count || 0) + " packets"]
  if (alert.iface) parts.push(alert.iface)
  if (alert.source === "ufw") parts.push("UFW")
  if (typeof alert.muted_until === "number" && alert.muted_until > now) parts.push("muted")
  return parts.join(" · ")
}

// "just now", "5 min ago", "2 h ago", "3 d ago".
function ago(ms) {
  var secs = Math.max(0, Math.round(ms / 1000))
  if (secs < 60) return "just now"
  var mins = Math.round(secs / 60)
  if (mins < 60) return mins + " min ago"
  var hours = Math.round(mins / 60)
  if (hours < 48) return hours + " h ago"
  return Math.round(hours / 24) + " d ago"
}

// The Overview's one-line summary of the modules: "All 7 modules active",
// or "5 of 7 modules active".
function modulesSummary(modules) {
  var list = modules || []
  var active = 0
  for (var i = 0; i < list.length; i++) if (list[i].state === "active") active++
  if (list.length === 0) return ""
  if (active === list.length) return "All " + list.length + " modules active"
  return active + " of " + list.length + " modules active"
}

if (typeof module !== "undefined") module.exports = {
  TABS: TABS, tabIndex: tabIndex, tabFor: tabFor, tabFromPayload: tabFromPayload,
  neighbour: neighbour, attention: attention, countText: countText, history: history,
  firewallTitle: firewallTitle, firewallDetail: firewallDetail, ago: ago, modulesSummary: modulesSummary
}
