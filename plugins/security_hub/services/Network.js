// SPDX-License-Identifier: MIT
//
// Rules for the Network views (plan tasks 3.6 and 3.10, docs/ipc-protocol.md
// §4.6): the saved firewall rules and the add-rule form (HubRules.qml), the
// held outbound connections that ConnectionPrompt.qml asks about, kept by
// SecurityIPC from FIREWALL_CONNECTION_PROMPT / _RESOLVED, and the
// mode-aware Network tab (NetworkSnitch.qml): the mode banner and switch,
// UFW's rules, blocked traffic and temporary decisions. Free of QML so it
// can be tested with plain node.
.pragma library

// ------------------------------------------------------------------ rules

// `rules` in rule_id order, the order the daemon adds them in.
function sortRules(rules) {
  if (!Array.isArray(rules)) return []
  return rules.slice().sort(function(a, b) { return a.rule_id - b.rule_id })
}

function findRule(rules, ruleId) {
  for (var i = 0; i < rules.length; i++)
    if (rules[i].rule_id === ruleId) return rules[i]
  return null
}

function removeRule(rules, ruleId) {
  var next = rules.filter(function(r) { return r.rule_id !== ruleId })
  return next.length === rules.length ? rules : next
}

function upsertRule(rules, rule) {
  if (!rule || typeof rule.rule_id !== "number") return rules
  return sortRules(removeRule(rules, rule.rule_id).concat([rule]))
}

// "0.0.0.0/0" and "::/0" read as "any address".
function isAnyAddress(address) {
  return address === "0.0.0.0/0" || address === "::/0"
}

function portText(spec) {
  var proto = spec.protocol ? spec.protocol.toUpperCase() : ""
  if (spec.port !== undefined && spec.port !== null) return (proto ? proto + " " : "") + "port " + spec.port
  return proto ? "all " + proto : "every protocol"
}

// "Block outbound to 203.0.113.0/24, TCP port 443"
function ruleTitle(rule) {
  if (!rule) return ""
  var verb = rule.verdict === "allow" ? "Allow" : "Block"
  var toFrom = rule.direction === "inbound" ? "inbound from " : "outbound to "
  var who = isAnyAddress(rule.address)
    ? (rule.address === "::/0" ? "any IPv6 address" : "any IPv4 address")
    : rule.address
  return verb + " " + toFrom + who + ", " + portText(rule)
}

// The program an executable rule is for, or "" for every program.
function ruleProgram(rule) {
  return rule && rule.executable ? rule.executable : ""
}

function ruleRole(rule) {
  if (rule && rule.loaded === false) return "muted"
  return rule && rule.verdict === "allow" ? "success" : "danger"
}

// Why a saved rule is not enforced now (FirewallRule.loaded is false).
function inactiveNote(rule, mode) {
  if (!rule || rule.loaded !== false) return ""
  if (mode === "ufw") return "Saved, not enforced while UFW is on"
  if (rule.executable) return "Saved, not enforced: connections cannot be intercepted"
  return "Saved, not enforced now"
}

// --------------------------------------------------------------- the form

function blankForm() {
  return { verdict: "block", direction: "outbound", address: "", protocol: "", port: "", executable: "" }
}

function isIPv4(text) {
  var parts = text.split(".")
  if (parts.length !== 4) return false
  return parts.every(function(p) { return /^[0-9]{1,3}$/.test(p) && Number(p) <= 255 })
}

// Loose: the daemon parses it properly. Hex groups, at most one "::",
// and an optional IPv4 tail.
function isIPv6(text) {
  if (!/^[0-9A-Fa-f:.]+$/.test(text) || text.indexOf(":") < 0) return false
  if (text.split("::").length > 2) return false
  var groups = text.split(":")
  var last = groups[groups.length - 1]
  if (last.indexOf(".") >= 0 && !isIPv4(last)) return false
  return groups.every(function(g, i) {
    return g === "" || (i === groups.length - 1 && g.indexOf(".") >= 0) || /^[0-9A-Fa-f]{1,4}$/.test(g)
  }) && groups.length <= 9
}

// "" when `text` is an address or CIDR prefix, otherwise why not.
function addressError(text) {
  if (text === "") return "Enter an address, such as 203.0.113.7 or 203.0.113.0/24"
  var slash = text.indexOf("/")
  var ip = slash >= 0 ? text.slice(0, slash) : text
  var v4 = isIPv4(ip)
  if (!v4 && !isIPv6(ip)) return "'" + text + "' is not an IP address or prefix"
  if (slash >= 0) {
    var len = text.slice(slash + 1)
    if (!/^[0-9]{1,3}$/.test(len) || Number(len) > (v4 ? 32 : 128))
      return "The prefix length must be 0 to " + (v4 ? 32 : 128)
  }
  return ""
}

// What FIREWALL_ADD_RULE would do with `form` in firewall mode `mode`:
// { spec } to send, or { error } to show. `warning` goes with a spec that
// can be sent but needs saying (a password, a rule saved but not
// enforced).
function specFromForm(form, mode) {
  var address = String(form.address || "").trim()
  var badAddress = addressError(address)
  if (badAddress) return { error: badAddress }
  var spec = { verdict: form.verdict === "allow" ? "allow" : "block",
               direction: form.direction === "inbound" ? "inbound" : "outbound",
               address: address }
  if (form.protocol === "tcp" || form.protocol === "udp") spec.protocol = form.protocol
  var port = String(form.port || "").trim()
  if (port !== "") {
    if (!spec.protocol) return { error: "Pick TCP or UDP to limit the rule to a port" }
    if (!/^[0-9]{1,5}$/.test(port) || Number(port) < 1 || Number(port) > 65535)
      return { error: "The port must be a number from 1 to 65535" }
    spec.port = Number(port)
  }
  var exe = String(form.executable || "").trim()
  if (exe !== "") {
    if (spec.direction !== "outbound") return { error: "A rule for one program must be outbound" }
    if (exe.charAt(0) !== "/") return { error: "Give the program's full path, such as /usr/bin/curl" }
    spec.executable = exe
  }
  // The daemon refuses this one (MODE_CONFLICT); say so before asking.
  if (spec.verdict === "allow" && spec.direction === "inbound" && (mode === "ufw" || mode === "both"))
    return { error: "UFW decides inbound traffic while it is on, so this allow would do nothing. "
      + "Use `ufw allow`, or switch to the Security Hub firewall." }
  var result = { spec: spec }
  if (spec.verdict === "allow" && spec.direction === "inbound") result.warning = "Asks for your password: this opens the machine to the network."
  else if (mode === "ufw" && !spec.executable) result.warning = "Saved, but not enforced while UFW is on."
  return result
}

function ruleErrorText(error) {
  if (!error) return ""
  switch (error.code) {
  case -32004: return "Not authorized: the password prompt was cancelled or refused."
  case -32003: return "That rule is already gone."
  case -32002: return error.message || "The firewall is not available."
  default: return error.message || "The firewall refused the rule."
  }
}

// ---------------------------------------------------------------- prompts

// Prompts kept, newest last. Pending ones are never dropped for room.
var MAX_PROMPTS = 50

// How long a resolved prompt stays on screen, by what ended it.
var LINGER_MS = { user: 1500, timeout: 4000 }

// Answers the prompt card offers, in order. `scope` goes to FIREWALL_DECIDE.
var SCOPES = [
  { id: "once", label: "Once", hint: "Only this connection" },
  { id: "process", label: "This process", hint: "Until this process exits" },
  { id: "always", label: "Always", hint: "Save a rule for this program, address and port" }
]

function isPending(prompt) {
  return !!prompt && !prompt.verdict
}

function findPrompt(prompts, requestId) {
  for (var i = 0; i < prompts.length; i++)
    if (prompts[i].request_id === requestId) return prompts[i]
  return null
}

function trim(prompts) {
  var extra = prompts.length - MAX_PROMPTS
  if (extra <= 0) return prompts
  return prompts.filter(function(p) {
    if (extra > 0 && !isPending(p)) {
      extra--
      return false
    }
    return true
  })
}

// FIREWALL_CONNECTION_PROMPT, seen at `now` (ms).
function addPrompt(prompts, params, now) {
  if (!params || typeof params.request_id !== "number") return prompts
  var prompt = {}
  for (var key in params) prompt[key] = params[key]
  prompt.received_at = now
  var next = prompts.filter(function(p) { return p.request_id !== prompt.request_id })
  next.push(prompt)
  return trim(next)
}

// FIREWALL_CONNECTION_RESOLVED `{request_id, verdict, decided_by}`.
// `scope` is what this shell sent, if it answered.
function resolvePrompt(prompts, params, now, scope) {
  if (!params || typeof params.request_id !== "number") return prompts
  var changed = false
  var next = prompts.map(function(p) {
    if (p.request_id !== params.request_id || !isPending(p)) return p
    changed = true
    var copy = {}
    for (var key in p) copy[key] = p[key]
    copy.verdict = params.verdict === "allow" ? "allow" : "block"
    copy.decided_by = params.decided_by === "user" ? "user" : "timeout"
    copy.resolved_at = now
    if (scope) copy.scope = scope
    return copy
  })
  return changed ? next : prompts
}

// Pending prompts, oldest first. One past its expires_at by more than a
// few seconds lost its RESOLVED event; the daemon has decided it.
function pendingPrompts(prompts, now) {
  return prompts.filter(function(p) { return isPending(p) && now < p.expires_at + 5000 })
}

function lingerMs(prompt) {
  return LINGER_MS[prompt.decided_by] || LINGER_MS.timeout
}

// When the card next changes on its own, in ms from `now`; -1 for never.
function nextChangeIn(prompts, now) {
  var soonest = -1
  for (var i = 0; i < prompts.length; i++) {
    var p = prompts[i]
    var at = isPending(p) ? p.expires_at + 5000 : p.resolved_at + lingerMs(p)
    var wait = at - now
    if (wait > 0 && (soonest < 0 || wait < soonest)) soonest = wait
  }
  return soonest
}

function secondsLeft(prompt, now) {
  if (!prompt) return 0
  return Math.max(0, Math.ceil((prompt.expires_at - now) / 1000))
}

// "24 s left"
function countdownText(prompt, now) {
  return secondsLeft(prompt, now) + " s left"
}

function programName(executable) {
  if (!executable) return "Unknown program"
  var path = String(executable).replace(/ \(deleted\)$/, "")
  var slash = path.lastIndexOf("/")
  return slash >= 0 && slash < path.length - 1 ? path.slice(slash + 1) : path
}

var WELL_KNOWN = { 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 123: "NTP", 143: "IMAP", 443: "HTTPS",
  465: "SMTPS", 587: "mail submission", 853: "DNS over TLS", 993: "IMAPS", 3478: "STUN", 5222: "XMPP", 8080: "HTTP" }

// "192.0.2.1, TCP port 443 (HTTPS)"
function destinationText(prompt) {
  if (!prompt) return ""
  var service = prompt.protocol === "tcp" || prompt.protocol === "udp" ? WELL_KNOWN[prompt.port] : undefined
  return prompt.address + ", " + String(prompt.protocol || "").toUpperCase() + " port " + prompt.port
    + (service ? " (" + service + ")" : "")
}

function promptTitle(prompt) {
  return programName(prompt && prompt.executable) + " wants to connect"
}

function scopeLabel(scopeId) {
  for (var i = 0; i < SCOPES.length; i++) if (SCOPES[i].id === scopeId) return SCOPES[i].label
  return ""
}

// What ended a resolved prompt, for the card.
function resolvedTitle(prompt) {
  if (!prompt || isPending(prompt)) return ""
  var verb = prompt.verdict === "allow" ? "Allowed" : "Blocked"
  if (prompt.decided_by === "timeout") return verb + ": no answer in time"
  if (prompt.scope === "always") return verb + " always"
  if (prompt.scope === "process") return verb + " until the process exits"
  if (prompt.scope === "once") return verb + " once"
  return verb + " (answered elsewhere)"
}

function resolvedRole(prompt) {
  if (!prompt || isPending(prompt)) return "accent"
  return prompt.verdict === "allow" ? "success" : "danger"
}

function decideErrorText(error) {
  if (!error) return ""
  switch (error.code) {
  case -32003: return "This connection was already decided."
  case -32004: return "The connection was answered, but saving the rule was not authorized."
  default: return error.message || "The answer was not accepted."
  }
}

// ------------------------------------------------------------------- mode

// The banner at the top of the Network tab (plan §5.21), for
// FirewallMode.mode. `actions` are the modes it offers to switch to.
function banner(mode) {
  var both = [{ mode: "ufw", label: "Use UFW" }, { mode: "standalone", label: "Use Security Hub firewall" }]
  switch (mode) {
  case "ufw": return { role: "accent",
    text: "UFW is active. It filters every packet alongside the Security Hub, and the hub cannot open ports UFW "
      + "blocks. The rules below are UFW's and are read-only here. Temporary allow and block still work.",
    actions: [{ mode: "standalone", label: "Use Security Hub firewall instead" }] }
  case "standalone": return { role: "success",
    text: "The Security Hub firewall protects this machine. UFW is off.",
    actions: [{ mode: "ufw", label: "Hand back to UFW" }] }
  case "both": return { role: "warning",
    text: "UFW and the Security Hub firewall are both enforcing. Traffic must pass both.", actions: both }
  case "none": return { role: "danger", text: "No firewall is active.", actions: both }
  case "unknown": return { role: "muted",
    text: "Cannot read the firewall state: the privileged helper is not running.", actions: [] }
  default: return { role: "muted", text: "", actions: [] }
  }
}

// Lines under the banner: what FirewallMode says is odd.
function modeNotes(info) {
  if (!info) return []
  var notes = []
  if (info.detail) notes.push(info.detail)
  if (info.ufw && info.ufw.before_rules_modified) notes.push("UFW's before.rules has local changes.")
  return notes
}

var RECOVERY_COMMAND = "sudo ufw --force enable && sudo nft delete table inet omarchy_sec && "
  + "sudo rm -f /var/lib/omarchy-security/firewall.nft /var/lib/omarchy-security/mode"

// What the switch dialog says before switching to `target` ("ufw" or
// "standalone") from FirewallMode `info`.
function switchPlan(target, info) {
  var from = info && info.mode ? info.mode : ""
  var docker = info && info.docker_protection
  if (target === "standalone") {
    var changes = []
    if (from === "both") changes.push("The Security Hub policy is already loaded; UFW is turned off.")
    else changes.push("The Security Hub loads its own policy first, then turns UFW off, so the machine is never unprotected.")
    changes.push("Incoming connections are dropped unless a rule allows them. Replies, loopback, the usual ICMP, "
      + "DHCP, mDNS and SSDP stay allowed, as with UFW.")
    changes.push("The policy is also loaded at boot, before you log in.")
    changes.push("UFW's rules stay in /etc/ufw for when you hand back.")
    return { title: "Switch to the Security Hub firewall", changes: changes,
      docker: "Docker: ports published by containers stay reachable from private networks only"
        + (docker === "ufw-docker" ? ", as ufw-docker does now." : "."),
      confirm: "Switch", password: "Asks for the administrator password." }
  }
  var back = []
  if (from === "both") back.push("UFW is already on; the Security Hub policy is removed.")
  else back.push("UFW is turned on again with the rules in /etc/ufw, then the Security Hub policy is removed.")
  back.push("The hub's saved rules are kept, but only its program rules are enforced while UFW is on.")
  back.push("Temporary inbound allows become UFW rules until they expire.")
  return { title: "Hand back to UFW", changes: back,
    docker: docker === "none" || !info || !info.ufw || !info.ufw.installed ? ""
      : "Docker: UFW protects published container ports only if ufw-docker is set up.",
    confirm: "Hand back", password: "Asks for the administrator password." }
}

function modeErrorText(error) {
  if (!error) return ""
  switch (error.code) {
  case -32004: return "Not switched: the password prompt was cancelled or refused."
  case -32009: return error.message || "The firewall cannot switch in this state."
  default: return error.message || "The firewall did not switch."
  }
}

// "Imported 6 of UFW's rules." after a switch, from SetModeResult.
function importSummary(result) {
  if (!result) return ""
  var n = Array.isArray(result.imported) ? result.imported.length : 0
  var skipped = Array.isArray(result.not_imported) ? result.not_imported.length : 0
  var parts = []
  if (n > 0) parts.push("Imported " + n + (n === 1 ? " rule" : " rules") + " from UFW.")
  if (skipped > 0) parts.push(skipped + (skipped === 1 ? " UFW rule was" : " UFW rules were") + " not imported.")
  return parts.join(" ")
}

// Which lists the Network tab shows in `mode` (plan §5.21). `info` is the
// FirewallMode, for `unknown`.
function sections(mode, info) {
  var ufwOn = !!(info && info.ufw && info.ufw.enabled_in_conf)
  switch (mode) {
  case "ufw": return { ufwRules: true, baseline: false, collapseInactive: true, alertsSample: true }
  case "standalone": return { ufwRules: false, baseline: true, collapseInactive: false, alertsSample: false }
  case "both": return { ufwRules: true, baseline: true, collapseInactive: false, alertsSample: true }
  case "unknown": return { ufwRules: ufwOn, baseline: false, collapseInactive: ufwOn, alertsSample: ufwOn }
  default: return { ufwRules: false, baseline: false, collapseInactive: false, alertsSample: false }
  }
}

// What the standalone policy allows before the saved rules (docs §4.6).
var BASELINE = [
  "Replies to connections this machine opened",
  "Loopback traffic",
  "The ICMP and ICMPv6 messages networks need (ping, errors, neighbour discovery)",
  "DHCP and DHCPv6 replies",
  "mDNS (local names) and SSDP (device discovery)",
  "Docker: published ports only from private networks",
  "Everything else inbound is dropped and logged"
]

// -------------------------------------------------------------- UFW rules

function ufwPortText(protocol, port) {
  var proto = protocol && protocol !== "any" ? String(protocol).toUpperCase() : ""
  if (port) return (proto ? proto + " " : "") + (/[,:]/.test(port) ? "ports " : "port ") + String(port).replace(/:/g, "-")
  return proto ? "all " + proto : "all traffic"
}

// "Allow in TCP port 22 from 192.168.1.0/24" for a UfwRule.
function ufwRuleTitle(rule) {
  if (!rule) return ""
  var verbs = { allow: "Allow", deny: "Deny", reject: "Reject", limit: "Limit" }
  var line = (verbs[rule.action] || rule.action) + (rule.direction === "out" ? " out " : " in ")
    + ufwPortText(rule.protocol, rule.port)
  if (rule.src && rule.src !== "any") line += " from " + rule.src
  if (rule.dst && rule.dst !== "any") line += " to " + rule.dst
  if (rule.iface) line += " on " + rule.iface
  return line + (rule.ipv6 ? " (IPv6)" : "")
}

// The rule's own comment, not the hub's tag on its temporary rules.
function ufwRuleComment(rule) {
  if (!rule || !rule.comment || rule.temp_id !== undefined) return ""
  return rule.comment
}

function ufwRuleRole(rule) {
  return rule && (rule.action === "allow" || rule.action === "limit") ? "success" : "danger"
}

// ------------------------------------------------------------- durations

var DEFAULT_DURATIONS = [300, 3600, 28800]

// The durations to offer: FIREWALL_TEMP_LIST's `durations_secs`, or the
// daemon's defaults from an older daemon.
function durations(list) {
  if (!Array.isArray(list)) return DEFAULT_DURATIONS
  var ok = list.filter(function(s) { return typeof s === "number" && s >= 60 && s <= 86400 && Math.floor(s) === s })
  return ok.length > 0 ? ok : DEFAULT_DURATIONS
}

// "5 min", "1 h", "1 h 30 min", "90 s"
function durationLabel(secs) {
  if (secs < 60) return secs + " s"
  if (secs < 3600) return (secs % 60 === 0 ? secs / 60 : Math.round(secs / 60)) + " min"
  var h = Math.floor(secs / 3600), m = Math.round((secs % 3600) / 60)
  return m === 0 ? h + " h" : h + " h " + m + " min"
}

// "45 s left", "12 min left", "2 h 5 min left"
function remainingText(expiresAt, now) {
  var secs = Math.max(0, Math.ceil((expiresAt - now) / 1000))
  if (secs < 60) return secs + " s left"
  var mins = Math.ceil(secs / 60)
  if (mins < 60) return mins + " min left"
  var h = Math.floor(mins / 60), m = mins % 60
  return (m === 0 ? h + " h" : h + " h " + m + " min") + " left"
}

// ---------------------------------------------------- temporary decisions

// The decisions still in force at `now`, the soonest to expire first.
function liveDecisions(decisions, now) {
  if (!Array.isArray(decisions)) return []
  return decisions.filter(function(d) { return d.expires_at > now })
    .sort(function(a, b) { return a.expires_at - b.expires_at || a.temp_id - b.temp_id })
}

function findDecision(decisions, tempId) {
  for (var i = 0; i < decisions.length; i++) if (decisions[i].temp_id === tempId) return decisions[i]
  return null
}

// The newest decision still in force that was made from alert `alertId`.
function decisionForAlert(decisions, alertId, now) {
  var found = null
  var live = liveDecisions(decisions, now)
  for (var i = 0; i < live.length; i++)
    if (live[i].alert_id === alertId && (!found || live[i].created_at > found.created_at)) found = live[i]
  return found
}

function backendLabel(backend) {
  return backend === "ufw" ? "UFW rule" : "Security Hub table"
}

// "Allowed, 58 min left" on an alert row with a decision.
function decisionNote(decision, now) {
  if (!decision) return ""
  return (decision.spec.verdict === "allow" ? "Allowed" : "Blocked") + ", " + remainingText(decision.expires_at, now)
}

function isMuted(alert, now) {
  return !!alert && typeof alert.muted_until === "number" && alert.muted_until > now
}

function tempErrorText(error) {
  if (!error) return ""
  switch (error.code) {
  case -32004: return "Not authorized: the password prompt was cancelled or refused."
  case -32003: return "Already gone."
  case -32009: return error.message || "No firewall is active; turn one on first."
  default: return error.message || "The firewall refused it."
  }
}

if (typeof module !== "undefined") module.exports = {
  sortRules: sortRules, findRule: findRule, removeRule: removeRule, upsertRule: upsertRule,
  isAnyAddress: isAnyAddress, ruleTitle: ruleTitle, ruleProgram: ruleProgram, ruleRole: ruleRole,
  inactiveNote: inactiveNote, blankForm: blankForm, addressError: addressError, specFromForm: specFromForm,
  ruleErrorText: ruleErrorText,
  MAX_PROMPTS: MAX_PROMPTS, LINGER_MS: LINGER_MS, SCOPES: SCOPES, isPending: isPending,
  findPrompt: findPrompt, addPrompt: addPrompt, resolvePrompt: resolvePrompt,
  pendingPrompts: pendingPrompts, lingerMs: lingerMs, nextChangeIn: nextChangeIn,
  secondsLeft: secondsLeft, countdownText: countdownText, programName: programName,
  destinationText: destinationText, promptTitle: promptTitle, scopeLabel: scopeLabel,
  resolvedTitle: resolvedTitle, resolvedRole: resolvedRole, decideErrorText: decideErrorText,
  banner: banner, modeNotes: modeNotes, RECOVERY_COMMAND: RECOVERY_COMMAND, switchPlan: switchPlan,
  modeErrorText: modeErrorText, importSummary: importSummary, sections: sections, BASELINE: BASELINE,
  ufwRuleTitle: ufwRuleTitle, ufwRuleComment: ufwRuleComment, ufwRuleRole: ufwRuleRole,
  DEFAULT_DURATIONS: DEFAULT_DURATIONS, durations: durations, durationLabel: durationLabel,
  remainingText: remainingText, liveDecisions: liveDecisions, findDecision: findDecision,
  decisionForAlert: decisionForAlert, backendLabel: backendLabel, decisionNote: decisionNote,
  isMuted: isMuted, tempErrorText: tempErrorText
}
