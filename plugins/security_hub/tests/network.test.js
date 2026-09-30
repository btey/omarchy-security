// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

// Network.js is a QML `.pragma library` script; drop the pragma to run it
// as plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Network.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const N = sandbox.module.exports
const plain = value => JSON.parse(JSON.stringify(value))
const ids = list => plain(list.map(p => p.request_id))

const rule = (id, extra) => Object.assign({ rule_id: id, verdict: "block", direction: "outbound",
  address: "203.0.113.0/24", loaded: true }, extra)
const prompt = (id, extra) => Object.assign({ request_id: id, pid: 4242, executable: "/usr/bin/curl",
  protocol: "tcp", address: "192.0.2.1", port: 443, expires_at: 31000 }, extra)
const form = extra => Object.assign(N.blankForm(), { address: "203.0.113.7" }, extra)

test("keeps rules in rule_id order", () => {
  let rules = N.sortRules([rule(3), rule(1)])
  rules = N.upsertRule(rules, rule(2))
  assert.deepStrictEqual(plain(rules.map(r => r.rule_id)), [1, 2, 3])
  assert.strictEqual(N.upsertRule(rules, null), rules)
  assert.strictEqual(N.removeRule(rules, 9), rules)
  assert.deepStrictEqual(plain(N.removeRule(rules, 2).map(r => r.rule_id)), [1, 3])
  assert.strictEqual(N.findRule(rules, 3).rule_id, 3)
  assert.deepStrictEqual(plain(N.sortRules(null)), [])
})

test("describes a rule", () => {
  assert.strictEqual(N.ruleTitle(rule(1)), "Block outbound to 203.0.113.0/24, every protocol")
  assert.strictEqual(N.ruleTitle(rule(1, { verdict: "allow", direction: "inbound", address: "0.0.0.0/0",
    protocol: "tcp", port: 22 })), "Allow inbound from any IPv4 address, TCP port 22")
  assert.strictEqual(N.ruleTitle(rule(1, { address: "::/0", protocol: "udp" })),
    "Block outbound to any IPv6 address, all UDP")
  assert.strictEqual(N.ruleProgram(rule(1, { executable: "/usr/bin/curl" })), "/usr/bin/curl")
  assert.strictEqual(N.ruleProgram(rule(1)), "")
  assert.deepStrictEqual([rule(1), rule(1, { verdict: "allow" }), rule(1, { loaded: false })].map(N.ruleRole),
    ["danger", "success", "muted"])
  assert.strictEqual(N.inactiveNote(rule(1), "ufw"), "")
  assert.match(N.inactiveNote(rule(1, { loaded: false }), "ufw"), /UFW is on/)
  assert.match(N.inactiveNote(rule(1, { loaded: false, executable: "/usr/bin/curl" }), "standalone"), /intercepted/)
})

test("checks addresses the way the daemon will", () => {
  for (const ok of ["203.0.113.7", "203.0.113.0/24", "0.0.0.0/0", "::/0", "2001:db8::1", "2001:db8::/32",
    "::ffff:192.0.2.1", "fe80::1:2:3:4"])
    assert.strictEqual(N.addressError(ok), "", ok)
  for (const bad of ["", "example.com", "256.1.1.1", "1.2.3", "1.2.3.4/33", "2001:db8::/129", "1::2::3",
    "1.2.3.4/", "12345::"])
    assert.notStrictEqual(N.addressError(bad), "", bad)
})

test("builds a rule from the form", () => {
  assert.deepStrictEqual(plain(N.specFromForm(form(), "standalone")),
    { spec: { verdict: "block", direction: "outbound", address: "203.0.113.7" } })
  assert.deepStrictEqual(plain(N.specFromForm(form({ protocol: "tcp", port: " 443 ", executable: "/usr/bin/curl" }),
    "ufw").spec), { verdict: "block", direction: "outbound", address: "203.0.113.7", protocol: "tcp",
    port: 443, executable: "/usr/bin/curl" })

  assert.match(N.specFromForm(form({ address: "" }), "standalone").error, /Enter an address/)
  assert.match(N.specFromForm(form({ port: "443" }), "standalone").error, /TCP or UDP/)
  assert.match(N.specFromForm(form({ protocol: "udp", port: "70000" }), "standalone").error, /1 to 65535/)
  assert.match(N.specFromForm(form({ protocol: "udp", port: "0" }), "standalone").error, /1 to 65535/)
  assert.match(N.specFromForm(form({ direction: "inbound", executable: "/usr/bin/sshd" }), "standalone").error,
    /outbound/)
  assert.match(N.specFromForm(form({ executable: "curl" }), "standalone").error, /full path/)

  // An inbound allow: refused while UFW decides inbound traffic, and asks
  // for the password otherwise.
  const allowIn = form({ verdict: "allow", direction: "inbound", protocol: "tcp", port: "22" })
  for (const mode of ["ufw", "both"]) assert.match(N.specFromForm(allowIn, mode).error, /ufw allow/)
  assert.match(N.specFromForm(allowIn, "standalone").warning, /password/)
  // Other rules are saved in ufw mode but not enforced, except for one
  // program.
  assert.match(N.specFromForm(form(), "ufw").warning, /not enforced/)
  assert.strictEqual(N.specFromForm(form({ executable: "/usr/bin/curl" }), "ufw").warning, undefined)
  assert.strictEqual(N.specFromForm(form(), "standalone").warning, undefined)
})

test("error texts", () => {
  assert.match(N.ruleErrorText({ code: -32004, message: "x" }), /password/)
  assert.strictEqual(N.ruleErrorText({ code: -32009, message: "use ufw allow" }), "use ufw allow")
  assert.strictEqual(N.ruleErrorText(null), "")
  assert.match(N.decideErrorText({ code: -32003, message: "x" }), /already decided/)
  assert.match(N.decideErrorText({ code: -32004, message: "x" }), /not authorized/)
})

test("follows a prompt from PROMPT to RESOLVED", () => {
  let list = N.addPrompt([], prompt(1), 1000)
  list = N.addPrompt(list, prompt(2, { executable: "/usr/lib/firefox/firefox" }), 1100)
  assert.strictEqual(list[0].received_at, 1000)
  assert.deepStrictEqual(ids(N.pendingPrompts(list, 2000)), [1, 2])

  list = N.resolvePrompt(list, { request_id: 1, verdict: "allow", decided_by: "user" }, 3000, "process")
  const done = N.findPrompt(list, 1)
  assert.deepStrictEqual(plain([done.verdict, done.decided_by, done.scope, done.resolved_at]),
    ["allow", "user", "process", 3000])
  assert.deepStrictEqual(ids(N.pendingPrompts(list, 3000)), [2])
  // Unknown or repeated: the same list.
  assert.strictEqual(N.resolvePrompt(list, { request_id: 9, verdict: "allow", decided_by: "user" }, 3000), list)
  assert.strictEqual(N.resolvePrompt(list, { request_id: 1, verdict: "block", decided_by: "timeout" }, 3000), list)
  assert.strictEqual(N.addPrompt(list, { pid: 1 }, 3000), list)

  // A prompt whose RESOLVED never came stops being pending a little after
  // expires_at.
  assert.deepStrictEqual(ids(N.pendingPrompts(list, 31000 + 4999)), [2])
  assert.deepStrictEqual(ids(N.pendingPrompts(list, 31000 + 5000)), [])
  // The next change: request 1 stops lingering.
  assert.strictEqual(N.nextChangeIn(list, 3000), N.LINGER_MS.user)
  assert.strictEqual(N.nextChangeIn(list, 40000), -1)
})

test("drops resolved prompts first when the list is full", () => {
  let list = N.addPrompt([], prompt(1), 0)
  for (let id = 2; id <= N.MAX_PROMPTS + 5; id++) {
    list = N.addPrompt(list, prompt(id), id)
    list = N.resolvePrompt(list, { request_id: id, verdict: "block", decided_by: "timeout" }, id)
  }
  assert.strictEqual(list.length, N.MAX_PROMPTS)
  assert.strictEqual(list[0].request_id, 1, "the pending prompt stays")
})

test("prompt texts", () => {
  assert.strictEqual(N.promptTitle(prompt(1)), "curl wants to connect")
  assert.strictEqual(N.programName("/tmp/x (deleted)"), "x")
  assert.strictEqual(N.programName(""), "Unknown program")
  assert.strictEqual(N.destinationText(prompt(1)), "192.0.2.1, TCP port 443 (HTTPS)")
  assert.strictEqual(N.destinationText(prompt(1, { protocol: "udp", port: 51820 })), "192.0.2.1, UDP port 51820")
  assert.strictEqual(N.countdownText(prompt(1), 6500), "25 s left")
  assert.strictEqual(N.secondsLeft(prompt(1), 40000), 0)
  assert.deepStrictEqual(plain(N.SCOPES.map(s => s.id)), ["once", "process", "always"])
  assert.strictEqual(N.scopeLabel("process"), "This process")

  const resolved = extra => Object.assign(prompt(1), { verdict: "block", decided_by: "user" }, extra)
  assert.strictEqual(N.resolvedTitle(resolved({ scope: "once" })), "Blocked once")
  assert.strictEqual(N.resolvedTitle(resolved({ verdict: "allow", scope: "always" })), "Allowed always")
  assert.strictEqual(N.resolvedTitle(resolved({ scope: "process" })), "Blocked until the process exits")
  assert.strictEqual(N.resolvedTitle(resolved({ decided_by: "timeout" })), "Blocked: no answer in time")
  assert.match(N.resolvedTitle(resolved({})), /elsewhere/)
  assert.strictEqual(N.resolvedTitle(prompt(1)), "")
  assert.deepStrictEqual([prompt(1), resolved({ verdict: "allow" }), resolved({})].map(N.resolvedRole),
    ["accent", "success", "danger"])
})

// ------------------------------------------------------ mode-aware (3.10)

test("words the banner for every firewall mode", () => {
  const modes = b => plain(b.actions.map(a => a.mode))
  assert.deepStrictEqual(modes(N.banner("ufw")), ["standalone"])
  assert.match(N.banner("ufw").text, /read-only here\. Temporary allow and block still work\.$/)
  assert.deepStrictEqual(modes(N.banner("standalone")), ["ufw"])
  assert.strictEqual(N.banner("standalone").actions[0].label, "Hand back to UFW")
  assert.deepStrictEqual(modes(N.banner("both")), ["ufw", "standalone"])
  assert.deepStrictEqual(modes(N.banner("none")), ["ufw", "standalone"])
  assert.deepStrictEqual(plain(["ufw", "standalone", "both", "none", "unknown", ""].map(m => N.banner(m).role)),
    ["accent", "success", "warning", "danger", "muted", "muted"])
  // Nothing can be switched without the helper.
  assert.deepStrictEqual(modes(N.banner("unknown")), [])
  assert.match(N.banner("unknown").text, /helper is not running/)
  assert.deepStrictEqual(plain(N.modeNotes({ detail: "nftables.service is enabled and flushes the ruleset",
    ufw: { before_rules_modified: true } })),
    ["nftables.service is enabled and flushes the ruleset", "UFW's before.rules has local changes."])
  assert.deepStrictEqual(plain(N.modeNotes(null)), [])
})

test("shows the lists each mode has", () => {
  const pick = s => [s.ufwRules, s.baseline, s.collapseInactive, s.alertsSample]
  assert.deepStrictEqual(pick(N.sections("ufw")), [true, false, true, true])
  assert.deepStrictEqual(pick(N.sections("standalone")), [false, true, false, false])
  assert.deepStrictEqual(pick(N.sections("both")), [true, true, false, true])
  assert.deepStrictEqual(pick(N.sections("none")), [false, false, false, false])
  // Without the helper, UFW's own files still say whether it is on.
  assert.deepStrictEqual(pick(N.sections("unknown", { ufw: { enabled_in_conf: true } })), [true, false, true, true])
  assert.deepStrictEqual(pick(N.sections("unknown", { ufw: { enabled_in_conf: false } })), [false, false, false, false])
})

test("plans a switch and sums up its result", () => {
  const toHub = N.switchPlan("standalone", { mode: "ufw", docker_protection: "ufw-docker", ufw: { installed: true } })
  assert.strictEqual(toHub.title, "Switch to the Security Hub firewall")
  assert.match(toHub.changes[0], /first, then turns UFW off/)
  assert.match(toHub.docker, /as ufw-docker does now/)
  assert.match(toHub.password, /administrator password/)
  assert.match(N.switchPlan("standalone", { mode: "both" }).changes[0], /already loaded/)
  const back = N.switchPlan("ufw", { mode: "standalone", docker_protection: "omarchy", ufw: { installed: true } })
  assert.strictEqual(back.confirm, "Hand back")
  assert.match(back.changes.join(" "), /program rules are enforced/)
  assert.match(back.docker, /ufw-docker/)
  assert.strictEqual(N.switchPlan("ufw", { mode: "none", docker_protection: "none", ufw: { installed: true } }).docker, "")
  assert.match(N.RECOVERY_COMMAND, /^sudo ufw --force enable && .*\/var\/lib\/omarchy-security\/mode$/)

  assert.strictEqual(N.importSummary({ imported: [{}, {}, {}], not_imported: [{}] }),
    "Imported 3 rules from UFW. 1 UFW rule was not imported.")
  assert.strictEqual(N.importSummary({ imported: [{}] }), "Imported 1 rule from UFW.")
  assert.strictEqual(N.importSummary({ mode: "ufw" }), "")
  assert.strictEqual(N.modeErrorText({ code: -32004 }), "Not switched: the password prompt was cancelled or refused.")
  assert.strictEqual(N.modeErrorText({ code: -32006, message: "ufw disable failed; both firewalls are enforcing" }),
    "ufw disable failed; both firewalls are enforcing")
})

test("describes UFW's rules", () => {
  const ufw = extra => Object.assign({ action: "allow", direction: "in", protocol: "tcp", src: "any", dst: "any",
    ipv6: false }, extra)
  assert.strictEqual(N.ufwRuleTitle(ufw({ port: "53317" })), "Allow in TCP port 53317")
  assert.strictEqual(N.ufwRuleTitle(ufw({ protocol: "udp", port: "53", src: "172.16.0.0/12", dst: "172.17.0.1" })),
    "Allow in UDP port 53 from 172.16.0.0/12 to 172.17.0.1")
  assert.strictEqual(N.ufwRuleTitle(ufw({ action: "deny", protocol: "any", iface: "wlan0", ipv6: true })),
    "Deny in all traffic on wlan0 (IPv6)")
  assert.strictEqual(N.ufwRuleTitle(ufw({ action: "limit", port: "1714:1764" })), "Limit in TCP ports 1714-1764")
  assert.strictEqual(N.ufwRuleTitle(ufw({ direction: "out", protocol: "udp", dst: "10.0.0.1" })),
    "Allow out all UDP to 10.0.0.1")
  assert.strictEqual(N.ufwRuleComment(ufw({ comment: "allow-docker-dns" })), "allow-docker-dns")
  // The hub's tag on its temporary rules is not a comment to show.
  assert.strictEqual(N.ufwRuleComment(ufw({ comment: "omarchy-security:tmp:9:1:2", temp_id: 9 })), "")
  assert.deepStrictEqual(["allow", "limit", "deny", "reject"].map(a => N.ufwRuleRole(ufw({ action: a }))),
    ["success", "success", "danger", "danger"])
})

test("offers durations and counts down", () => {
  assert.deepStrictEqual(plain(N.durations([300, 3600, 28800])), [300, 3600, 28800])
  // From an older daemon, or nonsense: the defaults.
  assert.deepStrictEqual(plain(N.durations(undefined)), [300, 3600, 28800])
  assert.deepStrictEqual(plain(N.durations([30, 90000, 1.5])), [300, 3600, 28800])
  assert.deepStrictEqual(plain(N.durations([30, 600])), [600])
  assert.deepStrictEqual([300, 3600, 5400, 28800, 86400].map(N.durationLabel), ["5 min", "1 h", "1 h 30 min", "8 h", "24 h"])
  assert.strictEqual(N.remainingText(45500, 1000), "45 s left")
  assert.strictEqual(N.remainingText(1000 + 12 * 60000, 1000), "12 min left")
  assert.strictEqual(N.remainingText(1000 + 3600000, 1000), "1 h left")
  assert.strictEqual(N.remainingText(1000 + 125 * 60000, 1000), "2 h 5 min left")
  assert.strictEqual(N.remainingText(0, 1000), "0 s left")
})

test("keeps temporary decisions and links them to alerts", () => {
  const decision = (id, extra) => Object.assign({ temp_id: id, backend: "table", created_at: 0, expires_at: 10000,
    spec: { verdict: "block", direction: "inbound", address: "192.0.2.1", port: 22, protocol: "tcp" } }, extra)
  const list = [decision(3, { expires_at: 9000 }), decision(1, { expires_at: 500 }), decision(2, { alert_id: 7, created_at: 5 }),
    decision(4, { alert_id: 7, created_at: 9, spec: { verdict: "allow", direction: "inbound", address: "192.0.2.1" } })]
  assert.deepStrictEqual(plain(N.liveDecisions(list, 1000).map(d => d.temp_id)), [3, 2, 4])
  assert.deepStrictEqual(plain(N.liveDecisions(null, 0)), [])
  assert.strictEqual(N.findDecision(list, 2).alert_id, 7)
  assert.strictEqual(N.decisionForAlert(list, 7, 1000).temp_id, 4)
  assert.strictEqual(N.decisionForAlert(list, 8, 1000), null)
  assert.strictEqual(N.decisionNote(decision(1, { expires_at: 1000 + 58 * 60000 }), 1000), "Blocked, 58 min left")
  assert.strictEqual(N.backendLabel("ufw"), "UFW rule")
  assert.strictEqual(N.backendLabel("table"), "Security Hub table")
  assert.strictEqual(N.isMuted({ muted_until: 2000 }, 1000), true)
  assert.strictEqual(N.isMuted({ muted_until: 500 }, 1000), false)
  assert.strictEqual(N.isMuted({}, 1000), false)
  assert.strictEqual(N.tempErrorText({ code: -32004 }), "Not authorized: the password prompt was cancelled or refused.")
  assert.strictEqual(N.tempErrorText({ code: -32009, message: "no firewall is active; turn one on first" }),
    "no firewall is active; turn one on first")
  assert.strictEqual(N.tempErrorText({ code: -32003 }), "Already gone.")
})
