// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

// Indicator.js is a QML `.pragma library` script; drop the pragma to run it
// as plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Indicator.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const I = sandbox.module.exports
const plain = value => JSON.parse(JSON.stringify(value))

const alert = (id, lastSeen, extra) => Object.assign({ alert_id: id, count: 1, first_seen: lastSeen, last_seen: lastSeen }, extra)

test("merges alerts by id, newest first", () => {
  let list = []
  list = I.mergeAlert(list, alert(1, 100))
  list = I.mergeAlert(list, alert(2, 200))
  assert.deepStrictEqual(plain(list.map(a => a.alert_id)), [2, 1])
  // A repeat of alert 1 replaces it in place; it does not move or duplicate.
  list = I.mergeAlert(list, alert(1, 300, { count: 4 }))
  assert.deepStrictEqual(plain(list.map(a => [a.alert_id, a.count])), [[2, 1], [1, 4]])
  assert.strictEqual(I.mergeAlert(list, null), list)
  assert.strictEqual(I.mergeAlert(list, { count: 1 }), list)

  let full = []
  for (let i = 0; i < I.MAX_ALERTS + 5; i++) full = I.mergeAlert(full, alert(i, i))
  assert.strictEqual(full.length, I.MAX_ALERTS)
  assert.strictEqual(full[0].alert_id, I.MAX_ALERTS + 4)
})

test("counts alerts with packets after the last look, except muted ones", () => {
  const now = 10_000
  const list = [
    alert(1, 5_000),
    alert(2, 3_000),
    alert(3, 6_000, { muted_until: now + 1 }),
    alert(4, 7_000, { muted_until: now - 1 }),
    alert(5, 8_000, { muted_until: null })
  ]
  assert.strictEqual(I.unseenCount(list, 0, now), 4)
  assert.strictEqual(I.unseenCount(list, 4_000, now), 3)
  assert.strictEqual(I.unseenCount(list, 8_000, now), 0)
  assert.strictEqual(I.unseenCount([], 0, now), 0)
})

test("formats the badge", () => {
  assert.strictEqual(I.badgeText(0), "")
  assert.strictEqual(I.badgeText(undefined), "")
  assert.strictEqual(I.badgeText(1), "1")
  assert.strictEqual(I.badgeText(9), "9")
  assert.strictEqual(I.badgeText(10), "9+")
})

test("maps every firewall mode to a shield state", () => {
  assert.deepStrictEqual(
    ["ufw", "standalone", "both", "none", "unknown", "", undefined].map(I.modeRole),
    ["normal", "normal", "warning", "danger", "dim", "dim", "dim"])
})

test("summarizes the widget state", () => {
  const off = plain(I.summarize({ ready: false, mode: "none", unseen: 3 }))
  assert.deepStrictEqual(off, { role: "dim", badge: "", tooltip: "Security Hub · daemon not connected" })
  assert.strictEqual(I.summarize(null).role, "dim")

  const ok = plain(I.summarize({ ready: true, mode: "ufw", modeLabel: "UFW", unseen: 0 }))
  assert.deepStrictEqual(ok, { role: "normal", badge: "", tooltip: "Security Hub\nFirewall: UFW" })

  const busy = plain(I.summarize({ ready: true, mode: "none", modeLabel: "No firewall", unseen: 12 }))
  assert.deepStrictEqual(busy, { role: "danger", badge: "9+",
    tooltip: "Security Hub\nFirewall: No firewall\n12 new blocked connections" })

  assert.match(I.summarize({ ready: true, mode: "both", modeLabel: "x", unseen: 1 }).tooltip, /1 new blocked connection$/)
  assert.match(I.summarize({ ready: true, mode: "", unseen: 0 }).tooltip, /reading state/)
  assert.strictEqual(I.summarize({ ready: true, mode: "ufw", modeLabel: "UFW", unseen: 0, update: "1.1.7" }).tooltip,
    "Security Hub\nFirewall: UFW\nSecurity Hub 1.1.7 is available")
  const unknown = I.summarize({ ready: true, mode: "unknown", modeLabel: "Unknown", unseen: 0 })
  assert.strictEqual(unknown.role, "dim")
  assert.match(unknown.tooltip, /helper not running/)
})

test("remembers when the alerts were seen", () => {
  const env = vars => name => vars[name] || ""
  assert.strictEqual(I.seenStatePath(env({ XDG_STATE_HOME: "/s", HOME: "/h" })), "/s/omarchy-security/shell-seen.json")
  assert.strictEqual(I.seenStatePath(env({ HOME: "/h" })), "/h/.local/state/omarchy-security/shell-seen.json")
  assert.strictEqual(I.seenStatePath(env({})), "")

  assert.strictEqual(I.parseSeenState('{"alerts_seen_at": 1759000000000}'), 1759000000000)
  for (const raw of ["", "not json", "null", '{"alerts_seen_at": "1"}', '{"alerts_seen_at": -5}', "{}"])
    assert.strictEqual(I.parseSeenState(raw), 0, raw)
})
