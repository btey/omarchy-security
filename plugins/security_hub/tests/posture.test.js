// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

// Posture.js is a QML `.pragma library` script; drop the pragma to run it
// as plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Posture.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const P = sandbox.module.exports
const plain = value => JSON.parse(JSON.stringify(value))

const check = (check_id, status) => ({ check_id, status, summary: check_id + " " + status })
const report = (checks, extra) => Object.assign({ overall: "pass", evaluated_at: 100000, checks }, extra)

test("orders checks and works out the worst status", () => {
  const r = report([check("swap_encryption", "pass"), check("new_check", "warn"), check("lsm", "warn"),
    check("docker_group", "fail"), check("ptrace_scope", "pass")])
  assert.deepStrictEqual(plain(P.sortedChecks(r).map(c => c.check_id)),
    ["lsm", "ptrace_scope", "docker_group", "swap_encryption", "new_check"])
  assert.strictEqual(P.overall(r), "fail")
  assert.strictEqual(P.overall(report([check("lsm", "unknown"), check("ptrace_scope", "pass")])), "unknown")
  assert.strictEqual(P.overall(report([check("lsm", "pass")])), "pass")
  assert.strictEqual(P.overall(report([], { overall: "warn" })), "warn")
  assert.strictEqual(P.overall(null), "unknown")
  assert.deepStrictEqual(plain(P.sortedChecks(null)), [])
  assert.strictEqual(P.checkLabel("docker_group"), "Docker group")
  assert.strictEqual(P.checkLabel("new_check"), "new_check")
})

test("summaries", () => {
  assert.strictEqual(P.summaryText(report([check("lsm", "pass"), check("ptrace_scope", "pass")])), "All 2 checks pass")
  assert.strictEqual(P.summaryText(report([check("lsm", "unknown"), check("ptrace_scope", "pass")])),
    "1 check could not be run")
  assert.strictEqual(P.summaryText(report([check("lsm", "warn"), check("docker_group", "fail"),
    check("swap_encryption", "fail")])), "2 problems, 1 warning")
  assert.strictEqual(P.summaryText(report([])), "")

  assert.strictEqual(P.checkedText(report([]), 100000 + 59000), "Checked just now")
  assert.strictEqual(P.checkedText(report([]), 100000 + 3 * 60000), "Checked 3 min ago")
  assert.strictEqual(P.checkedText(report([]), 100000 + 2 * 3600000), "Checked 2 hours ago")
  assert.strictEqual(P.checkedText(null, 0), "")
})

test("roles, labels and empty states", () => {
  assert.deepStrictEqual(["pass", "unknown", "warn", "fail"].map(P.statusRole),
    ["success", "muted", "warning", "danger"])
  assert.deepStrictEqual(["pass", "unknown", "warn", "fail", "x"].map(P.statusLabel),
    ["Pass", "Unknown", "Warning", "Fail", "Unknown"])
  assert.strictEqual(new Set(["pass", "unknown", "warn", "fail"].map(P.statusIcon)).size, 4)

  assert.match(P.emptyText(false, "", null, null), /Not connected/)
  assert.match(P.emptyText(true, "unavailable", null, null), /not available/)
  assert.match(P.emptyText(true, "active", { message: "boom" }, null), /boom/)
  assert.strictEqual(P.emptyText(true, "active", null, null), "Loading…")
  assert.match(P.emptyText(true, "active", null, report([])), /no checks/)
  assert.strictEqual(P.emptyText(true, "active", null, report([check("lsm", "pass")])), "")
})
