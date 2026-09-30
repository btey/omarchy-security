// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

// Threat.js is a QML `.pragma library` script; drop the pragma to run it as
// plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Threat.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const T = sandbox.module.exports
const plain = value => JSON.parse(JSON.stringify(value))
const ids = list => plain(list.map(a => a.alert_id))

const alert = (id, extra) => Object.assign({
  alert_id: id, pid: 4000 + id, ppid: 1, uid: 1000, start_time: 99,
  binary_path: "/tmp/x", argv: ["/tmp/x"], origin: "tmp", detected_at: 10000, state: "open"
}, extra)

test("keeps alerts in alert_id order and follows their state", () => {
  let list = []
  for (const id of [3, 1, 2]) list = T.upsertAlert(list, alert(id))
  assert.deepStrictEqual(ids(list), [1, 2, 3])
  assert.strictEqual(T.upsertAlert(list, null), list)
  assert.strictEqual(T.upsertAlert(list, { pid: 1 }), list)

  list = T.upsertAlert(list, alert(2, { state: "quarantined" }))
  assert.deepStrictEqual(ids(list), [1, 2, 3])
  assert.strictEqual(T.findAlert(list, 2).state, "quarantined")
  list = T.resolveAlert(list, { alert_id: 1, state: "exited" })
  assert.strictEqual(T.findAlert(list, 1).state, "exited")
  // Unknown or unchanged: the same list.
  assert.strictEqual(T.resolveAlert(list, { alert_id: 99, state: "killed" }), list)
  assert.strictEqual(T.resolveAlert(list, { alert_id: 1, state: "exited" }), list)
  assert.strictEqual(T.resolveAlert(list, null), list)
})

test("waiting alerts: pending ones, oldest first, without the ones put off", () => {
  const list = [alert(1, { state: "killed" }), alert(2), alert(3, { state: "quarantined" }), alert(4)]
  assert.deepStrictEqual(ids(T.queue(list, {})), [2, 3, 4])
  assert.deepStrictEqual(ids(T.queue(list, { 2: true })), [3, 4])
  assert.deepStrictEqual(ids(T.queue(list, null)), [2, 3, 4])
  for (const state of ["open", "quarantined"]) assert.ok(T.isPending(alert(1, { state })))
  for (const state of ["killed", "exited", "dismissed"]) assert.ok(!T.isPending(alert(1, { state })))
})

test("a listing replaces the pending alerts and keeps the resolved ones", () => {
  let list = [alert(1, { state: "killed" }), alert(2), alert(3)]
  // 2 was resolved while this shell was away; 5 is new.
  list = T.replaceAlerts(list, [alert(3), alert(5)])
  assert.deepStrictEqual(ids(list), [1, 3, 5])
  // A daemon restart forgets them all.
  assert.deepStrictEqual(ids(T.replaceAlerts(list, [])), [1])
})

test("drops resolved alerts first when the list is full", () => {
  let list = [alert(1)]
  for (let id = 2; id <= T.MAX_ALERTS + 10; id++) list = T.upsertAlert(list, alert(id, { state: "exited" }))
  assert.strictEqual(list.length, T.MAX_ALERTS)
  assert.strictEqual(list[0].alert_id, 1, "the open alert stays")
  assert.strictEqual(list[list.length - 1].alert_id, T.MAX_ALERTS + 10)
})

test("describes what ran", () => {
  assert.strictEqual(T.title(alert(1)), "Program started from /tmp")
  assert.strictEqual(T.title(alert(1, { origin: "dev_shm" })), "Program started from /dev/shm")
  assert.strictEqual(T.title(alert(1, { origin: "memfd" })), "Program started from memory")
  assert.match(T.reason(alert(1, { origin: "memfd" })), /no file on disk/)
  assert.match(T.reason(alert(1)), /temporary folder/)
  assert.strictEqual(T.programName(alert(1, { binary_path: "/tmp/.cache-x/update" })), "update")
  assert.strictEqual(T.programName(alert(1, { binary_path: "", argv: ["/usr/bin/sh"] })), "sh")
  assert.strictEqual(T.programName(alert(1, { binary_path: "", argv: [] })), "unknown")
  assert.strictEqual(T.processLine(alert(1)), "PID 4001 · parent 1 · user 1000")

  assert.strictEqual(T.commandLine(["/tmp/x", "--connect", "203.0.113.9:4444"]), "/tmp/x --connect 203.0.113.9:4444")
  assert.strictEqual(T.commandLine(["sh", "it's here", ""]), "sh 'it'\\''s here' ''")
  assert.strictEqual(T.commandLine([]), "")
  const long = T.commandLine(["/tmp/x", "a".repeat(500)], 40)
  assert.strictEqual(long.length, 40)
  assert.ok(long.endsWith("…"))

  assert.strictEqual(T.droppedLine(alert(1)), "")
  assert.strictEqual(T.droppedLine(alert(1, { dropped_at: 7700 })), "Written to /tmp 2 seconds before it ran")
  assert.strictEqual(T.durationText(400), "less than a second")
  assert.strictEqual(T.durationText(1000), "1 second")
  assert.strictEqual(T.durationText(90000), "2 minutes")
  assert.strictEqual(T.durationText(7200000), "2 hours")
})

test("offers responses that fit the alert's state", () => {
  const actionIds = a => plain(T.actionsFor(a).map(x => x.id))
  assert.deepStrictEqual(actionIds(alert(1)), ["kill", "isolate", "dismiss"])
  assert.deepStrictEqual(actionIds(alert(1, { state: "quarantined" })), ["kill", "resume"])
  for (const state of ["killed", "exited", "dismissed"]) assert.deepStrictEqual(actionIds(alert(1, { state })), [])
  assert.deepStrictEqual(actionIds(null), [])

  // Kill is SIGKILL: the daemon marks the alert killed once the signal is
  // sent, and a paused program would sit on a SIGTERM.
  assert.deepStrictEqual(plain(T.actionParams(alert(1), T.ACTIONS.kill)), { alert_id: 1, pid: 4001, signal: 9 })
  assert.deepStrictEqual(plain(T.actionParams(alert(1), T.ACTIONS.isolate)), { alert_id: 1, pid: 4001 })
  assert.strictEqual(T.ACTIONS.isolate.method, "THREAT_QUARANTINE_PROCESS")
  assert.strictEqual(T.ACTIONS.resume.method, "THREAT_RESUME_PROCESS")
  assert.strictEqual(T.ACTIONS.dismiss.method, "THREAT_DISMISS_ALERT")
})

test("labels, roles and error texts", () => {
  assert.deepStrictEqual(["open", "quarantined", "killed", "exited", "dismissed", "?"].map(T.stateLabel),
    ["Running", "Isolated (paused)", "Killed", "Exited", "Dismissed", "Unknown"])
  assert.deepStrictEqual(["open", "quarantined", "killed", "exited"].map(T.stateRole),
    ["danger", "warning", "success", "muted"])
  assert.match(T.outcomeText("killed"), /killed/)
  assert.match(T.outcomeText("dismissed"), /keeps running/)
  assert.strictEqual(T.outcomeText("open"), "")

  assert.match(T.actionErrorText({ code: -32005, message: "x" }), /already exited/)
  assert.match(T.actionErrorText({ code: -32004, message: "x" }), /another user/)
  assert.match(T.actionErrorText({ code: -32003, message: "x" }), /no longer open/)
  assert.match(T.actionErrorText({ code: -32602, message: "alert 3 is quarantined" }), /quarantined/)
  assert.strictEqual(T.actionErrorText({ code: -32603, message: "request timed out" }), "request timed out")
  assert.strictEqual(T.actionErrorText(null), "")
})

test("the hub's list: newest first, and its empty states", () => {
  const list = [alert(1), alert(3), alert(2)]
  assert.deepStrictEqual(T.newestFirst(list).map(a => a.alert_id), [3, 2, 1])
  assert.deepStrictEqual(list.map(a => a.alert_id), [1, 3, 2])
  assert.strictEqual(T.listEmptyText(false, "", "", []), "Not connected to omarchy-securityd")
  assert.strictEqual(T.listEmptyText(true, "not_implemented", "", []), "Programs are not watched by this daemon")
  assert.strictEqual(T.listEmptyText(true, "unavailable", "the eBPF program did not load", []),
    "Programs are not watched: the eBPF program did not load")
  assert.match(T.listEmptyText(true, "active", "", []), /^No program has started/)
  assert.strictEqual(T.listEmptyText(true, "active", "", [alert(1)]), "")
})
