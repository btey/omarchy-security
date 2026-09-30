// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

// Usb.js is a QML `.pragma library` script; drop the pragma to run it as
// plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Usb.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const U = sandbox.module.exports
const plain = value => JSON.parse(JSON.stringify(value))
const ids = list => plain(list.map(d => d.device_id))

const device = (id, extra) => Object.assign({
  device_id: id, name: "Device " + id, vendor_id: "0951", product_id: "1666",
  serial: "", rule: "block", interface_class: "08"
}, extra)

test("keeps devices in device_id order, whatever order they arrive in", () => {
  let list = []
  for (const id of [14, 2, 21, 5]) list = U.upsertDevice(list, device(id))
  assert.deepStrictEqual(ids(list), [2, 5, 14, 21])
  // A changed device stays in its row.
  list = U.upsertDevice(list, device(5, { rule: "allow" }))
  assert.deepStrictEqual(ids(list), [2, 5, 14, 21])
  assert.strictEqual(U.findDevice(list, 5).rule, "allow")
  assert.strictEqual(U.upsertDevice(list, null), list)
  assert.strictEqual(U.upsertDevice(list, { name: "no id" }), list)

  list = U.removeDevice(list, 14)
  assert.deepStrictEqual(ids(list), [2, 5, 21])
  assert.strictEqual(U.removeDevice(list, 99), list)
  assert.strictEqual(U.findDevice(list, 99), null)
})

test("policy changes set the rule and remember a saved one", () => {
  let list = [device(14)]
  list = U.applyPolicy(list, { device_id: 14, target: "allow", permanent: true })
  assert.deepStrictEqual(plain([list[0].rule, list[0].saved]), ["allow", true])
  // The daemon's own UsbDevice (a SET_POLICY result, a re-listing) does not
  // carry the marks; they survive it.
  list = U.upsertDevice(list, device(14, { rule: "allow" }))
  assert.strictEqual(list[0].saved, true)
  list = U.replaceDevices(list, [device(14, { rule: "allow" }), device(3)])
  assert.deepStrictEqual(ids(list), [3, 14])
  assert.strictEqual(U.findDevice(list, 14).saved, true)
  assert.strictEqual(U.findDevice(list, 3).saved, undefined)

  list = U.applyPolicy(list, { device_id: 14, target: "block", permanent: false })
  assert.deepStrictEqual(plain([U.findDevice(list, 14).rule, U.findDevice(list, 14).saved]), ["block", false])

  // Only this shell's Approve makes an allow temporary. The daemon reports
  // permanent: false for a saved rule USBGuard applies at plug-in, so an
  // event alone must not.
  list = U.applyPolicy(list, { device_id: 14, target: "allow", permanent: false })
  assert.strictEqual(U.findDevice(list, 14).temporary, false)
  list = U.markTemporary(list, 14)
  assert.deepStrictEqual(plain([U.findDevice(list, 14).temporary, U.findDevice(list, 14).saved]), [true, false])
  // The Approve's own event may arrive after its answer; it keeps the mark.
  list = U.applyPolicy(list, { device_id: 14, target: "allow", permanent: false })
  assert.strictEqual(U.findDevice(list, 14).temporary, true)
  list = U.replaceDevices(list, [device(14, { rule: "allow" })])
  assert.strictEqual(U.findDevice(list, 14).temporary, true)
  // Saving or blocking ends it.
  const saved = U.applyPolicy(list, { device_id: 14, target: "allow", permanent: true })
  assert.deepStrictEqual(plain([U.findDevice(saved, 14).temporary, U.findDevice(saved, 14).saved]), [false, true])
  assert.strictEqual(U.findDevice(U.applyPolicy(list, { device_id: 14, target: "block" }), 14).temporary, false)
  // Only an allowed device can be approved for now.
  assert.strictEqual(U.markTemporary([device(3)], 3)[0].temporary, undefined)
  assert.deepStrictEqual(plain(U.markTemporary([], 3)), [])

  // A device the list does not have yet waits for its PRESENTED or a listing.
  assert.strictEqual(U.applyPolicy(list, { device_id: 99, target: "allow" }), list)
  assert.strictEqual(U.applyPolicy(list, null), list)
})

test("describes interface classes, once each", () => {
  const receiver = device(2, { interface_class: "03", interfaces: ["03", "03", "03"] })
  assert.deepStrictEqual(plain(U.deviceClasses(receiver)), ["03", "03", "03"])
  assert.strictEqual(U.classSummary(receiver), "Keyboard / mouse")
  assert.strictEqual(U.classSummary(device(1, { interface_class: "08", interfaces: ["08", "03"] })),
    "Storage, Keyboard / mouse")
  assert.strictEqual(U.classSummary(device(1)), "Storage")
  assert.strictEqual(U.classLabel("0E"), "Video")
  assert.strictEqual(U.classLabel("42"), "Class 42")
  assert.strictEqual(U.classLabel(""), "Unknown")
  assert.deepStrictEqual(plain(U.deviceClasses(device(1, { interface_class: "" }))), [])
  // Storage wins over the keyboard for the icon; anything else gets the USB plug.
  assert.strictEqual(U.classIcon(device(1, { interfaces: ["03", "08"] })), "\u{F129E}")
  assert.strictEqual(U.classIcon(receiver), "\u{F030C}")
  assert.strictEqual(U.classIcon(device(1, { interface_class: "ff" })), "\u{F0553}")
})

test("warns about devices that can type as well as something else", () => {
  assert.match(U.riskNote(device(1, { interfaces: ["08", "03"] })), /known attack/)
  assert.match(U.riskNote(device(1, { interface_class: "01", interfaces: ["01", "01", "03"] })), /keyboard/)
  assert.strictEqual(U.riskNote(device(1, { interface_class: "03", interfaces: ["03", "03"] })), "")
  assert.strictEqual(U.riskNote(device(1)), "")
})

test("offers the actions that fit the device's rule", () => {
  const actionIds = d => plain(U.actionsFor(d).map(a => a.id))
  assert.deepStrictEqual(actionIds(device(1)), ["approve", "savePermanent", "reject"])
  // Save permanent only after this shell's Approve; a device found allowed
  // may already come from a rule.
  assert.deepStrictEqual(actionIds(device(1, { rule: "allow", temporary: true })), ["savePermanent", "block", "reject"])
  assert.deepStrictEqual(actionIds(device(1, { rule: "allow" })), ["block", "reject"])
  assert.deepStrictEqual(actionIds(device(1, { rule: "allow", saved: false })), ["block", "reject"])
  assert.deepStrictEqual(actionIds(device(1, { rule: "allow", saved: true })), ["block", "reject"])
  assert.deepStrictEqual(actionIds(device(1, { rule: "reject" })), [])
  // Blocking an allowed hub would cut off everything behind it (the root
  // hub carries the keyboard); a blocked one, like a new dock, can be let in.
  const rootHub = device(8, { name: "xHCI Host Controller", vendor_id: "1d6b", interface_class: "09", rule: "allow" })
  assert.deepStrictEqual(actionIds(rootHub), [])
  assert.match(U.noActionsNote(rootHub), /cuts off/)
  assert.deepStrictEqual(actionIds(Object.assign({}, rootHub, { rule: "block" })), ["approve", "savePermanent", "reject"])
  assert.strictEqual(U.noActionsNote(device(1, { rule: "allow" })), "")
  assert.deepStrictEqual(actionIds(null), [])
  // Only Reject asks for a second click; only Save permanent writes a rule.
  for (const a of Object.values(U.ACTIONS)) {
    assert.strictEqual(a.confirm, a.id === "reject")
    assert.strictEqual(a.permanent, a.id === "savePermanent")
  }
  assert.strictEqual(U.ACTIONS.approve.target, "allow")
})

test("labels, roles and the blocked count", () => {
  assert.strictEqual(U.idLine(device(1, { serial: "00187D0F2E3B" })), "0951:1666 · 00187D0F2E3B")
  assert.strictEqual(U.idLine(device(1)), "0951:1666")
  assert.strictEqual(U.ruleLabel(device(1, { rule: "allow", saved: true })), "Allowed · saved")
  assert.strictEqual(U.ruleLabel(device(1, { rule: "allow", temporary: true })), "Allowed until unplugged")
  assert.strictEqual(U.ruleLabel(device(1)), "Blocked")
  assert.strictEqual(U.ruleLabel(device(1, { rule: "reject" })), "Rejected")
  assert.deepStrictEqual(["allow", "block", "reject", "?"].map(U.ruleRole), ["success", "warning", "danger", "muted"])
  assert.strictEqual(U.blockedCount([device(1), device(2, { rule: "allow" }), device(3)]), 2)
})

test("states why there is no list, and why an action failed", () => {
  assert.match(U.emptyText(false, "", null, []), /Not connected/)
  assert.match(U.emptyText(true, "not_implemented", null, []), /without USBGuard/)
  assert.match(U.emptyText(true, "active", { code: -32007, message: "x" }, []), /without USBGuard/)
  assert.match(U.emptyText(true, "unavailable", null, []), /not running/)
  assert.match(U.emptyText(true, "active", { code: -32002, message: "x" }, []), /not running/)
  assert.match(U.emptyText(true, "active", { code: -32603, message: "request timed out" }, []), /timed out/)
  assert.match(U.emptyText(true, "active", null, []), /No USB devices/)
  assert.strictEqual(U.emptyText(true, "active", null, [device(1)]), "")

  assert.match(U.actionErrorText({ code: -32004, message: "x" }), /polkit/)
  assert.match(U.actionErrorText({ code: -32003, message: "x" }), /no longer connected/)
  assert.match(U.actionErrorText({ code: -32006, message: "x", data: { detail: "device busy" } }), /device busy/)
  assert.strictEqual(U.actionErrorText({ code: -32603, message: "request timed out" }), "request timed out")
  assert.strictEqual(U.actionErrorText(null), "")
})
