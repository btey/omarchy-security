// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

// Token.js is a QML `.pragma library` script; drop the pragma to run it
// as plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Token.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const T = sandbox.module.exports

const yubikey = { token_id: "usb-3-2-7", kind: "yubikey", name: "YubiKey OTP+FIDO+CCID", vendor_id: "1050",
  product_id: "0407", serial: "23456789", capabilities: ["fido2", "piv", "openpgp", "otp"] }

test("describes a token", () => {
  assert.strictEqual(T.kindLabel("yubikey"), "YubiKey")
  assert.strictEqual(T.kindLabel("fido2"), "FIDO2 key")
  assert.strictEqual(T.kindLabel("smartcard"), "Smart card reader")
  assert.strictEqual(T.kindLabel(""), "Security key")
  assert.strictEqual(T.idLine(yubikey), "1050:0407 · serial 23456789")
  assert.strictEqual(T.idLine({ vendor_id: "058f", product_id: "9540" }), "058f:9540")
  assert.deepStrictEqual(yubikey.capabilities.map(T.capabilityLabel), ["FIDO2", "PIV", "OpenPGP", "OTP"])
  assert.match(T.capabilityHint("fido2"), /pam_u2f/)
  assert.strictEqual(T.capabilityLabel("new"), "new")
  assert.strictEqual(T.capabilityHint("new"), "")
})

test("says when a key's touches are not shown", () => {
  assert.strictEqual(T.touchNote(yubikey), "")
  assert.strictEqual(T.touchNote({ kind: "nitrokey", capabilities: ["openpgp"] }), "")
  assert.match(T.touchNote({ kind: "yubikey", capabilities: ["otp"] }), /FIDO2 and OpenPGP only/)
  // A card in a reader gets GnuPG prompts under the reader's id.
  assert.strictEqual(T.touchNote({ kind: "smartcard", capabilities: [] }), "")
})

test("picks the request worth a line", () => {
  const now = 1000000
  const requests = [
    { request_id: 1, token_id: "a", source: "fido2", requested_at: now - 9000, outcome: "touched", completed_at: now - 8000 },
    { request_id: 2, token_id: "a", source: "gpg", requested_at: now - 7000, outcome: "timed_out", completed_at: now - 5000 },
    { request_id: 3, token_id: "b", source: "ssh", requested_at: now - 1000 },
  ]
  assert.strictEqual(T.latestRequest(requests, "a", now).request_id, 2)
  assert.strictEqual(T.latestRequest(requests, "b", now).request_id, 3)
  assert.strictEqual(T.latestRequest(requests, "c", now), null)
  // A waiting one wins over a later finished one.
  const waiting = requests.concat([{ request_id: 4, token_id: "a", source: "ssh", requested_at: now - 100 }])
  assert.strictEqual(T.latestRequest(waiting, "a", now).request_id, 4)
  // Old ones are not worth a line.
  assert.strictEqual(T.latestRequest(requests, "a", now + T.RECENT_MS), null)

  assert.deepStrictEqual(JSON.parse(JSON.stringify(T.requestLine(requests[2], now))),
    { text: "SSH is waiting for a touch", role: "warning" })
  assert.strictEqual(T.requestLine(requests[1], now).text, "GnuPG: not touched in time, just now")
  assert.strictEqual(T.requestLine(requests[0], now + 180000).text, "FIDO2: touched, 3 min ago")
  const removed = T.requestLine({ source: "ssh", outcome: "removed", completed_at: now }, now)
  assert.strictEqual(removed.text, "SSH: the key was unplugged while it waited, just now")
  assert.strictEqual(removed.role, "muted")
  assert.strictEqual(T.requestLine({ source: "fido2", outcome: "cancelled", completed_at: now }, now).text,
    "FIDO2: cancelled, just now")
  assert.strictEqual(T.requestLine(null, now), null)
})

test("empty states", () => {
  assert.match(T.emptyText(false, "", "", null, []), /Not connected/)
  assert.match(T.emptyText(true, "not_implemented", "", null, []), /not watched/)
  assert.strictEqual(T.emptyText(true, "unavailable", "no /sys", null, []), "Security keys are not watched: no /sys")
  assert.match(T.emptyText(true, "active", "", { code: -32002, message: "x" }, []), /not watched/)
  assert.match(T.emptyText(true, "active", "", { code: -32603, message: "boom" }, []), /boom/)
  assert.strictEqual(T.emptyText(true, "active", "", null, []), "No security key is plugged in.")
  assert.strictEqual(T.emptyText(true, "degraded", "gpg off", null, [yubikey]), "")
})
