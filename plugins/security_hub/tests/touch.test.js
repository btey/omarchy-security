// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

// Touch.js is a QML `.pragma library` script; drop the pragma to run it as
// plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Touch.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const T = sandbox.module.exports
const plain = value => JSON.parse(JSON.stringify(value))
const ids = list => plain(list.map(r => r.request_id))

const yubikey = { token_id: "usb-3-2-7", kind: "yubikey", name: "YubiKey OTP+FIDO+CCID",
  vendor_id: "1050", product_id: "0407", capabilities: ["fido2", "piv", "openpgp", "otp"] }
const solo = { token_id: "usb-1-4-3", kind: "solokey", name: "Solo 2", vendor_id: "1209",
  product_id: "beee", capabilities: ["fido2"] }
const ask = (id, extra) => Object.assign({ request_id: id, token_id: yubikey.token_id,
  source: "fido2", description: "YubiKey OTP+FIDO+CCID is waiting for a touch" }, extra)

test("keeps tokens in token_id order", () => {
  let tokens = T.upsertToken([], yubikey)
  tokens = T.upsertToken(tokens, solo)
  assert.deepStrictEqual(plain(tokens.map(t => t.token_id)), ["usb-1-4-3", "usb-3-2-7"])
  tokens = T.upsertToken(tokens, Object.assign({}, yubikey, { name: "Renamed" }))
  assert.strictEqual(tokens.length, 2)
  assert.strictEqual(T.findToken(tokens, yubikey.token_id).name, "Renamed")
  assert.strictEqual(T.upsertToken(tokens, null), tokens)
  assert.strictEqual(T.removeToken(tokens, "usb-9-9-9"), tokens)
  assert.deepStrictEqual(plain(T.removeToken(tokens, solo.token_id).map(t => t.token_id)), ["usb-3-2-7"])
  assert.strictEqual(T.findToken(tokens, "nope"), null)
})

test("follows a request from TOUCH_REQUESTED to TOUCH_COMPLETED", () => {
  let list = T.startRequest([], ask(1), 1000)
  assert.ok(T.isWaiting(list[0]))
  assert.strictEqual(list[0].requested_at, 1000)
  assert.deepStrictEqual(ids(T.waiting(list, 2000)), [1])
  assert.strictEqual(T.lingering(list, 2000), null)

  list = T.completeRequest(list, { request_id: 1, outcome: "touched" }, 3000)
  assert.deepStrictEqual(plain([list[0].outcome, list[0].completed_at]), ["touched", 3000])
  assert.deepStrictEqual(ids(T.waiting(list, 3000)), [])
  // A finished request stays on screen for a moment, by outcome.
  assert.strictEqual(T.lingering(list, 3000 + T.LINGER_MS.touched - 1).request_id, 1)
  assert.strictEqual(T.lingering(list, 3000 + T.LINGER_MS.touched), null)

  // Unknown, repeated or malformed: the same list.
  assert.strictEqual(T.completeRequest(list, { request_id: 9, outcome: "touched" }, 4000), list)
  assert.strictEqual(T.completeRequest(list, { request_id: 1, outcome: "timed_out" }, 4000), list)
  assert.strictEqual(T.completeRequest(list, null, 4000), list)
  assert.strictEqual(T.startRequest(list, { source: "gpg" }, 4000), list)
})

test("an unplugged key ends its own requests only", () => {
  let list = T.startRequest([], ask(1), 1000)
  list = T.startRequest(list, ask(2, { token_id: solo.token_id }), 1100)
  list = T.endForToken(list, yubikey.token_id, 2000)
  assert.strictEqual(T.findRequest(list, 1).outcome, "removed")
  assert.ok(T.isWaiting(T.findRequest(list, 2)))
  assert.strictEqual(T.endForToken(list, yubikey.token_id, 2500), list)
  assert.strictEqual(T.endForToken(list, "", 2500), list)
})

test("waiting requests go stale; the last one finished lingers", () => {
  let list = T.startRequest([], ask(1), 0)
  list = T.startRequest(list, ask(2, { source: "gpg" }), 500)
  assert.deepStrictEqual(ids(T.waiting(list, T.STALE_MS - 1)), [1, 2])
  assert.deepStrictEqual(ids(T.waiting(list, T.STALE_MS)), [2])
  // The next change is request 1 going stale.
  assert.strictEqual(T.nextChangeIn(list, 1000), T.STALE_MS - 1000)

  list = T.completeRequest(list, { request_id: 1, outcome: "cancelled" }, 2000)
  list = T.completeRequest(list, { request_id: 2, outcome: "timed_out" }, 2100)
  assert.strictEqual(T.lingering(list, 2200).request_id, 2)
  // timed_out stays longer than cancelled.
  assert.strictEqual(T.nextChangeIn(list, 2200), 2000 + T.LINGER_MS.cancelled - 2200)
  assert.strictEqual(T.nextChangeIn(list, 2100 + T.LINGER_MS.timed_out), -1)
  assert.strictEqual(T.lingerMs("something new"), T.LINGER_MS.cancelled)
})

test("drops finished requests first when the list is full", () => {
  let list = T.startRequest([], ask(1), 0)
  for (let id = 2; id <= T.MAX_REQUESTS + 5; id++) {
    list = T.startRequest(list, ask(id), id)
    list = T.completeRequest(list, { request_id: id, outcome: "touched" }, id)
  }
  assert.strictEqual(list.length, T.MAX_REQUESTS)
  assert.strictEqual(list[0].request_id, 1, "the waiting request stays")
})

test("titles and texts", () => {
  const tokens = [solo, yubikey]
  assert.strictEqual(T.waitingTitle([ask(1)], tokens), "Touch your YubiKey")
  assert.strictEqual(T.waitingTitle([ask(1, { token_id: solo.token_id })], tokens), "Touch your SoloKey")
  assert.strictEqual(T.waitingTitle([ask(1), ask(2)], tokens), "Touch your YubiKey")
  assert.strictEqual(T.waitingTitle([ask(1), ask(2, { token_id: solo.token_id })], tokens), "Touch your security keys")
  // A token this shell has not listed, or none named.
  assert.strictEqual(T.waitingTitle([ask(1, { token_id: "" })], tokens), "Touch your security key")
  assert.strictEqual(T.waitingTitle([], tokens), "")

  assert.deepStrictEqual(["ssh", "gpg", "fido2", "pcsc", "x"].map(T.sourceLabel),
    ["SSH", "GnuPG", "FIDO2 sign-in", "Smart card", "Security key"])
  assert.match(T.sourceHint("gpg"), /gpg-agent/)
  assert.match(T.sourceHint("fido2"), /pam_u2f/)
  assert.match(T.sourceHint("ssh"), /SSH/)

  assert.deepStrictEqual(["touched", "timed_out", "cancelled", "removed"].map(T.outcomeTitle),
    ["Touch received", "Touch timed out", "Request cancelled", "Key removed"])
  assert.strictEqual(T.outcomeText("touched"), "")
  assert.match(T.outcomeText("timed_out"), /again/)
  assert.deepStrictEqual([undefined, "touched", "timed_out", "cancelled", "removed"].map(T.outcomeRole),
    ["accent", "success", "warning", "muted", "muted"])
  assert.strictEqual(T.elapsedText({ requested_at: 1000 }, 5900), "Waiting 4 s")
  assert.strictEqual(T.elapsedText({ requested_at: 1000 }, 900), "Waiting 0 s")
})
