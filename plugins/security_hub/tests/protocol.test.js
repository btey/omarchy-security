// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

// Protocol.js is a QML `.pragma library` script; drop the pragma to run it
// as plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Protocol.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const P = sandbox.module.exports
// Objects built inside the vm context have that context's prototypes, which
// deepStrictEqual treats as different; compare their JSON shape instead.
const plain = value => JSON.parse(JSON.stringify(value))

test("encodes one request per line", () => {
  const frame = P.encodeRequest(7, "USBGUARD_SET_POLICY", { device_id: 14, target: "allow", permanent: true })
  assert.ok(frame.endsWith("\n"))
  assert.strictEqual(frame.indexOf("\n"), frame.length - 1)
  assert.deepStrictEqual(JSON.parse(frame), {
    jsonrpc: "2.0", id: 7, method: "USBGUARD_SET_POLICY",
    params: { device_id: 14, target: "allow", permanent: true }
  })
  assert.deepStrictEqual(JSON.parse(P.encodeRequest(1, "PING")).params, {})
})

test("classifies responses, errors, and events", () => {
  assert.deepStrictEqual(plain(P.decode('{"jsonrpc":"2.0","id":1,"result":{}}')),
    { kind: "response", id: 1, result: {} })
  const err = P.decode('{"jsonrpc":"2.0","id":2,"error":{"code":-32003,"message":"x"}}')
  assert.strictEqual(err.kind, "response")
  assert.strictEqual(err.error.code, P.ErrorCode.NOT_FOUND)
  const event = P.decode('{"jsonrpc":"2.0","method":"USB_DEVICE_PRESENTED","params":{"device_id":14}}')
  assert.deepStrictEqual(plain(event), { kind: "event", name: "USB_DEVICE_PRESENTED", params: { device_id: 14 } })
})

test("rejects what is not a v1 message", () => {
  for (const line of ["{", "[]", '{"jsonrpc":"1.0","id":1,"result":{}}', '{"jsonrpc":"2.0"}',
                      "x".repeat(P.MAX_FRAME_BYTES + 1)])
    assert.strictEqual(P.decode(line).kind, "invalid", line.slice(0, 40))
})

test("resolves the socket path like the daemon", () => {
  const env = vars => name => vars[name] || ""
  assert.strictEqual(P.socketPath(env({ XDG_RUNTIME_DIR: "/run/user/1000" })),
    "/run/user/1000/omarchy-security/securityd.sock")
  assert.strictEqual(P.socketPath(env({ XDG_RUNTIME_DIR: "/run/user/1000", OMARCHY_SECURITYD_SOCKET: "/x" })), "/x")
  assert.strictEqual(P.socketPath(env({})), "")
})

test("backs off from 1 s to a 30 s cap", () => {
  assert.deepStrictEqual([0, 1, 2, 5, 20].map(n => P.backoffMs(n)), [1000, 2000, 4000, 30000, 30000])
})

test("topics and error codes match the Rust crate", () => {
  const rust = fs.readFileSync(path.join(__dirname, "../../../crates/omarchy-security-proto/src/error.rs"), "utf8")
  for (const code of Object.values(P.ErrorCode))
    assert.ok(rust.includes(`=> ${code},`), `error code ${code} missing from error.rs`)
  assert.deepStrictEqual([...P.TOPICS],
    ["system", "threat", "usbguard", "token", "vault", "firewall", "posture"])
})

test("names the firewall prompt events and decision scopes", () => {
  assert.strictEqual(P.FirewallEvent.CONNECTION_PROMPT, "FIREWALL_CONNECTION_PROMPT")
  assert.strictEqual(P.FirewallEvent.CONNECTION_RESOLVED, "FIREWALL_CONNECTION_RESOLVED")
  assert.deepStrictEqual(plain(P.DECISION_SCOPES), ["once", "process", "always"])
  assert.deepStrictEqual(plain(P.DECIDED_BY), ["user", "timeout"])
})
