// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

// Sandbox.js is a QML `.pragma library` script; drop the pragma to run it
// as plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Sandbox.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const S = sandbox.module.exports
const plain = value => JSON.parse(JSON.stringify(value))

test("expands and checks paths", () => {
  assert.strictEqual(S.expandPath("  ~/Downloads/a.pdf\n", "/home/u"), "/home/u/Downloads/a.pdf")
  assert.strictEqual(S.expandPath("~", "/home/u"), "/home/u")
  assert.strictEqual(S.expandPath("~other/a", "/home/u"), "~other/a")
  assert.strictEqual(S.expandPath("~/a", ""), "~/a")
  assert.strictEqual(S.pathProblem("/usr/bin/zathura", "program"), "")
  assert.match(S.pathProblem("zathura", "program"), /full path, such as \/usr\/bin/)
  assert.match(S.pathProblem("a.pdf", "file"), /file's full path/)
  assert.match(S.pathProblem("/usr/bin/", "program"), /directory/)
  assert.match(S.pathProblem("/tmp/a\nb", "file"), /line break/)
})

test("builds SANDBOX_RUN params", () => {
  assert.deepStrictEqual(plain(S.checkForm({ executable: "", target: "", shareNet: false }, "/home/u")),
    { params: null, error: "", warning: "" })
  assert.deepStrictEqual(plain(S.checkForm({ executable: "/usr/bin/zathura" }, "/home/u").params),
    { executable: "/usr/bin/zathura", share_net: false })
  // The file is bound and passed as the only argument.
  assert.deepStrictEqual(plain(S.checkForm({ executable: "/usr/bin/zathura", target: "~/a.pdf", shareNet: true },
    "/home/u")), {
    params: { executable: "/usr/bin/zathura", share_net: true, target_file: "/home/u/a.pdf", args: ["/home/u/a.pdf"] },
    error: "", warning: "With network, the program can reach the internet and your local network."
  })
  const bad = S.checkForm({ executable: "/usr/bin/zathura", target: "a.pdf" }, "/home/u")
  assert.strictEqual(bad.params, null)
  assert.match(bad.error, /file's full path/)
  assert.match(S.checkForm({ executable: "zathura", target: "a.pdf" }, "").error, /program's full path/)
})

test("remembers and describes launches", () => {
  const run = (pid, extra) => Object.assign({ executable: "/usr/bin/zathura", share_net: false, pid, started_at: 0 }, extra)
  let runs = []
  for (let i = 1; i <= 7; i++) runs = S.addRun(runs, run(i))
  assert.deepStrictEqual(plain(runs.map(r => r.pid)), [7, 6, 5, 4, 3])
  assert.strictEqual(S.runTitle(run(1)), "zathura, no network")
  assert.strictEqual(S.runTitle(run(1, { target_file: "/home/u/a.pdf", share_net: true })), "zathura with a.pdf, with network")
  assert.strictEqual(S.runDetail(run(42), 30000), "PID 42 · just now")
  assert.strictEqual(S.runDetail(run(42), 5 * 60000), "PID 42 · 5 min ago")
  assert.strictEqual(S.runDetail(run(42), 3 * 3600000), "PID 42 · 3 h ago")
  assert.deepStrictEqual(plain(S.formFor(run(1, { target_file: "/x" }))), { executable: "/usr/bin/zathura", target: "/x", shareNet: false })
})

test("errors and unavailable states", () => {
  const err = (code, message) => ({ code, message })
  assert.strictEqual(S.runErrorText(err(-32602, "invalid params: executable /x: No such file or directory (os error 2)")),
    "Not started: executable /x: No such file or directory (os error 2)")
  assert.strictEqual(S.runErrorText(err(-32006, "starting bwrap: denied")), "Could not start the sandbox: starting bwrap: denied")
  // A missing module is the launcher's state, not this launch's error.
  assert.strictEqual(S.runErrorText(err(-32002, "bwrap is not installed")), "")
  assert.strictEqual(S.runErrorText(null), "")
  assert.match(S.unavailableText(false, "", "", null), /Not connected/)
  assert.match(S.unavailableText(true, "not_implemented", "", null), /not available in this daemon/)
  assert.strictEqual(S.unavailableText(true, "unavailable", "bwrap (bubblewrap) is not installed", null),
    "The sandbox is not available: bwrap (bubblewrap) is not installed")
  assert.strictEqual(S.unavailableText(true, "active", "", err(-32007, "SANDBOX_RUN is not implemented")),
    "The sandbox is not available: SANDBOX_RUN is not implemented")
  assert.strictEqual(S.unavailableText(true, "active", "", err(-32602, "x")), "")
})
