// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")
const { execFileSync } = require("node:child_process")

// Backend.js is a QML `.pragma library` script; drop the pragma to run it
// as plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Backend.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const B = sandbox.module.exports
const plain = value => JSON.parse(JSON.stringify(value))

test("compares versions by number", () => {
  assert.deepStrictEqual(plain(B.parseVersion("1.10.2")), [1, 10, 2])
  assert.deepStrictEqual(plain(B.parseVersion("v1.0.0-rc1")), [1, 0, 0])
  assert.strictEqual(B.parseVersion("1.0"), null)
  assert.strictEqual(B.parseVersion(""), null)
  assert.strictEqual(B.compareVersions("1.9.0", "1.10.0"), -1)
  assert.strictEqual(B.compareVersions("2.0.0", "1.99.99"), 1)
  assert.strictEqual(B.compareVersions("1.0.0", "1.0.0"), 0)
  assert.strictEqual(B.compareVersions("dev", "1.0.0"), null)
})

test("says what the backend needs", () => {
  // Connected: only the versions matter.
  assert.strictEqual(B.state(true, "1.0.0", "1.0.0", null), "ok")
  assert.strictEqual(B.state(true, "1.0.0", "1.1.0", null), "older")
  assert.strictEqual(B.state(true, "1.2.0", "1.1.0", null), "newer")
  // A version that is not comparable is not worth a warning.
  assert.strictEqual(B.state(true, "", "1.1.0", null), "ok")
  // Not connected: the probe says why.
  assert.strictEqual(B.state(false, "", "1.0.0", null), "checking")
  assert.strictEqual(B.state(false, "", "1.0.0", B.PROBE_MISSING), "missing")
  assert.strictEqual(B.state(false, "", "1.0.0", B.PROBE_STOPPED), "stopped")
  assert.strictEqual(B.state(false, "", "1.0.0", 0), "unreachable")
  for (const kind of ["checking", "missing", "stopped", "unreachable"]) assert.ok(B.blocksHub(kind), kind)
  for (const kind of ["ok", "older", "newer"]) assert.ok(!B.blocksHub(kind), kind)
})

test("offers the fix for each state", () => {
  const ctx = { pluginVersion: "1.1.0", daemonVersion: "1.0.0", scriptPath: "/p/backend/install.sh", lastError: "refused" }
  assert.strictEqual(B.message("missing", ctx).action, "install")
  assert.match(B.message("missing", ctx).body, /1\.1\.0/)
  assert.strictEqual(B.message("missing", ctx).manual, "/p/backend/install.sh --from-source")
  assert.strictEqual(B.message("stopped", ctx).action, "start")
  assert.strictEqual(B.message("unreachable", ctx).action, "")
  assert.strictEqual(B.message("unreachable", ctx).body, "refused")
  assert.strictEqual(B.message("older", ctx).action, "install")
  assert.match(B.message("older", ctx).title, /1\.0\.0 is older than the plugin \(1\.1\.0\)/)
  assert.strictEqual(B.message("newer", ctx).action, "")
  assert.strictEqual(B.message("newer", ctx).manual, "omarchy plugin update security-hub")
  assert.strictEqual(B.message("ok", ctx), null)
})

test("finds the script's path", () => {
  assert.strictEqual(B.localPath("file:///home/a%20b/backend/install.sh"), "/home/a b/backend/install.sh")
  assert.strictEqual(B.localPath("qrc:/x"), "")
})

test("quotes the path for the terminal launcher's bash", () => {
  const argv = B.terminalCommand("/home/it's/install.sh", ["--from-source"])
  assert.strictEqual(argv[0], "omarchy-launch-floating-terminal-with-presentation")
  assert.strictEqual(argv.length, 2)
  // The launcher runs its arguments as one bash command line.
  const words = execFileSync("bash", ["-c", 'for w in ' + argv[1] + '; do printf "%s\\n" "$w"; done'],
    { encoding: "utf8" }).trimEnd().split("\n")
  assert.deepStrictEqual(words, ["/home/it's/install.sh", "--from-source"])
})

test("the probe tells a missing daemon from a stopped one", () => {
  const run = env => {
    try {
      // By path: PATH holds only the stubs.
      assert.strictEqual(B.PROBE[0], "sh")
      execFileSync("/bin/sh", B.PROBE.slice(1), { env, stdio: "ignore" })
      return 0
    } catch (e) {
      return e.status
    }
  }
  const dir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "omsec-probe-"))
  try {
    // No omarchy-securityd on PATH.
    assert.strictEqual(run({ PATH: dir }), B.PROBE_MISSING)
    // One there, and a systemctl that says the unit is inactive.
    fs.writeFileSync(path.join(dir, "omarchy-securityd"), "#!/bin/sh\n", { mode: 0o755 })
    fs.writeFileSync(path.join(dir, "systemctl"), "#!/bin/sh\nexit 3\n", { mode: 0o755 })
    assert.strictEqual(run({ PATH: dir }), B.PROBE_STOPPED)
    fs.writeFileSync(path.join(dir, "systemctl"), "#!/bin/sh\nexit 0\n", { mode: 0o755 })
    assert.strictEqual(run({ PATH: dir }), 0)
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})
