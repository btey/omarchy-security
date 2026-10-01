// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const os = require("node:os")
const path = require("node:path")
const vm = require("node:vm")
const { execFileSync } = require("node:child_process")

// Update.js is a QML `.pragma library` script; drop the pragma to run it
// as plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Update.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const U = sandbox.module.exports
const plain = value => JSON.parse(JSON.stringify(value))
const DAY = 24 * 60 * 60 * 1000

test("finds the newest release tag", () => {
  const out = [
    "1111111111111111111111111111111111111111\trefs/tags/v1.1.5",
    "2222222222222222222222222222222222222222\trefs/tags/v1.10.0",
    "3333333333333333333333333333333333333333\trefs/tags/v1.9.9",
    // A pre-release, and tags that are not versions, are never offered.
    "4444444444444444444444444444444444444444\trefs/tags/v2.0.0-rc1",
    "5555555555555555555555555555555555555555\trefs/tags/vnext",
    "6666666666666666666666666666666666666666\trefs/tags/v3.0",
    ""
  ].join("\n")
  assert.strictEqual(U.latestTag(out), "1.10.0")
  assert.strictEqual(U.latestTag(""), "")
  assert.strictEqual(U.latestTag("garbage"), "")
})

test("offers only a newer version", () => {
  assert.strictEqual(U.available("1.1.6", "1.1.7"), "1.1.7")
  assert.strictEqual(U.available("1.1.6", "1.1.6"), "")
  assert.strictEqual(U.available("1.2.0", "1.1.9"), "")
  assert.strictEqual(U.available("1.1.6", ""), "")
  // A development build without a plain version is never told to update.
  assert.strictEqual(U.available("dev", "9.9.9"), "")
  assert.strictEqual(U.compareVersions("1.9.0", "1.10.0"), -1)
  assert.strictEqual(U.parseVersion("1.3.0-rc1"), null)
})

test("checks at most once a day", () => {
  const now = 10 * DAY
  assert.strictEqual(U.isDue(U.parseState(""), now), true)
  assert.strictEqual(U.isDue({ checkedAt: now - DAY + 1000 }, now), false)
  assert.strictEqual(U.isDue({ checkedAt: now - DAY }, now), true)
  // A clock set back does not stop the checks.
  assert.strictEqual(U.isDue({ checkedAt: now + 1000 }, now), true)
})

test("notifies once per version", () => {
  assert.strictEqual(U.shouldNotify({ notified: "" }, "1.1.7"), true)
  assert.strictEqual(U.shouldNotify({ notified: "1.1.7" }, "1.1.7"), false)
  assert.strictEqual(U.shouldNotify({ notified: "1.1.7" }, "1.1.8"), true)
  assert.strictEqual(U.shouldNotify({ notified: "" }, ""), false)
})

test("keeps its state across restarts", () => {
  const state = { checkedAt: 1790000000000, latest: "1.1.7", notified: "1.1.7" }
  assert.deepStrictEqual(plain(U.parseState(U.stateText(state))), state)
  assert.deepStrictEqual(plain(U.parseState("not json")), { checkedAt: 0, latest: "", notified: "" })
  assert.deepStrictEqual(plain(U.parseState('{"checked_at": -1, "latest": "x", "notified": 3}')),
    { checkedAt: 0, latest: "", notified: "" })
  const env = vars => name => vars[name] || ""
  assert.strictEqual(U.statePath(env({ XDG_STATE_HOME: "/s" })), "/s/omarchy-security/plugin-update.json")
  assert.strictEqual(U.statePath(env({ HOME: "/home/u" })), "/home/u/.local/state/omarchy-security/plugin-update.json")
  assert.strictEqual(U.statePath(env({})), "")
})

test("builds the commands", () => {
  assert.deepStrictEqual(plain(U.updateCommand("security-hub")),
    [U.TERMINAL, "omarchy plugin update security-hub"])
  const notify = plain(U.notifyCommand("security-hub", "1.1.6", "1.1.7"))
  assert.strictEqual(notify[0], "omarchy-notification-send")
  assert.ok(notify.includes("Security Hub 1.1.7 is available"))
  // A click runs the update; --exec comes last and takes the rest.
  assert.deepStrictEqual(notify.slice(notify.indexOf("--exec") + 1), plain(U.updateCommand("security-hub")))
  const ls = plain(U.lsRemote("/p"))
  assert.deepStrictEqual(ls.slice(-8), ["git", "-C", "/p", "ls-remote", "--tags", "--refs", "origin", "v*"])
  assert.ok(ls.includes("GIT_TERMINAL_PROMPT=0"))
})

// The command itself, against a local origin, as `omarchy plugin add`
// leaves a checkout.
test("reads the tags of a real checkout's origin", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "update-test-"))
  try {
    const git = (cwd, ...args) => execFileSync("git", args, { cwd, stdio: ["ignore", "pipe", "ignore"],
      env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" } }).toString()
    const origin = path.join(dir, "origin")
    fs.mkdirSync(origin)
    git(origin, "init", "-q", "-b", "main")
    git(origin, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "one")
    git(origin, "tag", "v1.1.6")
    git(origin, "tag", "v1.1.7")
    git(dir, "clone", "-q", origin, "checkout")
    const [cmd, ...args] = U.lsRemote(path.join(dir, "checkout"))
    const out = execFileSync(cmd, args).toString()
    assert.strictEqual(U.latestTag(out), "1.1.7")
  } finally {
    fs.rmSync(dir, { recursive: true, force: true })
  }
})
