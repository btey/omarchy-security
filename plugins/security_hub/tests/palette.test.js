// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

// Palette.js is a QML `.pragma library` script; drop the pragma to run it
// as plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Palette.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const P = sandbox.module.exports
const plain = value => JSON.parse(JSON.stringify(value))

test("parses named colours from colors.toml", () => {
  const colors = P.parseColors([
    'mode = "dark"',
    "",
    'accent = "#7aa2f7"',
    'red = "#F7768E"   # comment',
    "yellow = '#e0af68'",
    "green = #9ece6a",
    'Short = "#abc"',
    'alpha = "#11223344"',
    'bad = "#12345"',
    'name = "tokyo"',
    '# red = "#000000"'
  ].join("\n"))
  assert.deepStrictEqual(plain(colors), {
    accent: "#7aa2f7", red: "#F7768E", yellow: "#e0af68", green: "#9ece6a",
    short: "#abc", alpha: "#11223344"
  })
  assert.deepStrictEqual(plain(P.parseColors("")), {})
  assert.deepStrictEqual(plain(P.parseColors(undefined)), {})
})

test("semantic colours prefer named keys over ANSI slots", () => {
  assert.deepStrictEqual(plain(P.semantic({ red: "#f00", color1: "#a00", color3: "#aa0", green: "#0f0" })),
    { danger: "#f00", warning: "#aa0", success: "#0f0" })
  assert.deepStrictEqual(plain(P.semantic({})), { danger: "", warning: "", success: "" })
  assert.deepStrictEqual(plain(P.semantic(null)), { danger: "", warning: "", success: "" })
})

test("every shipped Omarchy theme yields all three semantic colours", t => {
  const themes = path.join(process.env.OMARCHY_PATH || "/usr/share/omarchy", "themes")
  if (!fs.existsSync(themes)) return t.skip("no Omarchy themes at " + themes)
  for (const name of fs.readdirSync(themes)) {
    const file = path.join(themes, name, "colors.toml")
    if (!fs.existsSync(file)) continue
    const semantic = P.semantic(P.parseColors(fs.readFileSync(file, "utf8")))
    for (const role of ["danger", "warning", "success"])
      assert.match(semantic[role], /^#[0-9A-Fa-f]{3,8}$/, name + " " + role)
  }
})

test("maps module states and posture statuses to roles", () => {
  assert.strictEqual(P.moduleStateRole("active"), "success")
  assert.strictEqual(P.moduleStateRole("degraded"), "warning")
  assert.strictEqual(P.moduleStateRole("unavailable"), "danger")
  assert.strictEqual(P.moduleStateRole("not_implemented"), "muted")
  assert.strictEqual(P.moduleStateRole(""), "muted")
  assert.strictEqual(P.postureRole("pass"), "success")
  assert.strictEqual(P.postureRole("warn"), "warning")
  assert.strictEqual(P.postureRole("fail"), "danger")
  assert.strictEqual(P.postureRole("unknown"), "muted")
})
