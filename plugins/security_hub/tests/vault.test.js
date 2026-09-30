// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

// Vault.js is a QML `.pragma library` script; drop the pragma to run it
// as plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Vault.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const V = sandbox.module.exports
const plain = value => JSON.parse(JSON.stringify(value))

const vault = (vault_id, extra) => Object.assign({ vault_id, name: vault_id.toUpperCase(), backend: "gocryptfs",
  mount_point: "/home/u/Vaults/" + vault_id, mounted: false }, extra)

test("keeps vaults in the daemon's order", () => {
  let list = [vault("b"), vault("a")]
  list = V.upsertVault(list, vault("a", { mounted: true }))
  list = V.upsertVault(list, vault("c"))
  assert.deepStrictEqual(plain(list.map(v => [v.vault_id, v.mounted])), [["b", false], ["a", true], ["c", false]])
  assert.strictEqual(V.upsertVault(list, null), list)
  assert.strictEqual(V.upsertVault(list, { name: "no id" }), list)
  assert.strictEqual(V.findVault(list, "a").mounted, true)
  assert.strictEqual(V.findVault(list, "x"), null)
  assert.strictEqual(V.mountedCount(list), 1)
  assert.strictEqual(V.mountedCount(null), 0)
})

test("describes a vault", () => {
  assert.strictEqual(V.backendLabel("luks"), "LUKS")
  assert.strictEqual(V.backendLabel("gocryptfs"), "gocryptfs")
  assert.strictEqual(V.shortPath("/home/u/Vaults/a", "/home/u"), "~/Vaults/a")
  assert.strictEqual(V.shortPath("/home/user2/x", "/home/u"), "/home/user2/x")
  assert.strictEqual(V.shortPath("/run/media/u/backup", "/home/u"), "/run/media/u/backup")
  assert.strictEqual(V.stateText(vault("a"), "", "/home/u"), "Locked")
  assert.strictEqual(V.stateText(vault("a", { mounted: true }), "", "/home/u"), "Open at ~/Vaults/a")
  // A LUKS vault's mount point is chosen by udisks2, and empty until then.
  assert.strictEqual(V.stateText(vault("a", { mounted: true, mount_point: "" }), "", ""), "Open")
  assert.strictEqual(V.stateText(vault("a"), "mount", ""), "Waiting for the passphrase…")
  assert.strictEqual(V.stateText(vault("a", { mounted: true }), "unmount", ""), "Unmounting…")
  assert.deepStrictEqual([vault("a"), vault("a", { mounted: true })].map(V.vaultRole), ["muted", "accent"])
})

test("offers Panic while something is open or asking", () => {
  assert.strictEqual(V.canPanic([vault("a")], {}), false)
  assert.strictEqual(V.canPanic([vault("a", { mounted: true })], {}), true)
  // A mount waiting for its passphrase: panic closes the prompt.
  assert.strictEqual(V.canPanic([vault("a")], { a: "mount" }), true)
  assert.strictEqual(V.canPanic([vault("a")], { a: "unmount" }), false)
  assert.strictEqual(V.canPanic(null, null), false)
})

test("error texts", () => {
  const err = (code, message) => ({ code, message })
  assert.strictEqual(V.opErrorText(err(-32008, "passphrase prompt was cancelled"), "mount"), "Cancelled.")
  assert.strictEqual(V.opErrorText(err(-32008, "panic mode ran while the passphrase was asked for"), "mount"),
    "Cancelled by Panic.")
  assert.match(V.opErrorText(err(-32004, "vault 'a': wrong passphrase"), "mount"), /Wrong passphrase/)
  assert.match(V.opErrorText(err(-32004, "udisks2: unlocking: NotAuthorized"), "mount"), /^Not authorized/)
  assert.match(V.opErrorText(err(-32006, "fusermount3 -u failed: Device or resource busy"), "unmount"),
    /Still in use.*Panic/)
  assert.strictEqual(V.opErrorText(err(-32006, "gocryptfs failed"), "mount"), "Could not mount: gocryptfs failed")
  assert.match(V.opErrorText(err(-32003, "no vault"), "mount"), /no longer/)
  assert.strictEqual(V.opErrorText(err(-32002, "vault 'a': gocryptfs is not installed"), "mount"),
    "vault 'a': gocryptfs is not installed")
  assert.strictEqual(V.opErrorText(null, "mount"), "")
  assert.strictEqual(V.opErrorRole(err(-32008, "x")), "muted")
  assert.strictEqual(V.opErrorRole(err(-32004, "x")), "danger")
  assert.match(V.panicErrorText(err(-32603, "request timed out")), /^Panic failed: request timed out/)
})

test("sums up a panic", () => {
  const list = [vault("a", { name: "Notes" }), vault("b", { name: "Work" }), vault("c", { name: "Photos" })]
  assert.deepStrictEqual(plain(V.panicSummary({ unmounted: ["a"], lazy: [], failed: [] }, list)),
    { title: "Panic locked 1 vault.", lines: [], role: "success" })
  assert.deepStrictEqual(plain(V.panicSummary({ unmounted: [], lazy: [], failed: [] }, list)),
    { title: "Panic ran: no vault was open.", lines: [], role: "success" })

  const lazy = V.panicSummary({ unmounted: ["a", "b"], lazy: ["b"], failed: [] }, list)
  assert.strictEqual(lazy.title, "Panic locked 2 vaults.")
  assert.strictEqual(lazy.role, "warning")
  assert.match(lazy.lines[0], /^Work was still in use and was detached lazily/)

  // A vault the compositor used: detached lazily, but reported as failed.
  const failed = V.panicSummary({ unmounted: ["a"], failed: [{ vault_id: "c", reason: "in use by Hyprland" }] }, list)
  assert.strictEqual(failed.title, "Panic locked 1 vault; 1 vault was not closed cleanly.")
  assert.deepStrictEqual(plain(failed.lines), ["Photos: in use by Hyprland"])
  assert.strictEqual(failed.role, "danger")
  // A vault this shell does not know is named by its id.
  assert.deepStrictEqual(plain(V.panicSummary({ unmounted: [], lazy: ["zz"] }, list).lines.map(l => l.split(" ")[0])),
    ["zz"])
  assert.strictEqual(V.panicSummary(null, list).title, "")
})

test("empty states", () => {
  assert.match(V.emptyText(false, "", "", null, []), /Not connected/)
  assert.match(V.emptyText(true, "not_implemented", "", null, []), /not available/)
  assert.strictEqual(V.emptyText(true, "unavailable", "gocryptfs is not installed", null, []),
    "Encrypted vaults are not available: gocryptfs is not installed")
  assert.match(V.emptyText(true, "active", "", { code: -32007, message: "x" }, []), /not available/)
  assert.match(V.emptyText(true, "active", "", { code: -32603, message: "boom" }, []), /boom/)
  assert.match(V.emptyText(true, "active", "", null, []), /\[\[vault\]\]/)
  assert.strictEqual(V.emptyText(true, "degraded", "luks: udisks2 missing", null, [vault("a")]), "")
})
