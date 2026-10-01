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
  assert.match(V.emptyText(true, "active", "", null, []), /Add vault/)
  assert.strictEqual(V.emptyText(true, "degraded", "luks: udisks2 missing", null, [vault("a")]), "")
})

test("removes a vault from the list", () => {
  const list = [vault("a"), vault("b")]
  assert.deepStrictEqual(plain(V.removeVault(list, "a").map(v => v.vault_id)), ["b"])
  assert.deepStrictEqual(plain(V.removeVault(list, "zz").map(v => v.vault_id)), ["a", "b"])
  assert.deepStrictEqual(plain(V.removeVault(null, "a")), [])
})

test("makes an id from the name", () => {
  assert.strictEqual(V.vaultIdFor("Work documents", []), "work-documents")
  assert.strictEqual(V.vaultIdFor("  Ünïcode – Café!  ", []), "unicode-cafe")
  assert.strictEqual(V.vaultIdFor("日本", []), "vault")
  assert.strictEqual(V.vaultIdFor("", []), "vault")
  assert.strictEqual(V.vaultIdFor("Work", [vault("work"), vault("work-2")]), "work-3")
  const long = V.vaultIdFor("x".repeat(100), [vault("x".repeat(60))])
  assert.ok(long.length <= V.VAULT_ID_MAX, long)
  assert.match(long, /^x+-2$/)
  // Cut at a separator: no dash is left at the end.
  assert.strictEqual(V.vaultIdFor("a".repeat(59) + " bcd", []), "a".repeat(59))
})

test("checks the add form", () => {
  const form = extra => Object.assign({ kind: "gocryptfs", name: "Work", source: "~/Vaults/work.enc", mountPoint: "" }, extra)
  // Nothing to say while a required field is blank.
  assert.strictEqual(V.checkAddForm(form({ name: " " }), []).params, null)
  assert.strictEqual(V.checkAddForm(form({ source: "" }), []).error, "")
  assert.strictEqual(V.checkAddForm(form({ source: "" }), []).params, null)

  // The mount point defaults beside a ….enc folder, else under ~/Vaults.
  const added = V.checkAddForm(form(), [])
  assert.strictEqual(added.method, "VAULT_ADD")
  assert.deepStrictEqual(plain(added.params), {
    vault_id: "work", name: "Work", backend: "gocryptfs", source: "~/Vaults/work.enc", mount_point: "~/Vaults/work"
  })
  assert.strictEqual(V.checkAddForm(form({ source: "/data/cipher/" }), []).mountPoint, "~/Vaults/work")
  assert.strictEqual(V.checkAddForm(form({ source: "/data/.enc" }), []).mountPoint, "~/Vaults/work")
  assert.strictEqual(V.checkAddForm(form({ mountPoint: " /mnt/w " }), []).params.mount_point, "/mnt/w")
  assert.strictEqual(V.checkAddForm(form(), [vault("work")]).params.vault_id, "work-2")

  // A LUKS vault has no mount point.
  const luks = V.checkAddForm(form({ kind: "luks", source: "/dev/sdb1", mountPoint: "/ignored" }), []).params
  assert.deepStrictEqual(plain(luks), { vault_id: "work", name: "Work", backend: "luks", source: "/dev/sdb1" })

  assert.match(V.checkAddForm(form({ source: "Vaults/w" }), []).error, /encrypted folder must be a full path/)
  assert.match(V.checkAddForm(form({ kind: "luks", source: "disk.img" }), []).error, /disk or image/)
  assert.match(V.checkAddForm(form({ mountPoint: "mnt" }), []).error, /mount point/)
  assert.match(V.checkAddForm(form({ source: "/a\nb" }), []).error, /line break/)
  assert.strictEqual(V.checkAddForm(form({ source: "Vaults/w" }), []).params, null)
})

test("checks the create form", () => {
  // A new vault needs only a name; the folders default from its id.
  const created = V.checkAddForm({ kind: "create", name: "Tax papers" }, [vault("tax-papers")])
  assert.strictEqual(created.method, "VAULT_CREATE")
  assert.deepStrictEqual(plain(created.params), {
    vault_id: "tax-papers-2", name: "Tax papers", source: "~/Vaults/tax-papers-2.enc", mount_point: "~/Vaults/tax-papers-2"
  })
  assert.strictEqual(created.source, "~/Vaults/tax-papers-2.enc")
  // An unknown kind is a new vault, the form's default.
  assert.strictEqual(V.checkAddForm({ name: "A" }, []).method, "VAULT_CREATE")
  assert.strictEqual(V.checkAddForm({ kind: "create", name: "" }, []).params, null)

  const typed = V.checkAddForm({ kind: "create", name: "A", source: "/data/a.enc", mountPoint: "" }, []).params
  assert.deepStrictEqual(plain(typed), { vault_id: "a", name: "A", source: "/data/a.enc", mount_point: "/data/a" })
  assert.match(V.checkAddForm({ kind: "create", name: "A", source: "a.enc" }, []).error, /encrypted folder/)
  assert.deepStrictEqual(plain(V.FORM_KINDS.map(k => k.id)), ["create", "gocryptfs", "luks"])
})

test("add and remove error texts", () => {
  const err = (code, message) => ({ code, message })
  assert.strictEqual(V.addErrorText(err(-32602, "invalid params: vault 'w': /x is not a directory")),
    "Not added: /x is not a directory")
  assert.strictEqual(V.addErrorText(err(-32602, "invalid params: vault id 'w' is defined twice")),
    "Not added: vault id 'w' is defined twice")
  assert.match(V.addErrorText(err(-32601, "method not found: VAULT_ADD")), /cannot add vaults/)
  assert.match(V.addErrorText(err(-32601, "method not found"), "VAULT_CREATE"), /cannot create vaults/)
  assert.strictEqual(V.addErrorText(err(-32602, "invalid params: vault 'w': /x is not empty; add it instead"),
    "VAULT_CREATE"), "Not created: /x is not empty; add it instead")
  assert.strictEqual(V.addErrorText(err(-32008, "passphrase prompt was cancelled"), "VAULT_CREATE"), "Cancelled.")
  assert.strictEqual(V.addErrorText(err(-32008, "panic mode ran while the passphrase was asked for"), "VAULT_CREATE"),
    "Cancelled by Panic.")
  assert.match(V.addErrorText(err(-32006, "gocryptfs -init failed"), "VAULT_CREATE"), /^Could not create the vault/)
  assert.match(V.addErrorText(err(-32006, "/c/config.toml is invalid, fix it first: x")), /^Could not add the vault: .*fix it first/)
  assert.strictEqual(V.addErrorText(null), "")
  assert.strictEqual(V.removeErrorText(err(-32006, "vault 'w' is mounted; unmount it first")),
    "Unmount it before removing it.")
  assert.match(V.removeErrorText(err(-32003, "no vault")), /no longer/)
  assert.match(V.removeErrorText(err(-32601, "x")), /cannot remove vaults/)
  assert.match(V.removeErrorText(err(-32006, "a vault is being mounted")), /^Could not remove the vault/)
  assert.strictEqual(V.removeErrorText(null), "")
})
