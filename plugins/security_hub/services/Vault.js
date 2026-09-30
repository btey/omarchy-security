// SPDX-License-Identifier: MIT
//
// Rules for the vault panel (VaultPanel.qml, plan task 3.7,
// docs/ipc-protocol.md §4.5): the vaults from VAULT_LIST and
// VAULT_STATE_CHANGED, what Mount, Unmount and Panic say when they fail,
// and the summary of a panic. Free of QML so it can be tested with plain
// node.
.pragma library

var ErrorCode = {
  MODULE_UNAVAILABLE: -32002,
  NOT_FOUND: -32003,
  PERMISSION_DENIED: -32004,
  BACKEND_ERROR: -32006,
  NOT_IMPLEMENTED: -32007,
  CANCELLED: -32008
}

// How long a client waits for an answer. A mount waits for pinentry: up to
// three tries of 120 s each (the daemon's SETTIMEOUT), then up to 60 s for
// gocryptfs. A panic stops processes (2 s grace) and flushes each vault
// (10 s at most).
var MOUNT_TIMEOUT_MS = 10 * 60 * 1000
var UNMOUNT_TIMEOUT_MS = 2 * 60 * 1000
var PANIC_TIMEOUT_MS = 2 * 60 * 1000

// Panic asks for a second click within this long.
var PANIC_CONFIRM_MS = 4000

function findVault(vaults, vaultId) {
  for (var i = 0; i < (vaults || []).length; i++) if (vaults[i].vault_id === vaultId) return vaults[i]
  return null
}

// The list with `vault` updated in place, or added at the end: the
// daemon lists vaults in the configuration's order.
function upsertVault(vaults, vault) {
  if (!vault || typeof vault.vault_id !== "string") return vaults
  var next = (vaults || []).slice()
  for (var i = 0; i < next.length; i++) {
    if (next[i].vault_id === vault.vault_id) {
      next[i] = vault
      return next
    }
  }
  next.push(vault)
  return next
}

function isMounted(vault) {
  return !!vault && vault.mounted === true
}

function mountedCount(vaults) {
  var n = 0
  for (var i = 0; i < (vaults || []).length; i++) if (isMounted(vaults[i])) n++
  return n
}

function backendLabel(backend) {
  switch (backend) {
  case "gocryptfs": return "gocryptfs"
  case "luks": return "LUKS"
  default: return backend || "unknown"
  }
}

// `path` with the home directory shortened to "~".
function shortPath(path, home) {
  if (!path) return ""
  if (home && home !== "/" && (path === home || path.indexOf(home + "/") === 0)) return "~" + path.slice(home.length)
  return path
}

// The line under a vault's name. `op` is what this shell is doing to it:
// "mount", "unmount" or "".
function stateText(vault, op, home) {
  if (!vault) return ""
  if (op === "mount") return "Waiting for the passphrase…"
  if (op === "unmount") return "Unmounting…"
  if (!isMounted(vault)) return "Locked"
  var where = shortPath(vault.mount_point, home)
  return where ? "Open at " + where : "Open"
}

function vaultRole(vault) {
  return isMounted(vault) ? "accent" : "muted"
}

// Panic has something to do: a vault is open, or a mount is waiting for
// its passphrase (panic closes the prompt).
function canPanic(vaults, ops) {
  if (mountedCount(vaults) > 0) return true
  for (var id in (ops || {})) if (ops[id] === "mount") return true
  return false
}

// What to say when Mount or Unmount failed; `action` is "mount" or
// "unmount".
function opErrorText(error, action) {
  if (!error) return ""
  var message = error.message || "unknown error"
  switch (error.code) {
  case ErrorCode.CANCELLED:
    return /panic/i.test(message) ? "Cancelled by Panic." : "Cancelled."
  case ErrorCode.PERMISSION_DENIED:
    if (action === "mount" && /passphrase/i.test(message)) return "Wrong passphrase three times. Try again."
    return "Not authorized: " + message
  case ErrorCode.BACKEND_ERROR:
    if (action === "unmount" && /busy/i.test(message))
      return "Still in use. Close the programs using it, or use Panic."
    return (action === "mount" ? "Could not mount: " : "Could not unmount: ") + message
  case ErrorCode.NOT_FOUND:
    return "This vault is no longer in the configuration."
  default:
    return message
  }
}

// A cancelled prompt is the user's own doing, not a failure.
function opErrorRole(error) {
  return error && error.code === ErrorCode.CANCELLED ? "muted" : "danger"
}

function vaultName(vaults, vaultId) {
  var vault = findVault(vaults, vaultId)
  return vault && vault.name ? vault.name : vaultId
}

function plural(n, one, many) {
  return n + " " + (n === 1 ? one : many)
}

// { title, lines, role } for a PanicResult; `vaults` supplies the names.
function panicSummary(result, vaults) {
  if (!result) return { title: "", lines: [], role: "muted" }
  var unmounted = Array.isArray(result.unmounted) ? result.unmounted : []
  var lazy = Array.isArray(result.lazy) ? result.lazy : []
  var failed = Array.isArray(result.failed) ? result.failed : []
  var title
  if (unmounted.length === 0 && failed.length === 0) title = "Panic ran: no vault was open."
  else if (failed.length === 0) title = "Panic locked " + plural(unmounted.length, "vault", "vaults") + "."
  else title = "Panic locked " + plural(unmounted.length, "vault", "vaults") + "; "
    + plural(failed.length, "vault was", "vaults were") + " not closed cleanly."
  var lines = []
  for (var i = 0; i < lazy.length; i++)
    lines.push(vaultName(vaults, lazy[i]) + " was still in use and was detached lazily: "
      + "a program the daemon cannot see may keep reading files it has open.")
  for (var j = 0; j < failed.length; j++)
    lines.push(vaultName(vaults, failed[j].vault_id) + ": " + (failed[j].reason || "failed"))
  var role = failed.length > 0 ? "danger" : lazy.length > 0 ? "warning" : "success"
  return { title: title, lines: lines, role: role }
}

function panicErrorText(error) {
  if (!error) return ""
  return "Panic failed: " + (error.message || "unknown error")
}

// Text for a panel with no vaults to draw, or "".
function emptyText(ready, moduleState, moduleDetail, error, vaults) {
  if (!ready) return "Not connected to omarchy-securityd"
  if (moduleState === "not_implemented") return "Encrypted vaults are not available in this daemon"
  if (moduleState === "unavailable")
    return "Encrypted vaults are not available" + (moduleDetail ? ": " + moduleDetail : "")
  if (error) {
    if (error.code === ErrorCode.MODULE_UNAVAILABLE || error.code === ErrorCode.NOT_IMPLEMENTED)
      return "Encrypted vaults are not available"
    return "Could not read the vaults: " + (error.message || "unknown error")
  }
  if (!vaults || vaults.length === 0)
    return "No vaults are set up. Add a [[vault]] table to ~/.config/omarchy-security/config.toml."
  return ""
}

if (typeof module !== "undefined") module.exports = {
  ErrorCode: ErrorCode, MOUNT_TIMEOUT_MS: MOUNT_TIMEOUT_MS, UNMOUNT_TIMEOUT_MS: UNMOUNT_TIMEOUT_MS,
  PANIC_TIMEOUT_MS: PANIC_TIMEOUT_MS, PANIC_CONFIRM_MS: PANIC_CONFIRM_MS,
  findVault: findVault, upsertVault: upsertVault, isMounted: isMounted, mountedCount: mountedCount,
  backendLabel: backendLabel, shortPath: shortPath, stateText: stateText, vaultRole: vaultRole,
  canPanic: canPanic, opErrorText: opErrorText, opErrorRole: opErrorRole, vaultName: vaultName,
  panicSummary: panicSummary, panicErrorText: panicErrorText, emptyText: emptyText
}
