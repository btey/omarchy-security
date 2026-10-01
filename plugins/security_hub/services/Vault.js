// SPDX-License-Identifier: MIT
//
// Rules for the vault panel (VaultPanel.qml, plan task 3.7,
// docs/ipc-protocol.md §4.5): the vaults from VAULT_LIST,
// VAULT_STATE_CHANGED and VAULT_REMOVED, what Mount, Unmount and Panic say
// when they fail, the summary of a panic, and the form behind VAULT_ADD
// and VAULT_CREATE.
// Free of QML so it can be tested with plain node.
.pragma library

var ErrorCode = {
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
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

// The list without `vaultId`.
function removeVault(vaults, vaultId) {
  return (vaults || []).filter(function(v) { return v.vault_id !== vaultId })
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

// VAULT_CREATE waits for the new passphrase, typed twice; as long as a
// mount at most.
var CREATE_TIMEOUT_MS = MOUNT_TIMEOUT_MS

// Bounds of a vault id (docs/configuration.md): 1 to 64 of a-z, 0-9, -.
var VAULT_ID_MAX = 64

// An id for a new vault called `name` that no vault in `vaults` has:
// "Work documents" → "work-documents", then "work-documents-2".
function vaultIdFor(name, vaults) {
  var base = String(name || "").toLowerCase()
  if (typeof base.normalize === "function") base = base.normalize("NFD").replace(/[\u0300-\u036f]/g, "")
  base = base.replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, VAULT_ID_MAX - 4).replace(/-+$/, "")
  if (base === "") base = "vault"
  var id = base
  for (var n = 2; findVault(vaults, id); n++) id = base + "-" + n
  return id
}

// Where a new gocryptfs vault opens when the form leaves it blank: beside
// a "….enc" cipher directory without the suffix, else ~/Vaults/<id>.
function defaultMountPoint(source, vaultId) {
  var s = String(source || "").trim().replace(/\/+$/, "")
  if (/[^/]\.enc$/.test(s)) return s.slice(0, -4)
  return "~/Vaults/" + vaultId
}

// Why `path`, typed for `what`, cannot be sent, or "". The daemon expands
// "~/" and checks the rest.
function vaultPathProblem(path, what) {
  if (path.charAt(0) !== "/" && path.indexOf("~/") !== 0)
    return "The " + what + " must be a full path, or start with ~/."
  if (/[\u0000\n\r]/.test(path)) return "The " + what + " has a line break in it."
  return ""
}

// What the add form can do: make a new gocryptfs vault (VAULT_CREATE), or
// add one that exists (VAULT_ADD).
var FORM_KINDS = [
  { id: "create", label: "New vault" },
  { id: "gocryptfs", label: "Existing gocryptfs folder" },
  { id: "luks", label: "LUKS disk or image" }
]

// Where a new vault's encrypted files go when the form leaves it blank.
function defaultCipherDir(vaultId) {
  return "~/Vaults/" + vaultId + ".enc"
}

// Checks the add form `{kind, name, source, mountPoint}`, `kind` one of
// FORM_KINDS. Returns `{method, params, error, vaultId, source,
// mountPoint}`: `method` and `params` to send when the form can be sent,
// else `params` is null, with `error` saying why (empty while a required
// field is still blank). `source` and `mountPoint` are what will be used,
// defaults included. Paths are sent as typed, "~/" included, so the
// configuration file stays readable.
function checkAddForm(form, vaults) {
  var f = form || {}
  var kind = f.kind === "luks" || f.kind === "gocryptfs" ? f.kind : "create"
  var name = String(f.name || "").trim()
  var vaultId = vaultIdFor(name, vaults)
  var source = String(f.source || "").trim()
  if (kind === "create" && source === "") source = defaultCipherDir(vaultId)
  var typedMount = String(f.mountPoint || "").trim()
  var mountPoint = kind !== "luks" ? (typedMount || defaultMountPoint(source, vaultId)) : ""
  var result = {
    method: kind === "create" ? "VAULT_CREATE" : "VAULT_ADD",
    params: null, error: "", vaultId: vaultId, source: source, mountPoint: mountPoint
  }
  if (name === "" || source === "") return result
  result.error = vaultPathProblem(source, kind === "luks" ? "disk or image" : "encrypted folder")
  if (!result.error && kind !== "luks") result.error = vaultPathProblem(mountPoint, "mount point")
  if (result.error) return result
  if (kind === "create") {
    result.params = { vault_id: vaultId, name: name, source: source, mount_point: mountPoint }
    return result
  }
  var params = { vault_id: vaultId, name: name, backend: kind, source: source }
  if (kind === "gocryptfs") params.mount_point = mountPoint
  result.params = params
  return result
}

// What to say when VAULT_ADD or VAULT_CREATE (`method`) failed.
// INVALID_PARAMS carries the daemon's reason, after "invalid params: " and
// "vault '<id>': ".
function addErrorText(error, method) {
  if (!error) return ""
  var create = method === "VAULT_CREATE"
  var message = error.message || "unknown error"
  switch (error.code) {
  case ErrorCode.METHOD_NOT_FOUND:
    return create ? "This omarchy-securityd cannot create vaults; update it."
      : "This omarchy-securityd cannot add vaults; update it, or edit config.toml."
  case ErrorCode.CANCELLED:
    return /panic/i.test(message) ? "Cancelled by Panic." : "Cancelled."
  case ErrorCode.INVALID_PARAMS:
    return (create ? "Not created: " : "Not added: ")
      + message.replace(/^invalid params: /, "").replace(/^vault '[^']*': /, "")
  default:
    return (create ? "Could not create the vault: " : "Could not add the vault: ") + message
  }
}

// What to say when VAULT_REMOVE failed.
function removeErrorText(error) {
  if (!error) return ""
  if (error.code === ErrorCode.METHOD_NOT_FOUND)
    return "This omarchy-securityd cannot remove vaults; update it, or edit config.toml."
  if (error.code === ErrorCode.NOT_FOUND) return "This vault is no longer in the configuration."
  if (error.code === ErrorCode.BACKEND_ERROR && /unmount it first/.test(error.message || ""))
    return "Unmount it before removing it."
  return "Could not remove the vault: " + (error.message || "unknown error")
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
    return "No vaults yet. Create one, or add a gocryptfs folder or LUKS disk you have, with Add vault."
  return ""
}

if (typeof module !== "undefined") module.exports = {
  ErrorCode: ErrorCode, MOUNT_TIMEOUT_MS: MOUNT_TIMEOUT_MS, UNMOUNT_TIMEOUT_MS: UNMOUNT_TIMEOUT_MS,
  PANIC_TIMEOUT_MS: PANIC_TIMEOUT_MS, PANIC_CONFIRM_MS: PANIC_CONFIRM_MS,
  findVault: findVault, upsertVault: upsertVault, removeVault: removeVault, isMounted: isMounted, mountedCount: mountedCount,
  backendLabel: backendLabel, shortPath: shortPath, stateText: stateText, vaultRole: vaultRole,
  canPanic: canPanic, opErrorText: opErrorText, opErrorRole: opErrorRole, vaultName: vaultName,
  panicSummary: panicSummary, panicErrorText: panicErrorText, emptyText: emptyText,
  VAULT_ID_MAX: VAULT_ID_MAX, vaultIdFor: vaultIdFor, defaultMountPoint: defaultMountPoint,
  vaultPathProblem: vaultPathProblem, checkAddForm: checkAddForm, addErrorText: addErrorText,
  FORM_KINDS: FORM_KINDS, defaultCipherDir: defaultCipherDir, CREATE_TIMEOUT_MS: CREATE_TIMEOUT_MS,
  removeErrorText: removeErrorText
}
