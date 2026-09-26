// SPDX-License-Identifier: MIT
//
// Shell side of the omarchy-securityd IPC protocol (docs/ipc-protocol.md).
// Kept free of QML so the framing and message classification can be tested
// with plain node.
.pragma library

var PROTOCOL_VERSION = 1
var MAX_FRAME_BYTES = 64 * 1024
var CLIENT_NAME = "omarchy-shell/security-hub"

var TOPICS = ["system", "threat", "usbguard", "token", "vault", "firewall", "posture"]

var ErrorCode = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  HANDSHAKE_REQUIRED: -32000,
  UNSUPPORTED_PROTOCOL_VERSION: -32001,
  MODULE_UNAVAILABLE: -32002,
  NOT_FOUND: -32003,
  PERMISSION_DENIED: -32004,
  STALE_TARGET: -32005,
  BACKEND_ERROR: -32006,
  NOT_IMPLEMENTED: -32007,
  CANCELLED: -32008
}

// Firewall connection prompts (docs/ipc-protocol.md §4.6). A prompt stays
// open until FIREWALL_CONNECTION_RESOLVED names its request_id, whichever
// client answered it.
var FirewallEvent = {
  CONNECTION_PROMPT: "FIREWALL_CONNECTION_PROMPT",
  CONNECTION_RESOLVED: "FIREWALL_CONNECTION_RESOLVED"
}
var DECISION_SCOPES = ["once", "process", "always"]
var DECIDED_BY = ["user", "timeout"]

// Display order and labels for the modules the daemon reports.
var MODULES = [
  { id: "threat", label: "Threat monitor" },
  { id: "usbguard", label: "USBGuard" },
  { id: "token", label: "Security tokens" },
  { id: "vault", label: "Encrypted vaults" },
  { id: "firewall", label: "Firewall" },
  { id: "sandbox", label: "Sandbox" },
  { id: "posture", label: "Hardening audit" }
]

function socketPath(env) {
  var override = env("OMARCHY_SECURITYD_SOCKET")
  if (override) return override
  var runtime = env("XDG_RUNTIME_DIR")
  return runtime ? runtime + "/omarchy-security/securityd.sock" : ""
}

function encodeRequest(id, method, params) {
  return JSON.stringify({ jsonrpc: "2.0", id: id, method: method, params: params || {} }) + "\n"
}

// Classifies one received line. Returns
//   { kind: "response", id, result } | { kind: "response", id, error }
//   { kind: "event", name, params }
//   { kind: "invalid", reason }
function decode(line) {
  if (line.length > MAX_FRAME_BYTES) return { kind: "invalid", reason: "frame too large" }
  var msg
  try { msg = JSON.parse(line) } catch (e) { return { kind: "invalid", reason: "not JSON" } }
  if (!msg || typeof msg !== "object" || msg.jsonrpc !== "2.0")
    return { kind: "invalid", reason: "not JSON-RPC 2.0" }
  if (msg.id !== undefined && msg.method === undefined) {
    if (msg.error) return { kind: "response", id: msg.id, error: msg.error }
    return { kind: "response", id: msg.id, result: msg.result }
  }
  if (typeof msg.method === "string" && msg.id === undefined)
    return { kind: "event", name: msg.method, params: msg.params || {} }
  return { kind: "invalid", reason: "neither response nor event" }
}

function moduleLabel(id) {
  for (var i = 0; i < MODULES.length; i++)
    if (MODULES[i].id === id) return MODULES[i].label
  return id
}

function stateLabel(state) {
  switch (state) {
  case "active": return "Active"
  case "degraded": return "Degraded"
  case "unavailable": return "Unavailable"
  case "not_implemented": return "Not implemented"
  default: return "Unknown"
  }
}

// Reconnect delay after `attempt` consecutive failures: 1 s doubling to 30 s.
function backoffMs(attempt) {
  return Math.min(30000, 1000 * Math.pow(2, Math.max(0, attempt)))
}

if (typeof module !== "undefined") module.exports = {
  PROTOCOL_VERSION: PROTOCOL_VERSION, MAX_FRAME_BYTES: MAX_FRAME_BYTES, TOPICS: TOPICS,
  ErrorCode: ErrorCode, FirewallEvent: FirewallEvent, DECISION_SCOPES: DECISION_SCOPES,
  DECIDED_BY: DECIDED_BY, MODULES: MODULES, socketPath: socketPath, encodeRequest: encodeRequest,
  decode: decode, moduleLabel: moduleLabel, stateLabel: stateLabel, backoffMs: backoffMs
}
