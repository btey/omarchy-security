// SPDX-License-Identifier: MIT
//
// Rules for the token panel (TokenPanel.qml, plan task 3.8,
// docs/ipc-protocol.md §4.4): how a SecurityToken from TOKEN_LIST and
// TOKEN_INSERTED is described, what its capabilities mean, the touch
// request of that token worth a line, and the empty states. The list and
// the requests are kept by SecurityIPC with Touch.js. Free of QML so it
// can be tested with plain node.
.pragma library

var ErrorCode = {
  MODULE_UNAVAILABLE: -32002,
  NOT_IMPLEMENTED: -32007
}

// A finished request stays on its token's row this long.
var RECENT_MS = 10 * 60 * 1000

function kindLabel(kind) {
  switch (kind) {
  case "yubikey": return "YubiKey"
  case "solokey": return "SoloKey"
  case "nitrokey": return "Nitrokey"
  case "fido2": return "FIDO2 key"
  case "smartcard": return "Smart card reader"
  default: return kind || "Security key"
  }
}

// The daemon's order is fido2, piv, openpgp, otp; keep it.
var CAPABILITIES = {
  fido2: { label: "FIDO2", hint: "Passkeys, web sign-in, SSH (sk keys) and sudo with pam_u2f" },
  piv: { label: "PIV", hint: "Certificates on the key (PIV smart card)" },
  openpgp: { label: "OpenPGP", hint: "GnuPG signing and decryption, and SSH through gpg-agent" },
  otp: { label: "OTP", hint: "One-time passwords typed by the key" }
}

function capabilityLabel(capability) {
  var known = CAPABILITIES[capability]
  return known ? known.label : String(capability || "")
}

function capabilityHint(capability) {
  var known = CAPABILITIES[capability]
  return known ? known.hint : ""
}

// "1050:0407 · serial 23456789"
function idLine(token) {
  if (!token) return ""
  var line = (token.vendor_id || "????") + ":" + (token.product_id || "????")
  if (token.serial) line += " · serial " + token.serial
  return line
}

// The hub notices a touch only for FIDO2 and OpenPGP (§4.4): say so when a
// key has neither, so its silence is not taken for a fault. A smart card
// reader lists no capabilities, but a card in it gets GnuPG prompts.
function touchNote(token) {
  if (!token || token.kind === "smartcard") return ""
  var caps = token.capabilities || []
  if (caps.indexOf("fido2") >= 0 || caps.indexOf("openpgp") >= 0) return ""
  return "Touch prompts are shown for FIDO2 and OpenPGP only."
}

// The request of `tokenId` worth a line under it: one waiting, or else the
// last finished within RECENT_MS. `requests` are Touch.js requests.
function latestRequest(requests, tokenId, now) {
  var waiting = null
  var finished = null
  for (var i = 0; i < (requests || []).length; i++) {
    var r = requests[i]
    if (r.token_id !== tokenId) continue
    if (!r.outcome) {
      if (!waiting || r.requested_at < waiting.requested_at) waiting = r
    } else if (now - r.completed_at < RECENT_MS && (!finished || r.completed_at >= finished.completed_at)) {
      finished = r
    }
  }
  return waiting || finished
}

function sourceName(source) {
  switch (source) {
  case "ssh": return "SSH"
  case "gpg": return "GnuPG"
  case "fido2": return "FIDO2"
  case "pcsc": return "Smart card"
  default: return "An app"
  }
}

function ago(ms) {
  var secs = Math.max(0, Math.round(ms / 1000))
  if (secs < 60) return "just now"
  var mins = Math.round(secs / 60)
  return mins + " min ago"
}

// { text, role } for latestRequest's result, or null.
function requestLine(request, now) {
  if (!request) return null
  var who = sourceName(request.source)
  if (!request.outcome) return { text: who + " is waiting for a touch", role: "warning" }
  var when = ago(now - request.completed_at)
  switch (request.outcome) {
  case "touched": return { text: who + ": touched, " + when, role: "muted" }
  case "timed_out": return { text: who + ": not touched in time, " + when, role: "warning" }
  case "removed": return { text: who + ": the key was unplugged while it waited, " + when, role: "muted" }
  default: return { text: who + ": cancelled, " + when, role: "muted" }
  }
}

// Text for a panel with no tokens to draw, or "".
function emptyText(ready, moduleState, moduleDetail, error, tokens) {
  if (!ready) return "Not connected to omarchy-securityd"
  if (moduleState === "not_implemented") return "Security keys are not watched by this daemon"
  if (moduleState === "unavailable")
    return "Security keys are not watched" + (moduleDetail ? ": " + moduleDetail : "")
  if (error) {
    if (error.code === ErrorCode.MODULE_UNAVAILABLE || error.code === ErrorCode.NOT_IMPLEMENTED)
      return "Security keys are not watched by this daemon"
    return "Could not read the security keys: " + (error.message || "unknown error")
  }
  if (!tokens || tokens.length === 0) return "No security key is plugged in."
  return ""
}

if (typeof module !== "undefined") module.exports = {
  ErrorCode: ErrorCode, RECENT_MS: RECENT_MS, kindLabel: kindLabel, capabilityLabel: capabilityLabel,
  capabilityHint: capabilityHint, idLine: idLine, touchNote: touchNote, latestRequest: latestRequest,
  requestLine: requestLine, emptyText: emptyText
}
