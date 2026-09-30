// SPDX-License-Identifier: MIT
//
// Rules for the security-key touch prompt (plan task 3.5,
// docs/ipc-protocol.md §4.4): the tokens SecurityIPC keeps from TOKEN_LIST
// and TOKEN_INSERTED / TOKEN_REMOVED, the touch requests it keeps from
// TOKEN_TOUCH_REQUESTED / TOKEN_TOUCH_COMPLETED, what the prompt shows, and
// for how long. Free of QML so it can be tested with plain node.
.pragma library

// Requests kept, newest last. Waiting ones are never dropped for room.
var MAX_REQUESTS = 20

// A request the daemon never finishes stops being shown after this long.
// FIDO2 requests end within 3 s of the key's last keepalive and gpg ones
// after 15 s, so this only covers a lost event.
var STALE_MS = 60000

// How long a finished request stays on screen, by outcome.
var LINGER_MS = {
  touched: 1200,
  timed_out: 5000,
  cancelled: 2500,
  removed: 2500
}

// ------------------------------------------------------------------ tokens

// `tokens` with `token` added or replaced, in token_id order.
function upsertToken(tokens, token) {
  if (!token || typeof token.token_id !== "string") return tokens
  var next = []
  for (var i = 0; i < tokens.length; i++)
    if (tokens[i].token_id !== token.token_id) next.push(tokens[i])
  next.push(token)
  next.sort(function(a, b) { return a.token_id < b.token_id ? -1 : a.token_id > b.token_id ? 1 : 0 })
  return next
}

function removeToken(tokens, tokenId) {
  var next = tokens.filter(function(t) { return t.token_id !== tokenId })
  return next.length === tokens.length ? tokens : next
}

function findToken(tokens, tokenId) {
  for (var i = 0; i < tokens.length; i++)
    if (tokens[i].token_id === tokenId) return tokens[i]
  return null
}

// ---------------------------------------------------------------- requests

// Waiting for a touch: no outcome yet.
function isWaiting(request) {
  return !!request && !request.outcome
}

function findRequest(requests, requestId) {
  for (var i = 0; i < requests.length; i++)
    if (requests[i].request_id === requestId) return requests[i]
  return null
}

function trim(requests) {
  var extra = requests.length - MAX_REQUESTS
  if (extra <= 0) return requests
  return requests.filter(function(r) {
    if (extra > 0 && !isWaiting(r)) {
      extra--
      return false
    }
    return true
  })
}

// TOKEN_TOUCH_REQUESTED, seen at `now` (ms, this clock). The daemon's
// request ids only grow while it runs.
function startRequest(requests, params, now) {
  if (!params || typeof params.request_id !== "number") return requests
  var request = {
    request_id: params.request_id,
    token_id: params.token_id || "",
    source: params.source || "",
    description: params.description || "",
    requested_at: now
  }
  var next = requests.filter(function(r) { return r.request_id !== request.request_id })
  next.push(request)
  return trim(next)
}

function finish(requests, match, outcome, now) {
  var changed = false
  var next = requests.map(function(r) {
    if (!isWaiting(r) || !match(r)) return r
    changed = true
    var copy = {}
    for (var key in r) copy[key] = r[key]
    copy.outcome = outcome
    copy.completed_at = now
    return copy
  })
  return changed ? next : requests
}

// TOKEN_TOUCH_COMPLETED `{request_id, outcome}`. A request this list does
// not have started before this shell connected; there is nothing to end.
function completeRequest(requests, params, now) {
  if (!params || typeof params.request_id !== "number") return requests
  return finish(requests, function(r) { return r.request_id === params.request_id },
    params.outcome || "cancelled", now)
}

// TOKEN_REMOVED: the daemon stops watching an unplugged key without ending
// its request, so the prompt ends it.
function endForToken(requests, tokenId, now) {
  if (!tokenId) return requests
  return finish(requests, function(r) { return r.token_id === tokenId }, "removed", now)
}

// Waiting requests younger than STALE_MS, oldest first.
function waiting(requests, now) {
  return requests.filter(function(r) { return isWaiting(r) && now - r.requested_at < STALE_MS })
}

// The finished request still worth showing when none waits: the one that
// finished last, within its LINGER_MS.
function lingering(requests, now) {
  var best = null
  for (var i = 0; i < requests.length; i++) {
    var r = requests[i]
    if (isWaiting(r) || now - r.completed_at >= lingerMs(r.outcome)) continue
    if (!best || r.completed_at >= best.completed_at) best = r
  }
  return best
}

function lingerMs(outcome) {
  return LINGER_MS[outcome] || LINGER_MS.cancelled
}

// When the prompt next changes on its own (a request going stale, a
// finished one leaving), in ms from `now`; -1 for never.
function nextChangeIn(requests, now) {
  var soonest = -1
  for (var i = 0; i < requests.length; i++) {
    var r = requests[i]
    var at = isWaiting(r) ? r.requested_at + STALE_MS : r.completed_at + lingerMs(r.outcome)
    var wait = at - now
    if (wait > 0 && (soonest < 0 || wait < soonest)) soonest = wait
  }
  return soonest
}

// ------------------------------------------------------------------- text

function sourceLabel(source) {
  switch (source) {
  case "ssh": return "SSH"
  case "gpg": return "GnuPG"
  case "fido2": return "FIDO2 sign-in"
  case "pcsc": return "Smart card"
  default: return "Security key"
  }
}

// What is probably asking, for the line under the description.
function sourceHint(source) {
  switch (source) {
  case "ssh": return "An SSH login or git push is waiting for the key."
  case "gpg": return "A GnuPG signature, decryption, or SSH through gpg-agent is waiting for the key."
  case "fido2": return "A browser, sudo (pam_u2f) or another app is waiting for the key."
  default: return "An app is waiting for the key."
  }
}

// "YubiKey", "Nitrokey", …: the kind of the token a request names, for the
// title. Falls back to "security key".
function keyNoun(token) {
  switch (token && token.kind) {
  case "yubikey": return "YubiKey"
  case "solokey": return "SoloKey"
  case "nitrokey": return "Nitrokey"
  default: return "security key"
  }
}

// Title for the waiting requests: one key named, or several.
function waitingTitle(list, tokens) {
  if (!list || list.length === 0) return ""
  var first = findToken(tokens, list[0].token_id)
  for (var i = 1; i < list.length; i++)
    if (list[i].token_id !== list[0].token_id) return "Touch your security keys"
  return "Touch your " + keyNoun(first)
}

function outcomeTitle(outcome) {
  switch (outcome) {
  case "touched": return "Touch received"
  case "timed_out": return "Touch timed out"
  case "cancelled": return "Request cancelled"
  case "removed": return "Key removed"
  default: return ""
  }
}

function outcomeText(outcome) {
  switch (outcome) {
  case "timed_out": return "The key was not touched in time. Run the command again to retry."
  case "cancelled": return "The app stopped waiting for the key."
  case "removed": return "The key was unplugged while it waited for a touch."
  default: return ""
  }
}

// ThemeProvider.role name for the card border and icon.
function outcomeRole(outcome) {
  switch (outcome) {
  case "touched": return "success"
  case "timed_out": return "warning"
  case undefined: case null: case "": return "accent"
  default: return "muted"
  }
}

// "Waiting 4 s"
function elapsedText(request, now) {
  if (!request) return ""
  return "Waiting " + Math.max(0, Math.floor((now - request.requested_at) / 1000)) + " s"
}

if (typeof module !== "undefined") module.exports = {
  MAX_REQUESTS: MAX_REQUESTS, STALE_MS: STALE_MS, LINGER_MS: LINGER_MS,
  upsertToken: upsertToken, removeToken: removeToken, findToken: findToken,
  isWaiting: isWaiting, findRequest: findRequest, startRequest: startRequest,
  completeRequest: completeRequest, endForToken: endForToken, waiting: waiting,
  lingering: lingering, lingerMs: lingerMs, nextChangeIn: nextChangeIn,
  sourceLabel: sourceLabel, sourceHint: sourceHint, keyNoun: keyNoun, waitingTitle: waitingTitle,
  outcomeTitle: outcomeTitle, outcomeText: outcomeText, outcomeRole: outcomeRole, elapsedText: elapsedText
}
