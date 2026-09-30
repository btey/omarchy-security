// SPDX-License-Identifier: MIT
//
// Reads the semantic colours the Security Hub needs out of an Omarchy
// theme's colors.toml. qs.Commons `Color` keeps only foreground, background,
// accent, muted and urgent, so the warning and success colours come from
// here. Kept free of QML so it can be tested with plain node.
.pragma library

// `key = "#rgb"`, `"#rrggbb"` or `"#rrggbbaa"`, quoted or not, with an
// optional trailing comment. Keys are lowercased; colours are returned as
// written.
function parseColors(raw) {
  var colors = {}
  var lines = String(raw || "").split("\n")
  for (var i = 0; i < lines.length; i++) {
    var match = lines[i].match(/^\s*([A-Za-z0-9_-]+)\s*=\s*["']?(#(?:[0-9A-Fa-f]{8}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{3}))["']?\s*(#.*)?$/)
    if (match) colors[match[1].toLowerCase()] = match[2]
  }
  return colors
}

// Named keys first, then the ANSI slots older themes use (the same
// fallback qs.Commons applies to `urgent`).
var SEMANTIC_KEYS = {
  danger: ["red", "color1"],
  warning: ["yellow", "color3"],
  success: ["green", "color2"]
}

// {danger, warning, success}: each the theme's colour, or "" when the theme
// defines none.
function semantic(colors) {
  var out = {}
  for (var role in SEMANTIC_KEYS) {
    var keys = SEMANTIC_KEYS[role]
    out[role] = ""
    for (var i = 0; i < keys.length; i++) {
      if (colors && colors[keys[i]]) { out[role] = colors[keys[i]]; break }
    }
  }
  return out
}

// Colour role for a module state (`ModuleStatus.state`, docs/ipc-protocol.md §4.1).
function moduleStateRole(state) {
  switch (state) {
  case "active": return "success"
  case "degraded": return "warning"
  case "unavailable": return "danger"
  default: return "muted"
  }
}

// Colour role for a posture check status or overall result (§4.8).
function postureRole(status) {
  switch (status) {
  case "pass": return "success"
  case "warn": return "warning"
  case "fail": return "danger"
  default: return "muted"
  }
}

if (typeof module !== "undefined") module.exports = {
  SEMANTIC_KEYS: SEMANTIC_KEYS, parseColors: parseColors, semantic: semantic,
  moduleStateRole: moduleStateRole, postureRole: postureRole
}
