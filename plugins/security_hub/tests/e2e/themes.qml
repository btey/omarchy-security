// SPDX-License-Identifier: MIT
//
// Live theme switching (plan task 4.2), run by tools/qml-e2e.sh under a
// throwaway HOME against tools/mock-securityd.py. Builds every view of the
// plugin (the tabbed hub and its panel, the bar widget, the threat card and
// the two prompts) without mapping a window, then applies each theme in
// $E2E_THEMES the way `omarchy theme set` does: tools/theme-apply.sh swaps
// the theme directory and pushes colors.toml and shell.toml to this
// instance with `shell applyTheme`. After each one it checks that
//
//   * ThemeProvider has the theme's colours, as Omarchy's own resolver
//     (omarchy-theme-color) reads them, or its fallbacks where the theme
//     has none;
//   * every colour on every item is one the theme explains: a colour of
//     the palette, of Color's surfaces or of ThemeProvider, at any alpha,
//     or one of these darkened or lightened the way qs.Ui does it;
//
// and, once all have been applied, that no item kept the same colour
// through every theme (it would be a colour of its own), that applying the
// first theme again gives every item its first colours back, and that a
// `[security-hub]` pin in ~/.config/omarchy/shell.toml takes effect live
// and survives a theme switch.
import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import "hub"
import "hub/services"
import "hub/components"
import "hub/services/Network.js" as Network

ShellRoot {
  id: root

  readonly property string home: Quickshell.env("HOME")
  readonly property string applyScript: Quickshell.env("E2E_THEME_APPLY")
  readonly property var themes: String(Quickshell.env("E2E_THEMES") || "").split(":").filter(function(t) { return t !== "" })
  readonly property string userShell: home + "/.config/omarchy/shell.toml"
  readonly property string pinned: "#123456"
  // Qt.darker / Qt.lighter factors qs.Ui derives colours with.
  readonly property var factors: [1.2, 1.25, 1.4, 1.5, 1.55, 1.6, 2.0]
  // qs.Ui's own outlines for laying out bar icons, hidden unless its
  // debugBounds / debugOpticalBounds is set: not the plugin's, not shown.
  readonly property var uiDebug: ({ "#4488ff": true, "#44ff88": true, "#ff4455": true })

  function uiDebugOutline(what, rgb) {
    return !!uiDebug[rgb] && /\/(BarIconButton|OpticalGlyph)_QMLTYPE_\d+( |\/QQuickItem)/.test(what)
  }

  // Steps, in order: {name, theme (a directory, or "" for the one the
  // shell started with), pin (the user's shell.toml, or undefined)}.
  readonly property var steps: {
    var out = [{ name: "startup", theme: "" }]
    for (var i = 0; i < themes.length; i++) out.push({ name: baseName(themes[i]), theme: themes[i], cycle: true })
    out.push({ name: "again:" + baseName(themes[0]), theme: themes[0], again: true })
    out.push({ name: "pin", pin: "[security-hub]\ndanger = \"" + pinned + "\"\nsuccess = \"accent\"\n" })
    out.push({ name: "pin:" + baseName(themes[1]), theme: themes[1], pinnedStep: true })
    out.push({ name: "unpin", pin: "" })
    return out
  }

  property int stepIndex: -1
  readonly property var step: stepIndex >= 0 && stepIndex < steps.length ? steps[stepIndex] : null
  // The palette omarchy-theme-color printed for the step's theme.
  property var oracle: ({})
  property bool scriptDone: false
  property bool applied: false
  property real appliedAt: 0
  property real lastChangeAt: 0
  property real slowest: 0
  property string slowestName: ""

  // Per item, per colour property: the rgbs it had in the cycle, and its
  // colour in the first theme, for the second visit.
  property var history: new Map()

  function baseName(path) { return String(path).replace(/\/+$/, "").split("/").pop() }

  function fail(reason) {
    console.log("E2E FAIL theme " + (step ? step.name : "") + ": " + reason)
    Qt.exit(1)
  }

  // ------------------------------------------------------------ colours

  function isColor(v) { return v !== null && typeof v === "object" && typeof v.r === "number" && typeof v.hslHue === "number" }
  function hex2(n) { var s = Math.round(n * 255).toString(16); return s.length < 2 ? "0" + s : s }
  function rgbOf(c) { return "#" + hex2(c.r) + hex2(c.g) + hex2(c.b) }
  function rgbaOf(c) { return rgbOf(c) + hex2(c.a) }
  function rgbOfString(s) {
    s = String(s).toLowerCase()
    if (/^#[0-9a-f]{3}$/.test(s)) return "#" + s[1] + s[1] + s[2] + s[2] + s[3] + s[3]
    return /^#[0-9a-f]{6}/.test(s) ? s.slice(0, 7) : ""
  }

  // Every colour the current theme explains, as rgb.
  function explained() {
    var base = new Set()
    function add(v) {
      if (isColor(v)) base.add(rgbOf(v))
      else if (typeof v === "string")
        v.split(/\s+/).forEach(function(part) { var h = rgbOfString(part); if (h) base.add(h) })
    }
    for (var k in oracle) add(oracle[k])
    for (var s in Color.shellValues) add(Color.shellValues[s])
    for (var c in Color) {
      var v = Color[c]
      if (isColor(v)) add(v)
      else if (v && typeof v === "object" && !Array.isArray(v) && c !== "shellValues" && c !== "themeShellValues"
          && c !== "userShellValues")
        for (var sub in v) add(v[sub])
    }
    ["background", "foreground", "text", "dimText", "separator", "accent", "muted", "accentText",
     "danger", "warning", "success"].forEach(function(p) { add(ThemeProvider[p]) })
    add(ThemeProvider.border.color)
    add(ThemeProvider.barForeground(bar))
    add(ThemeProvider.barDimForeground(bar))
    var out = new Set(base)
    base.forEach(function(h) {
      for (var i = 0; i < factors.length; i++) {
        out.add(rgbOf(Qt.darker(h, factors[i])))
        out.add(rgbOf(Qt.lighter(h, factors[i])))
      }
    })
    return out
  }

  // [{key, what, colour}] for every colour on every item under the views.
  function collect() {
    var out = []
    var seen = new Set()
    var ids = new Map()
    function visit(o, path) {
      if (!o || typeof o !== "object" || seen.has(o)) return
      seen.add(o)
      if (!ids.has(o)) ids.set(o, ids.size)
      var name = String(o).split("(")[0]
      if (isColor(o.color)) out.push({ key: o, prop: "color", what: path + " " + name + ".color", colour: o.color })
      // A Rectangle's pen is black and 1 px until set, and drawn only once
      // set, so a border left at that is not one.
      if (o.border && isColor(o.border.color) && o.border.width > 0
          && !(o.border.width === 1 && rgbaOf(o.border.color) === "#000000ff"))
        out.push({ key: o.border, prop: "border.color", what: path + " " + name + ".border.color", colour: o.border.color })
      if (isColor(o.placeholderTextColor))
        out.push({ key: o, prop: "placeholder", what: path + " " + name + ".placeholderTextColor", colour: o.placeholderTextColor })
      var kids = []
      if (o.contentItem) kids.push(o.contentItem)
      if (o.item && typeof o.item === "object") kids.push(o.item)
      var lists = [o.children, o.data]
      for (var l = 0; l < lists.length; l++)
        if (lists[l]) for (var i = 0; i < lists[l].length; i++) kids.push(lists[l][i])
      for (var j = 0; j < kids.length; j++) visit(kids[j], path + "/" + name)
    }
    var views = [hubView, hub, indicator, threatOsd, touchPrompt, connectionPrompt]
    for (var v = 0; v < views.length; v++) visit(views[v], "")
    return out
  }

  // ------------------------------------------------------------ checks

  function expectedFor(key, fallback) {
    var v = oracle[key]
    return v ? rgbOfString(v) : rgbOf(fallback)
  }

  // True once ThemeProvider holds the step's colours; the semantic ones
  // arrive a moment after the IPC call, when colors.toml is read again.
  function providerSettled() {
    var danger = step.pinnedStep || (step.pin && step.pin !== "") ? pinned : expectedFor("red", ThemeProvider.fallbackDanger)
    var success = step.pinnedStep || (step.pin && step.pin !== "") ? rgbOf(Color.accent) : expectedFor("green", ThemeProvider.fallbackSuccess)
    return rgbOf(ThemeProvider.danger) === danger
      && rgbOf(ThemeProvider.warning) === expectedFor("yellow", ThemeProvider.fallbackWarning)
      && rgbOf(ThemeProvider.success) === success
  }

  function checkProvider() {
    if (oracle.background && rgbOf(Color.background) !== rgbOfString(oracle.background))
      return "Color.background " + rgbOf(Color.background) + ", theme " + oracle.background
    if (oracle.accent && rgbOf(Color.accent) !== rgbOfString(oracle.accent))
      return "Color.accent " + rgbOf(Color.accent) + ", theme " + oracle.accent
    var urgent = [oracle.red, oracle.color1].filter(Boolean).map(rgbOfString)
    if (urgent.length && urgent.indexOf(rgbOf(Color.urgent)) < 0)
      return "Color.urgent " + rgbOf(Color.urgent) + ", theme " + JSON.stringify(urgent)
    var same = [
      ["background", ThemeProvider.background, Color.popups.background],
      ["foreground", ThemeProvider.foreground, Color.popups.text],
      ["accent", ThemeProvider.accent, Color.accent],
      ["muted", ThemeProvider.muted, Color.muted],
      ["border.color", ThemeProvider.border.color, Color.popups.border],
      ["accentText", ThemeProvider.accentText, Color.background],
      ["barForeground", ThemeProvider.barForeground(bar), Color.bar.text]
    ]
    for (var i = 0; i < same.length; i++)
      if (rgbaOf(same[i][1]) !== rgbaOf(same[i][2]))
        return "ThemeProvider." + same[i][0] + " " + rgbaOf(same[i][1]) + ", Color " + rgbaOf(same[i][2])
    if (ThemeProvider.border.radius !== Style.cornerRadius) return "border.radius " + ThemeProvider.border.radius
    if (!providerSettled())
      return "semantic colours " + JSON.stringify([rgbOf(ThemeProvider.danger), rgbOf(ThemeProvider.warning),
        rgbOf(ThemeProvider.success)]) + " for " + JSON.stringify([oracle.red, oracle.yellow, oracle.green])
    return ""
  }

  function checkItems() {
    var items = collect()
    if (items.length < 300) return "only " + items.length + " coloured items found"
    var ok = explained()
    var odd = []
    for (var i = 0; i < items.length; i++) {
      var it = items[i]
      if (it.colour.a === 0) continue
      var rgb = rgbOf(it.colour)
      if (uiDebugOutline(it.what, rgb)) continue
      if (!ok.has(rgb)) odd.push(it.what + " " + rgbaOf(it.colour))
      var perProp = history.get(it.key) || {}
      if (!perProp[it.prop]) perProp[it.prop] = { what: it.what, rgbs: new Set(), visits: 0, first: "" }
      var h = perProp[it.prop]
      if (step.cycle) { h.rgbs.add(rgb); h.visits++ }
      if (step.cycle && step.theme === themes[0]) h.first = rgbaOf(it.colour)
      if (step.again && h.first !== "" && h.first !== rgbaOf(it.colour))
        odd.push(it.what + " back in " + baseName(themes[0]) + " is " + rgbaOf(it.colour) + ", first " + h.first)
      history.set(it.key, perProp)
    }
    if (odd.length) return odd.length + " colours the theme does not explain: " + odd.slice(0, 8).join("; ")
    console.log("E2E ok theme " + step.name + ": " + items.length + " colours")
    return ""
  }

  // Items that kept one colour through every theme.
  function checkConstant() {
    var stuck = []
    history.forEach(function(perProp) {
      for (var p in perProp) {
        var h = perProp[p]
        if (h.visits >= themes.length && h.rgbs.size === 1) stuck.push(h.what + " " + Array.from(h.rgbs)[0])
      }
    })
    return stuck.length ? stuck.length + " colours never changed: " + stuck.slice(0, 8).join("; ") : ""
  }

  // ------------------------------------------------------------ driving

  function next() {
    stepIndex++
    if (stepIndex >= steps.length) {
      var stuck = checkConstant()
      if (stuck) return fail(stuck)
      console.log("E2E ok themes: " + themes.length + " applied live; the semantic colours followed within "
        + Math.round(slowest) + " ms (" + slowestName + ")")
      return Qt.exit(0)
    }
    scriptDone = false
    applied = false
    stepTimeout.restart()
    if (step.pin !== undefined) {
      applied = true
      appliedAt = Date.now()
      pinWriter.command = ["sh", "-c", 'mkdir -p "${1%/*}" && printf "%s" "$2" > "$1"', "sh", userShell, step.pin]
      pinWriter.running = true
      return
    }
    applier.command = step.theme === ""
      ? ["omarchy-theme-color", "--file", Color.currentThemePath + "/colors.toml", "--all"]
      : [applyScript, step.theme, Quickshell.shellDir]
    applier.running = true
  }

  // Runs the step's checks once its theme is in and has settled.
  function settle() {
    if (!step || !scriptDone || (step.theme !== "" && !applied) || itemsTimer.running || !providerSettled()) return
    // Colours bound to Color change within the IPC call; the semantic
    // ones when colors.toml (or the user's shell.toml) has been read.
    if (step.theme !== "") {
      var ms = Math.max(0, lastChangeAt - appliedAt)
      if (ms > slowest) { slowest = ms; slowestName = step.name }
    }
    var error = checkProvider()
    if (error) return fail(error)
    itemsTimer.restart()
  }

  function parseOracle(text) {
    var out = {}
    String(text).split("\n").forEach(function(line) {
      var kv = line.split("\t")
      if (kv.length === 2 && kv[1] !== "") out[kv[0]] = kv[1]
    })
    return out
  }

  // What omarchy-theme-set sends; the same body as the shell's own
  // `shell` target in $OMARCHY_PATH/shell/shell.qml.
  IpcHandler {
    target: "shell"

    function applyTheme(colorsB64: string, shellB64: string): string {
      var colorsRaw = ""
      var shellRaw = ""
      try { colorsRaw = Qt.atob(String(colorsB64 || "")) } catch (e) { colorsRaw = "" }
      try { shellRaw = Qt.atob(String(shellB64 || "")) } catch (e2) { shellRaw = "" }
      root.appliedAt = Date.now()
      Color.loadColors(colorsRaw)
      Color.loadShell(shellRaw)
      Style.scheduleRefresh()
      root.applied = true
      Qt.callLater(root.settle)
      return "ok"
    }
  }

  Process {
    id: applier
    stdout: StdioCollector { id: oracleOut }
    stderr: StdioCollector { id: applierErr }
    onExited: function(code) {
      if (code !== 0) return root.fail("theme-apply.sh exited " + code + ": " + applierErr.text)
      root.oracle = root.parseOracle(oracleOut.text)
      if (!root.oracle.background) return root.fail("no palette from omarchy-theme-color")
      root.scriptDone = true
      Qt.callLater(root.settle)
    }
  }

  Process {
    id: pinWriter
    onExited: function(code) {
      if (code !== 0) return root.fail("could not write " + root.userShell)
      root.scriptDone = true
      Qt.callLater(root.settle)
    }
  }

  Connections {
    target: ThemeProvider
    function onThemePaletteChanged() { root.lastChangeAt = Date.now(); Qt.callLater(root.settle) }
    function onDangerChanged() { root.lastChangeAt = Date.now(); Qt.callLater(root.settle) }
    function onSuccessChanged() { root.lastChangeAt = Date.now(); Qt.callLater(root.settle) }
  }

  // Items fade to a new colour (qs.Ui Button over 120 ms, the longest
  // 160 ms), so they are read once that is over.
  Timer {
    id: itemsTimer
    interval: 400
    onTriggered: {
      var error = root.checkProvider() || root.checkItems()
      if (error) return root.fail(error)
      root.next()
    }
  }

  Timer {
    id: stepTimeout
    interval: 5000
    onTriggered: root.fail("did not settle: " + (root.checkProvider() || "scriptDone " + root.scriptDone
      + ", applied " + root.applied))
  }

  // Starts once the views hold the mock's devices, rules and alerts, so
  // their rows are checked too, and once its scripted touches and held
  // connections have played out and their cards are gone (about 9 s): an
  // item that changes state between two visits of a theme would fail the
  // second.
  readonly property bool mockQuiet: ipc.ready && ThemeProvider.paletteReady && ipc.firewallAlerts.length > 0
    && ipc.connectionPrompts.length >= 2 && !ipc.connectionPrompts.some(Network.isPending)
    && !connectionPrompt.shown && !touchPrompt.shown

  Timer {
    running: root.mockQuiet && root.stepIndex < 0
    interval: 500
    onTriggered: {
      if (root.themes.length < 2 || !root.applyScript) return root.fail("E2E_THEMES and E2E_THEME_APPLY not set")
      root.next()
    }
  }

  Timer {
    interval: 120000
    running: true
    onTriggered: root.fail("timed out")
  }

  // ------------------------------------------------------------ views

  SecurityIPC { id: ipc }

  // The bar host's stand-in, with the bar's own themed foreground.
  QtObject {
    id: bar
    property var shell: QtObject { function serviceFor(id) { return ipc } }
    property color barForeground: Color.bar.text
    property color urgent: Color.urgent
    property string fontFamily: Style.font.family
    property bool vertical: false
    property int barSize: 26
    property bool foregroundAnimationEnabled: false
    function showTooltip(target, text) {}
    function hideTooltip(target) {}
  }

  StatusBarIndicator { id: indicator; bar: bar }
  HubView { id: hubView; security: ipc; shown: false }
  SecurityHub { id: hub; service: ipc }
  ThreatAlertOSD { id: threatOsd; security: ipc; showWindow: false }
  YubiKeyPrompt { id: touchPrompt; security: ipc; showWindow: false }
  ConnectionPrompt { id: connectionPrompt; security: ipc; showWindow: false }
}
