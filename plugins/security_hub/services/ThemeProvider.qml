pragma Singleton
// SPDX-License-Identifier: MIT
import QtQuick
import Quickshell.Io
import qs.Commons
import "Palette.js" as Palette

// The one place the plugin's views take colours and borders from (plan §3.1).
// Views import "services" (or "../services") and bind to ThemeProvider.*,
// never to hex values of their own. Spacing and typography have no theme
// logic of ours, so views keep using qs.Commons `Style` for those.
//
// Everything that qs.Commons already themes is passed through as a binding,
// so it follows `omarchy theme set`, the user's ~/.config/omarchy/shell.toml
// and Hyprland's rounding without any work here. The semantic colours are
// the exception: Color keeps only `urgent`, so warning and success are read
// from the theme's colors.toml (`yellow`/`color3`, `green`/`color2`).
//
// A theme or the user can pin any of the three in shell.toml:
//
//   [security-hub]
//   danger = "#f7768e"      # or a role: accent, urgent, foreground, muted
//   warning = "#e0af68"
//   success = "#9ece6a"
QtObject {
  id: root

  // ------------------------------------------------------------ surfaces
  //
  // Panels, modals and OSDs use the popup surface, which carries the
  // theme's `popups.background-alpha` (transparency) and border.
  readonly property color background: Color.popups.background
  readonly property color foreground: Color.popups.text
  readonly property color text: foreground
  readonly property color dimText: Util.alpha(foreground, 0.62)
  readonly property color separator: Util.alpha(foreground, 0.12)

  readonly property color accent: Color.accent
  readonly property color muted: Color.muted

  // Bar widgets draw on the bar instead. Its foreground depends on the bar
  // instance (it flips when the bar is made transparent), so pass the
  // widget's `bar`.
  function barForeground(bar) { return bar && bar.barForeground ? bar.barForeground : Color.bar.text }
  // The dimmed form first-party bar widgets use for an inactive state.
  function barDimForeground(bar) { return Qt.darker(barForeground(bar), 1.55) }
  // Bar colour for a widget state (Indicator.modeRole): "normal", "dim", or
  // a semantic role.
  function barRoleColor(bar, name) {
    if (name === "normal") return barForeground(bar)
    if (name === "dim") return barDimForeground(bar)
    return role(name)
  }

  // Text on an accent fill (badges): the theme's opaque background.
  readonly property color onAccent: Color.background

  // ------------------------------------------------------------ semantic
  //
  // danger: blocked process, rejected USB device, failed check.
  // warning: degraded module, posture warning, pending decision.
  // success: hardening OK, active module, approved device.
  readonly property color danger: semanticColor("danger", themePalette.danger, Color.urgent)
  readonly property color warning: semanticColor("warning", themePalette.warning, fallbackWarning)
  readonly property color success: semanticColor("success", themePalette.success, fallbackSuccess)

  // Used only when colors.toml has no yellow/green: muted like Color's own
  // built-in defaults, so they do not shout on a monochrome setup.
  readonly property color fallbackWarning: "#a58f55"
  readonly property color fallbackSuccess: "#6e9a5e"

  // ------------------------------------------------------------ borders
  readonly property QtObject border: QtObject {
    readonly property int radius: Style.cornerRadius
    readonly property color color: Color.popups.border
    readonly property int width: Style.normalBorderWidth > 0 ? Style.normalBorderWidth : 1
  }

  // ------------------------------------------------------------ helpers

  // Colour for a semantic role name, as returned by Palette.moduleStateRole
  // and Palette.postureRole.
  function role(name) {
    switch (name) {
    case "danger": return danger
    case "warning": return warning
    case "success": return success
    case "accent": return accent
    case "foreground": case "text": return foreground
    default: return muted
    }
  }

  function moduleStateColor(state) { return role(Palette.moduleStateRole(state)) }
  function postureColor(status) { return role(Palette.postureRole(status)) }

  // Translucent tint of `c` for row and badge backgrounds.
  function tint(c, opacity) { return Util.alpha(c, opacity === undefined ? 0.16 : opacity) }

  // ------------------------------------------------------------ loading

  // {danger, warning, success} as hex strings, "" where the theme has none.
  property var themePalette: ({ danger: "", warning: "", success: "" })
  // True once colors.toml has been read or found missing.
  property bool paletteReady: false

  function semanticColor(name, themeValue, fallback) {
    var pinned = Color.shellValues["security-hub." + name]
    if (typeof pinned === "string" && pinned.length > 0) return Color.flatColor(pinned, fallback)
    return themeValue ? themeValue : fallback
  }

  function applyColors(raw) {
    themePalette = Palette.semantic(Palette.parseColors(raw))
    paletteReady = true
  }

  property FileView colorsFile: FileView {
    path: Color.currentThemePath + "/colors.toml"
    watchChanges: false
    printErrors: false
    onLoaded: root.applyColors(text())
    onLoadFailed: root.applyColors("")
  }

  // `omarchy theme set` swaps the theme directory and then pushes the new
  // files to the shell over IPC rather than touching them in place, so a
  // file watch would miss it. Color.loadShell reassigns `shellValues` on
  // every theme apply, after the new colors.toml is on disk: re-read then.
  property Connections themeWatch: Connections {
    target: Color
    function onShellValuesChanged() { root.colorsFile.reload() }
  }
}
