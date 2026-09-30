// SPDX-License-Identifier: MIT
//
// Headless end-to-end check, run by tools/qml-e2e.sh against
// tools/mock-securityd.py. Loads the plugin's QML in a private Quickshell
// instance, never opens a window, and exits 0 only when handshake,
// subscription, events, requests, and error responses all behaved.
import QtQuick
import Quickshell
import "hub"
import "hub/services"

ShellRoot {
  id: root

  property var passed: ({})
  readonly property var expected: ["ready", "event", "setPolicy", "notImplemented", "policyChanged", "theme"]

  function pass(step) {
    var next = Object.assign({}, passed)
    next[step] = true
    passed = next
    console.log("E2E ok " + step)
    for (var i = 0; i < expected.length; i++) if (!passed[expected[i]]) return
    Qt.exit(0)
  }

  function fail(reason) {
    console.log("E2E FAIL " + reason)
    Qt.exit(1)
  }

  SecurityIPC {
    id: ipc
    onReadyChanged: {
      if (!ready) return
      if (moduleState("usbguard") !== "active") root.fail("usbguard module state " + moduleState("usbguard"))
      else root.pass("ready")
    }
    onEventReceived: function(name, params) {
      if (name === "USB_DEVICE_PRESENTED" && !root.passed.event) {
        root.pass("event")
        ipc.request("USBGUARD_SET_POLICY", { device_id: params.device_id, target: "allow", permanent: false },
          function(err, result) {
            if (err || !result || result.rule !== "allow") root.fail("set policy " + JSON.stringify(err))
            else root.pass("setPolicy")
          })
        ipc.request("VAULT_PANIC", {}, function(err) {
          if (err && err.code === -32007) root.pass("notImplemented")
          else root.fail("expected NOT_IMPLEMENTED, got " + JSON.stringify(err))
        })
      } else if (name === "USB_DEVICE_POLICY_CHANGED") {
        root.pass("policyChanged")
      }
    }
  }

  // The singleton resolves through services/qmldir and reads the active
  // theme's colors.toml (or finds it missing and falls back).
  function checkTheme() {
    if (!ThemeProvider.paletteReady || root.passed.theme) return
    var colors = [ThemeProvider.danger, ThemeProvider.warning, ThemeProvider.success,
      ThemeProvider.background, ThemeProvider.border.color]
    for (var i = 0; i < colors.length; i++)
      if (colors[i] === undefined || colors[i] === null) return root.fail("theme colour " + i + " unset")
    if (ThemeProvider.moduleStateColor("unavailable") !== ThemeProvider.danger) return root.fail("module state colour")
    root.pass("theme")
  }

  Connections {
    target: ThemeProvider
    function onPaletteReadyChanged() { root.checkTheme() }
  }

  Component.onCompleted: checkTheme()

  // Instantiated to prove they load; neither is shown.
  SecurityHub { service: ipc }
  StatusBarIndicator {}

  Timer {
    interval: 15000
    running: true
    onTriggered: root.fail("timed out; passed " + JSON.stringify(root.passed))
  }
}
