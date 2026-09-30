// SPDX-License-Identifier: MIT
//
// Headless end-to-end check, run by tools/qml-e2e.sh against
// tools/mock-securityd.py. Loads the plugin's QML in a private Quickshell
// instance, never opens a window, and exits 0 only when handshake,
// subscription, events, requests, and error responses all behaved.
import QtQuick
import Quickshell
import Quickshell.Io
import "hub"
import "hub/services"

ShellRoot {
  id: root

  property var passed: ({})
  readonly property var expected: ["ready", "event", "setPolicy", "notImplemented", "policyChanged", "theme",
    "firewallMode", "badge", "seen"]

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

  // The bar widget, given a stand-in for the bar host so that it finds the
  // service the way it does in the shell. Its state follows the mock's
  // firewall mode ("ufw") and alert stream.
  StatusBarIndicator {
    id: indicator
    bar: QtObject {
      property var shell: QtObject { function serviceFor(id) { return ipc } }
      property color barForeground: "#cacccc"
      property color urgent: "#a55555"
      property string fontFamily: "monospace"
      property bool vertical: false
      property int barSize: 26
      property bool foregroundAnimationEnabled: false
      function showTooltip(target, text) {}
      function hideTooltip(target) {}
    }

    onStatusChanged: {
      if (!root.passed.firewallMode && ipc.firewallMode === "ufw") {
        if (status.role !== "normal" || status.tooltip.indexOf("Firewall: UFW") < 0)
          return root.fail("indicator for ufw mode " + JSON.stringify(status))
        root.pass("firewallMode")
      }
      if (!root.passed.badge && ipc.unseenAlertCount > 0) {
        if (status.badge !== String(Math.min(ipc.unseenAlertCount, 9)))
          return root.fail("badge " + JSON.stringify(status) + " for " + ipc.unseenAlertCount)
        root.pass("badge")
        // Outside this handler, as the hub does it when it opens.
        Qt.callLater(root.clearBadge)
      }
    }
  }

  function clearBadge() {
    ipc.markAlertsSeen()
    if (ipc.unseenAlertCount !== 0 || indicator.status.badge !== "")
      return root.fail("badge not cleared: " + ipc.unseenAlertCount)
    seenCheck.start()
  }

  // markAlertsSeen() also writes the time down for the next shell start.
  FileView {
    id: seenFile
    property bool checking: false
    path: Quickshell.env("XDG_STATE_HOME") + "/omarchy-security/shell-seen.json"
    printErrors: false
    onLoaded: {
      if (!checking) return
      var saved = JSON.parse(text()).alerts_seen_at
      if (saved === ipc.alertsSeenAt) root.pass("seen")
      else root.fail("saved seen time " + saved + " != " + ipc.alertsSeenAt)
    }
    onLoadFailed: if (checking) root.fail("seen time not saved")
  }

  Timer {
    id: seenCheck
    interval: 300
    onTriggered: { seenFile.checking = true; seenFile.reload() }
  }

  // Instantiated to prove it loads; never shown.
  SecurityHub { service: ipc }

  Timer {
    interval: 15000
    running: true
    onTriggered: root.fail("timed out; passed " + JSON.stringify(root.passed))
  }
}
