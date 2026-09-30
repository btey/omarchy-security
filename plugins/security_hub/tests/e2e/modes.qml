// SPDX-License-Identifier: MIT
//
// The Network tab in each firewall mode but ufw (which shell.qml covers),
// run by tools/qml-e2e.sh once per mode against
// `tools/mock-securityd.py --mode $E2E_MODE`. Checks what the tab shows,
// then one path the mode has: switching back from standalone, MODE_CONFLICT
// for an inbound allow while both firewalls run and for a temporary
// decision with none, and a switch that fails while the helper is down.
import QtQuick
import Quickshell
import "hub/services"
import "hub/components"
import "hub/services/Network.js" as Network

ShellRoot {
  id: root

  readonly property string mode: Quickshell.env("E2E_MODE")
  readonly property var expected: ["shown", "path"]
  property var passed: ({})
  property bool started: false

  function pass(step) {
    var next = Object.assign({}, passed)
    next[step] = true
    passed = next
    console.log("E2E ok " + mode + " " + step)
    for (var i = 0; i < expected.length; i++) if (!passed[expected[i]]) return
    Qt.exit(0)
  }

  function fail(reason) {
    console.log("E2E FAIL " + mode + ": " + reason)
    Qt.exit(1)
  }

  SecurityIPC { id: ipc }

  NetworkSnitch {
    id: network
    security: ipc
  }

  Connections {
    target: ipc
    function onFirewallInfoChanged() { Qt.callLater(root.check) }
    function onUfwRulesChanged() { Qt.callLater(root.check) }
    function onFirewallAlertsChanged() { Qt.callLater(root.check) }
    function onFirewallModeChanged() { Qt.callLater(root.check) }
  }

  Connections {
    target: network.banner
    function onErrorChanged() { Qt.callLater(root.check) }
    function onDoneChanged() { Qt.callLater(root.check) }
  }

  Connections {
    target: network.alerts
    function onErrorsChanged() { Qt.callLater(root.check) }
  }

  function actions() {
    return JSON.stringify(network.banner.banner.actions.map(function(a) { return a.mode }))
  }

  function check() {
    if (!passed.shown) {
      if (!ipc.firewallInfo || !ipc.ufwRules || ipc.firewallMode !== mode) return
      var s = network.sections
      var want = {
        standalone: { actions: '["ufw"]', ufw: false, baseline: true, role: "success" },
        both: { actions: '["ufw","standalone"]', ufw: true, baseline: true, role: "warning" },
        none: { actions: '["ufw","standalone"]', ufw: false, baseline: false, role: "danger" },
        unknown: { actions: "[]", ufw: true, baseline: false, role: "muted" }
      }[mode]
      if (!want) return fail("no scenario")
      if (actions() !== want.actions || network.banner.banner.role !== want.role)
        return fail("banner " + JSON.stringify(network.banner.banner))
      if (network.ufwRules.visible !== want.ufw || network.hubRules.showBaseline !== want.baseline)
        return fail("sections " + JSON.stringify(s))
      pass("shown")
    }
    if (passed.path || started && mode === "both") return
    if (mode === "standalone") {
      if (!started) {
        started = true
        // Nothing to import on the way back, so no dry run.
        if (!network.banner.startSwitch("ufw") || network.banner.previewBusy) return fail("dialog")
        network.banner.confirm()
        if (!network.banner.confirm()) return fail("switch not sent")
      } else if (ipc.firewallMode === "ufw" && network.banner.done === "Switched to UFW.") {
        pass("path")
      }
    } else if (mode === "both") {
      started = true
      // The form refuses it first; the daemon refuses it too.
      ipc.addRule({ verdict: "allow", direction: "inbound", address: "192.168.1.0/24", port: 22, protocol: "tcp" },
        function(error) {
          if (!error || error.code !== -32009 || !/ufw is active/.test(Network.ruleErrorText(error)))
            return root.fail("inbound allow " + JSON.stringify(error))
          root.pass("path")
        })
    } else if (mode === "none") {
      var tcp = ipc.firewallAlerts.filter(function(a) { return a.protocol === "tcp" })[0]
      if (!tcp) return
      if (!started) {
        started = true
        if (!network.alerts.act(tcp.alert_id, "block")) return fail("block not sent")
      } else if (network.alerts.errors[tcp.alert_id]) {
        if (!/no firewall is active/.test(network.alerts.errors[tcp.alert_id]))
          return fail("block with no firewall: " + network.alerts.errors[tcp.alert_id])
        pass("path")
      }
    } else if (mode === "unknown") {
      if (!started) {
        started = true
        if (!network.banner.startSwitch("standalone")) return fail("dialog")
        network.banner.confirm()
        network.banner.confirm()
      } else if (network.banner.error !== "") {
        if (!/helper is not running/.test(network.banner.error) || network.banner.target !== "standalone")
          return fail("switch without the helper: " + network.banner.error)
        pass("path")
      }
    }
  }

  Timer {
    interval: 8000
    running: true
    onTriggered: root.fail("timed out; passed " + JSON.stringify(root.passed))
  }
}
