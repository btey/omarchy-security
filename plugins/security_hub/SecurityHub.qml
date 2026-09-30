// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import qs.Commons
import "services"
import "components"
import "services/Hub.js" as Hub

// Main panel, summoned by the bar widget, by the daemon's notifications,
// or by a keybinding, through the service's IPC target:
//   omarchy-shell security-hub open network     (or toggle, or close)
//   omarchy-shell shell toggle security-hub '{"tab": "network"}'
//
// A themed card with the daemon connection and the tabbed hub (plan task
// 3.9): Overview, Threats, USB, Security keys, Network, Vaults and
// Hardening, in components/HubView.qml. The payload's `tab` picks one (a
// tab id or a module id, such as {"tab": "network"} from the bar widget);
// without one the hub opens where it was left. Left / Right (or h / l)
// and 1-7 switch tabs while no text field has the keyboard.
Item {
  id: root

  // Injected by the shell.
  property var shell: null
  property var manifest: null
  property var service: null

  readonly property string pluginId: manifest && manifest.id ? String(manifest.id) : "security-hub"
  readonly property var security: service
    || (shell && typeof shell.serviceFor === "function" ? shell.serviceFor(pluginId) : null)

  property bool opened: false
  // The tab shown, a Hub.TABS id.
  property alias tab: hubView.tab

  function open(payloadJson) {
    tab = Hub.tabFromPayload(payloadJson, tab)
    opened = true
    // No event says another client changed the rules, that `sudo ufw`
    // changed UFW's, or that a reloaded configuration changed the vaults
    // or the durations offered.
    if (security && security.ready) {
      security.loadRules()
      security.loadUfwRules()
      security.loadTemps()
      security.loadVaults()
    }
    // The window is created hidden, so focus set at construction lands
    // nowhere; take it again once the surface is mapped.
    Qt.callLater(function() { if (root.opened) keyCatcher.forceActiveFocus() })
  }

  function close() {
    opened = false
  }

  function dismiss() {
    if (shell && typeof shell.hide === "function") shell.hide(pluginId)
    else close()
  }

  PanelWindow {
    visible: root.opened
    anchors { top: true; right: true }
    margins { top: Style.gapsOut; right: Style.gapsOut }
    implicitWidth: card.implicitWidth
    implicitHeight: card.implicitHeight
    color: "transparent"
    exclusionMode: ExclusionMode.Ignore
    WlrLayershell.namespace: "omarchy-security-hub"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.OnDemand

    Rectangle {
      id: card
      anchors.fill: parent
      implicitWidth: Style.space(380)
      implicitHeight: content.implicitHeight + Style.space(32)
      color: ThemeProvider.background
      border.color: ThemeProvider.border.color
      border.width: ThemeProvider.border.width
      radius: ThemeProvider.border.radius

      Item {
        id: keyCatcher
        anchors.fill: parent
        focus: true
        Keys.onEscapePressed: root.dismiss()
        Keys.onPressed: function(event) {
          if (event.key === Qt.Key_Right || event.text === "l") hubView.step(1)
          else if (event.key === Qt.Key_Left || event.text === "h") hubView.step(-1)
          else if (event.text >= "1" && event.text <= String(Hub.TABS.length) && event.text.length === 1)
            root.tab = Hub.TABS[Number(event.text) - 1].id
          else return
          event.accepted = true
        }
      }

      ColumnLayout {
        id: content
        anchors { left: parent.left; right: parent.right; top: parent.top; margins: Style.space(16) }
        spacing: Style.space(10)

        Text {
          text: "Security Hub"
          color: ThemeProvider.text
          font.family: Style.font.family
          font.pixelSize: Style.font.subtitle
          font.bold: true
        }

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: !root.security ? "IPC service not loaded"
            : root.security.ready ? "Connected to omarchy-securityd " + root.security.daemonVersion
            : root.security.lastError || "Connecting to omarchy-securityd…"
          color: root.security && root.security.ready ? ThemeProvider.dimText : ThemeProvider.danger
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
        }

        Rectangle {
          Layout.fillWidth: true
          implicitHeight: 1
          color: ThemeProvider.separator
        }

        HubView {
          id: hubView
          Layout.fillWidth: true
          security: root.security
          shown: root.opened
        }
      }
    }
  }
}
