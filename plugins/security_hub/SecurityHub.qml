// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import qs.Commons
import qs.Ui
import "services"
import "services/Protocol.js" as Protocol

// Main panel, summoned by the bar widget or by
//   omarchy-shell shell toggle security-hub '{}'
//
// Phase 1 template: a themed card that shows the daemon connection and the
// state of each module. The module views (USBGuard, threat OSD, tokens,
// firewall, hardening) replace the module list in Phase 3.
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
  // The tab a caller asked for (`{"tab": "network"}` from the bar widget).
  // Kept for the tabbed hub (3.9); the Phase 1 card has one view.
  property string tab: "overview"

  function open(payloadJson) {
    var payload = {}
    try { payload = JSON.parse(payloadJson || "{}") || {} } catch (e) {}
    if (typeof payload.tab === "string" && payload.tab !== "") tab = payload.tab
    opened = true
    // Opening the hub is how the user sees the alerts behind the bar badge.
    // Once 3.10 adds the alert list, only the Network tab should do this.
    if (security && typeof security.markAlertsSeen === "function") security.markAlertsSeen()
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
      implicitWidth: Style.space(340)
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

        Repeater {
          model: Protocol.MODULES

          RowLayout {
            required property var modelData
            readonly property string moduleStatus: root.security ? root.security.moduleState(modelData.id) : ""

            Layout.fillWidth: true
            spacing: Style.space(8)

            Rectangle {
              implicitWidth: Style.space(8)
              implicitHeight: Style.space(8)
              radius: width / 2
              color: ThemeProvider.moduleStateColor(parent.moduleStatus)
            }

            Text {
              Layout.fillWidth: true
              text: modelData.label
              color: ThemeProvider.text
              font.family: Style.font.family
              font.pixelSize: Style.font.body
            }

            Text {
              text: parent.moduleStatus === "" ? "—" : Protocol.stateLabel(parent.moduleStatus)
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }
        }
      }
    }
  }
}
