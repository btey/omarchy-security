// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import qs.Commons
import qs.Ui
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
// and 1-7 switch tabs while no text field has the keyboard. While the
// daemon is not reachable, components/BackendSetup.qml takes the tabs'
// place, with a way to install or start it (plan task 5.3).
Item {
  id: root

  // Injected by the shell.
  property var shell: null
  property var manifest: null
  property var service: null

  readonly property string pluginId: manifest && manifest.id ? String(manifest.id) : "security-hub"
  readonly property var security: service
    || (shell && typeof shell.serviceFor === "function" ? shell.serviceFor(pluginId) : null)

  // Clear of the bar, as Omarchy's notifications are: the shell exposes the
  // active bar's position, size and hidden state for this.
  readonly property var bar: shell ? shell.bar : null
  readonly property string barPosition: shell && shell.barConfig ? String(shell.barConfig.position || "top") : "top"
  readonly property int barSize: bar ? (bar.barHidden ? 0 : bar.barSize)
    : (barPosition === "left" || barPosition === "right" ? Style.bar.sizeVertical : Style.bar.sizeHorizontal)
  readonly property var panelMargins: Hub.panelMargins(barPosition, barSize, Style.gapsOut)

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
    margins { top: root.panelMargins.top; right: root.panelMargins.right }
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

        RowLayout {
          Layout.fillWidth: true

          Text {
            Layout.fillWidth: true
            text: "Security Hub"
            color: ThemeProvider.text
            font.family: Style.font.family
            font.pixelSize: Style.font.subtitle
            font.bold: true
          }

          // Esc closes it too, while the hub has the keyboard.
          Button {
            iconText: "\u{F0156}"  // nf-md-close
            tooltipText: "Close (Esc)"
            foreground: ThemeProvider.dimText
            accent: ThemeProvider.accent
            onClicked: root.dismiss()
          }
        }

        // Without a connection, BackendSetup below says why.
        Text {
          Layout.fillWidth: true
          visible: !root.security || root.security.ready
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: !root.security ? "IPC service not loaded"
            : "Connected to omarchy-securityd " + root.security.daemonVersion
          color: root.security ? ThemeProvider.dimText : ThemeProvider.danger
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
        }

        Rectangle {
          Layout.fillWidth: true
          implicitHeight: 1
          color: ThemeProvider.separator
        }

        // A newer plugin, found by the update check (services/Update.js).
        PluginUpdate {
          Layout.fillWidth: true
          security: root.security
        }

        // A plugin installed alone has no daemon to talk to: this offers
        // to install or start it, and says when the versions differ
        // (plan task 5.3).
        BackendSetup {
          id: backendSetup
          Layout.fillWidth: true
          visible: !!root.security && kind !== "ok"
          security: root.security
          pluginVersion: root.manifest && root.manifest.version ? String(root.manifest.version) : ""
          shown: root.opened
        }

        HubView {
          id: hubView
          Layout.fillWidth: true
          visible: !backendSetup.blocking
          security: root.security
          shown: root.opened
        }
      }
    }
  }
}
