// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"
import "../services/Hub.js" as Hub
import "../services/Network.js" as Network
import "../services/Posture.js" as Posture

// The tabbed hub (plan task 3.9, §5.11): a row of tabs and the view of the
// one selected. SecurityHub.qml puts this in its window; the e2e test
// drives it without one.
//
// Every view stays loaded while hidden, so a half-typed rule or sandbox
// form, or a Panic waiting for its second click, is still there when the
// user comes back to its tab. A tab with something waiting (an open
// threat, a blocked USB device, a key waiting for a touch, a held
// connection or new blocked traffic, a failed or warning audit) shows a
// count or a dot.
//
// The bar badge counts blocked traffic the user has not seen; it is seen
// once the Network tab shows it, so that tab clears it while the hub is
// `shown`, and keeps it clear as new alerts arrive.
Item {
  id: root

  property var security: null
  property string tab: "overview"
  // Whether the user can see the hub: its window is open.
  property bool shown: true

  readonly property bool ready: !!security && security.ready
  // For the held connections, which expire on their own.
  property real now: Date.now()
  readonly property var attention: ready ? Hub.attention({
    threatAlerts: security.threatAlerts,
    usbDevices: security.usbDevices,
    touchRequests: security.touchRequests,
    heldConnections: Network.pendingPrompts(security.connectionPrompts, now).length,
    unseenAlerts: security.unseenAlertCount,
    posture: security.posture ? Posture.overall(security.posture) : ""
  }) : ({})

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  // Shows `name` (a tab id or alias). Returns false for a name that is
  // not a tab.
  function show(name) {
    var next = Hub.tabFor(name)
    if (next === "") return false
    tab = next
    return true
  }

  function step(delta) { tab = Hub.neighbour(tab, delta) }

  onTabChanged: sections.contentY = 0

  readonly property bool alertsInView: shown && ready && tab === "network"
  onAlertsInViewChanged: if (alertsInView) security.markAlertsSeen()

  Connections {
    target: root.security
    enabled: root.alertsInView
    function onFirewallAlertsChanged() { root.security.markAlertsSeen() }
  }

  Timer {
    interval: 1000
    repeat: true
    running: root.visible && root.ready && root.security.connectionPrompts.length > 0
    onTriggered: root.now = Date.now()
  }

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(10)

    RowLayout {
      Layout.fillWidth: true
      spacing: Style.space(2)

      Repeater {
        model: Hub.TABS

        Item {
          id: tabItem
          required property var modelData
          readonly property var mark: root.attention[modelData.id] || null

          Layout.fillWidth: true
          implicitWidth: tabButton.implicitWidth
          implicitHeight: tabButton.implicitHeight

          Button {
            id: tabButton
            anchors.fill: parent
            iconText: tabItem.modelData.icon
            tooltipText: tabItem.modelData.label
            selected: root.tab === tabItem.modelData.id
            bordered: root.tab === tabItem.modelData.id
            foreground: ThemeProvider.foreground
            accent: ThemeProvider.accent
            onClicked: root.tab = tabItem.modelData.id
          }

          // The count, or a dot, at the icon's top right.
          Rectangle {
            visible: !!tabItem.mark
            readonly property string count: tabItem.mark ? Hub.countText(tabItem.mark.count) : ""
            anchors { top: parent.top; right: parent.right; topMargin: Style.space(1); rightMargin: Style.space(2) }
            width: count === "" ? Style.space(7) : Math.max(height, badgeText.implicitWidth + Style.space(6))
            height: count === "" ? Style.space(7) : badgeText.implicitHeight + Style.space(1)
            radius: height / 2
            color: tabItem.mark ? ThemeProvider.role(tabItem.mark.role) : "transparent"

            Text {
              id: badgeText
              anchors.centerIn: parent
              visible: parent.count !== ""
              textFormat: Text.PlainText
              text: parent.count
              color: ThemeProvider.background
              font.family: Style.font.family
              font.pixelSize: Style.font.caption * 0.85
              font.bold: true
            }
          }
        }
      }
    }

    // A dock can bring a dozen devices, and rules pile up; scroll rather
    // than grow past the screen.
    Flickable {
      id: sections
      Layout.fillWidth: true
      implicitHeight: Math.min(sectionColumn.implicitHeight, Style.space(560))
      contentHeight: sectionColumn.implicitHeight
      clip: true
      boundsBehavior: Flickable.StopAtBounds

      ColumnLayout {
        id: sectionColumn
        width: sections.width
        spacing: Style.space(14)

        Overview {
          id: overview
          Layout.fillWidth: true
          visible: root.tab === "overview"
          security: root.security
          onOpenTab: function(tab) { root.show(tab) }
        }

        ThreatList {
          Layout.fillWidth: true
          visible: root.tab === "threats"
          security: root.security
        }

        PanelSeparator {
          Layout.fillWidth: true
          visible: root.tab === "threats"
          foreground: ThemeProvider.foreground
        }

        // Opening an untrusted file is the other half of dealing with
        // untrusted code.
        SandboxLauncher {
          Layout.fillWidth: true
          visible: root.tab === "threats"
          security: root.security
        }

        USBGuardPanel {
          Layout.fillWidth: true
          visible: root.tab === "usb"
          security: root.security
        }

        TokenPanel {
          Layout.fillWidth: true
          visible: root.tab === "tokens"
          security: root.security
        }

        NetworkSnitch {
          Layout.fillWidth: true
          visible: root.tab === "network"
          security: root.security
        }

        VaultPanel {
          Layout.fillWidth: true
          visible: root.tab === "vaults"
          security: root.security
        }

        HardeningSem {
          Layout.fillWidth: true
          visible: root.tab === "hardening"
          security: root.security
        }
      }
    }
  }
}
