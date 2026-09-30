// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"
import "../services/Protocol.js" as Protocol
import "../services/Hub.js" as Hub
import "../services/Threat.js" as Threat

// The hub's Overview tab (plan task 3.9, §5.11): the state of each daemon
// module, and the latest alerts of this session, threat alerts and
// blocked traffic together. Every row opens the tab it is about.
Item {
  id: root

  property var security: null

  readonly property bool ready: !!security && security.ready
  readonly property var entries: ready ? Hub.history(security.threatAlerts, security.firewallAlerts, 8) : []
  readonly property string modulesSummary: ready ? Hub.modulesSummary(security.modules) : ""

  // For "N min ago".
  property real now: Date.now()

  signal openTab(string tab)

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  Timer {
    interval: 30000
    repeat: true
    running: root.visible
    onTriggered: root.now = Date.now()
  }

  onEntriesChanged: now = Date.now()

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(8)

    RowLayout {
      Layout.fillWidth: true

      PanelSectionHeader {
        Layout.fillWidth: true
        text: "Modules"
        foreground: ThemeProvider.foreground
      }

      Text {
        visible: text !== ""
        textFormat: Text.PlainText
        text: root.modulesSummary
        color: ThemeProvider.dimText
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }
    }

    Repeater {
      model: Protocol.MODULES

      Item {
        id: moduleRow
        required property var modelData
        readonly property string moduleStatus: root.security ? root.security.moduleState(modelData.id) : ""
        readonly property string tab: Hub.tabFor(modelData.id)

        Layout.fillWidth: true
        implicitHeight: moduleLine.implicitHeight + Style.space(4)

        Rectangle {
          anchors.fill: parent
          radius: Style.cornerRadius
          color: moduleHover.hovered ? ThemeProvider.tint(ThemeProvider.foreground, 0.08) : "transparent"
        }

        RowLayout {
          id: moduleLine
          anchors { left: parent.left; right: parent.right; verticalCenter: parent.verticalCenter }
          spacing: Style.space(8)

          Rectangle {
            implicitWidth: Style.space(8)
            implicitHeight: Style.space(8)
            radius: width / 2
            color: ThemeProvider.moduleStateColor(moduleRow.moduleStatus)
          }

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            text: moduleRow.modelData.label
            color: ThemeProvider.text
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
          }

          Text {
            textFormat: Text.PlainText
            text: moduleRow.moduleStatus === "" ? "—" : Protocol.stateLabel(moduleRow.moduleStatus)
            color: ThemeProvider.dimText
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
          }
        }

        HoverHandler { id: moduleHover; cursorShape: Qt.PointingHandCursor }
        TapHandler { onTapped: root.openTab(moduleRow.tab) }
      }
    }

    PanelSectionHeader {
      Layout.fillWidth: true
      Layout.topMargin: Style.space(6)
      text: "Recent alerts"
      foreground: ThemeProvider.foreground
    }

    Text {
      Layout.fillWidth: true
      visible: root.entries.length === 0
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: root.ready ? "No alerts since the hub connected." : "Not connected to omarchy-securityd"
      color: ThemeProvider.dimText
      font.family: Style.font.family
      font.pixelSize: Style.font.bodySmall
    }

    Repeater {
      model: root.entries

      Item {
        id: entry
        required property var modelData
        readonly property bool threat: modelData.kind === "threat"
        readonly property var alert: modelData.alert
        readonly property color markColor: threat ? ThemeProvider.role(Threat.stateRole(alert.state))
          : ThemeProvider.warning

        Layout.fillWidth: true
        implicitHeight: entryLine.implicitHeight + Style.space(6)

        Rectangle {
          anchors.fill: parent
          radius: Style.cornerRadius
          color: entryHover.hovered ? ThemeProvider.tint(ThemeProvider.foreground, 0.08) : "transparent"
        }

        RowLayout {
          id: entryLine
          anchors { left: parent.left; right: parent.right; verticalCenter: parent.verticalCenter }
          spacing: Style.space(8)

          Text {
            Layout.alignment: Qt.AlignTop
            textFormat: Text.PlainText
            text: entry.threat ? "\u{F0026}" : "\u{F059F}"  // nf-md-alert, nf-md-web
            color: entry.markColor
            font.family: Style.font.family
            font.pixelSize: Style.font.body
          }

          ColumnLayout {
            Layout.fillWidth: true
            spacing: 0

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              elide: Text.ElideRight
              text: entry.threat ? Threat.programName(entry.alert) + ": " + Threat.title(entry.alert)
                : Hub.firewallTitle(entry.alert)
              color: ThemeProvider.text
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              elide: Text.ElideRight
              text: (entry.threat ? Threat.stateLabel(entry.alert.state) : Hub.firewallDetail(entry.alert, root.now))
                + " · " + Hub.ago(root.now - entry.modelData.time)
              color: entry.threat && Threat.isPending(entry.alert) ? entry.markColor : ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }
        }

        HoverHandler { id: entryHover; cursorShape: Qt.PointingHandCursor }
        TapHandler { onTapped: root.openTab(entry.modelData.tab) }
      }
    }
  }
}
