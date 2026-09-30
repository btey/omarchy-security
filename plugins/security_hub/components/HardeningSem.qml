// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"
import "../services/Posture.js" as Posture

// The hardening audit as a traffic light (plan task 3.6;
// docs/ipc-protocol.md §4.8): the overall status, then one row per check
// with the daemon's summary and, where it gives one, what to do. The
// report lives in SecurityIPC, which follows POSTURE_CHANGED; "Check now"
// sends POSTURE_REFRESH. The checks only read the system, so nothing here
// changes it.
Item {
  id: root

  property var security: null

  readonly property bool ready: !!security && security.ready
  readonly property var report: ready ? security.posture : null
  readonly property var checks: Posture.sortedChecks(report)
  readonly property string overall: Posture.overall(report)
  readonly property string emptyText: Posture.emptyText(ready, ready ? security.moduleState("posture") : "",
    ready ? security.postureError : null, report)

  property bool busy: false
  property string errorText: ""
  // Moves "Checked N min ago" on.
  property real now: Date.now()

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  // Returns false when it could not be sent.
  function refresh() {
    if (!ready || busy) return false
    busy = true
    errorText = ""
    security.refreshPosture(function(error) {
      root.busy = false
      root.now = Date.now()
      if (error) root.errorText = "Check failed: " + (error.message || "unknown error")
    })
    return true
  }

  Timer {
    interval: 30000
    repeat: true
    running: root.visible && !!root.report
    onTriggered: root.now = Date.now()
  }

  onReportChanged: now = Date.now()

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(8)

    PanelSectionHeader {
      Layout.fillWidth: true
      text: "Hardening"
      foreground: ThemeProvider.foreground
    }

    Text {
      Layout.fillWidth: true
      visible: root.emptyText !== ""
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: root.emptyText
      color: ThemeProvider.dimText
      font.family: Style.font.family
      font.pixelSize: Style.font.bodySmall
    }

    // The light: three lamps, the one for the overall status lit.
    RowLayout {
      Layout.fillWidth: true
      visible: root.checks.length > 0
      spacing: Style.space(10)

      Row {
        spacing: Style.space(4)

        Repeater {
          model: ["fail", "warn", "pass"]

          Rectangle {
            id: lamp
            required property string modelData
            readonly property bool lit: root.overall === lamp.modelData
            width: Style.space(12)
            height: Style.space(12)
            radius: width / 2
            color: lamp.lit ? ThemeProvider.role(Posture.statusRole(lamp.modelData)) : "transparent"
            border.width: 1
            border.color: lamp.lit ? color : ThemeProvider.dimText
            opacity: lamp.lit ? 1 : 0.5
          }
        }
      }

      ColumnLayout {
        Layout.fillWidth: true
        spacing: 0

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          elide: Text.ElideRight
          text: Posture.summaryText(root.report)
          color: ThemeProvider.role(Posture.statusRole(root.overall))
          font.family: Style.font.family
          font.pixelSize: Style.font.body
          font.bold: true
        }

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          text: root.busy ? "Checking…" : Posture.checkedText(root.report, root.now)
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }
      }

      Button {
        enabled: !root.busy
        opacity: enabled ? 1 : 0.5
        text: "Check now"
        tooltipText: "Run the checks again"
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        fontSize: Style.font.caption
        onClicked: root.refresh()
      }
    }

    Repeater {
      model: root.checks

      RowLayout {
        id: row
        required property var modelData
        readonly property color roleColor: ThemeProvider.role(Posture.statusRole(modelData.status))

        Layout.fillWidth: true
        spacing: Style.space(10)

        Text {
          Layout.alignment: Qt.AlignTop
          textFormat: Text.PlainText
          text: Posture.statusIcon(row.modelData.status)
          color: row.roleColor
          font.family: Style.font.family
          font.pixelSize: Style.font.body
        }

        ColumnLayout {
          Layout.fillWidth: true
          spacing: Style.space(1)

          RowLayout {
            Layout.fillWidth: true

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              elide: Text.ElideRight
              text: Posture.checkLabel(row.modelData.check_id)
              color: ThemeProvider.text
              font.family: Style.font.family
              font.pixelSize: Style.font.bodySmall
            }

            Text {
              textFormat: Text.PlainText
              text: Posture.statusLabel(row.modelData.status)
              color: row.roleColor
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
              font.bold: row.modelData.status === "fail"
            }
          }

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: row.modelData.summary || ""
            color: ThemeProvider.dimText
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
          }

          Text {
            Layout.fillWidth: true
            visible: text !== ""
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: row.modelData.detail || ""
            color: ThemeProvider.dimText
            opacity: 0.8
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
          }
        }
      }
    }

    Text {
      Layout.fillWidth: true
      visible: text !== ""
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: root.errorText
      color: ThemeProvider.danger
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
    }
  }
}
