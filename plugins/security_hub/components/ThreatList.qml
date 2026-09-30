// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"
import "../services/Threat.js" as Threat

// The hub's Threats tab (plan task 3.9): every threat alert of this
// session, newest first, with the OSD's answers for the ones still open
// (3.4). An alert put off with Later on the card is answered here. The
// alerts live in SecurityIPC, from THREAT_LIST_ALERTS and the THREAT_*
// events; the daemon lists only open ones, so a resolved alert raised
// before this shell connected is not here.
//
// A new alert goes on top and moves the rows below it, so an answer is
// sent only on a second click on the same alert within 4 s.
Item {
  id: root

  property var security: null

  readonly property bool ready: !!security && security.ready
  readonly property var alerts: ready ? Threat.newestFirst(security.threatAlerts) : []
  readonly property var moduleStatus: {
    if (!ready) return null
    for (var i = 0; i < security.modules.length; i++)
      if (security.modules[i].module === "threat") return security.modules[i]
    return null
  }
  readonly property string moduleState: moduleStatus ? moduleStatus.state || "" : ""
  readonly property string moduleDetail: moduleStatus ? moduleStatus.detail || "" : ""
  readonly property string emptyText: Threat.listEmptyText(ready, moduleState, moduleDetail, alerts)
  readonly property int pending: {
    var n = 0
    for (var i = 0; i < alerts.length; i++) if (Threat.isPending(alerts[i])) n++
    return n
  }

  // Per-alert state of this view, by alert_id.
  property var busy: ({})
  property var errors: ({})
  // "<alert_id>:<action>" clicked once, "" for none.
  property string confirming: ""

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  function setEntry(map, alertId, value) {
    var next = Object.assign({}, map)
    if (value === undefined) delete next[alertId]
    else next[alertId] = value
    return next
  }

  // Sends one of Threat.ACTIONS for the alert `alertId`. Returns false when
  // the click only armed it or it could not be sent.
  function perform(alertId, actionId) {
    var alert = Threat.findAlert(ready ? security.threatAlerts : [], alertId)
    if (!alert || busy[alertId]) return false
    if (!Threat.actionsFor(alert).some(function(a) { return a.id === actionId })) return false
    var key = alertId + ":" + actionId
    if (confirming !== key) {
      confirming = key
      confirmTimer.restart()
      return false
    }
    confirming = ""
    busy = setEntry(busy, alertId, true)
    errors = setEntry(errors, alertId, undefined)
    security.respondToThreat(alert, actionId, function(error) {
      root.busy = root.setEntry(root.busy, alertId, undefined)
      if (error) root.errors = root.setEntry(root.errors, alertId, Threat.actionErrorText(error))
    })
    return true
  }

  Timer {
    id: confirmTimer
    interval: 4000
    onTriggered: root.confirming = ""
  }

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(10)

    RowLayout {
      Layout.fillWidth: true

      PanelSectionHeader {
        Layout.fillWidth: true
        text: "Suspicious programs"
        foreground: ThemeProvider.foreground
      }

      Text {
        visible: root.pending > 0
        textFormat: Text.PlainText
        text: root.pending + " open"
        color: ThemeProvider.danger
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }
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

    // A degraded monitor still reports, but may miss some programs.
    Text {
      Layout.fillWidth: true
      visible: root.ready && root.moduleState === "degraded" && root.moduleDetail !== ""
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: root.moduleDetail
      color: ThemeProvider.warning
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
    }

    Repeater {
      id: rows
      model: root.alerts

      ColumnLayout {
        id: row
        required property var modelData
        required property int index
        readonly property int alertId: modelData.alert_id
        readonly property color stateColor: ThemeProvider.role(Threat.stateRole(modelData.state))
        readonly property bool rowBusy: !!root.busy[row.alertId]
        readonly property string dropped: Threat.droppedLine(modelData)

        Layout.fillWidth: true
        spacing: Style.space(4)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(10)

          Text {
            Layout.alignment: Qt.AlignTop
            textFormat: Text.PlainText
            text: "\u{F0026}"  // nf-md-alert
            color: row.stateColor
            font.family: Style.font.family
            font.pixelSize: Style.font.heading
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
                text: Threat.programName(row.modelData)
                color: ThemeProvider.text
                font.family: Style.font.family
                font.pixelSize: Style.font.body
              }

              Text {
                textFormat: Text.PlainText
                text: row.rowBusy ? "Sending…" : Threat.stateLabel(row.modelData.state)
                color: row.rowBusy ? ThemeProvider.dimText : row.stateColor
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
                font.bold: Threat.isPending(row.modelData)
              }
            }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              text: Threat.title(row.modelData)
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              wrapMode: Text.WrapAnywhere
              maximumLineCount: 3
              elide: Text.ElideRight
              text: Threat.commandLine(row.modelData.argv, 160)
              color: ThemeProvider.text
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              elide: Text.ElideRight
              text: Threat.processLine(row.modelData)
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              visible: row.dropped !== ""
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              text: row.dropped
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }
        }

        Flow {
          Layout.fillWidth: true
          visible: answers.count > 0
          spacing: Style.space(6)
          enabled: !row.rowBusy
          opacity: enabled ? 1 : 0.5

          Repeater {
            id: answers
            model: Threat.actionsFor(row.modelData)

            Button {
              id: answer
              required property var modelData
              readonly property bool destructive: answer.modelData.id === "kill"
              readonly property bool armed: root.confirming === row.alertId + ":" + answer.modelData.id

              bordered: true
              text: answer.armed ? "Click again" : answer.modelData.label
              tooltipText: answer.modelData.hint
              foreground: answer.destructive ? ThemeProvider.danger : ThemeProvider.foreground
              accent: answer.destructive ? ThemeProvider.danger : ThemeProvider.accent
              active: answer.armed
              fontSize: Style.font.bodySmall
              onClicked: root.perform(row.alertId, answer.modelData.id)
            }
          }
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: root.errors[row.alertId] || ""
          color: ThemeProvider.danger
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        PanelSeparator {
          Layout.fillWidth: true
          visible: row.index < rows.count - 1
          foreground: ThemeProvider.foreground
        }
      }
    }
  }
}
