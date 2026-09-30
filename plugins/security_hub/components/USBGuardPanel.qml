// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"
import "../services/Usb.js" as Usb

// USB devices USBGuard knows about, with Approve / Save permanent / Reject
// (plan task 3.3). The list lives in SecurityIPC, so it is current however
// long the panel was closed; this view only draws it and sends
// USBGUARD_SET_POLICY.
//
// Rows keep USBGuard's order and never move when a device changes state,
// so a second click cannot land on another device's button. Reject asks
// for a second click, because a rejected device only comes back when it is
// unplugged and plugged in again.
Item {
  id: root

  property var security: null

  readonly property bool ready: !!security && security.ready
  readonly property var devices: ready ? security.usbDevices : []
  readonly property string emptyText: Usb.emptyText(ready,
    ready ? security.moduleState("usbguard") : "",
    ready ? security.usbListError : null, devices)
  readonly property int blocked: Usb.blockedCount(devices)

  // Per-device state of this view, by device_id.
  property var busy: ({})
  property var errors: ({})
  // The device whose Reject was clicked once, -1 for none.
  property int confirmingReject: -1

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  function setEntry(map, deviceId, value) {
    var next = Object.assign({}, map)
    if (value === undefined) delete next[deviceId]
    else next[deviceId] = value
    return next
  }

  // Runs one of Usb.ACTIONS on a device. Returns false when it only armed
  // a confirmation or could not be sent.
  function perform(deviceId, actionId) {
    var action = Usb.ACTIONS[actionId]
    if (!action || !ready || busy[deviceId]) return false
    if (action.confirm && confirmingReject !== deviceId) {
      confirmingReject = deviceId
      confirmTimer.restart()
      return false
    }
    confirmingReject = -1
    busy = setEntry(busy, deviceId, true)
    errors = setEntry(errors, deviceId, undefined)
    security.setUsbPolicy(deviceId, action.target, action.permanent, function(error) {
      root.busy = root.setEntry(root.busy, deviceId, undefined)
      if (error) root.errors = root.setEntry(root.errors, deviceId, Usb.actionErrorText(error))
    })
    return true
  }

  Timer {
    id: confirmTimer
    interval: 4000
    onTriggered: root.confirmingReject = -1
  }

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(10)

    RowLayout {
      Layout.fillWidth: true

      PanelSectionHeader {
        Layout.fillWidth: true
        text: "USB devices"
        foreground: ThemeProvider.foreground
      }

      Text {
        visible: root.blocked > 0
        textFormat: Text.PlainText
        text: root.blocked + " blocked"
        color: ThemeProvider.warning
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

    Repeater {
      id: rows
      model: root.devices

      ColumnLayout {
        id: row
        required property var modelData
        required property int index
        readonly property int deviceId: modelData.device_id
        readonly property color ruleColor: ThemeProvider.role(Usb.ruleRole(modelData.rule))
        readonly property string risk: Usb.riskNote(modelData)
        readonly property bool rowBusy: !!root.busy[row.deviceId]

        Layout.fillWidth: true
        spacing: Style.space(6)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(10)

          Text {
            Layout.alignment: Qt.AlignTop
            textFormat: Text.PlainText
            text: Usb.classIcon(row.modelData)
            color: row.ruleColor
            font.family: Style.font.family
            font.pixelSize: Style.font.heading
          }

          ColumnLayout {
            Layout.fillWidth: true
            spacing: Style.space(1)

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              elide: Text.ElideRight
              text: row.modelData.name
              color: ThemeProvider.text
              font.family: Style.font.family
              font.pixelSize: Style.font.body
            }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              elide: Text.ElideRight
              text: Usb.idLine(row.modelData)
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              text: Usb.classSummary(row.modelData)
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }

          Text {
            Layout.alignment: Qt.AlignTop
            textFormat: Text.PlainText
            text: row.rowBusy ? "Applying…" : Usb.ruleLabel(row.modelData)
            color: row.rowBusy ? ThemeProvider.dimText : row.ruleColor
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            font.bold: row.modelData.rule === "block"
          }
        }

        Text {
          Layout.fillWidth: true
          visible: row.risk !== "" && row.modelData.rule === "block"
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: row.risk
          color: ThemeProvider.warning
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: Usb.noActionsNote(row.modelData)
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Flow {
          Layout.fillWidth: true
          visible: actions.count > 0
          spacing: Style.space(6)
          enabled: !row.rowBusy
          opacity: enabled ? 1 : 0.5

          Repeater {
            id: actions
            model: Usb.actionsFor(row.modelData)

            Button {
              id: actionButton
              required property var modelData
              readonly property bool destructive: actionButton.modelData.target === "reject"
              readonly property bool confirming: actionButton.modelData.confirm
                && root.confirmingReject === row.deviceId

              bordered: true
              text: actionButton.confirming ? "Click again to reject" : actionButton.modelData.label
              tooltipText: actionButton.modelData.hint
              foreground: actionButton.destructive ? ThemeProvider.danger : ThemeProvider.foreground
              accent: actionButton.destructive ? ThemeProvider.danger : ThemeProvider.accent
              active: actionButton.confirming
              fontSize: Style.font.bodySmall
              onClicked: root.perform(row.deviceId, actionButton.modelData.id)
            }
          }
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: root.errors[row.deviceId] || ""
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
