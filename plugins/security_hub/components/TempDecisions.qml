// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"
import "../services/Network.js" as Network
import "../services/Protocol.js" as Protocol

// Temporary allow and block decisions still in force (plan task 3.10,
// §5.21), from FIREWALL_TEMP_LIST and FIREWALL_TEMP_CHANGED: what each
// does, where it lives (a UFW rule or our table), a countdown, and
// Revoke (FIREWALL_TEMP_REMOVE, on a second click within 4 s, since the
// list reorders as decisions expire).
Item {
  id: root

  property var security: null

  readonly property bool ready: !!security && security.ready
  property real now: Date.now()
  readonly property var decisions: ready ? Network.liveDecisions(security.tempDecisions, now) : []

  property var busy: ({})
  property var errors: ({})
  property real confirmingRevoke: -1

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  function setEntry(map, key, value) {
    var next = Object.assign({}, map)
    if (value === undefined) delete next[key]
    else next[key] = value
    return next
  }

  // Returns true when the removal was sent.
  function revoke(tempId) {
    if (!ready || busy[tempId] || !Network.findDecision(decisions, tempId)) return false
    if (confirmingRevoke !== tempId) {
      confirmingRevoke = tempId
      confirmTimer.restart()
      return false
    }
    confirmingRevoke = -1
    busy = setEntry(busy, tempId, true)
    errors = setEntry(errors, tempId, undefined)
    security.removeTemp(tempId, function(error) {
      root.busy = root.setEntry(root.busy, tempId, undefined)
      if (error && error.code !== Protocol.ErrorCode.NOT_FOUND)
        root.errors = root.setEntry(root.errors, tempId, Network.tempErrorText(error))
    })
    return true
  }

  Timer {
    id: confirmTimer
    interval: 4000
    onTriggered: root.confirmingRevoke = -1
  }

  Timer {
    interval: 1000
    repeat: true
    running: root.visible && root.ready && root.security.tempDecisions.length > 0
    onTriggered: root.now = Date.now()
  }

  Connections {
    target: root.security
    function onTempDecisionsChanged() { root.now = Date.now() }
  }

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(8)

    PanelSectionHeader {
      Layout.fillWidth: true
      text: "Temporary decisions"
      foreground: ThemeProvider.foreground
    }

    Text {
      Layout.fillWidth: true
      visible: root.decisions.length === 0
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: root.ready ? "None now. Allow or block blocked traffic above for a while; it ends on its own."
        : "Not connected to omarchy-securityd"
      color: ThemeProvider.dimText
      font.family: Style.font.family
      font.pixelSize: Style.font.bodySmall
    }

    Repeater {
      model: root.decisions

      ColumnLayout {
        id: row
        required property var modelData
        required property int index
        readonly property real tempId: modelData.temp_id
        readonly property bool allow: modelData.spec.verdict === "allow"
        readonly property bool rowBusy: !!root.busy[tempId]
        readonly property bool confirming: root.confirmingRevoke === tempId

        Layout.fillWidth: true
        spacing: Style.space(3)

        PanelSeparator {
          Layout.fillWidth: true
          visible: row.index > 0
          foreground: ThemeProvider.foreground
        }

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(10)

          Text {
            Layout.alignment: Qt.AlignTop
            textFormat: Text.PlainText
            // nf-md-check_circle_outline, nf-md-cancel
            text: row.allow ? "\u{F05E1}" : "\u{F073A}"
            color: row.allow ? ThemeProvider.success : ThemeProvider.danger
            font.family: Style.font.family
            font.pixelSize: Style.font.body
          }

          ColumnLayout {
            Layout.fillWidth: true
            spacing: 0

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              text: Network.ruleTitle(row.modelData.spec)
              color: ThemeProvider.text
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              elide: Text.ElideRight
              text: Network.backendLabel(row.modelData.backend) + " · " + Network.remainingText(row.modelData.expires_at, root.now)
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }

          Button {
            Layout.alignment: Qt.AlignTop
            bordered: row.confirming
            enabled: !row.rowBusy
            opacity: enabled ? 1 : 0.5
            text: row.rowBusy ? "Revoking…" : row.confirming ? "Click again" : "Revoke"
            tooltipText: row.confirming ? "" : "End it now"
            foreground: ThemeProvider.foreground
            accent: ThemeProvider.accent
            active: row.confirming
            fontSize: Style.font.caption
            onClicked: root.revoke(row.tempId)
          }
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: root.errors[row.tempId] || ""
          color: ThemeProvider.danger
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }
      }
    }
  }
}
