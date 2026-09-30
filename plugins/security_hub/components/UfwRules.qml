// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"
import "../services/Network.js" as Network
import "../services/Protocol.js" as Protocol

// UFW's own rules, read-only (plan task 3.10, §5.21), from
// FIREWALL_UFW_RULES: its user rules, what its built-in rules allow, and
// the temporary rules the hub added, each with a countdown and Revoke
// (FIREWALL_TEMP_REMOVE, on a second click within 4 s). Shown in the
// Network tab while UFW is on.
Item {
  id: root

  property var security: null

  readonly property bool ready: !!security && security.ready
  readonly property var list: ready ? security.ufwRules : null
  readonly property var rules: list && Array.isArray(list.rules) ? list.rules : []
  readonly property var builtin: list && Array.isArray(list.builtin) ? list.builtin : []
  readonly property string emptyText: !ready ? "Not connected to omarchy-securityd"
    : security.ufwRulesError ? "Could not read UFW's rules: " + (security.ufwRulesError.message || "unknown error")
    : !list ? "Reading UFW's rules…"
    : rules.length === 0 ? "UFW has no rules of its own."
    : ""
  readonly property bool hasTemporary: rules.some(function(r) { return r.temp_id !== undefined })

  property bool builtinOpen: false
  property real now: Date.now()

  // Per temporary rule, by temp_id.
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

  // Ends a temporary rule early. Returns true when it was sent.
  function revoke(tempId) {
    if (!ready || busy[tempId]) return false
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
    running: root.visible && root.hasTemporary
    onTriggered: root.now = Date.now()
  }

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(8)

    RowLayout {
      Layout.fillWidth: true

      PanelSectionHeader {
        Layout.fillWidth: true
        text: "UFW rules"
        foreground: ThemeProvider.foreground
      }

      Text {
        textFormat: Text.PlainText
        text: "Read-only"
        color: ThemeProvider.dimText
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
      model: root.rules

      ColumnLayout {
        id: row
        required property var modelData
        readonly property bool temporary: modelData.temp_id !== undefined
        readonly property real tempId: temporary ? modelData.temp_id : -1
        readonly property bool rowBusy: temporary && !!root.busy[tempId]
        readonly property bool confirming: temporary && root.confirmingRevoke === tempId
        readonly property string comment: Network.ufwRuleComment(modelData)

        Layout.fillWidth: true
        spacing: Style.space(2)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(10)

          Text {
            Layout.alignment: Qt.AlignTop
            textFormat: Text.PlainText
            // nf-md-check_circle_outline, nf-md-cancel
            text: Network.ufwRuleRole(row.modelData) === "success" ? "\u{F05E1}" : "\u{F073A}"
            color: ThemeProvider.role(Network.ufwRuleRole(row.modelData))
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
              text: Network.ufwRuleTitle(row.modelData)
              color: ThemeProvider.text
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              visible: text !== ""
              textFormat: Text.PlainText
              elide: Text.ElideRight
              text: row.temporary ? "Added by the hub · " + Network.remainingText(row.modelData.expires_at, root.now)
                : row.comment
              color: row.temporary ? ThemeProvider.warning : ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }

          Button {
            Layout.alignment: Qt.AlignTop
            visible: row.temporary
            bordered: row.confirming
            enabled: !row.rowBusy
            opacity: enabled ? 1 : 0.5
            text: row.rowBusy ? "Revoking…" : row.confirming ? "Click again" : "Revoke"
            tooltipText: row.confirming ? "" : "End this temporary rule now"
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
          text: row.temporary ? root.errors[row.tempId] || "" : ""
          color: ThemeProvider.danger
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }
      }
    }

    // What before.rules and after.rules allow on a stock install.
    Button {
      visible: root.builtin.length > 0
      text: (root.builtinOpen ? "Hide" : "Show") + " built-in rules (" + root.builtin.length + ")"
      iconText: root.builtinOpen ? "\u{F0140}" : "\u{F0142}"  // nf-md-chevron_down, chevron_right
      foreground: ThemeProvider.dimText
      fontSize: Style.font.caption
      onClicked: root.builtinOpen = !root.builtinOpen
    }

    Repeater {
      model: root.builtinOpen ? root.builtin : []

      Text {
        required property string modelData
        Layout.fillWidth: true
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        text: "• " + modelData
        color: ThemeProvider.dimText
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }
    }

    Text {
      Layout.fillWidth: true
      visible: root.list !== null
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: "From /etc/ufw/user.rules. Change them with `sudo ufw`."
      color: ThemeProvider.dimText
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
    }
  }
}
