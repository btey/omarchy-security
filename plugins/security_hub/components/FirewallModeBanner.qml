// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"
import "../services/Network.js" as Network
import "../services/Protocol.js" as Protocol

// The top of the Network tab (plan task 3.10, §5.21): which firewall
// protects the machine, and the switch between UFW and the Security Hub
// firewall. A switch opens a dialog that says what will change, which of
// UFW's rules will be imported and which cannot be (FIREWALL_SET_MODE with
// `dry_run`), the Docker note, the password, and the recovery command. It
// is sent only on a second click within 4 s, as Panic is.
Item {
  id: root

  property var security: null

  readonly property bool ready: !!security && security.ready
  readonly property string mode: ready ? security.firewallMode : ""
  readonly property var info: ready ? security.firewallInfo : null
  readonly property var banner: Network.banner(mode)
  readonly property var notes: Network.modeNotes(info)

  // The dialog: the mode it switches to, "" when closed.
  property string target: ""
  readonly property var plan: target !== "" ? Network.switchPlan(target, info) : null
  // FIREWALL_SET_MODE's dry run for `target`.
  property var preview: null
  property var previewError: null
  property bool previewBusy: false
  property bool confirming: false
  property bool busy: false
  property string error: ""
  // What the last switch did, until the next one starts.
  property string done: ""

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  // Opens the dialog for a switch to `mode`. Returns false when it cannot.
  function startSwitch(mode) {
    if (!ready || busy || Protocol.SETTABLE_FIREWALL_MODES.indexOf(mode) < 0) return false
    target = mode
    confirming = false
    error = ""
    done = ""
    preview = null
    previewError = null
    // Only a switch to standalone imports anything.
    if (mode !== "standalone") return true
    previewBusy = true
    security.previewFirewallMode(mode, function(err, result) {
      if (root.target !== mode) return
      root.previewBusy = false
      root.previewError = err || null
      root.preview = err ? null : result
    })
    return true
  }

  function cancel() {
    if (busy) return
    target = ""
    confirming = false
    error = ""
  }

  // The dialog's button: the first click arms it, the second sends.
  // Returns true when the switch was sent.
  function confirm() {
    if (!ready || busy || target === "") return false
    if (!confirming) {
      confirming = true
      confirmTimer.restart()
      return false
    }
    confirming = false
    busy = true
    error = ""
    var mode = target
    security.setFirewallMode(mode, function(err, result) {
      root.busy = false
      if (err) {
        root.error = Network.modeErrorText(err)
        return
      }
      root.target = ""
      root.done = "Switched to " + Protocol.firewallModeLabel(result && result.mode ? result.mode : mode) + "."
        + (Network.importSummary(result) ? " " + Network.importSummary(result) : "")
    })
    return true
  }

  Timer {
    id: confirmTimer
    interval: 4000
    onTriggered: root.confirming = false
  }

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(8)

    Rectangle {
      Layout.fillWidth: true
      visible: root.ready && root.banner.text !== ""
      implicitHeight: bannerColumn.implicitHeight + Style.space(16)
      radius: Style.cornerRadius
      color: ThemeProvider.tint(ThemeProvider.role(root.banner.role), 0.12)
      border.color: ThemeProvider.role(root.banner.role)
      border.width: ThemeProvider.border.width

      ColumnLayout {
        id: bannerColumn
        anchors { left: parent.left; right: parent.right; top: parent.top; margins: Style.space(8) }
        spacing: Style.space(6)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(8)

          Text {
            Layout.alignment: Qt.AlignTop
            textFormat: Text.PlainText
            // nf-md-shield_check, nf-md-shield_alert, nf-md-shield_off
            text: root.mode === "ufw" || root.mode === "standalone" ? "\u{F0565}"
              : root.mode === "none" ? "\u{F099E}" : "\u{F0ECC}"
            color: ThemeProvider.role(root.banner.role)
            font.family: Style.font.family
            font.pixelSize: Style.font.heading
          }

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: root.banner.text
            color: ThemeProvider.text
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
            font.bold: root.mode === "none" || root.mode === "both"
          }
        }

        Repeater {
          model: root.notes

          Text {
            required property string modelData
            Layout.fillWidth: true
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: modelData
            color: ThemeProvider.warning
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
          }
        }

        Flow {
          Layout.fillWidth: true
          visible: root.target === "" && root.banner.actions.length > 0
          spacing: Style.space(6)

          Repeater {
            model: root.banner.actions

            Button {
              required property var modelData
              bordered: true
              text: modelData.label
              tooltipText: "Asks for the administrator password"
              iconText: "\u{F033E}"  // nf-md-lock
              foreground: ThemeProvider.foreground
              accent: ThemeProvider.accent
              fontSize: Style.font.caption
              onClicked: root.startSwitch(modelData.mode)
            }
          }
        }
      }
    }

    Text {
      Layout.fillWidth: true
      visible: root.done !== "" && root.target === ""
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: root.done
      color: ThemeProvider.success
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
    }

    // The switch dialog.
    Rectangle {
      Layout.fillWidth: true
      visible: root.plan !== null
      implicitHeight: dialog.implicitHeight + Style.space(16)
      radius: Style.cornerRadius
      color: "transparent"
      border.color: ThemeProvider.border.color
      border.width: ThemeProvider.border.width

      ColumnLayout {
        id: dialog
        anchors { left: parent.left; right: parent.right; top: parent.top; margins: Style.space(8) }
        spacing: Style.space(6)

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: root.plan ? root.plan.title : ""
          color: ThemeProvider.text
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
          font.bold: true
        }

        Repeater {
          model: root.plan ? root.plan.changes : []

          Text {
            required property string modelData
            Layout.fillWidth: true
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: "• " + modelData
            color: ThemeProvider.text
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
          }
        }

        // What the switch takes over from UFW.
        ColumnLayout {
          Layout.fillWidth: true
          visible: root.target === "standalone"
          spacing: Style.space(2)

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: root.previewBusy ? "Reading UFW's rules…"
              : root.previewError ? "UFW's rules that a hub rule can express are imported on the first switch; "
                + "the list is shown once it is done."
              : root.preview && (root.preview.imported || root.preview.not_imported) ? "From UFW's rules:"
              : "No UFW rules will be imported."
            color: ThemeProvider.dimText
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
          }

          Repeater {
            model: root.preview && root.preview.imported ? root.preview.imported : []

            Text {
              required property var modelData
              Layout.fillWidth: true
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              text: "\u{F012C} Imported: " + Network.ufwRuleTitle(modelData.from)  // nf-md-check
                + (modelData.notes && modelData.notes.length ? " (" + modelData.notes.join("; ") + ")" : "")
              color: ThemeProvider.success
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }

          Repeater {
            model: root.preview && root.preview.not_imported ? root.preview.not_imported : []

            Text {
              required property var modelData
              Layout.fillWidth: true
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              text: "\u{F0156} Not imported: " + Network.ufwRuleTitle(modelData.from) + ": " + modelData.reason  // nf-md-close
              color: ThemeProvider.warning
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: root.plan ? root.plan.docker : ""
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: "\u{F033E} " + (root.plan ? root.plan.password : "")  // nf-md-lock
          color: ThemeProvider.warning
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: "If the machine is left unreachable, from a TTY or ssh:"
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        TextEdit {
          Layout.fillWidth: true
          readOnly: true
          selectByMouse: true
          textFormat: TextEdit.PlainText
          wrapMode: TextEdit.WrapAnywhere
          text: Network.RECOVERY_COMMAND
          color: ThemeProvider.text
          selectionColor: ThemeProvider.accent
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          visible: root.error !== ""
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: root.error
          color: ThemeProvider.danger
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(6)

          Button {
            bordered: true
            enabled: !root.busy && !root.previewBusy
            opacity: enabled ? 1 : 0.5
            text: root.busy ? "Switching…" : root.confirming ? "Click again" : root.plan ? root.plan.confirm : ""
            tooltipText: root.busy ? "Waiting for the password" : ""
            foreground: ThemeProvider.warning
            accent: ThemeProvider.warning
            active: root.confirming
            fontSize: Style.font.bodySmall
            onClicked: root.confirm()
          }

          Button {
            enabled: !root.busy
            text: "Cancel"
            foreground: ThemeProvider.dimText
            fontSize: Style.font.bodySmall
            onClicked: root.cancel()
          }

          Item { Layout.fillWidth: true }
        }
      }
    }
  }
}
