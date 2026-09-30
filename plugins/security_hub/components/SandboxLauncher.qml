// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import Quickshell
import qs.Commons
import qs.Ui
import "../services"
import "../services/Sandbox.js" as Sandbox

// Runs a program in the bubblewrap sandbox (plan task 3.8;
// docs/ipc-protocol.md §4.7, plan §5.11): a program, optionally one file
// for it to open, and network off unless switched on, then SANDBOX_RUN.
// The sandbox sees the system read-only and an empty home; the one file
// is bound read-write at its own path and passed as the only argument.
//
// Paths must be absolute ("~/" is expanded here). Whether they exist and
// the program is executable, the daemon checks, and says so if not.
Item {
  id: root

  property var security: null

  readonly property bool ready: !!security && security.ready
  readonly property string home: Quickshell.env("HOME") || ""
  readonly property var moduleStatus: {
    if (!ready) return null
    for (var i = 0; i < security.modules.length; i++)
      if (security.modules[i].module === "sandbox") return security.modules[i]
    return null
  }
  readonly property string moduleState: moduleStatus ? moduleStatus.state || "" : ""
  readonly property string moduleDetail: moduleStatus ? moduleStatus.detail || "" : ""
  readonly property var runs: ready ? security.sandboxRuns : []

  property var form: ({ executable: "", target: "", shareNet: false })
  readonly property var check: Sandbox.checkForm(form, home)
  property bool busy: false
  property var lastError: null
  readonly property string runError: Sandbox.runErrorText(lastError)
  readonly property string unavailableText: Sandbox.unavailableText(ready, moduleState, moduleDetail, lastError)
  // The run this form started last, for its confirmation line.
  property var started: null

  property real now: Date.now()

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  function setField(name, value) {
    var next = Object.assign({}, form)
    next[name] = value
    form = next
    lastError = null
    started = null
  }

  // Fills the form from an earlier launch.
  function reuse(run) {
    form = Sandbox.formFor(run)
    lastError = null
    started = null
  }

  // Sends SANDBOX_RUN. Returns false when the form cannot be sent.
  function run() {
    if (!ready || busy || !check.params || unavailableText !== "") return false
    busy = true
    lastError = null
    started = null
    security.runSandbox(check.params, function(error, run) {
      root.busy = false
      root.now = Date.now()
      if (error) root.lastError = error
      else root.started = run
    })
    return true
  }

  Timer {
    interval: 30000
    repeat: true
    running: root.visible && root.runs.length > 0
    onTriggered: root.now = Date.now()
  }

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(8)

    PanelSectionHeader {
      Layout.fillWidth: true
      text: "Sandbox"
      foreground: ThemeProvider.foreground
    }

    Text {
      Layout.fillWidth: true
      visible: root.unavailableText !== ""
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: root.unavailableText
      color: ThemeProvider.dimText
      font.family: Style.font.family
      font.pixelSize: Style.font.bodySmall
    }

    ColumnLayout {
      Layout.fillWidth: true
      visible: root.unavailableText === ""
      spacing: Style.space(6)

      Text {
        Layout.fillWidth: true
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        text: "Open an untrusted file or program with the system read-only and your home hidden."
        color: ThemeProvider.dimText
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }

      TextField {
        Layout.fillWidth: true
        placeholderText: "Program, e.g. /usr/bin/zathura"
        text: root.form.executable
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        font.pixelSize: Style.font.bodySmall
        onTextEdited: root.setField("executable", text)
        onAccepted: root.run()
      }

      TextField {
        Layout.fillWidth: true
        placeholderText: "File to open (optional), e.g. ~/Downloads/report.pdf"
        text: root.form.target
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        font.pixelSize: Style.font.bodySmall
        onTextEdited: root.setField("target", text)
        onAccepted: root.run()
      }

      Toggle {
        Layout.fillWidth: true
        label: "Network"
        description: root.form.shareNet ? "The program can use the network." : "No network: the program cannot connect anywhere."
        checked: root.form.shareNet
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        titleSize: Style.font.bodySmall
        onClicked: root.setField("shareNet", !root.form.shareNet)
      }

      Text {
        Layout.fillWidth: true
        visible: text !== ""
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        text: root.runError !== "" ? root.runError : root.check.error !== "" ? root.check.error : root.check.warning
        color: root.runError !== "" || root.check.error !== "" ? ThemeProvider.danger : ThemeProvider.warning
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: Style.space(8)

        Button {
          bordered: true
          enabled: root.ready && !root.busy && !!root.check.params
          opacity: enabled ? 1 : 0.5
          text: root.busy ? "Starting…" : "Run sandboxed"
          iconText: "\u{F040A}"  // nf-md-play
          foreground: ThemeProvider.foreground
          accent: ThemeProvider.accent
          fontSize: Style.font.bodySmall
          onClicked: root.run()
        }

        Text {
          Layout.fillWidth: true
          visible: !!root.started
          textFormat: Text.PlainText
          elide: Text.ElideRight
          text: root.started ? "Started (PID " + root.started.pid + ")" : ""
          color: ThemeProvider.success
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }
      }

      // Launches from this shell, to run one again.
      ColumnLayout {
        Layout.fillWidth: true
        visible: root.runs.length > 0
        spacing: Style.space(2)

        Text {
          Layout.fillWidth: true
          Layout.topMargin: Style.space(4)
          textFormat: Text.PlainText
          text: "Recent"
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
          font.bold: true
        }

        Repeater {
          model: root.runs

          RowLayout {
            id: runRow
            required property var modelData
            Layout.fillWidth: true
            spacing: Style.space(8)

            ColumnLayout {
              Layout.fillWidth: true
              spacing: 0

              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                elide: Text.ElideRight
                text: Sandbox.runTitle(runRow.modelData)
                color: ThemeProvider.text
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
              }

              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                elide: Text.ElideRight
                text: Sandbox.runDetail(runRow.modelData, root.now)
                color: ThemeProvider.dimText
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
              }
            }

            Button {
              text: "Use again"
              tooltipText: "Put this program and file back in the form"
              foreground: ThemeProvider.dimText
              accent: ThemeProvider.accent
              fontSize: Style.font.caption
              onClicked: root.reuse(runRow.modelData)
            }
          }
        }
      }
    }
  }
}
