// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "../services"
import "../services/Backend.js" as Backend

// The hub without a working backend (plan task 5.3, §5.22). A plugin
// install brings only the QML; while the daemon is not reachable,
// SecurityHub.qml shows this card instead of the tabs, with a button for
// what can fix it: Install (backend/install.sh in a terminal, where sudo
// asks for the password) or Start (the user unit). Once connected, it is
// one line above the tabs when the daemon and the plugin are at different
// versions, and nothing otherwise.
//
// Nothing runs without a click. The probe (is omarchy-securityd on PATH,
// is its unit active) runs every 5 s while the hub is open and not
// connected.
Item {
  id: root

  property var security: null
  property string pluginVersion: ""
  // Whether the hub is open; the probe only runs then.
  property bool shown: true

  readonly property bool ready: !!security && security.ready
  property var probeExit: null
  readonly property string kind: Backend.state(ready, ready ? security.daemonVersion : "",
    pluginVersion, probeExit)
  readonly property bool blocking: Backend.blocksHub(kind)
  readonly property string scriptPath: Backend.localPath(Qt.resolvedUrl("../backend/install.sh"))
  readonly property var info: Backend.message(kind, {
    pluginVersion: pluginVersion,
    daemonVersion: ready ? security.daemonVersion : "",
    lastError: security ? security.lastError : "",
    scriptPath: scriptPath
  })
  // Set by a click, until the probe or the connection says what happened.
  property string launched: ""

  visible: kind !== "ok"
  implicitWidth: column.implicitWidth
  implicitHeight: visible ? column.implicitHeight : 0

  function probe() {
    if (!probeProcess.running) probeProcess.running = true
  }

  function act() {
    if (!info) return
    if (info.action === "install") {
      Quickshell.execDetached(Backend.terminalCommand(scriptPath, []))
      launched = "The installer is running in a terminal."
    } else if (info.action === "start") {
      Quickshell.execDetached(Backend.START)
      launched = "Starting omarchy-securityd…"
    }
  }

  onKindChanged: launched = ""
  onShownChanged: if (shown && !ready) probe()
  onReadyChanged: if (!ready) probe()

  Process {
    id: probeProcess
    command: Backend.PROBE
    onExited: function(exitCode) { root.probeExit = exitCode }
  }

  Timer {
    interval: 5000
    repeat: true
    running: root.shown && !root.ready
    triggeredOnStart: true
    onTriggered: root.probe()
  }

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(8)

    Text {
      Layout.fillWidth: true
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: root.info ? root.info.title : ""
      color: root.kind === "checking" ? ThemeProvider.dimText
        : root.blocking ? ThemeProvider.danger : ThemeProvider.warning
      font.family: Style.font.family
      font.pixelSize: root.blocking ? Style.font.body : Style.font.bodySmall
      font.bold: root.blocking
    }

    Text {
      Layout.fillWidth: true
      visible: text !== ""
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: root.info ? root.info.body : ""
      color: ThemeProvider.dimText
      font.family: Style.font.family
      font.pixelSize: Style.font.bodySmall
    }

    RowLayout {
      Layout.fillWidth: true
      visible: !!root.info && root.info.action !== ""
      spacing: Style.space(8)

      Button {
        bordered: true
        text: !root.info ? "" : root.info.action === "start" ? "Start"
          : root.kind === "older" ? "Update backend" : "Install backend"
        tooltipText: root.info ? root.info.actionHint : ""
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        fontSize: Style.font.bodySmall
        onClicked: root.act()
      }

      Text {
        Layout.fillWidth: true
        visible: text !== ""
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        text: root.launched
        color: ThemeProvider.dimText
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }
    }

    // A command to run by hand, selectable for copying.
    ColumnLayout {
      Layout.fillWidth: true
      visible: !!root.info && root.info.manual !== ""
      spacing: Style.space(2)

      Text {
        textFormat: Text.PlainText
        text: root.kind === "missing" ? "Or build it from source, in a terminal:"
          : root.kind === "newer" ? "Update it with:" : "Its log:"
        color: ThemeProvider.dimText
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }

      TextEdit {
        Layout.fillWidth: true
        readOnly: true
        selectByMouse: true
        wrapMode: TextEdit.WrapAnywhere
        textFormat: TextEdit.PlainText
        text: root.info ? root.info.manual : ""
        color: ThemeProvider.text
        selectionColor: ThemeProvider.accent
        font.family: "monospace"
        font.pixelSize: Style.font.caption
      }
    }
  }
}
