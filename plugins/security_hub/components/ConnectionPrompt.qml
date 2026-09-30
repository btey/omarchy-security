// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import qs.Commons
import qs.Ui
import "../services"
import "../services/Network.js" as Network

// On-screen card for an outbound connection the firewall holds until the
// user answers (plan task 3.6, second part; docs/ipc-protocol.md §4.6):
// Allow or Block, Once, for This process, or Always, with the time left
// before the daemon's timeout verdict applies. SecurityIPC keeps the
// prompts and loads this once, so it appears whether or not the hub is
// open. It is a card and not a notification because it has to be answered
// before `expires_at` (plan §5.19).
//
// The same rules as the threat card: one prompt at a time, oldest first; a
// new prompt never replaces the one on screen; the buttons wait a moment
// after a card appears; and the card never takes the keyboard, so typing
// into another window cannot answer it.
Item {
  id: root

  property var security: null
  // False in tests, which drive the card without mapping a window.
  property bool showWindow: true
  // Room taken at the top of the screen by the threat card.
  property real topOffset: 0

  readonly property bool ready: !!security && security.ready
  readonly property var prompts: ready ? security.connectionPrompts : []

  // This clock, moved on by the timers below.
  property real now: Date.now()
  readonly property var pending: Network.pendingPrompts(prompts, now)

  // The prompt on screen, -1 for none.
  property int shownId: -1
  readonly property var shown: shownId >= 0 ? Network.findPrompt(prompts, shownId) : null
  // Resolved, by this shell, another client, or the timeout; the card
  // only reports it.
  readonly property bool finished: !!shown && !Network.isPending(shown)
  readonly property int moreWaiting: {
    var n = 0
    for (var i = 0; i < pending.length; i++) if (pending[i].request_id !== shownId) n++
    return n
  }

  property string scope: "once"
  property bool armed: false
  property bool busy: false
  property string errorText: ""

  readonly property int armDelayMs: 800
  readonly property color roleColor: ThemeProvider.role(Network.resolvedRole(shown))

  // Whether the prompt on screen should stay: pending, or resolved but
  // still within its linger time, or with an error to read.
  function keeps(prompt) {
    if (!prompt) return false
    if (Network.isPending(prompt)) return now < prompt.expires_at + 5000
    return errorText !== "" || now - prompt.resolved_at < Network.lingerMs(prompt)
  }

  function sync() {
    if (keeps(shown)) return
    var next = pending.length > 0 ? pending[0].request_id : -1
    if (next === shownId) return
    shownId = next
    scope = "once"
    busy = false
    errorText = ""
    armed = false
    if (next >= 0) armTimer.restart()
  }

  function refresh() {
    now = Date.now()
    var wait = Network.nextChangeIn(prompts, now)
    if (wait > 0) {
      changeTimer.interval = wait + 20
      changeTimer.restart()
    } else {
      changeTimer.stop()
    }
    sync()
  }

  function advance() {
    errorText = ""
    shownId = -1
    sync()
  }

  // Answers the prompt on screen with `verdict` and the chosen scope.
  // Returns false when it could not be sent now.
  function decide(verdict) {
    if (!shown || !armed || busy || finished) return false
    if (verdict !== "allow" && verdict !== "block") return false
    busy = true
    errorText = ""
    var requestId = shownId
    security.decideConnection(requestId, verdict, scope, function(error) {
      if (root.shownId !== requestId) return
      root.busy = false
      if (error) root.errorText = Network.decideErrorText(error)
      root.refresh()
    })
    return true
  }

  onPromptsChanged: Qt.callLater(refresh)

  Timer {
    id: armTimer
    interval: root.armDelayMs
    onTriggered: root.armed = true
  }

  Timer {
    id: changeTimer
    onTriggered: root.refresh()
  }

  // The countdown.
  Timer {
    interval: 1000
    repeat: true
    running: !!root.shown && !root.finished
    onTriggered: root.now = Date.now()
  }

  PanelWindow {
    visible: root.showWindow && !!root.shown
    // A full-screen surface whose input region is the card only, like the
    // threat card, so clicks next to it reach the app below.
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    exclusionMode: ExclusionMode.Normal
    WlrLayershell.namespace: "omarchy-security-connection"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.None
    mask: Region { item: card }

    Rectangle {
      id: card
      anchors { top: parent.top; horizontalCenter: parent.horizontalCenter; topMargin: Style.gapsOut + root.topOffset }
      width: Style.space(400)
      height: content.implicitHeight + Style.space(32)
      color: ThemeProvider.background
      border.color: root.roleColor
      border.width: Math.max(2, ThemeProvider.border.width)
      radius: ThemeProvider.border.radius

      ColumnLayout {
        id: content
        anchors { left: parent.left; right: parent.right; top: parent.top; margins: Style.space(16) }
        spacing: Style.space(4)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(10)

          Text {
            textFormat: Text.PlainText
            text: "\u{F059F}"  // nf-md-web
            color: root.roleColor
            font.family: Style.font.family
            font.pixelSize: Style.font.heading
          }

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            elide: Text.ElideRight
            text: root.finished ? Network.resolvedTitle(root.shown) : Network.promptTitle(root.shown)
            color: ThemeProvider.text
            font.family: Style.font.family
            font.pixelSize: Style.font.body
            font.bold: true
          }

          Text {
            visible: !root.finished
            textFormat: Text.PlainText
            text: root.busy ? "Sending…" : Network.countdownText(root.shown, root.now)
            color: Network.secondsLeft(root.shown, root.now) <= 5 ? ThemeProvider.warning : ThemeProvider.dimText
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
          }
        }

        Text {
          Layout.fillWidth: true
          Layout.topMargin: Style.space(4)
          textFormat: Text.PlainText
          elide: Text.ElideMiddle
          text: root.shown ? root.shown.executable || "Unknown program" : ""
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: "To " + Network.destinationText(root.shown)
          color: ThemeProvider.text
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
        }

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          text: root.shown ? "PID " + root.shown.pid : ""
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        ColumnLayout {
          Layout.fillWidth: true
          Layout.topMargin: Style.space(8)
          visible: !root.finished
          spacing: Style.space(6)

          ButtonGroup {
            options: Network.SCOPES.map(function(s) { return { value: s.id, label: s.label, tooltip: s.hint } })
            value: root.scope
            focusable: false
            enabled: root.armed && !root.busy
            opacity: enabled ? 1 : 0.5
            foreground: ThemeProvider.foreground
            accent: ThemeProvider.accent
            fontSize: Style.font.bodySmall
            onChanged: function(value) { root.scope = value }
          }

          RowLayout {
            Layout.fillWidth: true
            spacing: Style.space(6)

            Button {
              bordered: true
              enabled: root.armed && !root.busy
              opacity: enabled ? 1 : 0.5
              text: "Allow"
              foreground: ThemeProvider.foreground
              accent: ThemeProvider.accent
              fontSize: Style.font.bodySmall
              onClicked: root.decide("allow")
            }

            Button {
              bordered: true
              enabled: root.armed && !root.busy
              opacity: enabled ? 1 : 0.5
              text: "Block"
              foreground: ThemeProvider.danger
              accent: ThemeProvider.danger
              fontSize: Style.font.bodySmall
              onClicked: root.decide("block")
            }

            Item { Layout.fillWidth: true }
          }

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: root.scope === "always"
              ? "Saves a rule for " + Network.programName(root.shown ? root.shown.executable : "") + " to this address and port."
              : "Without an answer, the firewall's timeout verdict applies (Block unless changed)."
            color: ThemeProvider.dimText
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
          }
        }

        RowLayout {
          Layout.fillWidth: true
          Layout.topMargin: Style.space(4)
          visible: root.finished && root.errorText !== ""

          Item { Layout.fillWidth: true }

          Button {
            text: "Close"
            foreground: ThemeProvider.dimText
            fontSize: Style.font.bodySmall
            onClicked: root.advance()
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

        Text {
          Layout.fillWidth: true
          visible: root.moreWaiting > 0
          textFormat: Text.PlainText
          text: root.moreWaiting === 1 ? "1 more connection waiting" : root.moreWaiting + " more connections waiting"
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }
      }
    }
  }
}
