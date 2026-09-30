// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import qs.Commons
import "../services"
import "../services/Touch.js" as Touch

// On-screen prompt while a security key waits for a touch (plan task 3.5):
// FIDO2 sign-ins, SSH with a security key, and GnuPG with an OpenPGP card.
// SecurityIPC keeps the requests and loads this once, so it appears whether
// or not the hub is open.
//
// There is nothing to answer here: the answer is the touch. So the prompt
// is visual only. It never takes the keyboard or a click, and it leaves the
// middle of the screen alone, where the app that asked (a terminal, a
// browser, pinentry) usually is. It names what is probably asking, because
// a touch nobody asked for is the one to refuse. It stays while the key
// waits and reports the outcome briefly once the daemon has one.
Item {
  id: root

  property var security: null
  // False in tests, which read the prompt's state without mapping a window.
  property bool showWindow: true

  readonly property var requests: security && security.ready ? security.touchRequests : []
  readonly property var tokens: security && security.ready ? security.tokens : []

  // This clock, moved on by the timers below; everything shown is computed
  // from it, so a request goes stale or a finished one leaves on time.
  property real now: Date.now()
  readonly property var waiting: Touch.waiting(requests, now)
  readonly property var finished: waiting.length > 0 ? null : Touch.lingering(requests, now)
  readonly property bool shown: waiting.length > 0 || !!finished
  // "" while waiting.
  readonly property string outcome: finished ? finished.outcome : ""
  readonly property string title: waiting.length > 0 ? Touch.waitingTitle(waiting, tokens) : Touch.outcomeTitle(outcome)
  readonly property color roleColor: ThemeProvider.role(Touch.outcomeRole(outcome))

  function refresh() {
    now = Date.now()
    var wait = Touch.nextChangeIn(requests, now)
    if (wait > 0) {
      changeTimer.interval = wait + 20
      changeTimer.restart()
    } else {
      changeTimer.stop()
    }
  }

  onRequestsChanged: refresh()

  // The elapsed time while a key waits.
  Timer {
    interval: 1000
    repeat: true
    running: root.waiting.length > 0
    onTriggered: root.now = Date.now()
  }

  Timer {
    id: changeTimer
    onTriggered: root.refresh()
  }

  PanelWindow {
    visible: root.showWindow && root.shown
    // A full-screen surface with an empty input region, like the shell's
    // OSD: nothing here can be clicked, so a click always reaches the app
    // below.
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    exclusionMode: ExclusionMode.Normal
    WlrLayershell.namespace: "omarchy-security-touch"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.None
    mask: Region {}

    Rectangle {
      id: card
      // Above the shell's volume and brightness OSD, which sits at the
      // bottom centre.
      anchors { bottom: parent.bottom; horizontalCenter: parent.horizontalCenter; bottomMargin: Style.space(150) }
      width: Style.space(380)
      height: content.implicitHeight + Style.space(28)
      color: ThemeProvider.background
      border.color: root.roleColor
      border.width: Math.max(2, ThemeProvider.border.width)
      radius: ThemeProvider.border.radius

      ColumnLayout {
        id: content
        anchors { left: parent.left; right: parent.right; top: parent.top; margins: Style.space(14) }
        spacing: Style.space(4)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(10)

          Text {
            id: icon
            textFormat: Text.PlainText
            // nf-md-key, nf-md-check, nf-md-close
            text: root.outcome === "" ? "\u{F0306}" : root.outcome === "touched" ? "\u{F012C}" : "\u{F0156}"
            color: root.roleColor
            font.family: Style.font.family
            font.pixelSize: Style.font.heading

            // A slow pulse while the key waits, to draw the eye to the key.
            SequentialAnimation on opacity {
              running: root.showWindow && root.waiting.length > 0
              loops: Animation.Infinite
              onRunningChanged: if (!running) icon.opacity = 1
              NumberAnimation { to: 0.35; duration: 700; easing.type: Easing.InOutSine }
              NumberAnimation { to: 1; duration: 700; easing.type: Easing.InOutSine }
            }
          }

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            elide: Text.ElideRight
            text: root.title
            color: ThemeProvider.text
            font.family: Style.font.family
            font.pixelSize: Style.font.body
            font.bold: true
          }

          Text {
            visible: root.waiting.length > 0
            textFormat: Text.PlainText
            text: Touch.elapsedText(root.waiting[0], root.now)
            color: ThemeProvider.dimText
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
          }
        }

        // One entry per waiting request, oldest first; usually one.
        Repeater {
          model: root.waiting.slice(0, 3)

          ColumnLayout {
            id: entry
            required property var modelData
            Layout.fillWidth: true
            Layout.topMargin: Style.space(4)
            spacing: Style.space(2)

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              // The daemon's description names the source and the key.
              text: entry.modelData.description || Touch.sourceLabel(entry.modelData.source)
              color: ThemeProvider.text
              font.family: Style.font.family
              font.pixelSize: Style.font.bodySmall
            }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              text: Touch.sourceHint(entry.modelData.source)
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }
        }

        Text {
          Layout.fillWidth: true
          visible: root.waiting.length > 3
          textFormat: Text.PlainText
          text: (root.waiting.length - 3) + " more waiting"
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          Layout.topMargin: Style.space(4)
          visible: root.waiting.length > 0
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: "Didn't start this? Don't touch the key."
          color: ThemeProvider.warning
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          visible: text !== "" && root.waiting.length === 0
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: Touch.outcomeText(root.outcome)
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }
      }
    }
  }
}
