// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Wayland
import qs.Commons
import qs.Ui
import "../services"
import "../services/Threat.js" as Threat

// On-screen card for a suspicious execution (plan task 3.4), with Kill
// process, Isolate (pause) and It's safe. SecurityIPC keeps the alerts and
// loads this once, so it appears whether or not the hub is open.
//
// One alert is shown at a time, oldest first, and it stays until it is
// answered, put off with Later, or resolved some other way (the program
// exits). A new alert never replaces the one on screen, so a click cannot
// land on a different alert than the one read. The buttons also wait a
// moment after a card appears, so a click meant for the window below does
// not answer it. The card never takes the keyboard: typing into another
// window cannot trigger an action.
Item {
  id: root

  property var security: null
  // False in tests, which drive the card without mapping a window.
  property bool showWindow: true

  readonly property bool ready: !!security && security.ready
  readonly property var alerts: ready ? security.threatAlerts : []
  // Alerts put off with Later, by alert_id, until this shell restarts.
  property var later: ({})
  readonly property var waiting: Threat.queue(alerts, later)

  // The alert on screen, -1 for none.
  property int shownId: -1
  readonly property var shown: shownId >= 0 ? Threat.findAlert(alerts, shownId) : null
  // Answered, or resolved some other way; the card only reports it.
  readonly property bool finished: !!shown && !Threat.isPending(shown)
  readonly property int moreWaiting: {
    var n = 0
    for (var i = 0; i < waiting.length; i++) if (waiting[i].alert_id !== shownId) n++
    return n
  }

  property bool armed: false
  property bool busy: false
  property string errorText: ""

  // Room the card takes at the top of the screen, gap included, for the
  // connection prompt to sit below it; 0 while nothing is shown.
  readonly property real cardHeight: showWindow && shown ? card.height + Style.gapsOut : 0

  readonly property int armDelayMs: 800
  readonly property int finishedDelayMs: 5000

  // Keeps `shownId` on the alert being read; takes the oldest waiting one
  // when there is none.
  function sync() {
    if (shownId >= 0 && Threat.findAlert(alerts, shownId)) return
    var next = waiting.length > 0 ? waiting[0].alert_id : -1
    if (next === shownId) return
    shownId = next
    busy = false
    errorText = ""
    armed = false
    if (next >= 0) armTimer.restart()
  }

  function advance() {
    shownId = -1
    sync()
  }

  // Sends one of Threat.ACTIONS for the alert on screen. Returns false when
  // it could not be sent now.
  function perform(actionId) {
    if (!shown || !armed || busy || finished) return false
    var offered = Threat.actionsFor(shown).some(function(a) { return a.id === actionId })
    if (!offered) return false
    busy = true
    errorText = ""
    var alertId = shownId
    security.respondToThreat(shown, actionId, function(error) {
      if (root.shownId !== alertId) return
      root.busy = false
      if (error) root.errorText = Threat.actionErrorText(error)
    })
    return true
  }

  // Later: out of the way until this shell restarts. The alert stays open
  // in the daemon.
  function putOff() {
    if (!shown) return
    var next = Object.assign({}, later)
    next[shownId] = true
    later = next
    advance()
  }

  onAlertsChanged: Qt.callLater(sync)
  onWaitingChanged: Qt.callLater(sync)

  Timer {
    id: armTimer
    interval: root.armDelayMs
    onTriggered: root.armed = true
  }

  // A finished card stays long enough to read, and while the pointer is on
  // it.
  Timer {
    interval: root.finishedDelayMs
    running: root.finished && !cardHover.hovered
    onTriggered: root.advance()
  }

  PanelWindow {
    visible: root.showWindow && !!root.shown
    // A full-screen, click-through surface, like the shell's OSD and
    // notifications: the card changes size inside it, the surface never
    // does. Normal exclusion keeps it below the bar.
    anchors { top: true; bottom: true; left: true; right: true }
    color: "transparent"
    exclusionMode: ExclusionMode.Normal
    WlrLayershell.namespace: "omarchy-security-threat"
    WlrLayershell.layer: WlrLayer.Overlay
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.None
    mask: Region { item: card }

    Rectangle {
      id: card
      anchors { top: parent.top; horizontalCenter: parent.horizontalCenter; topMargin: Style.gapsOut }
      width: Style.space(400)
      height: content.implicitHeight + Style.space(32)
      color: ThemeProvider.background
      // The theme's border, in the alert's colour and never hairline.
      border.color: root.shown ? ThemeProvider.role(Threat.stateRole(root.shown.state)) : ThemeProvider.border.color
      border.width: Math.max(2, ThemeProvider.border.width)
      radius: ThemeProvider.border.radius

      HoverHandler { id: cardHover }

      ColumnLayout {
        id: content
        anchors { left: parent.left; right: parent.right; top: parent.top; margins: Style.space(16) }
        spacing: Style.space(4)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(10)

          Text {
            textFormat: Text.PlainText
            text: ""  // nf-fa-exclamation_triangle
            color: card.border.color
            font.family: Style.font.family
            font.pixelSize: Style.font.heading
          }

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            elide: Text.ElideRight
            text: Threat.title(root.shown)
            color: ThemeProvider.text
            font.family: Style.font.family
            font.pixelSize: Style.font.body
            font.bold: true
          }

          Text {
            textFormat: Text.PlainText
            text: root.busy ? "Sending…" : root.shown ? Threat.stateLabel(root.shown.state) : ""
            color: root.busy ? ThemeProvider.dimText : card.border.color
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
          }
        }

        Text {
          Layout.fillWidth: true
          Layout.topMargin: Style.space(4)
          textFormat: Text.PlainText
          elide: Text.ElideRight
          text: Threat.programName(root.shown)
          color: ThemeProvider.text
          font.family: Style.font.family
          font.pixelSize: Style.font.subtitle
          font.bold: true
        }

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          elide: Text.ElideMiddle
          text: root.shown ? root.shown.binary_path : ""
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          textFormat: Text.PlainText
          wrapMode: Text.WrapAnywhere
          maximumLineCount: 3
          elide: Text.ElideRight
          text: root.shown ? Threat.commandLine(root.shown.argv) : ""
          color: ThemeProvider.text
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          textFormat: Text.PlainText
          text: Threat.processLine(root.shown)
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: Threat.droppedLine(root.shown)
          color: ThemeProvider.warning
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          visible: !root.finished
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: Threat.reason(root.shown)
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          visible: root.finished
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: root.shown ? Threat.outcomeText(root.shown.state) : ""
          color: card.border.color
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
        }

        RowLayout {
          Layout.fillWidth: true
          Layout.topMargin: Style.space(8)
          spacing: Style.space(6)

          Repeater {
            model: Threat.actionsFor(root.shown)

            Button {
              id: actionButton
              required property var modelData
              readonly property bool destructive: actionButton.modelData.id === "kill"

              bordered: true
              enabled: root.armed && !root.busy
              opacity: enabled ? 1 : 0.5
              text: actionButton.modelData.label
              tooltipText: actionButton.modelData.hint
              foreground: actionButton.destructive ? ThemeProvider.danger : ThemeProvider.foreground
              accent: actionButton.destructive ? ThemeProvider.danger : ThemeProvider.accent
              fontSize: Style.font.bodySmall
              onClicked: root.perform(actionButton.modelData.id)
            }
          }

          Item { Layout.fillWidth: true }

          Button {
            text: root.finished ? "Close" : "Later"
            tooltipText: root.finished ? "" : "Hide this alert; the program keeps running"
            foreground: ThemeProvider.dimText
            fontSize: Style.font.bodySmall
            onClicked: root.finished ? root.advance() : root.putOff()
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
          text: root.moreWaiting === 1 ? "1 more alert waiting" : root.moreWaiting + " more alerts waiting"
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }
      }
    }
  }
}
