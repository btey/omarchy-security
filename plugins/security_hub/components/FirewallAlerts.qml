// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"
import "../services/Hub.js" as Hub
import "../services/Network.js" as Network
import "../services/Protocol.js" as Protocol

// Blocked traffic (plan task 3.10, §5.21): the FIREWALL_ALERT list, newest
// first, with Allow and Block for the duration picked above the list
// (FIREWALL_TEMP_ADD, the spec built from the alert), and Mute
// (FIREWALL_ALERT_MUTE, which stops the desktop notifications for that
// kind of packet). An inbound Allow asks for the password, and can be
// widened to any source. A blocked packet was already dropped; Allow is
// for the next ones.
Item {
  id: root

  property var security: null
  // In UFW mode the alerts are a sample; say so.
  property bool sample: false
  // Rows shown; the rest are counted.
  property int limit: 15

  readonly property bool ready: !!security && security.ready
  readonly property var alerts: ready ? security.firewallAlerts : []
  readonly property var shown: alerts.slice(0, limit)
  readonly property var durations: ready ? security.tempDurations : Network.DEFAULT_DURATIONS
  // The duration picked above the list, in seconds.
  property int duration: 0
  readonly property int effectiveDuration: durations.indexOf(duration) >= 0 ? duration
    : durations.indexOf(3600) >= 0 ? 3600 : durations[0]
  readonly property var moduleStatus: {
    if (!ready) return null
    for (var i = 0; i < security.modules.length; i++)
      if (security.modules[i].module === "firewall") return security.modules[i]
    return null
  }
  // "blocked-traffic alerts are off: …" when the journal cannot be read.
  readonly property string alertsOff: moduleStatus && moduleStatus.state === "degraded"
    && /alerts are off/.test(moduleStatus.detail || "") ? moduleStatus.detail : ""

  property real now: Date.now()

  // Per alert, by alert_id.
  property var busy: ({})
  property var errors: ({})
  property var anySource: ({})

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  function setEntry(map, key, value) {
    var next = Object.assign({}, map)
    if (value === undefined) delete next[key]
    else next[key] = value
    return next
  }

  function findAlert(alertId) {
    for (var i = 0; i < alerts.length; i++) if (alerts[i].alert_id === alertId) return alerts[i]
    return null
  }

  // The spec Allow or Block sends for this alert, or null.
  function specFor(alert, verdict) {
    return Protocol.specFromAlert(alert, verdict, !!anySource[alert.alert_id])
  }

  // `action` is "allow", "block" or "mute", for `effectiveDuration`.
  // Returns true when the request was sent.
  function act(alertId, action) {
    var alert = findAlert(alertId)
    if (!alert || busy[alertId]) return false
    var secs = effectiveDuration
    var finish = function(error) {
      root.busy = root.setEntry(root.busy, alertId, undefined)
      if (error) root.errors = root.setEntry(root.errors, alertId, Network.tempErrorText(error))
    }
    if (action === "mute") {
      busy = setEntry(busy, alertId, "mute")
      errors = setEntry(errors, alertId, undefined)
      security.muteAlert(alertId, secs, finish)
      return true
    }
    var spec = specFor(alert, action)
    if (!spec) return false
    busy = setEntry(busy, alertId, action)
    errors = setEntry(errors, alertId, undefined)
    security.addTemp(spec, secs, alertId, function(error) { finish(error) })
    return true
  }

  onAlertsChanged: now = Date.now()

  Timer {
    interval: 1000
    repeat: true
    running: root.visible && root.shown.length > 0
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
        text: "Blocked traffic"
        foreground: ThemeProvider.foreground
      }

      Text {
        visible: root.alerts.length > 0
        textFormat: Text.PlainText
        text: root.alerts.length + (root.alerts.length === 1 ? " alert" : " alerts")
        color: ThemeProvider.dimText
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }
    }

    Text {
      Layout.fillWidth: true
      visible: text !== ""
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: !root.ready ? "Not connected to omarchy-securityd"
        : root.alertsOff !== "" ? root.alertsOff
        : root.alerts.length === 0 ? "No blocked traffic since the daemon started."
        : ""
      color: root.alertsOff !== "" ? ThemeProvider.warning : ThemeProvider.dimText
      font.family: Style.font.family
      font.pixelSize: Style.font.bodySmall
    }

    Text {
      Layout.fillWidth: true
      visible: root.shown.length > 0
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: "These packets were already dropped; Allow lets the next ones through."
        + (root.sample ? " UFW logs only a sample, about 3 blocked packets a minute." : "")
      color: ThemeProvider.dimText
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
    }

    RowLayout {
      Layout.fillWidth: true
      visible: root.shown.length > 0
      spacing: Style.space(8)

      Text {
        textFormat: Text.PlainText
        text: "For"
        color: ThemeProvider.dimText
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }

      ButtonGroup {
        options: root.durations.map(function(s) { return { value: String(s), label: Network.durationLabel(s) } })
        value: String(root.effectiveDuration)
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        fontSize: Style.font.caption
        onChanged: function(value) { root.duration = Number(value) }
      }

      Item { Layout.fillWidth: true }
    }

    Repeater {
      model: root.shown

      ColumnLayout {
        id: row
        required property var modelData
        required property int index
        readonly property int alertId: modelData.alert_id
        readonly property var allowSpec: root.specFor(modelData, "allow")
        readonly property var decision: Network.decisionForAlert(root.ready ? root.security.tempDecisions : [], alertId, root.now)
        readonly property bool muted: Network.isMuted(modelData, root.now)
        readonly property string rowBusy: root.busy[alertId] || ""

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
            text: "\u{F073A}"  // nf-md-cancel
            color: row.muted ? ThemeProvider.dimText : ThemeProvider.warning
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
              text: Hub.firewallTitle(row.modelData)
              color: ThemeProvider.text
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              elide: Text.ElideRight
              text: Hub.firewallDetail(row.modelData, root.now) + " · " + Hub.ago(root.now - row.modelData.last_seen)
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              visible: row.decision !== null
              textFormat: Text.PlainText
              text: Network.decisionNote(row.decision, root.now)
              color: row.decision && row.decision.spec.verdict === "allow" ? ThemeProvider.success : ThemeProvider.danger
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }
        }

        Flow {
          Layout.fillWidth: true
          spacing: Style.space(6)
          enabled: row.rowBusy === ""
          opacity: enabled ? 1 : 0.5

          Button {
            visible: row.allowSpec !== null
            bordered: true
            text: row.rowBusy === "allow" ? "Allowing…" : "Allow"
            iconText: Protocol.needsPassword(row.allowSpec) ? "\u{F033E}" : ""  // nf-md-lock
            tooltipText: "Let the next packets like this through for " + Network.durationLabel(root.effectiveDuration)
              + (Protocol.needsPassword(row.allowSpec) ? " (asks for the password)" : "")
            foreground: ThemeProvider.foreground
            accent: ThemeProvider.accent
            fontSize: Style.font.caption
            onClicked: root.act(row.alertId, "allow")
          }

          Button {
            visible: row.allowSpec !== null
            bordered: true
            text: row.rowBusy === "block" ? "Blocking…" : "Block"
            tooltipText: "Block this for " + Network.durationLabel(root.effectiveDuration)
              + ", even replies to open connections"
            foreground: ThemeProvider.danger
            accent: ThemeProvider.danger
            fontSize: Style.font.caption
            onClicked: root.act(row.alertId, "block")
          }

          Button {
            visible: !row.muted
            bordered: true
            text: row.rowBusy === "mute" ? "Muting…" : "Mute"
            tooltipText: "Keep blocking, and stop the notifications for " + Network.durationLabel(root.effectiveDuration)
            foreground: ThemeProvider.dimText
            accent: ThemeProvider.accent
            fontSize: Style.font.caption
            onClicked: root.act(row.alertId, "mute")
          }

          // Only an inbound alert names one source to widen.
          Button {
            visible: row.allowSpec !== null && row.modelData.direction === "inbound"
            selected: !!root.anySource[row.alertId]
            text: "Any source"
            tooltipText: "Allow or block from every address, not only " + row.modelData.src
            foreground: ThemeProvider.dimText
            accent: ThemeProvider.accent
            fontSize: Style.font.caption
            onClicked: root.anySource = root.setEntry(root.anySource, row.alertId, root.anySource[row.alertId] ? undefined : true)
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
      }
    }

    Text {
      Layout.fillWidth: true
      visible: root.alerts.length > root.shown.length
      textFormat: Text.PlainText
      text: "and " + (root.alerts.length - root.shown.length) + " older"
      color: ThemeProvider.dimText
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
    }
  }
}
