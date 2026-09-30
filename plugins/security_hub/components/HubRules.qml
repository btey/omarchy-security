// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"
import "../services/Network.js" as Network
import "../services/Protocol.js" as Protocol

// The hub's own firewall rules, with Add and Remove (plan task 3.6, first
// part; docs/ipc-protocol.md §4.6), in the Network tab (NetworkSnitch.qml).
// The list lives in SecurityIPC; this view draws it and sends
// FIREWALL_ADD_RULE / FIREWALL_REMOVE_RULE.
//
// A rule the mode does not enforce says so, and the form refuses an
// inbound allow while UFW decides inbound traffic. In `ufw` mode
// (`collapseInactive`) the rules UFW makes inactive are folded into one
// group; in `standalone` and `both` (`showBaseline`) what the policy
// always allows is listed first, as fixed rows.
Item {
  id: root

  property var security: null
  property bool collapseInactive: false
  property bool showBaseline: false

  readonly property bool ready: !!security && security.ready
  readonly property var rules: ready ? security.firewallRules : []
  readonly property var shownRules: collapseInactive ? rules.filter(function(r) { return r.loaded !== false }) : rules
  readonly property var inactiveRules: collapseInactive ? rules.filter(function(r) { return r.loaded === false }) : []
  property bool inactiveOpen: false
  readonly property string mode: ready ? security.firewallMode : ""
  readonly property string emptyText: !ready ? "Not connected to omarchy-securityd"
    : security.firewallRulesError ? "Could not read the rules: " + (security.firewallRulesError.message || "unknown error")
    : rules.length === 0 ? "No saved rules yet."
    : ""

  // The add-rule form.
  property bool adding: false
  property var form: Network.blankForm()
  readonly property var check: Network.specFromForm(form, mode)
  // Only once something was typed: an empty form is not an error yet.
  readonly property string formError: form.address === "" && form.port === "" && form.executable === "" ? "" : check.error || ""
  property bool addBusy: false
  property string addError: ""

  // Per-rule state, by rule_id.
  property var busy: ({})
  property var errors: ({})
  // The rule whose Remove was clicked once, -1 for none.
  property int confirmingRemove: -1

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  function setEntry(map, key, value) {
    var next = Object.assign({}, map)
    if (value === undefined) delete next[key]
    else next[key] = value
    return next
  }

  function setField(name, value) {
    var next = Object.assign({}, form)
    next[name] = value
    // Only TCP and UDP have ports, and only outbound rules a program.
    if (name === "protocol" && value === "") next.port = ""
    if (name === "direction" && value === "inbound") next.executable = ""
    form = next
    addError = ""
  }

  function startAdding() {
    form = Network.blankForm()
    addError = ""
    adding = true
  }

  // Sends the form. Returns false when it cannot be sent.
  function submit() {
    if (!ready || addBusy || !check.spec) {
      if (check.error) addError = check.error
      return false
    }
    addBusy = true
    addError = ""
    security.addRule(check.spec, function(error) {
      root.addBusy = false
      if (error) {
        root.addError = Network.ruleErrorText(error)
        return
      }
      root.adding = false
      root.form = Network.blankForm()
    })
    return true
  }

  // Remove asks for a second click. Returns false when it only armed it
  // or could not be sent.
  function remove(ruleId) {
    if (!ready || busy[ruleId]) return false
    if (confirmingRemove !== ruleId) {
      confirmingRemove = ruleId
      confirmTimer.restart()
      return false
    }
    confirmingRemove = -1
    busy = setEntry(busy, ruleId, true)
    errors = setEntry(errors, ruleId, undefined)
    security.removeRule(ruleId, function(error) {
      root.busy = root.setEntry(root.busy, ruleId, undefined)
      if (error && error.code !== Protocol.ErrorCode.NOT_FOUND)
        root.errors = root.setEntry(root.errors, ruleId, Network.ruleErrorText(error))
    })
    return true
  }

  Timer {
    id: confirmTimer
    interval: 4000
    onTriggered: root.confirmingRemove = -1
  }

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(10)

    RowLayout {
      Layout.fillWidth: true

      PanelSectionHeader {
        Layout.fillWidth: true
        text: "Security Hub rules"
        foreground: ThemeProvider.foreground
      }

      Text {
        visible: root.mode !== ""
        textFormat: Text.PlainText
        text: Protocol.firewallModeLabel(root.mode)
        color: root.mode === "none" ? ThemeProvider.danger
          : root.mode === "both" ? ThemeProvider.warning : ThemeProvider.dimText
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }
    }

    // What the standalone policy allows whatever the rules say.
    ColumnLayout {
      Layout.fillWidth: true
      visible: root.showBaseline
      spacing: Style.space(2)

      Repeater {
        model: Network.BASELINE

        RowLayout {
          id: fixedRow
          required property string modelData
          Layout.fillWidth: true
          spacing: Style.space(10)

          Text {
            Layout.alignment: Qt.AlignTop
            textFormat: Text.PlainText
            text: "\u{F033E}"  // nf-md-lock
            color: ThemeProvider.dimText
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
          }

          Text {
            Layout.fillWidth: true
            textFormat: Text.PlainText
            wrapMode: Text.Wrap
            text: fixedRow.modelData
            color: ThemeProvider.dimText
            font.family: Style.font.family
            font.pixelSize: Style.font.caption
          }
        }
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
      model: root.shownRules
      delegate: ruleRow
    }

    // In ufw mode, the saved rules UFW makes inactive.
    Button {
      visible: root.inactiveRules.length > 0
      text: (root.inactiveOpen ? "Hide" : "Show") + " inactive while UFW is on (" + root.inactiveRules.length + ")"
      iconText: root.inactiveOpen ? "\u{F0140}" : "\u{F0142}"  // nf-md-chevron_down, chevron_right
      foreground: ThemeProvider.dimText
      fontSize: Style.font.caption
      onClicked: root.inactiveOpen = !root.inactiveOpen
    }

    Repeater {
      model: root.inactiveOpen ? root.inactiveRules : []
      delegate: ruleRow
    }

    Component {
      id: ruleRow

      ColumnLayout {
        id: row
        required property var modelData
        required property int index
        readonly property int ruleId: modelData.rule_id
        readonly property color roleColor: ThemeProvider.role(Network.ruleRole(modelData))
        readonly property bool rowBusy: !!root.busy[row.ruleId]
        readonly property bool confirming: root.confirmingRemove === row.ruleId

        Layout.fillWidth: true
        spacing: Style.space(4)

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
            text: row.modelData.verdict === "allow" ? "\u{F05E1}" : "\u{F073A}"
            color: row.roleColor
            font.family: Style.font.family
            font.pixelSize: Style.font.heading
          }

          ColumnLayout {
            Layout.fillWidth: true
            spacing: Style.space(1)

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              text: Network.ruleTitle(row.modelData)
              color: row.modelData.loaded === false ? ThemeProvider.dimText : ThemeProvider.text
              font.family: Style.font.family
              font.pixelSize: Style.font.bodySmall
            }

            Text {
              Layout.fillWidth: true
              visible: text !== ""
              textFormat: Text.PlainText
              elide: Text.ElideMiddle
              text: Network.ruleProgram(row.modelData) === "" ? "" : "Only " + Network.ruleProgram(row.modelData)
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              visible: text !== ""
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              text: Network.inactiveNote(row.modelData, root.mode)
              color: ThemeProvider.warning
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }

          Button {
            Layout.alignment: Qt.AlignTop
            bordered: row.confirming
            enabled: !row.rowBusy
            opacity: enabled ? 1 : 0.5
            text: row.rowBusy ? "Removing…" : row.confirming ? "Click again" : "Remove"
            tooltipText: row.confirming ? "" : "Delete this rule"
            foreground: ThemeProvider.danger
            accent: ThemeProvider.danger
            active: row.confirming
            fontSize: Style.font.caption
            onClicked: root.remove(row.ruleId)
          }
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: root.errors[row.ruleId] || ""
          color: ThemeProvider.danger
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

      }
    }

    Button {
      visible: !root.adding
      enabled: root.ready
      bordered: true
      text: "Add rule"
      iconText: "\u{F0415}"  // nf-md-plus
      foreground: ThemeProvider.foreground
      accent: ThemeProvider.accent
      fontSize: Style.font.bodySmall
      onClicked: root.startAdding()
    }

    // The form: what, which way, where, and optionally which port and
    // which program.
    ColumnLayout {
      Layout.fillWidth: true
      visible: root.adding
      spacing: Style.space(6)

      PanelSeparator {
        Layout.fillWidth: true
        foreground: ThemeProvider.foreground
      }

      Flow {
        Layout.fillWidth: true
        spacing: Style.space(8)

        ButtonGroup {
          options: [{ value: "block", label: "Block" }, { value: "allow", label: "Allow" }]
          value: root.form.verdict
          foreground: ThemeProvider.foreground
          accent: ThemeProvider.accent
          fontSize: Style.font.caption
          onChanged: function(value) { root.setField("verdict", value) }
        }

        ButtonGroup {
          options: [{ value: "outbound", label: "Outbound" }, { value: "inbound", label: "Inbound" }]
          value: root.form.direction
          foreground: ThemeProvider.foreground
          accent: ThemeProvider.accent
          fontSize: Style.font.caption
          onChanged: function(value) { root.setField("direction", value) }
        }
      }

      TextField {
        id: addressField
        Layout.fillWidth: true
        placeholderText: root.form.direction === "inbound" ? "From address, e.g. 192.168.1.0/24" : "To address, e.g. 203.0.113.7"
        text: root.form.address
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        font.pixelSize: Style.font.bodySmall
        onTextEdited: root.setField("address", text)
        onAccepted: root.submit()
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: Style.space(8)

        ButtonGroup {
          options: [{ value: "", label: "Any" }, { value: "tcp", label: "TCP" }, { value: "udp", label: "UDP" }]
          value: root.form.protocol
          foreground: ThemeProvider.foreground
          accent: ThemeProvider.accent
          fontSize: Style.font.caption
          onChanged: function(value) { root.setField("protocol", value) }
        }

        TextField {
          Layout.fillWidth: true
          enabled: root.form.protocol !== ""
          opacity: enabled ? 1 : 0.5
          placeholderText: enabled ? "Port (all if empty)" : "All ports"
          text: root.form.port
          inputMethodHints: Qt.ImhDigitsOnly
          maximumLength: 5
          foreground: ThemeProvider.foreground
          accent: ThemeProvider.accent
          font.pixelSize: Style.font.bodySmall
          onTextEdited: root.setField("port", text)
          onAccepted: root.submit()
        }
      }

      TextField {
        Layout.fillWidth: true
        visible: root.form.direction === "outbound"
        placeholderText: "Only for program (optional), e.g. /usr/bin/curl"
        text: root.form.executable
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        font.pixelSize: Style.font.bodySmall
        onTextEdited: root.setField("executable", text)
        onAccepted: root.submit()
      }

      Text {
        Layout.fillWidth: true
        visible: text !== ""
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        text: root.addError !== "" ? root.addError : root.formError !== "" ? root.formError : root.check.warning || ""
        color: root.addError !== "" || root.formError !== "" ? ThemeProvider.danger : ThemeProvider.warning
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: Style.space(6)

        Button {
          bordered: true
          enabled: !root.addBusy && !!root.check.spec
          opacity: enabled ? 1 : 0.5
          text: root.addBusy ? "Adding…" : "Add"
          foreground: ThemeProvider.foreground
          accent: ThemeProvider.accent
          fontSize: Style.font.bodySmall
          onClicked: root.submit()
        }

        Button {
          enabled: !root.addBusy
          text: "Cancel"
          foreground: ThemeProvider.dimText
          fontSize: Style.font.bodySmall
          onClicked: root.adding = false
        }

        Item { Layout.fillWidth: true }
      }
    }
  }
}
