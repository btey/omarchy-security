// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import Quickshell
import qs.Commons
import qs.Ui
import "../services"
import "../services/Vault.js" as Vault

// Encrypted vaults with Mount / Unmount, and Panic (plan task 3.7;
// docs/ipc-protocol.md §4.5, plan §5.11). The list lives in SecurityIPC,
// which follows VAULT_STATE_CHANGED, so a vault mounted outside the hub
// shows as open too.
//
// This view never asks for a passphrase: the daemon opens pinentry and
// reads it there. Panic needs a second click within 4 s; it stops the
// programs using the vaults, unmounts and locks all of them, and closes a
// passphrase prompt that is open.
//
// "Add vault" makes a new gocryptfs vault (VAULT_CREATE; the daemon asks
// for its passphrase with pinentry, typed twice) or registers an existing
// gocryptfs folder or LUKS disk (VAULT_ADD), and Remove, after a second
// click, takes one out (VAULT_REMOVE). The daemon writes
// ~/.config/omarchy-security/config.toml for all three; Remove leaves the
// encrypted data where it is.
Item {
  id: root

  property var security: null

  readonly property bool ready: !!security && security.ready
  readonly property var vaults: ready ? security.vaults : []
  readonly property var ops: ready ? security.vaultOps : ({})
  readonly property string home: Quickshell.env("HOME") || ""
  readonly property var moduleStatus: {
    if (!ready) return null
    for (var i = 0; i < security.modules.length; i++)
      if (security.modules[i].module === "vault") return security.modules[i]
    return null
  }
  readonly property string moduleState: moduleStatus ? moduleStatus.state || "" : ""
  readonly property string moduleDetail: moduleStatus ? moduleStatus.detail || "" : ""
  readonly property string emptyText: Vault.emptyText(ready, moduleState, moduleDetail,
    ready ? security.vaultsError : null, vaults)

  // Mount and Unmount errors, by vault_id: { action, error, mounted }. One
  // is shown only while the vault is still as it was when it failed, so a
  // vault since unmounted by Panic or elsewhere drops its "still in use".
  property var errors: ({})

  property bool confirmingPanic: false
  property bool panicBusy: false
  property var panicResult: null
  property string panicError: ""
  // Panic also closes the new passphrase's prompt.
  readonly property bool panicAvailable: Vault.canPanic(vaults, ops) || creating
  readonly property var panicSummary: Vault.panicSummary(panicResult, vaults)

  // The add form, while it is open.
  readonly property bool canEdit: ready && moduleState !== "not_implemented"
  property bool adding: false
  readonly property var emptyForm: ({ kind: "create", name: "", source: "", mountPoint: "" })
  property var form: emptyForm
  readonly property var addCheck: Vault.checkAddForm(form, vaults)
  property bool addBusy: false
  readonly property bool creating: addBusy && addCheck.method === "VAULT_CREATE"
  property string addError: ""

  // Remove asks for a second click, like Panic; errors by vault_id.
  property string confirmingRemove: ""
  property string removing: ""
  property var removeErrors: ({})

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  function setField(name, value) {
    var next = Object.assign({}, form)
    next[name] = value
    form = next
    addError = ""
  }

  function openForm() {
    form = emptyForm
    addError = ""
    adding = true
  }

  function closeForm() {
    adding = false
    form = emptyForm
    addError = ""
  }

  // Sends VAULT_ADD. Returns false when the form cannot be sent.
  function addVault() {
    if (!canEdit || addBusy || !addCheck.params) return false
    addBusy = true
    addError = ""
    var method = addCheck.method
    security.addVault(method, addCheck.params, function(error) {
      root.addBusy = false
      if (error) root.addError = Vault.addErrorText(error, method)
      else root.closeForm()
    })
    return true
  }

  function setRemoveError(vaultId, text) {
    var next = Object.assign({}, removeErrors)
    if (text) next[vaultId] = text
    else delete next[vaultId]
    removeErrors = next
  }

  // The first click arms Remove, the second sends it. Returns true only
  // when it was sent.
  function remove(vaultId) {
    var vault = Vault.findVault(vaults, vaultId)
    if (!canEdit || !vault || removing !== "" || ops[vaultId] || Vault.isMounted(vault)) return false
    if (confirmingRemove !== vaultId) {
      confirmingRemove = vaultId
      removeTimer.restart()
      return false
    }
    confirmingRemove = ""
    removeTimer.stop()
    removing = vaultId
    setRemoveError(vaultId, "")
    security.removeVault(vaultId, function(error) {
      root.removing = ""
      if (error) root.setRemoveError(vaultId, Vault.removeErrorText(error))
      else root.setRemoveError(vaultId, "")
    })
    return true
  }

  function setError(vaultId, error) {
    var next = Object.assign({}, errors)
    if (error) next[vaultId] = error
    else delete next[vaultId]
    errors = next
  }

  // The error to show under `vaultId`, or null.
  function errorFor(vaultId) {
    var failure = errors[vaultId]
    return failure && failure.mounted === Vault.isMounted(Vault.findVault(vaults, vaultId)) ? failure : null
  }

  // Mounts or unmounts `vaultId`, whichever it needs. Returns false when
  // it could not be sent.
  function toggle(vaultId) {
    var vault = Vault.findVault(vaults, vaultId)
    if (!ready || !vault || ops[vaultId]) return false
    var action = Vault.isMounted(vault) ? "unmount" : "mount"
    setError(vaultId, null)
    return security.vaultOp(vaultId, action, function(error) {
      if (error) root.setError(vaultId, { action: action, error: error, mounted: action === "unmount" })
    })
  }

  // The first click arms Panic, the second sends it. Returns true only
  // when it was sent.
  function panic() {
    if (!ready || panicBusy) return false
    if (!confirmingPanic) {
      if (!panicAvailable) return false
      confirmingPanic = true
      panicTimer.restart()
      return false
    }
    confirmingPanic = false
    panicTimer.stop()
    panicBusy = true
    panicResult = null
    panicError = ""
    security.panicVaults(function(error, result) {
      root.panicBusy = false
      if (error) root.panicError = Vault.panicErrorText(error)
      else root.panicResult = result || { unmounted: [], lazy: [], failed: [] }
    })
    return true
  }

  Timer {
    id: panicTimer
    interval: Vault.PANIC_CONFIRM_MS
    onTriggered: root.confirmingPanic = false
  }

  Timer {
    id: removeTimer
    interval: Vault.PANIC_CONFIRM_MS
    onTriggered: root.confirmingRemove = ""
  }

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(10)

    RowLayout {
      Layout.fillWidth: true

      PanelSectionHeader {
        Layout.fillWidth: true
        text: "Vaults"
        foreground: ThemeProvider.foreground
      }

      Button {
        visible: root.canEdit && !root.adding
        bordered: true
        text: "Add vault"
        iconText: "\u{F0415}"  // nf-md-plus
        tooltipText: "Create an encrypted vault, or add one you already have"
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        fontSize: Style.font.caption
        onClicked: root.openForm()
      }

      Button {
        visible: root.vaults.length > 0
        bordered: true
        active: root.confirmingPanic
        enabled: !root.panicBusy && (root.panicAvailable || root.confirmingPanic)
        opacity: enabled ? 1 : 0.5
        text: root.panicBusy ? "Locking…" : root.confirmingPanic ? "Click again to lock all" : "Panic"
        iconText: "\u{F033E}"  // nf-md-lock
        tooltipText: root.confirmingPanic ? "" : root.panicAvailable
          ? "Stop the programs using the vaults, then unmount and lock every vault"
          : "No vault is open"
        foreground: ThemeProvider.danger
        accent: ThemeProvider.danger
        fontSize: Style.font.caption
        onClicked: root.panic()
      }
    }

    Text {
      Layout.fillWidth: true
      visible: root.confirmingPanic
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: "Programs with files open in a vault are stopped, and unsaved work in them is lost."
      color: ThemeProvider.danger
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
    }

    // The add form.
    ColumnLayout {
      Layout.fillWidth: true
      visible: root.adding
      spacing: Style.space(6)

      Text {
        Layout.fillWidth: true
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        text: root.form.kind === "create"
          ? "Create an encrypted folder (gocryptfs). You choose its passphrase in a separate window; it is asked for each time you mount the vault, and never stored."
          : "Add an encrypted folder (gocryptfs) or disk (LUKS) you already have. Its passphrase is asked for each time you mount it, and never stored."
        color: ThemeProvider.dimText
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }

      TextField {
        Layout.fillWidth: true
        placeholderText: "Name, e.g. Work documents"
        text: root.form.name
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        font.pixelSize: Style.font.bodySmall
        onTextEdited: root.setField("name", text)
        onAccepted: root.addVault()
      }

      Flow {
        Layout.fillWidth: true
        spacing: Style.space(6)

        Repeater {
          model: Vault.FORM_KINDS

          Button {
            required property var modelData
            bordered: true
            enabled: !root.addBusy
            active: root.form.kind === modelData.id
            text: modelData.label
            foreground: ThemeProvider.foreground
            accent: ThemeProvider.accent
            fontSize: Style.font.caption
            onClicked: root.setField("kind", modelData.id)
          }
        }
      }

      TextField {
        Layout.fillWidth: true
        placeholderText: root.form.kind === "luks"
          ? "Image or disk, e.g. ~/Vaults/backup.img or /dev/disk/by-uuid/…"
          : root.form.kind === "create"
          ? "Encrypted files in (default " + root.addCheck.source + ")"
          : "Encrypted folder, e.g. ~/Vaults/work.enc"
        text: root.form.source
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        font.pixelSize: Style.font.bodySmall
        onTextEdited: root.setField("source", text)
        onAccepted: root.addVault()
      }

      TextField {
        Layout.fillWidth: true
        visible: root.form.kind !== "luks"
        placeholderText: "Open it at (default " + root.addCheck.mountPoint + ")"
        text: root.form.mountPoint
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        font.pixelSize: Style.font.bodySmall
        onTextEdited: root.setField("mountPoint", text)
        onAccepted: root.addVault()
      }

      Text {
        Layout.fillWidth: true
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        text: root.creating ? "Choose the passphrase in the passphrase window, and type it twice."
          : root.form.kind === "luks" ? "udisks2 chooses where it opens, under /run/media."
          : root.form.kind === "create" ? "The folder must be new or empty. Keep the passphrase safe: without it the files cannot be recovered."
          : "The folder must already hold a gocryptfs vault (gocryptfs.conf)."
        color: ThemeProvider.dimText
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }

      Text {
        Layout.fillWidth: true
        visible: text !== ""
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        text: root.addError !== "" ? root.addError : root.addCheck.error
        color: ThemeProvider.danger
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }

      RowLayout {
        Layout.fillWidth: true
        spacing: Style.space(8)

        Button {
          bordered: true
          enabled: !root.addBusy && !!root.addCheck.params
          opacity: enabled ? 1 : 0.5
          text: root.creating ? "Waiting for the passphrase…" : root.addBusy ? "Adding…"
            : root.form.kind === "create" ? "Create" : "Add"
          foreground: ThemeProvider.foreground
          accent: ThemeProvider.accent
          fontSize: Style.font.caption
          onClicked: root.addVault()
        }

        Button {
          enabled: !root.addBusy
          text: "Cancel"
          foreground: ThemeProvider.dimText
          accent: ThemeProvider.accent
          fontSize: Style.font.caption
          onClicked: root.closeForm()
        }
      }

      PanelSeparator {
        Layout.fillWidth: true
        visible: root.vaults.length > 0
        foreground: ThemeProvider.foreground
      }
    }

    Text {
      Layout.fillWidth: true
      visible: root.emptyText !== "" && !root.adding
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: root.emptyText
      color: ThemeProvider.dimText
      font.family: Style.font.family
      font.pixelSize: Style.font.bodySmall
    }

    // Some backends are missing: their vaults say so when used.
    Text {
      Layout.fillWidth: true
      visible: root.emptyText === "" && root.moduleState === "degraded" && root.moduleDetail !== ""
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: root.moduleDetail
      color: ThemeProvider.warning
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
    }

    Repeater {
      id: rows
      model: root.vaults

      ColumnLayout {
        id: row
        required property var modelData
        required property int index
        readonly property string vaultId: modelData.vault_id
        readonly property string op: root.ops[row.vaultId] || ""
        readonly property bool mounted: Vault.isMounted(modelData)
        readonly property var failure: root.errorFor(row.vaultId)
        readonly property color roleColor: ThemeProvider.role(Vault.vaultRole(modelData))

        Layout.fillWidth: true
        spacing: Style.space(4)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(10)

          Text {
            Layout.alignment: Qt.AlignTop
            textFormat: Text.PlainText
            // nf-md-lock_open, nf-md-lock
            text: row.mounted ? "\u{F033F}" : "\u{F033E}"
            color: row.roleColor
            font.family: Style.font.family
            font.pixelSize: Style.font.heading
          }

          ColumnLayout {
            Layout.fillWidth: true
            spacing: Style.space(1)

            RowLayout {
              Layout.fillWidth: true

              Text {
                Layout.fillWidth: true
                textFormat: Text.PlainText
                elide: Text.ElideRight
                text: row.modelData.name || row.vaultId
                color: ThemeProvider.text
                font.family: Style.font.family
                font.pixelSize: Style.font.bodySmall
              }

              Text {
                textFormat: Text.PlainText
                text: Vault.backendLabel(row.modelData.backend)
                color: ThemeProvider.dimText
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
              }
            }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              elide: Text.ElideMiddle
              text: Vault.stateText(row.modelData, row.op, root.home)
              color: row.mounted && row.op === "" ? row.roleColor : ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              visible: row.op === "mount"
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              text: "Enter it in the passphrase window."
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }

          Button {
            Layout.alignment: Qt.AlignTop
            bordered: true
            enabled: row.op === "" && !root.panicBusy
            opacity: enabled ? 1 : 0.5
            text: row.op === "mount" ? "Mounting…" : row.op === "unmount" ? "Unmounting…"
              : row.mounted ? "Unmount" : "Mount"
            tooltipText: row.op !== "" ? "" : row.mounted ? "Unmount and lock this vault"
              : "Asks for the passphrase in a separate window"
            foreground: ThemeProvider.foreground
            accent: ThemeProvider.accent
            fontSize: Style.font.caption
            onClicked: root.toggle(row.vaultId)
          }

          Button {
            Layout.alignment: Qt.AlignTop
            visible: root.canEdit
            readonly property bool confirming: root.confirmingRemove === row.vaultId
            bordered: confirming
            enabled: row.op === "" && !row.mounted && root.removing === "" && !root.panicBusy
            opacity: enabled ? 1 : 0.5
            text: root.removing === row.vaultId ? "Removing…" : confirming ? "Click again" : "Remove"
            tooltipText: row.mounted ? "Unmount it before removing it"
              : confirming ? "" : "Remove from the hub; the encrypted files are kept"
            foreground: ThemeProvider.danger
            accent: ThemeProvider.danger
            active: confirming
            fontSize: Style.font.caption
            onClicked: root.remove(row.vaultId)
          }
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: root.removeErrors[row.vaultId] || ""
          color: ThemeProvider.danger
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        Text {
          Layout.fillWidth: true
          visible: text !== ""
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: row.failure ? Vault.opErrorText(row.failure.error, row.failure.action) : ""
          color: ThemeProvider.role(Vault.opErrorRole(row.failure ? row.failure.error : null))
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }

        PanelSeparator {
          Layout.fillWidth: true
          visible: row.index < rows.count - 1
          foreground: ThemeProvider.foreground
        }
      }
    }

    // What the last panic did.
    ColumnLayout {
      Layout.fillWidth: true
      visible: root.panicSummary.title !== "" || root.panicError !== ""
      spacing: Style.space(2)

      Text {
        Layout.fillWidth: true
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        text: root.panicError !== "" ? root.panicError : root.panicSummary.title
        color: root.panicError !== "" ? ThemeProvider.danger : ThemeProvider.role(root.panicSummary.role)
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
        font.bold: true
      }

      Repeater {
        model: root.panicError !== "" ? [] : root.panicSummary.lines

        Text {
          required property string modelData
          Layout.fillWidth: true
          textFormat: Text.PlainText
          wrapMode: Text.Wrap
          text: modelData
          color: ThemeProvider.dimText
          font.family: Style.font.family
          font.pixelSize: Style.font.caption
        }
      }
    }
  }
}
