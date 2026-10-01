// SPDX-License-Identifier: MIT
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"

// One line above the tabs while the update check (services/Update.js) has
// found a newer version of the plugin, with a button that runs
// `omarchy plugin update` in a terminal. After that update, BackendSetup
// offers the matching backend.
Item {
  id: root

  property var security: null
  // Set by the click, until the shell reloads the updated plugin.
  property bool launched: false

  readonly property string version: security && security.updateChecks ? security.pluginUpdate : ""

  visible: version !== ""
  implicitWidth: column.implicitWidth
  implicitHeight: visible ? column.implicitHeight : 0

  onVersionChanged: launched = false

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(8)

    Text {
      Layout.fillWidth: true
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: "Security Hub " + root.version + " is available"
        + (root.security && root.security.pluginVersion ? " (you have " + root.security.pluginVersion + ")" : "")
      color: ThemeProvider.accent
      font.family: Style.font.family
      font.pixelSize: Style.font.bodySmall
    }

    RowLayout {
      Layout.fillWidth: true
      spacing: Style.space(8)

      Button {
        bordered: true
        text: "Update plugin"
        tooltipText: "Opens a terminal that runs omarchy plugin update "
          + (root.security ? root.security.pluginId : "security-hub")
        foreground: ThemeProvider.foreground
        accent: ThemeProvider.accent
        fontSize: Style.font.bodySmall
        onClicked: {
          root.security.updatePlugin()
          root.launched = true
        }
      }

      Text {
        Layout.fillWidth: true
        visible: root.launched
        textFormat: Text.PlainText
        wrapMode: Text.Wrap
        text: "It shows the changes and asks before it applies them."
        color: ThemeProvider.dimText
        font.family: Style.font.family
        font.pixelSize: Style.font.caption
      }
    }
  }
}
