// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"
import "../services/Token.js" as Token

// Security keys plugged in and what each can do (plan task 3.8;
// docs/ipc-protocol.md §4.4, plan §5.11). The list lives in SecurityIPC,
// from TOKEN_LIST and TOKEN_INSERTED / TOKEN_REMOVED; the touch requests
// it keeps give each key a line while one waits and for a while after.
// Read only: the daemon watches keys, it does not manage them.
Item {
  id: root

  property var security: null

  readonly property bool ready: !!security && security.ready
  readonly property var tokens: ready ? security.tokens : []
  readonly property var requests: ready ? security.touchRequests : []
  readonly property var moduleStatus: {
    if (!ready) return null
    for (var i = 0; i < security.modules.length; i++)
      if (security.modules[i].module === "token") return security.modules[i]
    return null
  }
  readonly property string moduleState: moduleStatus ? moduleStatus.state || "" : ""
  readonly property string moduleDetail: moduleStatus ? moduleStatus.detail || "" : ""
  readonly property string emptyText: Token.emptyText(ready, moduleState, moduleDetail,
    ready ? security.tokensError : null, tokens)

  // For "N min ago"; the requests' own changes update the rest.
  property real now: Date.now()

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  Timer {
    interval: 30000
    repeat: true
    running: root.visible && root.tokens.length > 0
    onTriggered: root.now = Date.now()
  }

  onRequestsChanged: now = Date.now()

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(10)

    PanelSectionHeader {
      Layout.fillWidth: true
      text: "Security keys"
      foreground: ThemeProvider.foreground
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

    // A degraded module still lists keys, but some prompts are off.
    Text {
      Layout.fillWidth: true
      visible: root.ready && root.moduleState === "degraded" && root.moduleDetail !== ""
      textFormat: Text.PlainText
      wrapMode: Text.Wrap
      text: root.moduleDetail
      color: ThemeProvider.warning
      font.family: Style.font.family
      font.pixelSize: Style.font.caption
    }

    Repeater {
      id: rows
      model: root.tokens

      ColumnLayout {
        id: row
        required property var modelData
        required property int index
        readonly property var latest: Token.latestRequest(root.requests, modelData.token_id, root.now)
        readonly property var request: Token.requestLine(latest, root.now)
        readonly property string note: Token.touchNote(modelData)

        Layout.fillWidth: true
        spacing: Style.space(4)

        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(10)

          Text {
            Layout.alignment: Qt.AlignTop
            textFormat: Text.PlainText
            text: "\u{F0306}"  // nf-md-key
            // Amber while the key waits for a touch.
            color: row.latest && !row.latest.outcome ? ThemeProvider.warning : ThemeProvider.accent
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
                text: row.modelData.name || Token.kindLabel(row.modelData.kind)
                color: ThemeProvider.text
                font.family: Style.font.family
                font.pixelSize: Style.font.bodySmall
              }

              Text {
                textFormat: Text.PlainText
                text: Token.kindLabel(row.modelData.kind)
                color: ThemeProvider.dimText
                font.family: Style.font.family
                font.pixelSize: Style.font.caption
              }
            }

            Text {
              Layout.fillWidth: true
              textFormat: Text.PlainText
              elide: Text.ElideRight
              text: Token.idLine(row.modelData)
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Flow {
              Layout.fillWidth: true
              Layout.topMargin: Style.space(3)
              spacing: Style.space(4)

              Repeater {
                model: row.modelData.capabilities || []

                Rectangle {
                  id: chip
                  required property string modelData
                  implicitWidth: chipText.implicitWidth + Style.space(12)
                  implicitHeight: chipText.implicitHeight + Style.space(4)
                  radius: Style.cornerRadius > 0 ? height / 2 : 0
                  color: "transparent"
                  border.width: 1
                  border.color: ThemeProvider.accent

                  Text {
                    id: chipText
                    anchors.centerIn: parent
                    textFormat: Text.PlainText
                    text: Token.capabilityLabel(chip.modelData)
                    color: ThemeProvider.accent
                    font.family: Style.font.family
                    font.pixelSize: Style.font.caption
                  }

                  HoverHandler { id: chipHover }

                  PanelToolTip {
                    visible: chipHover.hovered && text !== ""
                    text: Token.capabilityHint(chip.modelData)
                  }
                }
              }
            }

            Text {
              Layout.fillWidth: true
              visible: !!row.request
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              text: row.request ? row.request.text : ""
              color: row.request ? ThemeProvider.role(row.request.role) : ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }

            Text {
              Layout.fillWidth: true
              visible: row.note !== ""
              textFormat: Text.PlainText
              wrapMode: Text.Wrap
              text: row.note
              color: ThemeProvider.dimText
              font.family: Style.font.family
              font.pixelSize: Style.font.caption
            }
          }
        }

        PanelSeparator {
          Layout.fillWidth: true
          visible: row.index < rows.count - 1
          foreground: ThemeProvider.foreground
        }
      }
    }
  }
}
