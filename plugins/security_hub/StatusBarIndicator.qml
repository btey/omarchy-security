// SPDX-License-Identifier: MIT
import QtQuick
import Quickshell
import qs.Commons
import qs.Ui
import "services"
import "services/Indicator.js" as Indicator
import "services/Protocol.js" as Protocol

// Bar entry point (plan §5.21). A shield whose colour follows the firewall
// mode: the bar foreground for `ufw` and `standalone`, warning for `both`,
// danger for `none`, dimmed for `unknown` and while the daemon is not
// connected. A badge counts the blocked-traffic alerts the user has not
// seen yet. Clicking opens the hub on the Network tab, which clears it.
BarWidget {
  id: root

  moduleName: "security-hub"

  readonly property var security: bar && bar.shell ? bar.shell.serviceFor(moduleName) : null
  readonly property bool ready: !!security && security.ready
  readonly property string firewallMode: ready ? security.firewallMode : ""
  readonly property int unseenAlerts: ready ? security.unseenAlertCount : 0

  readonly property var status: Indicator.summarize({
    ready: ready,
    mode: firewallMode,
    modeLabel: Protocol.firewallModeLabel(firewallMode),
    unseen: unseenAlerts
  })

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  function togglePanel() {
    if (bar && bar.shell && typeof bar.shell.toggle === "function")
      bar.shell.toggle(moduleName, JSON.stringify({ tab: "network" }))
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "\uf132"  // nf-fa-shield
    slotSize: Style.bar.statusSlot
    foreground: ThemeProvider.barRoleColor(root.bar, root.status.role)
    tooltipText: root.status.tooltip
    onPressed: root.togglePanel()
  }

  // Drawn over the shield's top-right corner. It takes no input, so a
  // click on it reaches the button.
  Rectangle {
    id: badge
    visible: root.status.badge !== ""
    anchors { top: parent.top; right: parent.right; topMargin: Style.space(1) }
    height: badgeLabel.font.pixelSize + Style.space(2)
    width: Math.max(height, Math.round(badgeLabel.contentWidth + Style.space(3)))
    // Pill on rounded themes, square on sharp ones, like qs.Ui toggles.
    radius: ThemeProvider.border.radius > 0 ? height / 2 : 0
    color: ThemeProvider.accent

    Text {
      id: badgeLabel
      anchors.centerIn: parent
      text: root.status.badge
      color: ThemeProvider.onAccent
      font.family: Style.font.family
      font.pixelSize: Math.max(7, Style.font.caption - 3)
      font.bold: true
    }
  }
}
