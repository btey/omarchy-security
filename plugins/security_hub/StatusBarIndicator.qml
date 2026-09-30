// SPDX-License-Identifier: MIT
import QtQuick
import Quickshell
import qs.Commons
import qs.Ui
import "services"

// Bar entry point. Phase 1 shows only whether the daemon is reachable: a
// shield in the bar foreground when the handshake is done, dimmed when it
// is not. Threat and hardening colouring arrives with Phase 3.2.
BarWidget {
  id: root

  moduleName: "security-hub"

  readonly property var security: bar && bar.shell ? bar.shell.serviceFor(moduleName) : null
  readonly property bool ready: !!security && security.ready

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  function togglePanel() {
    if (bar && bar.shell && typeof bar.shell.toggle === "function")
      bar.shell.toggle(moduleName, "{}")
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: ""
    slotSize: Style.bar.statusSlot
    foreground: root.ready ? ThemeProvider.barForeground(root.bar) : ThemeProvider.barDimForeground(root.bar)
    tooltipText: root.ready
      ? "Security Hub · omarchy-securityd " + root.security.daemonVersion
      : "Security Hub · daemon not connected"
    onPressed: root.togglePanel()
  }
}
