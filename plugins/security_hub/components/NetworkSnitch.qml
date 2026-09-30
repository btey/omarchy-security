// SPDX-License-Identifier: MIT
pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Ui
import "../services"
import "../services/Network.js" as Network

// The hub's Network tab, mode-aware (plan tasks 3.6 and 3.10, §5.21):
//   * the mode banner and the switch between UFW and the Security Hub
//     firewall (FirewallModeBanner);
//   * the rules: UFW's, read-only, while UFW is on (UfwRules), and the
//     hub's own (HubRules), editable in every mode, with those UFW makes
//     inactive folded away in `ufw` mode and the fixed baseline in
//     `standalone` and `both`;
//   * blocked traffic, with Allow, Block and Mute (FirewallAlerts);
//   * the temporary decisions, with countdowns and Revoke (TempDecisions).
// The held-connection prompt is ConnectionPrompt.qml, an overlay.
Item {
  id: root

  property var security: null

  readonly property bool ready: !!security && security.ready
  readonly property string mode: ready ? security.firewallMode : ""
  readonly property var sections: Network.sections(mode, ready ? security.firewallInfo : null)

  // For the e2e test.
  property alias banner: banner
  property alias hubRules: hubRules
  property alias ufwRules: ufwRules
  property alias alerts: alerts
  property alias decisions: decisions

  implicitWidth: column.implicitWidth
  implicitHeight: column.implicitHeight

  ColumnLayout {
    id: column
    anchors { left: parent.left; right: parent.right }
    spacing: Style.space(14)

    FirewallModeBanner {
      id: banner
      Layout.fillWidth: true
      security: root.security
    }

    UfwRules {
      id: ufwRules
      Layout.fillWidth: true
      visible: root.sections.ufwRules
      security: root.security
    }

    HubRules {
      id: hubRules
      Layout.fillWidth: true
      security: root.security
      collapseInactive: root.sections.collapseInactive
      showBaseline: root.sections.baseline
    }

    PanelSeparator {
      Layout.fillWidth: true
      foreground: ThemeProvider.foreground
    }

    FirewallAlerts {
      id: alerts
      Layout.fillWidth: true
      security: root.security
      sample: root.sections.alertsSample
    }

    TempDecisions {
      id: decisions
      Layout.fillWidth: true
      security: root.security
    }
  }
}
