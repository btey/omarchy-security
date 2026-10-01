// SPDX-License-Identifier: MIT
//
// The shell tools/preview/capture.sh runs in a nested Hyprland: the hub
// against tools/mock-securityd.py, opened on each tab in turn. At each
// step it saves a screenshot and Hyprland's layer list (for the crop) in
// $CAPTURE_OUT, then a last pair with the hub closed, for the prompt and
// the threat alert, which SecurityIPC shows on their own.
import QtQuick
import Quickshell
import Quickshell.Io
import "hub"
import "hub/services"

ShellRoot {
  id: root

  readonly property string out: Quickshell.env("CAPTURE_OUT")
  readonly property var steps: ["overview", "threats", "usb", "tokens", "network", "vaults", "hardening", "osd"]
  property int step: -1

  SecurityIPC { id: ipc }

  // SecurityIPC loads the prompt and alert overlays once it has a shell.
  // They get one only for the last step, so they stay off the tab shots.
  QtObject {
    id: fakeShell
    function serviceFor(id) { return ipc }
    function summon(id, payload) {}
    function toggle(id, payload) {}
    function hide(id) {}
  }

  SecurityHub {
    id: hub
    service: ipc
  }

  function next() {
    step++
    if (step >= steps.length) return Qt.exit(0)
    var name = steps[step]
    if (name === "osd") {
      hub.close()
      ipc.shell = fakeShell
    }
    else hub.open(JSON.stringify({ tab: name }))
    settle.start()
  }

  // Long enough for the mock's prompts, alerts and lists to arrive.
  Timer {
    id: start
    interval: 5000
    running: ipc.ready
    onTriggered: root.next()
  }

  Timer {
    id: settle
    interval: 1500
    onTriggered: {
      var file = root.out + "/" + root.steps[root.step]
      shot.command = ["sh", "-c", 'grim -o CAP "$1.png" && hyprctl -j layers > "$1.json"', "sh", file]
      shot.running = true
    }
  }

  Process {
    id: shot
    onExited: function(code) {
      if (code !== 0) {
        console.log("CAPTURE failed at " + root.steps[root.step])
        Qt.exit(1)
      } else {
        console.log("CAPTURE " + root.steps[root.step])
        root.next()
      }
    }
  }
}
