// SPDX-License-Identifier: MIT
//
// Headless end-to-end check, run by tools/qml-e2e.sh against
// tools/mock-securityd.py. Loads the plugin's QML in a private Quickshell
// instance, never opens a window, and exits 0 only when handshake,
// subscription, events, requests, and error responses all behaved.
import QtQuick
import Quickshell
import Quickshell.Io
import "hub"
import "hub/services"
import "hub/components"
import "hub/services/Usb.js" as Usb
import "hub/services/Threat.js" as Threat
import "hub/services/Touch.js" as Touch
import "hub/services/Network.js" as Network
import "hub/services/Vault.js" as Vault
import "hub/services/Token.js" as Token
import "hub/services/Sandbox.js" as Sandbox
import "hub/services/Hub.js" as Hub

ShellRoot {
  id: root

  property var passed: ({})
  readonly property var expected: ["ready", "event", "setPolicy", "notImplemented", "policyChanged", "theme",
    "firewallMode", "badge", "seen", "usbList", "usbConfirm", "usbReject", "usbSave",
    "threatArmed", "threatIsolate", "threatLater", "threatKill", "threatStale",
    "touchWaiting", "touchTouched", "touchTimedOut", "touchRemoved", "touchCleared",
    "rulesListed", "ruleForm", "ruleAdded", "ruleRemoved",
    "promptQueued", "promptAlways", "promptTimeout", "postureShown", "postureRefresh",
    "vaultsListed", "vaultMounted", "vaultUnmounted", "vaultBusy", "vaultCancelled", "vaultPanic",
    "vaultAddRejected", "vaultAdded", "vaultRemoved", "vaultCreated", "vaultCreateCancelled",
    "tokensListed", "tokenWaiting", "sandboxForm", "sandboxRejected", "sandboxStarted", "sandboxReuse",
    "hubTabs", "hubAttention", "hubOverview", "hubThreatAnswered",
    "networkUfw", "allowRefused", "allowAsUfwRule", "blockedAsTable", "alertMuted", "tempRevoked",
    "modePreview", "modeSwitched", "modeBack", "hubIpc", "hubSeen", "backendOlder", "backendProbed"]

  function pass(step) {
    var next = Object.assign({}, passed)
    next[step] = true
    passed = next
    console.log("E2E ok " + step)
    for (var i = 0; i < expected.length; i++) if (!passed[expected[i]]) return
    Qt.exit(0)
  }

  function fail(reason) {
    console.log("E2E FAIL " + reason)
    Qt.exit(1)
  }

  SecurityIPC {
    id: ipc
    onReadyChanged: {
      if (!ready) return
      if (moduleState("usbguard") !== "active") root.fail("usbguard module state " + moduleState("usbguard"))
      else root.pass("ready")
    }
    onEventReceived: function(name, params) {
      if (name === "USB_DEVICE_PRESENTED" && !root.passed.event) {
        root.pass("event")
        ipc.request("USBGUARD_SET_POLICY", { device_id: params.device_id, target: "allow", permanent: false },
          function(err, result) {
            if (err || !result || result.rule !== "allow") root.fail("set policy " + JSON.stringify(err))
            else root.pass("setPolicy")
          })
        // Every method the mock does not know.
        ipc.request("MOCK_NOT_IMPLEMENTED", {}, function(err) {
          if (err && err.code === -32007) root.pass("notImplemented")
          else root.fail("expected NOT_IMPLEMENTED, got " + JSON.stringify(err))
        })
      } else if (name === "USB_DEVICE_POLICY_CHANGED") {
        root.pass("policyChanged")
      }
    }
  }

  // The singleton resolves through services/qmldir and reads the active
  // theme's colors.toml (or finds it missing and falls back).
  function checkTheme() {
    if (!ThemeProvider.paletteReady || root.passed.theme) return
    var colors = [ThemeProvider.danger, ThemeProvider.warning, ThemeProvider.success,
      ThemeProvider.background, ThemeProvider.border.color]
    for (var i = 0; i < colors.length; i++)
      if (colors[i] === undefined || colors[i] === null) return root.fail("theme colour " + i + " unset")
    if (ThemeProvider.moduleStateColor("unavailable") !== ThemeProvider.danger) return root.fail("module state colour")
    root.pass("theme")
  }

  Connections {
    target: ThemeProvider
    function onPaletteReadyChanged() { root.checkTheme() }
  }

  Component.onCompleted: checkTheme()

  // The bar widget, given a stand-in for the bar host so that it finds the
  // service the way it does in the shell. Its state follows the mock's
  // firewall mode ("ufw") and alert stream.
  StatusBarIndicator {
    id: indicator
    bar: QtObject {
      property var shell: QtObject { function serviceFor(id) { return ipc } }
      property color barForeground: "#cacccc"
      property color urgent: "#a55555"
      property string fontFamily: "monospace"
      property bool vertical: false
      property int barSize: 26
      property bool foregroundAnimationEnabled: false
      function showTooltip(target, text) {}
      function hideTooltip(target) {}
    }

    onStatusChanged: {
      if (!root.passed.firewallMode && ipc.firewallMode === "ufw") {
        if (status.role !== "normal" || status.tooltip.indexOf("Firewall: UFW") < 0)
          return root.fail("indicator for ufw mode " + JSON.stringify(status))
        root.pass("firewallMode")
      }
      if (!root.passed.badge && ipc.unseenAlertCount > 0) {
        if (status.badge !== String(Math.min(ipc.unseenAlertCount, 9)))
          return root.fail("badge " + JSON.stringify(status) + " for " + ipc.unseenAlertCount)
        root.pass("badge")
        // Outside this handler, as the hub does it when it opens.
        Qt.callLater(root.clearBadge)
      }
    }
  }

  function clearBadge() {
    ipc.markAlertsSeen()
    if (ipc.unseenAlertCount !== 0 || indicator.status.badge !== "")
      return root.fail("badge not cleared: " + ipc.unseenAlertCount)
    seenCheck.start()
  }

  // markAlertsSeen() also writes the time down for the next shell start.
  FileView {
    id: seenFile
    property bool checking: false
    path: Quickshell.env("XDG_STATE_HOME") + "/omarchy-security/shell-seen.json"
    printErrors: false
    onLoaded: {
      if (!checking) return
      var saved = JSON.parse(text()).alerts_seen_at
      if (saved === ipc.alertsSeenAt) root.pass("seen")
      else root.fail("saved seen time " + saved + " != " + ipc.alertsSeenAt)
    }
    onLoadFailed: if (checking) root.fail("seen time not saved")
  }

  Timer {
    id: seenCheck
    interval: 300
    onTriggered: { seenFile.checking = true; seenFile.reload() }
  }

  // The USBGuard panel, driven the way its buttons drive it. The mock
  // starts with devices 2, 5 and 14 and plugs in 21 (storage that can also
  // type) after SUBSCRIBE; the "event" step above approves 21 for now.
  USBGuardPanel {
    id: usbPanel
    security: ipc
  }

  // Drive 21, after the "event" step allows it directly: Block, Approve
  // (for now), then Save permanent, each through the panel once the last
  // change has landed.
  property int usbStage: 0

  Connections {
    target: ipc
    function onUsbDevicesChanged() { Qt.callLater(root.checkUsb) }
  }
  Connections {
    target: usbPanel
    function onBusyChanged() { Qt.callLater(root.checkUsb) }
  }

  function offers(device, actionId) {
    return Usb.actionsFor(device).some(function(a) { return a.id === actionId })
  }

  function checkUsb() {
    var devices = ipc.usbDevices
    if (!passed.usbList && Usb.findDevice(devices, 2) && Usb.findDevice(devices, 14)) {
      if (usbPanel.emptyText !== "" || usbPanel.blocked < 1) return fail("panel over " + JSON.stringify(devices))
      // Found allowed: it may already have a rule, so no second one.
      if (offers(Usb.findDevice(devices, 2), "savePermanent")) return fail("save offered for a device found allowed")
      pass("usbList")
      // Reject needs a second click.
      if (usbPanel.perform(14, "reject")) return fail("reject sent on the first click")
      if (usbPanel.confirmingReject !== 14) return fail("reject not armed")
      pass("usbConfirm")
      if (!usbPanel.perform(14, "reject")) return fail("confirmed reject not sent")
    }
    if (passed.usbConfirm && !passed.usbReject && !Usb.findDevice(devices, 14)) pass("usbReject")

    var drive = Usb.findDevice(devices, 21)
    if (!drive || passed.usbSave || usbPanel.busy[21]) return
    if (Usb.riskNote(drive) === "") return fail("no warning for storage that types")
    if (usbStage === 0 && drive.rule === "allow") {
      usbStage = 1
      if (!usbPanel.perform(21, "block")) fail("block not sent")
    } else if (usbStage === 1 && drive.rule === "block") {
      usbStage = 2
      if (!usbPanel.perform(21, "approve")) fail("approve not sent")
    } else if (usbStage === 2 && drive.rule === "allow" && drive.temporary === true) {
      if (!offers(drive, "savePermanent")) return fail("save not offered after approve")
      usbStage = 3
      if (!usbPanel.perform(21, "savePermanent")) fail("save permanent not sent")
    } else if (usbStage === 3 && drive.rule === "allow" && drive.saved === true) {
      if (offers(drive, "savePermanent") || drive.temporary) return fail("still temporary after save")
      pass("usbSave")
    }
  }

  // The threat OSD, driven the way its buttons drive it, without mapping
  // its window. The mock reports a binary dropped in /tmp, a program run
  // from memory, and a /dev/shm script whose process has already exited.
  ThreatAlertOSD {
    id: threatOsd
    security: ipc
    showWindow: false
  }

  property int threatStage: 0

  Connections {
    target: threatOsd
    function onShownChanged() { Qt.callLater(root.checkThreat) }
    function onArmedChanged() { Qt.callLater(root.checkThreat) }
    function onBusyChanged() { Qt.callLater(root.checkThreat) }
  }

  function checkThreat() {
    var shown = threatOsd.shown
    if (!shown || threatOsd.busy) return
    var origin = shown.origin
    if (threatStage === 0 && origin === "tmp") {
      // A card that just appeared ignores clicks.
      if (threatOsd.armed || threatOsd.perform("kill")) return fail("answered before the card was armed")
      if (Threat.droppedLine(shown) === "") return fail("no drop time on " + JSON.stringify(shown))
      threatStage = 1
      pass("threatArmed")
    } else if (threatStage === 1 && threatOsd.armed && shown.state === "open") {
      threatStage = 2
      if (!threatOsd.perform("isolate")) fail("isolate not sent")
    } else if (threatStage === 2 && shown.state === "quarantined") {
      if (threatOsd.perform("isolate")) return fail("isolate offered twice")
      threatStage = 3
      if (!threatOsd.perform("resume")) fail("resume not sent")
    } else if (threatStage === 3 && shown.state === "open") {
      pass("threatIsolate")
      var putOff = shown.alert_id
      threatOsd.putOff()
      // Still open in the daemon, but no longer waiting on screen.
      if (!Threat.isPending(Threat.findAlert(ipc.threatAlerts, putOff))) return fail("put-off alert resolved")
      if (threatOsd.waiting.some(function(a) { return a.alert_id === putOff })) return fail("put-off alert waiting")
      // The next one, oldest first, once it has arrived.
      if (threatOsd.shown && threatOsd.shown.origin !== "memfd") return fail("shown next: " + threatOsd.shown.origin)
      // The one on screen is not counted as waiting behind itself.
      if (threatOsd.moreWaiting !== threatOsd.waiting.length - 1) return fail("more waiting " + threatOsd.moreWaiting)
      threatStage = 4
      pass("threatLater")
    } else if (threatStage === 4 && origin === "memfd" && threatOsd.armed) {
      threatStage = 5
      if (!threatOsd.perform("kill")) fail("kill not sent")
    } else if (threatStage === 5 && threatOsd.finished) {
      if (shown.state !== "killed") return fail("kill left " + shown.state)
      pass("threatKill")
      threatStage = 6
      threatOsd.advance()
    } else if (threatStage === 6 && origin === "dev_shm" && threatOsd.armed) {
      threatStage = 7
      if (!threatOsd.perform("isolate")) fail("isolate on the exited one not sent")
    } else if (threatStage === 7) {
      if (!threatOsd.finished || shown.state !== "exited" || !/exited/.test(threatOsd.errorText))
        return fail("stale target: " + shown.state + " / " + threatOsd.errorText)
      pass("threatStale")
    }
  }

  // The touch prompt, read without mapping its window. After SUBSCRIBE the
  // mock's YubiKey is touched for a FIDO2 request, lets a GnuPG one time
  // out, and is unplugged during an SSH one.
  YubiKeyPrompt {
    id: touchPrompt
    security: ipc
    showWindow: false
  }

  Connections {
    target: touchPrompt
    function onWaitingChanged() { Qt.callLater(root.checkTouch) }
    function onFinishedChanged() { Qt.callLater(root.checkTouch) }
    function onShownChanged() { Qt.callLater(root.checkTouch) }
  }

  function checkTouch() {
    var waiting = touchPrompt.waiting
    var finished = touchPrompt.finished
    if (!passed.touchWaiting && waiting.length === 1 && waiting[0].source === "fido2") {
      // The title names the key's kind, from TOKEN_LIST.
      if (!touchPrompt.shown || touchPrompt.title !== "Touch your YubiKey" || touchPrompt.outcome !== "")
        return fail("waiting prompt: " + touchPrompt.title + " / " + touchPrompt.outcome)
      pass("touchWaiting")
    }
    if (!finished) {
      if (passed.touchRemoved && !passed.touchCleared && !touchPrompt.shown) pass("touchCleared")
      return
    }
    if (!touchPrompt.shown) return fail("finished request not shown")
    if (passed.touchWaiting && !passed.touchTouched && finished.outcome === "touched") pass("touchTouched")
    else if (!passed.touchTimedOut && finished.outcome === "timed_out") {
      if (finished.source !== "gpg" || touchPrompt.title !== "Touch timed out") return fail("timed out: " + JSON.stringify(finished))
      pass("touchTimedOut")
    } else if (!passed.touchRemoved && finished.outcome === "removed") {
      // TOKEN_REMOVED alone ended it, and took the key off the list.
      if (finished.source !== "ssh" || Touch.findToken(ipc.tokens, finished.token_id)) return fail("removed: " + JSON.stringify(finished))
      pass("touchRemoved")
    }
  }

  // The hub's firewall rules, driven the way its form and buttons drive
  // it. The mock starts in ufw mode with an outbound block (saved, not
  // enforced) and an allow for /usr/bin/curl (enforced).
  HubRules {
    id: snitch
    security: ipc
  }

  property int addedRule: -1

  Connections {
    target: ipc
    function onFirewallRulesChanged() { Qt.callLater(root.checkRules) }
  }

  function fillForm(fields) {
    snitch.startAdding()
    for (var name in fields) snitch.setField(name, fields[name])
  }

  function checkRules() {
    var rules = ipc.firewallRules
    if (!passed.rulesListed && rules.length >= 2 && ipc.firewallMode === "ufw") {
      var block = rules[0], curl = rules[1]
      if (block.loaded !== false || Network.inactiveNote(block, snitch.mode).indexOf("UFW") < 0)
        return fail("block rule in ufw mode: " + JSON.stringify(block))
      if (curl.loaded !== true || Network.ruleProgram(curl) !== "/usr/bin/curl")
        return fail("curl rule: " + JSON.stringify(curl))
      pass("rulesListed")

      // An inbound allow cannot be sent while UFW decides inbound traffic.
      fillForm({ verdict: "allow", direction: "inbound", address: "192.168.1.23", protocol: "tcp", port: "22" })
      if (snitch.check.spec || snitch.submit()) return fail("inbound allow sent in ufw mode")
      // Choosing inbound drops a program; Any drops the port.
      fillForm({ executable: "/usr/bin/curl", direction: "inbound", protocol: "tcp", port: "80" })
      snitch.setField("protocol", "")
      if (snitch.form.executable !== "" || snitch.form.port !== "") return fail("form kept " + JSON.stringify(snitch.form))
      pass("ruleForm")

      fillForm({ address: "203.0.113.9", protocol: "tcp", port: "8443" })
      if (!/not enforced/.test(snitch.check.warning || "")) return fail("no ufw warning: " + JSON.stringify(snitch.check))
      if (!snitch.submit()) return fail("rule not sent")
      return
    }
    if (passed.ruleForm && addedRule < 0 && !snitch.addBusy) {
      var added = rules.filter(function(r) { return r.address === "203.0.113.9" && r.port === 8443 })[0]
      if (!added) return
      if (snitch.adding || snitch.addError !== "") return fail("form after add: " + snitch.addError)
      addedRule = added.rule_id
      pass("ruleAdded")
      if (snitch.remove(addedRule)) return fail("removed on the first click")
      if (!snitch.remove(addedRule)) return fail("confirmed remove not sent")
      return
    }
    if (addedRule >= 0 && !passed.ruleRemoved && !Network.findRule(rules, addedRule)) pass("ruleRemoved")
  }

  // The connection prompt, driven the way its buttons drive it, without
  // mapping its window. After SUBSCRIBE the mock holds a git connection,
  // then a firefox one; git is answered Allow / Always, and firefox is
  // left to time out (3 s under this harness).
  ConnectionPrompt {
    id: prompt
    security: ipc
    showWindow: false
  }

  property int promptStage: 0

  Connections {
    target: prompt
    function onShownChanged() { Qt.callLater(root.checkPrompt) }
    function onArmedChanged() { Qt.callLater(root.checkPrompt) }
    function onFinishedChanged() { Qt.callLater(root.checkPrompt) }
    function onMoreWaitingChanged() { Qt.callLater(root.checkPrompt) }
  }

  function checkPrompt() {
    var shown = prompt.shown
    if (!shown) return
    var name = Network.programName(shown.executable)
    if (promptStage === 0 && name === "git" && prompt.moreWaiting === 1) {
      if (prompt.armed || prompt.decide("allow")) return fail("answered before the card was armed")
      if (Network.destinationText(shown) !== "140.82.112.3, TCP port 22 (SSH)") return fail("destination " + Network.destinationText(shown))
      promptStage = 1
      pass("promptQueued")
    } else if (promptStage === 1 && name === "git" && prompt.armed) {
      prompt.scope = "always"
      promptStage = 2
      if (!prompt.decide("allow")) fail("decision not sent")
    } else if (promptStage === 2 && prompt.finished) {
      if (name !== "git" || Network.resolvedTitle(shown) !== "Allowed always")
        return fail("resolved " + name + ": " + Network.resolvedTitle(shown))
      promptStage = 3
      // The daemon saved a rule for git; the list is read again.
      alwaysCheck.start()
    } else if (promptStage === 4 && name === "firefox" && prompt.finished) {
      if (shown.decided_by !== "timeout" || Network.resolvedTitle(shown) !== "Blocked: no answer in time")
        return fail("firefox " + JSON.stringify(shown))
      pass("promptTimeout")
    }
  }

  Timer {
    id: alwaysCheck
    interval: 500
    onTriggered: {
      var git = ipc.firewallRules.filter(function(r) { return r.executable === "/usr/bin/git" })[0]
      if (!git || git.port !== 22 || git.verdict !== "allow" || git.loaded !== true)
        return root.fail("no rule for git after Always: " + JSON.stringify(ipc.firewallRules))
      root.promptStage = 4
      root.pass("promptAlways")
      root.checkPrompt()
    }
  }

  // The hardening audit: the mock reports a failing docker check.
  HardeningSem {
    id: hardening
    security: ipc
  }

  property real firstEvaluated: 0

  Connections {
    target: hardening
    function onReportChanged() { Qt.callLater(root.checkPosture) }
  }

  function checkPosture() {
    var report = hardening.report
    if (!report) return
    if (!passed.postureShown) {
      if (hardening.checks.length !== 4 || hardening.overall !== "fail" || hardening.emptyText !== ""
          || hardening.checks[0].check_id !== "lsm")
        return fail("posture " + JSON.stringify(report))
      firstEvaluated = report.evaluated_at
      pass("postureShown")
      // A little later, so the new report has a later time.
      postureRefresh.start()
    } else if (!passed.postureRefresh && report.evaluated_at > firstEvaluated) {
      pass("postureRefresh")
    }
  }

  Timer {
    id: postureRefresh
    interval: 50
    onTriggered: if (!hardening.refresh()) root.fail("refresh not sent")
  }

  // The vault panel, driven the way its buttons drive it. The mock starts
  // with "notes" and "backup" locked and "work" open and in use; a mount
  // waits 1 s for its "passphrase", and the first one of "backup" is
  // cancelled. Notes: Mount, then Unmount. Work: Unmount fails as busy.
  // Backup: cancelled, then mounted again and cut short by Panic, which
  // detaches work lazily. Then Add vault: first with a mount point work
  // already uses, which the mock refuses, then elsewhere; and Remove, which
  // needs a second click. Last, a new vault from its name alone, and one
  // whose passphrase prompt is cancelled.
  VaultPanel {
    id: vaultPanel
    security: ipc
  }

  property int vaultStage: 0

  Connections {
    target: ipc
    function onVaultsChanged() { Qt.callLater(root.checkVaults) }
    function onVaultOpsChanged() { Qt.callLater(root.checkVaults) }
  }
  Connections {
    target: vaultPanel
    function onErrorsChanged() { Qt.callLater(root.checkVaults) }
    function onPanicResultChanged() { Qt.callLater(root.checkVaults) }
    function onAddBusyChanged() { Qt.callLater(root.checkVaults) }
    function onAddErrorChanged() { Qt.callLater(root.checkVaults) }
    function onRemovingChanged() { Qt.callLater(root.checkVaults) }
  }

  function vaultError(vaultId) {
    var failure = vaultPanel.errorFor(vaultId)
    return failure ? Vault.opErrorText(failure.error, failure.action) : ""
  }

  function checkVaults() {
    var vaults = ipc.vaults
    var notes = Vault.findVault(vaults, "notes"), work = Vault.findVault(vaults, "work")
    if (vaultStage === 0 && vaults.length === 3) {
      if (vaultPanel.emptyText !== "" || !Vault.isMounted(work) || Vault.isMounted(notes) || !vaultPanel.panicAvailable)
        return fail("vaults " + JSON.stringify(vaults) + " / " + vaultPanel.emptyText)
      pass("vaultsListed")
      vaultStage = 1
      if (!vaultPanel.toggle("notes")) return fail("mount not sent")
      if (ipc.vaultOps.notes !== "mount" || Vault.stateText(notes, "mount", "") !== "Waiting for the passphrase…")
        return fail("no mount in progress: " + JSON.stringify(ipc.vaultOps))
      if (vaultPanel.toggle("notes")) return fail("second mount sent while the first waits")
    } else if (vaultStage === 1 && Vault.isMounted(notes) && !ipc.vaultOps.notes) {
      pass("vaultMounted")
      vaultStage = 2
      if (!vaultPanel.toggle("notes")) return fail("unmount not sent")
    } else if (vaultStage === 2 && !Vault.isMounted(notes) && !ipc.vaultOps.notes) {
      pass("vaultUnmounted")
      vaultStage = 3
      if (!vaultPanel.toggle("work")) return fail("unmount of work not sent")
    } else if (vaultStage === 3 && vaultError("work") !== "") {
      if (!/Still in use/.test(vaultError("work")) || !Vault.isMounted(Vault.findVault(ipc.vaults, "work")))
        return fail("busy unmount: " + vaultError("work"))
      pass("vaultBusy")
      vaultStage = 4
      if (!vaultPanel.toggle("backup")) return fail("mount of backup not sent")
    } else if (vaultStage === 4 && vaultError("backup") !== "") {
      var failure = vaultPanel.errors.backup
      if (vaultError("backup") !== "Cancelled." || Vault.opErrorRole(failure.error) !== "muted")
        return fail("cancelled mount: " + vaultError("backup"))
      pass("vaultCancelled")
      vaultStage = 5
      // Again, and Panic while it waits: the first click only arms it.
      if (!vaultPanel.toggle("backup")) return fail("second mount of backup not sent")
      if (vaultPanel.panic() || !vaultPanel.confirmingPanic) return fail("panic sent on the first click")
      if (!vaultPanel.panic()) return fail("confirmed panic not sent")
    } else if (vaultStage === 5 && vaultPanel.panicResult && !ipc.vaultOps.backup && vaultError("backup") !== "") {
      var summary = vaultPanel.panicSummary
      if (vaultError("backup") !== "Cancelled by Panic.") return fail("mount during panic: " + vaultError("backup"))
      if (Vault.mountedCount(ipc.vaults) !== 0) return fail("still mounted after panic: " + JSON.stringify(ipc.vaults))
      if (summary.title !== "Panic locked 1 vault." || summary.role !== "warning" || !/Work documents/.test(summary.lines[0] || ""))
        return fail("panic summary " + JSON.stringify(summary))
      if (vaultPanel.panicAvailable) return fail("panic still offered with nothing open")
      // Work is no longer "still in use": Panic unmounted it.
      if (vaultError("work") !== "") return fail("stale error on work: " + vaultError("work"))
      vaultStage = 6
      pass("vaultPanic")
      vaultPanel.openForm()
      if (vaultPanel.addCheck.method !== "VAULT_CREATE") return fail("the form does not start on New vault")
      vaultPanel.setField("kind", "gocryptfs")
      vaultPanel.setField("name", "Work documents")
      vaultPanel.setField("source", "~/Vaults/work.enc")
      var check = vaultPanel.addCheck
      if (!check.params || check.params.vault_id !== "work-documents" || check.params.mount_point !== "~/Vaults/work")
        return fail("add form " + JSON.stringify(check))
      if (!vaultPanel.addVault()) return fail("add not sent")
    } else if (vaultStage === 6 && !vaultPanel.addBusy && vaultPanel.addError !== "") {
      if (!/^Not added: mount_point .* is used by another vault$/.test(vaultPanel.addError) || !vaultPanel.adding)
        return fail("shared mount point: " + vaultPanel.addError)
      pass("vaultAddRejected")
      vaultStage = 7
      vaultPanel.setField("mountPoint", "~/Vaults/work-docs")
      if (vaultPanel.addError !== "" || !vaultPanel.addVault()) return fail("second add not sent")
    } else if (vaultStage === 7 && !vaultPanel.addBusy) {
      var added = Vault.findVault(ipc.vaults, "work-documents")
      if (vaultPanel.adding || !added || added.mounted || added.mount_point !== root.home + "/Vaults/work-docs")
        return fail("added vault " + JSON.stringify(added) + " / " + vaultPanel.addError)
      pass("vaultAdded")
      vaultStage = 8
      if (vaultPanel.remove("work-documents") || vaultPanel.confirmingRemove !== "work-documents")
        return fail("remove sent on the first click")
      if (!vaultPanel.remove("work-documents")) return fail("confirmed remove not sent")
    } else if (vaultStage === 8 && vaultPanel.removing === "") {
      if (Vault.findVault(ipc.vaults, "work-documents") || vaultPanel.removeErrors["work-documents"])
        return fail("not removed: " + JSON.stringify(vaultPanel.removeErrors))
      vaultStage = 9
      pass("vaultRemoved")
      vaultPanel.openForm()
      vaultPanel.setField("name", "Tax papers")
      var create = vaultPanel.addCheck
      if (create.method !== "VAULT_CREATE" || !create.params || create.params.source !== "~/Vaults/tax-papers.enc"
          || create.params.mount_point !== "~/Vaults/tax-papers")
        return fail("create form " + JSON.stringify(create))
      if (!vaultPanel.addVault() || !vaultPanel.creating || !vaultPanel.panicAvailable)
        return fail("create not sent, or Panic not offered while it waits")
    } else if (vaultStage === 9 && !vaultPanel.addBusy) {
      var created = Vault.findVault(ipc.vaults, "tax-papers")
      if (vaultPanel.adding || !created || created.mounted || created.backend !== "gocryptfs")
        return fail("created vault " + JSON.stringify(created) + " / " + vaultPanel.addError)
      pass("vaultCreated")
      vaultStage = 10
      vaultPanel.openForm()
      vaultPanel.setField("name", "Scratch")
      vaultPanel.setField("source", "~/Vaults/cancel.enc")
      if (!vaultPanel.addVault()) return fail("second create not sent")
    } else if (vaultStage === 10 && !vaultPanel.addBusy && vaultPanel.addError !== "") {
      if (vaultPanel.addError !== "Cancelled." || !vaultPanel.adding || Vault.findVault(ipc.vaults, "scratch"))
        return fail("cancelled create: " + vaultPanel.addError)
      vaultStage = 11
      pass("vaultCreateCancelled")
    }
  }

  // Tokens: a YubiKey and a smart card reader, and the touch requests the
  // mock plays out after SUBSCRIBE (see the touch steps above).
  TokenPanel {
    id: tokenPanel
    security: ipc
  }

  Connections {
    target: tokenPanel
    function onTokensChanged() { Qt.callLater(root.checkTokens) }
    function onRequestsChanged() { Qt.callLater(root.checkTokens) }
  }

  function checkTokens() {
    var tokens = tokenPanel.tokens
    if (!root.passed.tokensListed && tokens.length === 2) {
      var reader = Touch.findToken(tokens, "usb-1-4-3"), key = Touch.findToken(tokens, "usb-3-2-7")
      if (tokenPanel.emptyText !== "" || !reader || !key) return fail("tokens " + JSON.stringify(tokens))
      if (Token.kindLabel(reader.kind) !== "Smart card reader" || Token.touchNote(reader) !== ""
          || key.capabilities.map(Token.capabilityLabel).join(" ") !== "FIDO2 PIV OpenPGP OTP")
        return fail("token labels " + JSON.stringify(tokens))
      pass("tokensListed")
    }
    if (!root.passed.tokenWaiting) {
      var line = Token.requestLine(Token.latestRequest(tokenPanel.requests, "usb-3-2-7", Date.now()), Date.now())
      if (line && line.role === "warning" && / is waiting for a touch$/.test(line.text)) pass("tokenWaiting")
    }
  }

  // Sandbox: a relative path is refused here, a missing file by the mock
  // (as by the daemon), then a run with a file and network, and Use again.
  SandboxLauncher {
    id: sandbox
    security: ipc
  }

  property int sandboxStage: 0
  readonly property string home: Quickshell.env("HOME") || ""

  Connections {
    target: sandbox
    function onUnavailableTextChanged() { Qt.callLater(root.checkSandbox) }
    function onBusyChanged() { Qt.callLater(root.checkSandbox) }
  }

  function checkSandbox() {
    if (sandbox.busy || sandbox.unavailableText !== "") return
    if (sandboxStage === 0) {
      sandbox.setField("executable", "zathura")
      if (sandbox.check.params || !/full path/.test(sandbox.check.error) || sandbox.run())
        return fail("relative program accepted: " + JSON.stringify(sandbox.check))
      sandbox.setField("executable", "/usr/bin/true")
      sandbox.setField("target", "~/no-such-e2e-file.pdf")
      var params = sandbox.check.params
      if (!params || params.target_file !== root.home + "/no-such-e2e-file.pdf" || params.args[0] !== params.target_file
          || params.share_net !== false)
        return fail("form params " + JSON.stringify(params))
      pass("sandboxForm")
      sandboxStage = 1
      if (!sandbox.run()) return fail("run not sent")
    } else if (sandboxStage === 1) {
      if (!/^Not started: target_file .*no-such-e2e-file/.test(sandbox.runError)) return fail("missing file: " + sandbox.runError)
      pass("sandboxRejected")
      sandboxStage = 2
      sandbox.setField("target", "/etc/passwd")
      sandbox.setField("shareNet", true)
      if (sandbox.check.warning === "" || !sandbox.run()) return fail("run with network not sent")
    } else if (sandboxStage === 2) {
      var run = ipc.sandboxRuns[0]
      if (!sandbox.started || !(sandbox.started.pid > 0) || !run || run.pid !== sandbox.started.pid
          || run.share_net !== true || run.target_file !== "/etc/passwd")
        return fail("sandbox run " + sandbox.runError + " " + JSON.stringify(ipc.sandboxRuns))
      if (Sandbox.runTitle(run) !== "true with passwd, with network") return fail("run title " + Sandbox.runTitle(run))
      pass("sandboxStarted")
      sandboxStage = 3
      sandbox.setField("executable", "")
      sandbox.reuse(run)
      if (sandbox.form.executable !== "/usr/bin/true" || sandbox.form.target !== "/etc/passwd" || !sandbox.form.shareNet)
        return fail("reuse " + JSON.stringify(sandbox.form))
      pass("sandboxReuse")
    }
  }

  // The tabbed hub, without its window. The payload and the keys pick the
  // tab; the tabs mark what waits; the Overview merges both kinds of alert;
  // and the alert put off with Later above is answered in the Threats tab.
  HubView {
    id: hubView
    security: ipc
    // Not on screen until hubSeen, so the badge steps see the alerts.
    shown: false
  }

  // Instantiated to prove it loads; never shown.
  SecurityHub {
    id: hub
    service: ipc
  }

  // The backend card (plan task 5.3). The mock is 0.0.0, older than any
  // plugin, so the connected one offers an update above the tabs; the one
  // with no connection probes this machine and blocks the tabs with what
  // it found (missing in CI, running or stopped on a desktop).
  BackendSetup {
    id: backendConnected
    security: ipc
    pluginVersion: "1.0.0"
    // `info` follows `kind`; read both once the bindings have settled.
    onKindChanged: Qt.callLater(check)
    function check() {
      if (kind !== "older" || root.passed.backendOlder) return
      if (blocking || info.action !== "install" || !/^Backend 0\.0\.0-mock is older/.test(info.title))
        root.fail("backend older " + JSON.stringify(info))
      else root.pass("backendOlder")
    }
  }

  BackendSetup {
    id: backendAlone
    security: null
    pluginVersion: "1.0.0"
    onKindChanged: Qt.callLater(check)
    function check() {
      if (kind === "checking" || root.passed.backendProbed) return
      var action = { missing: "install", stopped: "start", unreachable: "" }[kind]
      if (action === undefined || !blocking || info.action !== action
        || !/\/backend\/install\.sh$/.test(scriptPath))
        root.fail("backend probe " + kind + " " + scriptPath + " " + JSON.stringify(info))
      else root.pass("backendProbed")
    }
  }

  property bool hubThreatArmed: false

  Connections {
    target: hubView
    function onAttentionChanged() { Qt.callLater(root.checkHub) }
  }

  Connections {
    target: ipc
    function onThreatAlertsChanged() { Qt.callLater(root.checkHub) }
    function onFirewallAlertsChanged() { Qt.callLater(root.checkHub) }
  }

  function checkHub() {
    if (!root.passed.hubTabs) {
      if (hubView.tab !== "overview" || !hubView.show("firewall") || hubView.tab !== "network")
        return fail("hub tab " + hubView.tab)
      if (hubView.show("nonsense") || hubView.tab !== "network") return fail("unknown tab taken")
      hubView.step(1)
      if (hubView.tab !== "vaults") return fail("next tab " + hubView.tab)
      hubView.step(3)
      if (hubView.tab !== "threats") return fail("wrapped to " + hubView.tab)
      // The window's `tab` is its view's.
      hub.tab = "tokens"
      if (hub.tab !== "tokens" || Hub.tabFromPayload('{"tab": "usbguard"}', hub.tab) !== "usb")
        return fail("hub tab alias " + hub.tab)
      pass("hubTabs")
    }
    var marks = hubView.attention
    if (!root.passed.hubAttention && marks.threats && marks.usb && marks.tokens) {
      if (!(marks.threats.count > 0) || marks.threats.role !== "danger" || marks.usb.role !== "warning")
        return fail("attention " + JSON.stringify(marks))
      pass("hubAttention")
    }
    if (!root.passed.hubOverview) {
      var entries = Hub.history(ipc.threatAlerts, ipc.firewallAlerts, 8)
      var kinds = entries.map(function(e) { return e.kind })
      if (kinds.indexOf("threat") >= 0 && kinds.indexOf("firewall") >= 0) {
        for (var i = 1; i < entries.length; i++)
          if (entries[i].time > entries[i - 1].time) return fail("history order " + JSON.stringify(entries))
        pass("hubOverview")
      }
    }
    // The alert put off on the card is still open; dismiss it from the
    // list, which takes a second click.
    if (root.passed.threatLater && !root.passed.hubThreatAnswered) {
      var putOff = null
      for (var id in threatOsd.later) putOff = Threat.findAlert(ipc.threatAlerts, Number(id))
      if (!putOff) return
      if (putOff.state === "dismissed") return pass("hubThreatAnswered")
      if (root.hubThreatArmed || putOff.state !== "open") return
      if (threatList.perform(putOff.alert_id, "dismiss")) return fail("dismissed on the first click")
      if (!threatList.perform(putOff.alert_id, "dismiss")) return fail("dismiss not sent")
      root.hubThreatArmed = true
    }
  }

  ThreatList {
    id: threatList
    security: ipc
  }

  // The Network tab in ufw mode, driven the way its buttons drive it. The
  // mock's alerts come every second: TCP 22 and UDP 5000 inbound, then
  // ICMP; its first inbound allow is refused as a dismissed password
  // prompt. Once the rule steps above are done, the mode is switched to
  // standalone and back.
  NetworkSnitch {
    id: network
    security: ipc
  }

  property int netStage: 0
  property int tcpAlert: -1
  property real ufwTemp: -1

  Connections {
    target: ipc
    function onFirewallAlertsChanged() { Qt.callLater(root.checkNetwork) }
    function onTempDecisionsChanged() { Qt.callLater(root.checkNetwork) }
    function onUfwRulesChanged() { Qt.callLater(root.checkNetwork) }
    function onFirewallModeChanged() { Qt.callLater(root.checkNetwork) }
    function onFirewallRulesChanged() { Qt.callLater(root.checkNetwork) }
    function onHubRequested(tab, toggle) {
      if (tab === "network" && !toggle) root.pass("hubIpc")
      else root.fail("hub requested " + tab + " " + toggle)
    }
  }

  Connections {
    target: network.alerts
    function onErrorsChanged() { Qt.callLater(root.checkNetwork) }
  }

  Connections {
    target: network.banner
    function onPreviewChanged() { Qt.callLater(root.checkNetwork) }
    function onDoneChanged() { Qt.callLater(root.checkNetwork) }
    function onErrorChanged() { if (network.banner.error !== "") root.fail("switch: " + network.banner.error) }
  }

  function alertFor(protocol) {
    return ipc.firewallAlerts.filter(function(a) { return a.protocol === protocol })[0] || null
  }

  function decisionFor(alertId) {
    return ipc.tempDecisions.filter(function(d) { return d.alert_id === alertId })[0] || null
  }

  function checkNetwork() {
    var now = Date.now()
    if (netStage === 0) {
      var tcp = alertFor("tcp")
      if (!tcp || !ipc.ufwRules || ipc.firewallMode !== "ufw") return
      if (!network.sections.ufwRules || !network.hubRules.collapseInactive || network.hubRules.showBaseline)
        return fail("ufw sections " + JSON.stringify(network.sections))
      if (ipc.ufwRules.rules.length !== 4 || network.banner.banner.actions[0].mode !== "standalone")
        return fail("ufw rules " + ipc.ufwRules.rules.length + " / " + JSON.stringify(network.banner.banner))
      if (JSON.stringify(ipc.tempDurations) !== "[300,3600,28800]" || network.alerts.effectiveDuration !== 3600)
        return fail("durations " + JSON.stringify(ipc.tempDurations))
      pass("networkUfw")
      tcpAlert = tcp.alert_id
      netStage = 1
      if (!network.alerts.act(tcpAlert, "allow")) return fail("allow not sent")
    } else if (netStage === 1 && network.alerts.errors[tcpAlert]) {
      if (!/Not authorized/.test(network.alerts.errors[tcpAlert])) return fail("refused: " + network.alerts.errors[tcpAlert])
      pass("allowRefused")
      netStage = 2
      if (!network.alerts.act(tcpAlert, "allow")) return fail("second allow not sent")
    } else if (netStage === 2) {
      var allowed = decisionFor(tcpAlert)
      if (!allowed || !ipc.ufwRules.rules.some(function(r) { return r.temp_id === allowed.temp_id })) return
      if (allowed.backend !== "ufw" || allowed.spec.address !== "192.168.1.23" || allowed.expires_at - allowed.created_at !== 3600000)
        return fail("inbound allow " + JSON.stringify(allowed))
      if (!/^Allowed, (60 min|1 h) left$/.test(Network.decisionNote(Network.decisionForAlert(ipc.tempDecisions, tcpAlert, now), now)))
        return fail("note " + Network.decisionNote(allowed, now))
      ufwTemp = allowed.temp_id
      pass("allowAsUfwRule")
      netStage = 3
    }
    if (netStage === 3) {
      var udp = alertFor("udp")
      if (!udp) return
      netStage = 4
      network.alerts.duration = 300
      if (!network.alerts.act(udp.alert_id, "block")) return fail("block not sent")
    } else if (netStage === 4) {
      var blocked = decisionFor(alertFor("udp").alert_id)
      if (!blocked) return
      if (blocked.backend !== "table" || blocked.spec.verdict !== "block" || blocked.expires_at - blocked.created_at !== 300000)
        return fail("block " + JSON.stringify(blocked))
      pass("blockedAsTable")
      netStage = 5
    }
    if (netStage === 5) {
      var icmp = alertFor("icmp")
      if (!icmp) return
      if (network.alerts.specFor(icmp, "allow") !== null) return fail("ICMP alert offers Allow")
      netStage = 6
      if (!network.alerts.act(icmp.alert_id, "mute")) return fail("mute not sent")
    } else if (netStage === 6) {
      if (!Network.isMuted(alertFor("icmp"), now)) return
      pass("alertMuted")
      netStage = 7
      if (network.decisions.revoke(ufwTemp)) return fail("revoked on the first click")
      if (!network.decisions.revoke(ufwTemp)) return fail("revoke not sent")
    } else if (netStage === 7) {
      if (decisionFor(tcpAlert) || ipc.ufwRules.rules.some(function(r) { return r.temp_id === ufwTemp })) return
      pass("tempRevoked")
      netStage = 8
    }
    // The ufw-mode rule steps are done; switch.
    if (netStage === 8 && passed.ruleRemoved) {
      netStage = 9
      if (!network.banner.startSwitch("standalone")) return fail("switch dialog not opened")
    } else if (netStage === 9 && network.banner.preview) {
      var preview = network.banner.preview
      if (preview.mode !== "ufw" || preview.imported.length !== 3 || preview.not_imported.length !== 1
          || ipc.firewallMode !== "ufw")
        return fail("preview " + JSON.stringify(preview))
      pass("modePreview")
      netStage = 10
      if (network.banner.confirm()) return fail("switched on the first click")
      if (!network.banner.confirm()) return fail("switch not sent")
    } else if (netStage === 10 && ipc.firewallMode === "standalone" && network.banner.done !== "") {
      if (!/Imported 3 rules from UFW\. 1 UFW rule was not imported/.test(network.banner.done))
        return fail("switched: " + network.banner.done)
      if (network.sections.ufwRules || !network.hubRules.showBaseline || network.hubRules.collapseInactive)
        return fail("standalone sections " + JSON.stringify(network.sections))
      // The rules are read again after the switch.
      var saved = ipc.firewallRules.filter(function(r) { return r.address === "198.51.100.0/24" })[0]
      if (!saved || saved.loaded !== true) return
      pass("modeSwitched")
      netStage = 11
      network.banner.startSwitch("ufw")
      network.banner.confirm()
      network.banner.confirm()
    } else if (netStage === 11 && ipc.firewallMode === "ufw" && network.banner.done !== "" && network.banner.target === "") {
      if (!/^Switched to UFW\.$/.test(network.banner.done)) return fail("back: " + network.banner.done)
      pass("modeBack")
      netStage = 12
    }
    // The Network tab on screen clears the badge, and keeps it clear.
    if (passed.seen && passed.hubTabs && !passed.hubSeen) {
      if (!hubView.shown) {
        hubView.tab = "network"
        hubView.shown = true
        root.seenAlerts = ipc.firewallAlerts.length
        root.seenAt = Date.now()
      } else if (ipc.unseenAlertCount !== 0) {
        return fail("unseen with the Network tab shown: " + ipc.unseenAlertCount)
      } else if (ipc.firewallAlerts.length > root.seenAlerts || ipc.firewallAlerts.some(function(a) { return a.last_seen > root.seenAt })) {
        pass("hubSeen")
      }
    }
  }

  property int seenAlerts: 0
  property real seenAt: Date.now()

  // The notification action's route: omarchy-shell security-hub open network.
  Process {
    id: ipcCall
    command: ["qs", "ipc", "-p", Quickshell.shellDir, "call", "security-hub", "open", "network"]
  }

  Connections {
    target: ipc
    function onReadyChanged() { if (ipc.ready) ipcCall.running = true }
  }

  Timer {
    interval: 20000
    running: true
    onTriggered: root.fail("timed out; passed " + JSON.stringify(root.passed))
  }
}
