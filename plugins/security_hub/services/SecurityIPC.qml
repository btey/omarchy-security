// SPDX-License-Identifier: MIT
import QtQuick
import Quickshell
import Quickshell.Io
import "Protocol.js" as Protocol
import "Indicator.js" as Indicator
import "Usb.js" as Usb
import "Threat.js" as Threat
import "Touch.js" as Touch
import "Network.js" as Network
import "Vault.js" as Vault
import "Sandbox.js" as Sandbox

// The plugin's one connection to omarchy-securityd. The shell mounts this as
// the plugin's service singleton; the bar widget and the panel reach it
// through `shell.serviceFor(...)` so that there is only ever one socket,
// one handshake, and one subscription no matter how many views are open.
//
// Everything here is transport: connect, HELLO, SUBSCRIBE, correlate
// responses by id, fan events out through `eventReceived`, and reconnect
// with backoff when the daemon goes away.
Item {
  id: root

  visible: false
  width: 0
  height: 0

  // Injected by the shell.
  property var shell: null
  property var manifest: null
  property var pluginRegistry: null
  property var barWidgetRegistry: null

  readonly property string socketPath: Protocol.socketPath(function(name) { return Quickshell.env(name) })

  // `connected`: the socket is open. `ready`: HELLO succeeded, so requests
  // other than HELLO may be sent.
  readonly property bool connected: socket.connected
  property bool ready: false
  property string daemonVersion: ""
  property var modules: []
  property string lastError: ""

  // Firewall state the bar widget shows (plan §5.21). `firewallMode` is
  // FirewallMode.mode, "" until the daemon has answered; "unknown" also
  // covers a firewall module that cannot report one. `firewallAlerts` is
  // newest first, like FIREWALL_ALERT_LIST.
  property string firewallMode: ""
  // The whole FirewallMode (what `ufw` has, Docker protection, detail),
  // null until the daemon has answered.
  property var firewallInfo: null
  property var firewallAlerts: []
  // Last time (ms) the user looked at the alerts; see markAlertsSeen().
  property real alertsSeenAt: 0
  readonly property int unseenAlertCount: Indicator.unseenCount(firewallAlerts, alertsSeenAt, Date.now())

  // USB devices USBGuard knows about (plan task 3.3), in device_id order,
  // kept from USBGUARD_LIST_DEVICES and the USB_DEVICE_* events.
  // `usbListError` is the error of the last listing, null when it worked.
  property var usbDevices: []
  property var usbListError: null

  // Threat alerts this session (plan task 3.4), in alert_id order, kept from
  // THREAT_LIST_ALERTS and the THREAT_* events. The ThreatAlertOSD below
  // shows the ones that still need an answer.
  property var threatAlerts: []

  // Security tokens plugged in (plan task 3.5), in token_id order, from
  // TOKEN_LIST and TOKEN_INSERTED / TOKEN_REMOVED, and the touch requests
  // of this connection, from TOKEN_TOUCH_*. The YubiKeyPrompt below shows
  // the waiting ones. The daemon does not list requests already waiting,
  // so one that started before this shell connected is not shown.
  // `tokensError` is the last listing's error, null when it worked.
  property var tokens: []
  property var tokensError: null
  property var touchRequests: []

  // The hub's saved firewall rules (plan task 3.6), in rule_id order, from
  // FIREWALL_LIST_RULES. No event announces a change, so the list is read
  // again after every change made here, on a mode change, and when the hub
  // opens. `firewallRulesError` is the last listing's error, null when it
  // worked.
  property var firewallRules: []
  property var firewallRulesError: null

  // `ufw`'s own rules (plan task 3.10), from FIREWALL_UFW_RULES:
  // {rules, builtin, source}, null until read. Read after the handshake,
  // on a mode change, when temporary decisions change (the hub's
  // temporary UFW rules are among them), and when the hub opens.
  property var ufwRules: null
  property var ufwRulesError: null

  // Temporary allow and block decisions still in force, from
  // FIREWALL_TEMP_LIST and FIREWALL_TEMP_CHANGED, and the durations to
  // offer for new ones (`[firewall.alerts] temp_durations_secs`).
  property var tempDecisions: []
  property var tempDurations: Network.DEFAULT_DURATIONS

  // Outbound connections held for an answer, from
  // FIREWALL_CONNECTION_PROMPT / _RESOLVED; the ConnectionPrompt below asks
  // about the pending ones. Like touch requests, prompts sent before this
  // shell connected are not listed.
  property var connectionPrompts: []

  // The hardening audit (PostureReport), null until the daemon answers.
  property var posture: null
  property var postureError: null

  // Encrypted vaults (plan task 3.7), in the configuration's order, from
  // VAULT_LIST and VAULT_STATE_CHANGED. `vaultOps` is what this shell is
  // doing to each (vault_id -> "mount" | "unmount"); a mount can wait
  // minutes for its passphrase, and outlives a closed hub.
  property var vaults: []
  property var vaultsError: null
  property var vaultOps: ({})

  // Sandboxes this shell started (plan task 3.8), newest first: SANDBOX_RUN's
  // params with `pid` and `started_at`. The daemon does not list them.
  property var sandboxRuns: []

  signal eventReceived(string name, var params)

  property int nextId: 1
  property var pending: ({})
  property int failedAttempts: 0
  property bool stopping: false

  readonly property int requestTimeoutMs: 10000
  // For a call that waits for a polkit password dialog.
  readonly property int passwordTimeoutMs: 120000

  // Sends `method` and calls `callback(error, result)` once, with `error`
  // being a JSON-RPC error object or null. `timeoutMs` replaces the usual
  // wait for methods that wait on the user, such as a passphrase prompt.
  function request(method, params, callback, timeoutMs) {
    var done = callback || function() {}
    if (!socket.connected) {
      done({ code: Protocol.ErrorCode.INTERNAL_ERROR, message: "not connected to omarchy-securityd" }, null)
      return
    }
    if (!ready && method !== "HELLO") {
      done({ code: Protocol.ErrorCode.HANDSHAKE_REQUIRED, message: "handshake not complete" }, null)
      return
    }
    var id = nextId++
    pending[id] = { callback: done, sentAt: Date.now(), timeoutMs: timeoutMs || requestTimeoutMs }
    socket.write(Protocol.encodeRequest(id, method, params))
    socket.flush()
  }

  function moduleState(moduleId) {
    for (var i = 0; i < modules.length; i++)
      if (modules[i].module === moduleId) return modules[i].state
    return ""
  }

  // Clears the badge: every alert so far counts as seen, here and after a
  // shell restart.
  function markAlertsSeen() {
    var latest = Date.now()
    for (var i = 0; i < firewallAlerts.length; i++)
      if (firewallAlerts[i].last_seen > latest) latest = firewallAlerts[i].last_seen
    if (latest <= alertsSeenAt) return
    alertsSeenAt = latest
    if (seenFile.path !== "") seenFile.setText(JSON.stringify({ alerts_seen_at: latest }) + "\n")
  }

  function loadFirewall() {
    request("FIREWALL_GET_MODE", {}, function(error, result) {
      root.firewallMode = error || !result || !result.mode ? "unknown" : result.mode
      root.firewallInfo = error || !result ? null : result
    })
    request("FIREWALL_ALERT_LIST", {}, function(error, result) {
      if (error || !result || !Array.isArray(result.alerts)) return
      // Events that arrived while the list was on its way are newer.
      var merged = result.alerts.slice(0, Indicator.MAX_ALERTS)
      for (var i = root.firewallAlerts.length - 1; i >= 0; i--)
        merged = Indicator.mergeAlert(merged, root.firewallAlerts[i])
      root.firewallAlerts = merged
    })
  }

  function loadUfwRules() {
    request("FIREWALL_UFW_RULES", {}, function(error, result) {
      if (error || !result || !Array.isArray(result.rules)) {
        root.ufwRulesError = error || { code: Protocol.ErrorCode.INTERNAL_ERROR, message: "malformed rule list" }
        return
      }
      root.ufwRulesError = null
      root.ufwRules = result
    })
  }

  function loadTemps() {
    request("FIREWALL_TEMP_LIST", {}, function(error, result) {
      if (error || !result || !Array.isArray(result.decisions)) return
      root.tempDecisions = result.decisions
      root.tempDurations = Network.durations(result.durations_secs)
    })
  }

  // FIREWALL_SET_MODE with `dry_run`: what switching to `mode` would
  // import from UFW, without switching. `callback(error, result)` once.
  // A daemon older than 3.10 refuses the field (INVALID_PARAMS).
  function previewFirewallMode(mode, callback) {
    request("FIREWALL_SET_MODE", { mode: mode, dry_run: true }, callback || function() {})
  }

  // FIREWALL_SET_MODE. Asks for the administrator password, so it waits
  // longer than 10 s. `callback(error, result)` once; the mode itself
  // follows from FIREWALL_MODE_CHANGED.
  function setFirewallMode(mode, callback) {
    var done = callback || function() {}
    request("FIREWALL_SET_MODE", { mode: mode }, function(error, result) {
      if (!error && result && result.mode) {
        root.firewallMode = result.mode
        root.firewallInfo = result
      }
      // A failure part-way may have changed the mode; so may a success.
      root.loadFirewall()
      root.loadRules()
      root.loadUfwRules()
      done(error, result)
    }, passwordTimeoutMs)
  }

  // FIREWALL_TEMP_ADD. `callback(error, decision)` once. An inbound allow
  // waits for the password.
  function addTemp(spec, durationSecs, alertId, callback) {
    var done = callback || function() {}
    var params = { spec: spec, duration_secs: durationSecs }
    if (typeof alertId === "number") params.alert_id = alertId
    request("FIREWALL_TEMP_ADD", params, function(error, result) {
      if (!error && result) root.tempDecisions = Network.liveDecisions(
        root.tempDecisions.filter(function(d) { return d.temp_id !== result.temp_id }).concat([result]), Date.now())
      done(error, result)
    }, Protocol.needsPassword(spec) ? passwordTimeoutMs : requestTimeoutMs)
  }

  // FIREWALL_TEMP_REMOVE. `callback(error)` once.
  function removeTemp(tempId, callback) {
    var done = callback || function() {}
    request("FIREWALL_TEMP_REMOVE", { temp_id: tempId }, function(error) {
      if (!error || error.code === Protocol.ErrorCode.NOT_FOUND)
        root.tempDecisions = root.tempDecisions.filter(function(d) { return d.temp_id !== tempId })
      done(error)
    })
  }

  // FIREWALL_ALERT_MUTE. `callback(error)` once; the muted alert comes
  // back as FIREWALL_ALERT.
  function muteAlert(alertId, durationSecs, callback) {
    request("FIREWALL_ALERT_MUTE", { alert_id: alertId, duration_secs: durationSecs }, callback || function() {})
  }

  function loadUsb() {
    request("USBGUARD_LIST_DEVICES", {}, function(error, result) {
      if (error || !result || !Array.isArray(result.devices)) {
        root.usbListError = error || { code: Protocol.ErrorCode.INTERNAL_ERROR, message: "malformed device list" }
        root.usbDevices = []
        return
      }
      root.usbListError = null
      // Events that arrived while the list was on its way are already
      // applied; the listing is at least as new for every device it names.
      root.usbDevices = Usb.replaceDevices(root.usbDevices, result.devices)
    })
  }

  // USBGUARD_SET_POLICY. `callback(error)` once. The list follows from
  // the result and from USB_DEVICE_POLICY_CHANGED, which every client gets.
  function setUsbPolicy(deviceId, target, permanent, callback) {
    var done = callback || function() {}
    request("USBGUARD_SET_POLICY", { device_id: deviceId, target: target, permanent: !!permanent },
      function(error, result) {
        // A rejected device is removed (USB_DEVICE_REMOVED, possibly before
        // this answer), and one unplugged meanwhile must not come back.
        if (!error && result && target !== "reject" && Usb.findDevice(root.usbDevices, deviceId)) {
          var next = Usb.upsertDevice(root.usbDevices, result)
          next = Usb.applyPolicy(next, { device_id: deviceId, target: result.rule, permanent: !!permanent })
          if (target === "allow" && !permanent) next = Usb.markTemporary(next, deviceId)
          root.usbDevices = next
        }
        done(error)
      })
  }

  function loadThreats() {
    request("THREAT_LIST_ALERTS", {}, function(error, result) {
      if (error || !result || !Array.isArray(result.alerts)) return
      root.threatAlerts = Threat.replaceAlerts(root.threatAlerts, result.alerts)
    })
  }

  function loadTokens() {
    request("TOKEN_LIST", {}, function(error, result) {
      if (error || !result || !Array.isArray(result.tokens)) {
        root.tokensError = error || { code: Protocol.ErrorCode.INTERNAL_ERROR, message: "malformed token list" }
        return
      }
      root.tokensError = null
      var next = []
      for (var i = 0; i < result.tokens.length; i++) next = Touch.upsertToken(next, result.tokens[i])
      root.tokens = next
    })
  }

  function loadRules() {
    request("FIREWALL_LIST_RULES", {}, function(error, result) {
      if (error || !result || !Array.isArray(result.rules)) {
        root.firewallRulesError = error || { code: Protocol.ErrorCode.INTERNAL_ERROR, message: "malformed rule list" }
        return
      }
      root.firewallRulesError = null
      root.firewallRules = Network.sortRules(result.rules)
    })
  }

  // FIREWALL_ADD_RULE. `callback(error, rule)` once. An inbound allow
  // waits for the polkit password, so it gets longer than 10 s.
  function addRule(spec, callback) {
    var done = callback || function() {}
    request("FIREWALL_ADD_RULE", spec, function(error, result) {
      if (!error && result) root.firewallRules = Network.upsertRule(root.firewallRules, result)
      done(error, result)
      root.loadRules()
    }, Protocol.needsPassword(spec) ? passwordTimeoutMs : requestTimeoutMs)
  }

  // FIREWALL_REMOVE_RULE. `callback(error)` once.
  function removeRule(ruleId, callback) {
    var done = callback || function() {}
    request("FIREWALL_REMOVE_RULE", { rule_id: ruleId }, function(error) {
      // NOT_FOUND: someone else removed it.
      if (!error || error.code === Protocol.ErrorCode.NOT_FOUND)
        root.firewallRules = Network.removeRule(root.firewallRules, ruleId)
      done(error)
      root.loadRules()
    })
  }

  // FIREWALL_DECIDE. `callback(error)` once. The prompt closes on
  // FIREWALL_CONNECTION_RESOLVED, which every client gets; the scope sent
  // is remembered so the card can say what was decided.
  property var sentScopes: ({})
  function decideConnection(requestId, verdict, scope, callback) {
    var done = callback || function() {}
    var scopes = Object.assign({}, sentScopes)
    scopes[requestId] = scope
    sentScopes = scopes
    request("FIREWALL_DECIDE", { request_id: requestId, verdict: verdict, scope: scope }, function(error) {
      // "always" adds a rule, even when the connection was answered and
      // saving the rule failed.
      if (scope === "always") root.loadRules()
      done(error)
    })
  }

  function handlePromptEvent(name, params) {
    var now = Date.now()
    if (name === Protocol.FirewallEvent.CONNECTION_PROMPT) {
      connectionPrompts = Network.addPrompt(connectionPrompts, params, now)
    } else {
      var scope = sentScopes[params.request_id]
      if (scope !== undefined) {
        var scopes = Object.assign({}, sentScopes)
        delete scopes[params.request_id]
        sentScopes = scopes
      }
      connectionPrompts = Network.resolvePrompt(connectionPrompts, params, now, params.decided_by === "user" ? scope : undefined)
    }
  }

  function loadPosture() {
    request("POSTURE_GET_REPORT", {}, function(error, result) {
      root.postureError = error || null
      if (!error && result) root.posture = result
    })
  }

  // POSTURE_REFRESH: runs the checks now. `callback(error)` once.
  function refreshPosture(callback) {
    var done = callback || function() {}
    request("POSTURE_REFRESH", {}, function(error, result) {
      root.postureError = error || null
      if (!error && result) root.posture = result
      done(error)
    })
  }

  function loadVaults() {
    request("VAULT_LIST", {}, function(error, result) {
      if (error || !result || !Array.isArray(result.vaults)) {
        root.vaultsError = error || { code: Protocol.ErrorCode.INTERNAL_ERROR, message: "malformed vault list" }
        root.vaults = []
        return
      }
      root.vaultsError = null
      root.vaults = result.vaults
    })
  }

  function setVaultOp(vaultId, op) {
    var next = Object.assign({}, vaultOps)
    if (op) next[vaultId] = op
    else delete next[vaultId]
    vaultOps = next
  }

  // VAULT_MOUNT or VAULT_UNMOUNT (`op` "mount" | "unmount"). The daemon
  // asks for the passphrase itself, with pinentry. `callback(error)` once.
  // Returns false when that vault already has one on the way.
  function vaultOp(vaultId, op, callback) {
    var done = callback || function() {}
    if (vaultOps[vaultId]) return false
    setVaultOp(vaultId, op)
    request(op === "mount" ? "VAULT_MOUNT" : "VAULT_UNMOUNT", { vault_id: vaultId }, function(error, result) {
      root.setVaultOp(vaultId, "")
      if (!error && result) root.vaults = Vault.upsertVault(root.vaults, result)
      done(error)
    }, op === "mount" ? Vault.MOUNT_TIMEOUT_MS : Vault.UNMOUNT_TIMEOUT_MS)
    return true
  }

  // VAULT_PANIC. `callback(error, result)` once. Each vault that changed
  // also comes as VAULT_STATE_CHANGED; the list is read again anyway.
  function panicVaults(callback) {
    var done = callback || function() {}
    request("VAULT_PANIC", {}, function(error, result) {
      done(error, result)
      root.loadVaults()
    }, Vault.PANIC_TIMEOUT_MS)
  }

  // SANDBOX_RUN with `params` from Sandbox.checkForm. `callback(error,
  // run)` once.
  function runSandbox(params, callback) {
    var done = callback || function() {}
    request("SANDBOX_RUN", params, function(error, result) {
      if (error || !result) {
        done(error || { code: Protocol.ErrorCode.INTERNAL_ERROR, message: "no answer" }, null)
        return
      }
      var run = Object.assign({}, params, { pid: result.pid, started_at: Date.now() })
      root.sandboxRuns = Sandbox.addRun(root.sandboxRuns, run)
      done(null, run)
    })
  }

  function handleTokenEvent(name, params) {
    var now = Date.now()
    if (name === "TOKEN_INSERTED") tokens = Touch.upsertToken(tokens, params)
    else if (name === "TOKEN_REMOVED") {
      tokens = Touch.removeToken(tokens, params.token_id)
      touchRequests = Touch.endForToken(touchRequests, params.token_id, now)
    }
    else if (name === "TOKEN_TOUCH_REQUESTED") touchRequests = Touch.startRequest(touchRequests, params, now)
    else if (name === "TOKEN_TOUCH_COMPLETED") touchRequests = Touch.completeRequest(touchRequests, params, now)
  }

  // Sends one of Threat.ACTIONS for `alert`. `callback(error)` once. The
  // daemon announces only final states (THREAT_ALERT_RESOLVED), so the
  // answer is what records Isolate and Resume.
  function respondToThreat(alert, actionId, callback) {
    var done = callback || function() {}
    var action = Threat.ACTIONS[actionId]
    if (!action || !alert) {
      done({ code: Protocol.ErrorCode.INVALID_PARAMS, message: "unknown threat response " + actionId })
      return
    }
    request(action.method, Threat.actionParams(alert, action), function(error, result) {
      if (!error && result) root.threatAlerts = Threat.upsertAlert(root.threatAlerts, result)
      // The daemon resolves the alert as exited and says so in an event;
      // this answer may arrive first.
      else if (error && error.code === Protocol.ErrorCode.STALE_TARGET)
        root.threatAlerts = Threat.resolveAlert(root.threatAlerts, { alert_id: alert.alert_id, state: "exited" })
      done(error)
    })
  }

  function handleUsbEvent(name, params) {
    if (name === "USB_DEVICE_PRESENTED") usbDevices = Usb.upsertDevice(usbDevices, params)
    else if (name === "USB_DEVICE_POLICY_CHANGED") usbDevices = Usb.applyPolicy(usbDevices, params)
    else if (name === "USB_DEVICE_REMOVED") usbDevices = Usb.removeDevice(usbDevices, params.device_id)
  }

  function failPending(message) {
    var waiting = pending
    pending = ({})
    for (var id in waiting)
      waiting[id].callback({ code: Protocol.ErrorCode.INTERNAL_ERROR, message: message }, null)
  }

  function handshake() {
    request("HELLO", { protocol_version: Protocol.PROTOCOL_VERSION, client: Protocol.CLIENT_NAME },
      function(error, result) {
        if (error) {
          root.lastError = error.message || "HELLO failed"
          return
        }
        root.daemonVersion = result.daemon_version || ""
        root.modules = result.modules || []
        root.ready = true
        root.failedAttempts = 0
        root.lastError = ""
        root.request("SUBSCRIBE", { topics: Protocol.TOPICS }, function(subError) {
          if (subError) root.lastError = subError.message || "SUBSCRIBE failed"
        })
        root.loadFirewall()
        root.loadUsb()
        root.loadThreats()
        root.loadTokens()
        root.loadRules()
        root.loadUfwRules()
        root.loadTemps()
        root.loadPosture()
        root.loadVaults()
      })
  }

  function handleLine(line) {
    if (line === "") return
    var msg = Protocol.decode(line)
    if (msg.kind === "response") {
      var entry = pending[msg.id]
      if (!entry) return
      delete pending[msg.id]
      entry.callback(msg.error || null, msg.error ? null : msg.result)
    } else if (msg.kind === "event") {
      if (msg.name === "MODULE_STATE_CHANGED") updateModule(msg.params)
      else if (msg.name === Protocol.FirewallEvent.MODE_CHANGED) {
        firewallMode = msg.params.mode || "unknown"
        firewallInfo = msg.params
        // Which saved rules are enforced follows the mode, and temporary
        // inbound allows move between UFW and our table.
        loadRules()
        loadUfwRules()
      }
      else if (msg.name === Protocol.FirewallEvent.TEMP_CHANGED) {
        if (Array.isArray(msg.params.decisions)) tempDecisions = msg.params.decisions
        loadUfwRules()
      }
      else if (msg.name === Protocol.FirewallEvent.CONNECTION_PROMPT
               || msg.name === Protocol.FirewallEvent.CONNECTION_RESOLVED) handlePromptEvent(msg.name, msg.params)
      else if (msg.name === "POSTURE_CHANGED") posture = msg.params
      else if (msg.name === "VAULT_STATE_CHANGED") vaults = Vault.upsertVault(vaults, msg.params)
      else if (msg.name === Protocol.FirewallEvent.ALERT) firewallAlerts = Indicator.mergeAlert(firewallAlerts, msg.params)
      else if (msg.name.indexOf("USB_DEVICE_") === 0) handleUsbEvent(msg.name, msg.params)
      else if (msg.name === "THREAT_EXEC_DETECTED") threatAlerts = Threat.upsertAlert(threatAlerts, msg.params)
      else if (msg.name === "THREAT_ALERT_RESOLVED") threatAlerts = Threat.resolveAlert(threatAlerts, msg.params)
      else if (msg.name.indexOf("TOKEN_") === 0) handleTokenEvent(msg.name, msg.params)
      eventReceived(msg.name, msg.params)
    } else {
      console.warn("security-hub: dropped daemon message: " + msg.reason)
    }
  }

  function updateModule(status) {
    // USBGuard came back (usbguard-dbus restarted): the daemon resyncs its
    // cache without announcing the devices it already had, so list again.
    // While it is away, its devices are unknown.
    if (status.module === "usbguard") {
      if (status.state !== "active") usbDevices = []
      else if (moduleState("usbguard") !== "active") Qt.callLater(loadUsb)
    }
    // A backend that appears or goes changes which calls work.
    if (status.module === "vault" && status.state !== moduleState("vault")) Qt.callLater(loadVaults)
    if (status.module === "token" && status.state !== moduleState("token")) Qt.callLater(loadTokens)
    var next = modules.slice()
    for (var i = 0; i < next.length; i++) {
      if (next[i].module === status.module) {
        next[i] = status
        modules = next
        return
      }
    }
    next.push(status)
    modules = next
  }

  function scheduleReconnect() {
    // A dropped connection can report both a state change and an error;
    // count it as one failure.
    if (stopping || reconnectTimer.running) return
    reconnectTimer.interval = Protocol.backoffMs(failedAttempts)
    failedAttempts++
    reconnectTimer.restart()
  }

  function connectNow() {
    if (socketPath === "") {
      lastError = "XDG_RUNTIME_DIR is not set"
      return
    }
    socket.connected = true
  }

  Socket {
    id: socket
    path: root.socketPath

    parser: SplitParser {
      onRead: function(line) { root.handleLine(line) }
    }

    onConnectionStateChanged: {
      if (connected) {
        root.handshake()
        return
      }
      root.ready = false
      root.modules = []
      root.firewallMode = ""
      root.firewallInfo = null
      root.firewallAlerts = []
      root.ufwRules = null
      root.ufwRulesError = null
      root.tempDecisions = []
      root.usbDevices = []
      root.usbListError = null
      // A restarted daemon starts with no alerts; the next listing says
      // which are still open.
      root.threatAlerts = Threat.replaceAlerts(root.threatAlerts, [])
      // Request ids start over with a restarted daemon.
      root.tokens = []
      root.tokensError = null
      root.touchRequests = []
      root.firewallRules = []
      root.firewallRulesError = null
      // The daemon answers held connections itself when this client goes.
      root.connectionPrompts = []
      root.sentScopes = ({})
      root.posture = null
      root.postureError = null
      root.vaults = []
      root.vaultsError = null
      root.vaultOps = ({})
      root.failPending("connection to omarchy-securityd closed")
      root.scheduleReconnect()
    }

    onError: function(error) {
      if (connected) return
      root.lastError = "omarchy-securityd is not reachable at " + root.socketPath
      root.scheduleReconnect()
    }
  }

  FileView {
    id: seenFile
    path: Indicator.seenStatePath(function(name) { return Quickshell.env(name) })
    printErrors: false
    onLoaded: {
      var value = Indicator.parseSeenState(text())
      if (value > root.alertsSeenAt) root.alertsSeenAt = value
    }
  }

  // The OSD and the prompts need a window whether or not the hub is
  // open, and the service is the part of the plugin the shell always keeps
  // loaded. They are loaded by URL, since components/ imports this
  // directory. Only the shell sets `shell`, so a test that builds this
  // service alone gets no window.
  Loader {
    id: threatLoader
    active: root.shell !== null
    source: Qt.resolvedUrl("../components/ThreatAlertOSD.qml")
    onLoaded: item.security = root
  }

  Loader {
    active: root.shell !== null
    source: Qt.resolvedUrl("../components/YubiKeyPrompt.qml")
    onLoaded: item.security = root
  }

  // Below the threat card when both are up, so neither covers the other.
  Loader {
    active: root.shell !== null
    source: Qt.resolvedUrl("../components/ConnectionPrompt.qml")
    onLoaded: {
      item.security = root
      item.topOffset = Qt.binding(function() { return threatLoader.item ? threatLoader.item.cardHeight : 0 })
    }
  }

  // `omarchy-shell security-hub open network`: the daemon's notification
  // action, and a keybinding. `tab` is a tab or module id, or "" for the
  // tab the hub was left on. The service is always loaded, so this works
  // while the panel is not.
  IpcHandler {
    target: "security-hub"

    function open(tab: string): void { root.summonHub(tab, false) }
    function toggle(tab: string): void { root.summonHub(tab, true) }
    function close(): void { if (root.shell) root.shell.hide(root.pluginId) }
  }

  readonly property string pluginId: manifest && manifest.id ? String(manifest.id) : "security-hub"

  // Before the shell is asked; the e2e test has no shell.
  signal hubRequested(string tab, bool toggle)

  function summonHub(tab, toggle) {
    hubRequested(tab, toggle)
    if (!shell) return
    var payload = JSON.stringify(tab ? { tab: String(tab) } : {})
    if (toggle) shell.toggle(pluginId, payload)
    else shell.summon(pluginId, payload)
  }

  Timer {
    id: reconnectTimer
    repeat: false
    onTriggered: root.connectNow()
  }

  // A daemon that accepts a request and never answers must not leave its
  // caller waiting forever.
  Timer {
    interval: 1000
    repeat: true
    running: socket.connected
    onTriggered: {
      var now = Date.now()
      for (var id in root.pending) {
        var entry = root.pending[id]
        if (now - entry.sentAt < entry.timeoutMs) continue
        delete root.pending[id]
        entry.callback({ code: Protocol.ErrorCode.INTERNAL_ERROR, message: "request timed out" }, null)
      }
    }
  }

  Component.onCompleted: connectNow()
  Component.onDestruction: {
    stopping = true
    reconnectTimer.stop()
    socket.connected = false
  }
}
