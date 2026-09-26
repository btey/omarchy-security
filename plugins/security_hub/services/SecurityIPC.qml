// SPDX-License-Identifier: MIT
import QtQuick
import Quickshell
import Quickshell.Io
import "Protocol.js" as Protocol

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

  signal eventReceived(string name, var params)

  property int nextId: 1
  property var pending: ({})
  property int failedAttempts: 0
  property bool stopping: false

  readonly property int requestTimeoutMs: 10000

  // Sends `method` and calls `callback(error, result)` once, with `error`
  // being a JSON-RPC error object or null.
  function request(method, params, callback) {
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
    pending[id] = { callback: done, sentAt: Date.now() }
    socket.write(Protocol.encodeRequest(id, method, params))
    socket.flush()
  }

  function moduleState(moduleId) {
    for (var i = 0; i < modules.length; i++)
      if (modules[i].module === moduleId) return modules[i].state
    return ""
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
      eventReceived(msg.name, msg.params)
    } else {
      console.warn("security-hub: dropped daemon message: " + msg.reason)
    }
  }

  function updateModule(status) {
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
      root.failPending("connection to omarchy-securityd closed")
      root.scheduleReconnect()
    }

    onError: function(error) {
      if (connected) return
      root.lastError = "omarchy-securityd is not reachable at " + root.socketPath
      root.scheduleReconnect()
    }
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
        if (now - entry.sentAt < root.requestTimeoutMs) continue
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
