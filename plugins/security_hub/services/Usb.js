// SPDX-License-Identifier: MIT
//
// Rules for the USBGuard panel (plan task 3.3, docs/ipc-protocol.md §4.3):
// the device list SecurityIPC keeps from USBGUARD_LIST_DEVICES and the
// USB_DEVICE_* events, the actions each device offers, and the text the
// panel shows. Free of QML so it can be tested with plain node.
.pragma library

// Marks this shell keeps on a device, which the daemon's UsbDevice does not
// carry:
//   saved      the last change was written to rules.conf (permanent), so
//              the device is let in whenever it is plugged in again
//   temporary  this shell approved it for now, so Save permanent can
//              follow. Only the shell's own Approve sets it: the daemon
//              reports `permanent: false` for every change it did not make,
//              including USBGuard applying a saved rule at plug-in.
var MARKS = ["saved", "temporary"]

// `device` with the marks of `old` it does not set itself.
function withMarks(device, old) {
  if (!old) return device
  var copy = null
  for (var i = 0; i < MARKS.length; i++) {
    var mark = MARKS[i]
    if (old[mark] === undefined || device[mark] !== undefined) continue
    if (!copy) {
      copy = {}
      for (var key in device) copy[key] = device[key]
    }
    copy[mark] = old[mark]
  }
  return copy || device
}

function withFields(device, fields) {
  var copy = {}
  for (var key in device) copy[key] = device[key]
  for (var field in fields) copy[field] = fields[field]
  return copy
}

// `devices` with `device` added or, when its device_id is already there,
// replaced, keeping its marks. The list stays in device_id order, which is
// the order USBGuard saw the devices arrive: rows must not move under the
// pointer, or a second click could land on another device's button.
function upsertDevice(devices, device) {
  if (!device || typeof device.device_id !== "number") return devices
  var next = []
  var placed = false
  for (var i = 0; i < devices.length; i++) {
    var d = devices[i]
    if (d.device_id === device.device_id) {
      next.push(withMarks(device, d))
      placed = true
      continue
    }
    if (!placed && d.device_id > device.device_id) {
      next.push(device)
      placed = true
    }
    next.push(d)
  }
  if (!placed) next.push(device)
  return next
}

function removeDevice(devices, deviceId) {
  var next = []
  for (var i = 0; i < devices.length; i++)
    if (devices[i].device_id !== deviceId) next.push(devices[i])
  return next.length === devices.length ? devices : next
}

function findDevice(devices, deviceId) {
  for (var i = 0; i < devices.length; i++)
    if (devices[i].device_id === deviceId) return devices[i]
  return null
}

// USB_DEVICE_POLICY_CHANGED `{device_id, target, permanent}`. A permanent
// change sets `saved` and ends `temporary`; any change away from allow
// ends `temporary` too. A device the list does not have yet is left
// alone: USB_DEVICE_PRESENTED or the next listing brings it in with its
// name.
function applyPolicy(devices, change) {
  if (!change || typeof change.device_id !== "number") return devices
  var old = findDevice(devices, change.device_id)
  if (!old) return devices
  var permanent = !!change.permanent
  return upsertDevice(devices, withFields(old, {
    rule: change.target,
    saved: permanent,
    temporary: !permanent && change.target === "allow" && old.temporary === true
  }))
}

// After this shell's own Approve: the device is allowed until unplugged.
function markTemporary(devices, deviceId) {
  var old = findDevice(devices, deviceId)
  if (!old || old.rule !== "allow") return devices
  return upsertDevice(devices, withFields(old, { temporary: true, saved: false }))
}

// A listing replaces the list, but keeps the marks.
function replaceDevices(oldDevices, listed) {
  var next = []
  for (var i = 0; i < listed.length; i++)
    next = upsertDevice(next, withMarks(listed[i], findDevice(oldDevices, listed[i].device_id)))
  return next
}

// Every interface class the device exposes: `interfaces` when it has more
// than one, else the first one's.
function deviceClasses(device) {
  if (!device) return []
  if (device.interfaces && device.interfaces.length > 0) return device.interfaces
  return device.interface_class ? [device.interface_class] : []
}

var CLASS_LABELS = {
  "01": "Audio",
  "02": "Communications",
  "03": "Keyboard / mouse",
  "05": "Physical",
  "06": "Camera / scanner",
  "07": "Printer",
  "08": "Storage",
  "09": "Hub",
  "0a": "Data",
  "0b": "Smart card",
  "0d": "Content security",
  "0e": "Video",
  "0f": "Health",
  "10": "Audio / video",
  "11": "Billboard",
  "12": "USB-C bridge",
  "dc": "Diagnostic",
  "e0": "Wireless",
  "ef": "Miscellaneous",
  "fe": "Application",
  "ff": "Vendor specific"
}

function classLabel(code) {
  var key = String(code || "").toLowerCase()
  return CLASS_LABELS[key] || (key ? "Class " + key : "Unknown")
}

// "Storage, Keyboard / mouse", each class once, in interface order.
function classSummary(device) {
  var seen = {}
  var labels = []
  var classes = deviceClasses(device)
  for (var i = 0; i < classes.length; i++) {
    var label = classLabel(classes[i])
    if (seen[label]) continue
    seen[label] = true
    labels.push(label)
  }
  return labels.join(", ")
}

// Nerd Font glyph for the device's main class.
function classIcon(device) {
  var classes = deviceClasses(device)
  var has = function(c) { return classes.indexOf(c) >= 0 }
  if (has("08")) return "\u{F129E}"  // nf-md-usb_flash_drive
  if (has("03")) return "\u{F030C}"  // nf-md-keyboard
  if (has("0e") || has("06")) return "\u{F05A0}"  // nf-md-webcam
  if (has("01")) return "\u{F02CB}"  // nf-md-headset
  if (has("e0")) return "\u{F00AF}"  // nf-md-bluetooth
  if (has("0b")) return "\u{F0306}"  // nf-md-key
  return "\u{F0553}"  // nf-md-usb
}

// A warning for devices that can type. Something that looks like a USB
// stick but also registers a keyboard is the classic keystroke-injection
// attack ("BadUSB"). A keyboard with other interfaces (a headset's volume
// keys, a dock) is common, but still worth a line before approving it.
function riskNote(device) {
  var classes = deviceClasses(device)
  if (classes.indexOf("03") < 0) return ""
  var others = false
  for (var i = 0; i < classes.length; i++) if (classes[i] !== "03") others = true
  if (!others) return ""
  if (classes.indexOf("08") >= 0)
    return "Storage that can also type as a keyboard: a known attack. Approve only if you expected this."
  return "Can also type as a keyboard. Approve only if you expected that."
}

// "0951:1666 · 00187D0F2E3B"
function idLine(device) {
  if (!device) return ""
  var line = (device.vendor_id || "????") + ":" + (device.product_id || "????")
  return device.serial ? line + " · " + device.serial : line
}

function ruleLabel(device) {
  if (!device) return ""
  switch (device.rule) {
  case "allow": return device.saved ? "Allowed · saved" : device.temporary ? "Allowed until unplugged" : "Allowed"
  case "block": return device.saved ? "Blocked · saved" : "Blocked"
  case "reject": return "Rejected"
  default: return "Unknown"
  }
}

// ThemeProvider.role name for a device's rule.
function ruleRole(rule) {
  switch (rule) {
  case "allow": return "success"
  case "block": return "warning"
  case "reject": return "danger"
  default: return "muted"
  }
}

// Buttons for a device, in display order. Each is {id, label, hint,
// target, permanent, confirm}; `hint` is the tooltip and `confirm` asks
// for a second click. A blocked device
// can be approved for now (until it is unplugged), approved for good (a
// rule in /etc/usbguard/rules.conf) or rejected (removed until it is
// plugged in again). An allowed one can be blocked again or rejected, and
// saved for good when this shell approved it for now (`temporary`). The
// daemon does not say whether an allow comes from a rule, and devices
// allowed at startup normally do (usbguard generate-policy), so those are
// not offered a second rule.
//
// An allowed hub gets none: blocking one cuts off every device behind it,
// which on a laptop's root hub (listed as "xHCI Host Controller") includes
// the keyboard. A blocked hub, such as a new dock, can still be approved.
var ACTIONS = {
  approve: { id: "approve", label: "Approve", hint: "Allow it until it is unplugged",
    target: "allow", permanent: false, confirm: false },
  savePermanent: { id: "savePermanent", label: "Save permanent",
    hint: "Allow it now and whenever it is plugged in (adds a USBGuard rule)",
    target: "allow", permanent: true, confirm: false },
  block: { id: "block", label: "Block", hint: "Block it again; it stays plugged in",
    target: "block", permanent: false, confirm: false },
  reject: { id: "reject", label: "Reject", hint: "Remove it until it is unplugged and plugged in again",
    target: "reject", permanent: false, confirm: true }
}

function isHub(device) {
  return deviceClasses(device).indexOf("09") >= 0
}

function actionsFor(device) {
  if (!device) return []
  if (isHub(device) && device.rule === "allow") return []
  switch (device.rule) {
  case "block": return [ACTIONS.approve, ACTIONS.savePermanent, ACTIONS.reject]
  case "allow": return device.temporary === true ? [ACTIONS.savePermanent, ACTIONS.block, ACTIONS.reject]
    : [ACTIONS.block, ACTIONS.reject]
  default: return []
  }
}

// Why an allowed device has no buttons, or "".
function noActionsNote(device) {
  if (device && isHub(device) && device.rule === "allow")
    return "Blocking a hub cuts off every device behind it."
  return ""
}

function blockedCount(devices) {
  var n = 0
  for (var i = 0; i < devices.length; i++) if (devices[i].rule === "block") n++
  return n
}

// Error codes, as in Protocol.ErrorCode (kept here so this file stands alone).
var MODULE_UNAVAILABLE = -32002
var NOT_FOUND = -32003
var PERMISSION_DENIED = -32004
var BACKEND_ERROR = -32006
var NOT_IMPLEMENTED = -32007

// What the panel says instead of a list, or "" when it shows the list.
// `moduleState` is the usbguard ModuleStatus.state, `listError` the error
// of the last USBGUARD_LIST_DEVICES (null when it worked).
function emptyText(ready, moduleState, listError, devices) {
  if (!ready) return "Not connected to omarchy-securityd."
  if (moduleState === "not_implemented" || (listError && listError.code === NOT_IMPLEMENTED))
    return "This daemon was built without USBGuard support."
  if (moduleState === "unavailable" || (listError && listError.code === MODULE_UNAVAILABLE))
    return "USBGuard is not running. Start usbguard.service and usbguard-dbus.service."
  if (listError) return "Could not list USB devices: " + (listError.message || "unknown error")
  if (devices.length === 0) return "No USB devices connected."
  return ""
}

// A failed USBGUARD_SET_POLICY, for the line under the device.
function actionErrorText(error) {
  if (!error) return ""
  switch (error.code) {
  case PERMISSION_DENIED: return "Not allowed: polkit refused the change."
  case NOT_FOUND: return "The device is no longer connected."
  case MODULE_UNAVAILABLE: return "USBGuard is not running."
  case BACKEND_ERROR:
    return "USBGuard refused: " + (error.data && error.data.detail ? error.data.detail : error.message || "unknown reason")
  default: return error.message || "The change failed."
  }
}

if (typeof module !== "undefined") module.exports = {
  upsertDevice: upsertDevice, removeDevice: removeDevice, findDevice: findDevice,
  applyPolicy: applyPolicy, markTemporary: markTemporary, replaceDevices: replaceDevices, deviceClasses: deviceClasses,
  classLabel: classLabel, classSummary: classSummary, classIcon: classIcon, riskNote: riskNote,
  idLine: idLine, ruleLabel: ruleLabel, ruleRole: ruleRole, ACTIONS: ACTIONS, isHub: isHub,
  actionsFor: actionsFor, noActionsNote: noActionsNote,
  blockedCount: blockedCount, emptyText: emptyText, actionErrorText: actionErrorText
}
