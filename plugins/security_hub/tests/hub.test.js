// SPDX-License-Identifier: MIT
// node --test plugins/security_hub/tests/
"use strict"
const test = require("node:test")
const assert = require("node:assert")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

// Hub.js is a QML `.pragma library` script; drop the pragma to run it as
// plain JavaScript.
const source = fs.readFileSync(path.join(__dirname, "../services/Hub.js"), "utf8")
  .replace(/^\.pragma library$/m, "")
const sandbox = { module: { exports: {} } }
vm.runInNewContext(source, sandbox)
const H = sandbox.module.exports
const plain = value => JSON.parse(JSON.stringify(value))

test("names the seven tabs of §5.11", () => {
  assert.deepStrictEqual(plain(H.TABS.map(t => t.id)),
    ["overview", "threats", "usb", "tokens", "network", "vaults", "hardening"])
  for (const tab of H.TABS) assert.ok(tab.icon && tab.label, tab.id)
})

test("picks the tab a payload names", () => {
  assert.strictEqual(H.tabFor("network"), "network")
  assert.strictEqual(H.tabFor("Network"), "network")
  // Module ids work too.
  assert.strictEqual(H.tabFor("usbguard"), "usb")
  assert.strictEqual(H.tabFor("firewall"), "network")
  assert.strictEqual(H.tabFor("posture"), "hardening")
  assert.strictEqual(H.tabFor("sandbox"), "threats")
  assert.strictEqual(H.tabFor("nonsense"), "")
  assert.strictEqual(H.tabFor(undefined), "")
  assert.strictEqual(H.tabFromPayload('{"tab": "network"}', "overview"), "network")
  // No tab, an unknown one, or bad JSON: stay where the user was.
  assert.strictEqual(H.tabFromPayload("{}", "vaults"), "vaults")
  assert.strictEqual(H.tabFromPayload('{"tab": "nope"}', "vaults"), "vaults")
  assert.strictEqual(H.tabFromPayload("{not json", "usb"), "usb")
  assert.strictEqual(H.tabFromPayload("", ""), "overview")
})

test("steps between tabs and wraps", () => {
  assert.strictEqual(H.neighbour("overview", 1), "threats")
  assert.strictEqual(H.neighbour("overview", -1), "hardening")
  assert.strictEqual(H.neighbour("hardening", 1), "overview")
  assert.strictEqual(H.neighbour("bogus", 1), "overview")
})

test("marks tabs with something waiting", () => {
  assert.deepStrictEqual(plain(H.attention({})), {})
  const marks = H.attention({
    threatAlerts: [{ state: "open" }, { state: "quarantined" }, { state: "killed" }],
    usbDevices: [{ rule: "block" }, { rule: "allow" }],
    touchRequests: [{ request_id: 1 }, { request_id: 2, outcome: "touched" }],
    heldConnections: 0,
    unseenAlerts: 3,
    posture: "warn"
  })
  assert.deepStrictEqual(plain(marks), {
    threats: { count: 2, role: "danger" },
    usb: { count: 1, role: "warning" },
    tokens: { count: 1, role: "warning" },
    network: { count: 3, role: "warning" },
    hardening: { count: 0, role: "warning" }
  })
  // A held connection waits for an answer; new blocked traffic does not.
  assert.deepStrictEqual(plain(H.attention({ heldConnections: 1, unseenAlerts: 2, posture: "fail" })), {
    network: { count: 3, role: "danger" },
    hardening: { count: 0, role: "danger" }
  })
  assert.deepStrictEqual(plain(H.attention({ posture: "pass" })), {})
  assert.strictEqual(H.countText(0), "")
  assert.strictEqual(H.countText(4), "4")
  assert.strictEqual(H.countText(12), "9+")
})

test("merges both kinds of alert, newest first", () => {
  const threats = [
    { alert_id: 1, detected_at: 1000, state: "killed" },
    { alert_id: 2, detected_at: 5000, state: "open" }
  ]
  const blocked = [
    // A stream of packets: its last one counts.
    { alert_id: 9, first_seen: 500, last_seen: 6000 },
    { alert_id: 8, first_seen: 2000, last_seen: 2000 }
  ]
  const entries = H.history(threats, blocked, 8)
  assert.deepStrictEqual(plain(entries.map(e => e.key)), ["firewall:9", "threat:2", "firewall:8", "threat:1"])
  assert.deepStrictEqual(plain(entries.map(e => e.tab)), ["network", "threats", "network", "threats"])
  assert.strictEqual(H.history(threats, blocked, 2).length, 2)
  assert.deepStrictEqual(plain(H.history(undefined, null)), [])
})

test("describes blocked traffic and module states", () => {
  assert.strictEqual(H.firewallTitle({ direction: "inbound", protocol: "tcp", src: "203.0.113.9", dst: "192.168.1.5", dst_port: 22 }),
    "Blocked TCP from 203.0.113.9 to port 22")
  assert.strictEqual(H.firewallTitle({ direction: "forward", protocol: "tcp", src: "203.0.113.9", dst: "172.17.0.2", dst_port: 80 }),
    "Blocked TCP from 203.0.113.9 to a container, port 80")
  assert.strictEqual(H.firewallTitle({ direction: "outbound", protocol: "udp", src: "192.168.1.5", dst: "198.51.100.7", dst_port: 53 }),
    "Blocked UDP to 198.51.100.7 port 53")
  assert.strictEqual(H.firewallTitle({ direction: "inbound", protocol: "icmp", src: "10.0.0.2" }),
    "Blocked ICMP from 10.0.0.2")
  assert.strictEqual(H.firewallDetail({ count: 1, iface: "wlan0", source: "ufw" }, 0), "1 packet · wlan0 · UFW")
  assert.strictEqual(H.firewallDetail({ count: 12, iface: "eth0", source: "omarchy", muted_until: 5000 }, 1000),
    "12 packets · eth0 · muted")
  assert.strictEqual(H.ago(10 * 1000), "just now")
  assert.strictEqual(H.ago(5 * 60 * 1000), "5 min ago")
  assert.strictEqual(H.ago(3 * 3600 * 1000), "3 h ago")
  assert.strictEqual(H.ago(72 * 3600 * 1000), "3 d ago")
  assert.strictEqual(H.modulesSummary([]), "")
  assert.strictEqual(H.modulesSummary([{ state: "active" }, { state: "active" }]), "All 2 modules active")
  assert.strictEqual(H.modulesSummary([{ state: "active" }, { state: "unavailable" }]), "1 of 2 modules active")
})

// A qmldir replaces the implicit directory import: a view missing from it
// is not found at all.
test("every QML file is in its directory's qmldir", () => {
  for (const dir of ["components", "services"]) {
    const root = path.join(__dirname, "..", dir)
    const listed = fs.readFileSync(path.join(root, "qmldir"), "utf8").split("\n")
      .filter(line => line.trim() !== "" && !line.startsWith("#"))
      .map(line => line.trim().split(/\s+/).pop())
    for (const file of fs.readdirSync(root).filter(f => f.endsWith(".qml")))
      assert.ok(listed.includes(file), dir + "/" + file + " is not in " + dir + "/qmldir")
  }
})

test("keeps the panel clear of the bar", () => {
  const plain = value => JSON.parse(JSON.stringify(value))
  // Omarchy's bar is 26 px at the top; the gap is 10.
  assert.deepStrictEqual(plain(H.panelMargins("top", 26, 10)), { top: 36, right: 10 })
  assert.deepStrictEqual(plain(H.panelMargins("right", 28, 10)), { top: 10, right: 38 })
  // A bar on the left or at the bottom is not in the top-right corner.
  assert.deepStrictEqual(plain(H.panelMargins("left", 28, 10)), { top: 10, right: 10 })
  assert.deepStrictEqual(plain(H.panelMargins("bottom", 26, 10)), { top: 10, right: 10 })
  // A hidden bar takes no room.
  assert.deepStrictEqual(plain(H.panelMargins("top", 0, 10)), { top: 10, right: 10 })
  assert.deepStrictEqual(plain(H.panelMargins("", 26, 10)), { top: 36, right: 10 })
})
