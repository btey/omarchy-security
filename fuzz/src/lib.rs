// SPDX-License-Identifier: GPL-3.0-or-later

//! The checks behind the fuzz targets (plan task 4.5, §5.13). Each takes
//! arbitrary bytes, runs one parser that reads untrusted input, and panics
//! when the result breaks a property the rest of the code relies on. Not
//! panicking on its own is the first property: every parser must answer
//! `None` or an error for input it does not understand.
//!
//! `fuzz_targets/` hands them to libFuzzer (`make fuzz`, nightly), and
//! `tests/seeds.rs` replays `seeds/` through them on stable
//! (`make test-fuzz`).

use std::future::Future;
use std::net::IpAddr;
use std::path::Path;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use omarchy_security_helper::firewall::{QueueRule, render_with, ufw_temp_args};
use omarchy_security_helper::{exec, packet};
use omarchy_security_proto::MAX_FRAME_BYTES;
use omarchy_security_proto::helper::{HelperOp, HelperRequest, HubMode, UfwTempChange};
use omarchy_security_proto::rpc::{encode_frame, parse_request};
use omarchy_security_proto::types::{AlertDirection, FirewallRule, TempDecision, check_temp_spec};
use omarchy_security_proto::ufw::{parse_temp_tag, parse_tuple, temp_decision, temp_tag};
use omarchy_securityd::server::{FrameError, read_frame};
use omarchy_securityd::token::{TouchEdge, TouchTracker, relevant_uevent};
use omarchy_securityd::{alerts, ufw, usbguard};

/// Runs a future that never waits: every reader here is a byte slice.
fn ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    match pin!(future).poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("a read from a byte slice waited"),
    }
}

// ------------------------------------------------------ client socket

/// NDJSON framing and JSON-RPC parsing of the daemon's client socket
/// (`omarchy-securityd` `server.rs`). The first byte picks the reader's
/// buffer size, so frames cross buffer boundaries anywhere.
///
/// * The frames are the input's lines, without the newline; a line
///   longer than `MAX_FRAME_BYTES` ends the connection, and so does a
///   last line with no newline once it is that long.
/// * Every error response is one line of JSON: nothing a client sends can
///   add a line to what the daemon writes back.
pub fn rpc_frame(data: &[u8]) {
    let Some((&size, input)) = data.split_first() else {
        return;
    };
    let mut reader = tokio::io::BufReader::with_capacity(usize::from(size).max(1), input);
    let mut lines = input.split(|&b| b == b'\n').peekable();
    let mut frame = Vec::new();
    loop {
        let line = lines.next().expect("split yields at least one piece");
        let terminated = lines.peek().is_some();
        match ready(read_frame(&mut reader, &mut frame)) {
            Ok(true) => {
                assert!(terminated && line.len() <= MAX_FRAME_BYTES);
                assert_eq!(frame, line);
            }
            Ok(false) => {
                assert!(!terminated && line.len() <= MAX_FRAME_BYTES);
                return;
            }
            Err(FrameError::TooLong) => {
                assert!(line.len() > MAX_FRAME_BYTES);
                return;
            }
            Err(FrameError::Io(err)) => panic!("reading a slice failed: {err}"),
        }
        if frame.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if let Err(response) = parse_request(&frame) {
            let line = encode_frame(&response).expect("an error response serializes");
            assert_eq!(line.find('\n'), Some(line.len() - 1), "{line}");
            serde_json::from_str::<serde_json::Value>(&line).expect("the response is JSON");
        }
    }
}

// ------------------------------------------------------ helper socket

/// Requests to the root helper, and what it makes of the firewall ones:
/// the `nft` script (`render_with`) and the `ufw` argv (`ufw_temp_args`).
/// Whatever a client puts in a rule or a temporary decision, the script
/// holds only fixed text, numbers and addresses the helper printed itself,
/// one line per rule; the argv holds only such words, none an option.
pub fn helper_request(data: &[u8]) {
    let Ok(request) = serde_json::from_slice::<HelperRequest>(data) else {
        return;
    };
    let text = serde_json::to_string(&request).expect("a request serializes");
    let again: HelperRequest = serde_json::from_str(&text).expect("a request parses back");
    assert_eq!(again, request);
    let queue = Some(QueueRule {
        num: 7433,
        uid: 1000,
        loopback: false,
    });
    match &request.op {
        HelperOp::FirewallApply { rules } | HelperOp::FirewallSetMode { rules, .. } => {
            for mode in [HubMode::Ufw, HubMode::Standalone] {
                if let Ok(script) = render_with(mode, rules, queue, &[], 0) {
                    check_nft(&script, rules, &[], mode);
                }
            }
        }
        HelperOp::FirewallTempSet { decisions } => {
            for mode in [HubMode::Ufw, HubMode::Standalone] {
                if let Ok(script) = render_with(mode, &[], None, decisions, 0) {
                    check_nft(&script, &[], decisions, mode);
                }
            }
        }
        HelperOp::UfwTemp { change, decision } => {
            if let Ok(args) = ufw_temp_args(*change, decision) {
                check_ufw_args(&args);
            }
        }
        _ => {}
    }
}

/// Quoted strings the renderer writes itself.
const NFT_STRINGS: &[&str] = &[
    "mode=ufw",
    "mode=standalone",
    "lo",
    "docker0",
    "omarchy:queue",
    "omarchy:docker",
    "[OMSEC BLOCK] ",
    "[OMSEC DOCKER BLOCK] ",
];

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// The properties of a rendered script that keep it injection-safe.
pub fn check_nft(script: &str, rules: &[FirewallRule], temps: &[TempDecision], mode: HubMode) {
    let mut depth = 0i32;
    for line in script.lines() {
        let parts: Vec<&str> = line.split('"').collect();
        assert!(parts.len() % 2 == 1, "unbalanced quotes: {line:?}");
        for (i, part) in parts.iter().enumerate() {
            if i % 2 == 1 {
                let known = NFT_STRINGS.contains(part)
                    || part.strip_prefix("omarchy:tmp:").is_some_and(digits)
                    || part.strip_prefix("omarchy:").is_some_and(digits);
                assert!(known, "unexpected string {part:?} in {line:?}");
                continue;
            }
            for c in part.chars() {
                let allowed = c.is_ascii_alphanumeric() || " \t.:/_,@{}=-".contains(c);
                let header = c == ';' && line.trim_start().starts_with("type filter hook");
                assert!(allowed || header, "unexpected {c:?} in {line:?}");
                match c {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                assert!(depth >= 0, "unbalanced braces at {line:?}");
            }
        }
    }
    assert_eq!(depth, 0, "unbalanced braces in\n{script}");
    // One line per rule: nothing in a rule can start another.
    if mode == HubMode::Standalone {
        for rule in rules.iter().filter(|r| r.spec.executable.is_none()) {
            let tag = format!("comment \"omarchy:{}\"", rule.rule_id);
            let expected = rules
                .iter()
                .filter(|r| r.spec.executable.is_none() && r.rule_id == rule.rule_id)
                .count();
            assert_eq!(
                script.lines().filter(|l| l.ends_with(&tag)).count(),
                expected
            );
        }
    }
    for decision in temps {
        let tag = format!("comment \"omarchy:tmp:{}\"", decision.temp_id);
        assert!(script.lines().filter(|l| l.ends_with(&tag)).count() <= temps.len());
    }
}

/// The properties of a `ufw` argv: plain words, none of them an option.
pub fn check_ufw_args(args: &[String]) {
    assert!(matches!(
        args.first().map(String::as_str),
        Some("prepend" | "delete")
    ));
    for arg in args {
        assert!(!arg.is_empty() && !arg.starts_with('-'), "{args:?}");
        assert!(
            arg.chars()
                .all(|c| c.is_ascii_graphic() && c != '"' && c != '\\'),
            "{args:?}"
        );
    }
    let comment = args.iter().position(|a| a == "comment").expect("tagged");
    assert!(parse_temp_tag(&args[comment + 1]).is_some(), "{args:?}");
}

// ------------------------------------------------------------ USBGuard

/// USBGuard device rules, as `usbguard-dbus` sends them for every device
/// (`usbguard.rs`). A device chooses its own serial and name, so the
/// second half builds a rule the way USBGuard writes one (`"` and `\`
/// escaped, other bytes outside printable ASCII as `\xHH`) and checks that
/// the parser gives both strings back.
pub fn usbguard_rule(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let _ = usbguard::parse_device_rule(&text);
    let _ = usbguard::device_from_rule(1, &text, None);

    let (serial, name) = match data.iter().position(|&b| b == 0) {
        Some(i) => (&data[..i], &data[i + 1..]),
        None => (data, &[][..]),
    };
    let (serial, name) = (
        String::from_utf8_lossy(serial),
        String::from_utf8_lossy(name),
    );
    let rule = format!(
        "allow id 1d6b:0002 serial \"{}\" name \"{}\" with-interface {{ 03:01:01 }}",
        usbguard_escape(&serial),
        usbguard_escape(&name)
    );
    let parsed = usbguard::parse_device_rule(&rule).expect("a rule USBGuard writes parses");
    assert_eq!(parsed.serial, serial, "{rule}");
    assert_eq!(parsed.name, name, "{rule}");
    assert_eq!(parsed.interfaces, ["03:01:01"]);
}

/// How USBGuard quotes a string in a rule.
pub fn usbguard_escape(value: &str) -> String {
    let mut out = String::new();
    for &b in value.as_bytes() {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

// -------------------------------------------------------------- tokens

/// Kernel uevents and CTAPHID input reports from a security key
/// (`token.rs`). A report starts or ends a touch only in turn: never a
/// second start while one waits, never an end without a start.
pub fn token(data: &[u8]) {
    let _ = relevant_uevent(data);
    let mut tracker = TouchTracker::default();
    let mut waiting = false;
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        let len = usize::from(len % 65).min(tail.len());
        let (report, tail) = tail.split_at(len);
        rest = tail;
        match tracker.on_report(report) {
            Some(TouchEdge::Started) => {
                assert!(!waiting);
                waiting = true;
            }
            Some(TouchEdge::Finished(_)) => {
                assert!(waiting);
                waiting = false;
            }
            None => {}
        }
        assert_eq!(tracker.is_waiting(), waiting);
    }
    assert_eq!(tracker.on_silence().is_some(), waiting);
    assert!(!tracker.is_waiting());
}

// ---------------------------------------------------------- exec events

/// Ring buffer records from the eBPF exec monitor, and the tracepoint
/// `format` file the helper reads the filename offset from (`exec.rs`),
/// then the classification of the filename.
pub fn exec_event(data: &[u8]) {
    if let Some(raw) = exec::parse_event(data) {
        assert!(data.len() >= 16 + 256);
        // At most 256 bytes, each at worst one U+FFFD.
        assert!(raw.filename.chars().count() <= 256);
        let _ = omarchy_security_proto::helper::classify_exec(&raw.filename, Some("/tmp"), None);
    }
    let text = String::from_utf8_lossy(data);
    let _ = exec::filename_offset(&text);
    let _ = omarchy_security_proto::helper::classify_exec(&text, Some("/"), Some(&text));
}

// ------------------------------------------------------------- packets

/// Packets from the NFQUEUE (`packet.rs`): the addresses come from the
/// header the version nibble names.
pub fn packet(data: &[u8]) {
    let Some(flow) = packet::parse(data) else {
        return;
    };
    match data[0] >> 4 {
        4 => assert!(flow.src.is_ipv4() && flow.dst.is_ipv4() && data.len() >= 24),
        6 => assert!(flow.src.is_ipv6() && flow.dst.is_ipv6() && data.len() >= 44),
        v => panic!("parsed a packet of IP version {v}"),
    }
}

// ---------------------------------------------------------- kernel log

/// Blocked-packet lines from the kernel log, and the `journalctl -o json`
/// lines they arrive in (`alerts.rs`).
pub fn kernel_log(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    check_blocked(&text);
    for line in text.lines() {
        if let Some((message, _)) = alerts::parse_journal(line) {
            check_blocked(&message);
        }
    }
}

fn check_blocked(message: &str) {
    let Some(blocked) = alerts::parse_line(message) else {
        return;
    };
    assert_eq!(blocked.src.is_ipv4(), blocked.dst.is_ipv4());
    assert!(!blocked.iface.is_empty() && !blocked.iface.contains(char::is_whitespace));
    assert!(!blocked.protocol.contains(char::is_whitespace));
    let remote: IpAddr = blocked.remote();
    match blocked.direction {
        AlertDirection::Outbound => assert_eq!(remote, blocked.dst),
        AlertDirection::Inbound | AlertDirection::Forward => assert_eq!(remote, blocked.src),
    }
}

// ------------------------------------------------------------- ufw

/// `### tuple ###` lines of `/etc/ufw/user.rules` (`ufw.rs`), which the
/// daemon shows, imports into hub rules on a switch to `standalone`, and
/// which the helper deletes once a temporary one expires. Whatever a
/// tuple says, the rules imported from it render safely, and the `ufw
/// delete` for an expired one is plain words.
pub fn ufw_tuple(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    for ipv6 in [false, true] {
        let rules = ufw::parse_rules(&text, ipv6, Path::new("user.rules"));
        for line in text.lines() {
            let Some(rule) = parse_tuple(line, ipv6) else {
                continue;
            };
            if let Some(decision) = temp_decision(&rule) {
                check_temp_spec(&decision.spec).expect("a temporary decision is valid");
                let args = ufw_temp_args(UfwTempChange::Delete, &decision)
                    .expect("an expired rule can be deleted");
                check_ufw_args(&args);
            }
        }
        let (imported, _) = ufw::import(&rules);
        let rules: Vec<FirewallRule> = imported
            .into_iter()
            .zip(1..)
            .map(|(imported, rule_id)| FirewallRule {
                rule_id,
                spec: imported.spec,
                loaded: true,
            })
            .collect();
        let script =
            render_with(HubMode::Standalone, &rules, None, &[], 0).expect("imported rules render");
        check_nft(&script, &rules, &[], HubMode::Standalone);
    }
    if data.len() >= 24 {
        let n = |i: usize| u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
        let tag = temp_tag(n(0), n(8), n(16));
        assert_eq!(parse_temp_tag(&tag), Some((n(0), n(8), n(16))));
    }
}
