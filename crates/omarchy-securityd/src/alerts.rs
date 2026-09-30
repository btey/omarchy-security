// SPDX-License-Identifier: GPL-3.0-or-later

//! Blocked-traffic alerts (task 2.20, plan §5.19): packets `ufw` and the
//! standalone policy logged as dropped, read from the kernel log.
//!
//! The daemon follows `journalctl -k -f` and keeps the lines that start with
//! one of [`PREFIXES`]. Both firewalls log in the same `KEY=value` format.
//! Noise (multicast, broadcast, IGMP, and the configured `ignore` entries)
//! is dropped, and repeats of the same packet kind within `window_secs` of
//! the first one are grouped into one alert with a count. At most
//! [`MAX_ALERTS`] are kept, newest first.
//!
//! `ufw` with `LOGLEVEL=low` logs a rate-limited sample of what it blocks,
//! and nothing its default policy drops without a log rule; the alerts are
//! a sample in `ufw` mode.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::process::Stdio;
use std::time::Duration;

use omarchy_security_proto::types::{AlertDirection, AlertSource, FirewallAlert, parse_prefix};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

use crate::config::{AlertProtocol, AlertsConfig};

/// Log prefixes of blocked packets, and which firewall wrote them.
pub const PREFIXES: [(&str, AlertSource); 4] = [
    ("[UFW BLOCK] ", AlertSource::Ufw),
    ("[UFW LIMIT BLOCK] ", AlertSource::Ufw),
    ("[OMSEC BLOCK] ", AlertSource::Omarchy),
    ("[OMSEC DOCKER BLOCK] ", AlertSource::Omarchy),
];

pub const MAX_ALERTS: usize = 500;

/// `FIREWALL_ALERT` for a changed count is sent at most this often per alert.
pub const EMIT_EVERY_MS: u64 = 5_000;

/// One blocked packet from the kernel log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    pub source: AlertSource,
    pub direction: AlertDirection,
    /// Lowercase: `tcp`, `udp`, `icmp`, `icmpv6`, `igmp`, or as logged.
    pub protocol: String,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub iface: String,
}

impl Blocked {
    /// The other end: the source of an inbound or forwarded packet, the
    /// destination of an outbound one.
    pub fn remote(&self) -> IpAddr {
        match self.direction {
            AlertDirection::Outbound => self.dst,
            AlertDirection::Inbound | AlertDirection::Forward => self.src,
        }
    }

    /// This machine's port, as `[firewall.alerts] ignore` means it.
    fn local_port(&self) -> Option<u16> {
        match self.direction {
            AlertDirection::Outbound => self.src_port,
            AlertDirection::Inbound | AlertDirection::Forward => self.dst_port,
        }
    }
}

/// Parses a kernel log message such as
/// `[UFW BLOCK] IN=wlan0 OUT= MAC=... SRC=192.0.2.7 DST=192.0.2.2 ... PROTO=TCP SPT=51000 DPT=22 ...`.
/// Anything else, or a line without both addresses, gives `None`.
pub fn parse_line(message: &str) -> Option<Blocked> {
    let (rest, source) = PREFIXES
        .iter()
        .find_map(|(prefix, source)| Some((message.strip_prefix(prefix)?, *source)))?;
    let fields: HashMap<&str, &str> = rest
        .split_whitespace()
        .filter_map(|f| f.split_once('='))
        .collect();
    let (input, output) = (fields.get("IN").copied()?, fields.get("OUT").copied()?);
    let direction = match (input.is_empty(), output.is_empty()) {
        (false, true) => AlertDirection::Inbound,
        (true, false) => AlertDirection::Outbound,
        (false, false) => AlertDirection::Forward,
        (true, true) => return None,
    };
    let iface = match direction {
        AlertDirection::Outbound => output,
        _ => input,
    };
    let src: IpAddr = fields.get("SRC")?.parse().ok()?;
    let dst: IpAddr = fields.get("DST")?.parse().ok()?;
    if src.is_ipv4() != dst.is_ipv4() {
        return None;
    }
    let protocol = match fields.get("PROTO").copied()? {
        "2" => "igmp".to_owned(),
        other => other.to_ascii_lowercase(),
    };
    let port = |key| fields.get(key).and_then(|p| p.parse::<u16>().ok());
    Some(Blocked {
        source,
        direction,
        protocol,
        src,
        dst,
        src_port: port("SPT"),
        dst_port: port("DPT"),
        iface: iface.to_owned(),
    })
}

fn in_prefix(ip: IpAddr, prefix: &str) -> bool {
    let Ok((net, len)) = parse_prefix(prefix) else {
        return false;
    };
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(ip) & mask == u32::from(net)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            u128::from(ip) & mask == u128::from(net)
        }
        _ => false,
    }
}

/// Whether the noise filter drops `packet`.
pub fn ignored(packet: &Blocked, config: &AlertsConfig) -> bool {
    if config.ignore_multicast {
        let broadcast = packet.dst == IpAddr::from([255, 255, 255, 255]);
        if packet.dst.is_multicast() || broadcast || packet.protocol == "igmp" {
            return true;
        }
    }
    config.ignore.iter().any(|entry| {
        let protocol = entry.protocol.is_none_or(|p| {
            packet.protocol
                == match p {
                    AlertProtocol::Tcp => "tcp",
                    AlertProtocol::Udp => "udp",
                    AlertProtocol::Icmp => "icmp",
                    AlertProtocol::Icmpv6 => "icmpv6",
                    AlertProtocol::Igmp => "igmp",
                }
        });
        let port = entry.port.is_none_or(|p| packet.local_port() == Some(p));
        let address = entry
            .address
            .as_deref()
            .is_none_or(|a| in_prefix(packet.remote(), a));
        protocol && port && address
    })
}

/// What groups packets into one alert: source, direction, protocol,
/// remote address, and the destination port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    source: AlertSource,
    direction: AlertDirection,
    protocol: String,
    remote: IpAddr,
    port: Option<u16>,
}

impl Key {
    fn of(packet: &Blocked) -> Self {
        Self {
            source: packet.source,
            direction: packet.direction,
            protocol: packet.protocol.clone(),
            remote: packet.remote(),
            port: packet.dst_port,
        }
    }
}

struct Entry {
    alert: FirewallAlert,
    key: Key,
    /// When `FIREWALL_ALERT` last went out for it.
    emitted_at: u64,
    /// A changed count waits for the next emit.
    pending: bool,
}

/// What [`Alerts::record`] did with a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
    /// A new alert; emit it.
    New(FirewallAlert),
    /// The count of an alert went up. `emit` says whether to send it now;
    /// otherwise [`Alerts::flush`] it after `flush_in_ms`, when that is set
    /// (it is unset when a flush is already due).
    Updated {
        alert: FirewallAlert,
        emit: bool,
        flush_in_ms: Option<u64>,
    },
}

/// The alerts, newest first, and the mutes by kind of packet.
#[derive(Default)]
pub struct Alerts {
    entries: VecDeque<Entry>,
    mutes: HashMap<Key, u64>,
    next_id: u64,
}

impl Alerts {
    /// Adds a packet seen at `at` (ms), grouping it with an alert of the
    /// same kind whose first packet is less than `window_ms` older.
    pub fn record(&mut self, packet: &Blocked, at: u64, window_ms: u64) -> Recorded {
        let key = Key::of(packet);
        let muted_until = self.mutes.get(&key).copied().filter(|&until| until > at);
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|e| e.key == key && at.saturating_sub(e.alert.first_seen) < window_ms)
        {
            entry.alert.count += 1;
            entry.alert.last_seen = entry.alert.last_seen.max(at);
            entry.alert.muted_until = muted_until;
            let emit = at.saturating_sub(entry.emitted_at) >= EMIT_EVERY_MS;
            let flush_in_ms = if emit {
                entry.emitted_at = at;
                entry.pending = false;
                None
            } else if entry.pending {
                None
            } else {
                entry.pending = true;
                Some(EMIT_EVERY_MS - at.saturating_sub(entry.emitted_at))
            };
            return Recorded::Updated {
                alert: entry.alert.clone(),
                emit,
                flush_in_ms,
            };
        }
        self.next_id += 1;
        let alert = FirewallAlert {
            alert_id: self.next_id,
            source: packet.source,
            direction: packet.direction,
            protocol: packet.protocol.clone(),
            src: packet.src.to_string(),
            dst: packet.dst.to_string(),
            dst_port: packet.dst_port,
            iface: packet.iface.clone(),
            count: 1,
            first_seen: at,
            last_seen: at,
            muted_until,
        };
        self.entries.push_front(Entry {
            alert: alert.clone(),
            key,
            emitted_at: at,
            pending: false,
        });
        self.entries.truncate(MAX_ALERTS);
        Recorded::New(alert)
    }

    /// The alert whose changed count waited, if it still waits.
    pub fn flush(&mut self, alert_id: u64, now: u64) -> Option<FirewallAlert> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.alert.alert_id == alert_id && e.pending)?;
        entry.pending = false;
        entry.emitted_at = now;
        Some(entry.alert.clone())
    }

    pub fn get(&self, alert_id: u64) -> Option<&FirewallAlert> {
        self.entries
            .iter()
            .map(|e| &e.alert)
            .find(|a| a.alert_id == alert_id)
    }

    /// Newest first, at most `limit`; mutes that have run out are cleared.
    pub fn list(&mut self, limit: Option<usize>, now: u64) -> Vec<FirewallAlert> {
        self.mutes.retain(|_, until| *until > now);
        for entry in &mut self.entries {
            entry.alert.muted_until = self.mutes.get(&entry.key).copied();
        }
        self.entries
            .iter()
            .take(limit.unwrap_or(MAX_ALERTS))
            .map(|e| e.alert.clone())
            .collect()
    }

    /// Mutes the alert's kind of packet until `until`: later alerts of the
    /// same kind are muted too. Returns the updated alert.
    pub fn mute(&mut self, alert_id: u64, until: u64) -> Option<FirewallAlert> {
        let key = self
            .entries
            .iter()
            .find(|e| e.alert.alert_id == alert_id)?
            .key
            .clone();
        self.mutes.insert(key.clone(), until);
        let mut updated = None;
        for entry in self.entries.iter_mut().filter(|e| e.key == key) {
            entry.alert.muted_until = Some(until);
            if entry.alert.alert_id == alert_id {
                updated = Some(entry.alert.clone());
            }
        }
        updated
    }
}

/// How the kernel log is read.
#[derive(Debug, Clone)]
pub struct AlertsEnv {
    /// The command and its arguments; it prints one JSON object per line.
    pub journalctl: Vec<String>,
    /// Opens the hub on the Network tab, for a notification's default
    /// action: the plugin's `omarchy-shell` IPC target (task 3.10).
    pub open_hub: Vec<String>,
}

impl Default for AlertsEnv {
    fn default() -> Self {
        Self {
            journalctl: [
                "/usr/bin/journalctl",
                "-k",
                "-f",
                "-n",
                "0",
                "-o",
                "json",
                "--output-fields=MESSAGE,__REALTIME_TIMESTAMP",
            ]
            .map(String::from)
            .to_vec(),
            open_hub: {
                let omarchy =
                    std::env::var("OMARCHY_PATH").unwrap_or_else(|_| "/usr/share/omarchy".into());
                vec![
                    format!("{omarchy}/bin/omarchy-shell"),
                    "-q".into(),
                    "security-hub".into(),
                    "open".into(),
                    "network".into(),
                ]
            },
        }
    }
}

/// A kernel log line that starts with one of [`PREFIXES`], and when it was
/// logged (ms, when the journal says).
pub type LogLine = (String, Option<u64>);

/// What the follower reports about itself: `None` while it reads the
/// journal, or why it cannot.
pub type FollowerState = Option<String>;

/// The `MESSAGE` and time of one `journalctl -o json` line. The journal
/// writes a message that is not UTF-8 as an array of bytes.
pub fn parse_journal(line: &str) -> Option<LogLine> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let message = match &value["MESSAGE"] {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(bytes) => {
            let bytes: Vec<u8> = bytes
                .iter()
                .map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                .collect::<Option<_>>()?;
            String::from_utf8_lossy(&bytes).into_owned()
        }
        _ => return None,
    };
    if !PREFIXES.iter().any(|(p, _)| message.starts_with(p)) {
        return None;
    }
    let at = value["__REALTIME_TIMESTAMP"]
        .as_str()
        .and_then(|t| t.parse::<u64>().ok())
        .map(|us| us / 1000);
    Some((message, at))
}

/// Why `journalctl` cannot show the kernel log, from what it printed.
fn permission_problem(stderr: &str) -> bool {
    stderr.contains("insufficient permissions") || stderr.contains("not seeing messages")
}

/// Runs the journal follower for as long as `lines` is open, restarting it
/// with backoff (1 s doubling to 60 s) when it exits.
pub async fn follow(
    env: AlertsEnv,
    lines: mpsc::Sender<LogLine>,
    state: mpsc::Sender<FollowerState>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = std::time::Instant::now();
        let reason = run_once(&env, &lines, &state).await;
        if lines.is_closed() {
            return;
        }
        tracing::warn!("kernel log follower stopped: {reason}; restarting");
        let _ = state.send(Some(reason)).await;
        if started.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(1);
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = lines.closed() => return,
        }
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

/// Runs `journalctl` once; returns why it ended.
async fn run_once(
    env: &AlertsEnv,
    lines: &mpsc::Sender<LogLine>,
    state: &mpsc::Sender<FollowerState>,
) -> String {
    let Some((program, args)) = env.journalctl.split_first() else {
        return "no journalctl command".into();
    };
    let child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(err) => return format!("cannot run {program}: {err}"),
    };
    let mut stdout = BufReader::new(child.stdout.take().expect("piped")).lines();
    let mut stderr = BufReader::new(child.stderr.take().expect("piped")).lines();
    let _ = state.send(None).await;
    let mut stderr_open = true;
    loop {
        tokio::select! {
            line = stdout.next_line() => match line {
                Ok(Some(line)) => {
                    if let Some(parsed) = parse_journal(&line)
                        && lines.send(parsed).await.is_err()
                    {
                        return "stopped".into();
                    }
                }
                Ok(None) | Err(_) => break,
            },
            line = stderr.next_line(), if stderr_open => match line {
                Ok(Some(line)) => {
                    tracing::debug!("journalctl: {line}");
                    if permission_problem(&line) {
                        let _ = state
                            .send(Some("this user cannot read the kernel log (join the wheel or systemd-journal group)".into()))
                            .await;
                    }
                }
                Ok(None) | Err(_) => stderr_open = false,
            },
            _ = lines.closed() => return "stopped".into(),
        }
    }
    match child.wait().await {
        Ok(status) => format!("journalctl exited ({status})"),
        Err(err) => format!("journalctl: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AlertIgnore;

    const IGMP: &str = "[UFW BLOCK] IN=wlp0s20f3 OUT= MAC=01:00:5e:00:00:fb:3e:bb:13:ce:cb:b1:08:00 SRC=172.23.243.84 DST=224.0.0.251 LEN=32 TOS=0x00 PREC=0xC0 TTL=1 ID=30667 PROTO=2 ";
    const SYN: &str = "[UFW BLOCK] IN=wlan0 OUT= MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 SRC=192.168.1.23 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=4242 DF PROTO=TCP SPT=51544 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0 ";
    const V6: &str = "[OMSEC BLOCK] IN=wlan0 OUT= MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:86:dd SRC=2001:0db8:0000:0000:0000:0000:0000:0007 DST=2001:0db8:0000:0000:0000:0000:0000:0002 LEN=80 TC=0 HOPLIMIT=64 FLOWLBL=0 PROTO=UDP SPT=40000 DPT=5000 LEN=40 ";
    const DOCKER: &str = "[OMSEC DOCKER BLOCK] IN=wlan0 OUT=docker0 MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 SRC=203.0.113.9 DST=172.17.0.2 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=1 DF PROTO=TCP SPT=40001 DPT=80 WINDOW=64240 RES=0x00 SYN URGP=0 ";
    const OUT: &str = "[UFW BLOCK] IN= OUT=wlan0 SRC=192.168.1.10 DST=198.51.100.4 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=40002 DPT=25 WINDOW=64240 RES=0x00 SYN URGP=0 ";

    #[test]
    fn parses_real_log_lines() {
        let igmp = parse_line(IGMP).unwrap();
        assert_eq!(
            (igmp.source, igmp.direction, igmp.protocol.as_str()),
            (AlertSource::Ufw, AlertDirection::Inbound, "igmp")
        );
        assert_eq!(igmp.dst, "224.0.0.251".parse::<IpAddr>().unwrap());
        assert_eq!((igmp.src_port, igmp.dst_port), (None, None));

        assert_eq!(
            parse_line(SYN).unwrap(),
            Blocked {
                source: AlertSource::Ufw,
                direction: AlertDirection::Inbound,
                protocol: "tcp".into(),
                src: "192.168.1.23".parse().unwrap(),
                dst: "192.168.1.10".parse().unwrap(),
                src_port: Some(51544),
                dst_port: Some(22),
                iface: "wlan0".into(),
            }
        );
        let v6 = parse_line(V6).unwrap();
        assert_eq!(v6.source, AlertSource::Omarchy);
        assert_eq!(v6.src.to_string(), "2001:db8::7");
        assert_eq!((v6.protocol.as_str(), v6.dst_port), ("udp", Some(5000)));
        let docker = parse_line(DOCKER).unwrap();
        assert_eq!(
            (docker.direction, docker.iface.as_str()),
            (AlertDirection::Forward, "wlan0")
        );
        let out = parse_line(OUT).unwrap();
        assert_eq!(
            (out.direction, out.iface.as_str(), out.remote().to_string()),
            (AlertDirection::Outbound, "wlan0", "198.51.100.4".into())
        );

        for bad in [
            "perf: interrupt took too long",
            "[UFW ALLOW] IN=wlan0 OUT= SRC=1.2.3.4 DST=1.2.3.5 PROTO=TCP",
            "[UFW BLOCK] IN= OUT= SRC=1.2.3.4 DST=1.2.3.5 PROTO=TCP",
            "[UFW BLOCK] IN=wlan0 OUT= SRC=1.2.3 DST=1.2.3.5 PROTO=TCP",
            "[UFW BLOCK] IN=wlan0 OUT= SRC=1.2.3.4 DST=::1 PROTO=TCP",
            "[UFW BLOCK] IN=wlan0 SRC=1.2.3.4 DST=1.2.3.5 PROTO=TCP",
            "[UFW BLOCK] IN=wlan0 OUT= SRC=1.2.3.4 DST=1.2.3.5",
        ] {
            assert_eq!(parse_line(bad), None, "{bad}");
        }
        // A bad port is left out, not fatal.
        let odd = parse_line(&SYN.replace("DPT=22", "DPT=99999")).unwrap();
        assert_eq!(odd.dst_port, None);
    }

    #[test]
    fn reads_journal_json() {
        let line = format!(
            "{{\"__REALTIME_TIMESTAMP\":\"1790599576242746\",\"MESSAGE\":{}}}",
            serde_json::to_string(IGMP).unwrap()
        );
        assert_eq!(
            parse_journal(&line),
            Some((IGMP.to_owned(), Some(1_790_599_576_242)))
        );
        let bytes: Vec<u8> = SYN.bytes().collect();
        let line = serde_json::json!({ "MESSAGE": bytes }).to_string();
        assert_eq!(parse_journal(&line), Some((SYN.to_owned(), None)));
        assert_eq!(parse_journal("{\"MESSAGE\":\"perf: slow\"}"), None);
        assert_eq!(parse_journal("not json"), None);
    }

    #[test]
    fn filters_noise() {
        let config = AlertsConfig::default();
        assert!(ignored(&parse_line(IGMP).unwrap(), &config));
        let bcast = parse_line(&SYN.replace("DST=192.168.1.10", "DST=255.255.255.255")).unwrap();
        assert!(ignored(&bcast, &config));
        let mdns6 = parse_line(&V6.replace(
            "DST=2001:0db8:0000:0000:0000:0000:0000:0002",
            "DST=ff02::fb",
        ))
        .unwrap();
        assert!(ignored(&mdns6, &config));
        assert!(!ignored(&parse_line(SYN).unwrap(), &config));
        let loud = AlertsConfig {
            ignore_multicast: false,
            ..AlertsConfig::default()
        };
        assert!(!ignored(&parse_line(IGMP).unwrap(), &loud));

        let entries = |ignore| AlertsConfig {
            ignore,
            ..AlertsConfig::default()
        };
        let syn = parse_line(SYN).unwrap();
        for (entry, drops) in [
            (
                AlertIgnore {
                    port: Some(22),
                    ..Default::default()
                },
                true,
            ),
            (
                AlertIgnore {
                    port: Some(51544),
                    ..Default::default()
                },
                false,
            ),
            (
                AlertIgnore {
                    protocol: Some(AlertProtocol::Udp),
                    port: Some(22),
                    ..Default::default()
                },
                false,
            ),
            (
                AlertIgnore {
                    address: Some("192.168.1.0/24".into()),
                    ..Default::default()
                },
                true,
            ),
            (
                AlertIgnore {
                    address: Some("192.168.1.10".into()),
                    ..Default::default()
                },
                false,
            ),
            (
                AlertIgnore {
                    address: Some("::/0".into()),
                    ..Default::default()
                },
                false,
            ),
        ] {
            assert_eq!(
                ignored(&syn, &entries(vec![entry.clone()])),
                drops,
                "{entry:?}"
            );
        }
        // Outbound: the local port is the source port.
        let out = parse_line(OUT).unwrap();
        let by_port = entries(vec![AlertIgnore {
            port: Some(40002),
            ..Default::default()
        }]);
        assert!(ignored(&out, &by_port));
    }

    #[test]
    fn groups_repeats_within_the_window() {
        let mut alerts = Alerts::default();
        let syn = parse_line(SYN).unwrap();
        let window = 600_000;
        let Recorded::New(first) = alerts.record(&syn, 1_000, window) else {
            panic!()
        };
        assert_eq!(
            (first.alert_id, first.count, first.dst_port),
            (1, 1, Some(22))
        );

        // Within 5 s of the last emit: counted, flushed later, once.
        let again = alerts.record(&syn, 2_000, window);
        assert_eq!(
            again,
            Recorded::Updated {
                alert: FirewallAlert {
                    count: 2,
                    last_seen: 2_000,
                    ..first.clone()
                },
                emit: false,
                flush_in_ms: Some(4_000),
            }
        );
        let Recorded::Updated { flush_in_ms, .. } = alerts.record(&syn, 3_000, window) else {
            panic!()
        };
        assert_eq!(flush_in_ms, None, "a flush is already due");
        assert_eq!(alerts.flush(1, 6_000).unwrap().count, 3);
        assert_eq!(alerts.flush(1, 6_100), None, "nothing waits");
        // 5 s after that emit, at once.
        let Recorded::Updated { alert, emit, .. } = alerts.record(&syn, 11_000, window) else {
            panic!()
        };
        assert!(emit);
        assert_eq!(alert.count, 4);

        // Another port, another source port only: same or new alert.
        let other_client = parse_line(&SYN.replace("SPT=51544", "SPT=51545")).unwrap();
        assert!(matches!(
            alerts.record(&other_client, 12_000, window),
            Recorded::Updated { .. }
        ));
        let other_port = parse_line(&SYN.replace("DPT=22", "DPT=23")).unwrap();
        assert!(matches!(
            alerts.record(&other_port, 12_000, window),
            Recorded::New(_)
        ));
        // After the window: a new alert.
        let Recorded::New(later) = alerts.record(&syn, 1_000 + window, window) else {
            panic!()
        };
        assert_eq!(later.alert_id, 3);
        let ids: Vec<u64> = alerts.list(None, 0).iter().map(|a| a.alert_id).collect();
        assert_eq!(ids, [3, 2, 1], "newest first");
        assert_eq!(alerts.list(Some(1), 0).len(), 1);
    }

    #[test]
    fn keeps_at_most_500() {
        let mut alerts = Alerts::default();
        for port in 0..(MAX_ALERTS as u16 + 20) {
            let packet = parse_line(&SYN.replace("DPT=22", &format!("DPT={}", port + 1))).unwrap();
            alerts.record(&packet, 1, 600_000);
        }
        let list = alerts.list(None, 0);
        assert_eq!(list.len(), MAX_ALERTS);
        assert_eq!(list[0].alert_id, MAX_ALERTS as u64 + 20);
    }

    #[test]
    fn mutes_a_kind_of_packet() {
        let mut alerts = Alerts::default();
        let syn = parse_line(SYN).unwrap();
        alerts.record(&syn, 1_000, 10_000);
        let muted = alerts.mute(1, 50_000).unwrap();
        assert_eq!(muted.muted_until, Some(50_000));
        assert_eq!(alerts.mute(99, 50_000), None);
        // A later alert of the same kind starts muted, until the mute ends.
        let Recorded::New(next) = alerts.record(&syn, 20_000, 10_000) else {
            panic!()
        };
        assert_eq!(next.muted_until, Some(50_000));
        let Recorded::New(after) = alerts.record(&syn, 60_000, 10_000) else {
            panic!()
        };
        assert_eq!(after.muted_until, None);
        assert!(
            alerts
                .list(None, 60_000)
                .iter()
                .all(|a| a.muted_until.is_none())
        );
    }

    #[tokio::test]
    async fn follows_and_restarts_journalctl() {
        let dir = tempfile::tempdir().unwrap();
        let line =
            serde_json::json!({ "MESSAGE": SYN, "__REALTIME_TIMESTAMP": "5000000" }).to_string();
        let noise = serde_json::json!({ "MESSAGE": "perf: slow" }).to_string();
        let script = dir.path().join("journalctl");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\necho 'Hint: You are currently not seeing messages from other users and the system.' >&2\n\
                 echo '{noise}'\necho '{line}'\n"
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let env = AlertsEnv {
            journalctl: vec![script.display().to_string()],
            open_hub: vec![],
        };
        let (tx, mut rx) = mpsc::channel(4);
        let (state_tx, mut state) = mpsc::channel(16);
        tokio::spawn(follow(env, tx, state_tx));
        async fn recv(rx: &mut mpsc::Receiver<LogLine>) -> Option<LogLine> {
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("a line within 5 s")
        }
        assert_eq!(recv(&mut rx).await, Some((SYN.to_owned(), Some(5000))));
        // It exits, and is started again after a second.
        assert_eq!(recv(&mut rx).await.unwrap().0, SYN);
        let mut seen = vec![];
        while let Ok(s) = state.try_recv() {
            seen.push(s);
        }
        assert!(seen.contains(&None), "{seen:?}");
        assert!(
            seen.iter()
                .flatten()
                .any(|s| s.contains("cannot read the kernel log")),
            "{seen:?}"
        );
        assert!(
            seen.iter().flatten().any(|s| s.contains("exited")),
            "{seen:?}"
        );
    }
}
