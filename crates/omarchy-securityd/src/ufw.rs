// SPDX-License-Identifier: GPL-3.0-or-later

//! `ufw` detection and its read-only rules view (task 2.17, plan §5.15 and
//! §5.16).
//!
//! The daemon reads what is world-readable itself: `/etc/ufw/ufw.conf`,
//! `/etc/default/ufw`, `after.rules` (for the ufw-docker block) and the
//! `### tuple ###` lines of `user.rules` and `user6.rules`. What is loaded
//! in the kernel comes from the helper's `firewall_inspect`. The two
//! combine into one [`FirewallMode`]. `ufw status` is never called: it
//! needs root and is slow.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use nix::sys::inotify::AddWatchFlags;
use omarchy_security_proto::helper::{FirewallInspection, HubMode};
use omarchy_security_proto::methods::UfwRuleList;
use omarchy_security_proto::types::{
    Direction, DockerProtection, FirewallMode, FirewallModeKind, FirewallRuleSpec, Protocol,
    UfwAction, UfwDirection, UfwRule, UfwState, Verdict, parse_prefix,
};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

pub use omarchy_security_proto::ufw::parse_tuple;

use crate::inotify::{self, Watch};

/// The marker ufw-docker writes around its block in `after.rules`.
const UFW_DOCKER_MARKER: &str = "BEGIN UFW AND DOCKER";

/// Where `ufw`'s files are looked up.
#[derive(Debug, Clone)]
pub struct UfwEnv {
    /// `/` except in tests.
    pub root: PathBuf,
    /// Asked whether `nftables.service` or `firewalld` could undo the
    /// ruleset; `None` skips the check (tests).
    pub systemctl: Option<PathBuf>,
}

impl Default for UfwEnv {
    fn default() -> Self {
        Self {
            root: "/".into(),
            systemctl: Some("/usr/bin/systemctl".into()),
        }
    }
}

impl UfwEnv {
    /// `ufw`'s files under `root`, without the services check.
    #[cfg(test)]
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            systemctl: None,
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

/// What the daemon reads from `ufw`'s files itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Conf {
    pub installed: bool,
    pub enabled: bool,
    pub logging: Option<String>,
    pub default_input: Option<String>,
    pub default_output: Option<String>,
    pub default_forward: Option<String>,
    /// `after.rules` holds the ufw-docker block.
    pub ufw_docker: bool,
}

/// `KEY=value` lines of a shell-style file, quotes removed.
fn assignments(text: &str) -> HashMap<&str, &str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(key, value)| {
            let value = value.trim();
            let unquoted = ['"', '\'']
                .into_iter()
                .find_map(|q| value.strip_prefix(q)?.strip_suffix(q))
                .unwrap_or(value);
            (key.trim(), unquoted)
        })
        .collect()
}

pub fn read_conf(env: &UfwEnv) -> Conf {
    let read = |relative| std::fs::read_to_string(env.path(relative)).unwrap_or_default();
    let (conf, defaults) = (read("etc/ufw/ufw.conf"), read("etc/default/ufw"));
    let (conf, defaults) = (assignments(&conf), assignments(&defaults));
    let lower = |map: &HashMap<&str, &str>, key| map.get(key).map(|v| v.to_ascii_lowercase());
    Conf {
        installed: env.path("usr/bin/ufw").is_file(),
        enabled: conf
            .get("ENABLED")
            .is_some_and(|v| v.eq_ignore_ascii_case("yes")),
        logging: lower(&conf, "LOGLEVEL"),
        default_input: lower(&defaults, "DEFAULT_INPUT_POLICY"),
        default_output: lower(&defaults, "DEFAULT_OUTPUT_POLICY"),
        default_forward: lower(&defaults, "DEFAULT_FORWARD_POLICY"),
        ufw_docker: read("etc/ufw/after.rules").contains(UFW_DOCKER_MARKER),
    }
}

/// Combines the files with the helper's view of the kernel, or with why
/// the helper could not be asked.
pub fn derive(conf: &Conf, inspection: Result<&FirewallInspection, &str>) -> FirewallMode {
    let mut ufw = UfwState {
        installed: conf.installed,
        enabled_in_conf: conf.enabled,
        chains_loaded: None,
        default_input: conf.default_input.clone(),
        default_output: conf.default_output.clone(),
        default_forward: conf.default_forward.clone(),
        logging: conf.logging.clone(),
        before_rules_modified: None,
    };
    let inspection = match inspection {
        Ok(inspection) => inspection,
        Err(reason) => {
            // Only the files to go by.
            let docker_protection = if conf.enabled && conf.ufw_docker {
                DockerProtection::UfwDocker
            } else {
                DockerProtection::None
            };
            return FirewallMode {
                mode: FirewallModeKind::Unknown,
                ufw,
                table_loaded: None,
                docker_protection,
                detail: Some(format!("cannot inspect the loaded ruleset: {reason}")),
            };
        }
    };
    ufw.chains_loaded = Some(inspection.ufw_chains_loaded);
    ufw.before_rules_modified = inspection.before_rules_modified;
    let ufw_active = conf.enabled && inspection.ufw_chains_loaded;
    let standalone = inspection.table_mode.as_deref() == Some("standalone");
    let mode = match (ufw_active, standalone) {
        (true, false) => FirewallModeKind::Ufw,
        (false, true) => FirewallModeKind::Standalone,
        (true, true) => FirewallModeKind::Both,
        (false, false) => FirewallModeKind::None,
    };
    let docker_protection = if ufw_active && conf.ufw_docker {
        DockerProtection::UfwDocker
    } else if standalone {
        DockerProtection::Omarchy
    } else {
        DockerProtection::None
    };
    let mut details: Vec<String> = vec![];
    match (conf.enabled, inspection.ufw_chains_loaded) {
        (true, false) => {
            details.push("ufw is enabled in ufw.conf, but its chains are not loaded".into())
        }
        (false, true) => {
            details.push("ufw's chains are loaded, although ufw.conf says ENABLED=no".into())
        }
        _ if mode == FirewallModeKind::None && !conf.installed => {
            details.push("ufw is not installed".into())
        }
        _ => {}
    }
    if inspection.hub_mode == HubMode::Standalone && !standalone {
        details.push("the hub firewall is chosen, but its table is not loaded".into());
    }
    if let Some(err) = &inspection.boot_copy_error {
        details.push(format!(
            "the boot copy of the hub firewall could not be written ({err})"
        ));
    }
    let detail = (!details.is_empty()).then(|| details.join("; "));
    FirewallMode {
        mode,
        ufw,
        table_loaded: Some(inspection.table_loaded),
        docker_protection,
        detail,
    }
}

/// The mode in words, for the module's status detail.
pub fn describe(mode: FirewallModeKind) -> &'static str {
    match mode {
        FirewallModeKind::Ufw => "ufw is active",
        FirewallModeKind::Standalone => "the hub firewall is active",
        FirewallModeKind::Both => "ufw and the hub firewall are both active",
        FirewallModeKind::None => "no firewall is active",
        FirewallModeKind::Unknown => "the firewall mode is unknown",
    }
}

pub fn parse_rules(text: &str, ipv6: bool, source: &Path) -> Vec<UfwRule> {
    text.lines()
        .filter(|l| l.trim_start().starts_with("### tuple ###"))
        .filter_map(|l| {
            let rule = parse_tuple(l, ipv6);
            if rule.is_none() {
                tracing::debug!("skipping a ufw rule in {}: {l}", source.display());
            }
            rule
        })
        .collect()
}

/// What `before.rules` and `after.rules` do on a stock install.
pub fn builtin(ufw_docker: bool) -> Vec<String> {
    let mut rules: Vec<String> = [
        "Replies to established connections are allowed",
        "Loopback traffic is allowed",
        "Invalid packets are dropped",
        "ICMP and ICMPv6 control messages (ping, errors, neighbour discovery) are allowed",
        "DHCP client replies are allowed",
        "mDNS (UDP 5353 to 224.0.0.251 and ff02::fb) is allowed",
        "UPnP discovery (UDP 1900 to 239.255.255.250) is allowed",
    ]
    .map(String::from)
    .to_vec();
    if ufw_docker {
        rules.push(
            "ufw-docker: published Docker ports are reachable from private networks only".into(),
        );
    }
    rules
}

pub fn read_rules(env: &UfwEnv) -> UfwRuleList {
    let conf = read_conf(env);
    let mut rules = vec![];
    for (relative, ipv6) in [("etc/ufw/user.rules", false), ("etc/ufw/user6.rules", true)] {
        let path = env.path(relative);
        if let Ok(text) = std::fs::read_to_string(&path) {
            rules.extend(parse_rules(&text, ipv6, &path));
        }
    }
    UfwRuleList {
        rules,
        builtin: if conf.installed {
            builtin(conf.ufw_docker)
        } else {
            vec![]
        },
        source: "user.rules".into(),
    }
}

/// Whether an nftables script empties the whole ruleset.
fn flushes_ruleset(script: &str) -> bool {
    script
        .lines()
        .map(|l| l.split('#').next().unwrap_or_default().trim())
        .any(|l| l.split_whitespace().eq(["flush", "ruleset"]))
}

/// Services that would remove or fight `ufw`'s tables and ours, in words
/// for the mode's detail. `nftables.service` with the stock
/// `/etc/nftables.conf` flushes the ruleset on every start or reload.
pub async fn conflicts(env: &UfwEnv) -> Vec<String> {
    let Some(systemctl) = &env.systemctl else {
        return vec![];
    };
    let succeeds = |args: [&'static str; 3]| async move {
        tokio::process::Command::new(systemctl)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .is_ok_and(|s| s.success())
    };
    let mut found = vec![];
    if succeeds(["is-enabled", "--quiet", "nftables.service"]).await {
        // Unreadable: assume the stock file.
        let flushes = std::fs::read_to_string(env.path("etc/nftables.conf"))
            .map_or(true, |conf| flushes_ruleset(&conf));
        if flushes {
            found.push("nftables.service is enabled and flushes the ruleset".into());
        }
    }
    if succeeds(["is-active", "--quiet", "firewalld.service"]).await {
        found.push("firewalld is active and manages the ruleset as well".into());
    }
    found
}

/// A `ufw` rule converted into a hub rule by [`import`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub spec: FirewallRuleSpec,
    pub from: UfwRule,
    /// What the hub rule does differently, for the UI to show.
    pub notes: Vec<String>,
}

/// Converts `ufw`'s user rules into saved hub rules for the switch to
/// `standalone` (plan §5.17): `allow` stays `allow`, `deny` and `reject`
/// become `block`, and `limit` becomes `allow` (rate limiting is out of
/// scope). Rules a hub rule cannot express are returned with the reason;
/// duplicates are dropped.
pub fn import(rules: &[UfwRule]) -> (Vec<Imported>, Vec<(UfwRule, String)>) {
    let mut imported: Vec<Imported> = vec![];
    let mut skipped = vec![];
    for rule in rules {
        match convert(rule) {
            Ok((spec, notes)) => {
                if !imported.iter().any(|i| i.spec == spec) {
                    imported.push(Imported {
                        spec,
                        from: rule.clone(),
                        notes,
                    });
                }
            }
            Err(reason) => skipped.push((rule.clone(), reason)),
        }
    }
    (imported, skipped)
}

fn convert(rule: &UfwRule) -> Result<(FirewallRuleSpec, Vec<String>), String> {
    let mut notes = vec![];
    if let Some(iface) = &rule.iface {
        return Err(format!("it only applies to interface {iface}"));
    }
    if let Some(port) = &rule.src_port {
        return Err(format!("it matches source port {port}"));
    }
    let protocol = match rule.protocol.as_str() {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        "any" => None,
        other => return Err(format!("protocol {other} is not supported")),
    };
    let port = match rule.port.as_deref() {
        None => None,
        Some(port) => Some(
            port.parse::<u16>()
                .ok()
                .filter(|&p| p != 0)
                .ok_or_else(|| format!("port {port} is a range or a list"))?,
        ),
    };
    let verdict = match rule.action {
        UfwAction::Allow => Verdict::Allow,
        UfwAction::Limit => {
            notes.push("imported as a plain allow: rate limiting is not supported".into());
            Verdict::Allow
        }
        UfwAction::Deny => Verdict::Block,
        UfwAction::Reject => {
            notes.push("imported as block: the packets are dropped, not rejected".into());
            Verdict::Block
        }
    };
    let (direction, remote, local) = match rule.direction {
        UfwDirection::In => (Direction::Inbound, &rule.src, &rule.dst),
        UfwDirection::Out => (Direction::Outbound, &rule.dst, &rule.src),
    };
    if local != "any" {
        notes.push(format!(
            "not limited to the local address {local}: hub rules match the remote address only"
        ));
    }
    let address = match remote.as_str() {
        "any" if rule.ipv6 => "::/0".to_owned(),
        "any" => "0.0.0.0/0".to_owned(),
        remote => remote.to_owned(),
    };
    parse_prefix(&address)?;
    Ok((
        FirewallRuleSpec {
            verdict,
            direction,
            address,
            port,
            protocol,
            executable: None,
        },
        notes,
    ))
}

const WATCH_FLAGS: AddWatchFlags = AddWatchFlags::IN_CLOSE_WRITE
    .union(AddWatchFlags::IN_MOVED_TO)
    .union(AddWatchFlags::IN_MOVED_FROM)
    .union(AddWatchFlags::IN_CREATE)
    .union(AddWatchFlags::IN_DELETE)
    .union(AddWatchFlags::IN_ONLYDIR);

/// Sends on `changed` whenever one of `ufw`'s files is written or replaced
/// (they are replaced by rename, so their directories are watched). Returns
/// an error if neither directory can be watched, and `Ok` once the receiver
/// is gone.
pub async fn watch(env: UfwEnv, changed: mpsc::Sender<()>) -> std::io::Result<()> {
    let watcher = inotify::init()?;
    let mut dirs = HashMap::new();
    let files: [(&str, &[&str]); 2] = [
        (
            "etc/ufw",
            &["ufw.conf", "user.rules", "user6.rules", "after.rules"],
        ),
        ("etc/default", &["ufw"]),
    ];
    for (dir, names) in files {
        match watcher.add_watch(&env.path(dir), WATCH_FLAGS) {
            Ok(wd) => {
                dirs.insert(wd, names);
            }
            Err(err) => tracing::debug!("not watching {}: {err}", env.path(dir).display()),
        }
    }
    if dirs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "neither /etc/ufw nor /etc/default can be watched",
        ));
    }
    let fd = AsyncFd::new(Watch(watcher))?;
    loop {
        let events = tokio::select! {
            events = inotify::read(&fd) => events?,
            _ = changed.closed() => return Ok(()),
        };
        let relevant = events.iter().any(|e| {
            e.mask.contains(AddWatchFlags::IN_Q_OVERFLOW)
                || dirs.get(&e.wd).is_some_and(|names| {
                    e.name
                        .as_ref()
                        .is_some_and(|n| names.iter().any(|name| n == name))
                })
        });
        // A full channel already has a change pending.
        if relevant {
            let _ = changed.try_send(());
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::Duration;

    fn tuple(line: &str) -> Option<UfwRule> {
        parse_tuple(line, false)
    }

    fn rule(
        action: UfwAction,
        protocol: &str,
        port: Option<&str>,
        src: &str,
        dst: &str,
    ) -> UfwRule {
        UfwRule {
            action,
            direction: UfwDirection::In,
            protocol: protocol.into(),
            port: port.map(Into::into),
            src_port: None,
            src: src.into(),
            dst: dst.into(),
            iface: None,
            comment: None,
            ipv6: false,
            temp_id: None,
            expires_at: None,
        }
    }

    #[test]
    fn parses_the_omarchy_tuples() {
        assert_eq!(
            tuple("### tuple ### allow udp 53317 0.0.0.0/0 any 0.0.0.0/0 in"),
            Some(rule(UfwAction::Allow, "udp", Some("53317"), "any", "any"))
        );
        assert_eq!(
            tuple("### tuple ### allow tcp 53317 0.0.0.0/0 any 0.0.0.0/0 in"),
            Some(rule(UfwAction::Allow, "tcp", Some("53317"), "any", "any"))
        );
        for src in ["172.16.0.0/12", "192.168.0.0/16"] {
            let line = format!(
                "### tuple ### allow udp 53 172.17.0.1 any {src} in comment=616c6c6f772d646f636b65722d646e73"
            );
            assert_eq!(
                tuple(&line),
                Some(UfwRule {
                    comment: Some("allow-docker-dns".into()),
                    ..rule(UfwAction::Allow, "udp", Some("53"), src, "172.17.0.1")
                })
            );
        }
    }

    #[test]
    fn imports_the_omarchy_rules() {
        let text = std::fs::read_to_string(omarchy_root().path().join("etc/ufw/user.rules"))
            .unwrap()
            + "### tuple ### allow udp 53 172.17.0.1 any 172.16.0.0/12 in comment=616c6c6f772d646f636b65722d646e73\n";
        let mut rules = parse_rules(&text, false, Path::new("user.rules"));
        rules.extend(parse_rules(
            "### tuple ### allow tcp 53317 ::/0 any ::/0 in\n",
            true,
            Path::new("user6.rules"),
        ));
        let (imported, skipped) = import(&rules);
        assert!(skipped.is_empty(), "{skipped:?}");
        let spec = |address: &str, port, protocol| FirewallRuleSpec {
            verdict: Verdict::Allow,
            direction: Direction::Inbound,
            address: address.into(),
            port: Some(port),
            protocol: Some(protocol),
            executable: None,
        };
        let specs: Vec<&FirewallRuleSpec> = imported.iter().map(|i| &i.spec).collect();
        assert_eq!(
            specs,
            [
                &spec("0.0.0.0/0", 53317, Protocol::Udp),
                &spec("0.0.0.0/0", 53317, Protocol::Tcp),
                &spec("172.16.0.0/12", 53, Protocol::Udp),
                &spec("::/0", 53317, Protocol::Tcp),
            ]
        );
        assert!(imported[..2].iter().all(|i| i.notes.is_empty()));
        assert_eq!(
            imported[2].notes,
            [
                "not limited to the local address 172.17.0.1: hub rules match the remote address only"
            ]
        );
    }

    #[test]
    fn imports_what_a_hub_rule_can_express() {
        let out = |action, protocol, port: Option<&str>, dst: &str| UfwRule {
            direction: UfwDirection::Out,
            ..rule(action, protocol, port, "any", dst)
        };
        let rules = [
            rule(UfwAction::Limit, "tcp", Some("22"), "any", "any"),
            rule(UfwAction::Reject, "any", None, "203.0.113.0/24", "any"),
            out(UfwAction::Deny, "tcp", Some("25"), "any"),
            out(UfwAction::Allow, "udp", Some("53"), "192.0.2.53"),
            // Not expressible:
            rule(UfwAction::Allow, "tcp", Some("8000:8100"), "any", "any"),
            rule(UfwAction::Allow, "tcp", Some("80,443"), "any", "any"),
            rule(UfwAction::Allow, "esp", None, "any", "any"),
            UfwRule {
                iface: Some("wlan0".into()),
                ..rule(UfwAction::Allow, "tcp", Some("22"), "any", "any")
            },
            UfwRule {
                src_port: Some("67".into()),
                ..rule(UfwAction::Allow, "udp", Some("68"), "any", "any")
            },
            rule(UfwAction::Allow, "tcp", Some("22"), "not-an-address", "any"),
        ];
        let (imported, skipped) = import(&rules);
        type Summary<'a> = (Verdict, Direction, &'a str, Option<u16>, Option<Protocol>);
        let got: Vec<Summary> = imported
            .iter()
            .map(|i| {
                let s = &i.spec;
                (
                    s.verdict,
                    s.direction,
                    s.address.as_str(),
                    s.port,
                    s.protocol,
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (
                    Verdict::Allow,
                    Direction::Inbound,
                    "0.0.0.0/0",
                    Some(22),
                    Some(Protocol::Tcp)
                ),
                (
                    Verdict::Block,
                    Direction::Inbound,
                    "203.0.113.0/24",
                    None,
                    None
                ),
                (
                    Verdict::Block,
                    Direction::Outbound,
                    "0.0.0.0/0",
                    Some(25),
                    Some(Protocol::Tcp)
                ),
                (
                    Verdict::Allow,
                    Direction::Outbound,
                    "192.0.2.53",
                    Some(53),
                    Some(Protocol::Udp)
                ),
            ]
        );
        assert!(imported[0].notes[0].contains("rate limiting"));
        assert!(imported[1].notes[0].contains("not rejected"));
        let reasons: Vec<&str> = skipped.iter().map(|(_, r)| r.as_str()).collect();
        assert_eq!(
            reasons[..5],
            [
                "port 8000:8100 is a range or a list",
                "port 80,443 is a range or a list",
                "protocol esp is not supported",
                "it only applies to interface wlan0",
                "it matches source port 67",
            ]
        );
        assert!(reasons[5].contains("not-an-address"), "{}", reasons[5]);
    }

    #[test]
    fn notices_a_flushing_nftables_conf() {
        assert!(flushes_ruleset(
            "#!/usr/bin/nft -f\nflush ruleset\ntable inet filter {}\n"
        ));
        assert!(flushes_ruleset("  flush   ruleset # stock\n"));
        assert!(!flushes_ruleset("# flush ruleset\ntable inet filter {}\n"));
        assert!(!flushes_ruleset("flush table inet filter\n"));
    }

    #[tokio::test]
    async fn reports_services_that_undo_the_ruleset() {
        use std::os::unix::fs::PermissionsExt;
        let root = omarchy_root();
        let fake = root.path().join("systemctl");
        let script = |enabled: bool, active: bool| {
            format!(
                "#!/bin/sh\ncase \"$1 $3\" in\n\
                 'is-enabled nftables.service') exit {} ;;\n\
                 'is-active firewalld.service') exit {} ;;\n\
                 esac\nexit 4\n",
                u8::from(!enabled),
                u8::from(!active)
            )
        };
        let env = UfwEnv {
            systemctl: Some(fake.clone()),
            ..UfwEnv::at(root.path())
        };
        // Written aside and renamed: executing a file another thread still
        // has open for writing fails with ETXTBSY.
        let install = |text: String| {
            let tmp = fake.with_extension("new");
            std::fs::write(&tmp, text).unwrap();
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::rename(&tmp, &fake).unwrap();
        };
        install(script(false, false));
        assert!(conflicts(&env).await.is_empty());
        // Enabled, and no readable nftables.conf: assume the stock file.
        install(script(true, true));
        assert_eq!(
            conflicts(&env).await,
            [
                "nftables.service is enabled and flushes the ruleset",
                "firewalld is active and manages the ruleset as well",
            ]
        );
        std::fs::write(
            root.path().join("etc/nftables.conf"),
            "table inet filter {}\n",
        )
        .unwrap();
        install(script(true, false));
        assert!(conflicts(&env).await.is_empty());
        assert!(conflicts(&UfwEnv::at(root.path())).await.is_empty());
    }

    #[test]
    fn parses_ipv6_interfaces_apps_and_logging() {
        assert_eq!(
            parse_tuple("### tuple ### allow tcp 53317 ::/0 any ::/0 in", true),
            Some(UfwRule {
                ipv6: true,
                ..rule(UfwAction::Allow, "tcp", Some("53317"), "any", "any")
            })
        );
        assert_eq!(
            tuple("### tuple ### deny_log any 22 0.0.0.0/0 any 10.0.0.0/8 in_wlan0"),
            Some(UfwRule {
                iface: Some("wlan0".into()),
                ..rule(UfwAction::Deny, "any", Some("22"), "10.0.0.0/8", "any")
            })
        );
        assert_eq!(
            tuple("### tuple ### limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in"),
            Some(rule(UfwAction::Limit, "tcp", Some("22"), "any", "any"))
        );
        let out = tuple("### tuple ### reject tcp 25 0.0.0.0/0 1024:65535 0.0.0.0/0 out").unwrap();
        assert_eq!(
            (out.direction, out.src_port.as_deref()),
            (UfwDirection::Out, Some("1024:65535"))
        );
        // Not hex: kept as written.
        assert_eq!(
            tuple("### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in comment=xyz")
                .unwrap()
                .comment
                .as_deref(),
            Some("xyz")
        );
    }

    #[test]
    fn skips_malformed_and_routed_lines() {
        for line in [
            "### tuple ### allow tcp 80",
            "### tuple ### permit tcp 80 0.0.0.0/0 any 0.0.0.0/0 in",
            "### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 sideways",
            "### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_",
            "### tuple ### route:allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1",
            "-A ufw-user-input -p tcp --dport 80 -j ACCEPT",
        ] {
            assert_eq!(tuple(line), None, "{line}");
        }
        let text = "### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in\n\
                    ### tuple ### garbage\n\
                    ### tuple ### deny udp 53 0.0.0.0/0 any 0.0.0.0/0 out\n";
        assert_eq!(parse_rules(text, false, Path::new("user.rules")).len(), 2);
    }

    fn inspection(chains: bool, table: Option<&str>) -> FirewallInspection {
        FirewallInspection {
            ufw_chains_loaded: chains,
            table_loaded: table.is_some(),
            table_mode: table.filter(|m| !m.is_empty()).map(Into::into),
            before_rules_modified: Some(false),
            hub_mode: Default::default(),
            boot_copy_error: None,
            temp: vec![],
        }
    }

    #[test]
    fn derives_every_mode() {
        let conf = |enabled| Conf {
            installed: true,
            enabled,
            ufw_docker: true,
            ..Conf::default()
        };
        use FirewallModeKind as M;
        // (enabled in ufw.conf, chains loaded, table stamp) → mode
        let cases = [
            (true, true, None, M::Ufw),
            (true, true, Some(""), M::Ufw),
            (true, true, Some("ufw"), M::Ufw),
            (true, true, Some("standalone"), M::Both),
            (false, false, Some("standalone"), M::Standalone),
            (false, false, None, M::None),
            (false, false, Some("ufw"), M::None),
            (true, false, None, M::None),
            (true, false, Some("standalone"), M::Standalone),
            (false, true, None, M::None),
            (false, true, Some("standalone"), M::Standalone),
        ];
        for (enabled, chains, table, want) in cases {
            let mode = derive(&conf(enabled), Ok(&inspection(chains, table)));
            assert_eq!(mode.mode, want, "{enabled} {chains} {table:?}");
            assert_eq!(mode.ufw.chains_loaded, Some(chains));
            assert_eq!(mode.table_loaded, Some(table.is_some()));
            let docker = match (enabled && chains, table == Some("standalone")) {
                (true, _) => DockerProtection::UfwDocker,
                (false, true) => DockerProtection::Omarchy,
                (false, false) => DockerProtection::None,
            };
            assert_eq!(
                mode.docker_protection, docker,
                "{enabled} {chains} {table:?}"
            );
            assert_eq!(mode.detail.is_some(), enabled != chains, "{mode:?}");
        }

        let unknown = derive(&conf(true), Err("helper not reachable"));
        assert_eq!(unknown.mode, M::Unknown);
        assert_eq!(
            (unknown.ufw.chains_loaded, unknown.table_loaded),
            (None, None)
        );
        assert!(unknown.detail.unwrap().contains("helper not reachable"));
        assert_eq!(unknown.docker_protection, DockerProtection::UfwDocker);

        let absent = derive(&Conf::default(), Ok(&inspection(false, None)));
        assert_eq!(absent.mode, M::None);
        assert_eq!(absent.detail.as_deref(), Some("ufw is not installed"));

        // What the helper renders for, and its boot copy.
        let chosen = FirewallInspection {
            hub_mode: HubMode::Standalone,
            boot_copy_error: Some("read-only file system".into()),
            ..inspection(false, None)
        };
        let lost = derive(&conf(false), Ok(&chosen));
        assert_eq!(lost.mode, M::None);
        assert_eq!(
            lost.detail.as_deref(),
            Some(
                "the hub firewall is chosen, but its table is not loaded; \
                 the boot copy of the hub firewall could not be written (read-only file system)"
            )
        );
        let loaded = FirewallInspection {
            hub_mode: HubMode::Standalone,
            ..inspection(false, Some("standalone"))
        };
        assert_eq!(derive(&conf(false), Ok(&loaded)).detail, None);
    }

    /// An `/etc/ufw`-like tree under a temporary root.
    pub(crate) fn omarchy_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let write = |relative: &str, text: &str| {
            let path = root.path().join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write("usr/bin/ufw", "#!/usr/bin/python3\n");
        write("etc/ufw/ufw.conf", "# comment\nENABLED=yes\nLOGLEVEL=low\n");
        write(
            "etc/default/ufw",
            "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\nDEFAULT_FORWARD_POLICY='DROP'\n",
        );
        write(
            "etc/ufw/after.rules",
            "*filter\n# BEGIN UFW AND DOCKER\n:ufw-docker-logging-deny - [0:0]\n# END UFW AND DOCKER\nCOMMIT\n",
        );
        write(
            "etc/ufw/user.rules",
            "*filter\n### RULES ###\n\n\
             ### tuple ### allow udp 53317 0.0.0.0/0 any 0.0.0.0/0 in\n\
             -A ufw-user-input -p udp --dport 53317 -j ACCEPT\n\n\
             ### tuple ### allow tcp 53317 0.0.0.0/0 any 0.0.0.0/0 in\n\
             -A ufw-user-input -p tcp --dport 53317 -j ACCEPT\n\n\
             ### END RULES ###\nCOMMIT\n",
        );
        write(
            "etc/ufw/user6.rules",
            "### tuple ### allow tcp 53317 ::/0 any ::/0 in\n",
        );
        root
    }

    #[test]
    fn reads_an_etc_ufw_tree() {
        let root = omarchy_root();
        let env = UfwEnv::at(root.path());
        assert_eq!(
            read_conf(&env),
            Conf {
                installed: true,
                enabled: true,
                logging: Some("low".into()),
                default_input: Some("drop".into()),
                default_output: Some("accept".into()),
                default_forward: Some("drop".into()),
                ufw_docker: true,
            }
        );
        let list = read_rules(&env);
        assert_eq!(list.rules.len(), 3);
        assert_eq!(
            list.rules.iter().filter(|r| r.ipv6).count(),
            1,
            "{:?}",
            list.rules
        );
        assert!(list.builtin.last().unwrap().contains("ufw-docker"));
        assert_eq!(list.source, "user.rules");

        let missing = UfwEnv::at(root.path().join("nothing"));
        assert_eq!(read_conf(&missing), Conf::default());
        let empty = read_rules(&missing);
        assert!(empty.rules.is_empty() && empty.builtin.is_empty());
    }

    async fn within(
        rx: &mut mpsc::Receiver<()>,
        ms: u64,
    ) -> Result<Option<()>, tokio::time::error::Elapsed> {
        tokio::time::timeout(Duration::from_millis(ms), rx.recv()).await
    }

    #[tokio::test]
    async fn notices_files_replaced_by_rename() {
        let root = omarchy_root();
        let env = UfwEnv::at(root.path());
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(watch(env, tx));
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Something ufw does not own: no change.
        std::fs::write(root.path().join("etc/ufw/sysctl.conf"), "x").unwrap();
        assert!(within(&mut rx, 200).await.is_err());

        let conf = root.path().join("etc/ufw/ufw.conf");
        let tmp = root.path().join("etc/ufw/ufw.conf.tmp");
        std::fs::write(&tmp, "ENABLED=no\n").unwrap();
        std::fs::rename(&tmp, &conf).unwrap();
        assert_eq!(within(&mut rx, 2000).await, Ok(Some(())));
        std::fs::write(root.path().join("etc/default/ufw"), "IPV6=no\n").unwrap();
        assert_eq!(within(&mut rx, 2000).await, Ok(Some(())));

        drop(rx);
        let ended = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(matches!(ended, Ok(Ok(Ok(())))), "{ended:?}");

        let (tx, _rx) = mpsc::channel(1);
        let nowhere = UfwEnv::at(root.path().join("nothing"));
        assert!(watch(nowhere, tx).await.is_err());
    }
}
