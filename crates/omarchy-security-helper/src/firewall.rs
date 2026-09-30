// SPDX-License-Identifier: GPL-3.0-or-later

//! Renders the daemon's firewall rules into `table inet omarchy_sec` and
//! applies them with one `nft -f -` transaction.
//!
//! The table is always replaced whole: the script creates it (so the delete
//! cannot fail), deletes it, and recreates it with the new rules, all in one
//! atomic netlink batch. Nothing outside this table is touched.
//!
//! Within each chain, `allow` rules come before `block` rules, so an allow
//! rule acts as an exception to a broader block. An `accept` here does not
//! override a `drop` in another table: netfilter runs every table's base
//! chains.
//!
//! The table is rendered for one of two modes ([`HubMode`], kept in
//! `/var/lib/omarchy-security/mode`). In `ufw` mode `ufw` protects the
//! machine and the table holds only what adds to it: rules without an
//! `executable` are kept but not rendered, because a hub `allow` could not
//! override `ufw` anyway. In `standalone` mode the table holds the full
//! policy: a baseline that mirrors what Omarchy's `ufw` setup allows, an
//! input chain with `policy drop`, protection for published Docker ports,
//! and the saved rules. The mode is stamped into the table's comment.
//!
//! Every change also writes the boot copy, `/var/lib/omarchy-security/
//! firewall.nft`, which `omarchy-security-firewall.service` loads before
//! the network comes up. It holds the table without the queue rule (no one
//! is there to answer at boot); in `ufw` mode it only deletes the table.
//! The rules last applied are kept in `rules.json` beside it, so a
//! restarted helper renders the same table.
//!
//! Rules with an `executable` are not rendered: nftables cannot match a
//! process by path. While connections are intercepted
//! (`connections.rs`), the output chain ends with a rule that sends the
//! desktop user's new TCP and UDP connections to the NFQUEUE instead, where
//! the helper matches them. Loopback traffic is not queued.
//!
//! `inspect` reports what is loaded: whether `ufw`'s chains are, whether
//! our table is and the mode stamped into its comment, and whether `ufw`'s
//! `before.rules` differ from the packaged copies (which only root may
//! read).
//!
//! `set_mode` switches between the modes and turns `ufw` off or on with
//! them, in an order that never leaves the machine without a firewall
//! (plan §5.18). To `standalone`: load and verify our full table, write
//! the boot copy and the mode file, and only then run `ufw disable`. To
//! `ufw`: run `ufw --force enable` and check its chains, and only then
//! shrink our table. A failure part-way leaves both enforcing (mode
//! `both`), never neither. `ufw` is run directly, never through a shell,
//! with a cleared environment.
//!
//! Temporary decisions (plan §5.20) with the `table` backend are rendered
//! as one named set per decision, holding one element with a kernel
//! timeout, so they expire even if the helper dies. Their rules come first
//! in the input and output chains, blocks before allows, ahead of
//! `ct state established,related accept`, so a temporary block also cuts a
//! connection that is open. Since the table is always replaced whole, every
//! render includes the live decisions with their remaining time; they are
//! kept in memory only, never in the boot copy or `rules.json`. With the
//! `ufw` backend a decision is a `ufw` rule whose comment carries its
//! expiry; [`Firewall::sweep_ufw`] deletes expired ones every 30 s and at
//! startup, and those from an earlier boot.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use omarchy_security_proto::helper::{
    FirewallInspection, HelperError, HelperErrorKind, HubMode, UfwTempChange,
};
use omarchy_security_proto::types::{
    Direction, FirewallRule, Protocol, TempBackend, TempDecision, Verdict, check_temp_spec,
    parse_prefix,
};
use serde_json::Value;
use tokio::io::AsyncWriteExt;

pub const TABLE: &str = "omarchy_sec";

/// Where the mode, the boot copy and the applied rules live.
pub const STATE_DIR: &str = "/var/lib/omarchy-security";
const MODE_FILE: &str = "mode";
const BOOT_COPY: &str = "firewall.nft";
const RULES_FILE: &str = "rules.json";

pub const UFW: &str = "/usr/bin/ufw";

/// `ufw` waits for its lock; a switch gives up after this long.
const UFW_TIMEOUT: Duration = Duration::from_secs(60);

/// Before the saved inbound rules in `standalone` mode: what `ufw`'s
/// `before.rules` allow on a stock install.
const BASELINE_INPUT: &[&str] = &[
    "ct state established,related accept",
    "ct state invalid drop",
    "iif \"lo\" accept",
    "meta l4proto icmp icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } accept",
    "meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept",
    "udp sport 67 udp dport 68 accept",
    "udp sport 547 udp dport 546 accept",
    "ip daddr 224.0.0.251 udp dport 5353 accept",
    "ip6 daddr ff02::fb udp dport 5353 accept",
    "ip daddr 239.255.255.250 udp dport 1900 accept",
];

/// After the saved inbound rules; the chain's policy drops what is left.
const BASELINE_INPUT_LOG: &str =
    "limit rate 5/second burst 20 packets log prefix \"[OMSEC BLOCK] \" level info";

/// The intent of the ufw-docker block in `/etc/ufw/after.rules`: a new
/// connection from outside the private ranges into them is logged and
/// dropped. Only connections Docker DNAT-ed (published container ports)
/// are dropped, so routing that Docker does not own (libvirt, a VPN subnet
/// router) keeps working. `accept` here only ends this chain; Docker's own
/// chains still run.
const DOCKER_FORWARD: &[&str] = &[
    "ct state established,related accept",
    "ct state invalid drop",
    "iifname \"docker0\" oifname \"docker0\" accept",
    "ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept",
    "ct state new ct status dnat ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } limit rate 3/minute burst 10 packets log prefix \"[OMSEC DOCKER BLOCK] \" level info",
    "ct state new ct status dnat ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter drop comment \"omarchy:docker\"",
];

/// The NFQUEUE rule at the end of the output chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueRule {
    pub num: u16,
    /// Whose connections are queued (`meta skuid`).
    pub uid: u32,
    /// Queue loopback traffic too; only for tests, which have no other
    /// interface.
    pub loopback: bool,
}

fn render_rule(rule: &FirewallRule) -> Result<String, String> {
    let spec = &rule.spec;
    let (ip, len) = parse_prefix(&spec.address)?;
    let family = if ip.is_ipv4() { "ip" } else { "ip6" };
    let side = match spec.direction {
        Direction::Inbound => "saddr",
        Direction::Outbound => "daddr",
    };
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let mut line = if len == max {
        format!("{family} {side} {ip}")
    } else {
        format!("{family} {side} {ip}/{len}")
    };
    let proto = spec.protocol.map(|p| match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    });
    match (proto, spec.port) {
        (Some(proto), Some(port)) => write!(line, " {proto} dport {port}").unwrap(),
        (Some(proto), None) => write!(line, " meta l4proto {proto}").unwrap(),
        (None, Some(port)) => write!(line, " meta l4proto {{ tcp, udp }} th dport {port}").unwrap(),
        (None, None) => {}
    }
    let verdict = match spec.verdict {
        Verdict::Allow => "accept",
        Verdict::Block => "drop",
    };
    write!(
        line,
        " counter {verdict} comment \"omarchy:{}\"",
        rule.rule_id
    )
    .unwrap();
    Ok(line)
}

/// The complete `nft -f` script for `mode`, `rules` and `queue`. In `ufw`
/// mode without a queue rule the table is simply removed. Every rule is
/// checked in both modes, so that one kept in `ufw` mode cannot fail the
/// switch to `standalone` later.
pub fn render(
    mode: HubMode,
    rules: &[FirewallRule],
    queue: Option<QueueRule>,
) -> Result<String, String> {
    render_with(mode, rules, queue, &[], 0)
}

/// An address or prefix as nft writes it, without the length of a host.
fn nft_address(address: &str) -> Result<(String, bool), String> {
    let (ip, len) = parse_prefix(address)?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    Ok(if len == max {
        (ip.to_string(), ip.is_ipv4())
    } else {
        (format!("{ip}/{len}"), ip.is_ipv4())
    })
}

fn check_temp(decision: &TempDecision) -> Result<(), String> {
    if decision.backend != TempBackend::Table {
        return Err(format!(
            "temporary decision {} is not for the table",
            decision.temp_id
        ));
    }
    check_temp_spec(&decision.spec)
        .map_err(|e| format!("temporary decision {}: {e}", decision.temp_id))
}

/// The set and the rule of one temporary decision, or `None` once it has
/// less than a second left.
fn render_temp(decision: &TempDecision, now_ms: u64) -> Result<Option<(String, String)>, String> {
    check_temp(decision)?;
    let remaining = decision.expires_at.saturating_sub(now_ms);
    if remaining < 1000 {
        return Ok(None);
    }
    let left = remaining.div_ceil(1000);
    let spec = &decision.spec;
    let (address, v4) = nft_address(&spec.address)?;
    let (family, addr_type) = if v4 {
        ("ip", "ipv4_addr")
    } else {
        ("ip6", "ipv6_addr")
    };
    let side = match spec.direction {
        Direction::Inbound => "saddr",
        Direction::Outbound => "daddr",
    };
    let proto = spec.protocol.map(|p| match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    });
    let (types, key, element) = match (proto, spec.port) {
        (Some(proto), Some(port)) => (
            format!("{addr_type} . inet_proto . inet_service"),
            format!("{family} {side} . meta l4proto . th dport"),
            format!("{address} . {proto} . {port}"),
        ),
        (Some(proto), None) => (
            format!("{addr_type} . inet_proto"),
            format!("{family} {side} . meta l4proto"),
            format!("{address} . {proto}"),
        ),
        _ => (
            addr_type.to_owned(),
            format!("{family} {side}"),
            address.clone(),
        ),
    };
    let flags = if address.contains('/') {
        "interval, timeout"
    } else {
        "timeout"
    };
    let id = decision.temp_id;
    let set = format!(
        "\tset tmp_{id} {{\n\t\ttype {types}\n\t\tflags {flags}\n\t\telements = {{ {element} timeout {left}s }}\n\t}}\n"
    );
    let verdict = match spec.verdict {
        Verdict::Allow => "accept",
        Verdict::Block => "drop",
    };
    let rule = format!("{key} @tmp_{id} counter {verdict} comment \"omarchy:tmp:{id}\"");
    Ok(Some((set, rule)))
}

/// [`render`] with the temporary decisions that are live at `now_ms`.
pub fn render_with(
    mode: HubMode,
    rules: &[FirewallRule],
    queue: Option<QueueRule>,
    temps: &[TempDecision],
    now_ms: u64,
) -> Result<String, String> {
    let mut ordered_temps: Vec<(&TempDecision, String, String)> = vec![];
    for decision in temps {
        if let Some((set, rule)) = render_temp(decision, now_ms)? {
            ordered_temps.push((decision, set, rule));
        }
    }
    ordered_temps.sort_by_key(|(d, _, _)| (d.spec.verdict == Verdict::Allow, d.temp_id));
    let mut script = format!("table inet {TABLE}\ndelete table inet {TABLE}\n");
    let standalone = mode == HubMode::Standalone;
    let mut ordered: Vec<(&FirewallRule, String)> = vec![];
    for rule in rules.iter().filter(|r| r.spec.executable.is_none()) {
        let line = render_rule(rule).map_err(|e| format!("rule {}: {e}", rule.rule_id))?;
        if standalone {
            ordered.push((rule, line));
        }
    }
    if !standalone && queue.is_none() && ordered_temps.is_empty() {
        return Ok(script);
    }
    ordered.sort_by_key(|(r, _)| (r.spec.verdict == Verdict::Block, r.rule_id));
    writeln!(script, "table inet {TABLE} {{").unwrap();
    writeln!(script, "\tcomment \"mode={}\"", mode.as_str()).unwrap();
    for (_, set, _) in &ordered_temps {
        script.push_str(set);
    }
    for (chain, direction) in [
        ("input", Some(Direction::Inbound)),
        ("forward", None),
        ("output", Some(Direction::Outbound)),
    ] {
        let Some(direction) = direction else {
            if standalone {
                writeln!(script, "\tchain forward {{").unwrap();
                writeln!(
                    script,
                    "\t\ttype filter hook forward priority filter; policy accept;"
                )
                .unwrap();
                for line in DOCKER_FORWARD {
                    writeln!(script, "\t\t{line}").unwrap();
                }
                writeln!(script, "\t}}").unwrap();
            }
            continue;
        };
        let policy = match (standalone, direction) {
            (true, Direction::Inbound) => "drop",
            _ => "accept",
        };
        writeln!(script, "\tchain {chain} {{").unwrap();
        writeln!(
            script,
            "\t\ttype filter hook {chain} priority filter; policy {policy};"
        )
        .unwrap();
        for (_, _, rule) in ordered_temps
            .iter()
            .filter(|(d, _, _)| d.spec.direction == direction)
        {
            writeln!(script, "\t\t{rule}").unwrap();
        }
        if policy == "drop" {
            for line in BASELINE_INPUT {
                writeln!(script, "\t\t{line}").unwrap();
            }
        }
        for (_, line) in ordered
            .iter()
            .filter(|(r, _)| r.spec.direction == direction)
        {
            writeln!(script, "\t\t{line}").unwrap();
        }
        if policy == "drop" {
            writeln!(script, "\t\t{BASELINE_INPUT_LOG}").unwrap();
        }
        if let (Direction::Outbound, Some(queue)) = (direction, queue) {
            if !queue.loopback {
                writeln!(script, "\t\toif \"lo\" accept comment \"omarchy:queue\"").unwrap();
            }
            writeln!(
                script,
                "\t\tmeta skuid {} meta l4proto {{ tcp, udp }} ct state new counter queue num {} bypass comment \"omarchy:queue\"",
                queue.uid, queue.num
            )
            .unwrap();
        }
        writeln!(script, "\t}}").unwrap();
    }
    writeln!(script, "}}").unwrap();
    Ok(script)
}

/// What `omarchy-security-firewall.service` loads at boot: the table
/// without the queue rule.
pub fn boot_script(mode: HubMode, rules: &[FirewallRule]) -> Result<String, String> {
    Ok(format!(
        "# Written by omarchy-securityd-helper; do not edit.\n\
         # Loaded at boot by omarchy-security-firewall.service.\n{}",
        render(mode, rules, None)?
    ))
}

pub fn find_nft() -> Option<PathBuf> {
    ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// What the table currently holds, and what was last persisted.
#[derive(Default)]
struct Applied {
    mode: HubMode,
    rules: Vec<FirewallRule>,
    queue: Option<QueueRule>,
    /// Temporary decisions in the table; memory only.
    temps: Vec<TempDecision>,
    /// The boot copy last written, to skip rewriting an identical one.
    boot: Option<String>,
    boot_error: Option<String>,
}

pub struct Firewall {
    nft: Option<PathBuf>,
    /// Command `nft` and `ufw` run under; tests use `unshare -rn`.
    wrapper: Vec<String>,
    /// [`UFW`] except in tests.
    ufw: PathBuf,
    /// Where `etc/ufw` and `usr/share/ufw` are looked up; `/` except in tests.
    root: PathBuf,
    /// [`STATE_DIR`]; `None` keeps nothing on disk (tests).
    state_dir: Option<PathBuf>,
    /// Also serializes changes.
    applied: tokio::sync::Mutex<Applied>,
    /// Serializes `ufw` calls: each takes about a second.
    ufw_lock: tokio::sync::Mutex<()>,
}

impl Firewall {
    pub fn new(state_dir: &Path) -> Self {
        Self::with_wrapper(&[]).with_state_dir(state_dir)
    }

    pub fn with_wrapper(wrapper: &[&str]) -> Self {
        Self {
            nft: find_nft(),
            wrapper: wrapper.iter().map(|s| s.to_string()).collect(),
            ufw: PathBuf::from(UFW),
            root: PathBuf::from("/"),
            state_dir: None,
            applied: tokio::sync::Mutex::new(Applied::default()),
            ufw_lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Reads the mode and the rules last applied from `dir`. A missing or
    /// unreadable mode is `ufw`, what Omarchy ships with.
    pub fn with_state_dir(mut self, dir: &Path) -> Self {
        let applied = self.applied.get_mut();
        applied.mode = match std::fs::read_to_string(dir.join(MODE_FILE)) {
            Ok(text) => match text.trim() {
                "standalone" => HubMode::Standalone,
                "ufw" => HubMode::Ufw,
                other => {
                    tracing::warn!("unknown firewall mode '{other}' in {MODE_FILE}; using ufw");
                    HubMode::Ufw
                }
            },
            Err(_) => HubMode::Ufw,
        };
        let rules = dir.join(RULES_FILE);
        applied.rules = match std::fs::read(&rules) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|err| {
                tracing::warn!("ignoring unreadable {}: {err}", rules.display());
                vec![]
            }),
            Err(_) => vec![],
        };
        tracing::info!(
            mode = applied.mode.as_str(),
            rules = applied.rules.len(),
            "firewall state loaded"
        );
        self.state_dir = Some(dir.to_owned());
        self
    }

    #[cfg(test)]
    pub fn with_root(mut self, root: &Path) -> Self {
        self.root = root.to_owned();
        self
    }

    #[cfg(test)]
    pub fn with_ufw(mut self, ufw: &Path) -> Self {
        self.ufw = ufw.to_owned();
        self
    }

    pub fn available(&self) -> bool {
        self.nft.is_some()
    }

    /// Re-applies the standalone table from the saved state at startup, so
    /// that the table and the boot copy match what this helper renders
    /// even if the boot copy was stale. In `ufw` mode there is nothing to
    /// restore before the daemon connects.
    pub async fn restore(&self) -> Result<(), HelperError> {
        let mut applied = self.applied.lock().await;
        if applied.mode != HubMode::Standalone {
            return Ok(());
        }
        self.write(applied.mode, &applied.rules, applied.queue, &applied.temps)
            .await?;
        self.persist(&mut applied);
        Ok(())
    }

    /// Replaces the rules, keeping the queue rule.
    pub async fn apply(&self, rules: &[FirewallRule]) -> Result<(), HelperError> {
        let mut applied = self.applied.lock().await;
        self.write(applied.mode, rules, applied.queue, &applied.temps)
            .await?;
        self.save_rules(&mut applied, rules);
        self.persist(&mut applied);
        Ok(())
    }

    /// Whether `rules` load an inbound allow that is not loaded now. Only
    /// in `standalone` mode, where our table decides inbound traffic: in
    /// `ufw` mode such a rule is kept but not rendered.
    pub async fn opens_inbound(&self, rules: &[FirewallRule]) -> bool {
        let applied = self.applied.lock().await;
        applied.mode == HubMode::Standalone
            && rules.iter().any(|rule| {
                inbound_allow(rule) && !applied.rules.iter().any(|a| a.spec == rule.spec)
            })
    }

    /// Switches to `mode` with `rules` (plan §5.18), under the same lock as
    /// every other change.
    pub async fn set_mode(&self, mode: HubMode, rules: &[FirewallRule]) -> Result<(), HelperError> {
        let mut applied = self.applied.lock().await;
        match mode {
            HubMode::Standalone => self.to_standalone(&mut applied, rules).await,
            HubMode::Ufw => self.to_ufw(&mut applied, rules).await,
        }?;
        tracing::info!(
            mode = mode.as_str(),
            rules = rules.len(),
            "firewall mode set"
        );
        Ok(())
    }

    async fn to_standalone(
        &self,
        applied: &mut Applied,
        rules: &[FirewallRule],
    ) -> Result<(), HelperError> {
        let backend = |msg: String| HelperError::new(HelperErrorKind::Backend, msg);
        // 1. Our full policy, verified, while ufw still runs.
        self.write(HubMode::Standalone, rules, applied.queue, &applied.temps)
            .await?;
        if let Err(err) = self.standalone_loaded().await {
            if let Err(undo) = self
                .write(applied.mode, &applied.rules, applied.queue, &applied.temps)
                .await
            {
                tracing::warn!("restoring the table after a failed check: {undo}");
            }
            return Err(backend(format!("{err}; ufw was left on")));
        }
        applied.mode = HubMode::Standalone;
        self.save_rules(applied, rules);
        // 2. What holds at the next boot, before ufw goes away.
        self.persist(applied);
        if let Some(err) = &applied.boot_error {
            return Err(backend(format!(
                "writing the boot copy: {err}; ufw was left on, so both firewalls are enforcing"
            )));
        }
        self.write_mode(HubMode::Standalone).map_err(|err| {
            backend(format!(
                "writing the mode file: {err}; ufw was left on, so both firewalls are enforcing"
            ))
        })?;
        // 3 and 4. A failure keeps our table: ufw's state is unknown then.
        self.run_ufw(&["disable"])
            .await
            .map_err(|err| backend(format!("{err}; both firewalls may be enforcing")))?;
        if self.ufw_loaded().await? {
            return Err(backend(
                "ufw disable succeeded, but ufw's chains are still loaded; both firewalls are enforcing"
                    .into(),
            ));
        }
        Ok(())
    }

    async fn to_ufw(
        &self,
        applied: &mut Applied,
        rules: &[FirewallRule],
    ) -> Result<(), HelperError> {
        let backend = |msg: String| HelperError::new(HelperErrorKind::Backend, msg);
        // Checked before ufw is touched, like every rule in both modes.
        render(HubMode::Ufw, rules, applied.queue)
            .map_err(|e| HelperError::new(HelperErrorKind::Invalid, e))?;
        // 1. ufw first; a failure keeps our table.
        let keeps = "the hub firewall stays active";
        self.run_ufw(&["--force", "enable"])
            .await
            .map_err(|err| backend(format!("{err}; {keeps}")))?;
        if !self.ufw_loaded().await? {
            return Err(backend(format!(
                "ufw was enabled, but its chains are not loaded; {keeps}"
            )));
        }
        // 2. Only then our table shrinks.
        self.write(HubMode::Ufw, rules, applied.queue, &applied.temps)
            .await
            .map_err(|err| backend(format!("{err}; ufw is on, so both firewalls are enforcing")))?;
        applied.mode = HubMode::Ufw;
        self.save_rules(applied, rules);
        self.persist(applied);
        if let Err(err) = self.write_mode(HubMode::Ufw) {
            // ufw and the boot copy agree; a restarted helper would only
            // re-load our table next to ufw.
            tracing::error!("writing the mode file: {err}");
        }
        Ok(())
    }

    /// Checks what `nft` loaded for `standalone`: the stamp, and an input
    /// chain that drops by default.
    async fn standalone_loaded(&self) -> Result<(), HelperError> {
        let listing = self.nft_json(&["list", "table", "inet", TABLE]).await?;
        if standalone_loaded(&listing) {
            Ok(())
        } else {
            Err(HelperError::new(
                HelperErrorKind::Backend,
                "the standalone table did not load as rendered (no input chain with policy drop)",
            ))
        }
    }

    async fn ufw_loaded(&self) -> Result<bool, HelperError> {
        Ok(ufw_chains_loaded(
            &self.nft_json(&["list", "chains"]).await?,
        ))
    }

    /// Runs `ufw <args>` with a cleared environment and [`UFW_TIMEOUT`].
    async fn run_ufw<S: AsRef<std::ffi::OsStr>>(&self, args: &[S]) -> Result<(), String> {
        let wrapper: Vec<&str> = self.wrapper.iter().map(String::as_str).collect();
        let what = format!(
            "ufw {}",
            args.iter()
                .map(|a| a.as_ref().to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );
        let _serial = self.ufw_lock.lock().await;
        let mut command = command(&self.ufw, &wrapper);
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/usr/sbin")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(UFW_TIMEOUT, command.output())
            .await
            .map_err(|_| format!("{what} did not finish in {} s", UFW_TIMEOUT.as_secs()))?
            .map_err(|e| format!("running {what}: {e}"))?;
        if output.status.success() {
            tracing::info!("{what} done");
            return Ok(());
        }
        let text = [&output.stderr, &output.stdout]
            .into_iter()
            .map(|b| String::from_utf8_lossy(b).trim().to_owned())
            .find(|t| !t.is_empty())
            .unwrap_or_else(|| output.status.to_string());
        Err(format!("{what} failed: {text}"))
    }

    fn save_rules(&self, applied: &mut Applied, rules: &[FirewallRule]) {
        applied.rules = rules.to_vec();
        if let Some(dir) = &self.state_dir
            && let Err(err) = write_atomic(
                &dir.join(RULES_FILE),
                &serde_json::to_vec_pretty(rules).expect("rules serialize"),
            )
        {
            tracing::warn!("saving the applied rules: {err}");
        }
    }

    fn write_mode(&self, mode: HubMode) -> std::io::Result<()> {
        match &self.state_dir {
            Some(dir) => write_atomic(
                &dir.join(MODE_FILE),
                format!("{}\n", mode.as_str()).as_bytes(),
            ),
            None => Ok(()),
        }
    }

    /// Whether `decisions` add an inbound allow the table does not hold
    /// now: that needs the password, as a permanent one does.
    pub async fn temp_opens_inbound(&self, decisions: &[TempDecision]) -> bool {
        let applied = self.applied.lock().await;
        decisions.iter().any(|d| {
            d.spec.direction == Direction::Inbound
                && d.spec.verdict == Verdict::Allow
                && !applied
                    .temps
                    .iter()
                    .any(|a| a.temp_id == d.temp_id && a.spec == d.spec)
        })
    }

    /// Replaces the temporary decisions in the table, keeping everything
    /// else. Expired ones are dropped.
    pub async fn set_temp(&self, decisions: &[TempDecision]) -> Result<(), HelperError> {
        for decision in decisions {
            check_temp(decision).map_err(|e| HelperError::new(HelperErrorKind::Invalid, e))?;
        }
        let temps = live(decisions, now_ms());
        let mut applied = self.applied.lock().await;
        self.write(applied.mode, &applied.rules, applied.queue, &temps)
            .await?;
        tracing::info!(temps = temps.len(), "temporary decisions applied");
        applied.temps = temps;
        Ok(())
    }

    /// Adds or deletes the tagged `ufw` rule of a decision.
    pub async fn ufw_temp(
        &self,
        change: UfwTempChange,
        decision: &TempDecision,
    ) -> Result<(), HelperError> {
        let invalid = |msg: String| HelperError::new(HelperErrorKind::Invalid, msg);
        if decision.backend != TempBackend::Ufw {
            return Err(invalid(format!(
                "temporary decision {} is not for ufw",
                decision.temp_id
            )));
        }
        if change == UfwTempChange::Add && decision.expires_at <= now_ms() {
            return Err(invalid(format!(
                "temporary decision {} has expired",
                decision.temp_id
            )));
        }
        let args = ufw_temp_args(change, decision).map_err(invalid)?;
        self.run_ufw(&args)
            .await
            .map_err(|e| HelperError::new(HelperErrorKind::Backend, e))?;
        tracing::info!(temp_id = decision.temp_id, ?change, "temporary ufw rule");
        Ok(())
    }

    /// Deletes the hub's temporary `ufw` rules that have expired at
    /// `now_unix`, or were added before `boot_unix`. Returns how many.
    pub async fn sweep_ufw(&self, now_unix: u64, boot_unix: u64) -> usize {
        let mut stale = vec![];
        for (name, ipv6) in [("user.rules", false), ("user6.rules", true)] {
            let path = self.root.join("etc/ufw").join(name);
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            for rule in text
                .lines()
                .filter_map(|l| omarchy_security_proto::ufw::parse_tuple(l, ipv6))
            {
                let Some(decision) = omarchy_security_proto::ufw::temp_decision(&rule) else {
                    continue;
                };
                let expired = decision.expires_at <= now_unix.saturating_mul(1000);
                let old = decision.created_at < boot_unix.saturating_mul(1000);
                if (expired || old)
                    && !stale
                        .iter()
                        .any(|d: &TempDecision| d.temp_id == decision.temp_id)
                {
                    stale.push(decision);
                }
            }
        }
        let mut deleted = 0;
        for decision in &stale {
            match self.ufw_temp(UfwTempChange::Delete, decision).await {
                Ok(()) => deleted += 1,
                Err(err) => tracing::warn!(
                    temp_id = decision.temp_id,
                    "deleting an expired ufw rule: {err}"
                ),
            }
        }
        deleted
    }

    /// Sets the queue rule to what `wanted` says, keeping the rules.
    /// `wanted` runs under the lock, so concurrent callers each apply the
    /// state current at the time.
    pub async fn set_queue(
        &self,
        wanted: impl FnOnce() -> Option<QueueRule>,
    ) -> Result<(), HelperError> {
        let mut applied = self.applied.lock().await;
        let queue = wanted();
        if queue == applied.queue {
            return Ok(());
        }
        self.write(applied.mode, &applied.rules, queue, &applied.temps)
            .await?;
        applied.queue = queue;
        self.persist(&mut applied);
        Ok(())
    }

    /// Writes the boot copy for what `applied` holds, unless it is already
    /// on disk. A failure is kept for `inspect`: the table itself is loaded.
    fn persist(&self, applied: &mut Applied) {
        let Some(dir) = &self.state_dir else { return };
        let boot = match boot_script(applied.mode, &applied.rules) {
            Ok(boot) => boot,
            Err(err) => {
                applied.boot_error = Some(err);
                return;
            }
        };
        if applied.boot.as_ref() == Some(&boot) && applied.boot_error.is_none() {
            return;
        }
        match write_atomic(&dir.join(BOOT_COPY), boot.as_bytes()) {
            Ok(()) => {
                applied.boot = Some(boot);
                applied.boot_error = None;
            }
            Err(err) => {
                tracing::error!("writing the boot copy of the firewall: {err}");
                applied.boot = None;
                applied.boot_error = Some(err.to_string());
            }
        }
    }

    async fn nft_json(&self, args: &[&str]) -> Result<Value, HelperError> {
        let nft = self.nft.as_ref().ok_or_else(|| {
            HelperError::new(HelperErrorKind::Unavailable, "nft is not installed")
        })?;
        let wrapper: Vec<&str> = self.wrapper.iter().map(String::as_str).collect();
        nft_json(nft, &wrapper, args).await
    }

    async fn write(
        &self,
        mode: HubMode,
        rules: &[FirewallRule],
        queue: Option<QueueRule>,
        temps: &[TempDecision],
    ) -> Result<(), HelperError> {
        let script = render_with(mode, rules, queue, temps, now_ms())
            .map_err(|e| HelperError::new(HelperErrorKind::Invalid, e))?;
        let nft = self.nft.as_ref().ok_or_else(|| {
            HelperError::new(HelperErrorKind::Unavailable, "nft is not installed")
        })?;
        let wrapper: Vec<&str> = self.wrapper.iter().map(String::as_str).collect();
        run_nft(nft, &wrapper, &script).await
    }
}

impl Firewall {
    pub async fn inspect(&self) -> Result<FirewallInspection, HelperError> {
        let tables = self.nft_json(&["list", "tables"]).await?;
        let chains = self.nft_json(&["list", "chains"]).await?;
        let (table_loaded, table_mode) = our_table(&tables);
        let applied = self.applied.lock().await;
        Ok(FirewallInspection {
            ufw_chains_loaded: ufw_chains_loaded(&chains),
            table_loaded,
            table_mode,
            before_rules_modified: before_rules_modified(&self.root),
            hub_mode: applied.mode,
            boot_copy_error: applied.boot_error.clone(),
            temp: live(&applied.temps, now_ms()),
        })
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The decisions that have a second or more left.
fn live(decisions: &[TempDecision], now_ms: u64) -> Vec<TempDecision> {
    decisions
        .iter()
        .filter(|d| d.expires_at >= now_ms + 1000)
        .cloned()
        .collect()
}

/// When this boot started, from `btime` in `/proc/stat`.
pub fn boot_time() -> Option<u64> {
    std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("btime ")?.trim().parse().ok())
}

/// The `ufw` argv for a temporary decision, from typed values only:
/// `prepend allow in [proto P] from <addr> to any [port N] comment <tag>`,
/// or the same after `delete` to remove it. `prepend` works on an empty
/// list, unlike `insert 1`.
pub fn ufw_temp_args(
    change: UfwTempChange,
    decision: &TempDecision,
) -> Result<Vec<String>, String> {
    let spec = &decision.spec;
    check_temp_spec(spec)?;
    let (address, _) = nft_address(&spec.address)?;
    let mut args: Vec<String> = vec![
        match change {
            UfwTempChange::Add => "prepend",
            UfwTempChange::Delete => "delete",
        }
        .into(),
        match spec.verdict {
            Verdict::Allow => "allow",
            Verdict::Block => "deny",
        }
        .into(),
    ];
    let (direction, from, to) = match spec.direction {
        Direction::Inbound => ("in", address.as_str(), "any"),
        Direction::Outbound => ("out", "any", address.as_str()),
    };
    args.push(direction.into());
    if let Some(protocol) = spec.protocol {
        args.push("proto".into());
        args.push(
            match protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
            }
            .into(),
        );
    }
    args.extend(["from".into(), from.into(), "to".into(), to.into()]);
    if let Some(port) = spec.port {
        args.push("port".into());
        args.push(port.to_string());
    }
    args.push("comment".into());
    args.push(omarchy_security_proto::ufw::temp_tag(
        decision.temp_id,
        decision.created_at / 1000,
        decision.expires_at / 1000,
    ));
    Ok(args)
}

/// Replaces `path` with `bytes` (mode 0600): a temporary file, fsync,
/// rename, then fsync of the directory, so a crash leaves the old or the
/// new file and never a partial one.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or(Path::new("/"));
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(".tmp");
    let tmp = dir.join(name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)?;
    std::fs::File::open(dir)?.sync_all()
}

/// The objects of one kind (`"table"`, `"chain"`) in `nft -j` output.
fn objects<'a>(listing: &'a Value, kind: &'a str) -> impl Iterator<Item = &'a Value> {
    listing["nftables"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(move |o| o.get(kind))
}

/// Whether our table exists, and the mode in its `mode=<mode>` comment.
fn our_table(tables: &Value) -> (bool, Option<String>) {
    match objects(tables, "table").find(|t| t["family"] == "inet" && t["name"] == TABLE) {
        Some(table) => {
            let mode = table["comment"]
                .as_str()
                .and_then(|c| c.strip_prefix("mode="))
                .map(str::to_owned);
            (true, mode)
        }
        None => (false, None),
    }
}

/// A `nft -j list table` of our table rendered for `standalone`.
fn standalone_loaded(table: &Value) -> bool {
    let stamped =
        objects(table, "table").any(|t| t["name"] == TABLE && t["comment"] == "mode=standalone");
    let drops = objects(table, "chain")
        .any(|c| c["table"] == TABLE && c["hook"] == "input" && c["policy"] == "drop");
    stamped && drops
}

fn inbound_allow(rule: &FirewallRule) -> bool {
    rule.spec.executable.is_none()
        && rule.spec.direction == Direction::Inbound
        && rule.spec.verdict == Verdict::Allow
}

fn ufw_chains_loaded(chains: &Value) -> bool {
    objects(chains, "chain")
        .any(|c| c["family"] == "ip" && c["table"] == "filter" && c["name"] == "ufw-user-input")
}

/// Whether `before.rules` or `before6.rules` differ from what the package
/// shipped; `None` when no pair can be read.
fn before_rules_modified(root: &Path) -> Option<bool> {
    let mut compared = None;
    for name in ["before.rules", "before6.rules"] {
        let local = std::fs::read(root.join("etc/ufw").join(name));
        let packaged = std::fs::read(root.join("usr/share/ufw/iptables").join(name));
        if let (Ok(local), Ok(packaged)) = (local, packaged) {
            compared = Some(compared.unwrap_or(false) || local != packaged);
        }
    }
    compared
}

/// Runs `[wrapper...] nft -j <args>` and parses its output.
async fn nft_json(nft: &Path, wrapper: &[&str], args: &[&str]) -> Result<Value, HelperError> {
    let backend = |msg: String| HelperError::new(HelperErrorKind::Backend, msg);
    let output = command(nft, wrapper)
        .arg("-j")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| backend(format!("running nft: {e}")))?;
    if !output.status.success() {
        return Err(backend(format!(
            "nft {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|e| backend(format!("parsing nft {}: {e}", args.join(" "))))
}

/// `program` under `[wrapper...]`.
fn command(program: &Path, wrapper: &[&str]) -> tokio::process::Command {
    match wrapper.split_first() {
        Some((first, args)) => {
            let mut c = tokio::process::Command::new(first);
            c.args(args).arg(program);
            c
        }
        None => tokio::process::Command::new(program),
    }
}

/// Runs `[wrapper...] nft -f -` with `script` on stdin.
pub async fn run_nft(nft: &Path, wrapper: &[&str], script: &str) -> Result<(), HelperError> {
    let backend = |msg: String| HelperError::new(HelperErrorKind::Backend, msg);
    let mut child = command(nft, wrapper)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| backend(format!("starting nft: {e}")))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    stdin
        .write_all(script.as_bytes())
        .await
        .map_err(|e| backend(format!("writing to nft: {e}")))?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| backend(format!("waiting for nft: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(backend(format!(
            "nft failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omarchy_security_proto::types::FirewallRuleSpec;

    fn rule(
        id: u64,
        verdict: Verdict,
        direction: Direction,
        address: &str,
        port: Option<u16>,
        protocol: Option<Protocol>,
    ) -> FirewallRule {
        FirewallRule {
            rule_id: id,
            spec: FirewallRuleSpec {
                verdict,
                direction,
                address: address.into(),
                port,
                protocol,
                executable: None,
            },
            loaded: false,
        }
    }

    fn sample() -> Vec<FirewallRule> {
        vec![
            rule(
                1,
                Verdict::Block,
                Direction::Outbound,
                "0.0.0.0/0",
                Some(25),
                Some(Protocol::Tcp),
            ),
            rule(
                2,
                Verdict::Allow,
                Direction::Outbound,
                "192.0.2.10",
                Some(25),
                Some(Protocol::Tcp),
            ),
            rule(
                3,
                Verdict::Block,
                Direction::Inbound,
                "2001:db8::1/32",
                None,
                Some(Protocol::Udp),
            ),
            rule(
                4,
                Verdict::Block,
                Direction::Outbound,
                "10.1.2.3/8",
                Some(53),
                None,
            ),
            rule(
                5,
                Verdict::Allow,
                Direction::Inbound,
                "0.0.0.0/0",
                Some(53317),
                Some(Protocol::Tcp),
            ),
        ]
    }

    fn curl_rule() -> FirewallRule {
        let mut r = rule(
            9,
            Verdict::Block,
            Direction::Outbound,
            "1.1.1.1",
            None,
            None,
        );
        r.spec.executable = Some("/usr/bin/curl".into());
        r
    }

    const QUEUE: QueueRule = QueueRule {
        num: 7433,
        uid: 1000,
        loopback: false,
    };

    /// Compares `actual` with `testdata/<name>`; `UPDATE_GOLDEN=1`
    /// rewrites the file instead.
    fn golden(name: &str, actual: &str) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(name);
        if std::env::var_os("UPDATE_GOLDEN").is_some() {
            std::fs::write(&path, actual).unwrap();
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e} (UPDATE_GOLDEN=1 writes it)", path.display()));
        assert_eq!(actual, expected, "{} differs", path.display());
    }

    fn with_curl() -> Vec<FirewallRule> {
        let mut rules = sample();
        rules.push(curl_rule());
        rules
    }

    #[test]
    fn renders_the_standalone_policy() {
        // Baseline, allow before block, the Docker forward rules, the
        // log rule last in input; the executable rule is left to the queue.
        golden(
            "standalone.nft",
            &render(HubMode::Standalone, &with_curl(), Some(QUEUE)).unwrap(),
        );
    }

    #[test]
    fn ufw_mode_keeps_only_the_queue() {
        let delete_only = "table inet omarchy_sec\ndelete table inet omarchy_sec\n";
        assert_eq!(
            render(HubMode::Ufw, &with_curl(), None).unwrap(),
            delete_only
        );
        assert_eq!(render(HubMode::Ufw, &[], None).unwrap(), delete_only);
        golden(
            "ufw-queue.nft",
            &render(HubMode::Ufw, &with_curl(), Some(QUEUE)).unwrap(),
        );
        let loopback = render(
            HubMode::Ufw,
            &[],
            Some(QueueRule {
                loopback: true,
                ..QUEUE
            }),
        )
        .unwrap();
        assert!(!loopback.contains("oif"), "{loopback}");
        assert!(loopback.contains("queue num 7433 bypass"), "{loopback}");
    }

    #[test]
    fn the_boot_copy_never_queues() {
        let boot = boot_script(HubMode::Standalone, &with_curl()).unwrap();
        golden("standalone-boot.nft", &boot);
        assert!(!boot.contains("queue"), "{boot}");
        assert!(boot.ends_with(&render(HubMode::Standalone, &sample(), None).unwrap()));
        // In ufw mode the boot copy only removes the table.
        let boot = boot_script(HubMode::Ufw, &with_curl()).unwrap();
        assert!(
            boot.ends_with("\ntable inet omarchy_sec\ndelete table inet omarchy_sec\n"),
            "{boot}"
        );
    }

    #[test]
    fn a_bad_rule_fails_the_render() {
        let bad = rule(7, Verdict::Allow, Direction::Inbound, "nope", None, None);
        // Also in ufw mode, where it would not be rendered.
        for mode in [HubMode::Standalone, HubMode::Ufw] {
            let err = render(mode, std::slice::from_ref(&bad), None).unwrap_err();
            assert!(err.starts_with("rule 7:"), "{err}");
        }
    }

    fn namespaces() -> Option<PathBuf> {
        let Some(nft) = find_nft() else {
            eprintln!("nft not installed; skipping");
            return None;
        };
        let probe = std::process::Command::new("unshare")
            .args(["-rn", "true"])
            .status();
        if !probe.is_ok_and(|s| s.success()) {
            eprintln!("unprivileged user namespaces unavailable; skipping");
            return None;
        }
        Some(nft)
    }

    /// Applies the rendered scripts for real inside an unprivileged user
    /// and network namespace (`unshare -rn`), where nft has CAP_NET_ADMIN.
    #[tokio::test]
    async fn nft_accepts_the_rendered_ruleset() {
        let Some(nft) = namespaces() else { return };
        // Apply, replace, switch mode, list, and remove, in one namespace.
        let full = render(HubMode::Standalone, &sample(), Some(QUEUE)).unwrap();
        let smaller = render(HubMode::Standalone, &sample()[..1], None).unwrap();
        let queue_only = render(HubMode::Ufw, &sample(), Some(QUEUE)).unwrap();
        let empty = render(HubMode::Ufw, &[], None).unwrap();
        let script = format!(
            "set -e\n\
             printf '%s' \"$FULL\" | {nft} -f -\n\
             printf '%s' \"$SMALLER\" | {nft} -f -\n\
             {nft} list table inet omarchy_sec\n\
             printf '%s' \"$QUEUE_ONLY\" | {nft} -f -\n\
             echo ---\n\
             {nft} list table inet omarchy_sec\n\
             printf '%s' \"$EMPTY\" | {nft} -f -\n\
             ! {nft} list table inet omarchy_sec 2>/dev/null\n",
            nft = nft.display()
        );
        let output = std::process::Command::new("unshare")
            .args(["-rn", "sh", "-c", &script])
            .env("FULL", &full)
            .env("SMALLER", &smaller)
            .env("QUEUE_ONLY", &queue_only)
            .env("EMPTY", &empty)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "stdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let (standalone, ufw) = stdout.split_once("---").unwrap();
        assert!(
            standalone.contains("omarchy:1")
                && !standalone.contains("omarchy:2")
                && standalone.contains("policy drop")
                && standalone.contains("omarchy:docker")
                && standalone.contains("mode=standalone"),
            "{standalone}"
        );
        assert!(!standalone.contains("omarchy:queue"), "{standalone}");
        assert!(
            ufw.contains("mode=ufw")
                && ufw.contains("omarchy:queue")
                && !ufw.contains("omarchy:1")
                && !ufw.contains("policy drop"),
            "{ufw}"
        );

        // run_nft reports nft's own error text.
        let err = run_nft(
            &nft,
            &["unshare", "-rn"],
            "table inet omarchy_sec { chain c { bogus } }\n",
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind, HelperErrorKind::Backend);
        assert!(err.message.contains("syntax error"), "{}", err.message);
        run_nft(&nft, &["unshare", "-rn"], &full).await.unwrap();
    }

    /// The standalone table really drops what it does not list: a peer
    /// namespace connects over a veth pair (`testdata/standalone-netns.sh`).
    #[test]
    fn enforces_the_standalone_policy() {
        let Some(nft) = namespaces() else { return };
        if !["python3", "nsenter", "ip"].iter().all(|tool| {
            std::process::Command::new("sh")
                .args(["-c", &format!("command -v {tool}")])
                .stdout(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        }) {
            eprintln!("needs python3, nsenter and ip; skipping");
            return;
        }
        let rules = [rule(
            1,
            Verdict::Allow,
            Direction::Inbound,
            "0.0.0.0/0",
            Some(53317),
            Some(Protocol::Tcp),
        )];
        let script = render(HubMode::Standalone, &rules, None).unwrap();
        let output = std::process::Command::new("unshare")
            .arg("-rn")
            .arg("sh")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/standalone-netns.sh"))
            .env("SCRIPT", &script)
            .env("NFT", &nft)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "stdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for expected in [
            "listed=accepted",
            "unlisted=dropped",
            "loopback=accepted",
            "policy=drop",
        ] {
            assert!(
                stdout.lines().any(|l| l == expected),
                "{expected}: {stdout}"
            );
        }
    }

    /// The mode file, the rules kept for a restart, and the boot copy.
    #[tokio::test]
    async fn persists_the_mode_rules_and_boot_copy() {
        use std::os::unix::fs::PermissionsExt;
        let Some(_) = namespaces() else { return };
        let dir = tempfile::tempdir().unwrap();
        let boot = dir.path().join(BOOT_COPY);
        let fresh = Firewall::with_wrapper(&["unshare", "-rn"]).with_state_dir(dir.path());
        assert_eq!(fresh.applied.lock().await.mode, HubMode::Ufw);
        fresh.restore().await.unwrap();
        assert!(!boot.exists(), "nothing to restore in ufw mode");

        std::fs::write(dir.path().join(MODE_FILE), "standalone\n").unwrap();
        let firewall = Firewall::with_wrapper(&["unshare", "-rn"]).with_state_dir(dir.path());
        firewall.apply(&with_curl()).await.unwrap();
        let written = std::fs::read_to_string(&boot).unwrap();
        assert_eq!(
            written,
            boot_script(HubMode::Standalone, &with_curl()).unwrap()
        );
        assert_eq!(
            std::fs::metadata(&boot).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // The queue rule changes the table, not the boot copy.
        std::fs::remove_file(&boot).unwrap();
        firewall.set_queue(|| Some(QUEUE)).await.unwrap();
        assert!(!boot.exists(), "an unchanged boot copy is not rewritten");

        // A restarted helper renders the same table.
        let restarted = Firewall::with_wrapper(&["unshare", "-rn"]).with_state_dir(dir.path());
        assert_eq!(restarted.applied.lock().await.rules, with_curl());
        restarted.restore().await.unwrap();
        assert_eq!(std::fs::read_to_string(&boot).unwrap(), written);
        assert_eq!(
            restarted.inspect().await.unwrap().hub_mode,
            HubMode::Standalone
        );

        std::fs::write(dir.path().join(MODE_FILE), "bogus").unwrap();
        let unknown = Firewall::with_wrapper(&[]).with_state_dir(dir.path());
        assert_eq!(unknown.applied.lock().await.mode, HubMode::Ufw);
    }

    /// A network namespace that outlives one command, so that `ufw`'s
    /// chains and our table stay between calls: `unshare -rn` holds it,
    /// and `nsenter` runs each command inside.
    struct Netns {
        holder: std::process::Child,
        wrapper: Vec<String>,
    }

    impl Netns {
        fn start() -> Self {
            let holder = std::process::Command::new("unshare")
                .args(["-rn", "sleep", "600"])
                .spawn()
                .unwrap();
            let pid = holder.id();
            let ours = std::fs::read_link("/proc/self/ns/net").unwrap();
            for _ in 0..500 {
                if std::fs::read_link(format!("/proc/{pid}/ns/net")).is_ok_and(|ns| ns != ours) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            let wrapper = [
                "nsenter",
                "-t",
                &pid.to_string(),
                "-U",
                "-n",
                "--preserve-credentials",
            ]
            .map(String::from)
            .to_vec();
            Self { holder, wrapper }
        }

        fn wrapper(&self) -> Vec<&str> {
            self.wrapper.iter().map(String::as_str).collect()
        }

        fn nft(&self, nft: &Path, args: &[&str]) -> String {
            let output = std::process::Command::new(&self.wrapper[0])
                .args(&self.wrapper[1..])
                .arg(nft)
                .args(args)
                .output()
                .unwrap();
            String::from_utf8_lossy(&output.stdout).into_owned()
        }
    }

    impl Drop for Netns {
        fn drop(&mut self) {
            let _ = self.holder.kill();
            let _ = self.holder.wait();
        }
    }

    /// A stand-in for `/usr/bin/ufw` that loads or removes `ufw`-like
    /// chains and logs each call with the mode stamped into our table at
    /// that moment. A `fail` file makes it fail; a `noop` file makes it
    /// succeed without changing anything.
    struct FakeUfw {
        dir: tempfile::TempDir,
    }

    impl FakeUfw {
        fn new(nft: &Path) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let d = dir.path().display();
            let nft = nft.display();
            let script = format!(
                "#!/bin/sh\n\
                 table=$({nft} list table inet omarchy_sec 2>/dev/null | grep -o 'mode=[a-z]*' || echo none)\n\
                 echo \"$* table=$table env=$(env | grep -cv '^PATH=\\|^LC_ALL=\\|^PWD=\\|^SHLVL=\\|^_=')\" >> {d}/log\n\
                 if [ -e {d}/fail ]; then echo 'ERROR: simulated failure' >&2; exit 1; fi\n\
                 [ -e {d}/noop ] && exit 0\n\
                 case \"$*\" in\n\
                 disable) {nft} delete table ip filter ;;\n\
                 '--force enable') echo 'table ip filter {{ chain ufw-user-input {{ }}; }}' | {nft} -f - ;;\n\
                 *) exit 2 ;;\n\
                 esac\n"
            );
            let path = dir.path().join("ufw");
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            Self { dir }
        }

        fn path(&self) -> PathBuf {
            self.dir.path().join("ufw")
        }

        fn calls(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.path().join("log"))
                .unwrap_or_default()
                .lines()
                .map(String::from)
                .collect()
        }

        fn set(&self, name: &str, on: bool) {
            let path = self.dir.path().join(name);
            if on {
                std::fs::write(path, "").unwrap();
            } else {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    /// A namespace with `ufw` on, a state directory, and a helper firewall
    /// over them.
    fn switchable() -> Option<(Netns, FakeUfw, tempfile::TempDir, Firewall, PathBuf)> {
        let nft = namespaces()?;
        if !std::process::Command::new("nsenter")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
        {
            eprintln!("nsenter not installed; skipping");
            return None;
        }
        let netns = Netns::start();
        let ufw = FakeUfw::new(&nft);
        let enable = std::process::Command::new(&netns.wrapper[0])
            .args(&netns.wrapper[1..])
            .arg(ufw.path())
            .args(["--force", "enable"])
            .status()
            .unwrap();
        assert!(enable.success());
        std::fs::remove_file(ufw.dir.path().join("log")).unwrap();
        let state = tempfile::tempdir().unwrap();
        let firewall = Firewall::with_wrapper(&netns.wrapper())
            .with_ufw(&ufw.path())
            .with_state_dir(state.path());
        Some((netns, ufw, state, firewall, nft))
    }

    fn mode_file(dir: &Path) -> Option<String> {
        std::fs::read_to_string(dir.join(MODE_FILE)).ok()
    }

    #[tokio::test]
    async fn switches_modes_without_a_gap() {
        let Some((netns, ufw, state, firewall, nft)) = switchable() else {
            return;
        };
        let inspection = firewall.inspect().await.unwrap();
        assert!(inspection.ufw_chains_loaded && !inspection.table_loaded);

        // ufw is disabled only once our table is loaded, with nothing
        // from the helper's environment.
        firewall
            .set_mode(HubMode::Standalone, &sample())
            .await
            .unwrap();
        assert_eq!(ufw.calls(), ["disable table=mode=standalone env=0"]);
        let inspection = firewall.inspect().await.unwrap();
        assert!(!inspection.ufw_chains_loaded, "{inspection:?}");
        assert_eq!(inspection.table_mode.as_deref(), Some("standalone"));
        assert_eq!(inspection.hub_mode, HubMode::Standalone);
        assert_eq!(mode_file(state.path()).as_deref(), Some("standalone\n"));
        assert_eq!(
            std::fs::read_to_string(state.path().join(BOOT_COPY)).unwrap(),
            boot_script(HubMode::Standalone, &sample()).unwrap()
        );
        assert!(
            netns
                .nft(&nft, &["list", "table", "inet", TABLE])
                .contains("omarchy:5")
        );

        // Back: ufw is enabled while our table still holds the policy.
        firewall.set_mode(HubMode::Ufw, &sample()).await.unwrap();
        assert_eq!(
            ufw.calls()[1..],
            ["--force enable table=mode=standalone env=0"]
        );
        let inspection = firewall.inspect().await.unwrap();
        assert!(inspection.ufw_chains_loaded && !inspection.table_loaded);
        assert_eq!(inspection.hub_mode, HubMode::Ufw);
        assert_eq!(mode_file(state.path()).as_deref(), Some("ufw\n"));
        assert_eq!(
            std::fs::read_to_string(state.path().join(BOOT_COPY)).unwrap(),
            boot_script(HubMode::Ufw, &sample()).unwrap()
        );

        // A restarted helper keeps the chosen mode.
        let restarted = Firewall::with_wrapper(&netns.wrapper()).with_state_dir(state.path());
        assert_eq!(restarted.applied.lock().await.mode, HubMode::Ufw);
    }

    #[tokio::test]
    async fn a_failed_ufw_disable_leaves_both_enforcing() {
        let Some((_netns, ufw, state, firewall, _)) = switchable() else {
            return;
        };
        ufw.set("fail", true);
        let err = firewall
            .set_mode(HubMode::Standalone, &sample())
            .await
            .unwrap_err();
        assert_eq!(err.kind, HelperErrorKind::Backend);
        assert!(
            err.message.contains("simulated failure") && err.message.contains("both"),
            "{}",
            err.message
        );
        // Our table is not rolled back.
        let inspection = firewall.inspect().await.unwrap();
        assert!(inspection.ufw_chains_loaded);
        assert_eq!(inspection.table_mode.as_deref(), Some("standalone"));
        assert_eq!(mode_file(state.path()).as_deref(), Some("standalone\n"));

        // ufw reports success but keeps its chains.
        ufw.set("fail", false);
        ufw.set("noop", true);
        let err = firewall
            .set_mode(HubMode::Standalone, &sample())
            .await
            .unwrap_err();
        assert!(err.message.contains("still loaded"), "{}", err.message);
        let inspection = firewall.inspect().await.unwrap();
        assert!(inspection.ufw_chains_loaded);
        assert_eq!(inspection.table_mode.as_deref(), Some("standalone"));

        // Retried once ufw works: the same call finishes the switch.
        ufw.set("noop", false);
        firewall
            .set_mode(HubMode::Standalone, &sample())
            .await
            .unwrap();
        assert!(!firewall.inspect().await.unwrap().ufw_chains_loaded);
        assert_eq!(ufw.calls().len(), 3);
    }

    #[tokio::test]
    async fn ufw_is_not_touched_before_the_table_is_safe() {
        let Some((_netns, ufw, state, firewall, _)) = switchable() else {
            return;
        };
        // A rule nft cannot render.
        let bad = rule(7, Verdict::Allow, Direction::Inbound, "nope", None, None);
        let err = firewall
            .set_mode(HubMode::Standalone, &[bad])
            .await
            .unwrap_err();
        assert_eq!(err.kind, HelperErrorKind::Invalid);
        // The boot copy cannot be written.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let err = firewall
            .set_mode(HubMode::Standalone, &sample())
            .await
            .unwrap_err();
        std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            err.message.contains("boot copy") && err.message.contains("ufw was left on"),
            "{}",
            err.message
        );
        assert!(ufw.calls().is_empty(), "{:?}", ufw.calls());
        assert!(firewall.inspect().await.unwrap().ufw_chains_loaded);
        assert_eq!(mode_file(state.path()), None);
    }

    #[tokio::test]
    async fn a_failed_ufw_enable_keeps_the_hub_firewall() {
        let Some((_netns, ufw, state, firewall, _)) = switchable() else {
            return;
        };
        firewall
            .set_mode(HubMode::Standalone, &sample())
            .await
            .unwrap();
        for control in ["fail", "noop"] {
            ufw.set(control, true);
            let err = firewall
                .set_mode(HubMode::Ufw, &sample())
                .await
                .unwrap_err();
            ufw.set(control, false);
            assert!(
                err.message.contains("the hub firewall stays active"),
                "{control}: {}",
                err.message
            );
            let inspection = firewall.inspect().await.unwrap();
            assert!(!inspection.ufw_chains_loaded, "{control}");
            assert_eq!(inspection.table_mode.as_deref(), Some("standalone"));
            assert_eq!(inspection.hub_mode, HubMode::Standalone);
            assert_eq!(mode_file(state.path()).as_deref(), Some("standalone\n"));
        }
        // A bad rule fails before ufw is enabled.
        let bad = rule(7, Verdict::Allow, Direction::Inbound, "nope", None, None);
        let calls = ufw.calls().len();
        let err = firewall.set_mode(HubMode::Ufw, &[bad]).await.unwrap_err();
        assert_eq!(err.kind, HelperErrorKind::Invalid);
        assert_eq!(ufw.calls().len(), calls);
    }

    #[tokio::test]
    async fn only_a_new_inbound_allow_in_standalone_opens_inbound() {
        let dir = tempfile::tempdir().unwrap();
        let inbound = sample()[4].clone();
        let ufw_mode = Firewall::with_wrapper(&[]).with_state_dir(dir.path());
        assert!(
            !ufw_mode.opens_inbound(&sample()).await,
            "not rendered in ufw mode"
        );

        std::fs::write(dir.path().join(MODE_FILE), "standalone\n").unwrap();
        let standalone = Firewall::with_wrapper(&[]).with_state_dir(dir.path());
        assert!(standalone.opens_inbound(&sample()).await);
        assert!(
            !standalone.opens_inbound(&sample()[..4]).await,
            "no inbound allow"
        );
        std::fs::write(
            dir.path().join(RULES_FILE),
            serde_json::to_vec(std::slice::from_ref(&inbound)).unwrap(),
        )
        .unwrap();
        let restarted = Firewall::with_wrapper(&[]).with_state_dir(dir.path());
        assert!(!restarted.opens_inbound(&sample()).await, "already loaded");
    }

    fn temp(
        temp_id: u64,
        verdict: Verdict,
        direction: Direction,
        address: &str,
        port: Option<u16>,
        protocol: Option<Protocol>,
        backend: TempBackend,
    ) -> TempDecision {
        TempDecision {
            temp_id,
            spec: FirewallRuleSpec {
                verdict,
                direction,
                address: address.into(),
                port,
                protocol,
                executable: None,
            },
            backend,
            created_at: 1_000_000,
            expires_at: 1_000_000 + 3_600_000,
            alert_id: None,
        }
    }

    fn temps() -> Vec<TempDecision> {
        use TempBackend::Table;
        vec![
            temp(
                3,
                Verdict::Allow,
                Direction::Inbound,
                "203.0.113.7",
                Some(22),
                Some(Protocol::Tcp),
                Table,
            ),
            temp(
                4,
                Verdict::Block,
                Direction::Inbound,
                "198.51.100.0/24",
                None,
                None,
                Table,
            ),
            temp(
                5,
                Verdict::Block,
                Direction::Outbound,
                "2001:db8::/32",
                None,
                Some(Protocol::Udp),
                Table,
            ),
            temp(
                6,
                Verdict::Allow,
                Direction::Outbound,
                "192.0.2.1",
                Some(443),
                Some(Protocol::Tcp),
                Table,
            ),
        ]
    }

    #[test]
    fn renders_temporary_decisions() {
        // One set per decision at the top of its chain, blocks first, with
        // the time left; a decision with under a second left is dropped.
        let now = 1_000_000 + 58_000;
        let mut all = temps();
        all.push(TempDecision {
            expires_at: now + 500,
            ..temp(
                7,
                Verdict::Block,
                Direction::Inbound,
                "192.0.2.9",
                None,
                None,
                TempBackend::Table,
            )
        });
        let standalone = render_with(HubMode::Standalone, &sample(), None, &all, now).unwrap();
        golden("standalone-temp.nft", &standalone);
        assert!(standalone.contains("timeout 3542s"), "{standalone}");
        assert!(!standalone.contains("tmp_7"), "{standalone}");
        // In ufw mode they alone keep the table.
        let ufw = render_with(HubMode::Ufw, &sample(), None, &temps(), now).unwrap();
        golden("ufw-temp.nft", &ufw);
        assert!(!ufw.contains("omarchy:5\""), "saved rules stay out: {ufw}");
        let expired = render_with(HubMode::Ufw, &[], None, &temps(), now + 3_600_000).unwrap();
        assert_eq!(expired, render(HubMode::Ufw, &[], None).unwrap());
        // The boot copy never holds them.
        assert!(
            !boot_script(HubMode::Standalone, &sample())
                .unwrap()
                .contains("tmp_")
        );

        let mut bad = temps();
        bad[0].backend = TempBackend::Ufw;
        assert!(render_with(HubMode::Ufw, &[], None, &bad, now).is_err());
        bad = temps();
        bad[1].spec.executable = Some("/usr/bin/curl".into());
        assert!(render_with(HubMode::Ufw, &[], None, &bad, now).is_err());
    }

    /// A set element blocks, then the kernel removes it on its own: a
    /// local TCP connection is dropped while a 2 s block lasts, and
    /// accepted after it.
    #[test]
    fn temporary_decisions_expire_in_the_kernel() {
        let Some(nft) = namespaces() else { return };
        if std::process::Command::new("python3")
            .arg("-V")
            .output()
            .is_err()
        {
            eprintln!("python3 not installed; skipping");
            return;
        }
        let now = now_ms();
        let block = TempDecision {
            created_at: now,
            expires_at: now + 2_000,
            ..temp(
                1,
                Verdict::Block,
                Direction::Outbound,
                "127.0.0.1",
                Some(53999),
                Some(Protocol::Tcp),
                TempBackend::Table,
            )
        };
        let script = render_with(HubMode::Ufw, &[], None, &[block], now).unwrap();
        let shell = format!(
            "set -e\n\
             ip link set lo up\n\
             printf '%s' \"$SCRIPT\" | {nft} -f -\n\
             probe() {{ python3 -c 'import socket,sys\n\
             l=socket.socket(); l.bind((\"127.0.0.1\",53999)); l.listen()\n\
             c=socket.socket(); c.settimeout(0.5)\n\
             try: c.connect((\"127.0.0.1\",53999)); print(\"accepted\")\n\
             except OSError: print(\"dropped\")'; }}\n\
             echo \"during=$(probe)\"\n\
             sleep 2.5\n\
             echo \"after=$(probe)\"\n\
             {nft} list set inet omarchy_sec tmp_1\n",
            nft = nft.display()
        );
        let output = std::process::Command::new("unshare")
            .args(["-rn", "sh", "-c", &shell])
            .env("SCRIPT", &script)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "stdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("during=dropped"), "{stdout}");
        assert!(stdout.contains("after=accepted"), "{stdout}");
        assert!(
            !stdout.contains("elements"),
            "the element is gone: {stdout}"
        );
    }

    #[tokio::test]
    async fn nft_accepts_temporary_sets() {
        let Some(nft) = namespaces() else { return };
        let now = now_ms();
        let live: Vec<TempDecision> = temps()
            .into_iter()
            .map(|d| TempDecision {
                created_at: now,
                expires_at: now + 60_000,
                ..d
            })
            .collect();
        for mode in [HubMode::Standalone, HubMode::Ufw] {
            let script = render_with(mode, &sample(), Some(QUEUE), &live, now).unwrap();
            run_nft(&nft, &["unshare", "-rn"], &script)
                .await
                .unwrap_or_else(|e| panic!("{mode:?}: {e}\n{script}"));
        }
    }

    #[tokio::test]
    async fn temporary_decisions_survive_other_changes() {
        let Some(_) = namespaces() else { return };
        let dir = tempfile::tempdir().unwrap();
        let firewall = Firewall::with_wrapper(&["unshare", "-rn"]).with_state_dir(dir.path());
        let now = now_ms();
        let live: Vec<TempDecision> = temps()
            .into_iter()
            .map(|d| TempDecision {
                created_at: now,
                expires_at: now + 60_000,
                ..d
            })
            .collect();
        assert!(firewall.temp_opens_inbound(&live).await);
        firewall.set_temp(&live).await.unwrap();
        assert!(!firewall.temp_opens_inbound(&live).await, "already loaded");
        firewall.apply(&sample()).await.unwrap();
        assert_eq!(firewall.applied.lock().await.temps, live);
        // Never persisted.
        let boot = std::fs::read_to_string(dir.path().join(BOOT_COPY)).unwrap();
        assert!(!boot.contains("tmp_"), "{boot}");
        assert!(
            !std::fs::read_to_string(dir.path().join(RULES_FILE))
                .unwrap()
                .contains("temp")
        );
        // Expired ones are dropped; the rest are reported for a new daemon.
        let mut mixed = live.clone();
        mixed[0].expires_at = now;
        firewall.set_temp(&mixed).await.unwrap();
        assert_eq!(firewall.applied.lock().await.temps, live[1..]);
        let err = firewall
            .set_temp(&[TempDecision {
                backend: TempBackend::Ufw,
                ..live[0].clone()
            }])
            .await
            .unwrap_err();
        assert_eq!(err.kind, HelperErrorKind::Invalid);
    }

    #[test]
    fn builds_ufw_argv_from_typed_values() {
        let d = temp(
            42,
            Verdict::Allow,
            Direction::Inbound,
            "203.0.113.7",
            Some(22),
            Some(Protocol::Tcp),
            TempBackend::Ufw,
        );
        let tag = "omarchy-security:tmp:42:1000:4600";
        assert_eq!(
            ufw_temp_args(UfwTempChange::Add, &d).unwrap(),
            [
                "prepend",
                "allow",
                "in",
                "proto",
                "tcp",
                "from",
                "203.0.113.7",
                "to",
                "any",
                "port",
                "22",
                "comment",
                tag
            ]
        );
        assert_eq!(
            ufw_temp_args(UfwTempChange::Delete, &d).unwrap()[..3],
            ["delete", "allow", "in"]
        );
        let out = temp(
            43,
            Verdict::Allow,
            Direction::Outbound,
            "2001:db8::1:2/64",
            None,
            None,
            TempBackend::Ufw,
        );
        assert_eq!(
            ufw_temp_args(UfwTempChange::Add, &out).unwrap(),
            [
                "prepend",
                "allow",
                "out",
                "from",
                "any",
                "to",
                "2001:db8::/64",
                "comment",
                "omarchy-security:tmp:43:1000:4600"
            ]
        );
        for (address, port, protocol) in [
            ("203.0.113.7/33", Some(22), Some(Protocol::Tcp)),
            ("any; rm -rf /", Some(22), Some(Protocol::Tcp)),
            ("203.0.113.7", Some(0), Some(Protocol::Tcp)),
            ("203.0.113.7", Some(22), None),
        ] {
            let bad = temp(
                1,
                Verdict::Allow,
                Direction::Inbound,
                address,
                port,
                protocol,
                TempBackend::Ufw,
            );
            assert!(
                ufw_temp_args(UfwTempChange::Add, &bad).is_err(),
                "{address} {port:?}"
            );
        }
    }

    /// A stand-in `ufw` that only records its argv.
    fn recording_ufw(dir: &Path) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("ufw");
        std::fs::write(
            &path,
            format!("#!/bin/sh\necho \"$*\" >> {}/log\n", dir.display()),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[tokio::test]
    async fn ufw_temp_rules_are_added_and_swept() {
        let dir = tempfile::tempdir().unwrap();
        let ufw = recording_ufw(dir.path());
        let root = dir.path().join("root");
        std::fs::create_dir_all(root.join("etc/ufw")).unwrap();
        let hex = |t: &str| t.bytes().map(|b| format!("{b:02x}")).collect::<String>();
        let tagged = |id, created, expires| {
            format!(
                "### tuple ### allow tcp 22 0.0.0.0/0 any 203.0.113.{id} in comment={}\n",
                hex(&omarchy_security_proto::ufw::temp_tag(id, created, expires))
            )
        };
        // boot at 1000, now 5000: 1 expired, 2 live, 3 from an earlier
        // boot, and a rule the hub did not add.
        std::fs::write(
            root.join("etc/ufw/user.rules"),
            tagged(1, 2000, 4000)
                + &tagged(2, 2000, 9000)
                + &tagged(3, 500, 9000)
                + "### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in comment=6869\n",
        )
        .unwrap();
        let firewall = Firewall::with_wrapper(&[]).with_ufw(&ufw).with_root(&root);
        assert_eq!(firewall.sweep_ufw(5000, 1000).await, 2);
        let log = std::fs::read_to_string(dir.path().join("log")).unwrap();
        assert_eq!(
            log.lines().collect::<Vec<_>>(),
            [
                "delete allow in proto tcp from 203.0.113.1 to any port 22 comment omarchy-security:tmp:1:2000:4000",
                "delete allow in proto tcp from 203.0.113.3 to any port 22 comment omarchy-security:tmp:3:500:9000",
            ]
        );

        let d = TempDecision {
            expires_at: now_ms() + 60_000,
            ..temp(
                9,
                Verdict::Allow,
                Direction::Inbound,
                "192.0.2.1",
                Some(53317),
                Some(Protocol::Udp),
                TempBackend::Ufw,
            )
        };
        firewall.ufw_temp(UfwTempChange::Add, &d).await.unwrap();
        let log = std::fs::read_to_string(dir.path().join("log")).unwrap();
        assert!(
            log.lines()
                .last()
                .unwrap()
                .starts_with("prepend allow in proto udp from 192.0.2.1"),
            "{log}"
        );
        let expired = TempDecision {
            expires_at: 1,
            ..d.clone()
        };
        assert_eq!(
            firewall
                .ufw_temp(UfwTempChange::Add, &expired)
                .await
                .unwrap_err()
                .kind,
            HelperErrorKind::Invalid
        );
        let table = TempDecision {
            backend: TempBackend::Table,
            ..d
        };
        assert_eq!(
            firewall
                .ufw_temp(UfwTempChange::Add, &table)
                .await
                .unwrap_err()
                .kind,
            HelperErrorKind::Invalid
        );
    }

    #[test]
    fn checks_the_loaded_standalone_table() {
        let listing = |comment: &str, policy: &str| {
            serde_json::json!({"nftables": [
                {"table": {"family": "inet", "name": "omarchy_sec", "comment": comment}},
                {"chain": {"family": "inet", "table": "omarchy_sec", "name": "input",
                           "type": "filter", "hook": "input", "prio": 0, "policy": policy}},
            ]})
        };
        assert!(standalone_loaded(&listing("mode=standalone", "drop")));
        assert!(!standalone_loaded(&listing("mode=standalone", "accept")));
        assert!(!standalone_loaded(&listing("mode=ufw", "drop")));
        assert!(!standalone_loaded(&serde_json::json!({"nftables": []})));
    }

    #[test]
    fn reads_the_table_mode_and_ufw_chains() {
        let tables = serde_json::json!({"nftables": [
            {"metainfo": {"version": "1.1.7"}},
            {"table": {"family": "ip", "name": "filter", "handle": 2}},
            {"table": {"family": "inet", "name": "omarchy_sec", "handle": 1, "comment": "mode=standalone"}},
        ]});
        assert_eq!(our_table(&tables), (true, Some("standalone".into())));
        let plain =
            serde_json::json!({"nftables": [{"table": {"family": "inet", "name": "omarchy_sec"}}]});
        assert_eq!(our_table(&plain), (true, None));
        assert_eq!(
            our_table(&serde_json::json!({"nftables": []})),
            (false, None)
        );

        let chains = |family: &str, name: &str| serde_json::json!({"nftables": [{"chain": {"family": family, "table": "filter", "name": name}}]});
        assert!(ufw_chains_loaded(&chains("ip", "ufw-user-input")));
        assert!(!ufw_chains_loaded(&chains("ip6", "ufw-user-input")));
        assert!(!ufw_chains_loaded(&chains("ip", "INPUT")));
    }

    #[test]
    fn compares_before_rules_with_the_packaged_copies() {
        let root = tempfile::tempdir().unwrap();
        let (etc, share) = (
            root.path().join("etc/ufw"),
            root.path().join("usr/share/ufw/iptables"),
        );
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::create_dir_all(&share).unwrap();
        assert_eq!(before_rules_modified(root.path()), None);
        std::fs::write(etc.join("before.rules"), "stock").unwrap();
        std::fs::write(share.join("before.rules"), "stock").unwrap();
        assert_eq!(before_rules_modified(root.path()), Some(false));
        std::fs::write(etc.join("before6.rules"), "local").unwrap();
        std::fs::write(share.join("before6.rules"), "stock").unwrap();
        assert_eq!(before_rules_modified(root.path()), Some(true));
    }

    /// Inspects a namespace that holds `ufw`-like chains and a stamped
    /// table: the wrapper loads them before running nft.
    #[tokio::test]
    async fn inspects_a_live_ruleset() {
        let Some(nft) = namespaces() else { return };
        let empty =
            Firewall::with_wrapper(&["unshare", "-rn"]).with_root(Path::new("/nonexistent"));
        assert_eq!(
            empty.inspect().await.unwrap(),
            FirewallInspection {
                ufw_chains_loaded: false,
                table_loaded: false,
                table_mode: None,
                before_rules_modified: None,
                hub_mode: HubMode::Ufw,
                boot_copy_error: None,
                temp: vec![],
            }
        );
        let setup = format!(
            "printf 'table ip filter {{\\n chain ufw-user-input {{\\n }}\\n}}\\n\
             table inet omarchy_sec {{\\n comment \"mode=standalone\"\\n}}\\n' \
             | {} -f - && exec \"$0\" \"$@\"",
            nft.display()
        );
        let loaded = Firewall::with_wrapper(&["unshare", "-rn", "sh", "-c", &setup])
            .with_root(Path::new("/nonexistent"));
        let inspection = loaded.inspect().await.unwrap();
        assert!(inspection.ufw_chains_loaded, "{inspection:?}");
        assert!(inspection.table_loaded, "{inspection:?}");
        assert_eq!(inspection.table_mode.as_deref(), Some("standalone"));
    }
}
