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
//! Rules with an `executable` are not rendered: nftables cannot match a
//! process by path. While connections are intercepted
//! (`connections.rs`), the output chain ends with a rule that sends the
//! desktop user's new TCP and UDP connections to the NFQUEUE instead, where
//! the helper matches them. Loopback traffic is not queued.

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::Stdio;

use omarchy_security_proto::helper::{HelperError, HelperErrorKind};
use omarchy_security_proto::types::{Direction, FirewallRule, Protocol, Verdict, parse_prefix};
use tokio::io::AsyncWriteExt;

pub const TABLE: &str = "omarchy_sec";

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

/// The complete `nft -f` script for `rules` and `queue`. With neither the
/// table is simply removed.
pub fn render(rules: &[FirewallRule], queue: Option<QueueRule>) -> Result<String, String> {
    let mut script = format!("table inet {TABLE}\ndelete table inet {TABLE}\n");
    let mut ordered: Vec<&FirewallRule> = rules
        .iter()
        .filter(|r| r.spec.executable.is_none())
        .collect();
    if ordered.is_empty() && queue.is_none() {
        return Ok(script);
    }
    ordered.sort_by_key(|r| (r.spec.verdict == Verdict::Block, r.rule_id));
    writeln!(script, "table inet {TABLE} {{").unwrap();
    for (chain, direction) in [
        ("input", Direction::Inbound),
        ("output", Direction::Outbound),
    ] {
        writeln!(script, "\tchain {chain} {{").unwrap();
        writeln!(
            script,
            "\t\ttype filter hook {chain} priority filter; policy accept;"
        )
        .unwrap();
        for rule in ordered.iter().filter(|r| r.spec.direction == direction) {
            let line = render_rule(rule).map_err(|e| format!("rule {}: {e}", rule.rule_id))?;
            writeln!(script, "\t\t{line}").unwrap();
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

pub fn find_nft() -> Option<PathBuf> {
    ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

/// What the table currently holds.
#[derive(Default)]
struct Applied {
    rules: Vec<FirewallRule>,
    queue: Option<QueueRule>,
}

pub struct Firewall {
    nft: Option<PathBuf>,
    /// Command `nft` runs under; tests use `unshare -rn`.
    wrapper: Vec<String>,
    /// Also serializes changes.
    applied: tokio::sync::Mutex<Applied>,
}

impl Firewall {
    pub fn new() -> Self {
        Self::with_wrapper(&[])
    }

    pub fn with_wrapper(wrapper: &[&str]) -> Self {
        Self {
            nft: find_nft(),
            wrapper: wrapper.iter().map(|s| s.to_string()).collect(),
            applied: tokio::sync::Mutex::new(Applied::default()),
        }
    }

    pub fn available(&self) -> bool {
        self.nft.is_some()
    }

    /// Replaces the rules, keeping the queue rule.
    pub async fn apply(&self, rules: &[FirewallRule]) -> Result<(), HelperError> {
        let mut applied = self.applied.lock().await;
        self.write(rules, applied.queue).await?;
        applied.rules = rules.to_vec();
        Ok(())
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
        self.write(&applied.rules, queue).await?;
        applied.queue = queue;
        Ok(())
    }

    async fn write(
        &self,
        rules: &[FirewallRule],
        queue: Option<QueueRule>,
    ) -> Result<(), HelperError> {
        let script =
            render(rules, queue).map_err(|e| HelperError::new(HelperErrorKind::Invalid, e))?;
        let nft = self.nft.as_ref().ok_or_else(|| {
            HelperError::new(HelperErrorKind::Unavailable, "nft is not installed")
        })?;
        let wrapper: Vec<&str> = self.wrapper.iter().map(String::as_str).collect();
        run_nft(nft, &wrapper, &script).await
    }
}

/// Runs `[wrapper...] nft -f -` with `script` on stdin.
pub async fn run_nft(
    nft: &std::path::Path,
    wrapper: &[&str],
    script: &str,
) -> Result<(), HelperError> {
    let backend = |msg: String| HelperError::new(HelperErrorKind::Backend, msg);
    let mut command = match wrapper.split_first() {
        Some((program, args)) => {
            let mut c = tokio::process::Command::new(program);
            c.args(args).arg(nft);
            c
        }
        None => tokio::process::Command::new(nft),
    };
    let mut child = command
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
        ]
    }

    #[test]
    fn renders_allow_before_block() {
        let script = render(&sample(), None).unwrap();
        assert_eq!(
            script,
            "table inet omarchy_sec\n\
             delete table inet omarchy_sec\n\
             table inet omarchy_sec {\n\
             \tchain input {\n\
             \t\ttype filter hook input priority filter; policy accept;\n\
             \t\tip6 saddr 2001:db8::/32 meta l4proto udp counter drop comment \"omarchy:3\"\n\
             \t}\n\
             \tchain output {\n\
             \t\ttype filter hook output priority filter; policy accept;\n\
             \t\tip daddr 192.0.2.10 tcp dport 25 counter accept comment \"omarchy:2\"\n\
             \t\tip daddr 0.0.0.0/0 tcp dport 25 counter drop comment \"omarchy:1\"\n\
             \t\tip daddr 10.0.0.0/8 meta l4proto { tcp, udp } th dport 53 counter drop comment \"omarchy:4\"\n\
             \t}\n\
             }\n"
        );
    }

    #[test]
    fn empty_rules_remove_the_table() {
        assert_eq!(
            render(&[], None).unwrap(),
            "table inet omarchy_sec\ndelete table inet omarchy_sec\n"
        );
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

    #[test]
    fn leaves_executable_rules_to_the_queue() {
        let queue = QueueRule {
            num: 7433,
            uid: 1000,
            loopback: false,
        };
        assert_eq!(
            render(&[curl_rule()], None).unwrap(),
            "table inet omarchy_sec\ndelete table inet omarchy_sec\n"
        );
        let mut rules = sample()[..1].to_vec();
        rules.push(curl_rule());
        assert_eq!(
            render(&rules, Some(queue)).unwrap(),
            "table inet omarchy_sec\n\
             delete table inet omarchy_sec\n\
             table inet omarchy_sec {\n\
             \tchain input {\n\
             \t\ttype filter hook input priority filter; policy accept;\n\
             \t}\n\
             \tchain output {\n\
             \t\ttype filter hook output priority filter; policy accept;\n\
             \t\tip daddr 0.0.0.0/0 tcp dport 25 counter drop comment \"omarchy:1\"\n\
             \t\toif \"lo\" accept comment \"omarchy:queue\"\n\
             \t\tmeta skuid 1000 meta l4proto { tcp, udp } ct state new counter queue num 7433 bypass comment \"omarchy:queue\"\n\
             \t}\n\
             }\n"
        );
        let loopback = render(
            &[],
            Some(QueueRule {
                loopback: true,
                ..queue
            }),
        )
        .unwrap();
        assert!(!loopback.contains("oif"), "{loopback}");
        assert!(loopback.contains("queue num 7433 bypass"), "{loopback}");
    }

    /// Applies the rendered scripts for real inside an unprivileged user
    /// and network namespace (`unshare -rn`), where nft has CAP_NET_ADMIN.
    #[tokio::test]
    async fn nft_accepts_the_rendered_ruleset() {
        let Some(nft) = find_nft() else {
            eprintln!("nft not installed; skipping");
            return;
        };
        let probe = std::process::Command::new("unshare")
            .args(["-rn", "true"])
            .status();
        if !probe.is_ok_and(|s| s.success()) {
            eprintln!("unprivileged user namespaces unavailable; skipping");
            return;
        }
        // Apply, re-apply (replace), list, and remove, all in one namespace.
        let queue = QueueRule {
            num: 7433,
            uid: 1000,
            loopback: false,
        };
        let full = render(&sample(), Some(queue)).unwrap();
        let smaller = render(&sample()[..1], None).unwrap();
        let empty = render(&[], None).unwrap();
        let script = format!(
            "set -e\n\
             printf '%s' \"$FULL\" | {nft} -f -\n\
             printf '%s' \"$SMALLER\" | {nft} -f -\n\
             {nft} list table inet omarchy_sec\n\
             printf '%s' \"$EMPTY\" | {nft} -f -\n\
             ! {nft} list table inet omarchy_sec 2>/dev/null\n",
            nft = nft.display()
        );
        let output = std::process::Command::new("unshare")
            .args(["-rn", "sh", "-c", &script])
            .env("FULL", &full)
            .env("SMALLER", &smaller)
            .env("EMPTY", &empty)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "stdout: {stdout}\nstderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("omarchy:1") && !stdout.contains("omarchy:2"),
            "{stdout}"
        );
        assert!(!stdout.contains("omarchy:queue"), "{stdout}");

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
}
