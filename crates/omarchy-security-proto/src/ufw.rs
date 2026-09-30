// SPDX-License-Identifier: GPL-3.0-or-later

//! `ufw`'s `### tuple ###` lines, which both the daemon (the read-only
//! rules view) and the helper (expiring the hub's temporary rules) read.
//!
//! The hub's temporary `ufw` rules carry their expiry in the comment:
//! `omarchy-security:tmp:<temp_id>:<created_unix>:<expires_unix>`, so a
//! crash of the daemon or the helper cannot leave an allow in place past
//! its time.

use crate::types::{
    Direction, FirewallRuleSpec, Protocol, TempBackend, TempDecision, UfwAction, UfwDirection,
    UfwRule, Verdict, check_temp_spec,
};

/// How a temporary rule's comment starts.
pub const TEMP_TAG: &str = "omarchy-security:tmp:";

/// The comment of a temporary rule; times are Unix seconds.
pub fn temp_tag(temp_id: u64, created_unix: u64, expires_unix: u64) -> String {
    format!("{TEMP_TAG}{temp_id}:{created_unix}:{expires_unix}")
}

/// `(temp_id, created_unix, expires_unix)` from a temporary rule's comment.
pub fn parse_temp_tag(comment: &str) -> Option<(u64, u64, u64)> {
    let mut parts = comment.strip_prefix(TEMP_TAG)?.split(':');
    let mut next = || parts.next()?.parse::<u64>().ok();
    let tag = (next()?, next()?, next()?);
    parts.next().is_none().then_some(tag)
}

/// `ufw` writes "any" addresses as the whole address space.
fn address(value: &str) -> String {
    match value {
        "0.0.0.0/0" | "::/0" => "any".into(),
        other => other.into(),
    }
}

/// The comment is hex-encoded UTF-8; anything else is kept as it is.
fn comment(hex: &str) -> String {
    let bytes: Option<Vec<u8>> = (hex.len() % 2 == 0)
        .then(|| {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
                .collect()
        })
        .flatten();
    bytes
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_else(|| hex.into())
}

/// Parses one `### tuple ###` line:
/// `<action> <proto> <dport> <dst> <sport> <src> [<dapp> <sapp>] <direction>[_<iface>] [comment=<hex>]`.
/// Routed (`route:`) rules and anything malformed give `None`. A
/// temporary rule of the hub gets `temp_id` and `expires_at`.
pub fn parse_tuple(line: &str, ipv6: bool) -> Option<UfwRule> {
    let rest = line.trim().strip_prefix("### tuple ###")?;
    let mut fields: Vec<&str> = rest.split_whitespace().collect();
    let comment = match fields.last() {
        Some(last) if last.starts_with("comment=") => {
            let hex = fields.pop()?.trim_start_matches("comment=");
            Some(comment(hex))
        }
        _ => None,
    };
    let (action, protocol, dport, dst, sport, src, direction) = match fields[..] {
        [a, p, dp, d, sp, s, dir] | [a, p, dp, d, sp, s, _, _, dir] => (a, p, dp, d, sp, s, dir),
        _ => return None,
    };
    // `allow_log`, `deny_log-all`: the logging suffix does not matter here.
    let action = match action.split('_').next()? {
        "allow" => UfwAction::Allow,
        "deny" => UfwAction::Deny,
        "reject" => UfwAction::Reject,
        "limit" => UfwAction::Limit,
        _ => return None,
    };
    let (direction, iface) = match direction.split_once('_') {
        Some((d, iface)) if !iface.is_empty() => (d, Some(iface.to_owned())),
        Some(_) => return None,
        None => (direction, None),
    };
    let direction = match direction {
        "in" => UfwDirection::In,
        "out" => UfwDirection::Out,
        _ => return None,
    };
    let port = |p: &str| (p != "any").then(|| p.to_owned());
    let tag = comment.as_deref().and_then(parse_temp_tag);
    Some(UfwRule {
        action,
        direction,
        protocol: protocol.into(),
        port: port(dport),
        src_port: port(sport),
        src: address(src),
        dst: address(dst),
        iface,
        comment,
        ipv6,
        temp_id: tag.map(|(id, _, _)| id),
        expires_at: tag.map(|(_, _, expires)| expires.saturating_mul(1000)),
    })
}

/// The temporary decision a tagged rule stands for, or `None` for any
/// other rule and for one the hub could not have added.
pub fn temp_decision(rule: &UfwRule) -> Option<TempDecision> {
    let (temp_id, created, expires) = parse_temp_tag(rule.comment.as_deref()?)?;
    let verdict = match rule.action {
        UfwAction::Allow => Verdict::Allow,
        UfwAction::Deny | UfwAction::Reject => Verdict::Block,
        UfwAction::Limit => return None,
    };
    let (direction, remote) = match rule.direction {
        UfwDirection::In => (Direction::Inbound, &rule.src),
        UfwDirection::Out => (Direction::Outbound, &rule.dst),
    };
    let address = match remote.as_str() {
        "any" if rule.ipv6 => "::/0".to_owned(),
        "any" => "0.0.0.0/0".to_owned(),
        remote => remote.to_owned(),
    };
    let protocol = match rule.protocol.as_str() {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        "any" => None,
        _ => return None,
    };
    let port = match &rule.port {
        Some(port) => Some(port.parse::<u16>().ok()?),
        None => None,
    };
    let spec = FirewallRuleSpec {
        verdict,
        direction,
        address,
        port,
        protocol,
        executable: None,
    };
    check_temp_spec(&spec).ok()?;
    Some(TempDecision {
        temp_id,
        spec,
        backend: TempBackend::Ufw,
        created_at: created.saturating_mul(1000),
        expires_at: expires.saturating_mul(1000),
        alert_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> String {
        text.bytes().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn reads_temporary_rules_back() {
        let tag = temp_tag(42, 1_790_000_000, 1_790_003_600);
        assert_eq!(tag, "omarchy-security:tmp:42:1790000000:1790003600");
        assert_eq!(
            parse_temp_tag(&tag),
            Some((42, 1_790_000_000, 1_790_003_600))
        );
        for bad in [
            "omarchy-security:tmp:42:1",
            "omarchy-security:tmp:42:1:2:3",
            "omarchy-security:tmp:x:1:2",
            "allow-docker-dns",
        ] {
            assert_eq!(parse_temp_tag(bad), None, "{bad}");
        }

        let line = format!(
            "### tuple ### allow tcp 22 0.0.0.0/0 any 203.0.113.7 in comment={}",
            hex(&tag)
        );
        let rule = parse_tuple(&line, false).unwrap();
        assert_eq!(
            (rule.temp_id, rule.expires_at),
            (Some(42), Some(1_790_003_600_000))
        );
        let decision = temp_decision(&rule).unwrap();
        assert_eq!(
            decision.spec,
            FirewallRuleSpec {
                verdict: Verdict::Allow,
                direction: Direction::Inbound,
                address: "203.0.113.7".into(),
                port: Some(22),
                protocol: Some(Protocol::Tcp),
                executable: None,
            }
        );
        assert_eq!(decision.backend, TempBackend::Ufw);
        assert_eq!(decision.created_at, 1_790_000_000_000);

        // Any source, IPv6, no port; and an outbound allow.
        let v6 = format!(
            "### tuple ### allow any any ::/0 any ::/0 in comment={}",
            hex(&tag)
        );
        let decision = temp_decision(&parse_tuple(&v6, true).unwrap()).unwrap();
        assert_eq!(
            (decision.spec.address.as_str(), decision.spec.port),
            ("::/0", None)
        );
        let out = format!(
            "### tuple ### allow udp 53 192.0.2.53 any 0.0.0.0/0 out comment={}",
            hex(&tag)
        );
        let decision = temp_decision(&parse_tuple(&out, false).unwrap()).unwrap();
        assert_eq!(
            (decision.spec.direction, decision.spec.address.as_str()),
            (Direction::Outbound, "192.0.2.53")
        );

        // Untagged, and a range the hub never writes.
        let plain = parse_tuple(
            "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
            false,
        );
        assert_eq!(plain.as_ref().unwrap().temp_id, None);
        assert_eq!(temp_decision(&plain.unwrap()), None);
        let range = format!(
            "### tuple ### allow tcp 1000:2000 0.0.0.0/0 any 0.0.0.0/0 in comment={}",
            hex(&tag)
        );
        assert_eq!(temp_decision(&parse_tuple(&range, false).unwrap()), None);
    }
}
