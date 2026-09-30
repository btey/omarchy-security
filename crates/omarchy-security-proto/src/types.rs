// SPDX-License-Identifier: GPL-3.0-or-later

//! Domain objects that appear in method params, results, and events.
//!
//! Timestamps are Unix epoch milliseconds. Identifiers minted by the daemon
//! (`alert_id`, `rule_id`, `request_id`) are opaque and only meaningful for
//! the lifetime of one daemon process.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// A daemon module, one per backend in the architecture diagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Module {
    Threat,
    Usbguard,
    Token,
    Vault,
    Firewall,
    Sandbox,
    Posture,
}

impl Module {
    pub const ALL: [Self; 7] = [
        Self::Threat,
        Self::Usbguard,
        Self::Token,
        Self::Vault,
        Self::Firewall,
        Self::Sandbox,
        Self::Posture,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleState {
    /// Running and serving requests.
    Active,
    /// Running with reduced function; `detail` says what is missing.
    Degraded,
    /// Not running: disabled in config or a dependency is missing.
    Unavailable,
    /// Defined by the protocol but not built into this daemon yet.
    NotImplemented,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleStatus {
    pub module: Module,
    pub state: ModuleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Event subscription topic. Every event belongs to exactly one topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Topic {
    System,
    Threat,
    Usbguard,
    Token,
    Vault,
    Firewall,
    Posture,
}

impl Topic {
    pub const ALL: [Self; 7] = [
        Self::System,
        Self::Threat,
        Self::Usbguard,
        Self::Token,
        Self::Vault,
        Self::Firewall,
        Self::Posture,
    ];
}

// ---------------------------------------------------------------- threat

/// Why an execution was flagged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecOrigin {
    /// Binary under `/tmp`.
    Tmp,
    /// Binary under `/var/tmp`.
    VarTmp,
    /// Binary under `/dev/shm`.
    DevShm,
    /// Binary backed by an anonymous `memfd_create` descriptor.
    Memfd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    Open,
    /// Stopped with `SIGSTOP`; can be resumed or killed.
    Quarantined,
    Killed,
    Dismissed,
    /// The process exited on its own.
    Exited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub alert_id: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    /// Process start time in clock ticks since boot (`/proc/<pid>/stat`
    /// field 22). Together with `pid` it identifies the process across PID
    /// reuse.
    pub start_time: u64,
    pub binary_path: String,
    pub argv: Vec<String>,
    pub origin: ExecOrigin,
    pub detected_at: u64,
    pub state: AlertState,
    /// When a file at `binary_path` was reported by `THREAT_FILE_DROPPED`,
    /// if one was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dropped_at: Option<u64>,
}

/// An executable file written into `/tmp`, `/var/tmp`, or `/dev/shm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDrop {
    pub path: String,
    /// The file's owner.
    pub uid: u32,
    pub size: u64,
    pub detected_at: u64,
}

/// Signals the daemon will send on behalf of a client. Anything else is
/// rejected at parse time, so the socket cannot be used as a general
/// `kill(2)` proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub enum KillSignal {
    Term,
    Kill,
}

impl KillSignal {
    pub const fn number(self) -> u32 {
        match self {
            Self::Term => 15,
            Self::Kill => 9,
        }
    }
}

impl TryFrom<u32> for KillSignal {
    type Error = String;

    fn try_from(signal: u32) -> Result<Self, Self::Error> {
        match signal {
            15 => Ok(Self::Term),
            9 => Ok(Self::Kill),
            other => Err(format!("signal {other} not allowed (use 15 or 9)")),
        }
    }
}

impl From<KillSignal> for u32 {
    fn from(signal: KillSignal) -> Self {
        signal.number()
    }
}

// -------------------------------------------------------------- usbguard

/// USBGuard device policy target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsbTarget {
    Allow,
    Block,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbDevice {
    /// USBGuard's numeric device id.
    pub device_id: u32,
    pub name: String,
    /// Four hex digits, lowercase.
    pub vendor_id: String,
    /// Four hex digits, lowercase.
    pub product_id: String,
    #[serde(default)]
    pub serial: String,
    /// Current policy target of the device.
    pub rule: UsbTarget,
    /// Class of the first interface as two hex digits (`"08"` is mass
    /// storage). `interfaces` lists every interface when there are several.
    pub interface_class: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
}

// ----------------------------------------------------------------- token

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    Yubikey,
    Solokey,
    Nitrokey,
    /// Any other FIDO2/U2F authenticator.
    Fido2,
    /// Any other PC/SC smartcard reader.
    Smartcard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenCapability {
    Fido2,
    Piv,
    Openpgp,
    Otp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityToken {
    /// Stable for as long as the token stays plugged in (derived from the
    /// udev device path).
    pub token_id: String,
    pub kind: TokenKind,
    pub name: String,
    pub vendor_id: String,
    pub product_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<TokenCapability>,
}

/// What is waiting for a touch on the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TouchSource {
    Ssh,
    Gpg,
    Fido2,
    Pcsc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TouchOutcome {
    Touched,
    TimedOut,
    Cancelled,
}

// ----------------------------------------------------------------- vault

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultBackend {
    Luks,
    Gocryptfs,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    /// Name of the vault in the daemon configuration.
    pub vault_id: String,
    pub name: String,
    pub backend: VaultBackend,
    pub mount_point: String,
    pub mounted: bool,
}

// -------------------------------------------------------------- firewall

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A rule in `table inet omarchy_sec`, as the client specifies it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRuleSpec {
    pub verdict: Verdict,
    pub direction: Direction,
    /// IPv4/IPv6 address or CIDR prefix.
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Protocol>,
    /// Restrict the rule to one executable (absolute path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
}

/// Parses an address or CIDR prefix and clears the host bits, which nft
/// would otherwise reject.
pub fn parse_prefix(address: &str) -> Result<(IpAddr, u8), String> {
    let (addr, len) = match address.split_once('/') {
        Some((addr, len)) => (addr, Some(len)),
        None => (address, None),
    };
    let ip: IpAddr = addr
        .trim()
        .parse()
        .map_err(|_| format!("'{address}' is not an IP address or CIDR prefix"))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = match len {
        None => max,
        Some(len) => len
            .parse::<u8>()
            .ok()
            .filter(|&l| l <= max)
            .ok_or_else(|| format!("bad prefix length in '{address}'"))?,
    };
    let masked = match ip {
        IpAddr::V4(v4) => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            IpAddr::V4((u32::from(v4) & mask).into())
        }
        IpAddr::V6(v6) => {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            IpAddr::V6((u128::from(v6) & mask).into())
        }
    };
    Ok((masked, len))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRule {
    pub rule_id: u64,
    #[serde(flatten)]
    pub spec: FirewallRuleSpec,
    /// The rule is enforced now. Rules without an `executable` are only
    /// loaded in `standalone` mode; in `ufw` mode they are kept but `ufw`
    /// decides. Ignored in requests to the helper.
    #[serde(default)]
    pub loaded: bool,
}

/// Which firewall protects the machine, derived from `ufw`'s state and our
/// table's mode stamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallModeKind {
    /// `ufw` is active; our table holds only what adds to it.
    Ufw,
    /// `ufw` is inactive and our table holds the full policy.
    Standalone,
    /// Both are active (a conflict: safe, but confusing).
    Both,
    /// Neither is active: the machine is unprotected.
    None,
    /// The helper cannot be asked, so the state is unknown.
    Unknown,
}

/// `ufw`'s state as the daemon and the helper see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UfwState {
    /// `/usr/bin/ufw` exists.
    pub installed: bool,
    /// `ENABLED=yes` in `/etc/ufw/ufw.conf`.
    pub enabled_in_conf: bool,
    /// `ufw`'s chains are in the kernel; absent when the helper cannot be asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chains_loaded: Option<bool>,
    /// `DEFAULT_*_POLICY` from `/etc/default/ufw`, lowercased (`drop`,
    /// `accept`, `reject`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_input: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_output: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_forward: Option<String>,
    /// `LOGLEVEL` from `/etc/ufw/ufw.conf` (`off`, `low`, ... `full`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging: Option<String>,
    /// `before.rules` or `before6.rules` differ from the packaged copies;
    /// absent when the helper cannot compare them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_rules_modified: Option<bool>,
}

/// What keeps published Docker ports off the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DockerProtection {
    /// The `ufw-docker` block in `/etc/ufw/after.rules`, while `ufw` is active.
    UfwDocker,
    /// The standalone policy's own forward rules.
    Omarchy,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallMode {
    pub mode: FirewallModeKind,
    pub ufw: UfwState,
    /// `table inet omarchy_sec` exists; absent when the helper cannot be asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_loaded: Option<bool>,
    pub docker_protection: DockerProtection,
    /// Why the mode is what it is, when that is not obvious.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UfwAction {
    Allow,
    Deny,
    Reject,
    Limit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UfwDirection {
    In,
    Out,
}

/// A rule from `/etc/ufw/user.rules` or `user6.rules`. `any` in an address
/// or `protocol` means no constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UfwRule {
    pub action: UfwAction,
    pub direction: UfwDirection,
    /// `tcp`, `udp`, `any`, or another protocol name `ufw` accepts.
    pub protocol: String,
    /// Destination port, range (`8000:8100`) or list (`80,443`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_port: Option<String>,
    pub src: String,
    pub dst: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    pub ipv6: bool,
    /// Set on the temporary rules the hub added (`FIREWALL_TEMP_ADD`),
    /// from the tag in their comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub temp_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

/// Which log prefix a blocked packet was logged with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSource {
    /// `[UFW BLOCK]` or `[UFW LIMIT BLOCK]`.
    Ufw,
    /// `[OMSEC BLOCK]` or `[OMSEC DOCKER BLOCK]`, from the standalone policy.
    Omarchy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertDirection {
    Inbound,
    Outbound,
    /// Routed through this machine, such as to a Docker container.
    Forward,
}

/// Blocked packets from the kernel log, grouped: repeats within the
/// configured window only raise `count` and `last_seen`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallAlert {
    pub alert_id: u64,
    pub source: AlertSource,
    pub direction: AlertDirection,
    /// `tcp`, `udp`, `icmp`, `icmpv6`, `igmp`, or what the log says.
    pub protocol: String,
    pub src: String,
    pub dst: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    /// The interface the packet came in on (`inbound`, `forward`) or was
    /// leaving by (`outbound`).
    pub iface: String,
    pub count: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    /// Set by `FIREWALL_ALERT_MUTE`: no desktop notification until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub muted_until: Option<u64>,
}

/// Where a temporary decision is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TempBackend {
    /// A set element with a kernel timeout in `table inet omarchy_sec`.
    Table,
    /// A tagged `ufw` rule, removed by the helper when it expires.
    Ufw,
}

/// A temporary allow or block (`FIREWALL_TEMP_ADD`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempDecision {
    /// Unique across daemon restarts.
    pub temp_id: u64,
    /// Never has an `executable`; a `port` comes with a `protocol`.
    pub spec: FirewallRuleSpec,
    pub backend: TempBackend,
    pub created_at: u64,
    pub expires_at: u64,
    /// The alert the decision was made from, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_id: Option<u64>,
}

/// `FIREWALL_TEMP_LIST`'s result and `FIREWALL_TEMP_CHANGED`'s params.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TempDecisionList {
    pub decisions: Vec<TempDecision>,
    /// The durations to offer (`[firewall.alerts] temp_durations_secs`).
    /// Only in `FIREWALL_TEMP_LIST`'s result.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub durations_secs: Vec<u64>,
}

/// Checks what a temporary decision can express: an address or prefix, and
/// a protocol with or without a port. No `executable`.
pub fn check_temp_spec(spec: &FirewallRuleSpec) -> Result<(), String> {
    parse_prefix(&spec.address)?;
    if spec.executable.is_some() {
        return Err("temporary decisions cannot be scoped to an executable".into());
    }
    match (spec.port, spec.protocol) {
        (Some(0), _) => Err("port 0 is not a port".into()),
        (Some(_), None) => Err("a temporary decision with a port needs a protocol".into()),
        _ => Ok(()),
    }
}

/// How long a verdict on a connection prompt lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionScope {
    /// This connection only.
    Once,
    /// Until the process exits.
    Process,
    /// Persisted as a firewall rule.
    Always,
}

/// Who settled a connection prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecidedBy {
    /// A client's `FIREWALL_DECIDE`.
    User,
    /// Nobody answered by `expires_at`, or prompting stopped; the
    /// configured `timeout_verdict` applied.
    Timeout,
}

// --------------------------------------------------------------- posture

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureCheckId {
    /// SELinux enforcing or AppArmor profiles loaded.
    Lsm,
    /// `kernel.yama.ptrace_scope >= 1`.
    PtraceScope,
    /// Current user is not in the `docker` group.
    DockerGroup,
    /// Every active swap area is encrypted.
    SwapEncryption,
}

/// Ordered from best to worst so that the overall status is the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Unknown,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureCheck {
    pub check_id: PostureCheckId,
    pub status: CheckStatus,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PostureReport {
    pub overall: CheckStatus,
    pub evaluated_at: u64,
    pub checks: Vec<PostureCheck>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_are_validated_and_masked() {
        assert_eq!(
            parse_prefix("10.1.2.3/8").unwrap(),
            ("10.0.0.0".parse().unwrap(), 8)
        );
        assert_eq!(parse_prefix("::1").unwrap(), ("::1".parse().unwrap(), 128));
        assert_eq!(parse_prefix("0.0.0.0/0").unwrap().1, 0);
        for bad in [
            "",
            "example.com",
            "10.0.0.0/33",
            "::/129",
            "1.2.3.4/x",
            "1.2.3.4; drop",
        ] {
            assert!(parse_prefix(bad).is_err(), "{bad}");
        }
    }
}
