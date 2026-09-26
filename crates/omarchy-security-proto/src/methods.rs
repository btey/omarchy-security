// SPDX-License-Identifier: GPL-3.0-or-later

//! Client → daemon methods: their params and results.
//!
//! Params are parsed strictly (`deny_unknown_fields`): a typo in a field
//! name is an `INVALID_PARAMS` error, never a silently ignored option.
//! Results are parsed leniently, so a client keeps working when a newer
//! daemon adds fields.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::RpcError;
use crate::types::*;

/// Params of a method that takes none. `params` may be omitted, `null`, or
/// `{}` on the wire.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoParams {}

/// Result of a method that returns nothing but success.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

macro_rules! calls {
    ($( $(#[$doc:meta])* $variant:ident = $name:literal ($params:ty); )*) => {
        /// A parsed client request, one variant per method.
        #[derive(Debug, Clone, PartialEq)]
        pub enum Call {
            $( $(#[$doc])* $variant($params), )*
        }

        impl Call {
            /// Every method name, in specification order.
            pub const METHODS: &'static [&'static str] = &[$($name),*];

            pub fn method(&self) -> &'static str {
                match self {
                    $( Self::$variant(_) => $name, )*
                }
            }

            /// Builds a call from its wire parts. Unknown methods map to
            /// `METHOD_NOT_FOUND` and malformed params to `INVALID_PARAMS`,
            /// which one tagged serde enum cannot tell apart.
            pub fn from_parts(method: &str, params: Value) -> Result<Self, RpcError> {
                let params = match params {
                    Value::Null => Value::Object(Default::default()),
                    Value::Object(_) => params,
                    _ => return Err(RpcError::invalid_params("params must be an object")),
                };
                match method {
                    $( $name => serde_json::from_value::<$params>(params)
                        .map(Self::$variant)
                        .map_err(RpcError::invalid_params), )*
                    other => Err(RpcError::method_not_found(other)),
                }
            }

            pub fn params(&self) -> Value {
                let value = match self {
                    $( Self::$variant(p) => serde_json::to_value(p), )*
                };
                value.expect("params types serialize infallibly")
            }
        }
    };
}

calls! {
    // --- session ---------------------------------------------------------
    /// Handshake; must be the first request on a connection → [`HelloResult`].
    Hello = "HELLO" (HelloParams);
    /// Liveness check → [`Empty`].
    Ping = "PING" (NoParams);
    /// Daemon and module state → [`StatusResult`].
    GetStatus = "GET_STATUS" (NoParams);
    /// Replaces this connection's event topics → [`SubscribeResult`].
    Subscribe = "SUBSCRIBE" (SubscribeParams);

    // --- threat (eBPF) ---------------------------------------------------
    /// Alerts that are not yet resolved → [`AlertList`].
    ThreatListAlerts = "THREAT_LIST_ALERTS" (NoParams);
    /// Signals the process behind an alert → [`ThreatAlert`].
    ThreatKillProcess = "THREAT_KILL_PROCESS" (KillProcessParams);
    /// `SIGSTOP`s the process behind an alert → [`ThreatAlert`].
    ThreatQuarantineProcess = "THREAT_QUARANTINE_PROCESS" (AlertTarget);
    /// `SIGCONT`s a quarantined process → [`ThreatAlert`].
    ThreatResumeProcess = "THREAT_RESUME_PROCESS" (AlertTarget);
    /// Marks an alert as reviewed without acting on it → [`ThreatAlert`].
    ThreatDismissAlert = "THREAT_DISMISS_ALERT" (AlertTarget);

    // --- usbguard --------------------------------------------------------
    /// Connected devices and their policy → [`UsbDeviceList`].
    UsbguardListDevices = "USBGUARD_LIST_DEVICES" (NoParams);
    /// Applies allow / block / reject to a device → [`UsbDevice`].
    UsbguardSetPolicy = "USBGUARD_SET_POLICY" (UsbSetPolicyParams);

    // --- token (PC/SC, FIDO2) --------------------------------------------
    /// Security tokens currently plugged in → [`TokenList`].
    TokenList = "TOKEN_LIST" (NoParams);

    // --- vault -----------------------------------------------------------
    /// Configured encrypted containers → [`VaultList`].
    VaultList = "VAULT_LIST" (NoParams);
    /// Opens and mounts a vault → [`Vault`]. The passphrase never crosses
    /// this socket: the daemon asks for it through the system askpass agent.
    VaultMount = "VAULT_MOUNT" (VaultTarget);
    /// Unmounts and closes a vault → [`Vault`].
    VaultUnmount = "VAULT_UNMOUNT" (VaultTarget);
    /// Emergency unmount of every vault, then `sync` → [`PanicResult`].
    VaultPanic = "VAULT_PANIC" (NoParams);

    // --- firewall (nftables) ---------------------------------------------
    /// Rules in `table inet omarchy_sec` → [`FirewallRuleList`].
    FirewallListRules = "FIREWALL_LIST_RULES" (NoParams);
    /// Adds a rule → [`FirewallRule`].
    FirewallAddRule = "FIREWALL_ADD_RULE" (FirewallRuleSpec);
    /// Removes a rule → [`Empty`].
    FirewallRemoveRule = "FIREWALL_REMOVE_RULE" (RuleTarget);
    /// Answers a `FIREWALL_CONNECTION_PROMPT` event → [`Empty`].
    FirewallDecide = "FIREWALL_DECIDE" (FirewallDecideParams);

    // --- sandbox (bubblewrap) --------------------------------------------
    /// Launches an executable under bwrap as the calling user → [`SandboxRunResult`].
    SandboxRun = "SANDBOX_RUN" (SandboxRunParams);

    // --- posture ---------------------------------------------------------
    /// Most recent audit report → [`PostureReport`].
    PostureGetReport = "POSTURE_GET_REPORT" (NoParams);
    /// Re-runs the audit now instead of at the next 30 s tick → [`PostureReport`].
    PostureRefresh = "POSTURE_REFRESH" (NoParams);
}

// ------------------------------------------------------------------ params

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloParams {
    pub protocol_version: u32,
    /// Free-form client name for logs, e.g. `"omarchy-shell/security-hub"`.
    pub client: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscribeParams {
    pub topics: Vec<Topic>,
}

/// Identifies the process behind an alert. `pid` must match the alert: the
/// daemon acts only on processes it reported, and re-checks the process start
/// time so a recycled PID is refused with `STALE_TARGET`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertTarget {
    pub alert_id: u64,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillProcessParams {
    pub alert_id: u64,
    pub pid: u32,
    /// 15 (`SIGTERM`) or 9 (`SIGKILL`).
    pub signal: KillSignal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsbSetPolicyParams {
    pub device_id: u32,
    pub target: UsbTarget,
    /// Also append a rule to `/etc/usbguard/rules.conf`.
    #[serde(default)]
    pub permanent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultTarget {
    pub vault_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleTarget {
    pub rule_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallDecideParams {
    pub request_id: u64,
    pub verdict: Verdict,
    pub scope: DecisionScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRunParams {
    /// Absolute path of the program to run.
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// A single file bound read-write into the sandbox (the document being
    /// opened). Everything else is read-only or a private tmpfs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_file: Option<String>,
    #[serde(default)]
    pub share_net: bool,
}

// ----------------------------------------------------------------- results

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloResult {
    pub protocol_version: u32,
    pub daemon_version: String,
    pub modules: Vec<ModuleStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResult {
    pub protocol_version: u32,
    pub daemon_version: String,
    pub uptime_secs: u64,
    pub modules: Vec<ModuleStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeResult {
    pub topics: Vec<Topic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertList {
    pub alerts: Vec<ThreatAlert>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbDeviceList {
    pub devices: Vec<UsbDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenList {
    pub tokens: Vec<SecurityToken>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultList {
    pub vaults: Vec<Vault>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanicResult {
    pub unmounted: Vec<String>,
    /// The vaults in `unmounted` that were busy and only detached lazily
    /// (`umount -l`): processes the daemon could not see may still use the
    /// files they have open.
    #[serde(default)]
    pub lazy: Vec<String>,
    /// Vaults that could not be unmounted, with the reason.
    pub failed: Vec<PanicFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PanicFailure {
    pub vault_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRuleList {
    pub rules: Vec<FirewallRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRunResult {
    pub pid: u32,
}
