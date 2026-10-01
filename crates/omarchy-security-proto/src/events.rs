// SPDX-License-Identifier: GPL-3.0-or-later

//! Daemon → client events, sent as JSON-RPC notifications whose `method` is
//! the event name and whose `params` is the payload.

use serde::{Deserialize, Serialize};

use crate::types::*;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
pub enum Event {
    // --- system
    ModuleStateChanged(ModuleStatus),

    // --- threat
    /// A binary ran from `/tmp`, `/var/tmp`, `/dev/shm`, or a memfd.
    ThreatExecDetected(ThreatAlert),
    /// An alert left the `open` / `quarantined` states.
    ThreatAlertResolved(AlertResolved),
    /// An executable file appeared in `/tmp`, `/var/tmp`, or `/dev/shm`.
    ThreatFileDropped(FileDrop),

    // --- usbguard
    UsbDevicePresented(UsbDevice),
    UsbDevicePolicyChanged(UsbPolicyChanged),
    UsbDeviceRemoved(UsbDeviceRef),

    // --- token
    TokenInserted(SecurityToken),
    TokenRemoved(TokenRef),
    /// Something is waiting for a physical touch on a token.
    TokenTouchRequested(TouchRequest),
    TokenTouchCompleted(TouchCompleted),

    // --- vault
    VaultStateChanged(Vault),
    /// A vault left the configuration (`VAULT_REMOVE`, or an edit and a
    /// reload).
    VaultRemoved(VaultRef),

    // --- firewall
    /// An outbound connection matched no rule and awaits `FIREWALL_DECIDE`.
    FirewallConnectionPrompt(ConnectionPrompt),
    /// A prompt was answered or expired; clients close it.
    FirewallConnectionResolved(ConnectionResolved),
    /// `FIREWALL_GET_MODE`'s result changed.
    FirewallModeChanged(FirewallMode),
    /// A blocked-traffic alert was created, or its count changed (at most
    /// once per 5 s per alert).
    FirewallAlert(FirewallAlert),
    /// The temporary decisions changed; carries all of them.
    FirewallTempChanged(TempDecisionList),

    // --- posture
    /// The audit report differs from the previous one.
    PostureChanged(PostureReport),
}

impl Event {
    pub fn topic(&self) -> Topic {
        match self {
            Self::ModuleStateChanged(_) => Topic::System,
            Self::ThreatExecDetected(_)
            | Self::ThreatAlertResolved(_)
            | Self::ThreatFileDropped(_) => Topic::Threat,
            Self::UsbDevicePresented(_)
            | Self::UsbDevicePolicyChanged(_)
            | Self::UsbDeviceRemoved(_) => Topic::Usbguard,
            Self::TokenInserted(_)
            | Self::TokenRemoved(_)
            | Self::TokenTouchRequested(_)
            | Self::TokenTouchCompleted(_) => Topic::Token,
            Self::VaultStateChanged(_) | Self::VaultRemoved(_) => Topic::Vault,
            Self::FirewallConnectionPrompt(_)
            | Self::FirewallConnectionResolved(_)
            | Self::FirewallModeChanged(_)
            | Self::FirewallAlert(_)
            | Self::FirewallTempChanged(_) => Topic::Firewall,
            Self::PostureChanged(_) => Topic::Posture,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertResolved {
    pub alert_id: u64,
    pub state: AlertState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbPolicyChanged {
    pub device_id: u32,
    pub target: UsbTarget,
    pub permanent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsbDeviceRef {
    pub device_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultRef {
    pub vault_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRef {
    pub token_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TouchRequest {
    pub request_id: u64,
    /// `None` when the daemon cannot tell which token is being asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    pub source: TouchSource,
    /// Human-readable context, e.g. the SSH host or GPG key being used.
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TouchCompleted {
    pub request_id: u64,
    pub outcome: TouchOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionPrompt {
    pub request_id: u64,
    pub pid: u32,
    pub executable: String,
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    /// The connection is dropped if no decision arrives by this time.
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionResolved {
    pub request_id: u64,
    pub verdict: Verdict,
    pub decided_by: DecidedBy,
}
