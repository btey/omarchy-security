// SPDX-License-Identifier: GPL-3.0-or-later

//! Routes each non-session method to its module.

use std::sync::Arc;

use omarchy_security_proto::types::Module;
use omarchy_security_proto::{Call, ErrorCode, RpcError};
use serde::Serialize;
use serde_json::Value;

use crate::firewall::Firewall;
use crate::hub::Hub;
use crate::posture::Posture;
use crate::sandbox::Sandbox;
use crate::server::Dispatcher;
use crate::threat::Threat;
use crate::token::Tokens;
use crate::usbguard::Usbguard;
use crate::vault::Vaults;

pub struct Daemon {
    pub hub: Arc<Hub>,
    pub posture: Arc<Posture>,
    pub sandbox: Arc<Sandbox>,
    pub usbguard: Arc<Usbguard>,
    pub tokens: Arc<Tokens>,
    pub threat: Arc<Threat>,
    pub firewall: Arc<Firewall>,
    pub vaults: Arc<Vaults>,
}

fn value<T: Serialize>(result: Result<T, RpcError>) -> Result<Value, RpcError> {
    result.and_then(|r| {
        serde_json::to_value(r).map_err(|e| RpcError::new(ErrorCode::InternalError, e.to_string()))
    })
}

impl Dispatcher for Daemon {
    async fn call(&self, call: Call) -> Result<Value, RpcError> {
        let hub = &self.hub;
        match call {
            Call::Hello(_) | Call::Ping(_) | Call::GetStatus(_) | Call::Subscribe(_) => {
                Err(RpcError::new(
                    ErrorCode::InternalError,
                    "session method reached the dispatcher",
                ))
            }

            Call::PostureGetReport(_) => {
                hub.require(Module::Posture)?;
                value(Ok(self.posture.report().await))
            }
            Call::PostureRefresh(_) => {
                hub.require(Module::Posture)?;
                value(Ok(self.posture.refresh().await))
            }

            Call::ThreatListAlerts(_) => {
                hub.require(Module::Threat)?;
                value(Ok(self.threat.list()))
            }
            Call::ThreatKillProcess(params) => {
                hub.require(Module::Threat)?;
                value(self.threat.kill(params).await)
            }
            Call::ThreatQuarantineProcess(target) => {
                hub.require(Module::Threat)?;
                value(self.threat.quarantine(target).await)
            }
            Call::ThreatResumeProcess(target) => {
                hub.require(Module::Threat)?;
                value(self.threat.resume(target).await)
            }
            Call::ThreatDismissAlert(target) => {
                hub.require(Module::Threat)?;
                value(self.threat.dismiss(target).await)
            }

            Call::UsbguardListDevices(_) => {
                hub.require(Module::Usbguard)?;
                value(Ok(self.usbguard.list()))
            }
            Call::UsbguardSetPolicy(params) => {
                hub.require(Module::Usbguard)?;
                value(self.usbguard.set_policy(params).await)
            }

            Call::TokenList(_) => {
                hub.require(Module::Token)?;
                value(Ok(self.tokens.list()))
            }

            Call::FirewallListRules(_) => {
                hub.require(Module::Firewall)?;
                value(Ok(self.firewall.list().await))
            }
            Call::FirewallAddRule(spec) => {
                hub.require(Module::Firewall)?;
                value(self.firewall.add(spec).await)
            }
            Call::FirewallRemoveRule(target) => {
                hub.require(Module::Firewall)?;
                value(self.firewall.remove(target).await)
            }
            Call::FirewallDecide(params) => {
                hub.require(Module::Firewall)?;
                value(self.firewall.decide(params).await)
            }
            // Both work while the module is unavailable: the mode is then
            // `unknown`, and ufw's rules need no helper.
            Call::FirewallGetMode(_) => value(self.firewall.mode()),
            Call::FirewallUfwRules(_) => value(self.firewall.ufw_rules().await),
            Call::FirewallSetMode(params) => {
                hub.require(Module::Firewall)?;
                value(self.firewall.set_mode(params).await)
            }
            // Alerts come from the journal and need no helper.
            Call::FirewallAlertList(params) => value(Ok(self.firewall.alert_list(params))),
            Call::FirewallAlertMute(params) => value(self.firewall.alert_mute(params)),
            Call::FirewallTempList(_) => value(Ok(self.firewall.temp_list().await)),
            Call::FirewallTempAdd(params) => {
                hub.require(Module::Firewall)?;
                value(self.firewall.temp_add(params).await)
            }
            Call::FirewallTempRemove(target) => {
                hub.require(Module::Firewall)?;
                value(self.firewall.temp_remove(target).await)
            }

            Call::SandboxRun(params) => {
                hub.require(Module::Sandbox)?;
                value(self.sandbox.run(params).await)
            }

            Call::VaultList(_) => {
                hub.require(Module::Vault)?;
                value(Ok(self.vaults.list()))
            }
            Call::VaultMount(target) => {
                hub.require(Module::Vault)?;
                value(self.vaults.mount(target).await)
            }
            Call::VaultUnmount(target) => {
                hub.require(Module::Vault)?;
                value(self.vaults.unmount(target).await)
            }
            Call::VaultPanic(_) => {
                hub.require(Module::Vault)?;
                value(Ok(self.vaults.panic().await))
            }
            // Editing the configuration needs no backend.
            Call::VaultAdd(params) => value(self.vaults.add(params).await),
            Call::VaultRemove(target) => value(self.vaults.remove(target).await),
            Call::VaultCreate(params) => value(self.vaults.create(params).await),
        }
    }
}
