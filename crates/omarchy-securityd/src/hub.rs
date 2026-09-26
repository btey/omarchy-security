// SPDX-License-Identifier: GPL-3.0-or-later

//! State shared by the server and every module: the event bus and the
//! status of each module.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Instant;

use omarchy_security_proto::types::{Module, ModuleState, ModuleStatus, Topic};
use omarchy_security_proto::{ErrorCode, Event, RpcError};
use serde_json::json;
use tokio::sync::{broadcast, watch};

/// Events a client may fall behind by before it is disconnected.
pub const EVENT_BACKLOG: usize = 256;

pub struct Hub {
    started: Instant,
    events: broadcast::Sender<Event>,
    statuses: Mutex<Vec<ModuleStatus>>,
    /// Connections subscribed to each topic.
    listeners: watch::Sender<HashMap<Topic, usize>>,
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl Hub {
    pub fn new() -> Self {
        let statuses = Module::ALL
            .into_iter()
            .map(|module| ModuleStatus {
                module,
                state: ModuleState::NotImplemented,
                detail: None,
            })
            .collect();
        Self {
            started: Instant::now(),
            events: broadcast::channel(EVENT_BACKLOG).0,
            statuses: Mutex::new(statuses),
            listeners: watch::Sender::new(HashMap::new()),
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// Sends an event to every connection. Connections filter by topic.
    pub fn emit(&self, event: Event) {
        // An error only means no client is connected.
        let _ = self.events.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    /// Records that a connection's topics changed from `old` to `new`.
    /// A closing connection passes an empty `new`.
    pub fn set_topics(&self, old: &HashSet<Topic>, new: &HashSet<Topic>) {
        self.listeners.send_if_modified(|counts| {
            for topic in old.difference(new) {
                let count = counts.entry(*topic).or_default();
                *count = count.saturating_sub(1);
            }
            for topic in new.difference(old) {
                *counts.entry(*topic).or_default() += 1;
            }
            old != new
        });
    }

    /// How many connections are subscribed to `topic`, as it changes.
    pub fn listeners(&self) -> watch::Receiver<HashMap<Topic, usize>> {
        self.listeners.subscribe()
    }

    pub fn statuses(&self) -> Vec<ModuleStatus> {
        self.statuses.lock().expect("status lock").clone()
    }

    pub fn status(&self, module: Module) -> ModuleStatus {
        self.statuses()
            .into_iter()
            .find(|s| s.module == module)
            .expect("every module has a status")
    }

    /// Records a module's state, emitting `MODULE_STATE_CHANGED` and a log
    /// line when it differs from the previous one.
    pub fn set_status(&self, module: Module, state: ModuleState, detail: Option<String>) {
        let status = ModuleStatus {
            module,
            state,
            detail,
        };
        {
            let mut statuses = self.statuses.lock().expect("status lock");
            let slot = statuses
                .iter_mut()
                .find(|s| s.module == module)
                .expect("every module has a status");
            if *slot == status {
                return;
            }
            *slot = status.clone();
        }
        tracing::info!(module = ?module, state = ?state, detail = status.detail.as_deref().unwrap_or(""), "module state");
        self.emit(Event::ModuleStateChanged(status));
    }

    /// Fails unless the module can serve requests (`active` or `degraded`).
    pub fn require(&self, module: Module) -> Result<(), RpcError> {
        let status = self.status(module);
        let value = serde_json::to_value(module).expect("module serializes");
        let name = value.as_str().unwrap_or_default();
        match status.state {
            ModuleState::Active | ModuleState::Degraded => Ok(()),
            ModuleState::Unavailable => {
                let reason = status
                    .detail
                    .unwrap_or_else(|| "module is unavailable".into());
                Err(RpcError::new(
                    ErrorCode::ModuleUnavailable,
                    format!("{name} module unavailable: {reason}"),
                )
                .with_data(json!({ "module": name })))
            }
            ModuleState::NotImplemented => Err(RpcError::new(
                ErrorCode::NotImplemented,
                format!("the {name} module is not implemented in this daemon"),
            )
            .with_data(json!({ "module": name }))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_status_emits_only_on_change() {
        let hub = Hub::new();
        let mut rx = hub.subscribe();
        hub.set_status(Module::Posture, ModuleState::Active, None);
        hub.set_status(Module::Posture, ModuleState::Active, None);
        assert!(matches!(rx.try_recv(), Ok(Event::ModuleStateChanged(_))));
        assert!(rx.try_recv().is_err());
        assert!(hub.require(Module::Posture).is_ok());
    }

    #[test]
    fn counts_topic_listeners() {
        let hub = Hub::new();
        let rx = hub.listeners();
        let count = || rx.borrow().get(&Topic::Firewall).copied().unwrap_or(0);
        let none = HashSet::new();
        let firewall: HashSet<Topic> = [Topic::Firewall, Topic::System].into();
        hub.set_topics(&none, &firewall);
        hub.set_topics(&none, &[Topic::Firewall].into());
        assert_eq!(count(), 2);
        hub.set_topics(&firewall, &[Topic::System].into());
        hub.set_topics(&[Topic::Firewall].into(), &none);
        assert_eq!(count(), 0);
    }

    #[test]
    fn require_maps_states_to_error_codes() {
        let hub = Hub::new();
        let err = hub.require(Module::Vault).unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::NotImplemented));
        hub.set_status(
            Module::Usbguard,
            ModuleState::Unavailable,
            Some("down".into()),
        );
        let err = hub.require(Module::Usbguard).unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::ModuleUnavailable));
        assert_eq!(err.data, Some(json!({ "module": "usbguard" })));
    }
}
