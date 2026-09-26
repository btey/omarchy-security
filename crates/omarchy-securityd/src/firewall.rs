// SPDX-License-Identifier: GPL-3.0-or-later

//! Network module (tasks 2.5 and 2.14, plan §2.3): the rules of
//! `table inet omarchy_sec`, and the interactive connection prompts.
//!
//! The daemon owns the rule list and saves it to
//! `$XDG_STATE_HOME/omarchy-security/firewall.json`. The privileged helper
//! only renders and applies it, always as a whole, so the kernel table
//! matches the list after every change and after every helper restart. A
//! change is committed only once the helper has applied it.
//!
//! Rules with an `executable` are not written to the table (nftables cannot
//! match a process by path): the helper matches them against the outbound
//! connections it intercepts (task 2.13). A helper that cannot intercept
//! gets only the other rules, and the module reports itself degraded.
//!
//! Prompts: while `[firewall] prompt` is on and a client listens to the
//! `firewall` topic, the daemon subscribes to the helper's held
//! connections and turns each into a `FIREWALL_CONNECTION_PROMPT`. Held
//! connections with the same executable, address, port and protocol share
//! one prompt. The first `FIREWALL_DECIDE` wins; the daemon applies
//! `timeout_verdict` itself when a prompt expires, and the helper does too,
//! a little later, if the daemon never answers.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use omarchy_security_proto::Event;
use omarchy_security_proto::events::{ConnectionPrompt, ConnectionResolved};
use omarchy_security_proto::helper::{
    ConnectionRecord, HelperErrorKind, HelperHello, HelperOp, Remember,
};
use omarchy_security_proto::methods::{Empty, FirewallDecideParams, FirewallRuleList, RuleTarget};
use omarchy_security_proto::types::{
    DecidedBy, DecisionScope, Direction, FirewallRule, FirewallRuleSpec, Module, ModuleState,
    Protocol, Topic, Verdict, parse_prefix,
};
use omarchy_security_proto::{ErrorCode, RpcError};
use serde_json::json;
use tokio::sync::broadcast;

use crate::config::{Config, Settings};
use crate::helper_client::{HelperClient, HelperState};
use crate::hub::Hub;
use crate::now_ms;

/// How much longer than a prompt the helper holds a connection, so that
/// the daemon's own expiry normally comes first.
const HELPER_GRACE_SECS: u64 = 5;

pub fn default_store() -> Option<PathBuf> {
    let state = std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(state.join("omarchy-security/firewall.json"))
}

pub struct Firewall {
    hub: Arc<Hub>,
    helper: Arc<HelperClient>,
    settings: Arc<Settings>,
    store: Option<PathBuf>,
    /// Serializes changes: each is applied, then committed.
    rules: tokio::sync::Mutex<Vec<FirewallRule>>,
    next_id: AtomicU64,
    prompts: Mutex<Prompts>,
}

/// What makes two held connections the same question.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PromptKey {
    executable: String,
    address: String,
    port: u16,
    protocol: Protocol,
}

struct Pending {
    key: PromptKey,
    /// The helper's request ids of the connections the prompt stands for.
    held: Vec<u64>,
    timeout_verdict: Verdict,
    /// The helper subscription `held` belongs to.
    subscription: u64,
}

#[derive(Default)]
struct Prompts {
    pending: HashMap<u64, Pending>,
    next_id: u64,
    /// Counts helper subscriptions, so that a decision never answers a
    /// request id of an earlier helper connection.
    subscription: u64,
}

/// The `connection_subscribe` parameters: prompt timeout and verdict.
type Subscription = (u64, Verdict);

fn load(store: &Option<PathBuf>) -> Vec<FirewallRuleSpec> {
    let Some(path) = store else { return vec![] };
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|err| {
            tracing::warn!("ignoring unreadable {}: {err}", path.display());
            vec![]
        }),
        Err(_) => vec![],
    }
}

fn save(store: &Option<PathBuf>, rules: &[FirewallRule]) -> std::io::Result<()> {
    let Some(path) = store else { return Ok(()) };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let specs: Vec<&FirewallRuleSpec> = rules.iter().map(|r| &r.spec).collect();
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&specs)?)?;
    std::fs::rename(tmp, path)
}

fn helper_error(err: omarchy_security_proto::helper::HelperError) -> RpcError {
    let code = match err.kind {
        HelperErrorKind::Invalid => ErrorCode::InvalidParams,
        HelperErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
        HelperErrorKind::Unavailable => ErrorCode::ModuleUnavailable,
        HelperErrorKind::NotFound => ErrorCode::NotFound,
        HelperErrorKind::StaleTarget => ErrorCode::StaleTarget,
        HelperErrorKind::Backend => ErrorCode::BackendError,
    };
    let rpc = RpcError::new(code, err.message.clone());
    match code {
        ErrorCode::BackendError => rpc.with_data(json!({ "detail": err.message })),
        ErrorCode::ModuleUnavailable => rpc.with_data(json!({ "module": "firewall" })),
        _ => rpc,
    }
}

/// Checks an executable-scoped rule: an absolute path, outbound only (the
/// helper intercepts outbound connections only).
fn check_executable(spec: &FirewallRuleSpec) -> Result<(), RpcError> {
    let Some(executable) = &spec.executable else {
        return Ok(());
    };
    if !executable.starts_with('/') {
        return Err(RpcError::invalid_params(
            "executable must be an absolute path",
        ));
    }
    if spec.direction != Direction::Outbound {
        return Err(RpcError::invalid_params(
            "rules scoped to an executable must be outbound",
        ));
    }
    Ok(())
}

/// Why the helper cannot enforce executable rules, or `None` if it can.
fn interception_missing(hello: &HelperHello) -> Option<String> {
    (!hello.connections).then(|| {
        hello
            .connections_detail
            .clone()
            .unwrap_or_else(|| "the helper does not intercept connections".into())
    })
}

/// The rules the helper can apply, and how many it cannot.
fn enforceable(rules: &[FirewallRule], hello: Option<&HelperHello>) -> (Vec<FirewallRule>, usize) {
    if hello.is_none_or(|h| h.connections) {
        return (rules.to_vec(), 0);
    }
    let kept: Vec<FirewallRule> = rules
        .iter()
        .filter(|r| r.spec.executable.is_none())
        .cloned()
        .collect();
    let skipped = rules.len() - kept.len();
    (kept, skipped)
}

impl Firewall {
    pub fn start(
        hub: Arc<Hub>,
        helper: Arc<HelperClient>,
        settings: Arc<Settings>,
        store: Option<PathBuf>,
    ) -> Arc<Self> {
        let rules: Vec<FirewallRule> = load(&store)
            .into_iter()
            .zip(1..)
            .map(|(spec, rule_id)| FirewallRule { rule_id, spec })
            .collect();
        let firewall = Arc::new(Self {
            hub,
            helper,
            settings,
            store,
            next_id: AtomicU64::new(rules.len() as u64 + 1),
            rules: tokio::sync::Mutex::new(rules),
            prompts: Mutex::new(Prompts::default()),
        });
        tokio::spawn(firewall.clone().follow_helper());
        tokio::spawn(firewall.clone().follow_prompts());
        firewall
    }

    fn hello(&self) -> Option<HelperHello> {
        match &*self.helper.state().borrow() {
            HelperState::Connected { hello, .. } => Some(hello.clone()),
            HelperState::Disconnected(_) => None,
        }
    }

    /// Active, or degraded when `skipped` executable rules are not enforced.
    fn set_applied(&self, skipped: usize, hello: Option<&HelperHello>) {
        match hello.and_then(interception_missing).filter(|_| skipped > 0) {
            Some(reason) => self.hub.set_status(
                Module::Firewall,
                ModuleState::Degraded,
                Some(format!(
                    "{skipped} rule(s) scoped to an executable are not enforced: {reason}"
                )),
            ),
            None => self
                .hub
                .set_status(Module::Firewall, ModuleState::Active, None),
        }
    }

    /// Tracks the helper and re-applies the saved rules on every connect.
    async fn follow_helper(self: Arc<Self>) {
        let mut state = self.helper.state();
        loop {
            let current = state.borrow_and_update().clone();
            match current {
                HelperState::Disconnected(reason) => {
                    self.hub
                        .set_status(Module::Firewall, ModuleState::Unavailable, Some(reason))
                }
                HelperState::Connected { hello, .. } if !hello.firewall => self.hub.set_status(
                    Module::Firewall,
                    ModuleState::Unavailable,
                    Some("nft is not installed".into()),
                ),
                HelperState::Connected { hello, .. } => self.reapply(&hello).await,
            }
            if state.changed().await.is_err() {
                return;
            }
        }
    }

    async fn reapply(&self, hello: &HelperHello) {
        let rules = self.rules.lock().await;
        let (enforced, skipped) = enforceable(&rules, Some(hello));
        // An empty list needs no table; skipping it avoids a polkit prompt
        // at login for users who never added a rule.
        if enforced.is_empty() {
            self.set_applied(skipped, Some(hello));
            return;
        }
        match self
            .helper
            .request(HelperOp::FirewallApply { rules: enforced })
            .await
        {
            Ok(_) => {
                tracing::info!(rules = rules.len(), skipped, "firewall rules applied");
                self.set_applied(skipped, Some(hello));
            }
            Err(err) => {
                tracing::warn!("applying saved firewall rules: {err}");
                self.hub.set_status(
                    Module::Firewall,
                    ModuleState::Degraded,
                    Some(format!("saved rules are not applied: {err}")),
                );
            }
        }
    }

    pub async fn list(&self) -> FirewallRuleList {
        FirewallRuleList {
            rules: self.rules.lock().await.clone(),
        }
    }

    async fn commit(
        &self,
        rules: &mut Vec<FirewallRule>,
        next: Vec<FirewallRule>,
    ) -> Result<(), RpcError> {
        let hello = self.hello();
        let (enforced, skipped) = enforceable(&next, hello.as_ref());
        self.helper
            .request(HelperOp::FirewallApply { rules: enforced })
            .await
            .map_err(helper_error)?;
        *rules = next;
        self.set_applied(skipped, hello.as_ref());
        if let Err(err) = save(&self.store, rules) {
            tracing::warn!("saving firewall rules: {err}");
        }
        Ok(())
    }

    pub async fn add(&self, spec: FirewallRuleSpec) -> Result<FirewallRule, RpcError> {
        parse_prefix(&spec.address).map_err(RpcError::invalid_params)?;
        check_executable(&spec)?;
        if spec.executable.is_some()
            && let Some(reason) = self.hello().as_ref().and_then(interception_missing)
        {
            return Err(RpcError::new(
                ErrorCode::ModuleUnavailable,
                format!("rules scoped to an executable need connection interception: {reason}"),
            )
            .with_data(json!({ "module": "firewall" })));
        }
        let mut rules = self.rules.lock().await;
        let rule = FirewallRule {
            rule_id: self.next_id.fetch_add(1, Ordering::Relaxed),
            spec,
        };
        let mut next = rules.clone();
        next.push(rule.clone());
        self.commit(&mut rules, next).await?;
        tracing::info!(rule_id = rule.rule_id, "firewall rule added");
        Ok(rule)
    }

    pub async fn remove(&self, target: RuleTarget) -> Result<Empty, RpcError> {
        let mut rules = self.rules.lock().await;
        if !rules.iter().any(|r| r.rule_id == target.rule_id) {
            return Err(RpcError::new(
                ErrorCode::NotFound,
                format!("no firewall rule with id {}", target.rule_id),
            ));
        }
        let next = rules
            .iter()
            .filter(|r| r.rule_id != target.rule_id)
            .cloned()
            .collect();
        self.commit(&mut rules, next).await?;
        tracing::info!(rule_id = target.rule_id, "firewall rule removed");
        Ok(Empty {})
    }

    // ---------------------------------------------------------- prompts

    fn prompts(&self) -> std::sync::MutexGuard<'_, Prompts> {
        self.prompts.lock().expect("prompts lock")
    }

    /// The subscription the daemon wants now, if any.
    fn wanted(config: &Config, listeners: usize, helper: &HelperState) -> Option<Subscription> {
        let firewall = &config.firewall;
        let connected = matches!(helper, HelperState::Connected { hello, .. } if hello.connections);
        (firewall.prompt && listeners > 0 && connected)
            .then_some((firewall.prompt_timeout_secs, firewall.timeout_verdict))
    }

    /// Keeps the helper subscription in step with the configuration, the
    /// `firewall` listeners and the helper, and turns records into prompts.
    async fn follow_prompts(self: Arc<Self>) {
        let mut settings = self.settings.subscribe();
        let mut listeners = self.hub.listeners();
        let mut helper = self.helper.state();
        let mut records = self.helper.connections();
        let mut subscribed: Option<Subscription> = None;
        // A refused subscription is retried only once something changes.
        let mut refused: Option<Subscription> = None;
        loop {
            let config = settings.borrow_and_update().clone();
            let count = listeners
                .borrow_and_update()
                .get(&Topic::Firewall)
                .copied()
                .unwrap_or(0);
            let state = helper.borrow_and_update().clone();
            let wanted = Self::wanted(&config, count, &state);
            if wanted != subscribed && (wanted.is_none() || wanted != refused) {
                subscribed = self.resubscribe(subscribed, wanted).await;
                refused = if subscribed == wanted { None } else { wanted };
            }
            tokio::select! {
                changed = settings.changed() => if changed.is_err() { return },
                changed = listeners.changed() => if changed.is_err() { return },
                changed = helper.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    // Any change is a new helper connection, or none: the
                    // subscription and its held connections are gone.
                    if subscribed.take().is_some() {
                        self.end_prompts();
                    }
                    refused = None;
                    records = records.resubscribe();
                }
                record = records.recv() => match record {
                    Ok(record) => match subscribed {
                        Some(subscription) => self.prompt(record, subscription),
                        None => tracing::debug!(request_id = record.request_id, "ignoring a connection record while not subscribed"),
                    },
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("missed {n} connection records; the helper applies their timeout verdict");
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                },
            }
        }
    }

    /// Moves the helper subscription from `current` to `wanted`, and
    /// returns what is now in effect.
    async fn resubscribe(
        &self,
        current: Option<Subscription>,
        wanted: Option<Subscription>,
    ) -> Option<Subscription> {
        let Some((timeout_secs, timeout_verdict)) = wanted else {
            if let Err(err) = self.helper.request(HelperOp::ConnectionUnsubscribe).await {
                tracing::warn!("ending the connection subscription: {err}");
            }
            tracing::info!("connection prompts stopped");
            self.end_prompts();
            return None;
        };
        let op = HelperOp::ConnectionSubscribe {
            timeout_secs: (timeout_secs + HELPER_GRACE_SECS) as u32,
            timeout_verdict,
        };
        match self.helper.request(op).await {
            Ok(_) => {
                if current.is_none() {
                    self.prompts().subscription += 1;
                }
                tracing::info!(timeout_secs, ?timeout_verdict, "connection prompts started");
                wanted
            }
            Err(err) => {
                tracing::warn!("subscribing to connections for prompts: {err}");
                // The helper keeps a previous subscription it did not replace.
                current
            }
        }
    }

    /// Turns a held connection into a prompt, or adds it to the pending
    /// prompt that asks the same question.
    fn prompt(self: &Arc<Self>, record: ConnectionRecord, (timeout_secs, verdict): Subscription) {
        let key = PromptKey {
            executable: record.executable.clone(),
            address: record.address.clone(),
            port: record.port,
            protocol: record.protocol,
        };
        let mut prompts = self.prompts();
        if let Some(pending) = prompts.pending.values_mut().find(|p| p.key == key) {
            pending.held.push(record.request_id);
            return;
        }
        prompts.next_id += 1;
        let request_id = prompts.next_id;
        let subscription = prompts.subscription;
        prompts.pending.insert(
            request_id,
            Pending {
                key,
                held: vec![record.request_id],
                timeout_verdict: verdict,
                subscription,
            },
        );
        drop(prompts);
        let timeout = Duration::from_secs(timeout_secs);
        tracing::info!(request_id, pid = record.pid, executable = %record.executable,
            address = %record.address, port = record.port, "connection prompt");
        self.hub
            .emit(Event::FirewallConnectionPrompt(ConnectionPrompt {
                request_id,
                pid: record.pid,
                executable: record.executable,
                protocol: record.protocol,
                address: record.address,
                port: record.port,
                expires_at: now_ms() + timeout.as_millis() as u64,
            }));
        let this = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            this.expire(request_id).await;
        });
    }

    /// Takes a pending prompt, and whether its held ids are still valid.
    fn take(&self, request_id: u64) -> Option<(Pending, bool)> {
        let mut prompts = self.prompts();
        let pending = prompts.pending.remove(&request_id)?;
        let current = pending.subscription == prompts.subscription;
        Some((pending, current))
    }

    /// Answers every held connection of a prompt.
    async fn answer(&self, held: &[u64], verdict: Verdict, remember: Remember) {
        for &request_id in held {
            let op = HelperOp::ConnectionVerdict {
                request_id,
                verdict,
                remember,
            };
            match self.helper.request(op).await {
                // The helper already applied its own timeout.
                Ok(_)
                | Err(omarchy_security_proto::helper::HelperError {
                    kind: HelperErrorKind::NotFound,
                    ..
                }) => {}
                Err(err) => tracing::warn!(request_id, "answering a held connection: {err}"),
            }
        }
    }

    fn resolved(&self, request_id: u64, verdict: Verdict, decided_by: DecidedBy) {
        tracing::info!(
            request_id,
            ?verdict,
            ?decided_by,
            "connection prompt resolved"
        );
        self.hub
            .emit(Event::FirewallConnectionResolved(ConnectionResolved {
                request_id,
                verdict,
                decided_by,
            }));
    }

    async fn expire(&self, request_id: u64) {
        let Some((pending, current)) = self.take(request_id) else {
            return;
        };
        if current {
            self.answer(&pending.held, pending.timeout_verdict, Remember::None)
                .await;
        }
        self.resolved(request_id, pending.timeout_verdict, DecidedBy::Timeout);
    }

    /// Closes every prompt after the subscription ended; the helper has
    /// applied the timeout verdict to what it held.
    fn end_prompts(&self) {
        let pending: Vec<(u64, Pending)> = self.prompts().pending.drain().collect();
        for (request_id, pending) in pending {
            self.resolved(request_id, pending.timeout_verdict, DecidedBy::Timeout);
        }
    }

    pub async fn decide(&self, params: FirewallDecideParams) -> Result<Empty, RpcError> {
        let Some((pending, current)) = self.take(params.request_id) else {
            return Err(RpcError::new(
                ErrorCode::NotFound,
                format!(
                    "no pending connection prompt {} (already decided or expired)",
                    params.request_id
                ),
            ));
        };
        let remember = match params.scope {
            // The helper keeps it, keyed on pid and start time, until the
            // process exits.
            DecisionScope::Process => Remember::Process,
            DecisionScope::Once | DecisionScope::Always => Remember::None,
        };
        if current {
            self.answer(&pending.held, params.verdict, remember).await;
        }
        self.resolved(params.request_id, params.verdict, DecidedBy::User);
        if params.scope == DecisionScope::Always {
            let key = pending.key;
            let spec = FirewallRuleSpec {
                verdict: params.verdict,
                direction: Direction::Outbound,
                address: key.address,
                port: Some(key.port),
                protocol: Some(key.protocol),
                executable: Some(key.executable),
            };
            if self.rules.lock().await.iter().any(|r| r.spec == spec) {
                return Ok(Empty {});
            }
            self.add(spec).await?;
        }
        Ok(Empty {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper_client::tests::{FakeHelper, Respond, hello};
    use omarchy_security_proto::helper::HelperError;
    use serde_json::Value;
    use std::collections::HashSet;

    fn defaults() -> Arc<Settings> {
        Arc::new(Settings::load(None))
    }

    fn prompting(dir: &std::path::Path, timeout_secs: u64) -> Arc<Settings> {
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            format!("[firewall]\nprompt = true\nprompt_timeout_secs = {timeout_secs}\n"),
        )
        .unwrap();
        Arc::new(Settings::load(Some(path)))
    }

    fn intercepting() -> HelperHello {
        HelperHello {
            connections: true,
            ..hello(false)
        }
    }

    fn ok() -> Respond {
        Arc::new(|_| Ok(Value::Null))
    }

    fn record(request_id: u64, pid: u32, port: u16) -> ConnectionRecord {
        ConnectionRecord {
            request_id,
            pid,
            start_time: 99,
            uid: 1000,
            executable: "/usr/bin/curl".into(),
            protocol: Protocol::Tcp,
            address: "192.0.2.1".into(),
            port,
        }
    }

    fn listen(hub: &Hub, on: bool) {
        let (none, firewall) = (HashSet::new(), HashSet::from([Topic::Firewall]));
        if on {
            hub.set_topics(&none, &firewall);
        } else {
            hub.set_topics(&firewall, &none);
        }
    }

    async fn next_event(rx: &mut broadcast::Receiver<Event>, secs: u64) -> Event {
        let wait = async {
            loop {
                match rx.recv().await.unwrap() {
                    Event::ModuleStateChanged(_) => {}
                    event => return event,
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(secs), wait)
            .await
            .expect("an event in time")
    }

    async fn wait_request(fake: &FakeHelper, what: impl Fn(&HelperOp) -> bool) {
        for _ in 0..500 {
            if fake.requests.lock().unwrap().iter().any(&what) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("request never sent: {:?}", fake.requests.lock().unwrap());
    }

    fn verdicts(fake: &FakeHelper) -> Vec<(u64, Verdict, Remember)> {
        fake.requests
            .lock()
            .unwrap()
            .iter()
            .filter_map(|op| match op {
                HelperOp::ConnectionVerdict {
                    request_id,
                    verdict,
                    remember,
                } => Some((*request_id, *verdict, *remember)),
                _ => None,
            })
            .collect()
    }

    fn prompt_id(event: Event) -> ConnectionPrompt {
        match event {
            Event::FirewallConnectionPrompt(prompt) => prompt,
            other => panic!("expected a prompt, got {other:?}"),
        }
    }

    fn spec(address: &str) -> FirewallRuleSpec {
        FirewallRuleSpec {
            verdict: Verdict::Block,
            direction: Direction::Outbound,
            address: address.into(),
            port: Some(443),
            protocol: Some(Protocol::Tcp),
            executable: None,
        }
    }

    async fn wait_state(hub: &Hub, state: ModuleState) {
        for _ in 0..500 {
            if hub.status(Module::Firewall).state == state {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "firewall never became {state:?}: {:?}",
            hub.status(Module::Firewall)
        );
    }

    fn applied(fake: &FakeHelper) -> Vec<Vec<u64>> {
        fake.requests
            .lock()
            .unwrap()
            .iter()
            .filter_map(|op| match op {
                HelperOp::FirewallApply { rules } => {
                    Some(rules.iter().map(|r| r.rule_id).collect())
                }
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn rules_are_applied_saved_and_reapplied() {
        let fake = FakeHelper::start(hello(false), Arc::new(|_| Ok(Value::Null)));
        let store = fake.dir.path().join("state/firewall.json");
        let hub = Arc::new(Hub::new());
        let fw = Firewall::start(
            hub.clone(),
            HelperClient::start(fake.path()),
            defaults(),
            Some(store.clone()),
        );
        wait_state(&hub, ModuleState::Active).await;
        assert!(
            applied(&fake).is_empty(),
            "no rules: nothing applied at connect"
        );

        let a = fw.add(spec("192.0.2.0/24")).await.unwrap();
        let b = fw.add(spec("2001:db8::1")).await.unwrap();
        fw.remove(RuleTarget { rule_id: a.rule_id }).await.unwrap();
        assert_eq!(applied(&fake), [vec![1], vec![1, 2], vec![2]]);
        assert_eq!(fw.list().await.rules, std::slice::from_ref(&b));

        let err = fw.remove(RuleTarget { rule_id: 99 }).await.unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::NotFound));
        assert_eq!(
            fw.add(spec("example.com")).await.unwrap_err().kind(),
            Some(ErrorCode::InvalidParams)
        );
        // This helper does not intercept connections.
        let mut exe = spec("1.1.1.1");
        exe.executable = Some("/usr/bin/curl".into());
        assert_eq!(
            fw.add(exe).await.unwrap_err().kind(),
            Some(ErrorCode::ModuleUnavailable)
        );

        // A new daemon loads the saved rule and applies it on connect.
        let hub2 = Arc::new(Hub::new());
        let fw2 = Firewall::start(
            hub2.clone(),
            HelperClient::start(fake.path()),
            defaults(),
            Some(store),
        );
        wait_state(&hub2, ModuleState::Active).await;
        assert_eq!(fw2.list().await.rules.len(), 1);
        assert_eq!(fw2.list().await.rules[0].spec, b.spec);
        assert_eq!(applied(&fake).last().unwrap(), &vec![1]);
    }

    #[tokio::test]
    async fn a_refused_change_is_not_committed() {
        let respond: Respond = Arc::new(|op| match op {
            HelperOp::FirewallApply { .. } => Err(HelperError::new(
                HelperErrorKind::PermissionDenied,
                "not authorized",
            )),
            _ => Ok(Value::Null),
        });
        let fake = FakeHelper::start(hello(false), respond);
        let hub = Arc::new(Hub::new());
        let fw = Firewall::start(
            hub.clone(),
            HelperClient::start(fake.path()),
            defaults(),
            None,
        );
        wait_state(&hub, ModuleState::Active).await;
        let err = fw.add(spec("192.0.2.1")).await.unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::PermissionDenied));
        assert!(fw.list().await.rules.is_empty());
    }

    #[tokio::test]
    async fn unavailable_without_helper() {
        let dir = tempfile::tempdir().unwrap();
        let hub = Arc::new(Hub::new());
        let fw = Firewall::start(
            hub.clone(),
            HelperClient::start(dir.path().join("none.sock")),
            defaults(),
            None,
        );
        wait_state(&hub, ModuleState::Unavailable).await;
        let err = fw.add(spec("192.0.2.1")).await.unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::ModuleUnavailable));
    }

    #[tokio::test]
    async fn executable_rules_are_checked_and_skipped_without_interception() {
        let fake = FakeHelper::start(intercepting(), ok());
        let store = fake.dir.path().join("firewall.json");
        let hub = Arc::new(Hub::new());
        let fw = Firewall::start(
            hub.clone(),
            HelperClient::start(fake.path()),
            defaults(),
            Some(store.clone()),
        );
        wait_state(&hub, ModuleState::Active).await;
        let mut exe = spec("0.0.0.0/0");
        exe.executable = Some("/usr/bin/curl".into());
        fw.add(spec("192.0.2.1")).await.unwrap();
        fw.add(exe.clone()).await.unwrap();
        assert_eq!(applied(&fake).last().unwrap(), &vec![1, 2]);
        let mut relative = exe.clone();
        relative.executable = Some("curl".into());
        let mut inbound = exe.clone();
        inbound.direction = Direction::Inbound;
        for bad in [relative, inbound] {
            assert_eq!(
                fw.add(bad).await.unwrap_err().kind(),
                Some(ErrorCode::InvalidParams)
            );
        }

        // A helper that cannot intercept gets the other rules only.
        let plain = FakeHelper::start(hello(false), ok());
        let hub2 = Arc::new(Hub::new());
        let fw2 = Firewall::start(
            hub2.clone(),
            HelperClient::start(plain.path()),
            defaults(),
            Some(store),
        );
        wait_state(&hub2, ModuleState::Degraded).await;
        let detail = hub2.status(Module::Firewall).detail.unwrap();
        assert!(
            detail.contains("1 rule(s) scoped to an executable"),
            "{detail}"
        );
        assert_eq!(applied(&plain), [vec![1]]);
        // The rule stays saved and listed, and other changes still apply.
        fw2.remove(RuleTarget { rule_id: 1 }).await.unwrap();
        assert_eq!(applied(&plain).last().unwrap(), &Vec::<u64>::new());
        assert_eq!(fw2.list().await.rules.len(), 1);
    }

    #[tokio::test]
    async fn prompts_are_merged_decided_once_and_follow_listeners() {
        let fake = FakeHelper::start(intercepting(), ok());
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let fw = Firewall::start(
            hub.clone(),
            HelperClient::start(fake.path()),
            prompting(fake.dir.path(), 30),
            None,
        );
        wait_state(&hub, ModuleState::Active).await;
        // Nobody listens yet: no subscription.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(fake.requests.lock().unwrap().is_empty());

        listen(&hub, true);
        let subscribe = HelperOp::ConnectionSubscribe {
            timeout_secs: 35,
            timeout_verdict: Verdict::Block,
        };
        wait_request(&fake, |op| *op == subscribe).await;
        fake.connections.send(record(11, 100, 443)).unwrap();
        fake.connections.send(record(12, 200, 443)).unwrap();
        fake.connections.send(record(13, 100, 80)).unwrap();
        let first = prompt_id(next_event(&mut events, 5).await);
        let second = prompt_id(next_event(&mut events, 5).await);
        assert_eq!((first.pid, first.port, second.port), (100, 443, 80));
        assert!(first.expires_at > now_ms() + 25_000);

        let decide = |request_id, verdict, scope| FirewallDecideParams {
            request_id,
            verdict,
            scope,
        };
        fw.decide(decide(
            first.request_id,
            Verdict::Allow,
            DecisionScope::Process,
        ))
        .await
        .unwrap();
        assert_eq!(
            verdicts(&fake),
            [
                (11, Verdict::Allow, Remember::Process),
                (12, Verdict::Allow, Remember::Process)
            ]
        );
        assert_eq!(
            next_event(&mut events, 5).await,
            Event::FirewallConnectionResolved(ConnectionResolved {
                request_id: first.request_id,
                verdict: Verdict::Allow,
                decided_by: DecidedBy::User,
            })
        );
        let late = fw
            .decide(decide(
                first.request_id,
                Verdict::Block,
                DecisionScope::Once,
            ))
            .await
            .unwrap_err();
        assert_eq!(late.kind(), Some(ErrorCode::NotFound));

        // `always` answers once and saves an executable rule.
        fw.decide(decide(
            second.request_id,
            Verdict::Block,
            DecisionScope::Always,
        ))
        .await
        .unwrap();
        assert_eq!(
            verdicts(&fake).last().unwrap(),
            &(13, Verdict::Block, Remember::None)
        );
        let rules = fw.list().await.rules;
        assert_eq!(
            rules[0].spec,
            FirewallRuleSpec {
                verdict: Verdict::Block,
                direction: Direction::Outbound,
                address: "192.0.2.1".into(),
                port: Some(80),
                protocol: Some(Protocol::Tcp),
                executable: Some("/usr/bin/curl".into()),
            }
        );
        assert_eq!(applied(&fake), [vec![rules[0].rule_id]]);

        // The last listener leaves: the daemon unsubscribes, and a prompt
        // still pending closes with the timeout verdict.
        let _ = next_event(&mut events, 5).await; // resolved (second)
        fake.connections.send(record(14, 100, 8080)).unwrap();
        let third = prompt_id(next_event(&mut events, 5).await);
        listen(&hub, false);
        wait_request(&fake, |op| *op == HelperOp::ConnectionUnsubscribe).await;
        assert_eq!(
            next_event(&mut events, 5).await,
            Event::FirewallConnectionResolved(ConnectionResolved {
                request_id: third.request_id,
                verdict: Verdict::Block,
                decided_by: DecidedBy::Timeout,
            })
        );
        assert_eq!(verdicts(&fake).len(), 3, "the helper answers it itself");
    }

    #[tokio::test]
    async fn an_unanswered_prompt_times_out() {
        let fake = FakeHelper::start(intercepting(), ok());
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let _fw = Firewall::start(
            hub.clone(),
            HelperClient::start(fake.path()),
            prompting(fake.dir.path(), 5),
            None,
        );
        listen(&hub, true);
        wait_request(&fake, |op| {
            matches!(
                op,
                HelperOp::ConnectionSubscribe {
                    timeout_secs: 10,
                    ..
                }
            )
        })
        .await;
        fake.connections.send(record(21, 100, 443)).unwrap();
        let prompt = prompt_id(next_event(&mut events, 5).await);
        assert_eq!(
            next_event(&mut events, 8).await,
            Event::FirewallConnectionResolved(ConnectionResolved {
                request_id: prompt.request_id,
                verdict: Verdict::Block,
                decided_by: DecidedBy::Timeout,
            })
        );
        assert_eq!(verdicts(&fake), [(21, Verdict::Block, Remember::None)]);
    }
}
