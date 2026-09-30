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
//!
//! Mode (task 2.17): the daemon also tracks whether `ufw`, our table, both
//! or neither protect the machine (`ufw.rs`), from `ufw`'s files and the
//! helper's `firewall_inspect`. It re-checks every 30 s, after `ufw`'s files
//! change and whenever the helper connects or goes away, and emits
//! `FIREWALL_MODE_CHANGED` only on change. The module's status detail
//! starts with the mode, followed by any service that would undo the
//! ruleset (`nftables.service` flushing it, `firewalld`).
//!
//! Standalone policy (task 2.18): the helper renders the saved rules
//! without an `executable` only in `standalone` mode, next to a baseline
//! that mirrors Omarchy's `ufw` setup. Each rule reports whether it is
//! `loaded`. While `ufw` is active an inbound `allow` could not override
//! it, so adding one fails with `MODE_CONFLICT`.
//!
//! Switching modes (task 2.19): `FIREWALL_SET_MODE` has the helper turn
//! `ufw` off or on together with our table. The first switch to
//! `standalone` also saves `ufw`'s user rules as hub rules, where a hub rule
//! can express them.
//!
//! Blocked-traffic alerts (task 2.20): the daemon follows the kernel log
//! (`alerts.rs`), groups what `ufw` and the standalone policy dropped into
//! `FIREWALL_ALERT`s, and sends desktop notifications (`notify.rs`) whose
//! actions allow for an hour, mute, or open the hub. A mode change to
//! `both` or `none` is a notification too. Alerts need only the journal,
//! not the helper; without it the module is degraded.
//!
//! Temporary decisions (task 2.21, plan §5.20): `FIREWALL_TEMP_ADD` picks
//! the backend from the mode ([`temp_backend`]). `table` decisions are set
//! elements with kernel timeouts, `ufw` decisions are tagged `ufw` rules
//! that the helper deletes once expired. The daemon keeps the list, drops
//! each decision when it expires, re-sends the table ones when the helper
//! reconnects, takes over the ones a previous daemon left (from the helper
//! and from `user.rules`), and moves them to the other backend after a
//! mode switch.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use omarchy_security_proto::Event;
use omarchy_security_proto::events::{ConnectionPrompt, ConnectionResolved};
use omarchy_security_proto::helper::{
    ConnectionRecord, FirewallInspection, HelperErrorKind, HelperHello, HelperOp, HubMode,
    Remember, UfwTempChange,
};
use omarchy_security_proto::methods::{
    Empty, FirewallAlertList, FirewallAlertListParams, FirewallAlertMuteParams,
    FirewallDecideParams, FirewallRuleList, FirewallSetModeParams, FirewallTempAddParams,
    ImportedRule, NotImported, RuleTarget, SetModeResult, TempTarget, UfwRuleList,
};
use omarchy_security_proto::types::{
    AlertDirection, DecidedBy, DecisionScope, Direction, FirewallAlert, FirewallMode,
    FirewallModeKind, FirewallRule, FirewallRuleSpec, Module, ModuleState, Protocol, TempBackend,
    TempDecision, TempDecisionList, Topic, Verdict, check_temp_spec, parse_prefix,
};
use omarchy_security_proto::{ErrorCode, RpcError};
use serde_json::json;
use tokio::sync::{broadcast, mpsc};

use crate::alerts::{self, Alerts, AlertsEnv, Recorded};
use crate::config::{Config, Settings, TEMP_DURATION_SECS};
use crate::helper_client::{HelperClient, HelperState};
use crate::hub::Hub;
use crate::notify::{Action, Notifier};
use crate::now_ms;
use crate::ufw::{self, UfwEnv};

/// How much longer than a prompt the helper holds a connection, so that
/// the daemon's own expiry normally comes first.
const HELPER_GRACE_SECS: u64 = 5;

/// How often the mode is re-checked without a reason.
const MODE_POLL: Duration = Duration::from_secs(30);

/// `ufw` rewrites several files in a row; the mode is re-checked once they
/// have settled.
const MODE_SETTLE: Duration = Duration::from_millis(200);

/// "Allow for 1 h" in a notification.
const NOTIFY_ALLOW_SECS: u64 = 3600;
/// "Keep blocking, stop telling me" in a notification.
const NOTIFY_MUTE_SECS: u64 = 8 * 3600;

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
    /// Where `ufw`'s files are; `None` turns mode tracking off (tests).
    ufw: Option<UfwEnv>,
    status: Mutex<Status>,
    alerts: Mutex<Alerts>,
    /// Set once desktop notifications are available.
    notifier: OnceLock<Arc<Notifier>>,
    /// Serializes changes to the temporary decisions, like `rules`.
    temps: tokio::sync::Mutex<Vec<TempDecision>>,
    /// Starts at the current time, so ids stay unique across restarts.
    next_temp: AtomicU64,
    /// Wakes [`Self::follow_temps`] when the decisions change.
    temps_changed: tokio::sync::Notify,
}

/// The module status, and the mode its detail starts with. One lock, so
/// that the status published always matches both.
#[derive(Default)]
struct Status {
    /// Set once the helper's state is known.
    state: Option<(ModuleState, Option<String>)>,
    mode: Option<FirewallMode>,
    /// Services that would undo the ruleset, from [`ufw::conflicts`].
    conflicts: Vec<String>,
    /// Why blocked-traffic alerts are off, which degrades the module.
    alerts: Option<String>,
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

fn check_duration(secs: u64) -> Result<(), RpcError> {
    if TEMP_DURATION_SECS.contains(&secs) {
        Ok(())
    } else {
        Err(RpcError::invalid_params(format!(
            "duration_secs must be {}-{}",
            TEMP_DURATION_SECS.start(),
            TEMP_DURATION_SECS.end()
        )))
    }
}

fn table_decisions(decisions: &[TempDecision]) -> Vec<TempDecision> {
    decisions
        .iter()
        .filter(|d| d.backend == TempBackend::Table)
        .cloned()
        .collect()
}

/// Where a temporary decision goes in `mode` (plan §5.20). While `ufw` is
/// active only a `ufw` rule can let traffic through that `ufw` blocks: an
/// inbound allow, and an outbound one when `ufw`'s outbound policy is not
/// `accept`. Everything else is a table element.
pub fn temp_backend(
    mode: FirewallModeKind,
    default_output: Option<&str>,
    spec: &FirewallRuleSpec,
) -> Result<TempBackend, RpcError> {
    match mode {
        FirewallModeKind::Standalone => Ok(TempBackend::Table),
        FirewallModeKind::Ufw | FirewallModeKind::Both => {
            let ufw_blocks = match spec.direction {
                Direction::Inbound => true,
                Direction::Outbound => default_output.is_some_and(|p| p != "accept"),
            };
            Ok(if spec.verdict == Verdict::Allow && ufw_blocks {
                TempBackend::Ufw
            } else {
                TempBackend::Table
            })
        }
        FirewallModeKind::None | FirewallModeKind::Unknown => {
            let message = if mode == FirewallModeKind::None {
                "no firewall is active, so there is nothing to make a temporary exception in; \
                 turn on UFW or the Security Hub firewall first"
            } else {
                "the firewall mode is unknown (the privileged helper is not running)"
            };
            Err(RpcError::new(ErrorCode::ModeConflict, message).with_data(json!({ "mode": mode })))
        }
    }
}

/// The spec an alert's buttons act on: its protocol and port, and the
/// other end as a single host.
pub fn spec_from_alert(alert: &FirewallAlert, verdict: Verdict) -> Option<FirewallRuleSpec> {
    let protocol = match alert.protocol.as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        _ => return None,
    };
    let (direction, address) = match alert.direction {
        AlertDirection::Inbound => (Direction::Inbound, &alert.src),
        AlertDirection::Outbound => (Direction::Outbound, &alert.dst),
        AlertDirection::Forward => return None,
    };
    Some(FirewallRuleSpec {
        verdict,
        direction,
        address: address.clone(),
        port: Some(alert.dst_port?),
        protocol: Some(protocol),
        executable: None,
    })
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
        ufw: Option<UfwEnv>,
    ) -> Arc<Self> {
        let rules: Vec<FirewallRule> = load(&store)
            .into_iter()
            .zip(1..)
            .map(|(spec, rule_id)| FirewallRule {
                rule_id,
                spec,
                loaded: false,
            })
            .collect();
        let firewall = Arc::new(Self {
            hub,
            helper,
            settings,
            store,
            next_id: AtomicU64::new(rules.len() as u64 + 1),
            rules: tokio::sync::Mutex::new(rules),
            prompts: Mutex::new(Prompts::default()),
            status: Mutex::new(Status {
                state: None,
                mode: ufw
                    .as_ref()
                    .map(|env| ufw::derive(&ufw::read_conf(env), Err("not asked yet"))),
                conflicts: vec![],
                alerts: None,
            }),
            alerts: Mutex::new(Alerts::default()),
            notifier: OnceLock::new(),
            temps: tokio::sync::Mutex::new(vec![]),
            next_temp: AtomicU64::new(now_ms()),
            temps_changed: tokio::sync::Notify::new(),
            ufw,
        });
        firewall.adopt_ufw_temps();
        tokio::spawn(firewall.clone().follow_temps());
        tokio::spawn(firewall.clone().follow_helper());
        tokio::spawn(firewall.clone().follow_prompts());
        if let Some(env) = firewall.ufw.clone() {
            tokio::spawn(firewall.clone().follow_mode(env));
        }
        firewall
    }

    fn status(&self) -> std::sync::MutexGuard<'_, Status> {
        self.status.lock().expect("status lock")
    }

    fn set_status(&self, state: ModuleState, detail: Option<String>) {
        let mut status = self.status();
        status.state = Some((state, detail));
        self.publish(&status);
    }

    fn publish(&self, status: &Status) {
        let Some((mut state, detail)) = status.state.clone() else {
            return;
        };
        let alerts = status
            .alerts
            .as_ref()
            .map(|reason| format!("blocked-traffic alerts are off: {reason}"));
        if alerts.is_some() && state == ModuleState::Active {
            state = ModuleState::Degraded;
        }
        let parts: Vec<&str> = status
            .mode
            .as_ref()
            .map(|m| ufw::describe(m.mode))
            .into_iter()
            .chain(status.conflicts.iter().map(String::as_str))
            .chain(detail.as_deref())
            .chain(alerts.as_deref())
            .collect();
        let detail = (!parts.is_empty()).then(|| parts.join("; "));
        self.hub.set_status(Module::Firewall, state, detail);
    }

    // ------------------------------------------------------------- mode

    fn unavailable_mode() -> RpcError {
        RpcError::new(ErrorCode::ModuleUnavailable, "ufw detection is off")
            .with_data(json!({ "module": "firewall" }))
    }

    pub fn mode(&self) -> Result<FirewallMode, RpcError> {
        self.status()
            .mode
            .clone()
            .ok_or_else(Self::unavailable_mode)
    }

    pub async fn ufw_rules(&self) -> Result<UfwRuleList, RpcError> {
        let env = self.ufw.clone().ok_or_else(Self::unavailable_mode)?;
        tokio::task::spawn_blocking(move || ufw::read_rules(&env))
            .await
            .map_err(|e| RpcError::new(ErrorCode::InternalError, e.to_string()))
    }

    /// Re-checks the mode every [`MODE_POLL`], after `ufw`'s files change,
    /// and on every helper change.
    async fn follow_mode(self: Arc<Self>, env: UfwEnv) {
        let (tx, mut changes) = mpsc::channel(1);
        tokio::spawn({
            let env = env.clone();
            async move {
                if let Err(err) = ufw::watch(env, tx).await {
                    tracing::warn!("not watching ufw's files ({err}); checking every 30 s only");
                }
            }
        });
        let mut helper = self.helper.state();
        loop {
            self.refresh_mode(&env).await;
            tokio::select! {
                _ = tokio::time::sleep(MODE_POLL) => {}
                Some(()) = changes.recv() => {
                    tokio::time::sleep(MODE_SETTLE).await;
                    let _ = changes.try_recv();
                }
                changed = helper.changed() => if changed.is_err() { return },
            }
        }
    }

    async fn refresh_mode(&self, env: &UfwEnv) {
        let state = self.helper.state().borrow().clone();
        let inspection: Result<FirewallInspection, String> = match state {
            HelperState::Disconnected(reason) => Err(reason),
            HelperState::Connected { hello, .. } if !hello.firewall => {
                Err("nft is not installed".into())
            }
            HelperState::Connected { .. } => self
                .helper
                .request(HelperOp::FirewallInspect)
                .await
                .map_err(|e| e.to_string())
                .and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string())),
        };
        self.record_mode(env, inspection).await;
    }

    /// Derives the mode from `ufw`'s files and `inspection`, and publishes
    /// it if it changed.
    async fn record_mode(&self, env: &UfwEnv, inspection: Result<FirewallInspection, String>) {
        let conf = {
            let env = env.clone();
            tokio::task::spawn_blocking(move || ufw::read_conf(&env))
                .await
                .unwrap_or_default()
        };
        let held = inspection
            .as_ref()
            .map(|i| i.temp.clone())
            .unwrap_or_default();
        self.adopt_temps(held).await;
        let mut mode = ufw::derive(&conf, inspection.as_ref().map_err(String::as_str));
        let conflicts = ufw::conflicts(env).await;
        if !conflicts.is_empty() {
            let detail = mode
                .detail
                .take()
                .into_iter()
                .chain(conflicts.iter().cloned());
            mode.detail = Some(detail.collect::<Vec<_>>().join("; "));
        }
        let mut status = self.status();
        status.conflicts = conflicts;
        if status.mode.as_ref() == Some(&mode) {
            return;
        }
        tracing::info!(mode = ?mode.mode, detail = mode.detail.as_deref().unwrap_or(""), "firewall mode");
        status.mode = Some(mode.clone());
        self.publish(&status);
        drop(status);
        if let Some(notifier) = self.notifier.get().cloned() {
            let kind = mode.mode;
            tokio::spawn(async move { notifier.mode(kind).await });
        }
        self.hub.emit(Event::FirewallModeChanged(mode));
    }

    /// Takes over the table decisions the helper holds that this daemon
    /// does not know: those of a daemon that ran before.
    async fn adopt_temps(&self, held: Vec<TempDecision>) {
        if held.is_empty() {
            return;
        }
        let mut temps = self.temps.lock().await;
        let before = temps.len();
        for decision in held {
            if !temps.iter().any(|d| d.temp_id == decision.temp_id) {
                tracing::info!(
                    temp_id = decision.temp_id,
                    "taking over a temporary decision"
                );
                temps.push(decision);
            }
        }
        if temps.len() != before {
            self.temps_changed.notify_one();
            self.emit_temps(&temps);
        }
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
            Some(reason) => self.set_status(
                ModuleState::Degraded,
                Some(format!(
                    "{skipped} rule(s) scoped to an executable are not enforced: {reason}"
                )),
            ),
            None => self.set_status(ModuleState::Active, None),
        }
    }

    /// Tracks the helper and re-applies the saved rules on every connect.
    async fn follow_helper(self: Arc<Self>) {
        let mut state = self.helper.state();
        loop {
            let current = state.borrow_and_update().clone();
            match current {
                HelperState::Disconnected(reason) => {
                    self.set_status(ModuleState::Unavailable, Some(reason))
                }
                HelperState::Connected { hello, .. } if !hello.firewall => self.set_status(
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
        self.reapply_rules(hello).await;
        self.restore_temps().await;
    }

    async fn reapply_rules(&self, hello: &HelperHello) {
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
                self.set_status(
                    ModuleState::Degraded,
                    Some(format!("saved rules are not applied: {err}")),
                );
            }
        }
    }

    /// Whether rules without an `executable` are in the kernel: our table
    /// holds them in `standalone` mode, and in `both`.
    fn table_enforces(&self) -> bool {
        matches!(
            self.status().mode.as_ref().map(|m| m.mode),
            Some(FirewallModeKind::Standalone | FirewallModeKind::Both)
        )
    }

    /// Sets `loaded` on each rule from the mode and the helper.
    fn mark_loaded(&self, rules: &mut [FirewallRule]) {
        let hello = self.hello().filter(|h| h.firewall);
        let table = hello.is_some() && self.table_enforces();
        let queue = hello.is_some_and(|h| h.connections);
        for rule in rules {
            rule.loaded = match rule.spec.executable {
                Some(_) => queue,
                None => table,
            };
        }
    }

    pub async fn list(&self) -> FirewallRuleList {
        let mut rules = self.rules.lock().await.clone();
        self.mark_loaded(&mut rules);
        FirewallRuleList { rules }
    }

    /// An inbound `allow` while `ufw` is active would be saved but have no
    /// effect: `ufw`'s drop is final whatever our table accepts.
    fn check_mode(&self, spec: &FirewallRuleSpec) -> Result<(), RpcError> {
        if spec.executable.is_some()
            || spec.direction != Direction::Inbound
            || spec.verdict != Verdict::Allow
        {
            return Ok(());
        }
        let mode = self.status().mode.as_ref().map(|m| m.mode);
        match mode {
            Some(mode @ (FirewallModeKind::Ufw | FirewallModeKind::Both)) => Err(RpcError::new(
                ErrorCode::ModeConflict,
                "ufw is active and decides inbound traffic, so this allow would have no effect. \
                 Allow it with `sudo ufw allow` instead, or switch to the Security Hub firewall.",
            )
            .with_data(json!({ "mode": mode }))),
            _ => Ok(()),
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
        self.check_mode(&spec)?;
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
        let mut rule = FirewallRule {
            rule_id: self.next_id.fetch_add(1, Ordering::Relaxed),
            spec,
            loaded: false,
        };
        let mut next = rules.clone();
        next.push(rule.clone());
        self.commit(&mut rules, next).await?;
        tracing::info!(rule_id = rule.rule_id, "firewall rule added");
        self.mark_loaded(std::slice::from_mut(&mut rule));
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

    /// Whether `ufw`'s rules were imported once already, which makes later
    /// switches to `standalone` skip the import unless asked.
    fn import_marker(&self) -> Option<PathBuf> {
        self.store
            .as_ref()
            .map(|p| p.with_file_name("ufw-imported"))
    }

    /// `FIREWALL_SET_MODE` (plan §5.18): the helper switches `ufw` and our
    /// table in an order that never leaves the machine unprotected. The
    /// rules imported from `ufw` are committed only if the switch succeeds.
    /// With `dry_run`, nothing is switched or saved: the result is the
    /// current mode and what the switch would import (with `rule_id` 0).
    pub async fn set_mode(&self, params: FirewallSetModeParams) -> Result<SetModeResult, RpcError> {
        let env = self.ufw.clone().ok_or_else(Self::unavailable_mode)?;
        let mut rules = self.rules.lock().await;
        let marker = self.import_marker();
        let import = params.mode == HubMode::Standalone
            && params
                .import_ufw_rules
                .unwrap_or_else(|| marker.as_ref().is_some_and(|m| !m.exists()));
        let mut next = rules.clone();
        let mut imported = vec![];
        let mut not_imported = vec![];
        if import {
            let found = {
                let env = env.clone();
                tokio::task::spawn_blocking(move || ufw::read_rules(&env))
                    .await
                    .map_err(|e| RpcError::new(ErrorCode::InternalError, e.to_string()))?
            };
            let (converted, skipped) = ufw::import(&found.rules);
            for ufw::Imported { spec, from, notes } in converted {
                if next.iter().any(|r| r.spec == spec) {
                    continue;
                }
                let rule = FirewallRule {
                    rule_id: if params.dry_run {
                        0
                    } else {
                        self.next_id.fetch_add(1, Ordering::Relaxed)
                    },
                    spec,
                    // As it will be once the switch is done.
                    loaded: params.dry_run,
                };
                next.push(rule.clone());
                imported.push(ImportedRule { rule, from, notes });
            }
            not_imported = skipped
                .into_iter()
                .map(|(from, reason)| NotImported { from, reason })
                .collect();
        }
        if params.dry_run {
            return Ok(SetModeResult {
                mode: self.mode()?,
                imported,
                not_imported,
            });
        }
        let hello = self.hello();
        let (enforced, skipped) = enforceable(&next, hello.as_ref());
        let switched = self
            .helper
            .request(HelperOp::FirewallSetMode {
                mode: params.mode,
                rules: enforced,
            })
            .await;
        let inspection = match switched {
            Ok(value) => value,
            Err(err) => {
                tracing::warn!(
                    mode = params.mode.as_str(),
                    "switching the firewall mode: {err}"
                );
                // A failure part-way may leave both firewalls enforcing.
                drop(rules);
                self.refresh_mode(&env).await;
                return Err(helper_error(err));
            }
        };
        *rules = next;
        self.set_applied(skipped, hello.as_ref());
        if let Err(err) = save(&self.store, &rules) {
            tracing::warn!("saving firewall rules: {err}");
        }
        if import && let Some(marker) = &marker {
            if let Err(err) = std::fs::write(marker, b"") {
                tracing::warn!("writing {}: {err}", marker.display());
            }
        }
        tracing::info!(
            mode = params.mode.as_str(),
            imported = imported.len(),
            not_imported = not_imported.len(),
            "firewall mode switched"
        );
        drop(rules);
        let inspection = serde_json::from_value(inspection).map_err(|e| e.to_string());
        self.record_mode(&env, inspection).await;
        self.rebalance_temps().await;
        for item in &mut imported {
            self.mark_loaded(std::slice::from_mut(&mut item.rule));
        }
        Ok(SetModeResult {
            mode: self.mode()?,
            imported,
            not_imported,
        })
    }

    // ----------------------------------------------------------- alerts

    fn alerts(&self) -> std::sync::MutexGuard<'_, Alerts> {
        self.alerts.lock().expect("alerts lock")
    }

    fn set_alerts_state(&self, reason: Option<String>) {
        let mut status = self.status();
        if status.alerts != reason {
            status.alerts = reason;
            self.publish(&status);
        }
    }

    /// Starts reading the kernel log for blocked traffic, and, with a
    /// notifier, desktop notifications and their actions.
    pub fn start_alerts(
        self: &Arc<Self>,
        env: AlertsEnv,
        notifications: Option<(Arc<Notifier>, mpsc::Receiver<Action>)>,
    ) {
        let (lines_tx, lines) = mpsc::channel(64);
        let (state_tx, states) = mpsc::channel(8);
        tokio::spawn(alerts::follow(env.clone(), lines_tx, state_tx));
        tokio::spawn(self.clone().follow_alerts(lines, states));
        if let Some((notifier, actions)) = notifications {
            let _ = self.notifier.set(notifier.clone());
            if let Some(mode) = self.status().mode.as_ref().map(|m| m.mode) {
                tokio::spawn(async move { notifier.mode(mode).await });
            }
            tokio::spawn(self.clone().follow_actions(actions, env.open_hub));
        }
    }

    async fn follow_alerts(
        self: Arc<Self>,
        mut lines: mpsc::Receiver<alerts::LogLine>,
        mut states: mpsc::Receiver<alerts::FollowerState>,
    ) {
        loop {
            tokio::select! {
                line = lines.recv() => match line {
                    Some((message, at)) => self.on_blocked(&message, at),
                    None => return,
                },
                Some(state) = states.recv() => self.set_alerts_state(state),
            }
        }
    }

    /// Turns one kernel log line into a new or updated alert.
    fn on_blocked(self: &Arc<Self>, message: &str, at: Option<u64>) {
        let Some(packet) = alerts::parse_line(message) else {
            tracing::debug!("unparsed firewall log line: {message}");
            return;
        };
        let config = self.settings.current();
        let settings = &config.firewall.alerts;
        if alerts::ignored(&packet, settings) {
            return;
        }
        let at = at.unwrap_or_else(now_ms);
        let recorded = self
            .alerts()
            .record(&packet, at, settings.window_secs * 1000);
        match recorded {
            Recorded::New(alert) => self.emit_alert(alert, true),
            Recorded::Updated {
                alert,
                emit,
                flush_in_ms,
            } => {
                if emit {
                    self.emit_alert(alert.clone(), false);
                }
                if let Some(ms) = flush_in_ms {
                    let this = self.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        let flushed = this.alerts().flush(alert.alert_id, now_ms());
                        if let Some(alert) = flushed {
                            this.emit_alert(alert, false);
                        }
                    });
                }
            }
        }
    }

    fn emit_alert(&self, alert: FirewallAlert, new: bool) {
        if new {
            tracing::info!(alert_id = alert.alert_id, direction = ?alert.direction,
                protocol = %alert.protocol, src = %alert.src, port = ?alert.dst_port, "traffic blocked");
        }
        let config = self.settings.current();
        let settings = &config.firewall.alerts;
        if settings.notify
            && let Some(notifier) = self.notifier.get().cloned()
        {
            let (alert, per_minute) = (alert.clone(), settings.max_notifications_per_minute);
            tokio::spawn(async move { notifier.alert(&alert, new, now_ms(), per_minute).await });
        }
        self.hub.emit(Event::FirewallAlert(alert));
    }

    pub fn alert_list(&self, params: FirewallAlertListParams) -> FirewallAlertList {
        FirewallAlertList {
            alerts: self.alerts().list(params.limit, now_ms()),
        }
    }

    pub fn alert_mute(&self, params: FirewallAlertMuteParams) -> Result<Empty, RpcError> {
        check_duration(params.duration_secs)?;
        let until = now_ms() + params.duration_secs * 1000;
        let alert = self.alerts().mute(params.alert_id, until).ok_or_else(|| {
            RpcError::new(
                ErrorCode::NotFound,
                format!("no firewall alert with id {}", params.alert_id),
            )
        })?;
        tracing::info!(alert_id = params.alert_id, until, "firewall alert muted");
        self.hub.emit(Event::FirewallAlert(alert));
        Ok(Empty {})
    }

    /// Carries out what the user picked in a notification.
    async fn follow_actions(
        self: Arc<Self>,
        mut actions: mpsc::Receiver<Action>,
        open_hub: Vec<String>,
    ) {
        while let Some(action) = actions.recv().await {
            let this = self.clone();
            let open_hub = open_hub.clone();
            // Each may wait for a polkit prompt; the others must not.
            tokio::spawn(async move { this.act(action, &open_hub).await });
        }
    }

    async fn act(&self, action: Action, open_hub: &[String]) {
        let failed = match action {
            Action::Open => {
                if let Some((program, args)) = open_hub.split_first() {
                    let run = tokio::process::Command::new(program)
                        .args(args)
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .await;
                    if let Err(err) = run {
                        tracing::warn!("opening the hub with {program}: {err}");
                    }
                }
                None
            }
            Action::Allow(alert_id) => {
                let alert = self.alerts().get(alert_id).cloned();
                let spec = alert
                    .as_ref()
                    .and_then(|a| spec_from_alert(a, Verdict::Allow));
                match spec {
                    Some(spec) => self
                        .temp_add(FirewallTempAddParams {
                            spec,
                            duration_secs: NOTIFY_ALLOW_SECS,
                            alert_id: Some(alert_id),
                        })
                        .await
                        .err()
                        .map(|e| ("Could not allow the connection", e)),
                    None => Some((
                        "Could not allow the connection",
                        RpcError::new(
                            ErrorCode::NotFound,
                            "the alert is gone or cannot be allowed",
                        ),
                    )),
                }
            }
            Action::Mute(alert_id) => self
                .alert_mute(FirewallAlertMuteParams {
                    alert_id,
                    duration_secs: NOTIFY_MUTE_SECS,
                })
                .err()
                .map(|e| ("Could not mute the alert", e)),
            Action::SetMode(mode) => self
                .set_mode(FirewallSetModeParams {
                    mode,
                    import_ufw_rules: None,
                    dry_run: false,
                })
                .await
                .err()
                .map(|e| ("Could not switch the firewall", e)),
        };
        if let Some((summary, err)) = failed {
            tracing::warn!(?action, "notification action failed: {err}");
            // A refused or cancelled password prompt needs no second word.
            if err.kind() != Some(ErrorCode::PermissionDenied)
                && let Some(notifier) = self.notifier.get()
            {
                notifier.error(summary, &err.message).await;
            }
        }
    }

    // -------------------------------------------------- temporary decisions

    fn emit_temps(&self, decisions: &[TempDecision]) {
        self.hub.emit(Event::FirewallTempChanged(TempDecisionList {
            decisions: decisions.to_vec(),
            durations_secs: vec![],
        }));
    }

    /// Takes over the tagged `ufw` rules a previous daemon added; the
    /// comment carries each one's id and expiry.
    fn adopt_ufw_temps(&self) {
        let Some(env) = &self.ufw else { return };
        let now = now_ms();
        let found: Vec<TempDecision> = ufw::read_rules(env)
            .rules
            .iter()
            .filter_map(omarchy_security_proto::ufw::temp_decision)
            .filter(|d| d.expires_at > now)
            .collect();
        let mut temps = self.temps.try_lock().expect("nothing else runs yet");
        for decision in found {
            if !temps.iter().any(|d| d.temp_id == decision.temp_id) {
                tracing::info!(
                    temp_id = decision.temp_id,
                    "taking over a temporary ufw rule"
                );
                temps.push(decision);
            }
        }
    }

    /// After the helper (re)connects: gives it back the table decisions
    /// it lost when it restarted.
    async fn restore_temps(&self) {
        let temps = self.temps.lock().await;
        let now = now_ms();
        let table: Vec<TempDecision> = table_decisions(&temps)
            .into_iter()
            .filter(|d| d.expires_at > now)
            .collect();
        if !table.is_empty()
            && let Err(err) = self
                .helper
                .request(HelperOp::FirewallTempSet { decisions: table })
                .await
        {
            tracing::warn!("restoring temporary decisions: {err}");
        }
    }

    /// Drops each decision when it expires.
    async fn follow_temps(self: Arc<Self>) {
        loop {
            let next = self.temps.lock().await.iter().map(|d| d.expires_at).min();
            let wait = next.map(|at| Duration::from_millis(at.saturating_sub(now_ms())));
            tokio::select! {
                _ = tokio::time::sleep(wait.unwrap_or(Duration::MAX)), if wait.is_some() => {
                    self.expire_temps().await;
                }
                _ = self.temps_changed.notified() => {}
            }
        }
    }

    async fn expire_temps(&self) {
        let mut temps = self.temps.lock().await;
        let now = now_ms();
        let (expired, live): (Vec<TempDecision>, Vec<TempDecision>) =
            temps.drain(..).partition(|d| d.expires_at <= now);
        *temps = live;
        if expired.is_empty() {
            return;
        }
        for decision in expired {
            tracing::info!(temp_id = decision.temp_id, backend = ?decision.backend, "temporary decision expired");
            // The kernel has dropped a table element already; a ufw rule
            // the helper's sweep would catch within 30 s.
            if decision.backend == TempBackend::Ufw {
                self.delete_ufw_temp(&decision).await;
            }
        }
        self.emit_temps(&temps);
    }

    fn current_backend(&self, spec: &FirewallRuleSpec) -> Result<TempBackend, RpcError> {
        let status = self.status();
        let mode = status.mode.as_ref().ok_or_else(Self::unavailable_mode)?;
        temp_backend(mode.mode, mode.ufw.default_output.as_deref(), spec)
    }

    /// `FIREWALL_TEMP_ADD`. A decision for the same traffic and verdict
    /// replaces the earlier one.
    pub async fn temp_add(&self, params: FirewallTempAddParams) -> Result<TempDecision, RpcError> {
        check_duration(params.duration_secs)?;
        check_temp_spec(&params.spec).map_err(RpcError::invalid_params)?;
        let backend = self.current_backend(&params.spec)?;
        let now = now_ms();
        let decision = TempDecision {
            temp_id: self.next_temp.fetch_add(1, Ordering::Relaxed),
            spec: params.spec,
            backend,
            created_at: now,
            expires_at: now + params.duration_secs * 1000,
            alert_id: params.alert_id,
        };
        let mut temps = self.temps.lock().await;
        temps.retain(|d| d.expires_at > now);
        let replaced: Vec<TempDecision> = temps
            .iter()
            .filter(|d| d.spec == decision.spec)
            .cloned()
            .collect();
        let mut next: Vec<TempDecision> = temps
            .iter()
            .filter(|d| d.spec != decision.spec)
            .cloned()
            .collect();
        next.push(decision.clone());
        if backend == TempBackend::Ufw {
            self.helper
                .request(HelperOp::UfwTemp {
                    change: UfwTempChange::Add,
                    decision: decision.clone(),
                })
                .await
                .map_err(helper_error)?;
        }
        let table = table_decisions(&next);
        if table != table_decisions(&temps)
            && let Err(err) = self
                .helper
                .request(HelperOp::FirewallTempSet { decisions: table })
                .await
        {
            if backend == TempBackend::Ufw {
                self.delete_ufw_temp(&decision).await;
            }
            return Err(helper_error(err));
        }
        for old in replaced.iter().filter(|d| d.backend == TempBackend::Ufw) {
            self.delete_ufw_temp(old).await;
        }
        *temps = next;
        tracing::info!(temp_id = decision.temp_id, backend = ?backend,
            verdict = ?decision.spec.verdict, direction = ?decision.spec.direction,
            address = %decision.spec.address, secs = params.duration_secs, "temporary decision added");
        self.temps_changed.notify_one();
        self.emit_temps(&temps);
        Ok(decision)
    }

    async fn delete_ufw_temp(&self, decision: &TempDecision) {
        let op = HelperOp::UfwTemp {
            change: UfwTempChange::Delete,
            decision: decision.clone(),
        };
        if let Err(err) = self.helper.request(op).await {
            tracing::warn!(
                temp_id = decision.temp_id,
                "deleting a temporary ufw rule: {err}"
            );
        }
    }

    pub async fn temp_list(&self) -> TempDecisionList {
        let now = now_ms();
        let decisions = self
            .temps
            .lock()
            .await
            .iter()
            .filter(|d| d.expires_at > now)
            .cloned()
            .collect();
        TempDecisionList {
            decisions,
            durations_secs: self
                .settings
                .current()
                .firewall
                .alerts
                .temp_durations_secs
                .clone(),
        }
    }

    pub async fn temp_remove(&self, target: TempTarget) -> Result<Empty, RpcError> {
        let mut temps = self.temps.lock().await;
        let Some(decision) = temps.iter().find(|d| d.temp_id == target.temp_id).cloned() else {
            return Err(RpcError::new(
                ErrorCode::NotFound,
                format!(
                    "no temporary decision with id {} (it may have expired)",
                    target.temp_id
                ),
            ));
        };
        let next: Vec<TempDecision> = temps
            .iter()
            .filter(|d| d.temp_id != target.temp_id)
            .cloned()
            .collect();
        let op = match decision.backend {
            TempBackend::Ufw => HelperOp::UfwTemp {
                change: UfwTempChange::Delete,
                decision,
            },
            TempBackend::Table => HelperOp::FirewallTempSet {
                decisions: table_decisions(&next),
            },
        };
        self.helper.request(op).await.map_err(helper_error)?;
        *temps = next;
        tracing::info!(temp_id = target.temp_id, "temporary decision removed");
        self.emit_temps(&temps);
        Ok(Empty {})
    }

    /// After a mode switch, moves each decision to the backend the new
    /// mode needs: an inbound allow becomes a `ufw` rule when `ufw` is back
    /// on, and a table element when it is off.
    async fn rebalance_temps(&self) {
        let mut temps = self.temps.lock().await;
        let mut next = temps.clone();
        let mut changed = false;
        for decision in &mut next {
            let Ok(want) = self.current_backend(&decision.spec) else {
                continue;
            };
            if want == decision.backend {
                continue;
            }
            let moved = TempDecision {
                backend: want,
                ..decision.clone()
            };
            match want {
                TempBackend::Ufw => {
                    let op = HelperOp::UfwTemp {
                        change: UfwTempChange::Add,
                        decision: moved.clone(),
                    };
                    if let Err(err) = self.helper.request(op).await {
                        tracing::warn!(
                            temp_id = decision.temp_id,
                            "moving a temporary decision to ufw: {err}"
                        );
                        continue;
                    }
                }
                TempBackend::Table => self.delete_ufw_temp(decision).await,
            }
            *decision = moved;
            changed = true;
        }
        if !changed {
            return;
        }
        if let Err(err) = self
            .helper
            .request(HelperOp::FirewallTempSet {
                decisions: table_decisions(&next),
            })
            .await
        {
            tracing::warn!("moving temporary decisions to the table: {err}");
        }
        *temps = next;
        tracing::info!("temporary decisions moved to the new mode's backend");
        self.emit_temps(&temps);
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
    use omarchy_security_proto::types::FirewallModeKind;
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
            None,
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
            None,
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
            None,
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
            None,
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

    async fn next_mode(rx: &mut broadcast::Receiver<Event>) -> FirewallMode {
        match next_event(rx, 5).await {
            Event::FirewallModeChanged(mode) => mode,
            other => panic!("expected a mode change, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn tracks_the_mode_and_serves_ufw_rules() {
        use omarchy_security_proto::types::{DockerProtection, FirewallModeKind};
        let root = crate::ufw::tests::omarchy_root();
        let inspection = Arc::new(Mutex::new(
            json!({"ufw_chains_loaded": true, "table_loaded": false}),
        ));
        let respond: Respond = Arc::new({
            let inspection = inspection.clone();
            move |op| match op {
                HelperOp::FirewallInspect => Ok(inspection.lock().unwrap().clone()),
                _ => Ok(Value::Null),
            }
        });
        let fake = FakeHelper::start(hello(false), respond);
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let env = UfwEnv::at(root.path());
        let fw = Firewall::start(
            hub.clone(),
            HelperClient::start(fake.path()),
            defaults(),
            None,
            Some(env),
        );
        // The first check may run before the helper is connected.
        let mut mode = next_mode(&mut events).await;
        if mode.mode == FirewallModeKind::Unknown {
            mode = next_mode(&mut events).await;
        }
        assert_eq!(mode.mode, FirewallModeKind::Ufw);
        assert_eq!(mode.docker_protection, DockerProtection::UfwDocker);
        assert_eq!(mode.ufw.default_input.as_deref(), Some("drop"));
        assert_eq!(mode.table_loaded, Some(false));
        assert_eq!(fw.mode().unwrap(), mode);
        wait_state(&hub, ModuleState::Active).await;
        assert_eq!(
            hub.status(Module::Firewall).detail.as_deref(),
            Some("ufw is active")
        );

        // `ufw disable` rewrites ufw.conf and unloads the chains.
        *inspection.lock().unwrap() = json!({"ufw_chains_loaded": false, "table_loaded": false});
        let conf = root.path().join("etc/ufw/ufw.conf");
        std::fs::write(conf.with_extension("new"), "ENABLED=no\nLOGLEVEL=low\n").unwrap();
        std::fs::rename(conf.with_extension("new"), &conf).unwrap();
        let mode = next_mode(&mut events).await;
        assert_eq!(mode.mode, FirewallModeKind::None);
        assert!(!mode.ufw.enabled_in_conf);
        assert_eq!(mode.docker_protection, DockerProtection::None);
        for _ in 0..100 {
            if hub.status(Module::Firewall).detail.as_deref() == Some("no firewall is active") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            hub.status(Module::Firewall).detail.as_deref(),
            Some("no firewall is active")
        );

        let rules = fw.ufw_rules().await.unwrap();
        assert_eq!(rules.rules.len(), 3);
        assert_eq!(rules.rules[0].port.as_deref(), Some("53317"));
    }

    #[tokio::test]
    async fn rules_follow_the_mode() {
        use omarchy_security_proto::types::FirewallModeKind;
        let root = crate::ufw::tests::omarchy_root();
        let inspection = Arc::new(Mutex::new(
            json!({"ufw_chains_loaded": true, "table_loaded": false}),
        ));
        let respond: Respond = Arc::new({
            let inspection = inspection.clone();
            move |op| match op {
                HelperOp::FirewallInspect => Ok(inspection.lock().unwrap().clone()),
                _ => Ok(Value::Null),
            }
        });
        let fake = FakeHelper::start(hello(false), respond);
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let fw = Firewall::start(
            hub.clone(),
            HelperClient::start(fake.path()),
            defaults(),
            None,
            Some(UfwEnv::at(root.path())),
        );
        while next_mode(&mut events).await.mode != FirewallModeKind::Ufw {}
        wait_state(&hub, ModuleState::Active).await;

        // In ufw mode rules are saved but not loaded, and an inbound allow
        // is refused.
        let block = fw.add(spec("192.0.2.1")).await.unwrap();
        assert!(!block.loaded);
        let inbound_allow = FirewallRuleSpec {
            verdict: Verdict::Allow,
            direction: Direction::Inbound,
            ..spec("0.0.0.0/0")
        };
        let err = fw.add(inbound_allow.clone()).await.unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::ModeConflict));
        assert!(err.message.contains("sudo ufw allow"), "{}", err.message);
        let inbound_block = FirewallRuleSpec {
            direction: Direction::Inbound,
            ..spec("203.0.113.0/24")
        };
        fw.add(inbound_block).await.unwrap();
        assert_eq!(applied(&fake).len(), 2, "the refused rule is not applied");

        // After the switch to standalone they are loaded.
        *inspection.lock().unwrap() = json!({
            "ufw_chains_loaded": false,
            "table_loaded": true,
            "table_mode": "standalone",
            "hub_mode": "standalone",
        });
        let conf = root.path().join("etc/ufw/ufw.conf");
        std::fs::write(conf.with_extension("new"), "ENABLED=no\nLOGLEVEL=low\n").unwrap();
        std::fs::rename(conf.with_extension("new"), &conf).unwrap();
        assert_eq!(
            next_mode(&mut events).await.mode,
            FirewallModeKind::Standalone
        );
        assert!(fw.list().await.rules.iter().all(|r| r.loaded));
        let allow = fw.add(inbound_allow).await.unwrap();
        assert!(allow.loaded);
    }

    #[tokio::test]
    async fn switches_the_mode_and_imports_ufw_rules_once() {
        use omarchy_security_proto::types::FirewallModeKind;
        let root = crate::ufw::tests::omarchy_root();
        let ufw_on = json!({"ufw_chains_loaded": true, "table_loaded": false});
        let inspection = Arc::new(Mutex::new(ufw_on.clone()));
        let fail = Arc::new(Mutex::new(false));
        let respond: Respond = Arc::new({
            let inspection = inspection.clone();
            let fail = fail.clone();
            move |op| match op {
                HelperOp::FirewallSetMode { mode, .. } => {
                    if *fail.lock().unwrap() {
                        // Part-way: our table is up, ufw did not go away.
                        *inspection.lock().unwrap() = json!({
                            "ufw_chains_loaded": true, "table_loaded": true,
                            "table_mode": "standalone", "hub_mode": "standalone",
                        });
                        return Err(HelperError::new(
                            HelperErrorKind::Backend,
                            "ufw disable failed; both firewalls may be enforcing",
                        ));
                    }
                    *inspection.lock().unwrap() = match mode {
                        HubMode::Standalone => json!({
                            "ufw_chains_loaded": false, "table_loaded": true,
                            "table_mode": "standalone", "hub_mode": "standalone",
                        }),
                        HubMode::Ufw => json!({
                            "ufw_chains_loaded": true, "table_loaded": true,
                            "table_mode": "ufw", "hub_mode": "ufw",
                        }),
                    };
                    Ok(inspection.lock().unwrap().clone())
                }
                HelperOp::FirewallInspect => Ok(inspection.lock().unwrap().clone()),
                _ => Ok(Value::Null),
            }
        });
        let fake = FakeHelper::start(hello(false), respond);
        let store = fake.dir.path().join("state/firewall.json");
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let conf = root.path().join("etc/ufw/ufw.conf");
        let fw = Firewall::start(
            hub.clone(),
            HelperClient::start(fake.path()),
            defaults(),
            Some(store.clone()),
            Some(UfwEnv::at(root.path())),
        );
        while next_mode(&mut events).await.mode != FirewallModeKind::Ufw {}
        wait_state(&hub, ModuleState::Active).await;
        let block = fw.add(spec("192.0.2.1")).await.unwrap();
        let set = |mode, import_ufw_rules| FirewallSetModeParams {
            mode,
            import_ufw_rules,
            dry_run: false,
        };
        let sent = |fake: &FakeHelper| -> Vec<(HubMode, Vec<u64>)> {
            fake.requests
                .lock()
                .unwrap()
                .iter()
                .filter_map(|op| match op {
                    HelperOp::FirewallSetMode { mode, rules } => {
                        Some((*mode, rules.iter().map(|r| r.rule_id).collect()))
                    }
                    _ => None,
                })
                .collect()
        };

        // A dry run shows what the first switch would import, and changes
        // nothing.
        let preview = fw
            .set_mode(FirewallSetModeParams {
                dry_run: true,
                ..set(HubMode::Standalone, None)
            })
            .await
            .unwrap();
        assert_eq!(preview.mode.mode, FirewallModeKind::Ufw);
        assert_eq!(preview.imported.len(), 3, "{preview:?}");
        assert!(
            preview
                .imported
                .iter()
                .all(|i| i.rule.rule_id == 0 && i.rule.loaded)
        );
        assert!(sent(&fake).is_empty());
        assert_eq!(fw.list().await.rules.len(), 1);
        assert!(!store.with_file_name("ufw-imported").exists());

        // The first switch to standalone imports ufw's rules.
        std::fs::write(&conf, "ENABLED=no\nLOGLEVEL=low\n").unwrap();
        let result = fw.set_mode(set(HubMode::Standalone, None)).await.unwrap();
        assert_eq!(result.mode.mode, FirewallModeKind::Standalone);
        assert_eq!(result.imported.len(), 3, "{result:?}");
        assert!(result.not_imported.is_empty());
        assert!(result.imported.iter().all(|i| i.rule.loaded));
        assert_eq!(
            next_mode(&mut events).await.mode,
            FirewallModeKind::Standalone
        );
        let ids: Vec<u64> = fw.list().await.rules.iter().map(|r| r.rule_id).collect();
        assert_eq!(ids.len(), 4);
        assert_eq!(ids[0], block.rule_id);
        assert_eq!(sent(&fake), [(HubMode::Standalone, ids.clone())]);
        assert!(store.with_file_name("ufw-imported").exists());
        assert_eq!(load(&Some(store.clone())).len(), 4, "saved");

        // Back to ufw: nothing imported, rules kept but not loaded.
        std::fs::write(&conf, "ENABLED=yes\nLOGLEVEL=low\n").unwrap();
        let result = fw.set_mode(set(HubMode::Ufw, Some(true))).await.unwrap();
        assert_eq!(result.mode.mode, FirewallModeKind::Ufw);
        assert!(result.imported.is_empty());
        assert!(fw.list().await.rules.iter().all(|r| !r.loaded));

        // A later switch imports only when asked, and never twice.
        std::fs::write(&conf, "ENABLED=no\nLOGLEVEL=low\n").unwrap();
        let result = fw.set_mode(set(HubMode::Standalone, None)).await.unwrap();
        assert!(result.imported.is_empty());
        std::fs::write(&conf, "ENABLED=yes\nLOGLEVEL=low\n").unwrap();
        fw.set_mode(set(HubMode::Ufw, None)).await.unwrap();
        std::fs::write(&conf, "ENABLED=no\nLOGLEVEL=low\n").unwrap();
        let result = fw
            .set_mode(set(HubMode::Standalone, Some(true)))
            .await
            .unwrap();
        assert!(result.imported.is_empty(), "already saved: {result:?}");
        assert_eq!(fw.list().await.rules.len(), 4);

        // A failure part-way reports both, and commits nothing.
        std::fs::write(&conf, "ENABLED=yes\nLOGLEVEL=low\n").unwrap();
        fw.set_mode(set(HubMode::Ufw, None)).await.unwrap();
        fw.remove(RuleTarget { rule_id: ids[3] }).await.unwrap();
        *fail.lock().unwrap() = true;
        let err = fw
            .set_mode(set(HubMode::Standalone, Some(true)))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::BackendError));
        assert!(err.message.contains("both firewalls"), "{}", err.message);
        assert_eq!(fw.mode().unwrap().mode, FirewallModeKind::Both);
        assert_eq!(
            fw.list().await.rules.len(),
            3,
            "the import is not committed"
        );
    }

    #[test]
    fn temp_backend_follows_the_mode() {
        use FirewallModeKind as M;
        use TempBackend::{Table, Ufw};
        let spec = |verdict, direction| FirewallRuleSpec {
            verdict,
            direction,
            ..spec("192.0.2.1")
        };
        let (allow_in, allow_out) = (
            spec(Verdict::Allow, Direction::Inbound),
            spec(Verdict::Allow, Direction::Outbound),
        );
        let (block_in, block_out) = (
            spec(Verdict::Block, Direction::Inbound),
            spec(Verdict::Block, Direction::Outbound),
        );
        for mode in [M::Ufw, M::Both] {
            for s in [&block_in, &block_out] {
                assert_eq!(temp_backend(mode, Some("accept"), s).unwrap(), Table);
            }
            assert_eq!(
                temp_backend(mode, Some("accept"), &allow_out).unwrap(),
                Table
            );
            assert_eq!(temp_backend(mode, None, &allow_out).unwrap(), Table);
            assert_eq!(temp_backend(mode, Some("drop"), &allow_out).unwrap(), Ufw);
            assert_eq!(temp_backend(mode, Some("accept"), &allow_in).unwrap(), Ufw);
        }
        for s in [&allow_in, &allow_out, &block_in, &block_out] {
            assert_eq!(temp_backend(M::Standalone, Some("drop"), s).unwrap(), Table);
            for mode in [M::None, M::Unknown] {
                let err = temp_backend(mode, None, s).unwrap_err();
                assert_eq!(err.kind(), Some(ErrorCode::ModeConflict));
            }
        }
    }

    #[test]
    fn builds_specs_from_alerts() {
        use omarchy_security_proto::types::AlertSource;
        let alert = FirewallAlert {
            alert_id: 1,
            source: AlertSource::Ufw,
            direction: AlertDirection::Inbound,
            protocol: "tcp".into(),
            src: "192.168.1.23".into(),
            dst: "192.168.1.10".into(),
            dst_port: Some(22),
            iface: "wlan0".into(),
            count: 1,
            first_seen: 0,
            last_seen: 0,
            muted_until: None,
        };
        assert_eq!(
            spec_from_alert(&alert, Verdict::Allow).unwrap(),
            FirewallRuleSpec {
                verdict: Verdict::Allow,
                direction: Direction::Inbound,
                address: "192.168.1.23".into(),
                port: Some(22),
                protocol: Some(Protocol::Tcp),
                executable: None,
            }
        );
        let out = FirewallAlert {
            direction: AlertDirection::Outbound,
            ..alert.clone()
        };
        assert_eq!(
            spec_from_alert(&out, Verdict::Block).unwrap().address,
            "192.168.1.10"
        );
        for bad in [
            FirewallAlert {
                direction: AlertDirection::Forward,
                ..alert.clone()
            },
            FirewallAlert {
                protocol: "icmp".into(),
                ..alert.clone()
            },
            FirewallAlert {
                dst_port: None,
                ..alert.clone()
            },
        ] {
            assert_eq!(spec_from_alert(&bad, Verdict::Allow), None);
        }
    }

    type Inspection = Arc<Mutex<Value>>;

    /// A helper that answers `firewall_inspect` with what the test sets,
    /// and everything else with success.
    fn inspecting(value: Value) -> (FakeHelper, Inspection) {
        let inspection = Arc::new(Mutex::new(value));
        let respond: Respond = Arc::new({
            let inspection = inspection.clone();
            move |op| match op {
                HelperOp::FirewallInspect | HelperOp::FirewallSetMode { .. } => {
                    Ok(inspection.lock().unwrap().clone())
                }
                _ => Ok(Value::Null),
            }
        });
        (FakeHelper::start(hello(false), respond), inspection)
    }

    fn temp_ops(fake: &FakeHelper) -> Vec<String> {
        fake.requests
            .lock()
            .unwrap()
            .iter()
            .filter_map(|op| match op {
                HelperOp::FirewallTempSet { decisions } => Some(format!(
                    "set {:?}",
                    decisions
                        .iter()
                        .map(|d| d.spec.address.as_str())
                        .collect::<Vec<_>>()
                )),
                HelperOp::UfwTemp { change, decision } => {
                    Some(format!("ufw {change:?} {}", decision.spec.address))
                }
                _ => None,
            })
            .collect()
    }

    async fn next_temps(rx: &mut broadcast::Receiver<Event>) -> Vec<TempDecision> {
        loop {
            match next_event(rx, 5).await {
                Event::FirewallTempChanged(list) => return list.decisions,
                _ => continue,
            }
        }
    }

    #[tokio::test]
    async fn temporary_decisions_follow_the_mode() {
        let root = crate::ufw::tests::omarchy_root();
        let (fake, inspection) =
            inspecting(json!({"ufw_chains_loaded": true, "table_loaded": false}));
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let fw = Firewall::start(
            hub.clone(),
            HelperClient::start(fake.path()),
            defaults(),
            None,
            Some(UfwEnv::at(root.path())),
        );
        while next_mode(&mut events).await.mode != FirewallModeKind::Ufw {}
        wait_state(&hub, ModuleState::Active).await;
        let add = |verdict, direction, address: &str, duration_secs| FirewallTempAddParams {
            spec: FirewallRuleSpec {
                verdict,
                direction,
                address: address.into(),
                port: Some(22),
                protocol: Some(Protocol::Tcp),
                executable: None,
            },
            duration_secs,
            alert_id: Some(7),
        };

        // ufw mode: an inbound allow is a ufw rule, a block a set element.
        let allow = fw
            .temp_add(add(Verdict::Allow, Direction::Inbound, "192.0.2.1", 3600))
            .await
            .unwrap();
        assert_eq!((allow.backend, allow.alert_id), (TempBackend::Ufw, Some(7)));
        assert_eq!(allow.expires_at - allow.created_at, 3_600_000);
        assert_eq!(next_temps(&mut events).await.len(), 1);
        let block = fw
            .temp_add(add(Verdict::Block, Direction::Inbound, "198.51.100.1", 300))
            .await
            .unwrap();
        assert_eq!(block.backend, TempBackend::Table);
        let out = fw
            .temp_add(add(Verdict::Allow, Direction::Outbound, "203.0.113.1", 300))
            .await
            .unwrap();
        assert_eq!(out.backend, TempBackend::Table);
        // The same traffic again replaces the earlier decision.
        let again = fw
            .temp_add(add(Verdict::Allow, Direction::Inbound, "192.0.2.1", 60))
            .await
            .unwrap();
        assert!(again.temp_id > allow.temp_id);
        assert_eq!(
            temp_ops(&fake),
            [
                "ufw Add 192.0.2.1",
                "set [\"198.51.100.1\"]",
                "set [\"198.51.100.1\", \"203.0.113.1\"]",
                "ufw Add 192.0.2.1",
                "ufw Delete 192.0.2.1",
            ]
        );
        let ids: Vec<u64> = fw
            .temp_list()
            .await
            .decisions
            .iter()
            .map(|d| d.temp_id)
            .collect();
        assert_eq!(ids, [block.temp_id, out.temp_id, again.temp_id]);
        // The list says which durations the UI offers.
        assert_eq!(fw.temp_list().await.durations_secs, [300, 3600, 28800]);

        for (params, code) in [
            (
                add(Verdict::Block, Direction::Inbound, "192.0.2.1", 30),
                ErrorCode::InvalidParams,
            ),
            (
                add(Verdict::Block, Direction::Inbound, "192.0.2.1", 86_401),
                ErrorCode::InvalidParams,
            ),
            (
                add(Verdict::Block, Direction::Inbound, "example.com", 60),
                ErrorCode::InvalidParams,
            ),
            (
                FirewallTempAddParams {
                    spec: FirewallRuleSpec {
                        executable: Some("/usr/bin/curl".into()),
                        ..add(Verdict::Block, Direction::Outbound, "192.0.2.1", 60).spec
                    },
                    ..add(Verdict::Block, Direction::Outbound, "192.0.2.1", 60)
                },
                ErrorCode::InvalidParams,
            ),
        ] {
            assert_eq!(fw.temp_add(params).await.unwrap_err().kind(), Some(code));
        }

        // After a switch to standalone the ufw allow moves into the table.
        let conf = root.path().join("etc/ufw/ufw.conf");
        std::fs::write(&conf, "ENABLED=no\nLOGLEVEL=low\n").unwrap();
        *inspection.lock().unwrap() = json!({"ufw_chains_loaded": false, "table_loaded": true,
            "table_mode": "standalone", "hub_mode": "standalone"});
        fw.set_mode(FirewallSetModeParams {
            mode: HubMode::Standalone,
            import_ufw_rules: Some(false),
            dry_run: false,
        })
        .await
        .unwrap();
        let moved = fw.temp_list().await.decisions;
        assert!(
            moved.iter().all(|d| d.backend == TempBackend::Table),
            "{moved:?}"
        );
        assert_eq!(
            temp_ops(&fake)[5..],
            [
                "ufw Delete 192.0.2.1",
                "set [\"198.51.100.1\", \"203.0.113.1\", \"192.0.2.1\"]"
            ]
        );

        // Revoking a table decision re-sends the set without it.
        fw.temp_remove(TempTarget {
            temp_id: out.temp_id,
        })
        .await
        .unwrap();
        assert_eq!(
            temp_ops(&fake).last().unwrap(),
            "set [\"198.51.100.1\", \"192.0.2.1\"]"
        );
        assert_eq!(
            fw.temp_remove(TempTarget {
                temp_id: out.temp_id
            })
            .await
            .unwrap_err()
            .kind(),
            Some(ErrorCode::NotFound)
        );

        // Expiry drops it from the list without asking the helper.
        let sent = temp_ops(&fake).len();
        fw.temps.lock().await.iter_mut().for_each(|d| {
            if d.temp_id == block.temp_id {
                d.expires_at = now_ms();
            }
        });
        fw.temps_changed.notify_one();
        for _ in 0..500 {
            if fw.temps.lock().await.len() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(fw.temps.lock().await.len(), 1, "dropped, not only hidden");
        assert_eq!(temp_ops(&fake).len(), sent);

        // With no firewall there is nothing to make an exception in.
        std::fs::write(&conf, "ENABLED=no\nLOGLEVEL=low\n").unwrap();
        *inspection.lock().unwrap() = json!({"ufw_chains_loaded": false, "table_loaded": false});
        fw.refresh_mode(&UfwEnv::at(root.path())).await;
        let err = fw
            .temp_add(add(Verdict::Block, Direction::Inbound, "192.0.2.1", 60))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::ModeConflict));
    }

    #[tokio::test]
    async fn takes_over_decisions_a_previous_daemon_left() {
        let root = crate::ufw::tests::omarchy_root();
        let now_unix = now_ms() / 1000;
        let hex = |t: &str| t.bytes().map(|b| format!("{b:02x}")).collect::<String>();
        let tagged = |id, expires| {
            format!(
                "### tuple ### allow tcp 22 0.0.0.0/0 any 203.0.113.{id} in comment={}\n",
                hex(&omarchy_security_proto::ufw::temp_tag(
                    id,
                    now_unix - 10,
                    expires
                ))
            )
        };
        std::fs::write(
            root.path().join("etc/ufw/user.rules"),
            tagged(1, now_unix + 600) + &tagged(2, now_unix - 1),
        )
        .unwrap();
        let held = TempDecision {
            temp_id: 3,
            spec: spec("192.0.2.3"),
            backend: TempBackend::Table,
            created_at: now_ms(),
            expires_at: now_ms() + 600_000,
            alert_id: None,
        };
        let (fake, _) = inspecting(json!({"ufw_chains_loaded": true, "table_loaded": true,
            "table_mode": "ufw", "temp": [held]}));
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let fw = Firewall::start(
            hub.clone(),
            HelperClient::start(fake.path()),
            defaults(),
            None,
            Some(UfwEnv::at(root.path())),
        );
        assert_eq!(next_temps(&mut events).await.len(), 2);
        let decisions = fw.temp_list().await.decisions;
        let got: Vec<(u64, TempBackend)> =
            decisions.iter().map(|d| (d.temp_id, d.backend)).collect();
        assert_eq!(
            got,
            [(1, TempBackend::Ufw), (3, TempBackend::Table)],
            "the expired one is left to the sweep"
        );
        let listed = fw.ufw_rules().await.unwrap();
        assert_eq!(
            listed
                .rules
                .iter()
                .filter_map(|r| r.temp_id)
                .collect::<Vec<_>>(),
            [1, 2]
        );
    }

    #[tokio::test]
    async fn alerts_are_grouped_notified_and_acted_on() {
        use crate::notify::tests::{emit_action, serve};
        let Some(bus) = crate::testutil::Bus::start() else {
            eprintln!("dbus-daemon not available; skipping");
            return;
        };
        let root = crate::ufw::tests::omarchy_root();
        let (fake, _) = inspecting(json!({"ufw_chains_loaded": true, "table_loaded": false}));
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let fw = Firewall::start(
            hub.clone(),
            HelperClient::start(fake.path()),
            defaults(),
            None,
            Some(UfwEnv::at(root.path())),
        );
        while next_mode(&mut events).await.mode != FirewallModeKind::Ufw {}
        wait_state(&hub, ModuleState::Active).await;

        let (server, server_conn) = serve(&bus).await;
        let (tx, actions) = mpsc::channel(4);
        let notifier = Notifier::start(&bus.connect().await, tx).await.unwrap();
        let syn = "[UFW BLOCK] IN=wlan0 OUT= MAC=aa SRC=192.168.1.23 DST=192.168.1.10 LEN=60 PROTO=TCP SPT=51544 DPT=22 SYN ";
        let igmp = "[UFW BLOCK] IN=wlan0 OUT= SRC=172.23.243.84 DST=224.0.0.251 LEN=32 PROTO=2 ";
        let lines: String = [igmp, syn, syn]
            .iter()
            .map(|m| format!("{}\n", json!({"MESSAGE": m})))
            .collect();
        let log = root.path().join("log.json");
        std::fs::write(&log, lines).unwrap();
        let env = AlertsEnv {
            journalctl: vec![
                "sh".into(),
                "-c".into(),
                format!("cat {}; sleep 60", log.display()),
            ],
            open_hub: vec![],
        };
        fw.start_alerts(env, Some((notifier, actions)));

        let alert = loop {
            if let Event::FirewallAlert(alert) = next_event(&mut events, 5).await {
                break alert;
            }
        };
        assert_eq!(
            (alert.dst_port, alert.count),
            (Some(22), 1),
            "IGMP is noise"
        );
        for _ in 0..500 {
            if fw
                .alert_list(Default::default())
                .alerts
                .first()
                .is_some_and(|a| a.count == 2)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let list = fw.alert_list(Default::default()).alerts;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].count, 2);
        for _ in 0..500 {
            if !server.calls.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let call = server.calls.lock().unwrap()[0].clone();
        assert_eq!(call.summary, "Blocked incoming connection");

        // "Allow for 1 h" becomes a temporary ufw allow of that host.
        emit_action(&server_conn, 101, "allow").await;
        let decisions = next_temps(&mut events).await;
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].alert_id, Some(alert.alert_id));
        assert_eq!(decisions[0].backend, TempBackend::Ufw);
        assert_eq!(decisions[0].spec.address, "192.168.1.23");
        assert_eq!(temp_ops(&fake), ["ufw Add 192.168.1.23"]);

        // "Keep blocking" mutes it.
        emit_action(&server_conn, 101, "mute").await;
        let muted = loop {
            if let Event::FirewallAlert(a) = next_event(&mut events, 5).await
                && a.muted_until.is_some()
            {
                break a;
            }
        };
        assert!(muted.muted_until.unwrap() > now_ms() + 7 * 3_600_000);
        let err = fw
            .alert_mute(FirewallAlertMuteParams {
                alert_id: 99,
                duration_secs: 600,
            })
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::NotFound));
    }

    #[tokio::test]
    async fn the_mode_is_unknown_without_the_helper() {
        use omarchy_security_proto::types::FirewallModeKind;
        let root = crate::ufw::tests::omarchy_root();
        let hub = Arc::new(Hub::new());
        let fw = Firewall::start(
            hub.clone(),
            HelperClient::start(root.path().join("none.sock")),
            defaults(),
            None,
            Some(UfwEnv::at(root.path())),
        );
        wait_state(&hub, ModuleState::Unavailable).await;
        let mode = fw.mode().unwrap();
        assert_eq!(mode.mode, FirewallModeKind::Unknown);
        assert!(mode.ufw.enabled_in_conf);
        assert_eq!(mode.ufw.chains_loaded, None);
        let detail = hub.status(Module::Firewall).detail.unwrap();
        assert!(
            detail.starts_with("the firewall mode is unknown; "),
            "{detail}"
        );
        assert_eq!(fw.ufw_rules().await.unwrap().rules.len(), 3);

        // Without mode tracking both calls say so.
        let off = Firewall::start(
            Arc::new(Hub::new()),
            HelperClient::start(root.path().join("none.sock")),
            defaults(),
            None,
            None,
        );
        assert_eq!(
            off.mode().unwrap_err().kind(),
            Some(ErrorCode::ModuleUnavailable)
        );
        assert_eq!(
            off.ufw_rules().await.unwrap_err().kind(),
            Some(ErrorCode::ModuleUnavailable)
        );
    }
}
