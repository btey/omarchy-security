// SPDX-License-Identifier: GPL-3.0-or-later

//! Desktop notifications for blocked traffic and firewall mode warnings
//! (task 2.20, plan §5.19), sent over the session bus to
//! `org.freedesktop.Notifications`, which `omarchy-shell` serves. The shell
//! keeps them in its history and applies the user's do-not-disturb
//! setting: every notification here is urgency `normal` under the app name
//! `Omarchy Security`, except the warning that no firewall is active,
//! which is `critical`.
//!
//! One notification per alert; later counts replace it (`replaces_id`)
//! until the user closes it. At most `max_notifications_per_minute` new
//! ones; beyond that, one summary ("N more connections blocked") that is
//! replaced as N grows. Actions come back as [`Action`]s.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use futures_util::StreamExt;
use omarchy_security_proto::helper::HubMode;
use omarchy_security_proto::types::{AlertDirection, FirewallAlert, FirewallModeKind};
use tokio::sync::mpsc;
use zbus::zvariant::Value;

pub const APP_NAME: &str = "Omarchy Security";

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications",
    gen_blocking = false
)]
pub trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    fn close_notification(&self, id: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: String) -> zbus::Result<()>;

    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

/// What the user chose in a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Open the hub on the Network tab.
    Open,
    /// "Allow for 1 h": a temporary allow built from the alert.
    Allow(u64),
    /// "Keep blocking, stop telling me": mute the alert for 8 h.
    Mute(u64),
    /// "Use UFW" / "Use Security Hub firewall" on a mode warning.
    SetMode(HubMode),
}

/// What a new alert or a changed count should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    New,
    Replace(u32),
    /// The summary, new (`replaces` 0) or replaced, now counting `count`.
    Summary {
        replaces: u32,
        count: u64,
    },
    Skip,
}

/// The rate limit, with the clock passed in.
#[derive(Default)]
pub struct Policy {
    /// When each new alert notification of the last minute went out.
    sent: VecDeque<u64>,
    /// The open notification of each alert.
    alerts: HashMap<u64, u32>,
    /// The open summary: its id, count, and when it was first sent.
    summary: Option<(u32, u64, u64)>,
}

const MINUTE_MS: u64 = 60_000;

impl Policy {
    pub fn plan(&mut self, alert_id: u64, new: bool, now: u64, per_minute: u32) -> Plan {
        if !new {
            return match self.alerts.get(&alert_id) {
                Some(&id) => Plan::Replace(id),
                None => Plan::Skip,
            };
        }
        while self
            .sent
            .front()
            .is_some_and(|&t| now.saturating_sub(t) >= MINUTE_MS)
        {
            self.sent.pop_front();
        }
        if self.sent.len() < per_minute as usize {
            self.sent.push_back(now);
            return Plan::New;
        }
        match &mut self.summary {
            Some((id, count, since)) if now.saturating_sub(*since) < MINUTE_MS => {
                *count += 1;
                Plan::Summary {
                    replaces: *id,
                    count: *count,
                }
            }
            _ => {
                self.summary = Some((0, 1, now));
                Plan::Summary {
                    replaces: 0,
                    count: 1,
                }
            }
        }
    }

    /// Records the id the server gave for `plan`.
    pub fn sent(&mut self, plan: Plan, alert_id: u64, id: u32) {
        match plan {
            Plan::New | Plan::Replace(_) => {
                self.alerts.insert(alert_id, id);
            }
            Plan::Summary { .. } => {
                if let Some(summary) = &mut self.summary {
                    summary.0 = id;
                }
            }
            Plan::Skip => {}
        }
    }

    pub fn closed(&mut self, id: u32) {
        self.alerts.retain(|_, n| *n != id);
        if self.summary.is_some_and(|(n, _, _)| n == id) {
            self.summary = None;
        }
    }
}

/// What a notification id stands for, to route its actions.
#[derive(Debug, Clone, Copy)]
enum Target {
    Alert(u64),
    Summary,
    Mode,
    Other,
}

#[derive(Default)]
struct State {
    policy: Policy,
    targets: HashMap<u32, Target>,
    /// The open mode warning, and for which mode.
    warning: Option<(u32, FirewallModeKind)>,
}

pub struct Notifier {
    proxy: NotificationsProxy<'static>,
    state: Mutex<State>,
}

/// Whether "Allow for 1 h" can be built from the alert: TCP or UDP with a
/// port, inbound or outbound.
pub fn allowable(alert: &FirewallAlert) -> bool {
    alert.direction != AlertDirection::Forward
        && matches!(alert.protocol.as_str(), "tcp" | "udp")
        && alert.dst_port.is_some()
}

/// `body-markup` servers read `&`, `<` and `>` as markup.
fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Summary and body of an alert's notification.
pub fn describe(alert: &FirewallAlert) -> (String, String) {
    let summary = match alert.direction {
        AlertDirection::Inbound => "Blocked incoming connection",
        AlertDirection::Outbound => "Blocked outgoing connection",
        AlertDirection::Forward => "Blocked connection to a container",
    };
    let what = match alert.dst_port {
        Some(port) => format!("{} port {port}", alert.protocol.to_uppercase()),
        None => alert.protocol.to_uppercase(),
    };
    let mut body = match alert.direction {
        AlertDirection::Outbound => format!("{what} to {}", alert.dst),
        AlertDirection::Inbound => format!("{what} from {} on {}", alert.src, alert.iface),
        AlertDirection::Forward => format!("{what} from {} to {}", alert.src, alert.dst),
    };
    if alert.count > 1 {
        body.push_str(&format!(", {} times", alert.count));
    }
    (summary.into(), escape(&body))
}

fn hints(critical: bool) -> HashMap<&'static str, Value<'static>> {
    HashMap::from([("urgency", Value::U8(if critical { 2 } else { 1 }))])
}

impl Notifier {
    /// Connects to the notification server on `conn` and forwards the
    /// actions the user picks to `actions`.
    pub async fn start(
        conn: &zbus::Connection,
        actions: mpsc::Sender<Action>,
    ) -> zbus::Result<Arc<Self>> {
        let proxy = NotificationsProxy::new(conn).await?;
        let mut invoked = proxy.receive_action_invoked().await?;
        let mut closed = proxy.receive_notification_closed().await?;
        let notifier = Arc::new(Self {
            proxy,
            state: Mutex::new(State::default()),
        });
        let weak = Arc::downgrade(&notifier);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    signal = invoked.next() => {
                        let Some(signal) = signal else { return };
                        let Some(this) = weak.upgrade() else { return };
                        let Ok(args) = signal.args() else { continue };
                        if let Some(action) = this.action(args.id, &args.action_key) {
                            tracing::info!(id = args.id, ?action, "notification action");
                            if actions.send(action).await.is_err() {
                                return;
                            }
                        }
                    }
                    signal = closed.next() => {
                        let Some(signal) = signal else { return };
                        let Some(this) = weak.upgrade() else { return };
                        if let Ok(args) = signal.args() {
                            this.forget(args.id);
                        }
                    }
                }
            }
        });
        Ok(notifier)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().expect("notifier lock")
    }

    fn action(&self, id: u32, key: &str) -> Option<Action> {
        let target = *self.state().targets.get(&id)?;
        match (target, key) {
            (_, "default") => Some(Action::Open),
            (Target::Alert(alert_id), "allow") => Some(Action::Allow(alert_id)),
            (Target::Alert(alert_id), "mute") => Some(Action::Mute(alert_id)),
            (Target::Mode, "ufw") => Some(Action::SetMode(HubMode::Ufw)),
            (Target::Mode, "standalone") => Some(Action::SetMode(HubMode::Standalone)),
            _ => None,
        }
    }

    fn forget(&self, id: u32) {
        let mut state = self.state();
        state.policy.closed(id);
        state.targets.remove(&id);
        if state.warning.is_some_and(|(n, _)| n == id) {
            state.warning = None;
        }
    }

    async fn send(
        &self,
        replaces: u32,
        summary: &str,
        body: &str,
        actions: &[&str],
        critical: bool,
    ) -> Option<u32> {
        match self
            .proxy
            .notify(
                APP_NAME,
                replaces,
                "security-high",
                summary,
                body,
                actions,
                hints(critical),
                -1,
            )
            .await
        {
            Ok(id) => Some(id),
            Err(err) => {
                tracing::warn!("sending a desktop notification: {err}");
                None
            }
        }
    }

    /// Notifies about a new alert, or updates the notification of one
    /// whose count changed, within the rate limit.
    pub async fn alert(&self, alert: &FirewallAlert, new: bool, now: u64, per_minute: u32) {
        if alert.muted_until.is_some_and(|until| until > now) {
            return;
        }
        let plan = self
            .state()
            .policy
            .plan(alert.alert_id, new, now, per_minute);
        let (summary, body, actions, target) = match plan {
            Plan::Skip => return,
            Plan::New | Plan::Replace(_) => {
                let (summary, body) = describe(alert);
                let mut actions = vec!["default", "Open Security Hub"];
                if allowable(alert) {
                    actions.extend(["allow", "Allow for 1 h"]);
                }
                actions.extend(["mute", "Keep blocking, stop telling me"]);
                (summary, body, actions, Target::Alert(alert.alert_id))
            }
            Plan::Summary { count, .. } => (
                "Firewall".to_owned(),
                format!(
                    "{count} more connection{} blocked",
                    if count == 1 { "" } else { "s" }
                ),
                vec!["default", "Open Security Hub"],
                Target::Summary,
            ),
        };
        let replaces = match plan {
            Plan::Replace(id) | Plan::Summary { replaces: id, .. } => id,
            _ => 0,
        };
        if let Some(id) = self.send(replaces, &summary, &body, &actions, false).await {
            let mut state = self.state();
            state.policy.sent(plan, alert.alert_id, id);
            state.targets.insert(id, target);
        }
    }

    /// Warns once when the mode becomes `both` or `none`, and takes the
    /// warning back when a firewall is chosen again.
    pub async fn mode(&self, mode: FirewallModeKind) {
        let current = self.state().warning;
        match mode {
            FirewallModeKind::Both | FirewallModeKind::None => {
                if current.is_some_and(|(_, m)| m == mode) {
                    return;
                }
                let (summary, body, critical) = if mode == FirewallModeKind::None {
                    (
                        "Firewall is off",
                        "No firewall is active: this machine is exposed to the network.",
                        true,
                    )
                } else {
                    (
                        "Two firewalls are active",
                        "UFW and the Security Hub firewall are both enforcing. Traffic must pass both.",
                        false,
                    )
                };
                let actions = [
                    "default",
                    "Open Security Hub",
                    "ufw",
                    "Use UFW",
                    "standalone",
                    "Use Security Hub firewall",
                ];
                let replaces = current.map_or(0, |(id, _)| id);
                if let Some(id) = self.send(replaces, summary, body, &actions, critical).await {
                    let mut state = self.state();
                    state.warning = Some((id, mode));
                    state.targets.insert(id, Target::Mode);
                }
            }
            FirewallModeKind::Ufw | FirewallModeKind::Standalone => {
                if let Some((id, _)) = current {
                    self.forget(id);
                    if let Err(err) = self.proxy.close_notification(id).await {
                        tracing::debug!("closing the mode warning: {err}");
                    }
                }
            }
            // The helper is away: say nothing either way.
            FirewallModeKind::Unknown => {}
        }
    }

    /// Reports an action that failed.
    pub async fn error(&self, summary: &str, body: &str) {
        if let Some(id) = self.send(0, summary, &escape(body), &[], false).await {
            self.state().targets.insert(id, Target::Other);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::testutil::Bus;
    use omarchy_security_proto::types::AlertSource;
    use std::time::Duration;

    #[test]
    fn limits_new_notifications_per_minute() {
        let mut policy = Policy::default();
        let plans: Vec<Plan> = (1..=5).map(|id| policy.plan(id, true, 1_000, 3)).collect();
        assert_eq!(
            plans,
            [
                Plan::New,
                Plan::New,
                Plan::New,
                Plan::Summary {
                    replaces: 0,
                    count: 1
                },
                Plan::Summary {
                    replaces: 0,
                    count: 2
                },
            ]
        );
        policy.sent(Plan::New, 1, 10);
        policy.sent(plans[3], 4, 20);
        assert_eq!(
            policy.plan(6, true, 2_000, 3),
            Plan::Summary {
                replaces: 20,
                count: 3
            }
        );
        // A changed count replaces an open notification, and only that.
        assert_eq!(policy.plan(1, false, 3_000, 3), Plan::Replace(10));
        assert_eq!(policy.plan(2, false, 3_000, 3), Plan::Skip);
        policy.closed(10);
        assert_eq!(policy.plan(1, false, 3_000, 3), Plan::Skip);
        // A minute later there is room again, and a new summary.
        assert_eq!(policy.plan(7, true, 61_000, 3), Plan::New);
        policy.plan(8, true, 61_000, 3);
        policy.plan(9, true, 61_000, 3);
        assert_eq!(
            policy.plan(10, true, 61_500, 3),
            Plan::Summary {
                replaces: 0,
                count: 1
            }
        );
    }

    fn alert(alert_id: u64, protocol: &str, dst_port: Option<u16>) -> FirewallAlert {
        FirewallAlert {
            alert_id,
            source: AlertSource::Ufw,
            direction: AlertDirection::Inbound,
            protocol: protocol.into(),
            src: "192.168.1.23".into(),
            dst: "192.168.1.10".into(),
            dst_port,
            iface: "wlan0".into(),
            count: 1,
            first_seen: 0,
            last_seen: 0,
            muted_until: None,
        }
    }

    #[test]
    fn describes_alerts() {
        let mut a = alert(1, "tcp", Some(22));
        assert_eq!(
            describe(&a),
            (
                "Blocked incoming connection".into(),
                "TCP port 22 from 192.168.1.23 on wlan0".into()
            )
        );
        assert!(allowable(&a));
        a.count = 3;
        a.iface = "<b>".into();
        assert!(
            describe(&a).1.ends_with("on &lt;b&gt;, 3 times"),
            "{:?}",
            describe(&a)
        );
        assert!(!allowable(&alert(1, "icmp", None)));
        assert!(!allowable(&FirewallAlert {
            direction: AlertDirection::Forward,
            ..alert(1, "tcp", Some(80))
        }));
    }

    /// One call to the fake server.
    #[derive(Debug, Clone, PartialEq)]
    pub struct Call {
        pub app_name: String,
        pub replaces_id: u32,
        pub summary: String,
        pub body: String,
        pub actions: Vec<String>,
        pub urgency: u8,
    }

    /// A stand-in for `omarchy-shell`'s notification server.
    #[derive(Default, Clone)]
    pub struct FakeServer {
        pub calls: Arc<Mutex<Vec<Call>>>,
        pub closed: Arc<Mutex<Vec<u32>>>,
    }

    #[zbus::interface(name = "org.freedesktop.Notifications")]
    impl FakeServer {
        #[allow(clippy::too_many_arguments)]
        fn notify(
            &self,
            app_name: String,
            replaces_id: u32,
            _app_icon: String,
            summary: String,
            body: String,
            actions: Vec<String>,
            hints: HashMap<String, zbus::zvariant::OwnedValue>,
            _expire_timeout: i32,
        ) -> u32 {
            let urgency = hints
                .get("urgency")
                .and_then(|v| u8::try_from(v).ok())
                .unwrap_or(0);
            let mut calls = self.calls.lock().unwrap();
            calls.push(Call {
                app_name,
                replaces_id,
                summary,
                body,
                actions,
                urgency,
            });
            if replaces_id != 0 {
                replaces_id
            } else {
                calls.len() as u32 + 100
            }
        }

        fn close_notification(&self, id: u32) {
            self.closed.lock().unwrap().push(id);
        }

        #[zbus(signal)]
        pub async fn action_invoked(
            emitter: &zbus::object_server::SignalEmitter<'_>,
            id: u32,
            action_key: &str,
        ) -> zbus::Result<()>;

        #[zbus(signal)]
        pub async fn notification_closed(
            emitter: &zbus::object_server::SignalEmitter<'_>,
            id: u32,
            reason: u32,
        ) -> zbus::Result<()>;
    }

    /// Serves [`FakeServer`] on `bus`; the connection must be kept.
    pub async fn serve(bus: &Bus) -> (FakeServer, zbus::Connection) {
        let fake = FakeServer::default();
        let conn = zbus::connection::Builder::address(bus.address.as_str())
            .unwrap()
            .name("org.freedesktop.Notifications")
            .unwrap()
            .serve_at("/org/freedesktop/Notifications", fake.clone())
            .unwrap()
            .build()
            .await
            .unwrap();
        (fake, conn)
    }

    pub async fn emit_action(conn: &zbus::Connection, id: u32, key: &str) {
        let emitter =
            zbus::object_server::SignalEmitter::new(conn, "/org/freedesktop/Notifications")
                .unwrap();
        FakeServer::action_invoked(&emitter, id, key).await.unwrap();
    }

    #[tokio::test]
    async fn notifies_and_routes_actions() {
        let Some(bus) = Bus::start() else {
            eprintln!("dbus-daemon not available; skipping");
            return;
        };
        let (fake, server) = serve(&bus).await;
        let (tx, mut actions) = mpsc::channel(4);
        let notifier = Notifier::start(&bus.connect().await, tx).await.unwrap();

        let ssh = alert(1, "tcp", Some(22));
        notifier.alert(&ssh, true, 1_000, 3).await;
        notifier
            .alert(
                &FirewallAlert {
                    count: 2,
                    ..ssh.clone()
                },
                false,
                6_000,
                3,
            )
            .await;
        notifier
            .alert(&alert(2, "icmp", None), true, 6_000, 3)
            .await;
        let muted = FirewallAlert {
            muted_until: Some(99_000),
            ..alert(3, "tcp", Some(80))
        };
        notifier.alert(&muted, true, 6_000, 3).await;
        let calls = fake.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 3, "{calls:?}");
        assert_eq!(calls[0].app_name, APP_NAME);
        assert_eq!(calls[0].urgency, 1);
        assert_eq!(
            calls[0].actions,
            [
                "default",
                "Open Security Hub",
                "allow",
                "Allow for 1 h",
                "mute",
                "Keep blocking, stop telling me"
            ]
        );
        assert_eq!(
            (calls[1].replaces_id, calls[1].body.as_str()),
            (101, "TCP port 22 from 192.168.1.23 on wlan0, 2 times")
        );
        assert!(
            !calls[2].actions.contains(&"allow".to_owned()),
            "ICMP cannot be allowed"
        );

        async fn next(actions: &mut mpsc::Receiver<Action>) -> Option<Action> {
            tokio::time::timeout(Duration::from_secs(5), actions.recv())
                .await
                .expect("an action within 5 s")
        }
        emit_action(&server, 101, "allow").await;
        assert_eq!(next(&mut actions).await, Some(Action::Allow(1)));
        emit_action(&server, 101, "mute").await;
        assert_eq!(next(&mut actions).await, Some(Action::Mute(1)));
        emit_action(&server, 999, "allow").await; // not ours
        emit_action(&server, 103, "default").await;
        assert_eq!(next(&mut actions).await, Some(Action::Open));

        // The mode warnings: once per mode, critical only for none, taken
        // back when a firewall is chosen.
        notifier.mode(FirewallModeKind::None).await;
        notifier.mode(FirewallModeKind::Unknown).await;
        notifier.mode(FirewallModeKind::None).await;
        let calls = fake.calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 4);
        assert_eq!(
            (calls[3].summary.as_str(), calls[3].urgency),
            ("Firewall is off", 2)
        );
        emit_action(&server, 104, "standalone").await;
        assert_eq!(
            next(&mut actions).await,
            Some(Action::SetMode(HubMode::Standalone))
        );
        notifier.mode(FirewallModeKind::Both).await;
        let calls = fake.calls.lock().unwrap().clone();
        assert_eq!((calls[4].replaces_id, calls[4].urgency), (104, 1));
        notifier.mode(FirewallModeKind::Ufw).await;
        assert_eq!(*fake.closed.lock().unwrap(), [104]);
        notifier.mode(FirewallModeKind::Both).await;
        assert_eq!(
            fake.calls.lock().unwrap().len(),
            6,
            "a new warning after a fix"
        );
    }
}
