// SPDX-License-Identifier: GPL-3.0-or-later

//! Threat detection and response (task 2.2, plan §2.1).
//!
//! **Sources.** With the privileged helper running and its eBPF exec
//! monitor loaded, every suspicious execution on the system arrives as an
//! [`ExecRecord`] and the module is `active`. Otherwise the module is
//! `degraded`: it scans `/proc` every two seconds for processes of this
//! user whose executable lives in `/tmp`, `/var/tmp`, `/dev/shm`, or a
//! memfd. The scan misses short-lived processes and scripts, which is why
//! the eBPF path exists.
//!
//! **Response.** Kill, quarantine (`SIGSTOP`), and resume act only on
//! processes this module reported, and re-check the start time first
//! (`docs/ipc-protocol.md` §4.2). The daemon signals the user's own
//! processes itself and asks the helper for anyone else's.
//!
//! **Drops.** [`crate::drops`] reports executable files written into those
//! directories before they run (`THREAT_FILE_DROPPED`). Other users' files
//! are reported only while the helper is connected, since only it can act
//! on their processes. An alert for a path reported earlier carries the
//! drop time as `dropped_at`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use omarchy_security_proto::events::AlertResolved;
use omarchy_security_proto::helper::{
    ExecRecord, HelperErrorKind, HelperOp, HelperSignal, classify_exec,
};
use omarchy_security_proto::methods::{AlertList, AlertTarget, KillProcessParams};
use omarchy_security_proto::procfs::Proc;
use omarchy_security_proto::types::{
    AlertState, FileDrop, KillSignal, Module, ModuleState, ThreatAlert,
};
use omarchy_security_proto::{ErrorCode, Event, RpcError};
use tokio::sync::{broadcast, mpsc};

use crate::drops::{self, DropEnv, RateLimit};
use crate::helper_client::{HelperClient, HelperState};
use crate::hub::Hub;
use crate::now_ms;

const SCAN_INTERVAL: Duration = Duration::from_secs(2);
const EXIT_CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// Unresolved alerts kept; the oldest is dropped beyond this.
const MAX_ALERTS: usize = 256;
/// Detections remembered for de-duplication.
const MAX_SEEN: usize = 4096;
/// Dropped paths remembered for `dropped_at`.
const MAX_DROPPED: usize = 1024;
/// `THREAT_FILE_DROPPED` events: a burst of this many, then one per
/// [`DROP_REFILL`].
const DROP_BURST: u32 = 10;
const DROP_REFILL: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Kill(KillSignal),
    Quarantine,
    Resume,
    Dismiss,
}

#[derive(Default)]
struct Alerts {
    open: BTreeMap<u64, ThreatAlert>,
    seen: HashSet<(u32, u64, String)>,
}

pub struct Threat {
    hub: Arc<Hub>,
    helper: Arc<HelperClient>,
    proc: Proc,
    uid: u32,
    alerts: Mutex<Alerts>,
    next_id: AtomicU64,
    /// Path → `detected_at` of the drops reported.
    dropped: Mutex<HashMap<String, u64>>,
    drop_limit: Mutex<RateLimit>,
    /// Why no records arrive from the helper, if they do not.
    source: Mutex<Result<(), String>>,
    drop_problem: Mutex<Option<String>>,
}

impl Threat {
    pub fn start(
        hub: Arc<Hub>,
        helper: Arc<HelperClient>,
        proc: Proc,
        drops: Option<DropEnv>,
    ) -> Arc<Self> {
        let threat = Arc::new(Self {
            hub,
            helper,
            proc,
            uid: nix::unistd::getuid().as_raw(),
            alerts: Mutex::new(Alerts::default()),
            next_id: AtomicU64::new(1),
            dropped: Mutex::new(HashMap::new()),
            drop_limit: Mutex::new(RateLimit::new(DROP_BURST, DROP_REFILL)),
            source: Mutex::new(Err("starting".into())),
            drop_problem: Mutex::new(None),
        });
        tokio::spawn(threat.clone().follow_sources());
        tokio::spawn(threat.clone().watch_exits());
        if let Some(env) = drops {
            threat.clone().start_drops(env);
        }
        threat
    }

    fn start_drops(self: Arc<Self>, env: DropEnv) {
        let (tx, mut rx) = mpsc::channel(64);
        tokio::spawn({
            let threat = self.clone();
            async move {
                if let Err(err) = drops::watch(env, tx).await {
                    tracing::warn!("file drop detection stopped: {err}");
                    *threat.drop_problem.lock().expect("threat lock") =
                        Some(format!("file drop detection unavailable: {err}"));
                    threat.update_status();
                }
            }
        });
        tokio::spawn(async move {
            while let Some(drop) = rx.recv().await {
                self.on_drop(drop);
            }
        });
    }

    fn on_drop(&self, drop: FileDrop) {
        let helper = matches!(
            &*self.helper.state().borrow(),
            HelperState::Connected { .. }
        );
        if drop.uid != self.uid && !helper {
            return;
        }
        {
            let mut dropped = self.dropped.lock().expect("threat lock");
            if dropped.len() >= MAX_DROPPED && !dropped.contains_key(&drop.path) {
                let oldest = dropped
                    .iter()
                    .min_by_key(|(_, at)| **at)
                    .map(|(path, _)| path.clone());
                if let Some(oldest) = oldest {
                    dropped.remove(&oldest);
                }
            }
            dropped.insert(drop.path.clone(), drop.detected_at);
        }
        if !self
            .drop_limit
            .lock()
            .expect("threat lock")
            .allow(Instant::now())
        {
            return;
        }
        tracing::warn!(path = %drop.path, uid = drop.uid, size = drop.size, "executable file dropped");
        self.hub.emit(Event::ThreatFileDropped(drop));
    }

    fn update_status(&self) {
        let problem = self.drop_problem.lock().expect("threat lock").clone();
        match &*self.source.lock().expect("threat lock") {
            Ok(()) => self
                .hub
                .set_status(Module::Threat, ModuleState::Active, problem),
            Err(reason) => {
                let mut detail =
                    format!("{reason}; scanning /proc for this user's processes every 2 s");
                if let Some(problem) = problem {
                    detail = format!("{detail}; {problem}");
                }
                self.hub
                    .set_status(Module::Threat, ModuleState::Degraded, Some(detail));
            }
        }
    }

    /// Takes records from the helper while it can provide them, and scans
    /// `/proc` otherwise.
    async fn follow_sources(self: Arc<Self>) {
        let mut state = self.helper.state();
        let mut records = self.helper.exec_records();
        let mut scan = tokio::time::interval(SCAN_INTERVAL);
        scan.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut known: HashMap<u32, u64> = HashMap::new();
        loop {
            let ebpf = match &*state.borrow_and_update() {
                HelperState::Connected { exec: Ok(()), .. } => Ok(()),
                HelperState::Connected {
                    exec: Err(reason), ..
                } => Err(format!("eBPF monitor unavailable: {reason}")),
                HelperState::Disconnected(reason) => Err(reason.clone()),
            };
            *self.source.lock().expect("threat lock") = ebpf.clone();
            self.update_status();
            loop {
                tokio::select! {
                    changed = state.changed() => {
                        if changed.is_err() { return; }
                        break;
                    }
                    record = records.recv(), if ebpf.is_ok() => match record {
                        Ok(record) => self.ingest(record),
                        Err(broadcast::error::RecvError::Lagged(n)) => tracing::warn!("missed {n} exec records"),
                        Err(broadcast::error::RecvError::Closed) => return,
                    },
                    _ = scan.tick(), if ebpf.is_err() => {
                        for record in scan_proc(&self.proc, self.uid, &mut known) {
                            self.ingest(record);
                        }
                    }
                }
            }
        }
    }

    fn ingest(&self, record: ExecRecord) {
        let dropped_at = self
            .dropped
            .lock()
            .expect("threat lock")
            .get(&record.binary_path)
            .copied();
        let alert = {
            let mut alerts = self.alerts.lock().expect("threat lock");
            let key = (record.pid, record.start_time, record.binary_path.clone());
            if !alerts.seen.insert(key) {
                return;
            }
            if alerts.seen.len() > MAX_SEEN {
                alerts.seen.clear();
            }
            let alert = ThreatAlert {
                alert_id: self.next_id.fetch_add(1, Ordering::Relaxed),
                pid: record.pid,
                ppid: record.ppid,
                uid: record.uid,
                start_time: record.start_time,
                binary_path: record.binary_path,
                argv: record.argv,
                origin: record.origin,
                detected_at: now_ms(),
                // start_time 0: the process was gone before it was read.
                state: if record.start_time == 0 {
                    AlertState::Exited
                } else {
                    AlertState::Open
                },
                dropped_at,
            };
            if alert.state == AlertState::Open {
                alerts.open.insert(alert.alert_id, alert.clone());
                while alerts.open.len() > MAX_ALERTS {
                    alerts.open.pop_first();
                }
            }
            alert
        };
        tracing::warn!(alert_id = alert.alert_id, pid = alert.pid, uid = alert.uid, path = %alert.binary_path, origin = ?alert.origin, "suspicious execution");
        self.hub.emit(Event::ThreatExecDetected(alert));
    }

    async fn watch_exits(self: Arc<Self>) {
        let mut tick = tokio::time::interval(EXIT_CHECK_INTERVAL);
        loop {
            tick.tick().await;
            let gone: Vec<u64> = {
                let alerts = self.alerts.lock().expect("threat lock");
                alerts
                    .open
                    .values()
                    .filter(|a| !self.proc.is_same_process(a.pid, a.start_time))
                    .map(|a| a.alert_id)
                    .collect()
            };
            for alert_id in gone {
                self.resolve(alert_id, AlertState::Exited);
            }
        }
    }

    /// Moves an alert to a final state and announces it.
    fn resolve(&self, alert_id: u64, state: AlertState) -> Option<ThreatAlert> {
        let mut alert = self
            .alerts
            .lock()
            .expect("threat lock")
            .open
            .remove(&alert_id)?;
        alert.state = state;
        self.hub.emit(Event::ThreatAlertResolved(AlertResolved {
            alert_id,
            state,
        }));
        Some(alert)
    }

    pub fn list(&self) -> AlertList {
        AlertList {
            alerts: self
                .alerts
                .lock()
                .expect("threat lock")
                .open
                .values()
                .cloned()
                .collect(),
        }
    }

    pub async fn kill(&self, params: KillProcessParams) -> Result<ThreatAlert, RpcError> {
        let target = AlertTarget {
            alert_id: params.alert_id,
            pid: params.pid,
        };
        self.act(target, Action::Kill(params.signal)).await
    }

    pub async fn quarantine(&self, target: AlertTarget) -> Result<ThreatAlert, RpcError> {
        self.act(target, Action::Quarantine).await
    }

    pub async fn resume(&self, target: AlertTarget) -> Result<ThreatAlert, RpcError> {
        self.act(target, Action::Resume).await
    }

    pub async fn dismiss(&self, target: AlertTarget) -> Result<ThreatAlert, RpcError> {
        self.act(target, Action::Dismiss).await
    }

    async fn act(&self, target: AlertTarget, action: Action) -> Result<ThreatAlert, RpcError> {
        let alert = self
            .alerts
            .lock()
            .expect("threat lock")
            .open
            .get(&target.alert_id)
            .cloned()
            .ok_or_else(|| {
                RpcError::new(
                    ErrorCode::NotFound,
                    format!("no open alert with id {}", target.alert_id),
                )
            })?;
        if alert.pid != target.pid {
            return Err(RpcError::new(
                ErrorCode::NotFound,
                format!("alert {} is not about pid {}", alert.alert_id, target.pid),
            ));
        }
        let allowed = match action {
            Action::Kill(_) => true,
            Action::Quarantine | Action::Dismiss => alert.state == AlertState::Open,
            Action::Resume => alert.state == AlertState::Quarantined,
        };
        if !allowed {
            return Err(RpcError::invalid_params(format!(
                "alert {} is {}",
                alert.alert_id,
                serde_json::to_value(alert.state)
                    .expect("state serializes")
                    .as_str()
                    .unwrap_or_default()
            )));
        }
        if action == Action::Dismiss {
            tracing::info!(alert_id = alert.alert_id, "alert dismissed");
            return Ok(self
                .resolve(alert.alert_id, AlertState::Dismissed)
                .unwrap_or(alert));
        }
        if !self.proc.is_same_process(alert.pid, alert.start_time) {
            self.resolve(alert.alert_id, AlertState::Exited);
            return Err(RpcError::new(
                ErrorCode::StaleTarget,
                format!("process {} has exited", alert.pid),
            ));
        }
        let signal = match action {
            Action::Kill(KillSignal::Term) => HelperSignal::Term,
            Action::Kill(KillSignal::Kill) => HelperSignal::Kill,
            Action::Quarantine => HelperSignal::Stop,
            Action::Resume => HelperSignal::Cont,
            Action::Dismiss => unreachable!("handled above"),
        };
        self.signal(&alert, signal).await?;
        tracing::info!(
            alert_id = alert.alert_id,
            pid = alert.pid,
            ?signal,
            "responded to alert"
        );
        let next = match action {
            Action::Kill(_) => {
                return Ok(self
                    .resolve(alert.alert_id, AlertState::Killed)
                    .unwrap_or(alert));
            }
            Action::Quarantine => AlertState::Quarantined,
            _ => AlertState::Open,
        };
        let mut alerts = self.alerts.lock().expect("threat lock");
        let stored = alerts.open.get_mut(&alert.alert_id).ok_or_else(|| {
            RpcError::new(
                ErrorCode::StaleTarget,
                format!("process {} has exited", alert.pid),
            )
        })?;
        stored.state = next;
        Ok(stored.clone())
    }

    async fn signal(&self, alert: &ThreatAlert, signal: HelperSignal) -> Result<(), RpcError> {
        if alert.uid == self.uid {
            use nix::sys::signal::Signal as S;
            let sig = match signal {
                HelperSignal::Term => S::SIGTERM,
                HelperSignal::Kill => S::SIGKILL,
                HelperSignal::Stop => S::SIGSTOP,
                HelperSignal::Cont => S::SIGCONT,
            };
            match nix::sys::signal::kill(nix::unistd::Pid::from_raw(alert.pid as i32), sig) {
                Ok(()) => return Ok(()),
                // A setuid program: its effective uid is not ours.
                Err(nix::Error::EPERM) => {}
                Err(err) => {
                    return Err(RpcError::new(
                        ErrorCode::BackendError,
                        format!("kill({}): {err}", alert.pid),
                    ));
                }
            }
        }
        let op = HelperOp::Signal {
            pid: alert.pid,
            start_time: alert.start_time,
            signal,
        };
        self.helper.request(op).await.map(|_| ()).map_err(|err| {
            let code = match err.kind {
                HelperErrorKind::PermissionDenied | HelperErrorKind::Unavailable => {
                    ErrorCode::PermissionDenied
                }
                HelperErrorKind::NotFound => ErrorCode::NotFound,
                HelperErrorKind::StaleTarget => ErrorCode::StaleTarget,
                HelperErrorKind::Backend => ErrorCode::BackendError,
                HelperErrorKind::Invalid => ErrorCode::InternalError,
            };
            RpcError::new(
                code,
                format!(
                    "process {} belongs to uid {}: {}",
                    alert.pid, alert.uid, err.message
                ),
            )
        })
    }
}

/// One `/proc` pass over this user's processes. `known` maps each PID seen
/// before to its start time, so each process is examined once.
fn scan_proc(proc: &Proc, uid: u32, known: &mut HashMap<u32, u64>) -> Vec<ExecRecord> {
    let pids = proc.pids().unwrap_or_default();
    let live: HashSet<u32> = pids.iter().copied().collect();
    known.retain(|pid, _| live.contains(pid));
    let mut found = Vec::new();
    for pid in pids {
        let Ok(stat) = proc.stat(pid) else { continue };
        if known.insert(pid, stat.start_time) == Some(stat.start_time) {
            continue;
        }
        // Fails for other users' processes and kernel threads.
        let Ok(exe) = proc.exe(pid) else { continue };
        if proc.uid(pid).ok() != Some(uid) {
            continue;
        }
        let Some((origin, binary_path)) = classify_exec(&exe, None, Some(&exe)) else {
            continue;
        };
        found.push(ExecRecord {
            pid,
            ppid: stat.ppid,
            uid,
            start_time: stat.start_time,
            origin,
            binary_path,
            argv: proc.argv(pid).unwrap_or_default(),
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helper_client::tests::{FakeHelper, hello, wait_connected};
    use omarchy_security_proto::helper::HelperError;
    use omarchy_security_proto::types::ExecOrigin;
    use serde_json::Value;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    async fn next(rx: &mut broadcast::Receiver<Event>) -> Event {
        loop {
            match tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .expect("event")
                .unwrap()
            {
                Event::ModuleStateChanged(_) => continue,
                other => return other,
            }
        }
    }

    /// The next drop, skipping the alerts for other tests' processes.
    async fn next_drop(rx: &mut broadcast::Receiver<Event>) -> FileDrop {
        loop {
            match next(rx).await {
                Event::ThreatFileDropped(drop) => return drop,
                Event::ThreatExecDetected(_) | Event::ThreatAlertResolved(_) => continue,
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    async fn wait_state(hub: &Hub, state: ModuleState) {
        for _ in 0..500 {
            if hub.status(Module::Threat).state == state {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "threat module never became {state:?}: {:?}",
            hub.status(Module::Threat)
        );
    }

    /// Kills the child if the test fails, so a stopped process cannot keep
    /// the test harness's output pipe open.
    struct Reaper(std::process::Child);

    impl Drop for Reaper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn process_state(pid: u32) -> Option<String> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let rest = &stat[stat.rfind(')')? + 2..];
        rest.split_whitespace().next().map(str::to_owned)
    }

    async fn wait_process_state(pid: u32, want: &str) {
        for _ in 0..200 {
            if process_state(pid).as_deref() == Some(want) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!(
            "pid {pid} never reached state {want}: {:?}",
            process_state(pid)
        );
    }

    /// A copy of `sleep` under a temp dir inside /tmp or /dev/shm.
    fn planted_sleep() -> (tempfile::TempDir, PathBuf) {
        let base = if std::path::Path::new("/dev/shm").is_dir() {
            "/dev/shm"
        } else {
            "/tmp"
        };
        let dir = tempfile::Builder::new()
            .prefix("omsec-test")
            .tempdir_in(base)
            .unwrap();
        let bin = dir.path().join("sleeper");
        let sleep = ["/usr/bin/sleep", "/bin/sleep"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .unwrap();
        std::fs::copy(sleep, &bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        (dir, bin)
    }

    #[test]
    fn proc_scan_finds_planted_binaries_once() {
        let (_dir, bin) = planted_sleep();
        let child = Reaper(std::process::Command::new(&bin).arg("30").spawn().unwrap());
        let uid = nix::unistd::getuid().as_raw();
        let mut known = HashMap::new();
        let mut hits = Vec::new();
        for _ in 0..50 {
            hits = scan_proc(&Proc::default(), uid, &mut known)
                .into_iter()
                .filter(|r| r.pid == child.0.id())
                .collect();
            if !hits.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].binary_path, bin.display().to_string());
        assert!(matches!(
            hits[0].origin,
            ExecOrigin::DevShm | ExecOrigin::Tmp
        ));
        assert!(
            scan_proc(&Proc::default(), uid, &mut known)
                .iter()
                .all(|r| r.pid != child.0.id())
        );
    }

    #[tokio::test]
    async fn degraded_scan_then_quarantine_resume_kill() {
        let dir = tempfile::tempdir().unwrap();
        let helper = HelperClient::start(dir.path().join("absent.sock"));
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let threat = Threat::start(hub.clone(), helper, Proc::default(), None);
        wait_state(&hub, ModuleState::Degraded).await;

        let (_bin_dir, bin) = planted_sleep();
        let mut child = Reaper(std::process::Command::new(&bin).arg("30").spawn().unwrap());
        let pid = child.0.id();
        let alert = loop {
            match next(&mut events).await {
                Event::ThreatExecDetected(a) if a.pid == pid => break a,
                _ => continue,
            }
        };
        assert_eq!(alert.state, AlertState::Open);
        let target = AlertTarget {
            alert_id: alert.alert_id,
            pid,
        };

        let wrong = threat
            .quarantine(AlertTarget {
                alert_id: alert.alert_id,
                pid: pid + 1,
            })
            .await
            .unwrap_err();
        assert_eq!(wrong.kind(), Some(ErrorCode::NotFound));

        let q = threat.quarantine(target.clone()).await.unwrap();
        assert_eq!(q.state, AlertState::Quarantined);
        wait_process_state(pid, "T").await;
        assert_eq!(
            threat.dismiss(target.clone()).await.unwrap_err().kind(),
            Some(ErrorCode::InvalidParams)
        );

        assert_eq!(
            threat.resume(target.clone()).await.unwrap().state,
            AlertState::Open
        );
        let killed = threat
            .kill(KillProcessParams {
                alert_id: alert.alert_id,
                pid,
                signal: KillSignal::Kill,
            })
            .await
            .unwrap();
        assert_eq!(killed.state, AlertState::Killed);
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.0.wait().unwrap().signal(), Some(9));
        // Other tests' planted processes may be detected in between.
        let resolved = loop {
            match next(&mut events).await {
                Event::ThreatAlertResolved(r) if r.alert_id == alert.alert_id => break r,
                _ => continue,
            }
        };
        assert_eq!(resolved.state, AlertState::Killed);
        // Other tests may plant binaries concurrently; only this alert matters.
        assert!(
            threat
                .list()
                .alerts
                .iter()
                .all(|a| a.alert_id != alert.alert_id)
        );
        assert_eq!(
            threat.dismiss(target).await.unwrap_err().kind(),
            Some(ErrorCode::NotFound)
        );
    }

    #[tokio::test]
    async fn a_dropped_file_is_reported_and_its_run_carries_dropped_at() {
        let dir = tempfile::tempdir().unwrap();
        let helper = HelperClient::start(dir.path().join("absent.sock"));
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        // The planted directory stands in for /tmp, so the /proc scan still
        // classifies the run.
        let (bin_dir, bin) = planted_sleep();
        std::fs::remove_file(&bin).unwrap();
        let env = DropEnv {
            dirs: vec![bin_dir.path().to_owned()],
            ..DropEnv::default()
        };
        let _threat = Threat::start(hub.clone(), helper, Proc::default(), Some(env));
        wait_state(&hub, ModuleState::Degraded).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        let sleep = ["/usr/bin/sleep", "/bin/sleep"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .unwrap();
        std::fs::copy(sleep, &bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let drop = next_drop(&mut events).await;
        assert_eq!(drop.path, bin.display().to_string());
        assert_eq!(drop.uid, nix::unistd::getuid().as_raw());

        let child = Reaper(std::process::Command::new(&bin).arg("30").spawn().unwrap());
        let alert = loop {
            match next(&mut events).await {
                Event::ThreatExecDetected(a) if a.pid == child.0.id() => break a,
                _ => continue,
            }
        };
        assert_eq!(alert.dropped_at, Some(drop.detected_at));
    }

    #[tokio::test]
    async fn other_users_drops_need_the_helper() {
        let file = |uid| FileDrop {
            path: format!("/tmp/from-{uid}"),
            uid,
            size: 1,
            detected_at: 1,
        };
        let own = nix::unistd::getuid().as_raw();
        let other = own.wrapping_add(1);

        let dir = tempfile::tempdir().unwrap();
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let absent = HelperClient::start(dir.path().join("absent.sock"));
        let threat = Threat::start(hub.clone(), absent, Proc::default(), None);
        wait_state(&hub, ModuleState::Degraded).await;
        threat.on_drop(file(other));
        threat.on_drop(file(own));
        assert_eq!(next_drop(&mut events).await, file(own));

        let fake = FakeHelper::start(hello(true), Arc::new(|_| Ok(Value::Null)));
        let helper = HelperClient::start(fake.path());
        wait_connected(&helper).await;
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let threat = Threat::start(hub.clone(), helper, Proc::default(), None);
        wait_state(&hub, ModuleState::Active).await;
        threat.on_drop(file(other));
        assert_eq!(next_drop(&mut events).await, file(other));
    }

    #[tokio::test]
    async fn helper_records_become_alerts_and_other_users_go_through_the_helper() {
        let respond: crate::helper_client::tests::Respond = Arc::new(|op| match op {
            HelperOp::Signal { .. } => Err(HelperError::new(
                HelperErrorKind::PermissionDenied,
                "not authorized",
            )),
            _ => Ok(Value::Null),
        });
        let fake = FakeHelper::start(hello(true), respond);
        let helper = HelperClient::start(fake.path());
        wait_connected(&helper).await;
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let threat = Threat::start(hub.clone(), helper, Proc::default(), None);
        wait_state(&hub, ModuleState::Active).await;

        // A process of "another user": init, which is always alive. Its
        // start time is read so the liveness check passes.
        let init_start = Proc::default().stat(1).unwrap().start_time;
        let record = ExecRecord {
            pid: 1,
            ppid: 0,
            uid: 0,
            start_time: init_start,
            origin: ExecOrigin::Tmp,
            binary_path: "/tmp/evil".into(),
            argv: vec!["/tmp/evil".into()],
        };
        fake.exec.send(record.clone()).unwrap();
        let alert = match next(&mut events).await {
            Event::ThreatExecDetected(a) => a,
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(
            (alert.pid, alert.uid, alert.binary_path.as_str()),
            (1, 0, "/tmp/evil")
        );
        // Duplicates are ignored.
        fake.exec.send(record).unwrap();

        let err = threat
            .kill(KillProcessParams {
                alert_id: alert.alert_id,
                pid: 1,
                signal: KillSignal::Term,
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::PermissionDenied));
        assert!(fake.requests.lock().unwrap().iter().any(|op| matches!(
            op,
            HelperOp::Signal {
                pid: 1,
                signal: HelperSignal::Term,
                ..
            }
        )));
        assert_eq!(
            threat.list().alerts.len(),
            1,
            "a failed kill leaves the alert open"
        );

        let dismissed = threat
            .dismiss(AlertTarget {
                alert_id: alert.alert_id,
                pid: 1,
            })
            .await
            .unwrap();
        assert_eq!(dismissed.state, AlertState::Dismissed);
    }
}
