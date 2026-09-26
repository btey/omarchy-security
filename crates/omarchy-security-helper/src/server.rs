// SPDX-License-Identifier: GPL-3.0-or-later

//! The helper socket. Any local process may connect; each operation is
//! authorized with polkit against the connecting process.

use std::future::Future;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use omarchy_security_proto::MAX_FRAME_BYTES;
use omarchy_security_proto::helper::{
    ExecRecord, HELPER_PROTOCOL_VERSION, HelperError, HelperErrorKind, HelperHello, HelperMessage,
    HelperOp, HelperRequest, HelperSignal, actions,
};
use omarchy_security_proto::procfs::Proc;
use omarchy_security_proto::types::FirewallRule;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc};

use crate::connections::{self, Interceptor};
use crate::exec::Reported;
use crate::firewall::{Firewall, QueueRule};
use crate::polkit::{Authorizer, Peer};

pub struct State<A> {
    pub authorizer: A,
    pub firewall: Firewall,
    /// `None` when the exec monitor could not be loaded.
    pub exec: Option<broadcast::Sender<ExecRecord>>,
    pub exec_detail: Option<String>,
    pub reported: Arc<Reported>,
    pub proc: Proc,
    /// `None` when the NFQUEUE could not be bound.
    pub interceptor: Option<Arc<Interceptor>>,
    pub connections_detail: Option<String>,
    /// Queue loopback connections too (tests only).
    pub queue_loopback: bool,
}

/// Longest `connection_subscribe` timeout accepted.
const MAX_CONNECTION_TIMEOUT_SECS: u32 = 3600;

/// One client connection, as the request handlers see it.
#[derive(Clone)]
struct Client {
    id: u64,
    peer: Peer,
    out: mpsc::Sender<HelperMessage>,
    /// Set once the connection has closed.
    closed: Arc<AtomicBool>,
}

pub fn bind(path: &Path) -> Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(_) => {}
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    // Connectable by every local user: polkit decides per operation.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

pub async fn serve<A: Authorizer>(
    listener: UnixListener,
    path: PathBuf,
    state: Arc<State<A>>,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let state = state.clone();
                    tokio::spawn(async move { connection(stream, state).await });
                }
                Err(err) => {
                    tracing::warn!("accept failed: {err}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            },
        }
    }
    let _ = std::fs::remove_file(path);
}

fn error(kind: HelperErrorKind, message: impl Into<String>) -> HelperError {
    HelperError::new(kind, message)
}

async fn connection<A: Authorizer>(stream: UnixStream, state: Arc<State<A>>) {
    let peer = match stream.peer_cred().ok().as_ref().and_then(Peer::from_cred) {
        Some(peer) => peer,
        None => {
            tracing::warn!("dropping connection: cannot identify the peer process");
            return;
        }
    };
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    tracing::info!(pid = peer.pid, uid = peer.uid, "client connected");
    let (read_half, mut write_half) = stream.into_split();
    let (out, mut outgoing) = mpsc::channel::<HelperMessage>(256);
    let client = Client {
        id,
        peer,
        out: out.clone(),
        closed: Arc::new(AtomicBool::new(false)),
    };
    let writer = tokio::spawn(async move {
        while let Some(message) = outgoing.recv().await {
            let Ok(mut line) = serde_json::to_string(&message) else {
                continue;
            };
            line.push('\n');
            if write_half.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });

    let mut reader = BufReader::new(read_half);
    let mut line = Vec::new();
    let mut hello = false;
    let mut subscribed = false;
    loop {
        line.clear();
        let limit = MAX_FRAME_BYTES as u64 + 1;
        match (&mut reader).take(limit).read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if line.last() != Some(&b'\n') {
            tracing::warn!(
                pid = peer.pid,
                "closing connection: frame too long or truncated"
            );
            break;
        }
        let request: HelperRequest = match serde_json::from_slice(&line) {
            Ok(request) => request,
            Err(err) => {
                let _ = out
                    .send(response(
                        0,
                        Err(error(HelperErrorKind::Invalid, err.to_string())),
                    ))
                    .await;
                continue;
            }
        };
        let id = request.id;
        match request.op {
            HelperOp::Hello { version } => {
                let result = if version == HELPER_PROTOCOL_VERSION {
                    hello = true;
                    Ok(serde_json::to_value(HelperHello {
                        version: HELPER_PROTOCOL_VERSION,
                        exec_monitor: state.exec.is_some(),
                        exec_monitor_detail: state.exec_detail.clone(),
                        firewall: state.firewall.available(),
                        connections: state.interceptor.is_some(),
                        connections_detail: state.connections_detail.clone(),
                    })
                    .expect("hello serializes"))
                } else {
                    Err(error(
                        HelperErrorKind::Invalid,
                        format!("helper protocol {version} is not supported"),
                    ))
                };
                let _ = out.send(response(id, result)).await;
            }
            _ if !hello => {
                let _ = out
                    .send(response(
                        id,
                        Err(error(HelperErrorKind::Invalid, "send hello first")),
                    ))
                    .await;
            }
            HelperOp::ExecSubscribe if subscribed => {
                let _ = out.send(response(id, Ok(Value::Null))).await;
            }
            op => {
                if matches!(op, HelperOp::ExecSubscribe) {
                    subscribed = true;
                }
                let state = state.clone();
                let client = client.clone();
                tokio::spawn(async move {
                    let result = handle(&state, &client, op).await;
                    let _ = client.out.send(response(id, result)).await;
                });
            }
        }
    }
    // Release held connections before waiting for the writer: the
    // subscription holds a sender.
    client.closed.store(true, Ordering::SeqCst);
    end_subscription(&state, &client).await;
    drop(client);
    drop(out);
    let _ = writer.await;
    tracing::info!(pid = peer.pid, "client disconnected");
}

fn response(id: u64, result: Result<Value, HelperError>) -> HelperMessage {
    match result {
        Ok(result) => HelperMessage::Response {
            id,
            result,
            error: None,
        },
        Err(err) => HelperMessage::Response {
            id,
            result: Value::Null,
            error: Some(err),
        },
    }
}

async fn authorize<A: Authorizer>(
    state: &State<A>,
    peer: Peer,
    action: &'static str,
    interactive: bool,
) -> Result<(), HelperError> {
    match state.authorizer.authorize(peer, action, interactive).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(error(
            HelperErrorKind::PermissionDenied,
            format!("not authorized for {action}"),
        )),
        Err(reason) => Err(error(HelperErrorKind::PermissionDenied, reason)),
    }
}

fn interceptor<A>(state: &State<A>) -> Result<&Interceptor, HelperError> {
    state.interceptor.as_deref().ok_or_else(|| {
        let detail = state
            .connections_detail
            .clone()
            .unwrap_or_else(|| "not started".into());
        error(
            HelperErrorKind::Unavailable,
            format!("connection interception unavailable: {detail}"),
        )
    })
}

/// Adds, updates or removes the queue rule to match what the interceptor
/// needs now.
async fn sync_queue<A>(state: &State<A>) -> Result<(), HelperError> {
    let Some(interceptor) = &state.interceptor else {
        return Ok(());
    };
    state
        .firewall
        .set_queue(|| {
            interceptor.wanted_queue().map(|uid| QueueRule {
                num: interceptor.queue_num(),
                uid,
                loopback: state.queue_loopback,
            })
        })
        .await
}

/// Ends `client`'s subscription, if any, releasing what it held.
async fn end_subscription<A>(state: &State<A>, client: &Client) {
    if let Some(interceptor) = &state.interceptor {
        interceptor.disconnected(client.id);
        if let Err(err) = sync_queue(state).await {
            tracing::warn!("removing the queue rule: {err}");
        }
    }
}

async fn handle<A: Authorizer>(
    state: &State<A>,
    client: &Client,
    op: HelperOp,
) -> Result<Value, HelperError> {
    let peer = client.peer;
    let out = &client.out;
    match op {
        HelperOp::Hello { .. } => unreachable!("handled inline"),
        HelperOp::ExecSubscribe => {
            authorize(state, peer, actions::THREAT_MONITOR, false).await?;
            let Some(sender) = &state.exec else {
                let detail = state
                    .exec_detail
                    .clone()
                    .unwrap_or_else(|| "not loaded".into());
                return Err(error(
                    HelperErrorKind::Unavailable,
                    format!("exec monitor unavailable: {detail}"),
                ));
            };
            let mut records = sender.subscribe();
            let out = out.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = out.closed() => return,
                        record = records.recv() => match record {
                            Ok(record) => {
                                if out.send(HelperMessage::Exec(record)).await.is_err() {
                                    return;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!(pid = peer.pid, "client missed {n} exec records");
                            }
                            Err(broadcast::error::RecvError::Closed) => return,
                        },
                    }
                }
            });
            Ok(Value::Null)
        }
        HelperOp::FirewallApply { rules } => {
            authorize(state, peer, actions::FIREWALL_MANAGE, true).await?;
            let executable: Vec<FirewallRule> = rules
                .iter()
                .filter(|r| r.spec.executable.is_some())
                .cloned()
                .collect();
            for rule in &executable {
                connections::validate(rule).map_err(|e| error(HelperErrorKind::Invalid, e))?;
            }
            if !executable.is_empty() {
                interceptor(state)?;
            }
            state.firewall.apply(&rules).await?;
            if let Some(interceptor) = &state.interceptor {
                interceptor
                    .set_rules(&executable, peer.uid)
                    .map_err(|e| error(HelperErrorKind::Invalid, e))?;
                sync_queue(state).await?;
            }
            tracing::info!(pid = peer.pid, rules = rules.len(), "firewall applied");
            Ok(Value::Null)
        }
        HelperOp::ConnectionSubscribe {
            timeout_secs,
            timeout_verdict,
        } => {
            authorize(state, peer, actions::FIREWALL_MANAGE, false).await?;
            let interceptor = interceptor(state)?;
            if !(1..=MAX_CONNECTION_TIMEOUT_SECS).contains(&timeout_secs) {
                return Err(error(
                    HelperErrorKind::Invalid,
                    format!("timeout_secs must be 1-{MAX_CONNECTION_TIMEOUT_SECS}"),
                ));
            }
            interceptor.subscribe(
                client.id,
                peer.uid,
                out.clone(),
                Duration::from_secs(timeout_secs.into()),
                timeout_verdict,
            );
            // The connection may have closed while this ran.
            if client.closed.load(Ordering::SeqCst) {
                end_subscription(state, client).await;
                return Err(error(HelperErrorKind::Unavailable, "connection closed"));
            }
            if let Err(err) = sync_queue(state).await {
                end_subscription(state, client).await;
                return Err(err);
            }
            tracing::info!(pid = peer.pid, uid = peer.uid, "connections subscribed");
            Ok(Value::Null)
        }
        HelperOp::ConnectionUnsubscribe => {
            // Only gives up what this client holds, so needs no action.
            interceptor(state)?;
            end_subscription(state, client).await;
            tracing::info!(pid = peer.pid, "connections unsubscribed");
            Ok(Value::Null)
        }
        HelperOp::ConnectionVerdict {
            request_id,
            verdict,
            remember,
        } => {
            authorize(state, peer, actions::FIREWALL_MANAGE, false).await?;
            interceptor(state)?.verdict(client.id, request_id, verdict, remember)?;
            Ok(Value::Null)
        }
        HelperOp::Signal {
            pid,
            start_time,
            signal,
        } => {
            authorize(state, peer, actions::THREAT_RESPOND, true).await?;
            if pid <= 1 || !state.reported.contains(pid, start_time) {
                return Err(error(
                    HelperErrorKind::NotFound,
                    format!("process {pid} was not reported by the exec monitor"),
                ));
            }
            if !state.proc.is_same_process(pid, start_time) {
                return Err(error(
                    HelperErrorKind::StaleTarget,
                    format!("process {pid} is no longer the one reported"),
                ));
            }
            use nix::sys::signal::Signal as S;
            let sig = match signal {
                HelperSignal::Term => S::SIGTERM,
                HelperSignal::Kill => S::SIGKILL,
                HelperSignal::Stop => S::SIGSTOP,
                HelperSignal::Cont => S::SIGCONT,
            };
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), sig)
                .map_err(|e| error(HelperErrorKind::Backend, format!("kill({pid}, {sig}): {e}")))?;
            tracing::info!(pid = peer.pid, target = pid, ?signal, "signal sent");
            Ok(Value::Null)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omarchy_security_proto::types::ExecOrigin;
    use serde_json::json;
    use std::sync::Mutex;

    struct Policy {
        allowed: Vec<&'static str>,
        asked: Mutex<Vec<(&'static str, bool)>>,
    }

    impl Authorizer for Policy {
        async fn authorize(
            &self,
            peer: Peer,
            action: &'static str,
            interactive: bool,
        ) -> Result<bool, String> {
            assert_eq!(peer.pid, std::process::id(), "peer is this test process");
            self.asked.lock().unwrap().push((action, interactive));
            Ok(self.allowed.contains(&action))
        }
    }

    struct Harness {
        _dir: tempfile::TempDir,
        state: Arc<State<Policy>>,
        exec: broadcast::Sender<ExecRecord>,
        reader: BufReader<tokio::net::unix::OwnedReadHalf>,
        writer: tokio::net::unix::OwnedWriteHalf,
        next_id: u64,
    }

    impl Harness {
        async fn start(allowed: Vec<&'static str>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("helper.sock");
            let (exec, _) = broadcast::channel(16);
            let state = Arc::new(State {
                authorizer: Policy {
                    allowed,
                    asked: Mutex::new(vec![]),
                },
                firewall: Firewall::with_wrapper(&["unshare", "-rn"]),
                exec: Some(exec.clone()),
                exec_detail: None,
                reported: Arc::new(Reported::default()),
                proc: Proc::default(),
                interceptor: None,
                connections_detail: Some("not in tests".into()),
                queue_loopback: false,
            });
            let listener = bind(&path).unwrap();
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o666
            );
            tokio::spawn(serve(
                listener,
                path.clone(),
                state.clone(),
                std::future::pending(),
            ));
            let (r, w) = UnixStream::connect(&path).await.unwrap().into_split();
            let mut harness = Self {
                _dir: dir,
                state,
                exec,
                reader: BufReader::new(r),
                writer: w,
                next_id: 1,
            };
            let hello = harness
                .call(json!({"op": "hello", "version": HELPER_PROTOCOL_VERSION}))
                .await;
            assert_eq!(hello["result"]["exec_monitor"], true);
            assert_eq!(hello["result"]["connections"], false);
            harness
        }

        async fn call(&mut self, op: Value) -> Value {
            let id = self.next_id;
            self.next_id += 1;
            let mut request = op;
            request["id"] = json!(id);
            self.writer
                .write_all(format!("{request}\n").as_bytes())
                .await
                .unwrap();
            loop {
                let message = self.recv().await;
                if message["type"] == "response" && message["id"] == id {
                    return message;
                }
            }
        }

        async fn recv(&mut self) -> Value {
            let mut line = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                self.reader.read_line(&mut line),
            )
            .await
            .expect("message within 10 s")
            .unwrap();
            serde_json::from_str(&line).unwrap()
        }
    }

    fn record(pid: u32, start_time: u64) -> ExecRecord {
        ExecRecord {
            pid,
            ppid: 1,
            uid: 1000,
            start_time,
            origin: ExecOrigin::Tmp,
            binary_path: "/tmp/x".into(),
            argv: vec!["/tmp/x".into()],
        }
    }

    #[tokio::test]
    async fn requires_hello_and_authorization() {
        let mut h = Harness::start(vec![]).await;
        let denied = h.call(json!({"op": "exec_subscribe"})).await;
        assert_eq!(denied["error"]["kind"], "permission_denied");
        let denied = h.call(json!({"op": "firewall_apply", "rules": []})).await;
        assert_eq!(denied["error"]["kind"], "permission_denied");
        assert_eq!(
            *h.state.authorizer.asked.lock().unwrap(),
            [
                (actions::THREAT_MONITOR, false),
                (actions::FIREWALL_MANAGE, true)
            ]
        );

        // A fresh connection without hello is refused.
        let path = h._dir.path().join("helper.sock");
        let (r, mut w) = UnixStream::connect(&path).await.unwrap().into_split();
        w.write_all(b"{\"id\":1,\"op\":\"exec_subscribe\"}\n")
            .await
            .unwrap();
        let mut line = String::new();
        BufReader::new(r).read_line(&mut line).await.unwrap();
        assert!(line.contains("send hello first"), "{line}");
    }

    #[tokio::test]
    async fn connection_ops_are_authorized_and_need_the_queue() {
        let mut h = Harness::start(vec![]).await;
        let subscribe =
            json!({"op": "connection_subscribe", "timeout_secs": 30, "timeout_verdict": "block"});
        let denied = h.call(subscribe.clone()).await;
        assert_eq!(denied["error"]["kind"], "permission_denied");
        let verdict = json!({"op": "connection_verdict", "request_id": 1, "verdict": "allow"});
        let denied = h.call(verdict.clone()).await;
        assert_eq!(denied["error"]["kind"], "permission_denied");
        assert_eq!(
            *h.state.authorizer.asked.lock().unwrap(),
            [
                (actions::FIREWALL_MANAGE, false),
                (actions::FIREWALL_MANAGE, false)
            ]
        );

        let mut h = Harness::start(vec![actions::FIREWALL_MANAGE]).await;
        let unavailable = h.call(subscribe).await;
        assert_eq!(unavailable["error"]["kind"], "unavailable");
        assert!(
            unavailable["error"]["message"]
                .as_str()
                .unwrap()
                .contains("not in tests"),
            "{unavailable}"
        );
        assert_eq!(h.call(verdict).await["error"]["kind"], "unavailable");
        let unsubscribe = json!({"op": "connection_unsubscribe"});
        assert_eq!(h.call(unsubscribe).await["error"]["kind"], "unavailable");
        let rule = json!({"rule_id": 1, "verdict": "block", "direction": "outbound",
                          "address": "0.0.0.0/0", "executable": "/usr/bin/curl"});
        let err = h
            .call(json!({"op": "firewall_apply", "rules": [rule]}))
            .await;
        assert_eq!(err["error"]["kind"], "unavailable");
        let inbound = json!({"rule_id": 1, "verdict": "block", "direction": "inbound",
                             "address": "0.0.0.0/0", "executable": "/usr/bin/curl"});
        let err = h
            .call(json!({"op": "firewall_apply", "rules": [inbound]}))
            .await;
        assert_eq!(err["error"]["kind"], "invalid");
    }

    #[tokio::test]
    async fn streams_exec_records_after_subscribing() {
        let mut h = Harness::start(vec![actions::THREAT_MONITOR]).await;
        let ok = h.call(json!({"op": "exec_subscribe"})).await;
        assert!(ok.get("error").is_none(), "{ok}");
        h.exec.send(record(4242, 7)).unwrap();
        let message = h.recv().await;
        assert_eq!(message["type"], "exec");
        assert_eq!(message["pid"], 4242);
        assert_eq!(message["origin"], "tmp");
    }

    #[tokio::test]
    async fn signals_only_reported_processes() {
        let mut h = Harness::start(vec![actions::THREAT_RESPOND]).await;
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let start_time = Proc::default().stat(pid).unwrap().start_time;

        let refused = h
            .call(json!({"op": "signal", "pid": pid, "start_time": start_time, "signal": "kill"}))
            .await;
        assert_eq!(refused["error"]["kind"], "not_found");

        h.state.reported.insert(pid, start_time + 1);
        let stale = h
            .call(
                json!({"op": "signal", "pid": pid, "start_time": start_time + 1, "signal": "kill"}),
            )
            .await;
        assert_eq!(stale["error"]["kind"], "stale_target");

        h.state.reported.insert(pid, start_time);
        let ok = h
            .call(json!({"op": "signal", "pid": pid, "start_time": start_time, "signal": "kill"}))
            .await;
        assert!(ok.get("error").is_none(), "{ok}");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.wait().unwrap().signal(), Some(9));
    }

    #[tokio::test]
    async fn applies_and_reports_firewall_errors() {
        if !std::process::Command::new("unshare")
            .args(["-rn", "true"])
            .status()
            .is_ok_and(|s| s.success())
            || crate::firewall::find_nft().is_none()
        {
            eprintln!("needs nft and unprivileged user namespaces; skipping");
            return;
        }
        let mut h = Harness::start(vec![actions::FIREWALL_MANAGE]).await;
        let rule = json!({"rule_id": 1, "verdict": "block", "direction": "outbound", "address": "192.0.2.0/24", "port": 443, "protocol": "tcp"});
        let ok = h
            .call(json!({"op": "firewall_apply", "rules": [rule]}))
            .await;
        assert!(ok.get("error").is_none(), "{ok}");
        let bad = json!({"rule_id": 2, "verdict": "block", "direction": "outbound", "address": "not-an-ip"});
        let err = h
            .call(json!({"op": "firewall_apply", "rules": [bad]}))
            .await;
        assert_eq!(err["error"]["kind"], "invalid");
    }
}
