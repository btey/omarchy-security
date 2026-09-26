// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon's connection to `omarchy-securityd-helper`.
//!
//! One task owns the socket. It connects, says hello, subscribes to exec
//! records when the helper has the monitor, and then serves requests from
//! the modules until the connection drops. Connection records (after a
//! module sends `connection_subscribe`) are relayed on
//! [`HelperClient::connections`]. It reconnects with backoff, so
//! the helper can be installed, started, or restarted while the daemon
//! runs. Modules follow [`HelperState`] to report their own state.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use omarchy_security_proto::MAX_FRAME_BYTES;
use omarchy_security_proto::helper::{
    ConnectionRecord, ExecRecord, HELPER_PROTOCOL_VERSION, HELPER_SOCKET, HELPER_SOCKET_ENV,
    HelperError, HelperErrorKind, HelperHello, HelperMessage, HelperOp, HelperRequest,
};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Allows for a polkit authentication dialog.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperState {
    Disconnected(String),
    Connected {
        hello: HelperHello,
        /// Outcome of `exec_subscribe`: `Err` holds why no records flow.
        exec: Result<(), String>,
    },
}

type Reply = oneshot::Sender<Result<Value, HelperError>>;

pub struct HelperClient {
    state: watch::Sender<HelperState>,
    requests: mpsc::Sender<(HelperOp, Reply)>,
    exec: broadcast::Sender<ExecRecord>,
    connections: broadcast::Sender<ConnectionRecord>,
}

pub fn default_socket() -> PathBuf {
    std::env::var_os(HELPER_SOCKET_ENV)
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| HELPER_SOCKET.into())
}

fn unavailable(message: impl Into<String>) -> HelperError {
    HelperError::new(HelperErrorKind::Unavailable, message)
}

impl HelperClient {
    pub fn start(path: PathBuf) -> Arc<Self> {
        let (requests, rx) = mpsc::channel(32);
        let client = Arc::new(Self {
            state: watch::channel(HelperState::Disconnected("connecting".into())).0,
            requests,
            exec: broadcast::channel(256).0,
            connections: broadcast::channel(256).0,
        });
        tokio::spawn(run(path, client.clone(), rx));
        client
    }

    pub fn state(&self) -> watch::Receiver<HelperState> {
        self.state.subscribe()
    }

    pub fn exec_records(&self) -> broadcast::Receiver<ExecRecord> {
        self.exec.subscribe()
    }

    /// Outbound connections the helper holds for a verdict. Only flows
    /// while a `connection_subscribe` made through [`Self::request`] is
    /// active on the current helper connection; a reconnect ends it.
    pub fn connections(&self) -> broadcast::Receiver<ConnectionRecord> {
        self.connections.subscribe()
    }

    pub async fn request(&self, op: HelperOp) -> Result<Value, HelperError> {
        let (tx, rx) = oneshot::channel();
        self.requests
            .send((op, tx))
            .await
            .map_err(|_| unavailable("helper client stopped"))?;
        match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(unavailable("connection to the privileged helper was lost")),
            Err(_) => Err(unavailable("the privileged helper did not answer")),
        }
    }
}

impl HelperClient {
    /// Forwards a pushed record to its subscribers.
    fn relay(&self, message: HelperMessage) {
        match message {
            HelperMessage::Exec(record) => {
                let _ = self.exec.send(record);
            }
            HelperMessage::Connection(record) => {
                let _ = self.connections.send(record);
            }
            HelperMessage::Response { .. } => {}
        }
    }
}

struct Connection {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    next_id: u64,
    line: Vec<u8>,
}

impl Connection {
    async fn send(&mut self, op: HelperOp) -> std::io::Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let mut frame = serde_json::to_string(&HelperRequest { id, op })?;
        frame.push('\n');
        self.writer.write_all(frame.as_bytes()).await?;
        Ok(id)
    }

    /// Next message, or `None` at end of stream or on a bad frame.
    async fn recv(&mut self) -> Option<HelperMessage> {
        loop {
            self.line.clear();
            let limit = MAX_FRAME_BYTES as u64 + 1;
            match (&mut self.reader)
                .take(limit)
                .read_until(b'\n', &mut self.line)
                .await
            {
                Ok(0) | Err(_) => return None,
                Ok(_) if self.line.last() != Some(&b'\n') => return None,
                Ok(_) => {}
            }
            match serde_json::from_slice(&self.line) {
                Ok(message) => return Some(message),
                Err(err) => tracing::warn!("ignoring bad helper message: {err}"),
            }
        }
    }

    /// Sends `op` and waits for its response, forwarding anything else.
    async fn call(&mut self, op: HelperOp, client: &HelperClient) -> Result<Value, HelperError> {
        let id = self
            .send(op)
            .await
            .map_err(|e| unavailable(format!("writing to helper: {e}")))?;
        loop {
            match self.recv().await {
                None => return Err(unavailable("helper closed the connection")),
                Some(HelperMessage::Response {
                    id: got,
                    result,
                    error,
                }) if got == id => {
                    return error.map_or(Ok(result), Err);
                }
                Some(HelperMessage::Response { .. }) => {}
                Some(other) => client.relay(other),
            }
        }
    }
}

async fn handshake(
    path: &PathBuf,
    client: &HelperClient,
) -> Result<(Connection, HelperState), String> {
    let stream = UnixStream::connect(path).await.map_err(|e| {
        format!(
            "privileged helper is not reachable at {}: {e}",
            path.display()
        )
    })?;
    let (reader, writer) = stream.into_split();
    let mut conn = Connection {
        reader: BufReader::new(reader),
        writer,
        next_id: 1,
        line: Vec::new(),
    };
    let hello = conn
        .call(
            HelperOp::Hello {
                version: HELPER_PROTOCOL_VERSION,
            },
            client,
        )
        .await
        .map_err(|e| format!("helper hello failed: {e}"))?;
    let hello: HelperHello =
        serde_json::from_value(hello).map_err(|e| format!("bad helper hello: {e}"))?;
    let exec = if hello.exec_monitor {
        conn.call(HelperOp::ExecSubscribe, client)
            .await
            .map(|_| ())
            .map_err(|e| e.message)
    } else {
        Err(hello
            .exec_monitor_detail
            .clone()
            .unwrap_or_else(|| "exec monitor not loaded".into()))
    };
    Ok((conn, HelperState::Connected { hello, exec }))
}

async fn run(
    path: PathBuf,
    client: Arc<HelperClient>,
    mut requests: mpsc::Receiver<(HelperOp, Reply)>,
) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let (mut conn, state) = match handshake(&path, &client).await {
            Ok(connected) => connected,
            Err(reason) => {
                client.state.send_if_modified(|s| {
                    let next = HelperState::Disconnected(reason.clone());
                    let changed = *s != next;
                    *s = next;
                    changed
                });
                // Refuse requests while waiting to retry.
                let retry = tokio::time::sleep(backoff);
                tokio::pin!(retry);
                loop {
                    tokio::select! {
                        _ = &mut retry => break,
                        request = requests.recv() => match request {
                            Some((_, reply)) => {
                                let _ = reply.send(Err(unavailable("the privileged helper (omarchy-securityd-helper) is not running")));
                            }
                            None => return,
                        },
                    }
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        tracing::info!(helper = %path.display(), ?state, "connected to helper");
        backoff = Duration::from_secs(1);
        client.state.send_replace(state);

        let mut pending: HashMap<u64, Reply> = HashMap::new();
        loop {
            tokio::select! {
                request = requests.recv() => {
                    let Some((op, reply)) = request else { return };
                    match conn.send(op).await {
                        Ok(id) => { pending.insert(id, reply); }
                        Err(err) => {
                            let _ = reply.send(Err(unavailable(format!("writing to helper: {err}"))));
                            break;
                        }
                    }
                }
                message = conn.recv() => match message {
                    None => break,
                    Some(HelperMessage::Response { id, result, error }) => {
                        if let Some(reply) = pending.remove(&id) {
                            let _ = reply.send(error.map_or(Ok(result), Err));
                        }
                    }
                    Some(other) => client.relay(other),
                },
            }
        }
        tracing::warn!("lost connection to helper");
        for (_, reply) in pending.drain() {
            let _ = reply.send(Err(unavailable(
                "connection to the privileged helper was lost",
            )));
        }
        client.state.send_replace(HelperState::Disconnected(
            "connection to the privileged helper was lost".into(),
        ));
    }
}

#[cfg(test)]
pub mod tests {
    //! A scripted fake helper for the module tests.

    use super::*;
    use serde_json::json;
    use std::sync::Mutex;
    use tokio::net::UnixListener;

    /// Answers requests with `respond`, and pushes exec records sent on
    /// `exec`, and connection records sent on `connections`, to every
    /// connection subscribed to them.
    pub struct FakeHelper {
        pub dir: tempfile::TempDir,
        pub requests: Arc<Mutex<Vec<HelperOp>>>,
        pub exec: broadcast::Sender<ExecRecord>,
        pub connections: broadcast::Sender<ConnectionRecord>,
    }

    pub type Respond = Arc<dyn Fn(&HelperOp) -> Result<Value, HelperError> + Send + Sync>;

    impl FakeHelper {
        pub fn path(&self) -> PathBuf {
            self.dir.path().join("helper.sock")
        }

        pub fn start(hello: HelperHello, respond: Respond) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let listener = UnixListener::bind(dir.path().join("helper.sock")).unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let (exec, _) = broadcast::channel(16);
            let (connections, _) = broadcast::channel(16);
            let (log, records, held) = (requests.clone(), exec.clone(), connections.clone());
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let (log, respond, hello, mut records, mut held) = (
                        log.clone(),
                        respond.clone(),
                        hello.clone(),
                        records.subscribe(),
                        held.subscribe(),
                    );
                    tokio::spawn(async move {
                        let (r, mut w) = stream.into_split();
                        let mut lines = BufReader::new(r).lines();
                        let mut subscribed = false;
                        let mut prompting = false;
                        loop {
                            tokio::select! {
                                line = lines.next_line() => {
                                    let Ok(Some(line)) = line else { return };
                                    let request: HelperRequest = serde_json::from_str(&line).unwrap();
                                    let reply = match &request.op {
                                        HelperOp::Hello { .. } => Ok(serde_json::to_value(&hello).unwrap()),
                                        op => {
                                            log.lock().unwrap().push(op.clone());
                                            let reply = respond(op);
                                            match op {
                                                HelperOp::ExecSubscribe => subscribed = true,
                                                HelperOp::ConnectionSubscribe { .. } => prompting = reply.is_ok(),
                                                HelperOp::ConnectionUnsubscribe => prompting = false,
                                                _ => {}
                                            }
                                            reply
                                        }
                                    };
                                    let message = match reply {
                                        Ok(result) => json!({"type": "response", "id": request.id, "result": result}),
                                        Err(error) => json!({"type": "response", "id": request.id, "error": error}),
                                    };
                                    if w.write_all(format!("{message}\n").as_bytes()).await.is_err() { return }
                                }
                                record = records.recv(), if subscribed => {
                                    let Ok(record) = record else { return };
                                    let message = serde_json::to_string(&HelperMessage::Exec(record)).unwrap();
                                    if w.write_all(format!("{message}\n").as_bytes()).await.is_err() { return }
                                }
                                record = held.recv(), if prompting => {
                                    let Ok(record) = record else { return };
                                    let message = serde_json::to_string(&HelperMessage::Connection(record)).unwrap();
                                    if w.write_all(format!("{message}\n").as_bytes()).await.is_err() { return }
                                }
                            }
                        }
                    });
                }
            });
            Self {
                dir,
                requests,
                exec,
                connections,
            }
        }
    }

    pub fn hello(exec_monitor: bool) -> HelperHello {
        HelperHello {
            version: HELPER_PROTOCOL_VERSION,
            exec_monitor,
            exec_monitor_detail: (!exec_monitor).then(|| "object missing".into()),
            firewall: true,
            connections: false,
            connections_detail: None,
        }
    }

    pub async fn wait_connected(client: &HelperClient) -> HelperState {
        let mut state = client.state();
        let connected = state.wait_for(|s| matches!(s, HelperState::Connected { .. }));
        tokio::time::timeout(Duration::from_secs(5), connected)
            .await
            .expect("connects within 5 s")
            .unwrap()
            .clone()
    }

    #[tokio::test]
    async fn connects_subscribes_and_relays() {
        let fake = FakeHelper::start(hello(true), Arc::new(|_| Ok(Value::Null)));
        let client = HelperClient::start(fake.path());
        let state = wait_connected(&client).await;
        assert!(matches!(state, HelperState::Connected { exec: Ok(()), .. }));
        assert_eq!(*fake.requests.lock().unwrap(), [HelperOp::ExecSubscribe]);
        client
            .request(HelperOp::FirewallApply { rules: vec![] })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn reports_a_missing_helper_and_refuses_requests() {
        let dir = tempfile::tempdir().unwrap();
        let client = HelperClient::start(dir.path().join("absent.sock"));
        let mut state = client.state();
        let disconnected = state
            .wait_for(|s| matches!(s, HelperState::Disconnected(r) if r.contains("not reachable")));
        tokio::time::timeout(Duration::from_secs(5), disconnected)
            .await
            .unwrap()
            .unwrap();
        let err = client.request(HelperOp::ExecSubscribe).await.unwrap_err();
        assert_eq!(err.kind, HelperErrorKind::Unavailable);
    }

    #[tokio::test]
    async fn surfaces_a_denied_subscription() {
        let fake = FakeHelper::start(
            hello(true),
            Arc::new(|_| {
                Err(HelperError::new(
                    HelperErrorKind::PermissionDenied,
                    "not authorized",
                ))
            }),
        );
        let client = HelperClient::start(fake.path());
        match wait_connected(&client).await {
            HelperState::Connected {
                exec: Err(reason), ..
            } => assert_eq!(reason, "not authorized"),
            other => panic!("unexpected {other:?}"),
        }
    }
}
