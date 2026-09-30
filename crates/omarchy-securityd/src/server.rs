// SPDX-License-Identifier: GPL-3.0-or-later

//! The client socket (task 2.1): NDJSON JSON-RPC over a Unix stream socket,
//! as specified in `docs/ipc-protocol.md` §1 and §3.
//!
//! Each connection gets a reader and a writer task. The reader handles the
//! session methods (`HELLO`, `PING`, `GET_STATUS`, `SUBSCRIBE`) in order,
//! so a pipelined request after `HELLO` sees the handshake as done, and
//! spawns everything else so that a slow backend call does not hold up the
//! requests behind it. The writer merges responses with the events of the
//! topics the client subscribed to.

use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use omarchy_security_proto::methods::{
    Empty, HelloParams, HelloResult, StatusResult, SubscribeParams, SubscribeResult,
};
use omarchy_security_proto::types::Topic;
use omarchy_security_proto::{
    Call, ErrorCode, Event, Id, MAX_FRAME_BYTES, Notification, PROTOCOL_VERSION, Response,
    RpcError, encode_frame, parse_request,
};
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, broadcast, mpsc, watch};

use crate::hub::Hub;

/// Requests one connection may have in flight at once.
const MAX_IN_FLIGHT: usize = 32;

/// Handles every method that is not a session method.
pub trait Dispatcher: Send + Sync + 'static {
    fn call(&self, call: Call) -> impl Future<Output = Result<Value, RpcError>> + Send;
}

pub struct Server<D> {
    listener: UnixListener,
    path: PathBuf,
    hub: Arc<Hub>,
    dispatcher: Arc<D>,
    uid: u32,
}

impl<D: Dispatcher> Server<D> {
    /// Binds the socket at `path`, creating its directory with mode `0700`
    /// if it is missing and replacing a stale socket left by a crash.
    pub fn bind(path: &Path, hub: Arc<Hub>, dispatcher: Arc<D>) -> Result<Self> {
        let dir = path
            .parent()
            .context("socket path has no parent directory")?;
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        remove_stale_socket(path)?;
        let listener =
            UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting permissions on {}", path.display()))?;
        Ok(Self {
            listener,
            path: path.to_owned(),
            hub,
            dispatcher,
            uid: nix::unistd::getuid().as_raw(),
        })
    }

    /// Accepts connections until `shutdown` resolves, then removes the
    /// socket file. Open connections are dropped with the runtime.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => break,
                accepted = self.listener.accept() => match accepted {
                    Ok((stream, _)) => self.admit(stream),
                    Err(err) => {
                        tracing::warn!("accept failed: {err}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                },
            }
        }
        if let Err(err) = std::fs::remove_file(&self.path) {
            tracing::warn!("removing {}: {err}", self.path.display());
        }
    }

    fn admit(&self, stream: UnixStream) {
        let peer = match stream.peer_cred() {
            Ok(cred) => cred,
            Err(err) => {
                tracing::warn!("dropping connection: SO_PEERCRED failed: {err}");
                return;
            }
        };
        if peer.uid() != self.uid {
            tracing::warn!(peer_uid = peer.uid(), peer_pid = ?peer.pid(), "dropping connection from another user");
            return;
        }
        tracing::debug!(peer_pid = ?peer.pid(), "client connected");
        let hub = self.hub.clone();
        let dispatcher = self.dispatcher.clone();
        tokio::spawn(async move {
            connection(stream, hub, dispatcher).await;
            tracing::debug!(peer_pid = ?peer.pid(), "client disconnected");
        });
    }
}

fn remove_stale_socket(path: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("inspecting {}", path.display())),
    };
    if !meta.file_type().is_socket() {
        bail!("{} exists and is not a socket", path.display());
    }
    if std::os::unix::net::UnixStream::connect(path).is_ok() {
        bail!(
            "another omarchy-securityd is already listening on {}",
            path.display()
        );
    }
    std::fs::remove_file(path).with_context(|| format!("removing stale {}", path.display()))
}

/// Why a frame could not be read.
#[derive(Debug)]
pub enum FrameError {
    TooLong,
    Io(io::Error),
}

/// Reads one newline-terminated frame into `buf` without the newline.
/// Returns `Ok(false)` at end of stream; a partial last line is dropped.
pub async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<bool, FrameError> {
    buf.clear();
    loop {
        let available = reader.fill_buf().await.map_err(FrameError::Io)?;
        if available.is_empty() {
            return Ok(false);
        }
        let (chunk, done) = match available.iter().position(|&b| b == b'\n') {
            Some(i) => (&available[..i], true),
            None => (available, false),
        };
        if buf.len() + chunk.len() > MAX_FRAME_BYTES {
            return Err(FrameError::TooLong);
        }
        buf.extend_from_slice(chunk);
        let used = chunk.len() + usize::from(done);
        reader.consume(used);
        if done {
            return Ok(true);
        }
    }
}

struct Session {
    hello: bool,
    topics: watch::Sender<HashSet<Topic>>,
}

async fn connection<D: Dispatcher>(stream: UnixStream, hub: Arc<Hub>, dispatcher: Arc<D>) {
    let (read_half, write_half) = stream.into_split();
    let (out_tx, out_rx) = mpsc::channel::<Response>(MAX_IN_FLIGHT);
    let (topics_tx, topics_rx) = watch::channel(HashSet::new());
    let events = hub.subscribe();

    let writer = tokio::spawn(write_loop(write_half, out_rx, events, topics_rx));

    let mut session = Session {
        hello: false,
        topics: topics_tx,
    };
    let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let mut reader = BufReader::new(read_half);
    let mut frame = Vec::new();
    loop {
        match read_frame(&mut reader, &mut frame).await {
            Ok(true) => {}
            Ok(false) => break,
            Err(FrameError::TooLong) => {
                tracing::warn!("closing connection: frame longer than {MAX_FRAME_BYTES} bytes");
                break;
            }
            Err(FrameError::Io(err)) => {
                tracing::debug!("read failed: {err}");
                break;
            }
        }
        if frame.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let request = match parse_request(&frame) {
            Ok(request) => request,
            Err(response) => {
                if out_tx.send(response).await.is_err() {
                    break;
                }
                continue;
            }
        };
        let id = request.id;
        let response = match request.call {
            Call::Hello(params) => Some(hello(&mut session, &hub, id, params)),
            _ if !session.hello => Some(Response::error(
                Some(id),
                RpcError::new(ErrorCode::HandshakeRequired, "send HELLO first"),
            )),
            Call::Ping(_) => Some(Response::result(id, &Empty {})),
            Call::GetStatus(_) => Some(Response::result(id, &status(&hub))),
            Call::Subscribe(params) => Some(subscribe(&session, &hub, id, params)),
            call => {
                let Ok(permit) = in_flight.clone().acquire_owned().await else {
                    break;
                };
                let dispatcher = dispatcher.clone();
                let out_tx = out_tx.clone();
                tokio::spawn(async move {
                    let response = match dispatcher.call(call).await {
                        Ok(result) => Response::result(id, &result),
                        Err(error) => Response::error(Some(id), error),
                    };
                    let _ = out_tx.send(response).await;
                    drop(permit);
                });
                None
            }
        };
        if let Some(response) = response
            && out_tx.send(response).await.is_err()
        {
            break;
        }
    }
    hub.set_topics(&session.topics.borrow(), &HashSet::new());
    drop(out_tx);
    // Let responses still in flight drain; the writer stops when the last
    // sender is gone or the peer is.
    let _ = writer.await;
}

fn hello(session: &mut Session, hub: &Hub, id: Id, params: HelloParams) -> Response {
    if params.protocol_version != PROTOCOL_VERSION {
        return Response::error(
            Some(id),
            RpcError::new(
                ErrorCode::UnsupportedProtocolVersion,
                format!(
                    "protocol version {} is not supported",
                    params.protocol_version
                ),
            )
            .with_data(json!({ "supported": [PROTOCOL_VERSION] })),
        );
    }
    session.hello = true;
    tracing::debug!(client = %params.client, "handshake");
    Response::result(
        id,
        &HelloResult {
            protocol_version: PROTOCOL_VERSION,
            daemon_version: env!("CARGO_PKG_VERSION").into(),
            modules: hub.statuses(),
        },
    )
}

fn status(hub: &Hub) -> StatusResult {
    StatusResult {
        protocol_version: PROTOCOL_VERSION,
        daemon_version: env!("CARGO_PKG_VERSION").into(),
        uptime_secs: hub.uptime_secs(),
        modules: hub.statuses(),
    }
}

fn subscribe(session: &Session, hub: &Hub, id: Id, params: SubscribeParams) -> Response {
    let mut topics = Vec::new();
    for topic in params.topics {
        if !topics.contains(&topic) {
            topics.push(topic);
        }
    }
    let new: HashSet<Topic> = topics.iter().copied().collect();
    let old = session.topics.send_replace(new.clone());
    hub.set_topics(&old, &new);
    Response::result(id, &SubscribeResult { topics })
}

async fn write_loop(
    mut writer: tokio::net::unix::OwnedWriteHalf,
    mut responses: mpsc::Receiver<Response>,
    mut events: broadcast::Receiver<Event>,
    topics: watch::Receiver<HashSet<Topic>>,
) {
    loop {
        let frame = tokio::select! {
            response = responses.recv() => match response {
                Some(response) => encode_frame(&response),
                None => break,
            },
            event = events.recv() => match event {
                Ok(event) => {
                    if !topics.borrow().contains(&event.topic()) {
                        continue;
                    }
                    encode_frame(&Notification::from(event))
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    tracing::warn!("closing connection: client fell {missed} events behind");
                    break;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
        };
        let frame = match frame {
            Ok(frame) => frame,
            Err(err) => {
                tracing::error!("encoding frame: {err}");
                continue;
            }
        };
        if writer.write_all(frame.as_bytes()).await.is_err() {
            break;
        }
    }
    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use omarchy_security_proto::types::{Module, ModuleState};
    use serde_json::Value;
    use tokio::io::AsyncReadExt;

    struct Echo;

    impl Dispatcher for Echo {
        async fn call(&self, call: Call) -> Result<Value, RpcError> {
            match call {
                Call::PostureGetReport(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    Ok(json!({ "slow": true }))
                }
                call => Ok(json!({ "method": call.method() })),
            }
        }
    }

    struct Client {
        reader: BufReader<tokio::net::unix::OwnedReadHalf>,
        writer: tokio::net::unix::OwnedWriteHalf,
    }

    impl Client {
        async fn connect(path: &Path) -> Self {
            let (r, w) = UnixStream::connect(path).await.unwrap().into_split();
            Self {
                reader: BufReader::new(r),
                writer: w,
            }
        }

        async fn send(&mut self, frame: &str) {
            self.writer.write_all(frame.as_bytes()).await.unwrap();
            self.writer.write_all(b"\n").await.unwrap();
        }

        async fn call(&mut self, id: i64, method: &str, params: Value) -> Value {
            self.send(
                &json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
                    .to_string(),
            )
            .await;
            self.recv().await
        }

        async fn recv(&mut self) -> Value {
            let mut line = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.reader.read_line(&mut line),
            )
            .await
            .expect("reply within 5 s")
            .unwrap();
            serde_json::from_str(&line).unwrap()
        }

        async fn hello(&mut self) -> Value {
            self.call(1, "HELLO", json!({"protocol_version": 1, "client": "test"}))
                .await
        }
    }

    fn start() -> (
        tempfile::TempDir,
        PathBuf,
        Arc<Hub>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/securityd.sock");
        let hub = Arc::new(Hub::new());
        let server = Server::bind(&path, hub.clone(), Arc::new(Echo)).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        tokio::spawn(server.serve(async {
            let _ = stopped.await;
        }));
        (dir, path, hub, stop)
    }

    #[tokio::test]
    async fn socket_and_directory_are_private() {
        let (_dir, path, _hub, _stop) = start();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
    }

    #[tokio::test]
    async fn refuses_to_replace_a_live_socket() {
        let (_dir, path, hub, _stop) = start();
        assert!(Server::bind(&path, hub, Arc::new(Echo)).is_err());
    }

    #[tokio::test]
    async fn requires_hello_then_serves() {
        let (_dir, path, _hub, _stop) = start();
        let mut client = Client::connect(&path).await;
        let reply = client.call(1, "PING", json!(null)).await;
        assert_eq!(reply["error"]["code"], -32000);

        let reply = client
            .call(2, "HELLO", json!({"protocol_version": 99, "client": "t"}))
            .await;
        assert_eq!(reply["error"]["code"], -32001);
        assert_eq!(reply["error"]["data"]["supported"], json!([1]));

        let reply = client.hello().await;
        assert_eq!(reply["result"]["protocol_version"], 1);
        assert_eq!(
            reply["result"]["modules"].as_array().unwrap().len(),
            Module::ALL.len()
        );

        let reply = client.call(3, "PING", json!({})).await;
        assert_eq!(reply, json!({"jsonrpc": "2.0", "id": 3, "result": {}}));
        let reply = client.call(4, "TOKEN_LIST", json!(null)).await;
        assert_eq!(reply["result"]["method"], "TOKEN_LIST");
    }

    #[tokio::test]
    async fn pipelined_requests_answer_out_of_order() {
        let (_dir, path, _hub, _stop) = start();
        let mut client = Client::connect(&path).await;
        // HELLO and the requests behind it arrive in one write.
        client
            .send(concat!(
                r#"{"jsonrpc":"2.0","id":1,"method":"HELLO","params":{"protocol_version":1,"client":"t"}}"#, "\n",
                r#"{"jsonrpc":"2.0","id":2,"method":"POSTURE_GET_REPORT"}"#, "\n",
                r#"{"jsonrpc":"2.0","id":3,"method":"TOKEN_LIST"}"#
            ))
            .await;
        assert_eq!(client.recv().await["id"], 1);
        assert_eq!(client.recv().await["id"], 3);
        assert_eq!(client.recv().await["id"], 2);
    }

    #[tokio::test]
    async fn malformed_frames_get_errors_and_keep_the_connection() {
        let (_dir, path, _hub, _stop) = start();
        let mut client = Client::connect(&path).await;
        client.send("{not json").await;
        assert_eq!(client.recv().await["error"]["code"], -32700);
        client.send("").await; // blank lines are ignored
        client
            .send(r#"{"jsonrpc":"2.0","id":5,"method":"NOPE"}"#)
            .await;
        let reply = client.recv().await;
        assert_eq!(
            (reply["id"].clone(), reply["error"]["code"].clone()),
            (json!(5), json!(-32601))
        );
    }

    #[tokio::test]
    async fn oversized_frame_closes_the_connection() {
        let (_dir, path, _hub, _stop) = start();
        let mut client = Client::connect(&path).await;
        let big = "x".repeat(MAX_FRAME_BYTES + 1);
        let _ = client.writer.write_all(big.as_bytes()).await;
        let mut rest = Vec::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.reader.read_to_end(&mut rest),
        )
        .await
        .expect("connection closes");
        assert!(read.is_err() || rest.is_empty());
    }

    #[tokio::test]
    async fn events_follow_subscriptions() {
        let (_dir, path, hub, _stop) = start();
        let mut client = Client::connect(&path).await;
        client.hello().await;
        // Not subscribed yet: this event must not arrive.
        hub.set_status(Module::Posture, ModuleState::Active, None);
        let reply = client
            .call(2, "SUBSCRIBE", json!({"topics": ["system", "system"]}))
            .await;
        assert_eq!(reply["result"]["topics"], json!(["system"]));
        hub.set_status(Module::Posture, ModuleState::Degraded, Some("x".into()));
        let event = client.recv().await;
        assert_eq!(event["method"], "MODULE_STATE_CHANGED");
        assert_eq!(event["params"]["state"], "degraded");

        client
            .call(3, "SUBSCRIBE", json!({"topics": ["posture"]}))
            .await;
        hub.set_status(Module::Posture, ModuleState::Active, None);
        let reply = client.call(4, "PING", json!(null)).await;
        assert_eq!(reply["id"], 4, "system event was filtered out");

        // The hub counts listeners per topic, until the connection closes.
        let mut listeners = hub.listeners();
        let count = |l: &watch::Receiver<_>, topic| {
            let counts: &std::collections::HashMap<Topic, usize> = &l.borrow();
            counts.get(&topic).copied().unwrap_or(0)
        };
        assert_eq!(count(&listeners, Topic::Posture), 1);
        assert_eq!(count(&listeners, Topic::System), 0);
        drop(client);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            listeners.wait_for(|c| c.get(&Topic::Posture) == Some(&0)),
        )
        .await
        .expect("the count drops when the connection closes")
        .unwrap();
    }

    #[tokio::test]
    async fn shutdown_removes_the_socket() {
        let (_dir, path, _hub, stop) = start();
        stop.send(()).unwrap();
        for _ in 0..50 {
            if !path.exists() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("socket still exists after shutdown");
    }
}
