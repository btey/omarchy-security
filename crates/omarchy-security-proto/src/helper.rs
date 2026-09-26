// SPDX-License-Identifier: GPL-3.0-or-later

//! Internal protocol between `omarchy-securityd` and
//! `omarchy-securityd-helper`, the privileged system service that loads the
//! eBPF exec monitor, writes `table inet omarchy_sec`, and signals processes
//! the daemon may not signal itself.
//!
//! This is not part of the client contract in `docs/ipc-protocol.md`: only
//! the daemon speaks it, and both ends ship together. Framing is the same
//! NDJSON as the client socket. Each request carries an `id`, and the helper
//! answers it with a `response` of the same `id`. After `exec_subscribe`,
//! the helper also pushes `exec` messages, and after `connection_subscribe`
//! it pushes `connection` messages.
//!
//! The helper authorizes every operation with polkit against the peer's
//! `SO_PEERCRED` process, so the socket itself can be world-connectable.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::types::{ExecOrigin, FirewallRule, Protocol, Verdict};

pub const HELPER_PROTOCOL_VERSION: u32 = 2;

/// Where the helper listens (systemd `RuntimeDirectory=omarchy-security`).
pub const HELPER_SOCKET: &str = "/run/omarchy-security/helper.sock";

/// Overrides [`HELPER_SOCKET`] on the daemon side (tests, dev runs).
pub const HELPER_SOCKET_ENV: &str = "OMARCHY_SECURITY_HELPER_SOCKET";

/// Polkit action ids, one per privileged operation. They are declared in
/// `dist/polkit/org.omarchy.security.policy`.
pub mod actions {
    pub const THREAT_MONITOR: &str = "org.omarchy.security.threat.monitor";
    pub const THREAT_RESPOND: &str = "org.omarchy.security.threat.respond";
    pub const FIREWALL_MANAGE: &str = "org.omarchy.security.firewall.manage";
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelperRequest {
    pub id: u64,
    #[serde(flatten)]
    pub op: HelperOp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum HelperOp {
    /// First request on a connection → [`HelperHello`].
    Hello { version: u32 },
    /// Starts the stream of [`ExecRecord`]s for suspicious executions.
    ExecSubscribe,
    /// Atomically replaces the contents of `table inet omarchy_sec` with
    /// these rules. An empty list deletes the table. Rules with an
    /// `executable` are not written to the table: the helper matches them
    /// against intercepted outbound connections.
    FirewallApply { rules: Vec<FirewallRule> },
    /// Starts the stream of [`ConnectionRecord`]s: new outbound connections
    /// that no executable rule decides are held until a
    /// [`HelperOp::ConnectionVerdict`], or for `timeout_secs`, after which
    /// `timeout_verdict` applies. One connection is subscribed at a time; a
    /// new subscription replaces the old one.
    ConnectionSubscribe {
        timeout_secs: u32,
        timeout_verdict: Verdict,
    },
    /// Ends this connection's subscription. Connections it still holds get
    /// its `timeout_verdict` at once.
    ConnectionUnsubscribe,
    /// Answers a [`ConnectionRecord`] of this connection's subscription.
    ConnectionVerdict {
        request_id: u64,
        verdict: Verdict,
        #[serde(default)]
        remember: Remember,
    },
    /// Signals a process the helper reported in an [`ExecRecord`]. The
    /// helper refuses any other target and re-checks `start_time`.
    Signal {
        pid: u32,
        start_time: u64,
        signal: HelperSignal,
    },
}

/// Whether the helper keeps a connection verdict for later connections.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Remember {
    /// This connection only.
    #[default]
    None,
    /// Every later connection of the same process to the same address,
    /// port and protocol, until the process exits.
    Process,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperSignal {
    Term,
    Kill,
    Stop,
    Cont,
}

/// Result of `hello`: what this helper can do on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperHello {
    pub version: u32,
    /// The eBPF exec monitor is loaded and attached.
    pub exec_monitor: bool,
    /// Why `exec_monitor` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_monitor_detail: Option<String>,
    /// `nft` is available.
    pub firewall: bool,
    /// The helper reads its NFQUEUE, so executable rules and
    /// `connection_subscribe` work.
    #[serde(default)]
    pub connections: bool,
    /// Why `connections` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connections_detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HelperMessage {
    Response {
        id: u64,
        #[serde(default, skip_serializing_if = "Value::is_null")]
        result: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<HelperError>,
    },
    Exec(ExecRecord),
    Connection(ConnectionRecord),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HelperErrorKind {
    Invalid,
    PermissionDenied,
    NotFound,
    StaleTarget,
    Unavailable,
    Backend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct HelperError {
    pub kind: HelperErrorKind,
    pub message: String,
}

impl HelperError {
    pub fn new(kind: HelperErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// A suspicious execution, already classified and enriched from `/proc`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRecord {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    /// `/proc/<pid>/stat` field 22.
    pub start_time: u64,
    pub origin: ExecOrigin,
    /// The path that matched: the executed file, or the memfd name.
    pub binary_path: String,
    pub argv: Vec<String>,
}

/// A new outbound connection held for a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionRecord {
    pub request_id: u64,
    pub pid: u32,
    /// `/proc/<pid>/stat` field 22.
    pub start_time: u64,
    pub uid: u32,
    /// `/proc/<pid>/exe`, without a ` (deleted)` suffix.
    pub executable: String,
    pub protocol: Protocol,
    /// The remote address.
    pub address: String,
    /// The remote port.
    pub port: u16,
}

/// Decides whether an execution came from a suspicious location.
///
/// `filename` is the path as passed to `execve` (it may be relative, or
/// `/dev/fd/N` for `fexecve`), `cwd` resolves a relative `filename`, and
/// `exe` is the `/proc/<pid>/exe` link. For a script, `filename` is the
/// script and `exe` its interpreter, so both are checked. Returns the
/// origin and the path to report.
pub fn classify_exec(
    filename: &str,
    cwd: Option<&str>,
    exe: Option<&str>,
) -> Option<(ExecOrigin, String)> {
    let exe = exe.map(|e| e.strip_suffix(" (deleted)").unwrap_or(e));
    if let Some(exe) = exe
        && exe.starts_with("/memfd:")
    {
        return Some((ExecOrigin::Memfd, exe.to_owned()));
    }

    let resolved = if filename.starts_with('/') {
        Some(normalize(Path::new(filename)))
    } else {
        cwd.map(|cwd| normalize(&Path::new(cwd).join(filename)))
    };
    let candidates = resolved
        .filter(|p| !is_fd_path(p))
        .into_iter()
        .chain(exe.map(|e| normalize(Path::new(e))));
    for path in candidates {
        if let Some(origin) = origin_of(&path) {
            return Some((origin, path.to_string_lossy().into_owned()));
        }
    }
    None
}

fn origin_of(path: &Path) -> Option<ExecOrigin> {
    let under = |dir: &str| path.starts_with(dir) && path != Path::new(dir);
    if under("/tmp") {
        Some(ExecOrigin::Tmp)
    } else if under("/var/tmp") {
        Some(ExecOrigin::VarTmp)
    } else if under("/dev/shm") {
        Some(ExecOrigin::DevShm)
    } else {
        None
    }
}

/// `/dev/fd/N` or `/proc/<pid>/fd/N`: the name says nothing about the file.
fn is_fd_path(path: &Path) -> bool {
    let parts: Vec<_> = path.components().collect();
    match parts.as_slice() {
        [Component::RootDir, a, b, _] => a.as_os_str() == "dev" && b.as_os_str() == "fd",
        [Component::RootDir, a, _, b, _] => a.as_os_str() == "proc" && b.as_os_str() == "fd",
        _ => false,
    }
}

/// Lexical normalization: drops `.` and resolves `..` without touching the
/// filesystem, so `/usr/../tmp/x` is `/tmp/x`.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::ParentDir => {
                out.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn origin(filename: &str, cwd: Option<&str>, exe: Option<&str>) -> Option<ExecOrigin> {
        classify_exec(filename, cwd, exe).map(|(o, _)| o)
    }

    #[test]
    fn classifies_suspicious_directories() {
        assert_eq!(origin("/tmp/x", None, None), Some(ExecOrigin::Tmp));
        assert_eq!(origin("/var/tmp/a/b", None, None), Some(ExecOrigin::VarTmp));
        assert_eq!(origin("/dev/shm/x", None, None), Some(ExecOrigin::DevShm));
        assert_eq!(origin("/usr/bin/ls", None, Some("/usr/bin/ls")), None);
        assert_eq!(origin("/tmpfoo/x", None, None), None);
        assert_eq!(origin("/tmp", None, None), None);
    }

    #[test]
    fn resolves_relative_and_dotted_paths() {
        assert_eq!(
            classify_exec("./run", Some("/tmp/build"), None),
            Some((ExecOrigin::Tmp, "/tmp/build/run".into()))
        );
        assert_eq!(origin("../bin/ls", Some("/usr/lib"), None), None);
        assert_eq!(origin("/usr/../tmp/x", None, None), Some(ExecOrigin::Tmp));
        assert_eq!(origin("/tmp/../usr/bin/ls", None, None), None);
        // Unresolvable relative name: fall back to the exe link.
        assert_eq!(
            origin("x", None, Some("/dev/shm/x")),
            Some(ExecOrigin::DevShm)
        );
    }

    #[test]
    fn detects_memfd_and_deleted_binaries() {
        assert_eq!(
            classify_exec("/dev/fd/3", None, Some("/memfd:payload (deleted)")),
            Some((ExecOrigin::Memfd, "/memfd:payload".into()))
        );
        assert_eq!(
            classify_exec("/proc/self/fd/4", None, Some("/tmp/dropper (deleted)")),
            Some((ExecOrigin::Tmp, "/tmp/dropper".into()))
        );
        assert_eq!(origin("/dev/fd/3", None, Some("/usr/bin/true")), None);
    }

    #[test]
    fn scripts_are_flagged_by_their_own_path() {
        assert_eq!(
            classify_exec("/tmp/x.sh", None, Some("/usr/bin/bash")),
            Some((ExecOrigin::Tmp, "/tmp/x.sh".into()))
        );
    }

    #[test]
    fn wire_shapes() {
        let req = HelperRequest {
            id: 3,
            op: HelperOp::Signal {
                pid: 10,
                start_time: 99,
                signal: HelperSignal::Stop,
            },
        };
        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            json!({"id": 3, "op": "signal", "pid": 10, "start_time": 99, "signal": "stop"})
        );
        let ok: HelperMessage =
            serde_json::from_value(json!({"type": "response", "id": 3})).unwrap();
        assert_eq!(
            ok,
            HelperMessage::Response {
                id: 3,
                result: Value::Null,
                error: None
            }
        );
        let sub: HelperRequest =
            serde_json::from_value(json!({"id": 1, "op": "exec_subscribe"})).unwrap();
        assert_eq!(sub.op, HelperOp::ExecSubscribe);
        let verdict: HelperRequest = serde_json::from_value(
            json!({"id": 2, "op": "connection_verdict", "request_id": 7, "verdict": "block"}),
        )
        .unwrap();
        assert_eq!(
            verdict.op,
            HelperOp::ConnectionVerdict {
                request_id: 7,
                verdict: Verdict::Block,
                remember: Remember::None
            }
        );
        let connection = HelperMessage::Connection(ConnectionRecord {
            request_id: 7,
            pid: 10,
            start_time: 99,
            uid: 1000,
            executable: "/usr/bin/curl".into(),
            protocol: Protocol::Tcp,
            address: "192.0.2.1".into(),
            port: 443,
        });
        assert_eq!(
            serde_json::to_value(&connection).unwrap(),
            json!({"type": "connection", "request_id": 7, "pid": 10, "start_time": 99,
                   "uid": 1000, "executable": "/usr/bin/curl", "protocol": "tcp",
                   "address": "192.0.2.1", "port": 443})
        );
        // A version 1 hello, without the connection fields, still parses.
        let hello: HelperHello =
            serde_json::from_value(json!({"version": 1, "exec_monitor": true, "firewall": true}))
                .unwrap();
        assert!(!hello.connections);
    }
}
