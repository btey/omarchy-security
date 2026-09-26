// SPDX-License-Identifier: GPL-3.0-or-later

//! Wire protocol between `omarchy-securityd` and its clients.
//!
//! The protocol is JSON-RPC 2.0 over a Unix domain stream socket, one JSON
//! object per line (NDJSON). Clients send requests; the daemon answers each
//! with a response carrying the same `id`, and pushes events as JSON-RPC
//! notifications to clients that subscribed to their topic.
//!
//! `docs/ipc-protocol.md` is the normative specification. This crate is its
//! Rust rendering, and its tests pin the wire format against the examples
//! printed there.

pub mod error;
pub mod events;
pub mod helper;
pub mod methods;
pub mod procfs;
pub mod rpc;
pub mod systemd;
pub mod types;

use std::path::{Path, PathBuf};

pub use error::{ErrorCode, RpcError};
pub use events::Event;
pub use methods::Call;
pub use rpc::{Id, JsonRpcVersion, Notification, Request, Response, encode_frame, parse_request};

/// Protocol version negotiated by `HELLO`. Bumped on any incompatible change.
pub const PROTOCOL_VERSION: u32 = 1;

/// Largest accepted frame, newline excluded. A peer that sends a longer line
/// is disconnected rather than buffered.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

/// Environment variable that overrides the socket location (tests, dev runs).
pub const SOCKET_ENV: &str = "OMARCHY_SECURITYD_SOCKET";

const SOCKET_DIR: &str = "omarchy-security";
const SOCKET_FILE: &str = "securityd.sock";

/// Socket path inside a given runtime directory:
/// `<runtime_dir>/omarchy-security/securityd.sock`.
pub fn socket_path_in(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join(SOCKET_DIR).join(SOCKET_FILE)
}

/// Resolves the socket path from `$OMARCHY_SECURITYD_SOCKET`, falling back to
/// `$XDG_RUNTIME_DIR`. Returns `None` when neither is set, because a socket in
/// a shared directory such as `/tmp` would be reachable by other users.
pub fn default_socket_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(SOCKET_ENV).filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(path));
    }
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|p| !p.is_empty())
        .map(|dir| socket_path_in(Path::new(&dir)))
}
