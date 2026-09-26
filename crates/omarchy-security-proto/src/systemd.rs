// SPDX-License-Identifier: GPL-3.0-or-later

//! `sd_notify(3)` readiness for `Type=notify` units, without libsystemd.

use std::io;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

/// Sends `READY=1` to `$NOTIFY_SOCKET`. Does nothing outside systemd.
pub fn notify_ready() -> io::Result<()> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let addr = match path.as_encoded_bytes().strip_prefix(b"@") {
        Some(name) => SocketAddr::from_abstract_name(name)?,
        None => SocketAddr::from_pathname(&path)?,
    };
    UnixDatagram::unbound()?.send_to_addr(b"READY=1", &addr)?;
    Ok(())
}
