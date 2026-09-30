// SPDX-License-Identifier: GPL-3.0-or-later

//! The modules of `omarchy-securityd`, as a library for the binary in
//! `main.rs` and for the fuzz targets in `fuzz/` (plan task 4.5). Not a
//! stable API.

use std::time::{SystemTime, UNIX_EPOCH};

pub mod alerts;
pub mod config;
pub mod daemon;
pub mod drops;
pub mod firewall;
pub mod gpg;
pub mod helper_client;
pub mod holders;
pub mod hub;
pub mod inotify;
pub mod notify;
pub mod pinentry;
pub mod posture;
pub mod sandbox;
pub mod server;
#[cfg(test)]
mod testutil;
pub mod threat;
pub mod token;
pub mod udisks;
pub mod ufw;
pub mod usbguard;
pub mod vault;

/// Milliseconds since the Unix epoch, the protocol's timestamp unit.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
