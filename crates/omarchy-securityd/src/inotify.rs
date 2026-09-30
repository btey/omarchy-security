// SPDX-License-Identifier: GPL-3.0-or-later

//! nix's inotify on the tokio reactor, shared by the gpg touch trigger and
//! the file drop watcher.

use std::os::fd::{AsFd, AsRawFd, RawFd};

use nix::sys::inotify::{InitFlags, Inotify, InotifyEvent};
use tokio::io::unix::AsyncFd;

/// `Inotify` implements `AsFd` only; `AsyncFd` wants `AsRawFd`.
pub struct Watch(pub Inotify);

impl AsRawFd for Watch {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_fd().as_raw_fd()
    }
}

pub fn init() -> std::io::Result<Inotify> {
    Ok(Inotify::init(
        InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC,
    )?)
}

/// The next batch of events. Cancel-safe, so it can sit in a `select!`.
pub async fn read(fd: &AsyncFd<Watch>) -> std::io::Result<Vec<InotifyEvent>> {
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|w| w.get_ref().0.read_events().map_err(Into::into)) {
            Ok(events) => return events,
            Err(_would_block) => continue,
        }
    }
}

/// Drops every event queued so far.
pub fn drain(fd: &AsyncFd<Watch>) {
    while fd.get_ref().0.read_events().is_ok_and(|e| !e.is_empty()) {}
}
