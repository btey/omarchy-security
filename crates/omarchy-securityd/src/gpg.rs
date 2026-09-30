// SPDX-License-Identifier: GPL-3.0-or-later

//! OpenPGP card touch prompts (task 2.15, plan §2.2).
//!
//! A card waiting for a touch sends nothing the host can see, so this is a
//! heuristic, after the approach `yubikey-touch-detector` used until 2026
//! (ISC; reimplemented, not copied):
//!
//! * **Trigger.** gpg-agent opens a key's file in `private-keys-v1.d` for
//!   every private-key operation, including SSH through its SSH support. For
//!   a key on a card that file is a stub holding `shadowed-private-key`, so
//!   an `IN_OPEN` of a stub means a card operation is starting. `pubring.kbx`
//!   is not watched: every `gpg` command opens it, private key or not. The
//!   agent sockets are not watched either: connecting to a socket raises no
//!   inotify event.
//! * **Probe.** A moment later, a short query goes to scdaemon through
//!   `gpg-connect-agent --no-autostart`. scdaemon serializes access to the
//!   card, so the query waits while the card waits for a touch. No answer
//!   within [`GpgTiming::answer`] means the card is waiting; the answer that
//!   follows means it was touched. A pinentry of the user holds the card
//!   the same way while a PIN is typed, so the wait restarts when it closes.
//!
//! Upstream has since moved to a proxy on the agent socket, which sees the
//! Assuan commands themselves. That renames the user's gpg-agent socket, and
//! gpg breaks until the proxy is removed if the proxy dies; the daemon does
//! not take that risk.

use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use nix::sys::inotify::AddWatchFlags;
use omarchy_security_proto::procfs::Proc;
use omarchy_security_proto::types::TouchOutcome;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::inotify::{self, Watch, drain};
use crate::token::TouchEdge;

/// How long to wait for the keys directory to appear.
const RETRY: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct GpgTiming {
    /// Delay after the trigger, while gpg-agent talks to scdaemon.
    pub settle: Duration,
    /// A probe that takes longer than this is waiting behind a touch.
    pub answer: Duration,
    /// A touch request is abandoned after this long.
    pub touch_timeout: Duration,
    /// How often a running pinentry is checked for.
    pub poll: Duration,
}

impl Default for GpgTiming {
    fn default() -> Self {
        Self {
            settle: Duration::from_millis(200),
            answer: Duration::from_millis(400),
            touch_timeout: Duration::from_secs(15),
            poll: Duration::from_millis(200),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GpgEnv {
    /// `$GNUPGHOME`.
    pub home: PathBuf,
    /// The probe command, argv.
    pub probe: Vec<String>,
    pub timing: GpgTiming,
}

impl GpgEnv {
    /// `$GNUPGHOME`, or `~/.gnupg`. `None` without either variable.
    pub fn from_env() -> Option<Self> {
        let home = std::env::var_os("GNUPGHOME")
            .filter(|h| !h.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".gnupg")))?;
        Some(Self {
            home,
            probe: [
                "gpg-connect-agent",
                "--no-autostart",
                "SCD SERIALNO",
                "/bye",
            ]
            .map(String::from)
            .to_vec(),
            timing: GpgTiming::default(),
        })
    }

    fn keys_dir(&self) -> PathBuf {
        self.home.join("private-keys-v1.d")
    }
}

/// The names of the key files in `dir` that are stubs for card keys.
pub fn card_stubs(dir: &Path) -> HashSet<OsString> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            std::fs::read(entry.path())
                .is_ok_and(|data| data.windows(20).any(|w| w == b"shadowed-private-key"))
        })
        .map(|entry| entry.file_name())
        .collect()
}

// ---------------------------------------------------------------- trigger

const WATCH_FLAGS: AddWatchFlags = AddWatchFlags::IN_OPEN
    .union(AddWatchFlags::IN_CLOSE_WRITE)
    .union(AddWatchFlags::IN_CREATE)
    .union(AddWatchFlags::IN_DELETE)
    .union(AddWatchFlags::IN_MOVED_FROM)
    .union(AddWatchFlags::IN_MOVED_TO)
    .union(AddWatchFlags::IN_DELETE_SELF)
    .union(AddWatchFlags::IN_MOVE_SELF);

/// Sends on `trigger` whenever a card key stub is opened. Waits for the
/// keys directory while it does not exist, and returns only when the
/// receiver is gone or inotify is unavailable.
pub async fn watch(env: GpgEnv, trigger: mpsc::Sender<()>) -> std::io::Result<()> {
    let dir = env.keys_dir();
    loop {
        let inotify = inotify::init()?;
        if let Err(err) = inotify.add_watch(&dir, WATCH_FLAGS) {
            tracing::debug!("gpg keys {}: {err}", dir.display());
            tokio::select! {
                () = tokio::time::sleep(RETRY) => continue,
                () = trigger.closed() => return Ok(()),
            }
        }
        let fd = AsyncFd::new(Watch(inotify))?;
        let mut stubs = card_stubs(&dir);
        drain(&fd);
        tracing::debug!(dir = %dir.display(), stubs = stubs.len(), "watching gpg card keys");
        loop {
            let events = tokio::select! {
                events = inotify::read(&fd) => events?,
                () = trigger.closed() => return Ok(()),
            };
            let mut opened = false;
            let mut changed = false;
            let mut gone = false;
            for event in events {
                let mask = event.mask;
                if mask.contains(AddWatchFlags::IN_Q_OVERFLOW) {
                    opened |= !stubs.is_empty();
                    changed = true;
                }
                if mask.intersects(
                    AddWatchFlags::IN_IGNORED
                        | AddWatchFlags::IN_DELETE_SELF
                        | AddWatchFlags::IN_MOVE_SELF,
                ) {
                    gone = true;
                }
                if mask.contains(AddWatchFlags::IN_OPEN)
                    && event.name.as_ref().is_some_and(|n| stubs.contains(n))
                {
                    opened = true;
                }
                if mask.intersects(
                    AddWatchFlags::IN_CLOSE_WRITE
                        | AddWatchFlags::IN_CREATE
                        | AddWatchFlags::IN_DELETE
                        | AddWatchFlags::IN_MOVED_FROM
                        | AddWatchFlags::IN_MOVED_TO,
                ) {
                    changed = true;
                }
            }
            if opened {
                // A full channel already holds a pending probe.
                let _ = trigger.try_send(());
            }
            if gone {
                break;
            }
            if changed {
                stubs = card_stubs(&dir);
                // Reading the stubs opened them: drop those events.
                drain(&fd);
            }
        }
    }
}

// ------------------------------------------------------------------ probe

/// True while a pinentry of `uid` runs: it holds the card while a PIN is
/// typed.
fn pinentry_running(proc: &Proc, uid: u32) -> bool {
    proc.pids().unwrap_or_default().into_iter().any(|pid| {
        proc.comm(pid).is_ok_and(|c| c.starts_with("pinentry"))
            && proc.uid(pid).is_ok_and(|u| u == uid)
    })
}

/// Runs one probe after a trigger and reports the touch it finds, if any,
/// through `edge`: [`TouchEdge::Started`] when the probe stalls, then
/// [`TouchEdge::Finished`] when it answers or after the touch timeout.
pub async fn probe(
    env: &GpgEnv,
    proc: &Proc,
    uid: u32,
    mut edge: impl FnMut(TouchEdge),
) -> std::io::Result<()> {
    let timing = &env.timing;
    tokio::time::sleep(timing.settle).await;
    let (program, args) = env
        .probe
        .split_first()
        .ok_or_else(|| std::io::Error::other("empty probe command"))?;
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    loop {
        tokio::select! {
            _ = child.wait() => return Ok(()),
            () = tokio::time::sleep(timing.answer) => {}
        }
        if !pinentry_running(proc, uid) {
            break;
        }
        // Waiting for a PIN, not a touch: look again once pinentry closes.
        loop {
            tokio::select! {
                _ = child.wait() => return Ok(()),
                () = tokio::time::sleep(timing.poll) => {}
            }
            if !pinentry_running(proc, uid) {
                break;
            }
        }
    }
    edge(TouchEdge::Started);
    let outcome = tokio::select! {
        _ = child.wait() => TouchOutcome::Touched,
        () = tokio::time::sleep(timing.touch_timeout) => TouchOutcome::TimedOut,
    };
    edge(TouchEdge::Finished(outcome));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const STUB: &[u8] =
        b"Key: (shadowed-private-key (ecc (curve Ed25519)(q #40AB#)(shadowed openpgp-card))\n";

    fn env(home: &Path, probe: &str) -> GpgEnv {
        GpgEnv {
            home: home.to_owned(),
            probe: vec!["sh".into(), "-c".into(), probe.into()],
            timing: GpgTiming {
                settle: Duration::from_millis(10),
                answer: Duration::from_millis(150),
                touch_timeout: Duration::from_millis(600),
                poll: Duration::from_millis(20),
            },
        }
    }

    fn keys(home: &Path) -> PathBuf {
        let dir = home.join("private-keys-v1.d");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("AAAA.key"), STUB).unwrap();
        fs::write(dir.join("BBBB.key"), b"Key: (private-key (rsa (n #00#)))\n").unwrap();
        dir
    }

    #[test]
    fn finds_card_stubs() {
        let home = tempfile::tempdir().unwrap();
        let dir = keys(home.path());
        assert_eq!(
            card_stubs(&dir),
            HashSet::from([OsString::from("AAAA.key")])
        );
        assert!(card_stubs(&home.path().join("missing")).is_empty());
    }

    async fn edges(env: &GpgEnv, proc: &Proc) -> Vec<TouchEdge> {
        let mut seen = Vec::new();
        probe(env, proc, nix::unistd::getuid().as_raw(), |e| seen.push(e))
            .await
            .unwrap();
        seen
    }

    fn fake_proc(pinentry: bool) -> tempfile::TempDir {
        let proc = tempfile::tempdir().unwrap();
        let uid = nix::unistd::getuid().as_raw();
        for (pid, comm) in [(1, "systemd"), (40, "pinentry-gnome3")] {
            if comm.starts_with("pinentry") && !pinentry {
                continue;
            }
            let dir = proc.path().join(pid.to_string());
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("comm"), format!("{comm}\n")).unwrap();
            fs::write(
                dir.join("status"),
                format!("Uid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
            )
            .unwrap();
        }
        proc
    }

    #[tokio::test]
    async fn probe_state_machine() {
        let home = tempfile::tempdir().unwrap();
        let idle = fake_proc(false);
        let idle = Proc::new(idle.path());

        // The card answers at once: nothing is waiting.
        assert_eq!(edges(&env(home.path(), "true"), &idle).await, []);
        // It answers late: a touch, then touched.
        assert_eq!(
            edges(&env(home.path(), "sleep 0.4"), &idle).await,
            [
                TouchEdge::Started,
                TouchEdge::Finished(TouchOutcome::Touched)
            ]
        );
        // It never answers.
        assert_eq!(
            edges(&env(home.path(), "sleep 5"), &idle).await,
            [
                TouchEdge::Started,
                TouchEdge::Finished(TouchOutcome::TimedOut)
            ]
        );
        // Late, but a pinentry was open the whole time: a PIN, not a touch.
        let pin = fake_proc(true);
        assert_eq!(
            edges(&env(home.path(), "sleep 0.4"), &Proc::new(pin.path())).await,
            []
        );
        // The pinentry closes and the card still does not answer.
        let closing = pin.path().join("40");
        let remover = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            fs::remove_dir_all(closing).unwrap();
        });
        assert_eq!(
            edges(&env(home.path(), "sleep 0.8"), &Proc::new(pin.path())).await,
            [
                TouchEdge::Started,
                TouchEdge::Finished(TouchOutcome::Touched)
            ]
        );
        remover.await.unwrap();

        let mut broken = env(home.path(), "");
        broken.probe = vec!["/nonexistent/gpg-connect-agent".into()];
        assert!(probe(&broken, &idle, 0, |_| {}).await.is_err());
    }

    async fn triggered(rx: &mut mpsc::Receiver<()>, within: Duration) -> bool {
        tokio::time::timeout(within, rx.recv()).await.is_ok()
    }

    #[tokio::test]
    async fn triggers_on_card_stub_opens() {
        let home = tempfile::tempdir().unwrap();
        let dir = keys(home.path());
        let (tx, mut rx) = mpsc::channel(1);
        let watcher = tokio::spawn(watch(env(home.path(), "true"), tx));
        // Let the watch start.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!triggered(&mut rx, Duration::from_millis(100)).await);

        fs::read(dir.join("BBBB.key")).unwrap();
        assert!(
            !triggered(&mut rx, Duration::from_millis(200)).await,
            "not a stub"
        );
        fs::read(dir.join("AAAA.key")).unwrap();
        assert!(triggered(&mut rx, Duration::from_secs(2)).await);

        // A key moved to a card becomes a stub; rereading it is silent.
        fs::write(dir.join("BBBB.key"), STUB).unwrap();
        assert!(!triggered(&mut rx, Duration::from_millis(300)).await);
        fs::read(dir.join("BBBB.key")).unwrap();
        assert!(triggered(&mut rx, Duration::from_secs(2)).await);

        drop(rx);
        tokio::time::timeout(Duration::from_secs(2), watcher)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
