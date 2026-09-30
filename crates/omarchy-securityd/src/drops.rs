// SPDX-License-Identifier: GPL-3.0-or-later

//! Executable file drops (task 2.16, plan §2.1 and §5.10): the inotify half
//! of threat detection.
//!
//! `/tmp`, `/var/tmp`, and `/dev/shm` are watched without recursion, and so
//! is each directory created directly in them, for [`DropEnv::subdir_ttl`].
//! A regular file that its owner may execute and that starts with the ELF
//! magic or `#!` is reported when it is written, made executable, or moved
//! in. This names the file before it runs; the exec monitor still catches
//! the run itself. Files this user cannot read are not examined, so without
//! root most drops by other users go unseen.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::fcntl::OFlag;
use nix::sys::inotify::{AddWatchFlags, WatchDescriptor};
use omarchy_security_proto::types::FileDrop;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

use crate::inotify::{self, Watch};
use crate::now_ms;

/// Reported files remembered so a later chmod or rename is not reported
/// again.
const MAX_SEEN: usize = 4096;

const FILE_FLAGS: AddWatchFlags = AddWatchFlags::IN_CLOSE_WRITE
    .union(AddWatchFlags::IN_ATTRIB)
    .union(AddWatchFlags::IN_MOVED_TO)
    .union(AddWatchFlags::IN_ONLYDIR)
    .union(AddWatchFlags::IN_DONT_FOLLOW);

/// The watched roots also see new directories.
const ROOT_FLAGS: AddWatchFlags = FILE_FLAGS.union(AddWatchFlags::IN_CREATE);

#[derive(Debug, Clone)]
pub struct DropEnv {
    pub dirs: Vec<PathBuf>,
    /// How long a new first-level directory is watched.
    pub subdir_ttl: Duration,
    /// At most this many first-level directories are watched at once.
    pub max_subdirs: usize,
}

impl Default for DropEnv {
    fn default() -> Self {
        Self {
            dirs: ["/tmp", "/var/tmp", "/dev/shm"].map(PathBuf::from).to_vec(),
            subdir_ttl: Duration::from_secs(300),
            max_subdirs: 128,
        }
    }
}

/// Identifies one version of one file. The ctime is left out, since the
/// chmod that follows a write changes it.
type FileKey = (u64, u64, i64, i64, u64);

/// Examines `path`. `Some` for a regular executable file with the ELF magic
/// or a `#!` line.
fn examine(path: &Path) -> Option<(FileKey, FileDrop)> {
    // lstat first: opening a device node or FIFO can have side effects.
    let before = std::fs::symlink_metadata(path).ok()?;
    if !before.is_file() || before.mode() & 0o100 == 0 {
        return None;
    }
    let mut file = File::options()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_NOCTTY).bits())
        .open(path)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.ino() != before.ino() || meta.dev() != before.dev() {
        return None;
    }
    let mut head = Vec::with_capacity(4);
    (&mut file).take(4).read_to_end(&mut head).ok()?;
    if !(head.starts_with(b"\x7fELF") || head.starts_with(b"#!")) {
        return None;
    }
    let key = (
        meta.dev(),
        meta.ino(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.size(),
    );
    Some((
        key,
        FileDrop {
            path: path.to_string_lossy().into_owned(),
            uid: meta.uid(),
            size: meta.size(),
            detected_at: now_ms(),
        },
    ))
}

struct Dir {
    path: PathBuf,
    /// `None` for the roots, which are watched for good.
    expires: Option<Instant>,
}

/// Sends each executable file drop on `found`. Returns when the receiver is
/// gone, or with an error when inotify is unavailable or no root could be
/// watched.
pub async fn watch(env: DropEnv, found: mpsc::Sender<FileDrop>) -> std::io::Result<()> {
    let watcher = inotify::init()?;
    let mut dirs: HashMap<WatchDescriptor, Dir> = HashMap::new();
    let mut failed = Vec::new();
    for root in &env.dirs {
        match watcher.add_watch(root, ROOT_FLAGS) {
            Ok(wd) => {
                dirs.insert(
                    wd,
                    Dir {
                        path: root.clone(),
                        expires: None,
                    },
                );
            }
            Err(err) => {
                tracing::warn!("cannot watch {} for file drops: {err}", root.display());
                failed.push(format!("{}: {err}", root.display()));
            }
        }
    }
    if dirs.is_empty() {
        return Err(std::io::Error::other(failed.join("; ")));
    }
    let fd = AsyncFd::new(Watch(watcher))?;
    let mut seen: HashSet<FileKey> = HashSet::new();
    let mut sweep = tokio::time::interval((env.subdir_ttl / 2).max(Duration::from_millis(50)));
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let events = tokio::select! {
            events = inotify::read(&fd) => events?,
            _ = sweep.tick() => {
                let now = Instant::now();
                dirs.retain(|wd, dir| {
                    let keep = dir.expires.is_none_or(|t| t > now);
                    if !keep {
                        let _ = fd.get_ref().0.rm_watch(*wd);
                    }
                    keep
                });
                continue;
            }
            () = found.closed() => return Ok(()),
        };
        let mut drops = Vec::new();
        for event in events {
            let mask = event.mask;
            if mask.contains(AddWatchFlags::IN_Q_OVERFLOW) {
                tracing::warn!("file drop events overflowed; some files were not examined");
                continue;
            }
            if mask.contains(AddWatchFlags::IN_IGNORED) {
                dirs.remove(&event.wd);
                continue;
            }
            let (Some(dir), Some(name)) = (dirs.get(&event.wd), &event.name) else {
                continue;
            };
            let path = dir.path.join(name);
            if mask.contains(AddWatchFlags::IN_ISDIR) {
                let is_root = dir.expires.is_none();
                let subdirs = dirs.values().filter(|d| d.expires.is_some()).count();
                if is_root
                    && mask.intersects(AddWatchFlags::IN_CREATE | AddWatchFlags::IN_MOVED_TO)
                    && subdirs < env.max_subdirs
                {
                    // Other users' private directories fail here.
                    let Ok(wd) = fd.get_ref().0.add_watch(&path, FILE_FLAGS) else {
                        continue;
                    };
                    // Files written before the watch existed.
                    drops.extend(
                        std::fs::read_dir(&path)
                            .into_iter()
                            .flatten()
                            .flatten()
                            .filter_map(|entry| examine(&entry.path())),
                    );
                    dirs.insert(
                        wd,
                        Dir {
                            path,
                            expires: Some(Instant::now() + env.subdir_ttl),
                        },
                    );
                }
                continue;
            }
            if mask.intersects(
                AddWatchFlags::IN_CLOSE_WRITE
                    | AddWatchFlags::IN_ATTRIB
                    | AddWatchFlags::IN_MOVED_TO,
            ) {
                drops.extend(examine(&path));
            }
        }
        for (key, drop) in drops {
            if seen.len() >= MAX_SEEN {
                seen.clear();
            }
            if seen.insert(key) && found.send(drop).await.is_err() {
                return Ok(());
            }
        }
    }
}

/// A token bucket: `burst` reports at once, then one per `every`.
pub struct RateLimit {
    burst: u32,
    every: Duration,
    tokens: u32,
    last: Instant,
    suppressed: u64,
}

impl RateLimit {
    pub fn new(burst: u32, every: Duration) -> Self {
        Self {
            burst,
            every,
            tokens: burst,
            last: Instant::now(),
            suppressed: 0,
        }
    }

    pub fn allow(&mut self, now: Instant) -> bool {
        let earned = now.saturating_duration_since(self.last).as_nanos() / self.every.as_nanos();
        if earned > 0 {
            self.tokens = self.burst.min(
                self.tokens
                    .saturating_add(earned.try_into().unwrap_or(u32::MAX)),
            );
            self.last += self.every * u32::try_from(earned).unwrap_or(u32::MAX);
        }
        if self.tokens == 0 {
            self.suppressed += 1;
            return false;
        }
        if self.tokens == self.burst {
            self.last = now;
        }
        self.tokens -= 1;
        if self.suppressed > 0 {
            tracing::warn!("{} file drop reports were rate-limited", self.suppressed);
            self.suppressed = 0;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write(path: &Path, data: &[u8], mode: u32) {
        std::fs::write(path, data).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn examines_only_executable_programs() {
        let dir = tempfile::tempdir().unwrap();
        let p = |n: &str| dir.path().join(n);
        write(&p("elf"), b"\x7fELF\x02\x01", 0o755);
        write(&p("script"), b"#!/bin/sh\necho hi\n", 0o700);
        write(&p("text"), b"echo hi\n", 0o755);
        write(&p("noexec"), b"#!/bin/sh\n", 0o644);
        write(&p("group_exec"), b"#!/bin/sh\n", 0o654);
        write(&p("tiny"), b"#", 0o755);
        std::os::unix::fs::symlink(p("elf"), p("link")).unwrap();
        nix::unistd::mkfifo(&p("fifo"), nix::sys::stat::Mode::from_bits(0o755).unwrap()).unwrap();

        let elf = examine(&p("elf")).unwrap().1;
        assert_eq!(elf.path, p("elf").to_string_lossy());
        assert_eq!(elf.size, 6);
        assert_eq!(elf.uid, nix::unistd::getuid().as_raw());
        assert!(examine(&p("script")).is_some());
        for name in [
            "text",
            "noexec",
            "group_exec",
            "tiny",
            "link",
            "fifo",
            "absent",
        ] {
            assert!(examine(&p(name)).is_none(), "{name}");
        }
    }

    #[test]
    fn rate_limit_allows_a_burst_then_refills() {
        let start = Instant::now();
        let mut limit = RateLimit::new(3, Duration::from_secs(1));
        limit.last = start;
        assert_eq!((0..5).filter(|_| limit.allow(start)).count(), 3);
        assert!(!limit.allow(start + Duration::from_millis(900)));
        assert!(limit.allow(start + Duration::from_millis(1100)));
        assert!(!limit.allow(start + Duration::from_millis(1200)));
        let later = start + Duration::from_secs(60);
        assert_eq!((0..5).filter(|_| limit.allow(later)).count(), 3);
    }

    async fn next(rx: &mut mpsc::Receiver<FileDrop>) -> FileDrop {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("a file drop")
            .expect("watcher running")
    }

    async fn quiet(rx: &mut mpsc::Receiver<FileDrop>) {
        if let Ok(drop) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
            panic!("unexpected {drop:?}");
        }
    }

    #[tokio::test]
    async fn reports_drops_in_roots_and_new_subdirectories() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let env = DropEnv {
            dirs: vec![root.path().to_owned()],
            subdir_ttl: Duration::from_millis(600),
            max_subdirs: 8,
        };
        let (tx, mut rx) = mpsc::channel(16);
        let watcher = tokio::spawn(watch(env, tx));
        // Let the watch be added.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let path = |p: &Path| p.to_string_lossy().into_owned();

        // Written, then made executable: one report, on the chmod.
        let a = root.path().join("a");
        write(&a, b"#!/bin/sh\n", 0o644);
        quiet(&mut rx).await;
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(next(&mut rx).await.path, path(&a));
        std::fs::set_permissions(&a, std::fs::Permissions::from_mode(0o700)).unwrap();
        quiet(&mut rx).await;

        // Moved in.
        let b = outside.path().join("b");
        write(&b, b"\x7fELF", 0o755);
        std::fs::rename(&b, root.path().join("b")).unwrap();
        assert_eq!(next(&mut rx).await.path, path(&root.path().join("b")));

        // A new first-level directory, but not the ones below it.
        let sub = root.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        write(&sub.join("c"), b"#!/bin/sh\n", 0o755);
        assert_eq!(next(&mut rx).await.path, path(&sub.join("c")));
        std::fs::create_dir(sub.join("deeper")).unwrap();
        write(&sub.join("deeper/d"), b"#!/bin/sh\n", 0o755);
        quiet(&mut rx).await;

        // After its time is up, the subdirectory is no longer watched.
        tokio::time::sleep(Duration::from_millis(1000)).await;
        write(&sub.join("e"), b"#!/bin/sh\n", 0o755);
        quiet(&mut rx).await;

        drop(rx);
        write(&root.path().join("f"), b"#!/bin/sh\n", 0o755);
        tokio::time::timeout(Duration::from_secs(5), watcher)
            .await
            .expect("watcher ends")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn fails_without_any_root() {
        let dir = tempfile::tempdir().unwrap();
        let env = DropEnv {
            dirs: vec![dir.path().join("absent")],
            ..DropEnv::default()
        };
        let (tx, _rx) = mpsc::channel(1);
        assert!(watch(env, tx).await.is_err());
    }
}
