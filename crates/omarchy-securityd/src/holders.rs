// SPDX-License-Identifier: GPL-3.0-or-later

//! Finds and stops the processes that keep a mount busy, for vault panic
//! mode (plan §5.6).
//!
//! A process holds a mount when its `cwd` or `root`, one of its open files,
//! or one of its memory mappings lies under the mount point. All of these
//! are read from `/proc` as link targets and text, so the scan never stats
//! a file on the mount itself, which could hang on a stuck FUSE daemon.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

/// Processes panic mode never signals: stopping the compositor or the shell
/// would end the session. Matched against `comm`, which the kernel cuts to
/// 15 bytes, and the executable's file name.
const PROTECTED: &[&str] = &[
    "Hyprland",
    "quickshell",
    ".quickshell-wrapped",
    ".quickshell-wra",
    "qs",
    "omarchy-shell",
];

/// A process that uses a mount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub pid: u32,
    pub name: String,
    /// `starttime` from `/proc/<pid>/stat`, so a reused PID is not signalled.
    start: u64,
    pub protected: bool,
}

/// This user's processes, other than this one, that use a path under any
/// of `mounts`. The result has one list per mount, in the same order.
pub fn find(proc: &Path, mounts: &[PathBuf]) -> Vec<Vec<Holder>> {
    let mut found = vec![Vec::new(); mounts.len()];
    let uid = nix::unistd::getuid().as_raw();
    let own = std::process::id();
    let Ok(entries) = std::fs::read_dir(proc) else {
        return found;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == own {
            continue;
        }
        let dir = entry.path();
        if std::fs::metadata(&dir).ok().map(|m| m.uid()) != Some(uid) {
            continue;
        }
        let paths = used_paths(&dir);
        let hits: Vec<usize> = mounts
            .iter()
            .enumerate()
            .filter(|(_, mount)| paths.iter().any(|p| p.starts_with(mount)))
            .map(|(i, _)| i)
            .collect();
        if hits.is_empty() {
            continue;
        }
        let Some((start, false)) = stat(&dir) else {
            continue;
        };
        let name = std::fs::read_to_string(dir.join("comm"))
            .map(|c| c.trim_end().to_owned())
            .unwrap_or_default();
        let exe = std::fs::read_link(dir.join("exe")).ok();
        let exe_name = exe
            .as_deref()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let holder = Holder {
            pid,
            protected: PROTECTED.contains(&name.as_str()) || PROTECTED.contains(&exe_name),
            name,
            start,
        };
        for i in hits {
            found[i].push(holder.clone());
        }
    }
    found
}

/// Every path the process uses: `cwd`, `root`, open files and mappings.
fn used_paths(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = ["cwd", "root"]
        .iter()
        .filter_map(|link| std::fs::read_link(dir.join(link)).ok())
        .collect();
    if let Ok(fds) = std::fs::read_dir(dir.join("fd")) {
        paths.extend(
            fds.flatten()
                .filter_map(|fd| std::fs::read_link(fd.path()).ok()),
        );
    }
    if let Ok(maps) = std::fs::read_to_string(dir.join("maps")) {
        paths.extend(maps.lines().filter_map(map_path).map(PathBuf::from));
    }
    paths
}

/// The file of one `/proc/<pid>/maps` line, `proc_pid_maps(5)`: the sixth
/// field, which may contain spaces.
fn map_path(line: &str) -> Option<&str> {
    let mut rest = line;
    for _ in 0..5 {
        rest = rest.trim_start().split_once(' ')?.1;
    }
    let path = rest.trim_start();
    path.starts_with('/').then_some(path)
}

/// `starttime` and whether the process is a zombie, from its `stat`.
fn stat(dir: &Path) -> Option<(u64, bool)> {
    let text = std::fs::read_to_string(dir.join("stat")).ok()?;
    // `comm` is in parentheses and may itself contain them.
    let fields: Vec<&str> = text.rsplit_once(')')?.1.split_whitespace().collect();
    let state = fields.first()?;
    // starttime is field 22; fields[0] here is field 3.
    let start = fields.get(19)?.parse().ok()?;
    Some((start, *state == "Z" || *state == "X"))
}

fn alive(proc: &Path, holder: &Holder) -> bool {
    matches!(
        stat(&proc.join(holder.pid.to_string())),
        Some((start, false)) if start == holder.start
    )
}

fn signal(holder: &Holder, signal: Signal) {
    let Ok(pid) = i32::try_from(holder.pid) else {
        return;
    };
    if let Err(err) = kill(Pid::from_raw(pid), signal) {
        tracing::debug!(pid = holder.pid, "{signal}: {err}");
    }
}

/// Sends `SIGTERM` to every unprotected holder, waits up to `grace` for them
/// to exit, then sends `SIGKILL` to the rest and waits briefly for those.
/// Returns the holders still alive at the end.
pub async fn stop(proc: &Path, holders: &[Holder], grace: Duration) -> Vec<Holder> {
    let mut targets: HashMap<u32, Holder> = holders
        .iter()
        .filter(|h| !h.protected)
        .map(|h| (h.pid, h.clone()))
        .collect();
    for holder in targets.values() {
        tracing::info!(pid = holder.pid, name = %holder.name, "panic: SIGTERM");
        signal(holder, Signal::SIGTERM);
    }
    reap(proc, &mut targets, grace).await;
    for holder in targets.values() {
        tracing::warn!(pid = holder.pid, name = %holder.name, "panic: SIGKILL");
        signal(holder, Signal::SIGKILL);
    }
    reap(proc, &mut targets, Duration::from_millis(500)).await;
    targets.into_values().collect()
}

/// Waits up to `limit` for `targets` to exit, removing those that have.
async fn reap(proc: &Path, targets: &mut HashMap<u32, Holder>, limit: Duration) {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        targets.retain(|_, h| alive(proc, h));
        if targets.is_empty() || tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_maps_lines() {
        assert_eq!(
            map_path("7f00-7f01 r--p 00000000 00:2a 1234    /home/u/My Vault/lib.so"),
            Some("/home/u/My Vault/lib.so")
        );
        assert_eq!(
            map_path("7f00-7f01 rw-p 00000000 00:00 0          [heap]"),
            None
        );
        assert_eq!(map_path("7f00-7f01 rw-p 00000000 00:00 0"), None);
    }

    #[test]
    fn parses_stat() {
        let dir = tempfile::tempdir().unwrap();
        let mut fields = vec!["0"; 50];
        fields[0] = "S";
        fields[19] = "4242";
        std::fs::write(
            dir.path().join("stat"),
            format!("12 (a (b)) {}", fields.join(" ")),
        )
        .unwrap();
        assert_eq!(stat(dir.path()), Some((4242, false)));
        fields[0] = "Z";
        std::fs::write(
            dir.path().join("stat"),
            format!("12 (a) {}", fields.join(" ")),
        )
        .unwrap();
        assert_eq!(stat(dir.path()), Some((4242, true)));
    }

    #[tokio::test]
    async fn finds_and_stops_holders() {
        let work = tempfile::tempdir().unwrap();
        let mount = work.path().join("m");
        std::fs::create_dir(&mount).unwrap();
        std::fs::write(mount.join("f"), "x").unwrap();
        // Holds a file open, and ignores SIGTERM.
        let mut stubborn = std::process::Command::new("sh")
            .arg("-c")
            .arg("trap '' TERM; exec sleep 60 3<f")
            .current_dir(&mount)
            .spawn()
            .unwrap();
        // Protected by name: a copy of sleep called Hyprland.
        let fake = work.path().join("Hyprland");
        std::fs::copy(crate::sandbox::find_in_path("sleep").unwrap(), &fake).unwrap();
        let mut compositor = std::process::Command::new(&fake)
            .arg("60")
            .current_dir(&mount)
            .spawn()
            .unwrap();
        let other = work.path().join("n");
        std::fs::create_dir(&other).unwrap();

        let proc = Path::new("/proc");
        let mut found = Vec::new();
        for _ in 0..100 {
            found = find(proc, &[mount.clone(), other.clone()]);
            // Wait for sh to exec into sleep with the file open.
            if found[0].len() == 2 && found[0].iter().any(|h| h.name == "sleep") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(found[1].is_empty(), "{found:?}");
        let mut holders = found[0].clone();
        holders.sort_by_key(|h| h.protected);
        assert_eq!(holders.len(), 2, "{holders:?}");
        assert_eq!(holders[0].pid, stubborn.id());
        assert!(!holders[0].protected);
        assert_eq!(holders[1].pid, compositor.id());
        assert!(holders[1].protected);

        let left = stop(proc, &holders, Duration::from_millis(200)).await;
        assert!(left.is_empty(), "{left:?}");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            stubborn.wait().unwrap().signal(),
            Some(Signal::SIGKILL as i32)
        );
        assert!(
            compositor.try_wait().unwrap().is_none(),
            "protected survives"
        );
        compositor.kill().unwrap();
        compositor.wait().unwrap();
    }
}
