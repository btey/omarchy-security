// SPDX-License-Identifier: GPL-3.0-or-later

//! The few `/proc/<pid>` reads both the daemon and the helper need to
//! identify a process across PID reuse and describe it in an alert.

use std::io;
use std::path::{Path, PathBuf};

/// Fields of `/proc/<pid>/stat` and `/proc/<pid>/status` used here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcStat {
    pub ppid: u32,
    /// Field 22: start time in clock ticks since boot.
    pub start_time: u64,
}

pub struct Proc {
    root: PathBuf,
}

impl Default for Proc {
    fn default() -> Self {
        Self::new("/proc")
    }
}

impl Proc {
    /// `root` is `/proc` except in tests.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, pid: u32, file: &str) -> PathBuf {
        self.root.join(pid.to_string()).join(file)
    }

    pub fn stat(&self, pid: u32) -> io::Result<ProcStat> {
        parse_stat(&std::fs::read_to_string(self.path(pid, "stat"))?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed stat"))
    }

    /// Real UID, from the `Uid:` line of `/proc/<pid>/status`.
    pub fn uid(&self, pid: u32) -> io::Result<u32> {
        let status = std::fs::read_to_string(self.path(pid, "status"))?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|uid| uid.parse().ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no Uid in status"))
    }

    pub fn argv(&self, pid: u32) -> io::Result<Vec<String>> {
        let raw = std::fs::read(self.path(pid, "cmdline"))?;
        Ok(raw
            .split(|&b| b == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| String::from_utf8_lossy(arg).into_owned())
            .collect())
    }

    pub fn comm(&self, pid: u32) -> io::Result<String> {
        Ok(std::fs::read_to_string(self.path(pid, "comm"))?
            .trim_end()
            .to_owned())
    }

    pub fn exe(&self, pid: u32) -> io::Result<String> {
        self.link(pid, "exe")
    }

    pub fn cwd(&self, pid: u32) -> io::Result<String> {
        self.link(pid, "cwd")
    }

    fn link(&self, pid: u32, file: &str) -> io::Result<String> {
        Ok(std::fs::read_link(self.path(pid, file))?
            .to_string_lossy()
            .into_owned())
    }

    /// Every numeric entry of the proc root.
    pub fn pids(&self) -> io::Result<Vec<u32>> {
        Ok(std::fs::read_dir(&self.root)?
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
            .collect())
    }

    /// True when `pid` still runs the process that started at `start_time`.
    pub fn is_same_process(&self, pid: u32, start_time: u64) -> bool {
        self.stat(pid).is_ok_and(|s| s.start_time == start_time)
    }
}

/// Parses `/proc/<pid>/stat`. The command name (field 2) sits in
/// parentheses and may itself contain spaces and `)`, so fields are counted
/// from the last `)`.
pub fn parse_stat(stat: &str) -> Option<ProcStat> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // fields[0] is field 3 (state), so field N is fields[N - 3].
    Some(ProcStat {
        ppid: fields.get(1)?.parse().ok()?,
        start_time: fields.get(19)?.parse().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_with_awkward_comm() {
        let stat = "4242 (a) b) (c) S 17 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 10 18446744073709551615";
        assert_eq!(
            parse_stat(stat),
            Some(ProcStat {
                ppid: 17,
                start_time: 987654
            })
        );
        assert_eq!(parse_stat("1 (x) S 0"), None);
    }

    #[test]
    fn reads_this_process() {
        let proc = Proc::default();
        let pid = std::process::id();
        let stat = proc.stat(pid).unwrap();
        assert!(proc.is_same_process(pid, stat.start_time));
        assert!(!proc.is_same_process(pid, stat.start_time + 1));
        assert_eq!(proc.uid(pid).unwrap(), nix_free_uid());
        assert!(!proc.argv(pid).unwrap().is_empty());
        assert!(proc.pids().unwrap().contains(&pid));
    }

    fn nix_free_uid() -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self").unwrap().uid()
    }
}
