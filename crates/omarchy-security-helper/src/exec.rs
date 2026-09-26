// SPDX-License-Identifier: GPL-3.0-or-later

//! Loads the eBPF exec monitor (`crates/omarchy-security-ebpf`) and turns
//! its ring buffer records into classified, `/proc`-enriched
//! [`ExecRecord`]s.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use aya::maps::{MapData, RingBuf};
use aya::programs::TracePoint;
use omarchy_security_proto::helper::{ExecRecord, classify_exec};
use omarchy_security_proto::procfs::Proc;
use tokio::io::unix::AsyncFd;
use tokio::sync::broadcast;

pub const DEFAULT_OBJECT: &str = "/usr/lib/omarchy-security/exec-monitor.bpf.o";

const TRACEPOINT: (&str, &str) = ("sched", "sched_process_exec");
const FILENAME_LEN: usize = 256;
const EVENT_SIZE: usize = 16 + FILENAME_LEN;

/// How many reported processes the helper remembers as signal targets.
const REPORTED_CAPACITY: usize = 4096;

/// One ring buffer record, laid out as documented in the eBPF crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawExec {
    pub pid: u32,
    pub uid: u32,
    pub filename: String,
}

pub fn parse_event(bytes: &[u8]) -> Option<RawExec> {
    if bytes.len() < EVENT_SIZE {
        return None;
    }
    let u32_at = |at: usize| u32::from_ne_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
    let len = (u32_at(8) as usize).min(FILENAME_LEN);
    Some(RawExec {
        pid: u32_at(0),
        uid: u32_at(4),
        filename: String::from_utf8_lossy(&bytes[16..16 + len]).into_owned(),
    })
}

/// Offset of the `filename` field in a tracepoint `format` file.
pub fn filename_offset(format: &str) -> Option<u32> {
    format.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix("field:")?;
        let (decl, rest) = rest.split_once(';')?;
        if !decl.trim_end().ends_with(" filename") {
            return None;
        }
        rest.split(';')
            .find_map(|part| part.trim().strip_prefix("offset:"))
            .and_then(|offset| offset.parse().ok())
    })
}

/// Classifies an execution and fills in what `/proc` still knows about the
/// process. A process that already exited is still reported, with
/// `start_time` 0, as long as its filename alone is suspicious.
pub fn enrich(proc: &Proc, raw: &RawExec) -> Option<ExecRecord> {
    let cwd = proc.cwd(raw.pid).ok();
    let exe = proc.exe(raw.pid).ok();
    let (origin, binary_path) = classify_exec(&raw.filename, cwd.as_deref(), exe.as_deref())?;
    let stat = proc.stat(raw.pid).ok();
    Some(ExecRecord {
        pid: raw.pid,
        ppid: stat.map_or(0, |s| s.ppid),
        uid: raw.uid,
        start_time: stat.map_or(0, |s| s.start_time),
        origin,
        binary_path,
        argv: proc.argv(raw.pid).unwrap_or_default(),
    })
}

/// A process: PID and start time.
type ProcessKey = (u32, u64);

/// Processes the helper has reported, the only ones it will signal.
#[derive(Default)]
pub struct Reported {
    /// Insertion order, for eviction, and the same keys as a set.
    inner: Mutex<(VecDeque<ProcessKey>, HashSet<ProcessKey>)>,
}

impl Reported {
    pub fn insert(&self, pid: u32, start_time: u64) {
        let mut guard = self.inner.lock().expect("reported lock");
        let (order, set) = &mut *guard;
        if !set.insert((pid, start_time)) {
            return;
        }
        order.push_back((pid, start_time));
        if order.len() > REPORTED_CAPACITY
            && let Some(old) = order.pop_front()
        {
            set.remove(&old);
        }
    }

    pub fn contains(&self, pid: u32, start_time: u64) -> bool {
        self.inner
            .lock()
            .expect("reported lock")
            .1
            .contains(&(pid, start_time))
    }
}

/// The tracefs mount point. `/sys/kernel/tracing` automounts on first
/// access, so its existence is enough; permission errors surface when the
/// format file is read.
fn tracefs() -> Option<PathBuf> {
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_dir())
}

pub struct ExecMonitor {
    // Detaches the program when dropped, so it lives as long as the ring.
    _ebpf: aya::Ebpf,
    ring: RingBuf<MapData>,
}

impl ExecMonitor {
    pub fn load(object: &Path) -> Result<Self> {
        let tracefs = tracefs().context("tracefs is not available")?;
        let format_path = tracefs.join(format!("events/{}/{}/format", TRACEPOINT.0, TRACEPOINT.1));
        let format = std::fs::read_to_string(&format_path)
            .with_context(|| format!("reading {}", format_path.display()))?;
        let offset =
            filename_offset(&format).context("no filename field in the tracepoint format")?;

        let mut ebpf = aya::EbpfLoader::new()
            .override_global("FILENAME_FIELD_OFFSET", &offset, true)
            .load_file(object)
            .with_context(|| format!("loading {}", object.display()))?;
        let program: &mut TracePoint = ebpf
            .program_mut("exec_monitor")
            .context("exec_monitor program missing from the object")?
            .try_into()?;
        program
            .load()
            .context("loading exec_monitor into the kernel")?;
        program
            .attach(TRACEPOINT.0, TRACEPOINT.1)
            .context("attaching to sched:sched_process_exec")?;
        let ring = RingBuf::try_from(
            ebpf.take_map("EVENTS")
                .ok_or_else(|| anyhow!("EVENTS map missing"))?,
        )?;
        tracing::info!(object = %object.display(), filename_offset = offset, "exec monitor attached");
        Ok(Self { _ebpf: ebpf, ring })
    }

    /// Forwards every suspicious execution to `records` until the ring
    /// buffer fails.
    pub async fn run(
        self,
        records: broadcast::Sender<ExecRecord>,
        reported: &Reported,
    ) -> Result<()> {
        let Self { _ebpf, ring } = self;
        let mut ring = AsyncFd::new(ring)?;
        let proc = Proc::default();
        let mut batch = Vec::new();
        loop {
            let mut guard = ring.readable_mut().await?;
            let inner = guard.get_inner_mut();
            while let Some(item) = inner.next() {
                if let Some(raw) = parse_event(&item) {
                    batch.push(raw);
                }
            }
            guard.clear_ready();
            for raw in batch.drain(..) {
                let Some(record) = enrich(&proc, &raw) else {
                    continue;
                };
                tracing::info!(pid = record.pid, uid = record.uid, path = %record.binary_path, origin = ?record.origin, "suspicious exec");
                if record.start_time != 0 {
                    reported.insert(record.pid, record.start_time);
                }
                let _ = records.send(record);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omarchy_security_proto::types::ExecOrigin;

    #[test]
    fn parses_ring_records() {
        let mut bytes = vec![0u8; EVENT_SIZE];
        bytes[0..4].copy_from_slice(&42u32.to_ne_bytes());
        bytes[4..8].copy_from_slice(&1000u32.to_ne_bytes());
        bytes[8..12].copy_from_slice(&6u32.to_ne_bytes());
        bytes[16..22].copy_from_slice(b"/tmp/x");
        bytes[22] = b'!'; // past filename_len: ignored
        assert_eq!(
            parse_event(&bytes),
            Some(RawExec {
                pid: 42,
                uid: 1000,
                filename: "/tmp/x".into()
            })
        );
        assert_eq!(parse_event(&bytes[..20]), None);
    }

    #[test]
    fn reads_the_filename_offset() {
        let format = "name: sched_process_exec\nID: 312\nformat:\n\
            \tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
            \tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\
            \tfield:__data_loc char[] filename;\toffset:12;\tsize:4;\tsigned:0;\n\
            \tfield:pid_t pid;\toffset:16;\tsize:4;\tsigned:1;\n";
        assert_eq!(filename_offset(format), Some(12));
        assert_eq!(filename_offset("field:int x;\toffset:1;"), None);
    }

    #[test]
    fn enriches_a_live_process() {
        // This test process stands in for an exec'd binary from /tmp: its
        // exe does not match, but the filename does.
        let pid = std::process::id();
        let raw = RawExec {
            pid,
            uid: 1000,
            filename: "/tmp/dropper".into(),
        };
        let record = enrich(&Proc::default(), &raw).unwrap();
        assert_eq!(record.origin, ExecOrigin::Tmp);
        assert_eq!(record.binary_path, "/tmp/dropper");
        assert!(record.start_time > 0 && !record.argv.is_empty());

        let benign = RawExec {
            pid,
            uid: 1000,
            filename: "/home/u/bin/tool".into(),
        };
        assert_eq!(enrich(&Proc::default(), &benign), None);

        // Gone already: reported from the filename alone.
        let gone = RawExec {
            pid: u32::MAX - 1,
            uid: 0,
            filename: "/dev/shm/x".into(),
        };
        let record = enrich(&Proc::default(), &gone).unwrap();
        assert_eq!((record.origin, record.start_time), (ExecOrigin::DevShm, 0));
    }

    #[test]
    fn reported_set_is_bounded() {
        let reported = Reported::default();
        for pid in 0..(REPORTED_CAPACITY as u32 + 10) {
            reported.insert(pid, 1);
        }
        assert!(!reported.contains(0, 1));
        assert!(reported.contains(REPORTED_CAPACITY as u32 + 9, 1));
    }

    /// The object built by `make ebpf` parses and carries what `load` needs.
    #[test]
    fn built_object_has_program_map_and_global() {
        let object = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../omarchy-security-ebpf/target/bpfel-unknown-none/release/exec-monitor");
        let Ok(bytes) = std::fs::read(&object) else {
            eprintln!("{} not built; run `make ebpf`", object.display());
            return;
        };
        let obj = aya_obj::Object::parse(&bytes).expect("valid eBPF ELF");
        assert!(obj.programs.contains_key("exec_monitor"));
        assert!(obj.maps.contains_key("EVENTS"));
        // FILENAME_FIELD_OFFSET lives in .rodata, which aya patches.
        assert!(obj.maps.contains_key(".rodata"));
    }
}
