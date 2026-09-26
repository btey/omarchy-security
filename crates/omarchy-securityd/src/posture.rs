// SPDX-License-Identifier: GPL-3.0-or-later

//! Posture audit (task 2.6, plan §2.4). Every 30 s it evaluates:
//!
//! * `lsm`: SELinux enforcing, or AppArmor with profiles loaded.
//! * `ptrace_scope`: `kernel.yama.ptrace_scope >= 1`.
//! * `docker_group`: the user is not in `docker` (root-equivalent).
//! * `swap_encryption`: every swap area sits on dm-crypt or zram.
//!
//! Everything is read from `/proc`, `/sys`, and `/etc/group`, with no
//! privileges and no subprocesses. The roots are parameters so that the
//! checks run against fixture trees in tests.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use omarchy_security_proto::Event;
use omarchy_security_proto::types::{
    CheckStatus, Module, ModuleState, PostureCheck, PostureCheckId, PostureReport,
};

use crate::hub::Hub;
use crate::now_ms;

pub const INTERVAL: Duration = Duration::from_secs(30);

/// Where the checks read from, and who "the user" is.
#[derive(Debug, Clone)]
pub struct PostureEnv {
    pub proc: PathBuf,
    pub sys: PathBuf,
    pub etc_group: PathBuf,
    pub user: String,
    /// Primary and supplementary GIDs of the daemon process.
    pub gids: Vec<u32>,
}

impl PostureEnv {
    pub fn host() -> Self {
        let uid = nix::unistd::getuid();
        let user = nix::unistd::User::from_uid(uid)
            .ok()
            .flatten()
            .map(|u| u.name)
            .or_else(|| std::env::var("USER").ok())
            .unwrap_or_default();
        let mut gids: Vec<u32> = nix::unistd::getgroups()
            .unwrap_or_default()
            .into_iter()
            .map(|g| g.as_raw())
            .collect();
        gids.push(nix::unistd::getgid().as_raw());
        Self {
            proc: "/proc".into(),
            sys: "/sys".into(),
            etc_group: "/etc/group".into(),
            user,
            gids,
        }
    }
}

pub fn evaluate(env: &PostureEnv) -> Vec<PostureCheck> {
    vec![
        check_lsm(env),
        check_ptrace(env),
        check_docker(env),
        check_swap(env),
    ]
}

pub fn report(checks: Vec<PostureCheck>) -> PostureReport {
    PostureReport {
        overall: checks
            .iter()
            .map(|c| c.status)
            .max()
            .unwrap_or(CheckStatus::Unknown),
        evaluated_at: now_ms(),
        checks,
    }
}

fn check(
    check_id: PostureCheckId,
    status: CheckStatus,
    summary: impl Into<String>,
    detail: Option<String>,
) -> PostureCheck {
    PostureCheck {
        check_id,
        status,
        summary: summary.into(),
        detail,
    }
}

fn read_trimmed(path: &Path) -> std::io::Result<String> {
    Ok(std::fs::read_to_string(path)?.trim().to_owned())
}

fn check_lsm(env: &PostureEnv) -> PostureCheck {
    use CheckStatus::*;
    let id = PostureCheckId::Lsm;
    let security = env.sys.join("kernel/security");
    let lsms = read_trimmed(&security.join("lsm")).unwrap_or_default();
    let active: Vec<&str> = lsms.split(',').filter(|s| !s.is_empty()).collect();
    let detail = (!active.is_empty()).then(|| format!("Active LSMs: {}", active.join(", ")));

    if active.contains(&"selinux") {
        return match read_trimmed(&env.sys.join("fs/selinux/enforce")).as_deref() {
            Ok("1") => check(id, Pass, "SELinux is enforcing", detail),
            Ok(_) => check(id, Warn, "SELinux is in permissive mode", detail),
            Err(_) => check(
                id,
                Unknown,
                "SELinux is active but its mode is unreadable",
                detail,
            ),
        };
    }
    if active.contains(&"apparmor") {
        return match std::fs::read_to_string(security.join("apparmor/profiles")) {
            Ok(profiles) => {
                let enforcing = profiles
                    .lines()
                    .filter(|l| l.ends_with("(enforce)"))
                    .count();
                let total = profiles.lines().filter(|l| !l.trim().is_empty()).count();
                if enforcing > 0 {
                    check(
                        id,
                        Pass,
                        format!("AppArmor: {enforcing} of {total} profiles enforcing"),
                        detail,
                    )
                } else {
                    check(
                        id,
                        Warn,
                        "AppArmor is active but no profile is enforcing",
                        detail,
                    )
                }
            }
            Err(_) => check(
                id,
                Unknown,
                "AppArmor is active; its profile list is not readable",
                detail,
            ),
        };
    }
    check(
        id,
        Warn,
        "No mandatory access control (SELinux or AppArmor) is active",
        detail,
    )
}

fn check_ptrace(env: &PostureEnv) -> PostureCheck {
    use CheckStatus::*;
    let id = PostureCheckId::PtraceScope;
    let path = env.proc.join("sys/kernel/yama/ptrace_scope");
    match read_trimmed(&path) {
        Ok(value) => match value.parse::<u32>() {
            Ok(0) => check(
                id,
                Fail,
                "ptrace_scope = 0: any of your processes can trace any other",
                Some("Set kernel.yama.ptrace_scope = 1 in /etc/sysctl.d/.".into()),
            ),
            Ok(n @ 1..=3) => {
                let meaning = ["", "parents only", "admin only", "disabled"][n as usize];
                check(id, Pass, format!("ptrace_scope = {n} ({meaning})"), None)
            }
            _ => check(
                id,
                Unknown,
                format!("Unexpected ptrace_scope value '{value}'"),
                None,
            ),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => check(
            id,
            Fail,
            "Yama is not active: ptrace is unrestricted",
            Some("Boot with yama in the lsm= list.".into()),
        ),
        Err(err) => check(
            id,
            Unknown,
            format!("Cannot read ptrace_scope: {err}"),
            None,
        ),
    }
}

fn check_docker(env: &PostureEnv) -> PostureCheck {
    use CheckStatus::*;
    let id = PostureCheckId::DockerGroup;
    let groups = match std::fs::read_to_string(&env.etc_group) {
        Ok(groups) => groups,
        Err(err) => return check(id, Unknown, format!("Cannot read /etc/group: {err}"), None),
    };
    let docker = groups.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let gid: u32 = fields.nth(1)?.parse().ok()?;
        let members = fields.next().unwrap_or("");
        (name == "docker").then_some((gid, members.to_owned()))
    });
    let Some((gid, members)) = docker else {
        return check(id, Pass, "No docker group on this system", None);
    };
    let listed = members.split(',').any(|m| m.trim() == env.user);
    if listed || env.gids.contains(&gid) {
        check(
            id,
            Fail,
            format!("{} is in the docker group", env.user),
            Some(
                "Members of docker can start a privileged container and become root. \
                 Prefer rootless Docker or Podman."
                    .into(),
            ),
        )
    } else {
        check(
            id,
            Pass,
            format!("{} is not in the docker group", env.user),
            None,
        )
    }
}

/// What a block device ultimately sits on.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Backing {
    Encrypted,
    Ram,
    Plain(String),
}

fn check_swap(env: &PostureEnv) -> PostureCheck {
    use CheckStatus::*;
    let id = PostureCheckId::SwapEncryption;
    let swaps = match std::fs::read_to_string(env.proc.join("swaps")) {
        Ok(swaps) => swaps,
        Err(err) => return check(id, Unknown, format!("Cannot read /proc/swaps: {err}"), None),
    };
    let entries: Vec<(String, String)> = swaps
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((unescape(fields.next()?), fields.next()?.to_owned()))
        })
        .collect();
    if entries.is_empty() {
        return check(id, Pass, "No swap in use", None);
    }

    let mut plain = Vec::new();
    let mut unknown = Vec::new();
    let mut described = Vec::new();
    for (name, kind) in &entries {
        let backing = swap_device(env, name, kind)
            .ok_or_else(|| "backing device not found".to_owned())
            .and_then(|(major, minor)| backing(&env.sys, major, minor));
        match backing {
            Ok(Backing::Encrypted) => described.push(format!("{name}: dm-crypt")),
            Ok(Backing::Ram) => described.push(format!("{name}: zram (RAM only)")),
            Ok(Backing::Plain(dev)) => {
                described.push(format!("{name}: unencrypted ({dev})"));
                plain.push(name.clone());
            }
            Err(reason) => {
                described.push(format!("{name}: {reason}"));
                unknown.push(name.clone());
            }
        }
    }
    let detail = Some(described.join("; "));
    if !plain.is_empty() {
        check(
            id,
            Fail,
            format!("Unencrypted swap: {}", plain.join(", ")),
            detail,
        )
    } else if !unknown.is_empty() {
        check(
            id,
            Unknown,
            format!("Cannot tell whether {} is encrypted", unknown.join(", ")),
            detail,
        )
    } else {
        check(id, Pass, "All swap is encrypted or in RAM", detail)
    }
}

/// Major and minor number of the block device holding a swap area. For a
/// swap file this is the device of the filesystem it lives on, found through
/// mountinfo because btrfs reports an anonymous `st_dev`.
fn swap_device(env: &PostureEnv, name: &str, kind: &str) -> Option<(u64, u64)> {
    let device = if kind == "partition" {
        PathBuf::from(name)
    } else {
        let mountinfo = std::fs::read_to_string(env.proc.join("self/mountinfo")).ok()?;
        PathBuf::from(mount_source(&mountinfo, Path::new(name))?)
    };
    let rdev = std::fs::metadata(device).ok()?.rdev();
    Some((nix::sys::stat::major(rdev), nix::sys::stat::minor(rdev)))
}

/// Source device of the mount that contains `path` (longest mount point
/// that is a prefix of it).
fn mount_source(mountinfo: &str, path: &Path) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let (Some(mount_point), Some(source)) = (
            left.split_whitespace().nth(4),
            right.split_whitespace().nth(1),
        ) else {
            continue;
        };
        let mount_point = unescape(mount_point);
        let depth = Path::new(&mount_point).components().count();
        if path.starts_with(&mount_point) && best.as_ref().is_none_or(|(d, _)| depth >= *d) {
            best = Some((depth, unescape(source)));
        }
    }
    best.map(|(_, source)| source)
}

/// Follows a block device down through device-mapper slaves.
fn backing(sys: &Path, major: u64, minor: u64) -> Result<Backing, String> {
    let dev = sys.join(format!("dev/block/{major}:{minor}"));
    let resolved = std::fs::canonicalize(&dev).map_err(|e| format!("{}: {e}", dev.display()))?;
    backing_of(&resolved, 0)
}

fn backing_of(dev: &Path, depth: usize) -> Result<Backing, String> {
    let name = dev
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name.starts_with("zram") {
        return Ok(Backing::Ram);
    }
    if let Ok(uuid) = std::fs::read_to_string(dev.join("dm/uuid"))
        && uuid.starts_with("CRYPT-")
    {
        return Ok(Backing::Encrypted);
    }
    if depth > 8 {
        return Err("device-mapper stack too deep".into());
    }
    let slaves: Vec<PathBuf> = std::fs::read_dir(dev.join("slaves"))
        .map(|dir| {
            dir.filter_map(|e| std::fs::canonicalize(e.ok()?.path()).ok())
                .collect()
        })
        .unwrap_or_default();
    if slaves.is_empty() {
        return Ok(Backing::Plain(name));
    }
    // A stack is encrypted only if every leg is.
    for slave in &slaves {
        let leg = backing_of(slave, depth + 1)?;
        if leg != Backing::Encrypted {
            return Ok(leg);
        }
    }
    Ok(Backing::Encrypted)
}

/// Undoes the octal escapes (`\040` for space) in `/proc/swaps` and
/// mountinfo.
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let value = u8::from_str_radix(&field[i + 1..i + 4], 8).unwrap_or(b'?');
            out.push(value);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub struct Posture {
    hub: Arc<Hub>,
    env: PostureEnv,
    current: Mutex<Option<PostureReport>>,
}

impl Posture {
    /// Evaluates once, marks the module active, and re-evaluates every
    /// [`INTERVAL`].
    pub fn start(hub: Arc<Hub>, env: PostureEnv) -> Arc<Self> {
        let posture = Arc::new(Self {
            hub,
            env,
            current: Mutex::new(None),
        });
        posture
            .hub
            .set_status(Module::Posture, ModuleState::Active, None);
        let ticker = posture.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                ticker.refresh().await;
            }
        });
        posture
    }

    pub async fn report(&self) -> PostureReport {
        let cached = self.current.lock().expect("posture lock").clone();
        match cached {
            Some(report) => report,
            None => self.refresh().await,
        }
    }

    /// Evaluates now. Emits `POSTURE_CHANGED` if any check changed.
    pub async fn refresh(&self) -> PostureReport {
        let env = self.env.clone();
        let checks = tokio::task::spawn_blocking(move || evaluate(&env))
            .await
            .expect("posture evaluation does not panic");
        let report = report(checks);
        let changed = {
            let mut current = self.current.lock().expect("posture lock");
            let changed = current
                .as_ref()
                .is_none_or(|old| old.checks != report.checks);
            let first = current.is_none();
            *current = Some(report.clone());
            changed && !first
        };
        if changed {
            tracing::info!(overall = ?report.overall, "posture changed");
            self.hub.emit(Event::PostureChanged(report.clone()));
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let fixture = Self {
                dir: tempfile::tempdir().unwrap(),
            };
            fixture.write("proc/swaps", "Filename Type Size Used Priority\n");
            fixture.write("etc/group", "root:x:0:\nwheel:x:998:ben\n");
            fixture
        }

        fn write(&self, rel: &str, contents: &str) {
            let path = self.dir.path().join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }

        fn env(&self) -> PostureEnv {
            PostureEnv {
                proc: self.dir.path().join("proc"),
                sys: self.dir.path().join("sys"),
                etc_group: self.dir.path().join("etc/group"),
                user: "ben".into(),
                gids: vec![1000, 998],
            }
        }

        fn status(&self, id: PostureCheckId) -> PostureCheck {
            evaluate(&self.env())
                .into_iter()
                .find(|c| c.check_id == id)
                .unwrap()
        }
    }

    #[test]
    fn lsm_check() {
        let f = Fixture::new();
        assert_eq!(f.status(PostureCheckId::Lsm).status, CheckStatus::Warn);
        f.write("sys/kernel/security/lsm", "lockdown,capability,selinux\n");
        f.write("sys/fs/selinux/enforce", "1");
        assert_eq!(f.status(PostureCheckId::Lsm).status, CheckStatus::Pass);
        f.write("sys/fs/selinux/enforce", "0");
        assert_eq!(f.status(PostureCheckId::Lsm).status, CheckStatus::Warn);

        f.write("sys/kernel/security/lsm", "capability,apparmor");
        assert_eq!(f.status(PostureCheckId::Lsm).status, CheckStatus::Unknown);
        f.write(
            "sys/kernel/security/apparmor/profiles",
            "/usr/bin/man (complain)\nfirefox (enforce)\n",
        );
        let lsm = f.status(PostureCheckId::Lsm);
        assert_eq!(lsm.status, CheckStatus::Pass);
        assert_eq!(lsm.summary, "AppArmor: 1 of 2 profiles enforcing");
    }

    #[test]
    fn ptrace_check() {
        let f = Fixture::new();
        assert_eq!(
            f.status(PostureCheckId::PtraceScope).status,
            CheckStatus::Fail
        );
        f.write("proc/sys/kernel/yama/ptrace_scope", "0\n");
        assert_eq!(
            f.status(PostureCheckId::PtraceScope).status,
            CheckStatus::Fail
        );
        f.write("proc/sys/kernel/yama/ptrace_scope", "1\n");
        assert_eq!(
            f.status(PostureCheckId::PtraceScope).status,
            CheckStatus::Pass
        );
        f.write("proc/sys/kernel/yama/ptrace_scope", "7\n");
        assert_eq!(
            f.status(PostureCheckId::PtraceScope).status,
            CheckStatus::Unknown
        );
    }

    #[test]
    fn docker_check() {
        let f = Fixture::new();
        assert_eq!(
            f.status(PostureCheckId::DockerGroup).status,
            CheckStatus::Pass
        );
        f.write("etc/group", "docker:x:970:alice,bob\n");
        assert_eq!(
            f.status(PostureCheckId::DockerGroup).status,
            CheckStatus::Pass
        );
        f.write("etc/group", "docker:x:970:alice,ben\n");
        assert_eq!(
            f.status(PostureCheckId::DockerGroup).status,
            CheckStatus::Fail
        );
        // Membership through the process's GIDs (NSS, sssd) counts too.
        f.write("etc/group", "docker:x:998:\n");
        assert_eq!(
            f.status(PostureCheckId::DockerGroup).status,
            CheckStatus::Fail
        );
    }

    #[test]
    fn no_swap_passes() {
        let f = Fixture::new();
        assert_eq!(
            f.status(PostureCheckId::SwapEncryption).status,
            CheckStatus::Pass
        );
    }

    #[test]
    fn swap_backing_walks_device_mapper() {
        let f = Fixture::new();
        let sys = f.dir.path().join("sys");
        let block = sys.join("devices/virtual/block");
        // dm-1 (LVM) on dm-0 (LUKS) on nvme0n1p2; sda1 plain; zram0.
        f.write(
            "sys/devices/virtual/block/dm-0/dm/uuid",
            "CRYPT-LUKS2-abc-root\n",
        );
        f.write("sys/devices/virtual/block/dm-1/dm/uuid", "LVM-xyz\n");
        f.write("sys/devices/pci/nvme0n1/nvme0n1p2/size", "1");
        f.write("sys/devices/pci/sda/sda1/size", "1");
        f.write("sys/devices/virtual/block/zram0/size", "1");
        fs::create_dir_all(block.join("dm-1/slaves")).unwrap();
        fs::create_dir_all(block.join("dm-0/slaves")).unwrap();
        fs::create_dir_all(sys.join("dev/block")).unwrap();
        let link = |target: PathBuf, at: PathBuf| std::os::unix::fs::symlink(target, at).unwrap();
        link(block.join("dm-0"), block.join("dm-1/slaves/dm-0"));
        link(
            sys.join("devices/pci/nvme0n1/nvme0n1p2"),
            block.join("dm-0/slaves/nvme0n1p2"),
        );
        link(block.join("dm-1"), sys.join("dev/block/254:1"));
        link(sys.join("devices/pci/sda/sda1"), sys.join("dev/block/8:1"));
        link(block.join("zram0"), sys.join("dev/block/253:0"));

        assert_eq!(backing(&sys, 254, 1), Ok(Backing::Encrypted));
        assert_eq!(backing(&sys, 8, 1), Ok(Backing::Plain("sda1".into())));
        assert_eq!(backing(&sys, 253, 0), Ok(Backing::Ram));
        assert!(backing(&sys, 1, 1).is_err());
    }

    #[test]
    fn mount_source_picks_the_longest_prefix() {
        let mountinfo = "\
26 1 0:24 /@ / rw,relatime shared:1 - btrfs /dev/mapper/root rw\n\
27 26 0:25 /@swap /swap rw,relatime shared:2 - btrfs /dev/mapper/swap rw\n\
28 26 8:1 / /mnt/my\\040disk rw - ext4 /dev/sda1 rw\n";
        assert_eq!(
            mount_source(mountinfo, Path::new("/swap/swapfile")).as_deref(),
            Some("/dev/mapper/swap")
        );
        assert_eq!(
            mount_source(mountinfo, Path::new("/home/x")).as_deref(),
            Some("/dev/mapper/root")
        );
        assert_eq!(
            mount_source(mountinfo, Path::new("/mnt/my disk/swap")).as_deref(),
            Some("/dev/sda1")
        );
    }

    #[test]
    fn unescapes_octal() {
        assert_eq!(unescape(r"/a\040b"), "/a b");
        assert_eq!(unescape(r"/a\04"), r"/a\04");
    }

    #[test]
    fn overall_is_the_worst_check() {
        let f = Fixture::new();
        f.write("proc/sys/kernel/yama/ptrace_scope", "1\n");
        let report = report(evaluate(&f.env()));
        assert_eq!(report.overall, CheckStatus::Warn); // no LSM
        assert_eq!(report.checks.len(), 4);
    }

    #[test]
    fn host_evaluation_does_not_fail() {
        // Smoke test against the real machine: every check yields a status.
        let checks = evaluate(&PostureEnv::host());
        assert_eq!(checks.len(), 4);
        for check in checks {
            eprintln!("{:?}: {:?} {}", check.check_id, check.status, check.summary);
        }
    }

    #[tokio::test]
    async fn refresh_emits_only_when_checks_change() {
        let f = Fixture::new();
        let hub = Arc::new(Hub::new());
        let posture = Posture {
            hub: hub.clone(),
            env: f.env(),
            current: Mutex::new(None),
        };
        let mut rx = hub.subscribe();
        posture.refresh().await;
        posture.refresh().await;
        assert!(
            rx.try_recv().is_err(),
            "first and unchanged evaluations are silent"
        );
        f.write("proc/sys/kernel/yama/ptrace_scope", "2\n");
        posture.refresh().await;
        assert!(matches!(rx.try_recv(), Ok(Event::PostureChanged(_))));
    }
}
