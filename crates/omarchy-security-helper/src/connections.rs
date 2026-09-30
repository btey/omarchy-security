// SPDX-License-Identifier: GPL-3.0-or-later

//! Connection interception (task 2.13, plan §5.7).
//!
//! While the daemon subscribes to connections or has executable rules, the
//! output chain of `table inet omarchy_sec` sends every new outbound TCP
//! and UDP connection of the desktop user to NFQUEUE [`DEFAULT_QUEUE`]
//! (see `firewall.rs`). A dedicated thread reads the queue and, for each
//! packet:
//!
//! 1. parses its flow (`packet.rs`);
//! 2. finds the sending socket with `sock_diag` (`sockdiag.rs`), then the
//!    process that holds it by matching `socket:[inode]` in `/proc/*/fd`,
//!    and reads `/proc/<pid>/exe`;
//! 3. applies a `remember: process` verdict for that process, or else the
//!    executable rules (an allow wins over a block, as in the table);
//! 4. otherwise, with a subscriber, holds the packet and sends a
//!    [`ConnectionRecord`], until a verdict arrives or the subscription's
//!    timeout passes; without one, accepts it.
//!
//! Failing open, on purpose: the queue rule has `bypass`, so traffic flows
//! when the helper is not reading the queue (stopped, restarting), and the
//! queue is bound with `NFQA_CFG_F_FAIL_OPEN`, so a full queue accepts
//! rather than drops. A packet whose process cannot be found (it exited,
//! or the socket belongs to the kernel) is accepted as well. Blocking the
//! desktop's network whenever the helper hiccups would be worse than an
//! occasional unprompted connection; the static rules in the table still
//! apply in every case.
//!
//! Retransmissions of a held packet (TCP resends its SYN) join the held
//! connection instead of raising another prompt, and a decided flow keeps
//! its verdict for [`RECENT_TTL`], so a dropped SYN's retries are dropped
//! too.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use omarchy_security_proto::helper::{
    ConnectionRecord, HelperError, HelperErrorKind, HelperMessage, Remember,
};
use omarchy_security_proto::procfs::Proc;
use omarchy_security_proto::types::{Direction, FirewallRule, Protocol, Verdict, parse_prefix};
use tokio::sync::mpsc;

use crate::nfqueue::{Packet, Queue};
use crate::packet::{self, Flow};
use crate::sockdiag::SockDiag;

/// The NFQUEUE number, away from 0, which OpenSnitch and most examples use.
pub const DEFAULT_QUEUE: u16 = 7433;
/// How long a decided flow keeps its verdict for retransmissions.
const RECENT_TTL: Duration = Duration::from_secs(30);
/// How often the queue thread wakes to expire held connections.
const TICK: Duration = Duration::from_millis(100);
const PRUNE_EVERY: Duration = Duration::from_secs(10);
/// Bound on each lookup cache.
const CACHE_LIMIT: usize = 4096;

/// What a `remember: process` verdict covers besides the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Target {
    protocol: Protocol,
    address: IpAddr,
    port: u16,
}

/// An executable-scoped rule, parsed once when applied.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecRule {
    verdict: Verdict,
    executable: String,
    network: (IpAddr, u8),
    port: Option<u16>,
    protocol: Option<Protocol>,
}

impl ExecRule {
    fn parse(rule: &FirewallRule) -> Result<Self, String> {
        let spec = &rule.spec;
        let executable = spec
            .executable
            .clone()
            .ok_or_else(|| format!("rule {} has no executable", rule.rule_id))?;
        if !executable.starts_with('/') {
            return Err(format!(
                "rule {}: executable must be an absolute path",
                rule.rule_id
            ));
        }
        if spec.direction != Direction::Outbound {
            return Err(format!(
                "rule {}: executable rules apply to outbound connections only",
                rule.rule_id
            ));
        }
        Ok(Self {
            verdict: spec.verdict,
            executable,
            network: parse_prefix(&spec.address)
                .map_err(|e| format!("rule {}: {e}", rule.rule_id))?,
            port: spec.port,
            protocol: spec.protocol,
        })
    }

    fn matches(&self, executable: &str, flow: &Flow) -> bool {
        self.executable == executable
            && self.protocol.is_none_or(|p| p == flow.protocol)
            && self.port.is_none_or(|p| p == flow.dport)
            && in_prefix(flow.dst, self.network)
    }
}

/// Checks an executable-scoped rule before it is applied.
pub fn validate(rule: &FirewallRule) -> Result<(), String> {
    ExecRule::parse(rule).map(|_| ())
}

fn in_prefix(ip: IpAddr, (network, len): (IpAddr, u8)) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0);
            u32::from(ip) & mask == u32::from(network)
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            u128::from(ip) & mask == u128::from(network)
        }
        _ => false,
    }
}

/// The verdict of the rules for this connection, if any matches.
fn rule_verdict(rules: &[ExecRule], executable: &str, flow: &Flow) -> Option<Verdict> {
    let mut verdict = None;
    for rule in rules.iter().filter(|r| r.matches(executable, flow)) {
        if rule.verdict == Verdict::Allow {
            return Some(Verdict::Allow);
        }
        verdict = Some(Verdict::Block);
    }
    verdict
}

/// The process behind a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Owner {
    pid: u32,
    start_time: u64,
    uid: u32,
    executable: String,
}

/// Finds owners, caching sockets and executables. Used only by the queue
/// thread.
struct Lookup {
    diag: SockDiag,
    proc: Proc,
    /// The mount id of sockfs, which every socket is on.
    sockfs: u32,
    /// Socket inode → process.
    sockets: HashMap<u32, (u32, u64)>,
    /// Process → executable.
    executables: HashMap<(u32, u64), String>,
}

impl Lookup {
    fn owner(&mut self, flow: &Flow) -> Option<Owner> {
        let socket = match self.diag.find(flow) {
            Ok(Some(socket)) => socket,
            Ok(None) => return None,
            Err(err) => {
                tracing::warn!("sock_diag: {err}");
                return None;
            }
        };
        let cached = self
            .sockets
            .get(&socket.inode)
            .copied()
            .filter(|&(pid, start)| self.proc.is_same_process(pid, start));
        let (pid, start_time) = match cached {
            Some(process) => process,
            None => {
                let pid = socket_holder(&self.proc, self.sockfs, socket.inode, socket.uid)?;
                let start = self.proc.stat(pid).ok()?.start_time;
                if self.sockets.len() >= CACHE_LIMIT {
                    self.sockets.clear();
                }
                self.sockets.insert(socket.inode, (pid, start));
                (pid, start)
            }
        };
        let executable = match self.executables.get(&(pid, start_time)) {
            Some(exe) => exe.clone(),
            None => {
                let exe = self.proc.exe(pid).ok()?;
                let exe = exe.strip_suffix(" (deleted)").unwrap_or(&exe).to_owned();
                if self.executables.len() >= CACHE_LIMIT {
                    self.executables.clear();
                }
                self.executables.insert((pid, start_time), exe.clone());
                exe
            }
        };
        Some(Owner {
            pid,
            start_time,
            uid: socket.uid,
            executable,
        })
    }
}

/// The first process of `uid` with an open file descriptor for socket
/// `inode`.
///
/// It reads `/proc/<pid>/fdinfo`, not the links in `/proc/<pid>/fd`: the
/// kernel lets a process with `CAP_SYS_PTRACE` read another user's fdinfo,
/// but reading their `fd` directory needs `CAP_DAC_READ_SEARCH`, which the
/// helper's unit does not grant. An fdinfo names the file by `mnt_id` and
/// `ino`, and every socket is on the one sockfs mount (`sockfs`).
fn socket_holder(proc: &Proc, sockfs: u32, inode: u32, uid: u32) -> Option<u32> {
    proc.pids().ok()?.into_iter().find(|&pid| {
        let dir = proc.root().join(pid.to_string());
        if std::fs::metadata(&dir).map(|m| m.uid()).ok() != Some(uid) {
            return false;
        }
        let Ok(fds) = std::fs::read_dir(dir.join("fdinfo")) else {
            return false;
        };
        fds.flatten().any(|fd| {
            std::fs::read_to_string(fd.path()).is_ok_and(|info| fdinfo_names(&info, sockfs, inode))
        })
    })
}

/// Whether an fdinfo is that of the file `ino` on mount `mnt_id`.
fn fdinfo_names(info: &str, mnt_id: u32, ino: u32) -> bool {
    let field = |name: &str| {
        info.lines()
            .find_map(|line| line.strip_prefix(name)?.trim().parse::<u64>().ok())
    };
    field("mnt_id:") == Some(mnt_id.into()) && field("ino:") == Some(ino.into())
}

/// The mount id of sockfs, read from the fdinfo of a socket of our own
/// (AF_UNIX: the unit allows no other family that `socket(2)` would need).
fn sockfs_mnt_id(proc: &Proc) -> io::Result<u32> {
    let socket = std::os::unix::net::UnixDatagram::unbound()?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&socket);
    let info = std::fs::read_to_string(proc.root().join(format!("self/fdinfo/{fd}")))?;
    info.lines()
        .find_map(|line| line.strip_prefix("mnt_id:")?.trim().parse().ok())
        .ok_or_else(|| io::Error::other("no mnt_id in a socket's fdinfo"))
}

struct Subscriber {
    /// The helper connection that subscribed.
    conn: u64,
    uid: u32,
    out: mpsc::Sender<HelperMessage>,
    timeout: Duration,
    timeout_verdict: Verdict,
}

/// A connection held for a verdict.
struct Held {
    conn: u64,
    flow: Flow,
    /// The packet and its retransmissions.
    packets: Vec<u32>,
    deadline: Instant,
    timeout_verdict: Verdict,
    process: (u32, u64),
    target: Target,
}

#[derive(Default)]
struct Inner {
    rules: Vec<ExecRule>,
    /// Whose connections the rules are for: the uid that applied them.
    rules_uid: Option<u32>,
    subscriber: Option<Subscriber>,
    held: HashMap<u64, Held>,
    held_flows: HashMap<Flow, u64>,
    /// `remember: process` verdicts, by process and target.
    remembered: HashMap<((u32, u64), Target), Verdict>,
    recent: HashMap<Flow, (Verdict, Instant)>,
    next_request: u64,
    last_prune: Option<Instant>,
}

impl Inner {
    /// Forgets a held connection, keeping its verdict for retransmissions.
    fn resolve(&mut self, request_id: u64, verdict: Verdict, now: Instant) -> Option<Held> {
        let held = self.held.remove(&request_id)?;
        self.held_flows.remove(&held.flow);
        self.recent.insert(held.flow, (verdict, now));
        Some(held)
    }

    /// Releases every connection held for `conn`, with its timeout verdict.
    fn release_conn(&mut self, conn: u64, now: Instant) -> Vec<(Vec<u32>, Verdict)> {
        let ids: Vec<u64> = self
            .held
            .iter()
            .filter(|(_, h)| h.conn == conn)
            .map(|(&id, _)| id)
            .collect();
        ids.into_iter()
            .filter_map(|id| {
                let verdict = self.held.get(&id)?.timeout_verdict;
                Some((self.resolve(id, verdict, now)?.packets, verdict))
            })
            .collect()
    }
}

pub struct Interceptor {
    queue: Queue,
    inner: Mutex<Inner>,
    stop: AtomicBool,
}

impl Interceptor {
    /// Binds `queue_num` and starts the queue thread.
    pub fn start(queue_num: u16, proc: Proc) -> io::Result<Arc<Self>> {
        let queue = Queue::bind(queue_num)?;
        queue.set_timeout(TICK)?;
        let lookup = Lookup {
            diag: SockDiag::open()?,
            sockfs: sockfs_mnt_id(&proc)?,
            proc,
            sockets: HashMap::new(),
            executables: HashMap::new(),
        };
        let interceptor = Arc::new(Self {
            queue,
            inner: Mutex::new(Inner::default()),
            stop: AtomicBool::new(false),
        });
        let thread = interceptor.clone();
        std::thread::Builder::new()
            .name("nfqueue".into())
            .spawn(move || thread.run(lookup))?;
        Ok(interceptor)
    }

    pub fn queue_num(&self) -> u16 {
        self.queue.num()
    }

    /// Stops the queue thread; the queue is unbound once it exits.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("interceptor lock")
    }

    /// The uid whose connections should be queued, or `None` when nothing
    /// needs the queue.
    pub fn wanted_queue(&self) -> Option<u32> {
        let inner = self.lock();
        match &inner.subscriber {
            Some(subscriber) => Some(subscriber.uid),
            None if !inner.rules.is_empty() => inner.rules_uid,
            None => None,
        }
    }

    /// Replaces the executable rules, applied by `uid`.
    pub fn set_rules(&self, rules: &[FirewallRule], uid: u32) -> Result<(), String> {
        let parsed = rules
            .iter()
            .map(ExecRule::parse)
            .collect::<Result<_, _>>()?;
        let mut inner = self.lock();
        inner.rules = parsed;
        inner.rules_uid = Some(uid);
        Ok(())
    }

    /// Makes `conn` the subscriber, replacing any other.
    pub fn subscribe(
        &self,
        conn: u64,
        uid: u32,
        out: mpsc::Sender<HelperMessage>,
        timeout: Duration,
        timeout_verdict: Verdict,
    ) {
        let mut inner = self.lock();
        let released = match inner.subscriber.as_ref().map(|s| s.conn) {
            Some(old) if old != conn => inner.release_conn(old, Instant::now()),
            _ => vec![],
        };
        inner.subscriber = Some(Subscriber {
            conn,
            uid,
            out,
            timeout,
            timeout_verdict,
        });
        drop(inner);
        self.release_all(released);
    }

    /// Called when a helper connection closes: ends its subscription and
    /// releases what it held.
    pub fn disconnected(&self, conn: u64) {
        let mut inner = self.lock();
        if inner.subscriber.as_ref().is_some_and(|s| s.conn == conn) {
            inner.subscriber = None;
        }
        let released = inner.release_conn(conn, Instant::now());
        drop(inner);
        self.release_all(released);
    }

    /// A subscriber's verdict on a held connection.
    pub fn verdict(
        &self,
        conn: u64,
        request_id: u64,
        verdict: Verdict,
        remember: Remember,
    ) -> Result<(), HelperError> {
        let mut inner = self.lock();
        if inner.held.get(&request_id).is_none_or(|h| h.conn != conn) {
            return Err(HelperError::new(
                HelperErrorKind::NotFound,
                format!("no connection {request_id} is held for this client"),
            ));
        }
        let held = inner
            .resolve(request_id, verdict, Instant::now())
            .expect("checked above");
        if remember == Remember::Process {
            inner
                .remembered
                .insert((held.process, held.target), verdict);
        }
        drop(inner);
        tracing::info!(request_id, ?verdict, ?remember, "connection decided");
        self.release(&held.packets, verdict);
        Ok(())
    }

    fn release(&self, packets: &[u32], verdict: Verdict) {
        for &id in packets {
            if let Err(err) = self.queue.verdict(id, verdict == Verdict::Allow) {
                tracing::warn!("nfqueue verdict for packet {id}: {err}");
            }
        }
    }

    fn release_all(&self, released: Vec<(Vec<u32>, Verdict)>) {
        for (packets, verdict) in released {
            self.release(&packets, verdict);
        }
    }

    fn run(self: Arc<Self>, mut lookup: Lookup) {
        // Packets are cut to the copy range, so a batch fits easily.
        let mut buf = vec![0u8; 256 * 1024];
        while !self.stop.load(Ordering::Relaxed) {
            match self.queue.recv(&mut buf) {
                Ok(packets) => {
                    for packet in packets {
                        self.handle(packet, &mut lookup);
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(err) if err.raw_os_error() == Some(nix::errno::Errno::ENOBUFS as i32) => {
                    // The kernel accepted what it could not deliver
                    // (NFQA_CFG_F_FAIL_OPEN).
                    tracing::warn!("nfqueue: receive buffer overflowed");
                }
                Err(err) => {
                    tracing::error!("nfqueue: {err}");
                    std::thread::sleep(TICK);
                }
            }
            self.expire(Instant::now(), &lookup.proc);
        }
        tracing::info!("connection interception stopped");
    }

    fn handle(&self, packet: Packet, lookup: &mut Lookup) {
        let Some(flow) = packet::parse(&packet.payload) else {
            self.release(&[packet.id], Verdict::Allow);
            return;
        };
        let now = Instant::now();
        {
            let mut inner = self.lock();
            if let Some(&(verdict, at)) = inner.recent.get(&flow)
                && now.duration_since(at) < RECENT_TTL
            {
                drop(inner);
                self.release(&[packet.id], verdict);
                return;
            }
            if let Some(request_id) = inner.held_flows.get(&flow).copied()
                && let Some(held) = inner.held.get_mut(&request_id)
            {
                held.packets.push(packet.id);
                return;
            }
        }
        // Looked up without the lock: this reads /proc.
        let owner = lookup.owner(&flow);
        let verdict = self.decide(packet.id, flow, owner, now);
        if let Some(verdict) = verdict {
            self.release(&[packet.id], verdict);
        }
    }

    /// The immediate verdict for a new connection, or `None` once it is held.
    fn decide(&self, id: u32, flow: Flow, owner: Option<Owner>, now: Instant) -> Option<Verdict> {
        let Some(owner) = owner else {
            tracing::debug!(?flow, "no process for connection; accepting");
            return Some(Verdict::Allow);
        };
        let target = Target {
            protocol: flow.protocol,
            address: flow.dst,
            port: flow.dport,
        };
        let process = (owner.pid, owner.start_time);
        let mut inner = self.lock();
        if let Some(&verdict) = inner.remembered.get(&(process, target)) {
            return Some(verdict);
        }
        if let Some(verdict) = rule_verdict(&inner.rules, &owner.executable, &flow) {
            tracing::debug!(pid = owner.pid, exe = %owner.executable, ?verdict, "executable rule");
            return Some(verdict);
        }
        let (conn, out, timeout, timeout_verdict) = match &inner.subscriber {
            Some(s) => (s.conn, s.out.clone(), s.timeout, s.timeout_verdict),
            None => return Some(Verdict::Allow),
        };
        inner.next_request += 1;
        let request_id = inner.next_request;
        let record = ConnectionRecord {
            request_id,
            pid: owner.pid,
            start_time: owner.start_time,
            uid: owner.uid,
            executable: owner.executable,
            protocol: flow.protocol,
            address: flow.dst.to_string(),
            port: flow.dport,
        };
        if out.try_send(HelperMessage::Connection(record)).is_err() {
            tracing::warn!("subscriber is not reading; applying the timeout verdict");
            inner.recent.insert(flow, (timeout_verdict, now));
            return Some(timeout_verdict);
        }
        tracing::info!(request_id, pid = owner.pid, ?flow, "connection held");
        inner.held_flows.insert(flow, request_id);
        inner.held.insert(
            request_id,
            Held {
                conn,
                flow,
                packets: vec![id],
                deadline: now + timeout,
                timeout_verdict,
                process,
                target,
            },
        );
        None
    }

    /// Applies the timeout verdict to overdue connections, and prunes the
    /// memory of decided flows and of exited processes.
    fn expire(&self, now: Instant, proc: &Proc) {
        let mut inner = self.lock();
        let overdue: Vec<(u64, Verdict)> = inner
            .held
            .iter()
            .filter(|(_, h)| h.deadline <= now)
            .map(|(&id, h)| (id, h.timeout_verdict))
            .collect();
        let mut released = Vec::new();
        for (id, verdict) in overdue {
            if let Some(held) = inner.resolve(id, verdict, now) {
                tracing::info!(request_id = id, ?verdict, "connection timed out");
                released.push((held.packets, verdict));
            }
        }
        if inner
            .last_prune
            .is_none_or(|at| now.duration_since(at) >= PRUNE_EVERY)
        {
            inner.last_prune = Some(now);
            inner
                .recent
                .retain(|_, (_, at)| now.duration_since(*at) < RECENT_TTL);
            inner
                .remembered
                .retain(|((pid, start), _), _| proc.is_same_process(*pid, *start));
        }
        drop(inner);
        self.release_all(released);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use omarchy_security_proto::types::FirewallRuleSpec;

    fn exec_rule(verdict: Verdict, address: &str, port: Option<u16>) -> FirewallRule {
        FirewallRule {
            rule_id: 1,
            spec: FirewallRuleSpec {
                verdict,
                direction: Direction::Outbound,
                address: address.into(),
                port,
                protocol: Some(Protocol::Tcp),
                executable: Some("/usr/bin/curl".into()),
            },
            loaded: false,
        }
    }

    fn flow(dst: &str, dport: u16) -> Flow {
        Flow {
            protocol: Protocol::Tcp,
            src: if dst.contains(':') { "::1" } else { "10.0.0.1" }
                .parse()
                .unwrap(),
            sport: 40000,
            dst: dst.parse().unwrap(),
            dport,
        }
    }

    #[test]
    fn matches_executable_rules() {
        let rules: Vec<ExecRule> = [
            exec_rule(Verdict::Block, "0.0.0.0/0", None),
            exec_rule(Verdict::Allow, "192.0.2.0/24", Some(443)),
            exec_rule(Verdict::Block, "2001:db8::/32", None),
        ]
        .iter()
        .map(|r| ExecRule::parse(r).unwrap())
        .collect();
        let curl = "/usr/bin/curl";
        assert_eq!(
            rule_verdict(&rules, curl, &flow("192.0.2.9", 443)),
            Some(Verdict::Allow)
        );
        assert_eq!(
            rule_verdict(&rules, curl, &flow("192.0.2.9", 80)),
            Some(Verdict::Block)
        );
        assert_eq!(
            rule_verdict(&rules, curl, &flow("2001:db8::1", 80)),
            Some(Verdict::Block)
        );
        assert_eq!(rule_verdict(&rules, curl, &flow("2001:db9::1", 80)), None);
        assert_eq!(
            rule_verdict(&rules, "/usr/bin/wget", &flow("192.0.2.9", 80)),
            None
        );
        let mut udp = flow("192.0.2.9", 443);
        udp.protocol = Protocol::Udp;
        assert_eq!(rule_verdict(&rules, curl, &udp), None);
    }

    #[test]
    fn validates_executable_rules() {
        assert!(validate(&exec_rule(Verdict::Allow, "10.0.0.0/8", None)).is_ok());
        let mut relative = exec_rule(Verdict::Allow, "10.0.0.0/8", None);
        relative.spec.executable = Some("curl".into());
        assert!(validate(&relative).unwrap_err().contains("absolute"));
        let mut inbound = exec_rule(Verdict::Allow, "10.0.0.0/8", None);
        inbound.spec.direction = Direction::Inbound;
        assert!(validate(&inbound).unwrap_err().contains("outbound"));
        assert!(validate(&exec_rule(Verdict::Allow, "nope", None)).is_err());
    }

    #[test]
    fn checks_prefixes() {
        let net = |s: &str| parse_prefix(s).unwrap();
        assert!(in_prefix("10.1.2.3".parse().unwrap(), net("10.0.0.0/8")));
        assert!(!in_prefix("11.1.2.3".parse().unwrap(), net("10.0.0.0/8")));
        assert!(in_prefix("1.2.3.4".parse().unwrap(), net("0.0.0.0/0")));
        assert!(in_prefix("::1".parse().unwrap(), net("::/0")));
        assert!(!in_prefix("::1".parse().unwrap(), net("0.0.0.0/0")));
        assert!(in_prefix("192.0.2.1".parse().unwrap(), net("192.0.2.1")));
    }

    #[test]
    fn finds_the_holder_of_a_socket() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&socket);
        let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
        let inode: u32 = link
            .to_str()
            .unwrap()
            .trim_start_matches("socket:[")
            .trim_end_matches(']')
            .parse()
            .unwrap();
        let uid = std::fs::metadata("/proc/self").unwrap().uid();
        let proc = Proc::default();
        let sockfs = sockfs_mnt_id(&proc).unwrap();
        let holder = socket_holder(&proc, sockfs, inode, uid).unwrap();
        // Threads of this process share the fd table; the pid found is
        // this process.
        assert_eq!(holder, std::process::id());
        assert_eq!(
            socket_holder(&proc, sockfs, inode, uid.wrapping_add(1)),
            None
        );
        // The same inode number on another mount is not the socket.
        assert_eq!(socket_holder(&proc, sockfs + 1, inode, uid), None);
    }

    #[test]
    fn reads_fdinfo() {
        let socket = "pos:\t0\nflags:\t02000002\nmnt_id:\t12\nino:\t117629\n";
        assert!(fdinfo_names(socket, 12, 117629));
        assert!(!fdinfo_names(socket, 13, 117629));
        assert!(!fdinfo_names(socket, 12, 117628));
        // A file without an ino line (kernels before 5.14) never matches.
        assert!(!fdinfo_names(
            "pos:\t0\nflags:\t0100000\nmnt_id:\t12\n",
            12,
            0
        ));
    }

    const NAMESPACED_ENV: &str = "OMARCHY_SECURITY_NFQUEUE_TEST";

    /// Runs [`namespaced`] inside `unshare -rn`, where this process holds
    /// `CAP_NET_ADMIN` over a network namespace of its own with only `lo`.
    #[test]
    fn intercepts_connections_in_a_namespace() {
        if crate::firewall::find_nft().is_none()
            || !std::process::Command::new("unshare")
                .args(["-rn", "true"])
                .status()
                .is_ok_and(|s| s.success())
        {
            eprintln!("needs nft and unprivileged user namespaces; skipping");
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let output = std::process::Command::new("unshare")
            .args(["-rn", "sh", "-c", "ip link set lo up && exec \"$0\" \"$@\""])
            .arg(exe)
            .args([
                "--exact",
                "connections::tests::namespaced",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(NAMESPACED_ENV, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("NFQUEUE unavailable") {
            eprintln!("{stderr}; skipping");
            return;
        }
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "stdout: {stdout}\nstderr: {stderr}"
        );
    }

    /// The end-to-end check of plan §5.7, run by
    /// [`intercepts_connections_in_a_namespace`].
    #[test]
    #[ignore = "run inside a network namespace by intercepts_connections_in_a_namespace"]
    fn namespaced() {
        use crate::firewall::{Firewall, QueueRule};
        use std::net::{TcpListener, TcpStream, UdpSocket};

        if std::env::var_os(NAMESPACED_ENV).is_none() {
            return;
        }
        let interceptor = match Interceptor::start(DEFAULT_QUEUE, Proc::default()) {
            Ok(interceptor) => interceptor,
            Err(err) => {
                eprintln!("NFQUEUE unavailable: {err}");
                return;
            }
        };
        let uid = nix::unistd::geteuid().as_raw();
        let exe = std::env::current_exe().unwrap();
        let exe = exe.to_str().unwrap().to_owned();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let firewall = Firewall::with_wrapper(&[]);
        let queue = |i: &Interceptor| {
            i.wanted_queue().map(|uid| QueueRule {
                num: i.queue_num(),
                uid,
                loopback: true,
            })
        };
        let (tx, mut rx) = mpsc::channel(16);
        interceptor.subscribe(1, uid, tx.clone(), Duration::from_secs(20), Verdict::Block);
        runtime
            .block_on(firewall.set_queue(|| queue(&interceptor)))
            .unwrap();
        let next_record = |rx: &mut mpsc::Receiver<HelperMessage>| {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match rx.try_recv() {
                    Ok(HelperMessage::Connection(record)) => return record,
                    Ok(other) => panic!("unexpected {other:?}"),
                    Err(_) if Instant::now() < deadline => std::thread::sleep(TICK),
                    Err(_) => panic!("no connection record within 5 s"),
                }
            }
        };
        let udp_server = || {
            let server = UdpSocket::bind("127.0.0.1:0").unwrap();
            server
                .set_read_timeout(Some(Duration::from_millis(500)))
                .unwrap();
            server
        };
        let received = |server: &UdpSocket| server.recv(&mut [0u8; 16]).is_ok();

        // TCP, allowed: the process and executable are named.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = std::thread::spawn(move || {
            TcpStream::connect_timeout(&addr, Duration::from_secs(10)).is_ok()
        });
        let record = next_record(&mut rx);
        assert_eq!(record.pid, std::process::id());
        assert_eq!(record.uid, uid);
        assert_eq!(record.executable, exe);
        assert_eq!(record.protocol, Protocol::Tcp);
        assert_eq!(
            (record.address.as_str(), record.port),
            ("127.0.0.1", addr.port())
        );
        assert!(proc_same(record.pid, record.start_time));
        interceptor
            .verdict(1, record.request_id, Verdict::Allow, Remember::None)
            .unwrap();
        assert!(client.join().unwrap(), "allowed connection completes");
        // Only the subscriber that received a record may answer it.
        let err = interceptor
            .verdict(2, record.request_id, Verdict::Allow, Remember::None)
            .unwrap_err();
        assert_eq!(err.kind, HelperErrorKind::NotFound);

        // UDP, blocked and remembered for this process.
        let server = udp_server();
        let target = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.send_to(b"one", target).unwrap();
        let record = next_record(&mut rx);
        assert_eq!(record.protocol, Protocol::Udp);
        assert_eq!(record.port, target.port());
        interceptor
            .verdict(1, record.request_id, Verdict::Block, Remember::Process)
            .unwrap();
        assert!(!received(&server), "blocked datagram is dropped");
        // Another socket of the same process: decided without a prompt. It
        // must outlive the lookup; a closed socket names no process.
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        other.send_to(b"two", target).unwrap();
        assert!(!received(&server), "remembered block applies");
        assert!(rx.try_recv().is_err(), "no prompt for a remembered target");

        // An executable rule decides without a prompt.
        let rule = FirewallRule {
            rule_id: 5,
            spec: omarchy_security_proto::types::FirewallRuleSpec {
                verdict: Verdict::Allow,
                direction: Direction::Outbound,
                address: "127.0.0.0/8".into(),
                port: None,
                protocol: Some(Protocol::Udp),
                executable: Some(exe.clone()),
            },
            loaded: false,
        };
        interceptor.set_rules(&[rule], uid).unwrap();
        let ruled = udp_server();
        client
            .send_to(b"three", ruled.local_addr().unwrap())
            .unwrap();
        assert!(received(&ruled), "executable rule allows");
        assert!(rx.try_recv().is_err(), "no prompt when a rule matches");
        interceptor.set_rules(&[], uid).unwrap();

        // Unanswered: the timeout verdict applies.
        interceptor.subscribe(1, uid, tx, Duration::from_secs(1), Verdict::Allow);
        let late = udp_server();
        late.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let sent = Instant::now();
        client.send_to(b"four", late.local_addr().unwrap()).unwrap();
        next_record(&mut rx);
        assert!(received(&late), "timeout verdict allows");
        assert!(sent.elapsed() >= Duration::from_millis(900));

        // Without a subscriber or rules the queue rule goes away.
        interceptor.disconnected(1);
        assert_eq!(interceptor.wanted_queue(), None);
        runtime
            .block_on(firewall.set_queue(|| queue(&interceptor)))
            .unwrap();
        interceptor.stop();
    }

    fn proc_same(pid: u32, start_time: u64) -> bool {
        Proc::default().is_same_process(pid, start_time)
    }
}
