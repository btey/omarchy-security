// SPDX-License-Identifier: GPL-3.0-or-later

//! Security token module (task 2.4, plan §2.2).
//!
//! **Detection.** Tokens are found in sysfs (`/sys/bus/usb/devices`). A
//! device counts as a token when its vendor is Yubico, Nitrokey, or
//! SoloKeys, when it has a FIDO HID interface (report descriptor usage page
//! `0xF1D0`), or when it has a CCID smartcard interface. Hotplug comes from
//! the kernel's uevent netlink socket, which needs no privileges. udev
//! itself is not needed: sysfs is complete when the kernel announces a
//! device. Without the socket the module polls sysfs and reports
//! `degraded`.
//!
//! **Touch prompts.** While a FIDO2 authenticator waits for user presence it
//! sends CTAPHID `KEEPALIVE` reports with status `UPNEEDED`. hidraw copies
//! every input report to every reader, so the module keeps a read-only
//! handle on each FIDO hidraw node and turns those reports into
//! `TOKEN_TOUCH_REQUESTED` / `TOKEN_TOUCH_COMPLETED`, without touching the
//! request itself. The same udev `uaccess` rule that lets the user's
//! browser or `ssh` open the key lets this daemon read it. An
//! `ssh-sk-helper` process of the user at that moment means the request
//! came from SSH.
//!
//! Touch prompts for OpenPGP cards (gpg-agent/scdaemon over PC/SC) are not
//! detected yet: they need hooks into scdaemon rather than a passive read.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use omarchy_security_proto::Event;
use omarchy_security_proto::events::{TokenRef, TouchCompleted, TouchRequest};
use omarchy_security_proto::methods::TokenList;
use omarchy_security_proto::procfs::Proc;
use omarchy_security_proto::types::{
    Module, ModuleState, SecurityToken, TokenCapability, TokenKind, TouchOutcome, TouchSource,
};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::hub::Hub;

/// How long hotplug waits for a burst of uevents to settle before rescanning.
const SETTLE: Duration = Duration::from_millis(300);
/// Rescan interval without the uevent socket.
const POLL: Duration = Duration::from_secs(3);
/// A touch request is over when keepalives stop for this long.
const KEEPALIVE_GAP: Duration = Duration::from_secs(3);

// ------------------------------------------------------------- detection

/// A token found in sysfs, with the hidraw nodes of its FIDO interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub token: SecurityToken,
    pub fido_hidraw: Vec<String>,
}

#[derive(Debug, Default)]
struct Interfaces {
    fido_hidraw: Vec<String>,
    fido: bool,
    ccid: bool,
    keyboard: bool,
}

fn read_attr(dir: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(dir.join(name))
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn is_fido_descriptor(descriptor: &[u8]) -> bool {
    // Usage Page (FIDO Alliance) = 0xF1D0, as a two-byte usage page item.
    descriptor.windows(3).any(|w| w == [0x06, 0xD0, 0xF1])
}

fn scan_interfaces(device: &Path, name: &str) -> Interfaces {
    let mut found = Interfaces::default();
    let Ok(entries) = std::fs::read_dir(device) else {
        return found;
    };
    let prefix = format!("{name}:");
    for entry in entries.flatten() {
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !file_name.starts_with(&prefix) {
            continue;
        }
        let intf = entry.path();
        let class = read_attr(&intf, "bInterfaceClass").unwrap_or_default();
        let subclass = read_attr(&intf, "bInterfaceSubClass").unwrap_or_default();
        let protocol = read_attr(&intf, "bInterfaceProtocol").unwrap_or_default();
        match class.as_str() {
            "0b" => found.ccid = true,
            "03" => {
                if subclass == "01" && protocol == "01" {
                    found.keyboard = true;
                }
                // HID devices sit in subdirectories named BUS:VID:PID.N.
                for hid in std::fs::read_dir(&intf).into_iter().flatten().flatten() {
                    let hid = hid.path();
                    let Ok(descriptor) = std::fs::read(hid.join("report_descriptor")) else {
                        continue;
                    };
                    if !is_fido_descriptor(&descriptor) {
                        continue;
                    }
                    found.fido = true;
                    for node in std::fs::read_dir(hid.join("hidraw"))
                        .into_iter()
                        .flatten()
                        .flatten()
                    {
                        found
                            .fido_hidraw
                            .push(node.file_name().to_string_lossy().into_owned());
                    }
                }
            }
            _ => {}
        }
    }
    found.fido_hidraw.sort();
    found
}

fn kind_of(vendor: &str, product: &str, intf: &Interfaces) -> Option<TokenKind> {
    match (vendor, product) {
        ("1050", _) => Some(TokenKind::Yubikey),
        ("20a0", _) => Some(TokenKind::Nitrokey),
        ("0483", "a2ca") | ("1209", "5070") | ("1209", "beee") => Some(TokenKind::Solokey),
        _ if intf.fido => Some(TokenKind::Fido2),
        _ if intf.ccid => Some(TokenKind::Smartcard),
        _ => None,
    }
}

/// Every token under `<sys>/bus/usb/devices`, ordered by id.
pub fn scan(sys: &Path) -> Vec<Found> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(sys.join("bus/usb/devices")) else {
        return found;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Interfaces contain ':'; root hubs are usbN.
        if name.contains(':') || name.starts_with("usb") {
            continue;
        }
        let dir = entry.path();
        let (Some(vendor), Some(product)) =
            (read_attr(&dir, "idVendor"), read_attr(&dir, "idProduct"))
        else {
            continue;
        };
        let (vendor, product) = (vendor.to_ascii_lowercase(), product.to_ascii_lowercase());
        let intf = scan_interfaces(&dir, &name);
        let Some(kind) = kind_of(&vendor, &product, &intf) else {
            continue;
        };
        let mut capabilities = Vec::new();
        if intf.fido {
            capabilities.push(TokenCapability::Fido2);
        }
        if intf.ccid {
            match kind {
                TokenKind::Yubikey => {
                    capabilities.extend([TokenCapability::Piv, TokenCapability::Openpgp])
                }
                TokenKind::Nitrokey => capabilities.push(TokenCapability::Openpgp),
                _ => {}
            }
        }
        if intf.keyboard && kind == TokenKind::Yubikey {
            capabilities.push(TokenCapability::Otp);
        }
        let devnum = read_attr(&dir, "devnum").unwrap_or_default();
        let label = read_attr(&dir, "product")
            .unwrap_or_else(|| format!("Security key {vendor}:{product}"));
        found.push(Found {
            token: SecurityToken {
                token_id: format!("usb-{name}-{devnum}"),
                kind,
                name: label,
                vendor_id: vendor,
                product_id: product,
                serial: read_attr(&dir, "serial"),
                capabilities,
            },
            fido_hidraw: intf.fido_hidraw,
        });
    }
    found.sort_by(|a, b| a.token.token_id.cmp(&b.token.token_id));
    found
}

// ---------------------------------------------------------------- CTAPHID

const CTAPHID_KEEPALIVE: u8 = 0x80 | 0x3B;
const CTAPHID_ERROR: u8 = 0x80 | 0x3F;
const CTAPHID_CBOR: u8 = 0x80 | 0x10;
const STATUS_UPNEEDED: u8 = 2;
const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;
const CTAP2_ERR_USER_ACTION_TIMEOUT: u8 = 0x2F;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchEdge {
    Started,
    Finished(TouchOutcome),
}

/// Follows the CTAPHID input reports of one authenticator and reports when
/// it starts and stops waiting for a touch. One channel (`cid`) per client.
#[derive(Debug, Default)]
pub struct TouchTracker {
    waiting: Option<u32>,
}

impl TouchTracker {
    pub fn on_report(&mut self, report: &[u8]) -> Option<TouchEdge> {
        if report.len() < 8 {
            return None;
        }
        let cid = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        let cmd = report[4];
        if cmd & 0x80 == 0 {
            return None; // continuation packet
        }
        let first = report[7];
        if cmd == CTAPHID_KEEPALIVE {
            if first == STATUS_UPNEEDED && self.waiting.is_none() {
                self.waiting = Some(cid);
                return Some(TouchEdge::Started);
            }
            return None;
        }
        if self.waiting != Some(cid) {
            return None;
        }
        self.waiting = None;
        let outcome = match (cmd, first) {
            (CTAPHID_ERROR, _) => TouchOutcome::Cancelled,
            (CTAPHID_CBOR, CTAP2_ERR_USER_ACTION_TIMEOUT) => TouchOutcome::TimedOut,
            (CTAPHID_CBOR, CTAP2_ERR_OPERATION_DENIED | CTAP2_ERR_KEEPALIVE_CANCEL) => {
                TouchOutcome::Cancelled
            }
            _ => TouchOutcome::Touched,
        };
        Some(TouchEdge::Finished(outcome))
    }

    /// Keepalives stopped without a reply: the client gave up.
    pub fn on_silence(&mut self) -> Option<TouchEdge> {
        self.waiting
            .take()
            .map(|_| TouchEdge::Finished(TouchOutcome::Cancelled))
    }

    pub fn is_waiting(&self) -> bool {
        self.waiting.is_some()
    }
}

// ----------------------------------------------------------------- module

#[derive(Debug, Clone)]
pub struct TokenEnv {
    pub sys: PathBuf,
    pub dev: PathBuf,
    pub proc: PathBuf,
}

impl Default for TokenEnv {
    fn default() -> Self {
        Self {
            sys: "/sys".into(),
            dev: "/dev".into(),
            proc: "/proc".into(),
        }
    }
}

struct Monitor {
    task: JoinHandle<()>,
}

impl Drop for Monitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct Tokens {
    hub: Arc<Hub>,
    env: TokenEnv,
    tokens: Mutex<BTreeMap<String, Found>>,
    /// Touch monitors by hidraw node.
    monitors: Mutex<HashMap<String, Monitor>>,
    /// hidraw nodes this user cannot read, for the module detail.
    blind: Mutex<Vec<String>>,
    hotplug: Mutex<bool>,
    next_request: AtomicU64,
}

impl Tokens {
    pub fn start(hub: Arc<Hub>, env: TokenEnv) -> Arc<Self> {
        let module = Arc::new(Self {
            hub,
            env,
            tokens: Mutex::new(BTreeMap::new()),
            monitors: Mutex::new(HashMap::new()),
            blind: Mutex::new(Vec::new()),
            hotplug: Mutex::new(false),
            next_request: AtomicU64::new(1),
        });
        let (rescan_tx, rescan_rx) = mpsc::channel(1);
        match uevent_socket() {
            Ok(socket) => {
                *module.hotplug.lock().expect("token lock") = true;
                tokio::spawn(watch_uevents(socket, rescan_tx));
            }
            Err(err) => {
                tracing::warn!("uevent socket unavailable, polling sysfs: {err}");
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(POLL).await;
                        if rescan_tx.send(()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        }
        module.rescan(false);
        tokio::spawn(module.clone().rescan_loop(rescan_rx));
        module
    }

    async fn rescan_loop(self: Arc<Self>, mut rescan: mpsc::Receiver<()>) {
        while rescan.recv().await.is_some() {
            tokio::time::sleep(SETTLE).await;
            while rescan.try_recv().is_ok() {}
            let module = self.clone();
            // sysfs reads are quick but blocking.
            let found = tokio::task::spawn_blocking({
                let sys = module.env.sys.clone();
                move || scan(&sys)
            })
            .await
            .unwrap_or_default();
            self.apply(found, true);
        }
    }

    fn rescan(self: &Arc<Self>, announce: bool) {
        let found = scan(&self.env.sys);
        self.apply(found, announce);
    }

    /// Diffs a scan against the known tokens, emitting inserted and removed
    /// events, and keeps one touch monitor per FIDO hidraw node.
    ///
    /// A token seen again with different details (its interfaces bind a
    /// moment after the device appears) is announced again with
    /// `TOKEN_INSERTED`, which clients treat as an update.
    fn apply(self: &Arc<Self>, found: Vec<Found>, announce: bool) {
        let mut inserted = Vec::new();
        let mut removed = Vec::new();
        let next: BTreeMap<String, Found> = found
            .into_iter()
            .map(|f| (f.token.token_id.clone(), f))
            .collect();
        {
            let mut tokens = self.tokens.lock().expect("token lock");
            for (id, old) in tokens.iter() {
                if !next.contains_key(id) {
                    removed.push(old.token.clone());
                }
            }
            for (id, new) in &next {
                if tokens.get(id).map(|old| &old.token) != Some(&new.token) {
                    inserted.push(new.token.clone());
                }
            }
            *tokens = next.clone();
        }

        // Monitors follow the hidraw nodes, not the events.
        let wanted: HashMap<&str, &SecurityToken> = next
            .values()
            .flat_map(|f| f.fido_hidraw.iter().map(move |n| (n.as_str(), &f.token)))
            .collect();
        self.monitors
            .lock()
            .expect("token lock")
            .retain(|node, _| wanted.contains_key(node.as_str()));
        self.blind
            .lock()
            .expect("token lock")
            .retain(|node| wanted.contains_key(node.as_str()));
        for (node, token) in wanted {
            if !self.monitors.lock().expect("token lock").contains_key(node) {
                self.spawn_monitor(node, token);
            }
        }

        for gone in removed {
            tracing::info!(token = %gone.token_id, name = %gone.name, "token removed");
            if announce {
                self.hub.emit(Event::TokenRemoved(TokenRef {
                    token_id: gone.token_id,
                }));
            }
        }
        for new in inserted {
            tracing::info!(token = %new.token_id, name = %new.name, kind = ?new.kind, "token inserted");
            if announce {
                self.hub.emit(Event::TokenInserted(new));
            }
        }
        self.update_status();
    }

    fn update_status(&self) {
        let mut problems = Vec::new();
        if !*self.hotplug.lock().expect("token lock") {
            problems.push("no uevent socket: polling sysfs".to_owned());
        }
        let blind = self.blind.lock().expect("token lock").clone();
        if !blind.is_empty() {
            problems.push(format!(
                "cannot read {}: touch prompts unavailable for it",
                blind.join(", ")
            ));
        }
        if problems.is_empty() {
            self.hub
                .set_status(Module::Token, ModuleState::Active, None);
        } else {
            self.hub.set_status(
                Module::Token,
                ModuleState::Degraded,
                Some(problems.join("; ")),
            );
        }
    }

    fn spawn_monitor(self: &Arc<Self>, node: &str, token: &SecurityToken) {
        let path = self.env.dev.join(node);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
            .open(&path);
        let fd = match file.and_then(AsyncFd::new) {
            Ok(fd) => fd,
            Err(err) => {
                tracing::warn!("touch monitor for {}: {err}", path.display());
                let mut blind = self.blind.lock().expect("token lock");
                if !blind.iter().any(|n| n == node) {
                    blind.push(node.to_owned());
                }
                return;
            }
        };
        self.blind.lock().expect("token lock").retain(|n| n != node);
        let module = self.clone();
        let token = token.clone();
        let node_name = node.to_owned();
        let task = tokio::spawn(async move {
            module.monitor(fd, token).await;
            tracing::debug!(node = %node_name, "touch monitor stopped");
        });
        self.monitors
            .lock()
            .expect("token lock")
            .insert(node.to_owned(), Monitor { task });
    }

    async fn monitor(&self, fd: AsyncFd<File>, token: SecurityToken) {
        let mut tracker = TouchTracker::default();
        let mut request_id = 0;
        let mut report = [0u8; 64];
        loop {
            let readable = if tracker.is_waiting() {
                tokio::time::timeout(KEEPALIVE_GAP, fd.readable())
                    .await
                    .ok()
            } else {
                Some(fd.readable().await)
            };
            let edge = match readable {
                None => tracker.on_silence(),
                Some(Err(_)) => return,
                Some(Ok(mut guard)) => {
                    match guard.try_io(|inner| inner.get_ref().read(&mut report)) {
                        Ok(Ok(0)) | Ok(Err(_)) => return, // unplugged
                        Ok(Ok(n)) => tracker.on_report(&report[..n]),
                        Err(_would_block) => continue,
                    }
                }
            };
            match edge {
                Some(TouchEdge::Started) => {
                    request_id = self.next_request.fetch_add(1, Ordering::Relaxed);
                    let (source, description) = self.describe(&token);
                    tracing::info!(request_id, token = %token.token_id, ?source, "touch requested");
                    self.hub.emit(Event::TokenTouchRequested(TouchRequest {
                        request_id,
                        token_id: Some(token.token_id.clone()),
                        source,
                        description,
                    }));
                }
                Some(TouchEdge::Finished(outcome)) => {
                    tracing::info!(request_id, ?outcome, "touch completed");
                    self.hub.emit(Event::TokenTouchCompleted(TouchCompleted {
                        request_id,
                        outcome,
                    }));
                }
                None => {}
            }
        }
    }

    /// Guesses who is asking: SSH runs `ssh-sk-helper` for security keys.
    fn describe(&self, token: &SecurityToken) -> (TouchSource, String) {
        let proc = Proc::new(&self.env.proc);
        let uid = nix::unistd::getuid().as_raw();
        let ssh = proc.pids().unwrap_or_default().into_iter().any(|pid| {
            proc.uid(pid).is_ok_and(|u| u == uid)
                && proc.comm(pid).is_ok_and(|c| c == "ssh-sk-helper")
        });
        if ssh {
            (
                TouchSource::Ssh,
                format!("SSH is waiting for a touch on {}", token.name),
            )
        } else {
            (
                TouchSource::Fido2,
                format!("{} is waiting for a touch", token.name),
            )
        }
    }

    pub fn list(&self) -> TokenList {
        TokenList {
            tokens: self
                .tokens
                .lock()
                .expect("token lock")
                .values()
                .map(|f| f.token.clone())
                .collect(),
        }
    }
}

fn uevent_socket() -> std::io::Result<AsyncFd<OwnedFd>> {
    use nix::sys::socket::{
        AddressFamily, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, socket,
    };
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Datagram,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::NetlinkKObjectUEvent,
    )?;
    // Group 1: kernel uevents.
    bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 1))?;
    AsyncFd::new(fd)
}

/// True for uevents that can change the token list.
fn relevant_uevent(message: &[u8]) -> bool {
    message
        .split(|&b| b == 0)
        .any(|field| field == b"SUBSYSTEM=usb" || field == b"SUBSYSTEM=hidraw")
}

async fn watch_uevents(socket: AsyncFd<OwnedFd>, rescan: mpsc::Sender<()>) {
    let mut buf = vec![0u8; 8192];
    loop {
        let Ok(mut guard) = socket.readable().await else {
            return;
        };
        let received = guard.try_io(|fd| {
            nix::sys::socket::recv(
                fd.as_raw_fd(),
                &mut buf,
                nix::sys::socket::MsgFlags::empty(),
            )
            .map_err(std::io::Error::from)
        });
        match received {
            Ok(Ok(n)) if relevant_uevent(&buf[..n]) => {
                // A full channel already holds a pending rescan.
                let _ = rescan.try_send(());
            }
            Ok(Ok(_)) => {}
            Ok(Err(err)) => tracing::debug!("uevent recv: {err}"),
            Err(_would_block) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const FIDO_DESCRIPTOR: [u8; 8] = [0x06, 0xD0, 0xF1, 0x09, 0x01, 0xA1, 0x01, 0xC0];

    struct SysFixture {
        dir: tempfile::TempDir,
    }

    impl SysFixture {
        fn new() -> Self {
            let f = Self {
                dir: tempfile::tempdir().unwrap(),
            };
            fs::create_dir_all(f.devices()).unwrap();
            f
        }

        fn devices(&self) -> PathBuf {
            self.dir.path().join("bus/usb/devices")
        }

        fn device(&self, name: &str, vid: &str, pid: &str, product: Option<&str>) {
            let d = self.devices().join(name);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("idVendor"), format!("{vid}\n")).unwrap();
            fs::write(d.join("idProduct"), format!("{pid}\n")).unwrap();
            fs::write(d.join("devnum"), "7\n").unwrap();
            if let Some(product) = product {
                fs::write(d.join("product"), format!("{product}\n")).unwrap();
            }
        }

        fn interface(
            &self,
            dev: &str,
            n: u8,
            class: &str,
            sub: &str,
            proto: &str,
            hid: Option<(&[u8], &str)>,
        ) {
            let i = self.devices().join(dev).join(format!("{dev}:1.{n}"));
            fs::create_dir_all(&i).unwrap();
            fs::write(i.join("bInterfaceClass"), format!("{class}\n")).unwrap();
            fs::write(i.join("bInterfaceSubClass"), format!("{sub}\n")).unwrap();
            fs::write(i.join("bInterfaceProtocol"), format!("{proto}\n")).unwrap();
            if let Some((descriptor, hidraw)) = hid {
                let h = i.join("0003:1050:0407.0001");
                fs::create_dir_all(h.join("hidraw").join(hidraw)).unwrap();
                fs::write(h.join("report_descriptor"), descriptor).unwrap();
            }
        }
    }

    #[test]
    fn finds_a_yubikey_with_all_capabilities() {
        let f = SysFixture::new();
        f.device("1-2", "1050", "0407", Some("YubiKey OTP+FIDO+CCID"));
        f.interface(
            "1-2",
            0,
            "03",
            "01",
            "01",
            Some((&[0x05, 0x01, 0x09, 0x06], "hidraw4")),
        );
        f.interface(
            "1-2",
            1,
            "03",
            "00",
            "00",
            Some((&FIDO_DESCRIPTOR, "hidraw5")),
        );
        f.interface("1-2", 2, "0b", "00", "00", None);
        // Not tokens: a webcam and the root hub.
        f.device("1-5", "04f2", "b604", Some("Integrated Camera"));
        f.interface("1-5", 0, "0e", "01", "00", None);
        f.device("usb1", "1d6b", "0002", None);

        let found = scan(f.dir.path());
        assert_eq!(found.len(), 1);
        let yk = &found[0];
        assert_eq!(yk.fido_hidraw, ["hidraw5"]);
        assert_eq!(
            yk.token,
            SecurityToken {
                token_id: "usb-1-2-7".into(),
                kind: TokenKind::Yubikey,
                name: "YubiKey OTP+FIDO+CCID".into(),
                vendor_id: "1050".into(),
                product_id: "0407".into(),
                serial: None,
                capabilities: vec![
                    TokenCapability::Fido2,
                    TokenCapability::Piv,
                    TokenCapability::Openpgp,
                    TokenCapability::Otp
                ],
            }
        );
    }

    #[test]
    fn classifies_generic_fido_and_smartcards() {
        let f = SysFixture::new();
        f.device("3-1", "096e", "0858", None);
        f.interface(
            "3-1",
            0,
            "03",
            "00",
            "00",
            Some((&FIDO_DESCRIPTOR, "hidraw1")),
        );
        f.device("3-2", "076b", "3031", Some("OMNIKEY"));
        f.interface("3-2", 0, "0b", "00", "00", None);
        let kinds: Vec<_> = scan(f.dir.path())
            .into_iter()
            .map(|t| (t.token.kind, t.token.name))
            .collect();
        assert_eq!(
            kinds,
            [
                (TokenKind::Fido2, "Security key 096e:0858".to_owned()),
                (TokenKind::Smartcard, "OMNIKEY".to_owned())
            ]
        );
    }

    fn report(cid: u32, cmd: u8, first: u8) -> [u8; 64] {
        let mut r = [0u8; 64];
        r[..4].copy_from_slice(&cid.to_be_bytes());
        r[4] = cmd;
        r[6] = 1;
        r[7] = first;
        r
    }

    #[test]
    fn tracks_keepalive_upneeded() {
        let mut t = TouchTracker::default();
        assert_eq!(t.on_report(&report(9, CTAPHID_KEEPALIVE, 1)), None); // processing
        assert_eq!(
            t.on_report(&report(9, CTAPHID_KEEPALIVE, STATUS_UPNEEDED)),
            Some(TouchEdge::Started)
        );
        assert_eq!(
            t.on_report(&report(9, CTAPHID_KEEPALIVE, STATUS_UPNEEDED)),
            None
        );
        assert_eq!(
            t.on_report(&report(4, CTAPHID_CBOR, 0)),
            None,
            "other channel"
        );
        assert_eq!(
            t.on_report(&[0, 0, 0, 9, 0x05, 0, 0, 0]),
            None,
            "continuation"
        );
        assert_eq!(
            t.on_report(&report(9, CTAPHID_CBOR, 0)),
            Some(TouchEdge::Finished(TouchOutcome::Touched))
        );

        t.on_report(&report(9, CTAPHID_KEEPALIVE, STATUS_UPNEEDED));
        assert_eq!(
            t.on_report(&report(9, CTAPHID_CBOR, CTAP2_ERR_USER_ACTION_TIMEOUT)),
            Some(TouchEdge::Finished(TouchOutcome::TimedOut))
        );
        t.on_report(&report(9, CTAPHID_KEEPALIVE, STATUS_UPNEEDED));
        assert_eq!(
            t.on_report(&report(9, CTAPHID_CBOR, CTAP2_ERR_KEEPALIVE_CANCEL)),
            Some(TouchEdge::Finished(TouchOutcome::Cancelled))
        );
        t.on_report(&report(9, CTAPHID_KEEPALIVE, STATUS_UPNEEDED));
        assert_eq!(
            t.on_silence(),
            Some(TouchEdge::Finished(TouchOutcome::Cancelled))
        );
        assert_eq!(t.on_silence(), None);
    }

    #[test]
    fn filters_uevents() {
        assert!(relevant_uevent(
            b"add@/devices/pci/usb1/1-2\0ACTION=add\0SUBSYSTEM=usb\0"
        ));
        assert!(!relevant_uevent(
            b"change@/devices/virtual/net/lo\0SUBSYSTEM=net\0"
        ));
    }

    async fn next(rx: &mut tokio::sync::broadcast::Receiver<Event>) -> Event {
        loop {
            match tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .unwrap()
                .unwrap()
            {
                Event::ModuleStateChanged(_) => continue,
                other => return other,
            }
        }
    }

    #[tokio::test]
    async fn hotplug_and_touch_prompt() {
        let f = SysFixture::new();
        let dev = tempfile::tempdir().unwrap();
        let hub = Arc::new(Hub::new());
        let mut events = hub.subscribe();
        let env = TokenEnv {
            sys: f.dir.path().to_owned(),
            dev: dev.path().to_owned(),
            proc: "/proc".into(),
        };
        let module = Tokens::start(hub.clone(), env);
        assert!(module.list().tokens.is_empty());

        // A FIFO stands in for /dev/hidraw5: the test writes reports into it.
        f.device("1-2", "1050", "0402", Some("YubiKey FIDO"));
        f.interface(
            "1-2",
            0,
            "03",
            "00",
            "00",
            Some((&FIDO_DESCRIPTOR, "hidraw5")),
        );
        let fifo = dev.path().join("hidraw5");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let mut writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .unwrap();
        module.rescan(true);

        match next(&mut events).await {
            Event::TokenInserted(t) => assert_eq!(t.token_id, "usb-1-2-7"),
            other => panic!("unexpected {other:?}"),
        }

        // The CCID interface binds later: the token is announced again
        // with its new capabilities, and its touch monitor is kept.
        let monitor_task = module.monitors.lock().unwrap()["hidraw5"].task.id();
        f.interface("1-2", 1, "0b", "00", "00", None);
        module.rescan(true);
        match next(&mut events).await {
            Event::TokenInserted(t) => assert!(t.capabilities.contains(&TokenCapability::Piv)),
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            module.monitors.lock().unwrap()["hidraw5"].task.id(),
            monitor_task
        );
        module.rescan(true); // unchanged: silent

        use std::io::Write;
        writer
            .write_all(&report(1, CTAPHID_KEEPALIVE, STATUS_UPNEEDED))
            .unwrap();
        let request_id = match next(&mut events).await {
            Event::TokenTouchRequested(r) => {
                assert_eq!(r.token_id.as_deref(), Some("usb-1-2-7"));
                r.request_id
            }
            other => panic!("unexpected {other:?}"),
        };
        writer.write_all(&report(1, CTAPHID_CBOR, 0)).unwrap();
        assert_eq!(
            next(&mut events).await,
            Event::TokenTouchCompleted(TouchCompleted {
                request_id,
                outcome: TouchOutcome::Touched
            })
        );

        fs::remove_dir_all(f.devices().join("1-2")).unwrap();
        module.rescan(true);
        assert_eq!(
            next(&mut events).await,
            Event::TokenRemoved(TokenRef {
                token_id: "usb-1-2-7".into()
            })
        );
        assert!(module.monitors.lock().unwrap().is_empty());
    }
}
