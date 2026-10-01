// SPDX-License-Identifier: GPL-3.0-or-later

//! Encrypted vault module (task 2.11, plan §2.2 and §5.5): mounts and
//! unmounts the vaults defined in the configuration (`[[vault]]`,
//! `docs/configuration.md`).
//!
//! It runs entirely as the desktop user. gocryptfs vaults are mounted with
//! `gocryptfs` and unmounted with `fusermount3`; LUKS vaults go through
//! udisks2 (`udisks.rs`). The passphrase comes from pinentry, is written
//! only to gocryptfs's stdin or into the udisks2 call, and never crosses
//! the client socket.
//!
//! `mounted` is derived from the system, never remembered: gocryptfs vaults
//! from `/proc/self/mountinfo`, LUKS vaults from udisks2. Both are checked
//! again whenever mountinfo changes, so a vault unmounted outside the hub
//! still produces `VAULT_STATE_CHANGED`.
//!
//! Panic mode (`VAULT_PANIC`, task 2.12, plan §5.6) stops the processes
//! holding the mounted vaults (`holders.rs`), then flushes, unmounts and
//! locks every vault. It never prompts, and closes any passphrase prompt
//! that is open.
//!
//! `VAULT_ADD` and `VAULT_REMOVE` edit the `[[vault]]` tables of the
//! configuration file (`config.rs`). `VAULT_CREATE` first makes a new
//! gocryptfs cipher directory with `gocryptfs -init`, asking for the new
//! passphrase twice through pinentry. A vault that leaves the configuration
//! produces `VAULT_REMOVED`, whether the hub removed it or the file was
//! edited and reloaded.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use omarchy_security_proto::events::VaultRef;
use omarchy_security_proto::methods::{
    Empty, PanicFailure, PanicResult, VaultAddParams, VaultCreateParams, VaultList, VaultTarget,
};
use omarchy_security_proto::types::{Module, ModuleState, Vault, VaultBackend};
use omarchy_security_proto::{ErrorCode, Event, RpcError};
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use zeroize::Zeroizing;

use crate::config::{Config, EditError, NewVault, Settings, VaultConfig};
use crate::holders::{self, Holder};
use crate::hub::Hub;
use crate::pinentry::{self, PinError, Prompt, Repeat};
use crate::sandbox::find_in_path;
use crate::udisks::{self, Luks, Source};

/// gocryptfs's exit code for a wrong password.
const GOCRYPTFS_BAD_PASSWORD: i32 = 12;
const MAX_ATTEMPTS: usize = 3;
const MOUNT_TIMEOUT: Duration = Duration::from_secs(60);
/// udisks2 probes a new loop device before it has an `Encrypted` interface.
const PROBE_WAIT: Duration = Duration::from_secs(5);
/// How long panic mode gives a process between `SIGTERM` and `SIGKILL`.
const PANIC_GRACE: Duration = Duration::from_secs(2);
/// How long panic mode waits for a mount or unmount in progress, and for
/// each flush, before going ahead without it.
const PANIC_WAIT: Duration = Duration::from_secs(2);
const PANIC_SYNC_WAIT: Duration = Duration::from_secs(10);
const PROC: &str = "/proc";

/// The programs and files the module uses.
#[derive(Debug, Clone)]
pub struct VaultEnv {
    pub mountinfo: PathBuf,
    pub gocryptfs: Option<PathBuf>,
    pub fusermount: Option<PathBuf>,
    /// The pinentry command line: program, then arguments.
    pub pinentry: Vec<OsString>,
    /// `systemd-run`, when this daemon runs as a systemd service. gocryptfs
    /// then runs in its own scope, so that a daemon restart, which stops
    /// every process in its cgroup, does not kill the mounted vaults.
    pub systemd_run: Option<PathBuf>,
}

impl VaultEnv {
    pub fn host() -> Self {
        Self {
            mountinfo: "/proc/self/mountinfo".into(),
            gocryptfs: find_in_path("gocryptfs"),
            fusermount: find_in_path("fusermount3"),
            pinentry: vec![
                find_in_path("pinentry")
                    .map(PathBuf::into_os_string)
                    .unwrap_or_else(|| "pinentry".into()),
            ],
            systemd_run: std::env::var_os("INVOCATION_ID")
                .and_then(|_| find_in_path("systemd-run")),
        }
    }
}

pub struct Vaults {
    hub: Arc<Hub>,
    env: VaultEnv,
    settings: Arc<Settings>,
    bus: Option<zbus::Connection>,
    udisks: Mutex<bool>,
    /// The last reported state, in configuration order.
    state: Mutex<Vec<Vault>>,
    /// Serializes refreshes, so an older snapshot never overwrites a newer
    /// one.
    refreshing: tokio::sync::Mutex<()>,
    /// Serializes mounts and unmounts.
    ops: tokio::sync::Mutex<()>,
    /// Counts panics, so a mount whose prompt was open when one ran fails.
    panics: AtomicU64,
    /// Wakes open passphrase prompts when panic mode runs, to close them.
    panicked: tokio::sync::Notify,
}

fn not_found(id: &str) -> RpcError {
    RpcError::new(ErrorCode::NotFound, format!("no vault with id '{id}'"))
}

fn backend_error(message: String) -> RpcError {
    RpcError::new(ErrorCode::BackendError, message.clone()).with_data(json!({ "detail": message }))
}

fn udisks_error(what: &str, err: zbus::Error) -> RpcError {
    let text = err.to_string();
    let code = match &err {
        zbus::Error::MethodError(name, _, _) if name.contains("NotAuthorized") => {
            ErrorCode::PermissionDenied
        }
        zbus::Error::MethodError(name, _, _) if name.contains("ServiceUnknown") => {
            ErrorCode::ModuleUnavailable
        }
        _ => ErrorCode::BackendError,
    };
    RpcError::new(code, format!("udisks2: {what}: {text}")).with_data(json!({ "detail": text }))
}

fn cancelled_by_panic() -> RpcError {
    RpcError::new(
        ErrorCode::Cancelled,
        "panic mode ran while the passphrase was asked for",
    )
}

fn edit_error(err: EditError) -> RpcError {
    match err {
        EditError::Rejected(message) => RpcError::invalid_params(message),
        EditError::NotFound(message) => RpcError::new(ErrorCode::NotFound, message),
        EditError::Failed(message) => backend_error(message),
    }
}

fn pin_error(err: PinError) -> RpcError {
    match err {
        PinError::Cancelled => {
            RpcError::new(ErrorCode::Cancelled, "passphrase prompt was cancelled")
        }
        PinError::Failed(message) => backend_error(format!("asking for the passphrase: {message}")),
    }
}

impl Vaults {
    /// `bus` is the system bus, for udisks2; without it LUKS vaults are
    /// unavailable.
    pub fn start(
        hub: Arc<Hub>,
        settings: Arc<Settings>,
        bus: Option<zbus::Connection>,
        env: VaultEnv,
    ) -> Arc<Self> {
        let module = Arc::new(Self {
            hub,
            env,
            settings,
            bus,
            udisks: Mutex::new(false),
            state: Mutex::new(Vec::new()),
            refreshing: tokio::sync::Mutex::new(()),
            ops: tokio::sync::Mutex::new(()),
            panics: AtomicU64::new(0),
            panicked: tokio::sync::Notify::new(),
        });
        tokio::spawn(module.clone().run());
        module
    }

    async fn run(self: Arc<Self>) {
        let mut config = self.settings.subscribe();
        let watch = match MountWatch::open(&self.env.mountinfo) {
            Ok(watch) => Some(watch),
            Err(err) => {
                tracing::warn!(
                    "cannot watch {}: {err}; vaults unmounted outside the hub go unnoticed",
                    self.env.mountinfo.display()
                );
                None
            }
        };
        config.mark_changed();
        loop {
            tokio::select! {
                changed = config.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    self.reconfigure().await;
                }
                result = async {
                    match &watch {
                        Some(watch) => watch.changed().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Err(err) = result {
                        tracing::warn!("watching mountinfo: {err}");
                        return;
                    }
                    // A mount usually comes in a burst of changes.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    self.refresh().await;
                }
            }
        }
    }

    async fn reconfigure(&self) {
        let config = self.settings.current();
        let udisks = match &self.bus {
            Some(bus) if needs(&config, VaultBackend::Luks) => udisks::available(bus).await,
            _ => false,
        };
        *self.udisks.lock().expect("vault lock") = udisks;
        let (state, detail) = self.status(&config);
        self.hub.set_status(Module::Vault, state, detail);
        self.refresh().await;
    }

    /// Why `backend` cannot be used, if it cannot.
    fn missing(&self, backend: VaultBackend) -> Option<&'static str> {
        match backend {
            VaultBackend::Gocryptfs if self.env.gocryptfs.is_none() => {
                Some("gocryptfs is not installed")
            }
            VaultBackend::Gocryptfs if self.env.fusermount.is_none() => {
                Some("fusermount3 (fuse3) is not installed")
            }
            VaultBackend::Luks if self.bus.is_none() => Some("the system bus is unavailable"),
            VaultBackend::Luks if !*self.udisks.lock().expect("vault lock") => {
                Some("udisks2 is not available on the system bus")
            }
            _ => None,
        }
    }

    fn status(&self, config: &Config) -> (ModuleState, Option<String>) {
        if config.vaults.is_empty() {
            return (ModuleState::Active, Some("no vaults configured".into()));
        }
        let backends: BTreeSet<_> = config
            .vaults
            .iter()
            .map(|v| backend_name(v.backend))
            .collect();
        let missing: Vec<_> = [VaultBackend::Gocryptfs, VaultBackend::Luks]
            .into_iter()
            .filter(|b| backends.contains(backend_name(*b)))
            .filter_map(|b| self.missing(b))
            .collect();
        if missing.is_empty() {
            (ModuleState::Active, None)
        } else if missing.len() == backends.len() {
            (ModuleState::Unavailable, Some(missing.join("; ")))
        } else {
            (ModuleState::Degraded, Some(missing.join("; ")))
        }
    }

    pub fn list(&self) -> VaultList {
        VaultList {
            vaults: self.state.lock().expect("vault lock").clone(),
        }
    }

    /// Reads every vault's state again and emits `VAULT_STATE_CHANGED` for
    /// each one that differs from what was last reported.
    pub async fn refresh(&self) {
        let _guard = self.refreshing.lock().await;
        let config = self.settings.current();
        let mounts = match std::fs::read_to_string(&self.env.mountinfo) {
            Ok(text) => parse_mountinfo(&text),
            Err(err) => {
                tracing::warn!("reading {}: {err}", self.env.mountinfo.display());
                Vec::new()
            }
        };
        let blocks = match &self.bus {
            Some(bus) if needs(&config, VaultBackend::Luks) => match udisks::blocks(bus).await {
                Ok(blocks) => Some(blocks),
                Err(err) => {
                    tracing::debug!("listing udisks2 devices: {err}");
                    None
                }
            },
            _ => None,
        };
        let new: Vec<Vault> = config
            .vaults
            .iter()
            .map(|vault| observe(vault, &mounts, blocks.as_deref()))
            .collect();
        let (changed, removed): (Vec<Vault>, Vec<String>) = {
            let mut state = self.state.lock().expect("vault lock");
            let changed = new.iter().filter(|v| !state.contains(v)).cloned().collect();
            let removed = state
                .iter()
                .filter(|old| !new.iter().any(|v| v.vault_id == old.vault_id))
                .map(|old| old.vault_id.clone())
                .collect();
            *state = new;
            (changed, removed)
        };
        for vault_id in removed {
            tracing::info!(vault = %vault_id, "vault removed from the configuration");
            self.hub.emit(Event::VaultRemoved(VaultRef { vault_id }));
        }
        for vault in changed {
            tracing::info!(vault = %vault.vault_id, mounted = vault.mounted, mount_point = %vault.mount_point, "vault state");
            self.hub.emit(Event::VaultStateChanged(vault));
        }
    }

    fn get(&self, id: &str) -> Result<Vault, RpcError> {
        self.state
            .lock()
            .expect("vault lock")
            .iter()
            .find(|v| v.vault_id == id)
            .cloned()
            .ok_or_else(|| not_found(id))
    }

    fn lookup(&self, id: &str) -> Result<VaultConfig, RpcError> {
        let vault = self
            .settings
            .current()
            .vaults
            .iter()
            .find(|v| v.id == id)
            .cloned()
            .ok_or_else(|| not_found(id))?;
        if let Some(reason) = self.missing(vault.backend) {
            return Err(RpcError::new(
                ErrorCode::ModuleUnavailable,
                format!("vault '{id}': {reason}"),
            )
            .with_data(json!({ "module": "vault" })));
        }
        Ok(vault)
    }

    pub async fn mount(&self, target: VaultTarget) -> Result<Vault, RpcError> {
        let vault = self.lookup(&target.vault_id)?;
        let _op = self.ops.lock().await;
        self.refresh().await;
        if self.get(&vault.id)?.mounted {
            return self.get(&vault.id);
        }
        let result = match vault.backend {
            VaultBackend::Gocryptfs => self.mount_gocryptfs(&vault).await,
            VaultBackend::Luks => self.mount_luks(&vault).await,
        };
        self.refresh().await;
        result?;
        tracing::info!(vault = %vault.id, "vault mounted");
        self.get(&vault.id)
    }

    pub async fn unmount(&self, target: VaultTarget) -> Result<Vault, RpcError> {
        let vault = self.lookup(&target.vault_id)?;
        let _op = self.ops.lock().await;
        let result = match vault.backend {
            VaultBackend::Gocryptfs => self.unmount_gocryptfs(&vault).await,
            VaultBackend::Luks => self.unmount_luks(&vault).await,
        };
        self.refresh().await;
        result?;
        tracing::info!(vault = %vault.id, "vault unmounted");
        self.get(&vault.id)
    }

    /// Appends a vault to the configuration file. The source must exist,
    /// so that a typo is caught now rather than at the first mount.
    pub async fn add(&self, params: VaultAddParams) -> Result<Vault, RpcError> {
        let id = params.vault_id.clone();
        let source = self
            .settings
            .expand(&params.source)
            .map_err(|e| RpcError::invalid_params(format!("vault '{id}': source {e}")))?;
        match params.backend {
            VaultBackend::Gocryptfs if !source.is_dir() => {
                return Err(RpcError::invalid_params(format!(
                    "vault '{id}': {} is not a directory",
                    source.display()
                )));
            }
            VaultBackend::Gocryptfs if !source.join("gocryptfs.conf").is_file() => {
                return Err(RpcError::invalid_params(format!(
                    "vault '{id}': {} is not a gocryptfs directory; create it with gocryptfs -init",
                    source.display()
                )));
            }
            // A block device may be unplugged for now.
            VaultBackend::Luks if !source.starts_with("/dev") && !source.exists() => {
                return Err(RpcError::invalid_params(format!(
                    "vault '{id}': {} does not exist",
                    source.display()
                )));
            }
            _ => {}
        }
        self.settings
            .add_vault(&NewVault {
                id: id.clone(),
                name: params.name,
                backend: params.backend,
                source: params.source,
                mount_point: params.mount_point,
            })
            .map_err(edit_error)?;
        tracing::info!(vault = %id, "vault added to the configuration");
        self.reconfigure().await;
        self.get(&id)
    }

    /// Removes a vault from the configuration file. Its files are kept. A
    /// mounted vault, or one being mounted or unmounted, is refused.
    pub async fn remove(&self, target: VaultTarget) -> Result<Empty, RpcError> {
        let id = &target.vault_id;
        let Ok(_op) = self.ops.try_lock() else {
            return Err(backend_error(
                "a vault is being mounted or unmounted; try again when it is done".into(),
            ));
        };
        self.refresh().await;
        if self.get(id)?.mounted {
            return Err(backend_error(format!(
                "vault '{id}' is mounted; unmount it first"
            )));
        }
        self.settings.remove_vault(id).map_err(edit_error)?;
        self.reconfigure().await;
        Ok(Empty {})
    }

    async fn ask(
        &self,
        vault: &VaultConfig,
        attempt: usize,
    ) -> Result<Zeroizing<String>, RpcError> {
        let description = format!("Enter the passphrase to unlock the vault “{}”.", vault.name);
        let prompt = Prompt {
            title: "Omarchy Security",
            description: &description,
            prompt: "Passphrase:",
            error: (attempt > 0).then_some("Wrong passphrase, try again."),
            repeat: None,
        };
        self.prompt(&prompt).await.map(|(pin, _)| pin)
    }

    /// Asks for the passphrase of a new vault, typed twice. pinentry
    /// checks the two itself when it can (`SETREPEAT`); otherwise a second
    /// prompt asks again.
    async fn ask_new(&self, name: &str) -> Result<Zeroizing<String>, RpcError> {
        let description = format!(
            "Choose a passphrase for the new vault “{name}”. Without it, its files cannot be recovered."
        );
        let again = format!("Enter the passphrase for the new vault “{name}” again.");
        let mut error = None;
        for _ in 0..MAX_ATTEMPTS {
            let prompt = Prompt {
                title: "Omarchy Security",
                description: &description,
                prompt: "Passphrase:",
                error,
                repeat: Some(Repeat {
                    prompt: "Repeat:",
                    mismatch: "The passphrases do not match.",
                }),
            };
            let (pin, repeated) = self.prompt(&prompt).await?;
            if pin.is_empty() {
                error = Some("The passphrase cannot be empty.");
                continue;
            }
            if pin.contains(['\n', '\0']) {
                error = Some("The passphrase cannot contain a line break.");
                continue;
            }
            if repeated {
                return Ok(pin);
            }
            let confirm = Prompt {
                title: "Omarchy Security",
                description: &again,
                prompt: "Repeat:",
                error: None,
                repeat: None,
            };
            let (repeat, _) = self.prompt(&confirm).await?;
            if *repeat == *pin {
                return Ok(pin);
            }
            error = Some("The passphrases did not match, try again.");
        }
        Err(RpcError::invalid_params(
            "no usable passphrase after three tries",
        ))
    }

    /// Runs one pinentry prompt, which panic mode closes.
    async fn prompt(&self, prompt: &Prompt<'_>) -> Result<(Zeroizing<String>, bool), RpcError> {
        let panics = self.panics.load(Ordering::SeqCst);
        let panicked = self.panicked.notified();
        // Dropping the prompt's future kills pinentry.
        let pin = tokio::select! {
            pin = pinentry::get_pin_repeated(&self.env.pinentry, prompt) => pin.map_err(pin_error)?,
            () = panicked => return Err(cancelled_by_panic()),
        };
        if self.panics.load(Ordering::SeqCst) != panics {
            return Err(cancelled_by_panic());
        }
        Ok(pin)
    }

    /// Creates an empty gocryptfs vault at `source` with a new passphrase,
    /// then adds it to the configuration file. Everything is checked
    /// before the passphrase is asked for; if the configuration cannot be
    /// written in the end, the files `gocryptfs -init` made are removed.
    pub async fn create(&self, params: VaultCreateParams) -> Result<Vault, RpcError> {
        let id = params.vault_id.clone();
        let Some(gocryptfs) = self.env.gocryptfs.clone() else {
            return Err(RpcError::new(
                ErrorCode::ModuleUnavailable,
                format!("vault '{id}': gocryptfs is not installed"),
            )
            .with_data(json!({ "module": "vault" })));
        };
        let vault = NewVault {
            id: id.clone(),
            name: params.name.clone(),
            backend: VaultBackend::Gocryptfs,
            source: params.source.clone(),
            mount_point: Some(params.mount_point.clone()),
        };
        self.settings.check_vault(&vault).map_err(edit_error)?;
        let source = self
            .settings
            .expand(&params.source)
            .map_err(|e| RpcError::invalid_params(format!("vault '{id}': source {e}")))?;
        let make_dir = match std::fs::read_dir(&source) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    return Err(RpcError::invalid_params(format!(
                        "vault '{id}': {} is not empty; to use a vault that is already there, add it instead",
                        source.display()
                    )));
                }
                false
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
            Err(err) if err.kind() == std::io::ErrorKind::NotADirectory => {
                return Err(RpcError::invalid_params(format!(
                    "vault '{id}': {} is not a directory",
                    source.display()
                )));
            }
            Err(err) => return Err(backend_error(format!("{}: {err}", source.display()))),
        };

        let pin = self.ask_new(&params.name).await?;
        if make_dir {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&source)
                .map_err(|e| backend_error(format!("creating {}: {e}", source.display())))?;
        }
        let initialized = init_gocryptfs(&gocryptfs, &source, &pin).await;
        drop(pin);
        if let Err(err) = initialized {
            if make_dir {
                // Only if gocryptfs left it empty.
                let _ = std::fs::remove_dir(&source);
            }
            return Err(err);
        }
        if let Err(err) = self.settings.add_vault(&vault) {
            for file in ["gocryptfs.conf", "gocryptfs.diriv"] {
                let _ = std::fs::remove_file(source.join(file));
            }
            if make_dir {
                let _ = std::fs::remove_dir(&source);
            }
            return Err(edit_error(err));
        }
        tracing::info!(vault = %id, source = %source.display(), "vault created");
        self.reconfigure().await;
        self.get(&id)
    }

    // ------------------------------------------------------------ gocryptfs

    async fn mount_gocryptfs(&self, vault: &VaultConfig) -> Result<(), RpcError> {
        let gocryptfs = self.env.gocryptfs.as_ref().expect("checked by lookup");
        let mount_point = vault.mount_point.as_ref().expect("validated by config");
        if !vault.source.is_dir() {
            return Err(backend_error(format!(
                "vault '{}': {} is not a gocryptfs directory",
                vault.id,
                vault.source.display()
            )));
        }
        if !mount_point.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(mount_point)
                .map_err(|e| backend_error(format!("creating {}: {e}", mount_point.display())))?;
        }
        for attempt in 0..MAX_ATTEMPTS {
            let pin = self.ask(vault, attempt).await?;
            if pin.contains(['\n', '\0']) {
                return Err(RpcError::invalid_params(
                    "a gocryptfs passphrase cannot contain a newline",
                ));
            }
            let mut command = match &self.env.systemd_run {
                Some(systemd_run) => {
                    let mut c = tokio::process::Command::new(systemd_run);
                    c.args([
                        "--user",
                        "--scope",
                        "--quiet",
                        "--collect",
                        &format!("--description=Security Hub vault: {}", vault.id),
                        "--",
                    ])
                    .arg(gocryptfs);
                    c
                }
                None => tokio::process::Command::new(gocryptfs),
            };
            let mut child = command
                .args(["-passfile", "/dev/stdin", "--"])
                .arg(&vault.source)
                .arg(mount_point)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| backend_error(format!("starting gocryptfs: {e}")))?;
            {
                let mut stdin = child.stdin.take().expect("piped stdin");
                // gocryptfs reads the first line of the passfile.
                let written = async {
                    stdin.write_all(pin.as_bytes()).await?;
                    stdin.write_all(b"\n").await
                }
                .await;
                if let Err(err) = written {
                    tracing::debug!("writing the passphrase to gocryptfs: {err}");
                }
            }
            drop(pin);
            let output = tokio::time::timeout(MOUNT_TIMEOUT, child.wait_with_output())
                .await
                .map_err(|_| backend_error("gocryptfs did not finish within 60 s".into()))?
                .map_err(|e| backend_error(format!("waiting for gocryptfs: {e}")))?;
            match output.status.code() {
                Some(0) => return Ok(()),
                Some(GOCRYPTFS_BAD_PASSWORD) if attempt + 1 < MAX_ATTEMPTS => continue,
                Some(GOCRYPTFS_BAD_PASSWORD) => {
                    return Err(RpcError::new(
                        ErrorCode::PermissionDenied,
                        format!("vault '{}': wrong passphrase", vault.id),
                    ));
                }
                _ => {
                    return Err(backend_error(format!(
                        "gocryptfs failed ({}): {}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr).trim()
                    )));
                }
            }
        }
        unreachable!("the last attempt returns")
    }

    async fn unmount_gocryptfs(&self, vault: &VaultConfig) -> Result<(), RpcError> {
        if !self.get(&vault.id)?.mounted {
            return Ok(());
        }
        let mount_point = vault.mount_point.as_ref().expect("validated by config");
        self.fusermount(mount_point, false).await
    }

    /// `fusermount3 -u`, or with `lazy`, `fusermount3 -uz`.
    async fn fusermount(&self, mount_point: &Path, lazy: bool) -> Result<(), RpcError> {
        let fusermount = self
            .env
            .fusermount
            .as_ref()
            .ok_or_else(|| backend_error("fusermount3 (fuse3) is not installed".into()))?;
        let flag = if lazy { "-uz" } else { "-u" };
        let output = tokio::process::Command::new(fusermount)
            .arg(flag)
            .arg(mount_point)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| backend_error(format!("starting fusermount3: {e}")))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(backend_error(format!(
                "fusermount3 {flag} failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }

    // ----------------------------------------------------------------- LUKS

    fn bus(&self) -> &zbus::Connection {
        self.bus.as_ref().expect("checked by lookup")
    }

    async fn luks(&self, source: &Source) -> Result<Luks, RpcError> {
        let blocks = udisks::blocks(self.bus())
            .await
            .map_err(|e| udisks_error("listing devices", e))?;
        Ok(Luks::find(&blocks, source))
    }

    async fn mount_luks(&self, vault: &VaultConfig) -> Result<(), RpcError> {
        let bus = self.bus();
        let source = Source::resolve(&vault.source).map_err(|e| {
            backend_error(format!(
                "vault '{}': {}: {e}",
                vault.id,
                vault.source.display()
            ))
        })?;
        let mut luks = self.luks(&source).await?;
        // The loop device this call set up, to delete again on failure.
        let mut created_loop = None;
        if luks.backing.is_none() {
            let Source::File(file) = &source else {
                return Err(backend_error(format!(
                    "vault '{}': udisks2 does not know {}",
                    vault.id,
                    vault.source.display()
                )));
            };
            let device = udisks::loop_setup(bus, file)
                .await
                .map_err(|e| udisks_error("setting up a loop device", e))?;
            created_loop = Some(device);
            let deadline = tokio::time::Instant::now() + PROBE_WAIT;
            loop {
                luks = self.luks(&source).await?;
                let probed = luks.backing.as_ref().is_some_and(|b| b.encrypted);
                if probed || tokio::time::Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        let mut unlocked_here = false;
        let result = async {
            let backing = luks.backing.clone().ok_or_else(|| {
                backend_error(format!("vault '{}': the loop device disappeared", vault.id))
            })?;
            if !backing.encrypted {
                return Err(backend_error(format!(
                    "vault '{}': {} is not a LUKS container",
                    vault.id,
                    vault.source.display()
                )));
            }
            let cleartext = match &luks.cleartext {
                Some(cleartext) => cleartext.path.clone(),
                None => {
                    let path = self.unlock(vault, &backing.path).await?;
                    unlocked_here = true;
                    path
                }
            };
            if luks.mount_point().is_none() {
                udisks::mount(bus, &cleartext)
                    .await
                    .map_err(|e| udisks_error("mounting", e))?;
            }
            Ok(())
        }
        .await;

        if result.is_err() {
            if let Some(backing) = luks.backing.as_ref().filter(|_| unlocked_here) {
                if let Err(err) = udisks::lock(bus, &backing.path).await {
                    tracing::warn!(vault = %vault.id, "locking after a failed mount: {err}");
                }
            }
            if let Some(device) = &created_loop {
                if let Err(err) = udisks::loop_delete(bus, device).await {
                    tracing::warn!(vault = %vault.id, "deleting the loop device after a failed mount: {err}");
                }
            }
        }
        result
    }

    async fn unlock(
        &self,
        vault: &VaultConfig,
        backing: &zbus::zvariant::OwnedObjectPath,
    ) -> Result<zbus::zvariant::OwnedObjectPath, RpcError> {
        for attempt in 0..MAX_ATTEMPTS {
            let pin = self.ask(vault, attempt).await?;
            match udisks::unlock(self.bus(), backing, &pin).await {
                Ok(cleartext) => return Ok(cleartext),
                Err(err) if udisks::is_bad_passphrase(&err) => {
                    if attempt + 1 == MAX_ATTEMPTS {
                        return Err(RpcError::new(
                            ErrorCode::PermissionDenied,
                            format!("vault '{}': wrong passphrase", vault.id),
                        ));
                    }
                }
                Err(err) => return Err(udisks_error("unlocking", err)),
            }
        }
        unreachable!("the last attempt returns")
    }

    async fn unmount_luks(&self, vault: &VaultConfig) -> Result<(), RpcError> {
        self.close_luks(vault, false).await.map(drop)
    }

    /// Unmounts, locks and detaches a LUKS vault. With `force`, a busy
    /// filesystem is unmounted lazily; returns whether that happened.
    async fn close_luks(&self, vault: &VaultConfig, force: bool) -> Result<bool, RpcError> {
        let bus = self.bus.as_ref().ok_or_else(|| {
            RpcError::new(
                ErrorCode::ModuleUnavailable,
                "the system bus is unavailable",
            )
        })?;
        let Ok(source) = Source::resolve(&vault.source) else {
            return Ok(false);
        };
        let luks = self.luks(&source).await?;
        let Some(backing) = luks.backing.clone() else {
            return Ok(false);
        };
        let mut lazy = false;
        if let Some(cleartext) = &luks.cleartext {
            if luks.mount_point().is_some() {
                match udisks::unmount(bus, &cleartext.path, false).await {
                    Ok(()) => {}
                    Err(err) if force => {
                        tracing::warn!(vault = %vault.id, "unmount failed ({err}); unmounting lazily");
                        udisks::unmount(bus, &cleartext.path, true)
                            .await
                            .map_err(|e| udisks_error("unmounting", e))?;
                        lazy = true;
                    }
                    Err(err) => return Err(udisks_error("unmounting", err)),
                }
            }
            udisks::lock(bus, &backing.path)
                .await
                .map_err(|e| udisks_error("locking", e))?;
        }
        // udisks2 may have cleared the loop device on its own when locking.
        if matches!(source, Source::File(_)) {
            let luks = self.luks(&source).await?;
            if let Some(backing) = luks.backing {
                udisks::loop_delete(bus, &backing.path)
                    .await
                    .map_err(|e| udisks_error("deleting the loop device", e))?;
            }
        }
        Ok(lazy)
    }

    // ---------------------------------------------------------------- panic

    /// Emergency unmount of every mounted vault. Nothing here may prompt.
    pub async fn panic(&self) -> PanicResult {
        tracing::warn!("vault panic");
        self.panics.fetch_add(1, Ordering::SeqCst);
        self.panicked.notify_waiters();
        // A mount in progress is past its prompt; let it finish, so that
        // its vault is unmounted too.
        let _op = match tokio::time::timeout(PANIC_WAIT, self.ops.lock()).await {
            Ok(guard) => Some(guard),
            Err(_) => {
                tracing::warn!("panic: a vault operation is still running; going ahead");
                None
            }
        };
        self.refresh().await;
        let config = self.settings.current();
        let mounted: Vec<(VaultConfig, PathBuf)> = config
            .vaults
            .iter()
            .filter_map(|vault| {
                let state = self.get(&vault.id).ok().filter(|s| s.mounted)?;
                let mount_point = match vault.backend {
                    VaultBackend::Gocryptfs => canonical_mount_point(vault.mount_point.as_deref()?),
                    VaultBackend::Luks => PathBuf::from(state.mount_point),
                };
                Some((vault.clone(), mount_point))
            })
            .collect();

        let mount_points: Vec<PathBuf> = mounted.iter().map(|(_, m)| m.clone()).collect();
        let found =
            tokio::task::spawn_blocking(move || holders::find(Path::new(PROC), &mount_points))
                .await
                .unwrap_or_else(|_| vec![Vec::new(); mounted.len()]);
        let mut targets: Vec<Holder> = found.iter().flatten().cloned().collect();
        targets.sort_by_key(|h| h.pid);
        targets.dedup_by_key(|h| h.pid);
        let survivors = holders::stop(Path::new(PROC), &targets, PANIC_GRACE).await;

        let mut result = PanicResult {
            unmounted: Vec::new(),
            lazy: Vec::new(),
            failed: Vec::new(),
        };
        for ((vault, mount_point), holders) in mounted.iter().zip(&found) {
            let remaining: Vec<&Holder> = holders
                .iter()
                .filter(|h| h.protected || survivors.iter().any(|s| s.pid == h.pid))
                .collect();
            if !flush(mount_point).await {
                tracing::warn!(vault = %vault.id, "panic: syncfs did not finish");
            }
            let closed = match vault.backend {
                VaultBackend::Gocryptfs => match self.fusermount(mount_point, false).await {
                    Ok(()) => Ok(false),
                    Err(err) => {
                        tracing::warn!(vault = %vault.id, "{}; unmounting lazily", err.message);
                        self.fusermount(mount_point, true).await.map(|()| true)
                    }
                },
                VaultBackend::Luks => self.close_luks(vault, true).await,
            };
            let held = (!remaining.is_empty()).then(|| {
                let names: Vec<String> = remaining
                    .iter()
                    .map(|h| format!("{} (pid {})", h.name, h.pid))
                    .collect();
                format!("still in use by {}", names.join(", "))
            });
            match (closed, held) {
                (Ok(false), _) => result.unmounted.push(vault.id.clone()),
                (Ok(true), None) => {
                    result.unmounted.push(vault.id.clone());
                    result.lazy.push(vault.id.clone());
                }
                (Ok(true), Some(held)) => result.failed.push(PanicFailure {
                    vault_id: vault.id.clone(),
                    reason: format!(
                        "{held}; unmounted lazily, so it can still use the files it has open"
                    ),
                }),
                (Err(err), held) => result.failed.push(PanicFailure {
                    vault_id: vault.id.clone(),
                    reason: match held {
                        Some(held) => format!("{held}; {}", err.message),
                        None => err.message,
                    },
                }),
            }
        }
        let synced = tokio::task::spawn_blocking(nix::unistd::sync);
        if tokio::time::timeout(PANIC_SYNC_WAIT, synced).await.is_err() {
            tracing::warn!("panic: sync did not finish within 10 s");
        }
        self.refresh().await;
        tracing::warn!(unmounted = ?result.unmounted, lazy = ?result.lazy, failed = ?result.failed, "vault panic done");
        result
    }
}

/// `syncfs` on the filesystem mounted at `mount_point`. Returns false when
/// it did not finish in time, as on a stuck FUSE mount.
async fn flush(mount_point: &Path) -> bool {
    let path = mount_point.to_path_buf();
    let sync = tokio::task::spawn_blocking(move || {
        let dir = std::fs::File::open(&path)?;
        nix::unistd::syncfs(&dir).map_err(std::io::Error::from)
    });
    match tokio::time::timeout(PANIC_WAIT, sync).await {
        Ok(Ok(Ok(()))) => true,
        Ok(Ok(Err(err))) => {
            tracing::debug!("syncfs {}: {err}", mount_point.display());
            true
        }
        Ok(Err(_)) | Err(_) => false,
    }
}

fn needs(config: &Config, backend: VaultBackend) -> bool {
    config.vaults.iter().any(|v| v.backend == backend)
}

/// `gocryptfs -init` on the empty directory `cipher`, with the passphrase
/// on stdin. Without a terminal, gocryptfs does not print the master key.
async fn init_gocryptfs(gocryptfs: &Path, cipher: &Path, pin: &str) -> Result<(), RpcError> {
    let mut child = tokio::process::Command::new(gocryptfs)
        .args(["-init", "-q", "-passfile", "/dev/stdin", "--"])
        .arg(cipher)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| backend_error(format!("starting gocryptfs: {e}")))?;
    {
        let mut stdin = child.stdin.take().expect("piped stdin");
        let written = async {
            stdin.write_all(pin.as_bytes()).await?;
            stdin.write_all(b"\n").await
        }
        .await;
        if let Err(err) = written {
            tracing::debug!("writing the passphrase to gocryptfs: {err}");
        }
    }
    let output = tokio::time::timeout(MOUNT_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| backend_error("gocryptfs -init did not finish within 60 s".into()))?
        .map_err(|e| backend_error(format!("waiting for gocryptfs: {e}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let reason = stderr
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    Err(backend_error(format!(
        "gocryptfs -init failed ({}): {reason}",
        output.status
    )))
}

fn backend_name(backend: VaultBackend) -> &'static str {
    match backend {
        VaultBackend::Gocryptfs => "gocryptfs",
        VaultBackend::Luks => "luks",
    }
}

/// A vault's state from mountinfo (gocryptfs) or udisks2 (LUKS). A LUKS
/// vault that is not mounted has an empty `mount_point`: udisks2 chooses
/// one each time.
fn observe(vault: &VaultConfig, mounts: &[Mount], blocks: Option<&[udisks::Block]>) -> Vault {
    let (mounted, mount_point) = match vault.backend {
        VaultBackend::Gocryptfs => {
            let mount_point = vault.mount_point.clone().unwrap_or_default();
            let wanted = canonical_mount_point(&mount_point);
            let mounted = mounts
                .iter()
                .any(|m| m.fstype == "fuse.gocryptfs" && m.mount_point == wanted);
            (mounted, mount_point)
        }
        VaultBackend::Luks => {
            let found =
                blocks
                    .zip(Source::resolve(&vault.source).ok())
                    .and_then(|(blocks, source)| {
                        Luks::find(blocks, &source)
                            .mount_point()
                            .map(Path::to_path_buf)
                    });
            (found.is_some(), found.unwrap_or_default())
        }
    };
    Vault {
        vault_id: vault.id.clone(),
        name: vault.name.clone(),
        backend: vault.backend,
        mount_point: mount_point.display().to_string(),
        mounted,
    }
}

/// Resolves symlinks in the parent only: the mount point itself may be a
/// FUSE mount whose daemon died, which cannot be stat'ed.
fn canonical_mount_point(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => std::fs::canonicalize(parent)
            .map(|p| p.join(name))
            .unwrap_or_else(|_| path.to_path_buf()),
        _ => path.to_path_buf(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Mount {
    mount_point: PathBuf,
    fstype: String,
}

/// Parses `/proc/self/mountinfo`, `proc(5)`.
fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let (left, right) = line.split_once(" - ")?;
            let mount_point = left.split(' ').nth(4)?;
            let fstype = right.split(' ').next()?;
            Some(Mount {
                mount_point: PathBuf::from(unescape_octal(mount_point)),
                fstype: fstype.to_owned(),
            })
        })
        .collect()
}

/// mountinfo escapes space, tab, newline and backslash as `\ooo`.
fn unescape_octal(field: &str) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            if let Some(value) = bytes
                .get(i + 1..i + 4)
                .and_then(|o| std::str::from_utf8(o).ok())
                .and_then(|o| u8::from_str_radix(o, 8).ok())
            {
                out.push(value);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    OsString::from_vec(out)
}

/// Wakes when the mount table changes: mountinfo polls as `POLLPRI` then.
struct MountWatch(AsyncFd<std::fs::File>);

impl MountWatch {
    fn open(path: &Path) -> std::io::Result<Self> {
        // epoll refuses regular files, so this fails for anything but
        // procfs's mountinfo.
        let file = std::fs::File::open(path)?;
        Ok(Self(AsyncFd::with_interest(file, Interest::PRIORITY)?))
    }

    async fn changed(&self) -> std::io::Result<()> {
        let mut guard = self.0.ready(Interest::PRIORITY).await?;
        guard.clear_ready();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Bus;
    use std::collections::HashMap;
    use zbus::zvariant::OwnedObjectPath;

    const MOUNTINFO: &str = "\
22 1 259:2 / / rw,relatime shared:1 - btrfs /dev/nvme0n1p2 rw
358 59 0:89 / /home/u/My\\040Vault rw,nosuid,nodev,relatime shared:724 - fuse.gocryptfs /home/u/c rw,user_id=1000
359 59 0:90 / /home/u/other rw - fuse.sshfs host: rw
bad line
";

    #[test]
    fn parses_mountinfo() {
        let mounts = parse_mountinfo(MOUNTINFO);
        assert_eq!(mounts.len(), 3);
        assert_eq!(mounts[1].mount_point, Path::new("/home/u/My Vault"));
        assert_eq!(mounts[1].fstype, "fuse.gocryptfs");
        assert_eq!(unescape_octal("a\\134b\\01"), OsString::from("a\\b\\01"));
    }

    fn gocryptfs(id: &str, mount_point: &str) -> VaultConfig {
        VaultConfig {
            id: id.into(),
            name: id.into(),
            backend: VaultBackend::Gocryptfs,
            source: "/nonexistent/c".into(),
            mount_point: Some(mount_point.into()),
        }
    }

    #[test]
    fn observes_gocryptfs_mounts_by_type() {
        let mounts = parse_mountinfo(MOUNTINFO);
        assert!(observe(&gocryptfs("a", "/home/u/My Vault"), &mounts, None).mounted);
        assert!(!observe(&gocryptfs("b", "/home/u/other"), &mounts, None).mounted);
        let luks = VaultConfig {
            backend: VaultBackend::Luks,
            mount_point: None,
            ..gocryptfs("c", "")
        };
        let vault = observe(&luks, &mounts, None);
        assert!(!vault.mounted);
        assert_eq!(vault.mount_point, "");
    }

    struct Fixture {
        dir: tempfile::TempDir,
        hub: Arc<Hub>,
        settings: Arc<Settings>,
    }

    fn fixture(config: &str) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, config).unwrap();
        Fixture {
            hub: Arc::new(Hub::new()),
            settings: Arc::new(Settings::load(Some(path))),
            dir,
        }
    }

    fn env(dir: &Path, pin: &str, retry_pin: &str) -> VaultEnv {
        VaultEnv {
            mountinfo: "/proc/self/mountinfo".into(),
            gocryptfs: find_in_path("gocryptfs"),
            fusermount: find_in_path("fusermount3"),
            pinentry: pinentry::tests::fake(dir, pin, retry_pin),
            systemd_run: None,
        }
    }

    async fn wait_for(hub: &Hub, state: ModuleState) {
        for _ in 0..200 {
            if hub.status(Module::Vault).state == state {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "vault never became {state:?}: {:?}",
            hub.status(Module::Vault)
        );
    }

    async fn wait_for_detail(hub: &Hub, needle: &str) {
        for _ in 0..200 {
            if hub
                .status(Module::Vault)
                .detail
                .is_some_and(|d| d.contains(needle))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "vault detail never had {needle:?}: {:?}",
            hub.status(Module::Vault)
        );
    }

    async fn next_vault(rx: &mut tokio::sync::broadcast::Receiver<Event>) -> Vault {
        loop {
            let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("event within 5 s")
                .unwrap();
            if let Event::VaultStateChanged(vault) = event {
                return vault;
            }
        }
    }

    #[tokio::test]
    async fn status_follows_the_configured_backends() {
        let f = fixture("");
        let mut e = env(f.dir.path(), "x", "x");
        e.gocryptfs = None;
        let module = Vaults::start(f.hub.clone(), f.settings.clone(), None, e);
        wait_for(&f.hub, ModuleState::Active).await;
        assert!(module.list().vaults.is_empty());

        let path = f.dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[[vault]]\nid = \"a\"\nname = \"A\"\nbackend = \"gocryptfs\"\nsource = \"/x\"\nmount_point = \"/y\"\n",
        )
        .unwrap();
        f.settings.reload();
        wait_for_detail(&f.hub, "gocryptfs is not installed").await;
        assert_eq!(f.hub.status(Module::Vault).state, ModuleState::Unavailable);
        let err = module
            .mount(VaultTarget {
                vault_id: "a".into(),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::ModuleUnavailable));

        std::fs::write(
            &path,
            "[[vault]]\nid = \"a\"\nname = \"A\"\nbackend = \"gocryptfs\"\nsource = \"/x\"\nmount_point = \"/y\"\n\
             [[vault]]\nid = \"b\"\nname = \"B\"\nbackend = \"luks\"\nsource = \"/x\"\n",
        )
        .unwrap();
        f.settings.reload();
        wait_for_detail(&f.hub, "system bus").await;
        assert_eq!(f.hub.status(Module::Vault).state, ModuleState::Unavailable);
        let err = module
            .mount(VaultTarget {
                vault_id: "nope".into(),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::NotFound));
    }

    async fn next_removed(rx: &mut tokio::sync::broadcast::Receiver<Event>) -> String {
        loop {
            let event = tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("event within 5 s")
                .unwrap();
            if let Event::VaultRemoved(vault) = event {
                return vault.vault_id;
            }
        }
    }

    #[tokio::test]
    async fn vaults_are_added_and_removed() {
        let f = fixture("# mine\n");
        let module = Vaults::start(
            f.hub.clone(),
            f.settings.clone(),
            None,
            env(f.dir.path(), "x", "x"),
        );
        wait_for(&f.hub, ModuleState::Active).await;
        let mut events = f.hub.subscribe();
        let cipher = f.dir.path().join("c");
        let image = f.dir.path().join("disk.img");
        let add = |id: &str, backend, source: &Path, mount_point: Option<&str>| VaultAddParams {
            vault_id: id.into(),
            name: id.to_uppercase(),
            backend,
            source: source.display().to_string(),
            mount_point: mount_point.map(Into::into),
        };
        let mount_point = f.dir.path().join("m").display().to_string();

        for (params, needle) in [
            (
                add("a", VaultBackend::Gocryptfs, &cipher, Some(&mount_point)),
                "is not a directory",
            ),
            (add("a", VaultBackend::Luks, &image, None), "does not exist"),
            (
                add("a", VaultBackend::Luks, Path::new("disk.img"), None),
                "must be absolute",
            ),
        ] {
            let err = module.add(params).await.unwrap_err();
            assert_eq!(err.kind(), Some(ErrorCode::InvalidParams));
            assert!(err.message.contains(needle), "{err:?}");
        }
        std::fs::create_dir(&cipher).unwrap();
        let err = module
            .add(add(
                "a",
                VaultBackend::Gocryptfs,
                &cipher,
                Some(&mount_point),
            ))
            .await
            .unwrap_err();
        assert!(err.message.contains("gocryptfs -init"), "{err:?}");

        std::fs::write(cipher.join("gocryptfs.conf"), "{}").unwrap();
        let vault = module
            .add(add(
                "a",
                VaultBackend::Gocryptfs,
                &cipher,
                Some(&mount_point),
            ))
            .await
            .unwrap();
        assert_eq!(vault.name, "A");
        assert!(!vault.mounted);
        assert_eq!(next_vault(&mut events).await.vault_id, "a");
        // An absent block device is fine: it may be unplugged.
        module
            .add(add(
                "b",
                VaultBackend::Luks,
                Path::new("/dev/disk/by-uuid/0"),
                None,
            ))
            .await
            .unwrap();
        let err = module
            .add(add("b", VaultBackend::Luks, Path::new("/dev/sdz"), None))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::InvalidParams));
        assert!(err.message.contains("defined twice"), "{err:?}");
        let ids: Vec<_> = module
            .list()
            .vaults
            .into_iter()
            .map(|v| v.vault_id)
            .collect();
        assert_eq!(ids, ["a", "b"]);

        module
            .remove(VaultTarget {
                vault_id: "a".into(),
            })
            .await
            .unwrap();
        assert_eq!(next_removed(&mut events).await, "a");
        let err = module
            .remove(VaultTarget {
                vault_id: "a".into(),
            })
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::NotFound));
        let text = std::fs::read_to_string(f.dir.path().join("config.toml")).unwrap();
        assert!(text.starts_with("# mine\n"), "{text}");
        assert!(!text.contains("id = \"a\""), "{text}");

        // Removed by editing the file: the reload says so too.
        std::fs::write(f.dir.path().join("config.toml"), "").unwrap();
        f.settings.reload();
        assert_eq!(next_removed(&mut events).await, "b");
    }

    fn create_params(dir: &Path, id: &str) -> VaultCreateParams {
        VaultCreateParams {
            vault_id: id.into(),
            name: id.to_uppercase(),
            source: dir.join(format!("{id}.enc")).display().to_string(),
            mount_point: dir.join(id).display().to_string(),
        }
    }

    fn getpins(dir: &Path) -> usize {
        std::fs::read_to_string(dir.join("pinentry.log"))
            .unwrap_or_default()
            .matches("GETPIN")
            .count()
    }

    #[tokio::test]
    async fn create_checks_everything_before_asking() {
        let f = fixture(
            "[[vault]]\nid = \"taken\"\nname = \"T\"\nbackend = \"luks\"\nsource = \"/dev/sdz\"\n",
        );
        let module = Vaults::start(
            f.hub.clone(),
            f.settings.clone(),
            None,
            env(f.dir.path(), "secret", "secret"),
        );
        let work = tempfile::tempdir().unwrap();
        let full = work.path().join("full.enc");
        std::fs::create_dir(&full).unwrap();
        std::fs::write(full.join("x"), "").unwrap();
        std::fs::write(work.path().join("file.enc"), "").unwrap();

        for (params, code, needle) in [
            (
                create_params(work.path(), "taken"),
                ErrorCode::InvalidParams,
                "defined twice",
            ),
            (
                create_params(work.path(), "full"),
                ErrorCode::InvalidParams,
                "not empty",
            ),
            (
                create_params(work.path(), "file"),
                ErrorCode::InvalidParams,
                "not a directory",
            ),
            (
                VaultCreateParams {
                    mount_point: "relative".into(),
                    ..create_params(work.path(), "a")
                },
                ErrorCode::InvalidParams,
                "must be absolute",
            ),
        ] {
            let err = module.create(params).await.unwrap_err();
            assert_eq!(err.kind(), Some(code), "{err:?}");
            assert!(err.message.contains(needle), "{err:?}");
        }
        assert_eq!(getpins(f.dir.path()), 0);

        let mut e = env(f.dir.path(), "x", "x");
        e.gocryptfs = None;
        let without = Vaults::start(f.hub.clone(), f.settings.clone(), None, e);
        let err = without
            .create(create_params(work.path(), "a"))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::ModuleUnavailable));
    }

    #[tokio::test]
    async fn create_makes_a_vault_that_mounts_with_the_new_passphrase() {
        if !gocryptfs_available() {
            eprintln!("gocryptfs or /dev/fuse not available; skipping");
            return;
        }
        let f = fixture("");
        let mut e = env(f.dir.path(), "x", "x");
        e.pinentry = pinentry::tests::fake_repeating(f.dir.path(), "n3w secret");
        let module = Vaults::start(f.hub.clone(), f.settings.clone(), None, e);
        wait_for(&f.hub, ModuleState::Active).await;
        let mut events = f.hub.subscribe();
        let work = tempfile::tempdir().unwrap();
        // Parents that do not exist yet are made too.
        let params = VaultCreateParams {
            source: work.path().join("deep/new.enc").display().to_string(),
            ..create_params(work.path(), "new")
        };
        let vault = module.create(params).await.unwrap();
        assert_eq!((vault.vault_id.as_str(), vault.mounted), ("new", false));
        assert_eq!(next_vault(&mut events).await.vault_id, "new");
        let cipher = work.path().join("deep/new.enc");
        assert!(cipher.join("gocryptfs.conf").is_file());
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&cipher).unwrap().permissions(),
        ) & 0o777;
        assert_eq!(mode, 0o700);
        // pinentry confirmed it: one prompt.
        assert_eq!(getpins(f.dir.path()), 1);
        let log = std::fs::read_to_string(f.dir.path().join("pinentry.log")).unwrap();
        assert!(log.contains("SETREPEAT"), "{log}");
        assert!(!log.contains("n3w secret"), "{log}");
        assert_eq!(f.settings.current().vaults[0].source, cipher);

        // The same passphrase opens it.
        let target = VaultTarget {
            vault_id: "new".into(),
        };
        assert!(module.mount(target.clone()).await.unwrap().mounted);
        assert!(!module.unmount(target).await.unwrap().mounted);
    }

    #[tokio::test]
    async fn create_asks_again_without_setrepeat() {
        if !gocryptfs_available() {
            eprintln!("gocryptfs or /dev/fuse not available; skipping");
            return;
        }
        let f = fixture("");
        let work = tempfile::tempdir().unwrap();
        let start = |pins: &[&str]| {
            let mut e = env(f.dir.path(), "x", "x");
            e.pinentry = pinentry::tests::fake_sequence(f.dir.path(), pins);
            let _ = std::fs::remove_file(f.dir.path().join("pinentry.log"));
            Vaults::start(f.hub.clone(), f.settings.clone(), None, e)
        };

        // Empty, then a mismatch, then two that match.
        let module = start(&["", "one", "two", "same", "same"]);
        module
            .create(create_params(work.path(), "a"))
            .await
            .unwrap();
        assert_eq!(getpins(f.dir.path()), 5);
        let log = std::fs::read_to_string(f.dir.path().join("pinentry.log")).unwrap();
        assert!(
            log.contains("SETERROR The passphrase cannot be empty."),
            "{log}"
        );
        assert!(
            log.contains("SETERROR The passphrases did not match"),
            "{log}"
        );

        // Three mismatches: nothing is created.
        let module = start(&["a", "b", "c", "d", "e", "f"]);
        let err = module
            .create(create_params(work.path(), "b"))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::InvalidParams));
        assert!(!work.path().join("b.enc").exists());

        // Cancelled at the confirmation: nothing is created either.
        let module = start(&["a"]);
        let err = module
            .create(create_params(work.path(), "c"))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::Cancelled));
        assert!(!work.path().join("c.enc").exists());
        let ids: Vec<_> = f
            .settings
            .current()
            .vaults
            .iter()
            .map(|v| v.id.clone())
            .collect();
        assert_eq!(ids, ["a"]);
    }

    fn gocryptfs_available() -> bool {
        find_in_path("gocryptfs").is_some()
            && find_in_path("fusermount3").is_some()
            && std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/fuse")
                .is_ok()
    }

    /// Creates a gocryptfs cipher directory with the passphrase `right`.
    fn init_gocryptfs(cipher: &Path) {
        let mut init = std::process::Command::new("gocryptfs")
            .args([
                "-init",
                "-q",
                "-scryptn",
                "10",
                "-passfile",
                "/dev/stdin",
                "--",
            ])
            .arg(cipher)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        std::io::Write::write_all(init.stdin.as_mut().unwrap(), b"right\n").unwrap();
        drop(init.stdin.take());
        assert!(init.wait().unwrap().success());
    }

    #[tokio::test]
    async fn gocryptfs_vault_mounts_and_unmounts() {
        if !gocryptfs_available() {
            eprintln!("gocryptfs or /dev/fuse not available; skipping");
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let cipher = work.path().join("c");
        let mount_point = work.path().join("m");
        std::fs::create_dir(&cipher).unwrap();
        init_gocryptfs(&cipher);

        let f = fixture(&format!(
            "[[vault]]\nid = \"work\"\nname = \"Work\"\nbackend = \"gocryptfs\"\nsource = \"{}\"\nmount_point = \"{}\"\n",
            cipher.display(),
            mount_point.display()
        ));
        let mut events = f.hub.subscribe();
        // The first passphrase is wrong; the retry, after SETERROR, is right.
        let module = Vaults::start(
            f.hub.clone(),
            f.settings.clone(),
            None,
            env(f.dir.path(), "wrong", "right"),
        );
        wait_for(&f.hub, ModuleState::Active).await;
        let initial = next_vault(&mut events).await;
        assert!(!initial.mounted);

        let target = || VaultTarget {
            vault_id: "work".into(),
        };
        let vault = module.mount(target()).await.unwrap();
        assert!(vault.mounted, "{vault:?}");
        assert_eq!(vault.mount_point, mount_point.display().to_string());
        assert!(next_vault(&mut events).await.mounted);
        let log = std::fs::read_to_string(f.dir.path().join("pinentry.log")).unwrap();
        assert_eq!(log.matches("GETPIN").count(), 2, "{log}");
        std::fs::write(mount_point.join("secret.txt"), "hello").unwrap();
        // Mounting a mounted vault is a no-op.
        assert!(module.mount(target()).await.unwrap().mounted);

        // Unmounted outside the hub: the mountinfo watch notices.
        let status = std::process::Command::new("fusermount3")
            .arg("-u")
            .arg(&mount_point)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(!next_vault(&mut events).await.mounted);
        assert!(!module.list().vaults[0].mounted);

        let vault = module.mount(target()).await.unwrap();
        assert!(vault.mounted);
        assert_eq!(
            std::fs::read_to_string(mount_point.join("secret.txt")).unwrap(),
            "hello"
        );
        let err = module.remove(target()).await.unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::BackendError));
        assert!(err.message.contains("unmount it first"), "{err:?}");
        let vault = module.unmount(target()).await.unwrap();
        assert!(!vault.mounted);
        assert!(!mount_point.join("secret.txt").exists());
        // Unmounting an unmounted vault is a no-op.
        assert!(!module.unmount(target()).await.unwrap().mounted);
        module.remove(target()).await.unwrap();
        assert!(module.list().vaults.is_empty());
        // The cipher directory is kept.
        assert!(cipher.join("gocryptfs.conf").is_file());
    }

    #[tokio::test]
    async fn gocryptfs_cancel_and_wrong_passphrases() {
        if !gocryptfs_available() {
            eprintln!("gocryptfs or /dev/fuse not available; skipping");
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let cipher = work.path().join("c");
        std::fs::create_dir(&cipher).unwrap();
        init_gocryptfs(&cipher);
        let config = format!(
            "[[vault]]\nid = \"w\"\nname = \"W\"\nbackend = \"gocryptfs\"\nsource = \"{}\"\nmount_point = \"{}\"\n",
            cipher.display(),
            work.path().join("m").display()
        );
        let target = || VaultTarget {
            vault_id: "w".into(),
        };

        let f = fixture(&config);
        let module = Vaults::start(
            f.hub.clone(),
            f.settings.clone(),
            None,
            env(f.dir.path(), "CANCEL", "CANCEL"),
        );
        wait_for(&f.hub, ModuleState::Active).await;
        let err = module.mount(target()).await.unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::Cancelled));

        let f = fixture(&config);
        let module = Vaults::start(
            f.hub.clone(),
            f.settings.clone(),
            None,
            env(f.dir.path(), "bad", "bad"),
        );
        wait_for(&f.hub, ModuleState::Active).await;
        let err = module.mount(target()).await.unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::PermissionDenied), "{err:?}");
        let log = std::fs::read_to_string(f.dir.path().join("pinentry.log")).unwrap();
        assert_eq!(log.matches("GETPIN").count(), MAX_ATTEMPTS, "{log}");
        assert!(!module.list().vaults[0].mounted);
    }

    #[tokio::test]
    async fn panic_stops_holders_and_unmounts() {
        use std::os::unix::process::ExitStatusExt;
        if !gocryptfs_available() {
            eprintln!("gocryptfs or /dev/fuse not available; skipping");
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let cipher = work.path().join("c");
        let mount_point = work.path().join("m");
        std::fs::create_dir(&cipher).unwrap();
        init_gocryptfs(&cipher);
        let f = fixture(&format!(
            "[[vault]]\nid = \"work\"\nname = \"Work\"\nbackend = \"gocryptfs\"\nsource = \"{}\"\nmount_point = \"{}\"\n",
            cipher.display(),
            mount_point.display()
        ));
        let module = Vaults::start(
            f.hub.clone(),
            f.settings.clone(),
            None,
            env(f.dir.path(), "right", "right"),
        );
        wait_for(&f.hub, ModuleState::Active).await;
        let target = || VaultTarget {
            vault_id: "work".into(),
        };
        assert!(module.mount(target()).await.unwrap().mounted);
        std::fs::write(mount_point.join("secret.txt"), "hello").unwrap();
        let mut events = f.hub.subscribe();

        // One holder has its cwd in the vault; the other holds a file open
        // and ignores SIGTERM, so it needs SIGKILL.
        let mut polite = std::process::Command::new("sleep")
            .arg("60")
            .current_dir(&mount_point)
            .spawn()
            .unwrap();
        let mut stubborn = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "trap '' TERM; exec sleep 60 3<'{}'",
                mount_point.join("secret.txt").display()
            ))
            .spawn()
            .unwrap();
        // Let sh exec into sleep with the file open.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let started = std::time::Instant::now();
        let result = module.panic().await;
        assert_eq!(result.unmounted, ["work"], "{result:?}");
        assert!(result.lazy.is_empty(), "{result:?}");
        assert!(result.failed.is_empty(), "{result:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(
            polite.wait().unwrap().signal(),
            Some(nix::sys::signal::Signal::SIGTERM as i32)
        );
        assert_eq!(
            stubborn.wait().unwrap().signal(),
            Some(nix::sys::signal::Signal::SIGKILL as i32)
        );
        assert!(!next_vault(&mut events).await.mounted);
        assert!(!module.list().vaults[0].mounted);
        assert!(!mount_point.join("secret.txt").exists());

        // The daemon survived, and the vault mounts again.
        assert!(module.mount(target()).await.unwrap().mounted);
        assert_eq!(
            std::fs::read_to_string(mount_point.join("secret.txt")).unwrap(),
            "hello"
        );
        // Nothing mounted: an empty result.
        module.unmount(target()).await.unwrap();
        let result = module.panic().await;
        assert!(
            result.unmounted.is_empty() && result.failed.is_empty(),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn panic_spares_the_compositor_and_unmounts_lazily() {
        if !gocryptfs_available() {
            eprintln!("gocryptfs or /dev/fuse not available; skipping");
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let cipher = work.path().join("c");
        let mount_point = work.path().join("m");
        std::fs::create_dir(&cipher).unwrap();
        init_gocryptfs(&cipher);
        let f = fixture(&format!(
            "[[vault]]\nid = \"w\"\nname = \"W\"\nbackend = \"gocryptfs\"\nsource = \"{}\"\nmount_point = \"{}\"\n",
            cipher.display(),
            mount_point.display()
        ));
        let module = Vaults::start(
            f.hub.clone(),
            f.settings.clone(),
            None,
            env(f.dir.path(), "right", "right"),
        );
        wait_for(&f.hub, ModuleState::Active).await;
        let target = || VaultTarget {
            vault_id: "w".into(),
        };
        assert!(module.mount(target()).await.unwrap().mounted);

        // A copy of sleep called Hyprland, with its cwd in the vault.
        let compositor = work.path().join("Hyprland");
        std::fs::copy(find_in_path("sleep").unwrap(), &compositor).unwrap();
        let mut compositor = std::process::Command::new(&compositor)
            .arg("60")
            .current_dir(&mount_point)
            .spawn()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let result = module.panic().await;
        assert!(result.unmounted.is_empty(), "{result:?}");
        assert_eq!(result.failed.len(), 1, "{result:?}");
        assert_eq!(result.failed[0].vault_id, "w");
        let reason = &result.failed[0].reason;
        assert!(
            reason.contains(&format!("Hyprland (pid {})", compositor.id())),
            "{reason}"
        );
        assert!(reason.contains("lazily"), "{reason}");
        assert!(
            compositor.try_wait().unwrap().is_none(),
            "the compositor was signalled"
        );
        // Detached: gone from the mount table.
        assert!(!module.list().vaults[0].mounted);
        compositor.kill().unwrap();
        compositor.wait().unwrap();
    }

    #[tokio::test]
    async fn panic_closes_an_open_prompt() {
        if !gocryptfs_available() {
            eprintln!("gocryptfs or /dev/fuse not available; skipping");
            return;
        }
        let work = tempfile::tempdir().unwrap();
        let cipher = work.path().join("c");
        std::fs::create_dir(&cipher).unwrap();
        init_gocryptfs(&cipher);
        let f = fixture(&format!(
            "[[vault]]\nid = \"w\"\nname = \"W\"\nbackend = \"gocryptfs\"\nsource = \"{}\"\nmount_point = \"{}\"\n",
            cipher.display(),
            work.path().join("m").display()
        ));
        let module = Vaults::start(
            f.hub.clone(),
            f.settings.clone(),
            None,
            env(f.dir.path(), "HANG", "HANG"),
        );
        wait_for(&f.hub, ModuleState::Active).await;
        let mount = tokio::spawn({
            let module = module.clone();
            async move {
                module
                    .mount(VaultTarget {
                        vault_id: "w".into(),
                    })
                    .await
            }
        });
        let log = f.dir.path().join("pinentry.log");
        for _ in 0..200 {
            if std::fs::read_to_string(&log).is_ok_and(|l| l.contains("GETPIN")) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let result = module.panic().await;
        assert!(result.unmounted.is_empty(), "{result:?}");
        let err = tokio::time::timeout(Duration::from_secs(5), mount)
            .await
            .expect("mount ends when panic runs")
            .unwrap()
            .unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::Cancelled));
        assert!(!module.list().vaults[0].mounted);
    }

    // ------------------------------------------------------- fake udisks2

    const LOOP: &str = "/org/freedesktop/UDisks2/block_devices/loop0";
    const CLEAR: &str = "/org/freedesktop/UDisks2/block_devices/dm_2d0";
    const MEDIA: &str = "/run/media/user/backup";

    #[derive(Default)]
    struct FakeState {
        calls: Vec<String>,
        backing_file: Vec<u8>,
        mounted: bool,
    }

    type Shared = Arc<Mutex<FakeState>>;

    fn path(p: &str) -> OwnedObjectPath {
        OwnedObjectPath::try_from(p).unwrap()
    }

    type Options = HashMap<String, zbus::zvariant::OwnedValue>;

    struct FakeManager(Shared);

    #[zbus::interface(name = "org.freedesktop.UDisks2.Manager")]
    impl FakeManager {
        async fn loop_setup(
            &self,
            fd: zbus::zvariant::OwnedFd,
            _options: Options,
            #[zbus(object_server)] server: &zbus::ObjectServer,
        ) -> zbus::fdo::Result<OwnedObjectPath> {
            use std::os::fd::AsRawFd;
            use std::os::unix::ffi::OsStrExt;
            let file = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
            {
                let mut state = self.0.lock().unwrap();
                state.calls.push("LoopSetup".into());
                state.backing_file = file.as_os_str().as_bytes().to_vec();
                state.backing_file.push(0);
            }
            let shared = self.0.clone();
            server
                .at(
                    LOOP,
                    FakeBlock {
                        device_number: 0x0700,
                        crypto_backing: path("/"),
                    },
                )
                .await?;
            server.at(LOOP, FakeLoop(shared.clone())).await?;
            server.at(LOOP, FakeEncrypted(shared)).await?;
            Ok(path(LOOP))
        }
    }

    struct FakeBlock {
        device_number: u64,
        crypto_backing: OwnedObjectPath,
    }

    #[zbus::interface(name = "org.freedesktop.UDisks2.Block")]
    impl FakeBlock {
        #[zbus(property)]
        fn device_number(&self) -> u64 {
            self.device_number
        }

        #[zbus(property)]
        fn crypto_backing_device(&self) -> OwnedObjectPath {
            self.crypto_backing.clone()
        }
    }

    struct FakeLoop(Shared);

    #[zbus::interface(name = "org.freedesktop.UDisks2.Loop")]
    impl FakeLoop {
        #[zbus(property)]
        fn backing_file(&self) -> Vec<u8> {
            self.0.lock().unwrap().backing_file.clone()
        }

        async fn delete(
            &self,
            _options: Options,
            #[zbus(connection)] conn: &zbus::Connection,
        ) -> zbus::fdo::Result<()> {
            self.0.lock().unwrap().calls.push("Delete".into());
            // This interface is being called; remove the object afterwards.
            let conn = conn.clone();
            tokio::spawn(async move {
                let server = conn.object_server();
                let _ = server.remove::<FakeLoop, _>(LOOP).await;
                let _ = server.remove::<FakeEncrypted, _>(LOOP).await;
                let _ = server.remove::<FakeBlock, _>(LOOP).await;
            });
            Ok(())
        }
    }

    struct FakeEncrypted(Shared);

    #[zbus::interface(name = "org.freedesktop.UDisks2.Encrypted")]
    impl FakeEncrypted {
        async fn unlock(
            &self,
            passphrase: String,
            _options: Options,
            #[zbus(object_server)] server: &zbus::ObjectServer,
        ) -> zbus::fdo::Result<OwnedObjectPath> {
            self.0
                .lock()
                .unwrap()
                .calls
                .push(format!("Unlock:{passphrase}"));
            if passphrase != "right" {
                return Err(zbus::fdo::Error::Failed(format!(
                    "Error unlocking {LOOP}: Failed to activate device: Operation not permitted"
                )));
            }
            server
                .at(
                    CLEAR,
                    FakeBlock {
                        device_number: 0xfe00,
                        crypto_backing: path(LOOP),
                    },
                )
                .await?;
            server.at(CLEAR, FakeFilesystem(self.0.clone())).await?;
            Ok(path(CLEAR))
        }

        async fn lock(
            &self,
            _options: Options,
            #[zbus(object_server)] server: &zbus::ObjectServer,
        ) -> zbus::fdo::Result<()> {
            self.0.lock().unwrap().calls.push("Lock".into());
            server.remove::<FakeFilesystem, _>(CLEAR).await?;
            server.remove::<FakeBlock, _>(CLEAR).await?;
            Ok(())
        }
    }

    struct FakeFilesystem(Shared);

    #[zbus::interface(name = "org.freedesktop.UDisks2.Filesystem")]
    impl FakeFilesystem {
        #[zbus(property)]
        fn mount_points(&self) -> Vec<Vec<u8>> {
            if self.0.lock().unwrap().mounted {
                vec![format!("{MEDIA}\0").into_bytes()]
            } else {
                vec![]
            }
        }

        fn mount(&self, _options: Options) -> String {
            let mut state = self.0.lock().unwrap();
            state.calls.push("Mount".into());
            state.mounted = true;
            MEDIA.into()
        }

        fn unmount(&self, _options: Options) {
            let mut state = self.0.lock().unwrap();
            state.calls.push("Unmount".into());
            state.mounted = false;
        }
    }

    async fn fake_udisks(bus: &Bus, shared: Shared) -> zbus::Connection {
        zbus::connection::Builder::address(bus.address.as_str())
            .unwrap()
            .name(udisks::DEST)
            .unwrap()
            .serve_at("/org/freedesktop/UDisks2", zbus::fdo::ObjectManager)
            .unwrap()
            .serve_at("/org/freedesktop/UDisks2/Manager", FakeManager(shared))
            .unwrap()
            .build()
            .await
            .unwrap()
    }

    fn calls(shared: &Shared) -> Vec<String> {
        std::mem::take(&mut shared.lock().unwrap().calls)
    }

    #[tokio::test]
    async fn luks_vault_through_udisks() {
        let Some(bus) = Bus::start() else {
            eprintln!("dbus-daemon not available; skipping");
            return;
        };
        let shared = Shared::default();
        let _service = fake_udisks(&bus, shared.clone()).await;
        let work = tempfile::tempdir().unwrap();
        let image = work.path().join("backup.img");
        std::fs::write(&image, [0u8; 4096]).unwrap();
        let config = format!(
            "[[vault]]\nid = \"backup\"\nname = \"Backup\"\nbackend = \"luks\"\nsource = \"{}\"\n",
            image.display()
        );
        let target = || VaultTarget {
            vault_id: "backup".into(),
        };

        // Cancelled: the loop device set up for the attempt is deleted again.
        let f = fixture(&config);
        let module = Vaults::start(
            f.hub.clone(),
            f.settings.clone(),
            Some(bus.connect().await),
            env(f.dir.path(), "CANCEL", "CANCEL"),
        );
        wait_for(&f.hub, ModuleState::Active).await;
        let err = module.mount(target()).await.unwrap_err();
        assert_eq!(err.kind(), Some(ErrorCode::Cancelled));
        assert_eq!(calls(&shared), ["LoopSetup", "Delete"]);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let f = fixture(&config);
        let mut events = f.hub.subscribe();
        let module = Vaults::start(
            f.hub.clone(),
            f.settings.clone(),
            Some(bus.connect().await),
            env(f.dir.path(), "wrong", "right"),
        );
        wait_for(&f.hub, ModuleState::Active).await;
        let initial = next_vault(&mut events).await;
        assert!(!initial.mounted);
        assert_eq!(initial.mount_point, "");

        let vault = module.mount(target()).await.unwrap();
        assert!(vault.mounted, "{vault:?}");
        assert_eq!(vault.mount_point, MEDIA);
        assert_eq!(
            calls(&shared),
            ["LoopSetup", "Unlock:wrong", "Unlock:right", "Mount"]
        );
        assert_eq!(next_vault(&mut events).await, vault);
        assert_eq!(module.list().vaults, [vault]);

        let vault = module.unmount(target()).await.unwrap();
        assert!(!vault.mounted);
        assert_eq!(vault.mount_point, "");
        assert_eq!(calls(&shared), ["Unmount", "Lock", "Delete"]);
        assert!(!next_vault(&mut events).await.mounted);

        // Panic unmounts, locks and detaches it the same way.
        assert!(module.mount(target()).await.unwrap().mounted);
        assert!(next_vault(&mut events).await.mounted);
        calls(&shared);
        let result = module.panic().await;
        assert_eq!(result.unmounted, ["backup"], "{result:?}");
        assert_eq!(calls(&shared), ["Unmount", "Lock", "Delete"]);
        assert!(!next_vault(&mut events).await.mounted);
    }
}
