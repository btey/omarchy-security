// SPDX-License-Identifier: GPL-3.0-or-later

//! The daemon configuration (task 2.10, plan §5.4):
//! `$XDG_CONFIG_HOME/omarchy-security/config.toml`, documented in
//! `docs/configuration.md`.
//!
//! A missing file means the defaults. A file that does not parse or
//! validate is logged and ignored: the daemon keeps the configuration it
//! had (the defaults at startup) and never exits over it. `SIGHUP` reloads
//! the file, and modules that care watch [`Settings::subscribe`].
//!
//! `VAULT_ADD` and `VAULT_REMOVE` edit the file through
//! [`Settings::add_vault`] and [`Settings::remove_vault`], which keep its
//! comments and layout, check the result before writing it, and replace
//! the file atomically.

use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use omarchy_security_proto::types::{VaultBackend, Verdict, parse_prefix};
use serde::Deserialize;
use tokio::sync::watch;

pub fn default_path() -> Option<PathBuf> {
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(config.join("omarchy-security/config.toml"))
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    #[serde(rename = "vault")]
    pub vaults: Vec<VaultConfig>,
    pub firewall: FirewallConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// `vault_id` on the wire.
    pub id: String,
    pub name: String,
    pub backend: VaultBackend,
    /// The gocryptfs cipher directory, or the LUKS image file or block
    /// device. Absolute once loaded (`~` is expanded).
    pub source: PathBuf,
    /// gocryptfs only; udisks2 chooses the mount point of a LUKS vault.
    #[serde(default)]
    pub mount_point: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallConfig {
    /// Interactive connection prompts (2.14).
    pub prompt: bool,
    pub prompt_timeout_secs: u64,
    /// Applied to a held connection nobody answered in time.
    pub timeout_verdict: Verdict,
    pub alerts: AlertsConfig,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            prompt: false,
            prompt_timeout_secs: 30,
            timeout_verdict: Verdict::Block,
            alerts: AlertsConfig::default(),
        }
    }
}

/// Blocked-traffic alerts (2.20, plan §5.19) and temporary decisions
/// (2.21, §5.20).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AlertsConfig {
    /// Desktop notifications. Alerts still reach clients when this is off.
    pub notify: bool,
    /// Repeats of the same alert within this window are grouped.
    pub window_secs: u64,
    pub max_notifications_per_minute: u32,
    /// Drops multicast and broadcast destinations and IGMP.
    pub ignore_multicast: bool,
    pub ignore: Vec<AlertIgnore>,
    /// The durations offered for temporary allow and block decisions.
    pub temp_durations_secs: Vec<u64>,
}

impl Default for AlertsConfig {
    fn default() -> Self {
        Self {
            notify: true,
            window_secs: 600,
            max_notifications_per_minute: 3,
            ignore_multicast: true,
            ignore: Vec::new(),
            temp_durations_secs: vec![300, 3600, 28800],
        }
    }
}

/// Blocked packets matching every field given here raise no alert.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertIgnore {
    #[serde(default)]
    pub protocol: Option<AlertProtocol>,
    /// The local port: the destination of an inbound packet, the source of
    /// an outbound one.
    #[serde(default)]
    pub port: Option<u16>,
    /// The remote address, an IP or CIDR prefix.
    #[serde(default)]
    pub address: Option<String>,
}

/// The protocols a kernel log line can name, as `PROTO=` spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Igmp,
}

/// Bounds of `temp_durations_secs`, the same as `FIREWALL_TEMP_ADD`'s
/// `duration_secs` (plan §5.20).
pub const TEMP_DURATION_SECS: std::ops::RangeInclusive<u64> = 60..=86_400;
const PROMPT_TIMEOUT_SECS: std::ops::RangeInclusive<u64> = 5..=300;
const WINDOW_SECS: std::ops::RangeInclusive<u64> = 10..=86_400;
const MAX_NOTIFICATIONS_PER_MINUTE: std::ops::RangeInclusive<u32> = 1..=60;
const VAULT_ID_MAX: usize = 64;

impl Config {
    /// Parses and validates a configuration file's text. `home` expands a
    /// leading `~` in paths.
    pub fn parse(text: &str, home: Option<&Path>) -> Result<Self, String> {
        let mut config: Config = toml::from_str(text).map_err(|e| e.to_string())?;
        config.validate(home)?;
        Ok(config)
    }

    /// Reads `path`, or returns the defaults if it does not exist.
    pub fn load(path: &Path, home: Option<&Path>) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text, home),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err.to_string()),
        }
    }

    fn validate(&mut self, home: Option<&Path>) -> Result<(), String> {
        let mut ids = HashSet::new();
        let mut mount_points = HashSet::new();
        for vault in &mut self.vaults {
            let id = vault.id.clone();
            if id.is_empty()
                || id.len() > VAULT_ID_MAX
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(format!(
                    "vault id '{id}' must be 1 to {VAULT_ID_MAX} characters of a-z, 0-9 and -"
                ));
            }
            if !ids.insert(id.clone()) {
                return Err(format!("vault id '{id}' is defined twice"));
            }
            if vault.name.trim().is_empty() {
                return Err(format!("vault '{id}': name is empty"));
            }
            vault.source =
                expand(&vault.source, home).map_err(|e| format!("vault '{id}': source {e}"))?;
            match (vault.backend, &vault.mount_point) {
                (VaultBackend::Gocryptfs, None) => {
                    return Err(format!("vault '{id}': a gocryptfs vault needs mount_point"));
                }
                (VaultBackend::Luks, Some(_)) => {
                    return Err(format!(
                        "vault '{id}': mount_point is for gocryptfs only; udisks2 chooses it for luks"
                    ));
                }
                (VaultBackend::Gocryptfs, Some(mount_point)) => {
                    let mount_point = expand(mount_point, home)
                        .map_err(|e| format!("vault '{id}': mount_point {e}"))?;
                    if mount_point == vault.source {
                        return Err(format!("vault '{id}': mount_point is the same as source"));
                    }
                    if !mount_points.insert(mount_point.clone()) {
                        return Err(format!(
                            "vault '{id}': mount_point {} is used by another vault",
                            mount_point.display()
                        ));
                    }
                    vault.mount_point = Some(mount_point);
                }
                (VaultBackend::Luks, None) => {}
            }
        }

        let firewall = &self.firewall;
        in_range(
            "firewall.prompt_timeout_secs",
            firewall.prompt_timeout_secs,
            &PROMPT_TIMEOUT_SECS,
        )?;
        let alerts = &firewall.alerts;
        in_range(
            "firewall.alerts.window_secs",
            alerts.window_secs,
            &WINDOW_SECS,
        )?;
        in_range(
            "firewall.alerts.max_notifications_per_minute",
            alerts.max_notifications_per_minute,
            &MAX_NOTIFICATIONS_PER_MINUTE,
        )?;
        for (i, rule) in alerts.ignore.iter().enumerate() {
            if rule.protocol.is_none() && rule.port.is_none() && rule.address.is_none() {
                return Err(format!(
                    "firewall.alerts.ignore[{i}] needs at least one of protocol, port, address"
                ));
            }
            if let Some(address) = &rule.address {
                parse_prefix(address).map_err(|e| format!("firewall.alerts.ignore[{i}]: {e}"))?;
            }
        }
        if alerts.temp_durations_secs.is_empty() {
            return Err("firewall.alerts.temp_durations_secs is empty".into());
        }
        for &secs in &alerts.temp_durations_secs {
            in_range(
                "firewall.alerts.temp_durations_secs",
                secs,
                &TEMP_DURATION_SECS,
            )?;
        }
        Ok(())
    }
}

fn in_range<T: PartialOrd + std::fmt::Display>(
    key: &str,
    value: T,
    range: &std::ops::RangeInclusive<T>,
) -> Result<(), String> {
    if range.contains(&value) {
        Ok(())
    } else {
        Err(format!(
            "{key} is {value}, outside {}..={}",
            range.start(),
            range.end()
        ))
    }
}

/// Expands a leading `~` and requires the result to be absolute.
fn expand(path: &Path, home: Option<&Path>) -> Result<PathBuf, String> {
    let expanded = match path.strip_prefix("~") {
        Ok(rest) => home
            .ok_or_else(|| format!("{}: HOME is not set", path.display()))?
            .join(rest),
        Err(_) => path.to_path_buf(),
    };
    if expanded.is_absolute() {
        Ok(expanded)
    } else {
        Err(format!(
            "{} must be absolute or start with ~/",
            path.display()
        ))
    }
}

/// A vault to append to the file, as the user wrote it: paths may still
/// start with `~/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewVault {
    pub id: String,
    pub name: String,
    pub backend: VaultBackend,
    pub source: String,
    pub mount_point: Option<String>,
}

/// Why the file was not changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    /// The change would make the configuration invalid.
    Rejected(String),
    /// No vault has that id.
    NotFound(String),
    /// The file could not be read or written, or is invalid already.
    Failed(String),
}

/// The loaded configuration, and the file it came from.
pub struct Settings {
    path: Option<PathBuf>,
    home: Option<PathBuf>,
    tx: watch::Sender<Arc<Config>>,
    /// Serializes edits of the file.
    editing: Mutex<()>,
}

impl Settings {
    /// Loads `path` once. An error is logged, and the defaults are used.
    pub fn load(path: Option<PathBuf>) -> Self {
        let settings = Self {
            path,
            home: std::env::var_os("HOME").map(PathBuf::from),
            tx: watch::Sender::new(Arc::new(Config::default())),
            editing: Mutex::new(()),
        };
        match &settings.path {
            Some(_) => {
                settings.reload();
            }
            None => tracing::warn!(
                "no configuration path: XDG_CONFIG_HOME and HOME are unset; using defaults"
            ),
        }
        settings
    }

    pub fn current(&self) -> Arc<Config> {
        self.tx.borrow().clone()
    }

    /// Changes whenever a reload produces a different configuration.
    pub fn subscribe(&self) -> watch::Receiver<Arc<Config>> {
        self.tx.subscribe()
    }

    /// Reads the file again. On an error, keeps the current configuration
    /// and returns false.
    pub fn reload(&self) -> bool {
        let Some(path) = &self.path else {
            return true;
        };
        match Config::load(path, self.home.as_deref()) {
            Ok(config) => {
                let changed = self.tx.send_if_modified(|current| {
                    if **current == config {
                        return false;
                    }
                    *current = Arc::new(config);
                    true
                });
                let config = self.current();
                tracing::info!(
                    path = %path.display(),
                    changed,
                    vaults = config.vaults.len(),
                    prompts = config.firewall.prompt,
                    "configuration loaded"
                );
                true
            }
            Err(err) => {
                tracing::error!(
                    path = %path.display(),
                    "invalid configuration, keeping the previous one: {err}"
                );
                false
            }
        }
    }
}

impl Settings {
    /// Expands a leading `~` the way the file's paths are, and requires the
    /// result to be absolute.
    pub fn expand(&self, path: &str) -> Result<PathBuf, String> {
        expand(Path::new(path), self.home.as_deref())
    }

    /// Appends a `[[vault]]` table to the file, then reloads it.
    pub fn add_vault(&self, vault: &NewVault) -> Result<(), EditError> {
        self.append_vault(vault, true)
    }

    /// Whether [`Settings::add_vault`] would accept `vault` now, without
    /// writing anything.
    pub fn check_vault(&self, vault: &NewVault) -> Result<(), EditError> {
        self.append_vault(vault, false)
    }

    fn append_vault(&self, vault: &NewVault, write: bool) -> Result<(), EditError> {
        self.edit(write, |doc| {
            let mut table = toml_edit::Table::new();
            table["id"] = toml_edit::value(vault.id.as_str());
            table["name"] = toml_edit::value(vault.name.as_str());
            table["backend"] = toml_edit::value(match vault.backend {
                VaultBackend::Gocryptfs => "gocryptfs",
                VaultBackend::Luks => "luks",
            });
            table["source"] = toml_edit::value(vault.source.as_str());
            if let Some(mount_point) = &vault.mount_point {
                table["mount_point"] = toml_edit::value(mount_point.as_str());
            }
            // At the end of the file, after any comments there, and set off
            // by a blank line.
            let mut prefix = doc.trailing().as_str().unwrap_or("").to_owned();
            doc.set_trailing("");
            if !(prefix.is_empty() && doc.is_empty()) && !prefix.ends_with("\n\n") {
                prefix.push('\n');
            }
            table.decor_mut().set_prefix(prefix);
            match doc.get_mut("vault") {
                None => {
                    let mut vaults = toml_edit::ArrayOfTables::new();
                    vaults.push(table);
                    doc.insert("vault", toml_edit::Item::ArrayOfTables(vaults));
                }
                Some(toml_edit::Item::ArrayOfTables(vaults)) => vaults.push(table),
                Some(toml_edit::Item::Value(toml_edit::Value::Array(vaults))) => {
                    vaults.push(table.into_inline_table());
                }
                Some(_) => return Err(EditError::Failed("vault is not an array of tables".into())),
            }
            Ok(())
        })
    }

    /// Removes the `[[vault]]` table whose `id` is `id`, then reloads the
    /// file.
    pub fn remove_vault(&self, id: &str) -> Result<(), EditError> {
        let not_found = || EditError::NotFound(format!("no vault with id '{id}'"));
        self.edit(true, |doc| {
            let empty = match doc.get_mut("vault") {
                Some(toml_edit::Item::ArrayOfTables(vaults)) => {
                    let index = vaults
                        .iter()
                        .position(|t| t.get("id").and_then(|v| v.as_str()) == Some(id))
                        .ok_or_else(not_found)?;
                    // The comments above the first table are usually about
                    // all of them: keep them for the new first one.
                    let prefix = vaults.get(index).and_then(|t| t.decor().prefix().cloned());
                    vaults.remove(index);
                    if let (0, Some(prefix), Some(first)) = (index, prefix, vaults.get_mut(0)) {
                        first.decor_mut().set_prefix(prefix);
                    }
                    vaults.is_empty()
                }
                Some(toml_edit::Item::Value(toml_edit::Value::Array(vaults))) => {
                    let index = vaults
                        .iter()
                        .position(|v| {
                            v.as_inline_table()
                                .and_then(|t| t.get("id"))
                                .and_then(|v| v.as_str())
                                == Some(id)
                        })
                        .ok_or_else(not_found)?;
                    vaults.remove(index);
                    vaults.is_empty()
                }
                _ => return Err(not_found()),
            };
            if empty {
                doc.remove("vault");
            }
            Ok(())
        })
    }

    /// Applies `change` to the file and reloads it, if the result is a
    /// valid configuration; with `write` false, only checks that it would
    /// be. The file must be valid to begin with: an edit never starts from
    /// the defaults the daemon fell back to.
    fn edit(
        &self,
        write: bool,
        change: impl FnOnce(&mut toml_edit::DocumentMut) -> Result<(), EditError>,
    ) -> Result<(), EditError> {
        let _editing = self.editing.lock().expect("settings lock");
        let path = self.path.as_deref().ok_or_else(|| {
            EditError::Failed("no configuration path: XDG_CONFIG_HOME and HOME are unset".into())
        })?;
        // Replace what a symlink points to, not the link: the file may live
        // in a dotfiles repository.
        let target = match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => std::fs::canonicalize(path)
                .map_err(|e| EditError::Failed(format!("{}: {e}", path.display())))?,
            _ => path.to_path_buf(),
        };
        let text = match std::fs::read_to_string(&target) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(err) => return Err(EditError::Failed(format!("{}: {err}", target.display()))),
        };
        Config::parse(&text, self.home.as_deref()).map_err(|e| {
            EditError::Failed(format!("{} is invalid, fix it first: {e}", path.display()))
        })?;
        let mut doc: toml_edit::DocumentMut = text
            .parse()
            .map_err(|e| EditError::Failed(format!("{}: {e}", path.display())))?;
        change(&mut doc)?;
        let text = doc.to_string();
        Config::parse(&text, self.home.as_deref()).map_err(EditError::Rejected)?;
        if !write {
            return Ok(());
        }
        write_atomically(&target, &text)
            .map_err(|e| EditError::Failed(format!("writing {}: {e}", target.display())))?;
        if self.reload() {
            Ok(())
        } else {
            Err(EditError::Failed(format!(
                "{} changed while it was being written",
                path.display()
            )))
        }
    }
}

/// Replaces `path` with `text` through a temporary file in the same
/// directory, keeping the file's permissions (0600 for a new one).
fn write_atomically(path: &Path, text: &str) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("the path has no directory"))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let mode = match std::fs::metadata(path) {
        Ok(meta) => meta.permissions().mode() & 0o7777,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0o600,
        Err(err) => return Err(err),
    };
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        file.set_permissions(std::fs::Permissions::from_mode(mode))?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/home/user";

    fn parse(text: &str) -> Result<Config, String> {
        Config::parse(text, Some(Path::new(HOME)))
    }

    #[test]
    fn empty_file_is_the_defaults() {
        let config = parse("").unwrap();
        assert_eq!(config, Config::default());
        assert!(!config.firewall.prompt);
        assert_eq!(config.firewall.prompt_timeout_secs, 30);
        assert_eq!(config.firewall.timeout_verdict, Verdict::Block);
        assert_eq!(
            config.firewall.alerts.temp_durations_secs,
            [300, 3600, 28800]
        );
    }

    #[test]
    fn sample_file_parses() {
        let text = include_str!("../../../dist/config.example.toml");
        let config = parse(text).unwrap();
        assert_eq!(config.vaults.len(), 2);
        let work = &config.vaults[0];
        assert_eq!(work.id, "work");
        assert_eq!(work.backend, VaultBackend::Gocryptfs);
        assert_eq!(work.source, Path::new("/home/user/Vaults/work.enc"));
        assert_eq!(
            work.mount_point.as_deref(),
            Some(Path::new("/home/user/Vaults/work"))
        );
        assert_eq!(config.vaults[1].backend, VaultBackend::Luks);
        assert_eq!(config.vaults[1].mount_point, None);
        assert_eq!(
            config.firewall.alerts.ignore,
            [AlertIgnore {
                protocol: Some(AlertProtocol::Udp),
                port: Some(137),
                address: None,
            }]
        );
    }

    #[test]
    fn rejects_unknown_keys_and_bad_values() {
        for (text, needle) in [
            ("bogus = 1", "unknown field"),
            ("[firewall]\nprompts = true", "unknown field"),
            ("[firewall.alerts]\nnotfy = false", "unknown field"),
            ("[firewall]\ntimeout_verdict = \"drop\"", "unknown variant"),
            ("[firewall]\nprompt_timeout_secs = 0", "prompt_timeout_secs"),
            ("[firewall.alerts]\nwindow_secs = 1", "window_secs"),
            (
                "[firewall.alerts]\nmax_notifications_per_minute = 0",
                "max_notifications",
            ),
            ("[firewall.alerts]\ntemp_durations_secs = []", "empty"),
            (
                "[firewall.alerts]\ntemp_durations_secs = [30]",
                "outside 60..=86400",
            ),
            ("[firewall.alerts]\nignore = [{}]", "at least one"),
            (
                "[firewall.alerts]\nignore = [{address = \"host\"}]",
                "not an IP",
            ),
            ("[firewall.alerts]\nignore = [{port = 70000}]", "port"),
            (
                "[firewall.alerts]\nignore = [{protocol = \"sctp\"}]",
                "unknown variant",
            ),
        ] {
            let err = parse(text).unwrap_err();
            assert!(err.contains(needle), "{text:?}: {err}");
        }
    }

    fn vault(fields: &str) -> Result<Config, String> {
        parse(&format!("[[vault]]\nname = \"V\"\n{fields}"))
    }

    #[test]
    fn validates_vaults() {
        for (fields, needle) in [
            (
                "id = \"Work\"\nbackend = \"luks\"\nsource = \"/dev/sda1\"",
                "a-z, 0-9",
            ),
            (
                "id = \"\"\nbackend = \"luks\"\nsource = \"/dev/sda1\"",
                "a-z, 0-9",
            ),
            (
                "id = \"a\"\nbackend = \"gocryptfs\"\nsource = \"/x\"",
                "needs mount_point",
            ),
            (
                "id = \"a\"\nbackend = \"luks\"\nsource = \"/x\"\nmount_point = \"/y\"",
                "gocryptfs only",
            ),
            (
                "id = \"a\"\nbackend = \"luks\"\nsource = \"Vaults/x\"",
                "must be absolute",
            ),
            (
                "id = \"a\"\nbackend = \"gocryptfs\"\nsource = \"~/x\"\nmount_point = \"/home/user/x\"",
                "same as source",
            ),
            (
                "id = \"a\"\nbackend = \"zfs\"\nsource = \"/x\"",
                "unknown variant",
            ),
            ("id = \"a\"\nsource = \"/x\"", "missing field"),
        ] {
            let err = vault(fields).unwrap_err();
            assert!(err.contains(needle), "{fields:?}: {err}");
        }

        let twice = "[[vault]]\nid = \"a\"\nname = \"A\"\nbackend = \"luks\"\nsource = \"/x\"\n\
                     [[vault]]\nid = \"a\"\nname = \"B\"\nbackend = \"luks\"\nsource = \"/y\"";
        assert!(parse(twice).unwrap_err().contains("defined twice"));

        let shared = "[[vault]]\nid = \"a\"\nname = \"A\"\nbackend = \"gocryptfs\"\nsource = \"/x\"\nmount_point = \"/m\"\n\
                      [[vault]]\nid = \"b\"\nname = \"B\"\nbackend = \"gocryptfs\"\nsource = \"/y\"\nmount_point = \"/m\"";
        assert!(parse(shared).unwrap_err().contains("another vault"));

        let err = Config::parse(
            "[[vault]]\nid = \"a\"\nname = \"A\"\nbackend = \"luks\"\nsource = \"~/x\"",
            None,
        )
        .unwrap_err();
        assert!(err.contains("HOME is not set"), "{err}");
    }

    #[test]
    fn missing_file_is_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config::load(&dir.path().join("config.toml"), None).unwrap();
        assert_eq!(config, Config::default());
    }

    #[test]
    fn reload_keeps_the_previous_configuration_on_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[firewall]\nprompt = true\n").unwrap();
        let settings = Settings::load(Some(path.clone()));
        let mut rx = settings.subscribe();
        assert!(settings.current().firewall.prompt);

        std::fs::write(&path, "[firewall]\nprompt = maybe\n").unwrap();
        assert!(!settings.reload());
        assert!(settings.current().firewall.prompt);
        assert!(!rx.has_changed().unwrap());

        // Reloading an unchanged file does not wake subscribers.
        std::fs::write(&path, "[firewall]\nprompt = true\n").unwrap();
        assert!(settings.reload());
        assert!(!rx.has_changed().unwrap());

        std::fs::write(&path, "[firewall]\nprompt = false\n").unwrap();
        assert!(settings.reload());
        assert!(rx.has_changed().unwrap());
        assert!(!rx.borrow_and_update().firewall.prompt);

        std::fs::remove_file(&path).unwrap();
        assert!(settings.reload());
        assert_eq!(*settings.current(), Config::default());
    }

    #[test]
    fn an_invalid_file_at_startup_means_the_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[[vault]]\nid = 1\n").unwrap();
        let settings = Settings::load(Some(path));
        assert_eq!(*settings.current(), Config::default());
    }

    fn new_vault(id: &str) -> NewVault {
        NewVault {
            id: id.into(),
            name: format!("Vault {id}"),
            backend: VaultBackend::Gocryptfs,
            source: format!("~/Vaults/{id}.enc"),
            mount_point: Some(format!("~/Vaults/{id}")),
        }
    }

    #[test]
    fn adding_a_vault_keeps_the_rest_of_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = "# My settings\n[firewall]\nprompt = true # ask me\n";
        std::fs::write(&path, original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let settings = Settings::load(Some(path.clone()));
        let rx = settings.subscribe();

        settings.add_vault(&new_vault("work")).unwrap();
        let luks = NewVault {
            backend: VaultBackend::Luks,
            source: "/dev/disk/by-uuid/1234".into(),
            mount_point: None,
            ..new_vault("disk")
        };
        settings.add_vault(&luks).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(original), "{text}");
        assert!(text.contains("source = \"~/Vaults/work.enc\""), "{text}");
        assert!(rx.has_changed().unwrap());
        let config = settings.current();
        assert!(config.firewall.prompt);
        let ids: Vec<_> = config.vaults.iter().map(|v| v.id.as_str()).collect();
        assert_eq!(ids, ["work", "disk"]);
        assert_eq!(config.vaults[1].mount_point, None);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        // No temporary file is left behind.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn adding_creates_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("omarchy-security/config.toml");
        let settings = Settings::load(Some(path.clone()));
        settings.add_vault(&new_vault("a")).unwrap();
        assert_eq!(settings.current().vaults.len(), 1);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn an_invalid_vault_leaves_the_file_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        let settings = Settings::load(Some(path.clone()));
        settings.add_vault(&new_vault("a")).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();

        for (vault, needle) in [
            (new_vault("a"), "defined twice"),
            (new_vault("Bad Id"), "a-z, 0-9"),
            (
                NewVault {
                    mount_point: None,
                    ..new_vault("b")
                },
                "needs mount_point",
            ),
            (
                NewVault {
                    mount_point: Some("~/Vaults/a".into()),
                    ..new_vault("b")
                },
                "another vault",
            ),
            (
                NewVault {
                    source: "Vaults/b".into(),
                    ..new_vault("b")
                },
                "must be absolute",
            ),
        ] {
            match settings.add_vault(&vault) {
                Err(EditError::Rejected(err)) => assert!(err.contains(needle), "{vault:?}: {err}"),
                other => panic!("{vault:?}: {other:?}"),
            }
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    #[test]
    fn checking_a_vault_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let settings = Settings::load(Some(path.clone()));
        settings.check_vault(&new_vault("a")).unwrap();
        assert!(!path.exists());
        settings.add_vault(&new_vault("a")).unwrap();
        let before = std::fs::read_to_string(&path).unwrap();
        assert!(matches!(
            settings.check_vault(&new_vault("a")),
            Err(EditError::Rejected(e)) if e.contains("defined twice")
        ));
        settings.check_vault(&new_vault("b")).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        assert_eq!(settings.current().vaults.len(), 1);
    }

    #[test]
    fn an_invalid_file_is_not_edited() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[firewall]\nprompt = maybe\n").unwrap();
        let settings = Settings::load(Some(path.clone()));
        match settings.add_vault(&new_vault("a")) {
            Err(EditError::Failed(err)) => assert!(err.contains("fix it first"), "{err}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "[firewall]\nprompt = maybe\n"
        );
    }

    #[test]
    fn removing_a_vault_keeps_the_others() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let text = include_str!("../../../dist/config.example.toml");
        std::fs::write(&path, text).unwrap();
        let settings = Settings::load(Some(path.clone()));

        assert_eq!(
            settings.remove_vault("nope"),
            Err(EditError::NotFound("no vault with id 'nope'".into()))
        );
        settings.remove_vault("work").unwrap();
        let ids: Vec<_> = settings
            .current()
            .vaults
            .iter()
            .map(|v| v.id.clone())
            .collect();
        assert_eq!(ids, ["backup"]);
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("[firewall.alerts]"), "{after}");
        assert!(after.contains("# Encrypted vaults"), "{after}");

        settings.remove_vault("backup").unwrap();
        assert!(settings.current().vaults.is_empty());
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(!after.contains("[[vault]]"), "{after}");
        assert_eq!(settings.current().firewall, parse(text).unwrap().firewall);
    }

    #[test]
    fn inline_vault_arrays_are_edited_too() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "vault = [{ id = \"a\", name = \"A\", backend = \"luks\", source = \"/dev/sda1\" }]\n",
        )
        .unwrap();
        let settings = Settings::load(Some(path.clone()));
        settings.add_vault(&new_vault("b")).unwrap();
        assert_eq!(settings.current().vaults.len(), 2);
        settings.remove_vault("a").unwrap();
        settings.remove_vault("b").unwrap();
        assert!(settings.current().vaults.is_empty());
    }

    #[test]
    fn a_symlinked_file_stays_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("dotfiles/config.toml");
        std::fs::create_dir(dir.path().join("dotfiles")).unwrap();
        std::fs::write(&real, "").unwrap();
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let settings = Settings::load(Some(link.clone()));
        settings.add_vault(&new_vault("a")).unwrap();
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            std::fs::read_to_string(&real)
                .unwrap()
                .contains("[[vault]]")
        );
    }
}
