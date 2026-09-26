// SPDX-License-Identifier: GPL-3.0-or-later

//! LUKS vaults through udisks2 on the system bus (plan §5.5).
//!
//! udisks2's polkit defaults let an active local session set up a loop
//! device for a file it can open, unlock it and mount the cleartext
//! device, so none of this needs the helper. The vault's state is read
//! from udisks2's object tree: the loop device backed by the image file (or
//! the block device itself), the cleartext device whose
//! `CryptoBackingDevice` points at it, and that device's mount points.

use std::collections::HashMap;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;
use zbus::proxy::{CacheProperties, MethodFlags};
use zbus::zvariant::{DynamicType, Fd, ObjectPath, OwnedObjectPath, OwnedValue, Value};

pub const DEST: &str = "org.freedesktop.UDisks2";
const ROOT: &str = "/org/freedesktop/UDisks2";
const MANAGER: &str = "/org/freedesktop/UDisks2/Manager";
const IFACE_MANAGER: &str = "org.freedesktop.UDisks2.Manager";
const IFACE_BLOCK: &str = "org.freedesktop.UDisks2.Block";
const IFACE_LOOP: &str = "org.freedesktop.UDisks2.Loop";
const IFACE_ENCRYPTED: &str = "org.freedesktop.UDisks2.Encrypted";
const IFACE_FILESYSTEM: &str = "org.freedesktop.UDisks2.Filesystem";

/// A udisks2 block device, reduced to what vaults need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub path: OwnedObjectPath,
    pub device_number: u64,
    /// The device this one is the cleartext of.
    pub crypto_backing: Option<OwnedObjectPath>,
    /// Set for a loop device.
    pub backing_file: Option<PathBuf>,
    pub encrypted: bool,
    /// Set when the device holds a filesystem udisks2 can mount.
    pub mount_points: Option<Vec<PathBuf>>,
}

/// Where a vault's container lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// An image file, with symlinks resolved.
    File(PathBuf),
    /// A block device, by device number.
    Device(u64),
}

impl Source {
    pub fn resolve(path: &Path) -> std::io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        if meta.file_type().is_block_device() {
            Ok(Self::Device(meta.rdev()))
        } else if meta.is_file() {
            Ok(Self::File(std::fs::canonicalize(path)?))
        } else {
            Err(std::io::Error::other("not a regular file or block device"))
        }
    }
}

/// A vault's devices, as udisks2 currently has them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Luks {
    /// The loop device or block device holding the LUKS container.
    pub backing: Option<Block>,
    pub cleartext: Option<Block>,
}

impl Luks {
    pub fn find(blocks: &[Block], source: &Source) -> Self {
        let backing = blocks
            .iter()
            .find(|b| match source {
                Source::File(file) => b.backing_file.as_deref() == Some(file),
                Source::Device(number) => b.device_number == *number,
            })
            .cloned();
        let cleartext = backing.as_ref().and_then(|backing| {
            blocks
                .iter()
                .find(|b| b.crypto_backing.as_ref() == Some(&backing.path))
                .cloned()
        });
        Self { backing, cleartext }
    }

    pub fn mount_point(&self) -> Option<&Path> {
        self.cleartext
            .as_ref()?
            .mount_points
            .as_ref()?
            .first()
            .map(PathBuf::as_path)
    }
}

/// Every block device udisks2 knows.
pub async fn blocks(conn: &zbus::Connection) -> zbus::Result<Vec<Block>> {
    let manager = zbus::fdo::ObjectManagerProxy::builder(conn)
        .destination(DEST)?
        .path(ROOT)?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    let objects = manager.get_managed_objects().await?;
    Ok(objects
        .into_iter()
        .filter_map(|(path, interfaces)| {
            let props = |name: &str| {
                interfaces
                    .iter()
                    .find(|(i, _)| i.as_str() == name)
                    .map(|(_, p)| p)
            };
            let block = props(IFACE_BLOCK)?;
            let crypto_backing =
                get::<OwnedObjectPath>(block, "CryptoBackingDevice").filter(|p| p.as_str() != "/");
            Some(Block {
                path,
                device_number: get::<u64>(block, "DeviceNumber").unwrap_or(0),
                crypto_backing,
                backing_file: props(IFACE_LOOP)
                    .and_then(|l| get::<Vec<u8>>(l, "BackingFile"))
                    .map(bytes_path),
                encrypted: props(IFACE_ENCRYPTED).is_some(),
                mount_points: props(IFACE_FILESYSTEM).map(|f| {
                    get::<Vec<Vec<u8>>>(f, "MountPoints")
                        .unwrap_or_default()
                        .into_iter()
                        .map(bytes_path)
                        .collect()
                }),
            })
        })
        .collect())
}

fn get<T>(props: &HashMap<String, OwnedValue>, name: &str) -> Option<T>
where
    T: TryFrom<OwnedValue>,
{
    T::try_from(props.get(name)?.try_clone().ok()?).ok()
}

/// udisks2 sends paths as NUL-terminated byte strings.
fn bytes_path(mut bytes: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    PathBuf::from(std::ffi::OsString::from_vec(bytes))
}

fn no_options() -> HashMap<&'static str, Value<'static>> {
    HashMap::new()
}

async fn call<B, R>(
    conn: &zbus::Connection,
    path: &ObjectPath<'_>,
    interface: &str,
    method: &str,
    body: &B,
) -> zbus::Result<R>
where
    B: Serialize + DynamicType,
    R: DeserializeOwned + zbus::zvariant::Type,
{
    let proxy = zbus::proxy::Builder::<zbus::Proxy<'_>>::new(conn)
        .destination(DEST)?
        .path(path.to_owned())?
        .interface(interface.to_owned())?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    // Interactive auth lets a polkit agent ask, should the local policy
    // require it.
    proxy
        .call_with_flags(method, MethodFlags::AllowInteractiveAuth.into(), body)
        .await?
        .ok_or_else(|| zbus::Error::Failure(format!("{method}: no reply")))
}

/// Sets up a loop device for an image file and returns it.
pub async fn loop_setup(conn: &zbus::Connection, file: &Path) -> zbus::Result<OwnedObjectPath> {
    // Read-write if we may; udisks2 needs `read-only` otherwise.
    let (image, read_only) = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(file)
    {
        Ok(image) => (image, false),
        Err(_) => (
            std::fs::File::open(file)
                .map_err(|e| zbus::Error::Failure(format!("{}: {e}", file.display())))?,
            true,
        ),
    };
    let mut options = no_options();
    if read_only {
        options.insert("read-only", Value::from(true));
    }
    let root = ObjectPath::from_static_str_unchecked(MANAGER);
    call(
        conn,
        &root,
        IFACE_MANAGER,
        "LoopSetup",
        &(Fd::from(image.as_fd()), options),
    )
    .await
}

pub async fn unlock(
    conn: &zbus::Connection,
    backing: &ObjectPath<'_>,
    passphrase: &str,
) -> zbus::Result<OwnedObjectPath> {
    call(
        conn,
        backing,
        IFACE_ENCRYPTED,
        "Unlock",
        &(passphrase, no_options()),
    )
    .await
}

pub async fn mount(conn: &zbus::Connection, cleartext: &ObjectPath<'_>) -> zbus::Result<String> {
    call(conn, cleartext, IFACE_FILESYSTEM, "Mount", &(no_options(),)).await
}

/// With `force`, udisks2 unmounts lazily (`umount -l`) when the filesystem
/// is busy.
pub async fn unmount(
    conn: &zbus::Connection,
    cleartext: &ObjectPath<'_>,
    force: bool,
) -> zbus::Result<()> {
    let mut options = no_options();
    if force {
        options.insert("force", Value::from(true));
    }
    call(conn, cleartext, IFACE_FILESYSTEM, "Unmount", &(options,)).await
}

pub async fn lock(conn: &zbus::Connection, backing: &ObjectPath<'_>) -> zbus::Result<()> {
    call(conn, backing, IFACE_ENCRYPTED, "Lock", &(no_options(),)).await
}

pub async fn loop_delete(conn: &zbus::Connection, device: &ObjectPath<'_>) -> zbus::Result<()> {
    call(conn, device, IFACE_LOOP, "Delete", &(no_options(),)).await
}

/// Whether udisks2 runs, or can be started, on `conn`.
pub async fn available(conn: &zbus::Connection) -> bool {
    let Ok(dbus) = zbus::fdo::DBusProxy::new(conn).await else {
        return false;
    };
    let Ok(name) = zbus::names::BusName::from_static_str(DEST) else {
        return false;
    };
    if dbus.name_has_owner(name).await.unwrap_or(false) {
        return true;
    }
    dbus.list_activatable_names()
        .await
        .map(|names| names.iter().any(|n| n.as_str() == DEST))
        .unwrap_or(false)
}

/// Whether an `Unlock` error means the passphrase was wrong. cryptsetup
/// reports that as `EPERM`, and udisks2 passes on its message.
pub fn is_bad_passphrase(err: &zbus::Error) -> bool {
    let text = err.to_string();
    text.contains("Operation not permitted") || text.contains("No key available")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(path: &str) -> Block {
        Block {
            path: OwnedObjectPath::try_from(path).unwrap(),
            device_number: 0,
            crypto_backing: None,
            backing_file: None,
            encrypted: false,
            mount_points: None,
        }
    }

    #[test]
    fn finds_backing_and_cleartext() {
        let mut image_loop = block("/org/freedesktop/UDisks2/block_devices/loop0");
        image_loop.backing_file = Some("/home/u/v.img".into());
        image_loop.encrypted = true;
        let mut disk = block("/org/freedesktop/UDisks2/block_devices/sda1");
        disk.device_number = 0x801;
        disk.encrypted = true;
        let mut clear = block("/org/freedesktop/UDisks2/block_devices/dm_2d0");
        clear.crypto_backing = Some(image_loop.path.clone());
        clear.mount_points = Some(vec!["/run/media/u/v".into()]);
        let blocks = [disk.clone(), clear.clone(), image_loop.clone()];

        let luks = Luks::find(&blocks, &Source::File("/home/u/v.img".into()));
        assert_eq!(luks.backing, Some(image_loop));
        assert_eq!(luks.cleartext, Some(clear));
        assert_eq!(luks.mount_point(), Some(Path::new("/run/media/u/v")));

        let luks = Luks::find(&blocks, &Source::Device(0x801));
        assert_eq!(luks.backing, Some(disk));
        assert_eq!(luks.cleartext, None);
        assert_eq!(luks.mount_point(), None);

        assert_eq!(
            Luks::find(&blocks, &Source::File("/other".into())),
            Luks::default()
        );
    }

    #[test]
    fn strips_nul_terminators() {
        assert_eq!(
            bytes_path(b"/run/media/u/v\0".to_vec()),
            Path::new("/run/media/u/v")
        );
    }
}
