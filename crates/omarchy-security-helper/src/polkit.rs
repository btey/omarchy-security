// SPDX-License-Identifier: GPL-3.0-or-later

//! Authorization of helper operations through polkit.
//!
//! Each connection is identified by its `SO_PEERCRED` process. polkit's
//! `unix-process` subject takes the PID together with its start time, so a
//! PID recycled by another process after the check cannot inherit the
//! answer. The actions and their defaults are in
//! `dist/polkit/org.omarchy.security.policy`.

use std::collections::HashMap;
use std::future::Future;

use omarchy_security_proto::procfs::Proc;
use zbus::zvariant::Value;

/// The connecting process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub pid: u32,
    pub uid: u32,
    pub start_time: u64,
}

impl Peer {
    pub fn from_cred(cred: &tokio::net::unix::UCred) -> Option<Self> {
        let pid = u32::try_from(cred.pid()?).ok()?;
        let start_time = Proc::default().stat(pid).ok()?.start_time;
        Some(Self {
            pid,
            uid: cred.uid(),
            start_time,
        })
    }
}

pub trait Authorizer: Send + Sync + 'static {
    /// True when `peer` may perform `action`. With `interactive`, polkit may
    /// ask the user to authenticate through their session's agent.
    fn authorize(
        &self,
        peer: Peer,
        action: &'static str,
        interactive: bool,
    ) -> impl Future<Output = Result<bool, String>> + Send;
}

#[zbus::proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority",
    gen_blocking = false
)]
trait Authority {
    #[allow(clippy::type_complexity)]
    fn check_authorization(
        &self,
        subject: &(&str, HashMap<&str, Value<'_>>),
        action_id: &str,
        details: HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<(bool, bool, HashMap<String, String>)>;
}

const ALLOW_USER_INTERACTION: u32 = 1;

pub struct Polkit {
    authority: AuthorityProxy<'static>,
}

impl Polkit {
    pub async fn connect() -> zbus::Result<Self> {
        let conn = zbus::Connection::system().await?;
        Ok(Self {
            authority: AuthorityProxy::new(&conn).await?,
        })
    }
}

impl Authorizer for Polkit {
    async fn authorize(
        &self,
        peer: Peer,
        action: &'static str,
        interactive: bool,
    ) -> Result<bool, String> {
        let uid = i32::try_from(peer.uid).map_err(|_| "uid out of range".to_owned())?;
        let subject = (
            "unix-process",
            HashMap::from([
                ("pid", Value::from(peer.pid)),
                ("start-time", Value::from(peer.start_time)),
                ("uid", Value::from(uid)),
            ]),
        );
        let flags = if interactive {
            ALLOW_USER_INTERACTION
        } else {
            0
        };
        let (authorized, _challenge, _details) = self
            .authority
            .check_authorization(&subject, action, HashMap::new(), flags, "")
            .await
            .map_err(|e| format!("polkit: {e}"))?;
        tracing::info!(
            pid = peer.pid,
            uid = peer.uid,
            action,
            authorized,
            "polkit check"
        );
        Ok(authorized)
    }
}
