// SPDX-License-Identifier: GPL-3.0-or-later

//! Sandbox invoker (plan §2.3): runs a program under bubblewrap as the
//! calling user.
//!
//! The profile is the plan's, with one addition. The plan binds `/`
//! read-only, which leaves `$XDG_RUNTIME_DIR` visible inside the sandbox.
//! That directory holds this daemon's own socket and the systemd user bus,
//! and either would let the sandboxed program start something outside the
//! sandbox. So the runtime directory is replaced by a tmpfs, and only the
//! Wayland socket is bound back in.
//!
//! Under systemd, each sandbox runs in its own transient scope
//! (`systemd-run --user --scope`). Otherwise it would live in the daemon's
//! cgroup, share its memory limit, and be killed when the daemon restarts.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use omarchy_security_proto::methods::{SandboxRunParams, SandboxRunResult};
use omarchy_security_proto::types::{Module, ModuleState};
use omarchy_security_proto::{ErrorCode, RpcError};

use crate::hub::Hub;

/// The session paths the profile needs.
#[derive(Debug, Clone)]
pub struct Session {
    pub home: PathBuf,
    pub runtime_dir: Option<PathBuf>,
    pub wayland_display: Option<String>,
}

impl Session {
    pub fn from_env() -> Self {
        let var = |name| std::env::var_os(name).filter(|v| !v.is_empty());
        Self {
            home: var("HOME").map(PathBuf::from).unwrap_or_else(|| "/".into()),
            runtime_dir: var("XDG_RUNTIME_DIR").map(PathBuf::from),
            wayland_display: var("WAYLAND_DISPLAY").map(|v| v.to_string_lossy().into_owned()),
        }
    }
}

pub struct Sandbox {
    bwrap: Option<PathBuf>,
    /// `systemd-run`, when this daemon runs as a systemd service.
    systemd_run: Option<PathBuf>,
    session: Session,
}

impl Sandbox {
    pub fn start(hub: &Hub, session: Session) -> Arc<Self> {
        let bwrap = find_in_path("bwrap");
        match &bwrap {
            Some(_) => hub.set_status(Module::Sandbox, ModuleState::Active, None),
            None => hub.set_status(
                Module::Sandbox,
                ModuleState::Unavailable,
                Some("bwrap (bubblewrap) is not installed".into()),
            ),
        }
        let systemd_run =
            std::env::var_os("INVOCATION_ID").and_then(|_| find_in_path("systemd-run"));
        Arc::new(Self {
            bwrap,
            systemd_run,
            session,
        })
    }

    pub async fn run(&self, params: SandboxRunParams) -> Result<SandboxRunResult, RpcError> {
        let bwrap = self
            .bwrap
            .as_ref()
            .ok_or_else(|| RpcError::new(ErrorCode::ModuleUnavailable, "bwrap is not installed"))?;
        let args = bwrap_args(&params, &self.session)?;
        let mut command = match &self.systemd_run {
            Some(systemd_run) => {
                let mut c = tokio::process::Command::new(systemd_run);
                c.args(scope_args(&params.executable)).arg(bwrap);
                c
            }
            None => tokio::process::Command::new(bwrap),
        };
        let mut child = command
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(false)
            .spawn()
            .map_err(|e| {
                RpcError::new(ErrorCode::BackendError, format!("starting bwrap: {e}"))
                    .with_data(serde_json::json!({ "detail": e.to_string() }))
            })?;
        let pid = child.id().unwrap_or(0);
        tracing::info!(pid, executable = %params.executable, share_net = params.share_net, "sandbox started");
        // Reap it so it does not linger as a zombie.
        tokio::spawn(async move {
            match child.wait().await {
                Ok(status) => tracing::info!(pid, %status, "sandbox exited"),
                Err(err) => tracing::warn!(pid, "waiting for sandbox: {err}"),
            }
        });
        Ok(SandboxRunResult { pid })
    }
}

/// `systemd-run` arguments that put the sandbox in its own scope. With
/// `--scope`, systemd-run execs the command itself, so the PID stays the
/// sandbox's.
fn scope_args(executable: &str) -> Vec<String> {
    vec![
        "--user".into(),
        "--scope".into(),
        "--quiet".into(),
        "--collect".into(),
        format!("--description=Security Hub sandbox: {executable}"),
        "--".into(),
    ]
}

fn invalid(message: impl Into<String>) -> RpcError {
    RpcError::invalid_params(message.into())
}

/// Checks `path` is absolute and names an existing regular file, and
/// returns it with symlinks resolved.
fn existing_file(what: &str, path: &str) -> Result<PathBuf, RpcError> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(invalid(format!("{what} must be an absolute path")));
    }
    let real = std::fs::canonicalize(path)
        .map_err(|e| invalid(format!("{what} {}: {e}", path.display())))?;
    if !real.is_file() {
        return Err(invalid(format!(
            "{what} {} is not a regular file",
            path.display()
        )));
    }
    Ok(real)
}

pub fn bwrap_args(params: &SandboxRunParams, session: &Session) -> Result<Vec<OsString>, RpcError> {
    let executable = existing_file("executable", &params.executable)?;
    let mode = std::fs::metadata(&executable)
        .map(|m| m.permissions().mode())
        .unwrap_or(0);
    if mode & 0o111 == 0 {
        return Err(invalid(format!("{} is not executable", params.executable)));
    }
    let target = params
        .target_file
        .as_deref()
        .map(|t| existing_file("target_file", t).map(|real| (real, PathBuf::from(t))))
        .transpose()?;

    let mut args: Vec<OsString> = Vec::new();
    let mut push = |items: &[&std::ffi::OsStr]| args.extend(items.iter().map(|s| s.to_os_string()));
    push(&["--unshare-all".as_ref()]);
    if params.share_net {
        push(&["--share-net".as_ref()]);
    }
    push(&[
        "--new-session".as_ref(),
        "--ro-bind".as_ref(),
        "/".as_ref(),
        "/".as_ref(),
        "--tmpfs".as_ref(),
        "/tmp".as_ref(),
        "--tmpfs".as_ref(),
        session.home.as_os_str(),
    ]);
    if let Some(runtime) = &session.runtime_dir {
        push(&["--tmpfs".as_ref(), runtime.as_os_str()]);
        if let Some(display) = &session.wayland_display {
            let socket = runtime.join(display);
            if socket.exists() {
                push(&["--ro-bind".as_ref(), socket.as_os_str(), socket.as_os_str()]);
            }
        }
    }
    push(&[
        "--proc".as_ref(),
        "/proc".as_ref(),
        "--dev".as_ref(),
        "/dev".as_ref(),
    ]);
    // A program under $HOME or /tmp would be hidden by the tmpfs above.
    push(&[
        "--ro-bind".as_ref(),
        executable.as_os_str(),
        executable.as_os_str(),
    ]);
    if let Some((real, seen)) = &target {
        push(&["--bind".as_ref(), real.as_os_str(), seen.as_os_str()]);
    }
    push(&["--".as_ref(), executable.as_os_str()]);
    args.extend(params.args.iter().map(OsString::from));
    Ok(args)
}

pub(crate) fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(executable: &str) -> SandboxRunParams {
        SandboxRunParams {
            executable: executable.into(),
            args: vec!["--flag".into()],
            target_file: None,
            share_net: false,
        }
    }

    fn session(dir: &Path) -> Session {
        std::fs::write(dir.join("wayland-1"), "").unwrap();
        Session {
            home: "/home/u".into(),
            runtime_dir: Some(dir.to_owned()),
            wayland_display: Some("wayland-1".into()),
        }
    }

    fn joined(args: &[OsString]) -> String {
        args.iter()
            .map(|a| a.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn builds_the_plan_profile_without_network() {
        let dir = tempfile::tempdir().unwrap();
        let rt = dir.path().display().to_string();
        let args = joined(&bwrap_args(&params("/bin/sh"), &session(dir.path())).unwrap());
        let sh = std::fs::canonicalize("/bin/sh")
            .unwrap()
            .display()
            .to_string();
        assert_eq!(
            args,
            format!(
                "--unshare-all --new-session --ro-bind / / --tmpfs /tmp --tmpfs /home/u \
                 --tmpfs {rt} --ro-bind {rt}/wayland-1 {rt}/wayland-1 --proc /proc --dev /dev \
                 --ro-bind {sh} {sh} -- {sh} --flag"
            )
        );
    }

    #[test]
    fn share_net_and_target_file() {
        let dir = tempfile::tempdir().unwrap();
        let doc = dir.path().join("doc.pdf");
        std::fs::write(&doc, "").unwrap();
        let mut p = params("/bin/sh");
        p.share_net = true;
        p.target_file = Some(doc.display().to_string());
        let args = joined(&bwrap_args(&p, &session(dir.path())).unwrap());
        assert!(args.starts_with("--unshare-all --share-net "));
        let real = std::fs::canonicalize(&doc).unwrap();
        assert!(args.contains(&format!("--bind {} {}", real.display(), doc.display())));
    }

    #[test]
    fn rejects_bad_paths() {
        let dir = tempfile::tempdir().unwrap();
        let s = session(dir.path());
        let plain = dir.path().join("plain");
        std::fs::write(&plain, "").unwrap();
        for bad in ["sh", "/no/such/file", "/tmp", plain.to_str().unwrap()] {
            let err = bwrap_args(&params(bad), &s).unwrap_err();
            assert_eq!(err.kind(), Some(ErrorCode::InvalidParams), "{bad}");
        }
        let mut p = params("/bin/sh");
        p.target_file = Some("relative.txt".into());
        assert!(bwrap_args(&p, &s).is_err());
    }

    #[test]
    fn scope_wraps_the_command() {
        let args = scope_args("/usr/bin/zathura");
        assert_eq!(args.first().map(String::as_str), Some("--user"));
        assert!(args.contains(&"--scope".to_owned()));
        assert_eq!(args.last().map(String::as_str), Some("--"));
    }

    /// Runs a real sandbox: the program sees only the Wayland socket in the
    /// runtime directory, an empty home, and the one writable target file.
    #[tokio::test]
    async fn sandbox_hides_the_session() {
        if find_in_path("bwrap").is_none()
            || !std::process::Command::new("bwrap")
                .args(["--unshare-all", "--ro-bind", "/", "/", "true"])
                .status()
                .is_ok_and(|s| s.success())
        {
            eprintln!("bwrap cannot create namespaces here; skipping");
            return;
        }
        let runtime = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        std::fs::write(runtime.path().join("wayland-1"), "").unwrap();
        std::fs::write(runtime.path().join("bus"), "").unwrap();
        std::fs::write(home.path().join("secret"), "").unwrap();
        let out = home.path().join("report.txt");
        std::fs::write(&out, "").unwrap();

        let hub = Hub::new();
        let mut sandbox = Sandbox::start(
            &hub,
            Session {
                home: home.path().to_owned(),
                runtime_dir: Some(runtime.path().to_owned()),
                wayland_display: Some("wayland-1".into()),
            },
        );
        Arc::get_mut(&mut sandbox).unwrap().systemd_run = None;
        let script = format!(
            "ls {rt} > {out}; ls -A {home} >> {out}; echo x > /tmp/probe && echo tmp-ok >> {out}; echo done >> {out}",
            rt = runtime.path().display(),
            home = home.path().display(),
            out = out.display()
        );
        let result = sandbox
            .run(SandboxRunParams {
                executable: "/bin/sh".into(),
                args: vec!["-c".into(), script],
                target_file: Some(out.display().to_string()),
                share_net: false,
            })
            .await
            .unwrap();
        assert!(result.pid > 0);
        let mut report = String::new();
        for _ in 0..500 {
            report = std::fs::read_to_string(&out).unwrap();
            if report.contains("done") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let lines: Vec<&str> = report.lines().collect();
        // Runtime dir: only the Wayland socket. Home: only the bound file.
        assert_eq!(
            lines,
            ["wayland-1", "report.txt", "tmp-ok", "done"],
            "{report}"
        );
    }
}
