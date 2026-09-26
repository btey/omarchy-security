// SPDX-License-Identifier: GPL-3.0-or-later

//! `omarchy-securityd-helper`: the privileged half of the Security Hub.
//!
//! It runs as a system service (`omarchy-securityd-helper.service`) with a
//! narrow capability set, and does only the things the per-user daemon
//! cannot:
//!
//! * loads the eBPF exec monitor and streams suspicious executions
//!   (`CAP_BPF`, `CAP_PERFMON`; `CAP_SYS_PTRACE` to read `/proc/<pid>/exe`
//!   of other users' processes),
//! * replaces `table inet omarchy_sec` (`CAP_NET_ADMIN`),
//! * reads the NFQUEUE of new outbound connections and names the process
//!   behind each one (`CAP_NET_ADMIN`; `CAP_SYS_PTRACE` for `/proc/*/fd`),
//! * signals processes it reported itself (`CAP_KILL`).
//!
//! Every operation is authorized with polkit against the connecting
//! process. See `omarchy_security_proto::helper` for the protocol.

mod connections;
mod exec;
mod firewall;
mod netlink;
mod nfqueue;
mod packet;
mod polkit;
mod server;
mod sockdiag;

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use omarchy_security_proto::helper::HELPER_SOCKET;
use omarchy_security_proto::procfs::Proc;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::broadcast;
use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
Usage: omarchy-securityd-helper [OPTIONS]

Options:
      --socket <PATH>      Listen on PATH (default: /run/omarchy-security/helper.sock)
      --bpf-object <PATH>  eBPF exec monitor object
                           (default: /usr/lib/omarchy-security/exec-monitor.bpf.o)
      --no-exec-monitor    Do not load the exec monitor
      --queue-num <N>      NFQUEUE number for connection interception
                           (default: 7433)
      --no-connections     Do not intercept outbound connections
      --queue-loopback     Queue loopback connections too (for tests)
  -V, --version            Print version and exit
  -h, --help               Print this help and exit

Logging is controlled by RUST_LOG (default: info).";

struct Args {
    socket: PathBuf,
    bpf_object: PathBuf,
    exec_monitor: bool,
    queue_num: u16,
    connections: bool,
    queue_loopback: bool,
}

fn parse_args(mut argv: impl Iterator<Item = String>) -> Result<Option<Args>> {
    let mut args = Args {
        socket: HELPER_SOCKET.into(),
        bpf_object: exec::DEFAULT_OBJECT.into(),
        exec_monitor: true,
        queue_num: connections::DEFAULT_QUEUE,
        connections: true,
        queue_loopback: false,
    };
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("omarchy-securityd-helper {}", env!("CARGO_PKG_VERSION"));
                return Ok(None);
            }
            "--socket" => args.socket = argv.next().context("--socket requires a path")?.into(),
            "--bpf-object" => {
                args.bpf_object = argv.next().context("--bpf-object requires a path")?.into()
            }
            "--no-exec-monitor" => args.exec_monitor = false,
            "--queue-num" => {
                args.queue_num = argv
                    .next()
                    .context("--queue-num requires a number")?
                    .parse()
                    .context("--queue-num must be 0-65535")?
            }
            "--no-connections" => args.connections = false,
            "--queue-loopback" => args.queue_loopback = true,
            other => anyhow::bail!("unknown argument '{other}'\n\n{USAGE}"),
        }
    }
    Ok(Some(args))
}

async fn run(args: Args) -> Result<()> {
    tracing::info!(version = env!("CARGO_PKG_VERSION"), socket = %args.socket.display(), "starting");
    let authorizer = polkit::Polkit::connect()
        .await
        .context("connecting to polkit on the system bus")?;

    let reported = Arc::new(exec::Reported::default());
    let (exec_tx, exec_detail) = if !args.exec_monitor {
        (None, Some("disabled with --no-exec-monitor".to_owned()))
    } else {
        match exec::ExecMonitor::load(&args.bpf_object) {
            Ok(monitor) => {
                let (tx, _) = broadcast::channel(256);
                let sender = tx.clone();
                let reported = reported.clone();
                tokio::spawn(async move {
                    if let Err(err) = monitor.run(sender, &reported).await {
                        tracing::error!("exec monitor stopped: {err:#}");
                    }
                });
                (Some(tx), None)
            }
            Err(err) => {
                tracing::warn!("exec monitor unavailable: {err:#}");
                (None, Some(format!("{err:#}")))
            }
        }
    };

    let firewall = firewall::Firewall::new();
    if !firewall.available() {
        tracing::warn!("nft not found: firewall operations will fail");
    }
    let (interceptor, connections_detail) = if !args.connections {
        (None, Some("disabled with --no-connections".to_owned()))
    } else {
        match connections::Interceptor::start(args.queue_num, Proc::default()) {
            Ok(interceptor) => (Some(interceptor), None),
            Err(err) => {
                tracing::warn!(
                    queue = args.queue_num,
                    "connection interception unavailable: {err}"
                );
                (
                    None,
                    Some(format!("binding NFQUEUE {}: {err}", args.queue_num)),
                )
            }
        }
    };
    let state = Arc::new(server::State {
        authorizer,
        firewall,
        exec: exec_tx,
        exec_detail,
        reported,
        proc: Proc::default(),
        interceptor,
        connections_detail,
        queue_loopback: args.queue_loopback,
    });

    let listener = server::bind(&args.socket)?;
    if let Err(err) = omarchy_security_proto::systemd::notify_ready() {
        tracing::warn!("sd_notify READY=1 failed: {err}");
    }
    tracing::info!("listening");
    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    server::serve(listener, args.socket.clone(), state.clone(), async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    })
    .await;
    // Take the queue rule out before exiting; `bypass` would let traffic
    // through anyway, but a stale rule is confusing in `nft list`.
    if let Some(interceptor) = &state.interceptor {
        interceptor.stop();
        if let Err(err) = state.firewall.set_queue(|| None).await {
            tracing::warn!("removing the queue rule: {err}");
        }
    }
    tracing::info!("stopped");
    Ok(())
}

fn init_logging() {
    use std::io::IsTerminal;
    let builder = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal());
    // The journal stamps each line itself.
    if std::env::var_os("JOURNAL_STREAM").is_some() {
        builder.without_time().init();
    } else {
        builder.init();
    }
}

fn main() -> ExitCode {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(Some(args)) => args,
        Ok(None) => return ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("omarchy-securityd-helper: {err:#}");
            return ExitCode::from(2);
        }
    };
    init_logging();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build();
    let result = match runtime {
        Ok(runtime) => runtime.block_on(run(args)),
        Err(err) => Err(err).context("starting tokio runtime"),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("{err:#}");
            ExitCode::FAILURE
        }
    }
}
