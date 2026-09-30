// SPDX-License-Identifier: GPL-3.0-or-later

//! `omarchy-securityd`: the Security Hub daemon.
//!
//! Serves the client socket (`docs/ipc-protocol.md`) and runs the modules.
//! Everything that needs privileges goes through `omarchy-securityd-helper`,
//! a separate system service; this process runs as the desktop user.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use omarchy_security_proto::{PROTOCOL_VERSION, default_socket_path};
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::EnvFilter;

use omarchy_securityd::daemon::Daemon;
use omarchy_securityd::hub::Hub;
use omarchy_securityd::server::Server;
use omarchy_securityd::{
    alerts, config, drops, firewall, helper_client, notify, posture, sandbox, threat, token, ufw,
    usbguard, vault,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
Usage: omarchy-securityd [OPTIONS]

Options:
      --config <PATH>      Read the configuration from PATH instead of
                           $XDG_CONFIG_HOME/omarchy-security/config.toml
      --socket <PATH>      Listen on PATH instead of
                           $XDG_RUNTIME_DIR/omarchy-security/securityd.sock
      --helper-socket <PATH>
                           Reach the privileged helper at PATH instead of
                           /run/omarchy-security/helper.sock
      --print-socket-path  Print the resolved socket path and exit
  -V, --version            Print version and exit
  -h, --help               Print this help and exit

SIGHUP reloads the configuration. Logging is controlled by RUST_LOG
(default: info).";

#[derive(Debug, Default)]
struct Args {
    config: Option<PathBuf>,
    socket: Option<PathBuf>,
    helper_socket: Option<PathBuf>,
    print_socket_path: bool,
}

enum Command {
    Run(Args),
    Exit(&'static str),
}

fn parse_args(mut argv: impl Iterator<Item = String>) -> Result<Command> {
    let mut args = Args::default();
    while let Some(arg) = argv.next() {
        match arg.as_str() {
            "-h" | "--help" => return Ok(Command::Exit(USAGE)),
            "-V" | "--version" => {
                return Ok(Command::Exit(concat!(
                    "omarchy-securityd ",
                    env!("CARGO_PKG_VERSION")
                )));
            }
            "--print-socket-path" => args.print_socket_path = true,
            "--config" => {
                let path = argv.next().context("--config requires a path")?;
                args.config = Some(PathBuf::from(path));
            }
            "--socket" => {
                let path = argv.next().context("--socket requires a path")?;
                args.socket = Some(PathBuf::from(path));
            }
            "--helper-socket" => {
                let path = argv.next().context("--helper-socket requires a path")?;
                args.helper_socket = Some(PathBuf::from(path));
            }
            other => anyhow::bail!("unknown argument '{other}'\n\n{USAGE}"),
        }
    }
    Ok(Command::Run(args))
}

async fn run(args: Args) -> Result<()> {
    let socket = args
        .socket
        .or_else(default_socket_path)
        .context("cannot resolve socket path: XDG_RUNTIME_DIR is not set (pass --socket)")?;

    if args.print_socket_path {
        println!("{}", socket.display());
        return Ok(());
    }

    tracing::info!(version = VERSION, protocol = PROTOCOL_VERSION, socket = %socket.display(), "starting");

    let settings = Arc::new(config::Settings::load(
        args.config.or_else(config::default_path),
    ));
    let mut sighup = signal(SignalKind::hangup()).context("installing SIGHUP handler")?;
    tokio::spawn({
        let settings = settings.clone();
        async move {
            while sighup.recv().await.is_some() {
                tracing::info!("SIGHUP received, reloading the configuration");
                settings.reload();
            }
        }
    });

    let hub = Arc::new(Hub::new());
    let helper = helper_client::HelperClient::start(
        args.helper_socket
            .unwrap_or_else(helper_client::default_socket),
    );
    let system_bus = zbus::Connection::system().await;
    let firewall = firewall::Firewall::start(
        hub.clone(),
        helper.clone(),
        settings.clone(),
        firewall::default_store(),
        Some(ufw::UfwEnv::default()),
    );
    let (actions_tx, actions) = tokio::sync::mpsc::channel(16);
    let notifier = match zbus::Connection::session().await {
        Ok(session) => notify::Notifier::start(&session, actions_tx)
            .await
            .inspect_err(|err| tracing::warn!("desktop notifications are off: {err}"))
            .ok(),
        Err(err) => {
            tracing::warn!("desktop notifications are off: no session bus: {err}");
            None
        }
    };
    firewall.start_alerts(alerts::AlertsEnv::default(), notifier.map(|n| (n, actions)));
    let daemon = Arc::new(Daemon {
        threat: threat::Threat::start(
            hub.clone(),
            helper.clone(),
            Default::default(),
            Some(drops::DropEnv::default()),
        ),
        firewall,
        posture: posture::Posture::start(hub.clone(), posture::PostureEnv::host()),
        sandbox: sandbox::Sandbox::start(&hub, sandbox::Session::from_env()),
        usbguard: usbguard::Usbguard::start(hub.clone(), system_bus.clone()),
        tokens: token::Tokens::start(hub.clone(), token::TokenEnv::default()),
        vaults: vault::Vaults::start(
            hub.clone(),
            settings.clone(),
            system_bus.ok(),
            vault::VaultEnv::host(),
        ),
        hub: hub.clone(),
    });
    let server = Server::bind(&socket, hub.clone(), daemon)?;
    if let Err(err) = omarchy_security_proto::systemd::notify_ready() {
        tracing::warn!("sd_notify READY=1 failed: {err}");
    }
    tracing::info!("listening");

    let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
    server
        .serve(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => tracing::info!("SIGINT received"),
                _ = sigterm.recv() => tracing::info!("SIGTERM received"),
            }
        })
        .await;
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
    let command = match parse_args(std::env::args().skip(1)) {
        Ok(command) => command,
        Err(err) => {
            eprintln!("omarchy-securityd: {err:#}");
            return ExitCode::from(2);
        }
    };
    let args = match command {
        Command::Exit(text) => {
            println!("{text}");
            return ExitCode::SUCCESS;
        }
        Command::Run(args) => args,
    };

    init_logging();

    // One worker is plenty for an event-driven daemon with a 40 MB budget.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parses_socket_override() {
        let Command::Run(args) = parse(&["--socket", "/tmp/x.sock"]).unwrap() else {
            panic!()
        };
        assert_eq!(args.socket, Some(PathBuf::from("/tmp/x.sock")));
    }

    #[test]
    fn parses_config_override() {
        let Command::Run(args) = parse(&["--config", "/tmp/c.toml"]).unwrap() else {
            panic!()
        };
        assert_eq!(args.config, Some(PathBuf::from("/tmp/c.toml")));
        assert!(parse(&["--config"]).is_err());
    }

    #[test]
    fn rejects_unknown_and_incomplete_arguments() {
        assert!(parse(&["--bogus"]).is_err());
        assert!(parse(&["--socket"]).is_err());
    }
}
