use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use serde_json::Value;

use latchkey::config::{Config, default_data_dir};
use latchkey::identity::Identity;
use latchkey::trust::TrustStore;

#[derive(Parser)]
#[command(
    name = "latchkey",
    version,
    about = "A post-quantum peer-to-peer mesh network"
)]
struct Cli {
    /// Data directory holding the identity, trust list, config and control socket.
    #[arg(long, global = true, env = "LATCHKEY_DIR")]
    dir: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the node in the foreground.
    Run {
        /// Address to accept peer connections on (overrides the config file).
        #[arg(long)]
        listen: Option<SocketAddr>,
        /// Extra static peer to connect to, as host:port. Repeatable.
        #[arg(long = "peer")]
        peers: Vec<String>,
        /// Do not announce or discover nodes over multicast.
        #[arg(long)]
        no_discovery: bool,
    },
    /// Print this node's ID.
    Id,
    /// List connected peers.
    Peers,
    /// Measure the round-trip time to a peer.
    Ping { peer: String },
    /// Send a text message to a peer.
    Send {
        peer: String,
        #[arg(required = true, num_args = 1..)]
        text: Vec<String>,
    },
    /// Connect to a node at host:port.
    Connect { addr: String },
    /// Add a node to the trust allowlist.
    Trust { id: String },
    /// Remove a node from the trust allowlist.
    Untrust { id: String },
    /// List trusted nodes.
    Trusted,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match real_main().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn real_main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "latchkey=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let dir = cli.dir.unwrap_or_else(default_data_dir);
    let config = Config::load(&dir.join("config.toml"))?;

    match cli.command {
        Command::Run {
            listen,
            peers,
            no_discovery,
        } => {
            let mut config = config;
            if let Some(listen) = listen {
                config.listen = listen;
            }
            config.peers.extend(peers);
            if no_discovery {
                config.discovery.enabled = false;
            }
            run(config).await
        }
        Command::Id => {
            println!(
                "{}",
                Identity::load_or_create(&config.identity_path())?.id()
            );
            Ok(())
        }
        command => client(&config, command).await,
    }
}

#[cfg(unix)]
async fn run(config: Config) -> Result<()> {
    use latchkey::{Event, Node};

    let node = Node::start(config.clone()).await?;
    println!("latchkey node {}", node.id());
    println!("listening on {}", node.local_addr());

    let control_path = config.control_path();
    let control = tokio::spawn({
        let node = node.clone();
        let path = control_path.clone();
        async move { latchkey::control::serve(node, &path).await }
    });

    let mut events = node.subscribe();
    let printer = async {
        loop {
            match events.recv().await {
                Ok(Event::Message {
                    from,
                    trusted,
                    data,
                }) => {
                    let label = if trusted { "trusted" } else { "untrusted" };
                    println!(
                        "[{} {label}] {}",
                        from.short(),
                        String::from_utf8_lossy(&data)
                    );
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("dropped {n} events");
                }
                Err(_) => return,
            }
        }
    };

    let result = tokio::select! {
        _ = terminated() => Ok(()),
        r = control => r?,
        _ = printer => Ok(()),
    };
    node.shutdown();
    let _ = std::fs::remove_file(&control_path);
    result
}

/// Resolves on Ctrl-C or SIGTERM, so the control socket is cleaned up either way.
#[cfg(unix)]
async fn terminated() {
    use tokio::signal::unix::{SignalKind, signal};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn run(_config: Config) -> Result<()> {
    bail!("the latchkey daemon currently supports Unix-like systems only")
}

#[cfg(unix)]
async fn client(config: &Config, command: Command) -> Result<()> {
    use latchkey::control::{NotRunning, Request, request};

    let path = config.control_path();
    let req = match command {
        Command::Peers => Request::Peers,
        Command::Ping { peer } => Request::Ping { peer },
        Command::Send { peer, text } => Request::Send {
            peer,
            text: text.join(" "),
        },
        Command::Connect { addr } => Request::Connect { addr },
        Command::Trust { ref id } => Request::Trust { id: id.clone() },
        Command::Untrust { ref id } => Request::Untrust { id: id.clone() },
        Command::Trusted => Request::Trusted,
        Command::Run { .. } | Command::Id => unreachable!("handled in main"),
    };
    let result = match request(&path, &req).await {
        Ok(result) => result,
        Err(e) if e.is::<NotRunning>() => return offline(config, &req, e),
        Err(e) => return Err(e),
    };
    print_result(&req, &result);
    Ok(())
}

#[cfg(not(unix))]
async fn client(_config: &Config, _command: Command) -> Result<()> {
    bail!("the latchkey CLI currently supports Unix-like systems only")
}

/// Trust list commands still work without a daemon, as long as the ID is spelled out in full.
#[cfg(unix)]
fn offline(
    config: &Config,
    req: &latchkey::control::Request,
    not_running: anyhow::Error,
) -> Result<()> {
    use latchkey::control::Request;

    let mut store = TrustStore::load(&config.trust_path())?;
    match req {
        Request::Trust { id } => {
            let id = id.parse().map_err(|_| {
                anyhow::anyhow!("with the daemon stopped, give the full 64-character node ID")
            })?;
            report_change(store.trust(id)?, "trusted", &id)
        }
        Request::Untrust { id } => {
            let id = id.parse().map_err(|_| {
                anyhow::anyhow!("with the daemon stopped, give the full 64-character node ID")
            })?;
            report_change(store.untrust(&id)?, "untrusted", &id)
        }
        Request::Trusted => {
            for id in store.list() {
                println!("{id}");
            }
        }
        _ => bail!(not_running),
    }
    Ok(())
}

fn report_change(changed: bool, verb: &str, id: &impl std::fmt::Display) {
    if changed {
        println!("{verb} {id}");
    } else {
        println!("{id} was already {verb}");
    }
}

#[cfg(unix)]
fn print_result(req: &latchkey::control::Request, result: &Value) {
    use latchkey::control::Request;

    let str_of = |v: &Value| v.as_str().unwrap_or_default().to_string();
    let short = |v: &Value| str_of(v).chars().take(16).collect::<String>();
    let trust_label = |v: &Value| {
        if v.as_bool() == Some(true) {
            "trusted"
        } else {
            "untrusted"
        }
    };
    match req {
        Request::Peers => {
            let peers = result.as_array().cloned().unwrap_or_default();
            if peers.is_empty() {
                println!("no peers connected");
            }
            for p in peers {
                println!(
                    "{}  {:<9}  {:<8}  {}  ({}s)",
                    short(&p["id"]),
                    trust_label(&p["trusted"]),
                    if p["outbound"].as_bool() == Some(true) {
                        "outbound"
                    } else {
                        "inbound"
                    },
                    str_of(&p["addr"]),
                    p["connected_secs"],
                );
            }
        }
        Request::Ping { .. } => {
            println!(
                "{}: {:.2} ms",
                short(&result["id"]),
                result["rtt_ms"].as_f64().unwrap_or(0.0)
            );
        }
        Request::Send { .. } => {
            println!(
                "sent to {} ({})",
                short(&result["id"]),
                trust_label(&result["trusted"])
            );
        }
        Request::Connect { .. } => {
            println!(
                "connected to {} ({})",
                str_of(&result["id"]),
                trust_label(&result["trusted"])
            );
        }
        Request::Trust { .. } => {
            report_change(
                result["changed"].as_bool() == Some(true),
                "trusted",
                &str_of(&result["id"]),
            );
        }
        Request::Untrust { .. } => {
            report_change(
                result["changed"].as_bool() == Some(true),
                "untrusted",
                &str_of(&result["id"]),
            );
        }
        Request::Trusted => {
            for id in result.as_array().cloned().unwrap_or_default() {
                println!("{}", str_of(&id));
            }
        }
        Request::Status => println!("{result}"),
    }
}
