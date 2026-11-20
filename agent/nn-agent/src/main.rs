//! nn-agent: collects inventory data with the smallest possible scope and
//! sends it to nn-server as a v1 Observation. The agent listens on a port only
//! in `serve` mode and never executes commands from the server.

use clap::{Parser, Subcommand};
use nn_agent::collector::Collector;
use nn_agent::config::{self, Config};
use nn_agent::{client, collectors, pull, report};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "nn-agent",
    version = nn_agent::VERSION,
    about = "netnoodle agent: reports packages, services and interfaces of this host"
)]
struct Cli {
    /// Config file (optional).
    #[arg(long, global = true, default_value = config::DEFAULT_CONFIG)]
    config: PathBuf,
    /// Credentials file. Overrides the config.
    #[arg(long, global = true)]
    creds: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Pair with a server that will pull reports over mutual TLS.
    Pair {
        /// One-time code from the Peers page. Prefer the environment variable.
        #[arg(long, env = "NN_PAIR_CODE", hide_env_values = true)]
        code: String,
        /// SHA-256 fingerprint of the server's pull client certificate.
        #[arg(long)]
        server_fingerprint: String,
        /// Local address and port to listen on, e.g. 0.0.0.0:7444.
        #[arg(long)]
        listen: String,
        /// Replace the existing agent key and certificate.
        #[arg(long)]
        new_key: bool,
        /// Accept connections only from this address or network (CIDR),
        /// for example the server address. Repeat for more. Default: all.
        #[arg(long = "allow-from")]
        allow_from: Vec<String>,
    },
    /// Listen for report requests from the pinned server.
    Serve,
    /// Exchange a join token for credentials.
    Enroll {
        /// Server URL, e.g. https://10.0.0.2:7443
        #[arg(long)]
        server: String,
        /// SHA-256 fingerprint of the server certificate.
        #[arg(long)]
        fingerprint: String,
        /// Join token from the Peers page. Prefer the environment variable,
        /// so the token is not visible in the process list.
        #[arg(long, env = "NN_JOIN_TOKEN", hide_env_values = true)]
        token: String,
        /// Peer name. Default: the host name.
        #[arg(long)]
        name: Option<String>,
    },
    /// Collect and send reports.
    Run {
        /// Send one report and exit.
        #[arg(long)]
        once: bool,
    },
    /// Collect and print the report as JSON. Sends nothing.
    Collect {
        /// Read this directory as the root file system.
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Show the files, sockets and programs each enabled collector uses.
    Scope,
}

fn enabled(cfg: &Config) -> Result<Vec<Box<dyn Collector>>, String> {
    let all = collectors::all();
    let Some(names) = &cfg.collectors else {
        return Ok(all);
    };
    for n in names {
        if !all.iter().any(|c| c.name() == n) {
            let known: Vec<_> = all.iter().map(|c| c.name()).collect();
            return Err(format!(
                "unknown collector {n:?} (known: {})",
                known.join(", ")
            ));
        }
    }
    Ok(all
        .into_iter()
        .filter(|c| names.iter().any(|n| n == c.name()))
        .collect())
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default()
}

fn send_once(
    cfg: &Config,
    creds: &client::Credentials,
    cols: &[Box<dyn Collector>],
) -> Result<(), String> {
    let ctx = cfg.ctx(None);
    let r = report::collect(&ctx, cols);
    for e in &r.errors {
        eprintln!("nn-agent: collector {e}");
    }
    let (pkgs, svcs) = (r.entity.components.len(), r.entity.services.len());
    let obs = report::observation(r, &creds.name);
    let res = client::post_observation(creds, &obs)?;
    eprintln!("nn-agent: report sent: {pkgs} packages, {svcs} services; server: {res}");
    Ok(())
}

fn run(cli: Cli) -> Result<(), String> {
    let cfg = Config::load(&cli.config)?;
    let creds_path = cli.creds.clone().unwrap_or_else(|| cfg.credentials());
    match cli.cmd {
        Cmd::Pair {
            code,
            server_fingerprint,
            listen,
            new_key,
            allow_from,
        } => pull::pair_allow(
            &cfg.pull_state(),
            &code,
            &server_fingerprint,
            &listen,
            new_key,
            &hostname(),
            &allow_from,
        ),
        Cmd::Serve => pull::serve(&cfg, &enabled(&cfg)?, &hostname()),
        Cmd::Enroll {
            server,
            fingerprint,
            token,
            name,
        } => {
            let name = name.unwrap_or_else(hostname);
            let c = client::enroll(&server, &fingerprint, &token, &name)?;
            client::save(&creds_path, &c)?;
            println!(
                "enrolled as {:?} (role {}); credentials in {}",
                c.name,
                c.role,
                creds_path.display()
            );
            if c.role != "agent" {
                eprintln!(
                    "warning: the join token has role {:?}, not \"agent\"",
                    c.role
                );
            }
            Ok(())
        }
        Cmd::Run { once } => {
            let cols = enabled(&cfg)?;
            let creds = client::load(&creds_path)?;
            let every = cfg.interval()?;
            loop {
                if let Err(e) = send_once(&cfg, &creds, &cols) {
                    if once {
                        return Err(e);
                    }
                    eprintln!("nn-agent: {e}");
                }
                if once {
                    return Ok(());
                }
                std::thread::sleep(every);
            }
        }
        Cmd::Collect { root } => {
            let cols = enabled(&cfg)?;
            let ctx = cfg.ctx(root);
            let r = report::collect(&ctx, &cols);
            let obs = report::observation(r, "local");
            println!(
                "{}",
                serde_json::to_string_pretty(&obs).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        Cmd::Scope => {
            for c in enabled(&cfg)? {
                let a = c.access();
                println!("{}", c.name());
                for (label, list) in [
                    ("reads", &a.reads),
                    ("sockets", &a.sockets),
                    ("runs", &a.execs),
                ] {
                    for item in list {
                        println!("  {label:8} {item}");
                    }
                }
                if !a.privileged.is_empty() {
                    println!("  {:8} {}", "root for", a.privileged);
                }
            }
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nn-agent: {e}");
            ExitCode::FAILURE
        }
    }
}
