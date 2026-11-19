//! nn-actor-host: executes signed orders on the local host. It is a separate
//! program from nn-agent, so the agent stays read-only.
//!
//! Each action is a plug-in that implements [`Action`] and announces one
//! capability. The local allowlist decides which actions and which targets
//! (systemd units, ports) are permitted, independent of the server.

use nn_proto::{Capability, Order};

/// An action plug-in.
pub trait Action {
    /// The capability this action announces to the server.
    fn capability(&self) -> Capability;
    /// Executes a verified, allowlisted order. Returns a short message.
    fn execute(&self, order: &Order) -> Result<String, String>;
}

/// All compiled-in actions.
fn registry() -> Vec<Box<dyn Action>> {
    Vec::new()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("capabilities") => {
            let caps: Vec<Capability> = registry().iter().map(|a| a.capability()).collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&caps).unwrap_or_default()
            );
        }
        Some("version") | Some("--version") => {
            println!("nn-actor-host {}", env!("CARGO_PKG_VERSION"))
        }
        _ => {
            eprintln!("usage: nn-actor-host <capabilities|version>");
            std::process::exit(2);
        }
    }
}
