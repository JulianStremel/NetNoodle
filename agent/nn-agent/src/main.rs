//! nn-agent: collects inventory data with the smallest possible scope and
//! sends it to nn-server as a v1 Observation. The agent never listens on a
//! port and never executes commands from the server.

// Collectors are wired in at milestone M2.
#[allow(dead_code)]
mod collector;

use collector::Collector;

/// All compiled-in collectors. Collectors register here; the config
/// selects which of them run.
fn registry() -> Vec<Box<dyn Collector>> {
    Vec::new()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("scope") => {
            for c in registry() {
                println!("{}: {:?}", c.name(), c.access());
            }
        }
        Some("version") | Some("--version") => println!("nn-agent {}", env!("CARGO_PKG_VERSION")),
        _ => {
            eprintln!("usage: nn-agent <scope|version>");
            std::process::exit(2);
        }
    }
}
