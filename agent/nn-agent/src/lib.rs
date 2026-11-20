//! nn-agent library: collectors, report assembly and the server client.
//! Used by the `nn-agent` and `nn-agent-helper` programs.

pub mod client;
pub mod collector;
pub mod collectors;
pub mod config;
pub mod pull;
pub mod report;

/// Build identity shared by the CLI and push/pull reports.
pub const VERSION: &str = match option_env!("NN_VERSION") {
    Some(version) if !version.is_empty() => version,
    _ => env!("CARGO_PKG_VERSION"),
};
