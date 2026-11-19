//! The collector plug-in contract.
//!
//! A collector reads one kind of data (packages, sockets, containers, ...).
//! It declares the access it needs before it runs, so the operator can see
//! the full scope of the agent (`nn-agent scope`), and the agent can refuse
//! collectors that are not enabled in the config.

use nn_proto::Entity;

/// Access that a collector needs. Shown to the operator; never widened at run time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Access {
    /// Files and directories the collector reads.
    pub reads: Vec<String>,
    /// Unix sockets the collector connects to.
    pub sockets: Vec<String>,
    /// Programs the collector executes (read-only queries only).
    pub execs: Vec<String>,
    /// True if the collector needs root or extra capabilities to give full data.
    pub privileged: bool,
}

/// Runtime context for collectors.
pub struct Ctx {
    /// Root of the file system to read (normally "/"). Tests point it at fixtures.
    pub root: std::path::PathBuf,
}

/// What a collector adds to the report.
#[derive(Debug, Default)]
pub struct Contribution {
    /// Data merged into the host entity (components, services, interfaces, attributes, identifiers).
    pub host: Entity,
    /// Child entities (containers, VMs).
    pub children: Vec<Entity>,
}

/// A collector plug-in.
pub trait Collector {
    /// Stable name, used in the config to enable the collector.
    fn name(&self) -> &'static str;
    /// The access this collector needs.
    fn access(&self) -> Access;
    /// Collects data. Errors are reported but do not stop other collectors.
    fn collect(&self, ctx: &Ctx) -> Result<Contribution, String>;
}
