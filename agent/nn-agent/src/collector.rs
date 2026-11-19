//! The collector plug-in contract.
//!
//! A collector reads one kind of data (packages, sockets, containers, ...).
//! It declares the access it needs before it runs, so the operator can see
//! the full scope of the agent (`nn-agent scope`), and the agent can refuse
//! collectors that are not enabled in the config.

use nn_proto::{Component, Entity};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Access that a collector needs. Shown to the operator; never widened at run time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Access {
    /// Files and directories the collector reads.
    pub reads: Vec<&'static str>,
    /// Unix sockets the collector connects to.
    pub sockets: Vec<&'static str>,
    /// Programs the collector executes (read-only queries only).
    pub execs: Vec<&'static str>,
    /// What the collector cannot see without root or extra capabilities.
    /// Empty if it gives full data as an unprivileged user.
    pub privileged: &'static str,
}

/// Runtime context for collectors.
pub struct Ctx {
    /// Root of the file system to read (normally "/"). Tests point it at fixtures.
    pub root: PathBuf,
}

impl Ctx {
    /// Maps an absolute path like "/etc/os-release" below the root.
    pub fn path(&self, abs: &str) -> PathBuf {
        self.root.join(abs.trim_start_matches('/'))
    }
    /// True if the agent reads the live system (root is "/").
    pub fn is_live(&self) -> bool {
        self.root == Path::new("/")
    }
}

/// What a collector adds to the report.
#[derive(Debug, Default)]
pub struct Contribution {
    /// Data merged into the host entity (components, services, interfaces, attributes, identifiers).
    pub host: Entity,
    /// Executable path of each entry in `host.services` ("" if unknown). Used to
    /// find the package that owns a listening program.
    pub service_exes: Vec<String>,
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
    /// Package collectors return the package that owns each of the given
    /// files. Other collectors keep the default (no owners).
    fn owners(&self, _ctx: &Ctx, _paths: &[String]) -> BTreeMap<String, Component> {
        BTreeMap::new()
    }
}
