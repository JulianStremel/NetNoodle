//! Agent configuration file (JSON). Every field is optional.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_CONFIG: &str = "/etc/nn-agent/config.json";
pub const DEFAULT_CREDENTIALS: &str = "/var/lib/nn-agent/credentials.json";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Credentials file written by `nn-agent enroll`.
    pub credentials: Option<PathBuf>,
    /// Time between reports, e.g. "1h". Default 1h, minimum 1m.
    pub interval: Option<String>,
    /// Collectors to run. Default: all built-in collectors.
    pub collectors: Option<Vec<String>>,
    /// Root of the file system to read. Default "/".
    pub root: Option<PathBuf>,
}

impl Config {
    /// Reads the file. A missing file gives the defaults.
    pub fn load(path: &Path) -> Result<Config, String> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn credentials(&self) -> PathBuf {
        self.credentials
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CREDENTIALS))
    }

    pub fn root(&self) -> PathBuf {
        self.root.clone().unwrap_or_else(|| PathBuf::from("/"))
    }

    pub fn interval(&self) -> Result<Duration, String> {
        let d = match &self.interval {
            Some(s) => humantime::parse_duration(s).map_err(|e| format!("interval {s:?}: {e}"))?,
            None => Duration::from_secs(3600),
        };
        Ok(d.max(Duration::from_secs(60)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_defaults() {
        let c: Config = serde_json::from_str(r#"{"interval":"15m","collectors":["os"]}"#).unwrap();
        assert_eq!(c.interval().unwrap(), Duration::from_secs(900));
        assert_eq!(c.root(), PathBuf::from("/"));
        assert!(serde_json::from_str::<Config>(r#"{"bogus":1}"#).is_err());
        let d = Config::default();
        assert_eq!(d.interval().unwrap(), Duration::from_secs(3600));
    }
}
