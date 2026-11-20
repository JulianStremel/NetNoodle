//! Connection to nn-server: enrollment and observations over HTTPS. The
//! server certificate is pinned by its SHA-256 fingerprint.

use nn_proto::Observation;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// What the agent stores after enrollment. Same format as the Go peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub server: String,
    pub fingerprint: String,
    pub name: String,
    pub role: String,
    pub token: String,
}

/// Decodes a hex fingerprint; colons and case are ignored.
pub fn parse_fingerprint(fp: &str) -> Result<[u8; 32], String> {
    let s: String = fp
        .trim()
        .chars()
        .filter(|c| *c != ':')
        .collect::<String>()
        .to_lowercase();
    let err = || "fingerprint must be 64 hex characters (SHA-256)".to_string();
    if s.len() != 64 {
        return Err(err());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| err())?;
    }
    Ok(out)
}

/// Accepts exactly one leaf certificate. Handshake signatures are still verified.
#[derive(Debug)]
struct Pin {
    want: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = Sha256::digest(end_entity.as_ref());
        if got.as_slice() == self.want {
            Ok(ServerCertVerified::assertion())
        } else {
            let hex: String = got.iter().map(|b| format!("{b:02x}")).collect();
            Err(rustls::Error::General(format!(
                "server certificate fingerprint {hex} does not match the pinned one"
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn http_agent(fingerprint: &str) -> Result<ureq::Agent, String> {
    let want = parse_fingerprint(fingerprint)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pin { want, provider }))
        .with_no_client_auth();
    Ok(ureq::AgentBuilder::new()
        .tls_config(Arc::new(tls))
        .timeout(Duration::from_secs(120))
        .user_agent(concat!("nn-agent/", env!("CARGO_PKG_VERSION")))
        .build())
}

/// Largest server answer the agent reads (security review 2026-11-20: a
/// compromised server could stream an unbounded JSON value).
const MAX_RESPONSE: u64 = 64 << 10;

/// Reads a JSON answer of at most MAX_RESPONSE bytes.
fn read_json<T: serde::de::DeserializeOwned>(resp: ureq::Response) -> Result<T, String> {
    use std::io::Read;
    let mut buf = Vec::new();
    resp.into_reader()
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    if buf.len() as u64 > MAX_RESPONSE {
        return Err(format!("server answer larger than {MAX_RESPONSE} bytes"));
    }
    serde_json::from_slice(&buf).map_err(|e| e.to_string())
}

fn error_text(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let msg = read_json::<serde_json::Value>(resp)
                .ok()
                .and_then(|v| v.get("error").and_then(|m| m.as_str()).map(String::from))
                .unwrap_or_default();
            format!("server answered {code} {msg}")
        }
        ureq::Error::Transport(t) => t.to_string(),
    }
}

/// Exchanges a join token for credentials.
pub fn enroll(
    server: &str,
    fingerprint: &str,
    token: &str,
    name: &str,
) -> Result<Credentials, String> {
    #[derive(Deserialize)]
    struct Resp {
        name: String,
        role: String,
        token: String,
    }
    let server = server.trim_end_matches('/').to_string();
    require_https(&server)?;
    let r: Resp = read_json(
        http_agent(fingerprint)?
            .post(&format!("{server}/v1/enroll"))
            .send_json(serde_json::json!({"join_token": token, "name": name}))
            .map_err(error_text)?,
    )?;
    Ok(Credentials {
        server,
        fingerprint: fingerprint.to_string(),
        name: r.name,
        role: r.role,
        token: r.token,
    })
}

/// The fingerprint pin protects only https connections.
fn require_https(server: &str) -> Result<(), String> {
    if server.to_ascii_lowercase().starts_with("https://") {
        Ok(())
    } else {
        Err(format!(
            "server URL must start with https:// (got {server:?})"
        ))
    }
}

/// Sends an observation. Returns the server's summary.
pub fn post_observation(c: &Credentials, obs: &Observation) -> Result<serde_json::Value, String> {
    require_https(&c.server)?;
    read_json(
        http_agent(&c.fingerprint)?
            .post(&format!("{}/v1/observations", c.server))
            .set("Authorization", &format!("Bearer {}", c.token))
            .send_json(obs)
            .map_err(error_text)?,
    )
}

/// Writes credentials to a file that only the owner can read: a new file
/// (mode 0600 before any byte is written) replaces the old one atomically.
/// A symlink at `path` is replaced, not followed, and a directory that other
/// users can write is refused (security review 2026-11-20).
pub fn save(path: &Path, c: &Credentials) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(c).map_err(|e| e.to_string())?;
    write_private(path, &data)
}

/// Writes secret data to `path` as a new 0600 file that replaces the old
/// one atomically (see `save`). Used for credentials and the pull state.
pub fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .permissions()
            .mode();
        if mode & 0o022 != 0 {
            return Err(format!(
                "{}: directory is writable by other users",
                dir.display()
            ));
        }
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "credentials".into());
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    let written = opts.open(&tmp).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()
    });
    if let Err(e) = written.and_then(|_| std::fs::rename(&tmp, path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{}: {e}", path.display()));
    }
    #[cfg(unix)]
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// Reads a credentials file.
pub fn load(path: &Path) -> Result<Credentials, String> {
    let b = std::fs::read(path)
        .map_err(|e| format!("{}: {e} (run nn-agent enroll first)", path.display()))?;
    let c: Credentials =
        serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))?;
    if c.server.is_empty() || c.token.is_empty() || c.fingerprint.is_empty() {
        return Err(format!("{}: incomplete; enroll again", path.display()));
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_forms() {
        let hex = "bd9e6a1f5945e9850771682543db49e1966f50aaf8542e7821dda7b375015416";
        let a = parse_fingerprint(hex).unwrap();
        let colons: Vec<String> = (0..32)
            .map(|i| hex[i * 2..i * 2 + 2].to_uppercase())
            .collect();
        assert_eq!(parse_fingerprint(&colons.join(":")).unwrap(), a);
        assert!(parse_fingerprint("abc").is_err());
    }

    // Security review 2026-11-20: bounded answers, private atomic credentials.
    #[test]
    fn answers_are_bounded() {
        let small = ureq::Response::new(200, "OK", r#"{"ok":true}"#).unwrap();
        assert!(read_json::<serde_json::Value>(small).is_ok());
        let big = format!(r#"{{"x":"{}"}}"#, "a".repeat(MAX_RESPONSE as usize));
        let big = ureq::Response::new(200, "OK", &big).unwrap();
        assert!(read_json::<serde_json::Value>(big).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn save_replaces_symlink_and_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("nn-agent-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let path = dir.join("creds.json");
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        let c = Credentials {
            server: "https://s".into(),
            fingerprint: "f".into(),
            name: "n".into(),
            role: "agent".into(),
            token: "secret".into(),
        };
        save(&path, &c).unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
        let m = std::fs::symlink_metadata(&path).unwrap();
        assert!(!m.file_type().is_symlink());
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
        let shared = dir.join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(save(&shared.join("c.json"), &c).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
