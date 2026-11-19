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

fn error_text(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let msg = resp
                .into_json::<serde_json::Value>()
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
    let r: Resp = http_agent(fingerprint)?
        .post(&format!("{server}/v1/enroll"))
        .send_json(serde_json::json!({"join_token": token, "name": name}))
        .map_err(error_text)?
        .into_json()
        .map_err(|e| e.to_string())?;
    Ok(Credentials {
        server,
        fingerprint: fingerprint.to_string(),
        name: r.name,
        role: r.role,
        token: r.token,
    })
}

/// Sends an observation. Returns the server's summary.
pub fn post_observation(c: &Credentials, obs: &Observation) -> Result<serde_json::Value, String> {
    http_agent(&c.fingerprint)?
        .post(&format!("{}/v1/observations", c.server))
        .set("Authorization", &format!("Bearer {}", c.token))
        .send_json(obs)
        .map_err(error_text)?
        .into_json()
        .map_err(|e| e.to_string())
}

/// Writes credentials to a file that only the owner can read.
pub fn save(path: &Path, c: &Credentials) -> Result<(), String> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let data = serde_json::to_vec_pretty(c).map_err(|e| e.to_string())?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(path)
        .and_then(|mut f| f.write_all(&data))
        .map_err(|e| format!("{}: {e}", path.display()))
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
}
