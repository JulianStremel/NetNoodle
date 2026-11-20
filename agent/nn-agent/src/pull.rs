//! Pull-mode pairing and a sequential, certificate-pinned HTTPS listener.

use crate::{client, collector::Collector, config::Config, report};
use hmac::{Hmac, Mac};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};
use std::time::{Duration, Instant, SystemTime};

const MAX_HEAD: usize = 8 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);
const REPORT_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize)]
struct State {
    listen: SocketAddr,
    server_fingerprint: String,
    cert: String,
    key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    fn digit(b: u8) -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err("invalid hex in pull state".into()),
        }
    }
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return Err("invalid hex in pull state".into());
    }
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[hi, lo]| Ok(digit(*hi)? * 16 + digit(*lo)?))
        .collect()
}

fn fingerprint(s: &str) -> Result<[u8; 32], String> {
    // parse_fingerprint slices pairs of bytes; reject non-ASCII first.
    if !s.is_ascii() {
        return Err("fingerprint must be 64 hex characters (SHA-256)".into());
    }
    client::parse_fingerprint(s)
}

impl State {
    fn load(path: &Path) -> Result<Self, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("{}: {e} (run nn-agent pair first)", path.display()))?;
        serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let data = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        // Secure an existing file before writing the key to it, too.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("{}: {e}", path.display()))?;
        }
        file.write_all(&data)
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    fn agent_fingerprint(&self) -> Result<String, String> {
        Ok(hex(&Sha256::digest(unhex(&self.cert)?)))
    }
}

fn identity(hostname: &str) -> Result<(String, String), String> {
    let key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, format!("nn-agent {hostname}"));
    let now = SystemTime::now();
    params.not_before = (now - Duration::from_secs(3600)).into();
    params.not_after = now.into();
    let end_year = params.not_after.year() + 10;
    // February 29 becomes February 28 if the end year is not a leap year.
    params.not_after = params
        .not_after
        .replace_year(end_year)
        .or_else(|_| params.not_after.replace_day(28)?.replace_year(end_year))
        .map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key).map_err(|e| e.to_string())?;
    Ok((hex(cert.der().as_ref()), hex(&key.serialize_der())))
}

/// Stores a pull identity and a new one-time pairing code.
pub fn pair(
    path: &Path,
    code: &str,
    server_fingerprint: &str,
    listen: &str,
    new_key: bool,
    hostname: &str,
) -> Result<(), String> {
    let code = code.trim();
    if code.is_empty() || code.chars().count() > 128 {
        return Err("pairing code must contain 1 to 128 characters".into());
    }
    let server_fingerprint = hex(&fingerprint(server_fingerprint)?);
    let listen = listen
        .parse::<SocketAddr>()
        .map_err(|e| format!("listen: {e}"))?;
    let (cert, key) = if !new_key && path.try_exists().map_err(|e| e.to_string())? {
        let old = State::load(path)?;
        // Refuse to preserve an invalid or mismatched identity.
        tls_config(&old)?;
        (old.cert, old.key)
    } else {
        identity(hostname)?
    };
    let state = State {
        listen,
        server_fingerprint,
        cert,
        key,
        code: Some(code.into()),
    };
    state.save(path)?;
    println!("state: {}", path.display());
    println!("listen: {}", state.listen);
    println!("agent fingerprint: {}", state.agent_fingerprint()?);
    println!("start the service: nn-agent serve");
    Ok(())
}

fn proof(code: &str, agent_fp: &str, server_fp: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(code.as_bytes()).expect("HMAC accepts keys of every size");
    mac.update(b"netnoodle-pair-v1\n");
    mac.update(agent_fp.as_bytes());
    mac.update(b"\n");
    mac.update(server_fp.as_bytes());
    hex(&mac.finalize().into_bytes())
}

#[derive(Debug)]
struct ClientPin {
    want: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for ClientPin {
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if Sha256::digest(end_entity.as_ref()).as_slice() == self.want {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "client certificate does not match the pinned server".into(),
            ))
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

fn tls_config(state: &State) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let pin = ClientPin {
        want: fingerprint(&state.server_fingerprint)?,
        provider: provider.clone(),
    };
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(Arc::new(pin))
        .with_single_cert(
            vec![CertificateDer::from(unhex(&state.cert)?)],
            PrivatePkcs8KeyDer::from(unhex(&state.key)?).into(),
        )
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(config))
}

// Reapply the remaining deadline on every socket read, including reads that
// rustls performs internally. Dribbling TLS records cannot extend the limit.
struct DeadlineStream {
    socket: TcpStream,
    deadline: Instant,
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "request read timeout"))?;
        self.socket.set_read_timeout(Some(left))?;
        self.socket.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

#[derive(Debug)]
enum HeadError {
    TooLarge,
    BadRequest,
    Io(io::Error),
}

fn request_head(reader: &mut impl Read) -> Result<(String, String), HeadError> {
    let mut head = Vec::new();
    let mut buf = [0; 1024];
    loop {
        let n = reader.read(&mut buf).map_err(HeadError::Io)?;
        if n == 0 {
            return Err(HeadError::BadRequest);
        }
        head.extend_from_slice(&buf[..n]);
        if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            if end + 4 > MAX_HEAD {
                return Err(HeadError::TooLarge);
            }
            let line_end = head
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or(HeadError::BadRequest)?;
            let line = std::str::from_utf8(&head[..line_end]).map_err(|_| HeadError::BadRequest)?;
            return request_line(line);
        }
        if head.len() > MAX_HEAD {
            return Err(HeadError::TooLarge);
        }
    }
}

fn request_line(line: &str) -> Result<(String, String), HeadError> {
    let parts: Vec<_> = line.split(' ').collect();
    if parts.len() != 3 {
        return Err(HeadError::BadRequest);
    }
    let (method, path, version) = (parts[0], parts[1], parts[2]);
    // RFC HTTP token syntax; valid methods other than GET receive 405.
    if method.is_empty()
        || !method
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        || !path.starts_with('/')
        || path.bytes().any(|b| b.is_ascii_control())
        || version.len() != 8
        || !version.starts_with("HTTP/1.")
        || !version.as_bytes()[7].is_ascii_digit()
    {
        return Err(HeadError::BadRequest);
    }
    Ok((method.into(), path.into()))
}

fn respond(writer: &mut impl Write, status: u16, body: &[u8]) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        _ => "Internal Server Error",
    };
    write!(writer, "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", body.len())?;
    writer.write_all(body)?;
    writer.flush()
}

struct Server<'a> {
    cfg: &'a Config,
    collectors: &'a [Box<dyn Collector>],
    name: &'a str,
    state: State,
    agent_fp: String,
    last_report: Option<Instant>,
}

impl Server<'_> {
    fn request(&mut self, stream: &mut (impl Read + Write)) -> Result<(), String> {
        let (method, path) = match request_head(stream) {
            Ok(request) => request,
            Err(HeadError::Io(e)) => return Err(e.to_string()),
            Err(e) => {
                let (status, message) = match e {
                    HeadError::TooLarge => (431, "request head too large"),
                    _ => (400, "bad request"),
                };
                let body = serde_json::to_vec(&serde_json::json!({"error": message}))
                    .map_err(|e| e.to_string())?;
                respond(stream, status, &body).map_err(|e| e.to_string())?;
                return Err(message.into());
            }
        };
        let (status, body) = if path != "/v1/pair" && path != "/v1/report" {
            (404, br#"{"error":"not found"}"#.to_vec())
        } else if method != "GET" {
            (405, br#"{"error":"method not allowed"}"#.to_vec())
        } else if path == "/v1/pair" {
            match &self.state.code {
                Some(code) => (
                    200,
                    serde_json::to_vec(&serde_json::json!({"version": "v1", "proof": proof(code, &self.agent_fp, &self.state.server_fingerprint)}))
                        .map_err(|e| e.to_string())?,
                ),
                None => (404, br#"{"error":"not found"}"#.to_vec()),
            }
        } else if self
            .last_report
            .is_some_and(|t| t.elapsed() < REPORT_INTERVAL)
        {
            (429, br#"{"error":"too many requests"}"#.to_vec())
        } else {
            let r = report::collect(&self.cfg.ctx(None), self.collectors);
            self.last_report = Some(Instant::now());
            for e in &r.errors {
                eprintln!("nn-agent: collector {e}");
            }
            let obs = report::observation(r, self.name);
            let body = serde_json::to_vec(&obs).map_err(|e| e.to_string())?;
            (200, body)
        };
        respond(stream, status, &body).map_err(|e| e.to_string())?;
        if status == 200 && path == "/v1/report" && self.state.code.take().is_some() {
            if let Err(e) = self.state.save(&self.cfg.pull_state()) {
                eprintln!("nn-agent: removing pairing code: {e}");
            }
        }
        Ok(())
    }
}

fn serve_on(
    listener: TcpListener,
    cfg: &Config,
    collectors: &[Box<dyn Collector>],
    name: &str,
    state: State,
    stop: Option<&AtomicBool>,
) -> Result<(), String> {
    let tls = tls_config(&state)?;
    let mut server = Server {
        cfg,
        collectors,
        name,
        agent_fp: state.agent_fingerprint()?,
        state,
        last_report: None,
    };
    listener
        .set_nonblocking(stop.is_some())
        .map_err(|e| e.to_string())?;
    while !stop.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
        let socket = match listener.accept() {
            Ok((socket, _)) => socket,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(e) => {
                eprintln!("nn-agent: accept: {e}");
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let result = (|| {
            // An accepted socket is explicitly blocking on both platforms.
            socket.set_nonblocking(false).map_err(|e| e.to_string())?;
            socket
                .set_read_timeout(Some(READ_TIMEOUT))
                .map_err(|e| e.to_string())?;
            socket
                .set_write_timeout(Some(WRITE_TIMEOUT))
                .map_err(|e| e.to_string())?;
            let conn = rustls::ServerConnection::new(tls.clone()).map_err(|e| e.to_string())?;
            let socket = DeadlineStream {
                socket,
                deadline: Instant::now() + READ_TIMEOUT,
            };
            let mut stream = rustls::StreamOwned::new(conn, socket);
            while stream.conn.is_handshaking() {
                stream
                    .conn
                    .complete_io(&mut stream.sock)
                    .map_err(|e| e.to_string())?;
            }
            stream.sock.deadline = Instant::now() + READ_TIMEOUT;
            let result = server.request(&mut stream);
            stream.conn.send_close_notify();
            stream.flush().map_err(|e| e.to_string())?;
            result
        })();
        if let Err(e) = result {
            eprintln!("nn-agent: {e}");
        }
    }
    Ok(())
}

/// Serves reports to the one server pinned during pairing.
pub fn serve(
    cfg: &Config,
    collectors: &[Box<dyn Collector>],
    hostname: &str,
) -> Result<(), String> {
    let state = State::load(&cfg.pull_state())?;
    let listener = TcpListener::bind(state.listen).map_err(|e| format!("{}: {e}", state.listen))?;
    eprintln!(
        "nn-agent: listening on {}, agent fingerprint {}, accepting only server {}",
        listener.local_addr().map_err(|e| e.to_string())?,
        state.agent_fingerprint()?,
        state.server_fingerprint
    );
    serve_on(listener, cfg, collectors, hostname, state, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::ServerName;
    use std::path::PathBuf;
    use std::thread::JoinHandle;

    const CODE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "nn-agent-pull-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn state(server_cert: &str) -> State {
        let (cert, key) = identity("test-agent").unwrap();
        State {
            listen: "127.0.0.1:0".parse().unwrap(),
            server_fingerprint: hex(&Sha256::digest(unhex(server_cert).unwrap())),
            cert,
            key,
            code: Some(CODE.into()),
        }
    }

    #[test]
    fn hmac_fixed_vector() {
        // Independently computed with Python's hmac.new(..., hashlib.sha256).
        assert_eq!(
            proof(CODE, &"a".repeat(64), &"b".repeat(64)),
            "7ed0c7236c00d91067160e5c434ae2b07c4c257c46d0a2837ade5855e1f9d5dc"
        );
    }

    #[test]
    fn pull_state_config() {
        assert_eq!(
            Config::default().pull_state(),
            PathBuf::from(crate::config::DEFAULT_PULL_STATE)
        );
        let cfg: Config = serde_json::from_str(r#"{"pull_state":"custom-pull.json"}"#).unwrap();
        assert_eq!(cfg.pull_state(), PathBuf::from("custom-pull.json"));
        #[cfg(windows)]
        assert_eq!(
            crate::config::DEFAULT_PULL_STATE,
            r"C:\ProgramData\netnoodle\agent\pull.json"
        );
        #[cfg(not(windows))]
        assert_eq!(
            crate::config::DEFAULT_PULL_STATE,
            "/var/lib/nn-agent/pull.json"
        );
    }

    #[test]
    fn client_verifier_requires_authentication() {
        let pin = ClientPin {
            want: [0; 32],
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        };
        assert!(pin.offer_client_auth());
        assert!(pin.client_auth_mandatory());
        assert!(pin.root_hint_subjects().is_empty());
    }

    #[test]
    fn request_head_parsing() {
        let request = b"GET /v1/pair HTTP/1.1\r\nHost: localhost\r\n\r\nignored body";
        assert_eq!(
            request_head(&mut &request[..]).unwrap(),
            ("GET".into(), "/v1/pair".into())
        );
        let mut exact = b"GET /v1/pair HTTP/1.0\r\nX: ".to_vec();
        exact.resize(MAX_HEAD - 4, b'a');
        exact.extend_from_slice(b"\r\n\r\n");
        assert!(request_head(&mut exact.as_slice()).is_ok());
        // A body does not count against the request-head limit.
        exact.extend_from_slice(&[b'x'; 2048]);
        assert!(request_head(&mut exact.as_slice()).is_ok());
        let mut oversize = b"GET /v1/pair HTTP/1.1\r\nX: ".to_vec();
        oversize.resize(MAX_HEAD + 1, b'a');
        assert!(matches!(
            request_head(&mut oversize.as_slice()),
            Err(HeadError::TooLarge)
        ));
        oversize.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(
            request_head(&mut oversize.as_slice()),
            Err(HeadError::TooLarge)
        ));
        for line in [
            "G(ET /v1/pair HTTP/1.1",
            "GET /v1/pair",
            "GET /v1/pair HTTP/2.0",
            "GET  /v1/pair HTTP/1.1",
        ] {
            let request = format!("{line}\r\n\r\n");
            assert!(
                matches!(
                    request_head(&mut request.as_bytes()),
                    Err(HeadError::BadRequest)
                ),
                "{line}"
            );
        }
        assert_eq!(request_line("POST /v1/report HTTP/1.1").unwrap().0, "POST");
    }

    #[test]
    fn state_roundtrip_and_pairing() {
        let dir = TempDir::new();
        let path = dir.0.join("nested/pull.json");
        let pin = "AB:".repeat(31) + "AB";
        pair(
            &path,
            &format!("  {CODE}\n"),
            &pin,
            "127.0.0.1:7444",
            false,
            "test",
        )
        .unwrap();
        let first = State::load(&path).unwrap();
        assert_eq!(first.code.as_deref(), Some(CODE));
        assert_eq!(first.server_fingerprint, "ab".repeat(32));
        assert_eq!(first.listen.to_string(), "127.0.0.1:7444");
        assert!(tls_config(&first).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        pair(&path, "replacement", &pin, "127.0.0.1:7445", false, "test").unwrap();
        let mut second = State::load(&path).unwrap();
        assert_eq!(second.cert, first.cert);
        assert_eq!(second.key, first.key);
        assert_eq!(second.code.as_deref(), Some("replacement"));
        second.code = None;
        second.save(&path).unwrap();
        assert!(State::load(&path).unwrap().code.is_none());
        assert!(
            !serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap())
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("code")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        pair(&path, CODE, &pin, "127.0.0.1:7444", true, "test").unwrap();
        let renewed = State::load(&path).unwrap();
        assert_ne!(renewed.cert, first.cert);
        assert_ne!(renewed.key, first.key);
        for code in [" ".to_string(), "x".repeat(129)] {
            assert!(pair(&path, &code, &pin, "127.0.0.1:7444", false, "test").is_err());
        }
        assert!(pair(&path, CODE, "bad", "127.0.0.1:7444", false, "test").is_err());
        assert!(pair(&path, CODE, &pin, "localhost:7444", false, "test").is_err());
        assert_eq!(State::load(&path).unwrap().cert, renewed.cert);
        assert!(State::load(&dir.0.join("missing"))
            .err()
            .unwrap()
            .contains("run nn-agent pair first"));
    }

    struct TestServer {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
        cert: String,
        path: PathBuf,
        _dir: TempDir,
    }

    impl TestServer {
        fn start(state: State) -> Self {
            let dir = TempDir::new();
            let path = dir.0.join("pull.json");
            state.save(&path).unwrap();
            let cfg = Config {
                pull_state: Some(path.clone()),
                ..Config::default()
            };
            let listener = TcpListener::bind(state.listen).unwrap();
            let addr = listener.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = stop.clone();
            let cert = state.cert.clone();
            let thread = std::thread::spawn(move || {
                // Construct collectors inside the thread; Collector need not be Send.
                serve_on(listener, &cfg, &[], "test-host", state, Some(&thread_stop)).unwrap();
            });
            Self {
                addr,
                stop,
                thread: Some(thread),
                cert,
                path,
                _dir: dir,
            }
        }

        fn client_config(
            &self,
            identity: Option<&(String, String)>,
            version: &'static rustls::SupportedProtocolVersion,
        ) -> Arc<rustls::ClientConfig> {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let verifier = TestAgentPin(ClientPin {
                want: Sha256::digest(unhex(&self.cert).unwrap()).into(),
                provider: provider.clone(),
            });
            let builder = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[version])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier));
            Arc::new(match identity {
                Some((cert, key)) => builder
                    .with_client_auth_cert(
                        vec![CertificateDer::from(unhex(cert).unwrap())],
                        PrivatePkcs8KeyDer::from(unhex(key).unwrap()).into(),
                    )
                    .unwrap(),
                None => builder.with_no_client_auth(),
            })
        }

        fn exchange(
            &self,
            config: Arc<rustls::ClientConfig>,
            request: &[u8],
        ) -> io::Result<String> {
            let socket = TcpStream::connect(self.addr)?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            socket.set_write_timeout(Some(Duration::from_secs(5)))?;
            // The test agent certificate has only a CN, so use the custom
            // verifier below for pinning rather than DNS-name validation.
            let conn =
                rustls::ClientConnection::new(config, ServerName::try_from("localhost").unwrap())
                    .unwrap();
            let mut stream = rustls::StreamOwned::new(conn, socket);
            stream.write_all(request)?;
            stream.flush()?;
            let mut response = String::new();
            stream.read_to_string(&mut response)?;
            Ok(response)
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    #[derive(Debug)]
    struct TestAgentPin(ClientPin);

    impl rustls::client::danger::ServerCertVerifier for TestAgentPin {
        fn verify_server_cert(
            &self,
            cert: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _name: &ServerName<'_>,
            _ocsp: &[u8],
            now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            self.0.verify_client_cert(cert, intermediates, now)?;
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.0.verify_tls12_signature(message, cert, dss)
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            self.0.verify_tls13_signature(message, cert, dss)
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.supported_verify_schemes()
        }
    }

    fn assert_response(response: &str, status: u16) -> serde_json::Value {
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status} ")),
            "{response}"
        );
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        assert!(head.contains("\r\nConnection: close"));
        assert!(head.contains("\r\nContent-Type: application/json"));
        assert!(head.contains(&format!("\r\nContent-Length: {}", body.len())));
        serde_json::from_str(body).unwrap()
    }

    #[test]
    fn mutual_tls_end_to_end() {
        for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
            let client = identity("test-server").unwrap();
            let state = state(&client.0);
            let expected = proof(
                CODE,
                &state.agent_fingerprint().unwrap(),
                &state.server_fingerprint,
            );
            let server = TestServer::start(state);
            let good = server.client_config(Some(&client), version);
            let exchange = |request: &[u8]| server.exchange(good.clone(), request).unwrap();
            let pair = assert_response(
                &exchange(b"GET /v1/pair HTTP/1.1\r\nHost: test\r\n\r\n"),
                200,
            );
            assert_eq!(pair["proof"], expected);
            assert_eq!(pair["version"], "v1");
            assert_response(&exchange(b"POST /v1/report HTTP/1.1\r\n\r\n"), 405);
            assert_response(&exchange(b"GET /unknown HTTP/1.1\r\n\r\n"), 404);
            assert_response(&exchange(b"GET /v1/report\r\n\r\n"), 400);
            let mut oversize = b"GET /v1/report HTTP/1.1\r\nX: ".to_vec();
            oversize.resize(MAX_HEAD, b'a');
            oversize.extend_from_slice(b"\r\n\r\n");
            assert_response(&exchange(&oversize), 431);
            let report = assert_response(&exchange(b"GET /v1/report HTTP/1.1\r\n\r\n"), 200);
            assert_eq!(report["version"], "v1");
            assert_eq!(report["source"], "test-host");
            assert_response(&exchange(b"GET /v1/report HTTP/1.1\r\n\r\n"), 429);
            // The sequential server persists code removal before accepting this request.
            assert_response(&exchange(b"GET /v1/pair HTTP/1.1\r\n\r\n"), 404);
            assert!(State::load(&server.path).unwrap().code.is_none());
            let wrong = identity("different-server").unwrap();
            for identity in [Some(&wrong), None] {
                let config = server.client_config(identity, version);
                // TLS 1.3 may finish client-side before receiving the server's
                // rejection alert; reading the response must still fail.
                assert!(server
                    .exchange(config, b"GET /v1/pair HTTP/1.1\r\n\r\n")
                    .is_err());
            }
            // Rejected clients do not stop the accept loop.
            assert_response(&exchange(b"GET /v1/pair HTTP/1.1\r\n\r\n"), 404);
        }
    }
}
