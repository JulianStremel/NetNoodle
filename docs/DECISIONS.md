# Decision log

Decisions made without explicit user input, for later review.
Status: `proposed` (made by Claude, not yet reviewed), `accepted` (confirmed by the user), `open` (needs user input).

| ID | Date | Decision | Reason | Alternatives | Status |
|---|---|---|---|---|---|
| D-001 | 2026-11-19 | Greenfield restart. Go server, Rust agent and host actor. Dependencies are used freely; `go.sum` and `Cargo.lock` are committed. | User request. | — | accepted |
| D-002 | 2026-11-19 | Every pluggable part is an interface + generic `registry.Registry[T]`, selected by `{type,name,settings}` config entries. | User request: modular, generic interfaces so new actors etc. can be added later. | Hard-coded switch statements. | accepted |
| D-003 | 2026-11-19 | Go module path is `netnoodle`. | Simple; no remote decided. Easy to rename later. | `github.com/<user>/netnoodle`. | open |
| D-004 | 2026-11-19 | SQLite via `modernc.org/sqlite` (pure Go, no cgo). One open connection. | Single binary, works on Windows without a C compiler. One connection avoids `SQLITE_BUSY` on writes. | Postgres (more ops work), `mattn/go-sqlite3` (cgo). | proposed |
| D-005 | 2026-11-19 | `modernc.org/sqlite` needs Go 1.26; `go.mod` says `go 1.26.0` and Go downloads the toolchain. | Required by the driver. | Older driver version. | proposed |
| D-006 | 2026-11-19 | Web UI is plain HTML/CSS/JS ES modules embedded with `embed`, no build step. Pages register through `registerView`. | Fastest path to a working UI; nothing to install. | React/Svelte with a bundler. | proposed |
| D-007 | 2026-11-19 | Server TLS: self-signed ECDSA P-256 cert made on first start (10 years). Clients pin the SHA-256 fingerprint. | No CA to operate; pinning gives strong server identity. | Own CA + mTLS (more work), ACME (needs a domain). | proposed |
| D-008 | 2026-11-19 | Operator auth: bcrypt passwords, random session token (hash stored), `SameSite=Strict` cookie, JSON-only writes against CSRF, 10 failed logins / 5 min per IP. First start creates `admin` with a random password printed once. | Simple and safe enough for a LAN tool. | OIDC (later option), WebAuthn. | proposed |
| D-009 | 2026-11-19 | Default listen port is `:7443`. | `8443` is often taken (Docker Desktop holds `127.0.0.1:8443` on this machine). | 8443, 9443. | proposed |
| D-010 | 2026-11-19 | Components (sources, agents, actors) will enroll with a one-time join token and get a long random API token bound to a role. | Simple, revocable, no PKI. | mTLS client certificates. | proposed |
| D-011 | 2026-11-19 | Identity model: identifiers `{kind, value, strength}`; strong ids decide, weak ids only hint; parent links form the device tree. | Lets any source or agent describe devices without server changes. | Fixed MAC/IP/hostname columns. | proposed |
| D-012 | 2026-11-19 | Vulnerability matching via OSV `querybatch` by PURL; KEV and EPSS as enrichers. | OSV handles version rules of all ecosystems (deb, rpm, apk, ...). | Own NVD/CPE matching. | proposed |
| D-013 | 2026-11-19 | Orders are ed25519-signed by the server; actors check signature, expiry, nonce and a local allowlist. | Actors are the dangerous part; a compromised network path must not cause actions. | Bearer token only. | proposed |
| D-014 | 2026-11-19 | The LLM decider can only make a proposal safer (lower tier or require approval). | LLM output is not trusted to widen scope. | LLM free to choose. | proposed |
| D-015 | 2026-11-19 | `nn-scan` uses TCP connect only (open or refused = host up), no ICMP or raw sockets. 16 parallel ports per host, 32 hosts in parallel. | Runs without root on every OS. Hosts that drop all probed ports stay invisible to the scan but appear via gateway import. | ICMP via raw socket helper. | proposed |
| D-016 | 2026-11-19 | Locally administered MACs are demoted to weak identifiers by the server, whatever the source says. | Docker/VM bridge MACs repeat across hosts; randomized phone MACs rotate. | Trust the source. | proposed |
| D-017 | 2026-11-19 | The server overwrites `source` with the peer name and adds `agent=<peer>` to agent reports; agents must send one top-level entity. | A peer cannot impersonate another source or claim other devices. | Trust the body. | proposed |
| D-018 | 2026-11-19 | UniFi firmware is stored as attribute and as component `pkg:generic/ubiquiti/<model>@<fw>`. | Visible in inventory now; a firmware advisory feed can match it later (OSV has no UniFi data). | Attribute only. | proposed |
| D-019 | 2026-11-19 | Raw observations are kept 7 days (`observation_retention`). | Debugging and audit without unbounded growth. | Keep forever, keep none. | proposed |
| D-020 | 2026-11-19 | Device display name is set once (first non-empty) and then only by the operator; each source's name is kept as attribute `name.<source>`. | Avoids names flapping between sources. | Source priority list. | proposed |
