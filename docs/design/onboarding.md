# Onboarding: add a peer with one command

Status: implemented (first version).

## 1. Flow for the operator

1. Peers page, **Add peer**. Select the kind and enter a name:
   - `agent` (push mode), `agent-pull` (pull mode), `scan`, `actor-host`, `actor-unifi`, `actor-proxmox`.
   - Platform: Linux or Windows (Windows: `agent` and `scan` only in the first version).
2. The server makes an **onboarding session** and shows:
   - the **one-liner** for the platform (copy button),
   - the **setup code** (copy button),
   - a live status: waiting, enrolled, connected, done / rolled back (with the error).
3. On the device, the operator pastes the one-liner, then pastes the setup code when the script asks for it. Secrets that the server does not know (for example the UniFi API key) are asked by the script with hidden input. They never go to the server.

## 2. Trust

- The one-liner pins the server: Linux `curl -fsSLk --pinnedpubkey 'sha256//<SPKI>'` (with `-k`, curl still enforces the pin); Windows a certificate validation callback that compares the SHA-256 certificate fingerprint. No unpinned download from the server.
- The scripts (`/install.sh`, `/install.ps1`) contain no secrets. The server serves them embedded (package `internal/installscripts`).
- Program files come from the GitHub release of exactly the server's own version. The server tells the script the URL and the SHA-256 (manifest, section 4); the server gets the hashes from the release `SHA256SUMS` over normal HTTPS and caches them. The script refuses a file with another hash. (Later: Sigstore verification in the server.)
- The join token in the setup code is single-use, bound to the name and role, and valid for 30 minutes. The session secret authorizes only status and abort of this one session.

## 3. Setup code

`nnsetup1:` followed by base64url (no padding) of UTF-8 lines `key=value` (no JSON, so that POSIX `sh` and PowerShell 5.1 can read it without tools). Keys:

| Key | Example | Meaning |
|---|---|---|
| `server` | `https://10.0.0.5:7443` | server URL |
| `fingerprint` | 64 hex | SHA-256 of the server certificate (agent/actor pin) |
| `spki` | base64 | SHA-256 of the server public key (curl pin) |
| `session` | 16+ chars `[A-Za-z0-9-]` | onboarding session ID |
| `secret` | 43 chars base64url | session secret (status and abort) |
| `token` | join token | single-use, 30 min |
| `name` | `web01` | peer name |
| `kind` | `agent` | see section 1 |
| `version` | `v0.1.0` | server version = program version to install |
| `expires` | RFC 3339 | end of the session |

Unknown keys are ignored (forward compatible); missing required keys are an error.

## 4. Server API

User session (web interface, admin; creating a session requires the password again, like updates):

- `POST /api/onboard` `{kind, name, platform, password}` -> `{session, setup_code, one_liner, expires}`.
- `GET /api/onboard/{session}` -> `{state, error, peer_id, steps:[{name, ok, at, message}]}`.
- `POST /api/onboard/{session}/cancel` -> aborts (same rollback as below).

Public (no secrets in the answer):

- `GET /install.sh`, `GET /install.ps1` -> scripts, `Cache-Control: no-store`.
- `GET /v1/install/manifest?version=vX.Y.Z&platform=linux-x86_64|linux-aarch64|linux-armv7|windows-x86_64|windows-arm64&kind=...` -> `{version, artifacts:[{url, sha256, kind:"tar.gz"|"zip", files:[...]}]}`. `503` if the hashes of that version are not known yet.

Script (header `X-NN-Onboard-Secret: <secret>`):

- `GET /v1/onboard/{session}` -> `{state, peer_seen}`; `POST /v1/onboard/{session}/step` `{name, ok, message}` (progress for the web interface, at most 64 steps, messages at most 1 KiB);
- `POST /v1/onboard/{session}/abort` `{reason}` -> the server deletes the peer of this session (if enrolled) and revokes the token.

## 5. Session states (server)

`created` -> `enrolled` (the join token of the session was used; the peer ID is recorded) -> `connected` (first observation of that agent/scan peer, or the first actor hello / pull pairing done) -> `done` (the script reports success). Failure: `aborted` (script or operator) or `expired` (not `done` within 30 minutes). On `aborted` and `expired`, the server **deletes the peer of the session** and revokes the token: a half-installed peer never stays. A `done` session is kept for 7 days for the history, then deleted.

## 6. Script steps (Linux `install.sh`, POSIX sh; Windows `install.ps1`, PowerShell 5.1)

1. Elevate: not root -> `exec sudo` (or `doas`) with the same arguments. Windows: restart elevated (`Start-Process -Verb RunAs`).
2. Check the platform: Linux with systemd; arch `x86_64`, `aarch64`, `armv7l` (-> `armv7`). Refuse others with a clear message.
3. Ask for the setup code (read from `/dev/tty`; `--code` for automation). Check `expires`.
4. Preflight: the server answers `GET /v1/health` with the pin; the clock difference to the server `Date` is less than 5 minutes; enough free disk.
5. Get the manifest, download, check SHA-256, extract to a temporary directory.
6. Install with a journal: each created file, directory, user and unit is written to `/var/lib/nn-install/<name>.journal` before it is created. Existing installation of the same name: stop and ask (repair / abort); never overwrite silently.
7. Ask for secrets of the kind (UniFi API key, Proxmox token; hidden input) and write the config (actors: `dry_run: true` by default).
8. Enroll with the existing commands (`nn-agent enroll`, `nn-actor enroll`, `nn-scan enroll`, pull: `nn-agent pair`) using the token from the setup code.
9. Start the service. Health checks: local (`systemctl is-active`, the program's own check if it has one) and communication (poll `GET /v1/onboard/{session}` until `peer_seen`, at most 120 s). Report each step with `POST .../step`.
10. Success: `POST .../step {name:"done", ok:true}`; print a summary (name, server, service, how to uninstall).
11. Failure at any step after 5: **rollback** in reverse journal order (stop and disable the unit, remove files, directories and the user that this run made), then `POST .../abort`. Print what failed and what was rolled back. Rollback errors are reported, not hidden.
12. `--uninstall <name>` uses the journal to remove an installation.

## 7. Limits and tests

- The server keeps at most 20 open sessions; creating more is refused.
- Tests: session state machine and expiry (store contract), API auth (secret, wrong secret, other session), manifest building from a `SHA256SUMS` fixture, setup code encode/decode (Go) and parse (sh: a Go test runs `sh -n` and a parse function of the script with a fixture; PowerShell: syntax check only if `pwsh`/`powershell` exists), rollback journal (sh, in a temp root with a fake `systemctl`).
