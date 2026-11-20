# Design: pull mode (server collects from the agent)

Status: decided (D-041). The transport is HTTPS with mutual TLS. SSH is not used: SSH servers on different hosts operate differently, and the server would depend on their configuration.

## 1. Problem

In push mode, the agent connects to the server. In a zoned network this is not always permitted.

Example:

- The netnoodle server is in the internal zone.
- A reverse proxy is in the DMZ.
- The firewall permits connections from the internal zone to the DMZ.
- The firewall must not permit connections from the DMZ to the internal zone.

Thus, the agent on the reverse proxy cannot push its report. The server must pull the report.

## 2. Requirements

1. The server starts the connection. The DMZ host does not connect to the internal zone.
2. The data and the trust model are the same as in push mode:
   - The report is one top-level entity.
   - The server adds `agent=<peer name>`.
   - The peer can be disabled in the web interface.
3. Pull mode must not make the DMZ host weaker. The agent opens one port. Only the server can use this port.
4. The transport is a plug-in (`internal/pull.Transport`). The server core has no code for one specific transport.
5. The same mechanism operates on Linux and Windows hosts.
6. Later, actors in the DMZ (M6) can use the same transport in the other direction.

## 3. Overview

```
 internal zone                               DMZ
 nn-server ── TLS, client certificate ──▶  nn-agent serve (port 7444)
            GET /v1/pair    (one time)       only the pinned server certificate is accepted
            GET /v1/report  (each interval)  answers with a v1 observation
```

Keys and certificates:

| Key | Where | Pinned by |
|---|---|---|
| Pull client key (`data/tls/pull-client-*.pem`, made at first start, ECDSA P-256, extended key usage "client auth") | Server | The agent (`--server-fingerprint`) |
| Agent key (made by `nn-agent pair`, ECDSA P-256, self-signed) | Agent state file | The server, after pairing |

The pull client key is not the key of the HTTPS server of nn-server. Thus, the two keys can be replaced independently.

## 4. Pairing

1. The operator adds a pull agent on the **Peers** page: name, address (`host:port`), interval. The server makes a one-time pairing code (20 random bytes, base32 without padding, 32 characters). The code expires after 24 hours.
2. The web interface shows the command for the DMZ host:

   ```
   nn-agent pair --code <code> --server-fingerprint <pull client fingerprint> --listen <address>
   ```

   The agent makes its key and certificate (or keeps the existing key), and writes the state file. It shows its fingerprint.
3. The operator starts the agent service (`nn-agent serve`).
4. The server connects to `GET /v1/pair` each minute until pairing is complete or the code expires. The server does not verify the agent certificate in this request. It records the SHA-256 fingerprint of the agent certificate from the TLS connection.
5. The agent answers with a proof:

   ```
   proof = HMAC-SHA256(key = code, message = "netnoodle-pair-v1\n" + agent_fp + "\n" + server_fp)
   ```

   - `code` is the UTF-8 text of the code, without white space.
   - `agent_fp` and `server_fp` are lower-case hex SHA-256 fingerprints of the DER certificates, without colons.
   - `server_fp` is the fingerprint of the pull client certificate.
6. The server calculates the same HMAC with the agent fingerprint that it saw. If the values are equal, the server pins the agent fingerprint and deletes the code.
7. After the first successful `GET /v1/report`, the agent deletes the code from its state file.

Why this is safe:

- An attacker in the DMZ who imitates the agent does not know the code. A relay that forwards the proof of the real agent fails, because the proof contains the fingerprint of the real agent certificate and the server sees the certificate of the relay.
- An attacker who imitates the server does not have the pull client key. The agent refuses the TLS handshake.
- To pair again (for example after a new installation of the agent), the operator clicks **New pairing code**. The server deletes the pinned fingerprint.

## 5. Protocol of the agent

- TLS 1.2 or 1.3. The agent requires a client certificate. It accepts only a leaf certificate with the SHA-256 fingerprint `server_fp`.
- HTTP/1.1, one request for each connection, `Connection: close`. Request head maximum 8 KiB, read time limit 10 seconds. One connection at a time.
- `GET /v1/pair`:
  - Code active: `200`, `{"version":"v1","proof":"<hex>"}`.
  - No code: `404`.
- `GET /v1/report`:
  - `200`, `application/json`, a v1 observation (the same data as `nn-agent collect`).
  - Less than 10 seconds after the previous report: `429`.
- Other paths: `404`. Other methods: `405`.

## 6. Server

- `internal/pull`:

  ```go
  type Target struct{ Name, Address, Pin string }
  type Transport interface {
      // Pair connects to an unpaired agent, checks the proof and returns the agent fingerprint.
      Pair(ctx context.Context, t Target, code string) (pin string, err error)
      // Pull returns one report. It applies size and time limits.
      Pull(ctx context.Context, t Target) ([]byte, error)
  }
  ```

  `internal/pull/https` is the first transport. Limits: report 64 MiB, time 2 minutes, no redirects, no HTTP proxy.
- Pull peers are peers with the role `agent` and a row in `pull_peers` (transport, address, pinned fingerprint, code, interval, next pull, last pull, last error). A pull peer has no token, so it cannot push.
- The pull manager polls due peers every 30 seconds, 4 at a time. Interval: default 1 hour, minimum 1 minute, jitter ±10 %.
- A pulled report goes through the same checks and ingest as `POST /v1/observations`: strict JSON, version, entity limit, `PrepareAgent`, the source is the peer name.
- Disabled peers are not polled.
- API (login required):
  - `GET /api/pull-peers`
  - `POST /api/pull-peers` `{name, address, interval}` → peer, code, command.
  - `POST /api/pull-peers/{id}/pair` → new code; the pinned fingerprint is deleted.
  - `POST /api/pull-peers/{id}/pull` → pull now.

## 7. Agent

- `nn-agent pair` writes the state file `pull_state` (default `/var/lib/nn-agent/pull.json`, on Windows `C:\ProgramData\netnoodle\agent\pull.json`, mode 0600): listen address, server fingerprint, certificate, key, code.
- `nn-agent serve` reads the state file and listens. It uses the enabled collectors and the helper, as in push mode.
- Linux: `deploy/nn-agent-serve.service`. Add `IPAddressAllow=<server address>` to permit only the server.
- Windows: a scheduled task that starts `nn-agent serve`, and a firewall rule that permits only the server address.

## 8. Risks and countermeasures

| Risk | Countermeasure |
|---|---|
| Open port on the DMZ host. | mTLS with a pinned client certificate before any HTTP data is read; two read-only endpoints; no parameters; one connection at a time; time limits; bind to one address; firewall rule for the server address. |
| A compromised DMZ host sends malicious data. | Same as push: strict parsing, size limits, agent identity set by the server. |
| A compromised DMZ host attacks the server's HTTPS client. | Go TLS and net/http, size and time limits, no redirects. |
| Attacker gets the pull client key. | The key gives only read access to the reports. Replace the key (delete the files, restart, pair again). |
| Attacker in the DMZ imitates the agent. | Pinned agent certificate; the pairing proof is bound to the certificate. |

## 9. Rejected options

| Option | Reason |
|---|---|
| SSH with a forced command | SSH servers operate differently on different hosts (Windows OpenSSH, hardened configurations). The server would depend on them. |
| Relay host in the DMZ | One more component to operate and to secure. The relay holds data of many hosts. |
| Server reads files with SMB or NFS | Wide access, complex permissions. |
| Agent pushes through an HTTP proxy in the DMZ | Still a connection from the DMZ into the internal zone. |
