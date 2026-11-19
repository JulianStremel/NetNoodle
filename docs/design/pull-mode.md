# Design: pull mode (server collects from the agent)

Status: proposal, not implemented. Refer to D-041 in [DECISIONS.md](../DECISIONS.md).

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
3. Pull mode must not make the DMZ host weaker. A new open port is a risk. Each transport must keep this risk small.
4. The transport is a plug-in. The server core has no code for one specific transport.
5. The same mechanism must operate for Linux and Windows hosts.
6. Later, actors in the DMZ (M6) use the same transports in the other direction: the server delivers signed orders.

## 3. Transports

### 3.1 `ssh`: forced command on the existing SSH server (recommended first)

The DMZ host usually has an SSH server for administration. The firewall usually permits SSH from the internal zone.

1. The server makes an ed25519 SSH key on the first start. The web interface shows the public key.
2. On the DMZ host, the operator adds the key to the `authorized_keys` file of the user `nn-agent`. The entry has a forced command and the option `restrict`:

   ```
   command="/usr/local/bin/nn-agent collect --report",restrict ssh-ed25519 AAAA... netnoodle
   ```

3. The server connects, sends nothing, and reads the report from standard output. The size limit is 64 MiB and the time limit is 2 minutes.
4. The server pins the host key of the DMZ host. The operator gives the fingerprint, or the server accepts the first key (TOFU) when the operator selects this option.

Properties:

- No new open port. The SSH server is already audited and hardened.
- `restrict` blocks port forwarding, agent forwarding, X11 and the PTY. The forced command ignores the command that the client sends. Thus, the key can only start one read-only command.
- The agent runs as `nn-agent`, without root. The helper (`nn-agent-helper`) operates as in push mode.
- On Windows, the same procedure operates with the OpenSSH server of Windows (`administrators_authorized_keys` is not necessary; use a normal local user).

### 3.2 `https`: the agent listens (for hosts without SSH)

1. `nn-agent serve --listen <addr>:7444` starts a small HTTPS server with one endpoint: `GET /v1/report`. There are no other endpoints, no parameters and no commands.
2. Mutual TLS:
   - The agent accepts only the client certificate of the server. It pins the fingerprint of that certificate.
   - The server pins the certificate of the agent.
3. Pairing without manual copy of fingerprints:
   1. The operator creates a pull peer in the web interface (name, address). The server shows a pairing command with a one-time code and the fingerprint of the server client certificate.
   2. On the DMZ host: `nn-agent pair --code <code> --server-fingerprint <fp> --listen 10.1.2.3:7444`. The agent makes its key and certificate and starts to listen.
   3. The server connects to `/v1/pair`. The agent answers with `HMAC-SHA256(code, agent certificate fingerprint)`. The server verifies the HMAC and pins the agent certificate. The code becomes invalid.
4. The agent limits requests (1 per 10 seconds, 1 connection at a time) and closes slow connections.

Properties: a new open port on the DMZ host. The port accepts only the pinned server certificate. Use this transport only if SSH is not available, for example on Windows hosts without the OpenSSH server.

### 3.3 Rejected options

| Option | Reason |
|---|---|
| Relay host in the DMZ (agent pushes to relay, server pulls from relay) | One more component to operate and to secure. The relay holds data of many hosts. |
| Server reads files with SMB or NFS | Wide access, complex permissions. |
| Agent pushes through an HTTP proxy in the DMZ | Still a connection from the DMZ into the internal zone. |

## 4. Server design

- New plug-in interface `internal/pull.Transport`:

  ```go
  type Transport interface {
      Name() string
      // Pull returns one report. It must apply size and time limits.
      Pull(ctx context.Context) (raw []byte, err error)
  }
  var Registry = registry.New[Transport]("pull transport")
  ```

- Pull peers are stored in the `peers` table with `mode = 'pull'`, `transport`, `address` and the pinned keys. The operator creates them in the web interface (Peers page, "Add pull agent").
- A pull manager in the server polls each active pull peer (interval per peer, default 1 hour, jitter ±10 %). It uses the same ingest function as `POST /v1/observations` with the peer identity. Thus, all agent rules (one top-level entity, `agent=<peer>`) apply without new code.
- The **Peers** page shows the mode, the transport, the last pull, and the last error. A button starts a pull now.
- Disabled pull peers are not polled.

## 5. Agent design

- `nn-agent collect --report` prints the complete v1 observation (as `run --once` sends it) to standard output. Log messages go to standard error. This is the SSH transport.
- `nn-agent serve` and `nn-agent pair` are the HTTPS transport. They use the same collectors.
- A config option `mode: "push" | "pull"` prevents a pull agent from trying to push.

## 6. Risks and countermeasures

| Risk | Countermeasure |
|---|---|
| A compromised DMZ host sends malicious data when pulled. | Same as push: strict parsing, size limits, agent identity set by the server. |
| A compromised DMZ host attacks the server's SSH or HTTP client. | Use maintained libraries (`golang.org/x/crypto/ssh`, Go TLS), limits on size and time, no shell on the server side. |
| Attacker gets the server SSH key. | The key can only start the read-only forced command on each host. Rotate the key in the web interface. |
| Attacker in the DMZ impersonates the agent. | Pinned host key (SSH) or pinned agent certificate (HTTPS). |
| Open port on the DMZ host (HTTPS transport). | mTLS with a pinned client certificate, one read-only endpoint, rate limit, bind to one address. |

## 7. Order of work

1. `nn-agent collect --report` and the `ssh` transport with pinned host keys (config file first, then web interface).
2. Pull peers in the web interface.
3. The `https` transport with pairing.
4. Actors over the same transports (M6).
