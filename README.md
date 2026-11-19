# netnoodle

netnoodle finds the devices on your network.
It records the software and the services on each device.
It compares the software with vulnerability data.
When a dangerous vulnerability occurs, netnoodle can do an action, for example block a device.
Actions outside the automatic scope need the approval of an operator.

> **Status:** Milestone M1 (discovery). The server finds devices with `nn-scan` and the UniFi API, and removes duplicates.
> Refer to [docs/architecture.md](docs/architecture.md) for the design and the milestones.

## Parts

| Part | Language | Function |
|---|---|---|
| `nn-server` | Go | Central server. Web interface, ingest, deduplication, threat matching, decisions, order queue. |
| `nn-scan` | Go | Subnet scanner. Sends observations to the server. |
| `nn-agent` | Rust | Agent on a host or hypervisor. Collects packages, services and guests. (M2, M4) |
| `nn-actor` | Go | Actor for network APIs (UniFi, Proxmox). (M6) |
| `nn-actor-host` | Rust | Actor on a host (systemd units, firewall rules). (M6) |

All parts connect to the server. Agents and actors do not listen on a network port.

## Tools that you must have

- Go 1.26 or later. Go downloads the correct toolchain automatically.
- Rust (stable) with `rustfmt` and `clippy`.
- A POSIX shell. On Windows, use Git Bash.

## Procedure: build and test

1. Open a shell in the root directory of the repository.
2. Run the check script:

   ```sh
   sh scripts/check.sh
   ```

3. Make sure that the last line is `ALL CHECKS PASSED`.

The programs are in `bin/` and in `agent/target/debug/`.

## Procedure: start the server

1. Run the server:

   ```sh
   bin/nn-server
   ```

2. On the first start, the server shows the password of the user `admin`. Record this password.
3. Open `https://localhost:7443` in a web browser.
4. Accept the self-signed certificate.
5. Log in as `admin`.

The server keeps its data in the directory `data/`.
The server reads the file `netnoodle.json` if it exists.
Refer to [netnoodle.example.json](netnoodle.example.json) for an example.

To set a new password for `admin`, run `bin/nn-server -reset-admin`.

## Procedure: enroll a scanner

1. In the web interface, open **Peers**.
2. Set **Role** to `source` and **Name** to a name for the scanner, for example `scan-lan`.
3. Click **Create join token**.
4. Copy the command that the page shows.
5. On the scanner host, run that command with `bin/nn-scan`.
6. Write the file `nn-scan.json`:

   ```json
   { "cidrs": ["192.168.1.0/24"], "interval": "15m" }
   ```

7. Run `bin/nn-scan run -config nn-scan.json`.
8. Open **Devices** in the web interface.

To test a scan without a server, run `bin/nn-scan scan -cidr 192.168.1.0/24`.

## Procedure: import from UniFi

1. In UniFi Network, open **Settings > Control Plane > Integrations**.
2. Create an API key.
3. Get the SHA-256 fingerprint of the console certificate.
4. Add a source to `netnoodle.json`:

   ```json
   "sources": [{
     "type": "unifi", "name": "unifi", "interval": "10m",
     "settings": { "url": "https://192.168.1.1", "api_key_file": "unifi.key", "fingerprint": "<sha256>" }
   }]
   ```

5. Restart `nn-server`.

The API key gives read access only. The source reads sites, network devices and clients.

## Procedure: send notifications

Add a notifier to `netnoodle.json`:

```json
"notifiers": [{ "type": "webhook", "name": "hook", "settings": { "url": "https://ntfy.example/netnoodle", "types": ["device."] } }]
```

The server sends each event as JSON. Set `"format": "slack"` for Slack-type receivers.

## Certificate fingerprint

The server makes a self-signed TLS certificate on the first start.
The **Overview** page shows the SHA-256 fingerprint of this certificate.
Agents, scanners and actors use this fingerprint to identify the server.

## Extend netnoodle

Each part that you can replace or add has an interface and a registry.
Refer to section 4 of [docs/architecture.md](docs/architecture.md).
External programs in any language can also be sources or actors.
They use the JSON protocol in [api/v1](api/v1).

## Documents

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Design, plug-in contracts, milestones. |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Decision log and open questions. |
| [api/v1](api/v1) | JSON Schemas of the protocol. |
