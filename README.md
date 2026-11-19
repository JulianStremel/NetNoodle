# netnoodle

netnoodle finds the devices on your network.
It records the software and the services on each device.
It compares the software with vulnerability data.
When a dangerous vulnerability occurs, netnoodle can do an action, for example block a device.
Actions outside the automatic scope need the approval of an operator.

> **Status:** Milestone M0 (skeleton). The server, the login, and the plug-in contracts exist.
> Refer to [docs/architecture.md](docs/architecture.md) for the design and the milestones.

## Parts

| Part | Language | Function |
|---|---|---|
| `nn-server` | Go | Central server. Web interface, ingest, deduplication, threat matching, decisions, order queue. |
| `nn-scan` | Go | Subnet scanner. Sends observations to the server. (M1) |
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
