# netnoodle

netnoodle finds the devices on your network.
It records the software and the services on each device.
It compares the software with vulnerability data.
When a dangerous vulnerability occurs, netnoodle can do an action, for example block a device.
Actions outside the automatic scope need the approval of an operator.

> **Status:** Milestone M3 (threat feed). The server finds devices with `nn-scan` and the UniFi API, and removes duplicates.
> `nn-agent` reports the packages, listening services and interfaces of Linux hosts.
> The server compares the packages with OSV, CISA KEV and FIRST EPSS. The **Findings** page shows the vulnerable devices.
> Refer to [docs/architecture.md](docs/architecture.md) for the design and the milestones.

## Parts

| Part | Language | Function |
|---|---|---|
| `nn-server` | Go | Central server. Web interface, ingest, deduplication, threat matching, decisions, order queue. |
| `nn-scan` | Go | Subnet scanner. Sends observations to the server. |
| `nn-agent` | Rust | Agent on a Linux host. Collects packages, services and interfaces. Guests on hypervisors follow in M4. |
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

## Procedure: run with Docker

You can run `nn-server` and `nn-scan` in containers.
You must have Docker with Compose.

1. Start the server:

   ```sh
   docker compose up -d --build
   ```

2. Show the log of the server:

   ```sh
   docker compose logs server
   ```

3. Record the password of the user `admin` and the TLS fingerprint. The log shows the password only on the first start.
4. Open `https://localhost:7443` in a web browser and log in.

The server keeps its data in the Docker volume `server-data`.
To configure the server, put `netnoodle.json` in the directory `config/`. The containers read this directory at `/etc/netnoodle`.
File paths in `netnoodle.json`, for example `api_key_file`, must start with `/etc/netnoodle/`.
The containers operate as user ID 65532. This user must be able to read the files in `config/`.

To set a new password for `admin`, run `docker compose run --rm server -reset-admin`.

To start the scanner in a container, do these steps:

1. Make a join token with the role `source` on the **Peers** page.
2. Copy `deploy/nn-scan.example.json` to `config/nn-scan.json`. Change `cidrs`.
3. Enroll the scanner. Use the server URL `https://server:7443`:

   ```sh
   docker compose --profile scan run --rm scan enroll -server https://server:7443 -fingerprint <sha256> -token <join token>
   ```

4. Start the scanner:

   ```sh
   docker compose --profile scan up -d
   ```

> **Note:** In the default Docker network, the scanner cannot read the MAC addresses of the LAN. Thus, the server identifies these devices only by IP address and host name.
> On a Linux host, set `network_mode: host` for the `scan` service in `compose.yaml`. Then use the server URL `https://127.0.0.1:7443` when you enroll.
> Docker Desktop (Windows, macOS) operates containers in a virtual machine. There, the scanner cannot read the MAC addresses of the LAN. Use `bin/nn-scan` on the host.

> **Note:** In Git Bash on Windows, put `MSYS_NO_PATHCONV=1` before `docker compose` commands that have paths such as `/etc/netnoodle/...`.

`nn-agent` and `nn-actor-host` do not operate in containers. They read and change the host. Install them on the host.

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

## Procedure: install the agent

`nn-agent` operates on Linux x86_64. It only reads data. It does not listen on a network port.

1. Build the static binaries (Docker is necessary):

   ```sh
   docker build --target agent --output bin/linux .
   ```

2. Copy `bin/linux/nn-agent` to `/usr/local/bin/nn-agent` on the host. Make it executable.
3. Make a user and a data directory:

   ```sh
   useradd --system --no-create-home --shell /usr/sbin/nologin nn-agent
   install -d -o nn-agent -g nn-agent -m 700 /var/lib/nn-agent
   ```

4. In the web interface, open **Peers**. Set **Role** to `agent`. Click **Create join token**.
5. Enroll the agent:

   ```sh
   sudo -u nn-agent nn-agent enroll --server https://<server>:7443 --fingerprint <sha256> --token <join token>
   ```

   The peer name is the host name. To use a different name, add `--name <name>`.
   Give the join token in the environment variable `NN_JOIN_TOKEN`, as the **Peers** page shows. Then other users cannot see the token in the process list.
6. Install the service:

   ```sh
   cp deploy/nn-agent.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now nn-agent
   ```

7. Open **Devices** in the web interface. The host shows its packages and services.

The agent sends a report each hour. To change this, write `/etc/nn-agent/config.json`.
Refer to [deploy/nn-agent.example.json](deploy/nn-agent.example.json).

To see the files, sockets and programs that the agent uses, run `nn-agent scope`.
To see a report without sending it, run `nn-agent collect`.

The agent has no root permissions and no capabilities.
For each listening socket, it finds the program and its package:

- For programs of systemd services and containers, the agent needs no permissions. This needs Linux 5.9 or later.
- For other programs of other users, install the optional helper. Do the procedure that follows.

Procedure: install the helper (optional)

1. Copy `bin/linux/nn-agent-helper` to `/usr/local/bin/nn-agent-helper`. Make it executable.
2. Install the units:

   ```sh
   cp deploy/nn-agent-helper.socket deploy/nn-agent-helper@.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now nn-agent-helper.socket
   ```

The helper is a separate program with two capabilities: `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`.
It has no input. It only gives the programs of listening sockets.
Only members of the group `nn-agent` can connect to it. The agent itself keeps no capabilities.

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

## Vulnerability data

The server compares the packages from the agents with vulnerability data:

| Plug-in | Type | Data | Source |
|---|---|---|---|
| `osv` | Matcher | Vulnerabilities of Debian, Ubuntu, Alpine, Rocky Linux and AlmaLinux packages | `api.osv.dev` |
| `kev` | Enricher | Vulnerabilities that attackers use (Known Exploited Vulnerabilities) | CISA |
| `epss` | Enricher | Probability of exploitation in the next 30 days | FIRST EPSS |

The server sends only package names, versions and the distribution release to OSV. It sends no host names and no addresses.
The server downloads the KEV and EPSS lists each day. Then it compares all devices again.

To use other plug-ins or to stop the downloads, set `matchers` and `enrichers` in `netnoodle.json`. An empty list disables the plug-ins:

```json
{ "matchers": [], "enrichers": [] }
```

The **Findings** page shows the most urgent findings first:

1. Vulnerabilities that attackers use (KEV).
2. Vulnerabilities in a package that has a listening network service on the device.
3. The CVSS score, then the EPSS probability.

When a new report shows a fixed version, the server closes the finding.

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
