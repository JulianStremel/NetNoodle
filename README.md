# netnoodle

netnoodle finds the devices on your network.
It records the software and the services on each device.
It compares the software with vulnerability data.
When a dangerous vulnerability occurs, netnoodle can do an action, for example block a device.
Actions outside the automatic scope need the approval of an operator.

> **Status:** Milestone M3 (threat feed). The server finds devices with `nn-scan` and the UniFi API, and removes duplicates.
> `nn-agent` reports the packages, listening services and interfaces of Linux hosts.
> The server compares the packages with OSV, CISA KEV and FIRST EPSS. The **Findings** page shows the vulnerable devices.
> The `proxmox` source imports clusters, VMs and containers (M4, in progress). The agent also operates on Windows.
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

`nn-agent` operates on Linux x86_64. It only reads data. In push mode, it does not listen on a network port. For pull mode, refer to [Procedure: pull mode](#procedure-pull-mode-agent-in-a-dmz).

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

Procedure: report the packages of containers (optional)

On a host with LXC containers (for example Proxmox VE) or Docker or Podman containers, the agent can report the running containers as children of the host: operating system, packages, listening ports and interfaces. Then the server finds vulnerabilities in the containers, and the **Map** page shows them next to their host.

1. Install the helper program as in the procedure above (step 1).
2. Install the units:

   ```sh
   cp deploy/nn-agent-helper-containers.socket deploy/nn-agent-helper-containers@.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now nn-agent-helper-containers.socket
   ```

The helper uses the same two capabilities. It does not use the Docker socket and it does not start programs in the containers. It reads only these files of each running container: `os-release`, `hostname`, the dpkg or apk package database, and the network tables in `/proc`. It opens them with `openat2` and `RESOLVE_IN_ROOT`, so a link in a container cannot point to a file of the host.

Limits:

- Stopped containers are not read.
- Packages of RPM-based containers are not read (only the operating system).
- Files on another mount than the container's root (for example a volume at `/var`) are not read. A container could use such a mount to point at files of the host.
- Rootless containers (in a user's systemd tree) are not reported.
- MAC addresses come only from the Proxmox configuration (`/etc/pve/lxc/<id>.conf`), never from files in the container. Then a container cannot claim another guest.
- The ports of a container show the program name, but not the package of the program.
- Virtual machines (QEMU) are not read from the host. Install the agent in the virtual machine.

## Procedure: install the agent on Windows

`nn-agent` operates on Windows 10, Windows 11 and Windows Server (x64). It does not need administrator rights to collect data.
You need administrator rights only to install it.

1. Build the program on a Windows computer with Rust: `cd agent` and `cargo build --release -p nn-agent`.
2. In an administrator PowerShell, copy the program and make the data directory:

   ```powershell
   New-Item -ItemType Directory -Force "C:\Program Files\netnoodle", "C:\ProgramData\netnoodle\agent"
   Copy-Item agent\target\release\nn-agent.exe "C:\Program Files\netnoodle\"
   icacls "C:\ProgramData\netnoodle\agent" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "LOCAL SERVICE:(OI)(CI)M"
   ```

3. Make a join token with the role `agent` on the **Peers** page. Enroll:

   ```powershell
   $env:NN_JOIN_TOKEN = "<join token>"
   & "C:\Program Files\netnoodle\nn-agent.exe" enroll --server https://<server>:7443 --fingerprint <sha256>
   Remove-Item Env:NN_JOIN_TOKEN
   ```

4. Make a scheduled task that sends a report each hour as `LOCAL SERVICE`:

   ```powershell
   $a = New-ScheduledTaskAction -Execute "C:\Program Files\netnoodle\nn-agent.exe" -Argument "run --once"
   $t = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
   $p = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\LOCAL SERVICE" -LogonType ServiceAccount
   Register-ScheduledTask -TaskName "netnoodle agent" -Action $a -Trigger $t -Principal $p
   ```

The agent reports the Windows version and build, the installed programs, the listening ports with their programs, and the network interfaces.

The server finds vulnerabilities of Windows itself with the `msrc` plug-in (refer to [Vulnerability data](#vulnerability-data)). It does not find vulnerabilities of other installed programs yet.

## Procedure: pull mode (agent in a DMZ)

Use pull mode if the host of the agent must not connect to the server. Example: the server is in the internal zone and the agent is on a reverse proxy in the DMZ. The firewall permits connections from the internal zone to the DMZ only.

In pull mode, the agent listens on one port. It accepts only the pull certificate of the server (mutual TLS). The server connects to the agent and gets the report. Refer to [docs/design/pull-mode.md](docs/design/pull-mode.md).

1. Install the agent program as in [Procedure: install the agent](#procedure-install-the-agent), steps 1 to 3. Do not enroll the agent.
2. In the web interface, open **Peers**. In **Pull agents**, write the name, the address that the server connects to (`host:port`, for example `10.1.2.3:7444`) and the interval. Click **Add pull agent**.
3. The web interface shows a command. Run it on the host of the agent:

   ```sh
   sudo -u nn-agent NN_PAIR_CODE=<code> nn-agent pair --server-fingerprint <fingerprint> --listen 10.1.2.3:7444
   ```

   The code is valid for 24 hours and only one time. Give the code in the environment variable `NN_PAIR_CODE`, so that other users cannot see it in the process list.
   Add `--allow-from <server address>` (an address or a CIDR network, repeat for more). Then the agent closes all other connections before TLS starts, and other hosts cannot keep the agent busy.
4. Install and start the service:

   ```sh
   cp deploy/nn-agent-serve.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now nn-agent-serve
   ```

   To permit connections only from the server, add `IPAddressDeny=any` and `IPAddressAllow=<server address>` to the unit.
5. In the firewall, permit TCP from the server to the agent port.
6. Wait one minute. The **Pull agents** table shows **paired**. Then the server pulls a report at each interval. Click **Pull now** to pull a report immediately.

If you install the agent again (new key), click **New pairing code** and do step 3 again.

On Windows, do the same steps with `nn-agent.exe`. Do step 2 of [Procedure: install the agent on Windows](#procedure-install-the-agent-on-windows) first: it restricts the permissions of `C:\ProgramData
etnoodlegent`. The state file `pull.json` in it contains the private key of the agent. Make a scheduled task that starts `nn-agent.exe serve` when the computer starts, and a firewall rule that permits the agent port only from the server address:

```powershell
New-NetFirewallRule -DisplayName "netnoodle agent" -Direction Inbound -Protocol TCP -LocalPort 7444 -RemoteAddress <server address> -Action Allow
```

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

## Procedure: import from Proxmox VE

The `proxmox` source reads the nodes of a cluster, the virtual machines and the containers. It shows each guest below its node. It uses a token with read permissions only.

1. On a Proxmox node, make a user, a token and the permission:

   ```sh
   pveum user add netnoodle@pve
   pveum acl modify / --users netnoodle@pve --roles PVEAuditor
   pveum user token add netnoodle@pve audit --privsep 0
   ```

2. Record the token secret. Put it in the file `config/proxmox.token`.
3. Get the SHA-256 fingerprint of the certificate of the node: in the web interface of Proxmox, open **System > Certificates**.
4. Add a source to `netnoodle.json`:

   ```json
   "sources": [{
     "type": "proxmox", "name": "pve", "interval": "10m",
     "settings": { "url": "https://pve1:8006", "token_id": "netnoodle@pve!audit",
                   "token_secret_file": "/etc/netnoodle/proxmox.token", "fingerprint": "<sha256>" }
   }]
   ```

5. Restart `nn-server`. On the **Devices** page, select **Show as tree**.

The source gets IP addresses of containers from Proxmox. For virtual machines, it asks the QEMU guest agent. This needs the privilege `VM.GuestAgent.Audit` (Proxmox VE 9) or `VM.Monitor` (Proxmox VE 8). Without it, virtual machines show only their MAC addresses. To stop these requests, set `"guest_agent": false`.

When an agent also operates in a guest, the server merges the two records by the MAC address.

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
| `msrc` | Matcher | Vulnerabilities of Windows (by build number), from the monthly security updates | Microsoft Security Response Center (`api.msrc.microsoft.com`) |
| `kev` | Enricher | Vulnerabilities that attackers use (Known Exploited Vulnerabilities) | CISA |
| `epss` | Enricher | Probability of exploitation in the next 30 days | FIRST EPSS |

The server sends only package names, versions and the distribution release to OSV. It sends no host names and no addresses.
The `msrc` plug-in sends nothing about your devices. It downloads the security update documents of the last 24 months when a Windows device is first reported.
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

## Actions page (decisions)

For each new finding, the server decides on an action. In this version the server only records the decisions. Actors that execute actions come in a later version.

1. The `rules` decider uses an ordered list of rules. The first rule that matches gives the tier and the action. The default rules:

   | Rule | When | Result |
   |---|---|---|
   | `kev-exposed` | Known exploited (KEV) and the package has an exposed service | Approval needed: `isolate`, 24 h |
   | `critical-exposed` | CVSS 9 or more and exposed | Approval needed: `block-port`, 24 h |
   | `kev` | Known exploited | Notification |
   | `high` | CVSS 7 or more | Notification |

2. The guards operate after the rules. They can only make a decision safer:
   - `protected`: a device with the tag `protected` never gets an automatic action.
   - `scope`: an automatic action is permitted only for devices with the tag `auto` or in the configured networks.
   - `rate`: at most 10 automatic actions in one hour.
   - `killswitch`: when the kill switch on the **Actions** page is on, no action is automatic.
3. An automatic action must be reversible (`isolate`, `block-port`, `stop-service`, `snapshot`) and must have a time limit (TTL). If not, it needs approval. Configuration cannot change this.

The **Actions** page shows the decisions that need approval, with **Approve** and **Reject**. To set the tags of a device, open the device page.

To change the rules, set `deciders` in `netnoodle.json`, for example:

```json
{ "deciders": [ { "type": "rules", "name": "rules", "settings": { "rules": [
  { "name": "kev-dmz", "when": { "kev": true, "networks": ["172.16.0.0/24"] }, "then": { "tier": "approve", "action": "isolate", "ttl": "12h" } }
] } } ] }
```

## Procedure: install an actor (dry run)

An actor executes approved actions. In this version, `nn-actor` has only the `log` backend: it writes what it would do. Refer to [docs/design/actors.md](docs/design/actors.md).

1. In the web interface, make a join token with the role `actor`.
2. Enroll the actor:

   ```sh
   NN_JOIN_TOKEN=<token> nn-actor enroll -server https://<server>:7443 -fingerprint <sha256> -name actor1 -creds /var/lib/nn-actor/creds.json
   ```

   The actor stores the public order key of the server. It accepts only orders with a signature of this key.
3. Write the configuration. Refer to [deploy/nn-actor.example.json](deploy/nn-actor.example.json):
   - `dry_run` is `true` if you do not write it. In dry-run mode the actor executes nothing.
   - `allow` lists the permitted actions and targets (for example `mac=bc:24:11:*`). The actor refuses all other orders.
   - `max_per_hour` limits the orders (default 20).
4. Start the actor: `nn-actor run -config /etc/nn-actor/actor.json`.

Backend `unifi` (block a client in UniFi Network, action `isolate`, revert `unisolate`): refer to [deploy/nn-actor.unifi.example.json](deploy/nn-actor.unifi.example.json).

- Make a local API key on the UniFi console and write it to a file that only the actor can read (`api_key_file`).
- Write the SHA-256 fingerprint of the console certificate in `fingerprint`.
- Write the MAC addresses that must never be blocked (gateway, your administrator computer) in `never_block`. The backend also refuses to block UniFi devices.
- The backend uses the command `block-sta` of the classic Network API. Ubiquiti does not document this command. Test it with `dry_run: false` on a client that is not important before you use it.

Backend `proxmox` (Proxmox VE guests, target `proxmox.guest`): refer to [deploy/nn-actor.proxmox.example.json](deploy/nn-actor.proxmox.example.json).

- `isolate` sets `link_down=1` on all network interfaces of the guest. The guest keeps its MAC addresses and bridges. `unisolate` removes it again. This operates without the Proxmox firewall.
- `snapshot` makes a snapshot `nn-<order>` (no revert).
- Make a separate API token for the actor with only the permissions `VM.Audit`, `VM.Config.Network` and (for snapshots) `VM.Snapshot`. Do not use the read-only token of the import.
- Write the VM IDs that must never be isolated in `never_isolate`.

When you approve a decision on the **Actions** page, the server sends an order to an actor that can do the action for the device. The **Actions** page shows the state of the order. After the TTL, the server sends the revert order.

## Map page

The **Map** page shows all devices in one view. Select a visualization at the top:

| View | What it shows |
|---|---|
| Constellation | Each network is a nebula and each device is a star. A Proxmox host and its guests look like a small solar system. A ring shows a known exploited vulnerability (KEV). |
| Radar | The riskiest devices are near the center. Each sector is a network. Guests are near their host. |
| City | Each network is a district and each device is a building. Height shows the number of packages, color shows the risk. A red beacon shows a known exploited vulnerability (KEV). |
| Flow | The path from a vulnerability to the package, the exposed service, the device, the host and the network. |

![City view](docs/img/map-city.jpg)

Click a device to see its blast radius: its host, its guests and the other guests of the same host. A compromise of one of them can affect the others. Double-click a device to open its page.

The risk of a device (0 to 10) comes from its worst open finding: 70 % of the CVSS score, plus 2 if attackers use the vulnerability (KEV), plus 1 if the package has a network service that listens on an address other than loopback, plus the EPSS probability.

## Procedure: try netnoodle with demo data

`nn-demo` makes a data directory with an invented network (Proxmox hosts with guests, a DMZ, clients and IoT devices, with findings). Use it to look at the web interface without real data.

1. Make the demo data:

   ```sh
   go run ./cmd/nn-demo -data ./demo-data
   ```

2. Write `demo.json` with `{"data_dir": "./demo-data", "matchers": [], "enrichers": []}`. The empty lists stop the vulnerability downloads, so the invented findings stay.
3. Start the server with `go run ./cmd/nn-server -config demo.json`. Log in with the password that the server shows.

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
