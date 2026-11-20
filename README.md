# netnoodle

<img src="web/static/logo.svg" alt="" width="64" align="right">

netnoodle finds the devices in your network, finds their vulnerabilities, shows which ones are reachable from outside, and proposes actions. An operator approves an action, and an actor executes it for a limited time.

![Overview](docs/img/overview.jpg)

## What it does

- **Discovery:** subnet scanner, agents on Linux and Windows, imports from UniFi, Proxmox VE, Tailscale and Home Assistant. One device appears once, also when several sources report it.
- **Vulnerabilities:** packages and Windows builds are compared with OSV and Microsoft (MSRC), with the CISA list of known exploited vulnerabilities (KEV) and the FIRST exploit probability (EPSS).
- **Reachability:** each device and service is `internet`, `tunnel` (VPN, Tailscale) or `local`. Hosts, guests and containers are linked, so a problem on one shows the devices it can affect.
- **Decisions and actions:** rules propose actions (isolate, block a port). Safety checks and a kill switch apply. Actors for UniFi, Proxmox VE and Linux hosts (nftables) execute approved actions with signed orders, in dry-run mode by default, and undo them after their time limit.
- **Web interface:** a dark console with a map of the network in four views, and Home Assistant entities through MQTT.

## Quick start (Docker)

```sh
git clone https://github.com/JulianStremel/NetNoodle.git && cd NetNoodle
mkdir -p config && cp netnoodle.example.json config/netnoodle.json   # optional
docker compose up -d server
docker compose logs server | grep password      # first start: password of the user "admin"
```

Open `https://<host>:7443` and log in as `admin`. To look around without real data, use the demo data: [Getting started](docs/guide/getting-started.md#procedure-try-netnoodle-with-demo-data).

## Parts

| Part | Language | Function |
|---|---|---|
| `nn-server` | Go | Central server: web interface, ingest, deduplication, vulnerability matching, decisions, orders |
| `nn-scan` | Go | Subnet scanner |
| `nn-agent` | Rust | Agent on Linux and Windows hosts: packages, services, interfaces, containers. Push or pull mode |
| `nn-actor` | Go | Executes approved actions. Backends `unifi`, `proxmox`, `host` (nftables), `log` |

## Documentation

| Topic | Page |
|---|---|
| Build, start, Docker, demo data | [Getting started](docs/guide/getting-started.md) |
| Scanner, agents (Linux, Windows), helpers, pull mode | [Scanner and agents](docs/guide/agents.md) |
| UniFi, Proxmox VE, Tailscale, Home Assistant, notifications | [Integrations](docs/guide/integrations.md) |
| Vulnerability data, reachability, risk | [Vulnerabilities and risk](docs/guide/vulnerabilities.md) |
| Rules, approvals, kill switch, actors | [Decisions and actions](docs/guide/actions.md) |
| Pages and Map views | [Web interface](docs/guide/web-interface.md) |
| Storage, releases, updates, data locations | [Operations](docs/guide/operations.md) |
| Plug-ins, protocol, design documents | [Extending netnoodle](docs/guide/extending.md) |
| Architecture and milestones | [docs/architecture.md](docs/architecture.md) |
| Decisions and accepted risks | [docs/DECISIONS.md](docs/DECISIONS.md) |

## Status

Milestones M0 to M6 are done: discovery, agents, vulnerability matching, the Map page, decisions and actors. Next: an advisor that uses a language model of your choice (M7), updates from the web interface, and agents that the server distributes. Refer to [docs/architecture.md](docs/architecture.md) and the design documents in [docs/design](docs/design).

The connections to UniFi, Proxmox VE, Tailscale and Home Assistant are tested against test servers. Test them with your systems before you let an actor act (`dry_run: false`).
