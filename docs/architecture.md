# netnoodle architecture

This document gives the design of netnoodle.
It uses ASD-STE100 Simplified Technical English.
Refer to [DECISIONS.md](DECISIONS.md) for the reasons of the decisions.

## 1. Purpose

netnoodle does these tasks:

1. It finds the devices on the network. It uses a subnet scan and the APIs of network systems (UniFi first).
2. It collects the software and the services of each device. A Rust agent does this with the smallest possible scope.
3. It collects data about vulnerabilities from threat feeds.
4. It finds the devices that have vulnerable software.
5. It decides on an action from rules and, as an option, an LLM.
6. It sends the action to an actor. Actions outside the automatic scope need the approval of an operator.

## 2. Main rules

- The server and the API programs use Go. The agent and the host actor use Rust.
- Each part that you can replace or add has an interface and a registry. The configuration selects the parts by name.
- The protocol between the parts is versioned JSON. The schemas are in `api/v1`.
- The server has no code for one specific source or one specific actor. It uses only identifiers and capabilities.
- All parts connect to the server. Agents and actors do not listen on a network port.
- The agent only reads. Actions are done by separate actor programs.
- The server signs each order with ed25519. An actor examines the signature, the expiry time, the nonce and its local allowlist.
- An LLM can only make a decision safer. It cannot increase the scope of an action.

## 3. Components

```
 SOURCES (any language)               nn-server (Go)                       ACTORS (any language)
 nn-scan ──┐               ┌──────────────────────────────────┐
 nn-agent ─┼─ POST /v1/... │ ingest → identity resolver       │
 others ───┘ ─────────────▶│   → inventory (device tree)      │
 in-process: unifi,        │ matchers → enrichers → findings  │   GET /v1/orders (pull)
   proxmox ───────────────▶│ deciders → guards → planner      │◀── nn-actor (Go): unifi, proxmox
                           │   → orders and approvals         │◀── nn-actor-host (Rust)
                           │ notifiers · web UI · SQLite      │◀── others
                           └──────────────────────────────────┘
```

### 3.1 nn-server

- HTTPS with a self-signed certificate. The server makes the certificate on the first start. Clients pin its SHA-256 fingerprint.
- The web interface is HTML, CSS and JavaScript. The server embeds the files. There is no build step.
- Operators log in with a user name and a password (bcrypt). The session cookie is `HttpOnly`, `Secure` and `SameSite=Strict`.
- The operator API accepts only JSON for write requests. This blocks cross-site requests.
- The server keeps its data in SQLite.
- The server and `nn-scan` can operate in Docker containers (`Dockerfile`, `compose.yaml`). The agent and the host actor operate on the host.

### 3.2 Enrollment

1. An operator makes a join token in the web interface. The token has a role (`source`, `agent` or `actor`), a number of uses and an expiry time.
2. The peer sends the join token to `POST /v1/enroll`.
3. The server gives a peer token. The server keeps only the SHA-256 hash of the token.
4. The peer sends the peer token as a bearer token in each request.

The server sets the source name of each observation to the name of the peer.
Only the server sets identifiers of the kind `agent`. It removes them from all observations and adds `agent=<peer name>` to agent reports.

Rules for agent reports:

- One top-level entity. No parent link. Children only of kind `container`, each with one `container.id`; the server replaces it with `agent.child=<agent>/<id>` (D-050).
- The agent identifier decides the device. On the first report, the agent can take over one device that matches its MAC address, IP address or host name, but only if no other agent has that device.
- An agent report never merges devices. It never moves a strong identifier from a different device.

Sources (scanners, importers) are trusted to describe the network. A source can merge devices that share a strong identifier. Give the role `source` only to programs that you trust.

Limits on each observation: 64 MiB body, 20000 entities, 256 identifiers for each entity, 512 attributes for each device. Each peer can send 60 observations in 10 minutes. Unknown JSON fields are refused.

### 3.2a Discovery

- `nn-scan` is a separate program. Thus, it can operate in each subnet. It finds hosts with TCP connections. An open port or a refused connection shows that the host is on. It reads banners, HTTP headers, TLS certificates and the local ARP table. It does not need root permissions.
- The `unifi` source operates in the server. It uses a read-only API key. It reads clients and network devices.
- The `proxmox` source operates in the server. It uses an API token with the role `PVEAuditor`. It reads cluster nodes, virtual machines and containers.

### 3.3 Agent (nn-agent)

The agent has collectors. Each collector reads one type of data.
Each collector declares the files, sockets and programs that it uses.
The command `nn-agent scope` shows this access.
The configuration enables the collectors.

| Collector | Data | Milestone |
|---|---|---|
| `os` | Operating system and kernel | M2 |
| `dpkg`, `rpm`, `apk` | Installed packages | M2 |
| `sockets` | Listening sockets, process and package of each socket | M2 |
| `interfaces` | Network interfaces and MAC addresses | M2 |
| `containers` | Running LXC, Docker and Podman containers and their packages, through `nn-agent-helper containers` | Done (M4) |

The agent operates as a user without root permissions by default.
Collectors that need more permissions are optional.

- The agent sends one top-level entity for its host. Each report contains all packages and services (`complete: true`). The server then removes data that the report does not contain.
- If a collector fails, the report is not complete. The server then keeps the earlier data. The attribute `agent.errors` shows the failure.
- The `sockets` collector finds the program of each listening socket. The package collectors find the package that owns the program. The service then refers to the package URL.
- To find the program of a socket, the agent uses the first method that operates:
  1. `/proc/<pid>/fd` of its own processes (all processes if it operates as root).
  2. The optional helper service `nn-agent-helper`. Only this small program has the capabilities `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`. It has no input and it cannot use `ptrace`.
  3. Without permissions: netlink `sock_diag` gives the cgroup of the socket. The cgroup gives the systemd unit or the container. `systemctl show` gives the program of the unit.
- Package URLs use the qualifiers `arch`, `distro` and `upstream` (the source package). The matcher uses `upstream` for Debian and Ubuntu.

### 3.4 Inventory and deduplication

Each observation contains entities. Each entity has identifiers.
An identifier has a kind, a value, and a strength.

- Strong identifiers name exactly one entity. Examples: a MAC address that is not locally administered, an agent ID, a Proxmox guest ID.
- Weak identifiers are hints. Examples: an IP address, a host name.

The identity resolver uses these rules:

1. If a strong identifier agrees with a device, the observation belongs to that device.
2. If no strong identifier agrees, a weak identifier can agree. A weak identifier must not conflict with a strong identifier.
3. If two devices have the same strong identifier, the server merges the devices.
4. If weak identifiers conflict, the web interface shows a merge suggestion.

Each device can have a parent. Example: a virtual machine has its hypervisor node as parent.

### 3.5 Threat feed and matching

- The `osv` matcher maps each package URL to an OSV ecosystem (`Debian:12`, `Ubuntu:22.04:LTS`, `Alpine:v3.19`, `Rocky Linux:9`, `AlmaLinux:9`). For Debian, Ubuntu and Alpine it uses the source package (`upstream` qualifier). OSV compares the versions.
- The matcher keeps its answers for 24 hours. It sends only package names, versions and the distribution release.
- The CVSS score comes from the OSV record. If the record has no CVSS vector, the matcher uses the CVE record. Then it uses the severity word of the distribution.
- The `kev` and `epss` enrichers add the known-exploited status and the exploit probability.
- A new report starts a match for that device. A feed update starts a match for all devices.
- If a matcher fails, the server keeps the earlier findings of the device. It does not close them.
- A finding that a new match does not show is closed (`resolved`). If it occurs again, it opens again.
- A finding is "exposed" if a listening service on a non-loopback address belongs to the vulnerable package.
- Versions from scan banners do not give findings yet. OSV has no data for product names from banners.

### 3.6 Decisions

| Tier | Effect |
|---|---|
| `notify` | The server sends a notification only. |
| `auto` | The server sends the order automatically. The action must be reversible and must have a time limit. |
| `approve` | An operator must approve the order. |

- The `rules` decider uses an ordered list of rules. A rule examines the CVSS score, KEV, EPSS, exposure, device tags and confidence.
- The `llm` decider is optional. It writes a summary and a proposal. The server examines the output against a schema. The LLM can only make the tier safer.
- Guards operate last. Examples: protected devices, a limit of actions per hour, a kill switch.
- The planner selects an actor by its capabilities. A capability has an action name and the identifier kinds that the actor can use.

### 3.7 Actors

- `nn-actor` has backends: `unifi` (block a client) and `proxmox` (firewall rule, suspend, stop, snapshot).
- `nn-actor-host` stops or starts allowlisted systemd units. It adds rules to its own nftables table.
- The server reverses an action when its time limit ends. It also reverses an action when a new report shows a fixed version.

## 4. Plug-in contracts

Each plug-in registers a factory in a registry (`internal/registry`).
The configuration has entries with the format `{"type": ..., "name": ..., "settings": {...}}`.

| Package | Interface | Function |
|---|---|---|
| `internal/source` | `Source` | Pulls observations from an API in the server. |
| `internal/intel` | `Matcher` | Finds vulnerabilities for components. |
| `internal/intel` | `Enricher` | Adds facts to a vulnerability. |
| `internal/decide` | `Decider` | Proposes a tier and an action. |
| `internal/decide` | `Guard` | Makes a proposal safer. |
| `internal/notify` | `Notifier` | Sends events to a person. |
| `internal/actor` | `Backend` | Executes orders in `nn-actor`. |
| `internal/store` | `Store` | Keeps the data. SQLite is the first implementation. |
| `agent/nn-agent` | `Collector` (Rust trait) | Collects one type of data on a host. |
| `agent/nn-actor-host` | `Action` (Rust trait) | Executes one type of action on a host. |

To add a plug-in, do these steps:

1. Write a type that implements the interface.
2. Register the type in the registry in an `init` function.
3. Add an entry to the configuration.

An external program can also be a source or an actor. It uses the JSON protocol in `api/v1`.

## 5. Protocol (v1)

| Message | Direction | Schema |
|---|---|---|
| `Observation` | Source or agent to server | `api/v1/observation.schema.json` |
| `ActorHello` | Actor to server | `api/v1/actor.schema.json` |
| `SignedOrder` | Server to actor | `api/v1/actor.schema.json` |
| `OrderResult` | Actor to server | `api/v1/actor.schema.json` |

The Go types are in `internal/proto`. The Rust types are in `agent/nn-proto`.

## 6. Milestones

| ID | Contents | Status |
|---|---|---|
| M0 | Skeleton: protocol, registries, server with store, TLS, login and web interface shell | Done |
| M1 | Ingest API, identity resolver, `nn-scan`, `unifi` source, device list | Done |
| M2 | Agent enrollment, collectors `os`, `dpkg`, `rpm`, `apk`, `sockets`, `interfaces` | Done |
| M3 | OSV, KEV and EPSS, findings page | Done |
| M4 | `proxmox` source, `containers` collector, device tree, Map page, pull mode, MSRC matcher | Done. `qga` dropped: virtual machines run their own agent (D-050) |
| M5 | `rules` decider, guards, approval queue, webhook notifier, device tags | Done (decisions are recorded; execution in M6) |
| M6 | Actor protocol, signed orders, `nn-actor`, `nn-actor-host`, time limits | Not done |
| M7 | `llm` decider | Not done |
