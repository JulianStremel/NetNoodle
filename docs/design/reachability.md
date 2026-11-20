# Design: reachability (internet, tunnel, local)

Status: proposal (D-060). User request: a VPS with Tailscale is an ingress point to a subnet. Devices with Tailscale or another VPN, and the networks behind them, must be handled as reachable from outside.

## 1. Levels

| Level | Meaning | Evidence |
|---|---|---|
| `internet` | Reachable from the internet | A public address on an interface of the device; later: port forwards and Tailscale Funnel |
| `tunnel` | Reachable through a VPN or overlay network | A VPN interface (`tailscale0`, `wg*`, `zt*`, `tun*`, Windows adapters of Tailscale, WireGuard, ZeroTier); an address in `100.64.0.0/10` or `fd7a:115c:a1e0::/48`; a network that a subnet router or exit node makes reachable |
| `local` | Reachable only in the local network | All other devices |

The level of a device is the highest level that applies. The level of a listener (port) is the level of the addresses on which it listens: `0.0.0.0` and `::` take the device level, `127.0.0.1` and `::1` are not reachable, a specific address takes the level of that address.

## 2. Sources of evidence

1. **Agent** (Linux and Windows): marks each interface with `kind: "vpn"` and `vpn: "tailscale" | "wireguard" | "zerotier" | "tun"`. Only names, interface types and adapter descriptions are used. The agent runs no VPN program.
2. **Server**: classifies each address (public, CGNAT/Tailscale, private, link-local, loopback).
3. **Tailscale source** (read-only API key of the tailnet): nodes with their tailnet addresses, OS, client version, tags, last seen, advertised and enabled subnet routes, exit nodes. Enabled subnet routes make every device in those networks `tunnel` reachable, and the subnet router is the entry point. The client version becomes a component `pkg:golang/tailscale.com@v<version>`, so the OSV matcher finds Tailscale advisories.

## 3. Use of the level

- **Risk**: the exposure part of the finding weight depends on the level of the listener: local +1, tunnel +1.5, internet +2.
- **Rules**: new condition `when.reachable` (`internet`, `tunnel` or `local`; matches that level or higher).
- **Map**: an "Internet / tailnet" entry point. Radar and City mark edge devices; Flow gets an "Internet" column (entry point → subnet router → network → device).
- **Device page**: a badge with the level and the evidence.

## 4. Monitoring the ingress VPS

Use pull mode over the tailnet:

- The agent on the VPS listens only on its tailnet address: `--listen 100.x.y.z:7444`.
- `--allow-from <tailnet address of the server>`. Tailnet addresses do not change with the residential public address, and they are bound to the WireGuard key of the node.
- Add a Tailscale ACL that permits only the server node to reach port 7444 of the VPS.
- The pinned mTLS certificates stay the authentication; the address checks are more layers.

## 5. Order of work

1. Agent: VPN interface detection (Rust, Linux and Windows) and the protocol field.
2. Server: address classification, levels, risk, rule condition, device badge, graph fields.
3. Tailscale source (API v2 of tailscale.com; Headscale later).
4. Map: entry point and highlighting.
