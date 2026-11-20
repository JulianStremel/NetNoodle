# Design: actors and orders (M6)

Status: proposal (D-055). Not implemented.

## 1. Purpose

M5 records decisions. M6 executes them. An actor is a separate program that changes something in the network, for example it blocks a client in UniFi. Actors are the most dangerous part of netnoodle. Thus, each layer must refuse an order that it cannot verify.

## 2. Rules

1. The server never executes an action itself. Only actors execute actions.
2. Each order has an Ed25519 signature of the server. The actor verifies the signature, the expiry time, the nonce and its local allowlist before it executes the order.
3. An actor operates in **dry-run** mode by default. In dry-run mode it only writes what it would do. The operator must set `dry_run: false` in the configuration of the actor.
4. Only proposals in the state `approved` (approved by an operator) or `auto` (permitted by the rules and the guards) become orders.
5. The kill switch stops all new orders. Reverts continue.
6. An order with a TTL is reversed after the TTL. The server sends the revert order.

## 3. Keys

- The server makes an Ed25519 key on the first start: `data/keys/order-ed25519.pem`. The **Overview** page shows the public key.
- An actor gets the public key in the enrollment answer and stores it. It also accepts a fingerprint on the command line (`--order-key`) to compare.
- Signature: the server signs the exact JSON bytes of the order. The envelope is `{"payload": "<base64 of the order JSON>", "sig": "<base64>"}`. The actor verifies the bytes first and parses them after that. No canonical JSON is needed.

## 4. Protocol (the actor connects to the server)

| Request | Purpose |
|---|---|
| `POST /v1/actor/hello` | The actor sends its capabilities (`proto.ActorHello`). |
| `GET /v1/orders?wait=30` | Long poll. The server answers with the envelopes for this actor, or with an empty list after 30 seconds. |
| `POST /v1/orders/result` | The actor sends `proto.OrderResult`. |

All requests use the bearer token of a peer with the role `actor`. For actors in a DMZ, the pull transport of `docs/design/pull-mode.md` can be used later in the other direction.

## 5. Planner

For each proposal in state `approved` or `auto`:

1. Find the actors with a capability for the action of the proposal.
2. Keep the actors that can address the device: a `target_id_kinds` entry of the capability must be an identifier kind of the device (for example `mac` for UniFi, `proxmox.guest` for Proxmox, `agent` for the host actor).
3. Exactly one actor must remain. Preference: an actor with a strong identifier of the device. If no actor remains, the proposal gets the state `no-actor`. If more than one remains, the actor with the highest priority in the configuration wins.
4. The server makes the order: targets are the matching identifiers of the device, `not_after` is now + 10 minutes, the nonce is random.

Order states: `queued` → `sent` → `done` | `failed` | `rejected` | `expired`.

## 6. Revert

- When an order with a TTL is `done` and the capability is reversible, the server schedules a revert order (`revert_action`, `revert_of`) at done + TTL.
- When the finding is resolved earlier (a fixed version is reported), the server sends the revert order immediately.
- The operator can revert an order on the **Actions** page.

## 7. Actor programs

| Program | Backend | Action | Target |
|---|---|---|---|
| `nn-actor` (Go) | `log` | all (for tests) | all |
| `nn-actor` (Go) | `unifi` | `isolate` (block the client), revert `unisolate` | `mac` |
| `nn-actor` (Go) | `proxmox` | `snapshot`, `isolate` (guest firewall: drop all except the management network) | `proxmox.guest` |
| `nn-actor-host` (Rust) | host | `block-port` (own nftables table `inet netnoodle`, rules with timeout), `stop-service` (only units in the allowlist) | `agent` |

Each actor has a local allowlist in its configuration: permitted actions, permitted targets (MAC prefixes, guest IDs, units), and a limit of orders per hour. The allowlist is the last protection if the server is compromised.

## 8. Risks

| Risk | Countermeasure |
|---|---|
| The server is compromised and sends harmful orders. | Local allowlist and rate limit on the actor; dry-run by default; reversible actions only for `auto`. |
| An attacker replays an order. | Nonce store on the actor, `not_after` limit. |
| An attacker changes an order on the way. | Ed25519 signature over the exact bytes; TLS with the pinned server certificate. |
| An order isolates an important device. | Tag `protected` (guard), approval for `isolate` in the default rules, TTL and automatic revert. |
| The revert fails, so the device stays blocked. | The revert is retried; a failed revert makes an event with severity critical. |

## 9. Order of work

1. Server: signing key, actor hello, orders table, planner, long poll, results, revert scheduler, Actions page columns. `nn-actor` with the `log` backend. End-to-end test.
2. `unifi` backend (dry-run first).
3. `nn-actor-host` (Rust): `block-port` with nftables.
4. `proxmox` backend.
