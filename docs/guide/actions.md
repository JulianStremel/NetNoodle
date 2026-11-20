# Decisions and actions

How netnoodle decides on actions, the approval queue, and the actors that execute approved actions.

[← Back to the README](../../README.md)

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

   You can change the settings of the guards in the configuration (`guards`). You cannot remove `protected`, `scope` and `killswitch`. If they are not in the list, the server adds them.
3. An automatic action must be reversible (`isolate`, `block-port`, `stop-service`, `snapshot`) and must have a time limit (TTL). If not, it needs approval. Configuration cannot change this.

The **Actions** page shows the decisions that need approval, with **Approve** and **Reject**. To set the tags of a device, open the device page.

To change the rules, set `deciders` in `netnoodle.json`, for example:

```json
{ "deciders": [ { "type": "rules", "name": "rules", "settings": { "rules": [
  { "name": "kev-dmz", "when": { "kev": true, "networks": ["172.16.0.0/24"] }, "then": { "tier": "approve", "action": "isolate", "ttl": "12h" } }
] } } ] }
```

## Procedure: install an actor (dry run)

An actor executes approved actions. In this version, `nn-actor` has only the `log` backend: it writes what it would do. Refer to [docs/design/actors.md](../design/actors.md).

1. In the web interface, make a join token with the role `actor`.
2. Enroll the actor:

   ```sh
   NN_JOIN_TOKEN=<token> nn-actor enroll -server https://<server>:7443 -fingerprint <sha256> -name actor1 -creds /var/lib/nn-actor/creds.json
   ```

   The actor stores the public order key of the server. It accepts only orders with a signature of this key.
3. Write the configuration. Refer to [deploy/nn-actor.example.json](../../deploy/nn-actor.example.json):
   - `dry_run` is `true` if you do not write it. In dry-run mode the actor executes nothing.
   - `allow` lists the permitted actions and targets (for example `mac=bc:24:11:*`). The actor refuses all other orders.
   - `max_per_hour` limits the orders (default 20).
4. Start the actor: `nn-actor run -config /etc/nn-actor/actor.json`.

Backend `unifi` (block a client in UniFi Network, action `isolate`, revert `unisolate`): refer to [deploy/nn-actor.unifi.example.json](../../deploy/nn-actor.unifi.example.json).

- Make a local API key on the UniFi console and write it to a file that only the actor can read (`api_key_file`).
- Write the SHA-256 fingerprint of the console certificate in `fingerprint`.
- Write the MAC addresses that must never be blocked (gateway, UniFi console, netnoodle server, your administrator computer) in `never_block`. The backend does not start if `never_block` is empty. The backend also refuses to block UniFi devices. In a container, the backend sees only the MAC addresses of the container, thus it cannot find the MAC addresses of the host.
- The backend uses the command `block-sta` of the classic Network API. Ubiquiti does not document this command. Test it with `dry_run: false` on a client that is not important before you use it.

Backend `proxmox` (Proxmox VE guests, target `proxmox.guest`): refer to [deploy/nn-actor.proxmox.example.json](../../deploy/nn-actor.proxmox.example.json).

- `isolate` sets `link_down=1` on all network interfaces of the guest. The guest keeps its MAC addresses and bridges. `unisolate` removes it again. This operates without the Proxmox firewall.
- `snapshot` makes a snapshot `nn-<order>` (no revert).
- Make a separate API token for the actor with only the permissions `VM.Audit`, `VM.Config.Network` and (for snapshots) `VM.Snapshot`. Do not use the read-only token of the import.
- Write the VM IDs that must never be isolated in `never_isolate`.

Backend `host` (on the Linux host itself, target `agent=<name of the agent of this host>`): refer to [deploy/nn-actor.host.example.json](../../deploy/nn-actor.host.example.json) and [deploy/nn-actor-host.service](../../deploy/nn-actor-host.service).

- `block-port` adds the ports to sets of its own nftables table `inet netnoodle` and drops incoming packets to them. Each entry has a time limit (the TTL of the order, at most `max_ttl`). Thus the block ends also if the revert order does not arrive. `unblock-port` removes the entries.
- Ports 22, 7443 and 7444 are never blocked (setting `never_block_ports`), so that you can still log in and the actor can still get the revert order. The backend does not start with an empty `never_block_ports`, unless you set `allow_empty_never_block_ports`. The server also never sends a block for port 22, 7443, 7444 or for its own listen port.
- `stop-service` and `start-service` are permitted only for the units in `services`. They need root or a polkit rule. The service unit in `deploy/` gives only `CAP_NET_ADMIN`, which is sufficient for `block-port`.

When you approve a decision on the **Actions** page, the server sends an order to an actor that can do the action for the device. The **Actions** page shows the state of the order. After the TTL, the server sends the revert order.
