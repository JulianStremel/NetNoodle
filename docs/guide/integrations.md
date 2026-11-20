# Integrations

Import from UniFi, Proxmox VE and Home Assistant, give data to Home Assistant, and send notifications.

[← Back to the README](../../README.md)

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

## Procedure: import from Tailscale

The source `tailscale` reads the tailnet from the Tailscale API (read only). It reports each node with its tailnet addresses, operating system, tags, last-seen time, and the subnet routes and exit nodes that are enabled. Networks behind a subnet router become reachable through the tunnel (refer to [Reachability](vulnerabilities.md#reachability)). The version of the Tailscale client becomes a component `pkg:golang/tailscale.com`, so OSV finds Tailscale advisories.

1. In the Tailscale admin console, make an API access token with read access to devices. Write it to a file that only nn-server can read.
2. Add the source to `netnoodle.json`:

   ```json
   { "sources": [ { "type": "tailscale", "name": "tailnet", "interval": "15m",
       "settings": { "api_key_file": "/etc/netnoodle/tailscale-key" } } ] }
   ```

Monitor an ingress host (for example a VPS that is a subnet router) with an agent in pull mode over the tailnet: `--listen <tailnet address>:7444` and `--allow-from <tailnet address of the server>`. Refer to [Pull mode](agents.md#procedure-pull-mode-agent-in-a-dmz).

## Procedure: connect Home Assistant

netnoodle reads devices from Home Assistant, and gives data to Home Assistant for automations. Refer to [docs/design/homeassistant.md](../design/homeassistant.md).

**Read from Home Assistant** (source `homeassistant`):

1. In Home Assistant, make a dedicated user. The device registry needs an administrator user. Make a long-lived access token for this user and write it to a file that only nn-server can read.
2. Add the source to `netnoodle.json`:

   ```json
   { "sources": [ { "type": "homeassistant", "name": "ha-home", "interval": "10m",
       "settings": { "url": "https://ha.local:8123", "token_file": "/etc/netnoodle/ha-token", "fingerprint": "<sha256>" } } ] }
   ```

Use `https` with `"fingerprint"` of the Home Assistant certificate. Plain `http` is permitted only for a Home Assistant on the same computer (`127.0.0.1`), because the token is an administrator token.

The source reads the device registry (manufacturer, model, firmware, MAC addresses), the device trackers (IP addresses) and the versions of Home Assistant, Home Assistant OS and the add-ons. The server compares the Home Assistant version with the OSV data (ecosystem PyPI). Devices merge with the same devices from UniFi or the scanner by their MAC address.

**Give data to Home Assistant** (MQTT discovery):

1. Add the broker that Home Assistant uses to `netnoodle.json`:

   ```json
   { "mqtt": { "broker": "mqtts://mqtt.local:8883", "username": "netnoodle", "password_file": "/etc/netnoodle/mqtt-password" } }
   ```

2. Home Assistant makes these entities automatically (device "netnoodle"):

   | Entity | Content |
   |---|---|
   | `sensor.netnoodle_open_findings` | Open findings; attributes: critical, KEV, exposed |
   | `sensor.netnoodle_devices` | Devices; attributes: new in 24 h, internet, tunnel, local |
   | `binary_sensor.netnoodle_kev_reachable` | On if a device that is reachable from the internet or a tunnel has a known exploited vulnerability |
   | `sensor.netnoodle_pending_approvals` | Decisions that wait for approval |
   | `binary_sensor.netnoodle_kill_switch` | State of the kill switch (read only) |

3. For a risk sensor of a device, give the device the tag `ha` on its device page.
4. All events go to the topic `netnoodle/event` (JSON). Use them as MQTT triggers in automations.

If nn-server stops, the entities become unavailable (MQTT last will). Without the key `mqtt`, nothing is published. `mqtt://` without TLS is permitted only for a broker on the same computer, or with `"allow_plain": true`. For a broker with a self-signed certificate, write its SHA-256 fingerprint in `"fingerprint"`.

Only these events go to `netnoodle/event`, without their detail text: `device.new`, `finding.new`, `proposal.pending`, `order.done`, `order.failed`, `order.uncertain`, `order.expired`, `order.revert-blocked`. Change the list with `"events"` and add the detail text with `"event_details": true`.

> **Caution:** Configure the access control list of the broker: only netnoodle may write `netnoodle/#` and `homeassistant/+/netnoodle_*/#`, and only Home Assistant may read them. Other clients could otherwise read the inventory or send false states that start automations.

## Procedure: send notifications

Add a notifier to `netnoodle.json`:

```json
"notifiers": [{ "type": "webhook", "name": "hook", "settings": { "url": "https://ntfy.example/netnoodle", "types": ["device."] } }]
```

The server sends each event as JSON. Set `"format": "slack"` for Slack-type receivers.
