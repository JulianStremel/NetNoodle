# Integrations

Set up discovery sources, notifications, threat intelligence and AI providers on the Integrations page. Changes take effect without a server restart.

[← Back to the README](../../README.md)

## Set up in the web interface

1. Log in as **admin** and open **Integrations**.
2. Select a tab, then **Add integration**. Choose a type and select **Next**.
3. Enter a unique name and the settings shown in the form. Use read-only credentials for sources. Home Assistant needs a dedicated administrator token to read its device registry.
4. If a fingerprint field is shown, you can enter a known certificate fingerprint. For a self-signed source certificate, select **Fetch fingerprint**. Compare it with the certificate on that server through a trusted connection. Confirm it only if they match. Leave it empty to use normal certificate checks. For MQTT, copy a known broker fingerprint into the form.
5. Select **Test connection**. The table below explains what each test does.
6. Enter your administrator password and select **Save**.

| Tab | Types | Test action |
|---|---|---|
| Sources | UniFi, Proxmox, Tailscale, Home Assistant | Read once and count entities. Do not import data. |
| Notifications | Webhook, MQTT for Home Assistant | Send one `integration.test` event to this notifier only. |
| Threat intelligence | OSV, MSRC, KEV, EPSS | Fetch with a new instance. Do not save findings or change the running feed cache. |
| AI advisor | OpenAI-compatible, Anthropic | Send "Reply with OK". Show reply length in bytes and time in milliseconds. |

Use **Edit**, **Enable**, **Disable** or **Delete** to change an integration. Each change needs your administrator password. Leave a secret field empty when editing to keep its saved value. Entries from `netnoodle.json`, including the older `mqtt` entry, show as **from config file** and are read only here. Change those entries in the file and restart the server.

## Notifications

Use the **Notifications** tab to add a webhook or MQTT publisher. A webhook sends JSON events. Set its format to `slack` for a Slack-type receiver. Leave event prefixes empty to send all events. Enter private headers as a JSON object in the secret **Headers** field, for example `{"Authorization":"Bearer <token>"}`. The API never shows these headers again.

For MQTT, enter the broker address, username and password. Use `mqtts://` for TLS. Plain `mqtt://` needs a loopback IP address or the explicit **Allow plaintext** option. Use a unique client ID and topic prefix for each publisher. MQTT also publishes the Home Assistant discovery and inventory described below. Its test only sends an event; it does not publish discovery or inventory. Test events bypass event filters so you can verify delivery. The normal event filters still apply after saving.

## Threat intelligence

Use the **Threat intelligence** tab to add OSV and MSRC matchers, or KEV and EPSS feeds. OSV has a base URL, cache lifetime and parallel request limit. MSRC has a base URL and a month limit. KEV and EPSS have feed URLs. The form shows the current defaults. These are the same settings the plug-ins accept in the config file. Config-file defaults remain visible and read only; give any additional instance a different name.

Saving, enabling or disabling an entry replaces the active plug-ins through the server's intel runtime. No restart is needed. A test uses a separate instance: OSV sends an empty package batch, MSRC fetches its selected documents, and KEV and EPSS fetch their feeds. Tests do not send device names or addresses and do not save findings.

## AI providers

Use the **AI advisor** tab to save a provider for the future M7 advisor. M7 is not built yet. These providers do not make decisions or start actions. No inventory is sent during normal operation.

- **openai** supports the OpenAI chat completions API and compatible servers, including Ollama and LM Studio. Enter the server root or a base URL ending in `/v1`, then the model name from that server. An API key is optional for local servers.
- **anthropic** uses the Messages API. Its default base URL is `https://api.anthropic.com`. A model name and API key are required.

There is no default model. Enter the model yourself. HTTPS is required except for loopback URLs. Set a positive timeout. Replies are limited to 1 MiB. Tests send only the minimal prompt shown above and show the reply length and latency. The API never returns the reply text or API key.

**Send device names** and **Send IP addresses** are both off by default. These choices are stored for M7 and have no effect yet.

Credentials are stored in a separate column in the database. The data directory is private (0700) and the database file is private (0600). Storing credentials on the same disk as the order signing key is an accepted risk: anyone who can read that disk can read them. APIs show only whether a credential is set. Local database backups keep credentials; `nn-server export` removes them and disables the exported integrations. Enter credentials again after restoring an export.

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

## Config-file alternative: send notifications

You can still define a read-only webhook in `netnoodle.json`:

```json
"notifiers": [{ "type": "webhook", "name": "hook", "settings": { "url": "https://ntfy.example/netnoodle", "types": ["device."] } }]
```

Restart the server after changing the config file. The same webhook can be created and changed without a restart from the **Notifications** tab.
