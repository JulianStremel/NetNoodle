# Design: Home Assistant integration

Status: steps 1 and 2 implemented (source `homeassistant`, MQTT discovery); steps 3 to 5 planned (D-061). User request: collect data from Home Assistant, and give data to Home Assistant for automations.

## 1. Two directions

```
 Home Assistant ──(REST/WebSocket, token)──▶ nn-server      source "homeassistant": devices, MACs, versions
 Home Assistant ◀──(MQTT discovery)──────── nn-server      sensors, binary sensors, events for automations
 Home Assistant ◀──(webhook)─────────────── nn-server      instant triggers (existing webhook notifier)
 Home Assistant ◀──(service call, later)─── nn-actor       actor backend "homeassistant" (e.g. switch off a plug)
```

## 2. Source: Home Assistant → netnoodle

A server-side source plug-in (like `unifi` and `proxmox`). It does not need a program on the Home Assistant host.

Data (WebSocket API, read only):

| Data | API | Use in netnoodle |
|---|---|---|
| Device registry: manufacturer, model, firmware (`sw_version`), `connections` (MAC addresses), area, integration | `config/device_registry/list` | IoT devices with MAC (strong identifier), so they merge with UniFi and scan devices; firmware versions as components (`pkg:generic/<manufacturer>/<model>@<sw_version>`, low confidence) |
| Device trackers with IP and MAC | `get_states` (domain `device_tracker`, attributes `ip`, `mac`) | Addresses and presence |
| Core, Supervisor, OS versions, add-ons with versions | `get_config`, Supervisor API (`/api/hassio/...` through the core proxy) | The Home Assistant host itself: `pkg:pypi/homeassistant@<version>` (OSV ecosystem PyPI finds advisories), Home Assistant OS version, add-on versions |
| Integrations (config entries) | `config_entries/get` | Attribute only (which systems Home Assistant controls) |

Rules:

- Identifiers: `homeassistant.device=<source>/<device_id>` (strong), MACs from `connections` (strong), IPs (weak).
- The Home Assistant host is the parent of devices only when the device is a virtual or add-on device; physical devices stay top-level (they are on the network themselves).
- Limits: 20000 devices, field lengths, response size, as in the other sources.
- Token: Home Assistant has no read-only tokens. Use a long-lived token of a dedicated user. The device registry needs an administrator user; document this risk. The token is stored in a file (`token_file`), never in the database or logs.

## 3. Home Assistant ← netnoodle (automations)

### 3.1 MQTT discovery (recommended first)

A new plug-in `mqtt` publishes to the MQTT broker that Home Assistant uses. With MQTT discovery, Home Assistant makes the entities itself. No custom integration is necessary.

| Entity | Type | State |
|---|---|---|
| `sensor.netnoodle_open_findings` | sensor | Number of open findings; attributes: critical, KEV, exposed |
| `sensor.netnoodle_devices` | sensor | Number of devices; attributes: new in 24 h, by reachability level |
| `binary_sensor.netnoodle_kev_internet` | problem | On if a device that is reachable from the internet or the tailnet has a KEV finding |
| `sensor.netnoodle_pending_approvals` | sensor | Number of decisions that wait for approval |
| `binary_sensor.netnoodle_kill_switch` | binary sensor | State of the kill switch |
| per device (opt-in, by tag `ha`) | sensor | Risk 0–10 of the device, with the top findings as attributes |
| events | MQTT topic `netnoodle/event` | New device, new KEV finding, order done/failed, revert failed; use as automation trigger |

Settings: broker URL (TLS), user, password file, topic prefix, discovery prefix (`homeassistant`), devices tagged `ha` only.

### 3.2 Webhook (exists already)

The `webhook` notifier can call a Home Assistant webhook trigger (`/api/webhook/<id>`) for each event. This is the fastest way to start automations now.

### 3.3 Control from Home Assistant (later, optional)

- Kill switch as an MQTT `switch` entity: Home Assistant can turn automatic actions off. Turning it ON is always permitted; turning it OFF from Home Assistant needs the setting `ha_may_disable_killswitch: true`.
- Approve or reject from Home Assistant is NOT planned: an approval must come from an operator in the netnoodle interface (D-054).

## 4. Actor backend `homeassistant` (later)

An `nn-actor` backend that calls Home Assistant services, for example `switch.turn_off` of the smart plug of a compromised IoT device (action `isolate`, revert `switch.turn_on`). The mapping device → entity comes from the device registry (same Home Assistant device). Same rules as the other backends: allow list, dry run, journal, never-touch list (for example plugs of network equipment).

## 5. Read-only API for integrations

For 3.3 and for other tools, netnoodle needs a token role `reader` (GET on `/api/graph`, `/api/findings`, `/api/devices`, no writes). The MQTT plug-in does not need it (it runs in the server).

## 6. Order of work

1. Source `homeassistant` (device registry, trackers, versions).
2. Plug-in `mqtt` with discovery (sensors, binary sensors, events).
3. Kill switch entity.
4. Actor backend `homeassistant`.
5. Optional: Home Assistant add-on that packages `nn-scan` for networks that only Home Assistant can reach.
