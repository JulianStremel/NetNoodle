# Integrations in the web interface

Status: implemented for all server-side integration kinds: source, notify (webhook, MQTT), intel (OSV, MSRC, KEV, EPSS), and llm (OpenAI-compatible, Anthropic). Shared schemas, write-only secrets, test actions and hot reload. The M7 advisor is not built; LLM providers remain advisory and isolated from decisions.

## 1. Goal

An operator adds, changes, tests and removes integrations (in-process sources: `unifi`, `proxmox`, `tailscale`, `homeassistant`; later the MQTT publisher) on the **Integrations** page. No config file edit and no server restart. Sources in the config file keep working; they show as "from config file" (read only).

## 1a. Scope (user decision 2026-11-20)

**Every integration that lives in the server is configurable in the web interface**, not only sources. Each plug-in registry gets the same mechanism (schema, write-only secrets, probe/test where it makes sense, supervisor or hot reload):

| Registry | Plug-ins today | Test action |
|---|---|---|
| `source` | unifi, proxmox, tailscale, homeassistant | one poll without ingest |
| `notify` | webhook, mqtt (Home Assistant), later Home Assistant notifications and Telegram | send a test event |
| `intel` matchers and enrichers | osv, msrc, kev, epss (URL, cache, limits) | one refresh without saving |
| `llm` (M7 advisor, provider-agnostic) | none yet: OpenAI-compatible, Anthropic, local (Ollama/OpenAI-compatible); fields provider, base URL, model, API key (secret), timeout, data minimization options | one minimal prompt |

Deciders and guards are policy, not integrations; they stay in the config file (guards protected/scope/killswitch are mandatory anyway). The page groups the registries in tabs: Sources, Notifications, Threat intelligence, AI advisor. The LLM tab is shown when the LLM registry has at least one provider (M7).

Implementation order: sources first (the generic mechanism), then notify, intel, llm in a second step that reuses the same table (`integrations.kind` = registry name).

## 2. Generic settings schema (registry)

- Each source factory registers a schema with its constructor: `source.Registry.RegisterWithSchema(name, New, Schema{Fields: []Field{...}})`.
- `Field{Key, Label, Type: "url"|"string"|"secret"|"fingerprint"|"bool"|"duration"|"list", Required, Default, Help}`.
- The UI renders the form from the schema (`GET /api/integrations/types`). New source = new schema, no UI change.
- Secret fields are write-only: the API never returns them (it returns `"set": true`). An empty secret on update keeps the old value.

## 3. Storage and lifecycle

- Table `integrations(id, kind, type, name UNIQUE, settings_json, secrets_json, enabled, created_at, updated_at, last_ok_at, last_error)` (migration after the onboarding one).
- Secrets are stored in the database (data directory is 0700, database 0600) and are excluded from `nn-server export`; documented as an accepted risk (same disk as the order key).
- A source supervisor in the server starts, stops and restarts sources when a row changes (context per source). Config-file sources are started as before.
- Validation: the same constructor (`New`) validates; a failed `New` is shown to the user, nothing is saved.

## 4. API (admin, password step-up for create/update/delete, like updates)

- `GET /api/integrations` -> list (no secrets), with state (running, last poll, last error).
- `GET /api/integrations/types` -> schemas.
- `POST /api/integrations/probe` `{url}` -> certificate SHA-256 fingerprint and subject of the URL's TLS certificate (no verification; for the operator to compare and confirm; size and time limits; only https; refuse loopback-only? no: allowed, the operator chooses).
- `POST /api/integrations/test` `{type, settings, secrets}` -> runs one poll without ingest (a dry `Poll` with an emit that counts entities) with a 30 s timeout -> `{ok, entities, error}`.
- `POST /api/integrations`, `PUT /api/integrations/{id}`, `DELETE /api/integrations/{id}`, `POST /api/integrations/{id}/enable|disable`.

## 5. UI (Integrations page)

List with state; **Add integration** -> select type -> form from schema -> **Fetch fingerprint** (shows fingerprint and subject; operator confirms) -> **Test connection** -> **Save**. Edit and delete with password. DOM only with `el()`/`textContent`.

## 6. Tests

Schema registry; secret never in any API answer (test all routes); update with empty secret keeps the value; supervisor restarts a source on change and stops it on delete/disable; probe limits; test-poll timeout; store contract for the table.
