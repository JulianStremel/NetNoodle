# Operations

Storage, releases, updates and data locations.

[← Back to the README](../../README.md)

## Releases and channels

Each release `vX.Y.Z` has binaries for Linux (x86_64, aarch64) and Windows (x86_64, ARM64), and container images on GitHub Container Registry (`ghcr.io/julianstremel/netnoodle-server`, `-scan`, `-actor`, for amd64 and arm64).

| Image tag | Meaning |
|---|---|
| `vX.Y.Z`, `vX.Y` | One release (`vX.Y` follows its newest patch) |
| `latest` | The newest release |
| `stable` | The newest release that was promoted after a waiting time without problems |

Verify a download before you use it:

```sh
cosign verify-blob --bundle SHA256SUMS.sigstore.json   --certificate-identity-regexp 'https://github.com/JulianStremel/NetNoodle/'   --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
cosign verify ghcr.io/julianstremel/netnoodle-server:stable   --certificate-identity-regexp 'https://github.com/JulianStremel/NetNoodle/'   --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Update

Server in Docker, by hand: `docker compose pull && docker compose up -d`.

### Update from the web interface (host updater)

The server never gets the Docker socket. A small program on the host, `nn-host-updater`, does the update when the server asks for it (refer to [docs/design/lifecycle.md](../design/lifecycle.md), section 3a). It takes images only from the repository in its own configuration, checks the signature, refuses downgrades, makes a database backup, starts the new version, checks it, and goes back to the old version if something fails.

1. Install the program and its directories (Linux with Docker Compose v2 and cosign):

   ```sh
   go build -trimpath -o bin/nn-host-updater ./cmd/nn-host-updater
   sudo install -m 0755 bin/nn-host-updater /usr/local/sbin/nn-host-updater
   sudo install -d -m 0755 /etc/nn-host-updater /var/lib/netnoodle/updater /var/lib/netnoodle/updater/status
   sudo install -d -o 65532 -g 65532 -m 0750 /var/lib/netnoodle/updater/requests
   sudo install -m 0600 deploy/nn-host-updater.example.json /etc/nn-host-updater/config.json
   sudoedit /etc/nn-host-updater/config.json   # compose file, image repository, cosign trust, server fingerprint
   ```

   The updater keeps its private state in `/var/lib/netnoodle-updater` (`state_dir`, root, mode 0700). systemd makes this directory. It must not be in the shared directory: the server container must not see it. On the `stable` channel, the image must also have the signature of the promote workflow (`promote_identity_regexp`). The updater uses only the channel of its own configuration, and it gets the installed version from Docker or from the binary, not from the server. It keeps at most 8 requests and deletes other files in `requests/`. After 3 failed recoveries, it stops and the System page shows "manual action required".

2. Turn on updates in the server configuration and recreate the server with `compose.yaml` (it mounts the shared directory):

   ```json
   { "update": { "enabled": true, "shared_dir": "/var/lib/netnoodle/updater", "channel": "stable", "auto": false, "window": "Sun 03:00-05:00" } }
   ```

3. Install and start the units:

   ```sh
   sudo install -m 0644 deploy/nn-host-updater.path deploy/nn-host-updater.service      deploy/nn-host-updater-check.service deploy/nn-host-updater-check.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo nn-host-updater check
   sudo systemctl enable --now nn-host-updater.path nn-host-updater-check.timer
   ```

The **System** page then shows the version, the channel, an available update, **Update now** (your password is asked again), **Schedule for window**, the history of each step, and **Roll back** for the last update (7 days). The sidebar shows "Update available".

## Backup, restore and export

- Before the server changes the database schema (after an update), it copies the database to `data_dir/backups/` and keeps the last 3 copies. If there is not sufficient free disk space (2 × the database), the server does not start and does not change the schema.
- A database that is newer than the program (after a downgrade) is refused.
- Restore a copy (the server must be stopped; it holds `data_dir/nn-server.lock` while it runs):

  ```sh
  nn-server restore --latest        # or: --file data/backups/<name>.db
  ```

  The current database is kept in `backups/` as `pre-restore-…`.
- Export the database and the keys before you move or remove the server: `nn-server export --out netnoodle-export.tar.gz`. The archive does not contain configuration files with secrets (token files).
- `nn-server version` shows the version. The **Peers** page shows the version of each peer and marks peers that are too old; an actor that is too old gets no new orders (reverts still work).

## Where netnoodle keeps data

| Part | Place |
|---|---|
| Server | The data directory (`data_dir`, in Docker the volume `server-data`): database, `tls/` (certificates), `keys/` (order signing key), `backups/` |
| Agent (Linux) | `/etc/nn-agent/` (configuration), `/var/lib/nn-agent/` (credentials, pull state) |
| Agent (Windows) | `C:\ProgramData
etnoodlegent\` |
| Actor | Its credentials file, nonce file, journal and result outbox (paths in its configuration) |
| Scanner | Its credentials file and the `/var/lib/nn-scan` volume |

## Storage

The server keeps all data in one storage backend. The default is SQLite in the data directory (`netnoodle.db`); you do not have to configure it. To set it explicitly:

```json
{ "store": { "type": "sqlite", "settings": { "path": "netnoodle.db" } } }
```

The backend is a plug-in (`internal/store`, registry `store.Register`). A new backend (for example PostgreSQL) must pass the contract test suite in `internal/store/storetest`. The suite checks the guarantees that the safety of netnoodle depends on: one open proposal for each device, vulnerability and action; an approval only from the state "pending"; one order for each proposal; results only from the owning actor; single-use join tokens and pairing codes. Concurrent calls are part of the tests.
