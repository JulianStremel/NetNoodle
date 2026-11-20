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

Server in Docker: `docker compose pull && docker compose up -d`. Updates from the web interface, with automatic backup and rollback, are planned (refer to [docs/design/lifecycle.md](../design/lifecycle.md)).

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
