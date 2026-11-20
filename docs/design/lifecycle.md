# Design: install, update, roll back, uninstall

Status: proposal (D-065). User requests: easy deployment, updates of the whole stack, clean recovery when an update fails, and easy uninstall and cleanup.

## 1. Principles

1. **Every installer writes a manifest.** It lists each file, directory, unit, scheduled task, firewall rule, user and nftables table that it made (`/var/lib/<program>/install-manifest.json`, on Windows `C:\ProgramData\netnoodle\<program>\install-manifest.json`). Uninstall removes exactly these items. Nothing is guessed.
2. **Every step is idempotent.** Install, update, rollback and uninstall can run again after an interruption.
3. **Every destructive step has `--dry-run`.** It shows what the step would change.
4. **State machines on disk.** An update or uninstall records its state in a file. After a crash or power loss, the next start continues or rolls back from that state.
5. **The server knows the state of each peer** and shows it in the web interface.

## 2. Versions and compatibility

- Each program reports its version and the protocol version (`v1`). The web interface shows outdated peers.
- The server accepts peers of the current and the previous release.
- An actor with an incompatible version gets no new orders. Reverts are still sent.

## 2a. Release channels: `latest` and `stable`

| Tag (images) / channel | Points to | Moves when |
|---|---|---|
| `vX.Y.Z`, `vX.Y` | one release | never (`vX.Y` follows the newest patch of X.Y) |
| `latest` | the newest release | each release tag `vX.Y.Z` |
| `stable` | the newest **promoted** release | a promotion (below) |
| `edge` (optional) | the newest build of `main` | each push to `main` |

- **Promotion:** a release is first only `latest`. After it ran without a rollback on the canary environments for a waiting time (default 7 days), a manual workflow (`promote vX.Y.Z`) moves `stable` to it: the git branch `stable` is fast-forwarded to the release tag, and the image tag `stable` gets the SAME image digest (no new build, so the promoted bytes are exactly the tested bytes). The release notes mark it as stable.
- A patch release (`vX.Y.Z+1`) with a security fix can be promoted at once (the waiting time is a default, not a rule).
- **Environments follow a channel:** the server has a setting `update.channel` (`stable`, `latest` or `pinned`) and `update.auto` (on/off, with a time window, for example Sunday 03:00–05:00).
  - Server container: an environment on `stable` uses the image tag `stable` and an updater (Watchtower, `podman auto-update`, or a systemd timer that runs `docker compose pull && up -d`) inside the window. The backup before migrations (section 3) makes this safe; a failed start leaves the old container data untouched and the restore command ready.
  - Agents and actors: the server rolls them out to the version that belongs to its own release (agents are in the server image, section 4), so they follow the server's channel automatically, canary first.
  - `pinned` never updates by itself (production environments that want manual control).
- Downgrades never happen through a channel. If `stable` moves back (a bad promotion is withdrawn), environments stay on their version and show a warning.

## 3. Server update (container)

1. `docker compose pull && docker compose up -d`.
2. Before the server applies database migrations, it copies the database to `data/backups/netnoodle-<old version>-<time>.db` (the last 3 copies are kept, and the free disk space is checked first).
3. A migration runs in one transaction. If it fails, the server stops and does not start with a half-migrated database.
4. A database that is newer than the program (downgrade) is refused.
5. Recovery: `nn-server restore --latest` (or `--file`) puts a backup back.

## 4. Agent and actor update (self-update, controlled by the server)

Signatures: each binary has two signatures — the upstream release signature (CI, Sigstore or an offline release key) and the signature of the local server at download time. A peer installs only a binary that has both. A compromised server can thus not distribute its own code.

States in `/var/lib/<program>/update-state.json`:

```
idle → downloading → staged → swapped → healthy → idle
                 ↘ failed ↙        ↘ rolled-back ↗
```

1. **Downloading:** the peer checks the free disk space (at least 3 × the binary size), downloads to `staging/`, and checks size, SHA-256 and both signatures. Any error: delete `staging/`, state `failed`, report the reason.
2. **Staged → swapped:** a root updater (Linux: oneshot unit started by a systemd path unit; Windows: scheduled task as SYSTEM) checks the signatures again, keeps the current binaries as `*.prev`, puts the new ones in place with an atomic rename, and restarts the services.
3. **Healthy:** the new peer reports to the server within 10 minutes (actors: a successful long poll). Then the updater deletes `*.prev` and `staging/` after the next 3 good reports.
4. **Rollback:** no report within 10 minutes, a crash loop (3 restarts in 5 minutes), or a failed start makes the updater put `*.prev` back and restart. State `rolled-back`, reason sent to the server.
5. **Resume after an interruption:** at each start the updater reads the state file. `downloading`/`staged` → delete staging, `idle`. `swapped` without `healthy` → rollback. Thus no half-finished update stays.
6. **Actors** finish their open orders first (drain) and take no new orders during the swap.
7. **Rollout:** peers with the tag `canary` first. If one of them rolls back, the server stops the rollout and shows the reason.

## 5. Uninstall and cleanup

### 5.1 Agent

`nn-agent uninstall [--purge] [--dry-run]` (root or administrator):

1. Tells the server that the peer leaves (the server disables the token).
2. Stops and disables the services and sockets (agent, serve, helper, helper-containers, updater; Windows: scheduled tasks, firewall rule).
3. Removes the files in the manifest. `--purge` also removes configuration, state, keys, credentials and the user `nn-agent`.
4. Removes the manifest last. A second run finds nothing to do.

### 5.2 Actor

`nn-actor uninstall [--keep-actions] [--purge] [--dry-run]`:

1. Stops taking orders.
2. **Reverts everything it did**, from its journal: unblocks UniFi clients, enables guest network links, removes its nftables table `inet netnoodle`, starts stopped services. `--keep-actions` keeps them (for example while a device is still compromised); the command then lists what stays.
3. Reports the result to the server, then continues as for the agent.

### 5.3 Server side: decommission a peer

"Decommission" on the Peers page:

- disables the token or the pull pairing, deletes its join tokens;
- for an actor: shows its active actions and offers to revert them first (default) or to keep them;
- optional: deletes the devices that only this peer reported (default: keep them as history, marked "no source").

### 5.4 Server

- Export first: `nn-server export` writes the database and the keys to one archive.
- `docker compose down` stops; `docker compose down -v` also deletes the data volume.
- The README lists every place where netnoodle keeps data.

## 6. Order of work

1. Versions everywhere; outdated peers in the web interface.
2. Database backup before migrations, downgrade guard, `restore`, `export`.
3. Install manifests and `uninstall` for agent and actor (with revert of actor actions); decommission on the Peers page.
4. Release workflow with upstream signatures.
5. Agents in the server image, download with local signature, install one-liner.
6. Updater with state machine, rollback, canary rollout, actor drain.
