# Getting started

Build netnoodle, start the server (directly or with Docker), and try it with demo data.

[← Back to the README](../../README.md)

## Tools that you must have

- Go 1.26 or later. Go downloads the correct toolchain automatically.
- Rust (stable) with `rustfmt` and `clippy`.
- A POSIX shell. On Windows, use Git Bash.

## Procedure: build and test

1. Open a shell in the root directory of the repository.
2. Run the check script:

   ```sh
   sh scripts/check.sh
   ```

3. Make sure that the last line is `ALL CHECKS PASSED`.

The programs are in `bin/` and in `agent/target/debug/`.

## Procedure: start the server

1. Run the server:

   ```sh
   bin/nn-server
   ```

2. On the first start, the server shows the password of the user `admin`. Record this password.
3. Open `https://localhost:7443` in a web browser.
4. Accept the self-signed certificate.
5. Log in as `admin`.

The server keeps its data in the directory `data/`.
The server reads the file `netnoodle.json` if it exists.
Refer to [netnoodle.example.json](../../netnoodle.example.json) for an example.

To set a new password for `admin`, run `bin/nn-server -reset-admin`.

## Procedure: run with Docker

You can run `nn-server` and `nn-scan` in containers.
You must have Docker with Compose.

1. Start the server:

   ```sh
   docker compose up -d --build
   ```

2. Show the log of the server:

   ```sh
   docker compose logs server
   ```

3. Record the password of the user `admin` and the TLS fingerprint. The log shows the password only on the first start.
4. Open `https://localhost:7443` in a web browser and log in.

The server keeps its data in the Docker volume `server-data`.
To configure the server, put `netnoodle.json` in the directory `config/`. The containers read this directory at `/etc/netnoodle`.
File paths in `netnoodle.json`, for example `api_key_file`, must start with `/etc/netnoodle/`.
The containers operate as user ID 65532. This user must be able to read the files in `config/`.

To set a new password for `admin`, run `docker compose run --rm server -reset-admin`.

To start the scanner in a container, do these steps:

1. Make a join token with the role `source` on the **Peers** page.
2. Copy `deploy/nn-scan.example.json` to `config/nn-scan.json`. Change `cidrs`.
3. Enroll the scanner. Use the server URL `https://server:7443`:

   ```sh
   docker compose --profile scan run --rm scan enroll -server https://server:7443 -fingerprint <sha256> -token <join token>
   ```

4. Start the scanner:

   ```sh
   docker compose --profile scan up -d
   ```

> **Note:** In the default Docker network, the scanner cannot read the MAC addresses of the LAN. Thus, the server identifies these devices only by IP address and host name.
> On a Linux host, set `network_mode: host` for the `scan` service in `compose.yaml`. Then use the server URL `https://127.0.0.1:7443` when you enroll.
> Docker Desktop (Windows, macOS) operates containers in a virtual machine. There, the scanner cannot read the MAC addresses of the LAN. Use `bin/nn-scan` on the host.

> **Note:** In Git Bash on Windows, put `MSYS_NO_PATHCONV=1` before `docker compose` commands that have paths such as `/etc/netnoodle/...`.

`nn-agent` and `nn-actor` with the `host` backend do not operate in containers. They read and change the host. Install them on the host.

## Procedure: try netnoodle with demo data

`nn-demo` makes a data directory with an invented network (Proxmox hosts with guests, a DMZ, clients and IoT devices, with findings). Use it to look at the web interface without real data.

1. Make the demo data:

   ```sh
   go run ./cmd/nn-demo -data ./demo-data
   ```

2. Write `demo.json` with `{"data_dir": "./demo-data", "matchers": [], "enrichers": []}`. The empty lists stop the vulnerability downloads, so the invented findings stay.
3. Start the server with `go run ./cmd/nn-server -config demo.json`. Log in with the password that the server shows.

## Certificate fingerprint

The server makes a self-signed TLS certificate on the first start.
The **Overview** page shows the SHA-256 fingerprint of this certificate.
Agents, scanners and actors use this fingerprint to identify the server.
