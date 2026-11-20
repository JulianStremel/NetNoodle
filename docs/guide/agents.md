# Scanner and agents

Collect data: the subnet scanner, the agent on Linux and Windows, the helpers, and pull mode for hosts in a DMZ.

[← Back to the README](../../README.md)

## Procedure: enroll a scanner

1. In the web interface, open **Peers**.
2. Set **Role** to `source` and **Name** to a name for the scanner, for example `scan-lan`.
3. Click **Create join token**.
4. Copy the command that the page shows.
5. On the scanner host, run that command with `bin/nn-scan`.
6. Write the file `nn-scan.json`:

   ```json
   { "cidrs": ["192.168.1.0/24"], "interval": "15m" }
   ```

7. Run `bin/nn-scan run -config nn-scan.json`.
8. Open **Devices** in the web interface.

To test a scan without a server, run `bin/nn-scan scan -cidr 192.168.1.0/24`.

## Procedure: install the agent

`nn-agent` operates on Linux (x86_64, aarch64, armv7). It only reads data. In push mode, it does not listen on a network port. For pull mode, refer to [Procedure: pull mode](#procedure-pull-mode-agent-in-a-dmz).

1. Build the static binaries (Docker is necessary):

   ```sh
   docker build --target agent --output bin/linux .
   ```

2. Copy `bin/linux/nn-agent` to `/usr/local/bin/nn-agent` on the host. Make it executable.
3. Make a user and a data directory:

   ```sh
   useradd --system --no-create-home --shell /usr/sbin/nologin nn-agent
   install -d -o nn-agent -g nn-agent -m 700 /var/lib/nn-agent
   ```

4. In the web interface, open **Peers**. Set **Role** to `agent`. Click **Create join token**.
5. Enroll the agent:

   ```sh
   sudo -u nn-agent nn-agent enroll --server https://<server>:7443 --fingerprint <sha256> --token <join token>
   ```

   The peer name is the host name. To use a different name, add `--name <name>`.
   Give the join token in the environment variable `NN_JOIN_TOKEN`, as the **Peers** page shows. Then other users cannot see the token in the process list.
6. Install the service:

   ```sh
   cp deploy/nn-agent.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now nn-agent
   ```

7. Open **Devices** in the web interface. The host shows its packages and services.

The agent sends a report each hour. To change this, write `/etc/nn-agent/config.json`.
Refer to [deploy/nn-agent.example.json](../../deploy/nn-agent.example.json).

To see the files, sockets and programs that the agent uses, run `nn-agent scope`.
To see a report without sending it, run `nn-agent collect`.

The agent has no root permissions and no capabilities.
For each listening socket, it finds the program and its package:

- For programs of systemd services and containers, the agent needs no permissions. This needs Linux 5.9 or later.
- For other programs of other users, install the optional helper. Do the procedure that follows.

Procedure: install the helper (optional)

1. Copy `bin/linux/nn-agent-helper` to `/usr/local/bin/nn-agent-helper`. Make it executable.
2. Install the units:

   ```sh
   cp deploy/nn-agent-helper.socket deploy/nn-agent-helper@.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now nn-agent-helper.socket
   ```

The helper is a separate program with two capabilities: `CAP_SYS_PTRACE` and `CAP_DAC_READ_SEARCH`.
It has no input. It only gives the programs of listening sockets.
Only members of the group `nn-agent` can connect to it. The agent itself keeps no capabilities.

Procedure: report the packages of containers (optional)

On a host with LXC containers (for example Proxmox VE) or Docker or Podman containers, the agent can report the running containers as children of the host: operating system, packages, listening ports and interfaces. Then the server finds vulnerabilities in the containers, and the **Map** page shows them next to their host.

1. Install the helper program as in the procedure above (step 1).
2. Install the units:

   ```sh
   cp deploy/nn-agent-helper-containers.socket deploy/nn-agent-helper-containers@.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now nn-agent-helper-containers.socket
   ```

The helper uses the same two capabilities. It does not use the Docker socket and it does not start programs in the containers. It reads only these files of each running container: `os-release`, `hostname`, the dpkg or apk package database, and the network tables in `/proc`. It opens them with `openat2` and `RESOLVE_IN_ROOT`, so a link in a container cannot point to a file of the host.

Limits:

- Stopped containers are not read.
- Packages of RPM-based containers are not read (only the operating system).
- Files on another mount than the container's root (for example a volume at `/var`) are not read. A container could use such a mount to point at files of the host.
- Rootless containers (in a user's systemd tree) are not reported.
- MAC addresses come only from the Proxmox configuration (`/etc/pve/lxc/<id>.conf`), never from files in the container. Then a container cannot claim another guest.
- The ports of a container show the program name, but not the package of the program.
- Virtual machines (QEMU) are not read from the host. Install the agent in the virtual machine.

## Procedure: install the agent on Windows

`nn-agent` operates on Windows 10, Windows 11 and Windows Server (x64). It does not need administrator rights to collect data.
You need administrator rights only to install it.

1. Build the program on a Windows computer with Rust: `cd agent` and `cargo build --release -p nn-agent`.
2. In an administrator PowerShell, copy the program and make the data directory:

   ```powershell
   New-Item -ItemType Directory -Force "C:\Program Files\netnoodle", "C:\ProgramData\netnoodle\agent"
   Copy-Item agent\target\release\nn-agent.exe "C:\Program Files\netnoodle\"
   icacls "C:\ProgramData\netnoodle\agent" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "LOCAL SERVICE:(OI)(CI)M"
   ```

3. Make a join token with the role `agent` on the **Peers** page. Enroll:

   ```powershell
   $env:NN_JOIN_TOKEN = "<join token>"
   & "C:\Program Files\netnoodle\nn-agent.exe" enroll --server https://<server>:7443 --fingerprint <sha256>
   Remove-Item Env:NN_JOIN_TOKEN
   ```

4. Make a scheduled task that sends a report each hour as `LOCAL SERVICE`:

   ```powershell
   $a = New-ScheduledTaskAction -Execute "C:\Program Files\netnoodle\nn-agent.exe" -Argument "run --once"
   $t = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1)
   $p = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\LOCAL SERVICE" -LogonType ServiceAccount
   Register-ScheduledTask -TaskName "netnoodle agent" -Action $a -Trigger $t -Principal $p
   ```

The agent reports the Windows version and build, the installed programs, the listening ports with their programs, and the network interfaces.

The server finds vulnerabilities of Windows itself with the `msrc` plug-in (refer to [Vulnerability data](vulnerabilities.md#vulnerability-data)). It does not find vulnerabilities of other installed programs yet.

## Procedure: pull mode (agent in a DMZ)

Use pull mode if the host of the agent must not connect to the server. Example: the server is in the internal zone and the agent is on a reverse proxy in the DMZ. The firewall permits connections from the internal zone to the DMZ only.

In pull mode, the agent listens on one port. It accepts only the pull certificate of the server (mutual TLS). The server connects to the agent and gets the report. Refer to [docs/design/pull-mode.md](../design/pull-mode.md).

1. Install the agent program as in [Procedure: install the agent](#procedure-install-the-agent), steps 1 to 3. Do not enroll the agent.
2. In the web interface, open **Peers**. In **Pull agents**, write the name, the address that the server connects to (`host:port`, for example `10.1.2.3:7444`) and the interval. Click **Add pull agent**.
3. The web interface shows a command. Run it on the host of the agent:

   ```sh
   sudo -u nn-agent NN_PAIR_CODE=<code> nn-agent pair --server-fingerprint <fingerprint> --listen 10.1.2.3:7444
   ```

   The code is valid for 24 hours and only one time. Give the code in the environment variable `NN_PAIR_CODE`, so that other users cannot see it in the process list.
   Add `--allow-from <server address>` (an address or a CIDR network, repeat for more). Then the agent closes all other connections before TLS starts, and other hosts cannot keep the agent busy.
4. Install and start the service:

   ```sh
   cp deploy/nn-agent-serve.service /etc/systemd/system/
   systemctl daemon-reload
   systemctl enable --now nn-agent-serve
   ```

   To permit connections only from the server, add `IPAddressDeny=any` and `IPAddressAllow=<server address>` to the unit.
5. In the firewall, permit TCP from the server to the agent port.
6. Wait one minute. The **Pull agents** table shows **paired**. Then the server pulls a report at each interval. Click **Pull now** to pull a report immediately.

If you install the agent again (new key), click **New pairing code** and do step 3 again.

On Windows, do the same steps with `nn-agent.exe`. Do step 2 of [Procedure: install the agent on Windows](#procedure-install-the-agent-on-windows) first: it restricts the permissions of `C:\ProgramData
etnoodlegent`. The state file `pull.json` in it contains the private key of the agent. Make a scheduled task that starts `nn-agent.exe serve` when the computer starts, and a firewall rule that permits the agent port only from the server address:

```powershell
New-NetFirewallRule -DisplayName "netnoodle agent" -Direction Inbound -Protocol TCP -LocalPort 7444 -RemoteAddress <server address> -Action Allow
```
