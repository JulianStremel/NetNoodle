# Vulnerabilities and risk

Where the vulnerability data comes from and how netnoodle rates risk.

[← Back to the README](../../README.md)

## Vulnerability data

The server compares the packages from the agents with vulnerability data:

| Plug-in | Type | Data | Source |
|---|---|---|---|
| `osv` | Matcher | Vulnerabilities of Debian, Ubuntu, Alpine, Rocky Linux and AlmaLinux packages | `api.osv.dev` |
| `msrc` | Matcher | Vulnerabilities of Windows (by build number), from the monthly security updates | Microsoft Security Response Center (`api.msrc.microsoft.com`) |
| `kev` | Enricher | Vulnerabilities that attackers use (Known Exploited Vulnerabilities) | CISA |
| `epss` | Enricher | Probability of exploitation in the next 30 days | FIRST EPSS |

The server sends only package names, versions and the distribution release to OSV. It sends no host names and no addresses.
The `msrc` plug-in sends nothing about your devices. It downloads the security update documents of the last 24 months when a Windows device is first reported.
The server downloads the KEV and EPSS lists each day. Then it compares all devices again.

To use other plug-ins or to stop the downloads, set `matchers` and `enrichers` in `netnoodle.json`. An empty list disables the plug-ins:

```json
{ "matchers": [], "enrichers": [] }
```

The **Findings** page shows the most urgent findings first:

1. Vulnerabilities that attackers use (KEV).
2. Vulnerabilities in a package that has a listening network service on the device.
3. The CVSS score, then the EPSS probability.

When a new report shows a fixed version, the server closes the finding.

## Reachability

The server gives each device and each listening service one of three levels (refer to [docs/design/reachability.md](../design/reachability.md)):

| Level | Evidence |
|---|---|
| `internet` | A public address on an interface of the device |
| `tunnel` | A VPN interface (Tailscale, WireGuard, ZeroTier, tun) that the agent reports, a tailnet address, or a network behind a Tailscale subnet router |
| `local` | All other devices |

A service that listens on `0.0.0.0` or `::` has the level of the device. A service on `127.0.0.1` or `::1` is not reachable. The device page shows the level and the evidence.

## Risk

The risk of a device (0 to 10) comes from its worst open finding: 70 % of the CVSS score, plus 2 if attackers use the vulnerability (KEV), plus the EPSS probability, plus 1 (local), 1.5 (tunnel) or 2 (internet) if the package has a listening service at that level.
