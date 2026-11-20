//! `interfaces`: network interfaces, MAC addresses and IP addresses.

use crate::collector::{Access, Collector, Contribution, Ctx};
use nn_proto::Interface;
use std::collections::BTreeMap;
use std::net::IpAddr;

pub struct Interfaces;

/// Interfaces that say nothing about the identity of the host.
fn skip_iface(name: &str) -> bool {
    name == "lo" || name.starts_with("veth") || name.starts_with("fwpr") || name.starts_with("fwln")
}

/// Classify only the supplied name and sysfs evidence; no platform APIs needed.
fn classify_vpn(name: &str, if_type: &str, uevent: &str, has_tun_flags: bool) -> &'static str {
    // Kernel evidence wins over a potentially renamed interface.
    if if_type.trim().parse::<u32>() == Ok(65534)
        && uevent.lines().any(|line| line == "DEVTYPE=wireguard")
    {
        "wireguard"
    } else if name.starts_with("tailscale") {
        "tailscale"
    } else if name.starts_with("wg") {
        "wireguard"
    } else if name.starts_with("zt") {
        "zerotier"
    } else if name.starts_with("tun") || name.starts_with("tap") || has_tun_flags {
        "tun"
    } else {
        ""
    }
}

fn read_vpn(ctx: &Ctx, name: &str) -> &'static str {
    let dir = ctx.path("/sys/class/net").join(name);
    let if_type = std::fs::read_to_string(dir.join("type")).unwrap_or_default();
    let uevent = std::fs::read_to_string(dir.join("uevent")).unwrap_or_default();
    classify_vpn(name, &if_type, &uevent, dir.join("tun_flags").exists())
}

/// Addresses that are the same on many hosts or useless to find the host.
pub fn useful_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => !a.is_loopback() && !a.is_link_local() && !a.is_unspecified(),
        IpAddr::V6(a) => {
            !a.is_loopback() && !a.is_unspecified() && (a.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

/// Reads interface names and MAC addresses from /sys/class/net.
pub fn read_sysfs(ctx: &Ctx) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir(ctx.path("/sys/class/net")) else {
        return m;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if skip_iface(&name) {
            continue;
        }
        let mac = std::fs::read_to_string(e.path().join("address"))
            .map(|s| s.trim().to_lowercase())
            .unwrap_or_default();
        let mac = if mac.is_empty() || mac == "00:00:00:00:00:00" || mac.len() != 17 {
            String::new()
        } else {
            mac
        };
        m.insert(name, mac);
    }
    m
}

#[cfg(target_os = "linux")]
fn live_ips() -> BTreeMap<String, Vec<IpAddr>> {
    let mut m: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
        for a in addrs {
            let Some(sa) = a.address else { continue };
            let ip = if let Some(v4) = sa.as_sockaddr_in() {
                IpAddr::V4(v4.ip())
            } else if let Some(v6) = sa.as_sockaddr_in6() {
                IpAddr::V6(v6.ip())
            } else {
                continue;
            };
            m.entry(a.interface_name).or_default().push(ip);
        }
    }
    m
}

#[cfg(not(target_os = "linux"))]
fn live_ips() -> BTreeMap<String, Vec<IpAddr>> {
    BTreeMap::new()
}

/// Joins MACs and IPs per interface. Interfaces with neither are left out.
pub fn build(macs: BTreeMap<String, String>, ips: BTreeMap<String, Vec<IpAddr>>) -> Vec<Interface> {
    let mut out = Vec::new();
    for (name, mac) in macs {
        let mut list: Vec<String> = ips
            .get(&name)
            .into_iter()
            .flatten()
            .filter(|ip| useful_ip(ip))
            .map(|ip| ip.to_string())
            .collect();
        list.sort();
        list.dedup();
        if mac.is_empty() && list.is_empty() {
            continue;
        }
        out.push(Interface {
            name,
            mac,
            ips: list,
            ..Default::default()
        });
    }
    out
}

impl Collector for Interfaces {
    fn name(&self) -> &'static str {
        "interfaces"
    }

    fn access(&self) -> Access {
        Access {
            reads: vec![
                "/sys/class/net/*/address",
                "/sys/class/net/*/type",
                "/sys/class/net/*/uevent",
                "/sys/class/net/*/tun_flags",
            ],
            sockets: vec!["netlink (getifaddrs, read only)"],
            ..Default::default()
        }
    }

    fn collect(&self, ctx: &Ctx) -> Result<Contribution, String> {
        let macs = read_sysfs(ctx);
        if macs.is_empty() {
            return Err("no interfaces in /sys/class/net".into());
        }
        let ips = if ctx.is_live() {
            live_ips()
        } else {
            BTreeMap::new()
        };
        let mut c = Contribution::default();
        c.host.interfaces = build(macs, ips);
        for interface in &mut c.host.interfaces {
            let vpn = read_vpn(ctx, &interface.name);
            if !vpn.is_empty() {
                interface.kind = "vpn".into();
                interface.vpn = vpn.into();
            }
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_names_and_sysfs_evidence() {
        for (name, expected) in [
            ("tailscale0", "tailscale"),
            ("tailscale-test", "tailscale"),
            ("wg0", "wireguard"),
            ("wg-office", "wireguard"),
            ("ztabc123", "zerotier"),
            ("tun0", "tun"),
            ("tap-office", "tun"),
            ("eth0", ""),
            ("docker0", ""),
            ("br0", ""),
            ("mywg0", ""),
            ("", ""),
        ] {
            assert_eq!(classify_vpn(name, "", "", false), expected, "{name}");
        }
        for (if_type, uevent, expected) in [
            (
                "65534\n",
                "INTERFACE=private0\nDEVTYPE=wireguard\n",
                "wireguard",
            ),
            ("1", "DEVTYPE=wireguard\n", ""),
            ("invalid", "DEVTYPE=wireguard\n", ""),
            ("", "DEVTYPE=wireguard\n", ""),
            ("65534", "", ""),
            ("65534", "DEVTYPE=gre\n", ""),
            ("65534", "OTHER_DEVTYPE=wireguard\n", ""),
            ("65534", "DEVTYPE=wireguard-extra\n", ""),
        ] {
            assert_eq!(classify_vpn("private0", if_type, uevent, false), expected);
        }
        assert_eq!(classify_vpn("private0", "", "", true), "tun");
        for (name, expected) in [
            ("tailscale0", "tailscale"),
            ("wg0", "wireguard"),
            ("zt0", "zerotier"),
        ] {
            assert_eq!(classify_vpn(name, "", "", true), expected);
            assert_eq!(
                classify_vpn(name, "65534", "DEVTYPE=wireguard", true),
                "wireguard"
            );
        }
    }

    #[test]
    fn vpn_sysfs_fixture_marks_host_interfaces() {
        let ctx = super::super::testctx("vpn");
        let interfaces = Interfaces.collect(&ctx).unwrap().host.interfaces;
        assert_eq!(interfaces.len(), 10);
        for (name, expected) in [
            ("tailscale0", "tailscale"),
            ("wg0", "wireguard"),
            ("zt0", "zerotier"),
            ("tun0", "tun"),
            ("tap0", "tun"),
            ("overlay0", "wireguard"),
            ("private0", "tun"),
            ("tailscale9", "wireguard"),
            ("eth0", ""),
            ("other0", ""),
        ] {
            assert_eq!(read_vpn(&ctx, name), expected, "{name}");
            let interface = interfaces.iter().find(|i| i.name == name).unwrap();
            assert_eq!(interface.vpn, expected, "{name}");
            assert_eq!(interface.kind, if expected.is_empty() { "" } else { "vpn" });
            assert_eq!(interface.mac, "02:00:00:00:00:01");
            assert!(interface.ips.is_empty());
        }
        assert_eq!(read_vpn(&ctx, "missing0"), "");
    }

    #[test]
    fn sysfs_and_ips() {
        let ctx = super::super::testctx("debian");
        let macs = read_sysfs(&ctx);
        assert_eq!(macs.keys().collect::<Vec<_>>(), vec!["docker0", "eth0"]);
        let mut ips = BTreeMap::new();
        ips.insert(
            "eth0".to_string(),
            vec![
                "192.168.1.20".parse().unwrap(),
                "fe80::21a:2bff:fe3c:4d5e".parse().unwrap(),
                "2001:db8::20".parse().unwrap(),
            ],
        );
        let ifs = build(macs, ips);
        assert_eq!(ifs[1].name, "eth0");
        assert_eq!(ifs[1].mac, "00:1a:2b:3c:4d:5e");
        assert_eq!(ifs[1].ips, vec!["192.168.1.20", "2001:db8::20"]);
        assert_eq!(ifs[0].ips, Vec::<String>::new());
        assert!(ifs.iter().all(|i| i.kind.is_empty() && i.vpn.is_empty()));
    }

    #[test]
    fn vpn_without_mac_keeps_useful_ips() {
        let interfaces = build(
            BTreeMap::from([
                ("tun0".into(), String::new()),
                ("tap0".into(), String::new()),
            ]),
            BTreeMap::from([(
                "tun0".into(),
                vec![
                    "100.64.1.2".parse().unwrap(),
                    "100.64.1.2".parse().unwrap(),
                    "fd7a:115c:a1e0::1".parse().unwrap(),
                    "127.0.0.1".parse().unwrap(),
                    "fe80::1".parse().unwrap(),
                ],
            )]),
        );
        assert_eq!(interfaces.len(), 1);
        assert_eq!(interfaces[0].name, "tun0");
        assert!(interfaces[0].mac.is_empty());
        assert_eq!(interfaces[0].ips, ["100.64.1.2", "fd7a:115c:a1e0::1"]);
    }
}
