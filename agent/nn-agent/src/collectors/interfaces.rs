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
            reads: vec!["/sys/class/net/*/address"],
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
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
