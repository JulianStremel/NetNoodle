//! `sockets`: listening TCP and UDP sockets, with the program that owns each.
//!
//! The socket tables in /proc/net are readable by every user. The owning
//! program is found as described in [`super::sockowner`].

use super::sockowner::{self, Owner};
use crate::collector::{Access, Collector, Contribution, Ctx};
use nn_proto::{Confidence, Service};
use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

pub struct Sockets;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sock {
    pub proto: &'static str,
    pub addr: String,
    pub port: u16,
    pub inode: u64,
}

/// Decodes a /proc/net address like "0100007F:0050" or a 32-digit IPv6 form.
/// The address words are in host byte order (little-endian on x86 and ARM).
pub fn parse_addr(s: &str) -> Option<(String, u16)> {
    let (a, p) = s.split_once(':')?;
    let port = u16::from_str_radix(p, 16).ok()?;
    let ip = match a.len() {
        8 => Ipv4Addr::from(u32::from_str_radix(a, 16).ok()?.to_le_bytes()).to_string(),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&a[i * 8..i * 8 + 8], 16).ok()?;
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            let v6 = Ipv6Addr::from(b);
            match v6.to_ipv4_mapped() {
                Some(v4) => v4.to_string(),
                None => v6.to_string(),
            }
        }
        _ => return None,
    };
    Some((ip, port))
}

/// Parses one /proc/net/{tcp,tcp6,udp,udp6} table and keeps listening sockets.
pub fn parse_table(s: &str, proto: &'static str) -> Vec<Sock> {
    let mut out = Vec::new();
    for line in s.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let listening = match proto {
            "tcp" => f[3] == "0A",
            // An unconnected UDP socket has state 07 and remote port 0.
            _ => f[3] == "07" && f[2].ends_with(":0000"),
        };
        if !listening {
            continue;
        }
        let (Some((addr, port)), Ok(inode)) = (parse_addr(f[1]), f[9].parse()) else {
            continue;
        };
        out.push(Sock {
            proto,
            addr,
            port,
            inode,
        });
    }
    out
}

/// How widely a socket is reachable: any address > one address > loopback.
fn exposure(addr: &str) -> u8 {
    match addr {
        "0.0.0.0" | "::" => 3,
        a if a.starts_with("127.") || a == "::1" => 1,
        _ => 2,
    }
}

/// The ephemeral port range; UDP sockets in it are clients, not services.
pub fn ephemeral(ctx: &Ctx) -> (u16, u16) {
    std::fs::read_to_string(ctx.path("/proc/sys/net/ipv4/ip_local_port_range"))
        .ok()
        .and_then(|s| {
            let mut it = s.split_whitespace().map(|v| v.parse::<u16>());
            Some((it.next()?.ok()?, it.next()?.ok()?))
        })
        .unwrap_or((32768, 60999))
}

/// One entry per (proto, port): the most exposed address wins.
pub fn dedupe(socks: Vec<Sock>, eph: (u16, u16)) -> Vec<Sock> {
    let mut best: BTreeMap<(&'static str, u16), Sock> = BTreeMap::new();
    for s in socks {
        if s.proto == "udp" && s.port >= eph.0 && s.port <= eph.1 {
            continue;
        }
        let key = (s.proto, s.port);
        if best
            .get(&key)
            .is_none_or(|b| exposure(&s.addr) > exposure(&b.addr))
        {
            best.insert(key, s);
        }
    }
    best.into_values().collect()
}

/// All listening sockets from the /proc/net tables (before deduplication).
pub fn listening(ctx: &Ctx) -> Result<Vec<Sock>, String> {
    let mut socks = Vec::new();
    let mut read_any = false;
    for (file, proto) in [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp"),
    ] {
        if let Ok(s) = std::fs::read_to_string(ctx.path(file)) {
            read_any = true;
            socks.extend(parse_table(&s, proto));
        }
    }
    if read_any {
        Ok(socks)
    } else {
        Err("no socket tables in /proc/net".into())
    }
}

/// Finds the owners of the given socket inodes with the least privilege
/// that works. Notes on failed steps go to `notes`.
fn owners(ctx: &Ctx, inodes: &[u64], notes: &mut Vec<String>) -> HashMap<u64, Owner> {
    let mut out: HashMap<u64, Owner> = HashMap::new();
    let fd = sockowner::fd_owners(ctx);
    for &i in inodes {
        if let Some(&pid) = fd.get(&i) {
            out.insert(i, sockowner::owner_of_pid(ctx, i, pid));
        }
    }
    let missing = |out: &HashMap<u64, Owner>| -> Vec<u64> {
        inodes
            .iter()
            .copied()
            .filter(|i| !out.contains_key(i))
            .collect()
    };
    if !ctx.is_live() || missing(&out).is_empty() {
        return out;
    }
    if let Some(h) = ctx.helper.as_ref().filter(|h| h.exists()) {
        match sockowner::from_helper(h) {
            Ok(list) => {
                for o in list {
                    if inodes.contains(&o.inode) {
                        out.entry(o.inode).or_insert(o);
                    }
                }
            }
            Err(e) => notes.push(e),
        }
    }
    let rest = missing(&out);
    if !rest.is_empty() {
        match sockowner::by_cgroup(ctx, &rest) {
            Ok(m) => {
                for (k, v) in m {
                    out.entry(k).or_insert(v);
                }
            }
            Err(e) => notes.push(e),
        }
    }
    out
}

impl Collector for Sockets {
    fn name(&self) -> &'static str {
        "sockets"
    }

    fn access(&self) -> Access {
        Access {
            reads: vec![
                "/proc/net/tcp",
                "/proc/net/tcp6",
                "/proc/net/udp",
                "/proc/net/udp6",
                "/proc/sys/net/ipv4/ip_local_port_range",
                "/proc/<pid>/fd/ (own processes)",
                "/proc/<pid>/comm",
                "/proc/<pid>/exe (own processes)",
                "/sys/fs/cgroup/ (directory names, cgroup.procs)",
            ],
            sockets: vec![
                "netlink sock_diag (listening sockets, read only)",
                "/run/nn-agent-helper.sock (optional helper)",
            ],
            execs: vec!["systemctl show"],
            privileged: "programs of other users that run outside a systemd service or container (install nn-agent-helper)",
        }
    }

    fn collect(&self, ctx: &Ctx) -> Result<Contribution, String> {
        let socks = dedupe(listening(ctx)?, ephemeral(ctx));
        let inodes: Vec<u64> = socks.iter().map(|s| s.inode).collect();
        let mut notes = Vec::new();
        let owners = owners(ctx, &inodes, &mut notes);
        let mut c = Contribution::default();
        let mut unknown = 0;
        for s in socks {
            let o = owners.get(&s.inode);
            if o.is_none() {
                unknown += 1;
            }
            c.host.services.push(Service {
                port: s.port,
                proto: s.proto.into(),
                address: s.addr,
                process: o.map(|o| o.comm.clone()).unwrap_or_default(),
                confidence: Some(Confidence::High),
                ..Default::default()
            });
            c.service_exes
                .push(o.map(|o| o.exe.clone()).unwrap_or_default());
        }
        if unknown > 0 {
            c.host
                .attributes
                .insert("sockets.unknown_owner".into(), unknown.to_string());
        }
        if !notes.is_empty() {
            c.host
                .attributes
                .insert("sockets.notes".into(), notes.join("; "));
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(parse_addr("0100007F:0050"), Some(("127.0.0.1".into(), 80)));
        assert_eq!(parse_addr("00000000:0016"), Some(("0.0.0.0".into(), 22)));
        assert_eq!(
            parse_addr("00000000000000000000000000000000:01BB"),
            Some(("::".into(), 443))
        );
        assert_eq!(
            parse_addr("00000000000000000000000001000000:0019"),
            Some(("::1".into(), 25))
        );
    }

    #[test]
    fn listening_sockets_from_fixture() {
        let ctx = super::super::testctx("debian");
        let c = Sockets.collect(&ctx).unwrap();
        let got: Vec<_> = c
            .host
            .services
            .iter()
            .map(|s| format!("{}/{} {}", s.port, s.proto, s.address))
            .collect();
        // 22 on v4 and v6 -> one entry; 25 loopback only; 80 on v6 any;
        // UDP: 123 kept, 41000 (ephemeral) dropped; TCP ESTABLISHED dropped.
        assert_eq!(
            got,
            vec![
                "22/tcp 0.0.0.0",
                "25/tcp 127.0.0.1",
                "80/tcp ::",
                "123/udp 0.0.0.0"
            ]
        );
        assert_eq!(c.service_exes.len(), got.len());
    }
}
