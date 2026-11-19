//! `sockets`: listening TCP and UDP sockets, with the program that owns each.
//!
//! The socket tables in /proc/net are readable by every user. The owning
//! process is found through /proc/<pid>/fd, which an unprivileged user can
//! read only for its own processes.

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

/// Maps socket inodes to process IDs through /proc/<pid>/fd links.
fn inode_owners(ctx: &Ctx) -> HashMap<u64, u32> {
    let mut m = HashMap::new();
    let Ok(rd) = std::fs::read_dir(ctx.path("/proc")) else {
        return m;
    };
    for e in rd.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(e.path().join("fd")) else {
            continue; // other users' processes: permission denied
        };
        for fd in fds.flatten() {
            if let Ok(t) = std::fs::read_link(fd.path()) {
                let t = t.to_string_lossy();
                if let Some(n) = t.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) {
                    if let Ok(n) = n.parse() {
                        m.entry(n).or_insert(pid);
                    }
                }
            }
        }
    }
    m
}

/// The ephemeral port range; UDP sockets in it are clients, not services.
fn ephemeral(ctx: &Ctx) -> (u16, u16) {
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
                "/proc/<pid>/fd/",
                "/proc/<pid>/comm",
                "/proc/<pid>/exe",
            ],
            privileged: "program names of sockets owned by other users (needs root or CAP_SYS_PTRACE + CAP_DAC_READ_SEARCH)",
            ..Default::default()
        }
    }

    fn collect(&self, ctx: &Ctx) -> Result<Contribution, String> {
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
        if !read_any {
            return Err("no socket tables in /proc/net".into());
        }
        let socks = dedupe(socks, ephemeral(ctx));
        let owners = inode_owners(ctx);
        let mut c = Contribution::default();
        for s in socks {
            let mut svc = Service {
                port: s.port,
                proto: s.proto.into(),
                address: s.addr,
                confidence: Some(Confidence::High),
                ..Default::default()
            };
            let mut exe = String::new();
            if let Some(pid) = owners.get(&s.inode) {
                let base = format!("/proc/{pid}");
                svc.process = std::fs::read_to_string(ctx.path(&format!("{base}/comm")))
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                if let Ok(p) = std::fs::read_link(ctx.path(&format!("{base}/exe"))) {
                    exe = p
                        .to_string_lossy()
                        .trim_end_matches(" (deleted)")
                        .to_string();
                }
            }
            c.host.services.push(svc);
            c.service_exes.push(exe);
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
