//! Finds the program that owns a listening socket, with the least privilege
//! possible. Three ways, tried in this order:
//!
//! 1. `/proc/<pid>/fd` links. Complete as root; otherwise only the agent's
//!    own processes.
//! 2. The optional helper service (`nn-agent-helper`). It holds the two
//!    capabilities for step 1 and returns only the owners of listening
//!    sockets. The agent itself stays without privileges.
//! 3. Without privileges: netlink `sock_diag` gives the cgroup of each
//!    socket (kernel 5.9+, cgroup v2). The cgroup names a systemd unit or a
//!    container; `systemctl show` gives the program of the unit.

use crate::collector::Ctx;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::collections::HashMap;

/// The program that owns a socket.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owner {
    pub inode: u64,
    pub pid: u32,
    /// Process name (`/proc/<pid>/comm`).
    pub comm: String,
    /// Executable path; "" if unknown.
    pub exe: String,
}

fn read_comm(ctx: &Ctx, pid: u32) -> String {
    std::fs::read_to_string(ctx.path(&format!("/proc/{pid}/comm")))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Builds the owner record of one process from /proc.
pub fn owner_of_pid(ctx: &Ctx, inode: u64, pid: u32) -> Owner {
    let exe = std::fs::read_link(ctx.path(&format!("/proc/{pid}/exe")))
        .map(|p| {
            p.to_string_lossy()
                .trim_end_matches(" (deleted)")
                .to_string()
        })
        .unwrap_or_default();
    Owner {
        inode,
        pid,
        comm: read_comm(ctx, pid),
        exe,
    }
}

/// Step 1: maps socket inodes to process IDs through /proc/<pid>/fd links.
/// Processes that the caller may not inspect are skipped.
pub fn fd_owners(ctx: &Ctx) -> HashMap<u64, u32> {
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

/// Step 2: asks the helper service on its Unix socket. The helper reads no input.
#[cfg(unix)]
pub fn from_helper(path: &std::path::Path) -> Result<Vec<Owner>, String> {
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    let s = UnixStream::connect(path).map_err(|e| format!("{}: {e}", path.display()))?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;
    let _ = s.shutdown(std::net::Shutdown::Write);
    let mut buf = Vec::new();
    s.take(8 << 20)
        .read_to_end(&mut buf)
        .map_err(|e| format!("helper: {e}"))?;
    serde_json::from_slice(&buf).map_err(|e| format!("helper answer: {e}"))
}

#[cfg(not(unix))]
pub fn from_helper(_path: &std::path::Path) -> Result<Vec<Owner>, String> {
    Err("the helper needs a Unix system".into())
}

// --- step 3: sock_diag + cgroup + systemd ---

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const INET_DIAG_CGROUP_ID: u16 = 21;
/// TCP state LISTEN.
pub const STATES_TCP_LISTEN: u32 = 1 << 10;
/// Unconnected UDP sockets are in state CLOSE.
pub const STATES_UDP_UNCONNECTED: u32 = 1 << 7;

/// Builds one sock_diag dump request: nlmsghdr + inet_diag_req_v2.
pub fn diag_request(family: u8, protocol: u8, states: u32, seq: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(72);
    b.extend_from_slice(&72u32.to_ne_bytes());
    b.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    b.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    b.extend_from_slice(&seq.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes());
    b.extend_from_slice(&[family, protocol, 0, 0]);
    b.extend_from_slice(&states.to_ne_bytes());
    b.extend_from_slice(&[0u8; 48]); // inet_diag_sockid: match all
    b
}

fn ne_u16(b: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([b[at], b[at + 1]])
}
fn ne_u32(b: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(b[at..at + 4].try_into().unwrap())
}

/// Parses a buffer of sock_diag answers and adds inode -> cgroup ID.
/// Returns true when the dump is complete.
pub fn diag_parse(buf: &[u8], out: &mut HashMap<u64, u64>) -> Result<bool, String> {
    let mut off = 0;
    while off + 16 <= buf.len() {
        let len = ne_u32(buf, off) as usize;
        let ty = ne_u16(buf, off + 4);
        if len < 16 || off + len > buf.len() {
            return Err("bad netlink message".into());
        }
        let msg = &buf[off + 16..off + len];
        match ty {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => {
                let code = if msg.len() >= 4 {
                    -(ne_u32(msg, 0) as i32)
                } else {
                    0
                };
                return Err(format!("sock_diag: error {code}"));
            }
            SOCK_DIAG_BY_FAMILY if msg.len() >= 72 => {
                // inet_diag_msg: 4 bytes, sockid 48, expires, rqueue, wqueue, uid, inode.
                let inode = ne_u32(msg, 68) as u64;
                let mut a = 72;
                while a + 4 <= msg.len() {
                    let alen = ne_u16(msg, a) as usize;
                    let aty = ne_u16(msg, a + 2) & 0x3fff;
                    if alen < 4 || a + alen > msg.len() {
                        break;
                    }
                    if aty == INET_DIAG_CGROUP_ID && alen >= 12 {
                        let cg = u64::from_ne_bytes(msg[a + 4..a + 12].try_into().unwrap());
                        out.insert(inode, cg);
                    }
                    a += (alen + 3) & !3;
                }
            }
            _ => {}
        }
        off += (len + 3) & !3;
    }
    Ok(false)
}

/// The system service unit in a cgroup path, e.g. "system.slice/nginx.service".
/// Only units of the system manager count: a user could name a unit of
/// their own user manager like a system unit, and `systemctl show` would
/// then describe the system unit.
pub fn unit_of(cgroup: &str) -> Option<&str> {
    let parts: Vec<&str> = cgroup.split('/').collect();
    let start = parts.iter().position(|c| *c == "system.slice")?;
    if parts
        .iter()
        .any(|c| c.starts_with("user@") || *c == "user.slice")
    {
        return None;
    }
    parts[start + 1..]
        .iter()
        .rev()
        .find(|c| c.ends_with(".service"))
        .copied()
}

/// The container ID (12 characters) in a cgroup path of Docker, Podman or containerd.
pub fn container_of(cgroup: &str) -> Option<String> {
    let parts: Vec<&str> = cgroup.split('/').collect();
    for (i, c) in parts.iter().enumerate() {
        let id = if let Some(rest) = c.strip_suffix(".scope") {
            ["docker-", "libpod-", "cri-containerd-", "crio-"]
                .iter()
                .find_map(|p| rest.strip_prefix(p))
        } else if *c == "docker" || *c == "libpod_parent" {
            parts.get(i + 1).copied()
        } else {
            None
        };
        if let Some(id) = id {
            if id.len() >= 12 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Some(id[..12].to_string());
            }
        }
    }
    None
}

/// Unit data from `systemctl show --property=Id,MainPID,ExecStart`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UnitInfo {
    pub main_pid: u32,
    pub exe: String,
}

/// Parses `systemctl show` output for one or more units (blank-line separated).
pub fn parse_show(s: &str) -> HashMap<String, UnitInfo> {
    let mut out = HashMap::new();
    let s = s.replace("\r\n", "\n");
    for block in s.split("\n\n") {
        let (mut id, mut info) = (String::new(), UnitInfo::default());
        for line in block.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            match k {
                "Id" => id = v.to_string(),
                "MainPID" => info.main_pid = v.parse().unwrap_or(0),
                "ExecStart" if info.exe.is_empty() => {
                    if let Some(rest) = v.split_once("path=").map(|x| x.1) {
                        info.exe = rest.split(" ;").next().unwrap_or("").trim().to_string();
                    }
                }
                _ => {}
            }
        }
        if !id.is_empty() {
            out.insert(id, info);
        }
    }
    out
}

/// The cgroup v2 mount: `/sys/fs/cgroup` (unified) or `/sys/fs/cgroup/unified` (hybrid).
pub fn cgroup2_root(ctx: &Ctx) -> Option<std::path::PathBuf> {
    ["/sys/fs/cgroup", "/sys/fs/cgroup/unified"]
        .iter()
        .map(|p| ctx.path(p))
        .find(|p| p.join("cgroup.controllers").exists())
}

/// The first process in a cgroup.
pub fn first_pid(root: &std::path::Path, cgroup: &str) -> u32 {
    std::fs::read_to_string(root.join(cgroup).join("cgroup.procs"))
        .ok()
        .and_then(|s| s.lines().next().and_then(|l| l.trim().parse().ok()))
        .unwrap_or(0)
}

/// Step 3 for the given socket inodes. Needs Linux, a cgroup v2 mount and kernel 5.9+.
#[cfg(target_os = "linux")]
pub fn by_cgroup(ctx: &Ctx, inodes: &[u64]) -> Result<HashMap<u64, Owner>, String> {
    let mut out = HashMap::new();
    let root = cgroup2_root(ctx).ok_or("no cgroup v2 mount")?;
    let cg_of = linux::diag_cgroup_ids()?;
    let want: BTreeSet<u64> = inodes
        .iter()
        .filter_map(|i| cg_of.get(i).copied())
        .collect();
    if want.is_empty() {
        return Ok(out);
    }
    let paths = linux::cgroup_paths(&root, &want);
    let units: BTreeSet<&str> = paths.values().filter_map(|p| unit_of(p)).collect();
    let info = if units.is_empty() {
        HashMap::new()
    } else {
        linux::systemctl_show(&units)?
    };
    for &inode in inodes {
        let Some(path) = cg_of.get(&inode).and_then(|cg| paths.get(cg)) else {
            continue;
        };
        if let Some(u) = unit_of(path).and_then(|u| info.get(u)) {
            let pid = if u.main_pid != 0 {
                u.main_pid
            } else {
                first_pid(&root, path)
            };
            out.insert(
                inode,
                Owner {
                    inode,
                    pid,
                    comm: read_comm(ctx, pid),
                    exe: u.exe.clone(),
                },
            );
        } else if let Some(id) = container_of(path) {
            // The cgroup tells the container, not which of its processes
            // owns the socket. Do not guess a process.
            out.insert(
                inode,
                Owner {
                    inode,
                    pid: 0,
                    comm: format!("container {id}"),
                    exe: String::new(),
                },
            );
        }
    }
    Ok(out)
}

#[cfg(not(target_os = "linux"))]
pub fn by_cgroup(_ctx: &Ctx, _inodes: &[u64]) -> Result<HashMap<u64, Owner>, String> {
    Err("needs Linux".into())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    /// Dumps listening TCP and unconnected UDP sockets (IPv4 and IPv6) and
    /// returns inode -> cgroup ID. Needs no privileges.
    pub fn diag_cgroup_ids() -> Result<HashMap<u64, u64>, String> {
        let err = |what: &str| format!("sock_diag {what}: {}", std::io::Error::last_os_error());
        // SAFETY: plain socket(2) call; the result is checked and owned below.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_SOCK_DIAG,
            )
        };
        if fd < 0 {
            return Err(err("socket"));
        }
        // SAFETY: fd is a new, valid descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        // SAFETY: tv lives for the call; size matches the type.
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
        let mut out = HashMap::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut seq = 1;
        for family in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
            for (proto, states) in [
                (libc::IPPROTO_TCP as u8, STATES_TCP_LISTEN),
                (libc::IPPROTO_UDP as u8, STATES_UDP_UNCONNECTED),
            ] {
                let req = diag_request(family, proto, states, seq);
                seq += 1;
                // SAFETY: zeroed sockaddr_nl is valid; family set below.
                let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
                sa.nl_family = libc::AF_NETLINK as u16;
                // SAFETY: req and sa outlive the call; lengths are correct.
                let n = unsafe {
                    libc::sendto(
                        fd.as_raw_fd(),
                        req.as_ptr() as *const libc::c_void,
                        req.len(),
                        0,
                        &sa as *const _ as *const libc::sockaddr,
                        std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                    )
                };
                if n < 0 {
                    return Err(err("send"));
                }
                loop {
                    // SAFETY: buf is valid for buf.len() bytes.
                    let n = unsafe {
                        libc::recv(
                            fd.as_raw_fd(),
                            buf.as_mut_ptr() as *mut libc::c_void,
                            buf.len(),
                            0,
                        )
                    };
                    if n < 0 {
                        return Err(err("recv"));
                    }
                    if n == 0 || diag_parse(&buf[..n as usize], &mut out)? {
                        break;
                    }
                }
            }
        }
        Ok(out)
    }

    /// Finds cgroup v2 directories by ID (the directory inode is the cgroup ID).
    /// Returns ID -> path relative to the cgroup root ("" for the root).
    pub fn cgroup_paths(root: &Path, want: &BTreeSet<u64>) -> HashMap<u64, String> {
        let mut out = HashMap::new();
        let mut stack = vec![(root.to_path_buf(), String::new(), 0usize)];
        while let Some((dir, rel, depth)) = stack.pop() {
            if let Ok(md) = std::fs::metadata(&dir) {
                if want.contains(&md.ino()) {
                    out.insert(md.ino(), rel.clone());
                    if out.len() == want.len() {
                        break;
                    }
                }
            }
            if depth >= 12 {
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for e in rd.flatten() {
                    if e.file_type().is_ok_and(|t| t.is_dir()) {
                        let name = e.file_name().to_string_lossy().to_string();
                        let r = if rel.is_empty() {
                            name
                        } else {
                            format!("{rel}/{name}")
                        };
                        stack.push((e.path(), r, depth + 1));
                    }
                }
            }
        }
        out
    }

    /// Runs `systemctl show` (read-only) for the units.
    pub fn systemctl_show(units: &BTreeSet<&str>) -> Result<HashMap<String, UnitInfo>, String> {
        let out = std::process::Command::new("systemctl")
            .args(["show", "--property=Id,MainPID,ExecStart", "--"])
            .args(units)
            .output()
            .map_err(|e| format!("run systemctl: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "systemctl show: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(parse_show(&String::from_utf8_lossy(&out.stdout)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_names() {
        assert_eq!(unit_of("system.slice/nginx.service"), Some("nginx.service"));
        assert_eq!(
            unit_of("user.slice/user-1000.slice/user@1000.service/app.slice/sshd.service"),
            None
        );
        assert_eq!(
            unit_of("docker/2869f5f821df/system.slice/nginx.service"),
            Some("nginx.service")
        );
        assert_eq!(unit_of("user.slice/user-1000.slice/session-3.scope"), None);
        let id = "4f9c2a1b3d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8";
        assert_eq!(
            container_of(&format!("system.slice/docker-{id}.scope")),
            Some("4f9c2a1b3d5e".into())
        );
        assert_eq!(
            container_of(&format!("docker/{id}")),
            Some("4f9c2a1b3d5e".into())
        );
        assert_eq!(container_of("system.slice/docker.service"), None);
    }

    #[test]
    fn systemctl_show_output() {
        let s = "MainPID=812\nExecStart={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; master_process on; ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\nId=nginx.service\n\nMainPID=0\nId=gone.service\n";
        let m = parse_show(s);
        assert_eq!(
            m["nginx.service"],
            UnitInfo {
                main_pid: 812,
                exe: "/usr/sbin/nginx".into()
            }
        );
        assert_eq!(m["gone.service"].exe, "");
    }

    #[test]
    fn sock_diag_messages() {
        let req = diag_request(2, 6, STATES_TCP_LISTEN, 7);
        assert_eq!(req.len(), 72);
        assert_eq!(ne_u32(&req, 0), 72);

        // One answer with inode 4242 and cgroup ID 99, then DONE.
        let mut msg = vec![0u8; 72];
        msg[68..72].copy_from_slice(&4242u32.to_ne_bytes());
        msg.extend_from_slice(&4u16.to_ne_bytes()); // empty attribute (padding test)
        msg.extend_from_slice(&5u16.to_ne_bytes());
        msg.extend_from_slice(&12u16.to_ne_bytes());
        msg.extend_from_slice(&INET_DIAG_CGROUP_ID.to_ne_bytes());
        msg.extend_from_slice(&99u64.to_ne_bytes());
        let mut buf = Vec::new();
        buf.extend_from_slice(&((16 + msg.len()) as u32).to_ne_bytes());
        buf.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        buf.extend_from_slice(&[0u8; 10]);
        buf.extend_from_slice(&msg);
        buf.extend_from_slice(&20u32.to_ne_bytes());
        buf.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        buf.extend_from_slice(&[0u8; 14]);
        let mut out = HashMap::new();
        assert!(diag_parse(&buf, &mut out).unwrap());
        assert_eq!(out.get(&4242), Some(&99));
    }
}
