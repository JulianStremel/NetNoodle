//! Running LXC, Docker and Podman containers, via the optional privileged helper.
//! Kubernetes (cri-containerd/crio) cgroups are deliberately not collected.

use super::{apk, dpkg, sockowner, util};
use nn_proto::{Component, Confidence, Entity, EntityKind, Identifier, Interface, Service};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

const MAX_CONTAINERS: usize = 1000;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ContainerReport {
    pub id: String,
    pub name: String,
    pub attributes: BTreeMap<String, String>,
    pub components: Vec<Component>,
    pub services: Vec<Service>,
    pub interfaces: Vec<Interface>,
    pub errors: Vec<String>,
}

fn valid_id(id: &str) -> bool {
    let Some((runtime, name)) = id.split_once('/') else {
        return false;
    };
    !runtime.is_empty()
        && runtime.len() <= 16
        && runtime.as_bytes()[0].is_ascii_lowercase()
        && runtime
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.is_empty()
        && name.len() <= 128
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

/// Parse the path part, preserving colons in cgroup names (v1 and v2).
fn container_id(cgroups: &str) -> Option<String> {
    for line in cgroups.lines() {
        let Some(path) = line.splitn(3, ':').nth(2) else {
            continue;
        };
        let parts: Vec<_> = path.split('/').collect();
        if parts
            .iter()
            .any(|p| *p == "lxc.monitor" || p.starts_with("lxc.monitor."))
        {
            continue;
        }
        for (i, part) in parts.iter().enumerate() {
            let lxc = if *part == "lxc" || *part == "lxc.payload" {
                parts.get(i + 1).copied()
            } else {
                part.strip_prefix("lxc.payload.")
            };
            let id = if let Some(name) = lxc {
                Some(format!("lxc/{name}"))
            } else {
                // Reuse sockowner's ID validation/truncation, but only for these runtimes.
                let runtime = if part.starts_with("docker-") && part.ends_with(".scope")
                    || *part == "docker"
                {
                    "docker"
                } else if part.starts_with("libpod-") && part.ends_with(".scope")
                    || *part == "libpod_parent"
                {
                    "podman"
                } else {
                    continue;
                };
                sockowner::container_of(&format!("/{}/{}", part, parts.get(i + 1).unwrap_or(&"")))
                    .map(|id| format!("{runtime}/{id}"))
            };
            if let Some(id) = id.filter(|id| valid_id(id)) {
                return Some(id);
            }
        }
    }
    None
}

fn namespace_init(status: &str) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .and_then(|pids| pids.split_whitespace().last()?.parse::<u32>().ok())
        == Some(1)
}

/// fib_trie has no interface names. Preserve these IPs on an unnamed interface
/// rather than guessing which NIC owns them on a multi-interface container.
fn fib_trie(s: &str) -> Vec<String> {
    let mut ips = BTreeSet::new();
    let mut candidate = None;
    for line in s.lines() {
        let line = line.trim();
        if let Some(ip) = line.strip_prefix("|--") {
            candidate = ip.trim().parse::<Ipv4Addr>().ok();
        } else {
            if line.split_whitespace().eq(["/32", "host", "LOCAL"]) {
                if let Some(ip) = candidate.filter(|ip| !ip.is_loopback() && !ip.is_unspecified()) {
                    ips.insert(ip.to_string());
                }
            }
            candidate = None;
        }
    }
    ips.into_iter().collect()
}

fn if_inet6(s: &str) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for line in s.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 6 || f[0].len() != 32 || !f[0].bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let mut bytes = [0; 16];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&f[0][i * 2..i * 2 + 2], 16).unwrap();
        }
        let ip = Ipv6Addr::from(bytes);
        if f[5] != "lo"
            && !ip.is_loopback()
            && !ip.is_unspecified()
            && (ip.segments()[0] & 0xffc0) != 0xfe80
        {
            out.entry(f[5].into()).or_default().push(ip.to_string());
        }
    }
    for ips in out.values_mut() {
        ips.sort();
        ips.dedup();
    }
    out
}

fn packages(
    dpkg_status: Option<&str>,
    apk_installed: Option<&str>,
    osr: &BTreeMap<String, String>,
) -> Vec<Component> {
    let distro = util::distro(osr);
    if let Some(status) = dpkg_status {
        let ns = util::namespace(osr, "debian");
        return dpkg::parse_status(status)
            .iter()
            .map(|p| dpkg::component(p, &ns, &distro))
            .collect();
    }
    // apk::component is private. Keep its PURL qualifiers and origin semantics here.
    apk_installed
        .map(|db| {
            apk::parse_installed(db)
                .iter()
                .map(|p| {
                    let upstream = if p.origin != p.name {
                        p.origin.as_str()
                    } else {
                        ""
                    };
                    Component {
                        purl: util::purl(
                            "apk",
                            &util::namespace(osr, "alpine"),
                            &p.name,
                            &p.version,
                            &[
                                ("arch", &p.arch),
                                ("distro", &distro),
                                ("upstream", upstream),
                            ],
                        ),
                        name: p.name.clone(),
                        version: p.version.clone(),
                        confidence: Some(Confidence::High),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn child(mut report: ContainerReport) -> Option<Entity> {
    if !valid_id(&report.id) {
        return None;
    }
    let mut ids = vec![Identifier::strong("container.id", report.id)];
    for iface in &report.interfaces {
        if !iface.mac.is_empty() {
            let id = Identifier::strong("mac", &iface.mac);
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        for ip in &iface.ips {
            let id = Identifier::weak("ip", ip);
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    if !report.name.is_empty() {
        ids.push(Identifier::weak("hostname", &report.name));
    }
    if !report.errors.is_empty() {
        let mut errors = report.errors.join("; ");
        let mut end = errors.len().min(4096);
        while !errors.is_char_boundary(end) {
            end -= 1;
        }
        errors.truncate(end);
        report.attributes.insert("container.errors".into(), errors);
    }
    Some(Entity {
        kind: EntityKind::Container,
        name: report.name,
        identifiers: ids,
        attributes: report.attributes,
        components: report.components,
        services: report.services,
        interfaces: report.interfaces,
        ..Default::default()
    })
}

fn contribution(reports: Vec<ContainerReport>) -> crate::collector::Contribution {
    let mut seen = BTreeSet::new();
    crate::collector::Contribution {
        children: reports
            .into_iter()
            .filter(|r| seen.insert(r.id.clone()))
            .filter_map(child)
            .take(MAX_CONTAINERS)
            .collect(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_forms() {
        for line in include_str!("../../testdata/containers/cgroups.tsv").lines() {
            let (expected, cgroup) = line.split_once('\t').unwrap();
            assert_eq!(
                container_id(cgroup).as_deref(),
                (expected != "-").then_some(expected),
                "{cgroup}"
            );
        }
        assert_eq!(
            container_id("11:cpu:/system.slice\n0::/lxc/101/init.scope"),
            Some("lxc/101".into())
        );
        for id in [
            "docker/",
            "lxc/-bad",
            "LXC/101",
            "lxc/a/b",
            "lxc/with space",
            "lxc/ä",
            "lxc/a\n",
        ] {
            assert!(!valid_id(id), "{id}");
        }
        assert!(!valid_id(&format!("lxc/{}", "a".repeat(129))));
        assert!(valid_id(&format!("lxc/{}", "a".repeat(128))));
    }

    #[test]
    fn init_pid_from_status() {
        assert!(namespace_init(include_str!(
            "../../testdata/containers/init.status"
        )));
        assert!(!namespace_init(include_str!(
            "../../testdata/containers/worker.status"
        )));
        assert!(namespace_init("NSpid:\t991 9 1\n"));
        for s in [
            "",
            "Name:\tinit\n",
            "NSpid:\n",
            "NSpid:\tunknown\n",
            "NSpid:\t11 11\n",
        ] {
            assert!(!namespace_init(s));
        }
    }

    #[test]
    fn network_addresses() {
        assert_eq!(
            fib_trie(include_str!("../../testdata/containers/fib_trie")),
            ["10.42.0.7", "192.0.2.8"]
        );
        let ips = if_inet6(include_str!("../../testdata/containers/if_inet6"));
        assert_eq!(ips.len(), 2);
        assert_eq!(ips["eth0"], ["2001:db8::7"]);
        assert_eq!(ips["eth1"], ["fd00::8"]);
    }

    #[test]
    fn container_package_purls_match_host_parsers() {
        for (fixture, deb) in [("debian", true), ("alpine", false)] {
            let ctx = super::super::testctx(fixture);
            let osr = util::os_release(&ctx);
            let db = std::fs::read_to_string(ctx.path(if deb {
                "/var/lib/dpkg/status"
            } else {
                "/lib/apk/db/installed"
            }))
            .unwrap();
            let got = packages(
                deb.then_some(db.as_str()),
                (!deb).then_some(db.as_str()),
                &osr,
            );
            use crate::collector::Collector;
            let expected = if deb {
                dpkg::Dpkg.collect(&ctx).unwrap()
            } else {
                apk::Apk.collect(&ctx).unwrap()
            };
            assert_eq!(got, expected.host.components);
            assert!(got.iter().all(|p| p.purl.contains(if deb {
                "distro=debian-12"
            } else {
                "distro=alpine-3.19.1"
            })));
        }
        let ubuntu = util::parse_os_release("ID=ubuntu\nVERSION_ID=24.04\n");
        assert_eq!(
            packages(
                Some("Package: test\nVersion: 1\nArchitecture: arm64\n"),
                None,
                &ubuntu
            )[0]
            .purl,
            "pkg:deb/ubuntu/test@1?arch=arm64&distro=ubuntu-24.04"
        );
    }

    #[test]
    fn report_to_child_matches_server_shape() {
        let reports: Vec<ContainerReport> =
            serde_json::from_str(include_str!("../../testdata/containers/report.json")).unwrap();
        let c = contribution(reports);
        assert!(c.host.identifiers.is_empty());
        assert_eq!(c.children.len(), 1);
        let e = &c.children[0];
        assert_eq!(e.kind, EntityKind::Container);
        assert_eq!(e.name, "web1");
        assert_eq!(
            e.identifiers,
            [
                Identifier::strong("container.id", "lxc/101"),
                Identifier::strong("mac", "02:00:00:00:00:07"),
                Identifier::weak("ip", "10.42.0.7"),
                Identifier::weak("ip", "2001:db8::7"),
                Identifier::weak("hostname", "web1"),
            ]
        );
        assert!(e.children.is_empty());
        assert!(e.parent.is_empty());
        assert_eq!(e.attributes["container.errors"], "test error");
        assert_eq!(
            e.components[0].purl,
            "pkg:deb/debian/example@1?distro=debian-12"
        );
        assert_eq!(e.services[0].process, "nginx");
        assert!(e.services[0].component.is_empty());
        let value = serde_json::to_value(e).unwrap();
        assert_eq!(value["kind"], "container");
        assert_eq!(value["identifiers"][0]["kind"], "container.id");
    }

    #[test]
    fn invalid_duplicate_and_excess_children_are_filtered() {
        assert!(child(ContainerReport {
            id: "lxc/../bad".into(),
            ..Default::default()
        })
        .is_none());
        let reports = (0..1002)
            .map(|n| ContainerReport {
                id: format!("docker/{n}"),
                ..Default::default()
            })
            .collect();
        assert_eq!(contribution(reports).children.len(), 1000);
        let reports = (0..2)
            .map(|_| ContainerReport {
                id: "lxc/101".into(),
                ..Default::default()
            })
            .collect();
        assert_eq!(contribution(reports).children.len(), 1);
        let e = child(ContainerReport {
            id: "lxc/101".into(),
            errors: vec!["ä".repeat(5000)],
            ..Default::default()
        })
        .unwrap();
        assert_eq!(e.attributes["container.errors"].len(), 4096);
    }
}

#[cfg(target_os = "linux")]
pub use linux::{helper_json, Containers};

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::collector::{Access, Collector, Contribution, Ctx};
    use crate::collectors::sockets;
    use nix::libc;
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    const SOCKET: &str = "/run/nn-agent-helper-containers.sock";
    const OUTPUT_CAP: usize = 256 << 20;
    const PACKAGE_CAP: usize = 64 << 20;
    const SMALL_CAP: usize = 64 << 10;
    const PROC_CAP: usize = 16 << 20;

    pub struct Containers;

    fn helper_path(ctx: &Ctx) -> PathBuf {
        ctx.helper
            .as_deref()
            .and_then(Path::parent)
            .map(|p| p.join("nn-agent-helper-containers.sock"))
            .unwrap_or_else(|| ctx.path(SOCKET))
    }

    impl Collector for Containers {
        fn name(&self) -> &'static str {
            "containers"
        }
        fn access(&self) -> Access {
            Access {
                sockets: vec![SOCKET],
                privileged:
                    "packages of running containers (install nn-agent-helper-containers.socket)",
                ..Default::default()
            }
        }
        fn collect(&self, ctx: &Ctx) -> Result<Contribution, String> {
            let path = helper_path(ctx);
            if !path.exists() {
                return Ok(Contribution::default());
            }
            let stream =
                UnixStream::connect(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            stream
                .set_read_timeout(Some(Duration::from_secs(150)))
                .map_err(|e| e.to_string())?;
            let _ = stream.shutdown(std::net::Shutdown::Write);
            let mut buf = Vec::new();
            stream
                .take((OUTPUT_CAP + 1) as u64)
                .read_to_end(&mut buf)
                .map_err(|e| format!("container helper: {e}"))?;
            if buf.len() > OUTPUT_CAP {
                return Err("container helper output exceeds 256 MiB".into());
            }
            serde_json::from_slice(&buf)
                .map(contribution)
                .map_err(|e| format!("container helper answer: {e}"))
        }
    }

    fn budget(deadline: Instant) -> io::Result<()> {
        if Instant::now() >= deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "container time budget exceeded",
            ))
        } else {
            Ok(())
        }
    }

    fn directory(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(path)
    }

    // Linux UAPI open_how; using libc avoids adding nix features or dependencies.
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    fn confined_open(root: &File, path: &str) -> io::Result<File> {
        let path = CString::new(path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: 0x10 | 0x02, // RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
        };
        // SAFETY: valid dirfd and NUL-terminated path; how matches the Linux UAPI.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root.as_raw_fd(),
                path.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: syscall returned a new descriptor, exclusively owned here.
        Ok(unsafe { File::from_raw_fd(fd as libc::c_int) })
    }

    fn read_safe(root: &File, path: &str, cap: usize, deadline: Instant) -> io::Result<String> {
        budget(deadline)?;
        let file = confined_open(root, path)?;
        read_file(file, cap, deadline)
    }

    fn read_file(mut file: File, cap: usize, deadline: Instant) -> io::Result<String> {
        let meta = file.metadata()?; // fstat, never follow a path for the type check.
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a regular file",
            ));
        }
        if meta.len() > cap as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file exceeds size cap",
            ));
        }
        let mut out = Vec::new();
        let mut chunk = [0; 16 << 10];
        loop {
            budget(deadline)?;
            let n = file.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            if n > cap - out.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "file exceeds size cap",
                ));
            }
            out.extend_from_slice(&chunk[..n]);
        }
        // Package databases can hold bytes that are not UTF-8 (old
        // descriptions); keep the rest of the data.
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    fn optional(
        root: &File,
        path: &str,
        cap: usize,
        deadline: Instant,
        errors: &mut Vec<String>,
    ) -> Option<String> {
        match read_safe(root, path, cap, deadline) {
            Ok(s) => Some(s),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                errors.push(format!("{path}: {e}"));
                None
            }
        }
    }

    #[derive(Default)]
    struct Candidate {
        pids: Vec<u32>,
        init: Option<u32>,
    }

    fn proc_dir(pid: u32) -> io::Result<File> {
        directory(Path::new(&format!("/proc/{pid}")))
    }

    /// Only fixed, kernel-owned paths relative to a pinned /proc/<pid> directory.
    /// These are not files in a container's root. Discovery must also work on
    /// kernels lacking openat2 so each discovered container can report that error.
    fn read_proc(proc: &File, path: &str, cap: usize, deadline: Instant) -> io::Result<String> {
        budget(deadline)?;
        let path = CString::new(path)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in proc path"))?;
        // SAFETY: valid directory and C string. All callers use fixed proc paths.
        let fd = unsafe {
            libc::openat(
                proc.as_raw_fd(),
                path.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh descriptor.
        read_file(unsafe { File::from_raw_fd(fd) }, cap, deadline)
    }

    fn optional_proc(
        proc: &File,
        path: &str,
        cap: usize,
        deadline: Instant,
        errors: &mut Vec<String>,
    ) -> Option<String> {
        match read_proc(proc, path, cap, deadline) {
            Ok(s) => Some(s),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                errors.push(format!("proc/{path}: {e}"));
                None
            }
        }
    }

    fn belongs(proc: &File, id: &str, deadline: Instant) -> bool {
        read_proc(proc, "cgroup", SMALL_CAP, deadline)
            .ok()
            .and_then(|s| container_id(&s))
            .as_deref()
            == Some(id)
    }

    fn discover(deadline: Instant) -> io::Result<BTreeMap<String, Candidate>> {
        let hosts: BTreeSet<_> = [1, std::process::id()]
            .into_iter()
            .filter_map(|pid| {
                proc_dir(pid)
                    .ok()
                    .and_then(|p| read_proc(&p, "cgroup", SMALL_CAP, deadline).ok())
                    .and_then(|s| container_id(&s))
            })
            .collect();
        let mut groups: BTreeMap<String, Candidate> = BTreeMap::new();
        for entry in std::fs::read_dir("/proc")?.flatten() {
            if budget(deadline).is_err() {
                break;
            }
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Ok(proc) = proc_dir(pid) else {
                continue;
            };
            let Some(id) = read_proc(&proc, "cgroup", SMALL_CAP, deadline)
                .ok()
                .and_then(|s| container_id(&s))
            else {
                continue;
            };
            if hosts.contains(&id) {
                continue;
            }
            if groups.len() >= MAX_CONTAINERS && !groups.contains_key(&id) {
                continue;
            }
            let init =
                read_proc(&proc, "status", SMALL_CAP, deadline).is_ok_and(|s| namespace_init(&s));
            let c = groups.entry(id).or_default();
            c.pids.push(pid);
            if init {
                c.init = Some(c.init.map_or(pid, |old| old.min(pid)));
            }
        }
        for c in groups.values_mut() {
            c.pids.sort_unstable();
        }
        Ok(groups)
    }

    /// The one intentional magic-link traversal: anchor the process directory
    /// first, open its root, THEN verify membership again through the pinned proc fd.
    fn container_root(proc: &File, id: &str, deadline: Instant) -> io::Result<File> {
        // SAFETY: proc is an owned directory; literal is NUL-terminated. No input path.
        let fd = unsafe {
            libc::openat(
                proc.as_raw_fd(),
                c"root".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh descriptor.
        let root = unsafe { File::from_raw_fd(fd) };
        if !belongs(proc, id, deadline) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "container process changed",
            ));
        }
        Ok(root)
    }

    fn network(
        root: &File,
        proc: &File,
        id: &str,
        pids: &[u32],
        report: &mut ContainerReport,
        deadline: Instant,
    ) -> io::Result<()> {
        let mut socks = Vec::new();
        for (file, proto) in [
            ("tcp", "tcp"),
            ("tcp6", "tcp"),
            ("udp", "udp"),
            ("udp6", "udp"),
        ] {
            if let Some(s) = optional_proc(
                proc,
                &format!("net/{file}"),
                PROC_CAP,
                deadline,
                &mut report.errors,
            ) {
                socks.extend(sockets::parse_table(&s, proto));
            }
        }
        let eph = optional(
            root,
            "/proc/sys/net/ipv4/ip_local_port_range",
            SMALL_CAP,
            deadline,
            &mut report.errors,
        )
        .and_then(|s| {
            let mut it = s.split_whitespace();
            Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
        })
        .unwrap_or((32768, 60999));
        let socks = sockets::dedupe(socks, eph);
        let want: BTreeSet<_> = socks.iter().map(|s| s.inode).collect();
        let mut owners = BTreeMap::new();
        for &pid in pids {
            budget(deadline)?;
            let Ok(p) = proc_dir(pid) else {
                continue;
            };
            if !belongs(&p, id, deadline) {
                continue;
            }
            // Only enumerate fds of processes revalidated as members of this container.
            let Ok(fds) = std::fs::read_dir(format!("/proc/self/fd/{}/fd", p.as_raw_fd())) else {
                continue;
            };
            let comm = read_proc(&p, "comm", SMALL_CAP, deadline)
                .unwrap_or_default()
                .trim()
                .to_string();
            for fd in fds.flatten() {
                budget(deadline)?;
                let Ok(link) = std::fs::read_link(fd.path()) else {
                    continue;
                };
                let link = link.to_string_lossy();
                if let Some(inode) = link
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    if want.contains(&inode) {
                        owners.entry(inode).or_insert_with(|| comm.clone());
                    }
                }
            }
            if owners.len() == want.len() {
                break;
            }
        }
        report.services = socks
            .into_iter()
            .map(|s| Service {
                port: s.port,
                proto: s.proto.into(),
                address: s.addr,
                process: owners.remove(&s.inode).unwrap_or_default(),
                confidence: Some(Confidence::High),
                ..Default::default()
            })
            .collect();
        let mut interfaces: BTreeMap<String, Interface> = BTreeMap::new();
        if let Some(dev) = optional_proc(proc, "net/dev", PROC_CAP, deadline, &mut report.errors) {
            for name in dev
                .lines()
                .filter_map(|s| s.split_once(':').map(|v| v.0.trim()))
            {
                budget(deadline)?;
                if name == "lo" || name.contains('/') || name == "." || name == ".." {
                    continue;
                }
                let mac = optional(
                    root,
                    &format!("/sys/class/net/{name}/address"),
                    4096,
                    deadline,
                    &mut report.errors,
                )
                .unwrap_or_default()
                .trim()
                .to_string();
                interfaces.insert(
                    name.into(),
                    Interface {
                        name: name.into(),
                        mac,
                        ..Default::default()
                    },
                );
            }
        }
        if let Some(s) = optional_proc(proc, "net/if_inet6", PROC_CAP, deadline, &mut report.errors)
        {
            for (name, ips) in if_inet6(&s) {
                interfaces
                    .entry(name.clone())
                    .or_insert_with(|| Interface {
                        name,
                        ..Default::default()
                    })
                    .ips
                    .extend(ips);
            }
        }
        report.interfaces = interfaces.into_values().collect();
        if let Some(s) = optional_proc(proc, "net/fib_trie", PROC_CAP, deadline, &mut report.errors)
        {
            let ips = fib_trie(&s);
            if !ips.is_empty() {
                // With one interface (the usual container), the addresses
                // belong to it; else keep them on an unnamed interface.
                if let [only] = report.interfaces.as_mut_slice() {
                    only.ips.extend(ips);
                } else {
                    report.interfaces.push(Interface {
                        ips,
                        ..Default::default()
                    });
                }
            }
        }
        Ok(())
    }

    fn inspect(id: String, c: Candidate, deadline: Instant) -> Option<ContainerReport> {
        let pid = c.init.or_else(|| c.pids.first().copied())?;
        let proc = proc_dir(pid).ok()?;
        let mut r = ContainerReport {
            id,
            ..Default::default()
        };
        let root = container_root(&proc, &r.id, deadline).ok()?;
        // Fail closed on old kernels before reading any container file.
        let os = match read_safe(&root, "/etc/os-release", SMALL_CAP, deadline) {
            Ok(s) => Some(s),
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {
                r.errors
                    .push("openat2 unavailable; container skipped".into());
                return Some(r);
            }
            Err(e) => {
                if e.kind() != io::ErrorKind::NotFound {
                    r.errors.push(format!("/etc/os-release: {e}"));
                }
                optional(
                    &root,
                    "/usr/lib/os-release",
                    SMALL_CAP,
                    deadline,
                    &mut r.errors,
                )
            }
        };
        let osr = util::parse_os_release(os.as_deref().unwrap_or(""));
        if osr.is_empty() {
            r.errors.push("no os-release file".into());
        }
        for (key, attr) in [
            ("ID", "os.id"),
            ("VERSION_ID", "os.version"),
            ("VERSION_ID", "os.version_id"),
            ("PRETTY_NAME", "os.name"),
        ] {
            if let Some(value) = osr.get(key) {
                r.attributes.insert(attr.into(), value.clone());
            }
        }
        r.name = optional(&root, "/etc/hostname", SMALL_CAP, deadline, &mut r.errors)
            .unwrap_or_default()
            .trim()
            .to_string();
        let deb = optional(
            &root,
            "/var/lib/dpkg/status",
            PACKAGE_CAP,
            deadline,
            &mut r.errors,
        );
        let apk = if deb.is_none() {
            optional(
                &root,
                "/lib/apk/db/installed",
                PACKAGE_CAP,
                deadline,
                &mut r.errors,
            )
        } else {
            None
        };
        r.components = packages(deb.as_deref(), apk.as_deref(), &osr);
        if deb.is_none()
            && apk.is_none()
            && osr
                .get("ID")
                .into_iter()
                .chain(osr.get("ID_LIKE"))
                .any(|s| {
                    s.split_whitespace().any(|id| {
                        matches!(
                            id,
                            "rhel"
                                | "fedora"
                                | "centos"
                                | "rocky"
                                | "almalinux"
                                | "ol"
                                | "suse"
                                | "opensuse"
                                | "opensuse-leap"
                                | "opensuse-tumbleweed"
                                | "amzn"
                        )
                    })
                })
        {
            r.errors
                .push("rpm database not read (no rpm parser)".into());
        }
        let id = r.id.clone();
        if let Err(e) = network(&root, &proc, &id, &c.pids, &mut r, deadline) {
            r.errors.push(e.to_string());
        }
        // A process exiting/moving cgroups during collection cannot report stale data.
        if !belongs(&proc, &r.id, Instant::now() + Duration::from_millis(100)) {
            return None;
        }
        Some(r)
    }

    /// Bound even a blocked filesystem syscall: a timed-out worker is detached,
    /// and the helper process exits after writing its completed reports. Stop on
    /// timeout so there is at most one unfinished worker, rather than accumulating
    /// threads that a container's FUSE filesystem could keep blocked indefinitely.
    fn timed<T: Send + 'static>(
        deadline: Instant,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> io::Result<T> {
        budget(deadline)?;
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("container-reader".into())
            .spawn(move || {
                let _ = tx.send(f());
            })?;
        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, format!("container reader: {e}")))
    }

    /// Build bounded JSON before writing anything, so the peer always gets a
    /// complete array. Hard deadlines leave headroom below RuntimeMaxSec.
    pub fn helper_json() -> Result<Vec<u8>, String> {
        let deadline = Instant::now() + Duration::from_secs(95);
        let discovery_deadline = Instant::now() + Duration::from_secs(15);
        let candidates = timed(discovery_deadline, move || discover(discovery_deadline))
            .and_then(|r| r)
            .map_err(|e| e.to_string())?;
        let mut out = vec![b'['];
        let mut first = true;
        for (id, c) in candidates {
            if Instant::now() >= deadline {
                break;
            }
            let per_container = (Instant::now() + Duration::from_secs(2)).min(deadline);
            let error_id = id.clone();
            let remaining = OUTPUT_CAP.saturating_sub(out.len() + 2);
            let result = timed(per_container, move || {
                let mut r = inspect(id, c, per_container)?;
                let mut encoded = Capped(Vec::new(), remaining);
                if serde_json::to_writer(&mut encoded, &r).is_err() {
                    r.components.clear();
                    r.services.clear();
                    r.interfaces.clear();
                    r.attributes.clear();
                    r.name.clear();
                    r.errors = vec!["container omitted: helper output cap exceeded".into()];
                    encoded.0.clear();
                    serde_json::to_writer(&mut encoded, &r).ok()?;
                }
                Some(encoded.0)
            });
            let (encoded, stop) = match result {
                Ok(encoded) => (encoded, false),
                Err(e) => {
                    let r = ContainerReport {
                        id: error_id,
                        errors: vec![e.to_string()],
                        ..Default::default()
                    };
                    let mut encoded = Capped(Vec::new(), remaining);
                    let ok = serde_json::to_writer(&mut encoded, &r).is_ok();
                    (ok.then_some(encoded.0), true)
                }
            };
            if let Some(encoded) = encoded {
                if !first {
                    out.push(b',');
                }
                out.extend_from_slice(&encoded);
                first = false;
            }
            if stop {
                break;
            }
        }
        out.push(b']');
        Ok(out)
    }

    struct Capped(Vec<u8>, usize);
    impl Write for Capped {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.len() > self.1.saturating_sub(self.0.len()) {
                return Err(io::Error::other("helper output cap exceeded"));
            }
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;

        struct Temp(PathBuf);
        impl Temp {
            fn new() -> Self {
                let path = std::env::temp_dir().join(format!(
                    "nn-containers-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir(&path).unwrap();
                Self(path)
            }
        }
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        #[test]
        fn safe_reader_confines_symlinks_and_rejects_fifo_and_oversize() {
            let temp = Temp::new();
            let dir = temp.0.join("root");
            std::fs::create_dir_all(dir.join("var/lib/dpkg")).unwrap();
            let root = directory(&dir).unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let status = dir.join("var/lib/dpkg/status");
            symlink("/etc/hostname", &status).unwrap();
            assert_eq!(
                read_safe(&root, "/var/lib/dpkg/status", SMALL_CAP, deadline)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::NotFound
            );
            std::fs::create_dir(dir.join("etc")).unwrap();
            std::fs::write(dir.join("etc/hostname"), "known-container-hostname\n").unwrap();
            assert_eq!(
                read_safe(&root, "/var/lib/dpkg/status", SMALL_CAP, deadline).unwrap(),
                "known-container-hostname\n"
            );
            std::fs::remove_file(&status).unwrap();
            symlink("../../../../../../etc/hostname", &status).unwrap();
            assert_eq!(
                read_safe(&root, "/var/lib/dpkg/status", SMALL_CAP, deadline).unwrap(),
                "known-container-hostname\n"
            );
            let fifo = CString::new(dir.join("fifo").as_os_str().as_bytes()).unwrap();
            // SAFETY: valid C path and mode; mkfifo creates only a test fixture.
            assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
            assert_eq!(
                read_safe(&root, "fifo", SMALL_CAP, deadline)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            File::create(dir.join("big"))
                .unwrap()
                .set_len((PACKAGE_CAP + 1) as u64)
                .unwrap();
            assert_eq!(
                read_safe(&root, "big", PACKAGE_CAP, deadline)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(
                read_safe(&root, "etc", SMALL_CAP, deadline)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(
                read_safe(&root, "etc/hostname", SMALL_CAP, Instant::now())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            let host_root = directory(Path::new("/")).unwrap();
            assert_eq!(
                read_safe(
                    &host_root,
                    &format!("/proc/self/fd/{}", root.as_raw_fd()),
                    SMALL_CAP,
                    deadline
                )
                .unwrap_err()
                .raw_os_error(),
                Some(libc::ELOOP)
            );
        }

        #[test]
        fn collector_uses_sibling_socket_and_preserves_child_errors() {
            let temp = Temp::new();
            let mut ctx = Ctx::new(temp.0.clone());
            ctx.helper = Some(temp.0.join("nn-agent-helper.sock"));
            assert!(Containers.collect(&ctx).unwrap().children.is_empty());
            let listener = std::os::unix::net::UnixListener::bind(helper_path(&ctx)).unwrap();
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .write_all(include_bytes!("../../testdata/containers/report.json"))
                    .unwrap();
            });
            let got = Containers.collect(&ctx).unwrap();
            worker.join().unwrap();
            assert_eq!(got.children.len(), 1);
            assert_eq!(got.children[0].attributes["container.errors"], "test error");
        }

        #[test]
        fn output_writer_rejects_overflow() {
            let mut out = Capped(Vec::new(), 4);
            out.write_all(b"1234").unwrap();
            assert!(out.write_all(b"5").is_err());
            assert_eq!(out.0, b"1234");
        }

        #[test]
        fn stalled_worker_does_not_hold_up_helper() {
            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let result = timed(Instant::now() + Duration::from_millis(25), move || {
                rx.recv()
            });
            // Release the test worker even if a timing assertion below fails.
            let _ = tx.send(());
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
            assert_eq!(
                timed(Instant::now() + Duration::from_secs(1), || 7).unwrap(),
                7
            );
        }
    }
}
