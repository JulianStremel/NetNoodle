use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Sock {
    proto: &'static str,
    addr: String,
    port: u16,
    pid: u32,
}

fn address6(bytes: [u8; 16]) -> String {
    let ip = Ipv6Addr::from(bytes);
    ip.to_ipv4_mapped()
        .map_or_else(|| ip.to_string(), |a| a.to_string())
}
fn exposure(addr: &str) -> u8 {
    match addr.parse::<IpAddr>() {
        Ok(ip) if ip.is_unspecified() => 3,
        Ok(ip) if ip.is_loopback() => 1,
        _ => 2,
    }
}
fn dedupe(socks: Vec<Sock>) -> Vec<Sock> {
    let mut best: BTreeMap<(&str, u16), Sock> = BTreeMap::new();
    for s in socks {
        if s.proto == "udp" && s.port >= 49152 {
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

/// SCM paths can contain spaces without quotes; the executable extension
/// marks the end of those paths. Quoted paths end at the closing quote.
fn binary_path(command: &str) -> String {
    let command = command.trim();
    if let Some(rest) = command.strip_prefix('"') {
        return rest
            .split_once('"')
            .map(|(path, _)| path.to_string())
            .unwrap_or_default();
    }
    let lower = command.to_ascii_lowercase();
    for (i, _) in lower.match_indices(".exe") {
        let end = i + 4;
        if command[end..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace)
        {
            return command[..end].into();
        }
    }
    command.split_whitespace().next().unwrap_or("").into()
}
fn process_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or("").into()
}

/// Owner of a process that hosts one or more services. Several services in
/// one process (svchost) do not tell which of them owns a socket: then the
/// name lists them and no executable is given, so no program is guessed.
fn shared_owner(mut services: Vec<(String, String)>) -> (String, String) {
    if services.len() == 1 {
        return services.remove(0);
    }
    let same_exe = services
        .windows(2)
        .all(|w| w[0].1.eq_ignore_ascii_case(&w[1].1));
    let mut names: Vec<&str> = services.iter().map(|s| s.0.as_str()).collect();
    names.sort_unstable();
    let more = names.len().saturating_sub(4);
    let mut label = names[..names.len().min(4)].join(", ");
    if more > 0 {
        label.push_str(&format!(" +{more}"));
    }
    let exe = if same_exe && !services.is_empty() {
        services[0].1.clone()
    } else {
        String::new()
    };
    (label, exe)
}

#[cfg(windows)]
pub struct Sockets;
#[cfg(windows)]
impl crate::collector::Collector for Sockets {
    fn name(&self) -> &'static str {
        "sockets"
    }
    fn access(&self) -> crate::collector::Access {
        crate::collector::Access {
            reads: vec!["OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION), QueryFullProcessImageNameW", "SCM: EnumServicesStatusExW(SERVICE_WIN32, SERVICE_ACTIVE), QueryServiceConfigW", r"HKLM\SYSTEM\CurrentControlSet\Services\<name>\Parameters\ServiceDll", "ExpandEnvironmentStringsW"],
            sockets: vec!["GetExtendedTcpTable(TCP_TABLE_OWNER_PID_LISTENER), IPv4/IPv6", "GetExtendedUdpTable(UDP_TABLE_OWNER_PID), IPv4/IPv6"],
            privileged: "protected processes without a readable service configuration may have unknown owners",
            ..Default::default()
        }
    }
    fn collect(
        &self,
        _ctx: &crate::collector::Ctx,
    ) -> Result<crate::collector::Contribution, String> {
        let socks = dedupe(win::listening()?);
        let mut owners = BTreeMap::new();
        for s in &socks {
            owners.entry(s.pid).or_insert_with(|| win::process(s.pid));
        }
        let mut notes = Vec::new();
        if owners.values().any(Option::is_none) {
            match win::services() {
                Ok(services) => {
                    for (pid, owner) in &mut owners {
                        if owner.is_none() {
                            *owner = services.get(pid).cloned();
                        }
                    }
                }
                Err(e) => notes.push(e),
            }
        }
        let mut c = crate::collector::Contribution::default();
        let mut unknown = 0;
        for s in socks {
            let owner = owners.get(&s.pid).and_then(Option::as_ref);
            if owner.is_none() {
                unknown += 1;
            }
            c.host.services.push(nn_proto::Service {
                port: s.port,
                proto: s.proto.into(),
                address: s.addr,
                process: owner.map(|o| o.0.clone()).unwrap_or_default(),
                confidence: Some(nn_proto::Confidence::High),
                ..Default::default()
            });
            c.service_exes
                .push(owner.map(|o| o.1.clone()).unwrap_or_default());
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

#[cfg(windows)]
mod win {
    use super::super::{
        api::{error, string, wide, Buffer},
        registry::Key,
    };
    use super::*;
    use std::{
        mem::{offset_of, size_of},
        ptr::null,
    };
    use windows_sys::Win32::{
        Foundation::*,
        NetworkManagement::IpHelper::*,
        Networking::WinSock::{AF_INET, AF_INET6},
        System::{Services::*, Threading::*},
    };

    fn table(tcp: bool, family: u16) -> Result<Buffer, String> {
        let mut size = 0;
        for _ in 0..8 {
            let mut buf = Buffer::new(size);
            size = buf.len();
            // SAFETY: buffer is aligned, writable for size bytes; table classes match the API.
            let status = unsafe {
                if tcp {
                    GetExtendedTcpTable(
                        buf.ptr(),
                        &mut size,
                        0,
                        family as u32,
                        TCP_TABLE_OWNER_PID_LISTENER,
                        0,
                    )
                } else {
                    GetExtendedUdpTable(
                        buf.ptr(),
                        &mut size,
                        0,
                        family as u32,
                        UDP_TABLE_OWNER_PID,
                        0,
                    )
                }
            };
            if status == ERROR_INSUFFICIENT_BUFFER {
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(error(
                    if tcp {
                        "GetExtendedTcpTable"
                    } else {
                        "GetExtendedUdpTable"
                    },
                    status,
                ));
            }
            return Ok(buf);
        }
        Err("socket table buffer kept growing".into())
    }
    /// # Safety
    /// Buffer must contain the IP Helper table with rows of type T at offset.
    unsafe fn rows<T: Copy>(buf: &mut Buffer, offset: usize) -> Result<Vec<T>, String> {
        // SAFETY: the API's table header is a DWORD and Buffer always has at least eight bytes.
        let count = unsafe { buf.ptr().cast::<u32>().read() } as usize;
        if offset > buf.len() as usize || count > (buf.len() as usize - offset) / size_of::<T>() {
            return Err("truncated socket table".into());
        }
        (0..count)
            .map(|i| {
                // SAFETY: caller supplies the correct row type and the bounds were checked above.
                Ok(unsafe {
                    buf.ptr()
                        .cast::<u8>()
                        .add(offset + i * size_of::<T>())
                        .cast::<T>()
                        .read_unaligned()
                })
            })
            .collect()
    }
    pub fn listening() -> Result<Vec<Sock>, String> {
        let mut out = Vec::new();
        for family in [AF_INET, AF_INET6] {
            for tcp in [true, false] {
                let mut buf = table(tcp, family)?;
                let proto = if tcp { "tcp" } else { "udp" };
                // SAFETY: each branch selects the table/row layout used for this API query.
                unsafe {
                    match (tcp, family) {
                        (true, AF_INET) => {
                            for r in rows::<MIB_TCPROW_OWNER_PID>(
                                &mut buf,
                                offset_of!(MIB_TCPTABLE_OWNER_PID, table),
                            )? {
                                out.push(Sock {
                                    proto,
                                    addr: Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()).to_string(),
                                    port: u16::from_be(r.dwLocalPort as u16),
                                    pid: r.dwOwningPid,
                                });
                            }
                        }
                        (false, AF_INET) => {
                            for r in rows::<MIB_UDPROW_OWNER_PID>(
                                &mut buf,
                                offset_of!(MIB_UDPTABLE_OWNER_PID, table),
                            )? {
                                out.push(Sock {
                                    proto,
                                    addr: Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()).to_string(),
                                    port: u16::from_be(r.dwLocalPort as u16),
                                    pid: r.dwOwningPid,
                                });
                            }
                        }
                        (true, _) => {
                            for r in rows::<MIB_TCP6ROW_OWNER_PID>(
                                &mut buf,
                                offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
                            )? {
                                out.push(Sock {
                                    proto,
                                    addr: address6(r.ucLocalAddr),
                                    port: u16::from_be(r.dwLocalPort as u16),
                                    pid: r.dwOwningPid,
                                });
                            }
                        }
                        (false, _) => {
                            for r in rows::<MIB_UDP6ROW_OWNER_PID>(
                                &mut buf,
                                offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
                            )? {
                                out.push(Sock {
                                    proto,
                                    addr: address6(r.ucLocalAddr),
                                    port: u16::from_be(r.dwLocalPort as u16),
                                    pid: r.dwOwningPid,
                                });
                            }
                        }
                    }
                }
            }
        }
        Ok(out)
    }

    struct Process(HANDLE);
    impl Drop for Process {
        fn drop(&mut self) {
            // SAFETY: owns a valid OpenProcess handle, closed once.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    pub fn process(pid: u32) -> Option<(String, String)> {
        if pid == 4 {
            return Some(("System".into(), String::new()));
        }
        // SAFETY: read-only process query, the returned handle is checked and owned below.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let handle = Process(handle);
        let mut path = vec![0u16; 256];
        for _ in 0..8 {
            let mut size = path.len() as u32;
            // SAFETY: process handle is valid; path has size UTF-16 elements.
            if unsafe { QueryFullProcessImageNameW(handle.0, 0, path.as_mut_ptr(), &mut size) } != 0
            {
                let exe = String::from_utf16_lossy(&path[..size as usize]);
                return Some((process_name(&exe), exe));
            }
            // SAFETY: reads thread-local error from the preceding query.
            if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }
            path.resize(path.len() * 2, 0);
        }
        None
    }

    struct ServiceHandle(SC_HANDLE);
    impl Drop for ServiceHandle {
        fn drop(&mut self) {
            // SAFETY: owns an SCM/service handle returned by a successful open call.
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
    fn expand(value: &str) -> Result<String, String> {
        use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
        let value = wide(value);
        let mut buf = vec![0u16; 256];
        for _ in 0..8 {
            // SAFETY: input is terminated; output has the declared UTF-16 capacity.
            let size = unsafe {
                ExpandEnvironmentStringsW(value.as_ptr(), buf.as_mut_ptr(), buf.len() as u32)
            };
            if size == 0 {
                // SAFETY: reads the error of the immediately preceding API call.
                return Err(error("ExpandEnvironmentStringsW", unsafe {
                    GetLastError()
                }));
            }
            if size as usize <= buf.len() {
                return Ok(String::from_utf16_lossy(&buf[..size as usize - 1]));
            }
            buf.resize(size as usize, 0);
        }
        Err("environment expansion buffer kept growing".into())
    }
    fn service_binary(manager: &ServiceHandle, name: &str) -> Result<String, String> {
        let name = wide(name);
        // SAFETY: manager is open and name terminated; requests only read access.
        let handle = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_CONFIG) };
        if handle.is_null() {
            // SAFETY: reads last error from OpenServiceW.
            return Err(error("OpenServiceW", unsafe { GetLastError() }));
        }
        let handle = ServiceHandle(handle);
        let mut size = 0;
        for _ in 0..8 {
            let mut buf = Buffer::new(size);
            let capacity = buf.len();
            // SAFETY: owned service handle and aligned buffer of capacity bytes.
            if unsafe { QueryServiceConfigW(handle.0, buf.ptr().cast(), capacity, &mut size) } != 0
            {
                // SAFETY: successful call initialized QUERY_SERVICE_CONFIGW and its terminated binary path.
                return expand(&unsafe {
                    string((*buf.ptr().cast::<QUERY_SERVICE_CONFIGW>()).lpBinaryPathName)
                });
            }
            // SAFETY: reads the preceding query's error.
            let code = unsafe { GetLastError() };
            if code != ERROR_INSUFFICIENT_BUFFER {
                return Err(error("QueryServiceConfigW", code));
            }
        }
        Err("service config buffer kept growing".into())
    }

    pub fn services() -> Result<BTreeMap<u32, (String, String)>, String> {
        // SAFETY: null names select the local active SCM database; requests read access.
        let manager = unsafe {
            OpenSCManagerW(
                null(),
                null(),
                SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT,
            )
        };
        if manager.is_null() {
            // SAFETY: retrieves the error from OpenSCManagerW.
            return Err(error("OpenSCManagerW", unsafe { GetLastError() }));
        }
        let manager = ServiceHandle(manager);
        let mut out: BTreeMap<u32, Vec<(String, String)>> = BTreeMap::new();
        let mut resume = 0;
        let mut capacity = 64 * 1024;
        loop {
            let mut buf = Buffer::new(capacity);
            let (mut needed, mut returned) = (0, 0);
            // SAFETY: manager is valid, buffer aligned and correctly sized; pagination outputs are writable.
            let ok = unsafe {
                EnumServicesStatusExW(
                    manager.0,
                    SC_ENUM_PROCESS_INFO,
                    SERVICE_WIN32,
                    SERVICE_ACTIVE,
                    buf.ptr().cast(),
                    buf.len(),
                    &mut needed,
                    &mut returned,
                    &mut resume,
                    null(),
                )
            };
            // SAFETY: GetLastError reads this thread's status; ignored on success.
            let code = if ok == 0 {
                unsafe { GetLastError() }
            } else {
                ERROR_SUCCESS
            };
            if ok == 0 && code != ERROR_MORE_DATA {
                return Err(error("EnumServicesStatusExW", code));
            }
            if returned as usize > buf.len() as usize / size_of::<ENUM_SERVICE_STATUS_PROCESSW>() {
                return Err("truncated service enumeration".into());
            }
            for i in 0..returned as usize {
                // SAFETY: returned bounds were validated and the API filled this array and its strings.
                let service = unsafe { &*buf.ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>().add(i) };
                let pid = service.ServiceStatusProcess.dwProcessId;
                if pid == 0 {
                    continue;
                }
                // SAFETY: lpServiceName is terminated and lives in buf.
                let name = unsafe { string(service.lpServiceName) };
                // A service can disappear or deny access during enumeration; continue with others.
                let Ok(command) = service_binary(&manager, &name) else {
                    continue;
                };
                let mut exe = binary_path(&command);
                if exe.is_empty() {
                    continue;
                }
                let process = if process_name(&exe).eq_ignore_ascii_case("svchost.exe") {
                    let path = format!(r"SYSTEM\CurrentControlSet\Services\{name}\Parameters");
                    if let Ok(Some(key)) = Key::optional(&path) {
                        if let Ok(dll) = key.string("ServiceDll") {
                            if !dll.is_empty() {
                                exe = expand(&dll)?.trim_matches('"').into();
                            }
                        }
                    }
                    name
                } else {
                    process_name(&exe)
                };
                out.entry(pid).or_default().push((process, exe));
            }
            if ok != 0 {
                return Ok(out
                    .into_iter()
                    .map(|(pid, v)| (pid, shared_owner(v)))
                    .collect());
            }
            if returned == 0 {
                if capacity >= 256 * 1024 {
                    return Err("SCM enumeration made no progress".into());
                }
                capacity = needed.max(capacity * 2).min(256 * 1024);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_service_processes() {
        let one = shared_owner(vec![("Dnscache".into(), r"C:\x\dnsrslvr.dll".into())]);
        assert_eq!(one.1, r"C:\x\dnsrslvr.dll");
        let two = shared_owner(vec![
            ("b".into(), r"C:\x\b.dll".into()),
            ("a".into(), r"C:\x\a.dll".into()),
        ]);
        assert_eq!(two, ("a, b".into(), String::new()));
    }
    #[test]
    fn service_commands() {
        for (s, expected) in [
            (
                r#""C:\Program Files\App\app.exe" --service"#,
                r"C:\Program Files\App\app.exe",
            ),
            (
                r"C:\Program Files\App\APP.EXE -s x",
                r"C:\Program Files\App\APP.EXE",
            ),
            (
                r"C:\Windows\svchost.exe -k netsvcs",
                r"C:\Windows\svchost.exe",
            ),
            (
                r"C:\app.exe.config\run.exe -x",
                r"C:\app.exe.config\run.exe",
            ),
            ("", ""),
            (r#""unterminated"#, ""),
        ] {
            assert_eq!(binary_path(s), expected);
        }
        assert_eq!(process_name(r"C:\Windows\svchost.exe"), "svchost.exe");
    }
    #[test]
    fn addresses_and_deduplication() {
        assert_eq!(
            address6(Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets()),
            "127.0.0.1"
        );
        let socks = [
            ("tcp", "::1", 80, 1),
            ("tcp", "192.0.2.1", 80, 2),
            ("tcp", "::", 80, 3),
            ("tcp", "0.0.0.0", 80, 4),
            ("udp", "0.0.0.0", 49152, 5),
            ("udp", "0.0.0.0", 65535, 5),
            ("udp", "0.0.0.0", 49151, 5),
            ("tcp", "::", 65535, 6),
        ];
        let got = dedupe(
            socks
                .into_iter()
                .map(|(proto, addr, port, pid)| Sock {
                    proto,
                    addr: addr.into(),
                    port,
                    pid,
                })
                .collect(),
        );
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].pid, 3);
        assert_eq!(got[2].port, 49151);
    }
    #[cfg(windows)]
    #[test]
    fn live_sockets() {
        use crate::collector::{Collector, Ctx};
        let c = Sockets.collect(&Ctx::new("/".into())).unwrap();
        assert_eq!(c.host.services.len(), c.service_exes.len());
        assert_eq!(win::process(4), Some(("System".into(), String::new())));
        assert!(win::process(std::process::id()).is_some());
        assert!(!win::services().unwrap().is_empty());
    }
}
