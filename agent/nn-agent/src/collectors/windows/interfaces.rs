use std::net::IpAddr;

fn useful_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => !a.is_loopback() && !a.is_link_local() && !a.is_unspecified(),
        IpAddr::V6(a) => {
            !a.is_loopback() && !a.is_unspecified() && (a.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}
fn mac(bytes: &[u8]) -> String {
    if bytes.iter().all(|b| *b == 0) {
        String::new()
    } else {
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

#[cfg(windows)]
pub struct Interfaces;
#[cfg(windows)]
impl crate::collector::Collector for Interfaces {
    fn name(&self) -> &'static str {
        "interfaces"
    }
    fn access(&self) -> crate::collector::Access {
        crate::collector::Access {
            sockets: vec!["GetAdaptersAddresses (read only)"],
            ..Default::default()
        }
    }
    fn collect(
        &self,
        _ctx: &crate::collector::Ctx,
    ) -> Result<crate::collector::Contribution, String> {
        use super::api::{error, string, Buffer};
        use std::{
            mem::size_of,
            net::{Ipv4Addr, Ipv6Addr},
            ptr::null,
        };
        use windows_sys::Win32::{
            Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
            NetworkManagement::{IpHelper::*, Ndis::IfOperStatusUp},
            Networking::WinSock::*,
        };
        let mut size = 15 * 1024;
        for _ in 0..8 {
            let mut buffer = Buffer::new(size);
            size = buffer.len();
            // SAFETY: aligned buffer is size bytes; reserved is null as required.
            let status = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                    null(),
                    buffer.ptr().cast(),
                    &mut size,
                )
            };
            if status == ERROR_BUFFER_OVERFLOW {
                continue;
            }
            if status != ERROR_SUCCESS {
                return Err(error("GetAdaptersAddresses", status));
            }
            let mut c = crate::collector::Contribution::default();
            let mut adapter = buffer.ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            while !adapter.is_null() {
                // SAFETY: successful API returns a linked list within the still-live aligned buffer.
                let a = unsafe { &*adapter };
                adapter = a.Next;
                if a.OperStatus != IfOperStatusUp
                    || matches!(a.IfType, IF_TYPE_SOFTWARE_LOOPBACK | IF_TYPE_TUNNEL)
                {
                    continue;
                }
                // SAFETY: FriendlyName is a terminated string supplied by GetAdaptersAddresses.
                let name = unsafe { string(a.FriendlyName) };
                let mac = mac(&a.PhysicalAddress
                    [..(a.PhysicalAddressLength as usize).min(a.PhysicalAddress.len())]);
                let mut ips = Vec::new();
                let mut unicast = a.FirstUnicastAddress;
                while !unicast.is_null() {
                    // SAFETY: unicast belongs to the successful API's linked list in buffer.
                    let u = unsafe { &*unicast };
                    unicast = u.Next;
                    let sa = u.Address.lpSockaddr;
                    if sa.is_null() || u.Address.iSockaddrLength < size_of::<SOCKADDR>() as i32 {
                        continue;
                    }
                    // SAFETY: non-null address has at least a SOCKADDR header.
                    let family = unsafe { (*sa).sa_family };
                    let ip = match family {
                        AF_INET if u.Address.iSockaddrLength >= size_of::<SOCKADDR_IN>() as i32 => {
                            // SAFETY: family and length identify SOCKADDR_IN, provided by the API.
                            let v4 = unsafe { &*sa.cast::<SOCKADDR_IN>() };
                            // SAFETY: S_addr represents the four network-order address bytes.
                            Some(IpAddr::V4(Ipv4Addr::from(
                                unsafe { v4.sin_addr.S_un.S_addr }.to_ne_bytes(),
                            )))
                        }
                        AF_INET6
                            if u.Address.iSockaddrLength >= size_of::<SOCKADDR_IN6>() as i32 =>
                        {
                            // SAFETY: family and length identify SOCKADDR_IN6 and its address union.
                            Some(IpAddr::V6(Ipv6Addr::from(unsafe {
                                (*sa.cast::<SOCKADDR_IN6>()).sin6_addr.u.Byte
                            })))
                        }
                        _ => None,
                    };
                    if let Some(ip) = ip.filter(useful_ip) {
                        ips.push(ip.to_string());
                    }
                }
                ips.sort();
                ips.dedup();
                if !mac.is_empty() || !ips.is_empty() {
                    c.host
                        .interfaces
                        .push(nn_proto::Interface { name, mac, ips });
                }
            }
            c.host.interfaces.sort_by(|a, b| a.name.cmp(&b.name));
            return Ok(c);
        }
        Err("GetAdaptersAddresses: adapter buffer kept growing".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn addresses_and_mac() {
        for s in [
            "127.0.0.1",
            "169.254.1.2",
            "0.0.0.0",
            "::",
            "::1",
            "fe80::1",
            "febf::1",
        ] {
            assert!(!useful_ip(&s.parse().unwrap()), "{s}");
        }
        for s in ["192.168.1.2", "2001:db8::1", "fc00::1"] {
            assert!(useful_ip(&s.parse().unwrap()), "{s}");
        }
        assert_eq!(mac(&[0, 1, 0xab, 0xff, 2, 3]), "00:01:ab:ff:02:03");
        assert_eq!(mac(&[0; 6]), "");
        assert_eq!(mac(&[]), "");
    }
    #[cfg(windows)]
    #[test]
    fn live_interfaces() {
        use crate::collector::{Collector, Ctx};
        let c = Interfaces.collect(&Ctx::new("/".into())).unwrap();
        assert!(!c.host.interfaces.is_empty());
        assert!(c.host.interfaces.iter().all(|i| !i.name.is_empty()));
    }
}
