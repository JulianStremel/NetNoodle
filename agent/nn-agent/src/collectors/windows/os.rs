use nn_proto::{Component, Confidence, EntityKind};

fn windows_name(product: &str, build: u32, installation: &str) -> String {
    if build >= 22000 && installation.eq_ignore_ascii_case("Client") {
        product.replacen("Windows 10", "Windows 11", 1)
    } else {
        product.into()
    }
}

fn kind(vendor: &str, product: &str) -> EntityKind {
    let bios = format!("{vendor} {product}").to_lowercase();
    if [
        "qemu",
        "vmware",
        "virtualbox",
        "virtual machine",
        "xen",
        "kvm",
        "proxmox",
    ]
    .iter()
    .any(|s| bios.contains(s))
    {
        EntityKind::Vm
    } else {
        EntityKind::Host
    }
}

fn component(build: u32, ubr: u32, edition: &str, release: &str, ty: &str) -> Component {
    let version = format!("10.0.{build}.{ubr}");
    Component {
        purl: super::purl(
            "microsoft",
            "windows",
            &version,
            &[("edition", edition), ("release", release), ("type", ty)],
        ),
        name: "Windows".into(),
        version,
        confidence: Some(Confidence::High),
    }
}

#[cfg(windows)]
pub struct Os;

#[cfg(windows)]
impl crate::collector::Collector for Os {
    fn name(&self) -> &'static str {
        "os"
    }
    fn access(&self) -> crate::collector::Access {
        crate::collector::Access {
            reads: vec![
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                r"HKLM\HARDWARE\DESCRIPTION\System\BIOS",
                r"HKLM\SOFTWARE\Microsoft\Cryptography",
                "GetComputerNameExW",
                "GetNativeSystemInfo",
            ],
            ..Default::default()
        }
    }
    fn collect(
        &self,
        _ctx: &crate::collector::Ctx,
    ) -> Result<crate::collector::Contribution, String> {
        use super::{api::error, registry::Key};
        use windows_sys::Win32::Foundation::{GetLastError, ERROR_MORE_DATA};
        use windows_sys::Win32::System::SystemInformation::*;
        let os = Key::open(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")?;
        let bios = Key::open(r"HARDWARE\DESCRIPTION\System\BIOS")?;
        let crypto = Key::open(r"SOFTWARE\Microsoft\Cryptography")?;
        let product = os.string("ProductName")?;
        if product.is_empty() {
            return Err("registry ProductName is empty".into());
        }
        let build: u32 = os
            .string("CurrentBuildNumber")?
            .parse()
            .map_err(|e| format!("CurrentBuildNumber: {e}"))?;
        let ubr = os.dword("UBR")?;
        let release = os.string("DisplayVersion")?;
        let edition = os.string("EditionID")?;
        let installation = os.string("InstallationType")?;
        let vendor = bios.string("SystemManufacturer")?;
        let hardware = bios.string("SystemProductName")?;
        let ty = if installation.eq_ignore_ascii_case("Client") {
            "client"
        } else {
            "server"
        };
        let mut hostname = None;
        let mut buffer = vec![0u16; 256];
        for _ in 0..8 {
            let mut size = buffer.len() as u32;
            // SAFETY: buffer holds size UTF-16 elements and size is writable.
            if unsafe {
                GetComputerNameExW(ComputerNameDnsHostname, buffer.as_mut_ptr(), &mut size)
            } != 0
            {
                hostname = Some(String::from_utf16_lossy(&buffer[..size as usize]).to_lowercase());
                break;
            }
            // SAFETY: reads the current thread's last API error.
            let code = unsafe { GetLastError() };
            if code != ERROR_MORE_DATA {
                return Err(error("GetComputerNameExW", code));
            }
            buffer.resize(size as usize, 0);
        }
        let hostname = hostname
            .filter(|s| !s.is_empty())
            .ok_or("GetComputerNameExW: no hostname")?;
        // SAFETY: SYSTEM_INFO permits zero initialization; the API fills the entire structure.
        let mut info: SYSTEM_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: info points to writable SYSTEM_INFO storage.
        unsafe {
            GetNativeSystemInfo(&mut info);
        }
        // SAFETY: GetNativeSystemInfo initializes the processor architecture union field.
        let arch = match unsafe { info.Anonymous.Anonymous.wProcessorArchitecture } {
            PROCESSOR_ARCHITECTURE_AMD64 => "x86_64",
            PROCESSOR_ARCHITECTURE_ARM64 => "aarch64",
            PROCESSOR_ARCHITECTURE_INTEL => "x86",
            PROCESSOR_ARCHITECTURE_ARM => "arm",
            _ => "unknown",
        };
        let mut c = crate::collector::Contribution::default();
        c.host.kind = kind(&vendor, &hardware);
        c.host.name = hostname.clone();
        c.host
            .identifiers
            .push(nn_proto::Identifier::weak("hostname", hostname));
        c.host.attributes.extend([
            (
                "os.name".into(),
                windows_name(&product, build, &installation),
            ),
            ("os.release".into(), release.clone()),
            ("os.build".into(), format!("{build}.{ubr}")),
            ("os.edition".into(), edition.clone()),
            ("os.type".into(), ty.into()),
            ("machine.id".into(), crypto.string("MachineGuid")?),
            ("hw.vendor".into(), vendor),
            ("hw.product".into(), hardware),
            ("arch".into(), arch.into()),
        ]);
        c.host
            .components
            .push(component(build, ubr, &edition, &release, ty));
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn naming_and_vm_detection() {
        assert_eq!(
            windows_name("Windows 10 Pro", 22000, "Client"),
            "Windows 11 Pro"
        );
        assert_eq!(
            windows_name("Windows 10 Pro", 21999, "Client"),
            "Windows 10 Pro"
        );
        assert_eq!(
            windows_name("Windows Server 2025", 26100, "Server Core"),
            "Windows Server 2025"
        );
        for (vendor, product) in [
            ("QEMU", "Standard PC"),
            ("VMware, Inc.", "VM"),
            ("Oracle", "VirtualBox"),
            ("Microsoft Corporation", "Virtual Machine"),
            ("Xen", "HVM domU"),
            ("KVM", "PC"),
            ("Proxmox", "PC"),
        ] {
            assert_eq!(kind(vendor, product), EntityKind::Vm);
        }
        assert_eq!(kind("Microsoft Corporation", "Surface"), EntityKind::Host);
        let c = component(26100, 42, "Pro & More", "24H2", "client");
        assert_eq!(c.purl, "pkg:generic/microsoft/windows@10.0.26100.42?edition=Pro%20%26%20More&release=24H2&type=client");
    }
    #[cfg(windows)]
    #[test]
    fn live_os() {
        use crate::collector::{Collector, Ctx};
        let c = Os.collect(&Ctx::new("/".into())).unwrap();
        assert!(!c.host.name.is_empty());
        assert!(!c.host.attributes["os.name"].is_empty());
        assert_eq!(c.host.components.len(), 1);
        assert!(crate::config::Config::default().ctx(None).helper.is_none());
    }
}
