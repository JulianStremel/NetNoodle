//! `os`: operating system, kernel, host name, and the kind of machine.

use super::util;
use crate::collector::{Access, Collector, Contribution, Ctx};
use nn_proto::{EntityKind, Identifier};

pub struct Os;

fn read_trim(ctx: &Ctx, p: &str) -> String {
    std::fs::read_to_string(ctx.path(p))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Detects a container or a virtual machine from files that every user can read.
fn detect_kind(ctx: &Ctx) -> EntityKind {
    if ctx.path("/.dockerenv").exists() || ctx.path("/run/.containerenv").exists() {
        return EntityKind::Container;
    }
    let dmi = format!(
        "{} {}",
        read_trim(ctx, "/sys/class/dmi/id/sys_vendor"),
        read_trim(ctx, "/sys/class/dmi/id/product_name")
    )
    .to_lowercase();
    const VM: [&str; 8] = [
        "qemu",
        "kvm",
        "vmware",
        "virtualbox",
        "xen",
        "bochs",
        "virtual machine",
        "cloud hypervisor",
    ];
    if VM.iter().any(|v| dmi.contains(v)) {
        EntityKind::Vm
    } else {
        EntityKind::Host
    }
}

impl Collector for Os {
    fn name(&self) -> &'static str {
        "os"
    }

    fn access(&self) -> Access {
        Access {
            reads: vec![
                "/etc/os-release",
                "/usr/lib/os-release",
                "/etc/hostname",
                "/etc/machine-id",
                "/proc/sys/kernel/hostname",
                "/proc/sys/kernel/osrelease",
                "/sys/class/dmi/id/sys_vendor",
                "/sys/class/dmi/id/product_name",
                "/.dockerenv",
                "/run/.containerenv",
            ],
            ..Default::default()
        }
    }

    fn collect(&self, ctx: &Ctx) -> Result<Contribution, String> {
        let osr = util::os_release(ctx);
        if osr.is_empty() {
            return Err("no os-release file".into());
        }
        let mut c = Contribution::default();
        let h = &mut c.host;
        h.kind = detect_kind(ctx);
        let mut host = read_trim(ctx, "/proc/sys/kernel/hostname");
        if host.is_empty() {
            host = read_trim(ctx, "/etc/hostname");
        }
        if !host.is_empty() {
            h.name = host.clone();
            h.identifiers.push(Identifier::weak("hostname", host));
        }
        for (key, attr) in [
            ("ID", "os.id"),
            ("ID_LIKE", "os.id_like"),
            ("VERSION_ID", "os.version_id"),
            ("VERSION_CODENAME", "os.codename"),
            ("PRETTY_NAME", "os.name"),
        ] {
            if let Some(v) = osr.get(key).filter(|v| !v.is_empty()) {
                h.attributes.insert(attr.into(), v.clone());
            }
        }
        for (path, attr) in [
            ("/proc/sys/kernel/osrelease", "kernel.release"),
            ("/etc/machine-id", "machine.id"),
            ("/sys/class/dmi/id/sys_vendor", "hw.vendor"),
            ("/sys/class/dmi/id/product_name", "hw.product"),
        ] {
            let v = read_trim(ctx, path);
            if !v.is_empty() {
                h.attributes.insert(attr.into(), v);
            }
        }
        if ctx.is_live() {
            h.attributes
                .insert("arch".into(), std::env::consts::ARCH.into());
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debian_vm() {
        let ctx = super::super::testctx("debian");
        let c = Os.collect(&ctx).unwrap();
        assert_eq!(c.host.kind, EntityKind::Vm);
        assert_eq!(c.host.name, "web1");
        assert_eq!(c.host.attributes["os.id"], "debian");
        assert_eq!(c.host.attributes["os.version_id"], "12");
        assert_eq!(c.host.attributes["kernel.release"], "6.1.0-18-amd64");
        assert_eq!(
            c.host.identifiers,
            vec![Identifier::weak("hostname", "web1")]
        );
    }

    #[test]
    fn alpine_container() {
        let ctx = super::super::testctx("alpine");
        let c = Os.collect(&ctx).unwrap();
        assert_eq!(c.host.kind, EntityKind::Container);
    }
}
