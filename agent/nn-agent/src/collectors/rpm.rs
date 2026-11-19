//! `rpm`: installed RPM packages (Fedora, RHEL and its rebuilds, SUSE).
//!
//! The rpm database has several formats (SQLite, Berkeley DB, ndb). The
//! collector runs the read-only query `rpm -qa` instead of reading them.

use super::util;
use crate::collector::{Access, Collector, Contribution, Ctx};
use nn_proto::{Component, Confidence};
use std::collections::BTreeMap;
use std::process::Command;

pub struct Rpm;

const QF: &str = "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkg {
    pub name: String,
    pub epoch: String,
    pub version: String,
    pub release: String,
    pub arch: String,
    pub source_rpm: String,
}

/// Parses the output of `rpm -qa --qf QF`.
pub fn parse_qa(s: &str) -> Vec<Pkg> {
    s.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.trim_end_matches('\r').split('\t').collect();
            if f.len() != 6 || f[0] == "gpg-pubkey" {
                return None;
            }
            let none = |v: &str| {
                if v == "(none)" {
                    String::new()
                } else {
                    v.to_string()
                }
            };
            Some(Pkg {
                name: f[0].into(),
                epoch: if f[1] == "0" {
                    String::new()
                } else {
                    none(f[1])
                },
                version: f[2].into(),
                release: f[3].into(),
                arch: none(f[4]),
                source_rpm: none(f[5]),
            })
        })
        .collect()
}

fn component(p: &Pkg, ns: &str, distro: &str) -> Component {
    let vr = format!("{}-{}", p.version, p.release);
    let upstream = p.source_rpm.trim_end_matches(".src.rpm");
    Component {
        purl: util::purl(
            "rpm",
            ns,
            &p.name,
            &vr,
            &[
                ("arch", &p.arch),
                ("epoch", &p.epoch),
                ("distro", distro),
                ("upstream", upstream),
            ],
        ),
        name: p.name.clone(),
        version: if p.epoch.is_empty() {
            vr
        } else {
            format!("{}:{vr}", p.epoch)
        },
        confidence: Some(Confidence::High),
    }
}

fn has_db(ctx: &Ctx) -> bool {
    ctx.path("/var/lib/rpm").is_dir() || ctx.path("/usr/lib/sysimage/rpm").is_dir()
}

fn rpm(ctx: &Ctx, args: &[&str]) -> Result<String, String> {
    let out = Command::new("rpm")
        .arg("--root")
        .arg(&ctx.root)
        .args(args)
        .output()
        .map_err(|e| format!("run rpm: {e}"))?;
    if !out.status.success() && out.stdout.is_empty() {
        return Err(format!(
            "rpm: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

impl Collector for Rpm {
    fn name(&self) -> &'static str {
        "rpm"
    }

    fn access(&self) -> Access {
        Access {
            reads: vec!["/var/lib/rpm/", "/usr/lib/sysimage/rpm/", "/etc/os-release"],
            execs: vec!["rpm -qa", "rpm -qf"],
            ..Default::default()
        }
    }

    fn collect(&self, ctx: &Ctx) -> Result<Contribution, String> {
        let mut c = Contribution::default();
        if !has_db(ctx) {
            return Ok(c);
        }
        let osr = util::os_release(ctx);
        let (ns, distro) = (util::namespace(&osr, "rpm"), util::distro(&osr));
        let out = rpm(ctx, &["-qa", "--qf", QF])?;
        c.host.components = parse_qa(&out)
            .iter()
            .map(|p| component(p, &ns, &distro))
            .collect();
        Ok(c)
    }

    fn owners(&self, ctx: &Ctx, paths: &[String]) -> BTreeMap<String, Component> {
        let mut out = BTreeMap::new();
        if !has_db(ctx) {
            return out;
        }
        let osr = util::os_release(ctx);
        let (ns, distro) = (util::namespace(&osr, "rpm"), util::distro(&osr));
        for path in paths {
            // One query per path: "not owned" answers would break line order.
            if let Ok(s) = rpm(ctx, &["-qf", "--qf", QF, path]) {
                if let Some(p) = parse_qa(&s).into_iter().next() {
                    out.insert(path.clone(), component(&p, &ns, &distro));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qa_output() {
        let s = "openssl-libs\t1\t3.0.7\t24.el9\tx86_64\topenssl-3.0.7-24.el9.src.rpm\n\
                 bash\t0\t5.1.8\t6.el9_1\tx86_64\tbash-5.1.8-6.el9_1.src.rpm\n\
                 gpg-pubkey\t0\tfd431d51\t4ae0493b\t(none)\t(none)\n";
        let pkgs = parse_qa(s);
        assert_eq!(pkgs.len(), 2);
        let c = component(&pkgs[0], "rocky", "rocky-9.3");
        assert_eq!(
            c.purl,
            "pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?arch=x86_64&distro=rocky-9.3&epoch=1&upstream=openssl-3.0.7-24.el9"
        );
        assert_eq!(c.version, "1:3.0.7-24.el9");
        assert_eq!(component(&pkgs[1], "rocky", "").version, "5.1.8-6.el9_1");
    }
}
