//! `apk`: installed Alpine packages.

use super::util;
use crate::collector::{Access, Collector, Contribution, Ctx};
use nn_proto::{Component, Confidence};
use std::collections::BTreeMap;

pub struct Apk;

const DB: &str = "/lib/apk/db/installed";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Pkg {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub origin: String,
    /// Files of the package, as absolute paths.
    pub files: Vec<String>,
}

/// Parses the apk database: records separated by blank lines, `X:value` lines.
pub fn parse_installed(s: &str) -> Vec<Pkg> {
    let mut out = Vec::new();
    let mut cur = Pkg::default();
    let mut dir = String::new();
    let flush = |cur: &mut Pkg, out: &mut Vec<Pkg>| {
        if !cur.name.is_empty() && !cur.version.is_empty() {
            out.push(std::mem::take(cur));
        } else {
            *cur = Pkg::default();
        }
    };
    for line in s.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            flush(&mut cur, &mut out);
            dir.clear();
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        match k {
            "P" => cur.name = v.to_string(),
            "V" => cur.version = v.to_string(),
            "A" => cur.arch = v.to_string(),
            "o" => cur.origin = v.to_string(),
            "F" => dir = v.to_string(),
            "R" => cur.files.push(format!("/{dir}/{v}").replace("//", "/")),
            _ => {}
        }
    }
    flush(&mut cur, &mut out);
    out
}

fn component(p: &Pkg, distro: &str) -> Component {
    let upstream = if p.origin != p.name {
        p.origin.as_str()
    } else {
        ""
    };
    Component {
        purl: util::purl(
            "apk",
            "alpine",
            &p.name,
            &p.version,
            &[
                ("arch", &p.arch),
                ("distro", distro),
                ("upstream", upstream),
            ],
        ),
        name: p.name.clone(),
        version: p.version.clone(),
        confidence: Some(Confidence::High),
    }
}

fn distro(ctx: &Ctx) -> String {
    let osr = util::os_release(ctx);
    match osr.get("VERSION_ID") {
        Some(v) => format!("alpine-{v}"),
        None => String::new(),
    }
}

fn read(ctx: &Ctx) -> Option<Vec<Pkg>> {
    std::fs::read_to_string(ctx.path(DB))
        .ok()
        .map(|s| parse_installed(&s))
}

impl Collector for Apk {
    fn name(&self) -> &'static str {
        "apk"
    }

    fn access(&self) -> Access {
        Access {
            reads: vec![DB, "/etc/os-release"],
            ..Default::default()
        }
    }

    fn collect(&self, ctx: &Ctx) -> Result<Contribution, String> {
        let mut c = Contribution::default();
        if let Some(pkgs) = read(ctx) {
            let d = distro(ctx);
            c.host.components = pkgs.iter().map(|p| component(p, &d)).collect();
        }
        Ok(c)
    }

    fn owners(&self, ctx: &Ctx, paths: &[String]) -> BTreeMap<String, Component> {
        let mut out = BTreeMap::new();
        let Some(pkgs) = read(ctx) else {
            return out;
        };
        let d = distro(ctx);
        for path in paths {
            let variants = super::dpkg::path_variants(path);
            if let Some(p) = pkgs
                .iter()
                .find(|p| p.files.iter().any(|f| variants.contains(f)))
            {
                out.insert(path.clone(), component(p, &d));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn installed_db() {
        let ctx = super::super::testctx("alpine");
        let c = Apk.collect(&ctx).unwrap();
        let purls: Vec<_> = c.host.components.iter().map(|c| c.purl.as_str()).collect();
        assert_eq!(
            purls,
            vec![
                "pkg:apk/alpine/musl@1.2.4_git20230717-r4?arch=x86_64&distro=alpine-3.19.1",
                "pkg:apk/alpine/libcrypto3@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1&upstream=openssl",
                "pkg:apk/alpine/dropbear@2022.83-r4?arch=x86_64&distro=alpine-3.19.1",
            ]
        );
        let o = Apk.owners(&ctx, &["/usr/sbin/dropbear".into()]);
        assert_eq!(o["/usr/sbin/dropbear"].name, "dropbear");
    }
}
