//! `dpkg`: installed Debian and Ubuntu packages.

use super::util;
use crate::collector::{Access, Collector, Contribution, Ctx};
use nn_proto::{Component, Confidence};
use std::collections::{BTreeMap, HashMap};

pub struct Dpkg;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkg {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub source: String,
    pub source_version: String,
}

/// Parses dpkg status paragraphs. Only installed packages are returned.
/// Paragraphs without a Status field (distroless `status.d`) count as installed.
pub fn parse_status(s: &str) -> Vec<Pkg> {
    let mut out = Vec::new();
    let s = s.replace("\r\n", "\n");
    for para in s.split("\n\n") {
        let mut f: HashMap<&str, &str> = HashMap::new();
        for line in para.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                continue; // continuation lines (Description, Conffiles)
            }
            if let Some((k, v)) = line.split_once(':') {
                f.insert(k.trim(), v.trim());
            }
        }
        let (Some(name), Some(version)) = (f.get("Package"), f.get("Version")) else {
            continue;
        };
        if let Some(st) = f.get("Status") {
            if st.split_whitespace().last() != Some("installed") {
                continue;
            }
        }
        let (mut source, mut source_version) = (String::new(), String::new());
        if let Some(src) = f.get("Source") {
            let mut it = src.splitn(2, ' ');
            source = it.next().unwrap_or("").to_string();
            if let Some(v) = it.next() {
                source_version = v.trim_matches(|c| c == '(' || c == ')').to_string();
            }
        }
        out.push(Pkg {
            name: name.to_string(),
            version: version.to_string(),
            arch: f.get("Architecture").unwrap_or(&"").to_string(),
            source,
            source_version,
        });
    }
    out
}

/// Turns a package into a component. The `upstream` qualifier names the
/// source package, which vulnerability databases use for Debian and Ubuntu.
pub fn component(p: &Pkg, ns: &str, distro: &str) -> Component {
    let upstream = match (p.source.as_str(), p.source_version.as_str()) {
        ("", _) => String::new(),
        (s, v) if v.is_empty() || v == p.version => s.to_string(),
        (s, v) => format!("{s}@{v}"),
    };
    Component {
        purl: util::purl(
            "deb",
            ns,
            &p.name,
            &p.version,
            &[
                ("arch", &p.arch),
                ("distro", distro),
                ("upstream", &upstream),
            ],
        ),
        name: p.name.clone(),
        version: p.version.clone(),
        confidence: Some(Confidence::High),
    }
}

fn read_all(ctx: &Ctx) -> Vec<Pkg> {
    let mut pkgs = Vec::new();
    if let Ok(s) = std::fs::read_to_string(ctx.path("/var/lib/dpkg/status")) {
        pkgs.extend(parse_status(&s));
    }
    if let Ok(rd) = std::fs::read_dir(ctx.path("/var/lib/dpkg/status.d")) {
        let mut files: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        files.sort();
        for f in files {
            if f.extension().is_some_and(|e| e == "md5sums") {
                continue;
            }
            if let Ok(s) = std::fs::read_to_string(&f) {
                pkgs.extend(parse_status(&s));
            }
        }
    }
    pkgs
}

/// The same file can be at /bin/x and /usr/bin/x (merged /usr).
pub fn path_variants(p: &str) -> Vec<String> {
    match p.strip_prefix("/usr") {
        Some(rest) if rest.starts_with('/') => vec![p.to_string(), rest.to_string()],
        _ => vec![p.to_string(), format!("/usr{p}")],
    }
}

impl Collector for Dpkg {
    fn name(&self) -> &'static str {
        "dpkg"
    }

    fn access(&self) -> Access {
        Access {
            reads: vec![
                "/var/lib/dpkg/status",
                "/var/lib/dpkg/status.d/",
                "/var/lib/dpkg/info/*.list",
                "/etc/os-release",
            ],
            ..Default::default()
        }
    }

    fn collect(&self, ctx: &Ctx) -> Result<Contribution, String> {
        let mut c = Contribution::default();
        if !ctx.path("/var/lib/dpkg").is_dir() {
            return Ok(c);
        }
        let osr = util::os_release(ctx);
        let (ns, distro) = (util::namespace(&osr, "debian"), util::distro(&osr));
        c.host.components = read_all(ctx)
            .iter()
            .map(|p| component(p, &ns, &distro))
            .collect();
        Ok(c)
    }

    fn owners(&self, ctx: &Ctx, paths: &[String]) -> BTreeMap<String, Component> {
        let mut out = BTreeMap::new();
        let Ok(rd) = std::fs::read_dir(ctx.path("/var/lib/dpkg/info")) else {
            return out;
        };
        // variant path -> wanted path
        let mut want: HashMap<String, &String> = HashMap::new();
        for p in paths {
            for v in path_variants(p) {
                want.insert(v, p);
            }
        }
        let mut owner: HashMap<&String, String> = HashMap::new();
        for e in rd.flatten() {
            let fname = e.file_name().to_string_lossy().to_string();
            let Some(pkg) = fname.strip_suffix(".list") else {
                continue;
            };
            let pkg = pkg.split(':').next().unwrap_or(pkg).to_string();
            let Ok(s) = std::fs::read_to_string(e.path()) else {
                continue;
            };
            for line in s.lines() {
                if let Some(p) = want.get(line.trim_end()) {
                    owner.entry(p).or_insert_with(|| pkg.clone());
                }
            }
        }
        if owner.is_empty() {
            return out;
        }
        let osr = util::os_release(ctx);
        let (ns, distro) = (util::namespace(&osr, "debian"), util::distro(&osr));
        let pkgs = read_all(ctx);
        for (path, pkg) in owner {
            if let Some(p) = pkgs.iter().find(|p| p.name == pkg) {
                out.insert(path.clone(), component(p, &ns, &distro));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_parsing() {
        let ctx = super::super::testctx("debian");
        let c = Dpkg.collect(&ctx).unwrap();
        let purls: Vec<_> = c.host.components.iter().map(|c| c.purl.as_str()).collect();
        assert_eq!(
            purls,
            vec![
                "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl",
                "pkg:deb/debian/nginx-core@1.22.1-9?arch=amd64&distro=debian-12&upstream=nginx",
                "pkg:deb/debian/libc6@2.36-9%2Bdeb12u4?arch=amd64&distro=debian-12&upstream=glibc",
                "pkg:deb/debian/python3-six@1.16.0-4?arch=all&distro=debian-12&upstream=six%401.16.0-3",
            ]
        );
    }

    #[test]
    fn owner_of_program() {
        let ctx = super::super::testctx("debian");
        let o = Dpkg.owners(&ctx, &["/usr/sbin/nginx".into(), "/opt/x".into()]);
        assert_eq!(o.len(), 1);
        assert_eq!(o["/usr/sbin/nginx"].name, "nginx-core");
    }
}
