//! Helpers shared by collectors: os-release, package URLs.

use crate::collector::Ctx;
use std::collections::BTreeMap;

/// Reads os-release (`/etc/os-release`, then `/usr/lib/os-release`).
pub fn os_release(ctx: &Ctx) -> BTreeMap<String, String> {
    for p in ["/etc/os-release", "/usr/lib/os-release"] {
        if let Ok(s) = std::fs::read_to_string(ctx.path(p)) {
            return parse_os_release(&s);
        }
    }
    BTreeMap::new()
}

/// Parses KEY=value lines. Values can be quoted with " or '.
pub fn parse_os_release(s: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = v.trim();
        let v = if v.len() >= 2
            && ((v.starts_with('"') && v.ends_with('"'))
                || (v.starts_with('\'') && v.ends_with('\'')))
        {
            let inner = &v[1..v.len() - 1];
            let mut out = String::with_capacity(inner.len());
            let mut esc = false;
            for c in inner.chars() {
                if esc {
                    out.push(c);
                    esc = false;
                } else if c == '\\' {
                    esc = true;
                } else {
                    out.push(c);
                }
            }
            out
        } else {
            v.to_string()
        };
        m.insert(k.trim().to_string(), v);
    }
    m
}

/// The `distro` qualifier: "<id>-<version_id>" (or codename), as Syft writes it.
pub fn distro(osr: &BTreeMap<String, String>) -> String {
    let id = osr.get("ID").map(String::as_str).unwrap_or("");
    let ver = osr
        .get("VERSION_ID")
        .or_else(|| osr.get("VERSION_CODENAME"))
        .map(String::as_str)
        .unwrap_or("");
    match (id, ver) {
        ("", _) => String::new(),
        (id, "") => id.to_string(),
        (id, v) => format!("{id}-{v}"),
    }
}

/// Percent-encodes everything except unreserved characters (RFC 3986).
pub fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Builds a package URL. Empty qualifiers are left out; the others are sorted.
pub fn purl(ty: &str, ns: &str, name: &str, version: &str, quals: &[(&str, &str)]) -> String {
    let mut s = format!("pkg:{ty}/");
    if !ns.is_empty() {
        s.push_str(&enc(ns));
        s.push('/');
    }
    s.push_str(&enc(name));
    if !version.is_empty() {
        s.push('@');
        s.push_str(&enc(version));
    }
    let mut q: Vec<_> = quals.iter().filter(|(_, v)| !v.is_empty()).collect();
    q.sort();
    for (i, (k, v)) in q.iter().enumerate() {
        s.push(if i == 0 { '?' } else { '&' });
        s.push_str(k);
        s.push('=');
        s.push_str(&enc(v));
    }
    s
}

/// Lower-case namespace from the os-release ID ("debian", "ubuntu", "rocky").
pub fn namespace(osr: &BTreeMap<String, String>, fallback: &str) -> String {
    osr.get("ID")
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| fallback.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_quotes() {
        let m = parse_os_release(
            "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID='12'\n# c\n",
        );
        assert_eq!(m["PRETTY_NAME"], "Debian GNU/Linux 12 (bookworm)");
        assert_eq!(m["VERSION_ID"], "12");
        assert_eq!(distro(&m), "debian-12");
    }

    #[test]
    fn purl_encoding() {
        assert_eq!(
            purl(
                "deb",
                "debian",
                "libssl3",
                "1:3.0.11-1~deb12u2",
                &[("distro", "debian-12"), ("arch", "amd64"), ("upstream", "")]
            ),
            "pkg:deb/debian/libssl3@1%3A3.0.11-1~deb12u2?arch=amd64&distro=debian-12"
        );
        assert_eq!(
            purl("deb", "debian", "g++", "", &[]),
            "pkg:deb/debian/g%2B%2B"
        );
    }
}
