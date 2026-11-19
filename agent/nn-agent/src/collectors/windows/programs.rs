use nn_proto::{Component, Confidence};
use std::collections::BTreeMap;

#[derive(Clone)]
struct Program {
    component: Component,
    location: String,
}

fn normalize(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_lowercase()
}

fn program(
    name: &str,
    version: &str,
    publisher: &str,
    arch: &str,
    location: &str,
    system: u32,
    parent_present: bool,
) -> Option<Program> {
    if name.trim().is_empty() || system == 1 || parent_present {
        return None;
    }
    let location = normalize(location);
    Some(Program {
        component: Component {
            purl: super::purl(
                "",
                name,
                version,
                &[("publisher", publisher), ("arch", arch)],
            ),
            name: name.into(),
            version: version.into(),
            confidence: Some(Confidence::High),
        },
        location: if location.is_empty() {
            location
        } else {
            format!("{}\\", location.trim_end_matches('\\'))
        },
    })
}

fn dedupe(programs: Vec<Program>) -> Vec<Program> {
    let mut out: BTreeMap<String, Program> = BTreeMap::new();
    for p in programs {
        out.entry(p.component.purl.clone())
            .and_modify(|old| {
                if old.location.is_empty() {
                    old.location = p.location.clone();
                }
            })
            .or_insert(p);
    }
    out.into_values().collect()
}

fn owners(programs: &[Program], paths: &[String]) -> BTreeMap<String, Component> {
    paths
        .iter()
        .filter_map(|path| {
            let normalized = normalize(path);
            programs
                .iter()
                .filter(|p| !p.location.is_empty() && normalized.starts_with(&p.location))
                .max_by_key(|p| p.location.len())
                .map(|p| (path.clone(), p.component.clone()))
        })
        .collect()
}

#[cfg(windows)]
fn installed() -> Result<Vec<Program>, String> {
    use super::registry::Key;
    let mut out = Vec::new();
    for (path, arch) in [
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            "x64",
        ),
        (
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "x86",
        ),
    ] {
        let Some(root) = Key::optional(path)? else {
            continue;
        };
        for name in root.names()? {
            let Some(key) = root.subkey(&name)? else {
                continue;
            };
            let display_name = key.string("DisplayName")?;
            let system = key.dword("SystemComponent")?;
            let parent_present = key.has("ParentKeyName")?;
            if display_name.trim().is_empty() || system == 1 || parent_present {
                continue;
            }
            if let Some(p) = program(
                &display_name,
                &key.string("DisplayVersion")?,
                &key.string("Publisher")?,
                arch,
                &key.string("InstallLocation")?,
                system,
                parent_present,
            ) {
                out.push(p);
            }
        }
    }
    // Keep every installation path for owners(); collect() deduplicates components.
    Ok(out)
}

#[cfg(windows)]
pub struct Programs;
#[cfg(windows)]
impl crate::collector::Collector for Programs {
    fn name(&self) -> &'static str {
        "programs"
    }
    fn access(&self) -> crate::collector::Access {
        crate::collector::Access {
            reads: vec![
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (64-bit view)",
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            ],
            ..Default::default()
        }
    }
    fn collect(
        &self,
        _ctx: &crate::collector::Ctx,
    ) -> Result<crate::collector::Contribution, String> {
        let mut c = crate::collector::Contribution::default();
        c.host.components = dedupe(installed()?)
            .into_iter()
            .map(|p| p.component)
            .collect();
        Ok(c)
    }
    fn owners(
        &self,
        _ctx: &crate::collector::Ctx,
        paths: &[String],
    ) -> BTreeMap<String, Component> {
        installed().map(|p| owners(&p, paths)).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filtering_deduplication_and_ownership() {
        for (name, system, parent) in [("", 0, false), ("Hidden", 1, false), ("Update", 0, true)] {
            assert!(program(name, "1", "", "x64", "", system, parent).is_none());
        }
        let p = program(
            "App + Tools",
            "1.2",
            "A & B",
            "x64",
            r"C:\Program Files\App\",
            0,
            false,
        )
        .unwrap();
        assert_eq!(
            p.component.purl,
            "pkg:generic/App%20%2B%20Tools@1.2?arch=x64&publisher=A%20%26%20B"
        );
        let child = program(
            "Nested",
            "1",
            "",
            "x86",
            r"C:\Program Files\App\nested",
            0,
            false,
        )
        .unwrap();
        let mut second = p.clone();
        second.location = r"d:\app\".into();
        let p = vec![p.clone(), p, child, second];
        assert_eq!(dedupe(p.clone()).len(), 2);
        let paths = vec![
            r"c:\PROGRAM FILES\app\app.exe".into(),
            r"C:\Program Files\AppOther\app.exe".into(),
            r"C:/Program Files/App/nested/bin.exe".into(),
            r"D:\App\app.exe".into(),
        ];
        let m = owners(&p, &paths);
        assert_eq!(m[&paths[0]].name, "App + Tools");
        assert!(!m.contains_key(&paths[1]));
        assert_eq!(m[&paths[2]].name, "Nested");
        assert_eq!(m[&paths[3]].name, "App + Tools");
    }
    #[cfg(windows)]
    #[test]
    fn live_programs() {
        use crate::collector::{Collector, Ctx};
        assert!(!Programs
            .collect(&Ctx::new("/".into()))
            .unwrap()
            .host
            .components
            .is_empty());
    }
}
