//! Runs the enabled collectors and joins their data into one host entity.

use crate::collector::{Collector, Contribution, Ctx};
use nn_proto::{Confidence, Entity, EntityKind, Observation, VERSION};
use std::collections::{BTreeMap, BTreeSet};

pub struct Report {
    pub entity: Entity,
    /// "collector: message" for each collector that failed.
    pub errors: Vec<String>,
}

fn merge(dst: &mut Entity, exes: &mut Vec<String>, c: Contribution) {
    let Contribution {
        host,
        mut service_exes,
        children,
    } = c;
    if dst.kind == EntityKind::Unknown {
        dst.kind = host.kind;
    }
    if dst.name.is_empty() {
        dst.name = host.name;
    }
    for id in host.identifiers {
        if !dst.identifiers.contains(&id) {
            dst.identifiers.push(id);
        }
    }
    dst.attributes.extend(host.attributes);
    dst.components.extend(host.components);
    service_exes.resize(host.services.len(), String::new());
    dst.services.extend(host.services);
    exes.extend(service_exes);
    dst.interfaces.extend(host.interfaces);
    dst.children.extend(children);
}

/// Runs the collectors. A failed collector is recorded and the others go on.
pub fn collect(ctx: &Ctx, collectors: &[Box<dyn Collector>]) -> Report {
    let mut e = Entity::default();
    let mut exes = Vec::new();
    let mut errors = Vec::new();
    for c in collectors {
        match c.collect(ctx) {
            Ok(contrib) => merge(&mut e, &mut exes, contrib),
            Err(msg) => errors.push(format!("{}: {msg}", c.name())),
        }
    }

    // Find the package of each listening program.
    let paths: Vec<String> = exes
        .iter()
        .filter(|p| !p.is_empty())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if !paths.is_empty() {
        let mut owners = BTreeMap::new();
        for c in collectors {
            for (k, v) in c.owners(ctx, &paths) {
                owners.entry(k).or_insert(v);
            }
        }
        for (svc, exe) in e.services.iter_mut().zip(&exes) {
            if let Some(comp) = owners.get(exe) {
                svc.component = comp.purl.clone();
                svc.product = comp.name.clone();
                svc.version = comp.version.clone();
                svc.confidence = Some(Confidence::High);
            }
        }
    }

    if e.kind == EntityKind::Unknown {
        e.kind = EntityKind::Host;
    }
    e.attributes
        .insert("agent.version".into(), env!("CARGO_PKG_VERSION").into());
    if !errors.is_empty() {
        e.attributes
            .insert("agent.errors".into(), errors.join("; "));
    }
    Report { entity: e, errors }
}

/// Wraps a report in an observation. The report is complete (it replaces
/// earlier package and service lists) only if no collector failed.
pub fn observation(r: Report, source: &str) -> Observation {
    Observation {
        version: VERSION.into(),
        source: source.into(),
        observed_at: humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string(),
        complete: r.errors.is_empty(),
        entities: vec![r.entity],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debian_fixture_end_to_end() {
        let ctx = crate::collectors::testctx("debian");
        let all = crate::collectors::all();
        let r = collect(&ctx, &all);
        // rpm finds no database and returns nothing; no collector fails.
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        let e = &r.entity;
        assert_eq!(e.kind, EntityKind::Vm);
        assert_eq!(e.name, "web1");
        assert_eq!(e.components.len(), 4);
        assert_eq!(e.services.len(), 4);
        assert_eq!(e.interfaces.len(), 2);
        let obs = observation(r, "agent-x");
        assert!(obs.complete);
        assert_eq!(obs.entities.len(), 1);
    }
}
