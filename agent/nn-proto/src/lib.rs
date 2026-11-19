//! netnoodle v1 wire types. These mirror `internal/proto/proto.go` and the
//! JSON Schemas in `api/v1`. Field names and enum spellings must match.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Protocol version carried in every envelope.
pub const VERSION: &str = "v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Strength {
    Strong,
    Weak,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identifier {
    pub kind: String,
    pub value: String,
    pub strength: Strength,
}

impl Identifier {
    pub fn strong(kind: &str, value: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            value: value.into(),
            strength: Strength::Strong,
        }
    }
    pub fn weak(kind: &str, value: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            value: value.into(),
            strength: Strength::Weak,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EntityKind {
    Host,
    Vm,
    Container,
    NetworkDevice,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Low,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    pub purl: String,
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Service {
    pub port: u16,
    pub proto: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub product: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub process: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub component: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub banner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Interface {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Entity {
    pub kind: EntityKind,
    pub identifiers: Vec<Identifier>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub attributes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<Component>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<Service>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<Interface>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent: Vec<Identifier>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Entity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub version: String,
    pub source: String,
    /// RFC 3339 time.
    pub observed_at: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub complete: bool,
    pub entities: Vec<Entity>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Capability {
    pub action: String,
    pub target_id_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_schema: Option<serde_json::Value>,
    pub reversible: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub revert_action: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActorHello {
    pub version: String,
    pub actor: String,
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Order {
    pub version: String,
    pub id: String,
    pub actor: String,
    pub action: String,
    pub targets: Vec<Identifier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default, rename = "ttl_seconds", skip_serializing_if = "is_zero")]
    pub ttl: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub revert: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub revert_of: String,
    pub not_after: String,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub meta: BTreeMap<String, String>,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// A signed order. `payload` and `signature` are base64 in JSON (Go `[]byte`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOrder {
    pub payload: String,
    pub signature: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Done,
    Failed,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderResult {
    pub version: String,
    pub order_id: String,
    pub status: OrderStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    pub at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_round_trip_uses_wire_names() {
        let obs = Observation {
            version: VERSION.into(),
            source: "agent-x".into(),
            observed_at: "2026-11-19T10:00:00Z".into(),
            complete: true,
            entities: vec![Entity {
                kind: EntityKind::NetworkDevice,
                identifiers: vec![Identifier::strong("mac", "aa:bb:cc:dd:ee:ff")],
                components: vec![Component {
                    purl: "pkg:deb/debian/nginx@1.22.1-9".into(),
                    name: "nginx".into(),
                    version: "1.22.1-9".into(),
                    confidence: Some(Confidence::High),
                }],
                ..Default::default()
            }],
        };
        let v: serde_json::Value = serde_json::to_value(&obs).unwrap();
        assert_eq!(v["entities"][0]["kind"], "network-device");
        assert_eq!(v["entities"][0]["identifiers"][0]["strength"], "strong");
        assert_eq!(v["complete"], true);
        assert!(v["entities"][0].get("children").is_none());
        let back: Observation = serde_json::from_value(v).unwrap();
        assert_eq!(back, obs);
    }

    #[test]
    fn order_ttl_field_name() {
        let o: Order = serde_json::from_str(
            r#"{"version":"v1","id":"1","actor":"a","action":"stop-service",
               "targets":[{"kind":"agent","value":"x","strength":"strong"}],
               "ttl_seconds":600,"not_after":"2026-11-19T10:00:00Z","nonce":"n"}"#,
        )
        .unwrap();
        assert_eq!(o.ttl, 600);
    }
}
