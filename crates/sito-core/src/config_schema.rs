//! Config schema inventory and unknown-key enforcement.
//!
//! The authoritative v1→v2 field map is the checked-in
//! `crates/sito-core/config-v1-to-v2-map.toml`. It lives inside this package
//! so `include_str!` works for `cargo package`, and is embedded at compile
//! time so production validation and the migration tool use exactly the list
//! that CI verifies against the serde schema.

use crate::error::ConfigError;
use serde::Deserialize;
use std::sync::OnceLock;

/// The checked-in v1→v2 map, embedded at compile time.
pub const MAP_TOML: &str = include_str!("../config-v1-to-v2-map.toml");

/// Migration status of one configuration field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldStatus {
    /// Same path and meaning in v2; copied unchanged.
    Kept,
    /// Accepted for one 2.0 alpha and rewritten to `to` by the migration.
    Deprecated,
    /// No longer accepted in v2; the migration drops and reports it.
    Removed,
    /// Parsed historically but never used; the migration drops and reports it.
    Dead,
}

/// One field in the config v1→v2 map.
#[derive(Debug, Clone)]
pub struct SchemaField {
    /// Dotted path in the v1 document (`entries[].name`, `groups.*.lists`).
    pub path: String,
    pub status: FieldStatus,
    /// Canonical v2 path for deprecated aliases.
    pub to: Option<String>,
    segments: Vec<Segment>,
}

/// A parsed path segment.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    /// One arbitrary map key (`clients.groups.*`).
    Wildcard,
    /// Array element (`entries[]`).
    Array,
}

#[derive(Debug, Deserialize)]
struct MapFile {
    #[serde(rename = "schema_version")]
    format_version: u32,
    from_version: u32,
    to_version: u32,
    #[serde(default, rename = "field")]
    fields: Vec<MapEntry>,
}

#[derive(Debug, Deserialize)]
struct MapEntry {
    path: String,
    status: FieldStatus,
    #[serde(default)]
    to: Option<String>,
}

/// Parsed map.
#[derive(Debug)]
pub struct Schema {
    format_version: u32,
    from_version: u32,
    to_version: u32,
    fields: Vec<SchemaField>,
}

static SCHEMA: OnceLock<Schema> = OnceLock::new();

/// Returns the embedded schema. Panics only if the checked-in map is corrupt;
/// `test_map_is_well_formed` guarantees this in CI.
#[must_use]
pub fn schema() -> &'static Schema {
    SCHEMA.get_or_init(|| {
        Schema::from_toml(MAP_TOML).expect("embedded config-v1-to-v2-map.toml must be valid")
    })
}

impl Schema {
    fn from_toml(document: &str) -> Result<Self, String> {
        let map: MapFile = toml::from_str(document).map_err(|e| e.to_string())?;
        if map.format_version != 2 {
            return Err(format!(
                "config map schema_version must be 2, got {}",
                map.format_version
            ));
        }
        let fields: Vec<SchemaField> = map
            .fields
            .into_iter()
            .map(|entry| SchemaField {
                segments: parse_path(&entry.path),
                path: entry.path,
                status: entry.status,
                to: entry.to,
            })
            .collect();
        Ok(Self {
            format_version: map.format_version,
            from_version: map.from_version,
            to_version: map.to_version,
            fields,
        })
    }

    #[must_use]
    pub fn schema_version(&self) -> u32 {
        self.format_version
    }

    #[must_use]
    pub fn from_version(&self) -> u32 {
        self.from_version
    }

    #[must_use]
    pub fn to_version(&self) -> u32 {
        self.to_version
    }

    /// Every field in the map, in file order.
    #[must_use]
    pub fn fields(&self) -> &[SchemaField] {
        &self.fields
    }

    /// Looks up an exact path (no wildcard/index expansion).
    #[must_use]
    pub fn field(&self, path: &str) -> Option<&SchemaField> {
        let segments = parse_path(path);
        self.fields.iter().find(|field| field.segments == segments)
    }

    /// Looks up a document path, expanding `*` map segments.
    #[must_use]
    pub fn matching_field(&self, path: &str) -> Option<&SchemaField> {
        let segments = parse_path(path);
        self.fields
            .iter()
            .find(|field| path_matches(&field.segments, &segments))
    }

    /// True when `candidate` is a prefix of a schema path (so a table or array
    /// may recurse into it).
    fn is_prefix(&self, candidate: &[Segment]) -> bool {
        self.fields
            .iter()
            .any(|field| prefix_matches(&field.segments, candidate))
    }

    fn exact(&self, candidate: &[Segment]) -> Option<&SchemaField> {
        self.fields
            .iter()
            .find(|field| path_matches(&field.segments, candidate))
    }

    /// Returns every key in `table` that does not exist in the map (v1
    /// interpretation: removed/dead keys are known).
    #[must_use]
    pub fn unknown_keys(&self, table: &toml::Table) -> Vec<String> {
        let mut unknown = Vec::new();
        for (key, value) in table {
            let mut segments = Vec::new();
            let mut display = Vec::new();
            self.collect_unknown(value, &mut segments, &mut display, key, &mut unknown);
        }
        unknown
    }

    fn collect_unknown(
        &self,
        value: &toml::Value,
        segments: &mut Vec<Segment>,
        display: &mut Vec<String>,
        key: &str,
        unknown: &mut Vec<String>,
    ) {
        segments.push(Segment::Literal(key.to_string()));
        display.push(key.to_string());
        if self.is_prefix(segments) {
            self.descend(value, segments, display, unknown);
        } else {
            unknown.push(display.join("."));
        }
        display.pop();
        segments.pop();
    }

    fn descend(
        &self,
        value: &toml::Value,
        segments: &mut Vec<Segment>,
        display: &mut Vec<String>,
        unknown: &mut Vec<String>,
    ) {
        match value {
            toml::Value::Table(table) => {
                for (key, child) in table {
                    self.collect_unknown(child, segments, display, key, unknown);
                }
            }
            toml::Value::Array(items) => {
                // A leaf array (`dns.bind`, `acme.domains`) has no element
                // fields; every scalar element was accepted by the parent
                // key's map entry.
                if self.exact(segments).is_some() {
                    return;
                }
                segments.push(Segment::Array);
                if !self.is_prefix(segments) && self.exact(segments).is_none() {
                    unknown.push(format!("{}[]", display.join(".")));
                } else {
                    for (index, item) in items.iter().enumerate() {
                        let Some(original) = display.last().cloned() else {
                            continue;
                        };
                        if let Some(last) = display.last_mut() {
                            *last = format!("{original}[{index}]");
                        }
                        self.descend(item, segments, display, unknown);
                        if let Some(last) = display.last_mut() {
                            *last = original;
                        }
                    }
                }
                segments.pop();
            }
            toml::Value::String(_)
            | toml::Value::Integer(_)
            | toml::Value::Float(_)
            | toml::Value::Boolean(_)
            | toml::Value::Datetime(_) => {
                // A scalar where the map expects a table/array is a type
                // error, not an unknown key; the typed parser reports it with
                // the section's own field path.
                if self.exact(segments).is_none() && !self.is_prefix(segments) {
                    unknown.push(display.join("."));
                }
            }
        }
    }

    /// Removes every unknown key from `table`, returning the removed paths.
    pub fn remove_unknown_keys(&self, table: &mut toml::Table) -> Vec<String> {
        let mut removed = Vec::new();
        remove_unknown_in_table(self, table, &mut Vec::new(), &mut Vec::new(), &mut removed);
        removed
    }

    /// Validates a fully parsed v2 document against the map: unknown keys are
    /// rejected, and keys removed in v2 are rejected with a migration hint.
    pub fn validate_v2_document(&self, table: &toml::Table) -> Result<(), ConfigError> {
        let mut failure = None;
        self.check_v2_table(table, &mut Vec::new(), &mut Vec::new(), &mut failure);
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn check_v2_table(
        &self,
        table: &toml::Table,
        segments: &mut Vec<Segment>,
        display: &mut Vec<String>,
        failure: &mut Option<ConfigError>,
    ) {
        for (key, value) in table {
            segments.push(Segment::Literal(key.clone()));
            display.push(key.clone());
            if !self.is_prefix(segments) {
                *failure = Some(ConfigError::UnknownKey {
                    section: display.first().cloned().unwrap_or_default(),
                    key: display.join("."),
                });
                display.pop();
                segments.pop();
                return;
            }
            if let Some(field) = self.exact(segments)
                && matches!(field.status, FieldStatus::Removed | FieldStatus::Dead)
            {
                *failure = Some(ConfigError::RemovedKey {
                    key: display.join("."),
                    replaced_by: field.to.clone(),
                });
                display.pop();
                segments.pop();
                return;
            }
            self.check_v2_value(value, segments, display, failure);
            display.pop();
            segments.pop();
            if failure.is_some() {
                return;
            }
        }
    }

    fn check_v2_value(
        &self,
        value: &toml::Value,
        segments: &mut Vec<Segment>,
        display: &mut Vec<String>,
        failure: &mut Option<ConfigError>,
    ) {
        match value {
            toml::Value::Table(table) => {
                self.check_v2_table(table, segments, display, failure);
            }
            toml::Value::Array(items) => {
                // A leaf array (scalar elements) is fully described by its
                // parent key; a removed leaf array still fails closed.
                if let Some(field) = self.exact(segments) {
                    if matches!(field.status, FieldStatus::Removed | FieldStatus::Dead) {
                        *failure = Some(ConfigError::RemovedKey {
                            key: display.join("."),
                            replaced_by: field.to.clone(),
                        });
                    }
                    return;
                }
                segments.push(Segment::Array);
                if !self.is_prefix(segments) && self.exact(segments).is_none() {
                    *failure = Some(ConfigError::UnknownKey {
                        section: display.first().cloned().unwrap_or_default(),
                        key: format!("{}[]", display.join(".")),
                    });
                } else {
                    for (index, item) in items.iter().enumerate() {
                        let Some(original) = display.last().cloned() else {
                            continue;
                        };
                        if let Some(last) = display.last_mut() {
                            *last = format!("{original}[{index}]");
                        }
                        self.check_v2_value(item, segments, display, failure);
                        if let Some(last) = display.last_mut() {
                            *last = original;
                        }
                        if failure.is_some() {
                            break;
                        }
                    }
                }
                segments.pop();
            }
            _ => {
                match self.exact(segments) {
                    None if self.is_prefix(segments) => {
                        // Wrong value type for a known table/array path;
                        // the typed deserializer reports it.
                    }
                    None => {
                        *failure = Some(ConfigError::UnknownKey {
                            section: display.first().cloned().unwrap_or_default(),
                            key: display.join("."),
                        });
                    }
                    Some(field)
                        if matches!(field.status, FieldStatus::Removed | FieldStatus::Dead) =>
                    {
                        *failure = Some(ConfigError::RemovedKey {
                            key: display.join("."),
                            replaced_by: field.to.clone(),
                        });
                    }
                    Some(_) => {}
                }
            }
        }
    }
}

fn remove_unknown_in_table(
    schema: &Schema,
    table: &mut toml::Table,
    segments: &mut Vec<Segment>,
    display: &mut Vec<String>,
    removed: &mut Vec<String>,
) {
    let keys: Vec<String> = table.keys().cloned().collect();
    for key in keys {
        segments.push(Segment::Literal(key.clone()));
        display.push(key.clone());
        if !schema.is_prefix(segments) {
            table.remove(&key);
            removed.push(display.join("."));
        } else if let Some(value) = table.get_mut(&key) {
            remove_unknown_in_value(schema, value, segments, display, removed);
        }
        display.pop();
        segments.pop();
    }
}

fn remove_unknown_in_value(
    schema: &Schema,
    value: &mut toml::Value,
    segments: &mut Vec<Segment>,
    display: &mut Vec<String>,
    removed: &mut Vec<String>,
) {
    match value {
        toml::Value::Table(table) => {
            remove_unknown_in_table(schema, table, segments, display, removed);
        }
        toml::Value::Array(items) => {
            if schema.exact(segments).is_some() {
                return;
            }
            segments.push(Segment::Array);
            if !schema.is_prefix(segments) && schema.exact(segments).is_none() {
                // The whole array is unknown. Remove it by clearing the value;
                // callers re-check the parent table afterwards.
                *value = toml::Value::Array(Vec::new());
                removed.push(format!("{}[]", display.join(".")));
            } else {
                for (index, item) in items.iter_mut().enumerate() {
                    let Some(original) = display.last().cloned() else {
                        continue;
                    };
                    if let Some(last) = display.last_mut() {
                        *last = format!("{original}[{index}]");
                    }
                    remove_unknown_in_value(schema, item, segments, display, removed);
                    if let Some(last) = display.last_mut() {
                        *last = original;
                    }
                }
            }
            segments.pop();
        }
        _ => {
            if schema.exact(segments).is_none() {
                // Caller already decided this key is known as a prefix; a
                // scalar at a prefix path is malformed, leave it for the
                // typed parser to reject.
            }
        }
    }
}

fn parse_path(path: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    for part in path.split('.') {
        if part == "*" {
            segments.push(Segment::Wildcard);
        } else if let Some(base) = part.strip_suffix("[]") {
            if !base.is_empty() {
                segments.push(Segment::Literal(base.to_string()));
            }
            segments.push(Segment::Array);
        } else {
            segments.push(Segment::Literal(part.to_string()));
        }
    }
    segments
}

fn segment_matches(pattern: &Segment, candidate: &Segment) -> bool {
    match (pattern, candidate) {
        (Segment::Literal(left), Segment::Literal(right)) => left == right,
        (Segment::Wildcard, Segment::Literal(_)) | (Segment::Array, Segment::Array) => true,
        _ => false,
    }
}

fn prefix_matches(pattern: &[Segment], candidate: &[Segment]) -> bool {
    candidate.len() <= pattern.len()
        && pattern
            .iter()
            .zip(candidate)
            .all(|(pattern, candidate)| segment_matches(pattern, candidate))
}

fn path_matches(pattern: &[Segment], candidate: &[Segment]) -> bool {
    pattern.len() == candidate.len()
        && pattern
            .iter()
            .zip(candidate)
            .all(|(pattern, candidate)| segment_matches(pattern, candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_map_is_well_formed() {
        let schema = schema();
        assert_eq!(schema.schema_version(), 2);
        assert_eq!(schema.from_version(), 1);
        assert_eq!(schema.to_version(), 2);

        let mut seen = HashSet::new();
        for field in schema.fields() {
            assert!(
                seen.insert(field.path.clone()),
                "duplicate map path: {}",
                field.path
            );
            match field.status {
                FieldStatus::Deprecated => {
                    assert!(
                        field.to.is_some(),
                        "deprecated field '{}' must name its v2 path",
                        field.path
                    );
                }
                _ => assert!(
                    field.to.is_none(),
                    "field '{}' has status {:?} but a `to` path",
                    field.path,
                    field.status
                ),
            }
        }

        for required in [
            "config_version",
            "server.role",
            "dns.bind",
            "web.bind",
            "acme.enabled",
            "clients.entries[].name",
            "integrations.lists.categories.*.url",
        ] {
            assert!(
                schema.field(required).is_some(),
                "map is missing required field '{required}'"
            );
        }
    }

    #[test]
    fn test_unknown_and_removed_detection() {
        let schema = schema();
        let table: toml::Table =
            toml::from_str("[dns]\nbogus = 1\n[auth]\nadmin_password_hash = \"x\"\n").unwrap();
        assert_eq!(schema.unknown_keys(&table), vec!["dns.bogus"]);

        let err = schema
            .validate_v2_document(&toml::from_str("[dns]\nbogus = 1\n").unwrap())
            .expect_err("unknown key must be rejected in v2");
        assert!(matches!(
            err,
            ConfigError::UnknownKey { ref key, .. } if key == "dns.bogus"
        ));

        let removed = schema
            .validate_v2_document(&toml::from_str("[auth]\nadmin_password_hash = \"x\"\n").unwrap())
            .expect_err("removed key must be rejected in v2");
        assert!(matches!(removed, ConfigError::RemovedKey { .. }));
    }
}
