//! Label interning pool mapping label strings to compact u32 identifiers.

use fnv::FnvHashMap;

/// Pool that interns domain labels into 32-bit integer IDs.
#[derive(Default, Debug, Clone)]
pub struct LabelInterner {
    labels: Vec<Box<str>>,
    map: FnvHashMap<String, u32>,
}

impl LabelInterner {
    /// Creates a new empty `LabelInterner`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Interns a label string, returning its assigned `u32` ID.
    pub fn intern(&mut self, label: &str) -> u32 {
        if let Some(&id) = self.map.get(label) {
            return id;
        }
        let id = self.labels.len() as u32;
        self.labels.push(label.into());
        self.map.insert(label.to_string(), id);
        id
    }

    /// Looks up the ID for an already interned label.
    pub fn lookup(&self, label: &str) -> Option<u32> {
        self.map.get(label).copied()
    }

    /// Retrieves the label string corresponding to an ID.
    pub fn get(&self, id: u32) -> Option<&str> {
        self.labels.get(id as usize).map(|s| &**s)
    }

    /// Number of unique interned labels.
    pub fn len(&self) -> usize {
        self.labels.len()
    }

    /// Returns true if no labels have been interned.
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_interner_roundtrip() {
        let mut interner = LabelInterner::new();
        let com = interner.intern("com");
        let example = interner.intern("example");
        let com_again = interner.intern("com");

        assert_eq!(com, com_again);
        assert_ne!(com, example);

        assert_eq!(interner.lookup("com"), Some(com));
        assert_eq!(interner.lookup("example"), Some(example));
        assert_eq!(interner.lookup("org"), None);

        assert_eq!(interner.get(com), Some("com"));
        assert_eq!(interner.get(example), Some("example"));
        assert_eq!(interner.get(999), None);
        assert_eq!(interner.len(), 2);
    }
}
