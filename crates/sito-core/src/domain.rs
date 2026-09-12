//! Domain matching helpers shared by filtering, blocking and rewrite code.

/// Returns true when `candidate` equals `suffix` or is a subdomain of it.
///
/// Both values are expected to be normalized (lowercase, trailing dot
/// removed). This avoids per-query `format!(".{suffix}")` allocations on the
/// hot path.
#[must_use]
pub fn matches_domain_suffix(candidate: &str, suffix: &str) -> bool {
    if suffix.is_empty() {
        return false;
    }
    if candidate == suffix {
        return true;
    }
    candidate.len() > suffix.len()
        && candidate.ends_with(suffix)
        && candidate.as_bytes()[candidate.len() - suffix.len() - 1] == b'.'
}

/// Like [`matches_domain_suffix`] but requires the candidate to be a strict
/// subdomain (never the suffix itself).
#[must_use]
pub fn matches_strict_subdomain(candidate: &str, suffix: &str) -> bool {
    candidate != suffix && matches_domain_suffix(candidate, suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_domain_suffix() {
        assert!(matches_domain_suffix("example.com", "example.com"));
        assert!(matches_domain_suffix("sub.example.com", "example.com"));
        assert!(matches_domain_suffix("a.b.example.com", "example.com"));
        assert!(!matches_domain_suffix("notexample.com", "example.com"));
        assert!(!matches_domain_suffix("example.com.evil", "example.com"));
        assert!(!matches_domain_suffix("example.co", "example.com"));
        assert!(!matches_domain_suffix("anything", ""));

        assert!(!matches_strict_subdomain("example.com", "example.com"));
        assert!(matches_strict_subdomain("sub.example.com", "example.com"));
    }
}
