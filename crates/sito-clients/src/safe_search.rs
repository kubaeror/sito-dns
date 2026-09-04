//! Safe search domain identification and target synthesis per table 9.3.
//!
//! Provides system rewrites for:
//! - Google: `forcesafesearch.google.com` (all regional Google TLDs)
//! - Bing: `strict.bing.com`
//! - YouTube: `restrict.youtube.com` (strict) or `restrictmoderate.youtube.com` (moderate)
//! - DuckDuckGo: `safe.duckduckgo.com`

use serde::{Deserialize, Serialize};

/// YouTube safe search restriction level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum YouTubeSafeSearchMode {
    #[default]
    Strict,
    Moderate,
}

impl YouTubeSafeSearchMode {
    pub fn target_cname(&self) -> &'static str {
        match self {
            Self::Strict => "restrict.youtube.com",
            Self::Moderate => "restrictmoderate.youtube.com",
        }
    }
}

/// Evaluates if a given query domain matches a search engine requiring
/// safe search enforcement, returning the target CNAME domain if so.
pub fn match_safe_search(
    domain: &str,
    youtube_mode: YouTubeSafeSearchMode,
) -> Option<&'static str> {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();

    // 1. YouTube
    if is_youtube_domain(&d) {
        return Some(youtube_mode.target_cname());
    }

    // 2. Google
    if is_google_search_domain(&d) {
        return Some("forcesafesearch.google.com");
    }

    // 3. Bing
    if is_bing_domain(&d) {
        return Some("strict.bing.com");
    }

    // 4. DuckDuckGo
    if is_duckduckgo_domain(&d) {
        return Some("safe.duckduckgo.com");
    }

    None
}

fn is_youtube_domain(d: &str) -> bool {
    matches!(
        d,
        "youtube.com"
            | "www.youtube.com"
            | "m.youtube.com"
            | "youtubei.googleapis.com"
            | "youtube.googleapis.com"
            | "www.youtube-nocookie.com"
            | "youtube-nocookie.com"
    )
}

fn is_bing_domain(d: &str) -> bool {
    matches!(d, "bing.com" | "www.bing.com" | "cn.bing.com")
}

fn is_duckduckgo_domain(d: &str) -> bool {
    matches!(
        d,
        "duckduckgo.com" | "www.duckduckgo.com" | "safe.duckduckgo.com"
    )
}

fn is_google_search_domain(d: &str) -> bool {
    // Strip optional "www." prefix
    let candidate = d.strip_prefix("www.").unwrap_or(d);

    if !candidate.starts_with("google.") {
        return false;
    }

    let suffix = &candidate["google.".len()..];

    // Check for standard multi-part TLDs: e.g. co.uk, com.au, co.jp, etc.
    // or single-part TLDs: com, de, fr, pl, ca, es, it, nl, etc.
    if suffix.is_empty() {
        return false;
    }

    // Common Google regional domain patterns
    let parts: Vec<&str> = suffix.split('.').collect();
    match parts.len() {
        1 => {
            // google.<tld>
            let tld = parts[0];
            tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
        }
        2 => {
            // google.co.<tld> or google.com.<tld>
            let (mid, tld) = (parts[0], parts[1]);
            (mid == "co" || mid == "com" || mid == "org" || mid == "net")
                && tld.len() >= 2
                && tld.chars().all(|c| c.is_ascii_alphabetic())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_google_safe_search() {
        let mode = YouTubeSafeSearchMode::Strict;
        assert_eq!(
            match_safe_search("google.com", mode),
            Some("forcesafesearch.google.com")
        );
        assert_eq!(
            match_safe_search("www.google.com", mode),
            Some("forcesafesearch.google.com")
        );
        assert_eq!(
            match_safe_search("google.co.uk", mode),
            Some("forcesafesearch.google.com")
        );
        assert_eq!(
            match_safe_search("www.google.de", mode),
            Some("forcesafesearch.google.com")
        );
        assert_eq!(
            match_safe_search("google.pl.", mode),
            Some("forcesafesearch.google.com")
        );
        assert_eq!(
            match_safe_search("google.com.au", mode),
            Some("forcesafesearch.google.com")
        );
        assert_eq!(match_safe_search("notgoogle.com", mode), None);
        assert_eq!(match_safe_search("google.something.fake.xyz", mode), None);
    }

    #[test]
    fn test_bing_safe_search() {
        let mode = YouTubeSafeSearchMode::Strict;
        assert_eq!(match_safe_search("bing.com", mode), Some("strict.bing.com"));
        assert_eq!(
            match_safe_search("www.bing.com.", mode),
            Some("strict.bing.com")
        );
        assert_eq!(
            match_safe_search("cn.bing.com", mode),
            Some("strict.bing.com")
        );
        assert_eq!(match_safe_search("bingo.com", mode), None);
    }

    #[test]
    fn test_youtube_safe_search() {
        assert_eq!(
            match_safe_search("youtube.com", YouTubeSafeSearchMode::Strict),
            Some("restrict.youtube.com")
        );
        assert_eq!(
            match_safe_search("www.youtube.com", YouTubeSafeSearchMode::Strict),
            Some("restrict.youtube.com")
        );
        assert_eq!(
            match_safe_search("m.youtube.com", YouTubeSafeSearchMode::Moderate),
            Some("restrictmoderate.youtube.com")
        );
        assert_eq!(
            match_safe_search("youtubei.googleapis.com", YouTubeSafeSearchMode::Moderate),
            Some("restrictmoderate.youtube.com")
        );
        assert_eq!(
            match_safe_search("notyoutube.com", YouTubeSafeSearchMode::Strict),
            None
        );
    }

    #[test]
    fn test_duckduckgo_safe_search() {
        let mode = YouTubeSafeSearchMode::Strict;
        assert_eq!(
            match_safe_search("duckduckgo.com", mode),
            Some("safe.duckduckgo.com")
        );
        assert_eq!(
            match_safe_search("www.duckduckgo.com", mode),
            Some("safe.duckduckgo.com")
        );
        assert_eq!(match_safe_search("duck.com", mode), None);
    }

    #[test]
    fn test_unrelated_domain_returns_none() {
        let mode = YouTubeSafeSearchMode::Strict;
        assert_eq!(match_safe_search("example.com", mode), None);
        assert_eq!(match_safe_search("github.com", mode), None);
        assert_eq!(match_safe_search("wikipedia.org", mode), None);
    }
}
