//! DNSSEC modes, validation outcomes, EDE codes, and metrics.

#[allow(clippy::wildcard_imports)]
use super::*;

/// DNSSEC validation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnssecMode {
    /// Strict validation: bogus queries result in SERVFAIL with EDE.
    #[default]
    Validate,
    /// Permissive validation: log bogus queries and clear AD bit, but return response.
    LogOnly,
    /// DNSSEC validation disabled.
    Disabled,
}

impl From<&str> for DnssecMode {
    fn from(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "log-only" | "log_only" | "log_fail" | "permissive" => Self::LogOnly,
            "disabled" | "off" => Self::Disabled,
            _ => Self::Validate,
        }
    }
}

/// Outcome of a DNSSEC validation check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// Valid signature chain to a trust anchor (AD=1).
    Secure,
    /// Unsigned domain or proof of non-existence of DNSSEC (AD=0).
    Insecure,
    /// Signature verification failed, signature expired, or broken chain.
    Bogus { reason: String, ede_code: u16 },
    /// Inconclusive validation (missing DNSSEC records).
    Indeterminate,
    /// Bypassed validation due to Negative Trust Anchor (NTA).
    NtaBypass,
}

impl ValidationOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Secure => "secure",
            Self::Insecure | Self::NtaBypass => "insecure",
            Self::Bogus { .. } => "bogus",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// RFC 8914 Extended DNS Error (EDE) codes.
pub const EDE_DNSSEC_BOGUS: u16 = 6;
pub const EDE_SIGNATURE_EXPIRED: u16 = 7;

/// Attach an RFC 8914 Extended DNS Error (EDE) option to a DNS response.
pub fn apply_ede(response: &mut Message, code: u16, extra_text: &str) {
    let mut edns = response.edns.clone().unwrap_or_else(|| {
        let mut e = Edns::new();
        e.set_max_payload(1232);
        e.set_version(0);
        e
    });

    let mut payload = Vec::with_capacity(2 + extra_text.len());
    payload.extend_from_slice(&code.to_be_bytes());
    payload.extend_from_slice(extra_text.as_bytes());
    // Replace any previous EDE option instead of appending duplicates.
    edns.options_mut()
        .options
        .retain(|(option_code, _)| u16::from(*option_code) != 15);
    edns.options_mut().insert(EdnsOption::Unknown(15, payload));
    response.set_edns(edns);
}

/// Telemetry metrics for DNSSEC validation.
#[derive(Default)]
pub struct DnssecMetrics {
    pub secure_total: AtomicU64,
    pub insecure_total: AtomicU64,
    pub bogus_total: AtomicU64,
    pub indeterminate_total: AtomicU64,
    pub nta_bypass_total: AtomicU64,
    /// DNSKEY lookups served from the validated-key cache.
    pub key_cache_hits: AtomicU64,
    /// DNSKEY lookups that had to be resolved from the response or upstream.
    pub key_cache_misses: AtomicU64,
    /// Cryptographic RRSIG verification attempts made while validating
    /// responses (bounded per response; see `MAX_VERIFICATIONS_PER_RESPONSE`).
    pub signature_verifications: AtomicU64,
    pub bogus_by_upstream_reason: DashMap<(String, String), AtomicU64>,
}

impl DnssecMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_validation(&self, outcome: &ValidationOutcome) {
        match outcome {
            ValidationOutcome::Secure => {
                self.secure_total.fetch_add(1, Ordering::Relaxed);
            }
            ValidationOutcome::Insecure => {
                self.insecure_total.fetch_add(1, Ordering::Relaxed);
            }
            ValidationOutcome::Bogus { .. } => {
                self.bogus_total.fetch_add(1, Ordering::Relaxed);
            }
            ValidationOutcome::Indeterminate => {
                self.indeterminate_total.fetch_add(1, Ordering::Relaxed);
            }
            ValidationOutcome::NtaBypass => {
                self.nta_bypass_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Records a validated-key cache lookup.
    pub fn record_key_cache(&self, hit: bool) {
        if hit {
            self.key_cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.key_cache_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Cumulative validated-key cache hits.
    #[must_use]
    pub fn key_cache_hits(&self) -> u64 {
        self.key_cache_hits.load(Ordering::Relaxed)
    }

    /// Cumulative validated-key cache misses.
    #[must_use]
    pub fn key_cache_misses(&self) -> u64 {
        self.key_cache_misses.load(Ordering::Relaxed)
    }

    /// Records one cryptographic RRSIG verification attempt.
    pub fn record_signature_verification(&self) {
        self.signature_verifications.fetch_add(1, Ordering::Relaxed);
    }

    /// Cumulative cryptographic RRSIG verification attempts.
    #[must_use]
    pub fn signature_verifications(&self) -> u64 {
        self.signature_verifications.load(Ordering::Relaxed)
    }

    pub fn record_bogus(&self, upstream: Option<&str>, reason: &str) {
        const MAX_BOGUS_REASON_ENTRIES: usize = 256;
        let key = (
            upstream.unwrap_or("unknown").to_string(),
            reason.to_string(),
        );
        if let Some(counter) = self.bogus_by_upstream_reason.get(&key) {
            counter.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if self.bogus_by_upstream_reason.len() >= MAX_BOGUS_REASON_ENTRIES {
            return;
        }
        self.bogus_by_upstream_reason
            .entry(key)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_validations(&self, result: &str) -> u64 {
        match result {
            "secure" => self.secure_total.load(Ordering::Relaxed),
            "insecure" => self.insecure_total.load(Ordering::Relaxed),
            "bogus" => self.bogus_total.load(Ordering::Relaxed),
            "indeterminate" => self.indeterminate_total.load(Ordering::Relaxed),
            "nta_bypass" => self.nta_bypass_total.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    pub fn get_bogus(&self, upstream: &str, reason: &str) -> u64 {
        self.bogus_by_upstream_reason
            .get(&(upstream.to_string(), reason.to_string()))
            .map_or(0, |val| val.load(Ordering::Relaxed))
    }
}
