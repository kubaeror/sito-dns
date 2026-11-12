//! DNSKEY/DS policy helpers shared by verification.

#[allow(clippy::wildcard_imports)]
use super::*;

/// Allowed DNSKEY algorithms (RFC 8624). ED448 is not supported by the
/// underlying crypto backend and is therefore not usable for validation.
pub(super) fn allowed_dnskey_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::RSASHA256
            | Algorithm::RSASHA512
            | Algorithm::ECDSAP256SHA256
            | Algorithm::ECDSAP384SHA384
            | Algorithm::ED25519
    )
}

/// Allowed DS digest types (RFC 8624): SHA-256 and SHA-384 only.
pub(super) fn allowed_ds_digest(digest: DigestType) -> bool {
    matches!(digest, DigestType::SHA256 | DigestType::SHA384)
}

/// Bit length of the RSA modulus in a DNSKEY public key (RFC 3110 encoding).
pub(super) fn rsa_modulus_bits(encoded: &[u8]) -> Option<usize> {
    let (exponent_len, rest) = match encoded.split_first()? {
        (0, rest) if rest.len() >= 2 => {
            let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
            (len, &rest[2..])
        }
        (0, _) => return None,
        (len, rest) => (usize::from(*len), rest),
    };
    if exponent_len == 0 || rest.len() <= exponent_len {
        return None;
    }
    let modulus = &rest[exponent_len..];
    let significant = modulus.iter().position(|byte| *byte != 0)?;
    Some((modulus.len() - significant) * 8)
}

/// Whether a DNSKEY may be used for validation: zone key flag set, not
/// revoked, algorithm allowed by policy, and (for RSA) a modulus of at least
/// 2048 bits.
pub(super) fn dnskey_policy_ok(key: &DNSKEY) -> bool {
    if !key.zone_key() || key.revoke() || !allowed_dnskey_algorithm(key.algorithm()) {
        return false;
    }
    match key.algorithm() {
        Algorithm::RSASHA256 | Algorithm::RSASHA512 => {
            rsa_modulus_bits(key.public_key().public_bytes())
                .is_some_and(|bits| bits >= MIN_RSA_BITS)
        }
        _ => true,
    }
}

/// Identity of a validated DNSKEY: its full public-key bytes.
///
/// A 16-bit key tag is not a unique key identity (RFC 4035 §5.3.1): an
/// attacker can pair an anchored key with a same-tag forgery, so trust must
/// always be bound to the exact key material.
pub(super) fn dnskey_fingerprint(key: &DNSKEY) -> Vec<u8> {
    key.public_key().public_bytes().to_vec()
}

/// Whether two DNSKEYs carry the same public key material.
pub(super) fn same_public_key(a: &DNSKEY, b: &DNSKEY) -> bool {
    a.algorithm() == b.algorithm() && a.public_key().public_bytes() == b.public_key().public_bytes()
}
