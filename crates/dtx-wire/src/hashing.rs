use crate::{CanonicalCborError, CanonicalEncode, Sha256Digest, encode_deterministic_cbor};

/// Domain separator for v1 Job plan hashes, including its trailing NUL.
pub const PLAN_HASH_DOMAIN: &[u8] = b"dirextalk.job-plan.v1\0";

/// Computes the v1 domain-separated hash of a canonical Job plan body.
///
/// The hash is deliberately generic in S0.3: JOB2 owns the complete production
/// `JobPlanBodyV1` schema. The body implementation must expose every approved
/// field through [`CanonicalEncode`], and the stored hash is never part of that body.
///
/// # Errors
///
/// Returns [`CanonicalCborError`] when the body violates encoding limits or
/// contains a duplicate map key.
pub fn plan_hash<T>(body: &T) -> Result<Sha256Digest, CanonicalCborError>
where
    T: CanonicalEncode + ?Sized,
{
    let encoded = encode_deterministic_cbor(body)?;
    Ok(Sha256Digest::hash_domain(PLAN_HASH_DOMAIN, &encoded))
}
