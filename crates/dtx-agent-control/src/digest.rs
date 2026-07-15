use std::fmt;

use sha2::{Digest, Sha256};

const RUN_FAILED_REPORT_DOMAIN: &[u8] = b"dirextalk.run-failed-report.v1";

/// Fixed SHA-256 digest used for non-secret control-plane commitments.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Rehydrates a digest from its exact bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn ct_eq(self, other: Self) -> bool {
        self.0
            .iter()
            .zip(other.0)
            .fold(0_u8, |difference, (left, right)| {
                difference | (*left ^ right)
            })
            == 0
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest(<redacted>)")
    }
}

pub(crate) fn domain_digest(domain: &[u8], parts: &[&[u8]]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    update_part(&mut hasher, domain);
    for part in parts {
        update_part(&mut hasher, part);
    }
    Sha256Digest(hasher.finalize().into())
}

/// Computes a plain SHA-256 digest where the external contract calls for one.
#[must_use]
pub fn raw_sha256_digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest(Sha256::digest(bytes).into())
}

/// Commits one stable Run failure and its optional encrypted evidence reference.
///
/// The transcript is `COMMIT("dirextalk.run-failed-report.v1", code,
/// evidence-presence, artifact-id?, evidence-digest?)`, where presence is one
/// byte and the UUID is its 16 network-order bytes.
#[must_use]
pub fn run_failed_report_digest(
    stable_error_code: &str,
    evidence: Option<([u8; 16], Sha256Digest)>,
) -> Sha256Digest {
    match evidence {
        Some((artifact_id, digest)) => domain_digest(
            RUN_FAILED_REPORT_DOMAIN,
            &[
                stable_error_code.as_bytes(),
                &[1],
                &artifact_id,
                &digest.as_bytes(),
            ],
        ),
        None => domain_digest(
            RUN_FAILED_REPORT_DOMAIN,
            &[stable_error_code.as_bytes(), &[0]],
        ),
    }
}

fn update_part(hasher: &mut Sha256, part: &[u8]) {
    hasher.update((part.len() as u64).to_be_bytes());
    hasher.update(part);
}

#[cfg(test)]
mod tests {
    use super::{Sha256Digest, run_failed_report_digest};

    #[test]
    fn failed_report_digest_matches_the_frozen_lp_transcript() {
        assert_eq!(
            run_failed_report_digest(
                "RUNTIME_FAILED",
                Some((
                    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
                    Sha256Digest::from_bytes([0x55; 32]),
                )),
            )
            .as_bytes(),
            [
                0xa5, 0x1f, 0xd3, 0x13, 0xf6, 0xea, 0x5d, 0x44, 0x86, 0x5b, 0x86, 0x0c, 0x6d, 0xeb,
                0xe3, 0xec, 0x21, 0x6d, 0xf3, 0x88, 0x66, 0xff, 0x44, 0xa3, 0x9c, 0x27, 0xef, 0x4a,
                0x06, 0x0c, 0x9b, 0x7f,
            ]
        );
        assert_eq!(
            run_failed_report_digest(
                "RUNTIME_FAILED",
                Some((
                    [
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x76, 0x07, 0x88, 0x09, 0x0a,
                        0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                    ],
                    Sha256Digest::from_bytes([0x55; 32]),
                )),
            )
            .as_bytes(),
            [
                0x22, 0xe2, 0xb6, 0xb6, 0x49, 0x97, 0xbe, 0x42, 0xc0, 0x80, 0x97, 0x10, 0x64,
                0x16, 0xf2, 0x17, 0xc6, 0xc5, 0x6b, 0xe7, 0xf1, 0x6b, 0xeb, 0xb3, 0x42, 0x39,
                0x3f, 0x3f, 0x56, 0x07, 0x13, 0x11,
            ]
        );
    }
}
