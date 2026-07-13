use std::fmt;

use sha2::{Digest, Sha256};

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

fn update_part(hasher: &mut Sha256, part: &[u8]) {
    hasher.update((part.len() as u64).to_be_bytes());
    hasher.update(part);
}
