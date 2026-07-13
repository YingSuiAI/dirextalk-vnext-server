use std::{error::Error, fmt};

use dtx_domain::{ConnectorId, EnrollmentIntentId, HostId, RequestId, Revision, TenantId};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    ConnectorCredential, EnrollmentRequest, ProofError, Sha256Digest, digest::domain_digest,
};

const ENROLLMENT_TOKEN_DOMAIN: &[u8] = b"dirextalk.connector-enrollment-token.v1";

pub const DEFAULT_ENROLLMENT_TTL_MILLIS: i64 = 300_000;
pub const MAX_ENROLLMENT_TTL_MILLIS: i64 = 600_000;

/// Raw 256-bit one-time token. It is redacted from `Debug` and zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EnrollmentToken([u8; 32]);

impl EnrollmentToken {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the domain-separated digest that is safe to persist.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        domain_digest(ENROLLMENT_TOKEN_DOMAIN, &[&self.0])
    }

    /// Exposes the one-time token only for the lifetime of a caller-supplied closure.
    ///
    /// This is intended for the owner API's single response serialization. The
    /// token remains redacted from diagnostics and is zeroized when this wrapper drops.
    pub fn expose<R>(&self, use_token: impl FnOnce(&[u8; 32]) -> R) -> R {
        use_token(&self.0)
    }
}

impl fmt::Debug for EnrollmentToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnrollmentToken(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentIntentState {
    Open,
    Consumed,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum IntentOutcome {
    Open,
    Consumed {
        consumed_at_millis: i64,
        request_digest: Sha256Digest,
        result_digest: Sha256Digest,
        result: Box<ConnectorCredential>,
    },
    Expired {
        expired_at_millis: i64,
    },
    Revoked {
        revoked_at_millis: i64,
    },
}

/// Bounded one-time enrollment authorization for one exact Connector revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentIntent {
    intent_id: EnrollmentIntentId,
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
    generation: u64,
    spec_revision: Revision,
    request_id: RequestId,
    token_digest: Sha256Digest,
    created_at_millis: i64,
    expires_at_millis: i64,
    outcome: IntentOutcome,
}

/// Constructible durable form of an enrollment outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnrollmentIntentSnapshotState {
    Open,
    Consumed {
        consumed_at_millis: i64,
        request_digest: Sha256Digest,
        result_digest: Sha256Digest,
        result: Box<ConnectorCredential>,
    },
    Expired {
        expired_at_millis: i64,
    },
    Revoked {
        revoked_at_millis: i64,
    },
}

/// Complete non-secret persistence image. Raw enrollment tokens are never included.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentIntentSnapshot {
    pub intent_id: EnrollmentIntentId,
    pub tenant_id: TenantId,
    pub host_id: HostId,
    pub connector_id: ConnectorId,
    pub generation: u64,
    pub spec_revision: Revision,
    pub request_id: RequestId,
    pub token_digest: Sha256Digest,
    pub created_at_millis: i64,
    pub expires_at_millis: i64,
    pub state: EnrollmentIntentSnapshotState,
}

/// Result of validating an enrollment request before certificate issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnrollmentRequestDisposition {
    IssueCredential,
    Replay(ConnectorCredential),
}

impl EnrollmentIntent {
    /// Creates a bounded one-time enrollment authorization and stores only the token digest.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError`] for an invalid generation, server timestamp,
    /// lifetime, or timestamp overflow.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent_id: EnrollmentIntentId,
        tenant_id: TenantId,
        host_id: HostId,
        connector_id: ConnectorId,
        generation: u64,
        spec_revision: Revision,
        request_id: RequestId,
        created_at_millis: i64,
        ttl_millis: i64,
        token: &EnrollmentToken,
    ) -> Result<Self, EnrollmentError> {
        validate_generation(generation)?;
        if !valid_timestamp(created_at_millis) {
            return Err(EnrollmentError::InvalidTime);
        }
        if !(1..=MAX_ENROLLMENT_TTL_MILLIS).contains(&ttl_millis) {
            return Err(EnrollmentError::InvalidLifetime);
        }
        let expires_at_millis = created_at_millis
            .checked_add(ttl_millis)
            .ok_or(EnrollmentError::InvalidLifetime)?;
        if !valid_timestamp(expires_at_millis) {
            return Err(EnrollmentError::InvalidLifetime);
        }
        Ok(Self {
            intent_id,
            tenant_id,
            host_id,
            connector_id,
            generation,
            spec_revision,
            request_id,
            token_digest: token.digest(),
            created_at_millis,
            expires_at_millis,
            outcome: IntentOutcome::Open,
        })
    }

    /// Checks whether a repeated owner creation request is the same logical operation.
    ///
    /// Server-generated intent identity and timestamps are deliberately excluded: after a
    /// committed response is lost, a retry is reconstructed at a later time with a fresh
    /// candidate ID. The caller-controlled operation, Connector, token, and lifetime must
    /// still match exactly.
    #[must_use]
    pub fn matches_creation_request(
        &self,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        request_id: RequestId,
        ttl_millis: i64,
        token: &EnrollmentToken,
    ) -> bool {
        self.tenant_id == tenant_id
            && self.connector_id == connector_id
            && self.request_id == request_id
            && self.expires_at_millis.checked_sub(self.created_at_millis) == Some(ttl_millis)
            && self.token_digest.ct_eq(token.digest())
    }

    /// Checks whether another server-side candidate represents the same owner request.
    ///
    /// This is used after a concurrent insert wins. It intentionally applies the same
    /// caller-controlled comparison as [`Self::matches_creation_request`].
    #[must_use]
    pub fn matches_creation_candidate(&self, candidate: &Self) -> bool {
        self.tenant_id == candidate.tenant_id
            && self.connector_id == candidate.connector_id
            && self.request_id == candidate.request_id
            && self.expires_at_millis.checked_sub(self.created_at_millis)
                == candidate
                    .expires_at_millis
                    .checked_sub(candidate.created_at_millis)
            && self.token_digest.ct_eq(candidate.token_digest)
    }

    /// Consumes this intent or returns the persisted public result for an exact retry.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError`] for invalid token/proof/binding/result,
    /// expiry/revocation, or a changed idempotent retry.
    pub fn consume(
        &mut self,
        token: &EnrollmentToken,
        request: &EnrollmentRequest,
        result: ConnectorCredential,
        now_millis: i64,
    ) -> Result<ConnectorCredential, EnrollmentError> {
        match self.evaluate_request(token, request, now_millis)? {
            EnrollmentRequestDisposition::Replay(result) => return Ok(result),
            EnrollmentRequestDisposition::IssueCredential => {}
        }
        let request_digest = request.request_digest();
        result
            .validate_enrollment_result(request.transcript(), now_millis)
            .map_err(|_| EnrollmentError::InvalidCredentialResult)?;
        let result_digest = result.result_digest();
        self.outcome = IntentOutcome::Consumed {
            consumed_at_millis: now_millis,
            request_digest,
            result_digest,
            result: Box::new(result.clone()),
        };
        Ok(result)
    }

    /// Validates token, proof, binding, expiry, and retry semantics before an
    /// application asks its certificate issuer for a new public result.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError`] unless the request may safely issue or replay
    /// one exact credential result.
    pub fn evaluate_request(
        &self,
        token: &EnrollmentToken,
        request: &EnrollmentRequest,
        now_millis: i64,
    ) -> Result<EnrollmentRequestDisposition, EnrollmentError> {
        if !valid_timestamp(now_millis) {
            return Err(EnrollmentError::InvalidTime);
        }
        if !self.token_digest.ct_eq(token.digest()) {
            return Err(EnrollmentError::InvalidToken);
        }
        let request_digest = request.request_digest();
        match &self.outcome {
            IntentOutcome::Consumed {
                request_digest: persisted,
                result,
                ..
            } => {
                return if persisted.ct_eq(request_digest) {
                    Ok(EnrollmentRequestDisposition::Replay(
                        result.as_ref().clone(),
                    ))
                } else {
                    Err(EnrollmentError::IdempotencyConflict)
                };
            }
            IntentOutcome::Revoked { .. } => return Err(EnrollmentError::Revoked),
            IntentOutcome::Expired { .. } => return Err(EnrollmentError::Expired),
            IntentOutcome::Open => {}
        }
        if now_millis < self.created_at_millis || now_millis >= self.expires_at_millis {
            return Err(EnrollmentError::Expired);
        }
        self.validate_request(request)?;
        request.verify().map_err(EnrollmentError::from)?;
        Ok(EnrollmentRequestDisposition::IssueCredential)
    }

    /// Revokes an unused intent. Revocation is terminal and idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError`] for invalid time, expiry, or prior consumption.
    pub fn revoke(&mut self, now_millis: i64) -> Result<(), EnrollmentError> {
        if !valid_timestamp(now_millis) {
            return Err(EnrollmentError::InvalidTime);
        }
        match self.outcome {
            IntentOutcome::Consumed { .. } => Err(EnrollmentError::AlreadyConsumed),
            IntentOutcome::Expired { .. } => Err(EnrollmentError::Expired),
            IntentOutcome::Revoked { .. } => Ok(()),
            IntentOutcome::Open => {
                if now_millis < self.created_at_millis {
                    return Err(EnrollmentError::InvalidTime);
                }
                if now_millis >= self.expires_at_millis {
                    return Err(EnrollmentError::Expired);
                }
                self.outcome = IntentOutcome::Revoked {
                    revoked_at_millis: now_millis,
                };
                Ok(())
            }
        }
    }

    /// Terminally records expiration once the server clock reaches the deadline.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError`] for invalid time, an early expiry attempt,
    /// prior consumption, or revocation.
    pub fn expire(&mut self, now_millis: i64) -> Result<(), EnrollmentError> {
        if !valid_timestamp(now_millis) {
            return Err(EnrollmentError::InvalidTime);
        }
        match self.outcome {
            IntentOutcome::Consumed { .. } => Err(EnrollmentError::AlreadyConsumed),
            IntentOutcome::Revoked { .. } => Err(EnrollmentError::Revoked),
            IntentOutcome::Expired { .. } => Ok(()),
            IntentOutcome::Open => {
                if now_millis < self.expires_at_millis {
                    return Err(EnrollmentError::NotExpired);
                }
                self.outcome = IntentOutcome::Expired {
                    expired_at_millis: now_millis,
                };
                Ok(())
            }
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> EnrollmentIntentSnapshot {
        EnrollmentIntentSnapshot {
            intent_id: self.intent_id,
            tenant_id: self.tenant_id,
            host_id: self.host_id,
            connector_id: self.connector_id,
            generation: self.generation,
            spec_revision: self.spec_revision,
            request_id: self.request_id,
            token_digest: self.token_digest,
            created_at_millis: self.created_at_millis,
            expires_at_millis: self.expires_at_millis,
            state: match &self.outcome {
                IntentOutcome::Open => EnrollmentIntentSnapshotState::Open,
                IntentOutcome::Consumed {
                    consumed_at_millis,
                    request_digest,
                    result_digest,
                    result,
                } => EnrollmentIntentSnapshotState::Consumed {
                    consumed_at_millis: *consumed_at_millis,
                    request_digest: *request_digest,
                    result_digest: *result_digest,
                    result: result.clone(),
                },
                IntentOutcome::Expired { expired_at_millis } => {
                    EnrollmentIntentSnapshotState::Expired {
                        expired_at_millis: *expired_at_millis,
                    }
                }
                IntentOutcome::Revoked { revoked_at_millis } => {
                    EnrollmentIntentSnapshotState::Revoked {
                        revoked_at_millis: *revoked_at_millis,
                    }
                }
            },
        }
    }

    /// Rehydrates an exact non-secret enrollment persistence image.
    ///
    /// # Errors
    ///
    /// Returns [`EnrollmentError::InvalidSnapshot`] when persisted times,
    /// binding, result digest, or lifecycle facts are incoherent.
    pub fn try_from_snapshot(snapshot: EnrollmentIntentSnapshot) -> Result<Self, EnrollmentError> {
        validate_generation(snapshot.generation)?;
        let lifetime = snapshot
            .expires_at_millis
            .checked_sub(snapshot.created_at_millis)
            .ok_or(EnrollmentError::InvalidSnapshot)?;
        if !(1..=MAX_ENROLLMENT_TTL_MILLIS).contains(&lifetime) {
            return Err(EnrollmentError::InvalidSnapshot);
        }
        if !valid_timestamp(snapshot.created_at_millis)
            || !valid_timestamp(snapshot.expires_at_millis)
        {
            return Err(EnrollmentError::InvalidSnapshot);
        }
        let outcome = match snapshot.state {
            EnrollmentIntentSnapshotState::Open => IntentOutcome::Open,
            EnrollmentIntentSnapshotState::Consumed {
                consumed_at_millis,
                request_digest,
                result_digest,
                result,
            } => {
                if consumed_at_millis < snapshot.created_at_millis
                    || !valid_timestamp(consumed_at_millis)
                    || consumed_at_millis >= snapshot.expires_at_millis
                    || !result.matches_enrollment_binding(
                        snapshot.tenant_id,
                        snapshot.connector_id,
                        snapshot.generation,
                    )
                    || result.revision() != snapshot.spec_revision
                    || !result.is_valid_at(consumed_at_millis)
                    || !result.result_digest().ct_eq(result_digest)
                {
                    return Err(EnrollmentError::InvalidSnapshot);
                }
                IntentOutcome::Consumed {
                    consumed_at_millis,
                    request_digest,
                    result_digest,
                    result,
                }
            }
            EnrollmentIntentSnapshotState::Expired { expired_at_millis } => {
                if expired_at_millis < snapshot.expires_at_millis
                    || !valid_timestamp(expired_at_millis)
                {
                    return Err(EnrollmentError::InvalidSnapshot);
                }
                IntentOutcome::Expired { expired_at_millis }
            }
            EnrollmentIntentSnapshotState::Revoked { revoked_at_millis } => {
                if revoked_at_millis < snapshot.created_at_millis
                    || !valid_timestamp(revoked_at_millis)
                {
                    return Err(EnrollmentError::InvalidSnapshot);
                }
                IntentOutcome::Revoked { revoked_at_millis }
            }
        };
        Ok(Self {
            intent_id: snapshot.intent_id,
            tenant_id: snapshot.tenant_id,
            host_id: snapshot.host_id,
            connector_id: snapshot.connector_id,
            generation: snapshot.generation,
            spec_revision: snapshot.spec_revision,
            request_id: snapshot.request_id,
            token_digest: snapshot.token_digest,
            created_at_millis: snapshot.created_at_millis,
            expires_at_millis: snapshot.expires_at_millis,
            outcome,
        })
    }

    #[must_use]
    pub const fn intent_id(&self) -> EnrollmentIntentId {
        self.intent_id
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn spec_revision(&self) -> Revision {
        self.spec_revision
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    #[must_use]
    pub const fn token_digest(&self) -> Sha256Digest {
        self.token_digest
    }

    #[must_use]
    pub const fn expires_at_millis(&self) -> i64 {
        self.expires_at_millis
    }

    #[must_use]
    pub const fn created_at_millis(&self) -> i64 {
        self.created_at_millis
    }

    /// Returns the current durable state without deriving authorization from wall time.
    #[must_use]
    pub const fn state(&self) -> EnrollmentIntentState {
        match self.outcome {
            IntentOutcome::Open => EnrollmentIntentState::Open,
            IntentOutcome::Consumed { .. } => EnrollmentIntentState::Consumed,
            IntentOutcome::Expired { .. } => EnrollmentIntentState::Expired,
            IntentOutcome::Revoked { .. } => EnrollmentIntentState::Revoked,
        }
    }

    /// Projects an open intent as expired once its deadline has passed.
    #[must_use]
    pub const fn state_at(&self, now_millis: i64) -> EnrollmentIntentState {
        match self.outcome {
            IntentOutcome::Open if now_millis >= self.expires_at_millis => {
                EnrollmentIntentState::Expired
            }
            _ => self.state(),
        }
    }

    #[must_use]
    pub fn consumed_result(&self) -> Option<&ConnectorCredential> {
        match &self.outcome {
            IntentOutcome::Consumed { result, .. } => Some(result.as_ref()),
            IntentOutcome::Open | IntentOutcome::Expired { .. } | IntentOutcome::Revoked { .. } => {
                None
            }
        }
    }

    #[must_use]
    pub const fn consumed_request_digest(&self) -> Option<Sha256Digest> {
        match self.outcome {
            IntentOutcome::Consumed { request_digest, .. } => Some(request_digest),
            IntentOutcome::Open | IntentOutcome::Expired { .. } | IntentOutcome::Revoked { .. } => {
                None
            }
        }
    }

    #[must_use]
    pub const fn consumed_result_digest(&self) -> Option<Sha256Digest> {
        match self.outcome {
            IntentOutcome::Consumed { result_digest, .. } => Some(result_digest),
            IntentOutcome::Open | IntentOutcome::Expired { .. } | IntentOutcome::Revoked { .. } => {
                None
            }
        }
    }

    fn validate_request(&self, request: &EnrollmentRequest) -> Result<(), EnrollmentError> {
        let transcript = request.transcript();
        if transcript.tenant_id() != self.tenant_id
            || transcript.host_id() != self.host_id
            || transcript.connector_id() != self.connector_id
            || transcript.generation() != self.generation
            || transcript.spec_revision() != self.spec_revision
            || transcript.request_id() != self.request_id
            || !transcript.token_digest().ct_eq(self.token_digest)
        {
            return Err(EnrollmentError::IntentMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentError {
    InvalidGeneration,
    InvalidLifetime,
    InvalidTime,
    InvalidToken,
    Expired,
    NotExpired,
    Revoked,
    AlreadyConsumed,
    IntentMismatch,
    InvalidProof,
    InvalidCredentialResult,
    IdempotencyConflict,
    InvalidSnapshot,
}

impl From<ProofError> for EnrollmentError {
    fn from(_: ProofError) -> Self {
        Self::InvalidProof
    }
}

impl fmt::Display for EnrollmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGeneration => "enrollment generation is outside the safe positive range",
            Self::InvalidLifetime => "enrollment lifetime is outside the allowed bound",
            Self::InvalidTime => "enrollment time is invalid",
            Self::InvalidToken => "enrollment token is invalid",
            Self::Expired => "enrollment intent has expired",
            Self::NotExpired => "enrollment intent has not reached its expiry deadline",
            Self::Revoked => "enrollment intent is revoked",
            Self::AlreadyConsumed => "enrollment intent is already consumed",
            Self::IntentMismatch => "enrollment request does not match its intent",
            Self::InvalidProof => "enrollment proof-of-possession is invalid",
            Self::InvalidCredentialResult => "enrollment credential result is invalid",
            Self::IdempotencyConflict => "enrollment retry changed an accepted request",
            Self::InvalidSnapshot => "enrollment snapshot violates durable invariants",
        })
    }
}

impl Error for EnrollmentError {}

fn validate_generation(generation: u64) -> Result<(), EnrollmentError> {
    if generation == 0 || generation > Revision::MAX {
        Err(EnrollmentError::InvalidGeneration)
    } else {
        Ok(())
    }
}

fn valid_timestamp(value: i64) -> bool {
    (0..=Revision::MAX.cast_signed()).contains(&value)
}
