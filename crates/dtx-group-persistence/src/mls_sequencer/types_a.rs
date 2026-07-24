use dtx_domain::{
    DeviceEnrollmentChallengeId, DeviceId, IdentityId, RequestId, Revision, TenantId,
};
use dtx_group_policy::GroupScope;
use dtx_identity_log::{DeviceStatusV1, IdentityLogEventPayloadV1, IdentityLogEventV1};
use dtx_identity_persistence::{
    DeviceSessionCredential, DeviceSessionRepository, lock_and_load_active_snapshot,
};
use dtx_membership_command::MembershipCommandId;
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, Sha256Digest, SigningPublicKey,
    encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::{
    GroupPersistenceError, GroupPgStore,
    repository::{
        VerifiedDeviceActor, begin_authenticated_with_signing_key,
        remove_group_member_in_transaction, resolve_mls_commit_in_transaction, settle,
    },
};

const COMMIT_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-opaque-commit.v1\0";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-commit-request.v1\0";
const HEAD_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-sequencer-head.v1\0";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-commit-receipt.v1\0";
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.mls-commit-receipt-signature.v1\0";
const V3_REQUEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-commit-request.v3\0";
const V3_RECEIPT_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-commit-receipt.v3\0";
const V3_RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.mls-commit-receipt-signature.v3\0";
const V4_REQUEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-commit-request.v4\0";
const V4_RECEIPT_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-commit-receipt.v4\0";
const V4_RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.mls-commit-receipt-signature.v4\0";
const V5_REQUEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-commit-request.v5\0";
const V5_RECEIPT_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-commit-receipt.v5\0";
const V5_RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.mls-commit-receipt-signature.v5\0";
const V5_CONTROLLER_CONSENT_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.mls-recovery-controller-consent-digest.v5\0";
const V5_CONTROLLER_CONSENT_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.mls-recovery-controller-consent-signature.v5\0";
const V5_RECOVERY_SCOPE_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-recovery-scope-digest.v5\0";
const DEVICE_CONFIRMATION_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.mls-device-join-confirmation.v1\0";
/// V2 candidate possession transcript digest domain.
pub const MLS_CANDIDATE_PROOF_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-candidate-proof-digest.v2\0";
/// V2 candidate possession signature domain.
pub const MLS_CANDIDATE_PROOF_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.mls-candidate-proof-signature.v2\0";
/// V2 existing-device consent transcript digest domain.
pub const MLS_CONTROLLER_CONSENT_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.mls-controller-consent-digest.v2\0";
/// V2 existing-device consent signature domain.
pub const MLS_CONTROLLER_CONSENT_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.mls-controller-consent-signature.v2\0";
/// V2 raw HTTP idempotency-key hash domain.
pub const MLS_IDEMPOTENCY_KEY_HASH_DOMAIN: &[u8] = b"dirextalk.mls-idempotency-key.v2\0";
const MAX_COMMIT_BYTES: usize = 1_048_576;

/// Computes the protocol-frozen digest of opaque MLS Commit wire bytes.
#[must_use]
pub fn mls_opaque_commit_digest(commit_bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::hash_domain(COMMIT_DIGEST_DOMAIN, commit_bytes)
}

/// Exact bytes the candidate device signs after processing the accepted Welcome/head.
///
/// # Errors
///
/// Returns a corruption error only if the bounded canonical transcript cannot be encoded.
pub fn mls_device_confirmation_signature_input(
    confirmation: &MlsDeviceJoinConfirmation,
) -> Result<Vec<u8>, GroupPersistenceError> {
    let value = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(confirmation.submission_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(confirmation.identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(confirmation.device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            confirmation.receipt_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            confirmation.head_digest.to_canonical_value(),
        ),
    ]);
    let encoded = encode_deterministic_cbor(&value)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS confirmation encoding"))?;
    let digest = Sha256Digest::hash_domain(DEVICE_CONFIRMATION_SIGNATURE_DOMAIN, &encoded);
    Ok(digest.as_bytes().to_vec())
}

/// Admission authority for one exact MLS leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlsCommitAuthorization {
    /// Epoch-one bootstrap by the group Owner's exact live device.
    OwnerBootstrap,
    /// First leaf for an identity, bound to the stable approved GM1 workflow.
    ApprovedIdentityJoin {
        /// Approval command currently in `pending_commit`.
        membership_command_id: MembershipCommandId,
        /// Stable authorization digest produced when Owner/Admin approved.
        authorization_digest: Sha256Digest,
    },
    /// V30 first leaf authorized exclusively by durable candidate join and
    /// Owner/Admin approval facts. The owner never signs as the candidate.
    ApprovedIdentityJoinV3 {
        /// Durable Owner/Admin approval command.
        membership_command_id: MembershipCommandId,
        /// Fresh approval action-proof binding retained by GM1.
        authorization_digest: Sha256Digest,
        /// Candidate-authored V2 membership request digest.
        join_request_digest: Sha256Digest,
        /// Owner/Admin-authored V2 approval request digest.
        approval_request_digest: Sha256Digest,
    },
    /// Additional leaf for an identity already represented in group policy.
    ExistingMemberDeviceAdd {
        /// Existing active MLS device that signed the exact device-add consent.
        controller_device_id: DeviceId,
        /// Verified consent transcript digest binding scope, new device and `KeyPackage`.
        controller_consent_digest: Sha256Digest,
    },
    /// V40 recovery admission controlled by an already-active leaf of the same identity.
    ExistingMemberDeviceRecoveryAdd {
        controller_device_id: DeviceId,
        controller_consent_digest: Sha256Digest,
        recovery_request_id: DeviceEnrollmentChallengeId,
        recovery_request_digest: Sha256Digest,
        recovery_scope_digest: Sha256Digest,
    },
    /// V40 removal of one identity-log-revoked device leaf only.
    ExistingMemberDeviceRemove {
        identity_revoke_head_digest: Sha256Digest,
    },
    /// Owner-authored removal of one non-owner identity whose exact sole
    /// active MLS leaf is bound by the command target fields.
    MemberRemovalV4 {
        /// Product policy revision observed before preparing the MLS removal.
        expected_policy_revision: Revision,
    },
}

/// Immutable V40 authorization coordinates retained by the Group runtime.
///
/// These are lookup coordinates, not a portable identity authorization proof.
/// A federated caller must re-fetch the authoritative origin facts before each
/// receipt is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlsV5FederatedAuthorizationFacts {
    identity_id: IdentityId,
    controller_device_id: DeviceId,
    candidate_device_id: DeviceId,
    candidate_key_package_digest: Sha256Digest,
    authorization: MlsCommitAuthorization,
}

impl MlsV5FederatedAuthorizationFacts {
    #[must_use]
    pub const fn identity_id(self) -> IdentityId {
        self.identity_id
    }

    #[must_use]
    pub const fn controller_device_id(self) -> DeviceId {
        self.controller_device_id
    }

    #[must_use]
    pub const fn candidate_device_id(self) -> DeviceId {
        self.candidate_device_id
    }

    #[must_use]
    pub const fn candidate_key_package_digest(self) -> Sha256Digest {
        self.candidate_key_package_digest
    }

    #[must_use]
    pub const fn authorization(self) -> MlsCommitAuthorization {
        self.authorization
    }
}

/// Fully proof-verified MLS commit submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsCommitCommand {
    protocol_version: u8,
    submission_id: RequestId,
    scope: GroupScope,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    candidate_key_package_digest: Sha256Digest,
    candidate_proof_digest: Sha256Digest,
    idempotency_key_hash: Sha256Digest,
    expected_epoch: u64,
    expected_head: Sha256Digest,
    commit_bytes: Vec<u8>,
    commit_digest: Sha256Digest,
    welcome_digest: Sha256Digest,
    authorization: MlsCommitAuthorization,
    request_digest: Sha256Digest,
}

impl MlsCommitCommand {
    /// Constructs the exact command and rejects empty, oversized, or digest-mismatched commits.
    ///
    /// # Errors
    ///
    /// Returns an authorization error for invalid opaque Commit bounds/digest or epoch.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        submission_id: RequestId,
        scope: GroupScope,
        actor_identity_id: IdentityId,
        actor_device_id: DeviceId,
        candidate_identity_id: IdentityId,
        candidate_device_id: DeviceId,
        candidate_key_package_digest: Sha256Digest,
        candidate_proof_digest: Sha256Digest,
        idempotency_key_hash: Sha256Digest,
        expected_epoch: u64,
        expected_head: Sha256Digest,
        commit_bytes: Vec<u8>,
        commit_digest: Sha256Digest,
        welcome_digest: Sha256Digest,
        authorization: MlsCommitAuthorization,
    ) -> Result<Self, GroupPersistenceError> {
        if commit_bytes.is_empty() || commit_bytes.len() > MAX_COMMIT_BYTES {
            return Err(GroupPersistenceError::MlsAuthorizationRejected);
        }
        let actual = mls_opaque_commit_digest(&commit_bytes);
        if actual != commit_digest || expected_epoch >= 9_007_199_254_740_991 {
            return Err(GroupPersistenceError::MlsAuthorizationRejected);
        }
        let mut command = Self {
            protocol_version: 2,
            submission_id,
            scope,
            actor_identity_id,
            actor_device_id,
            candidate_identity_id,
            candidate_device_id,
            candidate_key_package_digest,
            candidate_proof_digest,
            idempotency_key_hash,
            expected_epoch,
            expected_head,
            commit_bytes,
            commit_digest,
            welcome_digest,
            authorization,
            request_digest: Sha256Digest::from_bytes([0; 32]),
        };
        command.request_digest = command.compute_request_digest()?;
        Ok(command)
    }

    /// Constructs a V30 approved-identity commit. Candidate possession was
    /// already verified by the durable V2 join request, so this request does
    /// not accept or require a candidate signature over the final Commit.
    ///
    /// # Errors
    ///
    /// Returns an error when the bounded canonical V3 request cannot be
    /// encoded or the delegated V2 command invariants are invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn new_v3_approved_identity_join(
        submission_id: RequestId,
        scope: GroupScope,
        actor_identity_id: IdentityId,
        actor_device_id: DeviceId,
        candidate_identity_id: IdentityId,
        candidate_device_id: DeviceId,
        candidate_key_package_digest: Sha256Digest,
        idempotency_key_hash: Sha256Digest,
        expected_epoch: u64,
        expected_head: Sha256Digest,
        commit_bytes: Vec<u8>,
        commit_digest: Sha256Digest,
        welcome_digest: Sha256Digest,
        membership_command_id: MembershipCommandId,
        authorization_digest: Sha256Digest,
        join_request_digest: Sha256Digest,
        approval_request_digest: Sha256Digest,
    ) -> Result<Self, GroupPersistenceError> {
        let mut command = Self::new(
            submission_id,
            scope,
            actor_identity_id,
            actor_device_id,
            candidate_identity_id,
            candidate_device_id,
            candidate_key_package_digest,
            Sha256Digest::from_bytes([0; 32]),
            idempotency_key_hash,
            expected_epoch,
            expected_head,
            commit_bytes,
            commit_digest,
            welcome_digest,
            MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                membership_command_id,
                authorization_digest,
                join_request_digest,
                approval_request_digest,
            },
        )?;
        command.protocol_version = 3;
        command.request_digest = command.compute_request_digest()?;
        Ok(command)
    }

    /// Constructs a V4 Owner-only single-member removal command.
    ///
    /// The target identity/device occupies the existing candidate binding
    /// fields, while `KeyPackage`, candidate-proof, and Welcome digests are
    /// deliberately zero because a removed peer grants no authority.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed commit bounds/digest or an invalid epoch.
    #[allow(clippy::too_many_arguments)]
    pub fn new_v4_member_removal(
        submission_id: RequestId,
        scope: GroupScope,
        actor_identity_id: IdentityId,
        actor_device_id: DeviceId,
        target_identity_id: IdentityId,
        target_device_id: DeviceId,
        idempotency_key_hash: Sha256Digest,
        expected_epoch: u64,
        expected_head: Sha256Digest,
        expected_policy_revision: Revision,
        commit_bytes: Vec<u8>,
        commit_digest: Sha256Digest,
    ) -> Result<Self, GroupPersistenceError> {
        let zero = Sha256Digest::from_bytes([0; 32]);
        let mut command = Self::new(
            submission_id,
            scope,
            actor_identity_id,
            actor_device_id,
            target_identity_id,
            target_device_id,
            zero,
            zero,
            idempotency_key_hash,
            expected_epoch,
            expected_head,
            commit_bytes,
            commit_digest,
            zero,
            MlsCommitAuthorization::MemberRemovalV4 {
                expected_policy_revision,
            },
        )?;
        command.protocol_version = 4;
        command.request_digest = command.compute_request_digest()?;
        Ok(command)
    }

    /// Constructs V40 same-identity device recovery without any candidate
    /// signature over controller-created final transcript bytes.
    ///
    /// # Errors
    ///
    /// Rejects malformed commit bounds or digests and incomplete recovery-add facts.
    #[allow(clippy::too_many_arguments)]
    pub fn new_v5_existing_member_device_recovery_add(
        submission_id: RequestId,
        scope: GroupScope,
        actor_identity_id: IdentityId,
        controller_device_id: DeviceId,
        candidate_device_id: DeviceId,
        candidate_key_package_digest: Sha256Digest,
        idempotency_key_hash: Sha256Digest,
        expected_epoch: u64,
        expected_head: Sha256Digest,
        commit_bytes: Vec<u8>,
        commit_digest: Sha256Digest,
        welcome_digest: Sha256Digest,
        recovery_request_id: DeviceEnrollmentChallengeId,
        recovery_request_digest: Sha256Digest,
        recovery_scope_digest: Sha256Digest,
        controller_consent_digest: Sha256Digest,
    ) -> Result<Self, GroupPersistenceError> {
        let zero = Sha256Digest::from_bytes([0; 32]);
        if candidate_key_package_digest == zero || welcome_digest == zero {
            return Err(GroupPersistenceError::MlsAuthorizationRejected);
        }
        let mut command = Self::new(
            submission_id,
            scope,
            actor_identity_id,
            controller_device_id,
            actor_identity_id,
            candidate_device_id,
            candidate_key_package_digest,
            zero,
            idempotency_key_hash,
            expected_epoch,
            expected_head,
            commit_bytes,
            commit_digest,
            welcome_digest,
            MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
                controller_device_id,
                controller_consent_digest,
                recovery_request_id,
                recovery_request_digest,
                recovery_scope_digest,
            },
        )?;
        command.protocol_version = 5;
        command.request_digest = command.compute_request_digest()?;
        Ok(command)
    }

    /// Constructs V40 removal of one revoked device leaf while preserving the
    /// account-level group membership and every other active leaf.
    ///
    /// # Errors
    ///
    /// Rejects malformed commit bounds or digests and invalid removal facts.
    #[allow(clippy::too_many_arguments)]
    pub fn new_v5_existing_member_device_remove(
        submission_id: RequestId,
        scope: GroupScope,
        identity_id: IdentityId,
        controller_device_id: DeviceId,
        revoked_device_id: DeviceId,
        idempotency_key_hash: Sha256Digest,
        expected_epoch: u64,
        expected_head: Sha256Digest,
        commit_bytes: Vec<u8>,
        commit_digest: Sha256Digest,
        identity_revoke_head_digest: Sha256Digest,
    ) -> Result<Self, GroupPersistenceError> {
        let zero = Sha256Digest::from_bytes([0; 32]);
        let mut command = Self::new(
            submission_id,
            scope,
            identity_id,
            controller_device_id,
            identity_id,
            revoked_device_id,
            zero,
            zero,
            idempotency_key_hash,
            expected_epoch,
            expected_head,
            commit_bytes,
            commit_digest,
            zero,
            MlsCommitAuthorization::ExistingMemberDeviceRemove {
                identity_revoke_head_digest,
            },
        )?;
        command.protocol_version = 5;
        command.request_digest = command.compute_request_digest()?;
        Ok(command)
    }

    #[allow(clippy::too_many_lines)] // Keeping the versioned canonical field order contiguous makes transcript review safer.
    fn compute_request_digest(&self) -> Result<Sha256Digest, GroupPersistenceError> {
        let (authorization_code, command_id, authorization_digest, controller_device, consent) =
            match self.authorization {
                MlsCommitAuthorization::OwnerBootstrap => (
                    0,
                    CanonicalValue::Null,
                    CanonicalValue::Null,
                    CanonicalValue::Null,
                    CanonicalValue::Null,
                ),
                MlsCommitAuthorization::ApprovedIdentityJoin {
                    membership_command_id,
                    authorization_digest,
                }
                | MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                    membership_command_id,
                    authorization_digest,
                    ..
                } => (
                    1,
                    CanonicalValue::Text(membership_command_id.request_id().to_string()),
                    authorization_digest.to_canonical_value(),
                    CanonicalValue::Null,
                    CanonicalValue::Null,
                ),
                MlsCommitAuthorization::ExistingMemberDeviceAdd {
                    controller_device_id,
                    controller_consent_digest,
                } => (
                    2,
                    CanonicalValue::Null,
                    CanonicalValue::Null,
                    CanonicalValue::Text(controller_device_id.to_string()),
                    controller_consent_digest.to_canonical_value(),
                ),
                MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
                    controller_device_id,
                    controller_consent_digest,
                    ..
                } => (
                    4,
                    CanonicalValue::Null,
                    CanonicalValue::Null,
                    CanonicalValue::Text(controller_device_id.to_string()),
                    controller_consent_digest.to_canonical_value(),
                ),
                MlsCommitAuthorization::MemberRemovalV4 {
                    expected_policy_revision,
                } => (
                    3,
                    CanonicalValue::Null,
                    CanonicalValue::Unsigned(expected_policy_revision.get()),
                    CanonicalValue::Null,
                    CanonicalValue::Null,
                ),
                MlsCommitAuthorization::ExistingMemberDeviceRemove {
                    identity_revoke_head_digest,
                } => (
                    5,
                    CanonicalValue::Null,
                    identity_revoke_head_digest.to_canonical_value(),
                    CanonicalValue::Null,
                    CanonicalValue::Null,
                ),
            };
        let mut fields = vec![
            (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Unsigned(u64::from(self.protocol_version)),
            ),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.submission_id.to_string()),
            ),
            (CanonicalValue::Unsigned(3), scope_value(self.scope)),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text(self.actor_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Text(self.actor_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Text(self.candidate_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Text(self.candidate_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(8),
                if self.protocol_version == 4
                    || matches!(
                        self.authorization,
                        MlsCommitAuthorization::ExistingMemberDeviceRemove { .. }
                    )
                {
                    CanonicalValue::Null
                } else {
                    self.candidate_key_package_digest.to_canonical_value()
                },
            ),
            (
                CanonicalValue::Unsigned(9),
                if self.protocol_version == 4
                    || matches!(
                        self.authorization,
                        MlsCommitAuthorization::ExistingMemberDeviceRemove { .. }
                    )
                {
                    CanonicalValue::Null
                } else {
                    self.candidate_proof_digest.to_canonical_value()
                },
            ),
            (
                CanonicalValue::Unsigned(10),
                CanonicalValue::Unsigned(self.expected_epoch),
            ),
            (
                CanonicalValue::Unsigned(11),
                self.expected_head.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(12),
                self.commit_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(13),
                if self.protocol_version == 4
                    || matches!(
                        self.authorization,
                        MlsCommitAuthorization::ExistingMemberDeviceRemove { .. }
                    )
                {
                    CanonicalValue::Null
                } else {
                    self.welcome_digest.to_canonical_value()
                },
            ),
            (
                CanonicalValue::Unsigned(14),
                CanonicalValue::Unsigned(authorization_code),
            ),
            (CanonicalValue::Unsigned(15), command_id),
            (CanonicalValue::Unsigned(16), authorization_digest),
            (CanonicalValue::Unsigned(17), controller_device),
            (CanonicalValue::Unsigned(18), consent),
        ];
        if let MlsCommitAuthorization::ApprovedIdentityJoinV3 {
            join_request_digest,
            approval_request_digest,
            ..
        } = self.authorization
        {
            fields.push((
                CanonicalValue::Unsigned(19),
                join_request_digest.to_canonical_value(),
            ));
            fields.push((
                CanonicalValue::Unsigned(20),
                approval_request_digest.to_canonical_value(),
            ));
        }
        if let MlsCommitAuthorization::ExistingMemberDeviceRecoveryAdd {
            recovery_request_id,
            recovery_request_digest,
            recovery_scope_digest,
            ..
        } = self.authorization
        {
            fields.push((
                CanonicalValue::Unsigned(19),
                CanonicalValue::Text(recovery_request_id.to_string()),
            ));
            fields.push((
                CanonicalValue::Unsigned(20),
                recovery_request_digest.to_canonical_value(),
            ));
            fields.push((
                CanonicalValue::Unsigned(21),
                recovery_scope_digest.to_canonical_value(),
            ));
        }
        let canonical = CanonicalValue::Map(fields);
        encode_deterministic_cbor(&canonical)
            .map(|bytes| {
                Sha256Digest::hash_domain(
                    match self.protocol_version {
                        3 => V3_REQUEST_DIGEST_DOMAIN,
                        4 => V4_REQUEST_DIGEST_DOMAIN,
                        5 => V5_REQUEST_DIGEST_DOMAIN,
                        _ => REQUEST_DIGEST_DOMAIN,
                    },
                    &bytes,
                )
            })
            .map_err(|_| GroupPersistenceError::CorruptData("MLS request encoding"))
    }

    /// Stable submission identity.
    #[must_use]
    pub const fn submission_id(&self) -> RequestId {
        self.submission_id
    }
    /// Frozen Sequencer protocol version used for this request.
    #[must_use]
    pub const fn protocol_version(&self) -> u8 {
        self.protocol_version
    }
    /// Immutable canonical request digest.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }
    /// Conversation scope bound by both candidate and controller proofs.
    #[must_use]
    pub const fn scope(&self) -> GroupScope {
        self.scope
    }
    /// Exact authenticated actor identity.
    #[must_use]
    pub const fn actor_identity_id(&self) -> IdentityId {
        self.actor_identity_id
    }
    /// Exact authenticated actor device.
    #[must_use]
    pub const fn actor_device_id(&self) -> DeviceId {
        self.actor_device_id
    }
    /// Exact candidate identity.
    #[must_use]
    pub const fn candidate_identity_id(&self) -> IdentityId {
        self.candidate_identity_id
    }
    /// Exact candidate device.
    #[must_use]
    pub const fn candidate_device_id(&self) -> DeviceId {
        self.candidate_device_id
    }
    /// `KeyPackage` digest whose possession the candidate proof establishes.
    #[must_use]
    pub const fn candidate_key_package_digest(&self) -> Sha256Digest {
        self.candidate_key_package_digest
    }
    /// Verified candidate proof binding retained in the durable request.
    #[must_use]
    pub const fn candidate_proof_digest(&self) -> Sha256Digest {
        self.candidate_proof_digest
    }
    /// Idempotency key hash bound into both device-proof transcripts.
    #[must_use]
    pub const fn idempotency_key_hash(&self) -> Sha256Digest {
        self.idempotency_key_hash
    }
    /// Expected parent epoch.
    #[must_use]
    pub const fn expected_epoch(&self) -> u64 {
        self.expected_epoch
    }
    /// Expected parent head.
    #[must_use]
    pub const fn expected_head(&self) -> Sha256Digest {
        self.expected_head
    }
    /// Domain-separated opaque commit digest.
    #[must_use]
    pub const fn commit_digest(&self) -> Sha256Digest {
        self.commit_digest
    }
    /// Opaque Welcome digest.
    #[must_use]
    pub const fn welcome_digest(&self) -> Sha256Digest {
        self.welcome_digest
    }
    /// Admission authority, including exact controller-consent binding when required.
    #[must_use]
    pub const fn authorization(&self) -> MlsCommitAuthorization {
        self.authorization
    }
}
