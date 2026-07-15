//! Durable single-node MLS Commit Sequencer.
//!
//! This module deliberately treats MLS artifacts as opaque. It serializes one
//! commit per conversation head, binds device admission to an approved GM1
//! workflow or an existing identity's active controller, and requires the new
//! device to confirm the signed receipt before becoming routable.

use dtx_domain::{DeviceId, IdentityId, RequestId, TenantId};
use dtx_group_policy::GroupScope;
use dtx_identity_persistence::{DeviceSessionCredential, DeviceSessionRepository};
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
        resolve_mls_commit_in_transaction, settle,
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
                self.candidate_key_package_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(9),
                self.candidate_proof_digest.to_canonical_value(),
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
                self.welcome_digest.to_canonical_value(),
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
        let canonical = CanonicalValue::Map(fields);
        encode_deterministic_cbor(&canonical)
            .map(|bytes| {
                Sha256Digest::hash_domain(
                    if self.protocol_version == 3 {
                        V3_REQUEST_DIGEST_DOMAIN
                    } else {
                        REQUEST_DIGEST_DOMAIN
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

fn mls_device_proof_transcript(command: &MlsCommitCommand) -> CanonicalValue {
    let (operation, membership_command, approval_digest, controller_device) =
        match command.authorization {
            MlsCommitAuthorization::OwnerBootstrap => (
                1,
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
                2,
                CanonicalValue::Text(membership_command_id.request_id().to_string()),
                authorization_digest.to_canonical_value(),
                CanonicalValue::Null,
            ),
            MlsCommitAuthorization::ExistingMemberDeviceAdd {
                controller_device_id,
                ..
            } => (
                3,
                CanonicalValue::Null,
                CanonicalValue::Null,
                CanonicalValue::Text(controller_device_id.to_string()),
            ),
        };
    CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Unsigned(operation),
        ),
        (CanonicalValue::Unsigned(3), scope_value(command.scope)),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(command.submission_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            command.idempotency_key_hash.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(command.actor_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(command.actor_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(command.candidate_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Text(command.candidate_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(10),
            command.candidate_key_package_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(11),
            CanonicalValue::Unsigned(command.expected_epoch),
        ),
        (
            CanonicalValue::Unsigned(12),
            command.expected_head.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(13),
            CanonicalValue::Unsigned(command.expected_epoch + 1),
        ),
        (
            CanonicalValue::Unsigned(14),
            command.commit_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(15),
            command.welcome_digest.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(16), membership_command),
        (CanonicalValue::Unsigned(17), approval_digest),
        (CanonicalValue::Unsigned(18), controller_device),
    ])
}

/// Canonical V2 proof transcript bytes shared by candidate and controller.
///
/// # Errors
///
/// Returns a corruption error if the bounded transcript cannot be encoded.
pub fn mls_device_proof_transcript_canonical_bytes(
    command: &MlsCommitCommand,
) -> Result<Vec<u8>, GroupPersistenceError> {
    encode_deterministic_cbor(&mls_device_proof_transcript(command))
        .map_err(|_| GroupPersistenceError::CorruptData("MLS device proof encoding"))
}

/// Recomputes the V2 candidate proof digest from server-decoded request facts.
///
/// # Errors
///
/// Returns a corruption error if the bounded transcript cannot be encoded.
pub fn mls_candidate_proof_digest(
    command: &MlsCommitCommand,
) -> Result<Sha256Digest, GroupPersistenceError> {
    let bytes = mls_device_proof_transcript_canonical_bytes(command)?;
    Ok(Sha256Digest::hash_domain(
        MLS_CANDIDATE_PROOF_DIGEST_DOMAIN,
        &bytes,
    ))
}

/// Exact candidate signature input for the V2 recomputed transcript digest.
///
/// # Errors
///
/// Returns a corruption error if the bounded transcript cannot be encoded.
pub fn mls_candidate_proof_signature_input(
    command: &MlsCommitCommand,
) -> Result<Vec<u8>, GroupPersistenceError> {
    let digest = mls_candidate_proof_digest(command)?;
    let mut input =
        Vec::with_capacity(MLS_CANDIDATE_PROOF_SIGNATURE_DOMAIN.len() + digest.as_bytes().len());
    input.extend_from_slice(MLS_CANDIDATE_PROOF_SIGNATURE_DOMAIN);
    input.extend_from_slice(digest.as_bytes());
    Ok(input)
}

/// Recomputes the V2 active-controller consent digest.
///
/// # Errors
///
/// Rejects non-device-add commands and transcript encoding failures.
pub fn mls_controller_consent_digest(
    command: &MlsCommitCommand,
) -> Result<Sha256Digest, GroupPersistenceError> {
    if !matches!(
        command.authorization,
        MlsCommitAuthorization::ExistingMemberDeviceAdd { .. }
    ) {
        return Err(GroupPersistenceError::MlsAuthorizationRejected);
    }
    let bytes = mls_device_proof_transcript_canonical_bytes(command)?;
    Ok(Sha256Digest::hash_domain(
        MLS_CONTROLLER_CONSENT_DIGEST_DOMAIN,
        &bytes,
    ))
}

/// Exact controller signature input for the V2 recomputed transcript digest.
///
/// # Errors
///
/// Rejects non-device-add commands and transcript encoding failures.
pub fn mls_controller_consent_signature_input(
    command: &MlsCommitCommand,
) -> Result<Vec<u8>, GroupPersistenceError> {
    let digest = mls_controller_consent_digest(command)?;
    let mut input =
        Vec::with_capacity(MLS_CONTROLLER_CONSENT_SIGNATURE_DOMAIN.len() + digest.as_bytes().len());
    input.extend_from_slice(MLS_CONTROLLER_CONSENT_SIGNATURE_DOMAIN);
    input.extend_from_slice(digest.as_bytes());
    Ok(input)
}

/// Immutable signed receipt returned after one CAS-accepted opaque commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsCommitReceipt {
    protocol_version: u8,
    submission_id: RequestId,
    request_digest: Sha256Digest,
    admitted_epoch: u64,
    head_digest: Sha256Digest,
    commit_digest: Sha256Digest,
    welcome_digest: Sha256Digest,
    candidate_key_package_digest: Sha256Digest,
    join_request_digest: Option<Sha256Digest>,
    approval_request_digest: Option<Sha256Digest>,
    canonical_cbor: Vec<u8>,
    receipt_digest: Sha256Digest,
    signing_public_key: SigningPublicKey,
    signature: Ed25519Signature,
}

impl MlsCommitReceipt {
    /// Frozen protocol version of the stored receipt.
    #[must_use]
    pub const fn protocol_version(&self) -> u8 {
        self.protocol_version
    }
    /// Stable submission ID used to query after response loss.
    #[must_use]
    pub const fn submission_id(&self) -> RequestId {
        self.submission_id
    }
    /// Exact request digest retained for conflict detection.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }
    /// Epoch admitted by the single-node sequencer.
    #[must_use]
    pub const fn admitted_epoch(&self) -> u64 {
        self.admitted_epoch
    }
    /// New canonical conversation head.
    #[must_use]
    pub const fn head_digest(&self) -> Sha256Digest {
        self.head_digest
    }
    /// Opaque commit digest.
    #[must_use]
    pub const fn commit_digest(&self) -> Sha256Digest {
        self.commit_digest
    }
    /// Opaque Welcome digest.
    #[must_use]
    pub const fn welcome_digest(&self) -> Sha256Digest {
        self.welcome_digest
    }
    /// Exact candidate `KeyPackage` admitted by this receipt.
    #[must_use]
    pub const fn candidate_key_package_digest(&self) -> Sha256Digest {
        self.candidate_key_package_digest
    }
    /// Candidate-authored V2 join request digest for V3 receipts.
    #[must_use]
    pub const fn join_request_digest(&self) -> Option<Sha256Digest> {
        self.join_request_digest
    }
    /// Owner/Admin V2 approval request digest for V3 receipts.
    #[must_use]
    pub const fn approval_request_digest(&self) -> Option<Sha256Digest> {
        self.approval_request_digest
    }
    /// Canonical unsigned receipt bytes signed by the server.
    #[must_use]
    pub fn canonical_cbor(&self) -> &[u8] {
        &self.canonical_cbor
    }
    /// Digest bound by device join confirmation.
    #[must_use]
    pub const fn receipt_digest(&self) -> Sha256Digest {
        self.receipt_digest
    }
    /// Server receipt verification key.
    #[must_use]
    pub const fn signing_public_key(&self) -> SigningPublicKey {
        self.signing_public_key
    }
    /// Server receipt signature.
    #[must_use]
    pub const fn signature(&self) -> Ed25519Signature {
        self.signature
    }
}

/// Submit outcome distinguishing a first response from exact replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsCommitExecution {
    receipt: MlsCommitReceipt,
    replayed: bool,
}

/// One immutable V30 commit-feed item. The signed receipt and opaque commit
/// bytes are loaded from the same durable sequencer intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsCommitFeedItem {
    receipt: MlsCommitReceipt,
    commit_bytes: Vec<u8>,
}

impl MlsCommitFeedItem {
    /// Exact signed receipt facts for the admitted commit.
    #[must_use]
    pub fn receipt(&self) -> &MlsCommitReceipt {
        &self.receipt
    }

    /// Exact opaque MLS Commit bytes submitted for this epoch.
    #[must_use]
    pub fn commit_bytes(&self) -> &[u8] {
        &self.commit_bytes
    }
}

/// Bounded keyset page of consecutive V30 commits after one known epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsCommitFeedPage {
    after_epoch: u64,
    items: Vec<MlsCommitFeedItem>,
}

impl MlsCommitFeedPage {
    /// Epoch supplied by the caller.
    #[must_use]
    pub const fn after_epoch(&self) -> u64 {
        self.after_epoch
    }

    /// Consecutive V30 commits ordered by admitted epoch.
    #[must_use]
    pub fn items(&self) -> &[MlsCommitFeedItem] {
        &self.items
    }
}

impl MlsCommitExecution {
    /// Immutable receipt.
    #[must_use]
    pub fn receipt(&self) -> &MlsCommitReceipt {
        &self.receipt
    }
    /// Whether a durable response was replayed.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

/// Exact state of an identity/device MLS leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlsDeviceMemberState {
    PendingConfirmation,
    Active,
    Removed,
}

/// Candidate-signed confirmation of the accepted receipt and current head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlsDeviceJoinConfirmation {
    pub submission_id: RequestId,
    pub identity_id: IdentityId,
    pub device_id: DeviceId,
    pub receipt_digest: Sha256Digest,
    pub head_digest: Sha256Digest,
    pub signature: Ed25519Signature,
}

/// Durable single-node sequencer repository.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlsCommitSequencerRepository;

#[allow(clippy::missing_errors_doc, clippy::too_many_arguments)]
impl MlsCommitSequencerRepository {
    /// Authenticates a local active member device, verifies its fresh
    /// route/query proof, and returns a bounded consecutive V30 commit page.
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_feed_authenticated_with_proof<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        actor_identity_id: IdentityId,
        actor_device_id: DeviceId,
        scope: GroupScope,
        after_epoch: u64,
        limit: usize,
        now_ms: i64,
        expected_signing_key: SigningPublicKey,
        verify_proof: F,
    ) -> Result<MlsCommitFeedPage, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        let result = async {
            if authenticated.session().identity_id() != actor_identity_id
                || authenticated.session().device_id() != actor_device_id
            {
                return Err(GroupPersistenceError::DeviceAuthenticationRejected);
            }
            verify_proof(authenticated.signing_key())?;
            load_commit_feed_in_transaction(
                session.connection(),
                tenant_id,
                scope,
                actor_identity_id,
                actor_device_id,
                after_epoch,
                limit,
                expected_signing_key,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Verifies a federated active device's fresh route/query proof, then
    /// rechecks local active membership before reading the V30 commit page.
    #[allow(clippy::too_many_arguments)]
    pub async fn commit_feed_verified_with_proof<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        actor: VerifiedDeviceActor,
        scope: GroupScope,
        after_epoch: u64,
        limit: usize,
        expected_signing_key: SigningPublicKey,
        verify_proof: F,
    ) -> Result<MlsCommitFeedPage, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            verify_proof(actor.signing_key())?;
            load_commit_feed_in_transaction(
                session.connection(),
                tenant_id,
                scope,
                actor.identity_id(),
                actor.device_id(),
                after_epoch,
                limit,
                expected_signing_key,
            )
            .await
        }
        .await;
        settle(session, result).await
    }

    /// Authenticates the exact actor, recomputes both V2 proof transcripts,
    /// persists the sequencer receipt, and (for an approved identity join)
    /// finalizes the canonical GM1 workflow in the same transaction.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn submit_authenticated<FS>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: &MlsCommitCommand,
        candidate_signature: Ed25519Signature,
        controller_signature: Option<Ed25519Signature>,
        now_ms: i64,
        sequencer_signing_key: SigningPublicKey,
        sign_receipt: FS,
    ) -> Result<MlsCommitExecution, GroupPersistenceError>
    where
        FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
    {
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        let authenticated_session = authenticated.session();
        if authenticated_session.identity_id() != command.actor_identity_id
            || authenticated_session.device_id() != command.actor_device_id
        {
            return settle(
                session,
                Err(GroupPersistenceError::DeviceAuthenticationRejected),
            )
            .await;
        }
        let candidate_key = DeviceSessionRepository::active_device_signing_key_in_transaction(
            session.connection(),
            command.candidate_identity_id,
            command.candidate_device_id,
        )
        .await
        .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)?;
        let expected_candidate_digest = mls_candidate_proof_digest(command)?;
        if expected_candidate_digest != command.candidate_proof_digest {
            return settle(
                session,
                Err(GroupPersistenceError::MlsAuthorizationRejected),
            )
            .await;
        }
        verify_signature(
            candidate_key,
            &mls_candidate_proof_signature_input(command)?,
            candidate_signature,
        )
        .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)?;

        let authorization_result = match command.authorization {
            MlsCommitAuthorization::ExistingMemberDeviceAdd {
                controller_device_id,
                controller_consent_digest,
            } => {
                let controller_signature =
                    controller_signature.ok_or(GroupPersistenceError::MlsAuthorizationRejected)?;
                let expected = mls_controller_consent_digest(command)?;
                if expected == controller_consent_digest {
                    let controller_key =
                        DeviceSessionRepository::active_device_signing_key_in_transaction(
                            session.connection(),
                            command.candidate_identity_id,
                            controller_device_id,
                        )
                        .await
                        .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)?;
                    verify_signature(
                        controller_key,
                        &mls_controller_consent_signature_input(command)?,
                        controller_signature,
                    )
                    .map_err(|_| GroupPersistenceError::MlsAuthorizationRejected)
                } else {
                    Err(GroupPersistenceError::MlsAuthorizationRejected)
                }
            }
            _ if controller_signature.is_some() => {
                Err(GroupPersistenceError::MlsAuthorizationRejected)
            }
            _ => Ok(()),
        };
        if let Err(error) = authorization_result {
            return settle(session, Err(error)).await;
        }
        let result = async {
            let execution = submit_in_transaction(
                session.connection(),
                tenant_id,
                command,
                now_ms,
                sequencer_signing_key,
                |_| Ok(()),
                |_| Ok(()),
                sign_receipt,
            )
            .await?;
            if let MlsCommitAuthorization::ApprovedIdentityJoin {
                membership_command_id,
                ..
            } = command.authorization
            {
                resolve_mls_commit_in_transaction(
                    session.connection(),
                    tenant_id,
                    command.scope,
                    membership_command_id,
                    execution.receipt.receipt_digest,
                    now_ms,
                )
                .await?;
            }
            Ok(execution)
        }
        .await;
        settle(session, result).await
    }

    /// Authenticates the Owner/Admin actor and accepts a V30 approved join
    /// using only the durable candidate join and approval facts. No candidate
    /// signature or private authority is accepted at this boundary.
    pub async fn submit_authenticated_v3<FS>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: &MlsCommitCommand,
        now_ms: i64,
        sequencer_signing_key: SigningPublicKey,
        sign_receipt: FS,
    ) -> Result<MlsCommitExecution, GroupPersistenceError>
    where
        FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
    {
        if command.protocol_version != 3
            || !matches!(
                command.authorization,
                MlsCommitAuthorization::ApprovedIdentityJoinV3 { .. }
            )
        {
            return Err(GroupPersistenceError::MlsAuthorizationRejected);
        }
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        if authenticated.session().identity_id() != command.actor_identity_id
            || authenticated.session().device_id() != command.actor_device_id
        {
            return settle(
                session,
                Err(GroupPersistenceError::DeviceAuthenticationRejected),
            )
            .await;
        }
        let result = async {
            let execution = submit_in_transaction(
                session.connection(),
                tenant_id,
                command,
                now_ms,
                sequencer_signing_key,
                |_| Ok(()),
                |_| Ok(()),
                sign_receipt,
            )
            .await?;
            let MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                membership_command_id,
                ..
            } = command.authorization
            else {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            };
            resolve_mls_commit_in_transaction(
                session.connection(),
                tenant_id,
                command.scope,
                membership_command_id,
                execution.receipt.receipt_digest,
                now_ms,
            )
            .await?;
            Ok(execution)
        }
        .await;
        settle(session, result).await
    }

    /// Authenticates an actor or candidate before returning an immutable receipt.
    pub async fn receipt_authenticated(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        scope: GroupScope,
        submission_id: RequestId,
        now_ms: i64,
        expected_signing_key: SigningPublicKey,
    ) -> Result<MlsCommitReceipt, GroupPersistenceError> {
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        let result = async {
            let receipt = load_receipt(
                session.connection(),
                tenant_id,
                scope,
                submission_id,
                expected_signing_key,
            )
            .await?
            .ok_or(GroupPersistenceError::GroupNotFound)?;
            let allowed: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.mls_commit_intents
                  WHERE tenant_id=$1 AND submission_id=$2 AND scope_kind=$3 AND scope_id=$4
                    AND ((actor_identity_id=$5 AND actor_device_id=$6)
                      OR (candidate_identity_id=$5 AND candidate_device_id=$6)))",
            )
            .bind(Uuid::from(tenant_id))
            .bind(Uuid::from(submission_id))
            .bind(scope_columns(scope).0)
            .bind(scope_columns(scope).1)
            .bind(authenticated.session().identity_id().to_string())
            .bind(Uuid::from(authenticated.session().device_id()))
            .fetch_one(session.connection())
            .await?;
            if !allowed {
                return Err(GroupPersistenceError::DeviceAuthenticationRejected);
            }
            Ok(receipt)
        }
        .await;
        settle(session, result).await
    }

    /// Authenticates the exact candidate device before activating its leaf.
    pub async fn confirm_authenticated(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        confirmation: MlsDeviceJoinConfirmation,
        now_ms: i64,
    ) -> Result<bool, GroupPersistenceError> {
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        let authenticated_session = authenticated.session();
        if authenticated_session.identity_id() != confirmation.identity_id
            || authenticated_session.device_id() != confirmation.device_id
        {
            return settle(
                session,
                Err(GroupPersistenceError::DeviceAuthenticationRejected),
            )
            .await;
        }
        let result = confirm_in_transaction(
            session.connection(),
            tenant_id,
            confirmation,
            now_ms,
            authenticated.signing_key(),
        )
        .await;
        settle(session, result).await
    }

    /// Confirms a V30 leaf after the Group Node has freshly resolved the exact
    /// federated candidate device and verified its route/body-bound proof.
    pub async fn confirm_verified(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        confirmation: MlsDeviceJoinConfirmation,
        now_ms: i64,
        candidate_signing_key: SigningPublicKey,
    ) -> Result<bool, GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result = confirm_in_transaction(
            session.connection(),
            tenant_id,
            confirmation,
            now_ms,
            candidate_signing_key,
        )
        .await;
        settle(session, result).await
    }

    /// CAS-submits an opaque commit, writes intent/outbox first, then signs and stores its receipt.
    ///
    /// For [`MlsCommitAuthorization::ApprovedIdentityJoin`], the worker that
    /// delivers this outbox receipt must next feed its commit reference into
    /// [`crate::GroupMembershipRepository::resolve_action`] as
    /// `SequencerResolution::Committed`. Until that GM1 transaction adds the
    /// identity to `groups.members`, [`Self::is_device_active`] remains false
    /// even after device confirmation. This repository intentionally does not
    /// forge that terminal policy transition.
    pub async fn submit<FC, FA, FS>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        command: &MlsCommitCommand,
        now_ms: i64,
        sequencer_signing_key: SigningPublicKey,
        verify_candidate_proof: FC,
        verify_authorization_proof: FA,
        sign_receipt: FS,
    ) -> Result<MlsCommitExecution, GroupPersistenceError>
    where
        FC: FnOnce(&MlsCommitCommand) -> Result<(), GroupPersistenceError>,
        FA: FnOnce(&MlsCommitCommand) -> Result<(), GroupPersistenceError>,
        FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
    {
        let mut session = store.begin(tenant_id).await?;
        let result = submit_in_transaction(
            session.connection(),
            tenant_id,
            command,
            now_ms,
            sequencer_signing_key,
            verify_candidate_proof,
            verify_authorization_proof,
            sign_receipt,
        )
        .await;
        settle(session, result).await
    }

    /// Queries the original immutable receipt after any lost response.
    pub async fn receipt(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        scope: GroupScope,
        submission_id: RequestId,
        expected_signing_key: SigningPublicKey,
    ) -> Result<MlsCommitReceipt, GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result = load_receipt(
            session.connection(),
            tenant_id,
            scope,
            submission_id,
            expected_signing_key,
        )
        .await?
        .ok_or(GroupPersistenceError::GroupNotFound);
        settle(session, result).await
    }

    /// Confirms that the exact new device processed the signed receipt/head.
    pub async fn confirm(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        confirmation: MlsDeviceJoinConfirmation,
        now_ms: i64,
        candidate_signing_key: SigningPublicKey,
    ) -> Result<bool, GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result = confirm_in_transaction(
            session.connection(),
            tenant_id,
            confirmation,
            now_ms,
            candidate_signing_key,
        )
        .await;
        settle(session, result).await
    }

    /// Exact Router admission query. Identity-level membership alone is insufficient.
    pub async fn is_device_active(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        scope: GroupScope,
        identity_id: IdentityId,
        device_id: DeviceId,
    ) -> Result<bool, GroupPersistenceError> {
        let (kind, id) = scope_columns(scope);
        let mut session = store.begin(tenant_id).await?;
        let result = sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1 FROM groups.mls_device_members device
                 JOIN groups.members member USING (tenant_id,scope_kind,scope_id,identity_id)
                  WHERE device.tenant_id=$1 AND device.scope_kind=$2 AND device.scope_id=$3
                    AND device.identity_id=$4 AND device.device_id=$5 AND device.state='active')",
        )
        .bind(Uuid::from(tenant_id))
        .bind(kind)
        .bind(id)
        .bind(identity_id.to_string())
        .bind(Uuid::from(device_id))
        .fetch_one(session.connection())
        .await
        .map_err(Into::into);
        settle(session, result).await
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn submit_in_transaction<FC, FA, FS>(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
    now_ms: i64,
    sequencer_signing_key: SigningPublicKey,
    verify_candidate_proof: FC,
    verify_authorization_proof: FA,
    sign_receipt: FS,
) -> Result<MlsCommitExecution, GroupPersistenceError>
where
    FC: FnOnce(&MlsCommitCommand) -> Result<(), GroupPersistenceError>,
    FA: FnOnce(&MlsCommitCommand) -> Result<(), GroupPersistenceError>,
    FS: FnOnce(&[u8]) -> Result<Ed25519Signature, GroupPersistenceError>,
{
    let (kind, id) = scope_columns(command.scope);
    let submission_lock = format!("{}:mls-submission:{}", tenant_id, command.submission_id);
    let idempotency_lock = format!(
        "{}:mls-idempotency:{}:{}:{}:{}",
        tenant_id, kind, id, command.actor_identity_id, command.idempotency_key_hash
    );
    let commit_lock = format!(
        "{}:mls-commit:{}:{}:{}",
        tenant_id, kind, id, command.commit_digest
    );
    let candidate_lock = format!(
        "{}:mls-candidate:{}:{}:{}:{}",
        tenant_id, kind, id, command.candidate_identity_id, command.candidate_device_id
    );
    let mut locks = vec![
        submission_lock,
        idempotency_lock,
        commit_lock,
        candidate_lock,
    ];
    if let MlsCommitAuthorization::ApprovedIdentityJoin {
        membership_command_id,
        ..
    }
    | MlsCommitAuthorization::ApprovedIdentityJoinV3 {
        membership_command_id,
        ..
    } = command.authorization
    {
        locks.push(format!(
            "{}:mls-membership-command:{}:{}:{}",
            tenant_id,
            kind,
            id,
            membership_command_id.request_id()
        ));
    }
    locks.sort();
    for lock in locks {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(lock)
            .execute(&mut *connection)
            .await?;
    }
    let policy = sqlx::query(
        "SELECT owner_identity_id FROM groups.policy_heads
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(GroupPersistenceError::GroupNotFound)?;

    if let Some(existing) =
        load_existing_submission(connection, tenant_id, command, sequencer_signing_key).await?
    {
        return replay_or_conflict(existing, command);
    }
    if let Some(existing) =
        load_existing_idempotency(connection, tenant_id, command, sequencer_signing_key).await?
    {
        return replay_or_conflict(existing, command);
    }
    if commit_digest_exists(connection, tenant_id, command).await? {
        return Err(GroupPersistenceError::MlsCommitConflict);
    }
    if membership_command_was_admitted(connection, tenant_id, command).await? {
        return Err(GroupPersistenceError::MlsAuthorizationRejected);
    }

    verify_candidate_proof(command)?;
    verify_authorization_proof(command)?;
    authorize(
        connection,
        tenant_id,
        command,
        policy.try_get("owner_identity_id")?,
    )
    .await?;
    let current = sqlx::query(
        "SELECT epoch, head_digest FROM groups.mls_heads
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .fetch_optional(&mut *connection)
    .await?;
    match current {
        Some(row) => {
            let epoch = u64::try_from(row.try_get::<i64, _>("epoch")?)
                .map_err(|_| GroupPersistenceError::CorruptData("MLS epoch"))?;
            let head = digest(row.try_get("head_digest")?, "MLS head")?;
            if epoch != command.expected_epoch || head != command.expected_head {
                return Err(GroupPersistenceError::StaleMlsHead);
            }
        }
        None if command.expected_epoch == 0
            && command.expected_head == Sha256Digest::from_bytes([0; 32])
            && matches!(
                command.authorization,
                MlsCommitAuthorization::OwnerBootstrap
            ) => {}
        None => return Err(GroupPersistenceError::StaleMlsHead),
    }
    let admitted_epoch = command.expected_epoch + 1;
    let head_digest = next_head(command, admitted_epoch)?;

    insert_intent(
        connection,
        tenant_id,
        command,
        admitted_epoch,
        head_digest,
        now_ms,
    )
    .await?;
    sqlx::query(
        "INSERT INTO groups.mls_sequencer_outbox
             (tenant_id, submission_id, scope_kind, scope_id, event_kind, payload_digest, created_at_ms)
         VALUES ($1,$2,$3,$4,'mls_commit_accepted',$5,$6)",
    ).bind(Uuid::from(tenant_id)).bind(Uuid::from(command.submission_id))
      .bind(kind).bind(&id).bind(command.request_digest.as_bytes().as_slice()).bind(now_ms)
      .execute(&mut *connection).await?;

    let canonical_cbor = receipt_cbor(command, admitted_epoch, head_digest)?;
    let receipt_digest = Sha256Digest::hash_domain(
        if command.protocol_version == 3 {
            V3_RECEIPT_DIGEST_DOMAIN
        } else {
            RECEIPT_DIGEST_DOMAIN
        },
        &canonical_cbor,
    );
    let signature_input = receipt_signature_input(command.protocol_version, receipt_digest);
    let signature = sign_receipt(&signature_input)?;
    verify_signature(sequencer_signing_key, &signature_input, signature)?;
    sqlx::query(
        "INSERT INTO groups.mls_commit_receipts
             (tenant_id, submission_id, receipt_cbor, receipt_digest, signing_public_key, signature)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(command.submission_id))
    .bind(&canonical_cbor)
    .bind(receipt_digest.as_bytes().as_slice())
    .bind(sequencer_signing_key.as_bytes().as_slice())
    .bind(signature.as_bytes().as_slice())
    .execute(&mut *connection)
    .await?;

    sqlx::query(
        "INSERT INTO groups.mls_heads
             (tenant_id,scope_kind,scope_id,epoch,head_digest,updated_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (tenant_id,scope_kind,scope_id) DO UPDATE
           SET epoch=EXCLUDED.epoch, head_digest=EXCLUDED.head_digest,
               updated_at_ms=EXCLUDED.updated_at_ms",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .bind(i64::try_from(admitted_epoch).map_err(|_| GroupPersistenceError::StaleMlsHead)?)
    .bind(head_digest.as_bytes().as_slice())
    .bind(now_ms)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO groups.mls_device_members
             (tenant_id,scope_kind,scope_id,identity_id,device_id,admitted_epoch,
              commit_digest,state,updated_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'pending_confirmation',$8)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .bind(command.candidate_identity_id.to_string())
    .bind(Uuid::from(command.candidate_device_id))
    .bind(i64::try_from(admitted_epoch).map_err(|_| GroupPersistenceError::StaleMlsHead)?)
    .bind(command.commit_digest.as_bytes().as_slice())
    .bind(now_ms)
    .execute(&mut *connection)
    .await?;

    Ok(MlsCommitExecution {
        receipt: MlsCommitReceipt {
            protocol_version: command.protocol_version,
            submission_id: command.submission_id,
            request_digest: command.request_digest,
            admitted_epoch,
            head_digest,
            commit_digest: command.commit_digest,
            welcome_digest: command.welcome_digest,
            candidate_key_package_digest: command.candidate_key_package_digest,
            join_request_digest: match command.authorization {
                MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                    join_request_digest,
                    ..
                } => Some(join_request_digest),
                _ => None,
            },
            approval_request_digest: match command.authorization {
                MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                    approval_request_digest,
                    ..
                } => Some(approval_request_digest),
                _ => None,
            },
            canonical_cbor,
            receipt_digest,
            signing_public_key: sequencer_signing_key,
            signature,
        },
        replayed: false,
    })
}

#[allow(clippy::too_many_lines)]
async fn authorize(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
    owner_identity_id: String,
) -> Result<(), GroupPersistenceError> {
    let (kind, id) = scope_columns(command.scope);
    let candidate_device_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM groups.mls_device_members
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
            AND identity_id=$4 AND device_id=$5)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .bind(command.candidate_identity_id.to_string())
    .bind(Uuid::from(command.candidate_device_id))
    .fetch_one(&mut *connection)
    .await?;
    if candidate_device_exists {
        return Err(GroupPersistenceError::MlsAuthorizationRejected);
    }
    match command.authorization {
        MlsCommitAuthorization::OwnerBootstrap => {
            let has_mls_facts: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.mls_heads
                                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3)
                     OR EXISTS (SELECT 1 FROM groups.mls_device_members
                                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .fetch_one(&mut *connection)
            .await?;
            if command.expected_epoch != 0
                || has_mls_facts
                || command.actor_identity_id != command.candidate_identity_id
                || command.actor_device_id != command.candidate_device_id
                || owner_identity_id != command.actor_identity_id.to_string()
            {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            }
        }
        MlsCommitAuthorization::ApprovedIdentityJoin {
            membership_command_id,
            authorization_digest,
        } => {
            let matches: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1 FROM groups.membership_workflows
                      WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
                        AND approval_command_id=$4 AND state='pending_commit'
                        AND candidate_identity_id=$5 AND candidate_device_id=$6
                        AND approval_actor_identity_id=$7 AND approval_actor_device_id=$8
                        AND approval_sequencer_head=$9 AND authorization_digest=$10)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(Uuid::from(membership_command_id.request_id()))
            .bind(command.candidate_identity_id.to_string())
            .bind(Uuid::from(command.candidate_device_id))
            .bind(command.actor_identity_id.to_string())
            .bind(Uuid::from(command.actor_device_id))
            .bind(command.expected_head.as_bytes().as_slice())
            .bind(authorization_digest.as_bytes().as_slice())
            .fetch_one(&mut *connection)
            .await?;
            if !matches {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            }
        }
        MlsCommitAuthorization::ApprovedIdentityJoinV3 {
            membership_command_id,
            authorization_digest,
            join_request_digest,
            approval_request_digest,
        } => {
            let matches: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1
                       FROM groups.membership_workflows AS workflow
                       JOIN groups.membership_commands AS approval
                         ON approval.tenant_id=workflow.tenant_id
                        AND approval.scope_kind=workflow.scope_kind
                        AND approval.scope_id=workflow.scope_id
                        AND approval.command_id=workflow.approval_command_id
                        AND approval.kind='approve_join'
                       JOIN groups.membership_commands AS request
                         ON request.tenant_id=workflow.tenant_id
                        AND request.scope_kind=workflow.scope_kind
                        AND request.scope_id=workflow.scope_id
                        AND request.workflow_id=workflow.request_id
                        AND request.kind='request_join'
                      WHERE workflow.tenant_id=$1
                        AND workflow.scope_kind=$2 AND workflow.scope_id=$3
                        AND workflow.approval_command_id=$4
                        AND workflow.state='pending_commit'
                        AND workflow.candidate_identity_id=$5
                        AND workflow.candidate_device_id=$6
                        AND workflow.candidate_identity_origin IS NOT NULL
                        AND workflow.candidate_key_package_digest=$7
                        AND workflow.approval_actor_identity_id=$8
                        AND workflow.approval_actor_device_id=$9
                        AND workflow.approval_sequencer_head=$10
                        AND workflow.authorization_digest=$11
                        AND request.request_digest=$12
                        AND approval.request_digest=$13)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(Uuid::from(membership_command_id.request_id()))
            .bind(command.candidate_identity_id.to_string())
            .bind(Uuid::from(command.candidate_device_id))
            .bind(command.candidate_key_package_digest.as_bytes().as_slice())
            .bind(command.actor_identity_id.to_string())
            .bind(Uuid::from(command.actor_device_id))
            .bind(command.expected_head.as_bytes().as_slice())
            .bind(authorization_digest.as_bytes().as_slice())
            .bind(join_request_digest.as_bytes().as_slice())
            .bind(approval_request_digest.as_bytes().as_slice())
            .fetch_one(&mut *connection)
            .await?;
            if !matches {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            }
        }
        MlsCommitAuthorization::ExistingMemberDeviceAdd {
            controller_device_id,
            ..
        } => {
            let identity_is_member: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(command.candidate_identity_id.to_string())
            .fetch_one(&mut *connection)
            .await?;
            let controller_active: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.mls_device_members
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4
                    AND device_id=$5 AND state='active')",
            )
            .bind(Uuid::from(tenant_id))
            .bind(kind)
            .bind(&id)
            .bind(command.candidate_identity_id.to_string())
            .bind(Uuid::from(controller_device_id))
            .fetch_one(&mut *connection)
            .await?;
            let actor_is_admin: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM groups.admin_terms
                  WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4 AND active)",
            ).bind(Uuid::from(tenant_id)).bind(kind).bind(&id)
              .bind(command.actor_identity_id.to_string()).fetch_one(&mut *connection).await?;
            let actor_allowed = command.actor_identity_id == command.candidate_identity_id
                || owner_identity_id == command.actor_identity_id.to_string()
                || actor_is_admin;
            if !identity_is_member || !controller_active || !actor_allowed {
                return Err(GroupPersistenceError::MlsAuthorizationRejected);
            }
        }
    }
    Ok(())
}

async fn insert_intent(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
    admitted_epoch: u64,
    result_head_digest: Sha256Digest,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let (kind, id) = scope_columns(command.scope);
    let (
        authorization_kind,
        membership_command_id,
        authorization_digest,
        controller_device_id,
        controller_consent_digest,
        join_request_digest,
        approval_request_digest,
    ) = match command.authorization {
        MlsCommitAuthorization::OwnerBootstrap => {
            ("owner_bootstrap", None, None, None, None, None, None)
        }
        MlsCommitAuthorization::ApprovedIdentityJoin {
            membership_command_id,
            authorization_digest,
        } => (
            "approved_identity_join",
            Some(Uuid::from(membership_command_id.request_id())),
            Some(authorization_digest.as_bytes().to_vec()),
            None,
            None,
            None,
            None,
        ),
        MlsCommitAuthorization::ApprovedIdentityJoinV3 {
            membership_command_id,
            authorization_digest,
            join_request_digest,
            approval_request_digest,
        } => (
            "approved_identity_join",
            Some(Uuid::from(membership_command_id.request_id())),
            Some(authorization_digest.as_bytes().to_vec()),
            None,
            None,
            Some(join_request_digest.as_bytes().to_vec()),
            Some(approval_request_digest.as_bytes().to_vec()),
        ),
        MlsCommitAuthorization::ExistingMemberDeviceAdd {
            controller_device_id,
            controller_consent_digest,
        } => (
            "existing_member_device_add",
            None,
            None,
            Some(Uuid::from(controller_device_id)),
            Some(controller_consent_digest.as_bytes().to_vec()),
            None,
            None,
        ),
    };
    sqlx::query(
        "INSERT INTO groups.mls_commit_intents
          (tenant_id,submission_id,membership_command_id,scope_kind,scope_id,authorization_kind,
           actor_identity_id,actor_device_id,candidate_identity_id,candidate_device_id,
           candidate_key_package_digest,candidate_proof_digest,controller_device_id,
           controller_consent_digest,idempotency_key_hash,request_digest,authorization_digest,
           parent_epoch,parent_head_digest,admitted_epoch,result_head_digest,commit_bytes,commit_digest,welcome_digest,created_at_ms,
           protocol_version,join_request_digest,approval_request_digest)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28)",
    ).bind(Uuid::from(tenant_id)).bind(Uuid::from(command.submission_id)).bind(membership_command_id)
      .bind(kind).bind(id).bind(authorization_kind).bind(command.actor_identity_id.to_string())
      .bind(Uuid::from(command.actor_device_id)).bind(command.candidate_identity_id.to_string())
      .bind(Uuid::from(command.candidate_device_id)).bind(command.candidate_key_package_digest.as_bytes().as_slice())
      .bind(command.candidate_proof_digest.as_bytes().as_slice()).bind(controller_device_id)
      .bind(controller_consent_digest).bind(command.idempotency_key_hash.as_bytes().as_slice())
      .bind(command.request_digest.as_bytes().as_slice()).bind(authorization_digest)
      .bind(i64::try_from(command.expected_epoch).map_err(|_| GroupPersistenceError::StaleMlsHead)?)
      .bind(command.expected_head.as_bytes().as_slice())
      .bind(i64::try_from(admitted_epoch).map_err(|_| GroupPersistenceError::StaleMlsHead)?)
      .bind(result_head_digest.as_bytes().as_slice()).bind(&command.commit_bytes).bind(command.commit_digest.as_bytes().as_slice())
      .bind(command.welcome_digest.as_bytes().as_slice()).bind(now_ms)
      .bind(i16::from(command.protocol_version)).bind(join_request_digest).bind(approval_request_digest)
      .execute(&mut *connection).await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn confirm_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    confirmation: MlsDeviceJoinConfirmation,
    now_ms: i64,
    candidate_signing_key: SigningPublicKey,
) -> Result<bool, GroupPersistenceError> {
    let row = sqlx::query(
        "SELECT intent.scope_kind,intent.scope_id,intent.candidate_identity_id,
                intent.candidate_device_id,receipt.receipt_digest,intent.result_head_digest
           FROM groups.mls_commit_intents intent
           JOIN groups.mls_commit_receipts receipt USING (tenant_id,submission_id)
          WHERE intent.tenant_id=$1 AND intent.submission_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(confirmation.submission_id))
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(GroupPersistenceError::MlsDeviceConfirmationRejected)?;
    if row.try_get::<String, _>("candidate_identity_id")? != confirmation.identity_id.to_string()
        || row.try_get::<Uuid, _>("candidate_device_id")? != Uuid::from(confirmation.device_id)
        || digest(row.try_get("receipt_digest")?, "MLS receipt")? != confirmation.receipt_digest
        || digest(row.try_get("result_head_digest")?, "MLS head")? != confirmation.head_digest
    {
        return Err(GroupPersistenceError::MlsDeviceConfirmationRejected);
    }
    let kind: String = row.try_get("scope_kind")?;
    let id: String = row.try_get("scope_id")?;
    sqlx::query(
        "SELECT state FROM groups.mls_device_members
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4 AND device_id=$5
          FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(&kind)
    .bind(&id)
    .bind(confirmation.identity_id.to_string())
    .bind(Uuid::from(confirmation.device_id))
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(GroupPersistenceError::MlsDeviceConfirmationRejected)?;
    if let Some(existing) = sqlx::query(
        "SELECT identity_id,device_id,receipt_digest,head_digest,signature
           FROM groups.mls_join_confirmations WHERE tenant_id=$1 AND submission_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(confirmation.submission_id))
    .fetch_optional(&mut *connection)
    .await?
    {
        let exact = existing.try_get::<String, _>("identity_id")?
            == confirmation.identity_id.to_string()
            && existing.try_get::<Uuid, _>("device_id")? == Uuid::from(confirmation.device_id)
            && digest(existing.try_get("receipt_digest")?, "confirmation receipt")?
                == confirmation.receipt_digest
            && digest(existing.try_get("head_digest")?, "confirmation head")?
                == confirmation.head_digest
            && existing.try_get::<Vec<u8>, _>("signature")? == confirmation.signature.as_bytes();
        return exact
            .then_some(true)
            .ok_or(GroupPersistenceError::MlsDeviceConfirmationRejected);
    }
    let signature_input = mls_device_confirmation_signature_input(&confirmation)?;
    let key = VerifyingKey::from_bytes(candidate_signing_key.as_bytes())
        .map_err(|_| GroupPersistenceError::MlsDeviceConfirmationRejected)?;
    key.verify_strict(
        &signature_input,
        &Signature::from_bytes(confirmation.signature.as_bytes()),
    )
    .map_err(|_| GroupPersistenceError::MlsDeviceConfirmationRejected)?;
    let updated = sqlx::query(
        "UPDATE groups.mls_device_members SET state='active',updated_at_ms=$6
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND identity_id=$4
            AND device_id=$5 AND state='pending_confirmation'",
    )
    .bind(Uuid::from(tenant_id))
    .bind(&kind)
    .bind(&id)
    .bind(confirmation.identity_id.to_string())
    .bind(Uuid::from(confirmation.device_id))
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(GroupPersistenceError::MlsDeviceConfirmationRejected);
    }
    sqlx::query(
        "INSERT INTO groups.mls_join_confirmations
          (tenant_id,submission_id,scope_kind,scope_id,identity_id,device_id,
           receipt_digest,head_digest,signature,confirmed_at_ms)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(confirmation.submission_id))
    .bind(kind)
    .bind(id)
    .bind(confirmation.identity_id.to_string())
    .bind(Uuid::from(confirmation.device_id))
    .bind(confirmation.receipt_digest.as_bytes().as_slice())
    .bind(confirmation.head_digest.as_bytes().as_slice())
    .bind(confirmation.signature.as_bytes().as_slice())
    .bind(now_ms)
    .execute(&mut *connection)
    .await?;
    Ok(false)
}

async fn load_existing_submission(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
    expected_signing_key: SigningPublicKey,
) -> Result<Option<MlsCommitReceipt>, GroupPersistenceError> {
    let stored_scope = sqlx::query(
        "SELECT scope_kind,scope_id FROM groups.mls_commit_intents
          WHERE tenant_id=$1 AND submission_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(command.submission_id))
    .fetch_optional(&mut *connection)
    .await?;
    let Some(stored_scope) = stored_scope else {
        return Ok(None);
    };
    let (kind, id) = scope_columns(command.scope);
    if stored_scope.try_get::<String, _>("scope_kind")? != kind
        || stored_scope.try_get::<String, _>("scope_id")? != id
    {
        return Err(GroupPersistenceError::MlsCommitConflict);
    }
    load_receipt(
        connection,
        tenant_id,
        command.scope,
        command.submission_id,
        expected_signing_key,
    )
    .await
}

async fn load_existing_idempotency(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
    expected_signing_key: SigningPublicKey,
) -> Result<Option<MlsCommitReceipt>, GroupPersistenceError> {
    let (kind, id) = scope_columns(command.scope);
    let submission: Option<Uuid> = sqlx::query_scalar(
        "SELECT submission_id FROM groups.mls_commit_intents
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
            AND actor_identity_id=$4 AND idempotency_key_hash=$5",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(id)
    .bind(command.actor_identity_id.to_string())
    .bind(command.idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(submission) = submission else {
        return Ok(None);
    };
    let id = RequestId::try_from(submission)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS submission ID"))?;
    load_receipt(
        connection,
        tenant_id,
        command.scope,
        id,
        expected_signing_key,
    )
    .await
}

async fn commit_digest_exists(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
) -> Result<bool, GroupPersistenceError> {
    let (kind, id) = scope_columns(command.scope);
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM groups.mls_commit_intents
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND commit_digest=$4)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(id)
    .bind(command.commit_digest.as_bytes().as_slice())
    .fetch_one(&mut *connection)
    .await
    .map_err(Into::into)
}

async fn membership_command_was_admitted(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &MlsCommitCommand,
) -> Result<bool, GroupPersistenceError> {
    let membership_command_id = match command.authorization {
        MlsCommitAuthorization::ApprovedIdentityJoin {
            membership_command_id,
            ..
        }
        | MlsCommitAuthorization::ApprovedIdentityJoinV3 {
            membership_command_id,
            ..
        } => membership_command_id,
        MlsCommitAuthorization::OwnerBootstrap
        | MlsCommitAuthorization::ExistingMemberDeviceAdd { .. } => return Ok(false),
    };
    let (kind, id) = scope_columns(command.scope);
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM groups.mls_commit_intents
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND membership_command_id=$4)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(id)
    .bind(Uuid::from(membership_command_id.request_id()))
    .fetch_one(&mut *connection)
    .await
    .map_err(Into::into)
}

async fn load_receipt(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    scope: GroupScope,
    submission_id: RequestId,
    expected_signing_key: SigningPublicKey,
) -> Result<Option<MlsCommitReceipt>, GroupPersistenceError> {
    let (kind, id) = scope_columns(scope);
    let row=sqlx::query(
        "SELECT intent.protocol_version,intent.request_digest,intent.admitted_epoch,intent.commit_digest,intent.welcome_digest,
                intent.candidate_identity_id,intent.candidate_device_id,intent.candidate_key_package_digest,
                intent.join_request_digest,intent.approval_request_digest,
                intent.result_head_digest,receipt.receipt_cbor,receipt.receipt_digest,
                receipt.signing_public_key,receipt.signature
           FROM groups.mls_commit_intents intent
           JOIN groups.mls_commit_receipts receipt USING (tenant_id,submission_id)
          WHERE intent.tenant_id=$1 AND intent.scope_kind=$2 AND intent.scope_id=$3 AND intent.submission_id=$4",
    ).bind(Uuid::from(tenant_id)).bind(kind).bind(id).bind(Uuid::from(submission_id))
      .fetch_optional(&mut *connection).await?;
    row.map(|row| receipt_from_row(submission_id, scope, expected_signing_key, &row))
        .transpose()
}

#[allow(clippy::too_many_arguments)]
async fn load_commit_feed_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    scope: GroupScope,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    after_epoch: u64,
    limit: usize,
    expected_signing_key: SigningPublicKey,
) -> Result<MlsCommitFeedPage, GroupPersistenceError> {
    const MAX_PAGE_SIZE: usize = 64;

    if !(1..=MAX_PAGE_SIZE).contains(&limit) {
        return Err(GroupPersistenceError::CorruptData(
            "invalid MLS commit feed page size",
        ));
    }
    let after_epoch = i64::try_from(after_epoch)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS commit feed epoch"))?;
    let limit = i64::try_from(limit)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS commit feed page size"))?;
    let (kind, id) = scope_columns(scope);
    let active_member: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM groups.members member
             JOIN groups.mls_device_members device
               USING (tenant_id,scope_kind,scope_id,identity_id)
              WHERE member.tenant_id=$1 AND member.scope_kind=$2 AND member.scope_id=$3
                AND member.identity_id=$4 AND device.device_id=$5 AND device.state='active')",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .bind(actor_identity_id.to_string())
    .bind(Uuid::from(actor_device_id))
    .fetch_one(&mut *connection)
    .await?;
    if !active_member {
        return Err(GroupPersistenceError::DeviceAuthenticationRejected);
    }

    let rows = sqlx::query(
        "SELECT intent.submission_id,intent.protocol_version,intent.request_digest,
                intent.admitted_epoch,intent.commit_bytes,intent.commit_digest,intent.welcome_digest,
                intent.candidate_identity_id,intent.candidate_device_id,
                intent.candidate_key_package_digest,intent.join_request_digest,
                intent.approval_request_digest,intent.result_head_digest,
                receipt.receipt_cbor,receipt.receipt_digest,receipt.signing_public_key,
                receipt.signature
           FROM groups.mls_commit_intents intent
           JOIN groups.mls_commit_receipts receipt USING (tenant_id,submission_id)
          WHERE intent.tenant_id=$1 AND intent.scope_kind=$2 AND intent.scope_id=$3
            AND intent.admitted_epoch>$4 AND intent.protocol_version=3
          ORDER BY intent.admitted_epoch
          LIMIT $5",
    )
    .bind(Uuid::from(tenant_id))
    .bind(kind)
    .bind(&id)
    .bind(after_epoch)
    .bind(limit)
    .fetch_all(&mut *connection)
    .await?;

    let mut expected_epoch = u64::try_from(after_epoch)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS commit feed epoch"))?
        .checked_add(1)
        .ok_or(GroupPersistenceError::CorruptData(
            "MLS commit feed epoch overflow",
        ))?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let submission_id = RequestId::try_from(row.try_get::<Uuid, _>("submission_id")?)
            .map_err(|_| GroupPersistenceError::CorruptData("MLS submission ID"))?;
        let receipt = receipt_from_row(submission_id, scope, expected_signing_key, &row)?;
        if receipt.protocol_version() != 3 || receipt.admitted_epoch() != expected_epoch {
            return Err(GroupPersistenceError::CorruptData(
                "non-consecutive MLS commit feed",
            ));
        }
        let commit_bytes: Vec<u8> = row.try_get("commit_bytes")?;
        if mls_opaque_commit_digest(&commit_bytes) != receipt.commit_digest() {
            return Err(GroupPersistenceError::CorruptData("MLS commit feed bytes"));
        }
        items.push(MlsCommitFeedItem {
            receipt,
            commit_bytes,
        });
        expected_epoch =
            expected_epoch
                .checked_add(1)
                .ok_or(GroupPersistenceError::CorruptData(
                    "MLS commit feed epoch overflow",
                ))?;
    }
    Ok(MlsCommitFeedPage {
        after_epoch: u64::try_from(after_epoch)
            .map_err(|_| GroupPersistenceError::CorruptData("MLS commit feed epoch"))?,
        items,
    })
}

fn receipt_from_row(
    submission_id: RequestId,
    scope: GroupScope,
    expected_signing_key: SigningPublicKey,
    row: &sqlx::postgres::PgRow,
) -> Result<MlsCommitReceipt, GroupPersistenceError> {
    let key: [u8; 32] = row
        .try_get::<Vec<u8>, _>("signing_public_key")?
        .try_into()
        .map_err(|_| GroupPersistenceError::CorruptData("MLS receipt key"))?;
    let signature: [u8; 64] = row
        .try_get::<Vec<u8>, _>("signature")?
        .try_into()
        .map_err(|_| GroupPersistenceError::CorruptData("MLS receipt signature"))?;
    let signing_public_key = SigningPublicKey::try_from(key)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS receipt key"))?;
    if signing_public_key != expected_signing_key {
        return Err(GroupPersistenceError::CorruptData("MLS receipt signer"));
    }
    let protocol_version = u8::try_from(row.try_get::<i16, _>("protocol_version")?)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS protocol version"))?;
    if !matches!(protocol_version, 2 | 3) {
        return Err(GroupPersistenceError::CorruptData("MLS protocol version"));
    }
    let request_digest = digest(row.try_get("request_digest")?, "MLS request")?;
    let admitted_epoch = u64::try_from(row.try_get::<i64, _>("admitted_epoch")?)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS admitted epoch"))?;
    let head_digest = digest(row.try_get("result_head_digest")?, "MLS head")?;
    let commit_digest = digest(row.try_get("commit_digest")?, "MLS commit")?;
    let welcome_digest = digest(row.try_get("welcome_digest")?, "MLS Welcome")?;
    let candidate_identity_id = row
        .try_get::<String, _>("candidate_identity_id")?
        .parse()
        .map_err(|_| GroupPersistenceError::CorruptData("MLS candidate identity"))?;
    let candidate_device_id = DeviceId::try_from(row.try_get::<Uuid, _>("candidate_device_id")?)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS candidate device"))?;
    let candidate_key_package_digest = digest(
        row.try_get("candidate_key_package_digest")?,
        "MLS candidate KeyPackage",
    )?;
    let join_request_digest = row
        .try_get::<Option<Vec<u8>>, _>("join_request_digest")?
        .map(|value| digest(value, "MLS join request"))
        .transpose()?;
    let approval_request_digest = row
        .try_get::<Option<Vec<u8>>, _>("approval_request_digest")?
        .map(|value| digest(value, "MLS approval request"))
        .transpose()?;
    let canonical_cbor: Vec<u8> = row.try_get("receipt_cbor")?;
    let expected_cbor = receipt_cbor_facts(
        protocol_version,
        submission_id,
        scope,
        request_digest,
        admitted_epoch,
        head_digest,
        commit_digest,
        welcome_digest,
        candidate_identity_id,
        candidate_device_id,
        candidate_key_package_digest,
        join_request_digest,
        approval_request_digest,
    )?;
    if canonical_cbor != expected_cbor {
        return Err(GroupPersistenceError::CorruptData(
            "MLS receipt canonical bytes",
        ));
    }
    let receipt_digest = digest(row.try_get("receipt_digest")?, "MLS receipt")?;
    if receipt_digest
        != Sha256Digest::hash_domain(
            if protocol_version == 3 {
                V3_RECEIPT_DIGEST_DOMAIN
            } else {
                RECEIPT_DIGEST_DOMAIN
            },
            &canonical_cbor,
        )
    {
        return Err(GroupPersistenceError::CorruptData("MLS receipt digest"));
    }
    let signature = Ed25519Signature::from_bytes(signature);
    verify_signature(
        signing_public_key,
        &receipt_signature_input(protocol_version, receipt_digest),
        signature,
    )?;
    Ok(MlsCommitReceipt {
        protocol_version,
        submission_id,
        request_digest,
        admitted_epoch,
        head_digest,
        commit_digest,
        welcome_digest,
        candidate_key_package_digest,
        join_request_digest,
        approval_request_digest,
        canonical_cbor,
        receipt_digest,
        signing_public_key,
        signature,
    })
}

fn replay_or_conflict(
    existing: MlsCommitReceipt,
    command: &MlsCommitCommand,
) -> Result<MlsCommitExecution, GroupPersistenceError> {
    if existing.request_digest != command.request_digest {
        return Err(GroupPersistenceError::MlsCommitConflict);
    }
    Ok(MlsCommitExecution {
        receipt: existing,
        replayed: true,
    })
}

fn next_head(
    command: &MlsCommitCommand,
    epoch: u64,
) -> Result<Sha256Digest, GroupPersistenceError> {
    let canonical = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            command.expected_head.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(epoch)),
        (
            CanonicalValue::Unsigned(4),
            command.commit_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(5),
            command.welcome_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(command.candidate_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(command.candidate_device_id.to_string()),
        ),
    ]);
    encode_deterministic_cbor(&canonical)
        .map(|v| Sha256Digest::hash_domain(HEAD_DIGEST_DOMAIN, &v))
        .map_err(|_| GroupPersistenceError::CorruptData("MLS head encoding"))
}

fn receipt_cbor(
    command: &MlsCommitCommand,
    epoch: u64,
    head: Sha256Digest,
) -> Result<Vec<u8>, GroupPersistenceError> {
    receipt_cbor_facts(
        command.protocol_version,
        command.submission_id,
        command.scope,
        command.request_digest,
        epoch,
        head,
        command.commit_digest,
        command.welcome_digest,
        command.candidate_identity_id,
        command.candidate_device_id,
        command.candidate_key_package_digest,
        match command.authorization {
            MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                join_request_digest,
                ..
            } => Some(join_request_digest),
            _ => None,
        },
        match command.authorization {
            MlsCommitAuthorization::ApprovedIdentityJoinV3 {
                approval_request_digest,
                ..
            } => Some(approval_request_digest),
            _ => None,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn receipt_cbor_facts(
    protocol_version: u8,
    submission_id: RequestId,
    scope: GroupScope,
    request_digest: Sha256Digest,
    epoch: u64,
    head: Sha256Digest,
    commit_digest: Sha256Digest,
    welcome_digest: Sha256Digest,
    candidate_identity_id: IdentityId,
    candidate_device_id: DeviceId,
    candidate_key_package_digest: Sha256Digest,
    join_request_digest: Option<Sha256Digest>,
    approval_request_digest: Option<Sha256Digest>,
) -> Result<Vec<u8>, GroupPersistenceError> {
    let mut fields = vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Unsigned(if protocol_version == 3 { 3 } else { 1 }),
        ),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(submission_id.to_string()),
        ),
        (CanonicalValue::Unsigned(3), scope_value(scope)),
        (
            CanonicalValue::Unsigned(4),
            request_digest.to_canonical_value(),
        ),
        (CanonicalValue::Unsigned(5), CanonicalValue::Unsigned(epoch)),
        (CanonicalValue::Unsigned(6), head.to_canonical_value()),
        (
            CanonicalValue::Unsigned(7),
            commit_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(8),
            welcome_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Text(candidate_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Text(candidate_device_id.to_string()),
        ),
    ];
    match (
        protocol_version,
        join_request_digest,
        approval_request_digest,
    ) {
        (3, Some(join_request_digest), Some(approval_request_digest)) => {
            fields.push((
                CanonicalValue::Unsigned(11),
                candidate_key_package_digest.to_canonical_value(),
            ));
            fields.push((
                CanonicalValue::Unsigned(12),
                join_request_digest.to_canonical_value(),
            ));
            fields.push((
                CanonicalValue::Unsigned(13),
                approval_request_digest.to_canonical_value(),
            ));
        }
        (2, None, None) => {}
        _ => {
            return Err(GroupPersistenceError::CorruptData(
                "MLS receipt V3 bindings",
            ));
        }
    }
    encode_deterministic_cbor(&CanonicalValue::Map(fields))
        .map_err(|_| GroupPersistenceError::CorruptData("MLS receipt encoding"))
}

fn receipt_signature_input(protocol_version: u8, digest: Sha256Digest) -> Vec<u8> {
    let domain = if protocol_version == 3 {
        V3_RECEIPT_SIGNATURE_DOMAIN
    } else {
        RECEIPT_SIGNATURE_DOMAIN
    };
    let mut input = Vec::with_capacity(domain.len() + 32);
    input.extend_from_slice(domain);
    input.extend_from_slice(digest.as_bytes());
    input
}

fn verify_signature(
    key: SigningPublicKey,
    input: &[u8],
    signature: Ed25519Signature,
) -> Result<(), GroupPersistenceError> {
    let key = VerifyingKey::from_bytes(key.as_bytes())
        .map_err(|_| GroupPersistenceError::CorruptData("MLS receipt signer"))?;
    key.verify_strict(input, &Signature::from_bytes(signature.as_bytes()))
        .map_err(|_| GroupPersistenceError::CorruptData("MLS receipt signature"))
}

fn scope_value(scope: GroupScope) -> CanonicalValue {
    let (kind, id) = scope_columns(scope);
    CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Unsigned(if kind == "private_conversation" { 1 } else { 2 }),
        ),
        (CanonicalValue::Unsigned(2), CanonicalValue::Text(id)),
    ])
}
fn scope_columns(scope: GroupScope) -> (&'static str, String) {
    match scope {
        GroupScope::PrivateConversation(id) => ("private_conversation", id.to_string()),
        GroupScope::ControlledPublicChannel(id) => ("controlled_public_channel", id.to_string()),
    }
}
fn digest(bytes: Vec<u8>, field: &'static str) -> Result<Sha256Digest, GroupPersistenceError> {
    let value: [u8; 32] = bytes
        .try_into()
        .map_err(|_| GroupPersistenceError::CorruptData(field))?;
    Ok(Sha256Digest::from_bytes(value))
}
