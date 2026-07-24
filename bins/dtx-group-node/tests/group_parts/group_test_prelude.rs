#[path = "../../../../crates/dtx-storage/tests/support/mod.rs"]
mod support;

use std::{
    error::Error,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{
    Clock, ClockError, ConversationId, DeviceEnrollmentChallengeId, DeviceId, DeviceSessionId,
    IdentityId, InviteCapabilityId, JoinRequestId, KeyPackageId, RequestId, Revision, TenantId,
};
use dtx_federated_identity::{
    MLS_V5_RECOVERY_AUTHORIZATION_CONTENT_TYPE, MlsV5RecoveryAuthorizationQuery,
};
use dtx_group_node::{
    DEVICE_SESSION_AUTHORIZATION_SCHEME, GROUP_ACTION_RECEIPT_CONTENT_TYPE,
    GROUP_APPROVE_JOIN_CONTENT_TYPE, GROUP_APPROVE_JOIN_V2_CONTENT_TYPE, GROUP_CREATE_CONTENT_TYPE,
    GROUP_GRANT_ADMIN_CONTENT_TYPE, GROUP_ISSUE_INVITE_CONTENT_TYPE,
    GROUP_JOIN_REQUEST_CONTENT_TYPE, GROUP_JOIN_REQUEST_PAGE_CONTENT_TYPE,
    GROUP_JOIN_REQUEST_PAGE_V2_CONTENT_TYPE, GROUP_JOIN_REQUEST_V2_CONTENT_TYPE,
    GROUP_MEMBERSHIP_RECEIPT_PATH_TEMPLATE, GROUP_QUERY_PROOF_HEADER, GROUP_SCOPE_PATH_TEMPLATE,
    GROUP_SERVICE_DESCRIPTOR_CONTENT_TYPE, GROUP_SERVICE_DESCRIPTOR_PATH, GroupNodeState,
    IDENTITY_ORIGIN_HEADER, MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE, MLS_COMMIT_CONTENT_TYPE,
    MLS_COMMIT_FEED_CONTENT_TYPE, MLS_COMMIT_FEED_V2_CONTENT_TYPE, MLS_COMMIT_FEED_V3_CONTENT_TYPE,
    MLS_COMMIT_PROOF_HEADER, MLS_COMMIT_RECEIPT_CONTENT_TYPE, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE,
    MLS_COMMIT_RECEIPT_V4_CONTENT_TYPE, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE,
    MLS_COMMIT_V3_CONTENT_TYPE, MLS_COMMIT_V4_CONTENT_TYPE, MLS_COMMIT_V5_CONTENT_TYPE,
    MLS_CONFIRMATION_CONTENT_TYPE, MLS_CONFIRMATION_PROOF_HEADER, MLS_CONFIRMATION_V3_CONTENT_TYPE,
    RECEIPT_QUERY_PROOF_HEADER, group_router_with_state,
};
use dtx_group_persistence::{
    GroupControlCommand, GroupControlDisposition, GroupControlOperation, GroupControlRejection,
    GroupControlRepository, GroupMembershipRepository, GroupPgStore,
    MLS_IDEMPOTENCY_KEY_HASH_DOMAIN, MlsCommitAuthorization, MlsCommitCommand,
    MlsDeviceJoinConfirmation, mls_candidate_proof_digest, mls_candidate_proof_signature_input,
    mls_device_confirmation_signature_input, mls_opaque_commit_digest, mls_recovery_scope_digest,
    mls_v5_controller_consent_digest, mls_v5_controller_consent_signature_input,
};
use dtx_group_policy::GroupScope;
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_node::{
    DEVICE_ENROLLMENT_CHALLENGE_PATH, DEVICE_ENROLLMENT_CONTENT_TYPE, DEVICE_ENROLLMENT_PATH,
    DEVICE_REVOKE_PATH_TEMPLATE, HISTORY_RECOVERY_REQUEST_CONTENT_TYPE,
    IDENTITY_LOG_EVENT_CONTENT_TYPE, IdentityBootstrapState, KEY_PACKAGE_CLAIM_PATH,
    KEY_PACKAGE_CLAIM_V2_CONTENT_TYPE, KEY_PACKAGE_PUBLISH_PATH_TEMPLATE,
    KEY_PACKAGE_PUBLISH_V2_CONTENT_TYPE, MLS_V5_RECOVERY_AUTHORIZATION_PATH_TEMPLATE,
    identity_bootstrap_router, identity_bootstrap_router_with_state,
};
use dtx_identity_persistence::{
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DeviceSessionCompletionCommand, DeviceSessionOutcome,
    DeviceSessionRepository, HISTORY_RECOVERY_REQUEST_HASH_DOMAIN, IdentityAppendCommand,
    IdentityAppendOutcome, IdentityLogHead, IdentityLogRepository, IdentityPgStore,
    KEY_PACKAGE_BYTES_HASH_DOMAIN, device_session_proof_input,
    history_recovery_request_signature_input, history_recovery_request_unsigned_canonical_bytes,
    key_package_publish_signature_input,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, Sha256Digest, SigningPublicKey, UtcMillis,
    decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::postgres::PgConnectOptions;
use tower::ServiceExt;

const AUDIENCE: &str = "https://group.test";
const NOW: i64 = 2_000;
const IDEMPOTENCY_HASH_DOMAIN: &[u8] = b"dirextalk.membership-idempotency-key.v1\0";
const BUSINESS_FIELDS_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-business-fields.v1\0";
const ACTION_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-binding.v1\0";
const ACTION_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.membership-action-signature.v1\0";
const FEDERATED_ACTION_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.membership-action-binding.v2\0";
const FEDERATED_ACTION_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.membership-action-signature.v2\0";
const GROUP_QUERY_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.group-query-binding.v1\0";
const GROUP_QUERY_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.group-query-signature.v1\0";
const MLS_CONFIRMATION_BODY_HASH_DOMAIN: &[u8] = b"dirextalk.mls-confirmation-body.v3\0";
const MLS_CONFIRMATION_BINDING_HASH_DOMAIN: &[u8] = b"dirextalk.mls-confirmation-binding.v3\0";
const MLS_CONFIRMATION_PROOF_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.mls-confirmation-proof-signature.v3\0";
const MLS_COMMIT_REQUEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-commit-request.v3\0";
const MLS_COMMIT_FEDERATED_BINDING_HASH_DOMAIN: &[u8] =
    b"dirextalk.mls-commit-federated-binding.v3\0";
const MLS_COMMIT_FEDERATED_PROOF_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.mls-commit-federated-proof-signature.v3\0";
