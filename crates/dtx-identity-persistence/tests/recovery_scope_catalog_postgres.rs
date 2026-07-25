#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, str::FromStr, time::Duration};

use dtx_domain::{DeviceId, DeviceSessionId, IdentityId};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    RelayDescriptorV1, UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1,
    device_certificate_signature_input, genesis_recovery_acceptance_input,
    identity_log_signature_input,
};
use dtx_identity_persistence::{
    CATALOG_CIPHERTEXT_HASH_DOMAIN, CATALOG_HEAD_SIGNATURE_DOMAIN,
    CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN, CatalogPreparationCommand,
    CatalogProviderResponseCommand, CatalogStatus, CatalogStatusInvalidation, CatalogUploadCommand,
    CreateDeviceEnrollmentChallengeCommand, DEVICE_SESSION_SECRET_HASH_DOMAIN,
    DeviceEnrollmentApprovalCommand, DeviceEnrollmentCapability, DeviceEnrollmentChallengeOutcome,
    DeviceEnrollmentRepository, DeviceSessionCompletionCommand, DeviceSessionCredential,
    DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogHead,
    IdentityLogRepository, IdentityPersistenceError, IdentityPgStore, PREPARATION_SIGNATURE_DOMAIN,
    PROVIDER_AAD_DIGEST_DOMAIN, PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
    PROVIDER_CIPHERTEXT_HASH_DOMAIN, PROVIDER_RESPONSE_SIGNATURE_DOMAIN, RECIPIENT_KEY_HASH_DOMAIN,
    RESPONSE_CAPABILITY_HASH_DOMAIN, RecoveryResponseCapability, RecoveryScopeCatalogRepository,
    device_session_proof_input,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};

const AUTHORITY_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a3";
const PROVIDER_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a4";
const CANDIDATE_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a5";
const SECOND_CANDIDATE_DEVICE: &str = "0190f2a5-7b1c-7abc-8def-0123456789a6";

include!("recovery_scope_catalog_parts/helpers.rs");

mod observations {
    use super::*;
    include!("recovery_scope_catalog_parts/observations.rs");
}
mod workflow {
    use super::*;
    include!("recovery_scope_catalog_parts/workflow.rs");
}
