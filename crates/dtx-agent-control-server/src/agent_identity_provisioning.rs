use std::{error::Error, fmt};

use dtx_agent_control::{
    DeliverAgentProvisioningCommand, DurableServerCommand, DurableServerCommandSnapshot,
    RevokeAgentProvisioningCommand, ServerCommandPayload, Sha256Digest as ControlSha256Digest,
};
use dtx_agent_persistence::{
    AgentDeviceRepository, AgentInstallationRepository, AgentPersistenceError,
    CommandLogRepository, CurrentWrite, DurableCommandDecoder,
};
use dtx_agent_registry::{
    AgentDeviceCommand, AgentDeviceState, DeviceCredentialFingerprint, InstallationCommand,
    InstallationDesiredState,
};
use dtx_domain::{
    AgentDeviceId, ApprovalId, BindingId, ConnectorId, DeviceId, IdentityId, InstallationId,
    ProvisioningDeliveryId, ProvisioningRecipientKeyId, RequestId, Revision, TenantId,
};
use dtx_identity_log::DeviceStatusV1;
use dtx_identity_persistence::{
    DeviceSessionCredential, DeviceSessionRepository, IdentityPersistenceError,
    lock_and_load_active_snapshot,
};
use dtx_storage::{PgStore, StorageError};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, UtcMillis,
    encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sqlx::Row;
use uuid::Uuid;

use crate::ProtobufDurableCommandEncoder;

pub const AGENT_IDENTITY_APPROVAL_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.agent-identity-approval-signature.v1\0";
pub const AGENT_IDENTITY_APPROVAL_BINDING_DOMAIN: &[u8] =
    b"dirextalk.agent-identity-approval-binding.v1\0";
pub const AGENT_IDENTITY_APPROVAL_REQUEST_DOMAIN: &[u8] =
    b"dirextalk.agent-identity-approval-request.v1\0";
pub const AGENT_DEVICE_CREDENTIAL_FINGERPRINT_DOMAIN: &[u8] =
    b"dirextalk.agent-device-credential-fingerprint.v1\0";
pub const AGENT_IDENTITY_APPROVAL_RECEIPT_DOMAIN: &[u8] =
    b"dirextalk.agent-identity-approval-receipt.v1\0";
pub const AGENT_PROVISIONING_INSTALLED_RECEIPT_DOMAIN: &[u8] =
    b"dirextalk.agent-provisioning-installed-receipt.v1\0";
pub const AGENT_PROVISIONING_CAPSULE_DOMAIN: &[u8] = b"dirextalk.agent-provisioning-capsule.v1\0";
pub const AGENT_PROVISIONING_DELIVERY_BINDING_DOMAIN: &[u8] =
    b"dirextalk.agent-provisioning-delivery-binding.v1\0";
pub const AGENT_PROVISIONING_DELIVERY_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.agent-provisioning-delivery-signature.v1\0";
pub const AGENT_PROVISIONING_DELIVERY_REQUEST_DOMAIN: &[u8] =
    b"dirextalk.agent-provisioning-delivery-request.v1\0";
pub const AGENT_PROVISIONING_REVOCATION_BINDING_DOMAIN: &[u8] =
    b"dirextalk.agent-provisioning-revocation-binding.v1\0";
pub const AGENT_PROVISIONING_REVOCATION_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.agent-provisioning-revocation-signature.v1\0";
pub const AGENT_PROVISIONING_REVOCATION_REQUEST_DOMAIN: &[u8] =
    b"dirextalk.agent-provisioning-revocation-request.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentProvisioningInstalledReceiptFacts {
    pub tenant_id: TenantId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub agent_device_id: AgentDeviceId,
    pub delivery_id: ProvisioningDeliveryId,
    pub recipient_key_id: ProvisioningRecipientKeyId,
    pub bundle_revision: Revision,
    pub capsule_digest: Sha256Digest,
}

/// Recomputes the sidecar installation receipt exclusively from durable facts.
///
/// # Errors
///
/// Returns an error if the frozen receipt cannot be encoded canonically.
pub fn agent_provisioning_installed_receipt_digest(
    facts: AgentProvisioningInstalledReceiptFacts,
) -> Result<Sha256Digest, AgentIdentityProvisioningError> {
    let canonical = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(facts.tenant_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(facts.installation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(facts.binding_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(facts.agent_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(facts.delivery_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(facts.recipient_key_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Unsigned(facts.bundle_revision.get()),
        ),
        (
            CanonicalValue::Unsigned(9),
            facts.capsule_digest.to_canonical_value(),
        ),
    ]))
    .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?;
    Ok(Sha256Digest::hash_domain(
        AGENT_PROVISIONING_INSTALLED_RECEIPT_DOMAIN,
        &canonical,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentIdentityApprovalCommand {
    pub approval_id: ApprovalId,
    pub tenant_id: TenantId,
    pub installation_id: InstallationId,
    pub expected_revision: Revision,
    pub binding_id: BindingId,
    pub agent_device_id: AgentDeviceId,
    pub agent_identity_id: IdentityId,
    pub identity_device_id: DeviceId,
    pub identity_head_sequence: SafeUint,
    pub identity_head_hash: Sha256Digest,
    pub credential_fingerprint: DeviceCredentialFingerprint,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub expires_at: UtcMillis,
    pub owner_signature: Ed25519Signature,
}

impl AgentIdentityApprovalCommand {
    fn unsigned_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.approval_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.tenant_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text(self.installation_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Text(self.binding_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Text(self.agent_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Text(self.agent_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Text(self.identity_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(9),
                self.identity_head_sequence.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(10),
                self.identity_head_hash.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(11),
                CanonicalValue::Bytes(self.credential_fingerprint.as_bytes().to_vec()),
            ),
            (
                CanonicalValue::Unsigned(12),
                CanonicalValue::Unsigned(self.expected_revision.get()),
            ),
            (
                CanonicalValue::Unsigned(13),
                CanonicalValue::Text(self.owner_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(14),
                CanonicalValue::Text(self.owner_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(15),
                self.expires_at.to_canonical_value(),
            ),
        ])
    }

    /// Produces the exact frozen bytes signed by the active Owner device.
    ///
    /// # Errors
    ///
    /// Returns an error if the binding cannot be encoded canonically.
    pub fn signature_input(&self) -> Result<Vec<u8>, AgentIdentityProvisioningError> {
        let digest = self.binding_digest()?;
        let mut input = AGENT_IDENTITY_APPROVAL_SIGNATURE_DOMAIN.to_vec();
        input.extend_from_slice(digest.as_bytes());
        Ok(input)
    }

    fn binding_digest(&self) -> Result<Sha256Digest, AgentIdentityProvisioningError> {
        let canonical = encode_deterministic_cbor(&self.unsigned_canonical_value())
            .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?;
        Ok(Sha256Digest::hash_domain(
            AGENT_IDENTITY_APPROVAL_BINDING_DOMAIN,
            &canonical,
        ))
    }

    fn request_digest(&self) -> Result<Sha256Digest, AgentIdentityProvisioningError> {
        let binding = self.unsigned_canonical_value();
        let binding_digest = self.binding_digest()?;
        let canonical = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), binding),
            (
                CanonicalValue::Unsigned(2),
                binding_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.owner_signature.to_canonical_value(),
            ),
        ]))
        .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?;
        Ok(Sha256Digest::hash_domain(
            AGENT_IDENTITY_APPROVAL_REQUEST_DOMAIN,
            &canonical,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentIdentityApprovalReceipt {
    pub replayed: bool,
    pub approval_id: ApprovalId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub agent_device_id: AgentDeviceId,
    pub agent_identity_id: IdentityId,
    pub identity_device_id: DeviceId,
    pub credential_fingerprint: DeviceCredentialFingerprint,
    pub identity_head_sequence: SafeUint,
    pub identity_head_hash: Sha256Digest,
    pub installation_revision: Revision,
    pub approved_at: UtcMillis,
    pub binding_digest: Sha256Digest,
    pub receipt_digest: Sha256Digest,
    pub exact_cbor: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentProvisioningTarget {
    pub approval_id: ApprovalId,
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub agent_device_id: AgentDeviceId,
    pub provisioning_revision: Revision,
    pub recipient_key_id: ProvisioningRecipientKeyId,
    pub recipient_public_key: [u8; 32],
    pub credential_id: dtx_domain::ConnectorCredentialId,
    pub credential_generation: Revision,
    pub created_at: UtcMillis,
    pub descriptor_digest: Sha256Digest,
    pub recipient_signature: Ed25519Signature,
    pub expires_at: UtcMillis,
    pub exact_cbor: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentProvisioningDeliveryCommand {
    pub delivery_id: ProvisioningDeliveryId,
    pub approval_id: ApprovalId,
    pub tenant_id: TenantId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub agent_device_id: AgentDeviceId,
    pub agent_identity_id: IdentityId,
    pub identity_device_id: DeviceId,
    pub provisioning_revision: Revision,
    pub recipient_key_id: ProvisioningRecipientKeyId,
    pub recipient_descriptor_digest: Sha256Digest,
    pub sealed_capsule: Vec<u8>,
    pub capsule_digest: Sha256Digest,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub created_at: UtcMillis,
    pub expires_at: UtcMillis,
    pub owner_signature: Ed25519Signature,
}

impl AgentProvisioningDeliveryCommand {
    fn binding_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.delivery_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.approval_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text(self.tenant_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Text(self.installation_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Text(self.binding_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Text(self.agent_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Text(self.agent_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(9),
                CanonicalValue::Text(self.identity_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(10),
                CanonicalValue::Unsigned(self.provisioning_revision.get()),
            ),
            (
                CanonicalValue::Unsigned(11),
                CanonicalValue::Text(self.recipient_key_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(12),
                self.recipient_descriptor_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(13),
                self.capsule_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(14),
                CanonicalValue::Text(self.owner_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(15),
                CanonicalValue::Text(self.owner_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(16),
                self.created_at.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(17),
                self.expires_at.to_canonical_value(),
            ),
        ])
    }

    fn binding_bytes(&self) -> Result<Vec<u8>, AgentIdentityProvisioningError> {
        encode_deterministic_cbor(&self.binding_value())
            .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)
    }

    fn binding_digest(&self) -> Result<Sha256Digest, AgentIdentityProvisioningError> {
        Ok(Sha256Digest::hash_domain(
            AGENT_PROVISIONING_DELIVERY_BINDING_DOMAIN,
            &self.binding_bytes()?,
        ))
    }

    fn signature_input(&self) -> Result<Vec<u8>, AgentIdentityProvisioningError> {
        let mut bytes = AGENT_PROVISIONING_DELIVERY_SIGNATURE_DOMAIN.to_vec();
        bytes.extend_from_slice(self.binding_digest()?.as_bytes());
        Ok(bytes)
    }

    fn request_digest(&self) -> Result<Sha256Digest, AgentIdentityProvisioningError> {
        let canonical = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), self.binding_value()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Bytes(self.sealed_capsule.clone()),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.binding_digest()?.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.owner_signature.to_canonical_value(),
            ),
        ]))
        .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?;
        Ok(Sha256Digest::hash_domain(
            AGENT_PROVISIONING_DELIVERY_REQUEST_DOMAIN,
            &canonical,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentProvisioningDeliveryReceipt {
    pub replayed: bool,
    pub delivery_id: ProvisioningDeliveryId,
    pub approval_id: ApprovalId,
    pub installation_id: InstallationId,
    pub provisioning_revision: Revision,
    pub connector_id: ConnectorId,
    pub command_sequence: u64,
    pub command_payload_digest: ControlSha256Digest,
    pub encoded_command_digest: ControlSha256Digest,
    pub capsule_digest: Sha256Digest,
    pub state: String,
    pub result_digest: Option<ControlSha256Digest>,
    pub rejection_code: Option<String>,
    pub created_at: UtcMillis,
    pub resolved_at: Option<UtcMillis>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentProvisioningRevocationCommand {
    pub revocation_id: RequestId,
    pub tenant_id: TenantId,
    pub installation_id: InstallationId,
    pub expected_revision: Revision,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub scope: u8,
    pub expires_at: UtcMillis,
    pub binding_digest: Sha256Digest,
    pub owner_signature: Ed25519Signature,
}

impl AgentProvisioningRevocationCommand {
    fn binding_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.revocation_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.tenant_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text(self.installation_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Unsigned(self.expected_revision.get()),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Text(self.owner_identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Text(self.owner_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Unsigned(u64::from(self.scope)),
            ),
            (
                CanonicalValue::Unsigned(9),
                self.expires_at.to_canonical_value(),
            ),
        ])
    }

    fn calculated_binding_digest(&self) -> Result<Sha256Digest, AgentIdentityProvisioningError> {
        let bytes = encode_deterministic_cbor(&self.binding_value())
            .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?;
        Ok(Sha256Digest::hash_domain(
            AGENT_PROVISIONING_REVOCATION_BINDING_DOMAIN,
            &bytes,
        ))
    }

    fn request_digest(&self) -> Result<Sha256Digest, AgentIdentityProvisioningError> {
        let canonical = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), self.binding_value()),
            (
                CanonicalValue::Unsigned(2),
                self.binding_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.owner_signature.to_canonical_value(),
            ),
        ]))
        .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?;
        Ok(Sha256Digest::hash_domain(
            AGENT_PROVISIONING_REVOCATION_REQUEST_DOMAIN,
            &canonical,
        ))
    }

    fn signature_input(&self) -> Vec<u8> {
        let mut bytes = AGENT_PROVISIONING_REVOCATION_SIGNATURE_DOMAIN.to_vec();
        bytes.extend_from_slice(self.binding_digest.as_bytes());
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentProvisioningRevocationReceipt {
    pub revocation_id: RequestId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub agent_device_id: Option<AgentDeviceId>,
    pub committed_revision: Revision,
    pub scope: u8,
    pub command_sequence: u64,
    pub command_payload_digest: ControlSha256Digest,
    pub encoded_command_digest: ControlSha256Digest,
    pub revoked_at: UtcMillis,
}

/// # Errors
///
/// Rejects stale sessions, invalid proofs, changed retries and persistence conflicts.
pub async fn approve_agent_identity(
    store: &PgStore,
    credential: &DeviceSessionCredential,
    idempotency_key_hash: Sha256Digest,
    command: AgentIdentityApprovalCommand,
    now: UtcMillis,
) -> Result<AgentIdentityApprovalReceipt, AgentIdentityProvisioningError> {
    if now >= command.expires_at {
        return Err(AgentIdentityProvisioningError::Expired);
    }
    let request_digest = command.request_digest()?;
    let mut session = store.begin_tenant(command.tenant_id).await?;
    let result = approve_in_transaction(
        session.connection(),
        credential,
        idempotency_key_hash,
        request_digest,
        command,
        now,
    )
    .await;
    match result {
        Ok(receipt) => {
            session.commit().await?;
            Ok(receipt)
        }
        Err(error) => {
            session.rollback().await?;
            Err(error)
        }
    }
}

/// Reads one committed approval using an exact active owner Device Session.
///
/// # Errors
///
/// Rejects stale sessions, non-owners, missing approvals and corrupt persistence.
pub async fn get_agent_identity_approval(
    store: &PgStore,
    credential: &DeviceSessionCredential,
    tenant_id: TenantId,
    approval_id: ApprovalId,
    now: UtcMillis,
) -> Result<AgentIdentityApprovalReceipt, AgentIdentityProvisioningError> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let owner = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
        session.connection(),
        credential,
        now,
    )
    .await?;
    let row = sqlx::query(
        "SELECT approval_id, installation_id, binding_id, agent_device_id,
                agent_identity_id, identity_device_id,
                credential_fingerprint, identity_head_sequence, identity_head_hash,
                committed_installation_revision, approved_at_ms, receipt_bytes, receipt_digest,
                owner_identity_id, owner_device_id
           FROM agent.agent_identity_approvals
          WHERE tenant_id=$1 AND approval_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(approval_id))
    .fetch_optional(session.connection())
    .await?
    .ok_or(AgentIdentityProvisioningError::NotFound)?;
    let owner_session = owner.session();
    if row.try_get::<String, _>("owner_identity_id")? != owner_session.identity_id().to_string()
        || row.try_get::<Uuid, _>("owner_device_id")? != Uuid::from(owner_session.device_id())
    {
        session.rollback().await?;
        return Err(AgentIdentityProvisioningError::Forbidden);
    }
    let receipt = receipt_from_row(&row)?;
    session.commit().await?;
    Ok(receipt)
}

/// Returns the one current, unconsumed provisioning recipient for an approved binding.
///
/// # Errors
///
/// Rejects non-owners, expired/stale recipients and changed Connector credentials.
#[allow(clippy::too_many_lines)]
pub async fn get_agent_provisioning_target(
    store: &PgStore,
    credential: &DeviceSessionCredential,
    tenant_id: TenantId,
    approval_id: ApprovalId,
    now: UtcMillis,
) -> Result<AgentProvisioningTarget, AgentIdentityProvisioningError> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let owner = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
        session.connection(),
        credential,
        now,
    )
    .await?;
    let row = sqlx::query(
        "SELECT a.installation_id, a.binding_id, a.agent_device_id,
                a.owner_identity_id, a.owner_device_id, a.committed_installation_revision,
                r.connector_id, r.recipient_key_id, r.recipient_public_key,
                r.credential_id, r.credential_generation, r.announced_at_ms,
                r.descriptor_digest, r.announce_signature, r.expires_at_ms
           FROM agent.agent_identity_approvals a
           JOIN agent.agent_provisioning_recipients r
             ON r.tenant_id=a.tenant_id AND r.binding_id=a.binding_id
           JOIN agent.connector_bindings b
             ON b.tenant_id=r.tenant_id AND b.binding_id=r.binding_id
           JOIN agent.connector_control_credential_heads h
             ON h.tenant_id=r.tenant_id AND h.connector_id=r.connector_id
           JOIN agent.connector_control_credential_revisions cr
             ON cr.tenant_id=h.tenant_id AND cr.connector_id=h.connector_id
            AND cr.authorization_revision=h.current_revision
           JOIN agent.connector_control_credentials cc
             ON cc.tenant_id=cr.tenant_id AND cc.connector_id=cr.connector_id
            AND cc.credential_id=cr.current_credential_id
          WHERE a.tenant_id=$1 AND a.approval_id=$2
            AND r.state='open' AND r.claimed_delivery_id IS NULL AND r.expires_at_ms>$3
            AND b.state='enabled' AND r.installation_id=a.installation_id
            AND r.agent_device_id=a.agent_device_id
            AND r.provisioning_revision=a.committed_installation_revision
            AND cr.lifecycle='active' AND r.credential_id=cr.current_credential_id
            AND r.credential_generation=cr.connector_generation
            AND r.connector_credential_fingerprint=cc.certificate_fingerprint",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(approval_id))
    .bind(now.get())
    .fetch_optional(session.connection())
    .await?
    .ok_or(AgentIdentityProvisioningError::NotFound)?;
    let owner_session = owner.session();
    if row.try_get::<String, _>("owner_identity_id")? != owner_session.identity_id().to_string()
        || row.try_get::<Uuid, _>("owner_device_id")? != Uuid::from(owner_session.device_id())
    {
        return Err(AgentIdentityProvisioningError::Forbidden);
    }
    let bytes =
        |name| -> Result<Vec<u8>, AgentIdentityProvisioningError> { Ok(row.try_get(name)?) };
    let public_key: [u8; 32] = bytes("recipient_public_key")?
        .try_into()
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)?;
    let signature: [u8; 64] = bytes("announce_signature")?
        .try_into()
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)?;
    let revision = positive_revision(row.try_get("committed_installation_revision")?)?;
    let credential_id =
        dtx_domain::ConnectorCredentialId::try_from(row.try_get::<Uuid, _>("credential_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?;
    let credential_generation = positive_revision(row.try_get("credential_generation")?)?;
    let created_at = UtcMillis::new(row.try_get("announced_at_ms")?)
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)?;
    let expires_at = UtcMillis::new(row.try_get("expires_at_ms")?)
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)?;
    let descriptor_digest =
        Sha256Digest::from_bytes(bytes32_from_vec(bytes("descriptor_digest")?)?);
    let recipient_signature = Ed25519Signature::from_bytes(signature);
    let exact_cbor = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(
                row.try_get::<Uuid, _>("recipient_key_id")?
                    .hyphenated()
                    .to_string(),
            ),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(tenant_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(
                row.try_get::<Uuid, _>("connector_id")?
                    .hyphenated()
                    .to_string(),
            ),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(
                row.try_get::<Uuid, _>("binding_id")?
                    .hyphenated()
                    .to_string(),
            ),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(
                row.try_get::<Uuid, _>("installation_id")?
                    .hyphenated()
                    .to_string(),
            ),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(
                row.try_get::<Uuid, _>("agent_device_id")?
                    .hyphenated()
                    .to_string(),
            ),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Unsigned(revision.get()),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Bytes(public_key.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Text(credential_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(11),
            CanonicalValue::Unsigned(credential_generation.get()),
        ),
        (
            CanonicalValue::Unsigned(12),
            created_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(13),
            expires_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(14),
            descriptor_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(15),
            recipient_signature.to_canonical_value(),
        ),
    ]))
    .map_err(|_| AgentIdentityProvisioningError::CorruptData)?;
    let target = AgentProvisioningTarget {
        approval_id,
        tenant_id,
        connector_id: ConnectorId::try_from(row.try_get::<Uuid, _>("connector_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        installation_id: InstallationId::try_from(row.try_get::<Uuid, _>("installation_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        binding_id: BindingId::try_from(row.try_get::<Uuid, _>("binding_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        agent_device_id: AgentDeviceId::try_from(row.try_get::<Uuid, _>("agent_device_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        provisioning_revision: revision,
        recipient_key_id: ProvisioningRecipientKeyId::try_from(
            row.try_get::<Uuid, _>("recipient_key_id")?,
        )
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        recipient_public_key: public_key,
        credential_id,
        credential_generation,
        created_at,
        descriptor_digest,
        recipient_signature,
        expires_at,
        exact_cbor,
    };
    session.commit().await?;
    Ok(target)
}

/// Claims one recipient and appends its opaque capsule as a durable Control 1.3 command.
///
/// # Errors
///
/// Rejects changed retries, stale approvals/recipients, invalid Owner proofs and any
/// transaction that cannot atomically persist both the delivery and command cursor.
#[allow(clippy::too_many_lines)]
pub async fn create_agent_provisioning_delivery<D: DurableCommandDecoder + ?Sized>(
    store: &PgStore,
    decoder: &D,
    credential: &DeviceSessionCredential,
    idempotency_key_hash: Sha256Digest,
    command: AgentProvisioningDeliveryCommand,
    now: UtcMillis,
) -> Result<AgentProvisioningDeliveryReceipt, AgentIdentityProvisioningError> {
    if command.created_at > now
        || command.expires_at <= now
        || command.expires_at <= command.created_at
        || command.sealed_capsule.is_empty()
        || command.sealed_capsule.len() > 196_608
        || Sha256Digest::hash_domain(AGENT_PROVISIONING_CAPSULE_DOMAIN, &command.sealed_capsule)
            != command.capsule_digest
    {
        return Err(AgentIdentityProvisioningError::InvalidRequest);
    }
    let request_digest = command.request_digest()?;
    let mut session = store.begin_tenant(command.tenant_id).await?;
    let owner = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
        session.connection(),
        credential,
        now,
    )
    .await?;
    let owner_session = owner.session();
    if owner_session.identity_id() != command.owner_identity_id
        || owner_session.device_id() != command.owner_device_id
    {
        return Err(AgentIdentityProvisioningError::Forbidden);
    }
    if let Some(row) = sqlx::query(
        "SELECT delivery_id, approval_id, installation_id, provisioning_revision,
                connector_id, command_sequence, command_payload_digest,
                encoded_command_digest, capsule_digest, state, result_digest,
                rejection_code, created_at_ms, resolved_at_ms, request_digest
           FROM agent.agent_provisioning_deliveries
          WHERE tenant_id=$1 AND idempotency_key_hash=$2",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(session.connection())
    .await?
    {
        if row.try_get::<Vec<u8>, _>("request_digest")?.as_slice() != request_digest.as_bytes() {
            return Err(AgentIdentityProvisioningError::Conflict);
        }
        let mut receipt = delivery_receipt_from_row(&row)?;
        receipt.replayed = true;
        session.commit().await?;
        return Ok(receipt);
    }
    let signature = Signature::from_bytes(command.owner_signature.as_bytes());
    let verifying_key = VerifyingKey::from_bytes(owner.signing_key().as_bytes())
        .map_err(|_| AgentIdentityProvisioningError::InvalidProof)?;
    verifying_key
        .verify_strict(&command.signature_input()?, &signature)
        .map_err(|_| AgentIdentityProvisioningError::InvalidProof)?;
    let row = sqlx::query(
        "SELECT a.agent_identity_id, a.identity_device_id,
                a.owner_identity_id, a.owner_device_id, a.committed_installation_revision,
                r.recipient_id, r.connector_id, r.recipient_key_id, r.descriptor_digest,
                r.expires_at_ms, r.state, r.claimed_delivery_id
           FROM agent.agent_identity_approvals a
           JOIN agent.agent_provisioning_recipients r
             ON r.tenant_id=a.tenant_id AND r.binding_id=a.binding_id
          WHERE a.tenant_id=$1 AND a.approval_id=$2 AND a.installation_id=$3
            AND a.binding_id=$4 AND a.agent_device_id=$5
            AND r.installation_id=a.installation_id AND r.agent_device_id=a.agent_device_id
            AND r.recipient_key_id=$6
          FOR UPDATE OF r",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.approval_id))
    .bind(Uuid::from(command.installation_id))
    .bind(Uuid::from(command.binding_id))
    .bind(Uuid::from(command.agent_device_id))
    .bind(Uuid::from(command.recipient_key_id))
    .fetch_optional(session.connection())
    .await?
    .ok_or(AgentIdentityProvisioningError::NotFound)?;
    let committed_revision = positive_revision(row.try_get("committed_installation_revision")?)?;
    let stored_identity: IdentityId = row
        .try_get::<String, _>("agent_identity_id")?
        .parse()
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)?;
    let stored_identity_device = DeviceId::try_from(row.try_get::<Uuid, _>("identity_device_id")?)
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)?;
    let descriptor = Sha256Digest::from_bytes(bytes32_from_vec(row.try_get("descriptor_digest")?)?);
    if row.try_get::<String, _>("owner_identity_id")? != command.owner_identity_id.to_string()
        || row.try_get::<Uuid, _>("owner_device_id")? != Uuid::from(command.owner_device_id)
        || stored_identity != command.agent_identity_id
        || stored_identity_device != command.identity_device_id
        || committed_revision != command.provisioning_revision
        || descriptor != command.recipient_descriptor_digest
        || row.try_get::<String, _>("state")? != "open"
        || row
            .try_get::<Option<Uuid>, _>("claimed_delivery_id")?
            .is_some()
        || row.try_get::<i64, _>("expires_at_ms")? <= now.get()
    {
        return Err(AgentIdentityProvisioningError::Conflict);
    }
    let connector_id = ConnectorId::try_from(row.try_get::<Uuid, _>("connector_id")?)
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)?;
    let recipient_id: Uuid = row.try_get("recipient_id")?;
    let repository = CommandLogRepository::new();
    let head = repository
        .lock_head_for_update(session.connection(), command.tenant_id, connector_id)
        .await?;
    if head.state() != dtx_agent_control::CommandLogState::Active {
        return Err(AgentIdentityProvisioningError::Conflict);
    }
    let sequence = head
        .last_sequence()
        .checked_add(1)
        .filter(|value| *value <= Revision::MAX)
        .ok_or(AgentIdentityProvisioningError::Conflict)?;
    let operation_id = command
        .delivery_id
        .to_string()
        .parse::<RequestId>()
        .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?;
    sqlx::query(
        "INSERT INTO agent.connector_control_operations (
             tenant_id, operation_id, connector_id, operation_kind, created_at_ms
         ) VALUES ($1,$2,$3,'deliver_agent_provisioning',$4)",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(operation_id))
    .bind(Uuid::from(connector_id))
    .bind(now.get())
    .execute(session.connection())
    .await
    .map_err(map_unique_conflict)?;
    let control_payload = ServerCommandPayload::DeliverAgentProvisioning(
        DeliverAgentProvisioningCommand::new(
            command.delivery_id,
            command.approval_id,
            command.binding_id,
            command.installation_id,
            command.agent_device_id,
            command.provisioning_revision,
            command.recipient_key_id,
            ControlSha256Digest::from_bytes(*command.recipient_descriptor_digest.as_bytes()),
            ControlSha256Digest::from_bytes(*command.capsule_digest.as_bytes()),
            command.sealed_capsule.clone(),
            command.expires_at.get(),
        )
        .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?,
    );
    let encoded = ProtobufDurableCommandEncoder
        .encode(
            sequence,
            operation_id,
            head.generation(),
            head.spec_revision(),
            &control_payload,
        )
        .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?;
    let payload_digest = encoded.payload_digest();
    let exact_bytes = encoded.into_exact_bytes();
    let durable = DurableServerCommand::try_from_snapshot(DurableServerCommandSnapshot {
        sequence,
        operation_id,
        generation: head.generation(),
        spec_revision: head.spec_revision(),
        payload: control_payload,
        payload_digest,
        encoded_command_digest: exact_bytes.encoded_command_digest(),
        exact_bytes,
    })
    .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?;
    repository
        .append_locked(
            session.connection(),
            command.tenant_id,
            connector_id,
            head,
            &durable,
            decoder,
            now.get(),
        )
        .await?;
    let binding_bytes = command.binding_bytes()?;
    sqlx::query(
        "INSERT INTO agent.agent_provisioning_deliveries (
             tenant_id, delivery_id, installation_id, approval_id, recipient_id,
             connector_id, binding_id, agent_device_id, recipient_key_id,
             provisioning_revision, command_sequence, command_payload_digest,
             encoded_command_digest, capsule_header, capsule_digest, sealed_capsule,
             idempotency_key_hash, request_digest, state, created_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,'pending',$19)",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.delivery_id))
    .bind(Uuid::from(command.installation_id))
    .bind(Uuid::from(command.approval_id))
    .bind(recipient_id)
    .bind(Uuid::from(connector_id))
    .bind(Uuid::from(command.binding_id))
    .bind(Uuid::from(command.agent_device_id))
    .bind(Uuid::from(command.recipient_key_id))
    .bind(
        i64::try_from(command.provisioning_revision.get())
            .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?,
    )
    .bind(i64::try_from(sequence).map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?)
    .bind(durable.payload_digest().as_bytes().as_slice())
    .bind(durable.encoded_command_digest().as_bytes().as_slice())
    .bind(&binding_bytes)
    .bind(command.capsule_digest.as_bytes().as_slice())
    .bind(&command.sealed_capsule)
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .bind(request_digest.as_bytes().as_slice())
    .bind(now.get())
    .execute(session.connection())
    .await
    .map_err(map_unique_conflict)?;
    let recipient_claim = sqlx::query(
        "UPDATE agent.agent_provisioning_recipients
            SET state='claimed', claimed_delivery_id=$3
          WHERE tenant_id=$1 AND recipient_id=$2 AND state='open' AND claimed_delivery_id IS NULL",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(recipient_id)
    .bind(Uuid::from(command.delivery_id))
    .execute(session.connection())
    .await?;
    if recipient_claim.rows_affected() != 1 {
        return Err(AgentIdentityProvisioningError::Conflict);
    }
    sqlx::query(
        "INSERT INTO agent.agent_provisioning_outbox (
             tenant_id, delivery_id, connector_id, command_sequence, command_digest,
             next_attempt_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.delivery_id))
    .bind(Uuid::from(connector_id))
    .bind(i64::try_from(sequence).map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?)
    .bind(durable.encoded_command_digest().as_bytes().as_slice())
    .bind(now.get())
    .execute(session.connection())
    .await?;
    session.commit().await?;
    Ok(AgentProvisioningDeliveryReceipt {
        replayed: false,
        delivery_id: command.delivery_id,
        approval_id: command.approval_id,
        installation_id: command.installation_id,
        provisioning_revision: command.provisioning_revision,
        connector_id,
        command_sequence: sequence,
        command_payload_digest: durable.payload_digest(),
        encoded_command_digest: durable.encoded_command_digest(),
        capsule_digest: command.capsule_digest,
        state: "pending".to_owned(),
        result_digest: None,
        rejection_code: None,
        created_at: now,
        resolved_at: None,
    })
}

/// Reads one delivery receipt without returning its opaque capsule.
///
/// # Errors
///
/// Rejects inactive sessions, non-owners and missing/corrupt deliveries.
pub async fn get_agent_provisioning_delivery(
    store: &PgStore,
    credential: &DeviceSessionCredential,
    tenant_id: TenantId,
    delivery_id: ProvisioningDeliveryId,
    now: UtcMillis,
) -> Result<AgentProvisioningDeliveryReceipt, AgentIdentityProvisioningError> {
    let mut session = store.begin_tenant(tenant_id).await?;
    let owner = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
        session.connection(),
        credential,
        now,
    )
    .await?;
    let row = sqlx::query(
        "SELECT d.delivery_id, d.approval_id, d.installation_id, d.provisioning_revision,
                d.connector_id, d.command_sequence,
                d.command_payload_digest, d.encoded_command_digest, d.capsule_digest,
                d.state, d.result_digest, d.rejection_code, d.created_at_ms,
                d.resolved_at_ms, a.owner_identity_id, a.owner_device_id
           FROM agent.agent_provisioning_deliveries d
           JOIN agent.agent_identity_approvals a
             ON a.tenant_id=d.tenant_id AND a.approval_id=d.approval_id
          WHERE d.tenant_id=$1 AND d.delivery_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(delivery_id))
    .fetch_optional(session.connection())
    .await?
    .ok_or(AgentIdentityProvisioningError::NotFound)?;
    if row.try_get::<String, _>("owner_identity_id")? != owner.session().identity_id().to_string()
        || row.try_get::<Uuid, _>("owner_device_id")? != Uuid::from(owner.session().device_id())
    {
        return Err(AgentIdentityProvisioningError::Forbidden);
    }
    let receipt = delivery_receipt_from_row(&row)?;
    session.commit().await?;
    Ok(receipt)
}

/// Atomically blocks routing and appends the exact local stop/delete command.
///
/// # Errors
///
/// Rejects non-owners, stale revisions, changed retries, invalid signatures and
/// any transaction that cannot commit the fail-closed state before command delivery.
#[allow(clippy::too_many_lines)]
pub async fn revoke_agent_provisioning<D: DurableCommandDecoder + ?Sized>(
    store: &PgStore,
    decoder: &D,
    credential: &DeviceSessionCredential,
    idempotency_key_hash: Sha256Digest,
    command: AgentProvisioningRevocationCommand,
    now: UtcMillis,
) -> Result<AgentProvisioningRevocationReceipt, AgentIdentityProvisioningError> {
    if command.expires_at <= now
        || !matches!(command.scope, 1 | 2)
        || command.calculated_binding_digest()? != command.binding_digest
    {
        return Err(AgentIdentityProvisioningError::InvalidRequest);
    }
    let request_digest = command.request_digest()?;
    let mut session = store.begin_tenant(command.tenant_id).await?;
    let owner = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
        session.connection(),
        credential,
        now,
    )
    .await?;
    if owner.session().identity_id() != command.owner_identity_id
        || owner.session().device_id() != command.owner_device_id
    {
        return Err(AgentIdentityProvisioningError::Forbidden);
    }
    if let Some(row) = sqlx::query(
        "SELECT operation_id, installation_id, binding_id, agent_device_id,
                committed_revision, scope, command_sequence, command_payload_digest,
                encoded_command_digest, revoked_at_ms, request_digest
           FROM agent.agent_installation_revocations
          WHERE tenant_id=$1 AND idempotency_key_hash=$2",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(session.connection())
    .await?
    {
        if row.try_get::<Vec<u8>, _>("request_digest")?.as_slice() != request_digest.as_bytes() {
            return Err(AgentIdentityProvisioningError::Conflict);
        }
        let receipt = revocation_receipt_from_row(&row)?;
        session.commit().await?;
        return Ok(receipt);
    }
    VerifyingKey::from_bytes(owner.signing_key().as_bytes())
        .map_err(|_| AgentIdentityProvisioningError::InvalidProof)?
        .verify_strict(
            &command.signature_input(),
            &Signature::from_bytes(command.owner_signature.as_bytes()),
        )
        .map_err(|_| AgentIdentityProvisioningError::InvalidProof)?;
    let mut installation = AgentInstallationRepository::new()
        .load(
            session.connection(),
            command.tenant_id,
            command.installation_id,
        )
        .await?
        .ok_or(AgentIdentityProvisioningError::NotFound)?;
    if installation.owner_id() != command.owner_identity_id
        || installation.revision() != command.expected_revision
        || installation.desired_state() == InstallationDesiredState::Revoked
    {
        return Err(AgentIdentityProvisioningError::Conflict);
    }
    let binding = sqlx::query(
        "SELECT b.binding_id, b.connector_id, b.agent_device_id, b.aggregate_revision, b.state
           FROM agent.agent_identity_approvals a
           JOIN agent.connector_bindings b
             ON b.tenant_id=a.tenant_id AND b.binding_id=a.binding_id
          WHERE a.tenant_id=$1 AND a.installation_id=$2 AND b.state='enabled'
          FOR UPDATE OF b",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.installation_id))
    .fetch_optional(session.connection())
    .await?
    .ok_or(AgentIdentityProvisioningError::NotFound)?;
    let binding_id = BindingId::try_from(binding.try_get::<Uuid, _>("binding_id")?)
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)?;
    let connector_id = ConnectorId::try_from(binding.try_get::<Uuid, _>("connector_id")?)
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)?;
    let agent_device_id = AgentDeviceId::try_from(binding.try_get::<Uuid, _>("agent_device_id")?)
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)?;
    let mut device = AgentDeviceRepository::new()
        .load(session.connection(), command.tenant_id, agent_device_id)
        .await?
        .ok_or(AgentIdentityProvisioningError::NotFound)?;
    let committed_revision = if command.scope == 1 {
        let revision = installation
            .apply(command.expected_revision, InstallationCommand::Revoke)
            .map_err(|_| AgentIdentityProvisioningError::Conflict)?;
        if AgentInstallationRepository::new()
            .save(session.connection(), &installation, now.get())
            .await?
            != CurrentWrite::Advanced
        {
            return Err(AgentIdentityProvisioningError::Conflict);
        }
        if device.state() != AgentDeviceState::Revoked {
            device
                .apply(&installation, device.revision(), AgentDeviceCommand::Revoke)
                .map_err(|_| AgentIdentityProvisioningError::Conflict)?;
            if AgentDeviceRepository::new()
                .save(session.connection(), &device, now.get())
                .await?
                != CurrentWrite::Advanced
            {
                return Err(AgentIdentityProvisioningError::Conflict);
            }
        }
        revision
    } else {
        device
            .apply(&installation, device.revision(), AgentDeviceCommand::Revoke)
            .map_err(|_| AgentIdentityProvisioningError::Conflict)?;
        let revision = device.revision();
        if AgentDeviceRepository::new()
            .save(session.connection(), &device, now.get())
            .await?
            != CurrentWrite::Advanced
        {
            return Err(AgentIdentityProvisioningError::Conflict);
        }
        revision
    };
    let previous_binding_revision: i64 = binding.try_get("aggregate_revision")?;
    let updated = sqlx::query(
        "UPDATE agent.connector_bindings
            SET state='revoked', aggregate_revision=aggregate_revision+1, updated_at_ms=$4
          WHERE tenant_id=$1 AND binding_id=$2 AND aggregate_revision=$3 AND state='enabled'",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(binding_id))
    .bind(previous_binding_revision)
    .bind(now.get())
    .execute(session.connection())
    .await?;
    if updated.rows_affected() != 1 {
        return Err(AgentIdentityProvisioningError::Conflict);
    }
    let repository = CommandLogRepository::new();
    let head = repository
        .lock_head_for_update(session.connection(), command.tenant_id, connector_id)
        .await?;
    if head.state() != dtx_agent_control::CommandLogState::Active {
        return Err(AgentIdentityProvisioningError::Conflict);
    }
    let sequence = head
        .last_sequence()
        .checked_add(1)
        .filter(|value| *value <= Revision::MAX)
        .ok_or(AgentIdentityProvisioningError::Conflict)?;
    sqlx::query(
        "INSERT INTO agent.connector_control_operations (
             tenant_id, operation_id, connector_id, operation_kind, created_at_ms
         ) VALUES ($1,$2,$3,'revoke_agent_provisioning',$4)",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.revocation_id))
    .bind(Uuid::from(connector_id))
    .bind(now.get())
    .execute(session.connection())
    .await
    .map_err(map_unique_conflict)?;
    let payload = ServerCommandPayload::RevokeAgentProvisioning(
        RevokeAgentProvisioningCommand::new(
            command.revocation_id,
            command.installation_id,
            binding_id,
            (command.scope == 2).then_some(agent_device_id),
            committed_revision,
            now.get(),
        )
        .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?,
    );
    let encoded = ProtobufDurableCommandEncoder
        .encode(
            sequence,
            command.revocation_id,
            head.generation(),
            head.spec_revision(),
            &payload,
        )
        .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?;
    let payload_digest = encoded.payload_digest();
    let exact_bytes = encoded.into_exact_bytes();
    let durable = DurableServerCommand::try_from_snapshot(DurableServerCommandSnapshot {
        sequence,
        operation_id: command.revocation_id,
        generation: head.generation(),
        spec_revision: head.spec_revision(),
        payload,
        payload_digest,
        encoded_command_digest: exact_bytes.encoded_command_digest(),
        exact_bytes,
    })
    .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?;
    repository
        .append_locked(
            session.connection(),
            command.tenant_id,
            connector_id,
            head,
            &durable,
            decoder,
            now.get(),
        )
        .await?;
    sqlx::query(
        "INSERT INTO agent.agent_installation_revocations (
             tenant_id, installation_id, operation_id, binding_id, connector_id,
             agent_device_id, scope, committed_revision, command_sequence,
             command_payload_digest, encoded_command_digest, idempotency_key_hash,
             request_digest, revoked_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.installation_id))
    .bind(Uuid::from(command.revocation_id))
    .bind(Uuid::from(binding_id))
    .bind(Uuid::from(connector_id))
    .bind((command.scope == 2).then_some(Uuid::from(agent_device_id)))
    .bind(i16::from(command.scope))
    .bind(
        i64::try_from(committed_revision.get())
            .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?,
    )
    .bind(i64::try_from(sequence).map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?)
    .bind(durable.payload_digest().as_bytes().as_slice())
    .bind(durable.encoded_command_digest().as_bytes().as_slice())
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .bind(request_digest.as_bytes().as_slice())
    .bind(now.get())
    .execute(session.connection())
    .await
    .map_err(map_unique_conflict)?;
    session.commit().await?;
    Ok(AgentProvisioningRevocationReceipt {
        revocation_id: command.revocation_id,
        installation_id: command.installation_id,
        binding_id,
        agent_device_id: (command.scope == 2).then_some(agent_device_id),
        committed_revision,
        scope: command.scope,
        command_sequence: sequence,
        command_payload_digest: durable.payload_digest(),
        encoded_command_digest: durable.encoded_command_digest(),
        revoked_at: now,
    })
}

#[allow(clippy::too_many_lines)]
async fn approve_in_transaction(
    connection: &mut sqlx::PgConnection,
    credential: &DeviceSessionCredential,
    idempotency_key_hash: Sha256Digest,
    request_digest: Sha256Digest,
    command: AgentIdentityApprovalCommand,
    now: UtcMillis,
) -> Result<AgentIdentityApprovalReceipt, AgentIdentityProvisioningError> {
    let owner = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
        connection, credential, now,
    )
    .await?;
    let owner_session = owner.session();
    let installation = AgentInstallationRepository::new()
        .load(connection, command.tenant_id, command.installation_id)
        .await?
        .ok_or(AgentIdentityProvisioningError::NotFound)?;
    if installation.owner_id() != owner_session.identity_id()
        || command.owner_identity_id != owner_session.identity_id()
        || command.owner_device_id != owner_session.device_id()
    {
        return Err(AgentIdentityProvisioningError::Forbidden);
    }
    if let Some(receipt) = load_approval_by_idempotency(
        connection,
        command.tenant_id,
        idempotency_key_hash,
        request_digest,
    )
    .await?
    {
        return Ok(receipt);
    }
    if installation.desired_state() == InstallationDesiredState::Revoked
        || installation.revision() != command.expected_revision
    {
        return Err(AgentIdentityProvisioningError::Conflict);
    }
    let signature = Signature::from_bytes(command.owner_signature.as_bytes());
    let verifying_key = VerifyingKey::from_bytes(owner.signing_key().as_bytes())
        .map_err(|_| AgentIdentityProvisioningError::InvalidProof)?;
    verifying_key
        .verify_strict(&command.signature_input()?, &signature)
        .map_err(|_| AgentIdentityProvisioningError::InvalidProof)?;

    let agent_identity =
        lock_and_load_active_snapshot(connection, command.agent_identity_id).await?;
    let head = agent_identity.head();
    if head.sequence() != command.identity_head_sequence
        || head.hash() != command.identity_head_hash
    {
        return Err(AgentIdentityProvisioningError::Conflict);
    }
    if agent_identity
        .projection()
        .device_status(command.identity_device_id)
        != Some(DeviceStatusV1::Active)
    {
        return Err(AgentIdentityProvisioningError::InvalidIdentity);
    }
    let certificate = agent_identity
        .projection()
        .device_certificate(command.identity_device_id)
        .ok_or(AgentIdentityProvisioningError::InvalidIdentity)?;
    let certificate_bytes = certificate
        .to_deterministic_cbor()
        .map_err(|_| AgentIdentityProvisioningError::InvalidIdentity)?;
    let fingerprint_digest = Sha256Digest::hash_domain(
        AGENT_DEVICE_CREDENTIAL_FINGERPRINT_DOMAIN,
        &certificate_bytes,
    );
    let fingerprint = DeviceCredentialFingerprint::from_bytes(*fingerprint_digest.as_bytes());
    if fingerprint != command.credential_fingerprint {
        return Err(AgentIdentityProvisioningError::InvalidIdentity);
    }

    let binding_matches: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM agent.connector_bindings
              WHERE tenant_id=$1 AND binding_id=$2 AND installation_id=$3
                AND agent_device_id=$4 AND state='enabled'
         )",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.binding_id))
    .bind(Uuid::from(command.installation_id))
    .bind(Uuid::from(command.agent_device_id))
    .fetch_one(&mut *connection)
    .await?;
    let device = AgentDeviceRepository::new()
        .load(connection, command.tenant_id, command.agent_device_id)
        .await?
        .ok_or(AgentIdentityProvisioningError::Conflict)?;
    if !binding_matches
        || device.installation_id() != command.installation_id
        || device.identity_device_id() != command.identity_device_id
        || device.state() == AgentDeviceState::Revoked
        || !device.credential_matches(fingerprint)
    {
        return Err(AgentIdentityProvisioningError::Conflict);
    }

    let mut updated = installation;
    updated
        .apply(
            command.expected_revision,
            InstallationCommand::BindAgentIdentity {
                identity_id: command.agent_identity_id,
            },
        )
        .map_err(|_| AgentIdentityProvisioningError::Conflict)?;
    if AgentInstallationRepository::new()
        .save(connection, &updated, now.get())
        .await?
        != CurrentWrite::Advanced
    {
        return Err(AgentIdentityProvisioningError::Conflict);
    }
    let approval_id = command.approval_id;
    let receipt_bytes = approval_receipt_bytes(
        approval_id,
        command.binding_digest()?,
        &command,
        updated.revision(),
        now,
    )?;
    let receipt_digest =
        Sha256Digest::hash_domain(AGENT_IDENTITY_APPROVAL_RECEIPT_DOMAIN, &receipt_bytes);
    sqlx::query(
        "INSERT INTO agent.agent_identity_approvals (
             tenant_id, approval_id, installation_id, binding_id, agent_device_id,
             agent_identity_id, identity_device_id, identity_head_sequence, identity_head_hash,
             credential_fingerprint, owner_identity_id, owner_device_id, owner_session_id,
             owner_operation_id, owner_operation_expires_at_ms, expected_installation_revision,
             committed_installation_revision, idempotency_key_hash, request_digest,
             receipt_bytes, receipt_digest, approved_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(approval_id))
    .bind(Uuid::from(command.installation_id))
    .bind(Uuid::from(command.binding_id))
    .bind(Uuid::from(command.agent_device_id))
    .bind(command.agent_identity_id.to_string())
    .bind(Uuid::from(command.identity_device_id))
    .bind(
        i64::try_from(command.identity_head_sequence.get())
            .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?,
    )
    .bind(command.identity_head_hash.as_bytes().as_slice())
    .bind(fingerprint.as_bytes().as_slice())
    .bind(owner_session.identity_id().to_string())
    .bind(Uuid::from(owner_session.device_id()))
    .bind(Uuid::from(owner_session.session_id()))
    .bind(Uuid::from(command.approval_id))
    .bind(command.expires_at.get())
    .bind(
        i64::try_from(command.expected_revision.get())
            .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?,
    )
    .bind(
        i64::try_from(updated.revision().get())
            .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)?,
    )
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .bind(request_digest.as_bytes().as_slice())
    .bind(&receipt_bytes)
    .bind(receipt_digest.as_bytes().as_slice())
    .bind(now.get())
    .execute(&mut *connection)
    .await
    .map_err(map_unique_conflict)?;
    Ok(AgentIdentityApprovalReceipt {
        replayed: false,
        approval_id,
        installation_id: command.installation_id,
        binding_id: command.binding_id,
        agent_device_id: command.agent_device_id,
        agent_identity_id: command.agent_identity_id,
        identity_device_id: command.identity_device_id,
        credential_fingerprint: fingerprint,
        identity_head_sequence: command.identity_head_sequence,
        identity_head_hash: command.identity_head_hash,
        installation_revision: updated.revision(),
        approved_at: now,
        binding_digest: command.binding_digest()?,
        receipt_digest,
        exact_cbor: receipt_bytes,
    })
}

fn approval_receipt_bytes(
    approval_id: ApprovalId,
    binding_digest: Sha256Digest,
    command: &AgentIdentityApprovalCommand,
    revision: Revision,
    now: UtcMillis,
) -> Result<Vec<u8>, AgentIdentityProvisioningError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(approval_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            binding_digest.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Unsigned(revision.get()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(command.agent_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(command.identity_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(command.binding_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(command.agent_device_id.to_string()),
        ),
        (CanonicalValue::Unsigned(9), now.to_canonical_value()),
    ]))
    .map_err(|_| AgentIdentityProvisioningError::InvalidRequest)
}

async fn load_approval_by_idempotency(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    idempotency_key_hash: Sha256Digest,
    request_digest: Sha256Digest,
) -> Result<Option<AgentIdentityApprovalReceipt>, AgentIdentityProvisioningError> {
    let row = sqlx::query(
        "SELECT approval_id, installation_id, binding_id, agent_device_id,
                agent_identity_id, identity_device_id,
                credential_fingerprint, identity_head_sequence, identity_head_hash,
                committed_installation_revision, approved_at_ms, receipt_bytes, receipt_digest,
                request_digest
           FROM agent.agent_identity_approvals
          WHERE tenant_id=$1 AND idempotency_key_hash=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else { return Ok(None) };
    if row.try_get::<Vec<u8>, _>("request_digest")?.as_slice() != request_digest.as_bytes() {
        return Err(AgentIdentityProvisioningError::Conflict);
    }
    let mut receipt = receipt_from_row(&row)?;
    receipt.replayed = true;
    Ok(Some(receipt))
}

fn receipt_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<AgentIdentityApprovalReceipt, AgentIdentityProvisioningError> {
    let uuid = |name| {
        row.try_get::<Uuid, _>(name)
            .map_err(AgentIdentityProvisioningError::from)
    };
    let bytes32 = |name| -> Result<[u8; 32], AgentIdentityProvisioningError> {
        row.try_get::<Vec<u8>, _>(name)?
            .try_into()
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)
    };
    let sequence = u64::try_from(row.try_get::<i64, _>("identity_head_sequence")?)
        .ok()
        .and_then(|value| SafeUint::new(value).ok())
        .ok_or(AgentIdentityProvisioningError::CorruptData)?;
    let revision = u64::try_from(row.try_get::<i64, _>("committed_installation_revision")?)
        .ok()
        .and_then(|value| Revision::new(value).ok())
        .ok_or(AgentIdentityProvisioningError::CorruptData)?;
    let exact_cbor = row.try_get::<Vec<u8>, _>("receipt_bytes")?;
    let receipt_fields = match dtx_wire::decode_deterministic_cbor(&exact_cbor)
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)?
    {
        CanonicalValue::Map(fields) if fields.len() == 9 => fields,
        _ => return Err(AgentIdentityProvisioningError::CorruptData),
    };
    let binding_digest = match receipt_fields.get(2) {
        Some((CanonicalValue::Unsigned(3), CanonicalValue::Bytes(bytes))) => {
            Sha256Digest::from_bytes(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
            )
        }
        _ => return Err(AgentIdentityProvisioningError::CorruptData),
    };
    Ok(AgentIdentityApprovalReceipt {
        replayed: false,
        approval_id: ApprovalId::try_from(uuid("approval_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        installation_id: InstallationId::try_from(uuid("installation_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        binding_id: BindingId::try_from(uuid("binding_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        agent_device_id: AgentDeviceId::try_from(uuid("agent_device_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        agent_identity_id: row
            .try_get::<String, _>("agent_identity_id")?
            .parse()
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        identity_device_id: DeviceId::try_from(uuid("identity_device_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        credential_fingerprint: DeviceCredentialFingerprint::from_bytes(bytes32(
            "credential_fingerprint",
        )?),
        identity_head_sequence: sequence,
        identity_head_hash: Sha256Digest::from_bytes(bytes32("identity_head_hash")?),
        installation_revision: revision,
        approved_at: UtcMillis::new(row.try_get("approved_at_ms")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        binding_digest,
        receipt_digest: Sha256Digest::from_bytes(bytes32("receipt_digest")?),
        exact_cbor,
    })
}

fn delivery_receipt_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<AgentProvisioningDeliveryReceipt, AgentIdentityProvisioningError> {
    let control_digest = |name| -> Result<ControlSha256Digest, AgentIdentityProvisioningError> {
        Ok(ControlSha256Digest::from_bytes(bytes32_from_vec(
            row.try_get(name)?,
        )?))
    };
    let optional_digest =
        |name| -> Result<Option<ControlSha256Digest>, AgentIdentityProvisioningError> {
            row.try_get::<Option<Vec<u8>>, _>(name)?
                .map(bytes32_from_vec)
                .transpose()
                .map(|value| value.map(ControlSha256Digest::from_bytes))
        };
    Ok(AgentProvisioningDeliveryReceipt {
        replayed: false,
        delivery_id: ProvisioningDeliveryId::try_from(row.try_get::<Uuid, _>("delivery_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        approval_id: ApprovalId::try_from(row.try_get::<Uuid, _>("approval_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        installation_id: InstallationId::try_from(row.try_get::<Uuid, _>("installation_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        provisioning_revision: positive_revision(row.try_get("provisioning_revision")?)?,
        connector_id: ConnectorId::try_from(row.try_get::<Uuid, _>("connector_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        command_sequence: u64::try_from(row.try_get::<i64, _>("command_sequence")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        command_payload_digest: control_digest("command_payload_digest")?,
        encoded_command_digest: control_digest("encoded_command_digest")?,
        capsule_digest: Sha256Digest::from_bytes(bytes32_from_vec(row.try_get("capsule_digest")?)?),
        state: row.try_get("state")?,
        result_digest: optional_digest("result_digest")?,
        rejection_code: row.try_get("rejection_code")?,
        created_at: UtcMillis::new(row.try_get("created_at_ms")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        resolved_at: row
            .try_get::<Option<i64>, _>("resolved_at_ms")?
            .map(UtcMillis::new)
            .transpose()
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
    })
}

fn revocation_receipt_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<AgentProvisioningRevocationReceipt, AgentIdentityProvisioningError> {
    Ok(AgentProvisioningRevocationReceipt {
        revocation_id: RequestId::try_from(row.try_get::<Uuid, _>("operation_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        installation_id: InstallationId::try_from(row.try_get::<Uuid, _>("installation_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        binding_id: BindingId::try_from(row.try_get::<Uuid, _>("binding_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        agent_device_id: row
            .try_get::<Option<Uuid>, _>("agent_device_id")?
            .map(AgentDeviceId::try_from)
            .transpose()
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        committed_revision: positive_revision(row.try_get("committed_revision")?)?,
        scope: u8::try_from(row.try_get::<i16, _>("scope")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        command_sequence: u64::try_from(row.try_get::<i64, _>("command_sequence")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        command_payload_digest: ControlSha256Digest::from_bytes(bytes32_from_vec(
            row.try_get("command_payload_digest")?,
        )?),
        encoded_command_digest: ControlSha256Digest::from_bytes(bytes32_from_vec(
            row.try_get("encoded_command_digest")?,
        )?),
        revoked_at: UtcMillis::new(row.try_get("revoked_at_ms")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
    })
}

fn bytes32_from_vec(bytes: Vec<u8>) -> Result<[u8; 32], AgentIdentityProvisioningError> {
    bytes
        .try_into()
        .map_err(|_| AgentIdentityProvisioningError::CorruptData)
}

fn positive_revision(value: i64) -> Result<Revision, AgentIdentityProvisioningError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| Revision::new(value).ok())
        .ok_or(AgentIdentityProvisioningError::CorruptData)
}

fn map_unique_conflict(error: sqlx::Error) -> AgentIdentityProvisioningError {
    if error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
    {
        AgentIdentityProvisioningError::Conflict
    } else {
        AgentIdentityProvisioningError::Database(error)
    }
}

#[derive(Debug)]
pub enum AgentIdentityProvisioningError {
    InvalidRequest,
    InvalidProof,
    InvalidIdentity,
    Forbidden,
    NotFound,
    Conflict,
    Expired,
    CorruptData,
    Database(sqlx::Error),
    Storage(StorageError),
    AgentPersistence(AgentPersistenceError),
    IdentityPersistence(IdentityPersistenceError),
}

impl From<sqlx::Error> for AgentIdentityProvisioningError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}
impl From<StorageError> for AgentIdentityProvisioningError {
    fn from(value: StorageError) -> Self {
        Self::Storage(value)
    }
}
impl From<AgentPersistenceError> for AgentIdentityProvisioningError {
    fn from(value: AgentPersistenceError) -> Self {
        Self::AgentPersistence(value)
    }
}
impl From<IdentityPersistenceError> for AgentIdentityProvisioningError {
    fn from(value: IdentityPersistenceError) -> Self {
        Self::IdentityPersistence(value)
    }
}

impl fmt::Display for AgentIdentityProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "invalid Agent identity approval request",
            Self::InvalidProof => "invalid Agent identity approval proof",
            Self::InvalidIdentity => "invalid Agent identity facts",
            Self::Forbidden => "Agent identity approval forbidden",
            Self::NotFound => "Agent installation not found",
            Self::Conflict => "Agent identity approval conflict",
            Self::Expired => "Agent identity approval expired",
            Self::CorruptData => "corrupt Agent identity approval data",
            Self::Database(_)
            | Self::Storage(_)
            | Self::AgentPersistence(_)
            | Self::IdentityPersistence(_) => "Agent identity approval unavailable",
        })
    }
}

impl Error for AgentIdentityProvisioningError {}

#[cfg(test)]
mod tests {
    use super::{
        AgentProvisioningInstalledReceiptFacts, agent_provisioning_installed_receipt_digest,
    };
    use dtx_domain::{
        AgentDeviceId, BindingId, InstallationId, ProvisioningDeliveryId,
        ProvisioningRecipientKeyId, Revision, TenantId,
    };
    use dtx_wire::Sha256Digest;

    #[test]
    fn installed_receipt_matches_the_v23_golden() {
        let digest =
            agent_provisioning_installed_receipt_digest(AgentProvisioningInstalledReceiptFacts {
                tenant_id: "0190f2a5-7b1c-7abc-8def-012345678901"
                    .parse::<TenantId>()
                    .unwrap(),
                installation_id: "0190f2a5-7b1c-7abc-8def-012345678902"
                    .parse::<InstallationId>()
                    .unwrap(),
                binding_id: "0190f2a5-7b1c-7abc-8def-012345678903"
                    .parse::<BindingId>()
                    .unwrap(),
                agent_device_id: "0190f2a5-7b1c-7abc-8def-012345678904"
                    .parse::<AgentDeviceId>()
                    .unwrap(),
                delivery_id: "0190f2a5-7b1c-7abc-8def-01234567890a"
                    .parse::<ProvisioningDeliveryId>()
                    .unwrap(),
                recipient_key_id: "0190f2a5-7b1c-7abc-8def-012345678907"
                    .parse::<ProvisioningRecipientKeyId>()
                    .unwrap(),
                bundle_revision: Revision::new(1).unwrap(),
                capsule_digest: Sha256Digest::from_bytes([
                    0x97, 0x5f, 0xf4, 0xbb, 0xe1, 0xdf, 0x2f, 0x18, 0x11, 0xfb, 0x80, 0xec, 0xa9,
                    0x43, 0x7d, 0x06, 0xa6, 0x16, 0x32, 0x2d, 0x54, 0xbe, 0x2e, 0x0b, 0x51, 0x8d,
                    0x28, 0xed, 0xdd, 0x1f, 0xbd, 0x5a,
                ]),
            })
            .unwrap();
        assert_eq!(
            digest.as_bytes(),
            &[
                0xd6, 0x7a, 0x52, 0xf7, 0x9a, 0x4a, 0xa2, 0x48, 0x9c, 0x0d, 0xb4, 0x03, 0xba, 0xac,
                0x49, 0x24, 0x4e, 0x7f, 0xae, 0x25, 0x4a, 0x6a, 0x60, 0xe3, 0xff, 0xba, 0x00, 0xe0,
                0x71, 0x89, 0xe9, 0xce,
            ]
        );
    }
}
