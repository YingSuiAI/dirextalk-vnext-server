use std::{error::Error, fmt};

use dtx_agent_persistence::{
    AgentDeviceRepository, AgentInstallationRepository, AgentPersistenceError, CurrentWrite,
};
use dtx_agent_registry::{
    AgentDeviceState, DeviceCredentialFingerprint, InstallationCommand, InstallationDesiredState,
};
use dtx_domain::{
    AgentDeviceId, ApprovalId, BindingId, DeviceId, IdentityId, InstallationId,
    ProvisioningDeliveryId, ProvisioningRecipientKeyId, Revision, TenantId,
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
    pub approval_id: ApprovalId,
    pub installation_id: InstallationId,
    pub agent_identity_id: IdentityId,
    pub identity_device_id: DeviceId,
    pub credential_fingerprint: DeviceCredentialFingerprint,
    pub identity_head_sequence: SafeUint,
    pub identity_head_hash: Sha256Digest,
    pub installation_revision: Revision,
    pub approved_at: UtcMillis,
    pub receipt_digest: Sha256Digest,
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
        "SELECT approval_id, installation_id, agent_identity_id, identity_device_id,
                credential_fingerprint, identity_head_sequence, identity_head_hash,
                committed_installation_revision, approved_at_ms, receipt_digest,
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
        || installation.desired_state() == InstallationDesiredState::Revoked
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
    if installation.revision() != command.expected_revision {
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
        approval_id,
        installation_id: command.installation_id,
        agent_identity_id: command.agent_identity_id,
        identity_device_id: command.identity_device_id,
        credential_fingerprint: fingerprint,
        identity_head_sequence: command.identity_head_sequence,
        identity_head_hash: command.identity_head_hash,
        installation_revision: updated.revision(),
        approved_at: now,
        receipt_digest,
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
        "SELECT approval_id, installation_id, agent_identity_id, identity_device_id,
                credential_fingerprint, identity_head_sequence, identity_head_hash,
                committed_installation_revision, approved_at_ms, receipt_digest, request_digest
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
    Ok(Some(receipt_from_row(&row)?))
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
    Ok(AgentIdentityApprovalReceipt {
        approval_id: ApprovalId::try_from(uuid("approval_id")?)
            .map_err(|_| AgentIdentityProvisioningError::CorruptData)?,
        installation_id: InstallationId::try_from(uuid("installation_id")?)
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
        receipt_digest: Sha256Digest::from_bytes(bytes32("receipt_digest")?),
    })
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
