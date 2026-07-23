use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_identity_log::{IdentityLogEventPayloadV1, IdentityLogEventV1};
use dtx_wire::{Sha256Digest, UtcMillis};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;
use x509_parser::pem::parse_x509_pem;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    IdentityAppendCommand, IdentityAppendOutcome, IdentityLogRepository, IdentityPersistenceError,
    IdentityPgStore,
};

pub const CLIENT_BINDING_AUTHORIZATION_HASH_DOMAIN: &[u8] =
    b"dirextalk.client-binding-authorization.v1\0";
const MAX_IMPORT_BYTES: usize = 24 * 1024;
const MAX_CA_BYTES: usize = 12 * 1024;

/// Domain separator reserved for the durable issuance request digest contract.
#[allow(
    dead_code,
    reason = "exported protocol domain is reserved for the issuance request wire"
)]
pub const CLIENT_BINDING_ISSUE_HASH_DOMAIN: &[u8] = b"dirextalk.client-binding-issue-request.v1\0";
pub const CLIENT_BINDING_BOOTSTRAP_HASH_DOMAIN: &[u8] =
    b"dirextalk.client-binding-bootstrap-request.v1\0";
pub const CLIENT_BINDING_INITIAL_DEVICE_HASH_DOMAIN: &[u8] =
    b"dirextalk.client-binding-initial-device-request.v1\0";

/// A client-binding bearer capability.  It deliberately has no Debug or Clone.
pub struct ClientBindingAuthorization([u8; 32]);
impl Drop for ClientBindingAuthorization {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
impl ClientBindingAuthorization {
    /// Parses the canonical unpadded base64url bearer value.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not exactly 32 decoded bytes.
    pub fn parse(value: &str) -> Result<Self, ClientBindingImportError> {
        if value.len() != 43 {
            return Err(ClientBindingImportError);
        }
        let mut raw = [0; 32];
        Base64UrlUnpadded::decode(value, &mut raw).map_err(|_| ClientBindingImportError)?;
        let authorization = Self(raw);
        raw.zeroize();
        Ok(authorization)
    }
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::hash_domain(CLIENT_BINDING_AUTHORIZATION_HASH_DOMAIN, &self.0)
    }
    #[must_use]
    pub fn encoded(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.0)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ImportWire {
    schema: String,
    schema_version: u8,
    binding_id: String,
    deployment_operation_id: String,
    tenant_id: String,
    server_origin: String,
    identity_tls_root_ca_pem: String,
    identity_tls_root_ca_sha256: String,
    expires_at_unix_ms: i64,
    authorization: String,
}

impl Drop for ImportWire {
    fn drop(&mut self) {
        self.authorization.zeroize();
        self.identity_tls_root_ca_pem.zeroize();
    }
}

/// Strict, locally parsed import.  The authorization is retained only in this
/// non-debuggable value and is zeroized at drop.
pub struct ClientBindingImport {
    pub binding_id: Uuid,
    pub deployment_operation_id: Uuid,
    pub tenant_id: Uuid,
    pub server_origin: String,
    pub identity_tls_root_ca_pem: String,
    pub expires_at_unix_ms: i64,
    authorization: ClientBindingAuthorization,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientBindingState {
    Issued,
    IdentityBound,
    Consumed,
    Expired,
    Revoked,
}

impl ClientBindingState {
    fn parse(value: &str) -> Result<Self, ClientBindingWorkflowError> {
        match value {
            "issued" => Ok(Self::Issued),
            "identity_bound" => Ok(Self::IdentityBound),
            "consumed" => Ok(Self::Consumed),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            _ => Err(ClientBindingWorkflowError::Corrupt),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClientBindingIssueCommand {
    pub binding_id: Uuid,
    pub deployment_operation_id: Uuid,
    pub tenant_id: Uuid,
    pub server_origin: String,
    pub tls_root_ca_sha256: Sha256Digest,
    pub authorization_digest: Sha256Digest,
    pub artifact_digest: Sha256Digest,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientBindingIssueOutcome {
    pub binding_id: Uuid,
    pub deployment_operation_id: Uuid,
    pub tenant_id: Uuid,
    pub server_origin: String,
    pub tls_root_ca_sha256: Sha256Digest,
    pub authorization_digest: Sha256Digest,
    pub artifact_digest: Sha256Digest,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub state: ClientBindingState,
    pub replayed: bool,
}

#[derive(Debug)]
pub enum ClientBindingWorkflowError {
    Persistence(IdentityPersistenceError),
    Invalid,
    Unauthorized,
    Conflict,
    Expired,
    Revoked,
    Corrupt,
}

impl From<IdentityPersistenceError> for ClientBindingWorkflowError {
    fn from(error: IdentityPersistenceError) -> Self {
        Self::Persistence(error)
    }
}

impl std::fmt::Display for ClientBindingWorkflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Persistence(_) => "client binding persistence failure",
            Self::Invalid => "invalid client binding request",
            Self::Unauthorized => "client binding authorization rejected",
            Self::Conflict => "client binding conflict",
            Self::Expired => "client binding expired",
            Self::Revoked => "client binding revoked",
            Self::Corrupt => "client binding state corrupt",
        })
    }
}

impl std::error::Error for ClientBindingWorkflowError {}

#[derive(Clone, Copy, Debug, Default)]
pub struct ClientBindingRepository;

impl ClientBindingRepository {
    /// Issues one durable binding, replaying an exact live operation request.
    ///
    /// # Errors
    ///
    /// Returns a workflow error when validation, persistence, or idempotency
    /// checks fail.
    #[allow(
        clippy::too_many_lines,
        reason = "transactional issuance keeps fence and rollback together"
    )]
    pub async fn issue(
        self,
        store: &IdentityPgStore,
        command: &ClientBindingIssueCommand,
    ) -> Result<ClientBindingIssueOutcome, ClientBindingWorkflowError> {
        if command.expires_at_ms <= command.issued_at_ms
            || command.expires_at_ms > command.issued_at_ms.saturating_add(900_000)
            || !is_canonical_https_origin(&command.server_origin)
        {
            return Err(ClientBindingWorkflowError::Invalid);
        }
        let mut session = store
            .begin()
            .await
            .map_err(ClientBindingWorkflowError::from)?;
        let result = async {
            let key = i64::from_be_bytes(
                command.deployment_operation_id.as_bytes()[..8]
                    .try_into()
                    .map_err(|_| ClientBindingWorkflowError::Corrupt)?,
            );
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(key)
                .execute(session.connection())
                .await
                .map_err(IdentityPersistenceError::from)?;
            if let Some(row) = sqlx::query(
                "SELECT binding_id, deployment_operation_id, tenant_id, server_origin,
                        tls_root_ca_sha256, authorization_digest, artifact_digest,
                        issued_at_ms, expires_at_ms, state
                   FROM identity.client_bindings
                  WHERE tenant_id=$1 AND deployment_operation_id=$2
                    AND state IN ('issued','identity_bound')
                  FOR UPDATE",
            )
            .bind(command.tenant_id)
            .bind(command.deployment_operation_id)
            .fetch_optional(session.connection())
            .await
            .map_err(IdentityPersistenceError::from)?
            {
                let existing = issue_outcome_from_row(&row, false)?;
                if existing.server_origin != command.server_origin
                    || existing.tls_root_ca_sha256 != command.tls_root_ca_sha256
                    || existing.authorization_digest != command.authorization_digest
                    || existing.artifact_digest != command.artifact_digest
                    || existing.issued_at_ms != command.issued_at_ms
                    || existing.expires_at_ms != command.expires_at_ms
                {
                    return Err(ClientBindingWorkflowError::Conflict);
                }
                return Ok(ClientBindingIssueOutcome {
                    replayed: true,
                    ..existing
                });
            }
            let inserted = sqlx::query(
                "INSERT INTO identity.client_bindings (
                     binding_id, deployment_operation_id, tenant_id, server_origin,
                     tls_root_ca_sha256, authorization_digest, artifact_digest,
                     issued_at_ms, expires_at_ms, state, revision
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'issued',1)",
            )
            .bind(command.binding_id)
            .bind(command.deployment_operation_id)
            .bind(command.tenant_id)
            .bind(&command.server_origin)
            .bind(command.tls_root_ca_sha256.as_bytes().as_slice())
            .bind(command.authorization_digest.as_bytes().as_slice())
            .bind(command.artifact_digest.as_bytes().as_slice())
            .bind(command.issued_at_ms)
            .bind(command.expires_at_ms)
            .execute(session.connection())
            .await;
            match inserted {
                Ok(_) => Ok(ClientBindingIssueOutcome {
                    binding_id: command.binding_id,
                    deployment_operation_id: command.deployment_operation_id,
                    tenant_id: command.tenant_id,
                    server_origin: command.server_origin.clone(),
                    tls_root_ca_sha256: command.tls_root_ca_sha256,
                    authorization_digest: command.authorization_digest,
                    artifact_digest: command.artifact_digest,
                    issued_at_ms: command.issued_at_ms,
                    expires_at_ms: command.expires_at_ms,
                    state: ClientBindingState::Issued,
                    replayed: false,
                }),
                Err(error) => Err(ClientBindingWorkflowError::Persistence(error.into())),
            }
        }
        .await;
        match result {
            Ok(value) => {
                session.commit().await?;
                Ok(value)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Revokes an issued or identity-bound binding before expiry.
    ///
    /// # Errors
    ///
    /// Returns a workflow error when the binding is absent, inactive, or the
    /// transaction cannot commit.
    pub async fn revoke(
        self,
        store: &IdentityPgStore,
        binding_id: Uuid,
        now_ms: i64,
    ) -> Result<(), ClientBindingWorkflowError> {
        let mut session = store
            .begin()
            .await
            .map_err(ClientBindingWorkflowError::from)?;
        let rows = sqlx::query(
            "UPDATE identity.client_bindings
                SET state='revoked', revision=revision+1
              WHERE binding_id=$1 AND state IN ('issued','identity_bound')
                AND expires_at_ms>$2",
        )
        .bind(binding_id)
        .bind(now_ms)
        .execute(session.connection())
        .await
        .map_err(|e| ClientBindingWorkflowError::Persistence(e.into()))?
        .rows_affected();
        if rows != 1 {
            let _ = session.rollback().await;
            return Err(ClientBindingWorkflowError::Conflict);
        }
        session.commit().await?;
        Ok(())
    }

    /// Marks all currently live bindings at or past expiry as expired.
    ///
    /// # Errors
    ///
    /// Returns a workflow error when the transaction cannot complete.
    pub async fn expire(
        self,
        store: &IdentityPgStore,
        now_ms: i64,
    ) -> Result<u64, ClientBindingWorkflowError> {
        let mut session = store
            .begin()
            .await
            .map_err(ClientBindingWorkflowError::from)?;
        let result = sqlx::query(
            "UPDATE identity.client_bindings SET state='expired', revision=revision+1
              WHERE state IN ('issued','identity_bound') AND expires_at_ms<=$1",
        )
        .bind(now_ms)
        .execute(session.connection())
        .await
        .map_err(|e| ClientBindingWorkflowError::Persistence(e.into()))?
        .rows_affected();
        session.commit().await?;
        Ok(result)
    }

    /// Appends the exact genesis event authorized by a live binding.
    ///
    /// # Errors
    ///
    /// Returns a workflow error when authorization, event shape, idempotency,
    /// or persistence checks fail.
    pub async fn deployment_bootstrap(
        self,
        store: &IdentityPgStore,
        binding_id: Uuid,
        authorization_digest: Sha256Digest,
        idempotency_key_hash: Sha256Digest,
        exact_event_bytes: Vec<u8>,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, ClientBindingWorkflowError> {
        let event = IdentityLogEventV1::decode_and_verify(&exact_event_bytes)
            .map_err(|_| ClientBindingWorkflowError::Invalid)?;
        if !matches!(event.payload(), IdentityLogEventPayloadV1::Genesis { .. })
            || event.sequence().get() != 1
        {
            return Err(ClientBindingWorkflowError::Invalid);
        }
        let mut session = store
            .begin()
            .await
            .map_err(ClientBindingWorkflowError::from)?;
        let result = async {
            let row = sqlx::query(
                "SELECT authorization_digest, expires_at_ms, state, identity_id,
                        identity_request_digest, identity_idempotency_key_hash
                   FROM identity.client_bindings WHERE binding_id=$1 FOR UPDATE",
            )
            .bind(binding_id)
            .fetch_optional(session.connection())
            .await
            .map_err(IdentityPersistenceError::from)?
            .ok_or(ClientBindingWorkflowError::Unauthorized)?;
            validate_authorization_row(&row, authorization_digest, committed_at.get())?;
            let request_digest = request_digest(
                CLIENT_BINDING_BOOTSTRAP_HASH_DOMAIN,
                &exact_event_bytes,
                idempotency_key_hash,
            );
            let state = ClientBindingState::parse(
                row.try_get::<String, _>("state")
                    .map_err(|_| ClientBindingWorkflowError::Corrupt)?
                    .as_str(),
            )?;
            if matches!(
                state,
                ClientBindingState::IdentityBound | ClientBindingState::Consumed
            ) && (row
                .try_get::<Option<Vec<u8>>, _>("identity_request_digest")
                .map_err(|_| ClientBindingWorkflowError::Corrupt)?
                .as_deref()
                != Some(request_digest.as_bytes())
                || row
                    .try_get::<Option<Vec<u8>>, _>("identity_idempotency_key_hash")
                    .map_err(|_| ClientBindingWorkflowError::Corrupt)?
                    .as_deref()
                    != Some(idempotency_key_hash.as_bytes()))
            {
                return Err(ClientBindingWorkflowError::Conflict);
            }
            let command = IdentityAppendCommand::new(idempotency_key_hash, None, exact_event_bytes)
                .map_err(ClientBindingWorkflowError::from)?;
            let outcome = IdentityLogRepository::new()
                .append_in_transaction(session.connection(), &command, committed_at)
                .await
                .map_err(ClientBindingWorkflowError::from)?;
            if state == ClientBindingState::Issued {
                let identity_id = event.identity_id().to_string();
                let updated = sqlx::query(
                    "UPDATE identity.client_bindings SET state='identity_bound', identity_id=$2,
                            identity_request_digest=$3, identity_idempotency_key_hash=$4,
                            revision=revision+1
                      WHERE binding_id=$1 AND state='issued'",
                )
                .bind(binding_id)
                .bind(identity_id)
                .bind(request_digest.as_bytes().as_slice())
                .bind(idempotency_key_hash.as_bytes().as_slice())
                .execute(session.connection())
                .await
                .map_err(IdentityPersistenceError::from)?;
                if updated.rows_affected() != 1 {
                    return Err(ClientBindingWorkflowError::Conflict);
                }
            }
            Ok(outcome)
        }
        .await;
        match result {
            Ok(value) => {
                session.commit().await?;
                Ok(value)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Appends and consumes the exact first-device event for a bound identity.
    ///
    /// # Errors
    ///
    /// Returns a workflow error when authorization, chain continuity,
    /// idempotency, or persistence checks fail.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "transactional chain append keeps authorization and consume atomic"
    )]
    pub async fn initial_device(
        self,
        store: &IdentityPgStore,
        binding_id: Uuid,
        authorization_digest: Sha256Digest,
        idempotency_key_hash: Sha256Digest,
        expected_genesis_hash: Sha256Digest,
        exact_event_bytes: Vec<u8>,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, ClientBindingWorkflowError> {
        let event = IdentityLogEventV1::decode_and_verify(&exact_event_bytes)
            .map_err(|_| ClientBindingWorkflowError::Invalid)?;
        if !matches!(event.payload(), IdentityLogEventPayloadV1::DeviceAdd { .. })
            || event.sequence().get() != 2
            || event.previous_event_hash() != Some(expected_genesis_hash)
        {
            return Err(ClientBindingWorkflowError::Invalid);
        }
        let mut session = store
            .begin()
            .await
            .map_err(ClientBindingWorkflowError::from)?;
        let result = async {
            let row = sqlx::query(
                "SELECT authorization_digest, expires_at_ms, state, identity_id,
                        identity_request_digest, identity_idempotency_key_hash,
                        consume_request_digest, consume_idempotency_key_hash
                   FROM identity.client_bindings WHERE binding_id=$1 FOR UPDATE",
            )
            .bind(binding_id)
            .fetch_optional(session.connection())
            .await
            .map_err(IdentityPersistenceError::from)?
            .ok_or(ClientBindingWorkflowError::Unauthorized)?;
            validate_authorization_row(&row, authorization_digest, committed_at.get())?;
            if row
                .try_get::<Option<String>, _>("identity_id")
                .map_err(|_| ClientBindingWorkflowError::Corrupt)?
                .as_deref()
                != Some(event.identity_id().to_string().as_str())
            {
                return Err(ClientBindingWorkflowError::Unauthorized);
            }
            let state = ClientBindingState::parse(
                row.try_get::<String, _>("state")
                    .map_err(|_| ClientBindingWorkflowError::Corrupt)?
                    .as_str(),
            )?;
            if !matches!(
                state,
                ClientBindingState::IdentityBound | ClientBindingState::Consumed
            ) {
                return Err(ClientBindingWorkflowError::Conflict);
            }
            let request_digest = request_digest(
                CLIENT_BINDING_INITIAL_DEVICE_HASH_DOMAIN,
                &exact_event_bytes,
                idempotency_key_hash,
            );
            if state == ClientBindingState::Consumed
                && (row
                    .try_get::<Option<Vec<u8>>, _>("consume_request_digest")
                    .map_err(|_| ClientBindingWorkflowError::Corrupt)?
                    .as_deref()
                    != Some(request_digest.as_bytes())
                    || row
                        .try_get::<Option<Vec<u8>>, _>("consume_idempotency_key_hash")
                        .map_err(|_| ClientBindingWorkflowError::Corrupt)?
                        .as_deref()
                        != Some(idempotency_key_hash.as_bytes()))
            {
                return Err(ClientBindingWorkflowError::Conflict);
            }
            let previous =
                dtx_wire::SafeUint::new(1).map_err(|_| ClientBindingWorkflowError::Invalid)?;
            let head = crate::IdentityLogHead::new(
                event.identity_id(),
                dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
                previous,
                expected_genesis_hash,
            );
            let command =
                IdentityAppendCommand::new(idempotency_key_hash, Some(head), exact_event_bytes)
                    .map_err(ClientBindingWorkflowError::from)?;
            let outcome = IdentityLogRepository::new()
                .append_in_transaction(session.connection(), &command, committed_at)
                .await
                .map_err(ClientBindingWorkflowError::from)?;
            if state == ClientBindingState::IdentityBound {
                let updated = sqlx::query(
                    "UPDATE identity.client_bindings SET state='consumed', device_id=$2,
                            consume_request_digest=$3, consume_idempotency_key_hash=$4,
                            revision=revision+1
                      WHERE binding_id=$1 AND state='identity_bound'",
                )
                .bind(binding_id)
                .bind(extract_device_id(&event).ok_or(ClientBindingWorkflowError::Invalid)?)
                .bind(request_digest.as_bytes().as_slice())
                .bind(idempotency_key_hash.as_bytes().as_slice())
                .execute(session.connection())
                .await
                .map_err(IdentityPersistenceError::from)?;
                if updated.rows_affected() != 1 {
                    return Err(ClientBindingWorkflowError::Conflict);
                }
            }
            Ok(outcome)
        }
        .await;
        match result {
            Ok(value) => {
                session.commit().await?;
                Ok(value)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }
}

fn is_canonical_https_origin(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.origin().ascii_serialization() == value
}

fn request_digest(domain: &[u8], body: &[u8], idempotency: Sha256Digest) -> Sha256Digest {
    let mut bytes = Vec::with_capacity(body.len() + 32);
    bytes.extend_from_slice(idempotency.as_bytes());
    bytes.extend_from_slice(body);
    Sha256Digest::hash_domain(domain, &bytes)
}

fn validate_authorization_row(
    row: &sqlx::postgres::PgRow,
    authorization_digest: Sha256Digest,
    now_ms: i64,
) -> Result<(), ClientBindingWorkflowError> {
    let stored = row
        .try_get::<Vec<u8>, _>("authorization_digest")
        .map_err(|_| ClientBindingWorkflowError::Corrupt)?;
    if stored.as_slice() != authorization_digest.as_bytes() {
        return Err(ClientBindingWorkflowError::Unauthorized);
    }
    let expires = row
        .try_get::<i64, _>("expires_at_ms")
        .map_err(|_| ClientBindingWorkflowError::Corrupt)?;
    if now_ms >= expires {
        return Err(ClientBindingWorkflowError::Expired);
    }
    match ClientBindingState::parse(
        row.try_get::<String, _>("state")
            .map_err(|_| ClientBindingWorkflowError::Corrupt)?
            .as_str(),
    )? {
        ClientBindingState::Revoked => Err(ClientBindingWorkflowError::Revoked),
        ClientBindingState::Expired => Err(ClientBindingWorkflowError::Expired),
        _ => Ok(()),
    }
}

fn issue_outcome_from_row(
    row: &sqlx::postgres::PgRow,
    replayed: bool,
) -> Result<ClientBindingIssueOutcome, ClientBindingWorkflowError> {
    let digest = |name: &str| -> Result<Sha256Digest, ClientBindingWorkflowError> {
        let bytes = row
            .try_get::<Vec<u8>, _>(name)
            .map_err(|_| ClientBindingWorkflowError::Corrupt)?;
        if bytes.len() != 32 {
            return Err(ClientBindingWorkflowError::Corrupt);
        }
        let mut value = [0_u8; 32];
        value.copy_from_slice(&bytes);
        Ok(Sha256Digest::from_bytes(value))
    };
    Ok(ClientBindingIssueOutcome {
        binding_id: row
            .try_get("binding_id")
            .map_err(|_| ClientBindingWorkflowError::Corrupt)?,
        deployment_operation_id: row
            .try_get("deployment_operation_id")
            .map_err(|_| ClientBindingWorkflowError::Corrupt)?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|_| ClientBindingWorkflowError::Corrupt)?,
        server_origin: row
            .try_get("server_origin")
            .map_err(|_| ClientBindingWorkflowError::Corrupt)?,
        tls_root_ca_sha256: digest("tls_root_ca_sha256")?,
        authorization_digest: digest("authorization_digest")?,
        artifact_digest: digest("artifact_digest")?,
        issued_at_ms: row
            .try_get("issued_at_ms")
            .map_err(|_| ClientBindingWorkflowError::Corrupt)?,
        expires_at_ms: row
            .try_get("expires_at_ms")
            .map_err(|_| ClientBindingWorkflowError::Corrupt)?,
        state: ClientBindingState::parse(
            row.try_get::<String, _>("state")
                .map_err(|_| ClientBindingWorkflowError::Corrupt)?
                .as_str(),
        )?,
        replayed,
    })
}

fn extract_device_id(event: &IdentityLogEventV1) -> Option<Uuid> {
    match event.payload() {
        IdentityLogEventPayloadV1::DeviceAdd { certificate } => {
            Some(*certificate.device_id().as_uuid())
        }
        _ => None,
    }
}
impl ClientBindingImport {
    /// Parses the exact canonical client-binding import artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the artifact is non-canonical, malformed, or its
    /// CA and authorization values fail validation.
    pub fn parse_exact(bytes: &[u8]) -> Result<Self, ClientBindingImportError> {
        if bytes.is_empty() || bytes.len() > MAX_IMPORT_BYTES || std::str::from_utf8(bytes).is_err()
        {
            return Err(ClientBindingImportError);
        }
        let mut wire: ImportWire =
            serde_json::from_slice(bytes).map_err(|_| ClientBindingImportError)?;
        let canonical =
            Zeroizing::new(serde_json::to_vec(&wire).map_err(|_| ClientBindingImportError)?);
        if *canonical != bytes {
            return Err(ClientBindingImportError);
        }
        if wire.schema != "dirextalk.client-binding"
            || wire.schema_version != 1
            || !canonical_origin(&wire.server_origin)
            || wire.identity_tls_root_ca_pem.len() > MAX_CA_BYTES
        {
            return Err(ClientBindingImportError);
        }
        let binding_id = canonical_v7(&wire.binding_id)?;
        let deployment_operation_id = canonical_v7(&wire.deployment_operation_id)?;
        let tenant_id = canonical_v7(&wire.tenant_id)?;
        let digest = hex_digest(&wire.identity_tls_root_ca_sha256)?;
        let (remainder, pem) = parse_x509_pem(wire.identity_tls_root_ca_pem.as_bytes())
            .map_err(|_| ClientBindingImportError)?;
        if !remainder.is_empty() {
            return Err(ClientBindingImportError);
        }
        let certificate = pem.parse_x509().map_err(|_| ClientBindingImportError)?;
        if !certificate.is_ca() {
            return Err(ClientBindingImportError);
        }
        let actual = Sha256::digest(wire.identity_tls_root_ca_pem.as_bytes());
        if actual.as_slice() != digest.as_bytes() {
            return Err(ClientBindingImportError);
        }
        let authorization = ClientBindingAuthorization::parse(&wire.authorization)?;
        Ok(Self {
            binding_id,
            deployment_operation_id,
            tenant_id,
            server_origin: std::mem::take(&mut wire.server_origin),
            identity_tls_root_ca_pem: std::mem::take(&mut wire.identity_tls_root_ca_pem),
            expires_at_unix_ms: wire.expires_at_unix_ms,
            authorization,
        })
    }
    #[must_use]
    pub fn authorization_digest(&self) -> Sha256Digest {
        self.authorization.digest()
    }
}
#[derive(Clone, Copy, Debug)]
pub struct ClientBindingImportError;
impl std::fmt::Display for ClientBindingImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid client binding")
    }
}
impl std::error::Error for ClientBindingImportError {}
fn canonical_v7(value: &str) -> Result<Uuid, ClientBindingImportError> {
    let id = Uuid::parse_str(value).map_err(|_| ClientBindingImportError)?;
    if id.to_string() != value || id.get_version_num() != 7 {
        Err(ClientBindingImportError)
    } else {
        Ok(id)
    }
}
fn canonical_origin(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.origin().ascii_serialization() == value
}
fn hex_digest(value: &str) -> Result<Sha256Digest, ClientBindingImportError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ClientBindingImportError);
    }
    let mut out = [0; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| ClientBindingImportError)?;
    }
    Ok(Sha256Digest::from_bytes(out))
}
