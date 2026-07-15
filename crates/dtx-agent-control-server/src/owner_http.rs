//! Owner-authenticated HTTP boundary for Agent identity approval and opaque provisioning.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_agent_control::ServerCommandPayload;
use dtx_agent_registry::DeviceCredentialFingerprint;
use dtx_domain::{
    AgentDeviceId, ApprovalId, BindingId, ConnectorId, DeviceId, DeviceSessionId, IdentityId,
    InstallationId, ProvisioningDeliveryId, ProvisioningRecipientKeyId, RequestId, Revision,
    TenantId,
};
use dtx_identity_persistence::DeviceSessionCredential;
use dtx_storage::PgStore;
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, UtcMillis,
    decode_deterministic_cbor, encode_deterministic_cbor,
};
use serde::Serialize;

use crate::connector_projection::{
    CONNECTOR_PROJECTION_MEDIA_TYPE_V1, ConnectorProjectionError, ConnectorProjectionQueryV1,
    DEFAULT_CONNECTOR_PROJECTION_LIMIT, MAX_CONNECTOR_PROJECTION_LIMIT,
    list_connector_projection_v1,
};
use crate::{AGENT_IDENTITY_APPROVAL_BINDING_DOMAIN, AgentIdentityApprovalCommand};
use crate::{
    AgentIdentityProvisioningError, AgentProvisioningDeliveryCommand,
    AgentProvisioningDeliveryReceipt, AgentProvisioningRevocationCommand,
    AgentProvisioningRevocationReceipt, ConnectorCommandFence, ConnectorControlApplicationError,
    ConnectorLifecycleAction, ConnectorLifecycleCommandWrite, PostgresConnectorControlApplication,
    ProtobufDurableCommandDecoder, approve_agent_identity, create_agent_provisioning_delivery,
    get_agent_identity_approval, get_agent_provisioning_delivery, get_agent_provisioning_target,
    revoke_agent_provisioning,
};

const DEVICE_SESSION_SCHEME: &str = "DTX-Device-Session";
const IDEMPOTENCY_DOMAIN: &[u8] = b"dirextalk.agent-provisioning-idempotency-key.v1\0";
const DELIVERY_BINDING_DOMAIN: &[u8] = b"dirextalk.agent-provisioning-delivery-binding.v1\0";
const CAPSULE_DIGEST_DOMAIN: &[u8] = b"dirextalk.agent-provisioning-capsule.v1\0";
const REVOCATION_BINDING_DOMAIN: &[u8] = b"dirextalk.agent-provisioning-revocation-binding.v1\0";
const MAX_SMALL_BODY: usize = 16 * 1024;
const MAX_DELIVERY_BODY: usize = 212_992;

pub type OwnerBackendFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CborOwnerReply, AgentProvisioningOwnerError>> + Send + 'a>>;

/// Exact HTTP response returned by the durable application boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CborOwnerReply {
    pub status: StatusCode,
    pub content_type: &'static str,
    pub exact_cbor: Vec<u8>,
}

/// Parsed, still-opaque delivery request. The server must never decrypt `sealed_capsule`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryOwnerCommand {
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
    pub capsule_digest: Sha256Digest,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub created_at: UtcMillis,
    pub expires_at: UtcMillis,
    pub sealed_capsule: Vec<u8>,
    pub binding_digest: Sha256Digest,
    pub owner_signature: Ed25519Signature,
}

/// Parsed fail-closed installation/device revocation request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationOwnerCommand {
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

/// A closed Owner request for one already enrolled Connector lifecycle action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorLifecycleOwnerCommand {
    pub connector_id: ConnectorId,
    pub operation_id: RequestId,
    pub generation: u64,
    pub spec_revision: Revision,
    pub action: ConnectorLifecycleAction,
}

/// Durable application interface. Parsing and stable HTTP errors stay independent of `PostgreSQL`.
pub trait AgentProvisioningOwnerBackend: Send + Sync + 'static {
    fn list_connectors(
        &self,
        credential: DeviceSessionCredential,
        query: ConnectorProjectionQueryV1,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_>;
    fn lifecycle(
        &self,
        credential: DeviceSessionCredential,
        command: ConnectorLifecycleOwnerCommand,
    ) -> OwnerBackendFuture<'_>;
    fn approve(
        &self,
        credential: DeviceSessionCredential,
        idempotency_key_hash: Sha256Digest,
        command: AgentIdentityApprovalCommand,
        exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_>;
    fn get_approval(
        &self,
        credential: DeviceSessionCredential,
        installation_id: InstallationId,
        approval_id: ApprovalId,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_>;
    fn get_target(
        &self,
        credential: DeviceSessionCredential,
        installation_id: InstallationId,
        approval_id: ApprovalId,
        binding_id: BindingId,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_>;
    fn deliver(
        &self,
        credential: DeviceSessionCredential,
        idempotency_key_hash: Sha256Digest,
        command: DeliveryOwnerCommand,
        exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_>;
    fn get_delivery(
        &self,
        credential: DeviceSessionCredential,
        installation_id: InstallationId,
        delivery_id: ProvisioningDeliveryId,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_>;
    fn revoke(
        &self,
        credential: DeviceSessionCredential,
        idempotency_key_hash: Sha256Digest,
        command: RevocationOwnerCommand,
        exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_>;
}

/// Stable transport-level failure vocabulary. It deliberately contains no secret-bearing detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentProvisioningOwnerError {
    InvalidRequest,
    AuthenticationRejected,
    AccessDenied,
    NotFound,
    Conflict,
    TemporarilyUnavailable,
}

/// `PostgreSQL` adapter for one tenant-scoped Owner API listener.
#[derive(Clone)]
pub struct PostgresAgentProvisioningOwnerBackend {
    store: PgStore,
    tenant_id: TenantId,
    connector_control: Arc<PostgresConnectorControlApplication>,
}

impl PostgresAgentProvisioningOwnerBackend {
    #[must_use]
    pub fn new(
        store: PgStore,
        tenant_id: TenantId,
        connector_control: Arc<PostgresConnectorControlApplication>,
    ) -> Self {
        Self {
            store,
            tenant_id,
            connector_control,
        }
    }
}

impl AgentProvisioningOwnerBackend for PostgresAgentProvisioningOwnerBackend {
    fn list_connectors(
        &self,
        credential: DeviceSessionCredential,
        query: ConnectorProjectionQueryV1,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            let page =
                list_connector_projection_v1(&self.store, self.tenant_id, &credential, query, now)
                    .await
                    .map_err(map_connector_projection_error)?;
            Ok(CborOwnerReply {
                status: StatusCode::OK,
                content_type: CONNECTOR_PROJECTION_MEDIA_TYPE_V1,
                exact_cbor: serde_json::to_vec(&page)
                    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?,
            })
        })
    }

    fn lifecycle(
        &self,
        credential: DeviceSessionCredential,
        command: ConnectorLifecycleOwnerCommand,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            let write = self
                .connector_control
                .enqueue_owner_lifecycle(
                    &credential,
                    command.action,
                    ConnectorCommandFence {
                        tenant_id: self.tenant_id,
                        connector_id: command.connector_id,
                        generation: command.generation,
                        spec_revision: command.spec_revision,
                    },
                    command.operation_id,
                )
                .await
                .map_err(map_connector_control_error)?;
            Ok(CborOwnerReply {
                status: if write.replayed() {
                    StatusCode::OK
                } else {
                    StatusCode::CREATED
                },
                content_type: "application/vnd.dirextalk.connector-lifecycle-receipt.v1+json",
                exact_cbor: connector_lifecycle_receipt_json(
                    command.action,
                    command.connector_id,
                    &write,
                )?,
            })
        })
    }

    fn approve(
        &self,
        credential: DeviceSessionCredential,
        idempotency_key_hash: Sha256Digest,
        command: AgentIdentityApprovalCommand,
        _exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            if command.tenant_id != self.tenant_id {
                return Err(AgentProvisioningOwnerError::AccessDenied);
            }
            let receipt = approve_agent_identity(
                &self.store,
                &credential,
                idempotency_key_hash,
                command,
                now,
            )
            .await
            .map_err(|error| map_application_error(&error))?;
            Ok(CborOwnerReply {
                status: approval_status(receipt.replayed),
                content_type: "application/vnd.dirextalk.agent-identity-approval-receipt.v1+cbor",
                exact_cbor: receipt.exact_cbor,
            })
        })
    }

    fn get_approval(
        &self,
        credential: DeviceSessionCredential,
        installation_id: InstallationId,
        approval_id: ApprovalId,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            let receipt = get_agent_identity_approval(
                &self.store,
                &credential,
                self.tenant_id,
                approval_id,
                now,
            )
            .await
            .map_err(|error| map_application_error(&error))?;
            if receipt.installation_id != installation_id {
                return Err(AgentProvisioningOwnerError::NotFound);
            }
            Ok(CborOwnerReply {
                status: StatusCode::OK,
                content_type: "application/vnd.dirextalk.agent-identity-approval-receipt.v1+cbor",
                exact_cbor: receipt.exact_cbor,
            })
        })
    }

    fn get_target(
        &self,
        credential: DeviceSessionCredential,
        installation_id: InstallationId,
        approval_id: ApprovalId,
        binding_id: BindingId,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            let target = get_agent_provisioning_target(
                &self.store,
                &credential,
                self.tenant_id,
                approval_id,
                now,
            )
            .await
            .map_err(|error| map_application_error(&error))?;
            if target.installation_id != installation_id || target.binding_id != binding_id {
                return Err(AgentProvisioningOwnerError::NotFound);
            }
            Ok(CborOwnerReply {
                status: StatusCode::OK,
                content_type: "application/vnd.dirextalk.agent-provisioning-recipient.v1+cbor",
                exact_cbor: target.exact_cbor,
            })
        })
    }

    fn deliver(
        &self,
        credential: DeviceSessionCredential,
        idempotency_key_hash: Sha256Digest,
        command: DeliveryOwnerCommand,
        _exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            if command.tenant_id != self.tenant_id {
                return Err(AgentProvisioningOwnerError::AccessDenied);
            }
            let receipt = create_agent_provisioning_delivery(
                &self.store,
                &ProtobufDurableCommandDecoder,
                &credential,
                idempotency_key_hash,
                AgentProvisioningDeliveryCommand {
                    delivery_id: command.delivery_id,
                    approval_id: command.approval_id,
                    tenant_id: command.tenant_id,
                    installation_id: command.installation_id,
                    binding_id: command.binding_id,
                    agent_device_id: command.agent_device_id,
                    agent_identity_id: command.agent_identity_id,
                    identity_device_id: command.identity_device_id,
                    provisioning_revision: command.provisioning_revision,
                    recipient_key_id: command.recipient_key_id,
                    recipient_descriptor_digest: command.recipient_descriptor_digest,
                    sealed_capsule: command.sealed_capsule,
                    capsule_digest: command.capsule_digest,
                    owner_identity_id: command.owner_identity_id,
                    owner_device_id: command.owner_device_id,
                    created_at: command.created_at,
                    expires_at: command.expires_at,
                    owner_signature: command.owner_signature,
                },
                now,
            )
            .await
            .map_err(|error| map_application_error(&error))?;
            Ok(CborOwnerReply {
                status: delivery_status(receipt.replayed),
                content_type: "application/vnd.dirextalk.agent-provisioning-delivery-receipt.v1+cbor",
                exact_cbor: delivery_receipt_cbor(&receipt)?,
            })
        })
    }

    fn get_delivery(
        &self,
        credential: DeviceSessionCredential,
        installation_id: InstallationId,
        delivery_id: ProvisioningDeliveryId,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            let receipt = get_agent_provisioning_delivery(
                &self.store,
                &credential,
                self.tenant_id,
                delivery_id,
                now,
            )
            .await
            .map_err(|error| map_application_error(&error))?;
            if receipt.installation_id != installation_id {
                return Err(AgentProvisioningOwnerError::NotFound);
            }
            Ok(CborOwnerReply {
                status: StatusCode::OK,
                content_type: "application/vnd.dirextalk.agent-provisioning-delivery-receipt.v1+cbor",
                exact_cbor: delivery_receipt_cbor(&receipt)?,
            })
        })
    }

    fn revoke(
        &self,
        credential: DeviceSessionCredential,
        idempotency_key_hash: Sha256Digest,
        command: RevocationOwnerCommand,
        _exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            if command.tenant_id != self.tenant_id {
                return Err(AgentProvisioningOwnerError::AccessDenied);
            }
            let receipt = revoke_agent_provisioning(
                &self.store,
                &ProtobufDurableCommandDecoder,
                &credential,
                idempotency_key_hash,
                AgentProvisioningRevocationCommand {
                    revocation_id: command.revocation_id,
                    tenant_id: command.tenant_id,
                    installation_id: command.installation_id,
                    expected_revision: command.expected_revision,
                    owner_identity_id: command.owner_identity_id,
                    owner_device_id: command.owner_device_id,
                    scope: command.scope,
                    expires_at: command.expires_at,
                    binding_digest: command.binding_digest,
                    owner_signature: command.owner_signature,
                },
                now,
            )
            .await
            .map_err(|error| map_application_error(&error))?;
            Ok(CborOwnerReply {
                status: StatusCode::OK,
                content_type: "application/vnd.dirextalk.agent-provisioning-revocation-receipt.v1+cbor",
                exact_cbor: revocation_receipt_cbor(&receipt)?,
            })
        })
    }
}

const fn approval_status(replayed: bool) -> StatusCode {
    if replayed {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    }
}

const fn delivery_status(replayed: bool) -> StatusCode {
    if replayed {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    }
}

fn revocation_receipt_cbor(
    receipt: &AgentProvisioningRevocationReceipt,
) -> Result<Vec<u8>, AgentProvisioningOwnerError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(receipt.revocation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(receipt.installation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(receipt.binding_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Unsigned(receipt.committed_revision.get()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Unsigned(u64::from(receipt.scope)),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Bytes(receipt.encoded_command_digest.as_bytes().to_vec()),
        ),
        (
            CanonicalValue::Unsigned(8),
            receipt.revoked_at.to_canonical_value(),
        ),
    ]))
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)
}

fn delivery_receipt_cbor(
    receipt: &AgentProvisioningDeliveryReceipt,
) -> Result<Vec<u8>, AgentProvisioningOwnerError> {
    let state = match receipt.state.as_str() {
        "pending" => 1,
        "dispatched" => 2,
        "installed" => 3,
        "rejected" => 4,
        "revoked" => 5,
        _ => return Err(AgentProvisioningOwnerError::TemporarilyUnavailable),
    };
    let result = receipt
        .result_digest
        .map_or(CanonicalValue::Null, |digest| {
            CanonicalValue::Bytes(digest.as_bytes().to_vec())
        });
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(receipt.delivery_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(receipt.approval_id.to_string()),
        ),
        (CanonicalValue::Unsigned(4), CanonicalValue::Unsigned(state)),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Bytes(receipt.capsule_digest.as_bytes().to_vec()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Unsigned(receipt.provisioning_revision.get()),
        ),
        (CanonicalValue::Unsigned(7), result),
        (
            CanonicalValue::Unsigned(8),
            receipt
                .resolved_at
                .unwrap_or(receipt.created_at)
                .to_canonical_value(),
        ),
    ]))
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)
}

fn map_application_error(error: &AgentIdentityProvisioningError) -> AgentProvisioningOwnerError {
    match error {
        AgentIdentityProvisioningError::InvalidRequest
        | AgentIdentityProvisioningError::InvalidProof
        | AgentIdentityProvisioningError::InvalidIdentity
        | AgentIdentityProvisioningError::Expired => AgentProvisioningOwnerError::InvalidRequest,
        AgentIdentityProvisioningError::Forbidden => AgentProvisioningOwnerError::AccessDenied,
        AgentIdentityProvisioningError::NotFound => AgentProvisioningOwnerError::NotFound,
        AgentIdentityProvisioningError::Conflict
        | AgentIdentityProvisioningError::IdentityPersistence(
            dtx_identity_persistence::IdentityPersistenceError::IdempotencyConflict
            | dtx_identity_persistence::IdentityPersistenceError::HeadConflict { .. }
            | dtx_identity_persistence::IdentityPersistenceError::GenesisConflict,
        ) => AgentProvisioningOwnerError::Conflict,
        AgentIdentityProvisioningError::IdentityPersistence(
            dtx_identity_persistence::IdentityPersistenceError::DeviceAuthenticationRejected,
        ) => AgentProvisioningOwnerError::AuthenticationRejected,
        AgentIdentityProvisioningError::CorruptData
        | AgentIdentityProvisioningError::Database(_)
        | AgentIdentityProvisioningError::Storage(_)
        | AgentIdentityProvisioningError::AgentPersistence(_)
        | AgentIdentityProvisioningError::IdentityPersistence(_) => {
            AgentProvisioningOwnerError::TemporarilyUnavailable
        }
    }
}

const fn map_connector_projection_error(
    error: ConnectorProjectionError,
) -> AgentProvisioningOwnerError {
    match error {
        ConnectorProjectionError::AuthenticationRejected => {
            AgentProvisioningOwnerError::AuthenticationRejected
        }
        ConnectorProjectionError::Unavailable => {
            AgentProvisioningOwnerError::TemporarilyUnavailable
        }
    }
}

const fn map_connector_control_error(
    error: ConnectorControlApplicationError,
) -> AgentProvisioningOwnerError {
    match error {
        ConnectorControlApplicationError::InvalidRequest => {
            AgentProvisioningOwnerError::InvalidRequest
        }
        ConnectorControlApplicationError::AuthenticationFailed => {
            AgentProvisioningOwnerError::AuthenticationRejected
        }
        ConnectorControlApplicationError::PermissionDenied => {
            AgentProvisioningOwnerError::AccessDenied
        }
        ConnectorControlApplicationError::NotFound => AgentProvisioningOwnerError::NotFound,
        ConnectorControlApplicationError::Conflict
        | ConnectorControlApplicationError::StaleFence
        | ConnectorControlApplicationError::StaleLease => AgentProvisioningOwnerError::Conflict,
        ConnectorControlApplicationError::ResourceExhausted
        | ConnectorControlApplicationError::Unavailable
        | ConnectorControlApplicationError::Internal => {
            AgentProvisioningOwnerError::TemporarilyUnavailable
        }
    }
}

#[derive(Serialize)]
struct ConnectorLifecycleReceiptV1 {
    schema_version: u8,
    action: &'static str,
    connector_id: String,
    operation_id: String,
    generation: u64,
    spec_revision: u64,
    command_sequence: u64,
    command_payload_digest: String,
    encoded_command_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rotation_deadline_ms: Option<i64>,
}

fn connector_lifecycle_receipt_json(
    action: ConnectorLifecycleAction,
    connector_id: ConnectorId,
    write: &ConnectorLifecycleCommandWrite,
) -> Result<Vec<u8>, AgentProvisioningOwnerError> {
    let command = write.command();
    let (action, rotation_deadline_ms) = match (action, command.payload()) {
        (ConnectorLifecycleAction::Drain, ServerCommandPayload::CloseStream(close))
            if close.reason() == dtx_agent_control::CloseStreamReason::Drained =>
        {
            ("drain", None)
        }
        (ConnectorLifecycleAction::Reconnect, ServerCommandPayload::CloseStream(close))
            if close.reason() == dtx_agent_control::CloseStreamReason::Reconnect =>
        {
            ("restart", None)
        }
        (
            ConnectorLifecycleAction::RotateCredential,
            ServerCommandPayload::RotateCredential(rotation),
        ) => ("rotate_credential", Some(rotation.deadline_millis())),
        _ => return Err(AgentProvisioningOwnerError::TemporarilyUnavailable),
    };
    serde_json::to_vec(&ConnectorLifecycleReceiptV1 {
        schema_version: 1,
        action,
        connector_id: connector_id.to_string(),
        operation_id: command.operation_id().to_string(),
        generation: command.generation(),
        spec_revision: command.spec_revision().get(),
        command_sequence: command.sequence(),
        command_payload_digest: Base64UrlUnpadded::encode_string(
            &command.payload_digest().as_bytes(),
        ),
        encoded_command_digest: Base64UrlUnpadded::encode_string(
            &command.encoded_command_digest().as_bytes(),
        ),
        rotation_deadline_ms,
    })
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)
}

/// Builds the complete V23 Owner API router.
pub fn agent_provisioning_owner_router(backend: Arc<dyn AgentProvisioningOwnerBackend>) -> Router {
    Router::new()
        .route("/v1/connectors", get(get_connectors))
        .route(
            "/v1/connectors/{connector_id}/drain",
            post(post_connector_drain),
        )
        .route(
            "/v1/connectors/{connector_id}/restart",
            post(post_connector_restart),
        )
        .route(
            "/v1/connectors/{connector_id}/rotate-credential",
            post(post_connector_credential_rotation),
        )
        .route(
            "/v1/agent-installations/{installation_id}/identity-approvals",
            post(post_approval),
        )
        .route(
            "/v1/agent-installations/{installation_id}/identity-approvals/{approval_id}",
            get(get_approval),
        )
        .route(
            "/v1/agent-installations/{installation_id}/provisioning-target",
            get(get_target),
        )
        .route(
            "/v1/agent-installations/{installation_id}/provisioning-deliveries",
            post(post_delivery),
        )
        .route(
            "/v1/agent-installations/{installation_id}/provisioning-deliveries/{delivery_id}",
            get(get_delivery),
        )
        .route(
            "/v1/agent-installations/{installation_id}/revocations",
            post(post_revocation),
        )
        .with_state(backend)
}

async fn get_connectors(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let query = parse_connector_projection_query(uri.query())?;
        let credential = parse_device_session(&headers)?;
        backend.list_connectors(credential, query, now()?).await
    }
    .await;
    owner_response(result)
}

async fn post_connector_drain(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path(connector_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    post_connector_lifecycle(
        backend,
        connector_id,
        headers,
        body,
        ConnectorLifecycleAction::Drain,
    )
    .await
}

async fn post_connector_restart(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path(connector_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    post_connector_lifecycle(
        backend,
        connector_id,
        headers,
        body,
        ConnectorLifecycleAction::Reconnect,
    )
    .await
}

async fn post_connector_credential_rotation(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path(connector_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    post_connector_lifecycle(
        backend,
        connector_id,
        headers,
        body,
        ConnectorLifecycleAction::RotateCredential,
    )
    .await
}

async fn post_connector_lifecycle(
    backend: Arc<dyn AgentProvisioningOwnerBackend>,
    connector_id: String,
    headers: HeaderMap,
    body: Bytes,
    action: ConnectorLifecycleAction,
) -> Response {
    let result = async {
        if !body.is_empty() {
            return Err(AgentProvisioningOwnerError::InvalidRequest);
        }
        let credential = parse_device_session(&headers)?;
        let operation_id = parse_connector_lifecycle_operation(&headers)?;
        let (generation, spec_revision) = parse_connector_lifecycle_fence(&headers)?;
        let connector_id = connector_id
            .parse::<ConnectorId>()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        backend
            .lifecycle(
                credential,
                ConnectorLifecycleOwnerCommand {
                    connector_id,
                    operation_id,
                    generation,
                    spec_revision,
                    action,
                },
            )
            .await
    }
    .await;
    owner_response(result)
}

fn parse_connector_projection_query(
    query: Option<&str>,
) -> Result<ConnectorProjectionQueryV1, AgentProvisioningOwnerError> {
    let mut after = None;
    let mut limit = DEFAULT_CONNECTOR_PROJECTION_LIMIT;
    let mut limit_seen = false;
    if let Some(query) = query {
        if query.is_empty() {
            return Err(AgentProvisioningOwnerError::InvalidRequest);
        }
        for pair in query.split('&') {
            let (name, value) = pair
                .split_once('=')
                .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
            match name {
                "after" if after.is_none() => {
                    after = Some(
                        value
                            .parse::<ConnectorId>()
                            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
                    );
                }
                "limit" if !limit_seen => {
                    limit_seen = true;
                    limit = value
                        .parse::<u16>()
                        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
                    if limit == 0 || limit > MAX_CONNECTOR_PROJECTION_LIMIT {
                        return Err(AgentProvisioningOwnerError::InvalidRequest);
                    }
                }
                _ => return Err(AgentProvisioningOwnerError::InvalidRequest),
            }
        }
    }
    Ok(ConnectorProjectionQueryV1 { after, limit })
}

async fn post_approval(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path(installation_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = async {
        require_content_type(
            &headers,
            "application/vnd.dirextalk.agent-identity-approval.v1+cbor",
        )?;
        bounded(&body, MAX_SMALL_BODY)?;
        let credential = parse_device_session(&headers)?;
        let idempotency = parse_idempotency(&headers)?;
        let installation_id = installation_id
            .parse::<InstallationId>()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        let command = parse_approval(&body)?;
        if command.installation_id != installation_id {
            return Err(AgentProvisioningOwnerError::InvalidRequest);
        }
        backend
            .approve(credential, idempotency, command, body.to_vec(), now()?)
            .await
    }
    .await;
    owner_response(result)
}

async fn get_approval(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path((installation_id, approval_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let credential = parse_device_session(&headers)?;
        let installation_id = installation_id
            .parse()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        let approval_id = approval_id
            .parse()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        backend
            .get_approval(credential, installation_id, approval_id, now()?)
            .await
    }
    .await;
    owner_response(result)
}

struct TargetQuery {
    approval_id: ApprovalId,
    binding_id: BindingId,
}

async fn get_target(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path(installation_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let query = parse_target_query(uri.query())?;
        let credential = parse_device_session(&headers)?;
        let installation_id = installation_id
            .parse()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        backend
            .get_target(
                credential,
                installation_id,
                query.approval_id,
                query.binding_id,
                now()?,
            )
            .await
    }
    .await;
    owner_response(result)
}

fn parse_target_query(query: Option<&str>) -> Result<TargetQuery, AgentProvisioningOwnerError> {
    let query = query.ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    let mut approval_id = None;
    let mut binding_id = None;
    for pair in query.split('&') {
        let (name, value) = pair
            .split_once('=')
            .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
        match name {
            "approval_id" if approval_id.is_none() => {
                approval_id = Some(
                    value
                        .parse()
                        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
                );
            }
            "binding_id" if binding_id.is_none() => {
                binding_id = Some(
                    value
                        .parse()
                        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
                );
            }
            _ => return Err(AgentProvisioningOwnerError::InvalidRequest),
        }
    }
    Ok(TargetQuery {
        approval_id: approval_id.ok_or(AgentProvisioningOwnerError::InvalidRequest)?,
        binding_id: binding_id.ok_or(AgentProvisioningOwnerError::InvalidRequest)?,
    })
}

async fn post_delivery(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path(installation_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = async {
        require_content_type(
            &headers,
            "application/vnd.dirextalk.agent-provisioning-delivery.v1+cbor",
        )?;
        bounded(&body, MAX_DELIVERY_BODY)?;
        let credential = parse_device_session(&headers)?;
        let idempotency = parse_idempotency(&headers)?;
        let installation_id = installation_id
            .parse::<InstallationId>()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        let command = parse_delivery(&body)?;
        if command.installation_id != installation_id {
            return Err(AgentProvisioningOwnerError::InvalidRequest);
        }
        backend
            .deliver(credential, idempotency, command, body.to_vec(), now()?)
            .await
    }
    .await;
    owner_response(result)
}

async fn get_delivery(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path((installation_id, delivery_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let credential = parse_device_session(&headers)?;
        let installation_id = installation_id
            .parse()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        let delivery_id = delivery_id
            .parse()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        backend
            .get_delivery(credential, installation_id, delivery_id, now()?)
            .await
    }
    .await;
    owner_response(result)
}

async fn post_revocation(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path(installation_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = async {
        require_content_type(
            &headers,
            "application/vnd.dirextalk.agent-provisioning-revocation.v1+cbor",
        )?;
        bounded(&body, MAX_SMALL_BODY)?;
        let credential = parse_device_session(&headers)?;
        let idempotency = parse_idempotency(&headers)?;
        let installation_id = installation_id
            .parse::<InstallationId>()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        let command = parse_revocation(&body)?;
        if command.installation_id != installation_id {
            return Err(AgentProvisioningOwnerError::InvalidRequest);
        }
        backend
            .revoke(credential, idempotency, command, body.to_vec(), now()?)
            .await
    }
    .await;
    owner_response(result)
}

fn parse_approval(
    body: &[u8],
) -> Result<AgentIdentityApprovalCommand, AgentProvisioningOwnerError> {
    let request = exact_map(
        decode_deterministic_cbor(body).map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
        3,
    )?;
    let binding = map_value(&request, 1)?.clone();
    let fields = exact_map(binding.clone(), 15)?;
    expect_version(&fields)?;
    let supplied = digest(map_value(&request, 2)?)?;
    if supplied != binding_hash(AGENT_IDENTITY_APPROVAL_BINDING_DOMAIN, &binding)? {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    Ok(AgentIdentityApprovalCommand {
        approval_id: text_id(&fields, 2)?,
        tenant_id: text_id(&fields, 3)?,
        installation_id: text_id(&fields, 4)?,
        binding_id: text_id(&fields, 5)?,
        agent_device_id: text_id(&fields, 6)?,
        agent_identity_id: text_id(&fields, 7)?,
        identity_device_id: text_id(&fields, 8)?,
        identity_head_sequence: positive_safe_uint(&fields, 9)?,
        identity_head_hash: digest(map_value(&fields, 10)?)?,
        credential_fingerprint: DeviceCredentialFingerprint::from_bytes(bytes_array(map_value(
            &fields, 11,
        )?)?),
        expected_revision: revision(&fields, 12)?,
        owner_identity_id: text_id(&fields, 13)?,
        owner_device_id: text_id(&fields, 14)?,
        expires_at: utc(&fields, 15)?,
        owner_signature: Ed25519Signature::from_bytes(bytes_array(map_value(&request, 3)?)?),
    })
}

fn parse_delivery(body: &[u8]) -> Result<DeliveryOwnerCommand, AgentProvisioningOwnerError> {
    let request = exact_map(
        decode_deterministic_cbor(body).map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
        4,
    )?;
    let binding = map_value(&request, 1)?.clone();
    let fields = exact_map(binding.clone(), 17)?;
    expect_version(&fields)?;
    let capsule = bytes(map_value(&request, 2)?)?;
    if capsule.is_empty() || capsule.len() > 196_608 {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let supplied = digest(map_value(&request, 3)?)?;
    if supplied != binding_hash(DELIVERY_BINDING_DOMAIN, &binding)? {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let capsule_digest = digest(map_value(&fields, 13)?)?;
    if capsule_digest != Sha256Digest::hash_domain(CAPSULE_DIGEST_DOMAIN, capsule) {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    Ok(DeliveryOwnerCommand {
        delivery_id: text_id(&fields, 2)?,
        approval_id: text_id(&fields, 3)?,
        tenant_id: text_id(&fields, 4)?,
        installation_id: text_id(&fields, 5)?,
        binding_id: text_id(&fields, 6)?,
        agent_device_id: text_id(&fields, 7)?,
        agent_identity_id: text_id(&fields, 8)?,
        identity_device_id: text_id(&fields, 9)?,
        provisioning_revision: revision(&fields, 10)?,
        recipient_key_id: text_id(&fields, 11)?,
        recipient_descriptor_digest: digest(map_value(&fields, 12)?)?,
        capsule_digest,
        owner_identity_id: text_id(&fields, 14)?,
        owner_device_id: text_id(&fields, 15)?,
        created_at: utc(&fields, 16)?,
        expires_at: utc(&fields, 17)?,
        sealed_capsule: capsule.to_vec(),
        binding_digest: supplied,
        owner_signature: Ed25519Signature::from_bytes(bytes_array(map_value(&request, 4)?)?),
    })
}

fn parse_revocation(body: &[u8]) -> Result<RevocationOwnerCommand, AgentProvisioningOwnerError> {
    let value =
        decode_deterministic_cbor(body).map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
    let fields = exact_map(value.clone(), 11)?;
    expect_version(&fields)?;
    let unsigned = CanonicalValue::Map(fields[..9].to_vec());
    let supplied = digest(map_value(&fields, 10)?)?;
    if supplied != binding_hash(REVOCATION_BINDING_DOMAIN, &unsigned)? {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let scope = unsigned_int(&fields, 8)?;
    if !(1..=2).contains(&scope) {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    Ok(RevocationOwnerCommand {
        revocation_id: text_id(&fields, 2)?,
        tenant_id: text_id(&fields, 3)?,
        installation_id: text_id(&fields, 4)?,
        expected_revision: revision(&fields, 5)?,
        owner_identity_id: text_id(&fields, 6)?,
        owner_device_id: text_id(&fields, 7)?,
        scope: u8::try_from(scope).map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
        expires_at: utc(&fields, 9)?,
        binding_digest: supplied,
        owner_signature: Ed25519Signature::from_bytes(bytes_array(map_value(&fields, 11)?)?),
    })
}

type Fields = Vec<(CanonicalValue, CanonicalValue)>;
fn exact_map(value: CanonicalValue, count: usize) -> Result<Fields, AgentProvisioningOwnerError> {
    let CanonicalValue::Map(fields) = value else {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    };
    if fields.len() != count
        || fields
            .iter()
            .enumerate()
            .any(|(i, (key, _))| *key != CanonicalValue::Unsigned((i + 1) as u64))
    {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    Ok(fields)
}
fn map_value(fields: &Fields, key: u64) -> Result<&CanonicalValue, AgentProvisioningOwnerError> {
    fields
        .get(usize::try_from(key - 1).map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?)
        .map(|(_, value)| value)
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)
}
fn expect_version(fields: &Fields) -> Result<(), AgentProvisioningOwnerError> {
    if unsigned_int(fields, 1)? == 1 {
        Ok(())
    } else {
        Err(AgentProvisioningOwnerError::InvalidRequest)
    }
}
fn unsigned_int(fields: &Fields, key: u64) -> Result<u64, AgentProvisioningOwnerError> {
    match map_value(fields, key)? {
        CanonicalValue::Unsigned(value) => Ok(*value),
        _ => Err(AgentProvisioningOwnerError::InvalidRequest),
    }
}
fn text_id<T: std::str::FromStr>(
    fields: &Fields,
    key: u64,
) -> Result<T, AgentProvisioningOwnerError> {
    match map_value(fields, key)? {
        CanonicalValue::Text(value) => value
            .parse()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest),
        _ => Err(AgentProvisioningOwnerError::InvalidRequest),
    }
}
fn bytes(value: &CanonicalValue) -> Result<&[u8], AgentProvisioningOwnerError> {
    match value {
        CanonicalValue::Bytes(value) => Ok(value),
        _ => Err(AgentProvisioningOwnerError::InvalidRequest),
    }
}
fn bytes_array<const N: usize>(
    value: &CanonicalValue,
) -> Result<[u8; N], AgentProvisioningOwnerError> {
    bytes(value)?
        .try_into()
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)
}
fn digest(value: &CanonicalValue) -> Result<Sha256Digest, AgentProvisioningOwnerError> {
    Ok(Sha256Digest::from_bytes(bytes_array(value)?))
}
fn safe_uint(fields: &Fields, key: u64) -> Result<SafeUint, AgentProvisioningOwnerError> {
    SafeUint::new(unsigned_int(fields, key)?)
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)
}
fn positive_safe_uint(fields: &Fields, key: u64) -> Result<SafeUint, AgentProvisioningOwnerError> {
    let value = safe_uint(fields, key)?;
    if value.get() == 0 {
        Err(AgentProvisioningOwnerError::InvalidRequest)
    } else {
        Ok(value)
    }
}
fn revision(fields: &Fields, key: u64) -> Result<Revision, AgentProvisioningOwnerError> {
    Revision::new(unsigned_int(fields, key)?)
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)
}
fn utc(fields: &Fields, key: u64) -> Result<UtcMillis, AgentProvisioningOwnerError> {
    let value = match map_value(fields, key)? {
        CanonicalValue::Unsigned(v) => i64::try_from(*v).ok(),
        CanonicalValue::Negative(v) => Some(*v),
        _ => None,
    }
    .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    UtcMillis::new(value).map_err(|_| AgentProvisioningOwnerError::InvalidRequest)
}
fn binding_hash(
    domain: &[u8],
    value: &CanonicalValue,
) -> Result<Sha256Digest, AgentProvisioningOwnerError> {
    let bytes = encode_deterministic_cbor(value)
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
    Ok(Sha256Digest::hash_domain(domain, &bytes))
}

fn parse_device_session(
    headers: &HeaderMap,
) -> Result<DeviceSessionCredential, AgentProvisioningOwnerError> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values
        .next()
        .ok_or(AgentProvisioningOwnerError::AuthenticationRejected)?;
    if values.next().is_some() {
        return Err(AgentProvisioningOwnerError::AuthenticationRejected);
    }
    let value = value
        .to_str()
        .map_err(|_| AgentProvisioningOwnerError::AuthenticationRejected)?;
    let value = value
        .strip_prefix(&format!("{DEVICE_SESSION_SCHEME} "))
        .ok_or(AgentProvisioningOwnerError::AuthenticationRejected)?;
    let (session, secret) = value
        .split_once('.')
        .ok_or(AgentProvisioningOwnerError::AuthenticationRejected)?;
    if secret.contains('.') || secret.len() != 43 || !secret.bytes().all(is_base64url) {
        return Err(AgentProvisioningOwnerError::AuthenticationRejected);
    }
    let session_id = session
        .parse::<DeviceSessionId>()
        .map_err(|_| AgentProvisioningOwnerError::AuthenticationRejected)?;
    let mut output = [0_u8; 32];
    let decoded = Base64UrlUnpadded::decode(secret, &mut output)
        .map_err(|_| AgentProvisioningOwnerError::AuthenticationRejected)?;
    if decoded.len() != 32 {
        return Err(AgentProvisioningOwnerError::AuthenticationRejected);
    }
    DeviceSessionCredential::new(session_id, output)
        .map_err(|_| AgentProvisioningOwnerError::AuthenticationRejected)
}
fn parse_idempotency(headers: &HeaderMap) -> Result<Sha256Digest, AgentProvisioningOwnerError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let value = values
        .next()
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    if values.next().is_some() {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let bytes = value.as_bytes();
    if !(16..=128).contains(&bytes.len()) || !bytes.iter().copied().all(is_base64url) {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    Ok(Sha256Digest::hash_domain(IDEMPOTENCY_DOMAIN, bytes))
}

fn parse_connector_lifecycle_operation(
    headers: &HeaderMap,
) -> Result<RequestId, AgentProvisioningOwnerError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let value = values
        .next()
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    if values.next().is_some() {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    value
        .to_str()
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?
        .parse()
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)
}

fn parse_connector_lifecycle_fence(
    headers: &HeaderMap,
) -> Result<(u64, Revision), AgentProvisioningOwnerError> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    if values.next().is_some() {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let value = value
        .strip_prefix("\"g")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    let (generation, spec_revision) = value
        .split_once("-r")
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    if generation.is_empty()
        || spec_revision.is_empty()
        || spec_revision.contains("-r")
        || !generation.bytes().all(|value| value.is_ascii_digit())
        || !spec_revision.bytes().all(|value| value.is_ascii_digit())
    {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let generation = generation
        .parse::<u64>()
        .ok()
        .filter(|generation| Revision::new(*generation).is_ok())
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    let spec_revision = spec_revision
        .parse::<u64>()
        .ok()
        .and_then(|revision| Revision::new(revision).ok())
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    Ok((generation, spec_revision))
}

const fn is_base64url(value: u8) -> bool {
    value.is_ascii_alphanumeric() || value == b'_' || value == b'-'
}
fn require_content_type(
    headers: &HeaderMap,
    expected: &str,
) -> Result<(), AgentProvisioningOwnerError> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let value = values
        .next()
        .and_then(|v| v.to_str().ok())
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    if values.next().is_some() || value != expected {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    Ok(())
}
fn bounded(body: &[u8], max: usize) -> Result<(), AgentProvisioningOwnerError> {
    if body.is_empty() || body.len() > max {
        Err(AgentProvisioningOwnerError::InvalidRequest)
    } else {
        Ok(())
    }
}
fn now() -> Result<UtcMillis, AgentProvisioningOwnerError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?
        .as_millis();
    UtcMillis::new(
        i64::try_from(millis).map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?,
    )
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)
}

fn owner_response(result: Result<CborOwnerReply, AgentProvisioningOwnerError>) -> Response {
    match result {
        Ok(reply) => {
            let mut response = (reply.status, reply.exact_cbor).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(reply.content_type),
            );
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(error) => error_response(error),
    }
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}
#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    retryable: bool,
}
fn error_response(error: AgentProvisioningOwnerError) -> Response {
    let (status, code, retryable) = match error {
        AgentProvisioningOwnerError::InvalidRequest => {
            (StatusCode::UNPROCESSABLE_ENTITY, "request_invalid", false)
        }
        AgentProvisioningOwnerError::AuthenticationRejected => (
            StatusCode::UNAUTHORIZED,
            "device_authentication_failed",
            false,
        ),
        AgentProvisioningOwnerError::AccessDenied => {
            (StatusCode::FORBIDDEN, "access_denied", false)
        }
        AgentProvisioningOwnerError::NotFound => {
            (StatusCode::NOT_FOUND, "resource_unavailable", false)
        }
        AgentProvisioningOwnerError::Conflict => (StatusCode::CONFLICT, "action_conflict", false),
        AgentProvisioningOwnerError::TemporarilyUnavailable => {
            (StatusCode::SERVICE_UNAVAILABLE, "service_unavailable", true)
        }
    };
    let body = serde_json::to_vec(&ErrorEnvelope {
        error: ErrorBody { code, retryable },
    })
    .expect("fixed error envelope serializes");
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, header};
    use base64ct::{Base64UrlUnpadded, Encoding};
    use dtx_agent_control::Sha256Digest as ControlSha256Digest;
    use dtx_domain::{RequestId, Revision};
    use dtx_wire::{CanonicalValue, decode_deterministic_cbor, encode_deterministic_cbor};
    use dtx_wire::{Sha256Digest, UtcMillis};
    use serde_json::Value;

    use super::{
        AgentProvisioningDeliveryReceipt, AgentProvisioningOwnerError, REVOCATION_BINDING_DOMAIN,
        approval_status, delivery_receipt_cbor, delivery_status, parse_approval,
        parse_connector_projection_query, parse_delivery, parse_device_session, parse_idempotency,
        parse_revocation,
    };

    const VECTORS: &str = include_str!(
        "../../../protocol/test-vectors/agent-provisioning/v1/agent-provisioning-v1.json"
    );

    #[test]
    fn connector_projection_query_is_keyset_bounded_and_closed() {
        let connector = dtx_domain::ConnectorId::new();
        let parsed =
            parse_connector_projection_query(Some(&format!("after={connector}&limit=64"))).unwrap();
        assert_eq!(parsed.after, Some(connector));
        assert_eq!(parsed.limit, 64);
        assert_eq!(
            parse_connector_projection_query(None).unwrap().limit,
            super::DEFAULT_CONNECTOR_PROJECTION_LIMIT
        );
        for rejected in [
            "",
            "limit=0",
            "limit=65",
            "limit=1&limit=2",
            "after=not-a-connector",
            "cursor=anything",
        ] {
            assert_eq!(
                parse_connector_projection_query(Some(rejected)),
                Err(AgentProvisioningOwnerError::InvalidRequest),
                "query must be rejected: {rejected}"
            );
        }
    }

    #[test]
    fn connector_lifecycle_requires_a_uuid_v7_operation_and_exact_fence() {
        let operation_id = RequestId::new();
        let mut headers = HeaderMap::new();
        headers.insert(
            "idempotency-key",
            HeaderValue::from_str(&operation_id.to_string()).unwrap(),
        );
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"g1-r1\""));
        assert_eq!(
            super::parse_connector_lifecycle_operation(&headers).unwrap(),
            operation_id
        );
        assert_eq!(
            super::parse_connector_lifecycle_fence(&headers).unwrap(),
            (1, Revision::INITIAL)
        );

        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"g0-r1\""));
        assert_eq!(
            super::parse_connector_lifecycle_fence(&headers),
            Err(AgentProvisioningOwnerError::InvalidRequest)
        );
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"g+1-r1\""));
        assert_eq!(
            super::parse_connector_lifecycle_fence(&headers),
            Err(AgentProvisioningOwnerError::InvalidRequest)
        );
        headers.insert(
            "idempotency-key",
            HeaderValue::from_static("retry-key-not-a-v7-id"),
        );
        assert_eq!(
            super::parse_connector_lifecycle_operation(&headers),
            Err(AgentProvisioningOwnerError::InvalidRequest)
        );
    }

    #[test]
    fn frozen_approval_and_delivery_vectors_parse_exactly() {
        let vectors: Value = serde_json::from_str(VECTORS).unwrap();
        let approval_binding = decoded_value(
            vectors["approval_golden"]["binding_canonical_cbor_hex"]
                .as_str()
                .unwrap(),
        );
        let approval = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), approval_binding),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Bytes(hex(vectors["approval_golden"]["binding_digest_hex"]
                    .as_str()
                    .unwrap())),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Bytes(hex(vectors["approval_golden"]["owner_signature_hex"]
                    .as_str()
                    .unwrap())),
            ),
        ]))
        .unwrap();
        let parsed = parse_approval(&approval).unwrap();
        assert_eq!(
            parsed.approval_id.to_string(),
            "0190f2a5-7b1c-7abc-8def-012345678900"
        );

        let delivery_binding = decoded_value(
            vectors["delivery_golden"]["binding_canonical_cbor_hex"]
                .as_str()
                .unwrap(),
        );
        let capsule = hex(vectors["delivery_golden"]["capsule_hex"].as_str().unwrap());
        let delivery = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), delivery_binding.clone()),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Bytes(capsule.clone()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Bytes(hex(vectors["delivery_golden"]["binding_digest_hex"]
                    .as_str()
                    .unwrap())),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Bytes(hex(vectors["delivery_golden"]["owner_signature_hex"]
                    .as_str()
                    .unwrap())),
            ),
        ]))
        .unwrap();
        assert_eq!(parse_delivery(&delivery).unwrap().sealed_capsule, capsule);

        let mut changed_capsule = capsule;
        changed_capsule[0] ^= 1;
        let changed = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), delivery_binding),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Bytes(changed_capsule),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Bytes(hex(vectors["delivery_golden"]["binding_digest_hex"]
                    .as_str()
                    .unwrap())),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Bytes(hex(vectors["delivery_golden"]["owner_signature_hex"]
                    .as_str()
                    .unwrap())),
            ),
        ]))
        .unwrap();
        assert_eq!(
            parse_delivery(&changed),
            Err(AgentProvisioningOwnerError::InvalidRequest)
        );
    }

    #[test]
    fn capability_and_idempotency_headers_are_exact_and_duplicate_free() {
        let mut headers = HeaderMap::new();
        let secret = Base64UrlUnpadded::encode_string(&[7_u8; 32]);
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!(
                "DTX-Device-Session 0190f2a5-7b1c-7abc-8def-012345678906.{secret}"
            ))
            .unwrap(),
        );
        headers.insert(
            "idempotency-key",
            HeaderValue::from_static("owner_retry_key_1"),
        );
        assert!(parse_device_session(&headers).is_ok());
        assert!(parse_idempotency(&headers).is_ok());
        headers.append(
            "idempotency-key",
            HeaderValue::from_static("owner_retry_key_1"),
        );
        assert!(parse_idempotency(&headers).is_err());
    }

    #[test]
    fn response_loss_replays_use_success_without_recreation_status() {
        assert_eq!(approval_status(false), axum::http::StatusCode::CREATED);
        assert_eq!(approval_status(true), axum::http::StatusCode::OK);
        assert_eq!(delivery_status(false), axum::http::StatusCode::ACCEPTED);
        assert_eq!(delivery_status(true), axum::http::StatusCode::OK);
    }

    #[test]
    fn delivery_receipt_is_byte_exact_to_the_frozen_cddl_field_semantics() {
        let receipt = AgentProvisioningDeliveryReceipt {
            replayed: false,
            delivery_id: "0190f2a5-7b1c-7abc-8def-01234567890a".parse().unwrap(),
            approval_id: "0190f2a5-7b1c-7abc-8def-012345678900".parse().unwrap(),
            installation_id: "0190f2a5-7b1c-7abc-8def-012345678902".parse().unwrap(),
            provisioning_revision: Revision::INITIAL,
            connector_id: "0190f2a5-7b1c-7abc-8def-012345678908".parse().unwrap(),
            command_sequence: 99,
            command_payload_digest: ControlSha256Digest::from_bytes([0x44; 32]),
            encoded_command_digest: ControlSha256Digest::from_bytes([0x55; 32]),
            capsule_digest: Sha256Digest::from_bytes(
                hex("975ff4bbe1df2f1811fb80eca9437d06a616322d54be2e0b518d28eddd1fbd5a")
                    .try_into()
                    .unwrap(),
            ),
            state: "pending".into(),
            result_digest: None,
            rejection_code: None,
            created_at: UtcMillis::new(1_756_700_000_000).unwrap(),
            resolved_at: None,
        };
        let exact = delivery_receipt_cbor(&receipt).unwrap();
        assert_eq!(
            exact,
            hex(concat!(
                "a8010102782430313930663261352d376231632d376162632d386465662d303132333435363738393061",
                "03782430313930663261352d376231632d376162632d386465662d303132333435363738393030",
                "0401055820975ff4bbe1df2f1811fb80eca9437d06a616322d54be2e0b518d28eddd1fbd5a",
                "060107f6081b00000199037abf00"
            ))
        );
    }

    #[test]
    fn revocation_rejects_a_changed_binding_digest() {
        let mut fields = vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-01234567890a".into()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-012345678901".into()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-012345678902".into()),
            ),
            (CanonicalValue::Unsigned(5), CanonicalValue::Unsigned(8)),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Text(
                    "dtxi155pujebuvamvkmouxx6okeiijjuzjxxw4ktjahrjy6z27frlobiq".into(),
                ),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-012345678906".into()),
            ),
            (CanonicalValue::Unsigned(8), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(9),
                CanonicalValue::Unsigned(1_756_700_000_000),
            ),
        ];
        let binding = CanonicalValue::Map(fields.clone());
        let binding_bytes = encode_deterministic_cbor(&binding).unwrap();
        let digest = dtx_wire::Sha256Digest::hash_domain(REVOCATION_BINDING_DOMAIN, &binding_bytes);
        fields.push((
            CanonicalValue::Unsigned(10),
            CanonicalValue::Bytes(digest.as_bytes().to_vec()),
        ));
        fields.push((
            CanonicalValue::Unsigned(11),
            CanonicalValue::Bytes(vec![9; 64]),
        ));
        let exact = encode_deterministic_cbor(&CanonicalValue::Map(fields.clone())).unwrap();
        assert!(parse_revocation(&exact).is_ok());
        fields[9].1 = CanonicalValue::Bytes(vec![0; 32]);
        let changed = encode_deterministic_cbor(&CanonicalValue::Map(fields)).unwrap();
        assert_eq!(
            parse_revocation(&changed),
            Err(AgentProvisioningOwnerError::InvalidRequest)
        );
    }

    fn decoded_value(encoded_hex: &str) -> CanonicalValue {
        decode_deterministic_cbor(&hex(encoded_hex)).unwrap()
    }

    fn hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }
}
