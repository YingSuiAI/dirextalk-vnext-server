//! Owner-authenticated HTTP boundary for Agent identity approval and opaque provisioning.

use std::{
    collections::BTreeMap,
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
    routing::{get, post, put},
};
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_agent_control::ServerCommandPayload;
use dtx_agent_persistence::{
    AgentDeviceRepository, AgentInstallationRepository, AgentPersistenceError,
    BindingSetRepository, ConversationGrantRepository,
};
use dtx_agent_registry::{
    AgentConversationPermission, AgentConversationPermissions, ConversationGrant,
    ConversationGrantCommand, ConversationGrantUpdate, DeviceCredentialFingerprint,
    PrivacyPolicyDigest, TriggerPolicy,
};
use dtx_agent_router::DispatchMode;
use dtx_connect_registry::{BindingError, BindingState, TenantRef};
use dtx_domain::{
    AgentDeviceId, AgentRouteBootstrapId, AgentRouteDeliveryId, ApprovalId, BindingId, ConnectorId,
    ConversationId, DeviceId, DeviceSessionId, EventId, GrantId, IdentityId, InstallationId,
    ProvisioningDeliveryId, ProvisioningRecipientKeyId, RequestId, Revision, RouteHealthKeyId,
    RunId, TenantId,
};
use dtx_identity_persistence::{DeviceSessionCredential, DeviceSessionRepository};
use dtx_storage::PgStore;
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, UtcMillis,
    decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use crate::connector_projection::{
    CONNECTOR_PROJECTION_MEDIA_TYPE_V1, CONNECTOR_PROJECTION_MEDIA_TYPE_V2,
    CONNECTOR_PROJECTION_MEDIA_TYPE_V3, CONNECTOR_PROJECTION_MEDIA_TYPE_V4,
    ConnectorProjectionError, ConnectorProjectionPageV2, ConnectorProjectionQueryV1,
    DEFAULT_CONNECTOR_PROJECTION_LIMIT, MAX_CONNECTOR_PROJECTION_LIMIT,
    list_connector_projection_v1, list_connector_projection_v3, list_connector_projection_v4,
};
use crate::mcp::mcp_router;
use crate::{AGENT_IDENTITY_APPROVAL_BINDING_DOMAIN, AgentIdentityApprovalCommand};
use crate::{
    AgentIdentityProvisioningError, AgentProvisioningDeliveryCommand,
    AgentProvisioningDeliveryReceipt, AgentProvisioningRevocationCommand,
    AgentProvisioningRevocationReceipt, AgentRouteBootstrapBeginCommand,
    AgentRouteBootstrapDeliveryCommand, AgentRouteBootstrapError, ConnectorCommandFence,
    ConnectorControlApplicationError, ConnectorLifecycleAction, ConnectorLifecycleCommandWrite,
    CreateAgentRunRequest, PostgresConnectorControlApplication, ProtobufDurableCommandDecoder,
    approve_agent_identity,
    begin_agent_route_bootstrap_with_receipt_keyring as begin_agent_route_bootstrap_application,
    create_agent_provisioning_delivery,
    deliver_agent_route_bootstrap as deliver_agent_route_bootstrap_application,
    get_agent_identity_approval, get_agent_provisioning_delivery, get_agent_provisioning_target,
    get_agent_route_bootstrap as get_agent_route_bootstrap_application,
    get_owned_agent_route_bootstrap_target, revoke_agent_provisioning,
};

const DEVICE_SESSION_SCHEME: &str = "DTX-Device-Session";
const IDEMPOTENCY_DOMAIN: &[u8] = b"dirextalk.agent-provisioning-idempotency-key.v1\0";
const DELIVERY_BINDING_DOMAIN: &[u8] = b"dirextalk.agent-provisioning-delivery-binding.v1\0";
const CAPSULE_DIGEST_DOMAIN: &[u8] = b"dirextalk.agent-provisioning-capsule.v1\0";
const REVOCATION_BINDING_DOMAIN: &[u8] = b"dirextalk.agent-provisioning-revocation-binding.v1\0";
const CONVERSATION_GRANT_BINDING_DOMAIN: &[u8] = b"dirextalk.conversation-agent-grant-binding.v1\0";
const CONVERSATION_GRANT_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.conversation-agent-grant-signature.v1\0";
const CONVERSATION_GRANT_REQUEST_DOMAIN: &[u8] = b"dirextalk.conversation-agent-grant-request.v1\0";
const CONVERSATION_GRANT_RECEIPT_DOMAIN: &[u8] = b"dirextalk.conversation-agent-grant-receipt.v1\0";
const CONNECTOR_BINDING_STATE_BINDING_DOMAIN: &[u8] =
    b"dirextalk.connector-binding-state-command-binding.v1\0";
const CONNECTOR_BINDING_STATE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.connector-binding-state-command-signature.v1\0";
const CONNECTOR_BINDING_STATE_REQUEST_DOMAIN: &[u8] =
    b"dirextalk.connector-binding-state-command-request.v1\0";
const CONNECTOR_BINDING_STATE_RECEIPT_DOMAIN: &[u8] =
    b"dirextalk.connector-binding-state-command-receipt.v1\0";
const AGENT_ROUTE_RUN_BINDING_DOMAIN: &[u8] = b"dirextalk.agent-route-run-binding.v1\0";
const AGENT_ROUTE_RUN_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.agent-route-run-signature.v1\0";
const AGENT_ROUTE_RUN_REQUEST_DOMAIN: &[u8] = b"dirextalk.agent-route-run-request.v1\0";
const AGENT_ROUTE_RUN_IDEMPOTENCY_DOMAIN: &[u8] = b"dirextalk.agent-route-run-idempotency.v1\0";
const AGENT_ROUTE_RUN_RECEIPT_DOMAIN: &[u8] = b"dirextalk.agent-route-run-receipt.v1\0";
const AGENT_ROUTE_BOOTSTRAP_MEDIA_TYPE_V1: &str =
    "application/vnd.dirextalk.agent-route-bootstrap.v1+cbor";
const AGENT_ROUTE_BOOTSTRAP_RECEIPT_MEDIA_TYPE_V1: &str =
    "application/vnd.dirextalk.agent-route-bootstrap-receipt.v1+cbor";
const AGENT_ROUTE_TARGET_MEDIA_TYPE_V1: &str =
    "application/vnd.dirextalk.agent-route-target.v1+cbor";
const MAX_SMALL_BODY: usize = 16 * 1024;
const MAX_DELIVERY_BODY: usize = 212_992;
const MAX_GRANT_PROOF_LIFETIME_MS: i64 = 10 * 60 * 1000;
const MAX_GRANT_LIFETIME_MS: i64 = 90 * 24 * 60 * 60 * 1000;
const MAX_BINDING_STATE_PROOF_LIFETIME_MS: i64 = 10 * 60 * 1000;

const CONVERSATION_GRANT_MEDIA_TYPE_V1: &str =
    "application/vnd.dirextalk.conversation-agent-grant.v1+cbor";
const CONVERSATION_GRANT_RECEIPT_MEDIA_TYPE_V1: &str =
    "application/vnd.dirextalk.conversation-agent-grant-receipt.v1+cbor";
const PRIVATE_CONVERSATION_PROFILE_V1: &[u8] = b"dirextalk/private-conversation-agent-profile/v1\nmention-only\nfuture-messages\nsend-messages\nexclude-history\nexclude-attachments\nexclude-tools\nexclude-cloud\nexclude-egress";
const PRIVATE_CONVERSATION_TOOLS_PROFILE_V1: &[u8] = b"dirextalk/private-conversation-agent-profile/v1\nmention-only\nfuture-messages\nsend-messages\nexclude-history\nexclude-attachments\ninclude-tools\nexclude-cloud\nexclude-egress";
pub const CONNECTOR_BINDING_STATE_COMMAND_MEDIA_TYPE_V1: &str =
    "application/vnd.dirextalk.connector-binding-state-command.v1+cbor";
pub const CONNECTOR_BINDING_STATE_RECEIPT_MEDIA_TYPE_V1: &str =
    "application/vnd.dirextalk.connector-binding-state-receipt.v1+cbor";
const AGENT_ROUTE_RUN_MEDIA_TYPE_V1: &str = "application/vnd.dirextalk.agent-route-run.v1+cbor";
const AGENT_ROUTE_RUN_RECEIPT_MEDIA_TYPE_V1: &str =
    "application/vnd.dirextalk.agent-route-run-receipt.v1+cbor";
const PRIVATE_AGENT_ROUTE_RUN_REQUIRED_CAPABILITIES: [&str; 2] = ["chat.streaming", "tool.invoke"];

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

/// Closed mutation permitted on a private-conversation Agent grant head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationGrantOwnerAction {
    /// Creates a first grant or replaces a revoked grant lifecycle.
    Grant,
    /// Revokes exactly one active grant lifecycle.
    Revoke,
}

/// Fresh device-signed Owner command for one private-conversation grant head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationGrantOwnerCommand {
    pub action: ConversationGrantOwnerAction,
    pub operation_id: RequestId,
    pub tenant_id: TenantId,
    pub conversation_id: ConversationId,
    pub installation_id: InstallationId,
    pub expected_grant_version: Option<Revision>,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub proof_expires_at: UtcMillis,
    pub grant_expires_at: Option<UtcMillis>,
    pub privacy_policy_hash: Option<PrivacyPolicyDigest>,
    pub binding_digest: Sha256Digest,
    pub owner_signature: Ed25519Signature,
}

/// Closed state transition permitted on exactly one Owner-owned Connector Binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorBindingStateOwnerAction {
    Enable,
    Disable,
}

/// Device-signed Owner command for one Connector Binding lifecycle revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorBindingStateOwnerCommand {
    pub action: ConnectorBindingStateOwnerAction,
    pub operation_id: RequestId,
    pub tenant_id: TenantId,
    pub binding_id: BindingId,
    pub expected_binding_revision: Revision,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub proof_expires_at: UtcMillis,
    pub binding_digest: Sha256Digest,
    pub owner_signature: Ed25519Signature,
}

/// Device-signed metadata-only ingress for one isolated AgentRoute Run.
///
/// `source_conversation_id` is used solely for Owner/grant authorization and
/// audit.  `route_id` is intentionally distinct and becomes the Router Run's
/// conversation identifier so the Agent data plane can resolve only the
/// isolated MLS route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRouteRunOwnerCommand {
    pub tenant_id: TenantId,
    pub source_conversation_id: ConversationId,
    pub route_id: ConversationId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub agent_control_device_id: AgentDeviceId,
    pub route_fence: [u8; 32],
    pub request_event_id: EventId,
    pub operation_id: RequestId,
    pub grant_version: Revision,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub proof_expires_at: UtcMillis,
    pub binding_digest: Sha256Digest,
    pub owner_signature: Ed25519Signature,
}

/// Durable application interface. Parsing and stable HTTP errors stay independent of `PostgreSQL`.
pub trait AgentProvisioningOwnerBackend: Send + Sync + 'static {
    fn list_connectors(
        &self,
        credential: DeviceSessionCredential,
        query: ConnectorProjectionQueryV1,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_>;
    /// Returns the authenticated V2 Connector projection when this backend owns
    /// a stable tenant identity. The conservative default keeps legacy backend
    /// implementations from inventing a tenant scope.
    fn list_connectors_v2(
        &self,
        _credential: DeviceSessionCredential,
        _query: ConnectorProjectionQueryV1,
        _now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async { Err(AgentProvisioningOwnerError::InvalidRequest) })
    }
    /// Returns the authenticated V3 Connector projection. The conservative
    /// default prevents legacy backends from silently widening Binding facts.
    fn list_connectors_v3(
        &self,
        _credential: DeviceSessionCredential,
        _query: ConnectorProjectionQueryV1,
        _now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async { Err(AgentProvisioningOwnerError::InvalidRequest) })
    }
    /// Returns the authenticated V4 Connector projection. Callers must opt in
    /// explicitly because V4 widens the adapter vocabulary with Hermes ACP.
    fn list_connectors_v4(
        &self,
        _credential: DeviceSessionCredential,
        _query: ConnectorProjectionQueryV1,
        _now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async { Err(AgentProvisioningOwnerError::InvalidRequest) })
    }
    /// Returns bounded references visible to the authenticated Owner device.
    ///
    /// The conservative default prevents alternate backends from inventing a
    /// room, Channel, or post authorization source.
    fn query_mcp_references(
        &self,
        _credential: DeviceSessionCredential,
        _query: String,
        _kind_mask: u8,
        _limit: u16,
        _now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async { Err(AgentProvisioningOwnerError::InvalidRequest) })
    }
    /// Revalidates one short-lived, digest-only Agent MCP credential.
    ///
    /// Raw bearer material never crosses this boundary.
    fn authenticate_agent_mcp(
        &self,
        _token_digest: [u8; 32],
        _node_id: String,
        _now: UtcMillis,
    ) -> Pin<Box<dyn Future<Output = Result<(), AgentProvisioningOwnerError>> + Send + '_>> {
        Box::pin(async { Err(AgentProvisioningOwnerError::InvalidRequest) })
    }
    /// Returns references scoped to one authenticated Agent MCP credential.
    fn query_agent_mcp_references(
        &self,
        _token_digest: [u8; 32],
        _node_id: String,
        _query: String,
        _kind_mask: u8,
        _limit: u16,
        _now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async { Err(AgentProvisioningOwnerError::InvalidRequest) })
    }
    fn lifecycle(
        &self,
        credential: DeviceSessionCredential,
        command: ConnectorLifecycleOwnerCommand,
    ) -> OwnerBackendFuture<'_>;
    /// Applies one durable, Owner-signed Connector Binding state transition.
    ///
    /// A conservative default preserves compatibility for non-PostgreSQL
    /// backend implementations that have not opted into this public command.
    fn mutate_connector_binding_state(
        &self,
        _credential: DeviceSessionCredential,
        _command: ConnectorBindingStateOwnerCommand,
        _exact_body: Vec<u8>,
        _now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async { Err(AgentProvisioningOwnerError::InvalidRequest) })
    }
    fn mutate_conversation_grant(
        &self,
        credential: DeviceSessionCredential,
        command: ConversationGrantOwnerCommand,
        exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_>;
    fn create_agent_route_run(
        &self,
        credential: DeviceSessionCredential,
        command: AgentRouteRunOwnerCommand,
        exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_>;
    fn begin_agent_route_bootstrap(
        &self,
        credential: DeviceSessionCredential,
        command: AgentRouteBootstrapBeginCommand,
        exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_>;
    fn get_agent_route_bootstrap(
        &self,
        credential: DeviceSessionCredential,
        bootstrap_id: AgentRouteBootstrapId,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_>;
    /// Resolves the one active AgentRoute control device for an Owner's binding.
    ///
    /// A default rejection preserves compatibility for backend implementations
    /// that have not opted into RouteBootstrap target discovery.
    fn get_agent_route_target(
        &self,
        _credential: DeviceSessionCredential,
        _installation_id: InstallationId,
        _binding_id: BindingId,
        _now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async { Err(AgentProvisioningOwnerError::InvalidRequest) })
    }
    fn deliver_agent_route_bootstrap(
        &self,
        credential: DeviceSessionCredential,
        command: AgentRouteBootstrapDeliveryCommand,
        exact_body: Vec<u8>,
        now: UtcMillis,
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
    receipt_keyring: Option<Arc<BTreeMap<RouteHealthKeyId, [u8; 32]>>>,
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
            receipt_keyring: None,
        }
    }

    #[must_use]
    pub fn with_route_health_receipt_keyring(
        mut self,
        receipt_keyring: Arc<BTreeMap<RouteHealthKeyId, [u8; 32]>>,
    ) -> Self {
        self.receipt_keyring = Some(receipt_keyring);
        self
    }

    async fn connector_projection_reply(
        &self,
        credential: DeviceSessionCredential,
        query: ConnectorProjectionQueryV1,
        observed_at: UtcMillis,
        representation: ConnectorProjectionRepresentation,
    ) -> Result<CborOwnerReply, AgentProvisioningOwnerError> {
        match representation {
            ConnectorProjectionRepresentation::V3 => {
                let page = list_connector_projection_v3(
                    &self.store,
                    self.tenant_id,
                    &credential,
                    query,
                    observed_at,
                )
                .await
                .map_err(map_connector_projection_error)?;
                return Ok(CborOwnerReply {
                    status: StatusCode::OK,
                    content_type: CONNECTOR_PROJECTION_MEDIA_TYPE_V3,
                    exact_cbor: serde_json::to_vec(&page)
                        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?,
                });
            }
            ConnectorProjectionRepresentation::V4 => {
                let page = list_connector_projection_v4(
                    &self.store,
                    self.tenant_id,
                    &credential,
                    query,
                    observed_at,
                )
                .await
                .map_err(map_connector_projection_error)?;
                return Ok(CborOwnerReply {
                    status: StatusCode::OK,
                    content_type: CONNECTOR_PROJECTION_MEDIA_TYPE_V4,
                    exact_cbor: serde_json::to_vec(&page)
                        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?,
                });
            }
            ConnectorProjectionRepresentation::V1 | ConnectorProjectionRepresentation::V2 => {}
        }
        // `list_connector_projection_v1` authenticates the Device Session in
        // the tenant-scoped transaction before returning a page. Keep the V2
        // tenant field construction after that await so it cannot be exposed
        // on an authentication failure.
        let page = list_connector_projection_v1(
            &self.store,
            self.tenant_id,
            &credential,
            query,
            observed_at,
        )
        .await
        .map_err(map_connector_projection_error)?;
        let (content_type, exact_cbor) = match representation {
            ConnectorProjectionRepresentation::V2 => (
                CONNECTOR_PROJECTION_MEDIA_TYPE_V2,
                serde_json::to_vec(&ConnectorProjectionPageV2::from_v1(self.tenant_id, page)),
            ),
            ConnectorProjectionRepresentation::V1 => (
                CONNECTOR_PROJECTION_MEDIA_TYPE_V1,
                serde_json::to_vec(&page),
            ),
            ConnectorProjectionRepresentation::V3 => {
                return Err(AgentProvisioningOwnerError::TemporarilyUnavailable);
            }
            ConnectorProjectionRepresentation::V4 => {
                return Err(AgentProvisioningOwnerError::TemporarilyUnavailable);
            }
        };
        Ok(CborOwnerReply {
            status: StatusCode::OK,
            content_type,
            exact_cbor: exact_cbor
                .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?,
        })
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
            self.connector_projection_reply(
                credential,
                query,
                now,
                ConnectorProjectionRepresentation::V1,
            )
            .await
        })
    }

    fn list_connectors_v2(
        &self,
        credential: DeviceSessionCredential,
        query: ConnectorProjectionQueryV1,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            self.connector_projection_reply(
                credential,
                query,
                now,
                ConnectorProjectionRepresentation::V2,
            )
            .await
        })
    }

    fn list_connectors_v3(
        &self,
        credential: DeviceSessionCredential,
        query: ConnectorProjectionQueryV1,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            self.connector_projection_reply(
                credential,
                query,
                now,
                ConnectorProjectionRepresentation::V3,
            )
            .await
        })
    }

    fn list_connectors_v4(
        &self,
        credential: DeviceSessionCredential,
        query: ConnectorProjectionQueryV1,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            self.connector_projection_reply(
                credential,
                query,
                now,
                ConnectorProjectionRepresentation::V4,
            )
            .await
        })
    }

    fn query_mcp_references(
        &self,
        credential: DeviceSessionCredential,
        query: String,
        kind_mask: u8,
        limit: u16,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            crate::mcp::query_postgres_references(
                &self.store,
                self.tenant_id,
                credential,
                query,
                kind_mask,
                limit,
                now,
            )
            .await
        })
    }

    fn authenticate_agent_mcp(
        &self,
        token_digest: [u8; 32],
        node_id: String,
        now: UtcMillis,
    ) -> Pin<Box<dyn Future<Output = Result<(), AgentProvisioningOwnerError>> + Send + '_>> {
        Box::pin(async move {
            crate::mcp::authenticate_postgres_agent_mcp(
                &self.store,
                self.tenant_id,
                token_digest,
                node_id,
                now,
            )
            .await
        })
    }

    fn query_agent_mcp_references(
        &self,
        token_digest: [u8; 32],
        node_id: String,
        query: String,
        kind_mask: u8,
        limit: u16,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            crate::mcp::query_postgres_agent_references(
                &self.store,
                self.tenant_id,
                token_digest,
                node_id,
                query,
                kind_mask,
                limit,
                now,
            )
            .await
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

    fn mutate_connector_binding_state(
        &self,
        credential: DeviceSessionCredential,
        command: ConnectorBindingStateOwnerCommand,
        exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            if command.tenant_id != self.tenant_id {
                return Err(AgentProvisioningOwnerError::AccessDenied);
            }
            let receipt = mutate_connector_binding_state_application(
                &self.store,
                &credential,
                command,
                exact_body,
                now,
            )
            .await?;
            Ok(CborOwnerReply {
                status: if receipt.replayed {
                    StatusCode::OK
                } else {
                    StatusCode::CREATED
                },
                content_type: CONNECTOR_BINDING_STATE_RECEIPT_MEDIA_TYPE_V1,
                exact_cbor: receipt.exact_cbor,
            })
        })
    }

    fn mutate_conversation_grant(
        &self,
        credential: DeviceSessionCredential,
        command: ConversationGrantOwnerCommand,
        exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            if command.tenant_id != self.tenant_id {
                return Err(AgentProvisioningOwnerError::AccessDenied);
            }
            let receipt = mutate_private_conversation_grant(
                &self.store,
                &credential,
                command,
                exact_body,
                now,
            )
            .await?;
            Ok(CborOwnerReply {
                status: if receipt.replayed {
                    StatusCode::OK
                } else if receipt.action == ConversationGrantOwnerAction::Grant {
                    StatusCode::CREATED
                } else {
                    StatusCode::OK
                },
                content_type: CONVERSATION_GRANT_RECEIPT_MEDIA_TYPE_V1,
                exact_cbor: receipt.exact_cbor,
            })
        })
    }

    fn create_agent_route_run(
        &self,
        credential: DeviceSessionCredential,
        command: AgentRouteRunOwnerCommand,
        exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            if command.tenant_id != self.tenant_id {
                return Err(AgentProvisioningOwnerError::AccessDenied);
            }
            let receipt = create_private_agent_route_run(
                &self.store,
                self.connector_control.as_ref(),
                &credential,
                command,
                exact_body,
                now,
            )
            .await?;
            Ok(CborOwnerReply {
                status: if receipt.replayed {
                    StatusCode::OK
                } else {
                    StatusCode::CREATED
                },
                content_type: AGENT_ROUTE_RUN_RECEIPT_MEDIA_TYPE_V1,
                exact_cbor: receipt.exact_cbor,
            })
        })
    }

    fn begin_agent_route_bootstrap(
        &self,
        credential: DeviceSessionCredential,
        command: AgentRouteBootstrapBeginCommand,
        exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            if command.tenant_id != self.tenant_id {
                return Err(AgentProvisioningOwnerError::AccessDenied);
            }
            let receipt = begin_agent_route_bootstrap_application(
                &self.store,
                &credential,
                command,
                exact_body,
                now,
                self.receipt_keyring.as_deref(),
            )
            .await
            .map_err(map_agent_route_bootstrap_error)?;
            Ok(CborOwnerReply {
                status: if receipt.replayed {
                    StatusCode::OK
                } else {
                    StatusCode::CREATED
                },
                content_type: AGENT_ROUTE_BOOTSTRAP_RECEIPT_MEDIA_TYPE_V1,
                exact_cbor: receipt.exact_cbor,
            })
        })
    }

    fn get_agent_route_bootstrap(
        &self,
        credential: DeviceSessionCredential,
        bootstrap_id: AgentRouteBootstrapId,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            let receipt = get_agent_route_bootstrap_application(
                &self.store,
                &credential,
                self.tenant_id,
                bootstrap_id,
                now,
            )
            .await
            .map_err(map_agent_route_bootstrap_error)?;
            Ok(CborOwnerReply {
                status: StatusCode::OK,
                content_type: AGENT_ROUTE_BOOTSTRAP_RECEIPT_MEDIA_TYPE_V1,
                exact_cbor: receipt.exact_cbor,
            })
        })
    }

    fn get_agent_route_target(
        &self,
        credential: DeviceSessionCredential,
        installation_id: InstallationId,
        binding_id: BindingId,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            let target = get_owned_agent_route_bootstrap_target(
                &self.store,
                &credential,
                self.tenant_id,
                installation_id,
                binding_id,
                now,
            )
            .await
            .map_err(map_agent_route_bootstrap_error)?;
            Ok(CborOwnerReply {
                status: StatusCode::OK,
                content_type: AGENT_ROUTE_TARGET_MEDIA_TYPE_V1,
                exact_cbor: agent_route_target_cbor(
                    self.tenant_id,
                    installation_id,
                    binding_id,
                    target.agent_control_device_id,
                    target.server_receipt_key_id,
                    target.server_receipt_public_key,
                )?,
            })
        })
    }

    fn deliver_agent_route_bootstrap(
        &self,
        credential: DeviceSessionCredential,
        command: AgentRouteBootstrapDeliveryCommand,
        exact_body: Vec<u8>,
        now: UtcMillis,
    ) -> OwnerBackendFuture<'_> {
        Box::pin(async move {
            if command.tenant_id != self.tenant_id {
                return Err(AgentProvisioningOwnerError::AccessDenied);
            }
            let receipt = deliver_agent_route_bootstrap_application(
                &self.store,
                &credential,
                command,
                exact_body,
                now,
            )
            .await
            .map_err(map_agent_route_bootstrap_error)?;
            Ok(CborOwnerReply {
                status: if receipt.replayed {
                    StatusCode::OK
                } else {
                    StatusCode::CREATED
                },
                content_type: AGENT_ROUTE_BOOTSTRAP_RECEIPT_MEDIA_TYPE_V1,
                exact_cbor: receipt.exact_cbor,
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

fn map_agent_route_bootstrap_error(error: AgentRouteBootstrapError) -> AgentProvisioningOwnerError {
    match error {
        AgentRouteBootstrapError::InvalidRequest => AgentProvisioningOwnerError::InvalidRequest,
        AgentRouteBootstrapError::AuthenticationRejected => {
            AgentProvisioningOwnerError::AuthenticationRejected
        }
        AgentRouteBootstrapError::Forbidden => AgentProvisioningOwnerError::AccessDenied,
        AgentRouteBootstrapError::NotFound => AgentProvisioningOwnerError::NotFound,
        AgentRouteBootstrapError::Conflict => AgentProvisioningOwnerError::Conflict,
        AgentRouteBootstrapError::Unavailable => {
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConversationGrantOwnerReceipt {
    replayed: bool,
    action: ConversationGrantOwnerAction,
    exact_cbor: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConnectorBindingStateOwnerReceipt {
    replayed: bool,
    action: ConnectorBindingStateOwnerAction,
    exact_cbor: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AgentRouteRunOwnerReceipt {
    replayed: bool,
    run_id: RunId,
    exact_cbor: Vec<u8>,
}

async fn create_private_agent_route_run(
    store: &PgStore,
    connector_control: &PostgresConnectorControlApplication,
    credential: &DeviceSessionCredential,
    command: AgentRouteRunOwnerCommand,
    exact_body: Vec<u8>,
    authenticated_at: UtcMillis,
) -> Result<AgentRouteRunOwnerReceipt, AgentProvisioningOwnerError> {
    let request_digest = Sha256Digest::hash_domain(AGENT_ROUTE_RUN_REQUEST_DOMAIN, &exact_body);
    let mut session = store
        .begin_tenant(command.tenant_id)
        .await
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let result = create_private_agent_route_run_in_transaction(
        session.connection(),
        connector_control,
        credential,
        &command,
        request_digest,
        authenticated_at,
    )
    .await;
    let receipt = match result {
        Ok(receipt) => {
            session
                .commit()
                .await
                .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
            receipt
        }
        Err(error) => {
            let _ = session.rollback().await;
            return Err(error);
        }
    };
    // The receipt/run relation committed before this best-effort offer.  A
    // response loss or transient Router error can only retry the exact route
    // operation; it cannot recreate the AgentRequest or alter its source
    // authorization facts.
    connector_control
        .offer_agent_run(command.tenant_id, receipt.run_id)
        .await
        .map_err(map_connector_control_error)?;
    Ok(receipt)
}

#[allow(clippy::too_many_lines)]
async fn create_private_agent_route_run_in_transaction(
    connection: &mut sqlx::PgConnection,
    connector_control: &PostgresConnectorControlApplication,
    credential: &DeviceSessionCredential,
    command: &AgentRouteRunOwnerCommand,
    request_digest: Sha256Digest,
    authenticated_at: UtcMillis,
) -> Result<AgentRouteRunOwnerReceipt, AgentProvisioningOwnerError> {
    let owner = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
        connection,
        credential,
        authenticated_at,
    )
    .await
    .map_err(map_conversation_grant_identity_error)?;
    let owner_session = owner.session();
    if owner_session.identity_id() != command.owner_identity_id
        || owner_session.device_id() != command.owner_device_id
    {
        return Err(AgentProvisioningOwnerError::AccessDenied);
    }
    let signature = Signature::from_bytes(command.owner_signature.as_bytes());
    let verifying_key = VerifyingKey::from_bytes(owner.signing_key().as_bytes())
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
    verifying_key
        .verify_strict(
            &agent_route_run_signature_input(command.binding_digest),
            &signature,
        )
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;

    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(agent_route_run_lock_key(*command.operation_id.as_uuid()))
        .execute(&mut *connection)
        .await
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(agent_route_run_lock_key(*command.route_id.as_uuid()))
        .execute(&mut *connection)
        .await
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    if let Some(receipt) =
        load_agent_route_run_operation(connection, command, request_digest).await?
    {
        return Ok(receipt);
    }
    let (route_connector_id, route_head_expires_at) =
        ensure_agent_route_installed_binding_head(connection, command, now()?).await?;

    let is_owner: bool =
        sqlx::query_scalar("SELECT groups.private_conversation_owner_authorized($1, $2, $3)")
            .bind(Uuid::from(command.tenant_id))
            .bind(Uuid::from(command.source_conversation_id))
            .bind(owner_session.identity_id().to_string())
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    if !is_owner {
        return Err(AgentProvisioningOwnerError::AccessDenied);
    }
    let installation = AgentInstallationRepository::new()
        .load(connection, command.tenant_id, command.installation_id)
        .await
        .map_err(map_conversation_grant_persistence_error)?
        .ok_or(AgentProvisioningOwnerError::NotFound)?;
    if installation.owner_id() != owner_session.identity_id() {
        return Err(AgentProvisioningOwnerError::AccessDenied);
    }

    // Check freshness only after the exact durable replay lookup.  A response
    // lost after commit must recover the original receipt even when its proof
    // has subsequently expired; a new operation never gets that exception.
    validate_agent_route_run_command(command, now()?)?;
    let idempotency_digest = Sha256Digest::hash_domain(
        AGENT_ROUTE_RUN_IDEMPOTENCY_DOMAIN,
        command.operation_id.as_uuid().as_bytes(),
    );
    let create = CreateAgentRunRequest::new(
        command.tenant_id,
        command.operation_id,
        *idempotency_digest.as_bytes(),
        *request_digest.as_bytes(),
        command.installation_id,
        command.route_id,
        command.request_event_id,
        Some(route_connector_id),
        // The frozen v1 AgentRoute request carries no trustworthy pure-chat
        // intent. Its Connector execution boundary can reach runtime tools and
        // MCP, so admission must fail closed on InvokeTools until a future
        // signed contract can explicitly select a narrower execution profile.
        Vec::from(PRIVATE_AGENT_ROUTE_RUN_REQUIRED_CAPABILITIES.map(str::to_owned)),
        DispatchMode::Single,
        command.grant_version.get(),
        None,
    )
    .map_err(map_connector_control_error)?;
    let created = connector_control
        .create_agent_run_in_transaction(
            connection,
            create,
            command.source_conversation_id,
            Some(command.binding_id),
        )
        .await
        .map_err(map_connector_control_error)?;
    let committed_at = now()?;
    if route_head_expires_at <= committed_at {
        // `create_agent_run_in_transaction` inserted only inside this outer
        // transaction, so rejecting here rolls it back rather than allowing a
        // Run to cross the RouteBootstrap expiry boundary mid-request.
        return Err(AgentProvisioningOwnerError::Conflict);
    }
    validate_agent_route_run_command(command, committed_at)?;
    let receipt_bytes = agent_route_run_receipt_cbor(
        command,
        created.run_id(),
        owner_session.device_id(),
        committed_at,
    )?;
    let receipt_digest = Sha256Digest::hash_domain(AGENT_ROUTE_RUN_RECEIPT_DOMAIN, &receipt_bytes);
    sqlx::query(
        "INSERT INTO agent.agent_route_run_operations (
             tenant_id, operation_id, run_id, source_conversation_id, route_id, installation_id,
             request_event_id, grant_version, owner_identity_id, owner_device_id, owner_session_id,
             request_digest, receipt_bytes, receipt_digest, committed_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.operation_id))
    .bind(Uuid::from(created.run_id()))
    .bind(Uuid::from(command.source_conversation_id))
    .bind(Uuid::from(command.route_id))
    .bind(Uuid::from(command.installation_id))
    .bind(Uuid::from(command.request_event_id))
    .bind(
        i64::try_from(command.grant_version.get())
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
    )
    .bind(owner_session.identity_id().to_string())
    .bind(Uuid::from(owner_session.device_id()))
    .bind(Uuid::from(owner_session.session_id()))
    .bind(request_digest.as_bytes().as_slice())
    .bind(&receipt_bytes)
    .bind(receipt_digest.as_bytes().as_slice())
    .bind(committed_at.get())
    .execute(&mut *connection)
    .await
    .map_err(map_agent_route_run_operation_insert_error)?;
    Ok(AgentRouteRunOwnerReceipt {
        replayed: false,
        run_id: created.run_id(),
        exact_cbor: receipt_bytes,
    })
}

async fn ensure_agent_route_installed_binding_head(
    connection: &mut sqlx::PgConnection,
    command: &AgentRouteRunOwnerCommand,
    authenticated_at: UtcMillis,
) -> Result<(ConnectorId, UtcMillis), AgentProvisioningOwnerError> {
    let row = sqlx::query(
        "SELECT bootstrap.connector_id, head.expires_at_ms
           FROM agent.agent_route_binding_heads AS head
           JOIN agent.agent_route_bootstraps AS bootstrap
             ON bootstrap.tenant_id=head.tenant_id
            AND bootstrap.bootstrap_id=head.bootstrap_id
           JOIN agent.connector_bindings AS binding
             ON binding.tenant_id=head.tenant_id
            AND binding.binding_id=head.binding_id
            AND binding.installation_id=head.installation_id
            AND binding.agent_device_id=head.agent_control_device_id
            AND binding.connector_id=bootstrap.connector_id
            AND binding.state='enabled'
          WHERE head.tenant_id=$1
            AND head.owner_identity_id=$2 AND head.owner_device_id=$3
            AND head.installation_id=$4 AND head.binding_id=$5
            AND head.agent_control_device_id=$6
            AND head.route_id=$7 AND head.route_fence=$8
            AND head.expires_at_ms > $9
            AND bootstrap.state='installed'
            AND bootstrap.delivery_id=head.delivery_id
            AND bootstrap.route_id=head.route_id
            AND bootstrap.route_fence=head.route_fence
          FOR SHARE OF head, bootstrap, binding",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(command.owner_identity_id.to_string())
    .bind(Uuid::from(command.owner_device_id))
    .bind(Uuid::from(command.installation_id))
    .bind(Uuid::from(command.binding_id))
    .bind(Uuid::from(command.agent_control_device_id))
    .bind(Uuid::from(command.route_id))
    .bind(command.route_fence.as_slice())
    .bind(authenticated_at.get())
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let row = row.ok_or(AgentProvisioningOwnerError::Conflict)?;
    let connector_id: Uuid = row
        .try_get("connector_id")
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let expires_at = UtcMillis::new(
        row.try_get("expires_at_ms")
            .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?,
    )
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    ConnectorId::try_from(connector_id)
        .map(|connector_id| (connector_id, expires_at))
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)
}

async fn load_agent_route_run_operation(
    connection: &mut sqlx::PgConnection,
    command: &AgentRouteRunOwnerCommand,
    request_digest: Sha256Digest,
) -> Result<Option<AgentRouteRunOwnerReceipt>, AgentProvisioningOwnerError> {
    let rows = sqlx::query(
        "SELECT operation_id, run_id, request_digest, receipt_bytes, receipt_digest
           FROM agent.agent_route_run_operations
          WHERE tenant_id=$1
            AND (operation_id=$2 OR (route_id=$3 AND request_event_id=$4))
          FOR UPDATE",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.operation_id))
    .bind(Uuid::from(command.route_id))
    .bind(Uuid::from(command.request_event_id))
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    if rows.len() > 1 {
        return Err(AgentProvisioningOwnerError::TemporarilyUnavailable);
    }
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let operation_id: Uuid = row
        .try_get("operation_id")
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let stored_request_digest: Vec<u8> = row
        .try_get("request_digest")
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    if operation_id != Uuid::from(command.operation_id)
        || stored_request_digest.as_slice() != request_digest.as_bytes()
    {
        return Err(AgentProvisioningOwnerError::Conflict);
    }
    let exact_cbor: Vec<u8> = row
        .try_get("receipt_bytes")
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let stored_digest: [u8; 32] = row
        .try_get::<Vec<u8>, _>("receipt_digest")
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?
        .try_into()
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    if *Sha256Digest::hash_domain(AGENT_ROUTE_RUN_RECEIPT_DOMAIN, &exact_cbor).as_bytes()
        != stored_digest
        || decode_deterministic_cbor(&exact_cbor).is_err()
    {
        return Err(AgentProvisioningOwnerError::TemporarilyUnavailable);
    }
    let run_id = RunId::try_from(
        row.try_get::<Uuid, _>("run_id")
            .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?,
    )
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    Ok(Some(AgentRouteRunOwnerReceipt {
        replayed: true,
        run_id,
        exact_cbor,
    }))
}

fn validate_agent_route_run_command(
    command: &AgentRouteRunOwnerCommand,
    now: UtcMillis,
) -> Result<(), AgentProvisioningOwnerError> {
    if command.source_conversation_id == command.route_id
        || command.request_event_id.as_uuid() != command.operation_id.as_uuid()
        || command.route_fence.iter().all(|byte| *byte == 0)
        || command.proof_expires_at.get() <= now.get()
        || command.proof_expires_at.get() > now.get().saturating_add(MAX_GRANT_PROOF_LIFETIME_MS)
    {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    Ok(())
}

fn agent_route_target_cbor(
    tenant_id: TenantId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    server_receipt_key_id: Option<RouteHealthKeyId>,
    server_receipt_public_key: Option<[u8; 32]>,
) -> Result<Vec<u8>, AgentProvisioningOwnerError> {
    let mut fields = vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Unsigned(
                if server_receipt_key_id.is_some() && server_receipt_public_key.is_some() {
                    2
                } else {
                    1
                },
            ),
        ),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(tenant_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(installation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(binding_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(agent_control_device_id.to_string()),
        ),
    ];
    if let (Some(key_id), Some(public_key)) = (server_receipt_key_id, server_receipt_public_key) {
        fields.push((
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(key_id.to_string()),
        ));
        fields.push((
            CanonicalValue::Unsigned(7),
            CanonicalValue::Bytes(public_key.to_vec()),
        ));
    }
    encode_deterministic_cbor(&CanonicalValue::Map(fields))
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)
}

fn agent_route_run_receipt_cbor(
    command: &AgentRouteRunOwnerCommand,
    run_id: RunId,
    owner_device_id: DeviceId,
    committed_at: UtcMillis,
) -> Result<Vec<u8>, AgentProvisioningOwnerError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(command.tenant_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(command.source_conversation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(command.route_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(command.installation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(command.request_event_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(command.operation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(run_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Unsigned(command.grant_version.get()),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Text(owner_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(11),
            committed_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(12),
            CanonicalValue::Text(command.binding_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(13),
            CanonicalValue::Text(command.agent_control_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(14),
            CanonicalValue::Bytes(command.route_fence.to_vec()),
        ),
    ]))
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)
}

fn agent_route_run_lock_key(id: Uuid) -> i64 {
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&id.as_bytes()[..8]);
    i64::from_be_bytes(prefix) ^ i64::MIN
}

fn map_agent_route_run_operation_insert_error(error: sqlx::Error) -> AgentProvisioningOwnerError {
    if error
        .as_database_error()
        .and_then(|error| error.code())
        .is_some_and(|code| code == "23505")
    {
        AgentProvisioningOwnerError::Conflict
    } else {
        AgentProvisioningOwnerError::TemporarilyUnavailable
    }
}

async fn mutate_private_conversation_grant(
    store: &PgStore,
    credential: &DeviceSessionCredential,
    command: ConversationGrantOwnerCommand,
    exact_body: Vec<u8>,
    authenticated_at: UtcMillis,
) -> Result<ConversationGrantOwnerReceipt, AgentProvisioningOwnerError> {
    let request_digest = Sha256Digest::hash_domain(CONVERSATION_GRANT_REQUEST_DOMAIN, &exact_body);
    let mut session = store
        .begin_tenant(command.tenant_id)
        .await
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let result = mutate_private_conversation_grant_in_transaction(
        session.connection(),
        credential,
        &command,
        request_digest,
        authenticated_at,
    )
    .await;
    match result {
        Ok(receipt) => {
            session
                .commit()
                .await
                .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
            Ok(receipt)
        }
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

async fn mutate_connector_binding_state_application(
    store: &PgStore,
    credential: &DeviceSessionCredential,
    command: ConnectorBindingStateOwnerCommand,
    exact_body: Vec<u8>,
    authenticated_at: UtcMillis,
) -> Result<ConnectorBindingStateOwnerReceipt, AgentProvisioningOwnerError> {
    let request_digest =
        Sha256Digest::hash_domain(CONNECTOR_BINDING_STATE_REQUEST_DOMAIN, &exact_body);
    let mut session = store
        .begin_tenant(command.tenant_id)
        .await
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let result = mutate_connector_binding_state_in_transaction(
        session.connection(),
        credential,
        &command,
        request_digest,
        authenticated_at,
    )
    .await;
    match result {
        Ok(receipt) => {
            session
                .commit()
                .await
                .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
            Ok(receipt)
        }
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn mutate_connector_binding_state_in_transaction(
    connection: &mut sqlx::PgConnection,
    credential: &DeviceSessionCredential,
    command: &ConnectorBindingStateOwnerCommand,
    request_digest: Sha256Digest,
    authenticated_at: UtcMillis,
) -> Result<ConnectorBindingStateOwnerReceipt, AgentProvisioningOwnerError> {
    let owner = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
        connection,
        credential,
        authenticated_at,
    )
    .await
    .map_err(map_conversation_grant_identity_error)?;
    let owner_session = owner.session();
    if owner_session.identity_id() != command.owner_identity_id
        || owner_session.device_id() != command.owner_device_id
    {
        return Err(AgentProvisioningOwnerError::AccessDenied);
    }
    let signature = Signature::from_bytes(command.owner_signature.as_bytes());
    let verifying_key = VerifyingKey::from_bytes(owner.signing_key().as_bytes())
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
    verifying_key
        .verify_strict(
            &connector_binding_state_signature_input(command.binding_digest),
            &signature,
        )
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;

    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(connector_binding_state_operation_lock_key(
            command.operation_id,
        ))
        .execute(&mut *connection)
        .await
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    if let Some(receipt) = load_connector_binding_state_operation(
        connection,
        command.tenant_id,
        command.operation_id,
        command.action,
        request_digest,
    )
    .await?
    {
        return Ok(receipt);
    }

    let binding_ref = TenantRef::new(command.tenant_id, command.binding_id);
    let repository = BindingSetRepository::new();
    let mut bindings = repository
        .load(connection, command.tenant_id)
        .await
        .map_err(map_conversation_grant_persistence_error)?;
    let binding = *bindings
        .binding(binding_ref)
        .map_err(map_connector_binding_state_error)?;
    let installation = AgentInstallationRepository::new()
        .load(connection, command.tenant_id, binding.installation_id())
        .await
        .map_err(map_conversation_grant_persistence_error)?
        .ok_or(AgentProvisioningOwnerError::NotFound)?;
    if installation.owner_id() != owner_session.identity_id() {
        return Err(AgentProvisioningOwnerError::AccessDenied);
    }

    // Exact retries returned before this point.  A command that waited for a
    // prior transition therefore cannot consume an already expired proof.
    let committed_at = now()?;
    validate_connector_binding_state_command(command, committed_at)?;
    let result_revision = match command.action {
        ConnectorBindingStateOwnerAction::Disable => bindings
            .disable(binding_ref, command.expected_binding_revision)
            .map_err(map_connector_binding_state_error)?,
        ConnectorBindingStateOwnerAction::Enable => {
            let device = AgentDeviceRepository::new()
                .load(connection, command.tenant_id, binding.agent_device_id())
                .await
                .map_err(map_conversation_grant_persistence_error)?
                .ok_or(AgentProvisioningOwnerError::Conflict)?;
            bindings
                .enable(
                    binding_ref,
                    command.expected_binding_revision,
                    &installation,
                    &device,
                )
                .map_err(map_connector_binding_state_error)?
        }
    };
    repository
        .save(connection, &bindings, committed_at.get())
        .await
        .map_err(map_conversation_grant_persistence_error)?;
    let result_state = bindings
        .binding(binding_ref)
        .map_err(map_connector_binding_state_error)?
        .state();
    let receipt_bytes = connector_binding_state_receipt_cbor(
        command.action,
        command.tenant_id,
        command.binding_id,
        result_state,
        result_revision,
        owner_session.device_id(),
        committed_at,
        command.operation_id,
        request_digest,
    )?;
    let receipt_digest =
        Sha256Digest::hash_domain(CONNECTOR_BINDING_STATE_RECEIPT_DOMAIN, &receipt_bytes);
    sqlx::query(
        "INSERT INTO agent.connector_binding_state_owner_operations (
             tenant_id, operation_id, binding_id, action, request_digest,
             result_state, result_revision, owner_identity_id, owner_device_id,
             owner_session_id, receipt_bytes, receipt_digest, committed_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.operation_id))
    .bind(Uuid::from(command.binding_id))
    .bind(connector_binding_state_action_code(command.action))
    .bind(request_digest.as_bytes().as_slice())
    .bind(connector_binding_state_database_state(result_state)?)
    .bind(
        i64::try_from(result_revision.get())
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
    )
    .bind(owner_session.identity_id().to_string())
    .bind(Uuid::from(owner_session.device_id()))
    .bind(Uuid::from(owner_session.session_id()))
    .bind(&receipt_bytes)
    .bind(receipt_digest.as_bytes().as_slice())
    .bind(committed_at.get())
    .execute(&mut *connection)
    .await
    .map_err(map_connector_binding_state_operation_insert_error)?;
    Ok(ConnectorBindingStateOwnerReceipt {
        replayed: false,
        action: command.action,
        exact_cbor: receipt_bytes,
    })
}

#[allow(clippy::too_many_lines)]
async fn mutate_private_conversation_grant_in_transaction(
    connection: &mut sqlx::PgConnection,
    credential: &DeviceSessionCredential,
    command: &ConversationGrantOwnerCommand,
    request_digest: Sha256Digest,
    authenticated_at: UtcMillis,
) -> Result<ConversationGrantOwnerReceipt, AgentProvisioningOwnerError> {
    let owner = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
        connection,
        credential,
        authenticated_at,
    )
    .await
    .map_err(map_conversation_grant_identity_error)?;
    let owner_session = owner.session();
    if owner_session.identity_id() != command.owner_identity_id
        || owner_session.device_id() != command.owner_device_id
    {
        return Err(AgentProvisioningOwnerError::AccessDenied);
    }
    let signature = Signature::from_bytes(command.owner_signature.as_bytes());
    let verifying_key = VerifyingKey::from_bytes(owner.signing_key().as_bytes())
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
    verifying_key
        .verify_strict(
            &conversation_grant_signature_input(command.binding_digest),
            &signature,
        )
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;

    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(conversation_grant_operation_lock_key(command.operation_id))
        .execute(&mut *connection)
        .await
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    if let Some(receipt) = load_conversation_grant_operation(
        connection,
        command.tenant_id,
        command.operation_id,
        command.action,
        request_digest,
    )
    .await?
    {
        return Ok(receipt);
    }

    let is_owner: bool =
        sqlx::query_scalar("SELECT groups.private_conversation_owner_authorized($1, $2, $3)")
            .bind(Uuid::from(command.tenant_id))
            .bind(Uuid::from(command.conversation_id))
            .bind(owner_session.identity_id().to_string())
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    if !is_owner {
        return Err(AgentProvisioningOwnerError::AccessDenied);
    }

    let installation = AgentInstallationRepository::new()
        .load(connection, command.tenant_id, command.installation_id)
        .await
        .map_err(map_conversation_grant_persistence_error)?
        .ok_or(AgentProvisioningOwnerError::NotFound)?;
    if installation.owner_id() != owner_session.identity_id() {
        return Err(AgentProvisioningOwnerError::AccessDenied);
    }
    if command.action == ConversationGrantOwnerAction::Grant
        && !installation_has_enabled_active_agent_device(
            connection,
            command.tenant_id,
            command.installation_id,
        )
        .await?
    {
        return Err(AgentProvisioningOwnerError::Conflict);
    }

    let repository = ConversationGrantRepository::new();
    let mut grant = repository
        .load_for_update(
            connection,
            command.tenant_id,
            command.conversation_id,
            command.installation_id,
        )
        .await
        .map_err(map_conversation_grant_persistence_error)?;
    // Exact retries have already returned above. Sample after the per-grant
    // write lock so a new operation cannot commit based on a proof that expired
    // while it waited for an earlier transition.
    let committed_at = now()?;
    validate_conversation_grant_command(command, committed_at)?;
    let expected = command.expected_grant_version;
    match (&mut grant, command.action, expected) {
        (None, ConversationGrantOwnerAction::Grant, None) => {
            grant = Some(new_private_conversation_grant(
                &installation,
                command,
                owner_session.device_id(),
                committed_at,
            )?);
        }
        (None, ConversationGrantOwnerAction::Grant, Some(_))
        | (None, ConversationGrantOwnerAction::Revoke, _) => {
            return Err(AgentProvisioningOwnerError::Conflict);
        }
        (Some(_), _, None) => return Err(AgentProvisioningOwnerError::Conflict),
        (Some(current), ConversationGrantOwnerAction::Grant, Some(expected)) => {
            if current.grant_version() != expected || current.snapshot().revoked_at_ms.is_none() {
                return Err(AgentProvisioningOwnerError::Conflict);
            }
            let update = new_private_conversation_grant_update(
                command,
                owner_session.device_id(),
                committed_at,
            )?;
            current
                .apply(
                    &installation,
                    expected,
                    ConversationGrantCommand::Regrant {
                        grant_id: GrantId::new(),
                        update,
                        permission_expansion:
                            dtx_agent_registry::PermissionExpansionConfirmation::confirmed(),
                        all_messages: None,
                    },
                )
                .map_err(|_| AgentProvisioningOwnerError::Conflict)?;
        }
        (Some(current), ConversationGrantOwnerAction::Revoke, Some(expected)) => {
            if current.grant_version() != expected || current.snapshot().revoked_at_ms.is_some() {
                return Err(AgentProvisioningOwnerError::Conflict);
            }
            current
                .apply(
                    &installation,
                    expected,
                    ConversationGrantCommand::Revoke {
                        revoked_at_ms: committed_at.get(),
                    },
                )
                .map_err(|_| AgentProvisioningOwnerError::Conflict)?;
        }
    }
    let grant = grant.ok_or(AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    repository
        .save_in_transaction(connection, &grant, committed_at.get())
        .await
        .map_err(map_conversation_grant_persistence_error)?;
    let snapshot = grant.snapshot();
    let revoked = snapshot.revoked_at_ms.is_some();
    let receipt_bytes = conversation_grant_receipt_cbor(
        command.action,
        command.tenant_id,
        command.conversation_id,
        command.installation_id,
        snapshot.grant_id,
        snapshot.grant_version,
        snapshot.privacy_policy_hash,
        owner_session.device_id(),
        committed_at,
        (command.action == ConversationGrantOwnerAction::Grant)
            .then_some(snapshot.expires_at_ms)
            .flatten(),
    )?;
    let receipt_digest =
        Sha256Digest::hash_domain(CONVERSATION_GRANT_RECEIPT_DOMAIN, &receipt_bytes);
    sqlx::query(
        "INSERT INTO agent.conversation_grant_owner_operations (
             tenant_id, operation_id, conversation_id, installation_id, action,
             request_digest, grant_id, grant_version, revoked, owner_identity_id,
             owner_device_id, owner_session_id, receipt_bytes, receipt_digest, committed_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.operation_id))
    .bind(Uuid::from(command.conversation_id))
    .bind(Uuid::from(command.installation_id))
    .bind(conversation_grant_action_code(command.action))
    .bind(request_digest.as_bytes().as_slice())
    .bind(Uuid::from(snapshot.grant_id))
    .bind(
        i64::try_from(snapshot.grant_version.get())
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
    )
    .bind(revoked)
    .bind(owner_session.identity_id().to_string())
    .bind(Uuid::from(owner_session.device_id()))
    .bind(Uuid::from(owner_session.session_id()))
    .bind(&receipt_bytes)
    .bind(receipt_digest.as_bytes().as_slice())
    .bind(committed_at.get())
    .execute(&mut *connection)
    .await
    .map_err(map_conversation_grant_operation_insert_error)?;
    Ok(ConversationGrantOwnerReceipt {
        replayed: false,
        action: command.action,
        exact_cbor: receipt_bytes,
    })
}

fn validate_connector_binding_state_command(
    command: &ConnectorBindingStateOwnerCommand,
    now: UtcMillis,
) -> Result<(), AgentProvisioningOwnerError> {
    let proof_expires_at = command.proof_expires_at.get();
    if proof_expires_at <= now.get()
        || proof_expires_at
            > now
                .get()
                .saturating_add(MAX_BINDING_STATE_PROOF_LIFETIME_MS)
    {
        Err(AgentProvisioningOwnerError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn validate_conversation_grant_command(
    command: &ConversationGrantOwnerCommand,
    now: UtcMillis,
) -> Result<(), AgentProvisioningOwnerError> {
    let proof_expires_at = command.proof_expires_at.get();
    if proof_expires_at <= now.get()
        || proof_expires_at > now.get().saturating_add(MAX_GRANT_PROOF_LIFETIME_MS)
    {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    match command.action {
        ConversationGrantOwnerAction::Grant => {
            let grant_expires_at = command
                .grant_expires_at
                .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
            if command.privacy_policy_hash.is_none()
                || grant_expires_at.get() <= now.get()
                || grant_expires_at.get() > now.get().saturating_add(MAX_GRANT_LIFETIME_MS)
            {
                return Err(AgentProvisioningOwnerError::InvalidRequest);
            }
        }
        ConversationGrantOwnerAction::Revoke
            if command.grant_expires_at.is_some() || command.privacy_policy_hash.is_some() =>
        {
            return Err(AgentProvisioningOwnerError::InvalidRequest);
        }
        ConversationGrantOwnerAction::Revoke => {}
    }
    Ok(())
}

fn new_private_conversation_grant(
    installation: &dtx_agent_registry::AgentInstallation,
    command: &ConversationGrantOwnerCommand,
    device_id: DeviceId,
    now: UtcMillis,
) -> Result<ConversationGrant, AgentProvisioningOwnerError> {
    ConversationGrant::issue(
        installation,
        GrantId::new(),
        command.conversation_id,
        private_conversation_permissions(
            command
                .privacy_policy_hash
                .ok_or(AgentProvisioningOwnerError::InvalidRequest)?,
        )?,
        TriggerPolicy::MentionOnly,
        command
            .privacy_policy_hash
            .ok_or(AgentProvisioningOwnerError::InvalidRequest)?,
        device_id,
        now.get(),
        Some(
            command
                .grant_expires_at
                .ok_or(AgentProvisioningOwnerError::InvalidRequest)?
                .get(),
        ),
        None,
    )
    .map_err(|_| AgentProvisioningOwnerError::Conflict)
}

fn new_private_conversation_grant_update(
    command: &ConversationGrantOwnerCommand,
    device_id: DeviceId,
    now: UtcMillis,
) -> Result<ConversationGrantUpdate, AgentProvisioningOwnerError> {
    Ok(ConversationGrantUpdate::new(
        private_conversation_permissions(
            command
                .privacy_policy_hash
                .ok_or(AgentProvisioningOwnerError::InvalidRequest)?,
        )?,
        TriggerPolicy::MentionOnly,
        command
            .privacy_policy_hash
            .ok_or(AgentProvisioningOwnerError::InvalidRequest)?,
        device_id,
        now.get(),
        Some(
            command
                .grant_expires_at
                .ok_or(AgentProvisioningOwnerError::InvalidRequest)?
                .get(),
        ),
    ))
}

fn private_conversation_permissions(
    privacy_policy_hash: PrivacyPolicyDigest,
) -> Result<AgentConversationPermissions, AgentProvisioningOwnerError> {
    let permissions = AgentConversationPermissions::none()
        .with(AgentConversationPermission::ReadFutureMessages)
        .with(AgentConversationPermission::SendMessages);
    let profile_digest = |profile: &[u8]| {
        PrivacyPolicyDigest::from_bytes(*Sha256Digest::hash_domain(&[], profile).as_bytes())
    };
    if privacy_policy_hash == profile_digest(PRIVATE_CONVERSATION_PROFILE_V1) {
        Ok(permissions)
    } else if privacy_policy_hash == profile_digest(PRIVATE_CONVERSATION_TOOLS_PROFILE_V1) {
        Ok(permissions.with(AgentConversationPermission::InvokeTools))
    } else {
        Err(AgentProvisioningOwnerError::InvalidRequest)
    }
}

async fn installation_has_enabled_active_agent_device(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    installation_id: InstallationId,
) -> Result<bool, AgentProvisioningOwnerError> {
    // `FOR SHARE` prevents a concurrent Binding state update from committing
    // between this grant precondition and the durable grant write below.
    sqlx::query_scalar::<_, Uuid>(
        "SELECT binding.binding_id
           FROM agent.connector_bindings AS binding
           JOIN agent.agent_devices AS device
             ON device.tenant_id=binding.tenant_id
            AND device.installation_id=binding.installation_id
            AND device.agent_device_id=binding.agent_device_id
          WHERE binding.tenant_id=$1
            AND binding.installation_id=$2
            AND binding.state='enabled'
            AND device.state='active'
          ORDER BY binding.binding_id
          LIMIT 1
          FOR SHARE OF binding",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(installation_id))
    .fetch_optional(&mut *connection)
    .await
    .map(|binding| binding.is_some())
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)
}

async fn load_conversation_grant_operation(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    operation_id: RequestId,
    action: ConversationGrantOwnerAction,
    request_digest: Sha256Digest,
) -> Result<Option<ConversationGrantOwnerReceipt>, AgentProvisioningOwnerError> {
    let row = sqlx::query(
        "SELECT action, request_digest, receipt_bytes, receipt_digest
           FROM agent.conversation_grant_owner_operations
          WHERE tenant_id=$1 AND operation_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(operation_id))
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row
        .try_get::<Vec<u8>, _>("request_digest")
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?
        .as_slice()
        != request_digest.as_bytes()
        || row
            .try_get::<String, _>("action")
            .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?
            != conversation_grant_action_code(action)
    {
        return Err(AgentProvisioningOwnerError::Conflict);
    }
    let exact_cbor = row
        .try_get::<Vec<u8>, _>("receipt_bytes")
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let stored_digest = row
        .try_get::<Vec<u8>, _>("receipt_digest")
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let stored_digest: [u8; 32] = stored_digest
        .try_into()
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    if *Sha256Digest::hash_domain(CONVERSATION_GRANT_RECEIPT_DOMAIN, &exact_cbor).as_bytes()
        != stored_digest
        || decode_deterministic_cbor(&exact_cbor).is_err()
    {
        return Err(AgentProvisioningOwnerError::TemporarilyUnavailable);
    }
    Ok(Some(ConversationGrantOwnerReceipt {
        replayed: true,
        action,
        exact_cbor,
    }))
}

async fn load_connector_binding_state_operation(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    operation_id: RequestId,
    action: ConnectorBindingStateOwnerAction,
    request_digest: Sha256Digest,
) -> Result<Option<ConnectorBindingStateOwnerReceipt>, AgentProvisioningOwnerError> {
    let row = sqlx::query(
        "SELECT action, request_digest, receipt_bytes, receipt_digest
           FROM agent.connector_binding_state_owner_operations
          WHERE tenant_id=$1 AND operation_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(operation_id))
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row
        .try_get::<Vec<u8>, _>("request_digest")
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?
        .as_slice()
        != request_digest.as_bytes()
        || row
            .try_get::<String, _>("action")
            .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?
            != connector_binding_state_action_code(action)
    {
        return Err(AgentProvisioningOwnerError::Conflict);
    }
    let exact_cbor = row
        .try_get::<Vec<u8>, _>("receipt_bytes")
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let stored_digest = row
        .try_get::<Vec<u8>, _>("receipt_digest")
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    let stored_digest: [u8; 32] = stored_digest
        .try_into()
        .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)?;
    if *Sha256Digest::hash_domain(CONNECTOR_BINDING_STATE_RECEIPT_DOMAIN, &exact_cbor).as_bytes()
        != stored_digest
        || decode_deterministic_cbor(&exact_cbor).is_err()
    {
        return Err(AgentProvisioningOwnerError::TemporarilyUnavailable);
    }
    Ok(Some(ConnectorBindingStateOwnerReceipt {
        replayed: true,
        action,
        exact_cbor,
    }))
}

fn conversation_grant_receipt_cbor(
    action: ConversationGrantOwnerAction,
    tenant_id: TenantId,
    conversation_id: ConversationId,
    installation_id: InstallationId,
    grant_id: GrantId,
    grant_version: Revision,
    privacy_policy_hash: PrivacyPolicyDigest,
    owner_device_id: DeviceId,
    committed_at: UtcMillis,
    grant_expires_at_ms: Option<i64>,
) -> Result<Vec<u8>, AgentProvisioningOwnerError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Unsigned(match action {
                ConversationGrantOwnerAction::Grant => 1,
                ConversationGrantOwnerAction::Revoke => 2,
            }),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(tenant_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(conversation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(installation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(grant_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Unsigned(grant_version.get()),
        ),
        (CanonicalValue::Unsigned(8), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Bytes(privacy_policy_hash.as_bytes().to_vec()),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Text(owner_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(11),
            committed_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(12),
            grant_expires_at_ms.map_or(CanonicalValue::Null, |value| {
                UtcMillis::new(value)
                    .expect("persisted Conversation Grant expiry is valid")
                    .to_canonical_value()
            }),
        ),
    ]))
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)
}

fn connector_binding_state_receipt_cbor(
    action: ConnectorBindingStateOwnerAction,
    tenant_id: TenantId,
    binding_id: BindingId,
    result_state: BindingState,
    result_revision: Revision,
    owner_device_id: DeviceId,
    committed_at: UtcMillis,
    operation_id: RequestId,
    request_digest: Sha256Digest,
) -> Result<Vec<u8>, AgentProvisioningOwnerError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Unsigned(connector_binding_state_action_value(action)),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(tenant_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(binding_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Unsigned(connector_binding_state_code(result_state)?),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Unsigned(result_revision.get()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(owner_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(8),
            committed_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Text(operation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Bytes(request_digest.as_bytes().to_vec()),
        ),
    ]))
    .map_err(|_| AgentProvisioningOwnerError::TemporarilyUnavailable)
}

fn conversation_grant_signature_input(binding_digest: Sha256Digest) -> Vec<u8> {
    let mut input = CONVERSATION_GRANT_SIGNATURE_DOMAIN.to_vec();
    input.extend_from_slice(binding_digest.as_bytes());
    input
}

fn connector_binding_state_signature_input(binding_digest: Sha256Digest) -> Vec<u8> {
    let mut input = CONNECTOR_BINDING_STATE_SIGNATURE_DOMAIN.to_vec();
    input.extend_from_slice(binding_digest.as_bytes());
    input
}

fn agent_route_run_signature_input(binding_digest: Sha256Digest) -> Vec<u8> {
    let mut input = AGENT_ROUTE_RUN_SIGNATURE_DOMAIN.to_vec();
    input.extend_from_slice(binding_digest.as_bytes());
    input
}

const fn conversation_grant_action_code(action: ConversationGrantOwnerAction) -> &'static str {
    match action {
        ConversationGrantOwnerAction::Grant => "grant",
        ConversationGrantOwnerAction::Revoke => "revoke",
    }
}

const fn connector_binding_state_action_value(action: ConnectorBindingStateOwnerAction) -> u64 {
    match action {
        ConnectorBindingStateOwnerAction::Enable => 1,
        ConnectorBindingStateOwnerAction::Disable => 2,
    }
}

const fn connector_binding_state_action_code(
    action: ConnectorBindingStateOwnerAction,
) -> &'static str {
    match action {
        ConnectorBindingStateOwnerAction::Enable => "enable",
        ConnectorBindingStateOwnerAction::Disable => "disable",
    }
}

fn connector_binding_state_code(state: BindingState) -> Result<u64, AgentProvisioningOwnerError> {
    match state {
        BindingState::Enabled => Ok(1),
        BindingState::Disabled => Ok(2),
        BindingState::Revoked => Err(AgentProvisioningOwnerError::Conflict),
    }
}

fn connector_binding_state_database_state(
    state: BindingState,
) -> Result<&'static str, AgentProvisioningOwnerError> {
    match state {
        BindingState::Enabled => Ok("enabled"),
        BindingState::Disabled => Ok("disabled"),
        BindingState::Revoked => Err(AgentProvisioningOwnerError::Conflict),
    }
}

fn conversation_grant_operation_lock_key(operation_id: RequestId) -> i64 {
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&operation_id.as_uuid().as_bytes()[..8]);
    i64::from_be_bytes(prefix)
}

fn connector_binding_state_operation_lock_key(operation_id: RequestId) -> i64 {
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&operation_id.as_uuid().as_bytes()[..8]);
    i64::from_be_bytes(prefix) ^ i64::MIN
}

fn map_conversation_grant_identity_error(
    error: dtx_identity_persistence::IdentityPersistenceError,
) -> AgentProvisioningOwnerError {
    match error {
        dtx_identity_persistence::IdentityPersistenceError::DeviceAuthenticationRejected => {
            AgentProvisioningOwnerError::AuthenticationRejected
        }
        _ => AgentProvisioningOwnerError::TemporarilyUnavailable,
    }
}

fn map_conversation_grant_persistence_error(
    error: AgentPersistenceError,
) -> AgentProvisioningOwnerError {
    match error {
        AgentPersistenceError::ImmutableConflict(_)
        | AgentPersistenceError::RevisionConflict { .. } => AgentProvisioningOwnerError::Conflict,
        AgentPersistenceError::Database(_)
        | AgentPersistenceError::CorruptData(_)
        | AgentPersistenceError::FenceConflict
        | AgentPersistenceError::ClaimRejected(_)
        | AgentPersistenceError::AuthorizationRejected(_)
        | AgentPersistenceError::CursorConflict { .. }
        | AgentPersistenceError::CommandDecodeRejected
        | AgentPersistenceError::MaterializationLimitExceeded(_)
        | AgentPersistenceError::SnapshotRejected(_) => {
            AgentProvisioningOwnerError::TemporarilyUnavailable
        }
    }
}

const fn map_connector_binding_state_error(error: BindingError) -> AgentProvisioningOwnerError {
    match error {
        BindingError::BindingNotFound => AgentProvisioningOwnerError::NotFound,
        BindingError::WrongTenant
        | BindingError::MissingConnectorConformance
        | BindingError::ConformanceConflict
        | BindingError::ConformanceAdapterMismatch
        | BindingError::BindingIdConflict
        | BindingError::DuplicateInstallationConnector
        | BindingError::AgentDeviceReused
        | BindingError::AgentDeviceScopeMismatch
        | BindingError::AgentDeviceNotActive
        | BindingError::AgentDeviceNotResolved
        | BindingError::InstallationNotActive
        | BindingError::InvalidBindingCapacity
        | BindingError::RoutingPolicyConflict
        | BindingError::RoutingPolicyNotFound
        | BindingError::ExclusivePriorityMustBeZero
        | BindingError::ExclusiveAlreadyEnabled
        | BindingError::PriorityConflict
        | BindingError::PriorityUpdateConflict
        | BindingError::BindingInstallationMismatch
        | BindingError::ConnectorSingleSession
        | BindingError::InvalidTransition
        | BindingError::RevisionConflict { .. }
        | BindingError::CounterExhausted => AgentProvisioningOwnerError::Conflict,
    }
}

fn map_conversation_grant_operation_insert_error(
    error: sqlx::Error,
) -> AgentProvisioningOwnerError {
    if error
        .as_database_error()
        .and_then(|error| error.code())
        .is_some_and(|code| code == "23505")
    {
        AgentProvisioningOwnerError::Conflict
    } else {
        AgentProvisioningOwnerError::TemporarilyUnavailable
    }
}

fn map_connector_binding_state_operation_insert_error(
    error: sqlx::Error,
) -> AgentProvisioningOwnerError {
    map_conversation_grant_operation_insert_error(error)
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
    let mcp = mcp_router(backend.clone());
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
            "/v1/connector-bindings/{binding_id}/enable",
            post(post_connector_binding_enable),
        )
        .route(
            "/v1/connector-bindings/{binding_id}/disable",
            post(post_connector_binding_disable),
        )
        .route(
            "/v1/conversations/{conversation_id}/agent-grants/{installation_id}",
            put(put_conversation_grant).delete(delete_conversation_grant),
        )
        .route(
            "/v1/conversations/{source_conversation_id}/agent-routes/{route_id}/runs",
            post(post_agent_route_run),
        )
        .route(
            "/v1/agent-route-bootstraps",
            post(post_agent_route_bootstrap),
        )
        .route(
            "/v1/agent-route-bootstraps/{bootstrap_id}",
            get(get_agent_route_bootstrap),
        )
        .route(
            "/v1/agent-route-bootstraps/{bootstrap_id}/deliveries/{delivery_id}",
            put(put_agent_route_bootstrap_delivery),
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
            "/v1/agent-installations/{installation_id}/agent-route-target",
            get(get_agent_route_target),
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
        .merge(mcp)
}

async fn get_connectors(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let query = parse_connector_projection_query(uri.query())?;
        let representation = parse_connector_projection_representation(&headers)?;
        let credential = parse_device_session(&headers)?;
        match representation {
            ConnectorProjectionRepresentation::V1 => {
                backend.list_connectors(credential, query, now()?).await
            }
            ConnectorProjectionRepresentation::V2 => {
                backend.list_connectors_v2(credential, query, now()?).await
            }
            ConnectorProjectionRepresentation::V3 => {
                backend.list_connectors_v3(credential, query, now()?).await
            }
            ConnectorProjectionRepresentation::V4 => {
                backend.list_connectors_v4(credential, query, now()?).await
            }
        }
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

async fn post_connector_binding_enable(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path(binding_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    post_connector_binding_state(
        backend,
        binding_id,
        headers,
        body,
        ConnectorBindingStateOwnerAction::Enable,
    )
    .await
}

async fn post_connector_binding_disable(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path(binding_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    post_connector_binding_state(
        backend,
        binding_id,
        headers,
        body,
        ConnectorBindingStateOwnerAction::Disable,
    )
    .await
}

async fn post_connector_binding_state(
    backend: Arc<dyn AgentProvisioningOwnerBackend>,
    binding_id: String,
    headers: HeaderMap,
    body: Bytes,
    action: ConnectorBindingStateOwnerAction,
) -> Response {
    let result = async {
        require_content_type(&headers, CONNECTOR_BINDING_STATE_COMMAND_MEDIA_TYPE_V1)?;
        require_accept(&headers, CONNECTOR_BINDING_STATE_RECEIPT_MEDIA_TYPE_V1)?;
        bounded(&body, MAX_SMALL_BODY)?;
        let credential = parse_device_session(&headers)?;
        let operation_id = parse_connector_binding_state_operation(&headers)?;
        let expected_binding_revision = parse_connector_binding_state_fence(&headers)?;
        let binding_id = binding_id
            .parse::<BindingId>()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        let command = parse_connector_binding_state(&body, action)?;
        if command.operation_id != operation_id
            || command.expected_binding_revision != expected_binding_revision
            || command.binding_id != binding_id
        {
            return Err(AgentProvisioningOwnerError::InvalidRequest);
        }
        backend
            .mutate_connector_binding_state(credential, command, body.to_vec(), now()?)
            .await
    }
    .await;
    owner_response(result)
}

async fn put_conversation_grant(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path((conversation_id, installation_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    mutate_conversation_grant(
        backend,
        conversation_id,
        installation_id,
        headers,
        body,
        ConversationGrantOwnerAction::Grant,
    )
    .await
}

async fn delete_conversation_grant(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path((conversation_id, installation_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    mutate_conversation_grant(
        backend,
        conversation_id,
        installation_id,
        headers,
        body,
        ConversationGrantOwnerAction::Revoke,
    )
    .await
}

async fn mutate_conversation_grant(
    backend: Arc<dyn AgentProvisioningOwnerBackend>,
    conversation_id: String,
    installation_id: String,
    headers: HeaderMap,
    body: Bytes,
    action: ConversationGrantOwnerAction,
) -> Response {
    let result = async {
        require_content_type(&headers, CONVERSATION_GRANT_MEDIA_TYPE_V1)?;
        bounded(&body, MAX_SMALL_BODY)?;
        let credential = parse_device_session(&headers)?;
        let operation_id = parse_conversation_grant_operation(&headers)?;
        let expected_grant_version = parse_conversation_grant_fence(&headers)?;
        let conversation_id = conversation_id
            .parse::<ConversationId>()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        let installation_id = installation_id
            .parse::<InstallationId>()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        let command = parse_conversation_grant(&body, action)?;
        if command.operation_id != operation_id
            || command.expected_grant_version != expected_grant_version
            || command.conversation_id != conversation_id
            || command.installation_id != installation_id
        {
            return Err(AgentProvisioningOwnerError::InvalidRequest);
        }
        backend
            .mutate_conversation_grant(credential, command, body.to_vec(), now()?)
            .await
    }
    .await;
    owner_response(result)
}

async fn post_agent_route_run(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path((source_conversation_id, route_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = async {
        require_content_type(&headers, AGENT_ROUTE_RUN_MEDIA_TYPE_V1)?;
        bounded(&body, MAX_SMALL_BODY)?;
        let credential = parse_device_session(&headers)?;
        let operation_id = parse_agent_route_run_operation(&headers)?;
        let grant_version = parse_agent_route_run_fence(&headers)?;
        let source_conversation_id = source_conversation_id
            .parse::<ConversationId>()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        let route_id = route_id
            .parse::<ConversationId>()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        let command = parse_agent_route_run(&body)?;
        if source_conversation_id == route_id
            || command.operation_id != operation_id
            || command.grant_version != grant_version
            || command.source_conversation_id != source_conversation_id
            || command.route_id != route_id
        {
            return Err(AgentProvisioningOwnerError::InvalidRequest);
        }
        backend
            .create_agent_route_run(credential, command, body.to_vec(), now()?)
            .await
    }
    .await;
    owner_response(result)
}

async fn post_agent_route_bootstrap(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = async {
        require_content_type(&headers, AGENT_ROUTE_BOOTSTRAP_MEDIA_TYPE_V1)?;
        bounded(&body, MAX_SMALL_BODY)?;
        let credential = parse_device_session(&headers)?;
        let command = parse_agent_route_bootstrap_begin(&body)?;
        backend
            .begin_agent_route_bootstrap(credential, command, body.to_vec(), now()?)
            .await
    }
    .await;
    owner_response(result)
}

async fn get_agent_route_bootstrap(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path(bootstrap_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let credential = parse_device_session(&headers)?;
        let bootstrap_id = bootstrap_id
            .parse::<AgentRouteBootstrapId>()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        backend
            .get_agent_route_bootstrap(credential, bootstrap_id, now()?)
            .await
    }
    .await;
    owner_response(result)
}

async fn put_agent_route_bootstrap_delivery(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path((bootstrap_id, delivery_id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let result = async {
        require_content_type(&headers, AGENT_ROUTE_BOOTSTRAP_MEDIA_TYPE_V1)?;
        bounded(&body, MAX_DELIVERY_BODY)?;
        let credential = parse_device_session(&headers)?;
        let bootstrap_id = bootstrap_id
            .parse::<AgentRouteBootstrapId>()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        let delivery_id = delivery_id
            .parse::<AgentRouteDeliveryId>()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        let command = parse_agent_route_bootstrap_delivery(&body)?;
        if command.bootstrap_id != bootstrap_id || command.delivery_id != delivery_id {
            return Err(AgentProvisioningOwnerError::InvalidRequest);
        }
        backend
            .deliver_agent_route_bootstrap(credential, command, body.to_vec(), now()?)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectorProjectionRepresentation {
    V1,
    V2,
    V3,
    V4,
}

fn parse_connector_projection_representation(
    headers: &HeaderMap,
) -> Result<ConnectorProjectionRepresentation, AgentProvisioningOwnerError> {
    let mut values = headers.get_all(header::ACCEPT).iter();
    let Some(value) = values.next() else {
        return Ok(ConnectorProjectionRepresentation::V1);
    };
    if values.next().is_some() {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    match value
        .to_str()
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?
    {
        CONNECTOR_PROJECTION_MEDIA_TYPE_V1 => Ok(ConnectorProjectionRepresentation::V1),
        CONNECTOR_PROJECTION_MEDIA_TYPE_V2 => Ok(ConnectorProjectionRepresentation::V2),
        CONNECTOR_PROJECTION_MEDIA_TYPE_V3 => Ok(ConnectorProjectionRepresentation::V3),
        CONNECTOR_PROJECTION_MEDIA_TYPE_V4 => Ok(ConnectorProjectionRepresentation::V4),
        _ => Err(AgentProvisioningOwnerError::InvalidRequest),
    }
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

async fn get_agent_route_target(
    State(backend): State<Arc<dyn AgentProvisioningOwnerBackend>>,
    Path(installation_id): Path<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let result = async {
        let binding_id = parse_agent_route_target_query(uri.query())?;
        let credential = parse_device_session(&headers)?;
        let installation_id = installation_id
            .parse()
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
        backend
            .get_agent_route_target(credential, installation_id, binding_id, now()?)
            .await
    }
    .await;
    owner_response(result)
}

fn parse_agent_route_target_query(
    query: Option<&str>,
) -> Result<BindingId, AgentProvisioningOwnerError> {
    let query = query.ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    let mut binding_id = None;
    for pair in query.split('&') {
        let (name, value) = pair
            .split_once('=')
            .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
        match name {
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
    binding_id.ok_or(AgentProvisioningOwnerError::InvalidRequest)
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

fn parse_connector_binding_state(
    body: &[u8],
    expected_action: ConnectorBindingStateOwnerAction,
) -> Result<ConnectorBindingStateOwnerCommand, AgentProvisioningOwnerError> {
    let request = exact_map(
        decode_deterministic_cbor(body).map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
        3,
    )?;
    let binding = map_value(&request, 1)?.clone();
    let fields = exact_map(binding.clone(), 9)?;
    expect_version(&fields)?;
    let action = match unsigned_int(&fields, 2)? {
        1 => ConnectorBindingStateOwnerAction::Enable,
        2 => ConnectorBindingStateOwnerAction::Disable,
        _ => return Err(AgentProvisioningOwnerError::InvalidRequest),
    };
    if action != expected_action {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let supplied = digest(map_value(&request, 2)?)?;
    if supplied != binding_hash(CONNECTOR_BINDING_STATE_BINDING_DOMAIN, &binding)? {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    Ok(ConnectorBindingStateOwnerCommand {
        action,
        tenant_id: text_id(&fields, 3)?,
        binding_id: text_id(&fields, 4)?,
        expected_binding_revision: revision(&fields, 5)?,
        operation_id: text_id(&fields, 6)?,
        owner_identity_id: text_id(&fields, 7)?,
        owner_device_id: text_id(&fields, 8)?,
        proof_expires_at: utc(&fields, 9)?,
        binding_digest: supplied,
        owner_signature: Ed25519Signature::from_bytes(bytes_array(map_value(&request, 3)?)?),
    })
}

fn parse_conversation_grant(
    body: &[u8],
    expected_action: ConversationGrantOwnerAction,
) -> Result<ConversationGrantOwnerCommand, AgentProvisioningOwnerError> {
    let request = exact_map(
        decode_deterministic_cbor(body).map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
        3,
    )?;
    let binding = map_value(&request, 1)?.clone();
    let fields = exact_map(binding.clone(), 12)?;
    expect_version(&fields)?;
    let action = match unsigned_int(&fields, 2)? {
        1 => ConversationGrantOwnerAction::Grant,
        2 => ConversationGrantOwnerAction::Revoke,
        _ => return Err(AgentProvisioningOwnerError::InvalidRequest),
    };
    if action != expected_action {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let supplied = digest(map_value(&request, 2)?)?;
    if supplied != binding_hash(CONVERSATION_GRANT_BINDING_DOMAIN, &binding)? {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let grant_expires_at = nullable_utc(&fields, 11)?;
    let privacy_policy_hash = nullable_digest(&fields, 12)?;
    match action {
        ConversationGrantOwnerAction::Grant
            if grant_expires_at.is_none() || privacy_policy_hash.is_none() =>
        {
            return Err(AgentProvisioningOwnerError::InvalidRequest);
        }
        ConversationGrantOwnerAction::Revoke
            if grant_expires_at.is_some() || privacy_policy_hash.is_some() =>
        {
            return Err(AgentProvisioningOwnerError::InvalidRequest);
        }
        _ => {}
    }
    Ok(ConversationGrantOwnerCommand {
        action,
        operation_id: text_id(&fields, 6)?,
        tenant_id: text_id(&fields, 3)?,
        conversation_id: text_id(&fields, 4)?,
        installation_id: text_id(&fields, 5)?,
        expected_grant_version: expected_grant_version(&fields, 7)?,
        owner_identity_id: text_id(&fields, 8)?,
        owner_device_id: text_id(&fields, 9)?,
        proof_expires_at: utc(&fields, 10)?,
        grant_expires_at,
        privacy_policy_hash,
        binding_digest: supplied,
        owner_signature: Ed25519Signature::from_bytes(bytes_array(map_value(&request, 3)?)?),
    })
}

fn parse_agent_route_bootstrap_begin(
    body: &[u8],
) -> Result<AgentRouteBootstrapBeginCommand, AgentProvisioningOwnerError> {
    let request = exact_map(
        decode_deterministic_cbor(body).map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
        3,
    )?;
    let binding = map_value(&request, 1)?.clone();
    let fields = exact_map(binding.clone(), 10)?;
    expect_version(&fields)?;
    let binding_digest = digest(map_value(&request, 2)?)?;
    if binding_digest != binding_hash(crate::AGENT_ROUTE_BOOTSTRAP_BEGIN_BINDING_DOMAIN, &binding)?
    {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    Ok(AgentRouteBootstrapBeginCommand {
        bootstrap_id: text_id(&fields, 2)?,
        tenant_id: text_id(&fields, 3)?,
        installation_id: text_id(&fields, 4)?,
        binding_id: text_id(&fields, 5)?,
        agent_control_device_id: text_id(&fields, 6)?,
        owner_identity_id: text_id(&fields, 7)?,
        owner_device_id: text_id(&fields, 8)?,
        expires_at: utc(&fields, 9)?,
        owner_signed_intent: bytes(map_value(&fields, 10)?)?.to_vec(),
        binding_digest,
        owner_signature: Ed25519Signature::from_bytes(bytes_array(map_value(&request, 3)?)?),
    })
}

fn parse_agent_route_bootstrap_delivery(
    body: &[u8],
) -> Result<AgentRouteBootstrapDeliveryCommand, AgentProvisioningOwnerError> {
    let request = exact_map(
        decode_deterministic_cbor(body).map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
        3,
    )?;
    let binding = map_value(&request, 1)?.clone();
    let fields = match binding.clone() {
        CanonicalValue::Map(fields) if fields.len() == 14 => {
            if unsigned_int(&fields, 1)? != 1 {
                return Err(AgentProvisioningOwnerError::InvalidRequest);
            }
            fields
        }
        CanonicalValue::Map(fields) if fields.len() == 16 => {
            if unsigned_int(&fields, 1)? != 2 {
                return Err(AgentProvisioningOwnerError::InvalidRequest);
            }
            fields
        }
        _ => return Err(AgentProvisioningOwnerError::InvalidRequest),
    };
    let binding_digest = digest(map_value(&request, 2)?)?;
    let binding_domain = if fields.len() == 16 {
        crate::agent_route_bootstrap::AGENT_ROUTE_BOOTSTRAP_DELIVERY_BINDING_DOMAIN_V2
    } else {
        crate::AGENT_ROUTE_BOOTSTRAP_DELIVERY_BINDING_DOMAIN
    };
    if binding_digest != binding_hash(binding_domain, &binding)? {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let server_receipt_key_id = (fields.len() == 16)
        .then(|| text_id(&fields, 15))
        .transpose()?;
    let server_receipt_public_key_digest = (fields.len() == 16)
        .then(|| digest(map_value(&fields, 16)?))
        .transpose()?;
    Ok(AgentRouteBootstrapDeliveryCommand {
        bootstrap_id: text_id(&fields, 2)?,
        delivery_id: text_id(&fields, 3)?,
        tenant_id: text_id(&fields, 4)?,
        installation_id: text_id(&fields, 5)?,
        binding_id: text_id(&fields, 6)?,
        agent_control_device_id: text_id(&fields, 7)?,
        owner_identity_id: text_id(&fields, 8)?,
        owner_device_id: text_id(&fields, 9)?,
        recipient_id: text_id(&fields, 10)?,
        route_id: text_id(&fields, 11)?,
        capsule_digest: digest(map_value(&fields, 12)?)?,
        opaque_sealed_bootstrap: bytes(map_value(&fields, 13)?)?.to_vec(),
        expires_at: utc(&fields, 14)?,
        binding_digest,
        owner_signature: Ed25519Signature::from_bytes(bytes_array(map_value(&request, 3)?)?),
        server_receipt_key_id,
        server_receipt_public_key_digest,
    })
}

fn parse_agent_route_run(
    body: &[u8],
) -> Result<AgentRouteRunOwnerCommand, AgentProvisioningOwnerError> {
    let request = exact_map(
        decode_deterministic_cbor(body).map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?,
        3,
    )?;
    let binding = map_value(&request, 1)?.clone();
    let fields = exact_map(binding.clone(), 14)?;
    expect_version(&fields)?;
    let supplied = digest(map_value(&request, 2)?)?;
    if supplied != binding_hash(AGENT_ROUTE_RUN_BINDING_DOMAIN, &binding)? {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let source_conversation_id = text_id(&fields, 3)?;
    let route_id = text_id(&fields, 4)?;
    if source_conversation_id == route_id {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let command = AgentRouteRunOwnerCommand {
        tenant_id: text_id(&fields, 2)?,
        source_conversation_id,
        route_id,
        installation_id: text_id(&fields, 5)?,
        binding_id: text_id(&fields, 12)?,
        agent_control_device_id: text_id(&fields, 13)?,
        route_fence: bytes_array(map_value(&fields, 14)?)?,
        request_event_id: text_id(&fields, 6)?,
        operation_id: text_id(&fields, 7)?,
        grant_version: revision(&fields, 8)?,
        owner_identity_id: text_id(&fields, 9)?,
        owner_device_id: text_id(&fields, 10)?,
        proof_expires_at: utc(&fields, 11)?,
        binding_digest: supplied,
        owner_signature: Ed25519Signature::from_bytes(bytes_array(map_value(&request, 3)?)?),
    };
    if command.request_event_id.as_uuid() != command.operation_id.as_uuid() {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    Ok(command)
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
fn nullable_utc(
    fields: &Fields,
    key: u64,
) -> Result<Option<UtcMillis>, AgentProvisioningOwnerError> {
    if matches!(map_value(fields, key)?, CanonicalValue::Null) {
        Ok(None)
    } else {
        utc(fields, key).map(Some)
    }
}
fn nullable_digest(
    fields: &Fields,
    key: u64,
) -> Result<Option<PrivacyPolicyDigest>, AgentProvisioningOwnerError> {
    if matches!(map_value(fields, key)?, CanonicalValue::Null) {
        Ok(None)
    } else {
        digest(map_value(fields, key)?)
            .map(|digest| PrivacyPolicyDigest::from_bytes(*digest.as_bytes()))
            .map(Some)
    }
}
fn expected_grant_version(
    fields: &Fields,
    key: u64,
) -> Result<Option<Revision>, AgentProvisioningOwnerError> {
    match unsigned_int(fields, key)? {
        0 => Ok(None),
        value => Revision::new(value)
            .map(Some)
            .map_err(|_| AgentProvisioningOwnerError::InvalidRequest),
    }
}
fn binding_hash(
    domain: &[u8],
    value: &CanonicalValue,
) -> Result<Sha256Digest, AgentProvisioningOwnerError> {
    let bytes = encode_deterministic_cbor(value)
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)?;
    Ok(Sha256Digest::hash_domain(domain, &bytes))
}

pub(crate) fn parse_device_session(
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

fn parse_conversation_grant_operation(
    headers: &HeaderMap,
) -> Result<RequestId, AgentProvisioningOwnerError> {
    let mut values = headers.get_all("idempotency-key").iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    if values.next().is_some() {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    value
        .parse()
        .map_err(|_| AgentProvisioningOwnerError::InvalidRequest)
}

fn parse_connector_binding_state_operation(
    headers: &HeaderMap,
) -> Result<RequestId, AgentProvisioningOwnerError> {
    parse_conversation_grant_operation(headers)
}

fn parse_agent_route_run_operation(
    headers: &HeaderMap,
) -> Result<RequestId, AgentProvisioningOwnerError> {
    parse_conversation_grant_operation(headers)
}

fn parse_conversation_grant_fence(
    headers: &HeaderMap,
) -> Result<Option<Revision>, AgentProvisioningOwnerError> {
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
    if value.is_empty() || !value.bytes().all(|value| value.is_ascii_digit()) {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    if value == "0" {
        return Ok(None);
    }
    if value.starts_with('0') {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    value
        .parse::<u64>()
        .ok()
        .and_then(|value| Revision::new(value).ok())
        .map(Some)
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)
}

fn parse_agent_route_run_fence(
    headers: &HeaderMap,
) -> Result<Revision, AgentProvisioningOwnerError> {
    parse_conversation_grant_fence(headers)?.ok_or(AgentProvisioningOwnerError::InvalidRequest)
}

fn parse_connector_binding_state_fence(
    headers: &HeaderMap,
) -> Result<Revision, AgentProvisioningOwnerError> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    if values.next().is_some() {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    let value = value
        .strip_prefix("\"b")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)?;
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|value| value.is_ascii_digit())
    {
        return Err(AgentProvisioningOwnerError::InvalidRequest);
    }
    value
        .parse::<u64>()
        .ok()
        .and_then(|revision| Revision::new(revision).ok())
        .ok_or(AgentProvisioningOwnerError::InvalidRequest)
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
fn require_accept(headers: &HeaderMap, expected: &str) -> Result<(), AgentProvisioningOwnerError> {
    let mut values = headers.get_all(header::ACCEPT).iter();
    let value = values
        .next()
        .and_then(|value| value.to_str().ok())
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
    use dtx_agent_registry::PrivacyPolicyDigest;
    use dtx_domain::{
        AgentDeviceId, AgentRouteBootstrapId, AgentRouteDeliveryId, AgentRouteRecipientId,
        BindingId, ConversationId, DeviceId, GrantId, InstallationId, RequestId, Revision,
        RouteHealthKeyId, TenantId,
    };
    use dtx_wire::{CanonicalValue, decode_deterministic_cbor, encode_deterministic_cbor};
    use dtx_wire::{Sha256Digest, UtcMillis};
    use serde_json::Value;

    use super::{
        AgentProvisioningDeliveryReceipt, AgentProvisioningOwnerError,
        ConversationGrantOwnerAction, PRIVATE_CONVERSATION_PROFILE_V1,
        PRIVATE_CONVERSATION_TOOLS_PROFILE_V1, REVOCATION_BINDING_DOMAIN, agent_route_target_cbor,
        approval_status, conversation_grant_receipt_cbor, delivery_receipt_cbor, delivery_status,
        parse_agent_route_bootstrap_delivery, parse_approval, parse_connector_projection_query,
        parse_connector_projection_representation, parse_conversation_grant,
        parse_conversation_grant_fence, parse_conversation_grant_operation, parse_delivery,
        parse_device_session, parse_idempotency, parse_revocation,
        private_conversation_permissions,
    };

    const VECTORS: &str = include_str!(
        "../../../protocol/test-vectors/agent-provisioning/v1/agent-provisioning-v1.json"
    );
    const CONVERSATION_GRANT_VECTORS: &str = include_str!(
        "../../../protocol/test-vectors/conversation-agent-grant/v1/conversation-agent-grant-v1.json"
    );

    #[test]
    fn frozen_private_conversation_grant_vectors_bind_headers_and_receipts() {
        let vectors: Value = serde_json::from_str(CONVERSATION_GRANT_VECTORS).unwrap();
        let tenant_id: TenantId = vectors["tenant_id"].as_str().unwrap().parse().unwrap();
        let conversation_id: ConversationId = vectors["conversation_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let installation_id: InstallationId = vectors["installation_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let owner_device_id: DeviceId = vectors["owner_device_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let grant_id: GrantId = vectors["server_generated_grant_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let grant = &vectors["grant"];
        let grant_body = hex(grant["request_canonical_cbor_hex"].as_str().unwrap());
        let command =
            parse_conversation_grant(&grant_body, ConversationGrantOwnerAction::Grant).unwrap();
        assert_eq!(command.tenant_id, tenant_id);
        assert_eq!(command.conversation_id, conversation_id);
        assert_eq!(command.installation_id, installation_id);
        assert_eq!(
            command.operation_id.to_string(),
            grant["operation_id"].as_str().unwrap()
        );
        assert_eq!(command.expected_grant_version, None);
        assert_eq!(command.grant_expires_at.unwrap().get(), 8_640_000);

        let mut headers = HeaderMap::new();
        headers.insert(
            "idempotency-key",
            HeaderValue::from_str(grant["operation_id"].as_str().unwrap()).unwrap(),
        );
        headers.insert(
            header::IF_MATCH,
            HeaderValue::from_str(grant["if_match"].as_str().unwrap()).unwrap(),
        );
        assert_eq!(
            parse_conversation_grant_operation(&headers).unwrap(),
            command.operation_id
        );
        assert_eq!(parse_conversation_grant_fence(&headers).unwrap(), None);

        let privacy_hash: [u8; 32] = hex(grant["privacy_policy_hash_hex"].as_str().unwrap())
            .try_into()
            .unwrap();
        let receipt = conversation_grant_receipt_cbor(
            ConversationGrantOwnerAction::Grant,
            tenant_id,
            conversation_id,
            installation_id,
            grant_id,
            Revision::INITIAL,
            PrivacyPolicyDigest::from_bytes(privacy_hash),
            owner_device_id,
            // The frozen receipt records the durable commit instant, which is
            // deliberately later than the request's sampled server time.
            UtcMillis::new(1_000_050).unwrap(),
            Some(grant["grant_expires_at_ms"].as_i64().unwrap()),
        )
        .unwrap();
        assert_eq!(
            receipt,
            hex(grant["receipt_canonical_cbor_hex"].as_str().unwrap())
        );

        let revoke = &vectors["revoke"];
        let revoke_body = hex(revoke["request_canonical_cbor_hex"].as_str().unwrap());
        let command =
            parse_conversation_grant(&revoke_body, ConversationGrantOwnerAction::Revoke).unwrap();
        assert_eq!(command.expected_grant_version, Some(Revision::INITIAL));
        assert!(command.grant_expires_at.is_none());
        assert!(command.privacy_policy_hash.is_none());
        let mut changed = decode_deterministic_cbor(&revoke_body).unwrap();
        let CanonicalValue::Map(fields) = &mut changed else {
            panic!("frozen revoke request must be a CBOR map");
        };
        let (_, CanonicalValue::Bytes(binding_digest)) = fields
            .iter_mut()
            .find(|(key, _)| *key == CanonicalValue::Unsigned(2))
            .unwrap()
        else {
            panic!("frozen revoke request must carry its binding digest");
        };
        binding_digest[0] ^= 1;
        let changed = encode_deterministic_cbor(&changed).unwrap();
        assert_eq!(
            parse_conversation_grant(&changed, ConversationGrantOwnerAction::Revoke),
            Err(AgentProvisioningOwnerError::InvalidRequest)
        );
    }

    #[test]
    fn signed_private_conversation_profile_controls_tool_authority_exactly() {
        use dtx_agent_registry::AgentConversationPermission;

        let digest = |profile: &[u8]| {
            PrivacyPolicyDigest::from_bytes(*Sha256Digest::hash_domain(&[], profile).as_bytes())
        };
        let chat = private_conversation_permissions(digest(PRIVATE_CONVERSATION_PROFILE_V1))
            .expect("the fixed no-tools profile is supported");
        assert!(!chat.contains(AgentConversationPermission::InvokeTools));

        let tools = private_conversation_permissions(digest(PRIVATE_CONVERSATION_TOOLS_PROFILE_V1))
            .expect("the fixed tools profile is supported");
        assert!(tools.contains(AgentConversationPermission::InvokeTools));
        assert_eq!(
            digest(PRIVATE_CONVERSATION_TOOLS_PROFILE_V1)
                .as_bytes()
                .as_slice(),
            hex("a2b7854914565e4716ce65af4f7d8844293c78131545cb467f7922fca4491476")
        );

        assert_eq!(
            private_conversation_permissions(PrivacyPolicyDigest::from_bytes([9; 32])),
            Err(AgentProvisioningOwnerError::InvalidRequest)
        );
    }

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
    fn connector_projection_accept_selects_only_published_versions() {
        let headers = HeaderMap::new();
        assert_eq!(
            parse_connector_projection_representation(&headers),
            Ok(super::ConnectorProjectionRepresentation::V1)
        );

        for (media_type, expected) in [
            (
                crate::connector_projection::CONNECTOR_PROJECTION_MEDIA_TYPE_V1,
                super::ConnectorProjectionRepresentation::V1,
            ),
            (
                crate::connector_projection::CONNECTOR_PROJECTION_MEDIA_TYPE_V2,
                super::ConnectorProjectionRepresentation::V2,
            ),
            (
                crate::connector_projection::CONNECTOR_PROJECTION_MEDIA_TYPE_V3,
                super::ConnectorProjectionRepresentation::V3,
            ),
            (
                crate::connector_projection::CONNECTOR_PROJECTION_MEDIA_TYPE_V4,
                super::ConnectorProjectionRepresentation::V4,
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, HeaderValue::from_static(media_type));
            assert_eq!(
                parse_connector_projection_representation(&headers),
                Ok(expected)
            );
        }

        for rejected in ["application/json", "*/*"] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, HeaderValue::from_static(rejected));
            assert_eq!(
                parse_connector_projection_representation(&headers),
                Err(AgentProvisioningOwnerError::InvalidRequest),
                "unsupported accept must be rejected: {rejected}"
            );
        }

        let mut duplicate = HeaderMap::new();
        duplicate.append(
            header::ACCEPT,
            HeaderValue::from_static(
                crate::connector_projection::CONNECTOR_PROJECTION_MEDIA_TYPE_V1,
            ),
        );
        duplicate.append(
            header::ACCEPT,
            HeaderValue::from_static(
                crate::connector_projection::CONNECTOR_PROJECTION_MEDIA_TYPE_V2,
            ),
        );
        assert_eq!(
            parse_connector_projection_representation(&duplicate),
            Err(AgentProvisioningOwnerError::InvalidRequest)
        );
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

    #[test]
    fn route_bootstrap_target_projection_keeps_legacy_and_pinned_shapes_distinct() {
        let tenant_id: TenantId = "0190f2a5-7b1c-7abc-8def-012345678901".parse().unwrap();
        let installation_id: InstallationId =
            "0190f2a5-7b1c-7abc-8def-012345678902".parse().unwrap();
        let binding_id: BindingId = "0190f2a5-7b1c-7abc-8def-012345678903".parse().unwrap();
        let device_id: AgentDeviceId = "0190f2a5-7b1c-7abc-8def-012345678904".parse().unwrap();
        let legacy = agent_route_target_cbor(
            tenant_id,
            installation_id,
            binding_id,
            device_id,
            None,
            None,
        )
        .unwrap();
        let legacy_value = decode_deterministic_cbor(&legacy).unwrap();
        let CanonicalValue::Map(legacy_fields) = legacy_value else {
            panic!("target projection must be a map")
        };
        assert_eq!(legacy_fields.len(), 5);
        assert_eq!(legacy_fields[0].1, CanonicalValue::Unsigned(1));

        let key_id = RouteHealthKeyId::new();
        let public_key = [0x42; 32];
        let pinned = agent_route_target_cbor(
            tenant_id,
            installation_id,
            binding_id,
            device_id,
            Some(key_id),
            Some(public_key),
        )
        .unwrap();
        let pinned_value = decode_deterministic_cbor(&pinned).unwrap();
        let CanonicalValue::Map(pinned_fields) = pinned_value else {
            panic!("target projection must be a map")
        };
        assert_eq!(pinned_fields.len(), 7);
        assert_eq!(pinned_fields[0].1, CanonicalValue::Unsigned(2));
        assert_eq!(pinned_fields[5].0, CanonicalValue::Unsigned(6));
        assert_eq!(pinned_fields[6].0, CanonicalValue::Unsigned(7));
        assert_eq!(
            pinned_fields[6].1,
            CanonicalValue::Bytes(public_key.to_vec())
        );
        assert_ne!(legacy, pinned);
    }

    #[test]
    fn route_bootstrap_delivery_v2_requires_an_exact_receipt_pin_pair() {
        let key_id = RouteHealthKeyId::new();
        let digest = [0x55; 32];
        let mut fields = route_bootstrap_delivery_fields(Some(key_id), Some(digest.to_vec()));
        let encoded = route_bootstrap_delivery_body(&fields);
        let parsed = parse_agent_route_bootstrap_delivery(&encoded).unwrap();
        assert_eq!(parsed.server_receipt_key_id, Some(key_id));
        assert_eq!(
            parsed.server_receipt_public_key_digest.unwrap().as_bytes(),
            &digest
        );

        fields.retain(|(key, _)| *key != CanonicalValue::Unsigned(15));
        assert_eq!(
            parse_agent_route_bootstrap_delivery(&route_bootstrap_delivery_body(&fields)),
            Err(AgentProvisioningOwnerError::InvalidRequest)
        );
        let mut fields = route_bootstrap_delivery_fields(Some(key_id), Some(digest.to_vec()));
        fields.retain(|(key, _)| *key != CanonicalValue::Unsigned(16));
        assert_eq!(
            parse_agent_route_bootstrap_delivery(&route_bootstrap_delivery_body(&fields)),
            Err(AgentProvisioningOwnerError::InvalidRequest)
        );

        let mut fields = route_bootstrap_delivery_fields(Some(key_id), Some(digest.to_vec()));
        fields[14].1 = CanonicalValue::Text(RouteHealthKeyId::new().to_string());
        // Parsing preserves the supplied pair; the transaction fence compares it
        // against the persisted bootstrap snapshot before any mutation.
        let parsed =
            parse_agent_route_bootstrap_delivery(&route_bootstrap_delivery_body(&fields)).unwrap();
        assert_ne!(parsed.server_receipt_key_id, Some(key_id));
    }

    #[test]
    fn route_bootstrap_delivery_v1_has_no_pin_fields_and_is_byte_stable() {
        let fields = route_bootstrap_delivery_fields(None, None);
        let encoded = route_bootstrap_delivery_body(&fields);
        let parsed = parse_agent_route_bootstrap_delivery(&encoded).unwrap();
        assert_eq!(parsed.server_receipt_key_id, None);
        assert_eq!(parsed.server_receipt_public_key_digest, None);
        assert_eq!(
            encoded,
            encode_deterministic_cbor(&decode_deterministic_cbor(&encoded).unwrap()).unwrap()
        );
    }

    fn route_bootstrap_delivery_fields(
        key_id: Option<RouteHealthKeyId>,
        digest: Option<Vec<u8>>,
    ) -> Vec<(CanonicalValue, CanonicalValue)> {
        let bootstrap_id = AgentRouteBootstrapId::new();
        let delivery_id = AgentRouteDeliveryId::new();
        let tenant_id = TenantId::new();
        let installation_id = InstallationId::new();
        let binding_id = BindingId::new();
        let agent_device_id = AgentDeviceId::new();
        let owner_id: dtx_domain::IdentityId =
            "dtxi155pujebuvamvkmouxx6okeiijjuzjxxw4ktjahrjy6z27frlobiq"
                .parse()
                .unwrap();
        let owner_device_id = DeviceId::new();
        let recipient_id = AgentRouteRecipientId::new();
        let route_id = ConversationId::new();
        let capsule = vec![0x77; 16];
        let capsule_digest =
            Sha256Digest::hash_domain(b"dirextalk.agent-route-bootstrap-capsule.v1\0", &capsule);
        let mut fields = vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(bootstrap_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(delivery_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text(tenant_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Text(installation_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Text(binding_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Text(agent_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Text(owner_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(9),
                CanonicalValue::Text(owner_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(10),
                CanonicalValue::Text(recipient_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(11),
                CanonicalValue::Text(route_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(12),
                CanonicalValue::Bytes(capsule_digest.as_bytes().to_vec()),
            ),
            (CanonicalValue::Unsigned(13), CanonicalValue::Bytes(capsule)),
            (
                CanonicalValue::Unsigned(14),
                CanonicalValue::Unsigned(1_756_700_000_000),
            ),
        ];
        if let (Some(key_id), Some(digest)) = (key_id, digest) {
            fields.push((
                CanonicalValue::Unsigned(15),
                CanonicalValue::Text(key_id.to_string()),
            ));
            fields.push((CanonicalValue::Unsigned(16), CanonicalValue::Bytes(digest)));
        } else {
            fields[0].1 = CanonicalValue::Unsigned(1);
        }
        fields
    }

    fn route_bootstrap_delivery_body(fields: &[(CanonicalValue, CanonicalValue)]) -> Vec<u8> {
        let binding = CanonicalValue::Map(fields.to_vec());
        let binding_bytes = encode_deterministic_cbor(&binding).unwrap();
        let binding_domain = if fields.len() == 16 {
            crate::agent_route_bootstrap::AGENT_ROUTE_BOOTSTRAP_DELIVERY_BINDING_DOMAIN_V2
        } else {
            crate::AGENT_ROUTE_BOOTSTRAP_DELIVERY_BINDING_DOMAIN
        };
        let binding_digest = Sha256Digest::hash_domain(binding_domain, &binding_bytes);
        encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), binding),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Bytes(binding_digest.as_bytes().to_vec()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Bytes(vec![0; 64]),
            ),
        ]))
        .unwrap()
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
