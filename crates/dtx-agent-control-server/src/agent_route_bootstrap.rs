//! Durable, opaque RouteBootstrapV1 application boundary.
//!
//! Owner Begin and Delivery atomically append authenticated durable Connector
//! commands with their bootstrap records.  Only the authenticated Connector
//! result path may advance a bootstrap to `Installed`; no HTTP action can
//! manufacture an eligible binding head.

use std::collections::BTreeMap;
use std::fmt;

use dtx_agent_control::{
    DeliverAgentRouteBootstrap, DurableServerCommand, DurableServerCommandSnapshot,
    OpaqueAgentRouteBytes, PrepareAgentRouteRecipient, ServerCommandPayload,
    Sha256Digest as ControlSha256Digest,
};
use dtx_agent_persistence::{AgentPersistenceError, CommandLogRepository};
use dtx_domain::{
    AgentDeviceId, AgentRouteBootstrapId, AgentRouteDeliveryId, AgentRouteRecipientId, BindingId,
    ConnectorId, ConversationId, DeviceId, IdentityId, InstallationId, OutboxId, RequestId,
    Revision, RouteHealthKeyId, TenantId,
};
use dtx_identity_persistence::{DeviceSessionCredential, DeviceSessionRepository};
use dtx_storage::PgStore;
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, Sha256Digest, UtcMillis,
    decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sqlx::Row;
use uuid::Uuid;

use crate::{ProtobufDurableCommandDecoder, ProtobufDurableCommandEncoder};

pub const AGENT_ROUTE_BOOTSTRAP_BEGIN_BINDING_DOMAIN: &[u8] =
    b"dirextalk.agent-route-bootstrap-begin-binding.v1\0";
pub const AGENT_ROUTE_BOOTSTRAP_BEGIN_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.agent-route-bootstrap-begin-signature.v1\0";
pub const AGENT_ROUTE_BOOTSTRAP_BEGIN_REQUEST_DOMAIN: &[u8] =
    b"dirextalk.agent-route-bootstrap-begin-request.v1\0";
pub const AGENT_ROUTE_BOOTSTRAP_BEGIN_RECEIPT_DOMAIN: &[u8] =
    b"dirextalk.agent-route-bootstrap-begin-receipt.v1\0";
pub const AGENT_ROUTE_BOOTSTRAP_DELIVERY_BINDING_DOMAIN: &[u8] =
    b"dirextalk.agent-route-bootstrap-delivery-binding.v1\0";
pub const AGENT_ROUTE_BOOTSTRAP_DELIVERY_BINDING_DOMAIN_V2: &[u8] =
    b"dirextalk.agent-route-bootstrap-delivery-binding.v2\0";
pub const AGENT_ROUTE_BOOTSTRAP_DELIVERY_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.agent-route-bootstrap-delivery-signature.v1\0";
pub const AGENT_ROUTE_BOOTSTRAP_DELIVERY_REQUEST_DOMAIN: &[u8] =
    b"dirextalk.agent-route-bootstrap-delivery-request.v1\0";
pub const AGENT_ROUTE_BOOTSTRAP_DELIVERY_REQUEST_DOMAIN_V2: &[u8] =
    b"dirextalk.agent-route-bootstrap-delivery-request.v2\0";
pub const AGENT_ROUTE_BOOTSTRAP_DELIVERY_RECEIPT_DOMAIN: &[u8] =
    b"dirextalk.agent-route-bootstrap-delivery-receipt.v1\0";
pub const AGENT_ROUTE_BOOTSTRAP_DELIVERY_RECEIPT_DOMAIN_V2: &[u8] =
    b"dirextalk.agent-route-bootstrap-delivery-receipt.v2\0";
pub const AGENT_ROUTE_RECIPIENT_CAPSULE_DOMAIN: &[u8] =
    b"dirextalk.agent-route-recipient-capsule.v1\0";
pub const AGENT_ROUTE_BOOTSTRAP_CAPSULE_DOMAIN: &[u8] =
    b"dirextalk.agent-route-bootstrap-capsule.v1\0";
pub const AGENT_ROUTE_BOOTSTRAP_OUTBOX_DOMAIN: &[u8] =
    b"dirextalk.agent-route-bootstrap-outbox.v1\0";
pub const AGENT_ROUTE_HEALTH_PUBLIC_KEY_DOMAIN: &[u8] =
    b"dirextalk.agent-route-health-public-key.v1\0";

const MAX_OPAQUE_BYTES: usize = 196_608;
const MAX_RECEIPT_BYTES: usize = 65_536;
const MAX_BOOTSTRAP_LIFETIME_MS: i64 = 90 * 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRouteBootstrapState {
    PendingRecipient,
    RecipientReady,
    PendingDelivery,
    Installed,
    Rejected,
    Expired,
    Revoked,
}

impl AgentRouteBootstrapState {
    const fn receipt_code(self) -> u64 {
        match self {
            Self::PendingRecipient => 1,
            Self::RecipientReady => 2,
            Self::PendingDelivery => 3,
            Self::Installed => 4,
            Self::Rejected => 5,
            Self::Expired => 6,
            Self::Revoked => 7,
        }
    }

    fn parse(value: &str) -> Result<Self, AgentRouteBootstrapError> {
        match value {
            "pending_recipient" => Ok(Self::PendingRecipient),
            "recipient_ready" => Ok(Self::RecipientReady),
            "pending_delivery" => Ok(Self::PendingDelivery),
            "installed" => Ok(Self::Installed),
            "rejected" => Ok(Self::Rejected),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            _ => Err(AgentRouteBootstrapError::Unavailable),
        }
    }
}

/// Stable public failure classification for the owner HTTP boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRouteBootstrapError {
    InvalidRequest,
    AuthenticationRejected,
    Forbidden,
    NotFound,
    Conflict,
    Unavailable,
}

impl fmt::Display for AgentRouteBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "invalid AgentRoute bootstrap request",
            Self::AuthenticationRejected => "AgentRoute bootstrap authentication rejected",
            Self::Forbidden => "AgentRoute bootstrap forbidden",
            Self::NotFound => "AgentRoute bootstrap not found",
            Self::Conflict => "AgentRoute bootstrap conflict",
            Self::Unavailable => "AgentRoute bootstrap temporarily unavailable",
        })
    }
}

impl std::error::Error for AgentRouteBootstrapError {}

/// One active, Owner-scoped Connector binding suitable for RouteBootstrap.
///
/// The Connector identifier is retained only for the in-process durable
/// command append.  It must never be returned by the Owner HTTP target
/// discovery representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AgentRouteBootstrapTarget {
    pub connector_id: ConnectorId,
    pub agent_control_device_id: AgentDeviceId,
    pub server_receipt_key_id: Option<RouteHealthKeyId>,
    pub server_receipt_public_key: Option<[u8; 32]>,
}

/// Owner-signed Begin intent.  The MLS route fence does not exist yet at this
/// point: it is created by the local import and accepted only from its
/// authenticated `Installed` receipt.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentRouteBootstrapBeginCommand {
    pub bootstrap_id: AgentRouteBootstrapId,
    pub tenant_id: TenantId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub agent_control_device_id: AgentDeviceId,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    /// Native-only opaque Owner intent for the isolated route.  It is neither
    /// parsed nor logged by the server and is forwarded verbatim to Agent
    /// Control inside the durable Prepare command.
    pub owner_signed_intent: Vec<u8>,
    pub expires_at: UtcMillis,
    pub binding_digest: Sha256Digest,
    pub owner_signature: Ed25519Signature,
}

impl fmt::Debug for AgentRouteBootstrapBeginCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentRouteBootstrapBeginCommand")
            .field("bootstrap_id", &self.bootstrap_id)
            .field("tenant_id", &self.tenant_id)
            .field("installation_id", &self.installation_id)
            .field("binding_id", &self.binding_id)
            .field("agent_control_device_id", &self.agent_control_device_id)
            .field("owner_identity_id", &self.owner_identity_id)
            .field("owner_device_id", &self.owner_device_id)
            .field("owner_signed_intent", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Owner-signed delivery of one encrypted MLS bootstrap.  The server never
/// parses `opaque_sealed_bootstrap`.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentRouteBootstrapDeliveryCommand {
    pub bootstrap_id: AgentRouteBootstrapId,
    pub delivery_id: AgentRouteDeliveryId,
    pub tenant_id: TenantId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub agent_control_device_id: AgentDeviceId,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub recipient_id: AgentRouteRecipientId,
    pub route_id: ConversationId,
    pub capsule_digest: Sha256Digest,
    pub opaque_sealed_bootstrap: Vec<u8>,
    pub expires_at: UtcMillis,
    pub binding_digest: Sha256Digest,
    pub owner_signature: Ed25519Signature,
    pub server_receipt_key_id: Option<RouteHealthKeyId>,
    pub server_receipt_public_key_digest: Option<Sha256Digest>,
}

impl fmt::Debug for AgentRouteBootstrapDeliveryCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentRouteBootstrapDeliveryCommand")
            .field("bootstrap_id", &self.bootstrap_id)
            .field("delivery_id", &self.delivery_id)
            .field("tenant_id", &self.tenant_id)
            .field("installation_id", &self.installation_id)
            .field("binding_id", &self.binding_id)
            .field("agent_control_device_id", &self.agent_control_device_id)
            .field("owner_identity_id", &self.owner_identity_id)
            .field("owner_device_id", &self.owner_device_id)
            .field("recipient_id", &self.recipient_id)
            .field("route_id", &self.route_id)
            .field("capsule_digest", &self.capsule_digest)
            .field("opaque_sealed_bootstrap", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Authenticated Agent-Control recipient result.  The peer tuple comes from
/// the control-stream authentication layer, not this untrusted payload.
#[derive(Clone, Eq, PartialEq)]
pub struct AgentRouteRecipientReadyCommand {
    pub bootstrap_id: AgentRouteBootstrapId,
    pub recipient_id: AgentRouteRecipientId,
    pub recipient_capsule_digest: Sha256Digest,
    pub opaque_recipient_capsule: Vec<u8>,
    pub expires_at: UtcMillis,
    pub route_health_key_id: Option<RouteHealthKeyId>,
    pub route_health_public_key: Option<[u8; 32]>,
    pub server_receipt_key_id: Option<RouteHealthKeyId>,
    pub server_receipt_public_key: Option<[u8; 32]>,
}

impl fmt::Debug for AgentRouteRecipientReadyCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentRouteRecipientReadyCommand")
            .field("bootstrap_id", &self.bootstrap_id)
            .field("recipient_id", &self.recipient_id)
            .field("recipient_capsule_digest", &self.recipient_capsule_digest)
            .field("opaque_recipient_capsule", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Authenticated terminal Agent-Control receipt.  `stable_code` is a closed,
/// redacted token such as `INSTALLED` or `INVALID_CAPSULE`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRouteBootstrapTerminalCommand {
    pub bootstrap_id: AgentRouteBootstrapId,
    pub delivery_id: AgentRouteDeliveryId,
    pub route_id: ConversationId,
    pub capsule_digest: Sha256Digest,
    /// Present only for the authenticated `Installed` receipt.  It is the
    /// fence produced by the local route import, never an owner echo.
    pub route_fence: Option<[u8; 32]>,
    pub stable_code: String,
    pub route_health_key_id: Option<RouteHealthKeyId>,
    pub route_health_public_key_digest: Option<Sha256Digest>,
    pub server_receipt_key_id: Option<RouteHealthKeyId>,
    pub server_receipt_public_key_digest: Option<Sha256Digest>,
}

/// Compact owner-visible response.  Only `Get` may include an opaque
/// recipient capsule, and only after authenticating the exact owner device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRouteBootstrapOwnerReceipt {
    pub replayed: bool,
    pub state: AgentRouteBootstrapState,
    pub exact_cbor: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RouteBootstrapRecord {
    bootstrap_id: AgentRouteBootstrapId,
    tenant_id: TenantId,
    owner_identity_id: IdentityId,
    owner_device_id: DeviceId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    connector_id: ConnectorId,
    route_health_key_id: Option<RouteHealthKeyId>,
    route_health_public_key: Option<[u8; 32]>,
    server_receipt_key_id: Option<RouteHealthKeyId>,
    server_receipt_public_key: Option<[u8; 32]>,
    server_receipt_public_key_digest: Option<Sha256Digest>,
    route_fence: Option<[u8; 32]>,
    state: AgentRouteBootstrapState,
    recipient_id: Option<AgentRouteRecipientId>,
    recipient_capsule_digest: Option<Sha256Digest>,
    opaque_recipient_capsule: Option<Vec<u8>>,
    route_id: Option<ConversationId>,
    delivery_id: Option<AgentRouteDeliveryId>,
    bootstrap_capsule_digest: Option<Sha256Digest>,
    rejection_code: Option<String>,
    expires_at: UtcMillis,
    created_at: UtcMillis,
    updated_at: UtcMillis,
}

/// Begins one RouteBootstrap and writes an opaque PrepareRecipient outbox row.
pub async fn begin_agent_route_bootstrap(
    store: &PgStore,
    credential: &DeviceSessionCredential,
    command: AgentRouteBootstrapBeginCommand,
    exact_body: Vec<u8>,
    now: UtcMillis,
) -> Result<AgentRouteBootstrapOwnerReceipt, AgentRouteBootstrapError> {
    begin_agent_route_bootstrap_with_receipt_keyring(
        store, credential, command, exact_body, now, None,
    )
    .await
}

pub async fn begin_agent_route_bootstrap_with_receipt_keyring(
    store: &PgStore,
    credential: &DeviceSessionCredential,
    command: AgentRouteBootstrapBeginCommand,
    exact_body: Vec<u8>,
    now: UtcMillis,
    receipt_keyring: Option<&BTreeMap<RouteHealthKeyId, [u8; 32]>>,
) -> Result<AgentRouteBootstrapOwnerReceipt, AgentRouteBootstrapError> {
    validate_begin(&command, &exact_body, now)?;
    let request_digest =
        Sha256Digest::hash_domain(AGENT_ROUTE_BOOTSTRAP_BEGIN_REQUEST_DOMAIN, &exact_body);
    let mut session = store
        .begin_tenant(command.tenant_id)
        .await
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
    let result = begin_in_transaction(
        session.connection(),
        credential,
        &command,
        &exact_body,
        request_digest,
        now,
        receipt_keyring,
    )
    .await;
    match result {
        Ok(receipt) => {
            session
                .commit()
                .await
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
            Ok(receipt)
        }
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

/// Reads current status and the owner-encrypted recipient capsule, if ready.
pub async fn get_agent_route_bootstrap(
    store: &PgStore,
    credential: &DeviceSessionCredential,
    tenant_id: TenantId,
    bootstrap_id: AgentRouteBootstrapId,
    now: UtcMillis,
) -> Result<AgentRouteBootstrapOwnerReceipt, AgentRouteBootstrapError> {
    let mut session = store
        .begin_tenant(tenant_id)
        .await
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
    let result = async {
        let owner = authenticate_owner(session.connection(), credential, now).await?;
        expire_bootstrap_if_due(session.connection(), tenant_id, bootstrap_id, now).await?;
        let row = load_bootstrap_for_update(session.connection(), tenant_id, bootstrap_id)
            .await?
            .ok_or(AgentRouteBootstrapError::NotFound)?;
        if row.owner_identity_id != owner.0 || row.owner_device_id != owner.1 {
            return Err(AgentRouteBootstrapError::Forbidden);
        }
        let exact_cbor = owner_view_cbor(&row)?;
        Ok(AgentRouteBootstrapOwnerReceipt {
            replayed: false,
            state: row.state,
            exact_cbor,
        })
    }
    .await;
    match result {
        Ok(receipt) => {
            session
                .commit()
                .await
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
            Ok(receipt)
        }
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

/// Resolves the single active RouteBootstrap target visible to the authenticated Owner.
///
/// The result intentionally contains only immutable routing identifiers.  It
/// never loads a recipient, capsule, credential, or Connector secret.  An
/// invalid owner/binding/device tuple is indistinguishable from an absent
/// target at this read boundary.
pub(crate) async fn get_owned_agent_route_bootstrap_target(
    store: &PgStore,
    credential: &DeviceSessionCredential,
    tenant_id: TenantId,
    installation_id: InstallationId,
    binding_id: BindingId,
    now: UtcMillis,
) -> Result<AgentRouteBootstrapTarget, AgentRouteBootstrapError> {
    let mut session = store
        .begin_tenant(tenant_id)
        .await
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
    let result = async {
        let owner = authenticate_owner(session.connection(), credential, now).await?;
        resolve_owned_agent_route_bootstrap_target(
            session.connection(),
            tenant_id,
            owner.0,
            installation_id,
            binding_id,
        )
        .await
    }
    .await;
    match result {
        Ok(target) => {
            session
                .commit()
                .await
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
            Ok(target)
        }
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

/// Stores one owner-authorized opaque bootstrap delivery and a durable outbox row.
pub async fn deliver_agent_route_bootstrap(
    store: &PgStore,
    credential: &DeviceSessionCredential,
    command: AgentRouteBootstrapDeliveryCommand,
    exact_body: Vec<u8>,
    now: UtcMillis,
) -> Result<AgentRouteBootstrapOwnerReceipt, AgentRouteBootstrapError> {
    validate_delivery(&command, &exact_body, now)?;
    let request_digest = Sha256Digest::hash_domain(
        if command.server_receipt_key_id.is_some() {
            AGENT_ROUTE_BOOTSTRAP_DELIVERY_REQUEST_DOMAIN_V2
        } else {
            AGENT_ROUTE_BOOTSTRAP_DELIVERY_REQUEST_DOMAIN
        },
        &exact_body,
    );
    let mut session = store
        .begin_tenant(command.tenant_id)
        .await
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
    let result = deliver_in_transaction(
        session.connection(),
        credential,
        &command,
        request_digest,
        now,
    )
    .await;
    match result {
        Ok(receipt) => {
            session
                .commit()
                .await
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
            Ok(receipt)
        }
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

/// Records a recipient created by an already authenticated Agent-Control peer.
async fn record_agent_route_recipient_ready(
    store: &PgStore,
    tenant_id: TenantId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    command: AgentRouteRecipientReadyCommand,
    now: UtcMillis,
) -> Result<(), AgentRouteBootstrapError> {
    if command.opaque_recipient_capsule.is_empty()
        || command.opaque_recipient_capsule.len() > MAX_OPAQUE_BYTES
        || command.expires_at <= now
        || Sha256Digest::hash_domain(
            AGENT_ROUTE_RECIPIENT_CAPSULE_DOMAIN,
            &command.opaque_recipient_capsule,
        ) != command.recipient_capsule_digest
    {
        return Err(AgentRouteBootstrapError::InvalidRequest);
    }
    let mut session = store
        .begin_tenant(tenant_id)
        .await
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
    let result = async {
        let row = load_bootstrap_for_update(session.connection(), tenant_id, command.bootstrap_id)
            .await?
            .ok_or(AgentRouteBootstrapError::NotFound)?;
        if row.binding_id != binding_id || row.agent_control_device_id != agent_control_device_id {
            return Err(AgentRouteBootstrapError::Forbidden);
        }
        if row.expires_at <= now || command.expires_at > row.expires_at {
            return Err(AgentRouteBootstrapError::Conflict);
        }
        match row.state {
            AgentRouteBootstrapState::PendingRecipient => {
                let updated = sqlx::query(
                    "UPDATE agent.agent_route_bootstraps
                        SET state='recipient_ready', recipient_id=$3,
                            recipient_capsule_digest=$4, opaque_recipient_capsule=$5,
                            updated_at_ms=$6
                      WHERE tenant_id=$1 AND bootstrap_id=$2 AND state='pending_recipient'",
                )
                .bind(Uuid::from(tenant_id))
                .bind(Uuid::from(command.bootstrap_id))
                .bind(Uuid::from(command.recipient_id))
                .bind(command.recipient_capsule_digest.as_bytes().as_slice())
                .bind(&command.opaque_recipient_capsule)
                .bind(now.get())
                .execute(session.connection())
                .await
                .map_err(map_sql)?;
                if updated.rows_affected() != 1 {
                    return Err(AgentRouteBootstrapError::Conflict);
                }
                Ok(())
            }
            AgentRouteBootstrapState::RecipientReady
                if row.recipient_id == Some(command.recipient_id)
                    && row.recipient_capsule_digest == Some(command.recipient_capsule_digest)
                    && row.opaque_recipient_capsule.as_deref()
                        == Some(command.opaque_recipient_capsule.as_slice()) =>
            {
                Ok(())
            }
            _ => Err(AgentRouteBootstrapError::Conflict),
        }
    }
    .await;
    match result {
        Ok(()) => session
            .commit()
            .await
            .map_err(|_| AgentRouteBootstrapError::Unavailable),
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

/// Records an authenticated successful install and only then creates or moves
/// the exact binding head used by AgentRoute Run ingress.
async fn record_agent_route_bootstrap_installed(
    store: &PgStore,
    tenant_id: TenantId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    command: AgentRouteBootstrapTerminalCommand,
    now: UtcMillis,
) -> Result<(), AgentRouteBootstrapError> {
    let route_fence = command
        .route_fence
        .filter(|value| !value.iter().all(|byte| *byte == 0))
        .ok_or(AgentRouteBootstrapError::InvalidRequest)?;
    if command.stable_code != "INSTALLED" {
        return Err(AgentRouteBootstrapError::InvalidRequest);
    }
    let mut session = store
        .begin_tenant(tenant_id)
        .await
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
    let result = async {
        let row = terminal_target(
            session.connection(),
            tenant_id,
            binding_id,
            agent_control_device_id,
            &command,
            now,
        )
        .await?;
        if row.state == AgentRouteBootstrapState::Installed {
            return if row.route_fence == Some(route_fence) {
                Ok(())
            } else {
                Err(AgentRouteBootstrapError::Conflict)
            };
        }
        if row.state != AgentRouteBootstrapState::PendingDelivery {
            return Err(AgentRouteBootstrapError::Conflict);
        }
        let changed = sqlx::query(
            "UPDATE agent.agent_route_bootstraps
                SET state='installed', route_fence=$3, updated_at_ms=$4
              WHERE tenant_id=$1 AND bootstrap_id=$2 AND state='pending_delivery'",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(command.bootstrap_id))
        .bind(route_fence.as_slice())
        .bind(now.get())
        .execute(session.connection())
        .await
        .map_err(map_sql)?;
        if changed.rows_affected() != 1 {
            return Err(AgentRouteBootstrapError::Conflict);
        }
        let upserted = sqlx::query(
            "INSERT INTO agent.agent_route_binding_heads (
                 tenant_id, owner_identity_id, owner_device_id, installation_id, binding_id,
                 agent_control_device_id, bootstrap_id, delivery_id, route_id, route_fence,
                 capsule_digest, expires_at_ms, installed_at_ms,
                 server_receipt_key_id, server_receipt_public_key,
                 server_receipt_public_key_digest
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
             ON CONFLICT (tenant_id, owner_identity_id, owner_device_id, installation_id,
                          binding_id, agent_control_device_id)
             DO UPDATE SET bootstrap_id=EXCLUDED.bootstrap_id,
                           delivery_id=EXCLUDED.delivery_id,
                           route_id=EXCLUDED.route_id,
                           route_fence=EXCLUDED.route_fence,
                           capsule_digest=EXCLUDED.capsule_digest,
                           expires_at_ms=EXCLUDED.expires_at_ms,
                           installed_at_ms=EXCLUDED.installed_at_ms,
                           server_receipt_key_id=EXCLUDED.server_receipt_key_id,
                           server_receipt_public_key=EXCLUDED.server_receipt_public_key,
                           server_receipt_public_key_digest=EXCLUDED.server_receipt_public_key_digest
             WHERE agent.agent_route_binding_heads.bootstrap_id=EXCLUDED.bootstrap_id
                OR agent.agent_route_binding_heads.expires_at_ms <= EXCLUDED.installed_at_ms",
        )
        .bind(Uuid::from(tenant_id))
        .bind(row.owner_identity_id.to_string())
        .bind(Uuid::from(row.owner_device_id))
        .bind(Uuid::from(row.installation_id))
        .bind(Uuid::from(row.binding_id))
        .bind(Uuid::from(row.agent_control_device_id))
        .bind(Uuid::from(row.bootstrap_id))
        .bind(Uuid::from(command.delivery_id))
        .bind(Uuid::from(command.route_id))
        .bind(route_fence.as_slice())
        .bind(command.capsule_digest.as_bytes().as_slice())
        .bind(row.expires_at.get())
        .bind(now.get())
        .bind(row.server_receipt_key_id.map(Uuid::from))
        .bind(row.server_receipt_public_key.map(|value| value.to_vec()))
        .bind(
            row.server_receipt_public_key_digest
                .map(|value| value.as_bytes().to_vec()),
        )
        .execute(session.connection())
        .await
        .map_err(map_sql)?;
        if upserted.rows_affected() != 1 {
            return Err(AgentRouteBootstrapError::Conflict);
        }
        Ok(())
    }
    .await;
    match result {
        Ok(()) => session
            .commit()
            .await
            .map_err(|_| AgentRouteBootstrapError::Unavailable),
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

/// Records an authenticated terminal rejection; it deliberately never makes a
/// binding head eligible for Run ingress.
async fn record_agent_route_bootstrap_rejected(
    store: &PgStore,
    tenant_id: TenantId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    command: AgentRouteBootstrapTerminalCommand,
    now: UtcMillis,
) -> Result<(), AgentRouteBootstrapError> {
    if command.route_fence.is_some()
        || !valid_stable_code(&command.stable_code)
        || command.stable_code == "INSTALLED"
    {
        return Err(AgentRouteBootstrapError::InvalidRequest);
    }
    let mut session = store
        .begin_tenant(tenant_id)
        .await
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
    let result = async {
        let row = terminal_target(
            session.connection(),
            tenant_id,
            binding_id,
            agent_control_device_id,
            &command,
            now,
        )
        .await?;
        match row.state {
            AgentRouteBootstrapState::Rejected
                if row.rejection_code.as_deref() == Some(command.stable_code.as_str()) =>
            {
                Ok(())
            }
            AgentRouteBootstrapState::PendingDelivery => {
                let changed = sqlx::query(
                    "UPDATE agent.agent_route_bootstraps
                        SET state='rejected', rejection_code=$3, updated_at_ms=$4
                      WHERE tenant_id=$1 AND bootstrap_id=$2 AND state='pending_delivery'",
                )
                .bind(Uuid::from(tenant_id))
                .bind(Uuid::from(command.bootstrap_id))
                .bind(&command.stable_code)
                .bind(now.get())
                .execute(session.connection())
                .await
                .map_err(map_sql)?;
                if changed.rows_affected() == 1 {
                    Ok(())
                } else {
                    Err(AgentRouteBootstrapError::Conflict)
                }
            }
            _ => Err(AgentRouteBootstrapError::Conflict),
        }
    }
    .await;
    match result {
        Ok(()) => session
            .commit()
            .await
            .map_err(|_| AgentRouteBootstrapError::Unavailable),
        Err(error) => {
            let _ = session.rollback().await;
            Err(error)
        }
    }
}

async fn begin_in_transaction(
    connection: &mut sqlx::PgConnection,
    credential: &DeviceSessionCredential,
    command: &AgentRouteBootstrapBeginCommand,
    _exact_body: &[u8],
    request_digest: Sha256Digest,
    now: UtcMillis,
    receipt_keyring: Option<&BTreeMap<RouteHealthKeyId, [u8; 32]>>,
) -> Result<AgentRouteBootstrapOwnerReceipt, AgentRouteBootstrapError> {
    let owner = authenticate_owner(connection, credential, now).await?;
    if owner.0 != command.owner_identity_id || owner.1 != command.owner_device_id {
        return Err(AgentRouteBootstrapError::Forbidden);
    }
    verify_owner_signature(
        owner.2,
        command.binding_digest,
        command.owner_signature,
        AGENT_ROUTE_BOOTSTRAP_BEGIN_SIGNATURE_DOMAIN,
    )?;
    lock_uuid(connection, *command.bootstrap_id.as_uuid()).await?;
    lock_uuid(connection, *command.binding_id.as_uuid()).await?;
    if let Some(row) = sqlx::query(
        "SELECT request_digest, begin_receipt_bytes, begin_receipt_digest
           FROM agent.agent_route_bootstraps
          WHERE tenant_id=$1 AND bootstrap_id=$2 FOR UPDATE",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.bootstrap_id))
    .fetch_optional(&mut *connection)
    .await
    .map_err(map_sql)?
    {
        let stored_request: Vec<u8> = row
            .try_get("request_digest")
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
        if stored_request.as_slice() != request_digest.as_bytes() {
            return Err(AgentRouteBootstrapError::Conflict);
        }
        let bytes: Vec<u8> = row
            .try_get("begin_receipt_bytes")
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
        let stored_digest = bytes32(
            row.try_get("begin_receipt_digest")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )?;
        if bytes.len() > MAX_RECEIPT_BYTES
            || Sha256Digest::hash_domain(AGENT_ROUTE_BOOTSTRAP_BEGIN_RECEIPT_DOMAIN, &bytes)
                .as_bytes()
                != &stored_digest
            || decode_deterministic_cbor(&bytes).is_err()
        {
            return Err(AgentRouteBootstrapError::Unavailable);
        }
        return Ok(AgentRouteBootstrapOwnerReceipt {
            replayed: true,
            state: AgentRouteBootstrapState::PendingRecipient,
            exact_cbor: bytes,
        });
    }
    let connector_id = ensure_owner_target(connection, command).await?;
    let (server_receipt_key_id, server_receipt_public_key) =
        load_current_server_receipt_pin(connection, command.tenant_id, connector_id).await?;
    if let Some(keyring) = receipt_keyring {
        let public = server_receipt_public_key.ok_or(AgentRouteBootstrapError::Conflict)?;
        let key_id = server_receipt_key_id.ok_or(AgentRouteBootstrapError::Conflict)?;
        crate::route_health_http::validate_receipt_pin(keyring, Some(key_id), Some(public))
            .map_err(|_| AgentRouteBootstrapError::Conflict)?;
    }
    let server_receipt_public_key_digest = server_receipt_public_key
        .map(|value| Sha256Digest::hash_domain(AGENT_ROUTE_HEALTH_PUBLIC_KEY_DOMAIN, &value));
    expire_live_tuple(connection, command, now).await?;
    let live: Option<Uuid> = sqlx::query_scalar(
        "SELECT bootstrap_id FROM agent.agent_route_bootstraps
          WHERE tenant_id=$1 AND owner_identity_id=$2 AND owner_device_id=$3
            AND installation_id=$4 AND binding_id=$5 AND agent_control_device_id=$6
            AND state IN ('pending_recipient','recipient_ready','pending_delivery','installed')
          FOR UPDATE",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(command.owner_identity_id.to_string())
    .bind(Uuid::from(command.owner_device_id))
    .bind(Uuid::from(command.installation_id))
    .bind(Uuid::from(command.binding_id))
    .bind(Uuid::from(command.agent_control_device_id))
    .fetch_optional(&mut *connection)
    .await
    .map_err(map_sql)?;
    if live.is_some() {
        return Err(AgentRouteBootstrapError::Conflict);
    }
    let receipt = owner_receipt_cbor(
        command.tenant_id,
        command.bootstrap_id,
        AgentRouteBootstrapState::PendingRecipient,
        None,
        None,
        None,
        None,
        server_receipt_key_id,
        server_receipt_public_key_digest,
        command.expires_at,
        now,
        None,
    )?;
    let receipt_digest =
        Sha256Digest::hash_domain(AGENT_ROUTE_BOOTSTRAP_BEGIN_RECEIPT_DOMAIN, &receipt);
    sqlx::query(
        "INSERT INTO agent.agent_route_bootstraps (
             tenant_id, bootstrap_id, owner_identity_id, owner_device_id, installation_id,
             binding_id, agent_control_device_id, connector_id, owner_signed_intent,
             request_digest, begin_receipt_bytes, begin_receipt_digest, state, expires_at_ms,
             created_at_ms, updated_at_ms, server_receipt_key_id,
             server_receipt_public_key, server_receipt_public_key_digest
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'pending_recipient',$13,$14,$14,$15,$16,$17)",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.bootstrap_id))
    .bind(command.owner_identity_id.to_string())
    .bind(Uuid::from(command.owner_device_id))
    .bind(Uuid::from(command.installation_id))
    .bind(Uuid::from(command.binding_id))
    .bind(Uuid::from(command.agent_control_device_id))
    .bind(Uuid::from(connector_id))
    .bind(&command.owner_signed_intent)
    .bind(request_digest.as_bytes().as_slice())
    .bind(&receipt)
    .bind(receipt_digest.as_bytes().as_slice())
    .bind(command.expires_at.get())
    .bind(now.get())
    .bind(server_receipt_key_id.map(Uuid::from))
    .bind(server_receipt_public_key.map(|value| value.to_vec()))
    .bind(server_receipt_public_key_digest.map(|value| value.as_bytes().to_vec()))
    .execute(&mut *connection)
    .await
    .map_err(map_sql)?;

    let operation_id = RequestId::try_from(Uuid::from(command.bootstrap_id))
        .map_err(|_| AgentRouteBootstrapError::InvalidRequest)?;
    let control_payload =
        ServerCommandPayload::PrepareAgentRouteRecipient(PrepareAgentRouteRecipient {
            bootstrap_id: command.bootstrap_id,
            tenant_id: command.tenant_id,
            installation_id: command.installation_id,
            binding_id: command.binding_id,
            agent_control_device_id: command.agent_control_device_id,
            owner_identity_id: command.owner_identity_id,
            owner_device_id: command.owner_device_id,
            // The native-only Owner intent remains opaque to Agent Control.
            owner_signed_intent: OpaqueAgentRouteBytes::new(command.owner_signed_intent.clone())
                .map_err(|_| AgentRouteBootstrapError::InvalidRequest)?,
            expires_at_millis: command.expires_at.get(),
            server_receipt_key_id,
            server_receipt_public_key,
        });
    let durable = append_route_bootstrap_command(
        connection,
        command.tenant_id,
        connector_id,
        operation_id,
        "prepare_agent_route_recipient",
        control_payload,
        now,
    )
    .await?;
    let payload = prepare_outbox_payload(command, &command.owner_signed_intent)?;
    let payload_digest = Sha256Digest::hash_domain(AGENT_ROUTE_BOOTSTRAP_OUTBOX_DOMAIN, &payload);
    sqlx::query(
        "INSERT INTO agent.agent_route_bootstrap_outbox (
             tenant_id, outbox_id, bootstrap_id, connector_id, operation_id,
             command_sequence, command_payload_digest, encoded_command_digest,
             command_kind, payload_digest, opaque_payload, state, created_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'prepare_recipient',$9,$10,'pending',$11)",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(OutboxId::new()))
    .bind(Uuid::from(command.bootstrap_id))
    .bind(Uuid::from(connector_id))
    .bind(Uuid::from(operation_id))
    .bind(i64::try_from(durable.sequence()).map_err(|_| AgentRouteBootstrapError::Unavailable)?)
    .bind(durable.payload_digest().as_bytes().as_slice())
    .bind(durable.encoded_command_digest().as_bytes().as_slice())
    .bind(payload_digest.as_bytes().as_slice())
    .bind(payload)
    .bind(now.get())
    .execute(&mut *connection)
    .await
    .map_err(map_sql)?;
    Ok(AgentRouteBootstrapOwnerReceipt {
        replayed: false,
        state: AgentRouteBootstrapState::PendingRecipient,
        exact_cbor: receipt,
    })
}

async fn deliver_in_transaction(
    connection: &mut sqlx::PgConnection,
    credential: &DeviceSessionCredential,
    command: &AgentRouteBootstrapDeliveryCommand,
    request_digest: Sha256Digest,
    now: UtcMillis,
) -> Result<AgentRouteBootstrapOwnerReceipt, AgentRouteBootstrapError> {
    let owner = authenticate_owner(connection, credential, now).await?;
    if owner.0 != command.owner_identity_id || owner.1 != command.owner_device_id {
        return Err(AgentRouteBootstrapError::Forbidden);
    }
    verify_owner_signature(
        owner.2,
        command.binding_digest,
        command.owner_signature,
        AGENT_ROUTE_BOOTSTRAP_DELIVERY_SIGNATURE_DOMAIN,
    )?;
    lock_uuid(connection, *command.bootstrap_id.as_uuid()).await?;
    lock_uuid(connection, *command.delivery_id.as_uuid()).await?;
    expire_bootstrap_if_due(connection, command.tenant_id, command.bootstrap_id, now).await?;
    let row = load_bootstrap_for_update(connection, command.tenant_id, command.bootstrap_id)
        .await?
        .ok_or(AgentRouteBootstrapError::NotFound)?;
    if row.owner_identity_id != command.owner_identity_id
        || row.owner_device_id != command.owner_device_id
        || row.installation_id != command.installation_id
        || row.binding_id != command.binding_id
        || row.agent_control_device_id != command.agent_control_device_id
    {
        return Err(AgentRouteBootstrapError::Forbidden);
    }
    if !receipt_pin_matches(
        row.server_receipt_key_id,
        row.server_receipt_public_key_digest,
        command.server_receipt_key_id,
        command.server_receipt_public_key_digest,
    ) {
        return Err(AgentRouteBootstrapError::Conflict);
    }
    if let Some(delivery_id) = row.delivery_id {
        if delivery_id != command.delivery_id {
            return Err(AgentRouteBootstrapError::Conflict);
        }
        let replay = sqlx::query(
            "SELECT delivery_request_digest, delivery_receipt_bytes, delivery_receipt_digest
               FROM agent.agent_route_bootstraps WHERE tenant_id=$1 AND bootstrap_id=$2",
        )
        .bind(Uuid::from(command.tenant_id))
        .bind(Uuid::from(command.bootstrap_id))
        .fetch_one(&mut *connection)
        .await
        .map_err(map_sql)?;
        let stored_request: Vec<u8> = replay
            .try_get("delivery_request_digest")
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
        if stored_request.as_slice() != request_digest.as_bytes() {
            return Err(AgentRouteBootstrapError::Conflict);
        }
        let exact_cbor: Vec<u8> = replay
            .try_get("delivery_receipt_bytes")
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
        let digest = bytes32(
            replay
                .try_get("delivery_receipt_digest")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )?;
        let receipt_domain = if row.server_receipt_key_id.is_some() {
            AGENT_ROUTE_BOOTSTRAP_DELIVERY_RECEIPT_DOMAIN_V2
        } else {
            AGENT_ROUTE_BOOTSTRAP_DELIVERY_RECEIPT_DOMAIN
        };
        if Sha256Digest::hash_domain(receipt_domain, &exact_cbor).as_bytes() != &digest
            || decode_deterministic_cbor(&exact_cbor).is_err()
        {
            return Err(AgentRouteBootstrapError::Unavailable);
        }
        return Ok(AgentRouteBootstrapOwnerReceipt {
            replayed: true,
            state: row.state,
            exact_cbor,
        });
    }
    if row.state != AgentRouteBootstrapState::RecipientReady
        || row.recipient_id != Some(command.recipient_id)
        || row.expires_at <= now
        || command.expires_at > row.expires_at
    {
        return Err(AgentRouteBootstrapError::Conflict);
    }
    if !is_owned_agent_route_bootstrap_target_live(
        connection,
        command.tenant_id,
        command.owner_identity_id,
        command.installation_id,
        command.binding_id,
        command.agent_control_device_id,
        row.connector_id,
    )
    .await?
    {
        return revoke_delivery_for_invalid_target(connection, &row, command, request_digest, now)
            .await;
    }
    let receipt = owner_receipt_cbor(
        command.tenant_id,
        command.bootstrap_id,
        AgentRouteBootstrapState::PendingDelivery,
        Some(command.recipient_id),
        Some(command.delivery_id),
        Some(command.route_id),
        None,
        row.server_receipt_key_id,
        row.server_receipt_public_key_digest,
        row.expires_at,
        now,
        None,
    )?;
    let receipt_digest = Sha256Digest::hash_domain(
        if row.server_receipt_key_id.is_some() {
            AGENT_ROUTE_BOOTSTRAP_DELIVERY_RECEIPT_DOMAIN_V2
        } else {
            AGENT_ROUTE_BOOTSTRAP_DELIVERY_RECEIPT_DOMAIN
        },
        &receipt,
    );
    let changed = sqlx::query(
        "UPDATE agent.agent_route_bootstraps
            SET state='pending_delivery', route_id=$3, delivery_id=$4,
                bootstrap_capsule_digest=$5, opaque_sealed_bootstrap=$6,
                delivery_request_digest=$7, delivery_receipt_bytes=$8,
                delivery_receipt_digest=$9, updated_at_ms=$10
          WHERE tenant_id=$1 AND bootstrap_id=$2 AND state='recipient_ready' AND delivery_id IS NULL",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.bootstrap_id))
    .bind(Uuid::from(command.route_id))
    .bind(Uuid::from(command.delivery_id))
    .bind(command.capsule_digest.as_bytes().as_slice())
    .bind(&command.opaque_sealed_bootstrap)
    .bind(request_digest.as_bytes().as_slice())
    .bind(&receipt)
    .bind(receipt_digest.as_bytes().as_slice())
    .bind(now.get())
    .execute(&mut *connection)
    .await
    .map_err(map_sql)?;
    if changed.rows_affected() != 1 {
        return Err(AgentRouteBootstrapError::Conflict);
    }
    let operation_id = RequestId::try_from(Uuid::from(command.delivery_id))
        .map_err(|_| AgentRouteBootstrapError::InvalidRequest)?;
    let control_payload =
        ServerCommandPayload::DeliverAgentRouteBootstrap(DeliverAgentRouteBootstrap {
            bootstrap_id: command.bootstrap_id,
            delivery_id: command.delivery_id,
            route_id: command.route_id,
            recipient_id: command.recipient_id,
            capsule_digest: ControlSha256Digest::from_bytes(*command.capsule_digest.as_bytes()),
            opaque_sealed_bootstrap: OpaqueAgentRouteBytes::new(
                command.opaque_sealed_bootstrap.clone(),
            )
            .map_err(|_| AgentRouteBootstrapError::InvalidRequest)?,
            expires_at_millis: command.expires_at.get(),
            installation_id: command.installation_id,
            binding_id: command.binding_id,
            agent_control_device_id: command.agent_control_device_id,
            route_health_key_id: row.route_health_key_id,
            route_health_public_key_digest: row.route_health_public_key.map(|value| {
                ControlSha256Digest::from_bytes(
                    *Sha256Digest::hash_domain(AGENT_ROUTE_HEALTH_PUBLIC_KEY_DOMAIN, &value)
                        .as_bytes(),
                )
            }),
            server_receipt_key_id: row.server_receipt_key_id,
            server_receipt_public_key_digest: row
                .server_receipt_public_key_digest
                .map(|value| ControlSha256Digest::from_bytes(*value.as_bytes())),
        });
    let durable = append_route_bootstrap_command(
        connection,
        command.tenant_id,
        row.connector_id,
        operation_id,
        "deliver_agent_route_bootstrap",
        control_payload,
        now,
    )
    .await?;
    let payload = delivery_outbox_payload(command)?;
    let payload_digest = Sha256Digest::hash_domain(AGENT_ROUTE_BOOTSTRAP_OUTBOX_DOMAIN, &payload);
    sqlx::query(
        "INSERT INTO agent.agent_route_bootstrap_outbox (
             tenant_id, outbox_id, bootstrap_id, delivery_id, connector_id, operation_id,
             command_sequence, command_payload_digest, encoded_command_digest,
             command_kind, payload_digest, opaque_payload, state, created_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'deliver_bootstrap',$10,$11,'pending',$12)",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(OutboxId::new()))
    .bind(Uuid::from(command.bootstrap_id))
    .bind(Uuid::from(command.delivery_id))
    .bind(Uuid::from(row.connector_id))
    .bind(Uuid::from(operation_id))
    .bind(i64::try_from(durable.sequence()).map_err(|_| AgentRouteBootstrapError::Unavailable)?)
    .bind(durable.payload_digest().as_bytes().as_slice())
    .bind(durable.encoded_command_digest().as_bytes().as_slice())
    .bind(payload_digest.as_bytes().as_slice())
    .bind(payload)
    .bind(now.get())
    .execute(&mut *connection)
    .await
    .map_err(map_sql)?;
    Ok(AgentRouteBootstrapOwnerReceipt {
        replayed: false,
        state: AgentRouteBootstrapState::PendingDelivery,
        exact_cbor: receipt,
    })
}

/// Terminates a delivery request whose previously selected target is no longer
/// usable.  No delivery command has been appended at this point, so persisting
/// the exact terminal owner receipt is sufficient to make retries stable.
async fn revoke_delivery_for_invalid_target(
    connection: &mut sqlx::PgConnection,
    row: &RouteBootstrapRecord,
    command: &AgentRouteBootstrapDeliveryCommand,
    request_digest: Sha256Digest,
    now: UtcMillis,
) -> Result<AgentRouteBootstrapOwnerReceipt, AgentRouteBootstrapError> {
    let receipt = owner_receipt_cbor(
        command.tenant_id,
        command.bootstrap_id,
        AgentRouteBootstrapState::Revoked,
        None,
        Some(command.delivery_id),
        Some(command.route_id),
        None,
        row.server_receipt_key_id,
        row.server_receipt_public_key_digest,
        row.expires_at,
        now,
        None,
    )?;
    let receipt_digest = Sha256Digest::hash_domain(
        if row.server_receipt_key_id.is_some() {
            AGENT_ROUTE_BOOTSTRAP_DELIVERY_RECEIPT_DOMAIN_V2
        } else {
            AGENT_ROUTE_BOOTSTRAP_DELIVERY_RECEIPT_DOMAIN
        },
        &receipt,
    );
    let changed = sqlx::query(
        "UPDATE agent.agent_route_bootstraps
            SET state='revoked', route_fence=NULL,
                recipient_id=NULL, recipient_capsule_digest=NULL, opaque_recipient_capsule=NULL,
                route_id=$3, delivery_id=$4, bootstrap_capsule_digest=NULL,
                opaque_sealed_bootstrap=NULL, delivery_request_digest=$5,
                delivery_receipt_bytes=$6, delivery_receipt_digest=$7,
                rejection_code=NULL, updated_at_ms=$8
          WHERE tenant_id=$1 AND bootstrap_id=$2
            AND state='recipient_ready' AND delivery_id IS NULL",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(Uuid::from(command.bootstrap_id))
    .bind(Uuid::from(command.route_id))
    .bind(Uuid::from(command.delivery_id))
    .bind(request_digest.as_bytes().as_slice())
    .bind(&receipt)
    .bind(receipt_digest.as_bytes().as_slice())
    .bind(now.get())
    .execute(&mut *connection)
    .await
    .map_err(map_sql)?;
    if changed.rows_affected() != 1 {
        return Err(AgentRouteBootstrapError::Conflict);
    }
    Ok(AgentRouteBootstrapOwnerReceipt {
        replayed: false,
        state: AgentRouteBootstrapState::Revoked,
        exact_cbor: receipt,
    })
}

/// Appends one RouteBootstrap command and its immutable operation publication
/// beneath the Connector stream-head lock held by this tenant transaction.
///
/// The caller persists its bootstrap state and audit outbox in the same
/// transaction.  The deferred publication trigger observes both the immutable
/// operation row and the exact command projection only at commit.
async fn append_route_bootstrap_command(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    operation_id: RequestId,
    operation_kind: &'static str,
    control_payload: ServerCommandPayload,
    now: UtcMillis,
) -> Result<DurableServerCommand, AgentRouteBootstrapError> {
    let repository = CommandLogRepository::new();
    let head = repository
        .lock_head_for_update(connection, tenant_id, connector_id)
        .await
        .map_err(map_command_log)?;
    if head.state() != dtx_agent_control::CommandLogState::Active {
        return Err(AgentRouteBootstrapError::Conflict);
    }
    let sequence = head
        .last_sequence()
        .checked_add(1)
        .filter(|value| *value <= Revision::MAX)
        .ok_or(AgentRouteBootstrapError::Conflict)?;

    // The operation is deliberately inserted before the durable command.  Its
    // publication trigger is deferred, so commit verifies the command has been
    // appended without exposing an operation that has no exact command row.
    sqlx::query(
        "INSERT INTO agent.connector_control_operations (
             tenant_id, operation_id, connector_id, operation_kind, created_at_ms
         ) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(operation_id))
    .bind(Uuid::from(connector_id))
    .bind(operation_kind)
    .bind(now.get())
    .execute(&mut *connection)
    .await
    .map_err(map_sql)?;

    let encoded = ProtobufDurableCommandEncoder
        .encode(
            sequence,
            operation_id,
            head.generation(),
            head.spec_revision(),
            &control_payload,
        )
        .map_err(|_| AgentRouteBootstrapError::InvalidRequest)?;
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
    .map_err(|_| AgentRouteBootstrapError::InvalidRequest)?;
    repository
        .append_locked(
            connection,
            tenant_id,
            connector_id,
            head,
            &durable,
            &ProtobufDurableCommandDecoder,
            now.get(),
        )
        .await
        .map_err(map_command_log)?;
    Ok(durable)
}

async fn terminal_target(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    command: &AgentRouteBootstrapTerminalCommand,
    now: UtcMillis,
) -> Result<RouteBootstrapRecord, AgentRouteBootstrapError> {
    expire_bootstrap_if_due(connection, tenant_id, command.bootstrap_id, now).await?;
    let row = load_bootstrap_for_update(connection, tenant_id, command.bootstrap_id)
        .await?
        .ok_or(AgentRouteBootstrapError::NotFound)?;
    if row.binding_id != binding_id
        || row.agent_control_device_id != agent_control_device_id
        || row.delivery_id != Some(command.delivery_id)
        || row.route_id != Some(command.route_id)
        || row.bootstrap_capsule_digest != Some(command.capsule_digest)
        || row.expires_at <= now
    {
        return Err(AgentRouteBootstrapError::Conflict);
    }
    Ok(row)
}

async fn authenticate_owner(
    connection: &mut sqlx::PgConnection,
    credential: &DeviceSessionCredential,
    now: UtcMillis,
) -> Result<(IdentityId, DeviceId, [u8; 32]), AgentRouteBootstrapError> {
    let authenticated = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
        connection, credential, now,
    )
    .await
    .map_err(|error| match error {
        dtx_identity_persistence::IdentityPersistenceError::DeviceAuthenticationRejected => {
            AgentRouteBootstrapError::AuthenticationRejected
        }
        _ => AgentRouteBootstrapError::Unavailable,
    })?;
    Ok((
        authenticated.session().identity_id(),
        authenticated.session().device_id(),
        *authenticated.signing_key().as_bytes(),
    ))
}

fn verify_owner_signature(
    public_key: [u8; 32],
    binding_digest: Sha256Digest,
    signature: Ed25519Signature,
    domain: &[u8],
) -> Result<(), AgentRouteBootstrapError> {
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| AgentRouteBootstrapError::InvalidRequest)?;
    let mut input = domain.to_vec();
    input.extend_from_slice(binding_digest.as_bytes());
    verifying_key
        .verify_strict(&input, &Signature::from_bytes(signature.as_bytes()))
        .map_err(|_| AgentRouteBootstrapError::InvalidRequest)
}

async fn ensure_owner_target(
    connection: &mut sqlx::PgConnection,
    command: &AgentRouteBootstrapBeginCommand,
) -> Result<ConnectorId, AgentRouteBootstrapError> {
    let target = resolve_owned_agent_route_bootstrap_target(
        connection,
        command.tenant_id,
        command.owner_identity_id,
        command.installation_id,
        command.binding_id,
    )
    .await
    .map_err(|error| match error {
        // Begin historically classifies an unavailable target as a mutable
        // route conflict.  Preserve that externally visible behavior while
        // the discovery GET can safely use a non-enumerating NotFound.
        AgentRouteBootstrapError::NotFound => AgentRouteBootstrapError::Conflict,
        other => other,
    })?;
    if target.agent_control_device_id != command.agent_control_device_id {
        return Err(AgentRouteBootstrapError::Conflict);
    }
    Ok(target.connector_id)
}

async fn load_current_server_receipt_pin(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> Result<(Option<RouteHealthKeyId>, Option<[u8; 32]>), AgentRouteBootstrapError> {
    let row = sqlx::query(
        "SELECT c.route_health_receipt_key_id,
                c.route_health_receipt_public_key
           FROM agent.connector_control_credential_heads AS h
           JOIN agent.connector_control_credential_revisions AS r
             ON r.tenant_id=h.tenant_id AND r.connector_id=h.connector_id
            AND r.authorization_revision=h.current_revision
           JOIN agent.connector_control_credentials AS c
             ON c.tenant_id=r.tenant_id AND c.connector_id=r.connector_id
            AND c.credential_id=r.current_credential_id
          WHERE h.tenant_id=$1 AND h.connector_id=$2
          LIMIT 1",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .fetch_optional(&mut *connection)
    .await
    .map_err(map_sql)?;
    let Some(row) = row else {
        // Legacy v1.5 fixtures may not materialize a credential revision row;
        // preserve the absence of a receipt pin rather than inventing one.
        return Ok((None, None));
    };
    let key_id: Option<Uuid> = row
        .try_get("route_health_receipt_key_id")
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
    let public: Option<Vec<u8>> = row
        .try_get("route_health_receipt_public_key")
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?;
    match (key_id, public) {
        (None, None) => Ok((None, None)),
        (Some(key_id), Some(public)) => Ok((
            Some(
                RouteHealthKeyId::try_from(key_id)
                    .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
            ),
            Some(
                public
                    .try_into()
                    .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
            ),
        )),
        _ => Err(AgentRouteBootstrapError::Unavailable),
    }
}

async fn resolve_owned_agent_route_bootstrap_target(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    owner_identity_id: IdentityId,
    installation_id: InstallationId,
    binding_id: BindingId,
) -> Result<AgentRouteBootstrapTarget, AgentRouteBootstrapError> {
    let target: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT b.connector_id, b.agent_device_id
           FROM agent.installations i
           JOIN agent.connector_bindings b
             ON b.tenant_id=i.tenant_id AND b.installation_id=i.installation_id
           JOIN agent.agent_devices d
             ON d.tenant_id=i.tenant_id AND d.agent_device_id=b.agent_device_id
          WHERE i.tenant_id=$1 AND i.installation_id=$2 AND i.owner_id=$3
            AND i.desired_state = 'enabled'
            AND b.binding_id=$4 AND b.state='enabled'
            AND d.installation_id=i.installation_id AND d.state = 'active'
          FOR SHARE OF i, b, d",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(installation_id))
    .bind(owner_identity_id.to_string())
    .bind(Uuid::from(binding_id))
    .fetch_optional(&mut *connection)
    .await
    .map_err(map_sql)?;
    let (connector_id, agent_control_device_id) =
        target.ok_or(AgentRouteBootstrapError::NotFound)?;
    let (server_receipt_key_id, server_receipt_public_key) = load_current_server_receipt_pin(
        connection,
        tenant_id,
        ConnectorId::try_from(connector_id).map_err(|_| AgentRouteBootstrapError::Unavailable)?,
    )
    .await?;
    Ok(AgentRouteBootstrapTarget {
        connector_id: ConnectorId::try_from(connector_id)
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        agent_control_device_id: AgentDeviceId::try_from(agent_control_device_id)
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        server_receipt_key_id,
        server_receipt_public_key,
    })
}

/// Revalidates the exact persisted tuple before accepting an asynchronous
/// Connector receipt.  A missing or unusable tuple is a normal terminal
/// condition; database failures remain unavailable so callers never convert
/// an infrastructure failure into a revocation.
pub(crate) async fn is_owned_agent_route_bootstrap_target_live(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    owner_identity_id: IdentityId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_control_device_id: AgentDeviceId,
    connector_id: ConnectorId,
) -> Result<bool, AgentRouteBootstrapError> {
    match resolve_owned_agent_route_bootstrap_target(
        connection,
        tenant_id,
        owner_identity_id,
        installation_id,
        binding_id,
    )
    .await
    {
        Ok(target) => Ok(target.agent_control_device_id == agent_control_device_id
            && target.connector_id == connector_id),
        Err(AgentRouteBootstrapError::NotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

async fn expire_live_tuple(
    connection: &mut sqlx::PgConnection,
    command: &AgentRouteBootstrapBeginCommand,
    now: UtcMillis,
) -> Result<(), AgentRouteBootstrapError> {
    sqlx::query(
        "UPDATE agent.agent_route_bootstraps SET state='expired', updated_at_ms=$7
          WHERE tenant_id=$1 AND owner_identity_id=$2 AND owner_device_id=$3
            AND installation_id=$4 AND binding_id=$5 AND agent_control_device_id=$6
            AND state IN ('pending_recipient','recipient_ready','pending_delivery','installed')
            AND expires_at_ms <= $7",
    )
    .bind(Uuid::from(command.tenant_id))
    .bind(command.owner_identity_id.to_string())
    .bind(Uuid::from(command.owner_device_id))
    .bind(Uuid::from(command.installation_id))
    .bind(Uuid::from(command.binding_id))
    .bind(Uuid::from(command.agent_control_device_id))
    .bind(now.get())
    .execute(&mut *connection)
    .await
    .map_err(map_sql)?;
    Ok(())
}

async fn expire_bootstrap_if_due(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    bootstrap_id: AgentRouteBootstrapId,
    now: UtcMillis,
) -> Result<(), AgentRouteBootstrapError> {
    sqlx::query(
        "UPDATE agent.agent_route_bootstraps SET state='expired', updated_at_ms=$3
          WHERE tenant_id=$1 AND bootstrap_id=$2
            AND state IN ('pending_recipient','recipient_ready','pending_delivery','installed')
            AND expires_at_ms <= $3",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(bootstrap_id))
    .bind(now.get())
    .execute(&mut *connection)
    .await
    .map_err(map_sql)?;
    Ok(())
}

async fn load_bootstrap_for_update(
    connection: &mut sqlx::PgConnection,
    tenant_id: TenantId,
    bootstrap_id: AgentRouteBootstrapId,
) -> Result<Option<RouteBootstrapRecord>, AgentRouteBootstrapError> {
    let row = sqlx::query(
        "SELECT bootstrap_id, tenant_id, owner_identity_id, owner_device_id, installation_id,
                binding_id, agent_control_device_id, connector_id, route_fence, state,
                recipient_id, recipient_capsule_digest, opaque_recipient_capsule, route_id,
                delivery_id, bootstrap_capsule_digest, rejection_code, expires_at_ms,
                created_at_ms, updated_at_ms, route_health_key_id,
                route_health_public_key, server_receipt_key_id,
                server_receipt_public_key, server_receipt_public_key_digest
           FROM agent.agent_route_bootstraps
          WHERE tenant_id=$1 AND bootstrap_id=$2 FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(bootstrap_id))
    .fetch_optional(&mut *connection)
    .await
    .map_err(map_sql)?;
    row.map(|row| route_bootstrap_record_from_row(&row))
        .transpose()
}

fn route_bootstrap_record_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<RouteBootstrapRecord, AgentRouteBootstrapError> {
    Ok(RouteBootstrapRecord {
        bootstrap_id: AgentRouteBootstrapId::try_from(
            row.try_get::<Uuid, _>("bootstrap_id")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        tenant_id: TenantId::try_from(
            row.try_get::<Uuid, _>("tenant_id")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        owner_identity_id: row
            .try_get::<String, _>("owner_identity_id")
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?
            .parse()
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        owner_device_id: DeviceId::try_from(
            row.try_get::<Uuid, _>("owner_device_id")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        installation_id: InstallationId::try_from(
            row.try_get::<Uuid, _>("installation_id")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        binding_id: BindingId::try_from(
            row.try_get::<Uuid, _>("binding_id")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        agent_control_device_id: AgentDeviceId::try_from(
            row.try_get::<Uuid, _>("agent_control_device_id")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        connector_id: ConnectorId::try_from(
            row.try_get::<Uuid, _>("connector_id")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        route_health_key_id: optional_uuid(row, "route_health_key_id")?
            .map(RouteHealthKeyId::try_from)
            .transpose()
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        route_health_public_key: row
            .try_get::<Option<Vec<u8>>, _>("route_health_public_key")
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?
            .map(|value| value.try_into())
            .transpose()
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        server_receipt_key_id: optional_uuid(row, "server_receipt_key_id")?
            .map(RouteHealthKeyId::try_from)
            .transpose()
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        server_receipt_public_key: row
            .try_get::<Option<Vec<u8>>, _>("server_receipt_public_key")
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?
            .map(|value| value.try_into())
            .transpose()
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        server_receipt_public_key_digest: optional_bytes32(
            row,
            "server_receipt_public_key_digest",
        )?
        .map(Sha256Digest::from_bytes),
        route_fence: optional_bytes32(row, "route_fence")?,
        state: AgentRouteBootstrapState::parse(
            &row.try_get::<String, _>("state")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )?,
        recipient_id: optional_uuid(row, "recipient_id")?
            .map(AgentRouteRecipientId::try_from)
            .transpose()
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        recipient_capsule_digest: optional_bytes32(row, "recipient_capsule_digest")?
            .map(Sha256Digest::from_bytes),
        opaque_recipient_capsule: row
            .try_get("opaque_recipient_capsule")
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        route_id: optional_uuid(row, "route_id")?
            .map(ConversationId::try_from)
            .transpose()
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        delivery_id: optional_uuid(row, "delivery_id")?
            .map(AgentRouteDeliveryId::try_from)
            .transpose()
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        bootstrap_capsule_digest: optional_bytes32(row, "bootstrap_capsule_digest")?
            .map(Sha256Digest::from_bytes),
        rejection_code: row
            .try_get("rejection_code")
            .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        expires_at: UtcMillis::new(
            row.try_get("expires_at_ms")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        created_at: UtcMillis::new(
            row.try_get("created_at_ms")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        updated_at: UtcMillis::new(
            row.try_get("updated_at_ms")
                .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
        )
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?,
    })
}

fn owner_receipt_cbor(
    tenant_id: TenantId,
    bootstrap_id: AgentRouteBootstrapId,
    state: AgentRouteBootstrapState,
    recipient_id: Option<AgentRouteRecipientId>,
    delivery_id: Option<AgentRouteDeliveryId>,
    route_id: Option<ConversationId>,
    route_fence: Option<[u8; 32]>,
    server_receipt_key_id: Option<RouteHealthKeyId>,
    server_receipt_public_key_digest: Option<Sha256Digest>,
    expires_at: UtcMillis,
    updated_at: UtcMillis,
    opaque_recipient_capsule: Option<&[u8]>,
) -> Result<Vec<u8>, AgentRouteBootstrapError> {
    let mut fields = vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Unsigned(
                if server_receipt_key_id.is_some() && server_receipt_public_key_digest.is_some() {
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
            CanonicalValue::Text(bootstrap_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Unsigned(state.receipt_code()),
        ),
        (CanonicalValue::Unsigned(5), optional_text(recipient_id)),
        (CanonicalValue::Unsigned(6), optional_text(delivery_id)),
        (CanonicalValue::Unsigned(7), optional_text(route_id)),
        (
            CanonicalValue::Unsigned(8),
            route_fence.map_or(CanonicalValue::Null, |value| {
                CanonicalValue::Bytes(value.to_vec())
            }),
        ),
        (CanonicalValue::Unsigned(9), expires_at.to_canonical_value()),
        (
            CanonicalValue::Unsigned(10),
            updated_at.to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(11),
            opaque_recipient_capsule.map_or(CanonicalValue::Null, |bytes| {
                CanonicalValue::Bytes(bytes.to_vec())
            }),
        ),
    ];
    if let (Some(key_id), Some(digest)) = (server_receipt_key_id, server_receipt_public_key_digest)
    {
        fields.push((CanonicalValue::Unsigned(12), optional_text(Some(key_id))));
        fields.push((
            CanonicalValue::Unsigned(13),
            CanonicalValue::Bytes(digest.as_bytes().to_vec()),
        ));
    }
    encode_deterministic_cbor(&CanonicalValue::Map(fields))
        .map_err(|_| AgentRouteBootstrapError::Unavailable)
}

fn owner_view_cbor(row: &RouteBootstrapRecord) -> Result<Vec<u8>, AgentRouteBootstrapError> {
    owner_receipt_cbor(
        row.tenant_id,
        row.bootstrap_id,
        row.state,
        row.recipient_id,
        row.delivery_id,
        row.route_id,
        row.route_fence,
        row.server_receipt_key_id,
        row.server_receipt_public_key_digest,
        row.expires_at,
        row.updated_at,
        row.opaque_recipient_capsule.as_deref(),
    )
}

fn prepare_outbox_payload(
    command: &AgentRouteBootstrapBeginCommand,
    owner_signed_intent: &[u8],
) -> Result<Vec<u8>, AgentRouteBootstrapError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(command.bootstrap_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(command.tenant_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(command.installation_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(command.binding_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(command.agent_control_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Text(command.owner_identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(command.owner_device_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Bytes(owner_signed_intent.to_vec()),
        ),
        (
            CanonicalValue::Unsigned(10),
            command.expires_at.to_canonical_value(),
        ),
    ]))
    .map_err(|_| AgentRouteBootstrapError::Unavailable)
}

fn delivery_outbox_payload(
    command: &AgentRouteBootstrapDeliveryCommand,
) -> Result<Vec<u8>, AgentRouteBootstrapError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(command.bootstrap_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(command.delivery_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(command.route_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(command.recipient_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Bytes(command.capsule_digest.as_bytes().to_vec()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Bytes(command.opaque_sealed_bootstrap.clone()),
        ),
        (
            CanonicalValue::Unsigned(8),
            command.expires_at.to_canonical_value(),
        ),
    ]))
    .map_err(|_| AgentRouteBootstrapError::Unavailable)
}

fn validate_begin(
    command: &AgentRouteBootstrapBeginCommand,
    exact_body: &[u8],
    now: UtcMillis,
) -> Result<(), AgentRouteBootstrapError> {
    if exact_body.is_empty()
        || exact_body.len() > MAX_OPAQUE_BYTES
        || command.owner_signed_intent.is_empty()
        || command.owner_signed_intent.len() > MAX_OPAQUE_BYTES
        || command.expires_at <= now
        || command.expires_at.get() > now.get().saturating_add(MAX_BOOTSTRAP_LIFETIME_MS)
    {
        return Err(AgentRouteBootstrapError::InvalidRequest);
    }
    Ok(())
}

fn validate_delivery(
    command: &AgentRouteBootstrapDeliveryCommand,
    exact_body: &[u8],
    now: UtcMillis,
) -> Result<(), AgentRouteBootstrapError> {
    if exact_body.is_empty()
        || exact_body.len() > MAX_OPAQUE_BYTES
        || command.opaque_sealed_bootstrap.is_empty()
        || command.opaque_sealed_bootstrap.len() > MAX_OPAQUE_BYTES
        || command.expires_at <= now
        || Sha256Digest::hash_domain(
            AGENT_ROUTE_BOOTSTRAP_CAPSULE_DOMAIN,
            &command.opaque_sealed_bootstrap,
        ) != command.capsule_digest
    {
        return Err(AgentRouteBootstrapError::InvalidRequest);
    }
    if command.server_receipt_key_id.is_some() != command.server_receipt_public_key_digest.is_some()
    {
        return Err(AgentRouteBootstrapError::InvalidRequest);
    }
    Ok(())
}

fn receipt_pin_matches(
    expected_key_id: Option<RouteHealthKeyId>,
    expected_public_key_digest: Option<Sha256Digest>,
    supplied_key_id: Option<RouteHealthKeyId>,
    supplied_public_key_digest: Option<Sha256Digest>,
) -> bool {
    expected_key_id == supplied_key_id && expected_public_key_digest == supplied_public_key_digest
}

#[cfg(test)]
mod tests {
    use super::{AgentRouteBootstrapState, owner_receipt_cbor, receipt_pin_matches};
    use dtx_domain::{AgentRouteBootstrapId, RouteHealthKeyId, TenantId};
    use dtx_wire::{CanonicalValue, Sha256Digest, UtcMillis, decode_deterministic_cbor};

    #[test]
    fn receipt_pin_fence_requires_the_exact_paired_id_and_digest() {
        let key_a = RouteHealthKeyId::new();
        let key_b = RouteHealthKeyId::new();
        let digest_a = Sha256Digest::from_bytes([0x11; 32]);
        let digest_b = Sha256Digest::from_bytes([0x22; 32]);
        assert!(receipt_pin_matches(
            Some(key_a),
            Some(digest_a),
            Some(key_a),
            Some(digest_a)
        ));
        assert!(!receipt_pin_matches(
            Some(key_a),
            Some(digest_a),
            None,
            None
        ));
        assert!(!receipt_pin_matches(
            Some(key_a),
            Some(digest_a),
            Some(key_a),
            None
        ));
        assert!(!receipt_pin_matches(
            Some(key_a),
            Some(digest_a),
            Some(key_b),
            Some(digest_a)
        ));
        assert!(!receipt_pin_matches(
            Some(key_a),
            Some(digest_a),
            Some(key_a),
            Some(digest_b)
        ));
        assert!(!receipt_pin_matches(
            Some(key_a),
            Some(digest_a),
            Some(key_b),
            Some(digest_b)
        ));
        assert!(receipt_pin_matches(None, None, None, None));
    }

    #[test]
    fn owner_receipt_v1_bytes_stay_legacy_and_pinned_replays_are_identical() {
        let tenant_id = TenantId::new();
        let bootstrap_id = AgentRouteBootstrapId::new();
        let expires_at = UtcMillis::new(1_756_700_000_000).unwrap();
        let updated_at = UtcMillis::new(1_756_699_999_000).unwrap();
        let legacy = owner_receipt_cbor(
            tenant_id,
            bootstrap_id,
            AgentRouteBootstrapState::PendingRecipient,
            None,
            None,
            None,
            None,
            None,
            None,
            expires_at,
            updated_at,
            None,
        )
        .unwrap();
        let CanonicalValue::Map(legacy_fields) = decode_deterministic_cbor(&legacy).unwrap() else {
            panic!("receipt must be a map")
        };
        assert_eq!(legacy_fields.len(), 11);
        assert_eq!(legacy_fields[0].1, CanonicalValue::Unsigned(1));

        let key_id = RouteHealthKeyId::new();
        let digest = Sha256Digest::from_bytes([0x33; 32]);
        let pinned = owner_receipt_cbor(
            tenant_id,
            bootstrap_id,
            AgentRouteBootstrapState::PendingRecipient,
            None,
            None,
            None,
            None,
            Some(key_id),
            Some(digest),
            expires_at,
            updated_at,
            None,
        )
        .unwrap();
        assert_eq!(
            pinned,
            owner_receipt_cbor(
                tenant_id,
                bootstrap_id,
                AgentRouteBootstrapState::PendingRecipient,
                None,
                None,
                None,
                None,
                Some(key_id),
                Some(digest),
                expires_at,
                updated_at,
                None,
            )
            .unwrap()
        );
        let CanonicalValue::Map(pinned_fields) = decode_deterministic_cbor(&pinned).unwrap() else {
            panic!("receipt must be a map")
        };
        assert_eq!(pinned_fields.len(), 13);
        assert_eq!(pinned_fields[0].1, CanonicalValue::Unsigned(2));
        assert_eq!(pinned_fields[11].0, CanonicalValue::Unsigned(12));
        assert_eq!(pinned_fields[12].0, CanonicalValue::Unsigned(13));
        assert_ne!(legacy, pinned);
    }
}

fn valid_stable_code(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && value.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
}

fn optional_text<T: ToString>(value: Option<T>) -> CanonicalValue {
    value.map_or(CanonicalValue::Null, |value| {
        CanonicalValue::Text(value.to_string())
    })
}

fn bytes32(value: Vec<u8>) -> Result<[u8; 32], AgentRouteBootstrapError> {
    value
        .try_into()
        .map_err(|_| AgentRouteBootstrapError::Unavailable)
}

fn optional_bytes32(
    row: &sqlx::postgres::PgRow,
    field: &str,
) -> Result<Option<[u8; 32]>, AgentRouteBootstrapError> {
    row.try_get::<Option<Vec<u8>>, _>(field)
        .map_err(|_| AgentRouteBootstrapError::Unavailable)?
        .map(bytes32)
        .transpose()
}

fn optional_uuid(
    row: &sqlx::postgres::PgRow,
    field: &str,
) -> Result<Option<Uuid>, AgentRouteBootstrapError> {
    row.try_get(field)
        .map_err(|_| AgentRouteBootstrapError::Unavailable)
}

async fn lock_uuid(
    connection: &mut sqlx::PgConnection,
    id: Uuid,
) -> Result<(), AgentRouteBootstrapError> {
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&id.as_bytes()[..8]);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(i64::from_be_bytes(prefix) ^ i64::MIN)
        .execute(&mut *connection)
        .await
        .map_err(map_sql)?;
    Ok(())
}

fn map_sql(error: sqlx::Error) -> AgentRouteBootstrapError {
    if error
        .as_database_error()
        .and_then(|database| database.code())
        .is_some_and(|code| code == "23505")
    {
        AgentRouteBootstrapError::Conflict
    } else {
        AgentRouteBootstrapError::Unavailable
    }
}

fn map_command_log(error: AgentPersistenceError) -> AgentRouteBootstrapError {
    match error {
        AgentPersistenceError::ImmutableConflict(_)
        | AgentPersistenceError::RevisionConflict { .. }
        | AgentPersistenceError::FenceConflict
        | AgentPersistenceError::ClaimRejected(_)
        | AgentPersistenceError::AuthorizationRejected(_)
        | AgentPersistenceError::CursorConflict { .. } => AgentRouteBootstrapError::Conflict,
        AgentPersistenceError::Database(error) => map_sql(error),
        AgentPersistenceError::CorruptData(_)
        | AgentPersistenceError::CommandDecodeRejected
        | AgentPersistenceError::MaterializationLimitExceeded(_)
        | AgentPersistenceError::SnapshotRejected(_) => AgentRouteBootstrapError::Unavailable,
    }
}
