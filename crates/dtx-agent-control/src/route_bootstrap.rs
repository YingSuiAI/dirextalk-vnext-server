//! Additive Agent Control 1.4 RouteBootstrap value objects.
//!
//! These payloads deliberately carry only identifiers, commitments, expiry,
//! and bounded opaque bytes.  They are transport-neutral so a future control
//! stream encoder can adopt them without teaching the control plane how to
//! inspect an MLS/HPKE recipient or bootstrap capsule.

use std::fmt;

use dtx_domain::{
    AgentDeviceId, AgentRouteBootstrapId, AgentRouteDeliveryId, AgentRouteRecipientId, BindingId,
    ConversationId, DeviceId, IdentityId, InstallationId, RouteHealthKeyId, TenantId,
};

use crate::{CommandError, Sha256Digest};

/// Largest opaque AgentRoute recipient or bootstrap capsule accepted by v1.4.
pub const MAX_AGENT_ROUTE_CAPSULE_BYTES: usize = 196_608;

/// Bounded opaque bytes retained and forwarded without parsing.
#[derive(Clone, Eq, PartialEq)]
pub struct OpaqueAgentRouteBytes(Vec<u8>);

impl OpaqueAgentRouteBytes {
    /// Retains non-empty opaque bytes within the RouteBootstrap v1.4 bound.
    pub fn new(bytes: Vec<u8>) -> Result<Self, CommandError> {
        if bytes.is_empty() || bytes.len() > MAX_AGENT_ROUTE_CAPSULE_BYTES {
            return Err(CommandError::InvalidCommandPayload);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

fn validate_opaque_command_payload(
    opaque_bytes: &OpaqueAgentRouteBytes,
    expires_at_millis: i64,
) -> Result<(), CommandError> {
    if expires_at_millis <= 0
        || opaque_bytes.as_slice().is_empty()
        || opaque_bytes.as_slice().len() > MAX_AGENT_ROUTE_CAPSULE_BYTES
    {
        return Err(CommandError::InvalidCommandPayload);
    }
    Ok(())
}

impl fmt::Debug for OpaqueAgentRouteBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OpaqueAgentRouteBytes")
            .field(&format_args!("<{} bytes>", self.0.len()))
            .finish()
    }
}

/// Server-to-Agent-Control request to make one one-time recipient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareAgentRouteRecipient {
    pub bootstrap_id: AgentRouteBootstrapId,
    pub tenant_id: TenantId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub agent_control_device_id: AgentDeviceId,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub owner_signed_intent: OpaqueAgentRouteBytes,
    pub expires_at_millis: i64,
}

impl PrepareAgentRouteRecipient {
    /// Validates the bounded opaque command body and its positive deadline.
    ///
    /// Identifier and digest validity is carried by their domain value types.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized opaque intent, or a non-positive expiry.
    pub fn validate(&self) -> Result<(), CommandError> {
        validate_opaque_command_payload(&self.owner_signed_intent, self.expires_at_millis)
    }
}

/// Agent-Control's opaque recipient answer for one bootstrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRouteRecipientReady {
    pub bootstrap_id: AgentRouteBootstrapId,
    pub recipient_id: AgentRouteRecipientId,
    pub recipient_capsule_digest: Sha256Digest,
    pub opaque_recipient_capsule: OpaqueAgentRouteBytes,
    pub expires_at_millis: i64,
}

/// Owner-authorized opaque route bootstrap delivery to Agent-Control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliverAgentRouteBootstrap {
    pub bootstrap_id: AgentRouteBootstrapId,
    pub delivery_id: AgentRouteDeliveryId,
    pub route_id: ConversationId,
    pub recipient_id: AgentRouteRecipientId,
    pub capsule_digest: Sha256Digest,
    pub opaque_sealed_bootstrap: OpaqueAgentRouteBytes,
    pub expires_at_millis: i64,
    /// Exact installation selected by the Owner; never inferred from route ID.
    pub installation_id: InstallationId,
    /// Exact Connector binding selected by the Owner; never inferred from installation alone.
    pub binding_id: BindingId,
    /// Exact Agent Control device that must import this isolated route.
    pub agent_control_device_id: AgentDeviceId,
    /// Exact health signing key selected by the recipient sidecar.  The
    /// private key never enters this command or the control plane.
    pub route_health_key_id: Option<RouteHealthKeyId>,
    pub route_health_public_key_digest: Option<Sha256Digest>,
}

impl DeliverAgentRouteBootstrap {
    /// Validates the bounded opaque command body and its positive deadline.
    ///
    /// Identifier and digest validity is carried by their domain value types.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized opaque bootstrap, or a non-positive expiry.
    pub fn validate(&self) -> Result<(), CommandError> {
        validate_opaque_command_payload(&self.opaque_sealed_bootstrap, self.expires_at_millis)?;
        if self.route_health_key_id.is_some() != self.route_health_public_key_digest.is_some() {
            return Err(CommandError::InvalidCommandPayload);
        }
        Ok(())
    }
}

/// Stable, non-secret reason returned by Agent-Control for a terminal result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRouteBootstrapStableCode {
    Installed,
    InvalidCapsule,
    Expired,
    Conflict,
    LocalUnavailable,
}

/// Agent-Control proof that one opaque delivery was installed locally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRouteBootstrapInstalled {
    pub bootstrap_id: AgentRouteBootstrapId,
    pub delivery_id: AgentRouteDeliveryId,
    pub route_id: ConversationId,
    pub capsule_digest: Sha256Digest,
    /// Generated by the local MLS route import; it is not supplied by the
    /// owner Begin or Delivery request.
    pub route_fence: [u8; 32],
    pub stable_code: AgentRouteBootstrapStableCode,
}

/// Agent-Control's terminal rejection for one opaque delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRouteBootstrapRejected {
    pub bootstrap_id: AgentRouteBootstrapId,
    pub delivery_id: AgentRouteDeliveryId,
    pub route_id: ConversationId,
    pub capsule_digest: Sha256Digest,
    pub stable_code: AgentRouteBootstrapStableCode,
}
