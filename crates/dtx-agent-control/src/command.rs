use std::{collections::BTreeSet, error::Error, fmt};

use dtx_connect_registry::ConnectorDesiredState;
use dtx_domain::{
    AgentDeviceId, ApprovalId, BindingId, ConnectorId, InstallationId, ProvisioningDeliveryId,
    ProvisioningRecipientKeyId, RequestId, Revision, TenantId,
};

use crate::{
    DeliverAgentRouteBootstrap, PrepareAgentRouteRecipient, Sha256Digest, digest::domain_digest,
};

const COMMAND_PAYLOAD_DOMAIN: &[u8] = b"dirextalk.connector-command-payload.v1";
const ENCODED_COMMAND_DOMAIN: &[u8] = b"dirextalk.connector-encoded-command.v1";

/// Maximum exact Protobuf bytes retained for one durable command.
pub const MAX_COMMAND_BYTES: usize = 196_608;
/// Maximum unacknowledged commands allowed for one Connector.
pub const MAX_COMMAND_BACKLOG: usize = 4_096;
pub const MAX_CONFIG_ENTRIES_PER_SCOPE: usize = 64;
pub const MAX_CONFIG_KEY_BYTES: usize = 64;
pub const MAX_CONFIG_VALUE_BYTES: usize = 1_024;
pub const MAX_CLOSE_STREAM_CODE_BYTES: usize = 64;
pub const MAX_CLOSE_STREAM_DETAIL_BYTES: usize = 512;
pub const MAX_PROVISIONING_CAPSULE_BYTES: usize = 196_608;

/// Exact immutable wire bytes used for byte-for-byte replay.
#[derive(Clone, Eq, PartialEq)]
pub struct ExactCommandBytes(Vec<u8>);

impl ExactCommandBytes {
    /// Retains one bounded, non-empty exact `DurableCommand` encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::InvalidCommandBytes`] outside the wire bound.
    pub fn new(bytes: Vec<u8>) -> Result<Self, CommandError> {
        if bytes.is_empty() || bytes.len() > MAX_COMMAND_BYTES {
            Err(CommandError::InvalidCommandBytes)
        } else {
            Ok(Self(bytes))
        }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    #[must_use]
    pub fn encoded_command_digest(&self) -> Sha256Digest {
        domain_digest(ENCODED_COMMAND_DOMAIN, &[&self.0])
    }
}

/// Computes the frozen digest over one exact selected command submessage.
///
/// # Errors
///
/// Returns [`CommandError::InvalidCommandPayloadBytes`] for empty or oversized bytes.
pub fn command_payload_digest(bytes: &[u8]) -> Result<Sha256Digest, CommandError> {
    if bytes.is_empty() || bytes.len() > MAX_COMMAND_BYTES {
        Err(CommandError::InvalidCommandPayloadBytes)
    } else {
        Ok(domain_digest(COMMAND_PAYLOAD_DOMAIN, &[bytes]))
    }
}

/// One bounded non-secret configuration value in a closed adapter/runtime map.
#[derive(Clone, Eq, PartialEq)]
pub struct ConfigEntry {
    key: String,
    value: String,
}

impl fmt::Debug for ConfigEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigEntry")
            .field("key", &self.key)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl ConfigEntry {
    /// Creates one bounded lower-stable-name configuration entry.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::InvalidConfigEntry`] for an invalid key, value,
    /// or control character.
    pub fn new(key: String, value: String) -> Result<Self, CommandError> {
        if !valid_lower_stable_name(&key, MAX_CONFIG_KEY_BYTES)
            || value.len() > MAX_CONFIG_VALUE_BYTES
            || contains_c0_c1_control(&value)
            || !registered_config_entry_is_valid(&key, &value)
        {
            return Err(CommandError::InvalidConfigEntry);
        }
        Ok(Self { key, value })
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for ExactCommandBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExactCommandBytes")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyConfigCommand {
    config_revision: Revision,
    desired_state: ConnectorDesiredState,
    adapter_config: Vec<ConfigEntry>,
    runtime_config: Vec<ConfigEntry>,
}

impl ApplyConfigCommand {
    /// Creates canonical, duplicate-free adapter and runtime configuration maps.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError`] for revocation-as-config, invalid entries,
    /// duplicates, or an excessive entry count.
    pub fn new(
        config_revision: Revision,
        desired_state: ConnectorDesiredState,
        mut adapter_config: Vec<ConfigEntry>,
        mut runtime_config: Vec<ConfigEntry>,
    ) -> Result<Self, CommandError> {
        if desired_state == ConnectorDesiredState::Revoked {
            return Err(CommandError::InvalidCommandPayload);
        }
        canonicalize_config(&mut adapter_config)?;
        canonicalize_config(&mut runtime_config)?;
        Ok(Self {
            config_revision,
            desired_state,
            adapter_config,
            runtime_config,
        })
    }

    #[must_use]
    pub const fn config_revision(&self) -> Revision {
        self.config_revision
    }

    #[must_use]
    pub const fn desired_state(&self) -> ConnectorDesiredState {
        self.desired_state
    }

    #[must_use]
    pub fn adapter_config(&self) -> &[ConfigEntry] {
        &self.adapter_config
    }

    #[must_use]
    pub fn runtime_config(&self) -> &[ConfigEntry] {
        &self.runtime_config
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotateCredentialCommand {
    nonce: [u8; 32],
    successor_revision: Revision,
    deadline_millis: i64,
}

impl RotateCredentialCommand {
    /// Creates one bounded credential-rotation instruction.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::InvalidCommandPayload`] for an invalid deadline.
    pub fn new(
        nonce: [u8; 32],
        successor_revision: Revision,
        deadline_millis: i64,
    ) -> Result<Self, CommandError> {
        if !(1..=Revision::MAX.cast_signed()).contains(&deadline_millis) {
            return Err(CommandError::InvalidCommandPayload);
        }
        Ok(Self {
            nonce,
            successor_revision,
            deadline_millis,
        })
    }

    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    #[must_use]
    pub const fn successor_revision(&self) -> Revision {
        self.successor_revision
    }

    #[must_use]
    pub const fn deadline_millis(&self) -> i64 {
        self.deadline_millis
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseStreamReason {
    Reconnect,
    Drained,
    Revoked,
    ProtocolUpgrade,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseStreamCommand {
    reason: CloseStreamReason,
    stable_code: String,
    redacted_detail: String,
}

impl CloseStreamCommand {
    /// Creates a close instruction containing only bounded redacted metadata.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::InvalidCloseStreamMetadata`] for an invalid code,
    /// control character, or oversized detail.
    pub fn new(
        reason: CloseStreamReason,
        stable_code: String,
        redacted_detail: String,
    ) -> Result<Self, CommandError> {
        if !valid_upper_snake_code(&stable_code, MAX_CLOSE_STREAM_CODE_BYTES)
            || redacted_detail.len() > MAX_CLOSE_STREAM_DETAIL_BYTES
            || contains_c0_c1_control(&redacted_detail)
        {
            return Err(CommandError::InvalidCloseStreamMetadata);
        }
        Ok(Self {
            reason,
            stable_code,
            redacted_detail,
        })
    }

    #[must_use]
    pub fn reconnect() -> Self {
        Self {
            reason: CloseStreamReason::Reconnect,
            stable_code: "RECONNECT".to_owned(),
            redacted_detail: String::new(),
        }
    }

    #[must_use]
    pub fn drained() -> Self {
        Self {
            reason: CloseStreamReason::Drained,
            stable_code: "DRAINED".to_owned(),
            redacted_detail: String::new(),
        }
    }

    #[must_use]
    pub fn revoked() -> Self {
        Self {
            reason: CloseStreamReason::Revoked,
            stable_code: "REVOKED".to_owned(),
            redacted_detail: String::new(),
        }
    }

    #[must_use]
    pub fn protocol_upgrade() -> Self {
        Self {
            reason: CloseStreamReason::ProtocolUpgrade,
            stable_code: "PROTOCOL_UPGRADE".to_owned(),
            redacted_detail: String::new(),
        }
    }

    #[must_use]
    pub const fn reason(&self) -> CloseStreamReason {
        self.reason
    }

    #[must_use]
    pub fn stable_code(&self) -> &str {
        &self.stable_code
    }

    #[must_use]
    pub fn redacted_detail(&self) -> &str {
        &self.redacted_detail
    }
}

/// Opaque, owner-authorized Agent provisioning capsule delivered to one exact Connector.
#[derive(Clone, Eq, PartialEq)]
pub struct DeliverAgentProvisioningCommand {
    delivery_id: ProvisioningDeliveryId,
    approval_id: ApprovalId,
    binding_id: BindingId,
    installation_id: InstallationId,
    agent_device_id: AgentDeviceId,
    provisioning_revision: Revision,
    recipient_key_id: ProvisioningRecipientKeyId,
    recipient_descriptor_digest: Sha256Digest,
    capsule_digest: Sha256Digest,
    sealed_capsule: Vec<u8>,
    expires_at_millis: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeAgentProvisioningCommand {
    revocation_id: RequestId,
    installation_id: InstallationId,
    binding_id: BindingId,
    agent_device_id: Option<AgentDeviceId>,
    revocation_revision: Revision,
    requested_at_millis: i64,
}

impl RevokeAgentProvisioningCommand {
    /// Creates one local stop/delete instruction after server-side revocation.
    ///
    /// # Errors
    ///
    /// Rejects non-positive timestamps.
    pub fn new(
        revocation_id: RequestId,
        installation_id: InstallationId,
        binding_id: BindingId,
        agent_device_id: Option<AgentDeviceId>,
        revocation_revision: Revision,
        requested_at_millis: i64,
    ) -> Result<Self, CommandError> {
        if requested_at_millis <= 0 {
            return Err(CommandError::InvalidCommandPayload);
        }
        Ok(Self {
            revocation_id,
            installation_id,
            binding_id,
            agent_device_id,
            revocation_revision,
            requested_at_millis,
        })
    }
    #[must_use]
    pub const fn revocation_id(&self) -> RequestId {
        self.revocation_id
    }
    #[must_use]
    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }
    #[must_use]
    pub const fn binding_id(&self) -> BindingId {
        self.binding_id
    }
    #[must_use]
    pub const fn agent_device_id(&self) -> Option<AgentDeviceId> {
        self.agent_device_id
    }
    #[must_use]
    pub const fn revocation_revision(&self) -> Revision {
        self.revocation_revision
    }
    #[must_use]
    pub const fn requested_at_millis(&self) -> i64 {
        self.requested_at_millis
    }
}

impl fmt::Debug for DeliverAgentProvisioningCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliverAgentProvisioningCommand")
            .field("delivery_id", &self.delivery_id)
            .field("approval_id", &self.approval_id)
            .field("binding_id", &self.binding_id)
            .field("installation_id", &self.installation_id)
            .field("agent_device_id", &self.agent_device_id)
            .field("provisioning_revision", &self.provisioning_revision)
            .field("recipient_key_id", &self.recipient_key_id)
            .field(
                "recipient_descriptor_digest",
                &self.recipient_descriptor_digest,
            )
            .field("capsule_digest", &self.capsule_digest)
            .field("sealed_capsule", &"[REDACTED]")
            .field("expires_at_millis", &self.expires_at_millis)
            .finish()
    }
}

impl DeliverAgentProvisioningCommand {
    /// Creates one bounded opaque provisioning delivery.
    ///
    /// # Errors
    ///
    /// Rejects empty/oversized capsules and non-positive expiry timestamps.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        delivery_id: ProvisioningDeliveryId,
        approval_id: ApprovalId,
        binding_id: BindingId,
        installation_id: InstallationId,
        agent_device_id: AgentDeviceId,
        provisioning_revision: Revision,
        recipient_key_id: ProvisioningRecipientKeyId,
        recipient_descriptor_digest: Sha256Digest,
        capsule_digest: Sha256Digest,
        sealed_capsule: Vec<u8>,
        expires_at_millis: i64,
    ) -> Result<Self, CommandError> {
        if sealed_capsule.is_empty()
            || sealed_capsule.len() > MAX_PROVISIONING_CAPSULE_BYTES
            || expires_at_millis <= 0
        {
            return Err(CommandError::InvalidCommandPayload);
        }
        Ok(Self {
            delivery_id,
            approval_id,
            binding_id,
            installation_id,
            agent_device_id,
            provisioning_revision,
            recipient_key_id,
            recipient_descriptor_digest,
            capsule_digest,
            sealed_capsule,
            expires_at_millis,
        })
    }

    #[must_use]
    pub const fn delivery_id(&self) -> ProvisioningDeliveryId {
        self.delivery_id
    }
    #[must_use]
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }
    #[must_use]
    pub const fn binding_id(&self) -> BindingId {
        self.binding_id
    }
    #[must_use]
    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }
    #[must_use]
    pub const fn agent_device_id(&self) -> AgentDeviceId {
        self.agent_device_id
    }
    #[must_use]
    pub const fn provisioning_revision(&self) -> Revision {
        self.provisioning_revision
    }
    #[must_use]
    pub const fn recipient_key_id(&self) -> ProvisioningRecipientKeyId {
        self.recipient_key_id
    }
    #[must_use]
    pub const fn recipient_descriptor_digest(&self) -> Sha256Digest {
        self.recipient_descriptor_digest
    }
    #[must_use]
    pub const fn capsule_digest(&self) -> Sha256Digest {
        self.capsule_digest
    }
    #[must_use]
    pub fn sealed_capsule(&self) -> &[u8] {
        &self.sealed_capsule
    }
    #[must_use]
    pub const fn expires_at_millis(&self) -> i64 {
        self.expires_at_millis
    }
}

/// Closed set of durable `MC2b` server commands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerCommandPayload {
    ApplyConfig(ApplyConfigCommand),
    RotateCredential(RotateCredentialCommand),
    CloseStream(CloseStreamCommand),
    DeliverAgentProvisioning(DeliverAgentProvisioningCommand),
    RevokeAgentProvisioning(RevokeAgentProvisioningCommand),
    /// Creates one one-time opaque recipient for an isolated AgentRoute.
    PrepareAgentRouteRecipient(PrepareAgentRouteRecipient),
    /// Delivers one already Owner-sealed isolated AgentRoute bootstrap.
    DeliverAgentRouteBootstrap(DeliverAgentRouteBootstrap),
}

/// One append-only, exactly replayable server command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableServerCommand {
    sequence: u64,
    operation_id: RequestId,
    generation: u64,
    spec_revision: Revision,
    payload: ServerCommandPayload,
    payload_digest: Sha256Digest,
    encoded_command_digest: Sha256Digest,
    exact_bytes: ExactCommandBytes,
}

impl DurableServerCommand {
    /// Rehydrates one independently fetched durable command after validating
    /// its closed payload and immutable encoded-byte digest.
    ///
    /// Sequence continuity and operation uniqueness remain command-log/head
    /// responsibilities; this constructor is intended for bounded suffix reads
    /// that have already proven those stream-level invariants.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::InvalidSnapshot`] when any command-local field is
    /// outside the frozen contract.
    pub fn try_from_snapshot(snapshot: DurableServerCommandSnapshot) -> Result<Self, CommandError> {
        validate_durable_command_snapshot(&snapshot)?;
        Ok(Self {
            sequence: snapshot.sequence,
            operation_id: snapshot.operation_id,
            generation: snapshot.generation,
            spec_revision: snapshot.spec_revision,
            payload: snapshot.payload,
            payload_digest: snapshot.payload_digest,
            encoded_command_digest: snapshot.encoded_command_digest,
            exact_bytes: snapshot.exact_bytes,
        })
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn operation_id(&self) -> RequestId {
        self.operation_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn spec_revision(&self) -> Revision {
        self.spec_revision
    }

    #[must_use]
    pub const fn payload(&self) -> &ServerCommandPayload {
        &self.payload
    }

    #[must_use]
    pub const fn payload_digest(&self) -> Sha256Digest {
        self.payload_digest
    }

    #[must_use]
    pub const fn encoded_command_digest(&self) -> Sha256Digest {
        self.encoded_command_digest
    }

    #[must_use]
    pub const fn exact_bytes(&self) -> &ExactCommandBytes {
        &self.exact_bytes
    }
}

/// Exact acknowledgement for one contiguous durable command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandAck {
    sequence: u64,
    payload_digest: Sha256Digest,
    encoded_command_digest: Sha256Digest,
    generation: u64,
    spec_revision: Revision,
}

impl CommandAck {
    #[must_use]
    pub const fn new(
        sequence: u64,
        payload_digest: Sha256Digest,
        encoded_command_digest: Sha256Digest,
        generation: u64,
        spec_revision: Revision,
    ) -> Self {
        Self {
            sequence,
            payload_digest,
            encoded_command_digest,
            generation,
            spec_revision,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandLogState {
    Active,
    Revoked,
}

/// Complete constructible persistence image for one command record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableServerCommandSnapshot {
    pub sequence: u64,
    pub operation_id: RequestId,
    pub generation: u64,
    pub spec_revision: Revision,
    pub payload: ServerCommandPayload,
    pub payload_digest: Sha256Digest,
    pub encoded_command_digest: Sha256Digest,
    pub exact_bytes: ExactCommandBytes,
}

/// Complete constructible persistence image for one Connector command log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandLogSnapshot {
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub generation: u64,
    pub spec_revision: Revision,
    pub acknowledged_sequence: u64,
    pub state: CommandLogState,
    pub commands: Vec<DurableServerCommandSnapshot>,
}

/// Per-Connector append-only command log and contiguous acknowledgement cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandLog {
    tenant_id: TenantId,
    connector_id: ConnectorId,
    generation: u64,
    spec_revision: Revision,
    acknowledged_sequence: u64,
    state: CommandLogState,
    commands: Vec<DurableServerCommand>,
}

impl CommandLog {
    /// Creates an empty command log at one exact Connector fence.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::InvalidGeneration`] for a non-positive or unsafe generation.
    pub fn new(
        tenant_id: TenantId,
        connector_id: ConnectorId,
        generation: u64,
        spec_revision: Revision,
    ) -> Result<Self, CommandError> {
        validate_generation(generation)?;
        Ok(Self {
            tenant_id,
            connector_id,
            generation,
            spec_revision,
            acknowledged_sequence: 0,
            state: CommandLogState::Active,
            commands: Vec::new(),
        })
    }

    /// Appends a command or returns the exact record for an identical operation retry.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError`] for a stale fence, invalid payload, changed
    /// operation retry, full backlog, revocation, or exhausted sequence.
    pub fn append(
        &mut self,
        generation: u64,
        spec_revision: Revision,
        operation_id: RequestId,
        payload: ServerCommandPayload,
        payload_digest: Sha256Digest,
        exact_bytes: ExactCommandBytes,
    ) -> Result<&DurableServerCommand, CommandError> {
        self.validate_fence(generation, spec_revision)?;
        validate_payload(&payload, spec_revision)?;
        let encoded_command_digest = exact_bytes.encoded_command_digest();
        if let Some(index) = self
            .commands
            .iter()
            .position(|command| command.operation_id == operation_id)
        {
            let existing = &self.commands[index];
            return if existing.generation == generation
                && existing.spec_revision == spec_revision
                && existing.payload == payload
                && existing.payload_digest.ct_eq(payload_digest)
                && existing
                    .encoded_command_digest
                    .ct_eq(encoded_command_digest)
                && existing.exact_bytes == exact_bytes
            {
                Ok(existing)
            } else {
                Err(CommandError::IdempotencyConflict)
            };
        }
        if self.state == CommandLogState::Revoked {
            return Err(CommandError::Revoked);
        }
        let acknowledged = usize::try_from(self.acknowledged_sequence)
            .map_err(|_| CommandError::InvalidSnapshot)?;
        let pending = self
            .commands
            .get(acknowledged..)
            .ok_or(CommandError::InvalidSnapshot)?;
        let pending_revoke = pending.iter().any(is_terminal_revoke);
        let has_fence_barrier = pending.iter().any(is_fence_barrier);
        let superseding_revoke = matches!(
            &payload,
            ServerCommandPayload::CloseStream(command)
                if command.reason == CloseStreamReason::Revoked
        );
        if pending_revoke || has_fence_barrier && !superseding_revoke {
            return Err(CommandError::UnacknowledgedCommands);
        }
        if self.commands.len().saturating_sub(acknowledged) >= MAX_COMMAND_BACKLOG
            && !superseding_revoke
        {
            return Err(CommandError::BacklogFull);
        }
        let sequence = (self.commands.len() as u64)
            .checked_add(1)
            .filter(|value| *value <= Revision::MAX)
            .ok_or(CommandError::CounterExhausted)?;
        self.commands.push(DurableServerCommand {
            sequence,
            operation_id,
            generation,
            spec_revision,
            payload,
            payload_digest,
            encoded_command_digest,
            exact_bytes,
        });
        self.commands.last().ok_or(CommandError::InvalidSnapshot)
    }

    /// Advances only one exact contiguous acknowledgement; exact retries are idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError`] for stale fences/cursors, gaps, unknown commands,
    /// or either digest mismatch.
    pub fn acknowledge(&mut self, acknowledgement: CommandAck) -> Result<(), CommandError> {
        self.validate_fence(acknowledgement.generation, acknowledgement.spec_revision)?;
        if acknowledgement.sequence == 0 || acknowledgement.sequence > Revision::MAX {
            return Err(CommandError::InvalidSequence);
        }
        if acknowledgement.sequence == self.acknowledged_sequence {
            let command = self
                .command(acknowledgement.sequence)
                .ok_or(CommandError::InvalidSequence)?;
            return if command.payload_digest.ct_eq(acknowledgement.payload_digest)
                && command
                    .encoded_command_digest
                    .ct_eq(acknowledgement.encoded_command_digest)
            {
                Ok(())
            } else {
                Err(CommandError::DigestMismatch)
            };
        }
        let expected = self
            .acknowledged_sequence
            .checked_add(1)
            .ok_or(CommandError::CounterExhausted)?;
        if acknowledgement.sequence < expected {
            return Err(CommandError::StaleCursor);
        }
        if acknowledgement.sequence > expected {
            return Err(CommandError::AckGap);
        }
        let command = self
            .command(acknowledgement.sequence)
            .ok_or(CommandError::UnknownCommand)?;
        if command.generation != acknowledgement.generation
            || command.spec_revision != acknowledgement.spec_revision
        {
            return Err(CommandError::StaleFence);
        }
        if !command.payload_digest.ct_eq(acknowledgement.payload_digest)
            || !command
                .encoded_command_digest
                .ct_eq(acknowledgement.encoded_command_digest)
        {
            return Err(CommandError::DigestMismatch);
        }
        self.acknowledged_sequence = acknowledgement.sequence;
        Ok(())
    }

    /// Replays immutable bytes after an exact durable resume cursor.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError`] for a stale fence, lost durable cursor, or a
    /// client cursor beyond the durable log.
    pub fn resume(
        &self,
        acknowledged_sequence: u64,
        generation: u64,
        spec_revision: Revision,
    ) -> Result<&[DurableServerCommand], CommandError> {
        self.validate_fence(generation, spec_revision)?;
        if acknowledged_sequence < self.acknowledged_sequence {
            return Err(CommandError::StaleCursor);
        }
        if acknowledged_sequence > self.commands.len() as u64 {
            return Err(CommandError::CursorGap);
        }
        // A Connector may have durably applied a command whose ACK was lost.
        // Its ahead cursor is evidence for idempotent replay, not authority to
        // advance the server cursor without an exact digest acknowledgement.
        let index = usize::try_from(self.acknowledged_sequence)
            .map_err(|_| CommandError::InvalidSequence)?;
        self.commands
            .get(index..)
            .ok_or(CommandError::InvalidSequence)
    }

    /// Advances the Connector/spec fence only after the old backlog is fully applied.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError`] for stale or non-contiguous fences, outstanding
    /// commands, terminal revocation, or counter exhaustion.
    pub fn advance_fence(
        &mut self,
        expected_generation: u64,
        expected_spec_revision: Revision,
        next_generation: u64,
        next_spec_revision: Revision,
    ) -> Result<(), CommandError> {
        self.validate_fence(expected_generation, expected_spec_revision)?;
        if self.state == CommandLogState::Revoked {
            return Err(CommandError::Revoked);
        }
        if self.acknowledged_sequence != self.commands.len() as u64 {
            return Err(CommandError::UnacknowledgedCommands);
        }
        let expected_revision = self
            .spec_revision
            .checked_next()
            .map_err(|_| CommandError::CounterExhausted)?;
        let same_generation = next_generation == self.generation;
        let next_connector_generation = self
            .generation
            .checked_add(1)
            .filter(|value| *value <= Revision::MAX);
        if next_spec_revision != expected_revision
            || (!same_generation && Some(next_generation) != next_connector_generation)
        {
            return Err(CommandError::InvalidFenceTransition);
        }
        self.generation = next_generation;
        self.spec_revision = next_spec_revision;
        Ok(())
    }

    /// Marks the log terminal after a durable revoke command has been appended.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::MissingRevokeCommand`] unless the last durable
    /// command is the closed terminal-revoke instruction.
    pub fn revoke(&mut self) -> Result<(), CommandError> {
        if self.state == CommandLogState::Revoked {
            return Ok(());
        }
        let has_terminal_command = self.commands.last().is_some_and(|command| {
            matches!(
                &command.payload,
                ServerCommandPayload::CloseStream(CloseStreamCommand {
                    reason: CloseStreamReason::Revoked,
                    ..
                })
            )
        });
        if !has_terminal_command {
            return Err(CommandError::MissingRevokeCommand);
        }
        self.state = CommandLogState::Revoked;
        Ok(())
    }

    /// Terminally revokes the log at the Connector's next spec fence without trusting an ACK.
    ///
    /// Administrative revocation is a local security boundary. The final `CloseStream::Revoked`
    /// command is retained for audit/best-effort delivery, while the head advances with the
    /// Connector so restart cannot resurrect the old active fence.
    ///
    /// # Errors
    ///
    /// Rejects a missing terminal revoke command, stale/non-contiguous fence, generation change,
    /// or an incoherent retry of an already terminal log.
    pub fn finalize_revoke_fence(
        &mut self,
        expected_generation: u64,
        expected_spec_revision: Revision,
        next_generation: u64,
        next_spec_revision: Revision,
    ) -> Result<(), CommandError> {
        if self.state == CommandLogState::Revoked {
            return if self.generation == next_generation && self.spec_revision == next_spec_revision
            {
                Ok(())
            } else {
                Err(CommandError::Revoked)
            };
        }
        self.validate_fence(expected_generation, expected_spec_revision)?;
        let expected_next_revision = self
            .spec_revision
            .checked_next()
            .map_err(|_| CommandError::CounterExhausted)?;
        if next_generation != self.generation || next_spec_revision != expected_next_revision {
            return Err(CommandError::InvalidFenceTransition);
        }
        if !self.commands.last().is_some_and(is_terminal_revoke) {
            return Err(CommandError::MissingRevokeCommand);
        }
        self.spec_revision = next_spec_revision;
        self.state = CommandLogState::Revoked;
        Ok(())
    }

    #[must_use]
    pub fn snapshot(&self) -> CommandLogSnapshot {
        CommandLogSnapshot {
            tenant_id: self.tenant_id,
            connector_id: self.connector_id,
            generation: self.generation,
            spec_revision: self.spec_revision,
            acknowledged_sequence: self.acknowledged_sequence,
            state: self.state,
            commands: self
                .commands
                .iter()
                .map(|command| DurableServerCommandSnapshot {
                    sequence: command.sequence,
                    operation_id: command.operation_id,
                    generation: command.generation,
                    spec_revision: command.spec_revision,
                    payload: command.payload.clone(),
                    payload_digest: command.payload_digest,
                    encoded_command_digest: command.encoded_command_digest,
                    exact_bytes: command.exact_bytes.clone(),
                })
                .collect(),
        }
    }

    /// Rehydrates a complete append-only log after validating every invariant.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::InvalidSnapshot`] or a specific bound error when
    /// persisted state is incoherent.
    pub fn try_from_snapshot(snapshot: CommandLogSnapshot) -> Result<Self, CommandError> {
        validate_command_snapshot(&snapshot)?;
        Ok(Self {
            tenant_id: snapshot.tenant_id,
            connector_id: snapshot.connector_id,
            generation: snapshot.generation,
            spec_revision: snapshot.spec_revision,
            acknowledged_sequence: snapshot.acknowledged_sequence,
            state: snapshot.state,
            commands: snapshot
                .commands
                .into_iter()
                .map(|command| DurableServerCommand {
                    sequence: command.sequence,
                    operation_id: command.operation_id,
                    generation: command.generation,
                    spec_revision: command.spec_revision,
                    payload: command.payload,
                    payload_digest: command.payload_digest,
                    encoded_command_digest: command.encoded_command_digest,
                    exact_bytes: command.exact_bytes,
                })
                .collect(),
        })
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn spec_revision(&self) -> Revision {
        self.spec_revision
    }

    #[must_use]
    pub const fn acknowledged_sequence(&self) -> u64 {
        self.acknowledged_sequence
    }

    #[must_use]
    pub const fn state(&self) -> CommandLogState {
        self.state
    }

    #[must_use]
    pub fn commands(&self) -> &[DurableServerCommand] {
        &self.commands
    }

    /// Returns the next sequence an application must embed in exact command bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CommandError::CounterExhausted`] at the safe-integer limit.
    pub fn next_sequence(&self) -> Result<u64, CommandError> {
        (self.commands.len() as u64)
            .checked_add(1)
            .filter(|value| *value <= Revision::MAX)
            .ok_or(CommandError::CounterExhausted)
    }

    /// Looks up a previously accepted operation before encoding an exact retry.
    #[must_use]
    pub fn operation(&self, operation_id: RequestId) -> Option<&DurableServerCommand> {
        self.commands
            .iter()
            .find(|command| command.operation_id == operation_id)
    }

    #[must_use]
    pub fn command(&self, sequence: u64) -> Option<&DurableServerCommand> {
        sequence
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.commands.get(index))
    }

    fn validate_fence(&self, generation: u64, spec_revision: Revision) -> Result<(), CommandError> {
        if generation != self.generation || spec_revision != self.spec_revision {
            Err(CommandError::StaleFence)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandError {
    InvalidGeneration,
    InvalidSequence,
    InvalidCommandBytes,
    InvalidCommandPayloadBytes,
    InvalidCommandPayload,
    InvalidConfigEntry,
    InvalidCloseStreamMetadata,
    StaleFence,
    StaleCursor,
    CursorGap,
    AckGap,
    UnknownCommand,
    DigestMismatch,
    IdempotencyConflict,
    BacklogFull,
    UnacknowledgedCommands,
    InvalidFenceTransition,
    MissingRevokeCommand,
    Revoked,
    CounterExhausted,
    InvalidSnapshot,
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGeneration => "command generation is outside the safe positive range",
            Self::InvalidSequence => "command sequence is outside the safe positive range",
            Self::InvalidCommandBytes => "command bytes are empty or exceed the frame bound",
            Self::InvalidCommandPayloadBytes => {
                "selected command payload bytes are empty or exceed the frame bound"
            }
            Self::InvalidCommandPayload => "command payload violates the closed MC2b contract",
            Self::InvalidConfigEntry => "command configuration entry is invalid or duplicated",
            Self::InvalidCloseStreamMetadata => {
                "close-stream code or redacted detail violates its bound"
            }
            Self::StaleFence => "command generation or spec revision is stale",
            Self::StaleCursor => "command cursor is older than the committed cursor",
            Self::CursorGap => "command cursor is ahead of the committed cursor",
            Self::AckGap => "command acknowledgement is not contiguous",
            Self::UnknownCommand => "command acknowledgement references an unknown command",
            Self::DigestMismatch => "command acknowledgement digest changed",
            Self::IdempotencyConflict => "command operation retry changed accepted input",
            Self::BacklogFull => "command backlog reached its bounded limit",
            Self::UnacknowledgedCommands => {
                "command fence cannot advance with an outstanding backlog"
            }
            Self::InvalidFenceTransition => {
                "command fence transition is not monotonic and contiguous"
            }
            Self::MissingRevokeCommand => {
                "command log cannot revoke before a durable revoke command"
            }
            Self::Revoked => "command log is terminally revoked",
            Self::CounterExhausted => "command sequence or fence counter is exhausted",
            Self::InvalidSnapshot => "command log snapshot violates durable invariants",
        })
    }
}

impl Error for CommandError {}

fn validate_command_snapshot(snapshot: &CommandLogSnapshot) -> Result<(), CommandError> {
    validate_generation(snapshot.generation)?;
    let acknowledged = usize::try_from(snapshot.acknowledged_sequence)
        .map_err(|_| CommandError::InvalidSnapshot)?;
    let pending_count = snapshot.commands.len().saturating_sub(acknowledged);
    let terminal_overflow = pending_count == MAX_COMMAND_BACKLOG.saturating_add(1)
        && snapshot
            .commands
            .last()
            .is_some_and(is_terminal_revoke_snapshot);
    if snapshot.commands.len() as u64 > Revision::MAX
        || snapshot.acknowledged_sequence > snapshot.commands.len() as u64
        || (pending_count > MAX_COMMAND_BACKLOG && !terminal_overflow)
    {
        return Err(CommandError::InvalidSnapshot);
    }
    let mut operations = BTreeSet::new();
    let mut previous_fence: Option<(u64, Revision)> = None;
    for (index, command) in snapshot.commands.iter().enumerate() {
        let expected_sequence = index as u64 + 1;
        if command.sequence != expected_sequence
            || validate_durable_command_snapshot(command).is_err()
            || command.generation > snapshot.generation
            || command.spec_revision > snapshot.spec_revision
            || !operations.insert(command.operation_id)
        {
            return Err(CommandError::InvalidSnapshot);
        }
        if let Some((generation, revision)) = previous_fence
            && (command.generation < generation
                || command.spec_revision < revision
                || (command.generation > generation
                    && command.generation != generation.saturating_add(1)))
        {
            return Err(CommandError::InvalidSnapshot);
        }
        previous_fence = Some((command.generation, command.spec_revision));
    }
    let pending = snapshot
        .commands
        .get(acknowledged..)
        .ok_or(CommandError::InvalidSnapshot)?;
    let mut barrier_seen = false;
    for (index, command) in pending.iter().enumerate() {
        let terminal_revoke = is_terminal_revoke_snapshot(command);
        if barrier_seen && !terminal_revoke {
            return Err(CommandError::InvalidSnapshot);
        }
        if terminal_revoke && index + 1 != pending.len() {
            return Err(CommandError::InvalidSnapshot);
        }
        barrier_seen |= is_fence_barrier_snapshot(command);
    }
    if snapshot.commands.last().is_some_and(|command| {
        command.generation > snapshot.generation || command.spec_revision > snapshot.spec_revision
    }) {
        return Err(CommandError::InvalidSnapshot);
    }
    if snapshot.state == CommandLogState::Revoked
        && !snapshot.commands.last().is_some_and(|command| {
            matches!(
                &command.payload,
                ServerCommandPayload::CloseStream(CloseStreamCommand {
                    reason: CloseStreamReason::Revoked,
                    ..
                })
            )
        })
    {
        return Err(CommandError::InvalidSnapshot);
    }
    Ok(())
}

fn validate_durable_command_snapshot(
    command: &DurableServerCommandSnapshot,
) -> Result<(), CommandError> {
    if command.sequence == 0
        || command.sequence > Revision::MAX
        || command.generation == 0
        || command.generation > Revision::MAX
        || !command
            .encoded_command_digest
            .ct_eq(command.exact_bytes.encoded_command_digest())
        || validate_payload(&command.payload, command.spec_revision).is_err()
    {
        Err(CommandError::InvalidSnapshot)
    } else {
        Ok(())
    }
}

fn is_fence_barrier_snapshot(command: &DurableServerCommandSnapshot) -> bool {
    matches!(
        command.payload,
        ServerCommandPayload::ApplyConfig(_) | ServerCommandPayload::RotateCredential(_)
    ) || is_terminal_revoke_snapshot(command)
}

fn is_terminal_revoke_snapshot(command: &DurableServerCommandSnapshot) -> bool {
    matches!(
        &command.payload,
        ServerCommandPayload::CloseStream(close) if close.reason == CloseStreamReason::Revoked
    )
}

fn validate_payload(
    payload: &ServerCommandPayload,
    spec_revision: Revision,
) -> Result<(), CommandError> {
    match payload {
        ServerCommandPayload::ApplyConfig(command) => {
            if spec_revision.checked_next() != Ok(command.config_revision)
                || command.desired_state == ConnectorDesiredState::Revoked
                || !canonical_config_is_valid(&command.adapter_config)
                || !canonical_config_is_valid(&command.runtime_config)
            {
                return Err(CommandError::InvalidCommandPayload);
            }
        }
        ServerCommandPayload::RotateCredential(command) => {
            if spec_revision.checked_next() != Ok(command.successor_revision)
                || command.deadline_millis <= 0
            {
                return Err(CommandError::InvalidCommandPayload);
            }
        }
        ServerCommandPayload::CloseStream(command) => {
            if !valid_upper_snake_code(&command.stable_code, MAX_CLOSE_STREAM_CODE_BYTES)
                || command.redacted_detail.len() > MAX_CLOSE_STREAM_DETAIL_BYTES
                || contains_c0_c1_control(&command.redacted_detail)
            {
                return Err(CommandError::InvalidCommandPayload);
            }
        }
        ServerCommandPayload::DeliverAgentProvisioning(command) => {
            if command.sealed_capsule.is_empty()
                || command.sealed_capsule.len() > MAX_PROVISIONING_CAPSULE_BYTES
                || command.expires_at_millis <= 0
            {
                return Err(CommandError::InvalidCommandPayload);
            }
        }
        ServerCommandPayload::RevokeAgentProvisioning(command) => {
            if command.requested_at_millis <= 0 {
                return Err(CommandError::InvalidCommandPayload);
            }
        }
        ServerCommandPayload::PrepareAgentRouteRecipient(command) => {
            command.validate()?;
        }
        ServerCommandPayload::DeliverAgentRouteBootstrap(command) => {
            command.validate()?;
        }
    }
    Ok(())
}

fn is_fence_barrier(command: &DurableServerCommand) -> bool {
    matches!(
        command.payload,
        ServerCommandPayload::ApplyConfig(_) | ServerCommandPayload::RotateCredential(_)
    ) || is_terminal_revoke(command)
}

fn is_terminal_revoke(command: &DurableServerCommand) -> bool {
    matches!(
        &command.payload,
        ServerCommandPayload::CloseStream(close) if close.reason == CloseStreamReason::Revoked
    )
}

fn validate_generation(generation: u64) -> Result<(), CommandError> {
    if generation == 0 || generation > Revision::MAX {
        Err(CommandError::InvalidGeneration)
    } else {
        Ok(())
    }
}

fn canonicalize_config(entries: &mut [ConfigEntry]) -> Result<(), CommandError> {
    if entries.len() > MAX_CONFIG_ENTRIES_PER_SCOPE {
        return Err(CommandError::InvalidConfigEntry);
    }
    entries.sort_unstable_by(|left, right| left.key.cmp(&right.key));
    if !canonical_config_is_valid(entries) {
        return Err(CommandError::InvalidConfigEntry);
    }
    Ok(())
}

fn canonical_config_is_valid(entries: &[ConfigEntry]) -> bool {
    entries.len() <= MAX_CONFIG_ENTRIES_PER_SCOPE
        && entries.iter().all(|entry| {
            valid_lower_stable_name(&entry.key, MAX_CONFIG_KEY_BYTES)
                && entry.value.len() <= MAX_CONFIG_VALUE_BYTES
                && !contains_c0_c1_control(&entry.value)
                && registered_config_entry_is_valid(&entry.key, &entry.value)
        })
        && entries.windows(2).all(|pair| pair[0].key < pair[1].key)
}

fn registered_config_entry_is_valid(key: &str, value: &str) -> bool {
    match key {
        "adapter" => matches!(
            value,
            "codex-app-server"
                | "openclaw-acp"
                | "eino"
                | "rig"
                | "claude-code"
                | "vendor-v1"
                | "hermes-acp"
        ),
        "endpoint" => matches!(value, "local" | "private" | "public"),
        "endpoint-profile" => matches!(value, "local" | "private" | "public"),
        "log-level" => matches!(value, "trace" | "debug" | "info" | "warn" | "error"),
        "max-concurrent-runs" => value
            .parse::<u32>()
            .is_ok_and(|maximum| (1..=4_096).contains(&maximum)),
        "model" => value == "agent-v1",
        "offline-policy" => matches!(value, "queue" | "reject"),
        "policy-id" => value == "policy-v1",
        "profile" => matches!(value, "safe" | "default"),
        "shutdown" => matches!(value, "graceful" | "immediate"),
        "workspace-mode" => matches!(value, "read-only" | "workspace-write"),
        _ => false,
    }
}

fn valid_lower_stable_name(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
}

fn valid_upper_snake_code(value: &str, maximum: usize) -> bool {
    (3..=maximum).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        && value.split('_').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        })
}

fn contains_c0_c1_control(value: &str) -> bool {
    value.chars().any(|character| {
        let scalar = u32::from(character);
        scalar <= 0x1f || (0x7f..=0x9f).contains(&scalar)
    })
}
