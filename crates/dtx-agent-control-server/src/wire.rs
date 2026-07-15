use std::{collections::BTreeSet, error::Error, fmt, str::FromStr};

use dtx_agent_control::{
    CommandAck, ConnectorCredential, CredentialRotationRequest, CredentialRotationTranscript,
    DurableServerCommand, EnrollmentRequest, EnrollmentToken, EnrollmentTranscript,
    MAX_ACTIVE_RUN_IDS, MAX_RUNTIME_CAPABILITIES, MAX_RUNTIME_QUEUE_DEPTH, RuntimeClaims,
    Sha256Digest, run_failed_report_digest,
};
use dtx_agent_control_proto::v1;
use dtx_connect_registry::{
    AdapterKind, ConnectorFence, ConnectorLease, HeartbeatAck, LeaseStatus,
};
use dtx_domain::{
    ArtifactId, BindingId, BootId, ConnectorCredentialId, ConnectorId, ConversationId,
    Ed25519PublicKey, EventId, HostId, InstallationId, LeaseId, RequestId, Revision, RunId,
    RunLeaseId, TenantId,
};
use zeroize::Zeroize as _;

const MAX_REQUIRED_SERVER_CAPABILITIES: usize = 32;
const MAX_STABLE_NAME_BYTES: usize = 128;
const MIN_HEARTBEAT_INTERVAL_MILLIS: u32 = 1_000;
const MAX_HEARTBEAT_INTERVAL_MILLIS: u32 = 60_000;
const MAX_HEARTBEAT_TTL_MILLIS: u32 = 300_000;
const MAX_CONCURRENT_RUNS: u32 = 65_535;

/// Sanitized category for a rejected protobuf field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireErrorKind {
    MissingField,
    InvalidIdentifier,
    InvalidLength,
    InvalidValue,
    UnsupportedValue,
}

/// A bounded wire failure that never retains or displays untrusted field contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireError {
    kind: WireErrorKind,
    field: &'static str,
}

impl WireError {
    #[must_use]
    pub const fn kind(self) -> WireErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn field(self) -> &'static str {
        self.field
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "agent-control wire field {} is invalid ({:?})",
            self.field, self.kind
        )
    }
}

impl Error for WireError {}

/// Validated enrollment payload retaining the raw token only in its zeroizing wrapper.
#[derive(Debug)]
pub struct ParsedEnrollment {
    pub token: EnrollmentToken,
    pub request: EnrollmentRequest,
}

/// Structurally valid protocol range. Negotiation policy remains server-owned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedProtocolRange {
    pub minimum_major: u32,
    pub minimum_minor: u32,
    pub maximum_major: u32,
    pub maximum_minor: u32,
}

impl ParsedProtocolRange {
    #[must_use]
    pub const fn supports(self, major: u32, minor: u32) -> bool {
        (major > self.minimum_major || (major == self.minimum_major && minor >= self.minimum_minor))
            && (major < self.maximum_major
                || (major == self.maximum_major && minor <= self.maximum_minor))
    }
}

/// Validated live Connector capacity report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedCapacity {
    pub maximum_concurrent_runs: u32,
    pub available_concurrent_runs: u32,
    pub maximum_queue_depth: u32,
}

/// Validated input fence. The authoritative aggregate must still compare every coordinate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedLeaseFence {
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub boot_id: BootId,
    pub connector_generation: u64,
    pub lease_id: LeaseId,
    pub lease_epoch: u64,
}

/// Validated v1.1 offer acknowledgement. It does not authorize execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRunClaim {
    pub connector_fence: ParsedLeaseFence,
    pub run_id: RunId,
    pub request_id: RequestId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub connector_id: ConnectorId,
    pub offer_attempt: u64,
    pub offer_deadline_millis: i64,
    pub required_capabilities: Vec<String>,
}

/// Validated v1.1 release carrying both the Connector and run-lease fences.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRunRelease {
    pub connector_fence: ParsedLeaseFence,
    pub run_id: RunId,
    pub request_id: RequestId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub connector_id: ConnectorId,
    pub offer_attempt: u64,
    pub run_lease_id: RunLeaseId,
    pub run_lease_epoch: u64,
    pub run_lease_deadline_millis: i64,
    pub stable_reason: String,
}

/// Server-owned inputs for a v1.1 capability-scoped offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunAvailableWire {
    /// Internal durable delivery cursor; never encoded as execution authority.
    pub connector_offer_sequence: u64,
    pub connector_fence: ParsedLeaseFence,
    pub run_id: RunId,
    pub request_id: RequestId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub connector_id: ConnectorId,
    pub offer_attempt: u64,
    pub offered_at_millis: i64,
    pub offer_deadline_millis: i64,
    pub required_capabilities: Vec<String>,
}

/// Server-owned inputs for the sole v1.1 execution-authorizing frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunLeaseGrantedWire {
    pub connector_fence: ParsedLeaseFence,
    pub run_id: RunId,
    pub request_id: RequestId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub connector_id: ConnectorId,
    pub offer_attempt: u64,
    pub run_lease_id: RunLeaseId,
    pub run_lease_epoch: u64,
    pub granted_at_millis: i64,
    pub run_lease_deadline_millis: i64,
    pub required_capabilities: Vec<String>,
    pub conversation_id: ConversationId,
    pub input_event_id: EventId,
    pub grant_version: u64,
}

/// Server-owned durable cancellation projected onto one exact execution fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunCancelRequestedWire {
    /// Internal durable delivery cursor; never encoded as cancellation authority.
    pub connector_cancel_sequence: u64,
    pub execution_fence: ParsedRunExecutionFence,
    pub stable_reason: String,
    pub requested_at_millis: i64,
    pub cancel_deadline_millis: i64,
}

/// Complete Connector and Run lease authority copied by every execution report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedRunExecutionFence {
    pub connector_fence: ParsedLeaseFence,
    pub run_id: RunId,
    pub request_id: RequestId,
    pub installation_id: InstallationId,
    pub binding_id: BindingId,
    pub connector_id: ConnectorId,
    pub offer_attempt: u64,
    pub run_lease_id: RunLeaseId,
    pub run_lease_epoch: u64,
    pub run_lease_deadline_millis: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRunCheckpoint {
    pub execution_fence: ParsedRunExecutionFence,
    pub checkpoint_sequence: u64,
    pub checkpoint_artifact_id: ArtifactId,
    pub checkpoint_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRunOutput {
    pub execution_fence: ParsedRunExecutionFence,
    pub output_sequence: u64,
    pub output_event_id: EventId,
    pub output_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRunCompleted {
    pub execution_fence: ParsedRunExecutionFence,
    pub terminal_sequence: u64,
    pub result_event_id: EventId,
    pub result_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRunFailed {
    pub execution_fence: ParsedRunExecutionFence,
    pub terminal_sequence: u64,
    pub stable_error_code: String,
    pub evidence: Option<(ArtifactId, Sha256Digest)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedProvisioningRecipientAnnouncement {
    pub connector_fence: ParsedLeaseFence,
    pub binding_id: BindingId,
    pub installation_id: InstallationId,
    pub agent_device_id: dtx_domain::AgentDeviceId,
    pub provisioning_revision: u64,
    pub recipient_key_id: RequestId,
    pub recipient_public_key: [u8; 32],
    pub credential_id: ConnectorCredentialId,
    pub created_at_millis: i64,
    pub expires_at_millis: i64,
    pub descriptor_digest: Sha256Digest,
    pub recipient_signature: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedAgentProvisioningInstalled {
    pub connector_fence: ParsedLeaseFence,
    pub delivery_id: RequestId,
    pub command_sequence: u64,
    pub command_payload_digest: Sha256Digest,
    pub encoded_command_digest: Sha256Digest,
    pub recipient_key_id: RequestId,
    pub capsule_digest: Sha256Digest,
    pub installation_receipt_digest: Sha256Digest,
    pub installed_at_millis: i64,
    pub result_digest: Sha256Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedAgentProvisioningRejected {
    pub connector_fence: ParsedLeaseFence,
    pub delivery_id: RequestId,
    pub command_sequence: u64,
    pub command_payload_digest: Sha256Digest,
    pub encoded_command_digest: Sha256Digest,
    pub recipient_key_id: RequestId,
    pub capsule_digest: Sha256Digest,
    pub stable_error_code: String,
    pub rejected_at_millis: i64,
    pub result_digest: Sha256Digest,
}

/// Validated first control-stream frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedHello {
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub host_id: HostId,
    pub boot_id: BootId,
    pub connector_generation: u64,
    pub spec_revision: Revision,
    pub protocol: ParsedProtocolRange,
    pub runtime_claims: RuntimeClaims,
    pub capacity: ParsedCapacity,
    pub last_applied_command_sequence: u64,
    pub required_server_capabilities: Vec<String>,
}

/// Validated readiness observation. It does not advance the durable command cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedReady {
    pub fence: ParsedLeaseFence,
    pub applied_config_revision: Revision,
    pub applied_command_sequence: u64,
}

/// Validated heartbeat observation. The application must compare its maximums with Hello.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedHeartbeat {
    pub fence: ParsedLeaseFence,
    pub heartbeat_sequence: u64,
    pub applied_config_revision: Revision,
    pub applied_command_sequence: u64,
    pub runtime_claims: RuntimeClaims,
    pub capacity: ParsedCapacity,
}

/// Validated acknowledgement plus the complete stream fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParsedCommandAcknowledgement {
    pub fence: ParsedLeaseFence,
    pub command_sequence: u64,
    pub payload_digest: Sha256Digest,
    pub encoded_command_digest: Sha256Digest,
}

impl ParsedCommandAcknowledgement {
    /// Binds the acknowledgement to the authoritative command-log specification revision.
    #[must_use]
    pub const fn command_ack(self, spec_revision: Revision) -> CommandAck {
        CommandAck::new(
            self.command_sequence,
            self.payload_digest,
            self.encoded_command_digest,
            self.fence.connector_generation,
            spec_revision,
        )
    }
}

/// Validated rotation proof fields that still require authenticated server-side context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedCredentialRotationProof {
    pub fence: ParsedLeaseFence,
    pub request_id: RequestId,
    pub command_sequence: u64,
    pub command_payload_digest: Sha256Digest,
    pub encoded_command_digest: Sha256Digest,
    pub successor_revision: Revision,
    pub new_control_public_key: Ed25519PublicKey,
    current_refresh_signature: [u8; 64],
    new_control_signature: [u8; 64],
}

impl ParsedCredentialRotationProof {
    /// Completes the signed domain request with the authenticated credential and command nonce.
    ///
    /// # Errors
    ///
    /// Returns a sanitized error when the complete transcript is not structurally valid.
    pub fn into_domain(
        self,
        current_credential_id: ConnectorCredentialId,
        rotation_nonce: [u8; 32],
    ) -> Result<CredentialRotationRequest, WireError> {
        let transcript = CredentialRotationTranscript::new(
            self.fence.tenant_id,
            self.fence.connector_id,
            self.request_id,
            current_credential_id,
            self.fence.connector_generation,
            self.command_sequence,
            self.command_payload_digest,
            self.successor_revision,
            rotation_nonce,
            self.new_control_public_key,
        )
        .map_err(|_| invalid_value("credential_rotation_proof"))?;
        Ok(CredentialRotationRequest::new(
            transcript,
            self.current_refresh_signature,
            self.new_control_signature,
        ))
    }

    /// Treats a committed rotation proof as the exact acknowledgement for its command.
    #[must_use]
    pub const fn command_ack(&self, spec_revision: Revision) -> CommandAck {
        CommandAck::new(
            self.command_sequence,
            self.command_payload_digest,
            self.encoded_command_digest,
            self.fence.connector_generation,
            spec_revision,
        )
    }
}

/// Any known, structurally validated client frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParsedClientFrame {
    Hello(ParsedHello),
    Ready(ParsedReady),
    Heartbeat(ParsedHeartbeat),
    CommandAcknowledgement(ParsedCommandAcknowledgement),
    CredentialRotationProof(ParsedCredentialRotationProof),
    RunClaim(ParsedRunClaim),
    RunRelease(ParsedRunRelease),
    RunCheckpoint(ParsedRunCheckpoint),
    RunOutput(ParsedRunOutput),
    RunCompleted(ParsedRunCompleted),
    RunFailed(ParsedRunFailed),
    ProvisioningRecipientAnnouncement(ParsedProvisioningRecipientAnnouncement),
    AgentProvisioningInstalled(ParsedAgentProvisioningInstalled),
    AgentProvisioningRejected(ParsedAgentProvisioningRejected),
}

/// Converts an enrollment protobuf message into proof-bound domain input.
///
/// # Errors
///
/// Rejects malformed `UUIDv7` values, wrong fixed lengths, invalid Ed25519 keys,
/// unsafe counters, revisions, or key reuse.
pub fn parse_enrollment_request(
    mut value: v1::EnrollConnectorRequest,
) -> Result<ParsedEnrollment, WireError> {
    let token = EnrollmentToken::from_bytes(take_exact_secret_array(
        &mut value.enrollment_token,
        "enrollment_token",
    )?);
    let transcript = EnrollmentTranscript::new(
        parse_id(&value.tenant_id, "tenant_id")?,
        parse_id(&value.host_id, "host_id")?,
        parse_id(&value.connector_id, "connector_id")?,
        positive_safe(value.connector_generation, "connector_generation")?,
        parse_revision(value.spec_revision, "spec_revision")?,
        parse_id(&value.enrollment_request_id, "enrollment_request_id")?,
        token.digest(),
        parse_public_key(&value.control_public_key, "control_public_key")?,
        parse_public_key(&value.refresh_public_key, "refresh_public_key")?,
    )
    .map_err(|_| invalid_value("enrollment_request"))?;
    let request = EnrollmentRequest::new(
        transcript,
        exact_array(value.control_signature, "control_signature")?,
        exact_array(value.refresh_signature, "refresh_signature")?,
    );
    Ok(ParsedEnrollment { token, request })
}

/// Validates a Hello frame without deriving authorization from its self-reported claims.
///
/// # Errors
///
/// Rejects missing nested messages, malformed IDs, unsupported runtime kinds,
/// invalid claim/capacity bounds, or unsafe counters.
pub fn parse_hello(value: v1::Hello) -> Result<ParsedHello, WireError> {
    let protocol = parse_protocol(required(value.protocol, "protocol")?)?;
    let runtime_claims = parse_runtime_claims(required(value.runtime_claims, "runtime_claims")?)?;
    let capacity = parse_capacity(required(value.capacity, "capacity")?)?;
    let mut required_server_capabilities = value.required_server_capabilities;
    validate_stable_names(
        &required_server_capabilities,
        MAX_REQUIRED_SERVER_CAPABILITIES,
        "required_server_capabilities",
    )?;
    required_server_capabilities.sort_unstable();

    Ok(ParsedHello {
        tenant_id: parse_id(&value.tenant_id, "tenant_id")?,
        connector_id: parse_id(&value.connector_id, "connector_id")?,
        host_id: parse_id(&value.host_id, "host_id")?,
        boot_id: parse_id(&value.boot_id, "boot_id")?,
        connector_generation: positive_safe(value.connector_generation, "connector_generation")?,
        spec_revision: parse_revision(value.spec_revision, "spec_revision")?,
        protocol,
        runtime_claims,
        capacity,
        last_applied_command_sequence: safe_cursor(
            value.last_applied_command_sequence,
            "last_applied_command_sequence",
        )?,
        required_server_capabilities,
    })
}

/// Validates a Ready frame.
///
/// # Errors
///
/// Rejects a missing or malformed fence, revision, or observation cursor.
pub fn parse_ready(value: v1::Ready) -> Result<ParsedReady, WireError> {
    Ok(ParsedReady {
        fence: parse_lease_fence(&required(value.fence, "fence")?)?,
        applied_config_revision: parse_revision(
            value.applied_config_revision,
            "applied_config_revision",
        )?,
        applied_command_sequence: safe_cursor(
            value.applied_command_sequence,
            "applied_command_sequence",
        )?,
    })
}

/// Validates a Heartbeat frame.
///
/// # Errors
///
/// Rejects malformed fences, counters, claims, capacity, or nested messages.
pub fn parse_heartbeat(value: v1::Heartbeat) -> Result<ParsedHeartbeat, WireError> {
    Ok(ParsedHeartbeat {
        fence: parse_lease_fence(&required(value.fence, "fence")?)?,
        heartbeat_sequence: positive_safe(value.heartbeat_sequence, "heartbeat_sequence")?,
        applied_config_revision: parse_revision(
            value.applied_config_revision,
            "applied_config_revision",
        )?,
        applied_command_sequence: safe_cursor(
            value.applied_command_sequence,
            "applied_command_sequence",
        )?,
        runtime_claims: parse_runtime_claims(required(value.runtime_claims, "runtime_claims")?)?,
        capacity: parse_capacity(required(value.capacity, "capacity")?)?,
    })
}

/// Validates the fence and both immutable digests in a command acknowledgement.
///
/// # Errors
///
/// Rejects malformed fences, command sequences, or digest lengths.
pub fn parse_command_acknowledgement(
    value: v1::CommandAcknowledgement,
) -> Result<ParsedCommandAcknowledgement, WireError> {
    Ok(ParsedCommandAcknowledgement {
        fence: parse_lease_fence(&required(value.fence, "fence")?)?,
        command_sequence: positive_safe(value.command_sequence, "command_sequence")?,
        payload_digest: parse_digest(value.payload_digest, "payload_digest")?,
        encoded_command_digest: parse_digest(
            value.encoded_command_digest,
            "encoded_command_digest",
        )?,
    })
}

/// Validates a rotation proof while retaining the authenticated-context inputs for the application.
///
/// # Errors
///
/// Rejects malformed identifiers, fences, revisions, keys, signatures, or digests.
pub fn parse_credential_rotation_proof(
    value: v1::CredentialRotationProof,
) -> Result<ParsedCredentialRotationProof, WireError> {
    Ok(ParsedCredentialRotationProof {
        fence: parse_lease_fence(&required(value.fence, "fence")?)?,
        request_id: parse_id(&value.request_id, "request_id")?,
        command_sequence: positive_safe(value.command_sequence, "command_sequence")?,
        command_payload_digest: parse_digest(
            value.command_payload_digest,
            "command_payload_digest",
        )?,
        encoded_command_digest: parse_digest(
            value.encoded_command_digest,
            "encoded_command_digest",
        )?,
        successor_revision: parse_revision(value.successor_revision, "successor_revision")?,
        new_control_public_key: parse_public_key(
            &value.new_control_public_key,
            "new_control_public_key",
        )?,
        current_refresh_signature: exact_array(
            value.current_refresh_signature,
            "current_refresh_signature",
        )?,
        new_control_signature: exact_array(value.new_control_signature, "new_control_signature")?,
    })
}

/// Validates a v1.1 run-offer acknowledgement without granting execution authority.
///
/// # Errors
///
/// Rejects missing fences, mismatched Connector identities, malformed identifiers,
/// unsafe counters or timestamps, and invalid capability sets.
pub fn parse_run_claim(value: v1::RunClaim) -> Result<ParsedRunClaim, WireError> {
    let connector_fence = parse_lease_fence(&required(value.connector_fence, "connector_fence")?)?;
    let connector_id = parse_id(&value.connector_id, "connector_id")?;
    if connector_id != connector_fence.connector_id {
        return Err(invalid_value("connector_id"));
    }
    let mut required_capabilities = value.required_capabilities;
    normalize_capabilities(&mut required_capabilities)?;

    Ok(ParsedRunClaim {
        connector_fence,
        run_id: parse_id(&value.run_id, "run_id")?,
        request_id: parse_id(&value.request_id, "request_id")?,
        installation_id: parse_id(&value.installation_id, "installation_id")?,
        binding_id: parse_id(&value.binding_id, "binding_id")?,
        connector_id,
        offer_attempt: positive_safe(value.offer_attempt, "offer_attempt")?,
        offer_deadline_millis: parse_wire_timestamp(
            value.offer_deadline_millis,
            "offer_deadline_millis",
        )?,
        required_capabilities,
    })
}

/// Validates a v1.1 run-lease release carrying both independent fences.
///
/// # Errors
///
/// Rejects missing fences, mismatched identities, malformed identifiers,
/// unsafe counters or timestamps, and non-stable release reasons.
pub fn parse_run_release(value: v1::RunRelease) -> Result<ParsedRunRelease, WireError> {
    let connector_fence = parse_lease_fence(&required(value.connector_fence, "connector_fence")?)?;
    let connector_id = parse_id(&value.connector_id, "connector_id")?;
    if connector_id != connector_fence.connector_id {
        return Err(invalid_value("connector_id"));
    }
    if !valid_upper_stable_code(&value.stable_reason) {
        return Err(invalid_value("stable_reason"));
    }

    Ok(ParsedRunRelease {
        connector_fence,
        run_id: parse_id(&value.run_id, "run_id")?,
        request_id: parse_id(&value.request_id, "request_id")?,
        installation_id: parse_id(&value.installation_id, "installation_id")?,
        binding_id: parse_id(&value.binding_id, "binding_id")?,
        connector_id,
        offer_attempt: positive_safe(value.offer_attempt, "offer_attempt")?,
        run_lease_id: parse_id(&value.run_lease_id, "run_lease_id")?,
        run_lease_epoch: positive_safe(value.run_lease_epoch, "run_lease_epoch")?,
        run_lease_deadline_millis: parse_wire_timestamp(
            value.run_lease_deadline_millis,
            "run_lease_deadline_millis",
        )?,
        stable_reason: value.stable_reason,
    })
}

fn parse_run_execution_fence(
    value: v1::RunExecutionFence,
) -> Result<ParsedRunExecutionFence, WireError> {
    let connector_fence = parse_lease_fence(&required(value.connector_fence, "connector_fence")?)?;
    let connector_id = parse_id(&value.connector_id, "connector_id")?;
    if connector_id != connector_fence.connector_id {
        return Err(invalid_value("connector_id"));
    }
    Ok(ParsedRunExecutionFence {
        connector_fence,
        run_id: parse_id(&value.run_id, "run_id")?,
        request_id: parse_id(&value.request_id, "request_id")?,
        installation_id: parse_id(&value.installation_id, "installation_id")?,
        binding_id: parse_id(&value.binding_id, "binding_id")?,
        connector_id,
        offer_attempt: positive_safe(value.offer_attempt, "offer_attempt")?,
        run_lease_id: parse_id(&value.run_lease_id, "run_lease_id")?,
        run_lease_epoch: positive_safe(value.run_lease_epoch, "run_lease_epoch")?,
        run_lease_deadline_millis: parse_wire_timestamp(
            value.run_lease_deadline_millis,
            "run_lease_deadline_millis",
        )?,
    })
}

/// Validates a fenced checkpoint reference and digest.
///
/// # Errors
///
/// Rejects missing or malformed fences, identifiers, counters, and digests.
pub fn parse_run_checkpoint(value: v1::RunCheckpoint) -> Result<ParsedRunCheckpoint, WireError> {
    Ok(ParsedRunCheckpoint {
        execution_fence: parse_run_execution_fence(required(
            value.execution_fence,
            "execution_fence",
        )?)?,
        checkpoint_sequence: positive_safe(value.checkpoint_sequence, "checkpoint_sequence")?,
        checkpoint_artifact_id: parse_id(&value.checkpoint_artifact_id, "checkpoint_artifact_id")?,
        checkpoint_digest: parse_digest(value.checkpoint_digest, "checkpoint_digest")?,
    })
}

/// Validates a fenced encrypted output-event reference and digest.
///
/// # Errors
///
/// Rejects missing or malformed fences, identifiers, counters, and digests.
pub fn parse_run_output(value: v1::RunOutput) -> Result<ParsedRunOutput, WireError> {
    Ok(ParsedRunOutput {
        execution_fence: parse_run_execution_fence(required(
            value.execution_fence,
            "execution_fence",
        )?)?,
        output_sequence: positive_safe(value.output_sequence, "output_sequence")?,
        output_event_id: parse_id(&value.output_event_id, "output_event_id")?,
        output_digest: parse_digest(value.output_digest, "output_digest")?,
    })
}

/// Validates a fenced successful terminal claim.
///
/// # Errors
///
/// Rejects missing or malformed fences, identifiers, counters, and digests.
pub fn parse_run_completed(value: v1::RunCompleted) -> Result<ParsedRunCompleted, WireError> {
    Ok(ParsedRunCompleted {
        execution_fence: parse_run_execution_fence(required(
            value.execution_fence,
            "execution_fence",
        )?)?,
        terminal_sequence: positive_safe(value.terminal_sequence, "terminal_sequence")?,
        result_event_id: parse_id(&value.result_event_id, "result_event_id")?,
        result_digest: parse_digest(value.result_digest, "result_digest")?,
    })
}

/// Validates a fenced stable failure claim containing references only.
///
/// # Errors
///
/// Rejects missing or malformed fences, counters, stable codes, or incomplete evidence pairs.
pub fn parse_run_failed(value: v1::RunFailed) -> Result<ParsedRunFailed, WireError> {
    if !valid_upper_stable_code(&value.stable_error_code) {
        return Err(invalid_value("stable_error_code"));
    }
    let evidence = match (
        value.evidence_artifact_id.is_empty(),
        value.evidence_digest.is_empty(),
    ) {
        (true, true) => None,
        (false, false) => Some((
            parse_id(&value.evidence_artifact_id, "evidence_artifact_id")?,
            parse_digest(value.evidence_digest, "evidence_digest")?,
        )),
        _ => return Err(invalid_value("evidence")),
    };
    Ok(ParsedRunFailed {
        execution_fence: parse_run_execution_fence(required(
            value.execution_fence,
            "execution_fence",
        )?)?,
        terminal_sequence: positive_safe(value.terminal_sequence, "terminal_sequence")?,
        stable_error_code: value.stable_error_code,
        evidence,
    })
}

#[must_use]
pub fn build_run_checkpoint_ack(value: &ParsedRunCheckpoint) -> v1::RunReportAcknowledged {
    build_run_report_ack(
        value.execution_fence,
        "checkpoint",
        value.checkpoint_sequence,
        value.checkpoint_digest.as_bytes(),
    )
}

#[must_use]
pub fn build_run_output_ack(value: &ParsedRunOutput) -> v1::RunReportAcknowledged {
    build_run_report_ack(
        value.execution_fence,
        "output",
        value.output_sequence,
        value.output_digest.as_bytes(),
    )
}

#[must_use]
pub fn build_run_completed_ack(value: &ParsedRunCompleted) -> v1::RunReportAcknowledged {
    build_run_report_ack(
        value.execution_fence,
        "completed",
        value.terminal_sequence,
        value.result_digest.as_bytes(),
    )
}

#[must_use]
pub fn build_run_failed_ack(value: &ParsedRunFailed) -> v1::RunReportAcknowledged {
    let digest = run_failed_report_digest(
        &value.stable_error_code,
        value
            .evidence
            .map(|(artifact_id, digest)| (*artifact_id.as_uuid().as_bytes(), digest)),
    );
    build_run_report_ack(
        value.execution_fence,
        "failed",
        value.terminal_sequence,
        digest.as_bytes(),
    )
}

fn build_run_report_ack(
    fence: ParsedRunExecutionFence,
    kind: &'static str,
    sequence: u64,
    digest: [u8; 32],
) -> v1::RunReportAcknowledged {
    v1::RunReportAcknowledged {
        run_id: fence.run_id.to_string(),
        run_lease_id: fence.run_lease_id.to_string(),
        run_lease_epoch: fence.run_lease_epoch,
        report_kind: kind.to_owned(),
        report_sequence: sequence,
        report_digest: digest.to_vec(),
    }
}

/// Builds a v1.1 offer. Receiving this frame never authorizes execution.
///
/// # Errors
///
/// Rejects an incoherent fence, identity, offer window, or capability set.
pub fn build_run_available(mut value: RunAvailableWire) -> Result<v1::RunAvailable, WireError> {
    positive_safe(value.connector_offer_sequence, "connector_offer_sequence")?;
    validate_connector_identity(&value.connector_fence, value.connector_id)?;
    let offered_at_millis = validated_timestamp(value.offered_at_millis, "offered_at_millis")?;
    let offer_deadline_millis =
        validated_timestamp(value.offer_deadline_millis, "offer_deadline_millis")?;
    if offer_deadline_millis <= offered_at_millis {
        return Err(invalid_value("offer_deadline_millis"));
    }
    normalize_capabilities(&mut value.required_capabilities)?;

    Ok(v1::RunAvailable {
        connector_fence: Some(build_parsed_lease_fence(value.connector_fence)?),
        run_id: value.run_id.to_string(),
        request_id: value.request_id.to_string(),
        installation_id: value.installation_id.to_string(),
        binding_id: value.binding_id.to_string(),
        connector_id: value.connector_id.to_string(),
        offer_attempt: positive_safe(value.offer_attempt, "offer_attempt")?,
        offered_at_millis,
        offer_deadline_millis,
        required_capabilities: value.required_capabilities,
    })
}

/// Builds the v1.1 frame that exclusively authorizes run execution.
///
/// # Errors
///
/// Rejects an incoherent Connector or run-lease fence, grant window, or capability set.
pub fn build_run_lease_granted(
    mut value: RunLeaseGrantedWire,
) -> Result<v1::RunLeaseGranted, WireError> {
    validate_connector_identity(&value.connector_fence, value.connector_id)?;
    let granted_at_millis = validated_timestamp(value.granted_at_millis, "granted_at_millis")?;
    let run_lease_deadline_millis =
        validated_timestamp(value.run_lease_deadline_millis, "run_lease_deadline_millis")?;
    if run_lease_deadline_millis <= granted_at_millis {
        return Err(invalid_value("run_lease_deadline_millis"));
    }
    normalize_capabilities(&mut value.required_capabilities)?;

    Ok(v1::RunLeaseGranted {
        connector_fence: Some(build_parsed_lease_fence(value.connector_fence)?),
        run_id: value.run_id.to_string(),
        request_id: value.request_id.to_string(),
        installation_id: value.installation_id.to_string(),
        binding_id: value.binding_id.to_string(),
        connector_id: value.connector_id.to_string(),
        offer_attempt: positive_safe(value.offer_attempt, "offer_attempt")?,
        run_lease_id: value.run_lease_id.to_string(),
        run_lease_epoch: positive_safe(value.run_lease_epoch, "run_lease_epoch")?,
        granted_at_millis,
        run_lease_deadline_millis,
        required_capabilities: value.required_capabilities,
        conversation_id: value.conversation_id.to_string(),
        input_event_id: value.input_event_id.to_string(),
        grant_version: positive_safe(value.grant_version, "grant_version")?,
    })
}

/// Builds one v1.2 durable cancellation request without plaintext task data.
///
/// # Errors
///
/// Rejects malformed stable reasons, incoherent fences, or invalid deadlines.
pub fn build_run_cancel_requested(
    value: RunCancelRequestedWire,
) -> Result<v1::RunCancelRequested, WireError> {
    if !valid_upper_stable_code(&value.stable_reason) {
        return Err(invalid_value("stable_reason"));
    }
    validate_connector_identity(
        &value.execution_fence.connector_fence,
        value.execution_fence.connector_id,
    )?;
    let requested_at_millis =
        validated_timestamp(value.requested_at_millis, "requested_at_millis")?;
    let cancel_deadline_millis =
        validated_timestamp(value.cancel_deadline_millis, "cancel_deadline_millis")?;
    let run_lease_deadline_millis = validated_timestamp(
        value.execution_fence.run_lease_deadline_millis,
        "run_lease_deadline_millis",
    )?;
    if cancel_deadline_millis <= requested_at_millis
        || cancel_deadline_millis > run_lease_deadline_millis
    {
        return Err(invalid_value("cancel_deadline_millis"));
    }
    let fence = value.execution_fence;
    Ok(v1::RunCancelRequested {
        execution_fence: Some(v1::RunExecutionFence {
            connector_fence: Some(build_parsed_lease_fence(fence.connector_fence)?),
            run_id: fence.run_id.to_string(),
            request_id: fence.request_id.to_string(),
            installation_id: fence.installation_id.to_string(),
            binding_id: fence.binding_id.to_string(),
            connector_id: fence.connector_id.to_string(),
            offer_attempt: positive_safe(fence.offer_attempt, "offer_attempt")?,
            run_lease_id: fence.run_lease_id.to_string(),
            run_lease_epoch: positive_safe(fence.run_lease_epoch, "run_lease_epoch")?,
            run_lease_deadline_millis,
        }),
        stable_reason: value.stable_reason,
        requested_at_millis,
        cancel_deadline_millis,
    })
}

/// Validates one known client-frame oneof member.
///
/// # Errors
///
/// Rejects an absent/unknown oneof member or any invalid nested frame.
pub fn parse_client_frame(value: v1::ClientFrame) -> Result<ParsedClientFrame, WireError> {
    use v1::client_frame::Kind;

    match required(value.kind, "client_frame.kind")? {
        Kind::Hello(frame) => parse_hello(frame).map(ParsedClientFrame::Hello),
        Kind::Ready(frame) => parse_ready(frame).map(ParsedClientFrame::Ready),
        Kind::Heartbeat(frame) => parse_heartbeat(frame).map(ParsedClientFrame::Heartbeat),
        Kind::CommandAcknowledgement(frame) => {
            parse_command_acknowledgement(frame).map(ParsedClientFrame::CommandAcknowledgement)
        }
        Kind::CredentialRotationProof(frame) => {
            parse_credential_rotation_proof(frame).map(ParsedClientFrame::CredentialRotationProof)
        }
        Kind::RunClaim(frame) => parse_run_claim(frame).map(ParsedClientFrame::RunClaim),
        Kind::RunRelease(frame) => parse_run_release(frame).map(ParsedClientFrame::RunRelease),
        Kind::RunCheckpoint(frame) => {
            parse_run_checkpoint(frame).map(ParsedClientFrame::RunCheckpoint)
        }
        Kind::RunOutput(frame) => parse_run_output(frame).map(ParsedClientFrame::RunOutput),
        Kind::RunCompleted(frame) => {
            parse_run_completed(frame).map(ParsedClientFrame::RunCompleted)
        }
        Kind::RunFailed(frame) => parse_run_failed(frame).map(ParsedClientFrame::RunFailed),
        Kind::ProvisioningRecipientAnnouncement(frame) => parse_provisioning_recipient(frame)
            .map(ParsedClientFrame::ProvisioningRecipientAnnouncement),
        Kind::AgentProvisioningInstalled(frame) => {
            parse_provisioning_installed(frame).map(ParsedClientFrame::AgentProvisioningInstalled)
        }
        Kind::AgentProvisioningRejected(frame) => {
            parse_provisioning_rejected(frame).map(ParsedClientFrame::AgentProvisioningRejected)
        }
    }
}

fn parse_provisioning_recipient(
    value: v1::ProvisioningRecipientAnnouncement,
) -> Result<ParsedProvisioningRecipientAnnouncement, WireError> {
    let created_at_millis = parse_wire_timestamp(value.created_at_millis, "created_at_millis")?;
    let expires_at_millis = parse_wire_timestamp(value.expires_at_millis, "expires_at_millis")?;
    if expires_at_millis <= created_at_millis
        || expires_at_millis.saturating_sub(created_at_millis) > 600_000
    {
        return Err(invalid_value("expires_at_millis"));
    }
    Ok(ParsedProvisioningRecipientAnnouncement {
        connector_fence: parse_required_lease_fence(value.connector_fence)?,
        binding_id: parse_id(&value.binding_id, "binding_id")?,
        installation_id: parse_id(&value.installation_id, "installation_id")?,
        agent_device_id: parse_id(&value.agent_device_id, "agent_device_id")?,
        provisioning_revision: positive_safe(value.provisioning_revision, "provisioning_revision")?,
        recipient_key_id: parse_id(&value.recipient_key_id, "recipient_key_id")?,
        recipient_public_key: exact_array(value.recipient_public_key, "recipient_public_key")?,
        credential_id: parse_id(&value.credential_id, "credential_id")?,
        created_at_millis,
        expires_at_millis,
        descriptor_digest: parse_digest(value.descriptor_digest, "descriptor_digest")?,
        recipient_signature: exact_array(value.recipient_signature, "recipient_signature")?,
    })
}

fn parse_provisioning_installed(
    value: v1::AgentProvisioningInstalled,
) -> Result<ParsedAgentProvisioningInstalled, WireError> {
    Ok(ParsedAgentProvisioningInstalled {
        connector_fence: parse_required_lease_fence(value.connector_fence)?,
        delivery_id: parse_id(&value.delivery_id, "delivery_id")?,
        command_sequence: positive_safe(value.command_sequence, "command_sequence")?,
        command_payload_digest: parse_digest(
            value.command_payload_digest,
            "command_payload_digest",
        )?,
        encoded_command_digest: parse_digest(
            value.encoded_command_digest,
            "encoded_command_digest",
        )?,
        recipient_key_id: parse_id(&value.recipient_key_id, "recipient_key_id")?,
        capsule_digest: parse_digest(value.capsule_digest, "capsule_digest")?,
        installation_receipt_digest: parse_digest(
            value.installation_receipt_digest,
            "installation_receipt_digest",
        )?,
        installed_at_millis: parse_wire_timestamp(
            value.installed_at_millis,
            "installed_at_millis",
        )?,
        result_digest: parse_digest(value.result_digest, "result_digest")?,
    })
}

fn parse_provisioning_rejected(
    value: v1::AgentProvisioningRejected,
) -> Result<ParsedAgentProvisioningRejected, WireError> {
    if !valid_upper_stable_code(&value.stable_error_code) {
        return Err(invalid_value("stable_error_code"));
    }
    Ok(ParsedAgentProvisioningRejected {
        connector_fence: parse_required_lease_fence(value.connector_fence)?,
        delivery_id: parse_id(&value.delivery_id, "delivery_id")?,
        command_sequence: positive_safe(value.command_sequence, "command_sequence")?,
        command_payload_digest: parse_digest(
            value.command_payload_digest,
            "command_payload_digest",
        )?,
        encoded_command_digest: parse_digest(
            value.encoded_command_digest,
            "encoded_command_digest",
        )?,
        recipient_key_id: parse_id(&value.recipient_key_id, "recipient_key_id")?,
        capsule_digest: parse_digest(value.capsule_digest, "capsule_digest")?,
        stable_error_code: value.stable_error_code,
        rejected_at_millis: parse_wire_timestamp(value.rejected_at_millis, "rejected_at_millis")?,
        result_digest: parse_digest(value.result_digest, "result_digest")?,
    })
}

/// Projects public domain credential facts onto their protobuf representation.
#[must_use]
pub fn build_credential_message(credential: &ConnectorCredential) -> v1::ConnectorCredential {
    v1::ConnectorCredential {
        credential_id: credential.credential_id().to_string(),
        credential_revision: credential.revision().get(),
        certificate_chain_der: credential.certificate_chain().to_vec(),
        leaf_fingerprint: credential.certificate_fingerprint().as_bytes().to_vec(),
        valid_from_millis: timestamp_to_u64(credential.not_before_millis()),
        valid_until_millis: timestamp_to_u64(credential.not_after_millis()),
    }
}

/// Builds the exact public result for an accepted or idempotently replayed enrollment.
#[must_use]
pub fn build_enrollment_response(
    request: &EnrollmentRequest,
    credential: &ConnectorCredential,
) -> v1::EnrollConnectorResponse {
    v1::EnrollConnectorResponse {
        credential: Some(build_credential_message(credential)),
        request_digest: request.request_digest().as_bytes().to_vec(),
        result_digest: credential.result_digest().as_bytes().to_vec(),
    }
}

/// Builds the public result for a committed pending-successor credential.
#[must_use]
pub fn build_credential_rotation_result(
    request: &CredentialRotationRequest,
    credential: &ConnectorCredential,
) -> v1::CredentialRotationResult {
    v1::CredentialRotationResult {
        request_id: request.transcript().request_id().to_string(),
        command_sequence: request.transcript().command_sequence(),
        credential: Some(build_credential_message(credential)),
        request_digest: request.request_digest().as_bytes().to_vec(),
        result_digest: credential.result_digest().as_bytes().to_vec(),
    }
}

/// Preserves the complete durable command bytes and their separately committed digest.
#[must_use]
pub fn build_durable_command_frame(command: &DurableServerCommand) -> v1::DurableCommandFrame {
    v1::DurableCommandFrame {
        encoded_command: command.exact_bytes().as_slice().to_vec(),
        encoded_command_digest: command.encoded_command_digest().as_bytes().to_vec(),
    }
}

/// Projects a server-owned aggregate fence to protobuf.
#[must_use]
pub fn build_lease_fence(fence: ConnectorFence) -> v1::LeaseFence {
    v1::LeaseFence {
        tenant_id: fence.tenant_id().to_string(),
        connector_id: fence.connector_id().to_string(),
        boot_id: fence.boot_id().to_string(),
        connector_generation: fence.generation().get(),
        lease_id: fence.lease_id().to_string(),
        lease_epoch: fence.lease_epoch().get(),
    }
}

/// Builds the first successful server response to Hello.
///
/// # Errors
///
/// Rejects a non-active lease, invalid heartbeat policy, timestamps, or cursor.
pub fn build_connect_lease(
    lease: ConnectorLease,
    protocol_minor: u32,
    heartbeat_interval_millis: u32,
    heartbeat_ttl_millis: u32,
    acknowledged_command_sequence: u64,
) -> Result<v1::ConnectLease, WireError> {
    if lease.status() != LeaseStatus::Active {
        return Err(invalid_value("lease.status"));
    }
    if !(MIN_HEARTBEAT_INTERVAL_MILLIS..=MAX_HEARTBEAT_INTERVAL_MILLIS)
        .contains(&heartbeat_interval_millis)
        || heartbeat_ttl_millis <= heartbeat_interval_millis
        || heartbeat_ttl_millis > MAX_HEARTBEAT_TTL_MILLIS
    {
        return Err(invalid_value("heartbeat_policy"));
    }
    let issued_at_millis = validated_timestamp(lease.issued_at_millis(), "issued_at_millis")?;
    let expires_at_millis = validated_timestamp(lease.expires_at_millis(), "expires_at_millis")?;
    if expires_at_millis <= issued_at_millis {
        return Err(invalid_value("expires_at_millis"));
    }
    Ok(v1::ConnectLease {
        fence: Some(build_lease_fence(lease.fence())),
        protocol_major: 1,
        protocol_minor,
        issued_at_millis,
        expires_at_millis,
        heartbeat_interval_millis,
        heartbeat_ttl_millis,
        acknowledged_command_sequence: safe_cursor(
            acknowledged_command_sequence,
            "acknowledged_command_sequence",
        )?,
    })
}

/// Builds the exact heartbeat acknowledgement returned by the Connector aggregate.
///
/// # Errors
///
/// Rejects unsafe timestamps or an incoherent expiry.
pub fn build_heartbeat_acknowledgement(
    acknowledgement: HeartbeatAck,
    observed_at_millis: i64,
) -> Result<v1::HeartbeatAcknowledgement, WireError> {
    let observed_at_millis = validated_timestamp(observed_at_millis, "observed_at_millis")?;
    let lease_expires_at_millis = validated_timestamp(
        acknowledgement.lease_expires_at_millis(),
        "lease_expires_at_millis",
    )?;
    if lease_expires_at_millis <= observed_at_millis {
        return Err(invalid_value("lease_expires_at_millis"));
    }
    Ok(v1::HeartbeatAcknowledgement {
        heartbeat_sequence: positive_safe(acknowledgement.sequence(), "heartbeat_sequence")?,
        observed_at_millis,
        lease_expires_at_millis,
    })
}

fn parse_protocol(value: v1::ProtocolRange) -> Result<ParsedProtocolRange, WireError> {
    if value.minimum_major == 0
        || value.maximum_major == 0
        || (value.maximum_major, value.maximum_minor) < (value.minimum_major, value.minimum_minor)
    {
        return Err(invalid_value("protocol"));
    }
    Ok(ParsedProtocolRange {
        minimum_major: value.minimum_major,
        minimum_minor: value.minimum_minor,
        maximum_major: value.maximum_major,
        maximum_minor: value.maximum_minor,
    })
}

fn parse_runtime_claims(value: v1::RuntimeClaims) -> Result<RuntimeClaims, WireError> {
    if value.capabilities.len() > MAX_RUNTIME_CAPABILITIES
        || value.active_run_ids.len() > MAX_ACTIVE_RUN_IDS
        || value.queue_depth > MAX_RUNTIME_QUEUE_DEPTH
    {
        return Err(invalid_value("runtime_claims"));
    }
    let active_run_ids = value
        .active_run_ids
        .iter()
        .map(|id| parse_id::<RunId>(id, "active_run_ids"))
        .collect::<Result<Vec<_>, _>>()?;
    let stable_error_code = if value.stable_error_code.is_empty() {
        None
    } else {
        Some(value.stable_error_code)
    };
    RuntimeClaims::new(
        parse_adapter_kind(&value.runtime_kind)?,
        value.runtime_version,
        parse_digest(value.adapter_build_digest, "adapter_build_digest")?,
        value.queue_depth,
        active_run_ids,
        stable_error_code,
        value.capabilities,
    )
    .map_err(|_| invalid_value("runtime_claims"))
}

fn parse_capacity(value: v1::Capacity) -> Result<ParsedCapacity, WireError> {
    if !(1..=MAX_CONCURRENT_RUNS).contains(&value.maximum_concurrent_runs)
        || value.available_concurrent_runs > value.maximum_concurrent_runs
        || !(1..=MAX_RUNTIME_QUEUE_DEPTH).contains(&value.maximum_queue_depth)
    {
        return Err(invalid_value("capacity"));
    }
    Ok(ParsedCapacity {
        maximum_concurrent_runs: value.maximum_concurrent_runs,
        available_concurrent_runs: value.available_concurrent_runs,
        maximum_queue_depth: value.maximum_queue_depth,
    })
}

fn parse_lease_fence(value: &v1::LeaseFence) -> Result<ParsedLeaseFence, WireError> {
    Ok(ParsedLeaseFence {
        tenant_id: parse_id(&value.tenant_id, "fence.tenant_id")?,
        connector_id: parse_id(&value.connector_id, "fence.connector_id")?,
        boot_id: parse_id(&value.boot_id, "fence.boot_id")?,
        connector_generation: positive_safe(
            value.connector_generation,
            "fence.connector_generation",
        )?,
        lease_id: parse_id(&value.lease_id, "fence.lease_id")?,
        lease_epoch: positive_safe(value.lease_epoch, "fence.lease_epoch")?,
    })
}

fn parse_required_lease_fence(
    value: Option<v1::LeaseFence>,
) -> Result<ParsedLeaseFence, WireError> {
    let value = required(value, "connector_fence")?;
    parse_lease_fence(&value)
}

fn build_parsed_lease_fence(value: ParsedLeaseFence) -> Result<v1::LeaseFence, WireError> {
    Ok(v1::LeaseFence {
        tenant_id: value.tenant_id.to_string(),
        connector_id: value.connector_id.to_string(),
        boot_id: value.boot_id.to_string(),
        connector_generation: positive_safe(
            value.connector_generation,
            "connector_fence.connector_generation",
        )?,
        lease_id: value.lease_id.to_string(),
        lease_epoch: positive_safe(value.lease_epoch, "connector_fence.lease_epoch")?,
    })
}

fn validate_connector_identity(
    fence: &ParsedLeaseFence,
    connector_id: ConnectorId,
) -> Result<(), WireError> {
    if fence.connector_id == connector_id {
        Ok(())
    } else {
        Err(invalid_value("connector_id"))
    }
}

fn normalize_capabilities(values: &mut [String]) -> Result<(), WireError> {
    validate_stable_names(values, MAX_RUNTIME_CAPABILITIES, "required_capabilities")?;
    values.sort_unstable();
    Ok(())
}

fn parse_adapter_kind(value: &str) -> Result<AdapterKind, WireError> {
    match value {
        "codex" => Ok(AdapterKind::Codex),
        "openclaw_acp" => Ok(AdapterKind::OpenClawAcp),
        "eino" => Ok(AdapterKind::Eino),
        "rig" => Ok(AdapterKind::Rig),
        "claude_code" => Ok(AdapterKind::ClaudeCode),
        "custom_acp" => Ok(AdapterKind::CustomAcp),
        _ => Err(WireError {
            kind: WireErrorKind::UnsupportedValue,
            field: "runtime_kind",
        }),
    }
}

fn parse_public_key(value: &[u8], field: &'static str) -> Result<Ed25519PublicKey, WireError> {
    Ed25519PublicKey::try_from(value).map_err(|_| WireError {
        kind: WireErrorKind::InvalidValue,
        field,
    })
}

fn parse_digest(value: Vec<u8>, field: &'static str) -> Result<Sha256Digest, WireError> {
    exact_array(value, field).map(Sha256Digest::from_bytes)
}

fn exact_array<const LENGTH: usize>(
    value: Vec<u8>,
    field: &'static str,
) -> Result<[u8; LENGTH], WireError> {
    value.try_into().map_err(|_| WireError {
        kind: WireErrorKind::InvalidLength,
        field,
    })
}

fn take_exact_secret_array<const LENGTH: usize>(
    value: &mut Vec<u8>,
    field: &'static str,
) -> Result<[u8; LENGTH], WireError> {
    let result = value.as_slice().try_into().map_err(|_| WireError {
        kind: WireErrorKind::InvalidLength,
        field,
    });
    value.as_mut_slice().zeroize();
    result
}

fn parse_id<T>(value: &str, field: &'static str) -> Result<T, WireError>
where
    T: FromStr,
{
    value.parse().map_err(|_| WireError {
        kind: WireErrorKind::InvalidIdentifier,
        field,
    })
}

fn parse_revision(value: u64, field: &'static str) -> Result<Revision, WireError> {
    Revision::new(value).map_err(|_| invalid_value(field))
}

fn positive_safe(value: u64, field: &'static str) -> Result<u64, WireError> {
    if value == 0 || value > Revision::MAX {
        Err(invalid_value(field))
    } else {
        Ok(value)
    }
}

fn safe_cursor(value: u64, field: &'static str) -> Result<u64, WireError> {
    if value > Revision::MAX {
        Err(invalid_value(field))
    } else {
        Ok(value)
    }
}

fn validated_timestamp(value: i64, field: &'static str) -> Result<u64, WireError> {
    if !(0..=Revision::MAX.cast_signed()).contains(&value) {
        return Err(invalid_value(field));
    }
    u64::try_from(value).map_err(|_| invalid_value(field))
}

fn parse_wire_timestamp(value: u64, field: &'static str) -> Result<i64, WireError> {
    if value > Revision::MAX {
        return Err(invalid_value(field));
    }
    i64::try_from(value).map_err(|_| invalid_value(field))
}

fn timestamp_to_u64(value: i64) -> u64 {
    u64::try_from(value).expect("ConnectorCredential validates non-negative timestamps")
}

fn required<T>(value: Option<T>, field: &'static str) -> Result<T, WireError> {
    value.ok_or(WireError {
        kind: WireErrorKind::MissingField,
        field,
    })
}

fn validate_stable_names(
    values: &[String],
    maximum_entries: usize,
    field: &'static str,
) -> Result<(), WireError> {
    if values.len() > maximum_entries || values.iter().any(|value| !valid_lower_stable_name(value))
    {
        return Err(invalid_value(field));
    }
    let mut unique = BTreeSet::new();
    if values.iter().all(|value| unique.insert(value.as_str())) {
        Ok(())
    } else {
        Err(invalid_value(field))
    }
}

fn valid_lower_stable_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_STABLE_NAME_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
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

fn valid_upper_stable_code(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && !value.as_bytes().windows(2).any(|window| window == b"__")
}

const fn invalid_value(field: &'static str) -> WireError {
    WireError {
        kind: WireErrorKind::InvalidValue,
        field,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT_ID: &str = "0190f2a5-7b1c-7abc-8def-0123456789a1";
    const CONNECTOR_ID: &str = "0190f2a5-7b1c-7abc-8def-0123456789a2";
    const BOOT_ID: &str = "0190f2a5-7b1c-7abc-8def-0123456789a3";
    const LEASE_ID: &str = "0190f2a5-7b1c-7abc-8def-0123456789a4";
    const RUN_ID: &str = "0190f2a5-7b1c-7abc-8def-0123456789a5";
    const REQUEST_ID: &str = "0190f2a5-7b1c-7abc-8def-0123456789a6";
    const INSTALLATION_ID: &str = "0190f2a5-7b1c-7abc-8def-0123456789a7";
    const BINDING_ID: &str = "0190f2a5-7b1c-7abc-8def-0123456789a8";
    const RUN_LEASE_ID: &str = "0190f2a5-7b1c-7abc-8def-0123456789a9";
    const CONVERSATION_ID: &str = "0190f2a5-7b1c-7abc-8def-0123456789aa";
    const INPUT_EVENT_ID: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";

    #[test]
    fn enrollment_token_wire_buffer_is_scrubbed_on_success_and_length_error() {
        let mut exact = vec![0x5a; 32];
        let copied = take_exact_secret_array::<32>(&mut exact, "enrollment_token")
            .expect("exact token length is accepted");
        assert_eq!(copied, [0x5a; 32]);
        assert!(exact.iter().all(|byte| *byte == 0));

        let mut wrong = vec![0xa5; 31];
        let error = take_exact_secret_array::<32>(&mut wrong, "enrollment_token")
            .expect_err("wrong token length is rejected");
        assert_eq!(error.kind(), WireErrorKind::InvalidLength);
        assert!(wrong.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn client_frame_requires_a_known_oneof_member() {
        let error = parse_client_frame(v1::ClientFrame { kind: None })
            .expect_err("missing oneof must be rejected");
        assert_eq!(error.kind(), WireErrorKind::MissingField);
        assert_eq!(error.field(), "client_frame.kind");
    }

    #[test]
    fn protocol_range_uses_ordered_major_minor_bounds() {
        let parsed = parse_protocol(v1::ProtocolRange {
            minimum_major: 1,
            minimum_minor: 2,
            maximum_major: 2,
            maximum_minor: 1,
        })
        .expect("ordered cross-major range");
        assert!(parsed.supports(1, 2));
        assert!(parsed.supports(2, 0));
        assert!(!parsed.supports(1, 1));
        assert!(!parsed.supports(2, 2));
    }

    #[test]
    fn capacity_rejects_available_above_maximum() {
        let error = parse_capacity(v1::Capacity {
            maximum_concurrent_runs: 2,
            available_concurrent_runs: 3,
            maximum_queue_depth: 1,
        })
        .expect_err("overcommitted report must be rejected");
        assert_eq!(error.field(), "capacity");
    }

    #[test]
    fn run_claim_is_a_validated_normalized_offer_ack() {
        let parsed = parse_client_frame(v1::ClientFrame {
            kind: Some(v1::client_frame::Kind::RunClaim(v1::RunClaim {
                connector_fence: Some(run_fence()),
                run_id: RUN_ID.into(),
                request_id: REQUEST_ID.into(),
                installation_id: INSTALLATION_ID.into(),
                binding_id: BINDING_ID.into(),
                connector_id: CONNECTOR_ID.into(),
                offer_attempt: 2,
                offer_deadline_millis: 2_000,
                required_capabilities: vec!["tools.web".into(), "runtime.codex".into()],
            })),
        })
        .expect("complete offer acknowledgement is accepted");
        let ParsedClientFrame::RunClaim(parsed) = parsed else {
            panic!("run claim remains on the existing parsed client-frame stream");
        };

        assert_eq!(parsed.offer_attempt, 2);
        assert_eq!(parsed.required_capabilities, ["runtime.codex", "tools.web"]);
    }

    #[test]
    fn run_frames_reject_connector_identity_outside_the_fence() {
        let error = parse_run_claim(v1::RunClaim {
            connector_fence: Some(run_fence()),
            run_id: RUN_ID.into(),
            request_id: REQUEST_ID.into(),
            installation_id: INSTALLATION_ID.into(),
            binding_id: BINDING_ID.into(),
            connector_id: TENANT_ID.into(),
            offer_attempt: 1,
            offer_deadline_millis: 2_000,
            required_capabilities: Vec::new(),
        })
        .expect_err("redundant Connector identity is a checked binding");

        assert_eq!(error.field(), "connector_id");
    }

    #[test]
    fn run_release_requires_both_fences_and_a_stable_reason() {
        let parsed = parse_run_release(v1::RunRelease {
            connector_fence: Some(run_fence()),
            run_id: RUN_ID.into(),
            request_id: REQUEST_ID.into(),
            installation_id: INSTALLATION_ID.into(),
            binding_id: BINDING_ID.into(),
            connector_id: CONNECTOR_ID.into(),
            offer_attempt: 1,
            run_lease_id: RUN_LEASE_ID.into(),
            run_lease_epoch: 3,
            run_lease_deadline_millis: 3_000,
            stable_reason: "CAPACITY_REBALANCE".into(),
        })
        .expect("complete dual-fence release is accepted");
        assert_eq!(parsed.run_lease_epoch, 3);

        let mut invalid = v1::RunRelease {
            connector_fence: Some(run_fence()),
            run_id: RUN_ID.into(),
            request_id: REQUEST_ID.into(),
            installation_id: INSTALLATION_ID.into(),
            binding_id: BINDING_ID.into(),
            connector_id: CONNECTOR_ID.into(),
            offer_attempt: 1,
            run_lease_id: RUN_LEASE_ID.into(),
            run_lease_epoch: 3,
            run_lease_deadline_millis: 3_000,
            stable_reason: "done".into(),
        };
        let error = parse_run_release(invalid.clone()).expect_err("free-form reason is rejected");
        assert_eq!(error.field(), "stable_reason");
        invalid.connector_fence = None;
        let error = parse_run_release(invalid).expect_err("Connector fence is required");
        assert_eq!(error.kind(), WireErrorKind::MissingField);
    }

    #[test]
    fn only_granted_builder_emits_a_run_lease_fence() {
        let fence = parse_lease_fence(&run_fence()).expect("test fence is valid");
        let available = build_run_available(RunAvailableWire {
            connector_offer_sequence: 1,
            connector_fence: fence,
            run_id: RUN_ID.parse().expect("run id"),
            request_id: REQUEST_ID.parse().expect("request id"),
            installation_id: INSTALLATION_ID.parse().expect("installation id"),
            binding_id: BINDING_ID.parse().expect("binding id"),
            connector_id: CONNECTOR_ID.parse().expect("connector id"),
            offer_attempt: 1,
            offered_at_millis: 1_000,
            offer_deadline_millis: 2_000,
            required_capabilities: vec!["tools.web".into()],
        })
        .expect("coherent offer builds");
        assert_eq!(available.run_id, RUN_ID);

        let granted = build_run_lease_granted(RunLeaseGrantedWire {
            connector_fence: fence,
            run_id: RUN_ID.parse().expect("run id"),
            request_id: REQUEST_ID.parse().expect("request id"),
            installation_id: INSTALLATION_ID.parse().expect("installation id"),
            binding_id: BINDING_ID.parse().expect("binding id"),
            connector_id: CONNECTOR_ID.parse().expect("connector id"),
            offer_attempt: 1,
            run_lease_id: RUN_LEASE_ID.parse().expect("run lease id"),
            run_lease_epoch: 2,
            granted_at_millis: 1_500,
            run_lease_deadline_millis: 2_500,
            required_capabilities: vec!["tools.web".into()],
            conversation_id: CONVERSATION_ID.parse().expect("conversation id"),
            input_event_id: INPUT_EVENT_ID.parse().expect("input event id"),
            grant_version: 3,
        })
        .expect("coherent grant builds");
        assert_eq!(granted.run_lease_id, RUN_LEASE_ID);
        assert_eq!(granted.run_lease_epoch, 2);
    }

    fn run_fence() -> v1::LeaseFence {
        v1::LeaseFence {
            tenant_id: TENANT_ID.into(),
            connector_id: CONNECTOR_ID.into(),
            boot_id: BOOT_ID.into(),
            connector_generation: 1,
            lease_id: LEASE_ID.into(),
            lease_epoch: 1,
        }
    }
}
