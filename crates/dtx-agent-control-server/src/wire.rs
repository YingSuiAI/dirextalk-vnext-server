use std::{collections::BTreeSet, error::Error, fmt, str::FromStr};

use dtx_agent_control::{
    CommandAck, ConnectorCredential, CredentialRotationRequest, CredentialRotationTranscript,
    DurableServerCommand, EnrollmentRequest, EnrollmentToken, EnrollmentTranscript,
    MAX_ACTIVE_RUN_IDS, MAX_RUNTIME_CAPABILITIES, MAX_RUNTIME_QUEUE_DEPTH, RuntimeClaims,
    Sha256Digest,
};
use dtx_agent_control_proto::v1;
use dtx_connect_registry::{
    AdapterKind, ConnectorFence, ConnectorLease, HeartbeatAck, LeaseStatus,
};
use dtx_domain::{
    BootId, ConnectorCredentialId, ConnectorId, Ed25519PublicKey, HostId, LeaseId, RequestId,
    Revision, RunId, TenantId,
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
    }
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

const fn invalid_value(field: &'static str) -> WireError {
    WireError {
        kind: WireErrorKind::InvalidValue,
        field,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
