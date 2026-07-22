//! Host-control operator v2 framing and bootstrap-material codec.
//!
//! The one-shot binary dispatches this closed, bounded protocol independently
//! from the frozen v1 frame.
//! No caller-controlled path, command, environment, service, URL, or secret
//! value is represented by the wire types.

use std::{
    fmt,
    io::{self, Write},
};

use dtx_domain::{ConnectorId, HostId, RequestId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

pub const PROTOCOL_V2: &str = "dirextalk.host-control.operator.v2";
pub const MAGIC_V2: &[u8; 8] = b"DTXHC02\0";
pub const MAX_HEADER_BYTES_V2: usize = 16 * 1024;
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
pub const MAX_TRUST_PEM_BYTES: usize = 64 * 1024;
pub const MAX_PLAN_BYTES: usize = 65_536;
pub const MAX_HANDOFF_BYTES: usize = 64 * 1024;
pub const MAX_MATERIAL_BYTES: usize = 384 * 1024;
pub const MAX_FRAME_BYTES_V2: usize =
    MAGIC_V2.len() + 4 + MAX_HEADER_BYTES_V2 + 4 + MAX_MATERIAL_BYTES;
pub const MAX_JSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

const MATERIAL_MAGIC: &[u8; 8] = b"DTXBMT01";
const MATERIAL_HEADER_BYTES: usize = 8 + (6 * 4);

/// Exactly the two v2 mutations. Read-only operations remain v1-only.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V2Operation {
    PrepareConnectorMaterial,
    FinalizeConnectorMaterial,
}

/// Closed adapter enum carried by bootstrap material operations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterV2 {
    Codex,
    OpenclawAcp,
    Eino,
    Rig,
    ClaudeCode,
    CustomAcp,
    HermesAcp,
}

/// The only platform targets accepted by this codec.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PlatformTarget {
    #[serde(rename = "linux-amd64")]
    LinuxAmd64,
    #[serde(rename = "linux-arm64")]
    LinuxArm64,
}

impl PlatformTarget {
    /// Maps an explicit target tuple, failing closed for anything unsupported.
    #[must_use]
    pub fn from_target(os: &str, arch: &str) -> Option<Self> {
        match (os, arch) {
            ("linux", "x86_64") => Some(Self::LinuxAmd64),
            ("linux", "aarch64") => Some(Self::LinuxArm64),
            _ => None,
        }
    }

    /// Returns the target compiled for the executing binary, or `None` when
    /// this binary is not a supported Linux target.
    #[must_use]
    pub fn executing() -> Option<Self> {
        Self::from_target(std::env::consts::OS, std::env::consts::ARCH)
    }
}

/// Strict v2 header. Digest strings are validated as lowercase SHA-256.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2Header {
    pub protocol: String,
    pub tenant_id: TenantId,
    pub host_id: HostId,
    pub host_operation_id: RequestId,
    pub expected_desired_revision: u64,
    pub expected_observed_revision: Option<u64>,
    pub connector_id: ConnectorId,
    pub adapter: AdapterV2,
    pub approved_release_sha256: String,
    pub lifecycle_operation_id: RequestId,
    pub platform_target: PlatformTarget,
    pub expiry_millis: u64,
    pub plan_sha256: String,
    pub handoff_sha256: String,
    pub config_sha256: Option<String>,
    pub enrollment_ca_sha256: Option<String>,
    pub control_ca_sha256: Option<String>,
    pub issuer_ca_sha256: Option<String>,
    /// SHA-256 of the original prepare material envelope, retained for
    /// header-only completed replays and finalize identity reconstruction.
    pub lifecycle_material_sha256: String,
    pub payload_sha256: String,
    pub prepared_receipt_sha256: Option<String>,
    pub operation: V2Operation,
}

/// Secret bootstrap material. It deliberately has no `Debug`, `Display`, or
/// serialization implementation; every byte is held in a zeroizing buffer.
pub struct BootstrapMaterialV1 {
    config_toml: Zeroizing<Vec<u8>>,
    enrollment_ca_pem: Zeroizing<Vec<u8>>,
    control_ca_pem: Zeroizing<Vec<u8>>,
    issuer_ca_pem: Zeroizing<Vec<u8>>,
    plan_json: Zeroizing<Vec<u8>>,
    handoff_json: Zeroizing<Vec<u8>>,
}

#[allow(
    dead_code,
    reason = "encoding is retained for isolated v2 contract tests"
)]
impl BootstrapMaterialV1 {
    #[must_use]
    pub fn new(
        config_toml: Vec<u8>,
        enrollment_ca_pem: Vec<u8>,
        control_ca_pem: Vec<u8>,
        issuer_ca_pem: Vec<u8>,
        plan_json: Vec<u8>,
        handoff_json: Vec<u8>,
    ) -> Self {
        Self {
            config_toml: Zeroizing::new(config_toml),
            enrollment_ca_pem: Zeroizing::new(enrollment_ca_pem),
            control_ca_pem: Zeroizing::new(control_ca_pem),
            issuer_ca_pem: Zeroizing::new(issuer_ca_pem),
            plan_json: Zeroizing::new(plan_json),
            handoff_json: Zeroizing::new(handoff_json),
        }
    }

    #[must_use]
    pub fn config_toml(&self) -> &[u8] {
        &self.config_toml
    }
    #[must_use]
    pub fn enrollment_ca_pem(&self) -> &[u8] {
        &self.enrollment_ca_pem
    }
    #[must_use]
    pub fn control_ca_pem(&self) -> &[u8] {
        &self.control_ca_pem
    }
    #[must_use]
    pub fn issuer_ca_pem(&self) -> &[u8] {
        &self.issuer_ca_pem
    }
    #[must_use]
    pub fn plan_json(&self) -> &[u8] {
        &self.plan_json
    }
    #[must_use]
    pub fn handoff_json(&self) -> &[u8] {
        &self.handoff_json
    }

    /// Encodes the strict binary envelope with six length-delimited fields.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, V2CodecError> {
        self.encode_for(V2Operation::PrepareConnectorMaterial)
    }

    /// Encodes material for either v2 mutation. Finalize intentionally carries
    /// only the exact plan and handoff fields; the first four lengths are zero.
    pub fn encode_for(&self, operation: V2Operation) -> Result<Zeroizing<Vec<u8>>, V2CodecError> {
        validate_material(self, operation)?;
        let fields = [
            self.config_toml.as_slice(),
            self.enrollment_ca_pem.as_slice(),
            self.control_ca_pem.as_slice(),
            self.issuer_ca_pem.as_slice(),
            self.plan_json.as_slice(),
            self.handoff_json.as_slice(),
        ];
        let total = fields
            .iter()
            .try_fold(MATERIAL_HEADER_BYTES, |total, field| {
                total
                    .checked_add(field.len())
                    .ok_or(V2CodecError::OversizedMaterial)
            })?;
        if total > MAX_MATERIAL_BYTES {
            return Err(V2CodecError::OversizedMaterial);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(total));
        out.extend_from_slice(MATERIAL_MAGIC);
        for field in fields {
            let length = u32::try_from(field.len()).map_err(|_| V2CodecError::OversizedMaterial)?;
            out.extend_from_slice(&length.to_be_bytes());
        }
        for field in fields {
            out.extend_from_slice(field);
        }
        Ok(out)
    }
}

/// Parsed v2 request frame. Material is always zeroized on drop.
pub struct V2RequestFrame {
    pub header: V2Header,
    /// None is accepted only as the header-only completed-replay seam.
    pub material: Option<BootstrapMaterialV1>,
}

/// The v2 response is deliberately a different, closed projection from the
/// frozen v1 operator response.  It never serializes material, paths, command
/// output, or a diagnostic error.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2Response {
    protocol: &'static str,
    status: V2ResponseStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<V2Result>,
}

/// Sanitized lifecycle result. Every field is a closed identity or revision;
/// no receipt bytes, credential reference, material, path, or diagnostics can
/// cross the operator boundary.
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
pub struct V2Result {
    pub(crate) operation: &'static str,
    pub(crate) application: V2Application,
    pub(crate) disposition: &'static str,
    pub(crate) desired_revision: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) observed_revision: Option<u64>,
    pub(crate) connector_id: String,
    pub(crate) lifecycle_state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) prepared_receipt_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) finalized_receipt_sha256: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum V2ResponseStatus {
    Succeeded,
    Rejected,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum V2Application {
    Applied,
    Replayed,
}

impl V2Response {
    #[must_use]
    pub const fn rejected(code: &'static str) -> Self {
        Self {
            protocol: PROTOCOL_V2,
            status: V2ResponseStatus::Rejected,
            error: Some(code),
            result: None,
        }
    }

    #[must_use]
    pub const fn succeeded(result: V2Result) -> Self {
        Self {
            protocol: PROTOCOL_V2,
            status: V2ResponseStatus::Succeeded,
            error: None,
            result: Some(result),
        }
    }

    #[must_use]
    pub const fn succeeded_status(&self) -> bool {
        matches!(self.status, V2ResponseStatus::Succeeded)
    }
}

pub fn encode_response_v2(mut writer: impl Write, response: &V2Response) -> io::Result<()> {
    serde_json::to_writer(&mut writer, response)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// Stable, non-diagnostic codec rejection. No payload or path is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum V2CodecError {
    InvalidFrame,
    InvalidHeader,
    UnsupportedProtocol,
    InvalidSha256,
    DigestMismatch,
    InvalidMaterial,
    MissingMaterial,
    OversizedMaterial,
    InvalidPlatform,
}

impl fmt::Display for V2CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid host-control v2 frame")
    }
}

impl std::error::Error for V2CodecError {}

/// Parses and validates one complete v2 frame, including every component
/// digest, strict envelope bounds, operation shape, and executing target.
/// The caller owns `input`; the dispatcher supplies its outer frame from a
/// bounded `Zeroizing<Vec<u8>>`. Decoded material is always zeroized.
pub fn read_frame_v2(input: &[u8]) -> Result<V2RequestFrame, V2CodecError> {
    if input.len() > MAX_FRAME_BYTES_V2 || input.len() < MAGIC_V2.len() + 8 {
        return Err(V2CodecError::InvalidFrame);
    }
    if input.get(..MAGIC_V2.len()) != Some(MAGIC_V2.as_slice()) {
        return Err(V2CodecError::InvalidFrame);
    }
    let header_len = read_u32(input, MAGIC_V2.len())?;
    if header_len == 0 || header_len > MAX_HEADER_BYTES_V2 {
        return Err(V2CodecError::InvalidHeader);
    }
    let header_start = MAGIC_V2.len() + 4;
    let header_end = header_start
        .checked_add(header_len)
        .ok_or(V2CodecError::InvalidFrame)?;
    let payload_len_offset = header_end;
    let payload_start = payload_len_offset
        .checked_add(4)
        .ok_or(V2CodecError::InvalidFrame)?;
    let payload_len = read_u32(input, payload_len_offset)?;
    if payload_len > MAX_MATERIAL_BYTES
        || payload_start.checked_add(payload_len) != Some(input.len())
    {
        return Err(V2CodecError::InvalidFrame);
    }
    reject_duplicate_json_keys(&input[header_start..header_end])
        .map_err(|_| V2CodecError::InvalidHeader)?;
    let mut decoder = serde_json::Deserializer::from_slice(&input[header_start..header_end]);
    let header = V2Header::deserialize(&mut decoder).map_err(|_| V2CodecError::InvalidHeader)?;
    decoder.end().map_err(|_| V2CodecError::InvalidHeader)?;
    validate_header(&header)?;
    let payload = &input[payload_start..];
    if digest(payload) != decode_digest(&header.payload_sha256)? {
        return Err(V2CodecError::DigestMismatch);
    }
    if !payload.is_empty()
        && header.operation == V2Operation::PrepareConnectorMaterial
        && digest(payload) != decode_digest(&header.lifecycle_material_sha256)?
    {
        return Err(V2CodecError::DigestMismatch);
    }
    if payload.is_empty() {
        return Ok(V2RequestFrame {
            header,
            material: None,
        });
    }
    let material = decode_material(payload, header.operation)?;
    validate_digests(&header, &material)?;
    if header.operation == V2Operation::PrepareConnectorMaterial
        && digest(payload) != decode_digest(&header.lifecycle_material_sha256)?
    {
        return Err(V2CodecError::DigestMismatch);
    }
    Ok(V2RequestFrame {
        header,
        material: Some(material),
    })
}

/// Encodes a complete frame for contract tests and trusted callers.
#[allow(
    dead_code,
    reason = "encoding is retained for isolated v2 contract tests"
)]
pub fn encode_frame_v2(
    header: &V2Header,
    payload: &[u8],
) -> Result<Zeroizing<Vec<u8>>, V2CodecError> {
    validate_header(header)?;
    if payload.len() > MAX_MATERIAL_BYTES {
        return Err(V2CodecError::OversizedMaterial);
    }
    if digest(payload) != decode_digest(&header.payload_sha256)? {
        return Err(V2CodecError::DigestMismatch);
    }
    if !payload.is_empty()
        && header.operation == V2Operation::PrepareConnectorMaterial
        && digest(payload) != decode_digest(&header.lifecycle_material_sha256)?
    {
        return Err(V2CodecError::DigestMismatch);
    }
    let encoded = serde_json::to_vec(header).map_err(|_| V2CodecError::InvalidHeader)?;
    if encoded.is_empty() || encoded.len() > MAX_HEADER_BYTES_V2 {
        return Err(V2CodecError::InvalidHeader);
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(
        MAGIC_V2.len() + 8 + encoded.len() + payload.len(),
    ));
    frame.extend_from_slice(MAGIC_V2);
    frame.extend_from_slice(
        &(u32::try_from(encoded.len()).map_err(|_| V2CodecError::InvalidHeader)?).to_be_bytes(),
    );
    frame.extend_from_slice(&encoded);
    frame.extend_from_slice(
        &(u32::try_from(payload.len()).map_err(|_| V2CodecError::OversizedMaterial)?).to_be_bytes(),
    );
    frame.extend_from_slice(payload);
    Ok(frame)
}

fn validate_header(header: &V2Header) -> Result<(), V2CodecError> {
    if header.protocol != PROTOCOL_V2 {
        return Err(V2CodecError::UnsupportedProtocol);
    }
    if PlatformTarget::executing() != Some(header.platform_target) {
        return Err(V2CodecError::InvalidPlatform);
    }
    if header.expected_desired_revision == 0
        || header.expected_desired_revision > MAX_JSON_SAFE_INTEGER
        || header
            .expected_observed_revision
            .is_some_and(|revision| revision == 0 || revision > MAX_JSON_SAFE_INTEGER)
        || header
            .expected_observed_revision
            .is_some_and(|revision| revision > header.expected_desired_revision)
        || header.expiry_millis == 0
        || header.expiry_millis > MAX_JSON_SAFE_INTEGER
    {
        return Err(V2CodecError::InvalidHeader);
    }
    for value in [
        &header.approved_release_sha256,
        &header.plan_sha256,
        &header.handoff_sha256,
        &header.lifecycle_material_sha256,
        &header.payload_sha256,
    ] {
        decode_digest(value)?;
    }
    for value in [
        &header.config_sha256,
        &header.enrollment_ca_sha256,
        &header.control_ca_sha256,
        &header.issuer_ca_sha256,
        &header.prepared_receipt_sha256,
    ]
    .into_iter()
    .flatten()
    {
        decode_digest(value)?;
    }
    match header.operation {
        V2Operation::PrepareConnectorMaterial => {
            if header.config_sha256.is_none()
                || header.enrollment_ca_sha256.is_none()
                || header.control_ca_sha256.is_none()
                || header.issuer_ca_sha256.is_none()
                || header.prepared_receipt_sha256.is_some()
            {
                return Err(V2CodecError::InvalidHeader);
            }
        }
        V2Operation::FinalizeConnectorMaterial => {
            if header.config_sha256.is_none()
                || header.enrollment_ca_sha256.is_none()
                || header.control_ca_sha256.is_none()
                || header.issuer_ca_sha256.is_none()
                || header.prepared_receipt_sha256.is_none()
            {
                return Err(V2CodecError::InvalidHeader);
            }
        }
    }
    Ok(())
}

fn validate_digests(header: &V2Header, material: &BootstrapMaterialV1) -> Result<(), V2CodecError> {
    let pairs = [
        (&header.plan_sha256, material.plan_json()),
        (&header.handoff_sha256, material.handoff_json()),
    ];
    for (expected, bytes) in pairs {
        if digest(bytes) != decode_digest(expected)? {
            return Err(V2CodecError::DigestMismatch);
        }
    }
    if header.operation == V2Operation::PrepareConnectorMaterial {
        let expected = header
            .config_sha256
            .as_ref()
            .ok_or(V2CodecError::InvalidHeader)?;
        for (expected, bytes) in [
            (expected, material.config_toml()),
            (
                header
                    .enrollment_ca_sha256
                    .as_ref()
                    .ok_or(V2CodecError::InvalidHeader)?,
                material.enrollment_ca_pem(),
            ),
            (
                header
                    .control_ca_sha256
                    .as_ref()
                    .ok_or(V2CodecError::InvalidHeader)?,
                material.control_ca_pem(),
            ),
            (
                header
                    .issuer_ca_sha256
                    .as_ref()
                    .ok_or(V2CodecError::InvalidHeader)?,
                material.issuer_ca_pem(),
            ),
        ] {
            if digest(bytes) != decode_digest(expected)? {
                return Err(V2CodecError::DigestMismatch);
            }
        }
    } else if !material.config_toml().is_empty()
        || !material.enrollment_ca_pem().is_empty()
        || !material.control_ca_pem().is_empty()
        || !material.issuer_ca_pem().is_empty()
    {
        return Err(V2CodecError::InvalidMaterial);
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "encoding is retained for isolated v2 contract tests"
)]
fn validate_material(
    material: &BootstrapMaterialV1,
    operation: V2Operation,
) -> Result<(), V2CodecError> {
    let lengths = [
        (material.config_toml().len(), MAX_CONFIG_BYTES),
        (material.enrollment_ca_pem().len(), MAX_TRUST_PEM_BYTES),
        (material.control_ca_pem().len(), MAX_TRUST_PEM_BYTES),
        (material.issuer_ca_pem().len(), MAX_TRUST_PEM_BYTES),
        (material.plan_json().len(), MAX_PLAN_BYTES),
        (material.handoff_json().len(), MAX_HANDOFF_BYTES),
    ];
    let required = if operation == V2Operation::PrepareConnectorMaterial {
        &lengths[..]
    } else {
        &lengths[4..]
    };
    if required
        .iter()
        .any(|(actual, max)| *actual == 0 || *actual > *max)
    {
        return Err(V2CodecError::MissingMaterial);
    }
    if operation == V2Operation::FinalizeConnectorMaterial
        && (!material.config_toml().is_empty()
            || !material.enrollment_ca_pem().is_empty()
            || !material.control_ca_pem().is_empty()
            || !material.issuer_ca_pem().is_empty())
    {
        return Err(V2CodecError::InvalidMaterial);
    }
    // Syntax-only boundary: `Value` would retain every handoff secret in an
    // ordinary heap String. Semantic parsing (including the secret-owning
    // parser) is deliberately deferred to production_v2.
    if reject_duplicate_json_keys(material.plan_json()).is_err()
        || reject_duplicate_json_keys(material.handoff_json()).is_err()
    {
        return Err(V2CodecError::InvalidMaterial);
    }
    Ok(())
}

fn decode_material(
    payload: &[u8],
    operation: V2Operation,
) -> Result<BootstrapMaterialV1, V2CodecError> {
    if payload.len() < MATERIAL_HEADER_BYTES || payload.get(..8) != Some(MATERIAL_MAGIC.as_slice())
    {
        return Err(V2CodecError::InvalidMaterial);
    }
    let mut lengths = [0usize; 6];
    for (index, length) in lengths.iter_mut().enumerate() {
        *length = read_u32(payload, 8 + (index * 4))?;
    }
    let mut offset = MATERIAL_HEADER_BYTES;
    let mut fields: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(6);
    for length in lengths {
        let end = offset
            .checked_add(length)
            .ok_or(V2CodecError::OversizedMaterial)?;
        if end > payload.len() {
            return Err(V2CodecError::InvalidMaterial);
        }
        fields.push(Zeroizing::new(payload[offset..end].to_vec()));
        offset = end;
    }
    if offset != payload.len() {
        return Err(V2CodecError::InvalidMaterial);
    }
    let material = BootstrapMaterialV1 {
        config_toml: fields.remove(0),
        enrollment_ca_pem: fields.remove(0),
        control_ca_pem: fields.remove(0),
        issuer_ca_pem: fields.remove(0),
        plan_json: fields.remove(0),
        handoff_json: fields.remove(0),
    };
    if operation == V2Operation::FinalizeConnectorMaterial
        && (!material.config_toml().is_empty()
            || !material.enrollment_ca_pem().is_empty()
            || !material.control_ca_pem().is_empty()
            || !material.issuer_ca_pem().is_empty())
    {
        return Err(V2CodecError::InvalidMaterial);
    }
    if material.plan_json().is_empty() || material.handoff_json().is_empty() {
        return Err(V2CodecError::MissingMaterial);
    }
    if operation == V2Operation::PrepareConnectorMaterial
        && (material.config_toml().is_empty()
            || material.enrollment_ca_pem().is_empty()
            || material.control_ca_pem().is_empty()
            || material.issuer_ca_pem().is_empty())
    {
        return Err(V2CodecError::MissingMaterial);
    }
    if material.config_toml().len() > MAX_CONFIG_BYTES
        || material.enrollment_ca_pem().len() > MAX_TRUST_PEM_BYTES
        || material.control_ca_pem().len() > MAX_TRUST_PEM_BYTES
        || material.issuer_ca_pem().len() > MAX_TRUST_PEM_BYTES
        || material.plan_json().len() > MAX_PLAN_BYTES
        || material.handoff_json().len() > MAX_HANDOFF_BYTES
        || payload.len() > MAX_MATERIAL_BYTES
    {
        return Err(V2CodecError::OversizedMaterial);
    }
    if reject_duplicate_json_keys(material.plan_json()).is_err()
        || reject_duplicate_json_keys(material.handoff_json()).is_err()
    {
        return Err(V2CodecError::InvalidMaterial);
    }
    Ok(material)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn decode_digest(value: &str) -> Result<[u8; 32], V2CodecError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(V2CodecError::InvalidSha256);
    }
    let mut result = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        result[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(result)
}

fn nibble(byte: u8) -> Result<u8, V2CodecError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(V2CodecError::InvalidSha256),
    }
}

fn read_u32(input: &[u8], offset: usize) -> Result<usize, V2CodecError> {
    let bytes = input
        .get(offset..offset.checked_add(4).ok_or(V2CodecError::InvalidFrame)?)
        .ok_or(V2CodecError::InvalidFrame)?;
    usize::try_from(u32::from_be_bytes(
        bytes.try_into().map_err(|_| V2CodecError::InvalidFrame)?,
    ))
    .map_err(|_| V2CodecError::InvalidFrame)
}

/// Reject duplicate members at every object depth and require one complete JSON
/// value.  This deliberately never builds a `Value`, which would copy handoff
/// secrets into ordinary `String`s before the zeroizing parser owns them.
pub(crate) fn reject_duplicate_json_keys(raw: &[u8]) -> Result<(), V2CodecError> {
    use serde::de::{DeserializeSeed as _, MapAccess, SeqAccess, Visitor};

    struct Check;
    impl<'de> serde::de::DeserializeSeed<'de> for Check {
        type Value = ();
        fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Check {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("JSON value")
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
            Ok(())
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<(), E> {
            Ok(())
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<(), E> {
            Ok(())
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<(), E> {
            Ok(())
        }
        fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<(), E> {
            Ok(())
        }
        fn visit_borrowed_str<E: serde::de::Error>(self, _: &'de str) -> Result<(), E> {
            Ok(())
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<(), E> {
            Ok(())
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
            Ok(())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
            while a.next_element_seed(Check)?.is_some() {}
            Ok(())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
            let mut seen = std::collections::BTreeSet::new();
            while let Some(key) = a.next_key::<std::borrow::Cow<'de, str>>()? {
                if !seen.insert(key) {
                    return Err(serde::de::Error::custom("duplicate JSON key"));
                }
                a.next_value_seed(Check)?;
            }
            Ok(())
        }
    }
    let mut d = serde_json::Deserializer::from_slice(raw);
    Check
        .deserialize(&mut d)
        .map_err(|_| V2CodecError::InvalidMaterial)?;
    d.end().map_err(|_| V2CodecError::InvalidMaterial)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    const TENANT: &str = "0197f1f0-0000-7000-8000-000000000001";
    const HOST: &str = "0197f1f0-0000-7000-8000-000000000002";
    const CONNECTOR: &str = "0197f1f0-0000-7000-8000-000000000003";
    const HOST_OPERATION: &str = "0197f1f0-0000-7000-8000-000000000004";
    const PLAN_OPERATION: &str = "0197f1f0-0000-7000-8000-000000000005";

    fn id<T: std::str::FromStr>(value: &str) -> T {
        value.parse().ok().expect("valid UUIDv7")
    }

    fn prepare_material() -> BootstrapMaterialV1 {
        BootstrapMaterialV1::new(
            b"[connector]\n".to_vec(),
            b"enrollment".to_vec(),
            b"control".to_vec(),
            b"issuer".to_vec(),
            br#"{"plan":"redacted"}"#.to_vec(),
            br#"{"handoff":"opaque"}"#.to_vec(),
        )
    }

    fn digest_text(bytes: &[u8]) -> String {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        let mut text = String::with_capacity(64);
        for byte in digest {
            let _ = write!(text, "{byte:02x}");
        }
        text
    }

    fn header(operation: V2Operation, material: &BootstrapMaterialV1, payload: &[u8]) -> V2Header {
        V2Header {
            protocol: PROTOCOL_V2.to_owned(),
            tenant_id: id(TENANT),
            host_id: id(HOST),
            host_operation_id: id(HOST_OPERATION),
            expected_desired_revision: 1,
            expected_observed_revision: Some(1),
            connector_id: id(CONNECTOR),
            adapter: AdapterV2::Codex,
            approved_release_sha256: digest_text(b"release"),
            lifecycle_operation_id: id(PLAN_OPERATION),
            platform_target: PlatformTarget::executing().expect("test target is supported"),
            expiry_millis: 4_000_000_000,
            plan_sha256: digest_text(material.plan_json()),
            handoff_sha256: digest_text(material.handoff_json()),
            config_sha256: Some(digest_text(material.config_toml())),
            enrollment_ca_sha256: Some(digest_text(material.enrollment_ca_pem())),
            control_ca_sha256: Some(digest_text(material.control_ca_pem())),
            issuer_ca_sha256: Some(digest_text(material.issuer_ca_pem())),
            lifecycle_material_sha256: digest_text(payload),
            payload_sha256: digest_text(payload),
            prepared_receipt_sha256: (operation == V2Operation::FinalizeConnectorMaterial)
                .then(|| digest_text(b"prepared-receipt")),
            operation,
        }
    }

    #[test]
    fn platform_mapping_accepts_only_supported_linux_targets() {
        assert_eq!(
            PlatformTarget::from_target("linux", "x86_64"),
            Some(PlatformTarget::LinuxAmd64)
        );
        assert_eq!(
            PlatformTarget::from_target("linux", "aarch64"),
            Some(PlatformTarget::LinuxArm64)
        );
        assert_eq!(PlatformTarget::from_target("windows", "x86_64"), None);
        assert_eq!(PlatformTarget::from_target("linux", "riscv64"), None);
    }

    #[test]
    fn rejects_non_json_safe_revision_and_expiry_values() {
        let material = prepare_material();
        let payload = material.encode().expect("material encodes");
        let mut header = header(V2Operation::PrepareConnectorMaterial, &material, &payload);
        header.expected_desired_revision = MAX_JSON_SAFE_INTEGER + 1;
        assert!(matches!(
            encode_frame_v2(&header, &payload),
            Err(V2CodecError::InvalidHeader)
        ));
        header.expected_desired_revision = 1;
        header.expiry_millis = MAX_JSON_SAFE_INTEGER + 1;
        assert!(matches!(
            encode_frame_v2(&header, &payload),
            Err(V2CodecError::InvalidHeader)
        ));
    }

    #[test]
    fn prepare_round_trip_binds_every_material_digest() {
        let material = prepare_material();
        let payload = material.encode().expect("material encodes");
        let header = header(V2Operation::PrepareConnectorMaterial, &material, &payload);
        let frame = encode_frame_v2(&header, &payload).expect("frame encodes");
        let parsed = read_frame_v2(&frame).expect("frame parses");
        assert_eq!(parsed.header, header);
        assert_eq!(
            parsed.material.expect("material is present").plan_json(),
            material.plan_json()
        );
    }

    #[test]
    fn rejects_trailing_payload_and_uppercase_digest() {
        let material = prepare_material();
        let payload = material.encode().expect("material encodes");
        let mut uppercase_header =
            header(V2Operation::PrepareConnectorMaterial, &material, &payload);
        uppercase_header.plan_sha256 = uppercase_header.plan_sha256.to_ascii_uppercase();
        assert!(matches!(
            encode_frame_v2(&uppercase_header, &payload),
            Err(V2CodecError::InvalidSha256)
        ));

        let mut mismatched_header =
            header(V2Operation::PrepareConnectorMaterial, &material, &payload);
        mismatched_header.payload_sha256 = digest_text(b"different-payload");
        assert!(matches!(
            encode_frame_v2(&mismatched_header, &payload),
            Err(V2CodecError::DigestMismatch)
        ));

        let mut trailing = payload.to_vec();
        trailing.push(0);
        let header = header(V2Operation::PrepareConnectorMaterial, &material, &trailing);
        let frame = encode_frame_v2(&header, &trailing).expect("frame encodes");
        assert!(matches!(
            read_frame_v2(&frame),
            Err(V2CodecError::InvalidMaterial)
        ));
    }

    #[test]
    fn finalize_envelope_contains_only_plan_and_handoff() {
        let material = BootstrapMaterialV1::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            br#"{"plan":"exact"}"#.to_vec(),
            br#"{"handoff":"exact"}"#.to_vec(),
        );
        let payload = material
            .encode_for(V2Operation::FinalizeConnectorMaterial)
            .expect("material encodes");
        let header = header(V2Operation::FinalizeConnectorMaterial, &material, &payload);
        let frame = encode_frame_v2(&header, &payload).expect("frame encodes");
        assert!(read_frame_v2(&frame).is_ok());
    }

    #[test]
    fn header_only_replay_is_a_codec_seam_not_material() {
        let material = prepare_material();
        let payload = material.encode().expect("material encodes");
        let mut header = header(V2Operation::PrepareConnectorMaterial, &material, &payload);
        header.payload_sha256 = digest_text(b"");
        let frame = encode_frame_v2(&header, b"").expect("header-only frame encodes");
        assert!(
            read_frame_v2(&frame)
                .expect("header accepted")
                .material
                .is_none()
        );
    }

    #[test]
    fn finalize_header_only_replay_preserves_original_lifecycle_digest() {
        let material = BootstrapMaterialV1::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            br#"{"plan":"exact"}"#.to_vec(),
            br#"{"handoff":"exact"}"#.to_vec(),
        );
        let payload = material
            .encode_for(V2Operation::FinalizeConnectorMaterial)
            .expect("material");
        let mut header = header(V2Operation::FinalizeConnectorMaterial, &material, &payload);
        header.lifecycle_material_sha256 = digest_text(b"original-prepare-material");
        header.payload_sha256 = digest_text(b"");
        let frame = encode_frame_v2(&header, b"").expect("header-only frame");
        let parsed = read_frame_v2(&frame).expect("header accepted");
        assert!(parsed.material.is_none());
        assert_eq!(
            parsed.header.lifecycle_material_sha256,
            digest_text(b"original-prepare-material")
        );
    }

    #[test]
    fn v2_response_success_is_exact_sanitized_allowlist() {
        let response = V2Response::succeeded(V2Result {
            operation: "finalize_connector_material",
            application: V2Application::Replayed,
            disposition: "applied",
            desired_revision: 9,
            observed_revision: Some(8),
            connector_id: "0197f1f0-0000-7000-8000-000000000003".into(),
            lifecycle_state: "finalized",
            prepared_receipt_sha256: Some("aa".repeat(32)),
            finalized_receipt_sha256: Some("bb".repeat(32)),
        });
        let value: serde_json::Value = serde_json::to_value(&response).expect("json");
        let object = value.as_object().expect("object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            ["protocol", "result", "status"]
                .into_iter()
                .collect::<Vec<_>>()
        );
        let result = object
            .get("result")
            .and_then(serde_json::Value::as_object)
            .expect("result");
        assert_eq!(
            result.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "application",
                "connector_id",
                "desired_revision",
                "disposition",
                "finalized_receipt_sha256",
                "lifecycle_state",
                "observed_revision",
                "operation",
                "prepared_receipt_sha256",
            ]
            .into_iter()
            .collect::<Vec<_>>()
        );
        let encoded = serde_json::to_string(&response).expect("encoded");
        for leaked in [
            "raw receipt",
            "credential",
            "bearer",
            "leaf_fingerprint",
            "pem",
            "path",
            "argv",
            "env",
            "service",
            "url",
            "diagnostic",
        ] {
            assert!(!encoded.contains(leaked), "leaked {leaked}");
        }
        assert!(!result.contains_key("material"));
        assert!(!result.contains_key("payload"));
        assert!(encoded.contains(&"aa".repeat(32)));
        assert!(encoded.contains(&"bb".repeat(32)));
    }

    #[test]
    fn v2_response_expired_omits_receipts_and_rejection_has_only_static_error() {
        let expired = V2Response::succeeded(V2Result {
            operation: "prepare_connector_material",
            application: V2Application::Applied,
            disposition: "expired_unclaimed",
            desired_revision: 1,
            observed_revision: None,
            connector_id: "0197f1f0-0000-7000-8000-000000000003".into(),
            lifecycle_state: "expired_unclaimed",
            prepared_receipt_sha256: None,
            finalized_receipt_sha256: None,
        });
        let expired_json = serde_json::to_value(&expired).expect("json");
        let result = expired_json
            .get("result")
            .and_then(serde_json::Value::as_object)
            .expect("result");
        assert!(!result.contains_key("prepared_receipt_sha256"));
        assert!(!result.contains_key("finalized_receipt_sha256"));
        assert!(!result.contains_key("observed_revision"));

        let rejected = V2Response::rejected("MATERIAL_REQUIRED");
        let rejected_json = serde_json::to_value(&rejected).expect("json");
        let rejected_object = rejected_json.as_object().expect("object");
        assert_eq!(
            rejected_object
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["error", "protocol", "status"]
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert_eq!(rejected_object["error"], "MATERIAL_REQUIRED");
    }

    #[test]
    fn prepare_lifecycle_digest_binds_nonempty_material() {
        let material = prepare_material();
        let payload = material.encode().expect("material encodes");
        let mut header = header(V2Operation::PrepareConnectorMaterial, &material, &payload);
        header.lifecycle_material_sha256 = digest_text(b"other");
        assert!(matches!(
            encode_frame_v2(&header, &payload),
            Err(V2CodecError::DigestMismatch)
        ));
    }

    #[test]
    fn header_duplicate_member_is_rejected_before_deserialization() {
        let material = prepare_material();
        let payload = material.encode().expect("material");
        let mut header = header(V2Operation::PrepareConnectorMaterial, &material, &payload);
        header.payload_sha256 = digest_text(b"");
        let encoded = serde_json::to_vec(&header).expect("header");
        let mut duplicate = encoded[..encoded.len() - 1].to_vec();
        duplicate.extend_from_slice(br#","protocol":"dirextalk.host-control.operator.v2"}"#);
        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC_V2);
        frame.extend_from_slice(&(u32::try_from(duplicate.len()).expect("length")).to_be_bytes());
        frame.extend_from_slice(&duplicate);
        frame.extend_from_slice(&0_u32.to_be_bytes());
        assert!(matches!(
            read_frame_v2(&frame),
            Err(V2CodecError::InvalidHeader)
        ));
    }
}
