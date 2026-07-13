use std::io::{self, Read, Write};

use dtx_domain::{ConnectorId, HostId, RequestId, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

pub const PROTOCOL: &str = "dirextalk.host-control.operator.v1";
const MAGIC: &[u8; 8] = b"DTXHC01\0";
const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const MAX_FRAME_BYTES: usize = MAGIC.len() + 4 + MAX_HEADER_BYTES + 4 + MAX_CREDENTIAL_BYTES;

pub struct RequestFrame {
    pub request: OperatorRequest,
    pub credential: Zeroizing<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRequest {
    pub protocol: String,
    pub tenant_id: TenantId,
    pub host_id: HostId,
    pub request: RequestBody,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RequestBody {
    Snapshot,
    Observe {
        connector_id: ConnectorId,
    },
    Execute {
        operation_id: RequestId,
        expected_desired_revision: u64,
        expected_observed_revision: Option<u64>,
        command: CommandWire,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandWire {
    Ensure {
        connector_id: ConnectorId,
        adapter_kind: AdapterWire,
        release_sha256: String,
    },
    Start {
        connector_id: ConnectorId,
    },
    Stop {
        connector_id: ConnectorId,
    },
    Restart {
        connector_id: ConnectorId,
    },
    RotateCredential {
        connector_id: ConnectorId,
        credential_sha256: String,
    },
    Remove {
        connector_id: ConnectorId,
    },
}

impl CommandWire {
    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        match self {
            Self::Ensure { connector_id, .. }
            | Self::Start { connector_id }
            | Self::Stop { connector_id }
            | Self::Restart { connector_id }
            | Self::RotateCredential { connector_id, .. }
            | Self::Remove { connector_id } => *connector_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterWire {
    Codex,
    OpenclawAcp,
    Eino,
    Rig,
    ClaudeCode,
    CustomAcp,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorResponse {
    protocol: &'static str,
    status: ResponseStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<OperatorResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<OperatorFailure>,
}

impl OperatorResponse {
    #[must_use]
    pub fn completed(result: OperatorResult) -> Self {
        Self {
            protocol: PROTOCOL,
            status: ResponseStatus::Succeeded,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub fn rejected(error: OperatorFailure) -> Self {
        Self {
            protocol: PROTOCOL,
            status: ResponseStatus::Rejected,
            result: None,
            error: Some(error),
        }
    }

    #[must_use]
    pub const fn succeeded(&self) -> bool {
        matches!(self.status, ResponseStatus::Succeeded)
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ResponseStatus {
    Succeeded,
    Rejected,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OperatorResult {
    Snapshot {
        host: HostProjection,
    },
    Observation {
        revision: RevisionProjection,
        connector: ConnectorProjection,
        actual_observation: &'static str,
    },
    Command {
        application: &'static str,
        disposition: &'static str,
        revision: RevisionProjection,
        connector: ConnectorProjection,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct HostProjection {
    pub tenant_id: TenantId,
    pub host_id: HostId,
    pub revision: RevisionProjection,
    pub connectors: Vec<ConnectorProjection>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct RevisionProjection {
    pub desired: u64,
    pub observed: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectorProjection {
    pub connector_id: ConnectorId,
    pub adapter_kind: &'static str,
    pub release_sha256: String,
    pub desired_state: &'static str,
    pub recorded_observation: &'static str,
    pub credential_generation: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct OperatorFailure {
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_revision: Option<RevisionProjection>,
}

impl OperatorFailure {
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self {
            code,
            current_revision: None,
        }
    }

    #[must_use]
    pub const fn at_revision(code: &'static str, current_revision: RevisionProjection) -> Self {
        Self {
            code,
            current_revision: Some(current_revision),
        }
    }
}

pub fn read_frame(mut reader: impl Read) -> Result<RequestFrame, OperatorFailure> {
    let mut input = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(u64::try_from(MAX_FRAME_BYTES + 1).expect("frame limit fits u64"))
        .read_to_end(&mut input)
        .map_err(|_| OperatorFailure::new("REQUEST_UNAVAILABLE"))?;
    if input.len() > MAX_FRAME_BYTES
        || input.len() < MAGIC.len() + 8
        || &input[..MAGIC.len()] != MAGIC
    {
        return Err(OperatorFailure::new("INVALID_FRAME"));
    }
    let header_length = read_u32(&input, MAGIC.len())?;
    if header_length == 0 || header_length > MAX_HEADER_BYTES {
        return Err(OperatorFailure::new("INVALID_FRAME"));
    }
    let header_start = MAGIC.len() + 4;
    let header_end = header_start
        .checked_add(header_length)
        .ok_or_else(|| OperatorFailure::new("INVALID_FRAME"))?;
    let payload_length_offset = header_end;
    let payload_start = payload_length_offset
        .checked_add(4)
        .ok_or_else(|| OperatorFailure::new("INVALID_FRAME"))?;
    let payload_length = read_u32(&input, payload_length_offset)?;
    if payload_length > MAX_CREDENTIAL_BYTES
        || payload_start.checked_add(payload_length) != Some(input.len())
    {
        return Err(OperatorFailure::new("INVALID_FRAME"));
    }
    let request: OperatorRequest = serde_json::from_slice(&input[header_start..header_end])
        .map_err(|_| OperatorFailure::new("INVALID_REQUEST"))?;
    if request.protocol != PROTOCOL {
        return Err(OperatorFailure::new("UNSUPPORTED_PROTOCOL"));
    }
    let credential = Zeroizing::new(input[payload_start..].to_vec());
    validate_payload(&request, &credential)?;
    Ok(RequestFrame {
        request,
        credential,
    })
}

pub fn encode_response(mut writer: impl Write, response: &OperatorResponse) -> io::Result<()> {
    serde_json::to_writer(&mut writer, response)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn validate_payload(request: &OperatorRequest, credential: &[u8]) -> Result<(), OperatorFailure> {
    match &request.request {
        RequestBody::Execute {
            command:
                CommandWire::RotateCredential {
                    credential_sha256, ..
                },
            ..
        } => {
            decode_sha256(credential_sha256)?;
            if !credential.is_empty() {
                let expected = decode_sha256(credential_sha256)?;
                let actual: [u8; 32] = Sha256::digest(credential).into();
                if actual != expected {
                    return Err(OperatorFailure::new("CREDENTIAL_DIGEST_MISMATCH"));
                }
            }
        }
        RequestBody::Snapshot | RequestBody::Observe { .. } | RequestBody::Execute { .. } => {
            if !credential.is_empty() {
                return Err(OperatorFailure::new("UNEXPECTED_CREDENTIAL_PAYLOAD"));
            }
        }
    }
    Ok(())
}

fn read_u32(input: &[u8], offset: usize) -> Result<usize, OperatorFailure> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| OperatorFailure::new("INVALID_FRAME"))?;
    let bytes: [u8; 4] = input
        .get(offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| OperatorFailure::new("INVALID_FRAME"))?;
    usize::try_from(u32::from_be_bytes(bytes)).map_err(|_| OperatorFailure::new("INVALID_FRAME"))
}

pub fn decode_sha256(value: &str) -> Result<[u8; 32], OperatorFailure> {
    if value.len() != 64 {
        return Err(OperatorFailure::new("INVALID_SHA256"));
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0]).ok_or_else(|| OperatorFailure::new("INVALID_SHA256"))?;
        let low = decode_nibble(pair[1]).ok_or_else(|| OperatorFailure::new("INVALID_SHA256"))?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

#[must_use]
pub fn encode_sha256(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "0197f1f0-0000-7000-8000-000000000001";
    const HOST: &str = "0197f1f0-0000-7000-8000-000000000002";
    const CONNECTOR: &str = "0197f1f0-0000-7000-8000-000000000003";
    const OPERATION: &str = "0197f1f0-0000-7000-8000-000000000004";

    #[test]
    fn accepts_bounded_snapshot_frame() {
        let request = request(RequestBody::Snapshot);
        let frame = frame(&request, &[]);
        let parsed = read_frame(frame.as_slice()).expect("snapshot frame parses");
        assert_eq!(parsed.request, request);
        assert!(parsed.credential.is_empty());
    }

    #[test]
    fn payload_is_rotate_only_and_digest_bound() {
        let connector_id = CONNECTOR.parse().expect("connector ID parses");
        let operation_id = OPERATION.parse().expect("operation ID parses");
        let start = request(RequestBody::Execute {
            operation_id,
            expected_desired_revision: 1,
            expected_observed_revision: None,
            command: CommandWire::Start { connector_id },
        });
        let Err(start_error) = read_frame(frame(&start, b"secret").as_slice()) else {
            panic!("start payload unexpectedly succeeded");
        };
        assert_eq!(start_error.code, "UNEXPECTED_CREDENTIAL_PAYLOAD");

        let rotate = request(RequestBody::Execute {
            operation_id,
            expected_desired_revision: 1,
            expected_observed_revision: None,
            command: CommandWire::RotateCredential {
                connector_id,
                credential_sha256: encode_sha256(Sha256::digest(b"other").into()),
            },
        });
        let Err(rotate_error) = read_frame(frame(&rotate, b"secret").as_slice()) else {
            panic!("mismatched credential unexpectedly succeeded");
        };
        assert_eq!(rotate_error.code, "CREDENTIAL_DIGEST_MISMATCH");
    }

    fn request(body: RequestBody) -> OperatorRequest {
        OperatorRequest {
            protocol: PROTOCOL.to_owned(),
            tenant_id: TENANT.parse().expect("tenant ID parses"),
            host_id: HOST.parse().expect("host ID parses"),
            request: body,
        }
    }

    fn frame(request: &OperatorRequest, payload: &[u8]) -> Vec<u8> {
        let header = serde_json::to_vec(request).expect("request serializes");
        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(
            &u32::try_from(header.len())
                .expect("header fits")
                .to_be_bytes(),
        );
        frame.extend_from_slice(&header);
        frame.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("payload fits")
                .to_be_bytes(),
        );
        frame.extend_from_slice(payload);
        frame
    }
}
