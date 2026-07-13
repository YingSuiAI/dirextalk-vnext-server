use dtx_agent_control::{
    ApplyConfigCommand, CloseStreamCommand, CloseStreamReason, CommandError, ConfigEntry,
    ExactCommandBytes, MAX_COMMAND_BYTES, RotateCredentialCommand, ServerCommandPayload,
    Sha256Digest, command_payload_digest,
};
use dtx_agent_control_proto::v1;
use dtx_agent_persistence::{
    DecodedDurableCommand, DurableCommandDecodeError, DurableCommandDecoder,
};
use dtx_connect_registry::ConnectorDesiredState;
use dtx_domain::{RequestId, Revision};
use prost::Message as _;

type DecodeResult<T> = Result<T, DurableCommandDecodeError>;

const DURABLE_COMMAND_RULES: &[FieldRule] = &[
    FieldRule::singular(1, WireType::Varint),
    FieldRule::singular(2, WireType::LengthDelimited),
    FieldRule::singular(3, WireType::Varint),
    FieldRule::singular(4, WireType::Varint),
    FieldRule::singular(5, WireType::LengthDelimited),
    FieldRule::singular(10, WireType::LengthDelimited),
    FieldRule::singular(11, WireType::LengthDelimited),
    FieldRule::singular(12, WireType::LengthDelimited),
];
const APPLY_CONFIG_RULES: &[FieldRule] = &[
    FieldRule::singular(1, WireType::Varint),
    FieldRule::singular(2, WireType::Varint),
    FieldRule::repeated(3, WireType::LengthDelimited),
    FieldRule::repeated(4, WireType::LengthDelimited),
];
const CONFIG_ENTRY_RULES: &[FieldRule] = &[
    FieldRule::singular(1, WireType::LengthDelimited),
    FieldRule::singular(2, WireType::LengthDelimited),
];
const ROTATE_CREDENTIAL_RULES: &[FieldRule] = &[
    FieldRule::singular(1, WireType::LengthDelimited),
    FieldRule::singular(2, WireType::Varint),
    FieldRule::singular(3, WireType::Varint),
];
const CLOSE_STREAM_RULES: &[FieldRule] = &[
    FieldRule::singular(1, WireType::Varint),
    FieldRule::singular(2, WireType::LengthDelimited),
    FieldRule::singular(3, WireType::LengthDelimited),
];

/// Canonical protobuf encoding needed by [`dtx_agent_control::CommandLog::append`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedDurableCommand {
    payload_digest: Sha256Digest,
    exact_bytes: ExactCommandBytes,
}

impl EncodedDurableCommand {
    #[must_use]
    pub const fn payload_digest(&self) -> Sha256Digest {
        self.payload_digest
    }

    #[must_use]
    pub const fn exact_bytes(&self) -> &ExactCommandBytes {
        &self.exact_bytes
    }

    #[must_use]
    pub fn into_exact_bytes(self) -> ExactCommandBytes {
        self.exact_bytes
    }
}

/// Canonical production encoder paired with [`ProtobufDurableCommandDecoder`].
#[derive(Clone, Copy, Debug, Default)]
pub struct ProtobufDurableCommandEncoder;

impl ProtobufDurableCommandEncoder {
    /// Encodes one already-validated typed payload into the frozen v1 protobuf envelope.
    ///
    /// # Errors
    ///
    /// Rejects invalid sequence/generation counters or an out-of-bounds exact encoding.
    pub fn encode(
        self,
        sequence: u64,
        operation_id: RequestId,
        generation: u64,
        spec_revision: Revision,
        payload: &ServerCommandPayload,
    ) -> Result<EncodedDurableCommand, CommandError> {
        Revision::new(sequence).map_err(|_| CommandError::InvalidSequence)?;
        Revision::new(generation).map_err(|_| CommandError::InvalidGeneration)?;
        let (command, exact_payload) = encode_payload(payload)?;
        let payload_digest = command_payload_digest(&exact_payload)?;
        let exact_bytes = ExactCommandBytes::new(
            v1::DurableCommand {
                command_sequence: sequence,
                operation_id: operation_id.to_string(),
                connector_generation: generation,
                spec_revision: spec_revision.get(),
                payload_digest: payload_digest.as_bytes().to_vec(),
                command: Some(command),
            }
            .encode_to_vec(),
        )?;
        Ok(EncodedDurableCommand {
            payload_digest,
            exact_bytes,
        })
    }
}

fn encode_payload(
    payload: &ServerCommandPayload,
) -> Result<(v1::durable_command::Command, Vec<u8>), CommandError> {
    match payload {
        ServerCommandPayload::ApplyConfig(command) => {
            let encoded = v1::ApplyConfig {
                config_revision: command.config_revision().get(),
                desired_state: encode_desired_state(command.desired_state()) as i32,
                adapter_config: encode_config_entries(command.adapter_config()),
                runtime_config: encode_config_entries(command.runtime_config()),
            };
            let exact = encoded.encode_to_vec();
            Ok((v1::durable_command::Command::ApplyConfig(encoded), exact))
        }
        ServerCommandPayload::RotateCredential(command) => {
            let deadline_millis = u64::try_from(command.deadline_millis())
                .map_err(|_| CommandError::InvalidCommandPayload)?;
            let encoded = v1::RotateCredential {
                rotation_nonce: command.nonce().to_vec(),
                successor_revision: command.successor_revision().get(),
                deadline_millis,
            };
            let exact = encoded.encode_to_vec();
            Ok((
                v1::durable_command::Command::RotateCredential(encoded),
                exact,
            ))
        }
        ServerCommandPayload::CloseStream(command) => {
            let encoded = v1::CloseStream {
                reason: encode_close_stream_reason(command.reason()) as i32,
                stable_code: command.stable_code().to_owned(),
                redacted_detail: command.redacted_detail().to_owned(),
            };
            let exact = encoded.encode_to_vec();
            Ok((v1::durable_command::Command::CloseStream(encoded), exact))
        }
    }
}

fn encode_config_entries(entries: &[ConfigEntry]) -> Vec<v1::ConfigEntry> {
    entries
        .iter()
        .map(|entry| v1::ConfigEntry {
            key: entry.key().to_owned(),
            value: entry.value().to_owned(),
        })
        .collect()
}

const fn encode_desired_state(value: ConnectorDesiredState) -> v1::DesiredConnectorState {
    match value {
        ConnectorDesiredState::Running => v1::DesiredConnectorState::Running,
        ConnectorDesiredState::Draining => v1::DesiredConnectorState::Draining,
        ConnectorDesiredState::Stopped => v1::DesiredConnectorState::Stopped,
        ConnectorDesiredState::Revoked => v1::DesiredConnectorState::Unspecified,
    }
}

const fn encode_close_stream_reason(value: CloseStreamReason) -> v1::CloseStreamReason {
    match value {
        CloseStreamReason::Reconnect => v1::CloseStreamReason::Reconnect,
        CloseStreamReason::Drained => v1::CloseStreamReason::Drained,
        CloseStreamReason::Revoked => v1::CloseStreamReason::Revoked,
        CloseStreamReason::ProtocolUpgrade => v1::CloseStreamReason::ProtocolUpgrade,
    }
}

/// Strict decoder for exact durable-command bytes stored by the control plane.
///
/// Prost supplies the typed view while the small wire scanner retains the
/// selected submessage verbatim for its digest and rejects encodings whose
/// duplicate or wrong-wire fields Prost would otherwise normalize away.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProtobufDurableCommandDecoder;

impl DurableCommandDecoder for ProtobufDurableCommandDecoder {
    fn decode(&self, exact_bytes: &[u8]) -> DecodeResult<DecodedDurableCommand> {
        if exact_bytes.is_empty() || exact_bytes.len() > MAX_COMMAND_BYTES {
            return Err(DurableCommandDecodeError);
        }
        let fields = validate_wire_schema(exact_bytes, DURABLE_COMMAND_RULES)?;
        let (payload_field, exact_payload) = selected_payload(&fields)?;
        let command =
            v1::DurableCommand::decode(exact_bytes).map_err(|_| DurableCommandDecodeError)?;

        Revision::new(command.command_sequence).map_err(|_| DurableCommandDecodeError)?;
        Revision::new(command.connector_generation).map_err(|_| DurableCommandDecodeError)?;
        let spec_revision =
            Revision::new(command.spec_revision).map_err(|_| DurableCommandDecodeError)?;
        let operation_id = command
            .operation_id
            .parse::<RequestId>()
            .map_err(|_| DurableCommandDecodeError)?;
        let stored_payload_digest = digest(command.payload_digest)?;
        let calculated_payload_digest =
            command_payload_digest(exact_payload).map_err(|_| DurableCommandDecodeError)?;
        if stored_payload_digest != calculated_payload_digest {
            return Err(DurableCommandDecodeError);
        }

        let payload = decode_payload(payload_field, command.command, exact_payload, spec_revision)?;
        Ok(DecodedDurableCommand {
            sequence: command.command_sequence,
            operation_id,
            generation: command.connector_generation,
            spec_revision,
            payload,
            payload_digest: stored_payload_digest,
        })
    }
}

fn decode_payload(
    payload_field: u32,
    command: Option<v1::durable_command::Command>,
    exact_payload: &[u8],
    spec_revision: Revision,
) -> DecodeResult<ServerCommandPayload> {
    match (payload_field, command) {
        (10, Some(v1::durable_command::Command::ApplyConfig(command))) => {
            validate_apply_config_wire(exact_payload)?;
            let config_revision =
                Revision::new(command.config_revision).map_err(|_| DurableCommandDecodeError)?;
            if spec_revision.checked_next() != Ok(config_revision) {
                return Err(DurableCommandDecodeError);
            }
            let desired_state = desired_state(command.desired_state)?;
            let adapter_config = config_entries(command.adapter_config)?;
            let runtime_config = config_entries(command.runtime_config)?;
            ApplyConfigCommand::new(
                config_revision,
                desired_state,
                adapter_config,
                runtime_config,
            )
            .map(ServerCommandPayload::ApplyConfig)
            .map_err(|_| DurableCommandDecodeError)
        }
        (11, Some(v1::durable_command::Command::RotateCredential(command))) => {
            validate_wire_schema(exact_payload, ROTATE_CREDENTIAL_RULES)?;
            let nonce: [u8; 32] = command
                .rotation_nonce
                .try_into()
                .map_err(|_| DurableCommandDecodeError)?;
            let successor_revision =
                Revision::new(command.successor_revision).map_err(|_| DurableCommandDecodeError)?;
            if spec_revision.checked_next() != Ok(successor_revision) {
                return Err(DurableCommandDecodeError);
            }
            let deadline_millis =
                i64::try_from(command.deadline_millis).map_err(|_| DurableCommandDecodeError)?;
            RotateCredentialCommand::new(nonce, successor_revision, deadline_millis)
                .map(ServerCommandPayload::RotateCredential)
                .map_err(|_| DurableCommandDecodeError)
        }
        (12, Some(v1::durable_command::Command::CloseStream(command))) => {
            validate_wire_schema(exact_payload, CLOSE_STREAM_RULES)?;
            CloseStreamCommand::new(
                close_stream_reason(command.reason)?,
                command.stable_code,
                command.redacted_detail,
            )
            .map(ServerCommandPayload::CloseStream)
            .map_err(|_| DurableCommandDecodeError)
        }
        _ => Err(DurableCommandDecodeError),
    }
}

fn validate_apply_config_wire(bytes: &[u8]) -> DecodeResult<()> {
    let fields = validate_wire_schema(bytes, APPLY_CONFIG_RULES)?;
    for field in fields {
        if matches!(field.number, 3 | 4) {
            validate_wire_schema(field.value, CONFIG_ENTRY_RULES)?;
        }
    }
    Ok(())
}

fn selected_payload<'a>(fields: &[WireField<'a>]) -> DecodeResult<(u32, &'a [u8])> {
    let mut selected = None;
    for field in fields {
        if matches!(field.number, 10..=12)
            && selected.replace((field.number, field.value)).is_some()
        {
            return Err(DurableCommandDecodeError);
        }
    }
    selected.ok_or(DurableCommandDecodeError)
}

fn config_entries(entries: Vec<v1::ConfigEntry>) -> DecodeResult<Vec<ConfigEntry>> {
    let entries = entries
        .into_iter()
        .map(|entry| {
            ConfigEntry::new(entry.key, entry.value).map_err(|_| DurableCommandDecodeError)
        })
        .collect::<DecodeResult<Vec<_>>>()?;
    if entries
        .windows(2)
        .any(|pair| pair[0].key() >= pair[1].key())
    {
        return Err(DurableCommandDecodeError);
    }
    Ok(entries)
}

fn desired_state(value: i32) -> DecodeResult<ConnectorDesiredState> {
    match v1::DesiredConnectorState::try_from(value).map_err(|_| DurableCommandDecodeError)? {
        v1::DesiredConnectorState::Running => Ok(ConnectorDesiredState::Running),
        v1::DesiredConnectorState::Draining => Ok(ConnectorDesiredState::Draining),
        v1::DesiredConnectorState::Stopped => Ok(ConnectorDesiredState::Stopped),
        v1::DesiredConnectorState::Unspecified => Err(DurableCommandDecodeError),
    }
}

fn close_stream_reason(value: i32) -> DecodeResult<CloseStreamReason> {
    match v1::CloseStreamReason::try_from(value).map_err(|_| DurableCommandDecodeError)? {
        v1::CloseStreamReason::Reconnect => Ok(CloseStreamReason::Reconnect),
        v1::CloseStreamReason::Drained => Ok(CloseStreamReason::Drained),
        v1::CloseStreamReason::Revoked => Ok(CloseStreamReason::Revoked),
        v1::CloseStreamReason::ProtocolUpgrade => Ok(CloseStreamReason::ProtocolUpgrade),
        v1::CloseStreamReason::Unspecified => Err(DurableCommandDecodeError),
    }
}

fn digest(bytes: Vec<u8>) -> DecodeResult<Sha256Digest> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| DurableCommandDecodeError)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

#[derive(Clone, Copy)]
struct FieldRule {
    number: u32,
    wire_type: WireType,
    repeated: bool,
}

impl FieldRule {
    const fn singular(number: u32, wire_type: WireType) -> Self {
        Self {
            number,
            wire_type,
            repeated: false,
        }
    }

    const fn repeated(number: u32, wire_type: WireType) -> Self {
        Self {
            number,
            wire_type,
            repeated: true,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WireType {
    Varint = 0,
    Fixed64 = 1,
    LengthDelimited = 2,
    Fixed32 = 5,
}

impl TryFrom<u8> for WireType {
    type Error = DurableCommandDecodeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Varint),
            1 => Ok(Self::Fixed64),
            2 => Ok(Self::LengthDelimited),
            5 => Ok(Self::Fixed32),
            _ => Err(DurableCommandDecodeError),
        }
    }
}

#[derive(Clone, Copy)]
struct WireField<'a> {
    number: u32,
    wire_type: WireType,
    value: &'a [u8],
}

fn validate_wire_schema<'a>(
    bytes: &'a [u8],
    rules: &[FieldRule],
) -> DecodeResult<Vec<WireField<'a>>> {
    let fields = scan_message(bytes)?;
    let mut counts = vec![0_usize; rules.len()];
    for field in &fields {
        let Some((index, rule)) = rules
            .iter()
            .enumerate()
            .find(|(_, rule)| rule.number == field.number)
        else {
            continue;
        };
        if field.wire_type != rule.wire_type || (!rule.repeated && counts[index] != 0) {
            return Err(DurableCommandDecodeError);
        }
        counts[index] += 1;
    }
    Ok(fields)
}

fn scan_message(bytes: &[u8]) -> DecodeResult<Vec<WireField<'_>>> {
    let mut fields = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let key = take_varint(bytes, &mut cursor)?;
        let number = u32::try_from(key >> 3).map_err(|_| DurableCommandDecodeError)?;
        if number == 0 || number > 0x1fff_ffff {
            return Err(DurableCommandDecodeError);
        }
        let wire_type = WireType::try_from((key & 7) as u8)?;
        let value = match wire_type {
            WireType::Varint => {
                let start = cursor;
                take_varint(bytes, &mut cursor)?;
                &bytes[start..cursor]
            }
            WireType::Fixed64 => take_bytes(bytes, &mut cursor, 8)?,
            WireType::LengthDelimited => {
                let length = usize::try_from(take_varint(bytes, &mut cursor)?)
                    .map_err(|_| DurableCommandDecodeError)?;
                take_bytes(bytes, &mut cursor, length)?
            }
            WireType::Fixed32 => take_bytes(bytes, &mut cursor, 4)?,
        };
        fields.push(WireField {
            number,
            wire_type,
            value,
        });
    }
    Ok(fields)
}

fn take_varint(bytes: &[u8], cursor: &mut usize) -> DecodeResult<u64> {
    let start = *cursor;
    let mut value = 0_u64;
    for index in 0..10 {
        let byte = *bytes.get(*cursor).ok_or(DurableCommandDecodeError)?;
        *cursor += 1;
        if index == 9 && byte > 1 {
            return Err(DurableCommandDecodeError);
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            if *cursor - start != encoded_varint_length(value) {
                return Err(DurableCommandDecodeError);
            }
            return Ok(value);
        }
    }
    Err(DurableCommandDecodeError)
}

fn encoded_varint_length(mut value: u64) -> usize {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

fn take_bytes<'a>(bytes: &'a [u8], cursor: &mut usize, length: usize) -> DecodeResult<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or(DurableCommandDecodeError)?;
    let value = &bytes[*cursor..end];
    *cursor = end;
    Ok(value)
}
