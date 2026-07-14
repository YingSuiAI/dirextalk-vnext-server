use std::{error::Error, fmt, str::FromStr};

use dtx_domain::{
    AgentDeviceId, AggregateId, ApprovalId, BindingId, BootId, CloudConnectionId, ConnectorId,
    ConsentId, ConversationId, DeviceId, DirectoryRegistrationId, EnvelopeId, EventId, HostId,
    IndexerId, InstallationId, JobEvidenceId, JobId, JobResourceId, JobStepId, KeyPackageId,
    LeaseId, MailboxId, ManagedServiceId, PublicSubjectId, RequestId, RunId, ServiceOperationId,
    TenantId, WorkerId,
};

use crate::{
    ApiErrorCode, BoundedString, CanonicalValue, SafeUint, Sha256Digest, StableCode, UtcMillis,
};

const MAX_LIST_ENTRIES: usize = 4096;

/// Decodes one typed value from the already validated deterministic CBOR model.
pub trait CanonicalDecode: Sized {
    /// Validates the declared field type and returns its typed representation.
    ///
    /// # Errors
    ///
    /// Returns [`CanonicalDecodeError`] when the value has the wrong shape or
    /// violates a primitive or collection bound.
    fn decode_canonical(value: &CanonicalValue) -> Result<Self, CanonicalDecodeError>;
}

/// A deterministic CBOR value did not match its typed wire contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalDecodeError {
    /// A generated payload was not an integer-keyed map with exactly its fields.
    InvalidMapFields,
    /// The CBOR major type did not match the declared field type.
    TypeMismatch,
    /// Text, bytes, IDs, timestamps, or another primitive failed validation.
    InvalidPrimitive,
    /// An unsigned integer exceeded its declared or cross-platform exact range.
    IntegerOutOfRange,
    /// A typed list exceeded its contract limit.
    ListTooLong,
    /// Decoding and generated re-encoding did not preserve the exact payload value.
    RoundTripMismatch,
}

impl fmt::Display for CanonicalDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidMapFields => "canonical payload fields do not match its schema",
            Self::TypeMismatch => "canonical payload field has the wrong CBOR type",
            Self::InvalidPrimitive => "canonical payload primitive is invalid",
            Self::IntegerOutOfRange => "canonical payload integer is outside its field range",
            Self::ListTooLong => "canonical payload list exceeds its field limit",
            Self::RoundTripMismatch => {
                "decoded payload does not round-trip to its exact canonical value"
            }
        })
    }
}

impl Error for CanonicalDecodeError {}

/// Validates a generated payload map with contiguous positive keys `1..=field_count`.
///
/// # Errors
///
/// Returns [`CanonicalDecodeError::InvalidMapFields`] for a non-map, a missing
/// field, an extra field, or a different key.
pub fn decode_struct_map(
    value: &CanonicalValue,
    field_count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], CanonicalDecodeError> {
    let CanonicalValue::Map(entries) = value else {
        return Err(CanonicalDecodeError::InvalidMapFields);
    };
    if entries.len() != field_count
        || entries.iter().enumerate().any(|(index, (key, _))| {
            u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_add(1))
                .is_none_or(|expected| key != &CanonicalValue::Unsigned(expected))
        })
    {
        Err(CanonicalDecodeError::InvalidMapFields)
    } else {
        Ok(entries)
    }
}

/// Decodes one generated payload field after [`decode_struct_map`] validation.
///
/// # Errors
///
/// Returns [`CanonicalDecodeError`] for an absent/different key or invalid value.
pub fn decode_struct_field<T>(
    entries: &[(CanonicalValue, CanonicalValue)],
    key: u64,
) -> Result<T, CanonicalDecodeError>
where
    T: CanonicalDecode,
{
    let index = key
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(CanonicalDecodeError::InvalidMapFields)?;
    let (actual_key, value) = entries
        .get(index)
        .ok_or(CanonicalDecodeError::InvalidMapFields)?;
    if actual_key != &CanonicalValue::Unsigned(key) {
        return Err(CanonicalDecodeError::InvalidMapFields);
    }
    T::decode_canonical(value)
}

fn decode_text<T>(value: &CanonicalValue) -> Result<T, CanonicalDecodeError>
where
    T: FromStr,
{
    let CanonicalValue::Text(value) = value else {
        return Err(CanonicalDecodeError::TypeMismatch);
    };
    value
        .parse()
        .map_err(|_| CanonicalDecodeError::InvalidPrimitive)
}

macro_rules! impl_text_decode {
    ($($type:ty),+ $(,)?) => {
        $(
            impl CanonicalDecode for $type {
                fn decode_canonical(
                    value: &CanonicalValue,
                ) -> Result<Self, CanonicalDecodeError> {
                    decode_text(value)
                }
            }
        )+
    };
}

impl_text_decode!(
    AgentDeviceId,
    AggregateId,
    ApprovalId,
    BindingId,
    BootId,
    CloudConnectionId,
    ConnectorId,
    ConsentId,
    ConversationId,
    DeviceId,
    DirectoryRegistrationId,
    EnvelopeId,
    EventId,
    HostId,
    IndexerId,
    InstallationId,
    JobEvidenceId,
    JobId,
    JobResourceId,
    JobStepId,
    KeyPackageId,
    LeaseId,
    MailboxId,
    ManagedServiceId,
    PublicSubjectId,
    RequestId,
    RunId,
    ServiceOperationId,
    TenantId,
    WorkerId,
    StableCode,
    BoundedString,
);

impl CanonicalDecode for ApiErrorCode {
    fn decode_canonical(value: &CanonicalValue) -> Result<Self, CanonicalDecodeError> {
        let CanonicalValue::Text(value) = value else {
            return Err(CanonicalDecodeError::TypeMismatch);
        };
        Self::parse(value).map_err(|_| CanonicalDecodeError::InvalidPrimitive)
    }
}

impl CanonicalDecode for SafeUint {
    fn decode_canonical(value: &CanonicalValue) -> Result<Self, CanonicalDecodeError> {
        let CanonicalValue::Unsigned(value) = value else {
            return Err(CanonicalDecodeError::TypeMismatch);
        };
        Self::new(*value).map_err(|_| CanonicalDecodeError::IntegerOutOfRange)
    }
}

impl CanonicalDecode for u32 {
    fn decode_canonical(value: &CanonicalValue) -> Result<Self, CanonicalDecodeError> {
        let CanonicalValue::Unsigned(value) = value else {
            return Err(CanonicalDecodeError::TypeMismatch);
        };
        Self::try_from(*value).map_err(|_| CanonicalDecodeError::IntegerOutOfRange)
    }
}

impl CanonicalDecode for bool {
    fn decode_canonical(value: &CanonicalValue) -> Result<Self, CanonicalDecodeError> {
        let CanonicalValue::Bool(value) = value else {
            return Err(CanonicalDecodeError::TypeMismatch);
        };
        Ok(*value)
    }
}

impl CanonicalDecode for Sha256Digest {
    fn decode_canonical(value: &CanonicalValue) -> Result<Self, CanonicalDecodeError> {
        let CanonicalValue::Bytes(bytes) = value else {
            return Err(CanonicalDecodeError::TypeMismatch);
        };
        let bytes = bytes
            .as_slice()
            .try_into()
            .map_err(|_| CanonicalDecodeError::InvalidPrimitive)?;
        Ok(Self::from_bytes(bytes))
    }
}

impl CanonicalDecode for UtcMillis {
    fn decode_canonical(value: &CanonicalValue) -> Result<Self, CanonicalDecodeError> {
        let value = match value {
            CanonicalValue::Unsigned(value) => {
                i64::try_from(*value).map_err(|_| CanonicalDecodeError::IntegerOutOfRange)?
            }
            CanonicalValue::Negative(value) => *value,
            _ => return Err(CanonicalDecodeError::TypeMismatch),
        };
        Self::new(value).map_err(|_| CanonicalDecodeError::InvalidPrimitive)
    }
}

impl<T> CanonicalDecode for Option<T>
where
    T: CanonicalDecode,
{
    fn decode_canonical(value: &CanonicalValue) -> Result<Self, CanonicalDecodeError> {
        if value == &CanonicalValue::Null {
            Ok(None)
        } else {
            T::decode_canonical(value).map(Some)
        }
    }
}

impl<T> CanonicalDecode for Vec<T>
where
    T: CanonicalDecode,
{
    fn decode_canonical(value: &CanonicalValue) -> Result<Self, CanonicalDecodeError> {
        let CanonicalValue::Array(values) = value else {
            return Err(CanonicalDecodeError::TypeMismatch);
        };
        if values.len() > MAX_LIST_ENTRIES {
            return Err(CanonicalDecodeError::ListTooLong);
        }
        values.iter().map(T::decode_canonical).collect()
    }
}
