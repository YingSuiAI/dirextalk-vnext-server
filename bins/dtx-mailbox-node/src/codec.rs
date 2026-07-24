pub(crate) struct RegistrationRequest {
    pub(crate) mailbox_id: MailboxId,
    pub(crate) owner_identity_id: IdentityId,
    pub(crate) owner_device_id: DeviceId,
    pub(crate) write_capability_hash: Sha256Digest,
    pub(crate) expires_at: UtcMillis,
}

pub(crate) struct EnvelopeRequest {
    pub(crate) envelope_id: EnvelopeId,
    pub(crate) opaque_ciphertext: Vec<u8>,
    pub(crate) expires_at: UtcMillis,
}

pub(crate) struct AcknowledgementRequest {
    pub(crate) envelope_ids: Vec<EnvelopeId>,
}

pub(crate) fn parse_registration_request(
    bytes: &[u8],
) -> Result<RegistrationRequest, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 6)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    Ok(RegistrationRequest {
        mailbox_id: parse_cbor_mailbox_id(cbor_field(fields, 2)?)?,
        owner_identity_id: parse_cbor_identity_id(cbor_field(fields, 3)?)?,
        owner_device_id: parse_cbor_device_id(cbor_field(fields, 4)?)?,
        write_capability_hash: Sha256Digest::from_bytes(parse_cbor_bytes::<32>(cbor_field(
            fields, 5,
        )?)?),
        expires_at: parse_cbor_utc_millis(cbor_field(fields, 6)?)?,
    })
}

pub(crate) fn parse_envelope_request(bytes: &[u8]) -> Result<EnvelopeRequest, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 4)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    let opaque_ciphertext = match cbor_field(fields, 3)? {
        CanonicalValue::Bytes(value) if !value.is_empty() => value.clone(),
        _ => return Err(MailboxFailure::InvalidRequest),
    };
    Ok(EnvelopeRequest {
        envelope_id: parse_cbor_envelope_id(cbor_field(fields, 2)?)?,
        opaque_ciphertext,
        expires_at: parse_cbor_utc_millis(cbor_field(fields, 4)?)?,
    })
}

pub(crate) fn parse_pull_request(bytes: &[u8]) -> Result<MailboxPullRequest, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 3)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    let after_sequence = parse_cbor_safe_uint(cbor_field(fields, 2)?)?;
    let CanonicalValue::Unsigned(limit) = cbor_field(fields, 3)? else {
        return Err(MailboxFailure::InvalidRequest);
    };
    let limit = u16::try_from(*limit).map_err(|_| MailboxFailure::InvalidRequest)?;
    MailboxPullRequest::new(after_sequence, limit).map_err(|error| map_persistence_error(&error))
}

pub(crate) fn parse_acknowledgement_request(
    bytes: &[u8],
) -> Result<AcknowledgementRequest, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 2)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    let CanonicalValue::Array(values) = cbor_field(fields, 2)? else {
        return Err(MailboxFailure::InvalidRequest);
    };
    if values.is_empty() || values.len() > 100 {
        return Err(MailboxFailure::InvalidRequest);
    }
    let envelope_ids = values
        .iter()
        .map(parse_cbor_envelope_id)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AcknowledgementRequest { envelope_ids })
}

pub(crate) fn parse_identity_pull_v3_request(
    bytes: &[u8],
) -> Result<IdentityMailboxPullRequest, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 3)?;
    if cbor_field(fields, 1)? != &CanonicalValue::Unsigned(3) {
        return Err(MailboxFailure::InvalidRequest);
    }
    let after_sequence = parse_cbor_safe_uint(cbor_field(fields, 2)?)?;
    let CanonicalValue::Unsigned(limit) = cbor_field(fields, 3)? else {
        return Err(MailboxFailure::InvalidRequest);
    };
    IdentityMailboxPullRequest::new(
        after_sequence,
        u16::try_from(*limit).map_err(|_| MailboxFailure::InvalidRequest)?,
    )
    .map_err(|error| map_persistence_error(&error))
}

pub(crate) fn parse_identity_ack_v2_request(bytes: &[u8]) -> Result<SafeUint, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 2)?;
    require_cbor_version_v2(cbor_field(fields, 1)?)?;
    parse_cbor_safe_uint(cbor_field(fields, 2)?)
}

pub(crate) fn parse_device_history_grant(
    bytes: &[u8],
) -> Result<DeviceHistoryGrantCommand, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 12)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    let authorization = match cbor_field(fields, 7)? {
        CanonicalValue::Unsigned(1) => DeviceHistoryAuthorization::ActiveDevice,
        CanonicalValue::Unsigned(2) => DeviceHistoryAuthorization::RecoveryKey,
        CanonicalValue::Unsigned(3) => DeviceHistoryAuthorization::RootKey,
        _ => return Err(MailboxFailure::InvalidRequest),
    };
    let CanonicalValue::Text(authorizer_id) = cbor_field(fields, 8)? else {
        return Err(MailboxFailure::InvalidRequest);
    };
    let earliest = parse_cbor_safe_uint(cbor_field(fields, 5)?)?;
    DeviceHistoryGrantCommand::new(
        parse_cbor_identity_id(cbor_field(fields, 2)?)?,
        parse_cbor_device_id(cbor_field(fields, 3)?)?,
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 4)?)?),
        earliest.get(),
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 6)?)?),
        authorization,
        authorizer_id.clone(),
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 9)?)?),
        parse_cbor_utc_millis(cbor_field(fields, 10)?)?,
        Ed25519Signature::from_bytes(parse_cbor_bytes(cbor_field(fields, 11)?)?),
        Ed25519Signature::from_bytes(parse_cbor_bytes(cbor_field(fields, 12)?)?),
        bytes.to_vec(),
    )
    .map_err(|error| map_persistence_error(&error))
}

pub(crate) fn parse_device_history_grant_v2(
    bytes: &[u8],
    idempotency_key_hash: Sha256Digest,
) -> Result<DeviceHistoryGrantCommandV2, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 22)?;
    require_cbor_version_v2(cbor_field(fields, 1)?)?;
    let CanonicalValue::Text(request_id) = cbor_field(fields, 3)? else {
        return Err(MailboxFailure::InvalidRequest);
    };
    let authority = match cbor_field(fields, 8)? {
        CanonicalValue::Unsigned(1) => DeviceHistoryGrantAuthorityV2::ActiveDevice,
        CanonicalValue::Unsigned(2) => DeviceHistoryGrantAuthorityV2::RootKey,
        CanonicalValue::Unsigned(3) => DeviceHistoryGrantAuthorityV2::RecoveryKey,
        _ => return Err(MailboxFailure::InvalidRequest),
    };
    let CanonicalValue::Text(authority_id) = cbor_field(fields, 9)? else {
        return Err(MailboxFailure::InvalidRequest);
    };
    let CanonicalValue::Unsigned(highwater) = cbor_field(fields, 12)? else {
        return Err(MailboxFailure::InvalidRequest);
    };
    let CanonicalValue::Unsigned(earliest) = cbor_field(fields, 13)? else {
        return Err(MailboxFailure::InvalidRequest);
    };
    if *earliest != highwater.saturating_add(1)
        || Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 19)?)?)
            != idempotency_key_hash
    {
        return Err(MailboxFailure::InvalidRequest);
    }
    let CanonicalValue::Bytes(opaque_offer) = cbor_field(fields, 22)? else {
        return Err(MailboxFailure::InvalidRequest);
    };
    DeviceHistoryGrantCommandV2::new(
        idempotency_key_hash,
        parse_cbor_identity_id(cbor_field(fields, 2)?)?,
        request_id
            .parse::<DeviceEnrollmentChallengeId>()
            .map_err(|_| MailboxFailure::InvalidRequest)?,
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 4)?)?),
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 5)?)?),
        parse_cbor_device_id(cbor_field(fields, 6)?)?,
        parse_cbor_device_id(cbor_field(fields, 7)?)?,
        authority,
        authority_id.clone(),
        parse_cbor_mailbox_id(cbor_field(fields, 10)?)?,
        parse_cbor_envelope_id(cbor_field(fields, 11)?)?,
        *highwater,
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 14)?)?),
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 15)?)?),
        opaque_offer.clone(),
        parse_cbor_utc_millis(cbor_field(fields, 17)?)?,
        parse_cbor_utc_millis(cbor_field(fields, 18)?)?,
        Ed25519Signature::from_bytes(parse_cbor_bytes(cbor_field(fields, 20)?)?),
        Ed25519Signature::from_bytes(parse_cbor_bytes(cbor_field(fields, 21)?)?),
        bytes.to_vec(),
    )
    .map_err(|error| map_persistence_error(&error))
}

pub(crate) fn parse_account_read_cursor_write(
    bytes: &[u8],
    idempotency_key_hash: Sha256Digest,
) -> Result<AccountReadCursorWriteCommand, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 6)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    AccountReadCursorWriteCommand::new(
        idempotency_key_hash,
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 2)?)?),
        parse_cbor_safe_uint(cbor_field(fields, 3)?)?,
        parse_cbor_safe_uint(cbor_field(fields, 4)?)?,
        match cbor_field(fields, 5)? {
            CanonicalValue::Bytes(bytes) => bytes.clone(),
            _ => return Err(MailboxFailure::InvalidRequest),
        },
        Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(fields, 6)?)?),
        bytes.to_vec(),
    )
    .map_err(|error| map_persistence_error(&error))
}

pub(crate) fn parse_account_read_cursor_query(
    bytes: &[u8],
) -> Result<Sha256Digest, MailboxFailure> {
    let value = decode_deterministic_cbor(bytes).map_err(|_| MailboxFailure::InvalidRequest)?;
    let fields = exact_cbor_fields(&value, 2)?;
    require_cbor_version(cbor_field(fields, 1)?)?;
    Ok(Sha256Digest::from_bytes(parse_cbor_bytes(cbor_field(
        fields, 2,
    )?)?))
}

pub(crate) fn exact_cbor_fields(
    value: &CanonicalValue,
    expected_count: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], MailboxFailure> {
    let CanonicalValue::Map(fields) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    if fields.len() != expected_count
        || fields.iter().enumerate().any(|(index, (key, _))| {
            key != &CanonicalValue::Unsigned(u64::try_from(index + 1).unwrap_or(u64::MAX))
        })
    {
        Err(MailboxFailure::InvalidRequest)
    } else {
        Ok(fields)
    }
}

pub(crate) fn cbor_field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: usize,
) -> Result<&CanonicalValue, MailboxFailure> {
    fields
        .get(key.checked_sub(1).ok_or(MailboxFailure::InvalidRequest)?)
        .map(|(_, value)| value)
        .ok_or(MailboxFailure::InvalidRequest)
}

pub(crate) fn require_cbor_version(value: &CanonicalValue) -> Result<(), MailboxFailure> {
    if value == &CanonicalValue::Unsigned(1) {
        Ok(())
    } else {
        Err(MailboxFailure::InvalidRequest)
    }
}

pub(crate) fn require_cbor_version_v2(value: &CanonicalValue) -> Result<(), MailboxFailure> {
    if value == &CanonicalValue::Unsigned(2) {
        Ok(())
    } else {
        Err(MailboxFailure::InvalidRequest)
    }
}

pub(crate) fn parse_cbor_mailbox_id(value: &CanonicalValue) -> Result<MailboxId, MailboxFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}

pub(crate) fn parse_cbor_envelope_id(value: &CanonicalValue) -> Result<EnvelopeId, MailboxFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}

pub(crate) fn parse_cbor_identity_id(value: &CanonicalValue) -> Result<IdentityId, MailboxFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}

pub(crate) fn parse_cbor_device_id(value: &CanonicalValue) -> Result<DeviceId, MailboxFailure> {
    let CanonicalValue::Text(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}

pub(crate) fn parse_cbor_bytes<const N: usize>(
    value: &CanonicalValue,
) -> Result<[u8; N], MailboxFailure> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    value
        .as_slice()
        .try_into()
        .map_err(|_| MailboxFailure::InvalidRequest)
}

pub(crate) fn parse_cbor_safe_uint(value: &CanonicalValue) -> Result<SafeUint, MailboxFailure> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(MailboxFailure::InvalidRequest);
    };
    SafeUint::new(*value).map_err(|_| MailboxFailure::InvalidRequest)
}

pub(crate) fn parse_cbor_utc_millis(value: &CanonicalValue) -> Result<UtcMillis, MailboxFailure> {
    let value = match value {
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| MailboxFailure::InvalidRequest)?
        }
        CanonicalValue::Negative(value) => *value,
        _ => return Err(MailboxFailure::InvalidRequest),
    };
    UtcMillis::new(value).map_err(|_| MailboxFailure::InvalidRequest)
}

pub(crate) fn parse_mailbox_id(value: &str) -> Result<MailboxId, MailboxFailure> {
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}

pub(crate) fn parse_envelope_id(value: &str) -> Result<EnvelopeId, MailboxFailure> {
    value.parse().map_err(|_| MailboxFailure::InvalidRequest)
}
use dtx_domain::{DeviceEnrollmentChallengeId, DeviceId, EnvelopeId, IdentityId, MailboxId};
use dtx_mailbox::{
    AccountReadCursorWriteCommand, DeviceHistoryAuthorization, DeviceHistoryGrantAuthorityV2,
    DeviceHistoryGrantCommand, DeviceHistoryGrantCommandV2, IdentityMailboxPullRequest,
    MailboxPullRequest,
};
use dtx_wire::{
    CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, UtcMillis, decode_deterministic_cbor,
};

use super::errors::{MailboxFailure, map_persistence_error};
