use std::{error::Error, fmt};

use dtx_domain::{DeviceId, IdentityId, Revision, TenantId};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const MIN_TOKEN_BYTES: usize = 1;
pub const MAX_TOKEN_BYTES: usize = 4096;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provider {
    Fcm,
}

impl Provider {
    pub const fn as_str(self) -> &'static str {
        "fcm"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationState {
    Active,
    Suspended,
    Revoked,
}

impl RegistrationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
        }
    }
}

/// A bounded provider token. It deliberately has no `Debug`, `Display`, or serde implementation.
pub struct SecretToken(Zeroizing<Vec<u8>>);

impl SecretToken {
    pub fn new(value: Vec<u8>) -> Result<Self, PushError> {
        if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&value.len()) {
            return Err(PushError::TokenLength);
        }
        Ok(Self(Zeroizing::new(value)))
    }
    pub fn expose<T>(&self, f: impl FnOnce(&[u8]) -> T) -> T {
        f(self.0.as_slice())
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl Drop for SecretToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct RegistrationMutation {
    pub provider: Provider,
    pub token: SecretToken,
    pub expected_revision: u64,
}

impl RegistrationMutation {
    pub fn fcm(token: Vec<u8>, expected_revision: u64) -> Result<Self, PushError> {
        if expected_revision > Revision::MAX {
            return Err(PushError::RevisionOutOfRange);
        }
        Ok(Self {
            provider: Provider::Fcm,
            token: SecretToken::new(token)?,
            expected_revision,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedactedReceipt {
    pub version: u8,
    pub provider: &'static str,
    pub revision: u64,
    pub state: &'static str,
}

impl RedactedReceipt {
    pub fn new(revision: u64, state: RegistrationState) -> Result<Self, PushError> {
        if revision == 0 || revision > Revision::MAX {
            return Err(PushError::RevisionOutOfRange);
        }
        Ok(Self {
            version: 1,
            provider: "fcm",
            revision,
            state: state.as_str(),
        })
    }
    /// Encodes the exact V43 canonical-CBOR public replay representation.
    pub fn canonical_cbor(&self) -> Vec<u8> {
        let mut out = vec![0xa4, 0x01, 0x01, 0x02, 0x63];
        out.extend_from_slice(b"fcm");
        out.push(0x03);
        encode_uint(&mut out, self.revision);
        out.extend_from_slice(&[
            0x04,
            0x60 + u8::try_from(self.state.len()).expect("bounded state"),
        ]);
        out.extend_from_slice(self.state.as_bytes());
        out
    }

    /// Accepts only the exact canonical V43 receipt encoding: fixed map keys,
    /// definite lengths, minimally encoded revision, and no extra bytes.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, PushError> {
        if bytes.len() < 13 || bytes[..8] != [0xa4, 0x01, 0x01, 0x02, 0x63, b'f', b'c', b'm'] {
            return Err(PushError::ReceiptInvalid);
        }
        let mut offset = 8;
        if bytes.get(offset) != Some(&0x03) {
            return Err(PushError::ReceiptInvalid);
        }
        offset += 1;
        let revision = decode_minimal_uint(bytes, &mut offset)?;
        if bytes.get(offset) != Some(&0x04) {
            return Err(PushError::ReceiptInvalid);
        }
        offset += 1;
        let Some(&header) = bytes.get(offset) else {
            return Err(PushError::ReceiptInvalid);
        };
        offset += 1;
        if !(0x60..=0x77).contains(&header) {
            return Err(PushError::ReceiptInvalid);
        }
        let length = usize::from(header - 0x60);
        let state = match bytes.get(offset..offset + length) {
            Some(b"active") => RegistrationState::Active,
            Some(b"suspended") => RegistrationState::Suspended,
            Some(b"revoked") => RegistrationState::Revoked,
            _ => return Err(PushError::ReceiptInvalid),
        };
        offset += length;
        let receipt = Self::new(revision, state)?;
        if offset != bytes.len() || receipt.canonical_cbor() != bytes {
            return Err(PushError::ReceiptInvalid);
        }
        Ok(receipt)
    }
}

fn encode_uint(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=23 => out.push(u8::try_from(value).expect("small integer")),
        24..=0xff => {
            out.push(0x18);
            out.push(value as u8);
        }
        0x100..=0xffff => {
            out.push(0x19);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0x1a);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(0x1b);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn decode_minimal_uint(bytes: &[u8], offset: &mut usize) -> Result<u64, PushError> {
    let first = *bytes.get(*offset).ok_or(PushError::ReceiptInvalid)?;
    *offset += 1;
    let (value, minimum, width) = match first {
        0..=23 => return Ok(u64::from(first)),
        0x18 => (0, 24, 1),
        0x19 => (0, 0x100, 2),
        0x1a => (0, 0x1_0000, 4),
        0x1b => (0, 0x1_0000_0000, 8),
        _ => return Err(PushError::ReceiptInvalid),
    };
    let raw = bytes
        .get(*offset..*offset + width)
        .ok_or(PushError::ReceiptInvalid)?;
    *offset += width;
    let decoded = raw
        .iter()
        .fold(value, |acc, byte| (acc << 8) | u64::from(*byte));
    if decoded < minimum {
        return Err(PushError::ReceiptInvalid);
    }
    Ok(decoded)
}

#[derive(Clone, Eq, PartialEq)]
pub struct IdempotencyBinding {
    method: String,
    path: String,
    key: Vec<u8>,
    if_match_revision: u64,
    request_digest: [u8; 32],
}

impl fmt::Debug for IdempotencyBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdempotencyBinding")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("key_len", &self.key.len())
            .field("if_match_revision", &self.if_match_revision)
            .field("request_digest", &"[REDACTED]")
            .finish()
    }
}

impl IdempotencyBinding {
    pub fn new(
        method: impl Into<String>,
        path: impl Into<String>,
        key: Vec<u8>,
        if_match_revision: u64,
        request_bytes: &[u8],
    ) -> Result<Self, PushError> {
        let method = method.into();
        let path = path.into();
        if method.is_empty()
            || method.len() > 16
            || path.is_empty()
            || path.len() > 256
            || key.is_empty()
            || key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        {
            return Err(PushError::IdempotencyBinding);
        }
        if if_match_revision > Revision::MAX {
            return Err(PushError::RevisionOutOfRange);
        }
        let request_digest = Sha256::digest(request_bytes).into();
        Ok(Self {
            method,
            path,
            key,
            if_match_revision,
            request_digest,
        })
    }
    pub fn method(&self) -> &str {
        &self.method
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn key(&self) -> &[u8] {
        &self.key
    }
    pub const fn if_match_revision(&self) -> u64 {
        self.if_match_revision
    }
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Authenticated envelope binding. The tenant is always explicitly supplied by
/// the caller; broker deployments must use one stable tenant and persist this
/// same value through the envelope context.
pub struct RegistrationBinding {
    pub tenant_id: TenantId,
    pub identity_id: IdentityId,
    pub device_id: DeviceId,
    pub provider: Provider,
    pub revision: Revision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushError {
    TokenLength,
    RevisionOutOfRange,
    IdempotencyBinding,
    InvalidWakeDeliveryId,
    Encryption,
    Decryption,
    ContextMismatch,
    ProviderUnavailable,
    Persistence,
    Expired,
    LeaseLost,
    RegistrationRevoked,
    EnvelopeInvalid,
    ReceiptInvalid,
}
impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TokenLength => "token length is outside the allowed boundary",
            Self::RevisionOutOfRange => "revision is outside the allowed boundary",
            Self::IdempotencyBinding => "idempotency binding is invalid",
            Self::InvalidWakeDeliveryId => "wake delivery ID must be canonical UUIDv7",
            Self::Encryption => "token encryption failed",
            Self::Decryption => "token decryption failed",
            Self::ContextMismatch => "token encryption context mismatch",
            Self::ProviderUnavailable => "provider unavailable",
            Self::Persistence => "push persistence operation failed",
            Self::Expired => "push delivery expired",
            Self::LeaseLost => "push delivery lease lost",
            Self::RegistrationRevoked => "push registration is not active",
            Self::EnvelopeInvalid => "token envelope frame is invalid",
            Self::ReceiptInvalid => "push receipt encoding is invalid",
        })
    }
}
impl Error for PushError {}
