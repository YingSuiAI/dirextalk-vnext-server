use crate::ContactError;
use dtx_domain::{
    ConversationId, DeviceId, EnvelopeId, IdentityId, InviteCapabilityId, KeyPackageId, RequestId,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};

const ENVELOPE_PREFIX_V1: &[u8] = b"DTXPA1\0";
const OFFER_SIGNATURE_DOMAIN_V1: &[u8] = b"dirextalk.peer-admission-offer-signature.v1\0";
const WELCOME_SIGNATURE_DOMAIN_V1: &[u8] = b"dirextalk.peer-admission-welcome-signature.v1\0";

/// Domain-separated HPKE `info` used by clients for both peer-admission artifacts.
pub const PEER_ADMISSION_HPKE_INFO_V1: &[u8] = b"dirextalk.peer-admission-hpke.v1\0";
/// Maximum exact encoded offer plaintext accepted by a V1 client.
pub const MAX_PEER_ADMISSION_OFFER_BYTES: usize = 16 * 1024;
/// Maximum exact encoded welcome plaintext accepted by a V1 client.
pub const MAX_PEER_ADMISSION_WELCOME_BYTES: usize = 240 * 1024;
/// Maximum combined receipt, commit, and MLS Welcome bytes.
pub const MAX_PEER_ADMISSION_WELCOME_BLOBS_BYTES: usize = 240 * 1024;
/// Maximum prefixed opaque mailbox capsule accepted by a V1 client or relay.
pub const MAX_PEER_ADMISSION_ENVELOPE_BYTES: usize = 256 * 1024;
/// Maximum opaque HPKE payload permitted by the frozen envelope CDDL.
pub const MAX_PEER_ADMISSION_SEALED_BYTES: usize = 262_016;
/// Maximum validity interval of an offer or welcome.
pub const MAX_PEER_ADMISSION_LIFETIME_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
/// Clock skew tolerated when deciding whether a signed plaintext is currently usable.
pub const PEER_ADMISSION_CLOCK_SKEW_MS: i64 = 5 * 60 * 1_000;

/// Opaque, prefixed capsule stored and relayed by mailbox infrastructure.
///
/// The server intentionally has no API that exposes or decrypts `sealed`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAdmissionEnvelopeV1 {
    envelope_id: EnvelopeId,
    sealed: Vec<u8>,
}

impl PeerAdmissionEnvelopeV1 {
    pub fn new(envelope_id: EnvelopeId, sealed: Vec<u8>) -> Result<Self, ContactError> {
        let value = Self {
            envelope_id,
            sealed,
        };
        if value.sealed.is_empty()
            || value.sealed.len() > MAX_PEER_ADMISSION_SEALED_BYTES
            || value.encode()?.len() > MAX_PEER_ADMISSION_ENVELOPE_BYTES
        {
            return Err(ContactError::Invalid);
        }
        Ok(value)
    }

    pub fn decode(exact: &[u8]) -> Result<Self, ContactError> {
        if exact.len() > MAX_PEER_ADMISSION_ENVELOPE_BYTES || !exact.starts_with(ENVELOPE_PREFIX_V1)
        {
            return Err(ContactError::Invalid);
        }
        let value = decode_deterministic_cbor(&exact[ENVELOPE_PREFIX_V1.len()..])
            .map_err(|_| ContactError::Invalid)?;
        let fields = exact_map(&value, 3)?;
        require_unsigned(field(fields, 1)?, 1)?;
        let envelope = Self {
            envelope_id: id(field(fields, 2)?)?,
            sealed: bounded_bytes(field(fields, 3)?, MAX_PEER_ADMISSION_SEALED_BYTES)?,
        };
        if envelope.encode()? != exact {
            return Err(ContactError::Invalid);
        }
        Ok(envelope)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ContactError> {
        let encoded = encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (u(1), u(1)),
            (u(2), CanonicalValue::Text(self.envelope_id.to_string())),
            (u(3), CanonicalValue::Bytes(self.sealed.clone())),
        ]))
        .map_err(|_| ContactError::Invalid)?;
        let mut exact = Vec::with_capacity(ENVELOPE_PREFIX_V1.len() + encoded.len());
        exact.extend_from_slice(ENVELOPE_PREFIX_V1);
        exact.extend_from_slice(&encoded);
        if self.sealed.is_empty()
            || self.sealed.len() > MAX_PEER_ADMISSION_SEALED_BYTES
            || exact.len() > MAX_PEER_ADMISSION_ENVELOPE_BYTES
        {
            return Err(ContactError::Invalid);
        }
        Ok(exact)
    }

    /// Exact deterministic CBOR authenticated as HPKE AAD.
    pub fn aad(&self) -> Result<Vec<u8>, ContactError> {
        encode_deterministic_cbor(&CanonicalValue::Map(vec![
            (u(1), u(1)),
            (u(2), CanonicalValue::Text(self.envelope_id.to_string())),
        ]))
        .map_err(|_| ContactError::Invalid)
    }

    #[must_use]
    pub const fn envelope_id(&self) -> EnvelopeId {
        self.envelope_id
    }

    #[must_use]
    pub fn sealed(&self) -> &[u8] {
        &self.sealed
    }
}

/// Signed fields 1 through 20 of a V1 peer-admission offer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAdmissionOfferUnsignedV1 {
    pub admission_id: RequestId,
    pub contact_request_id: RequestId,
    pub conversation_id: ConversationId,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub owner_origin: String,
    pub peer_identity_id: IdentityId,
    pub peer_device_id: DeviceId,
    pub group_origin: String,
    pub sequencer_signing_key: SigningPublicKey,
    pub invite_id: InviteCapabilityId,
    pub policy_revision: SafeUint,
    pub epoch: SafeUint,
    pub head_digest: Sha256Digest,
    pub candidate_key_package_id: KeyPackageId,
    pub candidate_key_package_digest: Sha256Digest,
    pub issued_at: UtcMillis,
    pub expires_at: UtcMillis,
}

/// Client-decrypted offer that binds the contact request to one MLS `KeyPackage`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAdmissionOfferV1 {
    unsigned: PeerAdmissionOfferUnsignedV1,
    signature: Ed25519Signature,
}

impl PeerAdmissionOfferV1 {
    pub fn new(
        unsigned: PeerAdmissionOfferUnsignedV1,
        signature: Ed25519Signature,
    ) -> Result<Self, ContactError> {
        validate_offer(&unsigned)?;
        let value = Self {
            unsigned,
            signature,
        };
        if value.encode()?.len() > MAX_PEER_ADMISSION_OFFER_BYTES {
            return Err(ContactError::Invalid);
        }
        Ok(value)
    }

    pub fn decode(exact: &[u8]) -> Result<Self, ContactError> {
        if exact.len() > MAX_PEER_ADMISSION_OFFER_BYTES {
            return Err(ContactError::Invalid);
        }
        let value = decode_deterministic_cbor(exact).map_err(|_| ContactError::Invalid)?;
        let fields = exact_map(&value, 21)?;
        require_unsigned(field(fields, 1)?, 1)?;
        require_unsigned(field(fields, 2)?, 1)?;
        let unsigned = PeerAdmissionOfferUnsignedV1 {
            admission_id: id(field(fields, 3)?)?,
            contact_request_id: id(field(fields, 4)?)?,
            conversation_id: id(field(fields, 5)?)?,
            owner_identity_id: identity(field(fields, 6)?)?,
            owner_device_id: id(field(fields, 7)?)?,
            owner_origin: origin(field(fields, 8)?)?,
            peer_identity_id: identity(field(fields, 9)?)?,
            peer_device_id: id(field(fields, 10)?)?,
            group_origin: origin(field(fields, 11)?)?,
            sequencer_signing_key: signing_key(field(fields, 12)?)?,
            invite_id: id(field(fields, 13)?)?,
            policy_revision: safe_uint(field(fields, 14)?)?,
            epoch: safe_uint(field(fields, 15)?)?,
            head_digest: digest(field(fields, 16)?)?,
            candidate_key_package_id: id(field(fields, 17)?)?,
            candidate_key_package_digest: digest(field(fields, 18)?)?,
            issued_at: millis(field(fields, 19)?)?,
            expires_at: millis(field(fields, 20)?)?,
        };
        let offer = Self::new(unsigned, signature(field(fields, 21)?)?)?;
        if offer.encode()? != exact {
            return Err(ContactError::Invalid);
        }
        Ok(offer)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ContactError> {
        validate_offer(&self.unsigned)?;
        encode_deterministic_cbor(self).map_err(|_| ContactError::Invalid)
    }

    pub fn signature_input(&self) -> Result<Vec<u8>, ContactError> {
        signature_input(OFFER_SIGNATURE_DOMAIN_V1, &self.unsigned_value())
    }

    pub fn verify_owner_signature(
        &self,
        owner_signing_key: SigningPublicKey,
    ) -> Result<(), ContactError> {
        verify_signature(owner_signing_key, self.signature, &self.signature_input()?)
    }

    #[must_use]
    pub fn is_usable_at(&self, now: UtcMillis) -> bool {
        usable_at(self.unsigned.issued_at, self.unsigned.expires_at, now)
    }

    #[must_use]
    pub const fn unsigned(&self) -> &PeerAdmissionOfferUnsignedV1 {
        &self.unsigned
    }

    #[must_use]
    pub const fn signature(&self) -> Ed25519Signature {
        self.signature
    }

    fn unsigned_value(&self) -> CanonicalValue {
        CanonicalValue::Map(offer_fields(&self.unsigned))
    }
}

impl CanonicalEncode for PeerAdmissionOfferV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        let mut fields = offer_fields(&self.unsigned);
        fields.push((u(21), self.signature.to_canonical_value()));
        CanonicalValue::Map(fields)
    }
}

/// Signed fields 1 through 19 of a V1 peer-admission welcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAdmissionWelcomeUnsignedV1 {
    pub admission_id: RequestId,
    pub conversation_id: ConversationId,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub peer_identity_id: IdentityId,
    pub peer_device_id: DeviceId,
    pub group_origin: String,
    pub sequencer_signing_key: SigningPublicKey,
    pub submission_id: RequestId,
    pub approval_command_id: RequestId,
    pub join_request_digest: Sha256Digest,
    pub candidate_key_package_digest: Sha256Digest,
    pub exact_v3_receipt: Vec<u8>,
    pub exact_mls_commit: Vec<u8>,
    pub exact_mls_welcome: Vec<u8>,
    pub issued_at: UtcMillis,
    pub expires_at: UtcMillis,
}

/// Client-decrypted acceptance artifact carrying exact V3 Sequencer and MLS bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAdmissionWelcomeV1 {
    unsigned: PeerAdmissionWelcomeUnsignedV1,
    signature: Ed25519Signature,
}

impl PeerAdmissionWelcomeV1 {
    pub fn new(
        unsigned: PeerAdmissionWelcomeUnsignedV1,
        signature: Ed25519Signature,
    ) -> Result<Self, ContactError> {
        validate_welcome(&unsigned)?;
        let value = Self {
            unsigned,
            signature,
        };
        if value.encode()?.len() > MAX_PEER_ADMISSION_WELCOME_BYTES {
            return Err(ContactError::Invalid);
        }
        Ok(value)
    }

    pub fn decode(exact: &[u8]) -> Result<Self, ContactError> {
        if exact.len() > MAX_PEER_ADMISSION_WELCOME_BYTES {
            return Err(ContactError::Invalid);
        }
        let value = decode_deterministic_cbor(exact).map_err(|_| ContactError::Invalid)?;
        let fields = exact_map(&value, 20)?;
        require_unsigned(field(fields, 1)?, 1)?;
        require_unsigned(field(fields, 2)?, 2)?;
        let unsigned = PeerAdmissionWelcomeUnsignedV1 {
            admission_id: id(field(fields, 3)?)?,
            conversation_id: id(field(fields, 4)?)?,
            owner_identity_id: identity(field(fields, 5)?)?,
            owner_device_id: id(field(fields, 6)?)?,
            peer_identity_id: identity(field(fields, 7)?)?,
            peer_device_id: id(field(fields, 8)?)?,
            group_origin: origin(field(fields, 9)?)?,
            sequencer_signing_key: signing_key(field(fields, 10)?)?,
            submission_id: id(field(fields, 11)?)?,
            approval_command_id: id(field(fields, 12)?)?,
            join_request_digest: digest(field(fields, 13)?)?,
            candidate_key_package_digest: digest(field(fields, 14)?)?,
            exact_v3_receipt: bounded_bytes(
                field(fields, 15)?,
                MAX_PEER_ADMISSION_WELCOME_BLOBS_BYTES,
            )?,
            exact_mls_commit: bounded_bytes(
                field(fields, 16)?,
                MAX_PEER_ADMISSION_WELCOME_BLOBS_BYTES,
            )?,
            exact_mls_welcome: bounded_bytes(
                field(fields, 17)?,
                MAX_PEER_ADMISSION_WELCOME_BLOBS_BYTES,
            )?,
            issued_at: millis(field(fields, 18)?)?,
            expires_at: millis(field(fields, 19)?)?,
        };
        let welcome = Self::new(unsigned, signature(field(fields, 20)?)?)?;
        if welcome.encode()? != exact {
            return Err(ContactError::Invalid);
        }
        Ok(welcome)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ContactError> {
        validate_welcome(&self.unsigned)?;
        encode_deterministic_cbor(self).map_err(|_| ContactError::Invalid)
    }

    pub fn signature_input(&self) -> Result<Vec<u8>, ContactError> {
        signature_input(WELCOME_SIGNATURE_DOMAIN_V1, &self.unsigned_value())
    }

    pub fn verify_owner_signature(
        &self,
        owner_signing_key: SigningPublicKey,
    ) -> Result<(), ContactError> {
        verify_signature(owner_signing_key, self.signature, &self.signature_input()?)
    }

    #[must_use]
    pub fn is_usable_at(&self, now: UtcMillis) -> bool {
        usable_at(self.unsigned.issued_at, self.unsigned.expires_at, now)
    }

    #[must_use]
    pub const fn unsigned(&self) -> &PeerAdmissionWelcomeUnsignedV1 {
        &self.unsigned
    }

    #[must_use]
    pub const fn signature(&self) -> Ed25519Signature {
        self.signature
    }

    fn unsigned_value(&self) -> CanonicalValue {
        CanonicalValue::Map(welcome_fields(&self.unsigned))
    }
}

impl CanonicalEncode for PeerAdmissionWelcomeV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        let mut fields = welcome_fields(&self.unsigned);
        fields.push((u(20), self.signature.to_canonical_value()));
        CanonicalValue::Map(fields)
    }
}

fn offer_fields(value: &PeerAdmissionOfferUnsignedV1) -> Vec<(CanonicalValue, CanonicalValue)> {
    vec![
        (u(1), u(1)),
        (u(2), u(1)),
        (u(3), text_id(&value.admission_id)),
        (u(4), text_id(&value.contact_request_id)),
        (u(5), text_id(&value.conversation_id)),
        (u(6), text_id(&value.owner_identity_id)),
        (u(7), text_id(&value.owner_device_id)),
        (u(8), CanonicalValue::Text(value.owner_origin.clone())),
        (u(9), text_id(&value.peer_identity_id)),
        (u(10), text_id(&value.peer_device_id)),
        (u(11), CanonicalValue::Text(value.group_origin.clone())),
        (u(12), value.sequencer_signing_key.to_canonical_value()),
        (u(13), text_id(&value.invite_id)),
        (u(14), value.policy_revision.to_canonical_value()),
        (u(15), value.epoch.to_canonical_value()),
        (u(16), value.head_digest.to_canonical_value()),
        (u(17), text_id(&value.candidate_key_package_id)),
        (
            u(18),
            value.candidate_key_package_digest.to_canonical_value(),
        ),
        (u(19), value.issued_at.to_canonical_value()),
        (u(20), value.expires_at.to_canonical_value()),
    ]
}

fn welcome_fields(value: &PeerAdmissionWelcomeUnsignedV1) -> Vec<(CanonicalValue, CanonicalValue)> {
    vec![
        (u(1), u(1)),
        (u(2), u(2)),
        (u(3), text_id(&value.admission_id)),
        (u(4), text_id(&value.conversation_id)),
        (u(5), text_id(&value.owner_identity_id)),
        (u(6), text_id(&value.owner_device_id)),
        (u(7), text_id(&value.peer_identity_id)),
        (u(8), text_id(&value.peer_device_id)),
        (u(9), CanonicalValue::Text(value.group_origin.clone())),
        (u(10), value.sequencer_signing_key.to_canonical_value()),
        (u(11), text_id(&value.submission_id)),
        (u(12), text_id(&value.approval_command_id)),
        (u(13), value.join_request_digest.to_canonical_value()),
        (
            u(14),
            value.candidate_key_package_digest.to_canonical_value(),
        ),
        (u(15), CanonicalValue::Bytes(value.exact_v3_receipt.clone())),
        (u(16), CanonicalValue::Bytes(value.exact_mls_commit.clone())),
        (
            u(17),
            CanonicalValue::Bytes(value.exact_mls_welcome.clone()),
        ),
        (u(18), value.issued_at.to_canonical_value()),
        (u(19), value.expires_at.to_canonical_value()),
    ]
}

fn validate_offer(value: &PeerAdmissionOfferUnsignedV1) -> Result<(), ContactError> {
    if !valid_origin(&value.owner_origin)
        || !valid_origin(&value.group_origin)
        || value.policy_revision.get() == 0
        || value.owner_identity_id == value.peer_identity_id
    {
        return Err(ContactError::Invalid);
    }
    validate_lifetime(value.issued_at, value.expires_at)
}

fn validate_welcome(value: &PeerAdmissionWelcomeUnsignedV1) -> Result<(), ContactError> {
    let combined = value
        .exact_v3_receipt
        .len()
        .checked_add(value.exact_mls_commit.len())
        .and_then(|size| size.checked_add(value.exact_mls_welcome.len()))
        .ok_or(ContactError::Invalid)?;
    if !valid_origin(&value.group_origin)
        || value.owner_identity_id == value.peer_identity_id
        || value.exact_v3_receipt.is_empty()
        || value.exact_mls_commit.is_empty()
        || value.exact_mls_welcome.is_empty()
        || combined > MAX_PEER_ADMISSION_WELCOME_BLOBS_BYTES
    {
        return Err(ContactError::Invalid);
    }
    validate_lifetime(value.issued_at, value.expires_at)
}

fn validate_lifetime(issued_at: UtcMillis, expires_at: UtcMillis) -> Result<(), ContactError> {
    let lifetime = expires_at
        .get()
        .checked_sub(issued_at.get())
        .ok_or(ContactError::Invalid)?;
    if lifetime <= 0 || lifetime > MAX_PEER_ADMISSION_LIFETIME_MS {
        Err(ContactError::Invalid)
    } else {
        Ok(())
    }
}

fn usable_at(issued_at: UtcMillis, expires_at: UtcMillis, now: UtcMillis) -> bool {
    issued_at
        .get()
        .checked_sub(PEER_ADMISSION_CLOCK_SKEW_MS)
        .is_some_and(|earliest| now.get() >= earliest)
        && expires_at
            .get()
            .checked_add(PEER_ADMISSION_CLOCK_SKEW_MS)
            .is_some_and(|latest| now.get() <= latest)
}

fn signature_input(domain: &[u8], unsigned: &CanonicalValue) -> Result<Vec<u8>, ContactError> {
    let exact = encode_deterministic_cbor(unsigned).map_err(|_| ContactError::Invalid)?;
    let mut input = Vec::with_capacity(domain.len() + exact.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&exact);
    Ok(input)
}

fn verify_signature(
    key: SigningPublicKey,
    signature: Ed25519Signature,
    input: &[u8],
) -> Result<(), ContactError> {
    let key =
        VerifyingKey::from_bytes(key.as_bytes()).map_err(|_| ContactError::InvalidSignature)?;
    key.verify_strict(input, &Signature::from_bytes(signature.as_bytes()))
        .map_err(|_| ContactError::InvalidSignature)
}

fn valid_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if value.len() > 512
        || !value.is_ascii()
        || authority.is_empty()
        || authority.contains(['/', '@', '?', '#', '\\', '[', ']'])
        || authority.matches(':').count() > 1
    {
        return false;
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    valid_dns_host(host) && port.is_none_or(valid_port)
}

fn valid_dns_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.ends_with('.')
        && host.bytes().any(|byte| byte.is_ascii_lowercase())
        && !host.split('.').all(|part| {
            !part.is_empty()
                && (part.bytes().all(|byte| byte.is_ascii_digit())
                    || part.strip_prefix("0x").is_some_and(|hex| {
                        !hex.is_empty()
                            && hex
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    }))
        })
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_port(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value
            .parse::<u16>()
            .is_ok_and(|port| port != 0 && port != 443)
}

fn exact_map(
    value: &CanonicalValue,
    length: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], ContactError> {
    let CanonicalValue::Map(fields) = value else {
        return Err(ContactError::Invalid);
    };
    if fields.len() == length {
        Ok(fields)
    } else {
        Err(ContactError::Invalid)
    }
}

fn field(
    fields: &[(CanonicalValue, CanonicalValue)],
    key: u64,
) -> Result<&CanonicalValue, ContactError> {
    fields
        .iter()
        .find_map(|(candidate, value)| (*candidate == u(key)).then_some(value))
        .ok_or(ContactError::Invalid)
}

fn require_unsigned(value: &CanonicalValue, expected: u64) -> Result<(), ContactError> {
    if *value == u(expected) {
        Ok(())
    } else {
        Err(ContactError::Invalid)
    }
}

fn u(value: u64) -> CanonicalValue {
    CanonicalValue::Unsigned(value)
}

fn text_id(value: &impl ToString) -> CanonicalValue {
    CanonicalValue::Text(value.to_string())
}

fn text(value: &CanonicalValue) -> Result<&str, ContactError> {
    let CanonicalValue::Text(value) = value else {
        return Err(ContactError::Invalid);
    };
    Ok(value)
}

fn id<T: std::str::FromStr>(value: &CanonicalValue) -> Result<T, ContactError> {
    text(value)?.parse().map_err(|_| ContactError::Invalid)
}

fn identity(value: &CanonicalValue) -> Result<IdentityId, ContactError> {
    id(value)
}

fn origin(value: &CanonicalValue) -> Result<String, ContactError> {
    let value = text(value)?;
    if valid_origin(value) {
        Ok(value.to_owned())
    } else {
        Err(ContactError::Invalid)
    }
}

fn fixed_bytes<const N: usize>(value: &CanonicalValue) -> Result<[u8; N], ContactError> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(ContactError::Invalid);
    };
    value.clone().try_into().map_err(|_| ContactError::Invalid)
}

fn digest(value: &CanonicalValue) -> Result<Sha256Digest, ContactError> {
    Ok(Sha256Digest::from_bytes(fixed_bytes(value)?))
}

fn signature(value: &CanonicalValue) -> Result<Ed25519Signature, ContactError> {
    Ok(Ed25519Signature::from_bytes(fixed_bytes(value)?))
}

fn signing_key(value: &CanonicalValue) -> Result<SigningPublicKey, ContactError> {
    SigningPublicKey::try_from(fixed_bytes(value)?).map_err(|_| ContactError::Invalid)
}

fn safe_uint(value: &CanonicalValue) -> Result<SafeUint, ContactError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(ContactError::Invalid);
    };
    SafeUint::new(*value).map_err(|_| ContactError::Invalid)
}

fn millis(value: &CanonicalValue) -> Result<UtcMillis, ContactError> {
    let value = match value {
        CanonicalValue::Unsigned(value) => {
            i64::try_from(*value).map_err(|_| ContactError::Invalid)?
        }
        CanonicalValue::Negative(value) => *value,
        _ => return Err(ContactError::Invalid),
    };
    UtcMillis::new(value).map_err(|_| ContactError::Invalid)
}

fn bounded_bytes(value: &CanonicalValue, maximum: usize) -> Result<Vec<u8>, ContactError> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(ContactError::Invalid);
    };
    if value.is_empty() || value.len() > maximum {
        Err(ContactError::Invalid)
    } else {
        Ok(value.clone())
    }
}
