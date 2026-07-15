#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    reason = "the frozen V27 CDDL documents protocol rejection semantics during first-validation delivery"
)]

//! Opaque direct-contact capability, request, review, and delivery bindings.

use dtx_domain::{DeviceId, IdentityId, InviteCapabilityId, RequestId};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, Sha256Digest, UtcMillis,
    decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha256};
use std::{error::Error, fmt};

mod repository;
pub use repository::{
    ContactRepository, ContactRequestRecord, ContactStoreError, StoredContactReceipt,
};

pub const MAX_SEALED_CONTACT_REQUEST_BYTES: usize = 131_072;
pub const MAX_SEALED_CONTACT_DELIVERY_BYTES: usize = 262_144;
pub const MAX_INVITE_LIFETIME_MS: i64 = 86_400_000;
pub const MAX_REQUEST_LIFETIME_MS: i64 = 86_400_000;
pub const MAX_INVITE_USES: u8 = 8;
const CAPABILITY_DOMAIN: &[u8] = b"dirextalk.contact-invite-capability.v1\0";
const INVITE_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.contact-invite-signature.v1\0";
const REQUEST_AAD_DOMAIN: &[u8] = b"dirextalk.contact-request-sealed-aad.v1\0";
const DELIVERY_AAD_DOMAIN: &[u8] = b"dirextalk.contact-delivery-sealed-aad.v1\0";
const RECEIPT_CAPABILITY_DOMAIN: &[u8] = b"dirextalk.contact-receipt-capability.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactError {
    Invalid,
    InvalidSignature,
}
impl fmt::Display for ContactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "invalid contact protocol value",
            Self::InvalidSignature => "invalid contact invite signature",
        })
    }
}
impl Error for ContactError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactInviteV1 {
    invite_id: InviteCapabilityId,
    owner_identity_id: IdentityId,
    owner_device_id: DeviceId,
    capability_hash: Sha256Digest,
    max_uses: u8,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    signature: Ed25519Signature,
}
impl ContactInviteV1 {
    pub fn decode(exact: &[u8]) -> Result<Self, ContactError> {
        let value = decode_deterministic_cbor(exact).map_err(|_| ContactError::Invalid)?;
        let fields = map(&value, 9)?;
        require_version(field(fields, 1)?)?;
        let invite_id = uuid_text(field(fields, 2)?)?;
        let owner_identity_id = text(field(fields, 3)?)?
            .parse()
            .map_err(|_| ContactError::Invalid)?;
        let owner_device_id = uuid_text(field(fields, 4)?)?;
        let capability_hash = digest(field(fields, 5)?)?;
        let max_uses =
            u8::try_from(unsigned(field(fields, 6)?)?).map_err(|_| ContactError::Invalid)?;
        if !(1..=MAX_INVITE_USES).contains(&max_uses) {
            return Err(ContactError::Invalid);
        }
        let issued_at = millis(field(fields, 7)?)?;
        let expires_at = millis(field(fields, 8)?)?;
        if expires_at.get() <= issued_at.get()
            || expires_at.get() - issued_at.get() > MAX_INVITE_LIFETIME_MS
        {
            return Err(ContactError::Invalid);
        }
        let signature = signature(field(fields, 9)?)?;
        let value = Self {
            invite_id,
            owner_identity_id,
            owner_device_id,
            capability_hash,
            max_uses,
            issued_at,
            expires_at,
            signature,
        };
        if value.encode()? != exact {
            return Err(ContactError::Invalid);
        }
        Ok(value)
    }
    pub fn encode(&self) -> Result<Vec<u8>, ContactError> {
        encode_deterministic_cbor(self).map_err(|_| ContactError::Invalid)
    }
    pub fn verify(&self, signing_key: &[u8; 32]) -> Result<(), ContactError> {
        let key =
            VerifyingKey::from_bytes(signing_key).map_err(|_| ContactError::InvalidSignature)?;
        let input = self.signature_input()?;
        key.verify(&input, &Signature::from_bytes(self.signature.as_bytes()))
            .map_err(|_| ContactError::InvalidSignature)
    }
    pub fn signature_input(&self) -> Result<Vec<u8>, ContactError> {
        let unsigned = CanonicalValue::Map(self.fields(false));
        let exact = encode_deterministic_cbor(&unsigned).map_err(|_| ContactError::Invalid)?;
        let mut input = Vec::with_capacity(INVITE_SIGNATURE_DOMAIN.len() + exact.len());
        input.extend_from_slice(INVITE_SIGNATURE_DOMAIN);
        input.extend_from_slice(&exact);
        Ok(input)
    }
    fn fields(&self, signature: bool) -> Vec<(CanonicalValue, CanonicalValue)> {
        let mut fields = vec![
            (u(1), u(1)),
            (u(2), CanonicalValue::Text(self.invite_id.to_string())),
            (
                u(3),
                CanonicalValue::Text(self.owner_identity_id.to_string()),
            ),
            (u(4), CanonicalValue::Text(self.owner_device_id.to_string())),
            (u(5), self.capability_hash.to_canonical_value()),
            (u(6), u(u64::from(self.max_uses))),
            (u(7), self.issued_at.to_canonical_value()),
            (u(8), self.expires_at.to_canonical_value()),
        ];
        if signature {
            fields.push((u(9), self.signature.to_canonical_value()));
        }
        fields
    }
    #[must_use]
    pub const fn invite_id(&self) -> InviteCapabilityId {
        self.invite_id
    }
    #[must_use]
    pub const fn owner_identity_id(&self) -> IdentityId {
        self.owner_identity_id
    }
    #[must_use]
    pub const fn owner_device_id(&self) -> DeviceId {
        self.owner_device_id
    }
    #[must_use]
    pub const fn capability_hash(&self) -> Sha256Digest {
        self.capability_hash
    }
    #[must_use]
    pub const fn max_uses(&self) -> u8 {
        self.max_uses
    }
    #[must_use]
    pub const fn issued_at(&self) -> UtcMillis {
        self.issued_at
    }
    #[must_use]
    pub const fn expires_at(&self) -> UtcMillis {
        self.expires_at
    }
}
impl CanonicalEncode for ContactInviteV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(self.fields(true))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactRequestV1 {
    request_id: RequestId,
    invite_id: InviteCapabilityId,
    target_identity_id: IdentityId,
    target_device_id: DeviceId,
    receipt_capability_hash: Sha256Digest,
    sealed_request: Vec<u8>,
    aad_digest: Sha256Digest,
}
impl ContactRequestV1 {
    pub fn decode(exact: &[u8]) -> Result<Self, ContactError> {
        let value = decode_deterministic_cbor(exact).map_err(|_| ContactError::Invalid)?;
        let f = map(&value, 8)?;
        require_version(field(f, 1)?)?;
        let request_id = uuid_text(field(f, 2)?)?;
        let invite_id = uuid_text(field(f, 3)?)?;
        let target_identity_id = text(field(f, 4)?)?
            .parse()
            .map_err(|_| ContactError::Invalid)?;
        let target_device_id = uuid_text(field(f, 5)?)?;
        let receipt_capability_hash = digest(field(f, 6)?)?;
        let sealed_request = bytes(field(f, 7)?, MAX_SEALED_CONTACT_REQUEST_BYTES)?;
        let aad_digest = digest(field(f, 8)?)?;
        let v = Self {
            request_id,
            invite_id,
            target_identity_id,
            target_device_id,
            receipt_capability_hash,
            sealed_request,
            aad_digest,
        };
        if v.expected_aad_digest()? != aad_digest || v.encode()? != exact {
            return Err(ContactError::Invalid);
        }
        Ok(v)
    }
    pub fn encode(&self) -> Result<Vec<u8>, ContactError> {
        encode_deterministic_cbor(self).map_err(|_| ContactError::Invalid)
    }
    fn aad_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (u(1), u(1)),
            (u(2), CanonicalValue::Text(self.request_id.to_string())),
            (u(3), CanonicalValue::Text(self.invite_id.to_string())),
            (
                u(4),
                CanonicalValue::Text(self.target_identity_id.to_string()),
            ),
            (
                u(5),
                CanonicalValue::Text(self.target_device_id.to_string()),
            ),
            (u(6), self.receipt_capability_hash.to_canonical_value()),
        ])
    }
    pub fn expected_aad_digest(&self) -> Result<Sha256Digest, ContactError> {
        Ok(domain_digest(
            REQUEST_AAD_DOMAIN,
            &encode_deterministic_cbor(&self.aad_value()).map_err(|_| ContactError::Invalid)?,
        ))
    }
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }
    #[must_use]
    pub const fn invite_id(&self) -> InviteCapabilityId {
        self.invite_id
    }
    #[must_use]
    pub const fn target_identity_id(&self) -> IdentityId {
        self.target_identity_id
    }
    #[must_use]
    pub const fn target_device_id(&self) -> DeviceId {
        self.target_device_id
    }
    #[must_use]
    pub const fn receipt_capability_hash(&self) -> Sha256Digest {
        self.receipt_capability_hash
    }
    #[must_use]
    pub fn sealed_request(&self) -> &[u8] {
        &self.sealed_request
    }
}
impl CanonicalEncode for ContactRequestV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (u(1), u(1)),
            (u(2), CanonicalValue::Text(self.request_id.to_string())),
            (u(3), CanonicalValue::Text(self.invite_id.to_string())),
            (
                u(4),
                CanonicalValue::Text(self.target_identity_id.to_string()),
            ),
            (
                u(5),
                CanonicalValue::Text(self.target_device_id.to_string()),
            ),
            (u(6), self.receipt_capability_hash.to_canonical_value()),
            (u(7), CanonicalValue::Bytes(self.sealed_request.clone())),
            (u(8), self.aad_digest.to_canonical_value()),
        ])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactDecisionV1 {
    Accept,
    Reject,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactReviewV1 {
    request_id: RequestId,
    decision: ContactDecisionV1,
    sealed_delivery: Option<Vec<u8>>,
    aad_digest: Option<Sha256Digest>,
}
impl ContactReviewV1 {
    pub fn decode(exact: &[u8]) -> Result<Self, ContactError> {
        let value = decode_deterministic_cbor(exact).map_err(|_| ContactError::Invalid)?;
        let f = map(&value, 5)?;
        require_version(field(f, 1)?)?;
        let request_id = uuid_text(field(f, 2)?)?;
        let decision = match unsigned(field(f, 3)?)? {
            1 => ContactDecisionV1::Accept,
            2 => ContactDecisionV1::Reject,
            _ => return Err(ContactError::Invalid),
        };
        let sealed_delivery = optional_bytes(field(f, 4)?, MAX_SEALED_CONTACT_DELIVERY_BYTES)?;
        let aad_digest = optional_digest(field(f, 5)?)?;
        if matches!(decision, ContactDecisionV1::Accept)
            != (sealed_delivery.is_some() && aad_digest.is_some())
        {
            return Err(ContactError::Invalid);
        }
        let v = Self {
            request_id,
            decision,
            sealed_delivery,
            aad_digest,
        };
        if v.encode()? != exact {
            return Err(ContactError::Invalid);
        }
        Ok(v)
    }
    pub fn encode(&self) -> Result<Vec<u8>, ContactError> {
        encode_deterministic_cbor(self).map_err(|_| ContactError::Invalid)
    }
    pub fn verify_aad(
        &self,
        invite_id: InviteCapabilityId,
        target_identity: IdentityId,
        target_device: DeviceId,
    ) -> Result<(), ContactError> {
        if self.decision == ContactDecisionV1::Reject {
            return Ok(());
        }
        let value = CanonicalValue::Map(vec![
            (u(1), u(1)),
            (u(2), CanonicalValue::Text(self.request_id.to_string())),
            (u(3), CanonicalValue::Text(invite_id.to_string())),
            (u(4), CanonicalValue::Text(target_identity.to_string())),
            (u(5), CanonicalValue::Text(target_device.to_string())),
            (u(6), u(1)),
        ]);
        let exact = encode_deterministic_cbor(&value).map_err(|_| ContactError::Invalid)?;
        if self.aad_digest == Some(domain_digest(DELIVERY_AAD_DOMAIN, &exact)) {
            Ok(())
        } else {
            Err(ContactError::Invalid)
        }
    }
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }
    #[must_use]
    pub const fn decision(&self) -> ContactDecisionV1 {
        self.decision
    }
    #[must_use]
    pub fn sealed_delivery(&self) -> Option<&[u8]> {
        self.sealed_delivery.as_deref()
    }
}
impl CanonicalEncode for ContactReviewV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (u(1), u(1)),
            (u(2), CanonicalValue::Text(self.request_id.to_string())),
            (
                u(3),
                u(match self.decision {
                    ContactDecisionV1::Accept => 1,
                    ContactDecisionV1::Reject => 2,
                }),
            ),
            (
                u(4),
                self.sealed_delivery
                    .clone()
                    .map_or(CanonicalValue::Null, CanonicalValue::Bytes),
            ),
            (
                u(5),
                self.aad_digest
                    .map_or(CanonicalValue::Null, |v| v.to_canonical_value()),
            ),
        ])
    }
}

#[must_use]
pub fn invite_capability_hash(secret: &[u8; 32]) -> Sha256Digest {
    domain_digest(CAPABILITY_DOMAIN, secret)
}
#[must_use]
pub fn contact_receipt_capability_hash(secret: &[u8; 32]) -> Sha256Digest {
    domain_digest(RECEIPT_CAPABILITY_DOMAIN, secret)
}
fn domain_digest(domain: &[u8], bytes: &[u8]) -> Sha256Digest {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    Sha256Digest::from_bytes(h.finalize().into())
}
fn u(v: u64) -> CanonicalValue {
    CanonicalValue::Unsigned(v)
}
fn field(f: &[(CanonicalValue, CanonicalValue)], k: u64) -> Result<&CanonicalValue, ContactError> {
    f.iter()
        .find_map(|(a, b)| (*a == u(k)).then_some(b))
        .ok_or(ContactError::Invalid)
}
fn map(v: &CanonicalValue, n: usize) -> Result<&[(CanonicalValue, CanonicalValue)], ContactError> {
    let CanonicalValue::Map(f) = v else {
        return Err(ContactError::Invalid);
    };
    if f.len() != n {
        return Err(ContactError::Invalid);
    }
    Ok(f)
}
fn require_version(v: &CanonicalValue) -> Result<(), ContactError> {
    if *v == u(1) {
        Ok(())
    } else {
        Err(ContactError::Invalid)
    }
}
fn text(v: &CanonicalValue) -> Result<&str, ContactError> {
    if let CanonicalValue::Text(v) = v {
        Ok(v)
    } else {
        Err(ContactError::Invalid)
    }
}
fn unsigned(v: &CanonicalValue) -> Result<u64, ContactError> {
    if let CanonicalValue::Unsigned(v) = v {
        Ok(*v)
    } else {
        Err(ContactError::Invalid)
    }
}
fn uuid_text<T: std::str::FromStr>(v: &CanonicalValue) -> Result<T, ContactError> {
    text(v)?.parse().map_err(|_| ContactError::Invalid)
}
fn digest(v: &CanonicalValue) -> Result<Sha256Digest, ContactError> {
    let CanonicalValue::Bytes(v) = v else {
        return Err(ContactError::Invalid);
    };
    Ok(Sha256Digest::from_bytes(
        v.clone().try_into().map_err(|_| ContactError::Invalid)?,
    ))
}
fn signature(v: &CanonicalValue) -> Result<Ed25519Signature, ContactError> {
    let CanonicalValue::Bytes(v) = v else {
        return Err(ContactError::Invalid);
    };
    Ok(Ed25519Signature::from_bytes(
        v.clone().try_into().map_err(|_| ContactError::Invalid)?,
    ))
}
fn millis(v: &CanonicalValue) -> Result<UtcMillis, ContactError> {
    let value = match v {
        CanonicalValue::Unsigned(v) => i64::try_from(*v).map_err(|_| ContactError::Invalid)?,
        CanonicalValue::Negative(v) => *v,
        _ => return Err(ContactError::Invalid),
    };
    UtcMillis::new(value).map_err(|_| ContactError::Invalid)
}
fn bytes(v: &CanonicalValue, max: usize) -> Result<Vec<u8>, ContactError> {
    let CanonicalValue::Bytes(v) = v else {
        return Err(ContactError::Invalid);
    };
    if v.is_empty() || v.len() > max {
        return Err(ContactError::Invalid);
    }
    Ok(v.clone())
}
fn optional_bytes(v: &CanonicalValue, max: usize) -> Result<Option<Vec<u8>>, ContactError> {
    if *v == CanonicalValue::Null {
        Ok(None)
    } else {
        bytes(v, max).map(Some)
    }
}
fn optional_digest(v: &CanonicalValue) -> Result<Option<Sha256Digest>, ContactError> {
    if *v == CanonicalValue::Null {
        Ok(None)
    } else {
        digest(v).map(Some)
    }
}
