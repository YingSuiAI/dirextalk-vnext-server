//! Production-neutral validators for the catalog-exhaustive History Recovery
//! wire objects.  This crate intentionally has no database, HTTP, mailbox, or
//! testkit dependency: callers retain the returned bytes and perform
//! currentness/authorization checks at their own persistence boundary.

use std::{fmt, str::FromStr};

use dtx_domain::{DeviceId, IdentityId};
use dtx_wire::{
    CanonicalValue, Sha256Digest, decode_deterministic_cbor, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use uuid::Uuid;

pub const MAX_CATALOG_HEAD_BYTES: usize = 466;
pub const MAX_REQUEST_BYTES: usize = 37_114;
pub const MAX_MANIFEST_BYTES: usize = 35_477;
pub const MAX_OFFER_BYTES: usize = 1_049_093;
pub const MAX_GRANT_BYTES: usize = 1_050_699;
pub const MAX_DELIVERY_BYTES: usize = 366;
pub const MAX_COMPLETION_BYTES: usize = 3_593_836;
pub const MAX_ENTRY_BYTES: usize = 1_387;
pub const MAX_LEAF_BYTES: usize = 220;
pub const MAX_PROOF_BYTES: usize = 427;
pub const MAX_CERTIFICATE_BYTES: usize = 389;
pub const MAX_EVIDENCE_BYTES: usize = 250;

pub const CATALOG_HEAD_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-head-signature.v2\0";
pub const CATALOG_HEAD_DIGEST_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-head.v2\0";
pub const REQUEST_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.history-recovery.request-signature.v4\0";
pub const REQUEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.history-recovery.request.v4\0";
pub const MANIFEST_DIGEST_DOMAIN: &[u8] = b"dirextalk.history-recovery.manifest.v2\0";
pub const LEAF_SET_DOMAIN: &[u8] = b"dirextalk.history-recovery.leaf-set.v2\0";
pub const OFFER_DIGEST_DOMAIN: &[u8] = b"dirextalk.history-recovery.recipient-offer.v3\0";
pub const OFFER_CIPHERTEXT_DOMAIN: &[u8] = b"dirextalk.history-recovery.offer-ciphertext.v3\0";
pub const GRANT_PROVIDER_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.grant-provider-signature.v5\0";
pub const GRANT_AUTHORITY_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.grant-authority-signature.v5\0";
pub const GRANT_DIGEST_DOMAIN: &[u8] = b"dirextalk.history-recovery.grant.v5\0";
pub const DELIVERY_FACT_DOMAIN: &[u8] = b"dirextalk.history-recovery.delivery-fact.v2\0";
pub const COMPLETION_ENTRY_DOMAIN: &[u8] = b"dirextalk.history-recovery.completion-entry.v2\0";
pub const COMPLETION_ENTRY_NODE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.completion-entry-node.v2\0";
pub const CERTIFICATE_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.mls-recovery.completion-child-certificate.v1\0";
pub const EVIDENCE_DIGEST_DOMAIN: &[u8] = b"dirextalk.mls-recovery.redacted-evidence.v1\0";
pub const CHILD_POP_DOMAIN: &[u8] = b"dirextalk.mls-recovery.completion-child-pop.v1\0";
pub const CERTIFICATE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.mls-recovery.completion-child-certificate-signature.v1\0";
pub const EVIDENCE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.mls-recovery.redacted-evidence-signature.v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolError(&'static str);
impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ProtocolError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogHeadV2 {
    identity: IdentityId,
    catalog_id: Uuid,
    generation: u64,
    leaf_count: u64,
    digest: Sha256Digest,
}
impl CatalogHeadV2 {
    pub fn identity_id(&self) -> &IdentityId {
        &self.identity
    }
    pub fn catalog_id(&self) -> Uuid {
        self.catalog_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestV4 {
    request_id: Uuid,
    identity: IdentityId,
    device: DeviceId,
    signing_key: [u8; 32],
    digest: Sha256Digest,
    manifest_digest: Sha256Digest,
}
impl RequestV4 {
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub fn identity_id(&self) -> &IdentityId {
        &self.identity
    }
    pub fn device_id(&self) -> DeviceId {
        self.device
    }
    pub fn signing_key(&self) -> &[u8; 32] {
        &self.signing_key
    }
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }
    pub fn manifest_digest(&self) -> Sha256Digest {
        self.manifest_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestV2 {
    catalog_id: Uuid,
    generation: u64,
    head_digest: Sha256Digest,
    leaf_count: u64,
    leaf_set_digest: Sha256Digest,
    digest: Sha256Digest,
}
impl ManifestV2 {
    pub fn catalog_id(&self) -> Uuid {
        self.catalog_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn head_digest(&self) -> Sha256Digest {
        self.head_digest
    }
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }
    pub fn leaf_set_digest(&self) -> Sha256Digest {
        self.leaf_set_digest
    }
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfferV3 {
    request_id: Uuid,
    digest: Sha256Digest,
    provider_response_digest: Sha256Digest,
}
impl OfferV3 {
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }
    pub fn provider_response_digest(&self) -> Sha256Digest {
        self.provider_response_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantV5 {
    digest: Sha256Digest,
}
impl GrantV5 {
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryV2 {
    pub delivery_fact_id: Uuid,
    pub mailbox_id: Uuid,
    pub envelope_id: Uuid,
    pub grant_digest: Sha256Digest,
    pub offer_digest: Sha256Digest,
    pub request_id: Uuid,
    pub device_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateV1 {
    child_key: [u8; 32],
    digest: Sha256Digest,
    context_digest: Sha256Digest,
    generation: u64,
    head_digest: Sha256Digest,
    count: u64,
    index: u64,
    leaf_digest: Sha256Digest,
    issued_at: u64,
    expires_at: u64,
}
impl CertificateV1 {
    pub fn child_key(&self) -> &[u8; 32] {
        &self.child_key
    }
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }
}

fn err(label: &'static str) -> ProtocolError {
    ProtocolError(label)
}
fn map(v: &CanonicalValue, n: usize) -> Result<Vec<CanonicalValue>, ProtocolError> {
    let CanonicalValue::Map(fields) = v else {
        return Err(err("map"));
    };
    if fields.len() != n
        || fields
            .iter()
            .enumerate()
            .any(|(i, (k, _))| *k != CanonicalValue::Unsigned((i + 1) as u64))
    {
        return Err(err("fields"));
    }
    Ok(fields.iter().map(|(_, v)| v.clone()).collect())
}
fn bytes(v: &CanonicalValue, max: usize) -> Result<Vec<u8>, ProtocolError> {
    match v {
        CanonicalValue::Bytes(b) if !b.is_empty() && b.len() <= max => Ok(b.clone()),
        _ => Err(err("bytes")),
    }
}
fn fixed<const N: usize>(v: &CanonicalValue) -> Result<[u8; N], ProtocolError> {
    match v {
        CanonicalValue::Bytes(b) if b.len() == N => Ok(b.as_slice().try_into().unwrap()),
        _ => Err(err("fixed bytes")),
    }
}
fn digest(v: &CanonicalValue) -> Result<Sha256Digest, ProtocolError> {
    Ok(Sha256Digest::from_bytes(
        fixed::<32>(v).map_err(|_| err("digest bytes"))?,
    ))
}
fn uuid(v: &CanonicalValue) -> Result<Uuid, ProtocolError> {
    let CanonicalValue::Text(s) = v else {
        return Err(err("uuid"));
    };
    let id = Uuid::parse_str(s).map_err(|_| err("uuid"))?;
    if id.to_string() != *s || id.get_version_num() != 7 {
        return Err(err("uuid v7"));
    }
    Ok(id)
}
fn identity(v: &CanonicalValue) -> Result<IdentityId, ProtocolError> {
    let CanonicalValue::Text(s) = v else {
        return Err(err("identity"));
    };
    IdentityId::from_str(s).map_err(|_| err("identity"))
}
fn device(v: &CanonicalValue) -> Result<DeviceId, ProtocolError> {
    let CanonicalValue::Text(s) = v else {
        return Err(err("device"));
    };
    DeviceId::from_str(s).map_err(|_| err("device"))
}
fn uint(v: &CanonicalValue, positive: bool) -> Result<u64, ProtocolError> {
    let CanonicalValue::Unsigned(n) = v else {
        return Err(err("uint"));
    };
    if *n > 9_007_199_254_740_991 || (positive && *n == 0) {
        return Err(err("uint"));
    }
    Ok(*n)
}
fn signature(v: &CanonicalValue) -> Result<[u8; 64], ProtocolError> {
    fixed::<64>(v)
}
fn verify(
    key: [u8; 32],
    domain: &[u8],
    unsigned: &CanonicalValue,
    sig: [u8; 64],
) -> Result<(), ProtocolError> {
    let bytes = encode_deterministic_cbor(unsigned).map_err(|_| err("encode"))?;
    let mut input = Vec::with_capacity(domain.len() + bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&bytes);
    VerifyingKey::from_bytes(&key)
        .map_err(|_| err("key"))?
        .verify(&input, &Signature::from_bytes(&sig))
        .map_err(|_| err("signature"))
}
fn unsigned(fields: &[CanonicalValue]) -> CanonicalValue {
    CanonicalValue::Map(
        fields
            .iter()
            .enumerate()
            .map(|(i, v)| (CanonicalValue::Unsigned((i + 1) as u64), v.clone()))
            .collect(),
    )
}

pub fn validate_catalog_head_v2(raw: &[u8]) -> Result<CatalogHeadV2, ProtocolError> {
    if raw.is_empty() || raw.len() > MAX_CATALOG_HEAD_BYTES {
        return Err(err("catalog head bounds"));
    }
    let fields = map(
        &decode_deterministic_cbor(raw).map_err(|_| err("catalog head cbor"))?,
        16,
    )?;
    if uint(&fields[0], false)? != 2 {
        return Err(err("catalog head version"));
    }
    let catalog_id = uuid(&fields[1])?;
    let identity_id = identity(&fields[2])?;
    let generation = uint(&fields[3], true)?;
    if !matches!(&fields[4], CanonicalValue::Null) {
        let _ = digest(&fields[4])?;
    }
    let leaf_count = uint(&fields[5], true)?;
    if leaf_count > 1023 {
        return Err(err("leaf count"));
    };
    let _head_digest = digest(&fields[9])?;
    let _merkle_root = digest(&fields[6])?;
    let _ciphertext_digest = digest(&fields[7])?;
    let _observed_sequence = uint(&fields[8], false)?;
    let _authority_device = uuid(&fields[10])?;
    let _authority_key_id = uuid(&fields[11])?;
    let key = fixed::<32>(&fields[12])?;
    let issued = uint(&fields[13], false)?;
    let expires = uint(&fields[14], false)?;
    if issued >= expires {
        return Err(err("interval"));
    };
    verify(
        key,
        CATALOG_HEAD_SIGNATURE_DOMAIN,
        &unsigned(&fields[..15]),
        signature(&fields[15])?,
    )?;
    Ok(CatalogHeadV2 {
        identity: identity_id,
        catalog_id,
        generation,
        leaf_count,
        digest: Sha256Digest::hash_domain(CATALOG_HEAD_DIGEST_DOMAIN, raw),
    })
}

pub fn validate_manifest_v2(raw: &[u8]) -> Result<ManifestV2, ProtocolError> {
    if raw.is_empty() || raw.len() > MAX_MANIFEST_BYTES {
        return Err(err("manifest bounds"));
    }
    let fields = map(
        &decode_deterministic_cbor(raw).map_err(|_| err("manifest cbor"))?,
        10,
    )?;
    if uint(&fields[0], false)? != 2 {
        return Err(err("manifest version"));
    };
    let identity_id = identity(&fields[1])?;
    let catalog_id = uuid(&fields[2])?;
    let generation = uint(&fields[3], true)?;
    let head_bytes = bytes(&fields[4], MAX_CATALOG_HEAD_BYTES)?;
    let head = validate_catalog_head_v2(&head_bytes)?;
    let head_digest = digest(&fields[5])?;
    let _root = digest(&fields[6])?;
    let leaf_count = uint(&fields[7], true)?;
    if leaf_count > 1023
        || head.catalog_id() != catalog_id
        || head.generation() != generation
        || head.digest() != head_digest
        || head.identity_id() != &identity_id
    {
        return Err(err("manifest coordinates"));
    };
    let leaf_set = digest(&fields[8])?;
    let CanonicalValue::Array(leaves) = &fields[9] else {
        return Err(err("leaf set"));
    };
    if leaves.len() != leaf_count as usize {
        return Err(err("leaf count"));
    };
    let mut seen = std::collections::HashSet::new();
    for leaf in leaves {
        let d = digest(leaf)?;
        if !seen.insert(d) {
            return Err(err("leaf duplicate"));
        }
    }
    let leaf_bytes = encode_deterministic_cbor(&fields[9]).map_err(|_| err("leaf set"))?;
    if Sha256Digest::hash_domain(LEAF_SET_DOMAIN, &leaf_bytes) != leaf_set {
        return Err(err("leaf set digest"));
    };
    Ok(ManifestV2 {
        catalog_id,
        generation,
        head_digest,
        leaf_count,
        leaf_set_digest: leaf_set,
        digest: Sha256Digest::hash_domain(MANIFEST_DIGEST_DOMAIN, raw),
    })
}

pub fn validate_request_v4(raw: &[u8]) -> Result<RequestV4, ProtocolError> {
    if raw.is_empty() || raw.len() > MAX_REQUEST_BYTES {
        return Err(err("request bounds"));
    }
    let fields = map(
        &decode_deterministic_cbor(raw).map_err(|_| err("request cbor"))?,
        21,
    )?;
    if uint(&fields[0], false)? != 4 {
        return Err(err("request version"));
    };
    let request_id = uuid(&fields[1])?;
    let identity_id = identity(&fields[2])?;
    let device_id = device(&fields[3])?;
    let signing_key = fixed::<32>(&fields[4])?;
    let manifest = encode_deterministic_cbor(&fields[14]).map_err(|_| err("manifest encoding"))?;
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(err("manifest bounds"));
    }
    let manifest_parsed = validate_manifest_v2(&manifest)?;
    if digest(&fields[15])? != manifest_parsed.digest() {
        return Err(err("manifest digest"));
    };
    let issued = uint(&fields[16], false)?;
    let expires = uint(&fields[17], false)?;
    if issued >= expires {
        return Err(err("request interval"));
    };
    verify(
        signing_key,
        REQUEST_SIGNATURE_DOMAIN,
        &unsigned(&fields[..20]),
        signature(&fields[20])?,
    )?;
    Ok(RequestV4 {
        request_id,
        identity: identity_id,
        device: device_id,
        signing_key,
        digest: Sha256Digest::hash_domain(REQUEST_DIGEST_DOMAIN, raw),
        manifest_digest: manifest_parsed.digest(),
    })
}

pub fn validate_offer_v3(raw: &[u8]) -> Result<OfferV3, ProtocolError> {
    if raw.is_empty() || raw.len() > MAX_OFFER_BYTES {
        return Err(err("offer bounds"));
    }
    let fields = map(
        &decode_deterministic_cbor(raw).map_err(|_| err("offer cbor"))?,
        16,
    )?;
    if uint(&fields[0], false)? != 3 {
        return Err(err("offer version"));
    };
    let request_id = uuid(&fields[1])?;
    let cipher = bytes(&fields[9], 1_048_576)?;
    if digest(&fields[10])? != Sha256Digest::hash_domain(OFFER_CIPHERTEXT_DOMAIN, &cipher) {
        return Err(err("offer ciphertext"));
    };
    let issued = uint(&fields[12], false)?;
    let expires = uint(&fields[13], false)?;
    if issued >= expires {
        return Err(err("offer interval"));
    };
    let provider = digest(&fields[15])?;
    Ok(OfferV3 {
        request_id,
        digest: Sha256Digest::hash_domain(OFFER_DIGEST_DOMAIN, raw),
        provider_response_digest: provider,
    })
}

pub fn validate_grant_v5(raw: &[u8]) -> Result<GrantV5, ProtocolError> {
    if raw.is_empty() || raw.len() > MAX_GRANT_BYTES {
        return Err(err("grant bounds"));
    }
    let fields = map(
        &decode_deterministic_cbor(raw).map_err(|_| err("grant cbor"))?,
        36,
    )?;
    if uint(&fields[0], false)? != 5 {
        return Err(err("grant version"));
    };
    let head = bytes(&fields[7], MAX_CATALOG_HEAD_BYTES)?;
    let head = validate_catalog_head_v2(&head)?;
    if digest(&fields[8])? != head.digest()
        || uuid(&fields[5])? != head.catalog_id()
        || uint(&fields[6], true)? != head.generation()
        || uint(&fields[10], true)? != head.leaf_count()
    {
        return Err(err("grant catalog coordinates"));
    }
    let provider = map(&fields[21], 3)?;
    let authority = map(&fields[22], 3)?;
    if uint(&provider[0], false)? != 2 || device(&provider[1]).is_err() {
        return Err(err("provider descriptor"));
    }
    let provider_device = device(&provider[1])?;
    let candidate_device = device(&fields[12])?;
    let authority_kind = uint(&authority[0], false)?;
    if !(1..=3).contains(&authority_kind)
        || (authority_kind == 1 && device(&authority[1]).is_err())
        || (authority_kind != 1 && digest(&authority[1]).is_err())
    {
        return Err(err("authority descriptor"));
    }
    let provider_key = fixed::<32>(&provider[2]).map_err(|_| err("provider key bytes"))?;
    let authority_key = fixed::<32>(&authority[2]).map_err(|_| err("authority key bytes"))?;
    if provider_key == authority_key {
        return Err(err("signer separation"));
    };
    if authority_kind == 1 {
        let authority_device = device(&authority[1])?;
        if authority_device == provider_device || authority_device == candidate_device {
            return Err(err("authority device separation"));
        }
    }
    let offer = encode_deterministic_cbor(&fields[35]).map_err(|_| err("offer"))?;
    let offer_parsed = validate_offer_v3(&offer)?;
    if digest(&fields[23])?
        != Sha256Digest::hash_domain(
            b"dirextalk.recovery-recipient-key.v1\0",
            &fixed::<32>(&fields[14]).map_err(|_| err("candidate key bytes"))?,
        )
        || digest(&fields[24])? != offer_parsed.digest()
    {
        return Err(err("grant offer coordinates"));
    }
    let offer_fields = map(&fields[35], 16)?;
    if offer_fields[1] != fields[2]
        || offer_fields[2] != fields[3]
        || offer_fields[3] != fields[4]
        || offer_fields[4] != fields[5]
        || offer_fields[5] != fields[6]
        || offer_fields[6] != fields[8]
        || offer_fields[7] != fields[11]
        || offer_fields[14] != fields[23]
    {
        return Err(err("offer coordinates"));
    }
    verify(
        provider_key,
        GRANT_PROVIDER_SIGNATURE_DOMAIN,
        &unsigned(&fields[..33]),
        signature(&fields[33])?,
    )?;
    verify(
        authority_key,
        GRANT_AUTHORITY_SIGNATURE_DOMAIN,
        &unsigned(&fields[..33]),
        signature(&fields[34])?,
    )?;
    Ok(GrantV5 {
        digest: Sha256Digest::hash_domain(GRANT_DIGEST_DOMAIN, raw),
    })
}

pub fn validate_delivery_v2(raw: &[u8]) -> Result<DeliveryV2, ProtocolError> {
    if raw.is_empty() || raw.len() > MAX_DELIVERY_BYTES {
        return Err(err("delivery bounds"));
    }
    let f = map(
        &decode_deterministic_cbor(raw).map_err(|_| err("delivery cbor"))?,
        12,
    )?;
    if uint(&f[0], false)? != 2 {
        return Err(err("delivery version"));
    };
    Ok(DeliveryV2 {
        delivery_fact_id: uuid(&f[1])?,
        mailbox_id: uuid(&f[2])?,
        envelope_id: uuid(&f[3])?,
        grant_digest: digest(&f[5])?,
        offer_digest: digest(&f[6])?,
        request_id: uuid(&f[7])?,
        device_id: uuid(&f[8])?,
    })
}

pub fn validate_completion_entry_v2(
    raw: &[u8],
    completion_id: Uuid,
    count: u64,
    index: u64,
) -> Result<Sha256Digest, ProtocolError> {
    if !(1..=1023).contains(&count) || !(1..=count).contains(&index) {
        return Err(err("entry bounds"));
    }
    if raw.is_empty() || raw.len() > MAX_ENTRY_BYTES {
        return Err(err("entry bounds"));
    }
    let f = map(
        &decode_deterministic_cbor(raw).map_err(|_| err("entry cbor"))?,
        9,
    )?;
    if uint(&f[0], false)? != 2 || uint(&f[1], true)? != index {
        return Err(err("entry coordinates"));
    };
    let leaf = bytes(&f[2], MAX_LEAF_BYTES)?;
    let lf = map(
        &decode_deterministic_cbor(&leaf).map_err(|_| err("leaf cbor"))?,
        12,
    )?;
    if uint(&lf[0], false)? != 2
        || uuid(&lf[1]).is_err()
        || uint(&lf[2], true).is_err()
        || uint(&lf[3], true)? != index
        || digest(&lf[4]).is_err()
        || digest(&lf[5]).is_err()
        || uint(&lf[6], false)? != 1
        || uint(&lf[7], false)? != 1
        || fixed::<32>(&lf[8]).is_err()
        || uint(&lf[9], false).is_err()
        || uint(&lf[10], false).is_err()
        || digest(&lf[11]).is_err()
    {
        return Err(err("leaf index"));
    };
    if uint(&lf[9], false)? >= uint(&lf[10], false)? {
        return Err(err("leaf interval"));
    }
    if digest(&f[3])?
        != Sha256Digest::hash_domain(
            b"dirextalk.recovery-scope-catalog-leaf-commitment.v2\0",
            &leaf,
        )
    {
        return Err(err("leaf digest"));
    };
    let proof = bytes(&f[4], MAX_PROOF_BYTES)?;
    let pf = map(
        &decode_deterministic_cbor(&proof).map_err(|_| err("proof cbor"))?,
        6,
    )?;
    if uint(&pf[0], false)? != 2
        || uuid(&pf[1])? != completion_id
        || uint(&pf[2], true)? != count
        || uint(&pf[3], true)? != index
    {
        return Err(err("proof coordinates"));
    };
    let entry_digest = Sha256Digest::hash_domain(COMPLETION_ENTRY_DOMAIN, raw);
    if digest(&pf[4])? != entry_digest {
        return Err(err("proof entry digest"));
    };
    let CanonicalValue::Array(siblings) = &pf[5] else {
        return Err(err("proof siblings"));
    };
    let mut expected_siblings = 0_usize;
    let mut width = count;
    let mut position = index;
    while width > 1 {
        if !(width % 2 == 1 && position == width) {
            expected_siblings += 1;
        }
        width = width.div_ceil(2);
        position = position.div_ceil(2);
    }
    if siblings.len() != expected_siblings || siblings.iter().any(|s| fixed::<32>(s).is_err()) {
        return Err(err("proof sibling count"));
    }
    let cert = bytes(&f[5], MAX_CERTIFICATE_BYTES)?;
    let cert_parsed = validate_certificate(&cert)?;
    if digest(&f[6])? != cert_parsed.digest() {
        return Err(err("certificate digest"));
    };
    let evidence = bytes(&f[7], MAX_EVIDENCE_BYTES)?;
    validate_evidence(&evidence, &cert_parsed)?;
    if digest(&f[8])? != Sha256Digest::hash_domain(EVIDENCE_DIGEST_DOMAIN, &evidence) {
        return Err(err("evidence digest"));
    };
    Ok(entry_digest)
}

fn validate_certificate(raw: &[u8]) -> Result<CertificateV1, ProtocolError> {
    let f = map(
        &decode_deterministic_cbor(raw).map_err(|_| err("certificate cbor"))?,
        16,
    )?;
    if uint(&f[0], false)? != 1 {
        return Err(err("certificate version"));
    };
    let issuer = fixed::<32>(&f[1])?;
    let _ = digest(&f[2])?;
    let _ = uint(&f[3], true)?;
    let _ = digest(&f[4])?;
    let cert_count = uint(&f[5], true)?;
    let cert_index = uint(&f[6], true)?;
    if cert_count > 1023 || cert_index > cert_count {
        return Err(err("certificate catalog coordinates"));
    }
    let _ = digest(&f[7])?;
    let _ = digest(&f[8])?;
    if uint(&f[9], false)? != 1 || uint(&f[10], false)? != 1 {
        return Err(err("certificate constants"));
    };
    let child = fixed::<32>(&f[11])?;
    let nbf = uint(&f[12], false)?;
    let exp = uint(&f[13], false)?;
    if nbf >= exp {
        return Err(err("certificate interval"));
    };
    verify(
        child,
        CHILD_POP_DOMAIN,
        &unsigned(&f[..14]),
        signature(&f[14])?,
    )?;
    verify(
        issuer,
        CERTIFICATE_SIGNATURE_DOMAIN,
        &unsigned(&f[..15]),
        signature(&f[15])?,
    )?;
    Ok(CertificateV1 {
        child_key: child,
        digest: Sha256Digest::hash_domain(CERTIFICATE_DIGEST_DOMAIN, raw),
        context_digest: digest(&f[8])?,
        generation: uint(&f[3], true)?,
        head_digest: digest(&f[4])?,
        count: cert_count,
        index: cert_index,
        leaf_digest: digest(&f[7])?,
        issued_at: nbf,
        expires_at: exp,
    })
}
fn validate_evidence(raw: &[u8], cert: &CertificateV1) -> Result<(), ProtocolError> {
    let f = map(
        &decode_deterministic_cbor(raw).map_err(|_| err("evidence cbor"))?,
        12,
    )?;
    if uint(&f[0], false)? != 1 {
        return Err(err("evidence version"));
    };
    if digest(&f[1])? != cert.digest
        || digest(&f[2])? != cert.context_digest
        || uint(&f[3], true)? != cert.generation
        || digest(&f[4])? != cert.head_digest
        || uint(&f[5], true)? != cert.count
        || uint(&f[6], true)? != cert.index
        || digest(&f[7])? != cert.leaf_digest
    {
        return Err(err("evidence coordinates"));
    }
    if f[8] != CanonicalValue::Unsigned(3) {
        return Err(err("evidence state"));
    };
    let issued = uint(&f[9], false)?;
    let expires = uint(&f[10], false)?;
    if issued != cert.issued_at || expires != cert.expires_at || issued >= expires {
        return Err(err("evidence interval"));
    };
    verify(
        *cert.child_key(),
        EVIDENCE_SIGNATURE_DOMAIN,
        &unsigned(&f[..11]),
        signature(&f[11])?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_boundary_rejects_empty_and_noncanonical_payloads() {
        let malformed = [0xff, 0x00];
        assert!(validate_catalog_head_v2(&[]).is_err());
        assert!(validate_request_v4(&malformed).is_err());
        assert!(validate_manifest_v2(&malformed).is_err());
        assert!(validate_offer_v3(&malformed).is_err());
        assert!(validate_grant_v5(&malformed).is_err());
        assert!(validate_delivery_v2(&malformed).is_err());
        assert!(validate_completion_entry_v2(&malformed, Uuid::now_v7(), 1, 1).is_err());
    }

    #[test]
    fn delivery_requires_exact_numbered_map_and_version() {
        let value = CanonicalValue::Map(vec![(
            CanonicalValue::Unsigned(1),
            CanonicalValue::Unsigned(3),
        )]);
        let bytes = encode_deterministic_cbor(&value).expect("canonical cbor");
        assert!(validate_delivery_v2(&bytes).is_err());
    }
}
