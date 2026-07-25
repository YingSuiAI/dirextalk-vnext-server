use dtx_history_recovery_protocol as recovery_protocol;
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, Sha256Digest, SigningPublicKey, UtcMillis,
    encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::{IdentityPersistenceError, IdentityPgStore, is_canonical_https_origin};

pub const COMPLETION_DESCRIPTOR_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.completion-key-descriptor.v2\0";
pub const COMPLETION_DESCRIPTOR_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.completion-key-descriptor-signature.v2\0";
pub const COMPLETION_RECEIPT_DOMAIN: &[u8] = b"dirextalk.history-recovery.completion-receipt.v2\0";
pub const COMPLETION_RECEIPT_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.completion-receipt-signature.v2\0";

// These locks serialize the two mutable decisions around otherwise immutable
// recovery artifacts. The values are constructed only from canonical command
// coordinates after device authentication, and are released with the enclosing
// transaction.
const COMPLETION_DESCRIPTOR_HEAD_LOCK_DOMAIN: &str =
    "dirextalk.history-recovery.completion-descriptor-head.v2";
const COMPLETION_REQUEST_LOCK_DOMAIN: &str = "dirextalk.history-recovery.completion-request.v2";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionKeyDescriptor {
    pub key_id: Uuid,
    pub public_key: SigningPublicKey,
    pub epoch: u64,
    pub rollback_floor_epoch: u64,
    pub issued_at: UtcMillis,
    pub expires_at: UtcMillis,
    pub previous_descriptor_digest: Option<Sha256Digest>,
    pub signature: Ed25519Signature,
    pub exact_bytes: Vec<u8>,
    pub digest: Sha256Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompletionSignerMetadata {
    pub key_id: Uuid,
    pub epoch: u64,
    pub rollback_floor_epoch: u64,
    pub issued_at: UtcMillis,
    pub expires_at: UtcMillis,
    pub previous_descriptor_digest: Option<Sha256Digest>,
}

impl CompletionKeyDescriptor {
    pub fn from_signer(
        metadata: CompletionSignerMetadata,
        origin: &str,
        signing_key: &SigningKey,
    ) -> Result<Self, IdentityPersistenceError> {
        if !is_canonical_https_origin(origin)
            || metadata.key_id.get_version_num() != 7
            || metadata.epoch == 0
            || metadata.rollback_floor_epoch == 0
            || metadata.rollback_floor_epoch > metadata.epoch
            || metadata.expires_at <= metadata.issued_at
        {
            return Err(IdentityPersistenceError::InvalidCommand(
                "invalid completion descriptor",
            ));
        }
        let public_key = SigningPublicKey::try_from(signing_key.verifying_key().to_bytes())
            .map_err(|_| IdentityPersistenceError::InvalidCommand("completion public key"))?;
        let mut fields = vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(origin.to_owned()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(metadata.key_id.to_string()),
            ),
            (CanonicalValue::Unsigned(4), public_key.to_canonical_value()),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Unsigned(metadata.epoch),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Unsigned(metadata.rollback_floor_epoch),
            ),
            (
                CanonicalValue::Unsigned(7),
                metadata.issued_at.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(8),
                metadata.expires_at.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(9),
                metadata
                    .previous_descriptor_digest
                    .map_or(CanonicalValue::Null, |v| v.to_canonical_value()),
            ),
        ];
        let unsigned = CanonicalValue::Map(fields.clone());
        let mut input = COMPLETION_DESCRIPTOR_SIGNATURE_DOMAIN.to_vec();
        input.extend_from_slice(
            &encode_deterministic_cbor(&unsigned)
                .map_err(|_| IdentityPersistenceError::InvalidCommand("completion descriptor"))?,
        );
        fields.push((
            CanonicalValue::Unsigned(10),
            Ed25519Signature::from_bytes(signing_key.sign(&input).to_bytes()).to_canonical_value(),
        ));
        let exact_bytes = encode_deterministic_cbor(&CanonicalValue::Map(fields))
            .map_err(|_| IdentityPersistenceError::InvalidCommand("completion descriptor"))?;
        let digest = Sha256Digest::hash_domain(COMPLETION_DESCRIPTOR_DOMAIN, &exact_bytes);
        Ok(Self {
            key_id: metadata.key_id,
            public_key,
            epoch: metadata.epoch,
            rollback_floor_epoch: metadata.rollback_floor_epoch,
            issued_at: metadata.issued_at,
            expires_at: metadata.expires_at,
            previous_descriptor_digest: metadata.previous_descriptor_digest,
            signature: Ed25519Signature::from_bytes(signing_key.sign(&input).to_bytes()),
            exact_bytes,
            digest,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletionReceiptOutcome {
    pub created: bool,
    pub receipt_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct HistoryRecoveryCompletionCommand {
    pub completion_id: Uuid,
    pub identity_id: String,
    pub device_id: Uuid,
    pub highwater: u64,
    pub head_at_highwater: Sha256Digest,
    pub highwater_next: u64,
    pub final_head_hash: Sha256Digest,
    pub catalog_id: Uuid,
    pub catalog_generation: u64,
    pub catalog_head_digest: Sha256Digest,
    pub catalog_root_digest: Sha256Digest,
    pub catalog_leaf_count: u64,
    pub leaf_set_digest: Sha256Digest,
    pub preparation_digest: Sha256Digest,
    pub request_id: Uuid,
    pub candidate_signing_key: [u8; 32],
    pub request_digest: Sha256Digest,
    pub manifest_digest: Sha256Digest,
    pub grant_digest: Sha256Digest,
    pub offer_digest: Sha256Digest,
    pub delivery_digest: Sha256Digest,
    pub entry_root: Sha256Digest,
    pub idempotency_digest: Sha256Digest,
    pub issued_at: UtcMillis,
    pub expires_at: UtcMillis,
    pub exact_bytes: Vec<u8>,
}

impl HistoryRecoveryCompletionCommand {
    pub fn parse(
        bytes: Vec<u8>,
        idempotency_digest: Sha256Digest,
    ) -> Result<Self, IdentityPersistenceError> {
        if bytes.is_empty() || bytes.len() > 3_593_836 {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let value = dtx_wire::decode_deterministic_cbor_with_limit(&bytes, 3_593_836)
            .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        let fields = numbered(&value, 36)?;
        if fields[0] != CanonicalValue::Unsigned(2) {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        // The neutral production validator owns nested wire semantics. Keep the
        // persistence parser focused on DB currentness and completion coordinates.
        macro_rules! validate_nested {
            ($field:expr, $validator:path) => {{
                let nested = bytes_field(&fields[$field - 1], 3_593_836)
                    .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
                $validator(&nested)
                    .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
            }};
        }
        validate_nested!(11, recovery_protocol::validate_catalog_head_v2);
        validate_nested!(20, recovery_protocol::validate_manifest_v2);
        validate_nested!(18, recovery_protocol::validate_request_v4);
        validate_nested!(22, recovery_protocol::validate_grant_v5);
        validate_nested!(24, recovery_protocol::validate_offer_v3);
        validate_nested!(26, recovery_protocol::validate_delivery_v2);
        let completion_id = uuid_field(&fields[1])?;
        let identity_id = text_field(&fields[2])?;
        let device_id = uuid_field(&fields[3])?;
        let highwater = uint_field(&fields[4])?;
        let highwater_next = uint_field(&fields[6])?;
        let final_head_hash = digest_field(&fields[7])?;
        let head_at_highwater = digest_field(&fields[5])?;
        if highwater == 0
            || highwater >= 9_007_199_254_740_991
            || highwater_next != highwater + 1
            || head_at_highwater.as_bytes() == &[0; 32]
        {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let catalog_id = uuid_field(&fields[8])?;
        let catalog_generation = uint_field(&fields[9])?;
        if catalog_generation == 0 {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let catalog_head = bytes_field(&fields[10], 466)?;
        let catalog_head_digest = digest_field(&fields[11])?;
        let parsed_head = crate::parse_signed_catalog_head_v2(&catalog_head)
            .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        if Sha256Digest::hash_domain(b"dirextalk.recovery-scope-catalog-head.v2\0", &catalog_head)
            != catalog_head_digest
        {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let catalog_root_digest = digest_field(&fields[12])?;
        let catalog_leaf_count = uint_field(&fields[13])?;
        if !(1..=1023).contains(&catalog_leaf_count) {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        if parsed_head.catalog_id != catalog_id
            || parsed_head.generation.get() != catalog_generation
            || parsed_head.merkle_root != catalog_root_digest
            || parsed_head.leaf_count.get() != catalog_leaf_count
        {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let leaf_set_digest = digest_field(&fields[14])?;
        let preparation = bytes_field(&fields[15], 532)?;
        let preparation_digest = digest_field(&fields[16])?;
        if Sha256Digest::hash_domain(
            b"dirextalk.recovery-scope-catalog-handoff-preparation-digest.v2\0",
            &preparation,
        ) != preparation_digest
        {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let request = bytes_field(&fields[17], 37_114)?;
        let request_digest = digest_field(&fields[18])?;
        if Sha256Digest::hash_domain(b"dirextalk.history-recovery.request.v4\0", &request)
            != request_digest
        {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let manifest = bytes_field(&fields[19], 35_477)?;
        let manifest_digest = digest_field(&fields[20])?;
        if Sha256Digest::hash_domain(b"dirextalk.history-recovery.manifest.v2\0", &manifest)
            != manifest_digest
        {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let grant = bytes_field(&fields[21], recovery_protocol::MAX_GRANT_BYTES)?;
        let grant_digest = digest_field(&fields[22])?;
        if Sha256Digest::hash_domain(b"dirextalk.history-recovery.grant.v5\0", &grant)
            != grant_digest
        {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let offer = bytes_field(&fields[23], 1_049_093)?;
        let offer_digest = digest_field(&fields[24])?;
        if Sha256Digest::hash_domain(b"dirextalk.history-recovery.recipient-offer.v3\0", &offer)
            != offer_digest
        {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let delivery = bytes_field(&fields[25], 366)?;
        let delivery_digest = digest_field(&fields[26])?;
        if Sha256Digest::hash_domain(b"dirextalk.history-recovery.delivery-fact.v2\0", &delivery)
            != delivery_digest
        {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let entry_count = uint_field(&fields[27])?;
        if entry_count != catalog_leaf_count {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let entry_root = digest_field(&fields[28])?;
        let entries = match &fields[29] {
            CanonicalValue::Array(v) if v.len() == entry_count as usize => v,
            _ => return Err(IdentityPersistenceError::RecoveryCompletionInvalid),
        };
        let computed = merkle_entries(entries)?;
        if computed != entry_root {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let issued_at = utc_field(&fields[30])?;
        let expires_at = utc_field(&fields[31])?;
        if issued_at >= expires_at {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        if digest_field(&fields[32])? != idempotency_digest {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let context = bytes_field(&fields[33], 373)?;
        let context_value = dtx_wire::decode_deterministic_cbor(&context)
            .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        let context_fields = numbered(&context_value, 12)?;
        if uint_field(&context_fields[0])? != 2
            || uuid_field(&context_fields[2])? != completion_id
            || uuid_field(&context_fields[3])? != uuid_from_request(&request)?
            || digest_field(&context_fields[4])? != request_digest
            || text_field(&context_fields[5])? != identity_id
            || uuid_field(&context_fields[6])? != device_id
            || uuid_field(&context_fields[7])? != catalog_id
            || uint_field(&context_fields[8])? != catalog_generation
            || digest_field(&context_fields[9])? != catalog_head_digest
            || uint_field(&context_fields[10])? != catalog_leaf_count
            || digest_field(&context_fields[11])? != leaf_set_digest
            || Sha256Digest::hash_domain(COMPLETION_CONTEXT_DOMAIN, &context)
                != digest_field(&fields[34])?
        {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let request_value = dtx_wire::decode_deterministic_cbor(&request)
            .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        let request_fields = numbered(&request_value, 21)?;
        let candidate_key = fixed32(&request_fields[4])?;
        let request_unsigned = dtx_wire::encode_deterministic_cbor(&CanonicalValue::Map(
            request_fields[..20]
                .iter()
                .enumerate()
                .map(|(i, v)| (CanonicalValue::Unsigned((i + 1) as u64), v.clone()))
                .collect(),
        ))
        .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        let request_vk = VerifyingKey::from_bytes(&candidate_key)
            .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        let request_sig = fixed64(&request_fields[20])?;
        request_vk
            .verify(
                &[
                    b"dirextalk.history-recovery.request-signature.v4\0",
                    request_unsigned.as_slice(),
                ]
                .concat(),
                &Signature::from_bytes(&request_sig),
            )
            .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        if uint_field(&request_fields[0])? != 4
            || uuid_field(&request_fields[1])? != uuid_from_request(&request)?
            || text_field(&request_fields[2])? != identity_id
            || uuid_field(&request_fields[3])? != device_id
            || uint_field(&request_fields[6])? != highwater
            || digest_field(&request_fields[7])? != head_at_highwater
            || uint_field(&request_fields[8])? != highwater_next
            || digest_field(&request_fields[9])? != final_head_hash
            || digest_field(&request_fields[13])? != preparation_digest
            || digest_field(&request_fields[15])? != manifest_digest
        {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let manifest_parsed = recovery_protocol::validate_manifest_v2(&manifest)
            .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        if manifest_parsed.catalog_root_digest() != catalog_root_digest
            || manifest_parsed.leaves().len() != entries.len()
        {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        let manifest_value = dtx_wire::decode_deterministic_cbor(&manifest)
            .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        let manifest_fields = numbered(&manifest_value, 10)?;
        let head_bytes = bytes_field(
            &manifest_fields[4],
            recovery_protocol::MAX_CATALOG_HEAD_BYTES,
        )?;
        let head = recovery_protocol::validate_catalog_head_v2(&head_bytes)
            .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        let grant_value = dtx_wire::decode_deterministic_cbor(&grant)
            .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        let grant_fields = numbered(&grant_value, 36)?;
        let context_digest = digest_field(&fields[34])?;
        for (offset, entry) in entries.iter().enumerate() {
            let index = (offset + 1) as u64;
            validate_entry(
                entry,
                recovery_protocol::CompletionEntryExpectations {
                    catalog_id,
                    generation: catalog_generation,
                    index,
                    completion_id,
                    count: catalog_leaf_count,
                    leaf_digest: manifest_parsed.leaves()[offset],
                    context_digest,
                    head_digest: catalog_head_digest,
                    request_issued_at: uint_field(&request_fields[16])?,
                    request_expires_at: uint_field(&request_fields[17])?,
                    head_issued_at: head.issued_at(),
                    head_expires_at: head.expires_at(),
                    grant_issued_at: uint_field(&grant_fields[30])?,
                    grant_expires_at: uint_field(&grant_fields[31])?,
                },
            )?;
        }
        let signature = fixed64(&fields[35])?;
        let unsigned = dtx_wire::encode_deterministic_cbor(&CanonicalValue::Map(
            fields[..35]
                .iter()
                .enumerate()
                .map(|(i, v)| (CanonicalValue::Unsigned((i + 1) as u64), v.clone()))
                .collect(),
        ))
        .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        let vk = VerifyingKey::from_bytes(&candidate_key)
            .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        vk.verify(
            &[COMPLETION_SIGNATURE_DOMAIN, unsigned.as_slice()].concat(),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        let canonical = dtx_wire::encode_deterministic_cbor(&value)
            .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
        if canonical != bytes {
            return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
        }
        Ok(Self {
            completion_id,
            identity_id,
            device_id,
            highwater,
            head_at_highwater,
            highwater_next,
            final_head_hash,
            catalog_id,
            catalog_generation,
            catalog_head_digest,
            catalog_root_digest,
            catalog_leaf_count,
            leaf_set_digest,
            preparation_digest,
            request_id: uuid_from_request(&request)?,
            candidate_signing_key: candidate_key,
            request_digest,
            manifest_digest,
            grant_digest,
            offer_digest,
            delivery_digest,
            entry_root,
            idempotency_digest,
            issued_at,
            expires_at,
            exact_bytes: bytes,
        })
    }
}

const COMPLETION_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery.completion-command-signature.v2\0";
const COMPLETION_CONTEXT_DOMAIN: &[u8] = b"dirextalk.history-recovery-completion-context.v2\0";
fn numbered(
    value: &CanonicalValue,
    count: usize,
) -> Result<Vec<CanonicalValue>, IdentityPersistenceError> {
    let CanonicalValue::Map(fields) = value else {
        return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
    };
    if fields.len() != count
        || fields
            .iter()
            .enumerate()
            .any(|(i, (k, _))| *k != CanonicalValue::Unsigned((i + 1) as u64))
    {
        return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
    }
    Ok(fields.iter().map(|(_, v)| v.clone()).collect())
}
fn uint_field(v: &CanonicalValue) -> Result<u64, IdentityPersistenceError> {
    match v {
        CanonicalValue::Unsigned(x) => Ok(*x),
        _ => Err(IdentityPersistenceError::RecoveryCompletionInvalid),
    }
}
fn text_field(v: &CanonicalValue) -> Result<String, IdentityPersistenceError> {
    match v {
        CanonicalValue::Text(x) => Ok(x.clone()),
        _ => Err(IdentityPersistenceError::RecoveryCompletionInvalid),
    }
}
fn uuid_field(v: &CanonicalValue) -> Result<Uuid, IdentityPersistenceError> {
    text_field(v)?
        .parse()
        .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)
}
fn uuid_from_request(bytes: &[u8]) -> Result<Uuid, IdentityPersistenceError> {
    let v = dtx_wire::decode_deterministic_cbor(bytes)
        .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
    let f = numbered(&v, 21)?;
    uuid_field(&f[1])
}
fn bytes_field(v: &CanonicalValue, max: usize) -> Result<Vec<u8>, IdentityPersistenceError> {
    match v {
        CanonicalValue::Bytes(x) if !x.is_empty() && x.len() <= max => Ok(x.clone()),
        _ => Err(IdentityPersistenceError::RecoveryCompletionInvalid),
    }
}
fn digest_field(v: &CanonicalValue) -> Result<Sha256Digest, IdentityPersistenceError> {
    let b = bytes_field(v, 32)?;
    digest32(&b)
}
fn fixed32(v: &CanonicalValue) -> Result<[u8; 32], IdentityPersistenceError> {
    let b = bytes_field(v, 32)?;
    b.try_into()
        .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)
}
fn fixed64(v: &CanonicalValue) -> Result<[u8; 64], IdentityPersistenceError> {
    let CanonicalValue::Bytes(b) = v else {
        return Err(IdentityPersistenceError::RecoveryCompletionInvalid);
    };
    b.as_slice()
        .try_into()
        .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)
}
fn utc_field(v: &CanonicalValue) -> Result<UtcMillis, IdentityPersistenceError> {
    UtcMillis::new(uint_field(v)? as i64)
        .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)
}
fn merkle_entries(entries: &[CanonicalValue]) -> Result<Sha256Digest, IdentityPersistenceError> {
    let mut level = entries
        .iter()
        .map(|v| {
            dtx_wire::encode_deterministic_cbor(v)
                .map(|b| {
                    Sha256Digest::hash_domain(
                        b"dirextalk.history-recovery.completion-entry.v2\0",
                        &b,
                    )
                })
                .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    while level.len() > 1 {
        let mut n = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut x = Vec::with_capacity(64);
            x.extend_from_slice(pair[0].as_bytes());
            x.extend_from_slice(right.as_bytes());
            n.push(Sha256Digest::hash_domain(
                b"dirextalk.history-recovery.completion-entry-node.v2\0",
                &x,
            ));
        }
        level = n;
    }
    Ok(level[0])
}
fn validate_entry(
    value: &CanonicalValue,
    expected: recovery_protocol::CompletionEntryExpectations,
) -> Result<(), IdentityPersistenceError> {
    let encoded = encode_deterministic_cbor(value)
        .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
    recovery_protocol::validate_completion_entry_v2(&encoded, expected)
        .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
    Ok(())
}
fn k(v: u64) -> CanonicalValue {
    CanonicalValue::Unsigned(v)
}
fn u(v: u64) -> CanonicalValue {
    CanonicalValue::Unsigned(v)
}
fn extract_value(bytes: &[u8], field: u64) -> Result<CanonicalValue, IdentityPersistenceError> {
    let value = dtx_wire::decode_deterministic_cbor(bytes)
        .map_err(|_| IdentityPersistenceError::RecoveryCompletionInvalid)?;
    let fields = numbered(&value, 36)?;
    fields
        .get((field - 1) as usize)
        .cloned()
        .ok_or(IdentityPersistenceError::RecoveryCompletionInvalid)
}
fn extract_bytes(bytes: &[u8], field: u64) -> Result<Vec<u8>, IdentityPersistenceError> {
    bytes_field(&extract_value(bytes, field)?, 1_100_000)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct HistoryRecoveryCompletionRepository;

impl HistoryRecoveryCompletionRepository {
    pub async fn get_receipt(
        &self,
        store: &IdentityPgStore,
        credential: &crate::DeviceSessionCredential,
        completion_id: Uuid,
        now: UtcMillis,
    ) -> Result<Option<Vec<u8>>, IdentityPersistenceError> {
        let mut tx = store.begin().await?;
        let auth = crate::DeviceSessionRepository::authenticate_in_transaction(
            tx.connection(),
            credential,
            now,
        )
        .await?;
        let row=sqlx::query("SELECT receipt_bytes,candidate_device_id FROM identity.history_recovery_completions_v2 WHERE identity_id=$1 AND completion_id=$2").bind(auth.identity_id().to_string()).bind(completion_id).fetch_optional(tx.connection()).await?;
        let result = match row {
            Some(row)
                if row.try_get::<Uuid, _>("candidate_device_id")?
                    == *auth.device_id().as_uuid() =>
            {
                Some(row.try_get::<Vec<u8>, _>("receipt_bytes")?)
            }
            Some(_) => None,
            None => None,
        };
        tx.commit().await?;
        Ok(result)
    }
    pub async fn submit(
        &self,
        store: &IdentityPgStore,
        command: &HistoryRecoveryCompletionCommand,
        credential: &crate::DeviceSessionCredential,
        descriptor: &CompletionKeyDescriptor,
        signing_key: &SigningKey,
        now: UtcMillis,
    ) -> Result<CompletionReceiptOutcome, IdentityPersistenceError> {
        let mut tx = store.begin().await?;
        let result = async {
            let authenticated = crate::DeviceSessionRepository::authenticate_with_signing_key_in_transaction(tx.connection(), credential, now).await?;
            if authenticated.session().identity_id().to_string() != command.identity_id || authenticated.session().device_id().as_uuid() != &command.device_id || authenticated.signing_key().as_bytes() != &command.candidate_signing_key { return Err(IdentityPersistenceError::DeviceAuthenticationRejected); }
            if let Some(row) = sqlx::query("SELECT receipt_bytes,completion_digest FROM identity.history_recovery_completions_v2 WHERE identity_id=$1 AND completion_id=$2").bind(&command.identity_id).bind(command.completion_id).fetch_optional(&mut *tx.connection()).await? {
                let bytes: Vec<u8> = row.try_get("receipt_bytes")?; if row.try_get::<Vec<u8>,_>("completion_digest")? != Sha256Digest::hash_domain(b"dirextalk.history-recovery.completion-command.v2\0", &command.exact_bytes).as_bytes() { return Err(IdentityPersistenceError::IdempotencyConflict); } return Ok(CompletionReceiptOutcome { created:false, receipt_bytes:bytes });
            }
            if let Some(row) = sqlx::query("SELECT receipt_bytes,completion_digest FROM identity.history_recovery_completions_v2 WHERE identity_id=$1 AND idempotency_digest=$2").bind(&command.identity_id).bind(command.idempotency_digest.as_bytes()).fetch_optional(&mut *tx.connection()).await? {
                if row.try_get::<Vec<u8>,_>("completion_digest")? != Sha256Digest::hash_domain(b"dirextalk.history-recovery.completion-command.v2\0", &command.exact_bytes).as_bytes() { return Err(IdentityPersistenceError::IdempotencyConflict); }
                return Ok(CompletionReceiptOutcome { created:false, receipt_bytes:row.try_get("receipt_bytes")? });
            }
            if let Some(row) = sqlx::query("SELECT receipt_bytes,completion_digest FROM identity.history_recovery_completions_v2 WHERE identity_id=$1 AND request_id=$2").bind(&command.identity_id).bind(command.request_id).fetch_optional(&mut *tx.connection()).await? {
                if row.try_get::<Vec<u8>,_>("completion_digest")? != Sha256Digest::hash_domain(b"dirextalk.history-recovery.completion-command.v2\0", &command.exact_bytes).as_bytes() { return Err(IdentityPersistenceError::IdempotencyConflict); }
                return Ok(CompletionReceiptOutcome { created:false, receipt_bytes:row.try_get("receipt_bytes")? });
            }
            if command.issued_at > now || now >= command.expires_at { return Err(IdentityPersistenceError::RecoveryCompletionExpired); }
            if now < descriptor.issued_at || now >= descriptor.expires_at || command.issued_at < descriptor.issued_at || command.expires_at > descriptor.expires_at { return Err(IdentityPersistenceError::RecoveryCompletionExpired); }
            // Serialize terminal consumption on the immutable candidate request. The
            // completion uniqueness fence below remains authoritative, but the
            // transaction-scoped advisory lock lets the runtime role retain only
            // SELECT/INSERT on the request relation.
            completion_advisory_lock(
                tx.connection(),
                COMPLETION_REQUEST_LOCK_DOMAIN,
                &format!("{}:{}", authenticated.session().identity_id(), command.request_id),
            )
            .await?;
            let request = sqlx::query("SELECT identity_id,candidate_device_id,candidate_signing_key,request_digest,manifest_digest,preparation_digest,post_head_hash,post_head_sequence,expires_at_ms FROM identity.history_recovery_requests WHERE request_id=$1").bind(command.request_id).fetch_optional(&mut *tx.connection()).await?.ok_or(IdentityPersistenceError::RecoveryCompletionInvalid)?;
            if request.try_get::<String,_>("identity_id")? != command.identity_id || request.try_get::<Uuid,_>("candidate_device_id")? != command.device_id || request.try_get::<Vec<u8>,_>("candidate_signing_key")? != command.candidate_signing_key || request.try_get::<Vec<u8>,_>("request_digest")? != command.request_digest.as_bytes() || request.try_get::<Vec<u8>,_>("manifest_digest")? != command.manifest_digest.as_bytes() || request.try_get::<Vec<u8>,_>("preparation_digest")? != command.preparation_digest.as_bytes() || request.try_get::<Vec<u8>,_>("post_head_hash")? != command.final_head_hash.as_bytes() || request.try_get::<i64,_>("post_head_sequence")? as u64 != command.highwater_next || request.try_get::<i64,_>("expires_at_ms")? <= now.get() { return Err(IdentityPersistenceError::RecoveryCompletionInvalid); }
            // A competing transaction may have committed while this request row was
            // waiting for its lock. Re-read the terminal fence after the lock so the
            // same request+grant pair is an exact replay, never a second receipt.
            if let Some(row) = sqlx::query("SELECT receipt_bytes,completion_digest FROM identity.history_recovery_completions_v2 WHERE identity_id=$1 AND request_id=$2").bind(&command.identity_id).bind(command.request_id).fetch_optional(&mut *tx.connection()).await? {
                if row.try_get::<Vec<u8>,_>("completion_digest")? != Sha256Digest::hash_domain(b"dirextalk.history-recovery.completion-command.v2\0", &command.exact_bytes).as_bytes() { return Err(IdentityPersistenceError::IdempotencyConflict); }
                return Ok(CompletionReceiptOutcome { created:false, receipt_bytes:row.try_get("receipt_bytes")? });
            }
            let delivery_value=dtx_wire::decode_deterministic_cbor(&extract_bytes(&command.exact_bytes,26)?).map_err(|_|IdentityPersistenceError::RecoveryCompletionInvalid)?; let delivery_fields=numbered(&delivery_value,12)?;
            let delivery_fact_id = uuid_field(&delivery_fields[1])?; let accepted_at = now;
            let grant_value = dtx_wire::decode_deterministic_cbor(&extract_bytes(&command.exact_bytes,22)?).map_err(|_|IdentityPersistenceError::RecoveryCompletionInvalid)?; let grant_fields = numbered(&grant_value,36)?;
            if uint_field(&grant_fields[0])? != 5 || text_field(&grant_fields[1])? != command.identity_id || uuid_field(&grant_fields[2])? != command.request_id || digest_field(&grant_fields[3])? != command.request_digest || digest_field(&grant_fields[4])? != command.manifest_digest || uuid_field(&grant_fields[5])? != command.catalog_id || uint_field(&grant_fields[6])? != command.catalog_generation || digest_field(&grant_fields[8])? != command.catalog_head_digest || digest_field(&grant_fields[9])? != command.catalog_root_digest || uint_field(&grant_fields[10])? != command.catalog_leaf_count || digest_field(&grant_fields[11])? != command.leaf_set_digest || uuid_field(&grant_fields[12])? != command.device_id || uint_field(&grant_fields[15])? != command.highwater || uint_field(&grant_fields[17])? != command.highwater_next || digest_field(&grant_fields[18])? != command.final_head_hash || digest_field(&grant_fields[20])? != command.preparation_digest || digest_field(&grant_fields[24])? != command.offer_digest || uuid_field(&grant_fields[29])? != delivery_fact_id { return Err(IdentityPersistenceError::RecoveryCompletionInvalid); }
            if uint_field(&delivery_fields[0])? != 2 || uuid_field(&delivery_fields[2])? != uuid_field(&grant_fields[25])? || uuid_field(&delivery_fields[3])? != uuid_field(&grant_fields[26])? || uint_field(&delivery_fields[4])? != uint_field(&grant_fields[28])? || digest_field(&delivery_fields[5])? != command.grant_digest || digest_field(&delivery_fields[6])? != command.offer_digest || uuid_field(&delivery_fields[7])? != command.request_id || uuid_field(&delivery_fields[8])? != command.device_id || uint_field(&delivery_fields[9])? < uint_field(&grant_fields[30])? || uint_field(&delivery_fields[9])? > uint_field(&grant_fields[31])? { return Err(IdentityPersistenceError::RecoveryCompletionInvalid); }
            let offer_value = dtx_wire::decode_deterministic_cbor(&extract_bytes(&command.exact_bytes,24)?).map_err(|_|IdentityPersistenceError::RecoveryCompletionInvalid)?; let offer_fields = numbered(&offer_value,16)?;
            if uint_field(&offer_fields[0])? != 3 || uuid_field(&offer_fields[1])? != command.request_id || digest_field(&offer_fields[2])? != command.request_digest || digest_field(&offer_fields[3])? != command.manifest_digest || uuid_field(&offer_fields[4])? != command.catalog_id || uint_field(&offer_fields[5])? != command.catalog_generation || digest_field(&offer_fields[6])? != command.catalog_head_digest || digest_field(&offer_fields[7])? != command.leaf_set_digest { return Err(IdentityPersistenceError::RecoveryCompletionInvalid); }
            let context_digest = digest_field(&extract_value(&command.exact_bytes,35)?)?;
            let ack = CanonicalValue::Map(vec![(k(1),u(2)),(k(2),CanonicalValue::Text(command.completion_id.to_string())),(k(3),CanonicalValue::Text(command.request_id.to_string())),(k(4),CanonicalValue::Text(delivery_fact_id.to_string())),(k(5),command.delivery_digest.to_canonical_value()),(k(6),command.offer_digest.to_canonical_value()),(k(7),context_digest.to_canonical_value()),(k(8),accepted_at.to_canonical_value())]);
            let ack_bytes=encode_deterministic_cbor(&ack).map_err(|_|IdentityPersistenceError::RecoveryCompletionInvalid)?; let complete=CanonicalValue::Map(vec![(k(1),u(2)),(k(2),CanonicalValue::Text(command.identity_id.clone())),(k(3),CanonicalValue::Text(command.completion_id.to_string())),(k(4),CanonicalValue::Text(command.request_id.to_string())),(k(5),CanonicalValue::Text(command.device_id.to_string())),(k(6),command.request_digest.to_canonical_value()),(k(7),context_digest.to_canonical_value()),(k(8),u(command.catalog_leaf_count)),(k(9),command.entry_root.to_canonical_value()),(k(10),accepted_at.to_canonical_value()),(k(11),u(1))]); let complete_bytes=encode_deterministic_cbor(&complete).map_err(|_|IdentityPersistenceError::RecoveryCompletionInvalid)?;
            let descriptor_value=dtx_wire::decode_deterministic_cbor(&descriptor.exact_bytes).map_err(|_|IdentityPersistenceError::RecoveryCompletionInvalid)?; let receipt=CanonicalValue::Map(vec![(k(1),u(2)),(k(2),CanonicalValue::Text(command.completion_id.to_string())),(k(3),CanonicalValue::Text(command.identity_id.clone())),(k(4),CanonicalValue::Text(command.device_id.to_string())),(k(5),u(command.highwater)),(k(6),CanonicalValue::Unsigned(command.highwater_next)),(k(7),command.final_head_hash.to_canonical_value()),(k(8),CanonicalValue::Text(command.catalog_id.to_string())),(k(9),u(command.catalog_generation)),(k(10),command.catalog_head_digest.to_canonical_value()),(k(11),u(command.catalog_leaf_count)),(k(12),command.leaf_set_digest.to_canonical_value()),(k(13),CanonicalValue::Text(command.request_id.to_string())),(k(14),command.request_digest.to_canonical_value()),(k(15),command.manifest_digest.to_canonical_value()),(k(16),command.grant_digest.to_canonical_value()),(k(17),command.offer_digest.to_canonical_value()),(k(18),CanonicalValue::Text(delivery_fact_id.to_string())),(k(19),command.delivery_digest.to_canonical_value()),(k(20),command.entry_root.to_canonical_value()),(k(21),u(command.catalog_leaf_count)),(k(22),ack),(k(23),Sha256Digest::hash_domain(b"dirextalk.history-recovery.offer-ack.v2\0",&ack_bytes).to_canonical_value()),(k(24),complete),(k(25),Sha256Digest::hash_domain(b"dirextalk.history-recovery.complete.v2\0",&complete_bytes).to_canonical_value()),(k(26),context_digest.to_canonical_value()),(k(27),CanonicalValue::Text(descriptor.key_id.to_string())),(k(28),descriptor.digest.to_canonical_value()),(k(29),u(descriptor.epoch)),(k(30),accepted_at.to_canonical_value()),(k(31),u(1))]); let receipt_bytes=encode_deterministic_cbor(&receipt).map_err(|_|IdentityPersistenceError::RecoveryCompletionInvalid)?; let receipt_digest=Sha256Digest::hash_domain(COMPLETION_RECEIPT_DOMAIN,&receipt_bytes); let wrapper_unsigned=CanonicalValue::Map(vec![(k(1),receipt.clone()),(k(2),receipt_digest.to_canonical_value()),(k(3),descriptor_value.clone()),(k(4),descriptor.digest.to_canonical_value())]); let mut sig_input=COMPLETION_RECEIPT_SIGNATURE_DOMAIN.to_vec(); sig_input.extend_from_slice(&encode_deterministic_cbor(&wrapper_unsigned).map_err(|_|IdentityPersistenceError::RecoveryCompletionInvalid)?); let signature=Ed25519Signature::from_bytes(signing_key.sign(&sig_input).to_bytes()); let signed=encode_deterministic_cbor(&CanonicalValue::Map(vec![(k(1),receipt),(k(2),receipt_digest.to_canonical_value()),(k(3),descriptor_value),(k(4),descriptor.digest.to_canonical_value()),(k(5),signature.to_canonical_value())])).map_err(|_|IdentityPersistenceError::RecoveryCompletionInvalid)?;
            let inserted = sqlx::query("INSERT INTO identity.history_recovery_completions_v2(identity_id,completion_id,candidate_device_id,request_id,grant_digest,idempotency_digest,completion_digest,completion_bytes,descriptor_digest,descriptor_bytes,receipt_digest,receipt_bytes,accepted_at_ms,created_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT DO NOTHING").bind(&command.identity_id).bind(command.completion_id).bind(command.device_id).bind(command.request_id).bind(command.grant_digest.as_bytes()).bind(command.idempotency_digest.as_bytes()).bind(Sha256Digest::hash_domain(b"dirextalk.history-recovery.completion-command.v2\0",&command.exact_bytes).as_bytes()).bind(&command.exact_bytes).bind(descriptor.digest.as_bytes()).bind(&descriptor.exact_bytes).bind(receipt_digest.as_bytes()).bind(&signed).bind(accepted_at.get()).bind(now.get()).execute(&mut *tx.connection()).await?;
            if inserted.rows_affected() == 0 {
                let row = sqlx::query("SELECT receipt_bytes,completion_digest FROM identity.history_recovery_completions_v2 WHERE identity_id=$1 AND completion_id=$2").bind(&command.identity_id).bind(command.completion_id).fetch_optional(&mut *tx.connection()).await?;
                let row = match row {
                    Some(row) => row,
                    None => sqlx::query("SELECT receipt_bytes,completion_digest FROM identity.history_recovery_completions_v2 WHERE identity_id=$1 AND request_id=$2").bind(&command.identity_id).bind(command.request_id).fetch_optional(&mut *tx.connection()).await?.ok_or(IdentityPersistenceError::CorruptData("completion conflict"))?,
                };
                if row.try_get::<Vec<u8>,_>("completion_digest")? != Sha256Digest::hash_domain(b"dirextalk.history-recovery.completion-command.v2\0", &command.exact_bytes).as_bytes() { return Err(IdentityPersistenceError::IdempotencyConflict); }
                return Ok(CompletionReceiptOutcome { created:false, receipt_bytes:row.try_get("receipt_bytes")? });
            }
            Ok(CompletionReceiptOutcome { created:true, receipt_bytes:signed })
        }.await;
        match result {
            Ok(value) => {
                tx.commit().await?;
                Ok(value)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }
    pub async fn ensure_descriptor(
        &self,
        store: &IdentityPgStore,
        origin: &str,
        config: CompletionSignerMetadata,
        signing_key: &SigningKey,
        now: UtcMillis,
    ) -> Result<CompletionKeyDescriptor, IdentityPersistenceError> {
        let mut tx = store.begin().await?;
        let result = self
            .ensure_descriptor_tx(tx.connection(), origin, config, signing_key, now)
            .await;
        match result {
            Ok(value) => {
                tx.commit().await?;
                Ok(value)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    pub async fn current_descriptor(
        &self,
        store: &IdentityPgStore,
    ) -> Result<Option<CompletionKeyDescriptor>, IdentityPersistenceError> {
        let mut tx = store.begin_readonly_repeatable().await?;
        let row = sqlx::query("SELECT d.descriptor_bytes,d.descriptor_digest FROM identity.history_recovery_completion_key_head h JOIN identity.history_recovery_completion_descriptors d ON d.descriptor_digest=h.descriptor_digest WHERE h.singleton=true").fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        row.map(|row| {
            decode_descriptor(
                row.try_get("descriptor_bytes")?,
                row.try_get("descriptor_digest")?,
            )
        })
        .transpose()
    }

    pub async fn historical_descriptor(
        &self,
        store: &IdentityPgStore,
        digest: Sha256Digest,
    ) -> Result<Option<CompletionKeyDescriptor>, IdentityPersistenceError> {
        let mut tx = store.begin_readonly_repeatable().await?;
        let row = sqlx::query("SELECT descriptor_bytes,descriptor_digest FROM identity.history_recovery_completion_descriptors WHERE descriptor_digest=$1").bind(digest.as_bytes()).fetch_optional(tx.connection()).await?;
        tx.commit().await?;
        row.map(|row| {
            decode_descriptor(
                row.try_get("descriptor_bytes")?,
                row.try_get("descriptor_digest")?,
            )
        })
        .transpose()
    }

    async fn ensure_descriptor_tx(
        &self,
        connection: &mut PgConnection,
        origin: &str,
        config: CompletionSignerMetadata,
        signing_key: &SigningKey,
        now: UtcMillis,
    ) -> Result<CompletionKeyDescriptor, IdentityPersistenceError> {
        completion_advisory_lock(
            connection,
            COMPLETION_DESCRIPTOR_HEAD_LOCK_DOMAIN,
            "singleton",
        )
        .await?;
        let descriptor = CompletionKeyDescriptor::from_signer(config, origin, signing_key)?;
        let descriptor_bytes = descriptor.exact_bytes.clone();
        let descriptor_digest = descriptor.digest;
        let existing = sqlx::query("SELECT descriptor_bytes,descriptor_digest,epoch,rollback_floor_epoch FROM identity.history_recovery_completion_descriptors WHERE descriptor_digest=$1").bind(descriptor_digest.as_bytes()).fetch_optional(&mut *connection).await?;
        let head = sqlx::query("SELECT d.descriptor_digest,d.epoch,d.rollback_floor_epoch FROM identity.history_recovery_completion_key_head h JOIN identity.history_recovery_completion_descriptors d ON d.descriptor_digest=h.descriptor_digest WHERE h.singleton=true").fetch_optional(&mut *connection).await?;
        let has_head = head.is_some();
        if let Some(row) = head {
            let current_digest = digest32(&row.try_get::<Vec<u8>, _>("descriptor_digest")?)?;
            let current_epoch = row.try_get::<i64, _>("epoch")? as u64;
            let current_floor = row.try_get::<i64, _>("rollback_floor_epoch")? as u64;
            let same = descriptor_digest == current_digest;
            if (!same
                && (config.epoch != current_epoch.saturating_add(1)
                    || config.previous_descriptor_digest != Some(current_digest)))
                || (same && config.epoch != current_epoch)
                || config.rollback_floor_epoch < current_floor
            {
                return Err(IdentityPersistenceError::RecoveryCompletionSignerMismatch);
            }
        }
        if let Some(row) = existing {
            if row.try_get::<Vec<u8>, _>("descriptor_bytes")? != descriptor_bytes
                || row.try_get::<i64, _>("epoch")? != config.epoch as i64
                || row.try_get::<i64, _>("rollback_floor_epoch")?
                    != config.rollback_floor_epoch as i64
            {
                return Err(IdentityPersistenceError::RecoveryCompletionSignerMismatch);
            }
            return decode_descriptor(descriptor_bytes, descriptor_digest.as_bytes().to_vec());
        } else if !has_head && (config.epoch != 1 || config.previous_descriptor_digest.is_some()) {
            return Err(IdentityPersistenceError::RecoveryCompletionSignerMismatch);
        }
        sqlx::query("INSERT INTO identity.history_recovery_completion_descriptors(descriptor_digest,key_id,public_key,epoch,rollback_floor_epoch,issued_at_ms,expires_at_ms,previous_descriptor_digest,signature,descriptor_bytes,created_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)").bind(descriptor_digest.as_bytes()).bind(config.key_id).bind(descriptor.public_key.as_bytes()).bind(config.epoch as i64).bind(config.rollback_floor_epoch as i64).bind(config.issued_at.get()).bind(config.expires_at.get()).bind(config.previous_descriptor_digest.map(|d| d.as_bytes().to_vec())).bind(descriptor.signature.as_bytes()).bind(&descriptor_bytes).bind(now.get()).execute(&mut *connection).await?;
        sqlx::query("INSERT INTO identity.history_recovery_completion_key_head(singleton,descriptor_digest,updated_at_ms) VALUES(true,$1,$2) ON CONFLICT(singleton) DO UPDATE SET descriptor_digest=EXCLUDED.descriptor_digest,updated_at_ms=EXCLUDED.updated_at_ms").bind(descriptor_digest.as_bytes()).bind(now.get()).execute(&mut *connection).await?;
        decode_descriptor(descriptor_bytes, descriptor_digest.as_bytes().to_vec())
    }
}

async fn completion_advisory_lock(
    connection: &mut PgConnection,
    domain: &str,
    canonical_coordinates: &str,
) -> Result<(), IdentityPersistenceError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("{domain}:{canonical_coordinates}"))
        .execute(&mut *connection)
        .await?;
    Ok(())
}

fn decode_descriptor(
    bytes: Vec<u8>,
    digest_bytes: Vec<u8>,
) -> Result<CompletionKeyDescriptor, IdentityPersistenceError> {
    if Sha256Digest::hash_domain(COMPLETION_DESCRIPTOR_DOMAIN, &bytes) != digest32(&digest_bytes)? {
        return Err(IdentityPersistenceError::CorruptData(
            "completion descriptor digest",
        ));
    }
    let value = dtx_wire::decode_deterministic_cbor(&bytes)
        .map_err(|_| IdentityPersistenceError::CorruptData("completion descriptor"))?;
    let CanonicalValue::Map(fields) = value else {
        return Err(IdentityPersistenceError::CorruptData(
            "completion descriptor",
        ));
    };
    if fields.len() != 10
        || fields
            .iter()
            .enumerate()
            .any(|(i, (k, _))| *k != CanonicalValue::Unsigned((i + 1) as u64))
    {
        return Err(IdentityPersistenceError::CorruptData(
            "completion descriptor",
        ));
    }
    let key_id: Uuid = match &fields[2].1 {
        CanonicalValue::Text(v) => v
            .parse()
            .map_err(|_| IdentityPersistenceError::CorruptData("completion descriptor"))?,
        _ => {
            return Err(IdentityPersistenceError::CorruptData(
                "completion descriptor",
            ));
        }
    };
    let public_key = match &fields[3].1 {
        CanonicalValue::Bytes(v) => {
            let raw: [u8; 32] = v
                .as_slice()
                .try_into()
                .map_err(|_| IdentityPersistenceError::CorruptData("completion descriptor"))?;
            SigningPublicKey::try_from(raw)
                .map_err(|_| IdentityPersistenceError::CorruptData("completion descriptor"))?
        }
        _ => {
            return Err(IdentityPersistenceError::CorruptData(
                "completion descriptor",
            ));
        }
    };
    let epoch = match fields[4].1 {
        CanonicalValue::Unsigned(v) => v,
        _ => {
            return Err(IdentityPersistenceError::CorruptData(
                "completion descriptor",
            ));
        }
    };
    let floor = match fields[5].1 {
        CanonicalValue::Unsigned(v) => v,
        _ => {
            return Err(IdentityPersistenceError::CorruptData(
                "completion descriptor",
            ));
        }
    };
    let issued = match fields[6].1 {
        CanonicalValue::Unsigned(v) => UtcMillis::new(v as i64)
            .map_err(|_| IdentityPersistenceError::CorruptData("completion descriptor"))?,
        _ => {
            return Err(IdentityPersistenceError::CorruptData(
                "completion descriptor",
            ));
        }
    };
    let expires = match fields[7].1 {
        CanonicalValue::Unsigned(v) => UtcMillis::new(v as i64)
            .map_err(|_| IdentityPersistenceError::CorruptData("completion descriptor"))?,
        _ => {
            return Err(IdentityPersistenceError::CorruptData(
                "completion descriptor",
            ));
        }
    };
    let previous = match &fields[8].1 {
        CanonicalValue::Null => None,
        v => Some(digest32(match v {
            CanonicalValue::Bytes(b) => b,
            _ => {
                return Err(IdentityPersistenceError::CorruptData(
                    "completion descriptor",
                ));
            }
        })?),
    };
    let signature = match &fields[9].1 {
        CanonicalValue::Bytes(v) => Ed25519Signature::from_bytes(
            v.as_slice()
                .try_into()
                .map_err(|_| IdentityPersistenceError::CorruptData("completion descriptor"))?,
        ),
        _ => {
            return Err(IdentityPersistenceError::CorruptData(
                "completion descriptor",
            ));
        }
    };
    let unsigned = dtx_wire::encode_deterministic_cbor(&CanonicalValue::Map(fields[..9].to_vec()))
        .map_err(|_| IdentityPersistenceError::CorruptData("completion descriptor"))?;
    let verify_key = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|_| IdentityPersistenceError::CorruptData("completion descriptor"))?;
    let signature_value = Signature::from_bytes(signature.as_bytes());
    verify_key
        .verify(
            &[COMPLETION_DESCRIPTOR_SIGNATURE_DOMAIN, unsigned.as_slice()].concat(),
            &signature_value,
        )
        .map_err(|_| IdentityPersistenceError::CorruptData("completion descriptor"))?;
    Ok(CompletionKeyDescriptor {
        key_id,
        public_key,
        epoch,
        rollback_floor_epoch: floor,
        issued_at: issued,
        expires_at: expires,
        previous_descriptor_digest: previous,
        signature,
        exact_bytes: bytes,
        digest: digest32(&digest_bytes)?,
    })
}

fn digest32(bytes: &[u8]) -> Result<Sha256Digest, IdentityPersistenceError> {
    Ok(Sha256Digest::from_bytes(bytes.try_into().map_err(
        |_| IdentityPersistenceError::CorruptData("completion digest"),
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_https_origin_is_exact_and_shared() {
        for value in [
            "https://identity.example/path",
            "https://identity.example?query",
            "https://identity.example#fragment",
            "https://user@identity.example",
            "https://identity.example:443",
            "HTTPS://identity.example",
            "https://identity.example/",
        ] {
            assert!(!is_canonical_https_origin(value), "accepted {value}");
        }
        assert!(is_canonical_https_origin("https://identity.example"));
        assert!(is_canonical_https_origin("https://127.0.0.1"));
        assert!(!is_canonical_https_origin("http://127.0.0.1"));
    }

    #[test]
    fn descriptor_is_canonical_and_signed_by_provisioned_key() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let metadata = CompletionSignerMetadata {
            key_id: Uuid::now_v7(),
            epoch: 1,
            rollback_floor_epoch: 1,
            issued_at: UtcMillis::new(1_000).unwrap(),
            expires_at: UtcMillis::new(2_000).unwrap(),
            previous_descriptor_digest: None,
        };
        let descriptor =
            CompletionKeyDescriptor::from_signer(metadata, "https://identity.example", &key)
                .unwrap();
        let decoded = decode_descriptor(
            descriptor.exact_bytes.clone(),
            descriptor.digest.as_bytes().to_vec(),
        )
        .unwrap();
        assert_eq!(decoded, descriptor);
    }
}
