use std::{fmt::Write, str::FromStr};

use dtx_domain::{AggregateId, EventId, InstallationId, TenantId};
use dtx_wire::{
    AgentInstallationChangedV1, BoundedString, CanonicalDecodeError, CanonicalEncode,
    CanonicalValue, Ed25519Signature, EventEnvelopeV1, EventIntegrityError, IntegrityVerification,
    ProtocolVersion, SafeUint, Sha256Digest, SigningPublicKey, StableCode, UnknownEventAction,
    UnsignedEventEnvelopeV1, UtcMillis, WireVersion, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};

const UUID_V7: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";
const PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

fn unsigned_event() -> UnsignedEventEnvelopeV1<AgentInstallationChangedV1> {
    UnsignedEventEnvelopeV1::new(
        WireVersion::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 0)),
        UUID_V7.parse::<EventId>().unwrap(),
        UUID_V7.parse::<TenantId>().unwrap(),
        UUID_V7.parse::<AggregateId>().unwrap(),
        SafeUint::new(3).unwrap(),
        SafeUint::new(42).unwrap(),
        UtcMillis::new(1_721_234_567_890).unwrap(),
        AgentInstallationChangedV1 {
            installation_id: UUID_V7.parse::<InstallationId>().unwrap(),
            descriptor_hash: Sha256Digest::from_bytes([0x11; 32]),
            state: StableCode::parse("installed").unwrap(),
            policy_revision: SafeUint::new(7).unwrap(),
        },
    )
    .expect("registered event constants are valid")
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn event_vector() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/v1/event-envelope.json"
    ))
    .expect("event vector is valid JSON")
}

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn hash_only_event_verifies_before_projection_use() {
    let envelope = EventEnvelopeV1::hash_only(unsigned_event()).unwrap();
    let verified = envelope.clone().verify(ProtocolVersion::new(1, 0)).unwrap();

    assert_eq!(verified.verification(), IntegrityVerification::HashOnly);
    assert_eq!(
        verified.event_type().as_str(),
        "agent.installation.changed.v1"
    );
    assert_eq!(verified.aggregate_type().as_str(), "agent_installation");

    let encoded = envelope.to_deterministic_cbor().unwrap();
    dtx_wire::validate_deterministic_cbor(&encoded).unwrap();
}

#[test]
fn hash_and_signed_envelopes_match_the_independent_golden_vector() {
    let vector = event_vector();
    let unsigned = unsigned_event();
    assert_eq!(
        hex(&encode_deterministic_cbor(&unsigned).unwrap()),
        vector["unsigned_cbor_hex"]
    );

    let hash_only = EventEnvelopeV1::hash_only(unsigned_event()).unwrap();
    assert_eq!(
        hex(&hash_only.to_deterministic_cbor().unwrap()),
        vector["hash_only_cbor_hex"]
    );

    let expected_signer =
        SigningPublicKey::from_str(vector["signer_public_key"].as_str().unwrap()).unwrap();
    let signature = Ed25519Signature::from_str(vector["signature"].as_str().unwrap()).unwrap();
    let signed_envelope =
        EventEnvelopeV1::signed(unsigned_event(), expected_signer, signature).unwrap();
    assert_eq!(
        hex(&signed_envelope.to_deterministic_cbor().unwrap()),
        vector["signed_cbor_hex"]
    );
    assert_eq!(
        signed_envelope
            .verify(ProtocolVersion::new(1, 0))
            .unwrap()
            .verification(),
        IntegrityVerification::Signed {
            signer: expected_signer
        }
    );
}

#[test]
fn typed_decoder_verifies_hash_only_and_signed_golden_envelopes() {
    let vector = event_vector();
    let hash_only = unhex(vector["hash_only_cbor_hex"].as_str().unwrap());
    let signed = unhex(vector["signed_cbor_hex"].as_str().unwrap());

    let hash_verified = EventEnvelopeV1::<AgentInstallationChangedV1>::decode_and_verify(
        &hash_only,
        ProtocolVersion::new(1, 0),
    )
    .unwrap();
    assert_eq!(
        hash_verified.verification(),
        IntegrityVerification::HashOnly
    );
    assert_eq!(hash_verified.payload().installation_id.to_string(), UUID_V7);
    assert_eq!(
        hash_verified.payload().descriptor_hash,
        Sha256Digest::from_bytes([0x11; 32])
    );
    assert_eq!(hash_verified.payload().state.as_str(), "installed");
    assert_eq!(
        hash_verified.payload().policy_revision,
        SafeUint::new(7).unwrap()
    );

    let decoded_signer =
        SigningPublicKey::from_str(vector["signer_public_key"].as_str().unwrap()).unwrap();
    assert_eq!(
        EventEnvelopeV1::<AgentInstallationChangedV1>::decode_and_verify(
            &signed,
            ProtocolVersion::new(1, 0),
        )
        .unwrap()
        .verification(),
        IntegrityVerification::Signed {
            signer: decoded_signer
        }
    );
    assert!(matches!(
        dtx_wire::decode_registered_event(&hash_only, ProtocolVersion::new(1, 0)).unwrap(),
        Some(dtx_wire::RegisteredEventEnvelope::AgentInstallationChangedV1(_))
    ));
}

fn rehash_hash_only(entries: &mut [(CanonicalValue, CanonicalValue)]) {
    let unsigned = CanonicalValue::Map(entries[..13].to_vec());
    let unsigned_bytes = encode_deterministic_cbor(&unsigned).unwrap();
    let digest = Sha256Digest::hash_domain(dtx_wire::EVENT_HASH_DOMAIN, &unsigned_bytes);
    entries[13].1 = CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text("sha256".to_owned()),
        ),
        (CanonicalValue::Unsigned(2), digest.to_canonical_value()),
    ]);
}

#[test]
fn typed_decoder_rejects_unknown_fields_wrong_metadata_unsafe_uint_and_tamper() {
    let vector = event_vector();
    let golden = unhex(vector["hash_only_cbor_hex"].as_str().unwrap());

    let CanonicalValue::Map(mut extra_payload) =
        dtx_wire::decode_deterministic_cbor(&golden).unwrap()
    else {
        unreachable!()
    };
    let CanonicalValue::Map(payload) = &mut extra_payload[12].1 else {
        unreachable!()
    };
    payload.push((CanonicalValue::Unsigned(5), CanonicalValue::Null));
    rehash_hash_only(&mut extra_payload);
    let extra_payload = encode_deterministic_cbor(&CanonicalValue::Map(extra_payload)).unwrap();
    assert_eq!(
        EventEnvelopeV1::<AgentInstallationChangedV1>::decode_and_verify(
            &extra_payload,
            ProtocolVersion::new(1, 0),
        ),
        Err(EventIntegrityError::PayloadDecode(
            CanonicalDecodeError::InvalidMapFields
        ))
    );

    let CanonicalValue::Map(mut extra_envelope) =
        dtx_wire::decode_deterministic_cbor(&golden).unwrap()
    else {
        unreachable!()
    };
    extra_envelope.push((CanonicalValue::Unsigned(15), CanonicalValue::Null));
    let extra_envelope = encode_deterministic_cbor(&CanonicalValue::Map(extra_envelope)).unwrap();
    assert_eq!(
        EventEnvelopeV1::<AgentInstallationChangedV1>::decode_and_verify(
            &extra_envelope,
            ProtocolVersion::new(1, 0),
        ),
        Err(EventIntegrityError::ContractMismatch)
    );

    let CanonicalValue::Map(mut wrong_type) = dtx_wire::decode_deterministic_cbor(&golden).unwrap()
    else {
        unreachable!()
    };
    wrong_type[10].1 = CanonicalValue::Text("other.changed.v1".to_owned());
    rehash_hash_only(&mut wrong_type);
    let wrong_type = encode_deterministic_cbor(&CanonicalValue::Map(wrong_type)).unwrap();
    assert_eq!(
        EventEnvelopeV1::<AgentInstallationChangedV1>::decode_and_verify(
            &wrong_type,
            ProtocolVersion::new(1, 0),
        ),
        Err(EventIntegrityError::ContractMismatch)
    );

    let CanonicalValue::Map(mut unsafe_uint) =
        dtx_wire::decode_deterministic_cbor(&golden).unwrap()
    else {
        unreachable!()
    };
    let CanonicalValue::Map(payload) = &mut unsafe_uint[12].1 else {
        unreachable!()
    };
    payload[3].1 = CanonicalValue::Unsigned(SafeUint::MAX + 1);
    rehash_hash_only(&mut unsafe_uint);
    let unsafe_uint = encode_deterministic_cbor(&CanonicalValue::Map(unsafe_uint)).unwrap();
    assert_eq!(
        EventEnvelopeV1::<AgentInstallationChangedV1>::decode_and_verify(
            &unsafe_uint,
            ProtocolVersion::new(1, 0),
        ),
        Err(EventIntegrityError::PayloadDecode(
            CanonicalDecodeError::IntegerOutOfRange
        ))
    );

    let mut tampered = golden;
    *tampered.last_mut().unwrap() ^= 1;
    assert_eq!(
        EventEnvelopeV1::<AgentInstallationChangedV1>::decode_and_verify(
            &tampered,
            ProtocolVersion::new(1, 0),
        ),
        Err(EventIntegrityError::DigestMismatch)
    );
}

#[test]
fn tampering_or_contract_metadata_mismatch_invalidates_the_envelope() {
    let envelope = EventEnvelopeV1::hash_only(unsigned_event()).unwrap();
    let mut tampered = serde_json::to_value(&envelope).unwrap();
    tampered["payload"]["state"] = serde_json::Value::String("revoked".to_owned());
    let tampered: EventEnvelopeV1<AgentInstallationChangedV1> =
        serde_json::from_value(tampered).unwrap();
    assert!(matches!(
        tampered.verify(ProtocolVersion::new(1, 0)),
        Err(EventIntegrityError::DigestMismatch)
    ));

    let mut wrong_type = serde_json::to_value(&envelope).unwrap();
    wrong_type["event_type"] = serde_json::Value::String("other.changed.v1".to_owned());
    let wrong_type: EventEnvelopeV1<AgentInstallationChangedV1> =
        serde_json::from_value(wrong_type).unwrap();
    assert!(matches!(
        wrong_type.verify(ProtocolVersion::new(1, 0)),
        Err(EventIntegrityError::ContractMismatch)
    ));
}

#[test]
fn typed_event_json_rejects_unknown_envelope_and_payload_fields() {
    let envelope = EventEnvelopeV1::hash_only(unsigned_event()).unwrap();
    let mut unknown_envelope = serde_json::to_value(&envelope).unwrap();
    unknown_envelope["unknown"] = serde_json::Value::Bool(true);
    assert!(
        serde_json::from_value::<EventEnvelopeV1<AgentInstallationChangedV1>>(unknown_envelope)
            .is_err()
    );

    let mut unknown_payload = serde_json::to_value(&envelope).unwrap();
    unknown_payload["payload"]["unknown"] = serde_json::Value::Bool(true);
    assert!(
        serde_json::from_value::<EventEnvelopeV1<AgentInstallationChangedV1>>(unknown_payload)
            .is_err()
    );
}

#[test]
fn signed_constructor_rejects_a_signature_that_does_not_match_the_event() {
    let signer = SigningPublicKey::try_from(PUBLIC_KEY).unwrap();
    let signature = Ed25519Signature::from_bytes([0_u8; 64]);

    assert!(matches!(
        EventEnvelopeV1::signed(unsigned_event(), signer, signature),
        Err(EventIntegrityError::InvalidSignature)
    ));
}

#[test]
fn v1_event_constructor_rejects_a_different_protocol_major() {
    let result = UnsignedEventEnvelopeV1::new(
        WireVersion::new(ProtocolVersion::new(2, 0), ProtocolVersion::new(2, 0)),
        UUID_V7.parse::<EventId>().unwrap(),
        UUID_V7.parse::<TenantId>().unwrap(),
        UUID_V7.parse::<AggregateId>().unwrap(),
        SafeUint::new(1).unwrap(),
        SafeUint::new(1).unwrap(),
        UtcMillis::new(1_721_234_567_890).unwrap(),
        AgentInstallationChangedV1 {
            installation_id: UUID_V7.parse::<InstallationId>().unwrap(),
            descriptor_hash: Sha256Digest::from_bytes([0x11; 32]),
            state: StableCode::parse("installed").unwrap(),
            policy_revision: SafeUint::new(1).unwrap(),
        },
    );

    assert_eq!(result, Err(EventIntegrityError::ContractMismatch));
}

fn opaque_hash_only_event(
    event_type: &str,
    schema_version: u64,
    required_reader_capability: Option<&str>,
    aggregate_revision: u64,
    stream_sequence: u64,
) -> Vec<u8> {
    let aggregate_type = match event_type {
        "connector.observed.v1" | "connector.observed.v2" => "connector",
        "agent.installation.changed.v1" | "agent.installation.changed.v2" => "agent_installation",
        _ => "future_aggregate",
    };
    opaque_hash_only_event_with_aggregate(
        event_type,
        aggregate_type,
        schema_version,
        required_reader_capability,
        aggregate_revision,
        stream_sequence,
    )
}

fn opaque_hash_only_event_with_aggregate(
    event_type: &str,
    aggregate_type: &str,
    schema_version: u64,
    required_reader_capability: Option<&str>,
    aggregate_revision: u64,
    stream_sequence: u64,
) -> Vec<u8> {
    let unsigned = CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            ProtocolVersion::new(1, 0).to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(2),
            ProtocolVersion::new(1, 0).to_canonical_value(),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(UUID_V7.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Text(UUID_V7.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Text(aggregate_type.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Text(UUID_V7.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Unsigned(aggregate_revision),
        ),
        (
            CanonicalValue::Unsigned(8),
            CanonicalValue::Unsigned(stream_sequence),
        ),
        (
            CanonicalValue::Unsigned(9),
            CanonicalValue::Unsigned(1_721_234_567_890),
        ),
        (
            CanonicalValue::Unsigned(10),
            CanonicalValue::Unsigned(schema_version),
        ),
        (
            CanonicalValue::Unsigned(11),
            CanonicalValue::Text(event_type.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(12),
            required_reader_capability.map_or(CanonicalValue::Null, |capability| {
                CanonicalValue::Text(capability.to_owned())
            }),
        ),
        (CanonicalValue::Unsigned(13), CanonicalValue::Map(vec![])),
    ]);
    let unsigned_bytes = encode_deterministic_cbor(&unsigned).unwrap();
    let digest = Sha256Digest::hash_domain(dtx_wire::EVENT_HASH_DOMAIN, &unsigned_bytes);
    let CanonicalValue::Map(mut entries) = unsigned else {
        unreachable!()
    };
    entries.push((
        CanonicalValue::Unsigned(14),
        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Text("sha256".to_owned()),
            ),
            (CanonicalValue::Unsigned(2), digest.to_canonical_value()),
        ]),
    ));
    encode_deterministic_cbor(&CanonicalValue::Map(entries)).unwrap()
}

fn opaque_signed_event(event_type: &str, schema_version: u64) -> Vec<u8> {
    let hash_only = opaque_hash_only_event(event_type, schema_version, None, 1, 2);
    let CanonicalValue::Map(mut entries) = dtx_wire::decode_deterministic_cbor(&hash_only).unwrap()
    else {
        unreachable!()
    };
    let unsigned = CanonicalValue::Map(entries[..13].to_vec());
    let unsigned_bytes = encode_deterministic_cbor(&unsigned).unwrap();
    let digest = Sha256Digest::hash_domain(dtx_wire::EVENT_HASH_DOMAIN, &unsigned_bytes);
    let signing_key = SigningKey::from_bytes(&[0x42; 32]);
    let signer = SigningPublicKey::try_from(signing_key.verifying_key().to_bytes()).unwrap();
    let signature = signing_key.sign(&dtx_wire::event_signature_input(digest));
    entries[13].1 = CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text("ed25519".to_owned()),
        ),
        (CanonicalValue::Unsigned(2), digest.to_canonical_value()),
        (CanonicalValue::Unsigned(3), signer.to_canonical_value()),
        (
            CanonicalValue::Unsigned(4),
            CanonicalValue::Bytes(signature.to_bytes().to_vec()),
        ),
    ]);
    encode_deterministic_cbor(&CanonicalValue::Map(entries)).unwrap()
}

#[test]
fn opaque_admission_rejects_an_empty_map_instead_of_trusting_caller_metadata() {
    let empty = encode_deterministic_cbor(&CanonicalValue::Map(vec![])).unwrap();

    assert_eq!(
        dtx_wire::OpaqueCanonicalEvent::admit(empty, ProtocolVersion::new(1, 0)),
        Err(EventIntegrityError::ContractMismatch)
    );

    let known_schema_with_empty_payload =
        opaque_hash_only_event("agent.installation.changed.v1", 1, None, 1, 2);
    assert_eq!(
        dtx_wire::OpaqueCanonicalEvent::admit(
            known_schema_with_empty_payload,
            ProtocolVersion::new(1, 0),
        ),
        Err(EventIntegrityError::ContractMismatch)
    );
}

#[test]
fn unknown_event_types_stop_even_when_the_envelope_claims_no_required_capability() {
    let bytes = opaque_hash_only_event("future.optional.changed.v1", 1, None, 1, 2);
    let admitted =
        dtx_wire::OpaqueCanonicalEvent::admit(bytes.clone(), ProtocolVersion::new(1, 0)).unwrap();

    assert_eq!(admitted.action(), UnknownEventAction::StopCursor);
    assert_eq!(admitted.as_bytes(), bytes);
}

#[test]
fn known_family_future_version_requires_both_registry_and_envelope_to_be_optional() {
    let optional_without_capability =
        opaque_hash_only_event("connector.observed.v2", 2, None, 1, 2);
    let optional_with_claimed_capability = opaque_hash_only_event(
        "connector.observed.v2",
        2,
        Some("attacker.claimed_required.v1"),
        1,
        2,
    );
    let required_with_spoofed_null =
        opaque_hash_only_event("agent.installation.changed.v2", 2, None, 1, 2);

    assert_eq!(
        dtx_wire::decode_registered_event(
            &optional_without_capability,
            ProtocolVersion::new(1, 0),
        )
        .unwrap(),
        None
    );
    assert_eq!(
        dtx_wire::OpaqueCanonicalEvent::admit(
            optional_without_capability,
            ProtocolVersion::new(1, 0),
        )
        .unwrap()
        .action(),
        UnknownEventAction::PreserveAndSkip
    );
    assert_eq!(
        dtx_wire::OpaqueCanonicalEvent::admit(
            optional_with_claimed_capability,
            ProtocolVersion::new(1, 0),
        )
        .unwrap()
        .action(),
        UnknownEventAction::StopCursor
    );
    assert_eq!(
        dtx_wire::OpaqueCanonicalEvent::admit(
            required_with_spoofed_null,
            ProtocolVersion::new(1, 0),
        )
        .unwrap()
        .action(),
        UnknownEventAction::StopCursor
    );

    let wrong_aggregate = opaque_hash_only_event_with_aggregate(
        "connector.observed.v2",
        "attacker_aggregate",
        2,
        None,
        1,
        2,
    );
    assert_eq!(
        dtx_wire::OpaqueCanonicalEvent::admit(wrong_aggregate, ProtocolVersion::new(1, 0)),
        Err(EventIntegrityError::ContractMismatch)
    );

    let mismatched_type_suffix = opaque_hash_only_event("connector.observed.v1", 2, None, 1, 2);
    assert_eq!(
        dtx_wire::OpaqueCanonicalEvent::admit(mismatched_type_suffix, ProtocolVersion::new(1, 0),),
        Err(EventIntegrityError::ContractMismatch)
    );
}

#[test]
fn opaque_admission_rejects_zero_sequences_and_tampered_integrity() {
    let zero_revision = opaque_hash_only_event("future.changed.v1", 1, None, 0, 2);
    assert_eq!(
        dtx_wire::OpaqueCanonicalEvent::admit(zero_revision, ProtocolVersion::new(1, 0)),
        Err(EventIntegrityError::ContractMismatch)
    );
    let unsafe_sequence =
        opaque_hash_only_event("future.changed.v1", 1, None, 1, (1_u64 << 53) + 1);
    assert_eq!(
        dtx_wire::OpaqueCanonicalEvent::admit(unsafe_sequence, ProtocolVersion::new(1, 0)),
        Err(EventIntegrityError::ContractMismatch)
    );

    let mut tampered = opaque_hash_only_event("future.changed.v1", 1, None, 1, 2);
    let last = tampered.last_mut().expect("envelope is nonempty");
    *last ^= 1;
    assert_eq!(
        dtx_wire::OpaqueCanonicalEvent::admit(tampered, ProtocolVersion::new(1, 0)),
        Err(EventIntegrityError::DigestMismatch)
    );
}

#[test]
fn opaque_admission_strictly_verifies_ed25519_before_retaining_bytes() {
    let signed = opaque_signed_event("future.signed.changed.v1", 1);
    let admitted =
        dtx_wire::OpaqueCanonicalEvent::admit(signed.clone(), ProtocolVersion::new(1, 0)).unwrap();
    let IntegrityVerification::Signed { signer } = admitted.verification() else {
        panic!("signed envelope must establish signed verification")
    };
    assert_eq!(admitted.as_bytes(), signed);
    assert_eq!(signer.as_bytes().len(), 32);

    let mut tampered_signature = signed;
    *tampered_signature.last_mut().unwrap() ^= 1;
    assert_eq!(
        dtx_wire::OpaqueCanonicalEvent::admit(tampered_signature, ProtocolVersion::new(1, 0),),
        Err(EventIntegrityError::InvalidSignature)
    );
}

#[test]
fn stable_codes_and_bounded_strings_reject_ambiguous_or_unbounded_text() {
    assert!(StableCode::parse("connector.online_v1").is_ok());
    assert!(StableCode::parse("Connector.Online").is_err());
    assert!(StableCode::parse("connector..online").is_err());
    assert!(BoundedString::new("visible summary").is_ok());
    assert!(BoundedString::new("line\nbreak").is_err());
    assert!(BoundedString::new("x".repeat(1025)).is_err());
}
