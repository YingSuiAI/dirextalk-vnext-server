use dtx_domain::{InstallationId, JobEvidenceId, PublicSubjectId};
use dtx_wire::{
    ApiErrorCode, BoundedString, CanonicalDecode, CanonicalDecodeError, CanonicalValue, SafeUint,
    Sha256Digest, StableCode, UtcMillis, decode_struct_field, decode_struct_map,
};

const UUID_V7: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";
const IDENTITY_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

#[test]
fn generated_struct_helpers_require_exact_contiguous_fields() {
    let value = CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text(UUID_V7.to_owned()),
        ),
        (CanonicalValue::Unsigned(2), CanonicalValue::Bool(true)),
    ]);
    let fields = decode_struct_map(&value, 2).unwrap();
    let id: InstallationId = decode_struct_field(fields, 1).unwrap();
    let enabled: bool = decode_struct_field(fields, 2).unwrap();
    assert_eq!(id.to_string(), UUID_V7);
    assert!(enabled);

    assert_eq!(
        decode_struct_map(&value, 1),
        Err(CanonicalDecodeError::InvalidMapFields)
    );
    assert_eq!(
        decode_struct_map(
            &CanonicalValue::Map(vec![(CanonicalValue::Unsigned(2), CanonicalValue::Null,)]),
            1,
        ),
        Err(CanonicalDecodeError::InvalidMapFields)
    );
}

#[test]
fn primitive_decoders_enforce_declared_types_and_bounds() {
    assert_eq!(
        SafeUint::decode_canonical(&CanonicalValue::Unsigned(SafeUint::MAX)).unwrap(),
        SafeUint::new(SafeUint::MAX).unwrap()
    );
    assert_eq!(
        SafeUint::decode_canonical(&CanonicalValue::Unsigned(SafeUint::MAX + 1)),
        Err(CanonicalDecodeError::IntegerOutOfRange)
    );
    assert_eq!(
        u32::decode_canonical(&CanonicalValue::Unsigned(u64::from(u32::MAX))).unwrap(),
        u32::MAX
    );
    assert_eq!(
        bool::decode_canonical(&CanonicalValue::Unsigned(1)),
        Err(CanonicalDecodeError::TypeMismatch)
    );

    assert_eq!(
        StableCode::decode_canonical(&CanonicalValue::Text("valid_code.v1".to_owned()))
            .unwrap()
            .as_str(),
        "valid_code.v1"
    );
    assert_eq!(
        BoundedString::decode_canonical(&CanonicalValue::Text("summary".to_owned()))
            .unwrap()
            .as_str(),
        "summary"
    );
    assert_eq!(
        ApiErrorCode::decode_canonical(&CanonicalValue::Text("FUTURE_CODE".to_owned()))
            .unwrap()
            .as_str(),
        "FUTURE_CODE"
    );
    assert_eq!(
        PublicSubjectId::decode_canonical(&CanonicalValue::Text(IDENTITY_ID.to_owned()))
            .unwrap()
            .to_string(),
        IDENTITY_ID
    );

    assert_eq!(
        Sha256Digest::decode_canonical(&CanonicalValue::Bytes(vec![0x11; 32])).unwrap(),
        Sha256Digest::from_bytes([0x11; 32])
    );
    assert_eq!(
        UtcMillis::decode_canonical(&CanonicalValue::Negative(-1)).unwrap(),
        UtcMillis::new(-1).unwrap()
    );
}

#[test]
fn optional_and_evidence_list_decoders_are_bounded() {
    assert_eq!(
        Option::<UtcMillis>::decode_canonical(&CanonicalValue::Null).unwrap(),
        None
    );
    assert_eq!(
        Option::<UtcMillis>::decode_canonical(&CanonicalValue::Unsigned(1)).unwrap(),
        Some(UtcMillis::new(1).unwrap())
    );

    let evidence = CanonicalValue::Array(vec![CanonicalValue::Text(UUID_V7.to_owned())]);
    let decoded = Vec::<JobEvidenceId>::decode_canonical(&evidence).unwrap();
    assert_eq!(decoded[0].to_string(), UUID_V7);
    assert_eq!(
        Vec::<JobEvidenceId>::decode_canonical(&CanonicalValue::Array(vec![
            CanonicalValue::Text(
                UUID_V7.to_owned()
            );
            4097
        ])),
        Err(CanonicalDecodeError::ListTooLong)
    );
}
