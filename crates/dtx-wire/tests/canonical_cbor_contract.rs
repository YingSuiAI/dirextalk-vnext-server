use std::fmt::Write;

use dtx_wire::{
    CanonicalCborError, CanonicalEncode, CanonicalValue, PLAN_HASH_DOMAIN,
    encode_deterministic_cbor, plan_hash, validate_deterministic_cbor,
};
use proptest::prelude::*;
use serde::Deserialize;

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

#[test]
fn map_keys_follow_rfc_8949_bytewise_lexicographic_order() {
    let value = CanonicalValue::Map(vec![
        (CanonicalValue::Bool(false), CanonicalValue::Null),
        (
            CanonicalValue::Array(vec![CanonicalValue::Negative(-1)]),
            CanonicalValue::Null,
        ),
        (CanonicalValue::Text("aa".to_owned()), CanonicalValue::Null),
        (CanonicalValue::Unsigned(100), CanonicalValue::Null),
        (
            CanonicalValue::Array(vec![CanonicalValue::Unsigned(100)]),
            CanonicalValue::Null,
        ),
        (CanonicalValue::Negative(-1), CanonicalValue::Null),
        (CanonicalValue::Text("z".to_owned()), CanonicalValue::Null),
        (CanonicalValue::Unsigned(10), CanonicalValue::Null),
    ]);

    let encoded = encode_deterministic_cbor(&value).expect("valid deterministic map");

    assert_eq!(
        hex(&encoded),
        "a80af61864f620f6617af6626161f6811864f68120f6f4f6"
    );
    validate_deterministic_cbor(&encoded).expect("encoder output validates");
}

#[test]
fn encoder_is_independent_of_map_insertion_order() {
    let left = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(2), CanonicalValue::Bool(true)),
        (CanonicalValue::Unsigned(1), CanonicalValue::Bool(false)),
    ]);
    let right = CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Bool(false)),
        (CanonicalValue::Unsigned(2), CanonicalValue::Bool(true)),
    ]);

    assert_eq!(
        encode_deterministic_cbor(&left).unwrap(),
        encode_deterministic_cbor(&right).unwrap()
    );
}

#[test]
fn map_key_sorting_obeys_the_shared_encoded_byte_budget() {
    let oversized_pending_keys = CanonicalValue::Map(
        (0..4096)
            .map(|_| (CanonicalValue::Bytes(vec![0_u8; 300]), CanonicalValue::Null))
            .collect(),
    );

    assert_eq!(
        encode_deterministic_cbor(&oversized_pending_keys),
        Err(CanonicalCborError::InputTooLarge)
    );
}

#[test]
fn strict_validator_rejects_ambiguous_or_unsupported_encodings() {
    assert!(matches!(
        validate_deterministic_cbor(&[0x18, 0x17]),
        Err(CanonicalCborError::NonPreferredArgument)
    ));
    assert!(matches!(
        validate_deterministic_cbor(&[0x9f, 0x01, 0xff]),
        Err(CanonicalCborError::IndefiniteLength)
    ));
    assert!(matches!(
        validate_deterministic_cbor(&[0xa2, 0x02, 0x00, 0x01, 0x00]),
        Err(CanonicalCborError::MapKeyOrder)
    ));
    assert!(matches!(
        validate_deterministic_cbor(&[0xa2, 0x01, 0x00, 0x01, 0x01]),
        Err(CanonicalCborError::DuplicateMapKey)
    ));
    assert!(matches!(
        validate_deterministic_cbor(&[0xf9, 0x3c, 0x00]),
        Err(CanonicalCborError::FloatingPointNotAllowed)
    ));
    assert!(matches!(
        validate_deterministic_cbor(&[0xc0, 0x00]),
        Err(CanonicalCborError::TagNotAllowed)
    ));
    assert!(matches!(
        validate_deterministic_cbor(&[0x61, 0xff]),
        Err(CanonicalCborError::InvalidUtf8)
    ));
    assert!(matches!(
        validate_deterministic_cbor(&[0x01, 0x02]),
        Err(CanonicalCborError::TrailingBytes)
    ));
}

#[test]
fn missing_null_and_unicode_normalization_remain_distinct() {
    let missing = CanonicalValue::Map(vec![]);
    let explicit_null =
        CanonicalValue::Map(vec![(CanonicalValue::Unsigned(1), CanonicalValue::Null)]);
    let nfc = CanonicalValue::Text("é".to_owned());
    let nfd = CanonicalValue::Text("e\u{301}".to_owned());

    assert_ne!(
        encode_deterministic_cbor(&missing).unwrap(),
        encode_deterministic_cbor(&explicit_null).unwrap()
    );
    assert_ne!(
        encode_deterministic_cbor(&nfc).unwrap(),
        encode_deterministic_cbor(&nfd).unwrap()
    );
}

#[derive(Deserialize)]
struct PlanVector {
    version: u16,
    body: PlanBody,
    canonical_cbor_hex: String,
    plan_hash: String,
}

#[derive(Deserialize)]
struct PlanBody {
    job_id: String,
    revision: u64,
    objective_hash_hex: String,
    region: String,
    resources: Vec<PlanResource>,
    max_cost: PlanCost,
    max_runtime_ms: u64,
    artifact_policy: String,
    verification_policy: String,
}

#[derive(Deserialize)]
struct PlanResource {
    logical_name: String,
    lifecycle: String,
    kind: String,
}

#[derive(Deserialize)]
struct PlanCost {
    currency: String,
    minor_units: u64,
}

impl CanonicalEncode for PlanBody {
    fn to_canonical_value(&self) -> CanonicalValue {
        let objective_hash = (0..self.objective_hash_hex.len())
            .step_by(2)
            .map(|index| {
                u8::from_str_radix(&self.objective_hash_hex[index..index + 2], 16).unwrap()
            })
            .collect();
        let resources = self
            .resources
            .iter()
            .map(|resource| {
                CanonicalValue::Map(vec![
                    (
                        CanonicalValue::Unsigned(1),
                        CanonicalValue::Text(resource.logical_name.clone()),
                    ),
                    (
                        CanonicalValue::Unsigned(2),
                        CanonicalValue::Text(resource.lifecycle.clone()),
                    ),
                    (
                        CanonicalValue::Unsigned(3),
                        CanonicalValue::Text(resource.kind.clone()),
                    ),
                ])
            })
            .collect();

        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                CanonicalValue::Text(self.job_id.clone()),
            ),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Unsigned(self.revision),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Bytes(objective_hash),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Text(self.region.clone()),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Array(resources),
            ),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Map(vec![
                    (
                        CanonicalValue::Unsigned(1),
                        CanonicalValue::Text(self.max_cost.currency.clone()),
                    ),
                    (
                        CanonicalValue::Unsigned(2),
                        CanonicalValue::Unsigned(self.max_cost.minor_units),
                    ),
                ]),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Unsigned(self.max_runtime_ms),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Text(self.artifact_policy.clone()),
            ),
            (
                CanonicalValue::Unsigned(9),
                CanonicalValue::Text(self.verification_policy.clone()),
            ),
        ])
    }
}

#[test]
fn plan_hash_matches_the_independent_cross_language_fixture() {
    let vector: PlanVector = serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/v1/plan-hash.json"
    ))
    .expect("plan vector is valid JSON");
    assert_eq!(vector.version, 1);

    let encoded = encode_deterministic_cbor(&vector.body).expect("fixture is canonical encodable");
    assert_eq!(hex(&encoded), vector.canonical_cbor_hex);
    assert_eq!(PLAN_HASH_DOMAIN, b"dirextalk.job-plan.v1\0");
    assert_eq!(
        plan_hash(&vector.body).unwrap().to_string(),
        vector.plan_hash
    );
}

proptest! {
    #[test]
    fn every_unsigned_integer_uses_a_valid_preferred_encoding(value in any::<u64>()) {
        let encoded = encode_deterministic_cbor(&CanonicalValue::Unsigned(value)).unwrap();
        prop_assert!(validate_deterministic_cbor(&encoded).is_ok());
    }

    #[test]
    fn every_encodable_restricted_value_is_accepted_by_the_validator(
        value in canonical_value_strategy()
    ) {
        let encoded = encode_deterministic_cbor(&value).expect("strategy stays within limits");
        prop_assert_eq!(validate_deterministic_cbor(&encoded), Ok(()));
    }
}

fn canonical_value_strategy() -> impl Strategy<Value = CanonicalValue> {
    let leaf = prop_oneof![
        any::<u64>().prop_map(CanonicalValue::Unsigned),
        (i64::MIN..=-1_i64).prop_map(CanonicalValue::Negative),
        prop::collection::vec(any::<u8>(), 0..32).prop_map(CanonicalValue::Bytes),
        "[^\\p{C}]{0,32}".prop_map(CanonicalValue::Text),
        any::<bool>().prop_map(CanonicalValue::Bool),
        Just(CanonicalValue::Null),
    ];

    leaf.prop_recursive(6, 128, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(CanonicalValue::Array),
            prop::collection::vec(inner, 0..8).prop_map(|values| {
                CanonicalValue::Map(
                    values
                        .into_iter()
                        .enumerate()
                        .map(|(index, value)| (CanonicalValue::Unsigned(index as u64), value))
                        .collect(),
                )
            }),
        ]
    })
}

#[test]
fn encoder_and_validator_enforce_the_same_total_item_budget() {
    const OUTER_ENTRIES: usize = 4096;
    const INNER_ENTRIES: usize = 16;

    let value = CanonicalValue::Array(
        (0..OUTER_ENTRIES)
            .map(|_| CanonicalValue::Array(vec![CanonicalValue::Null; INNER_ENTRIES]))
            .collect(),
    );
    assert_eq!(
        encode_deterministic_cbor(&value),
        Err(CanonicalCborError::ContainerTooLarge)
    );

    // 0x99 0x1000 is a preferred definite array of 4096 entries; every entry
    // is a definite array of 16 nulls. It is below the byte and per-container
    // limits but exceeds the shared 65,536-item budget.
    let mut encoded = vec![0x99, 0x10, 0x00];
    for _ in 0..OUTER_ENTRIES {
        encoded.push(0x90);
        encoded.extend(std::iter::repeat_n(0xf6, INNER_ENTRIES));
    }
    assert_eq!(
        validate_deterministic_cbor(&encoded),
        Err(CanonicalCborError::ContainerTooLarge)
    );
}
