use std::str::FromStr;

use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, ProtocolVersion, SafeUint, Sha256Digest,
    SigningPublicKey, UtcMillis, WireVersion, encode_deterministic_cbor,
};

const PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

#[test]
fn canonical_time_accepts_only_the_supported_epoch_millisecond_range() {
    let minimum = UtcMillis::new(-62_135_596_800_000).expect("year 1 boundary");
    let maximum = UtcMillis::new(253_402_300_799_999).expect("year 9999 boundary");

    assert_eq!(serde_json::to_string(&minimum).unwrap(), "-62135596800000");
    assert_eq!(
        serde_json::from_str::<UtcMillis>("253402300799999").unwrap(),
        maximum
    );
    assert!(UtcMillis::new(-62_135_596_800_001).is_err());
    assert!(UtcMillis::new(253_402_300_800_000).is_err());
    assert!(serde_json::from_str::<UtcMillis>("1.5").is_err());
}

#[test]
fn safe_uint_accepts_only_cross_platform_exact_json_integers() {
    const MAX_SAFE_UINT: u64 = 9_007_199_254_740_991;

    let maximum = SafeUint::new(MAX_SAFE_UINT).expect("2^53 - 1 is exact in web JSON");

    assert_eq!(maximum.get(), MAX_SAFE_UINT);
    assert_eq!(
        serde_json::to_string(&maximum).unwrap(),
        MAX_SAFE_UINT.to_string()
    );
    assert_eq!(
        serde_json::from_str::<SafeUint>(&MAX_SAFE_UINT.to_string()).unwrap(),
        maximum
    );
    assert_eq!(
        maximum.to_canonical_value(),
        CanonicalValue::Unsigned(MAX_SAFE_UINT)
    );
    assert_eq!(
        encode_deterministic_cbor(&maximum).unwrap(),
        [0x1b, 0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    assert!(SafeUint::new(MAX_SAFE_UINT + 1).is_err());
    assert!(serde_json::from_str::<SafeUint>(&(MAX_SAFE_UINT + 1).to_string()).is_err());
    assert!(serde_json::from_str::<SafeUint>("-1").is_err());
    assert!(serde_json::from_str::<SafeUint>("1.0").is_err());
}

#[test]
fn digest_json_is_lowercase_algorithm_tagged_and_fixed_length() {
    let digest = Sha256Digest::from_bytes([0xab; 32]);
    let expected = format!("sha256:{}", "ab".repeat(32));

    assert_eq!(digest.to_string(), expected);
    assert_eq!(
        serde_json::to_string(&digest).unwrap(),
        format!("\"{expected}\"")
    );
    assert_eq!(Sha256Digest::from_str(&expected).unwrap(), digest);
    assert!(Sha256Digest::from_str(&expected.to_uppercase()).is_err());
    assert!(Sha256Digest::from_str("sha256:ab").is_err());
    assert!(Sha256Digest::from_str(&format!("sha512:{}", "ab".repeat(32))).is_err());
}

#[test]
fn public_key_and_signature_json_are_unpadded_algorithm_tagged_base64url() {
    let key = SigningPublicKey::try_from(PUBLIC_KEY).expect("valid public key");
    let signature = Ed25519Signature::from_bytes([0_u8; 64]);

    assert_eq!(
        key.to_string(),
        "ed25519:11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    );
    assert_eq!(
        signature.to_string(),
        concat!(
            "ed25519:",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAAAAA"
        )
    );
    assert_eq!(SigningPublicKey::from_str(&key.to_string()).unwrap(), key);
    assert_eq!(
        Ed25519Signature::from_str(&signature.to_string()).unwrap(),
        signature
    );
    assert!(SigningPublicKey::from_str(&(key.to_string() + "=")).is_err());
    assert!(SigningPublicKey::try_from([0_u8; 32]).is_err());
    assert!(Ed25519Signature::from_str("ed25519:AA==").is_err());
}

#[test]
fn protocol_versions_have_strict_text_and_reject_unknown_fields() {
    let version = ProtocolVersion::new(1, 4);
    let wire = WireVersion::new(version, ProtocolVersion::new(1, 2));

    assert_eq!(serde_json::to_string(&version).unwrap(), "\"1.4\"");
    assert_eq!(
        serde_json::from_str::<ProtocolVersion>("\"1.4\"").unwrap(),
        version
    );
    assert!(serde_json::from_str::<ProtocolVersion>("\"01.4\"").is_err());
    assert!(serde_json::from_str::<ProtocolVersion>("\"1.04\"").is_err());
    assert!(serde_json::from_str::<ProtocolVersion>("\"1\"").is_err());

    let json = serde_json::to_string(&wire).unwrap();
    assert_eq!(serde_json::from_str::<WireVersion>(&json).unwrap(), wire);
    assert!(
        serde_json::from_str::<WireVersion>(
            r#"{"protocol":"1.4","minimum_reader":"1.2","unknown":true}"#,
        )
        .is_err()
    );
}
