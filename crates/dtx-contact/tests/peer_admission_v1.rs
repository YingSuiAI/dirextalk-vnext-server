use dtx_contact::{
    ContactError, PeerAdmissionEnvelopeV1, PeerAdmissionOfferV1, PeerAdmissionWelcomeV1,
};
use dtx_wire::{SigningPublicKey, UtcMillis};
use serde_json::Value;

fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/conversation-admission/v1/conversation-admission-v1.json"
    ))
    .expect("valid frozen V30 vector")
}

fn bytes(vector: &Value, field: &str) -> Vec<u8> {
    let hex = vector[field].as_str().expect("hex vector field");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("lower hex"))
        .collect()
}

#[test]
fn frozen_offer_welcome_and_opaque_envelope_are_byte_exact() {
    let vector = vector();
    let envelope_exact = bytes(&vector, "prefixed_envelope_hex");
    let envelope = PeerAdmissionEnvelopeV1::decode(&envelope_exact).expect("opaque envelope");
    assert_eq!(envelope.encode().unwrap(), envelope_exact);
    assert_eq!(
        envelope.aad().unwrap(),
        bytes(&vector, "aad_canonical_cbor_hex")
    );
    assert_eq!(envelope.sealed(), &[0xaa; 48]);

    let owner_key_bytes: [u8; 32] = bytes(&vector, "owner_public_key_hex")
        .try_into()
        .expect("32-byte key");
    let owner_key = SigningPublicKey::try_from(owner_key_bytes).expect("valid Ed25519 key");
    let offer_exact = bytes(&vector, "offer_canonical_cbor_hex");
    let offer = PeerAdmissionOfferV1::decode(&offer_exact).expect("signed offer");
    assert_eq!(offer.encode().unwrap(), offer_exact);
    offer.verify_owner_signature(owner_key).unwrap();
    assert!(offer.is_usable_at(UtcMillis::new(1_300_000).unwrap()));

    let welcome_exact = bytes(&vector, "welcome_canonical_cbor_hex");
    let welcome = PeerAdmissionWelcomeV1::decode(&welcome_exact).expect("signed welcome");
    assert_eq!(welcome.encode().unwrap(), welcome_exact);
    welcome.verify_owner_signature(owner_key).unwrap();
    assert!(welcome.is_usable_at(UtcMillis::new(1_500_000).unwrap()));
}

#[test]
fn noncanonical_origin_and_prefix_fail_closed() {
    let vector = vector();
    let offer = PeerAdmissionOfferV1::decode(&bytes(&vector, "offer_canonical_cbor_hex"))
        .expect("signed offer");
    let mut invalid = offer.unsigned().clone();
    invalid.group_origin = "https://group.example/".to_owned();
    assert_eq!(
        PeerAdmissionOfferV1::new(invalid, offer.signature()),
        Err(ContactError::Invalid)
    );

    let mut envelope = bytes(&vector, "prefixed_envelope_hex");
    envelope[0] ^= 1;
    assert_eq!(
        PeerAdmissionEnvelopeV1::decode(&envelope),
        Err(ContactError::Invalid)
    );
}
