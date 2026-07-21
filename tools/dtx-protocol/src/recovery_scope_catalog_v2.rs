use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::Path,
};

use dtx_identity_log::{IDENTITY_LOG_WIRE_VERSION, IdentityLogEventPayloadV1, IdentityLogEventV1};
use dtx_wire::{
    CanonicalValue, decode_deterministic_cbor, decode_deterministic_cbor_with_limit,
    encode_deterministic_cbor, encode_deterministic_cbor_with_limit,
};
use ed25519_dalek::{Signature, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, PskBundle, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::ProtocolToolError;

const CDDL_PATH: &str = "protocol/cddl/recovery-scope-catalog/v2/recovery-scope-catalog-v2.cddl";
const OPENAPI_PATH: &str = "protocol/openapi/recovery-scope-catalog/v2/openapi.yaml";
const VECTOR_PATH: &str =
    "protocol/test-vectors/recovery-scope-catalog/v2/recovery-scope-catalog-v2.json";
const OPENAPI_ROUTE: &str = "/v2/recovery-scope-catalogs/{catalog_id}";
const OPENAPI_OPERATION: &str = "/paths/~1v2~1recovery-scope-catalogs~1{catalog_id}/put";
const PREPARATION_ROUTE: &str = "/v3/devices/enroll/catalog-preparations";
const PREPARATION_OPERATION: &str = "/paths/~1v3~1devices~1enroll~1catalog-preparations/post";
const STATUS_ROUTE: &str = "/v3/devices/enroll/catalog-preparations/{request_id}";
const STATUS_OPERATION: &str =
    "/paths/~1v3~1devices~1enroll~1catalog-preparations~1{request_id}/get";
const PROVIDER_RESPONSE_ROUTE: &str =
    "/v3/devices/enroll/catalog-preparations/{request_id}/provider-response";
const PROVIDER_RESPONSE_OPERATION: &str =
    "/paths/~1v3~1devices~1enroll~1catalog-preparations~1{request_id}~1provider-response/put";
const REQUEST_MEDIA: &str = "application/vnd.dirextalk.recovery-scope-catalog.v2+cbor";
const RESPONSE_MEDIA: &str = "application/vnd.dirextalk.recovery-scope-catalog-head.v2+cbor";
const PREPARATION_MEDIA: &str =
    "application/vnd.dirextalk.recovery-scope-catalog-preparation.v2+cbor";
const PREPARATION_RECEIPT_MEDIA: &str =
    "application/vnd.dirextalk.recovery-scope-catalog-preparation-receipt.v2+cbor";
const PROVIDER_RESPONSE_MEDIA: &str =
    "application/vnd.dirextalk.recovery-scope-catalog-provider-response.v2+cbor";
const PROVIDER_RESPONSE_RECEIPT_MEDIA: &str =
    "application/vnd.dirextalk.recovery-scope-catalog-provider-response-receipt.v2+cbor";
const STATUS_MEDIA: &str = "application/vnd.dirextalk.recovery-scope-catalog-status.v2+cbor";
const MAX_CATALOG_LEAVES: usize = 1_023;
const MAX_PROOF_SIBLINGS: usize = 10;
const MAX_CIPHERTEXT_BYTES: usize = 1_048_576;
const MIN_CATALOG_OPENING_BYTES: usize = 1_019;
const MIN_CATALOG_PLAINTEXT_OVERHEAD_BYTES: usize = 147;
const CATALOG_INDEX_OCCURRENCES_PER_OPENING: usize = 3;
const CATALOG_ONE_BYTE_INDEX_MAXIMUM: usize = 23;
const CATALOG_TWO_BYTE_INDEX_MAXIMUM: usize = 255;
const CATALOG_MIDDLE_INDEX_COUNT: usize = 232;
const CATALOG_MIDDLE_INDEX_EXTRA_BYTES: usize = 3;
const CATALOG_LARGE_INDEX_COUNT: usize = 768;
const CATALOG_LARGE_INDEX_EXTRA_BYTES: usize = 6;
const MAX_MINIMAL_CATALOG_BYTES: usize = 1_047_888;
const MIN_OVERFLOW_CATALOG_BYTES: usize = 1_048_913;
const MAX_SIGNED_CATALOG_HEAD_BYTES: usize = 466;
const MAX_CATALOG_UPLOAD_BODY_BYTES: usize = 1_049_050;
// Defensive HTTP decoder headroom. This is deliberately greater than the
// exact valid Catalog upload body and is not a valid-body allowance.
const MAX_ENVELOPE_BYTES: usize = 1_065_984;
const MAX_PREPARATION_BODY_BYTES: usize = 533;
const MAX_PROVIDER_PACKAGE_BYTES: usize = 1_049_457;
const MAX_HPKE_CIPHERTEXT_BYTES: usize = 1_049_473;
const MAX_HPKE_ENCODED_ENVELOPE_BYTES: usize = 1_049_517;
const MAX_DEVICE_ADD_BYTES: usize = 533;
const MAX_PROVIDER_RESPONSE_BODY_BYTES: usize = 1_050_929;
const MAX_STATUS_BODY_BYTES: usize = 1_050_986;

const MEMBERSHIP_RECEIPT_DOMAIN: &[u8] = b"dirextalk.recovery-scope-membership-receipt.v1\0";
const RECOVERY_SCOPE_DOMAIN: &[u8] = b"dirextalk.recovery-scope.v1\0";
const PRIVATE_BODY_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-private-body.v2\0";
const PRIVATE_BODY_DOMAIN_WITHOUT_NUL: &[u8] = b"dirextalk.recovery-scope-catalog-private-body.v2";
const OPENING_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-opening.v2\0";
const VERIFIER_BINDING_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-verifier-binding.v1\0";
const VERIFIER_BINDING_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-verifier-binding-signature.v1\0";
const VERIFIER_BINDING_SIGNATURE_DOMAIN_WITHOUT_NUL: &[u8] =
    b"dirextalk.recovery-scope-catalog-verifier-binding-signature.v1";
const COMPLETION_VERIFIER_DESCRIPTOR_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-completion-verifier-descriptor.v1\0";
const COMPLETION_VERIFIER_DESCRIPTOR_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-completion-verifier-descriptor-signature.v1\0";
const COMPLETION_EVIDENCE_POP_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-completion-evidence-pop.v1\0";
const COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-completion-evidence-origin-authorization.v1\0";
const COMPLETION_EVIDENCE_AUTHORIZATION_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-completion-evidence-authorization-digest.v1\0";
const LEAF_COMMITMENT_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-leaf-commitment.v2\0";
const CIPHERTEXT_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-ciphertext.v2\0";
const HEAD_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-head.v2\0";
const HEAD_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-head-signature.v2\0";
const MERKLE_NODE_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-node.v2\0";
const HPKE_INFO: &str = "dirextalk.recovery-scope-catalog-handoff-hpke.v2\0";
const RESPONSE_CAPABILITY_DOMAIN: &[u8] = b"dirextalk.recovery-response-capability.v1\0";
const RECIPIENT_KEY_DOMAIN: &[u8] = b"dirextalk.recovery-recipient-key.v1\0";
const DEVICE_HISTORY_AUTHORITY_ID_DOMAIN: &[u8] = b"dirextalk.device-history-authority-id.v1\0";
const IDENTITY_DEVICE_ADD_DOMAIN: &[u8] = b"dirextalk.identity-device-add.v1\0";
const PREPARATION_IDEMPOTENCY_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-preparation-idempotency.v2\0";
const RESPONSE_IDEMPOTENCY_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-response-idempotency.v2\0";
const PREPARATION_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-preparation-signature.v2\0";
const PREPARATION_DIGEST_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-preparation-digest.v2\0";
const PROVIDER_PACKAGE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-package.v2\0";
const PROVIDER_AAD_DOMAIN: &[u8] = b"dirextalk.recovery-scope-catalog-handoff-provider-aad.v2\0";
const PROVIDER_ENVELOPE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-envelope.v2\0";
const PROVIDER_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-signature.v2\0";
const PROVIDER_AUTHORITY_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-authority-signature.v2\0";
const PROVIDER_RESPONSE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-response.v2\0";
const PREPARATION_ALTERNATE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-preparation-signature.v2.alternate\0";
const PROVIDER_ALTERNATE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-signature.v2.alternate\0";
const PROVIDER_AUTHORITY_ALTERNATE_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.recovery-scope-catalog-handoff-provider-authority-signature.v2.alternate\0";
const ORIGIN_IDENTITY_SNAPSHOT_SIGNATURE_DOMAIN: &[u8] =
    b"dirextalk.origin-authenticated-current-identity-snapshot-signature.v1\0";
const PUBLIC_TEST_PSK: [u8; 32] = [0x91; 32];
const PUBLIC_TEST_PSK_ID: &[u8] = b"catalog-v2-b2a-public-test-psk";
// RFC 7748 section 5.2's public test scalar. It is deliberately fixed and is
// not key-generation material or a credential.
const X25519_PUBLIC_VALIDATION_SCALAR: [u8; 32] = [
    0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
    0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
];
// Public deterministic trust anchor for the signed vector-only current-state
// snapshots. No signing material is retained in the repository.
const ORIGIN_IDENTITY_SNAPSHOT_AUTHENTICATION_PUBLIC_KEY: [u8; 32] = [
    0xc9, 0x57, 0x1e, 0xeb, 0x4a, 0xa9, 0xde, 0x11, 0x59, 0x85, 0x8b, 0xc6, 0xa3, 0xd4, 0xa6, 0x26,
    0xc4, 0xf4, 0x84, 0x5e, 0x8e, 0xeb, 0xd5, 0xf5, 0x54, 0xb2, 0xec, 0x0f, 0x50, 0xc6, 0x88, 0x60,
];

const CORE_RULE_FIELD_COUNTS: &[(&str, usize)] = &[
    ("recovery-scope-catalog-private-body-v2", 10),
    (
        "recovery-scope-catalog-completion-verifier-descriptor-unsigned-v1",
        7,
    ),
    (
        "recovery-scope-catalog-completion-verifier-descriptor-v1",
        8,
    ),
    (
        "recovery-scope-catalog-completion-verifier-binding-unsigned-v1",
        22,
    ),
    ("recovery-scope-catalog-completion-verifier-binding-v1", 23),
    ("recovery-scope-catalog-leaf-commitment-v2", 12),
    ("recovery-scope-catalog-opening-v2", 3),
    ("recovery-scope-catalog-plaintext-v2", 8),
    ("recovery-scope-catalog-head-unsigned-v2", 15),
    ("recovery-scope-catalog-head-v2", 16),
    ("recovery-scope-catalog-upload-v2", 2),
    ("catalog-merkle-proof-v2", 6),
    ("recovery-scope-catalog-preparation-unsigned-v2", 16),
    ("recovery-scope-catalog-preparation-v2", 17),
    ("recovery-scope-catalog-provider-descriptor-v2", 3),
    ("recovery-scope-catalog-active-authority-v2", 3),
    ("recovery-scope-catalog-root-authority-v2", 3),
    ("recovery-scope-catalog-recovery-authority-v2", 3),
    ("recovery-scope-catalog-hpke-envelope-v2", 3),
    ("recovery-scope-catalog-provider-package-v2", 17),
    ("recovery-scope-catalog-provider-public-aad-v2", 20),
    ("recovery-scope-catalog-provider-response-unsigned-v2", 22),
    ("recovery-scope-catalog-provider-response-v2", 26),
    ("recovery-scope-catalog-preparation-receipt-v2", 4),
    ("recovery-scope-catalog-provider-response-receipt-v2", 4),
    ("recovery-scope-catalog-status-pending-v2", 6),
    ("recovery-scope-catalog-status-ready-v2", 6),
    ("recovery-scope-catalog-status-expired-v2", 6),
    ("recovery-scope-catalog-status-cancelled-v2", 6),
    ("recovery-scope-catalog-status-invalidated-v2", 6),
];

const REQUIRED_BOUNDS: &[(&str, &str)] = &[
    ("digest", "digest = bstr .size 32"),
    ("signature", "signature = bstr .size 64"),
    ("Ed25519 public key", "ed25519-public-key = bstr .size 32"),
    ("per-leaf hiding nonce", "hiding-nonce = bstr .size 32"),
    ("UUIDv7", "uuid-v7 = tstr .size 36"),
    ("identity ID", "identity-id = tstr .size 57"),
    ("channel ID", "channel-id = tstr .size 57"),
    ("catalog count/index", "catalog-count = 1..1023"),
    (
        "HTTPS authority origin",
        "https-authority-origin = tstr .size (9..2048)",
    ),
    (
        "plaintext openings",
        "8: [1*1023 recovery-scope-catalog-opening-v2]",
    ),
    ("opaque ciphertext", "2: bstr .size (1..1048576)"),
    ("Merkle siblings", "6: [0*10 digest]"),
    ("X25519 public key", "x25519-public-key = bstr .size 32"),
    ("safe highwater", "safe-highwater = 0..9007199254740990"),
    (
        "positive safe successor",
        "positive-safe-successor = 1..9007199254740991",
    ),
    (
        "exact signed Catalog V2 head",
        "exact-signed-catalog-head-v2 = bstr .size (1..466)",
    ),
    (
        "exact Catalog V2 plaintext",
        "exact-catalog-plaintext-v2 = bstr .size (1..1048576)",
    ),
    (
        "exact direct DeviceAdd",
        "exact-device-add-event-v1 = bstr .size (1..533)",
    ),
    (
        "exact provider package",
        "exact-provider-package-v2 = bstr .size (1..1049457)",
    ),
    (
        "HPKE ciphertext",
        "hpke-ciphertext-v2 = bstr .size (17..1049473)",
    ),
    (
        "exact HPKE envelope",
        "exact-hpke-envelope-v2 = bstr .size (1..1049517)",
    ),
    (
        "exact provider response",
        "exact-provider-response-v2 = bstr .size (1..1050929)",
    ),
    (
        "exact ready status",
        "exact-ready-status-v2 = bstr .size (1..1050986)",
    ),
];

const REQUIRED_CRYPTO_DOMAIN_DECLARATIONS: &[(&str, &str)] = &[
    (
        "membership-receipt-domain",
        "dirextalk.recovery-scope-membership-receipt.v1\\0",
    ),
    ("recovery-scope-domain", "dirextalk.recovery-scope.v1\\0"),
    (
        "private-body-domain",
        "dirextalk.recovery-scope-catalog-private-body.v2\\0",
    ),
    (
        "opening-domain",
        "dirextalk.recovery-scope-catalog-opening.v2\\0",
    ),
    (
        "verifier-binding-domain",
        "dirextalk.recovery-scope-catalog-verifier-binding.v1\\0",
    ),
    (
        "verifier-binding-signature-domain",
        "dirextalk.recovery-scope-catalog-verifier-binding-signature.v1\\0",
    ),
    (
        "completion-verifier-descriptor-domain",
        "dirextalk.recovery-scope-catalog-completion-verifier-descriptor.v1\\0",
    ),
    (
        "completion-verifier-descriptor-signature-domain",
        "dirextalk.recovery-scope-catalog-completion-verifier-descriptor-signature.v1\\0",
    ),
    (
        "completion-evidence-pop-domain",
        "dirextalk.recovery-scope-catalog-completion-evidence-pop.v1\\0",
    ),
    (
        "completion-evidence-origin-authorization-domain",
        "dirextalk.recovery-scope-catalog-completion-evidence-origin-authorization.v1\\0",
    ),
    (
        "completion-evidence-authorization-digest-domain",
        "dirextalk.recovery-scope-catalog-completion-evidence-authorization-digest.v1\\0",
    ),
    (
        "leaf-commitment-domain",
        "dirextalk.recovery-scope-catalog-leaf-commitment.v2\\0",
    ),
    (
        "ciphertext-domain",
        "dirextalk.recovery-scope-catalog-ciphertext.v2\\0",
    ),
    ("head-domain", "dirextalk.recovery-scope-catalog-head.v2\\0"),
    (
        "head-signature-domain",
        "dirextalk.recovery-scope-catalog-head-signature.v2\\0",
    ),
    (
        "merkle-node-domain",
        "dirextalk.recovery-scope-catalog-node.v2\\0",
    ),
    (
        "response-capability-domain",
        "dirextalk.recovery-response-capability.v1\\0",
    ),
    (
        "recipient-key-domain",
        "dirextalk.recovery-recipient-key.v1\\0",
    ),
    (
        "device-history-authority-id-domain",
        "dirextalk.device-history-authority-id.v1\\0",
    ),
    (
        "identity-device-add-domain",
        "dirextalk.identity-device-add.v1\\0",
    ),
    (
        "preparation-idempotency-domain",
        "dirextalk.recovery-scope-catalog-handoff-preparation-idempotency.v2\\0",
    ),
    (
        "response-idempotency-domain",
        "dirextalk.recovery-scope-catalog-handoff-response-idempotency.v2\\0",
    ),
    (
        "preparation-signature-domain",
        "dirextalk.recovery-scope-catalog-handoff-preparation-signature.v2\\0",
    ),
    (
        "preparation-digest-domain",
        "dirextalk.recovery-scope-catalog-handoff-preparation-digest.v2\\0",
    ),
    (
        "provider-package-domain",
        "dirextalk.recovery-scope-catalog-handoff-provider-package.v2\\0",
    ),
    (
        "provider-aad-domain",
        "dirextalk.recovery-scope-catalog-handoff-provider-aad.v2\\0",
    ),
    (
        "provider-envelope-domain",
        "dirextalk.recovery-scope-catalog-handoff-provider-envelope.v2\\0",
    ),
    (
        "provider-signature-domain",
        "dirextalk.recovery-scope-catalog-handoff-provider-signature.v2\\0",
    ),
    (
        "provider-authority-signature-domain",
        "dirextalk.recovery-scope-catalog-handoff-provider-authority-signature.v2\\0",
    ),
    (
        "provider-response-domain",
        "dirextalk.recovery-scope-catalog-handoff-provider-response.v2\\0",
    ),
];

const REQUIRED_CRYPTO_TRANSCRIPTS: &[&str] = &[
    "membership receipt digest = SHA-256(membership-receipt-domain || exact field-6 bytes)",
    "recovery-scope digest = SHA-256(recovery-scope-domain || exact canonical CBOR(field 5))",
    "private-body digest = SHA-256(private-body-domain || exact canonical CBOR(private-body-v2))",
    "opening digest = SHA-256(opening-domain || exact canonical CBOR(recovery-scope-catalog-opening-v2))",
    "signed verifier-binding digest = SHA-256(verifier-binding-domain || exact canonical CBOR(signed verifier-binding-v1))",
    "verifier-binding signature input = verifier-binding-signature-domain || exact canonical CBOR(unsigned verifier-binding-v1)",
    "completion-verifier descriptor digest = SHA-256(completion-verifier-descriptor-domain || exact canonical CBOR(signed descriptor-v1))",
    "completion-verifier descriptor signature input = completion-verifier-descriptor-signature-domain || exact canonical CBOR(unsigned descriptor fields 1..7)",
    "completion-evidence ESK proof input = completion-evidence-pop-domain || exact canonical CBOR(binding fields 1..20)",
    "completion-evidence origin authorization input = completion-evidence-origin-authorization-domain || exact canonical CBOR(binding fields 1..21)",
    "completion-evidence authorization digest A = SHA-256(completion-evidence-authorization-digest-domain || exact canonical CBOR(binding fields 1..22))",
    "leaf-commitment digest = SHA-256(leaf-commitment-domain || exact canonical CBOR(leaf-commitment-v2))",
    "ciphertext digest = SHA-256(ciphertext-domain || exact opaque upload ciphertext bytes)",
    "signed head digest = SHA-256(head-domain || exact canonical CBOR(signed head-v2))",
    "head signature input = head-signature-domain || exact canonical CBOR(unsigned head-v2)",
    "Merkle node digest = SHA-256(merkle-node-domain || left32 || right32)",
    "response-capability digest = SHA-256(response-capability-domain || exact raw response capability bytes)",
    "recipient-key digest = SHA-256(recipient-key-domain || exact candidate X25519 public-key bytes)",
    "root/recovery authority key digest = SHA-256(device-history-authority-id-domain || exact Ed25519 public-key bytes)",
    "DeviceAdd event digest = SHA-256(identity-device-add-domain || exact direct DeviceAdd canonical CBOR bytes)",
    "preparation idempotency digest = SHA-256(preparation-idempotency-domain || exact raw Idempotency-Key bytes)",
    "response idempotency digest = SHA-256(response-idempotency-domain || exact raw Idempotency-Key bytes)",
    "preparation signature input = preparation-signature-domain || exact deterministic canonical CBOR(unsigned preparation fields 1..16)",
    "signed preparation digest = SHA-256(preparation-digest-domain || exact deterministic canonical CBOR(signed preparation fields 1..17))",
    "decrypted package digest = SHA-256(provider-package-domain || exact deterministic canonical CBOR(decrypted package))",
    "public AAD digest = SHA-256(provider-aad-domain || exact deterministic canonical CBOR(public AAD))",
    "HPKE envelope digest = SHA-256(provider-envelope-domain || exact deterministic canonical CBOR(HPKE envelope))",
    "provider signature input = provider-signature-domain || exact deterministic canonical CBOR(provider response unsigned fields 1..22)",
    "authority signature input = provider-authority-signature-domain || exact deterministic canonical CBOR(provider response unsigned fields 1..22)",
    "provider response digest = SHA-256(provider-response-domain || exact deterministic canonical CBOR(full provider response fields 1..26))",
];

const REQUIRED_TIME_AND_PROOF_RULES: &[&str] = &[
    "Fields 12 and 13 are issued_at and expires_at with issued_at < expires_at.",
    "Head issued_at <= binding issued_at < binding expires_at <= head expires_at.",
    "After decrypting, the candidate validates every verifier tuple",
    "Before durable issuance",
    "of the exact child certificate and evidence, verifier rotation invalidates",
    "candidate-local outstanding work and stops completion. After that issuance,",
    "routine descriptor rotation or ordinary MLS head advance is non-retroactive;",
    "exact committed cache/replay remains valid, and no single-use Catalog-head",
    "reservation exists. Explicit candidate, device, member, Catalog, or request",
    "revocation still fences cache use and routing.",
    "Every leaf in one Catalog uses one exact",
    "EPK across all retained Catalog V2 bindings and generations.",
    "Multiple preparations and recovery requests may use one signed Catalog head.",
    "cannot prove hidden origin currentness or HSM custody.",
    "cannot observe or enforce this hidden tuple.",
    "Binding fields 14..15 equal",
    "At each level, an odd final node duplicates itself and consumes no sibling;",
    "otherwise consume exactly one bottom-up sibling, then set count=ceil(count/2)",
    "the array length is exactly implied by count/index and never exceeds 10.",
    "Count 1 consumes zero siblings; count 1023 can mathematically require all 10.",
    "A minimum structurally valid opening is 1019 bytes for indices 1..23 and the",
    "minimum outer plaintext overhead is 147 bytes. Its one-based index occurs in",
    "private-body field 4, signed-binding field 5, and public-leaf field 4, so",
    "indices 24..255 add 3 bytes per opening and indices 256+ add 6. Therefore",
    "N=1023 requires exactly 147 + 1023*1019 + 232*3 + 768*6 = 1047888 bytes and",
    "fits the 1048576-byte exact plaintext ceiling. N=1024 requires 1048913 bytes",
    "and cannot fit. This is a structural CDDL plus consecutive-index semantic",
    "size boundary, not a 1023-opening full-cryptographic fixture.",
    "The opening digest covers this exact complete three-field canonical map:",
    "candidate-private body, full signed issuer binding, and public leaf only.",
];

const REQUIRED_HANDOFF_RULES: &[&str] = &[
    "request_id == enrollment challenge_id",
    "X25519 key as enrollment-candidate field 5 and the direct DeviceAdd",
    "derives field 9 from the candidate protected X25519 secret",
    "caller-supplied recovery key is never accepted",
    "Both signatures cover identical exact canonical fields 1..22",
    "Candidate/provider/authority Ed25519 public keys",
    "An active authority device ID differs from candidate",
    "provider authenticated session equals field-15",
    "RFC9180 base mode only: KEM 0x0020 X25519/HKDF-SHA256, KDF 0x0001",
    "AEAD 0x0003 ChaCha20Poly1305",
    "return the stored envelope",
    "Runtime rejects all-zero or low-order DH output",
    "RFC 9180 Seal/Open aad input = exact deterministic canonical CBOR bytes of",
    "with no digest, domain prefix,",
    "Response field 18 remains the public",
    "deterministic HPKE vector for this exact raw-byte selection.",
    "exact canonical package is at most 1049457 bytes before HPKE",
    "separate 1065984-byte upload decoder ceiling is not an envelope allowance",
    "Package and public AAD repeat their",
    "response field 3 is the digest",
    "Package field 4 is the",
    "derived count/Merkle",
    "DeviceAdd field 25 is exact canonical Identity Log V1.1 kind DeviceAdd",
    "sequence exactly H+1, predecessor head@H",
    "certificate and event signatures",
    "every repeated H/head pair is byte-equal",
    "response/package/AAD times are byte-equal",
    "Preparation, response, package, and AAD each require issued_at < expires_at",
    "response validity is contained by preparation and signed-Catalog validity",
    "candidate recipient X25519 bytes",
    "never decrypts the package, recomputes",
    "After decryption the candidate",
    "Field 6 is stable state_changed_at",
    "equal-time state priority is cancelled(4), invalidated(5)",
    "Invalidated equal-time reason priority is numeric",
    "GET derives this authoritative status read-only and never creates a transition",
    "Portable dual signatures are issuance evidence only",
    "origin-authenticated exact Identity Log state at H+1",
    "is no H+2 grace state and no portable checkpoint is claimed",
    "can never be the provider",
    "Challenge DELETE is the sole cancellation truth; no preparation DELETE",
    "POST/PUT receipts stay byte-identical and immutable after later GET",
    "operation+identity+request Idempotency-Key plus",
    "resolves before mutable business currentness",
    "Only first admission runs mutable gates and the one",
    "Raw capabilities and raw",
];

const EXACT_HANDOFF_MAPS: &[(&str, &str)] = &[
    (
        "recovery-scope-catalog-preparation-unsigned-v2",
        "{1:2,2:uuid-v7,3:identity-id,4:uuid-v7,5:positive-uint,6:digest,7:uuid-v7,8:ed25519-public-key,9:x25519-public-key,10:safe-highwater,11:digest,12:bstr.size32,13:digest,14:digest,15:utc-millis,16:utc-millis}",
    ),
    (
        "recovery-scope-catalog-preparation-v2",
        "{1:2,2:uuid-v7,3:identity-id,4:uuid-v7,5:positive-uint,6:digest,7:uuid-v7,8:ed25519-public-key,9:x25519-public-key,10:safe-highwater,11:digest,12:bstr.size32,13:digest,14:digest,15:utc-millis,16:utc-millis,17:signature}",
    ),
    (
        "recovery-scope-catalog-provider-descriptor-v2",
        "{1:2,2:uuid-v7,3:ed25519-public-key}",
    ),
    (
        "recovery-scope-catalog-active-authority-v2",
        "{1:1,2:uuid-v7,3:ed25519-public-key}",
    ),
    (
        "recovery-scope-catalog-root-authority-v2",
        "{1:2,2:digest,3:ed25519-public-key}",
    ),
    (
        "recovery-scope-catalog-recovery-authority-v2",
        "{1:3,2:digest,3:ed25519-public-key}",
    ),
    (
        "recovery-scope-catalog-hpke-envelope-v2",
        "{1:2,2:bstr.size32,3:hpke-ciphertext-v2}",
    ),
    (
        "recovery-scope-catalog-provider-package-v2",
        "{1:2,2:uuid-v7,3:digest,4:exact-signed-catalog-head-v2,5:exact-catalog-plaintext-v2,6:identity-id,7:uuid-v7,8:positive-uint,9:uuid-v7,10:x25519-public-key,11:safe-highwater,12:digest,13:positive-safe-successor,14:digest,15:digest,16:utc-millis,17:utc-millis}",
    ),
    (
        "recovery-scope-catalog-provider-public-aad-v2",
        "{1:2,2:uuid-v7,3:digest,4:identity-id,5:uuid-v7,6:positive-uint,7:digest,8:uuid-v7,9:digest,10:safe-highwater,11:digest,12:positive-safe-successor,13:digest,14:digest,15:recovery-scope-catalog-provider-descriptor-v2,16:recovery-scope-catalog-independent-authority-v2,17:digest,18:digest,19:utc-millis,20:utc-millis}",
    ),
    (
        "recovery-scope-catalog-provider-response-unsigned-v2",
        "{1:2,2:uuid-v7,3:digest,4:identity-id,5:uuid-v7,6:positive-uint,7:digest,8:uuid-v7,9:digest,10:safe-highwater,11:digest,12:positive-safe-successor,13:digest,14:digest,15:recovery-scope-catalog-provider-descriptor-v2,16:recovery-scope-catalog-independent-authority-v2,17:digest,18:digest,19:digest,20:digest,21:utc-millis,22:utc-millis}",
    ),
    (
        "recovery-scope-catalog-provider-response-v2",
        "{1:2,2:uuid-v7,3:digest,4:identity-id,5:uuid-v7,6:positive-uint,7:digest,8:uuid-v7,9:digest,10:safe-highwater,11:digest,12:positive-safe-successor,13:digest,14:digest,15:recovery-scope-catalog-provider-descriptor-v2,16:recovery-scope-catalog-independent-authority-v2,17:digest,18:digest,19:digest,20:digest,21:utc-millis,22:utc-millis,23:signature,24:signature,25:exact-device-add-event-v1,26:recovery-scope-catalog-hpke-envelope-v2}",
    ),
    (
        "recovery-scope-catalog-preparation-receipt-v2",
        "{1:2,2:uuid-v7,3:digest,4:utc-millis}",
    ),
    (
        "recovery-scope-catalog-provider-response-receipt-v2",
        "{1:2,2:uuid-v7,3:digest,4:utc-millis}",
    ),
    (
        "recovery-scope-catalog-status-pending-v2",
        "{1:2,2:uuid-v7,3:1,4:null,5:null,6:utc-millis}",
    ),
    (
        "recovery-scope-catalog-status-ready-v2",
        "{1:2,2:uuid-v7,3:2,4:recovery-scope-catalog-provider-response-v2,5:null,6:utc-millis}",
    ),
    (
        "recovery-scope-catalog-status-expired-v2",
        "{1:2,2:uuid-v7,3:3,4:null,5:1,6:utc-millis}",
    ),
    (
        "recovery-scope-catalog-status-cancelled-v2",
        "{1:2,2:uuid-v7,3:4,4:null,5:2,6:utc-millis}",
    ),
    (
        "recovery-scope-catalog-status-invalidated-v2",
        "{1:2,2:uuid-v7,3:5,4:null,5:1..6,6:utc-millis}",
    ),
];

pub(crate) fn validate(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = read_cddl(root)?;
    validate_parse(&cddl)?;
    validate_rule_names(&cddl)?;
    validate_field_counts(&cddl)?;
    validate_bounds(&cddl)?;
    validate_crypto_transcripts(&cddl)?;
    validate_time_and_proof_rules(&cddl)?;
    validate_handoff_rules(&cddl)?;
    let openapi = read_openapi(root)?;
    validate_openapi_source(&openapi)?;
    validate_catalog_vector(root, &cddl, &openapi)
}

fn read_cddl(root: &Path) -> Result<String, ProtocolToolError> {
    let path = root.join(CDDL_PATH);
    fs::read_to_string(&path).map_err(|error| {
        ProtocolToolError::new(format!(
            "read Recovery Scope Catalog V2 CDDL {}: {error}",
            path.display()
        ))
    })
}

fn validate_parse(cddl: &str) -> Result<(), ProtocolToolError> {
    cddl_cat::parse_cddl(cddl).map(|_| ()).map_err(|error| {
        ProtocolToolError::new(format!("parse Recovery Scope Catalog V2 CDDL: {error}"))
    })
}

fn validate_rule_names(cddl: &str) -> Result<(), ProtocolToolError> {
    for (rule, _) in CORE_RULE_FIELD_COUNTS {
        let declaration = format!("{rule} =");
        let count = cddl
            .lines()
            .filter(|line| line.trim_start().starts_with(&declaration))
            .count();
        if count != 1 {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 must declare {rule} exactly once"
            )));
        }
    }

    Ok(())
}

fn validate_field_counts(cddl: &str) -> Result<(), ProtocolToolError> {
    for (rule, expected_count) in CORE_RULE_FIELD_COUNTS {
        let body = rule_body(cddl, rule)?;
        let actual_keys = numbered_map_keys(body);
        let expected_keys = (1..=*expected_count).collect::<Vec<_>>();
        if actual_keys != expected_keys {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 rule {rule} keys {actual_keys:?} do not match frozen keys {expected_keys:?}"
            )));
        }
    }
    Ok(())
}

fn validate_bounds(cddl: &str) -> Result<(), ProtocolToolError> {
    for (label, required) in REQUIRED_BOUNDS {
        if !cddl.contains(required) {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 {label} bound is not frozen"
            )));
        }
    }
    Ok(())
}

fn validate_crypto_transcripts(cddl: &str) -> Result<(), ProtocolToolError> {
    let actual_domains = parse_crypto_domain_declarations(cddl)?;
    let expected_domains = REQUIRED_CRYPTO_DOMAIN_DECLARATIONS
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect::<BTreeMap<_, _>>();
    if actual_domains != expected_domains {
        return Err(ProtocolToolError::new(
            "Recovery Scope Catalog V2 crypto domain declaration set does not match the exact 30-domain contract",
        ));
    }
    for transcript in REQUIRED_CRYPTO_TRANSCRIPTS {
        if !cddl.contains(transcript) {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 must freeze transcript {transcript}"
            )));
        }
    }
    if !cddl.contains("Strict Ed25519") || !cddl.contains("deterministic canonical CBOR") {
        return Err(ProtocolToolError::new(
            "Recovery Scope Catalog V2 must require strict Ed25519 and deterministic canonical CBOR",
        ));
    }
    Ok(())
}

fn parse_crypto_domain_declarations(
    cddl: &str,
) -> Result<BTreeMap<String, String>, ProtocolToolError> {
    let mut declarations = BTreeMap::new();
    for line in cddl.lines() {
        let line = line.trim();
        let declaration = line.strip_prefix(';').map_or(line, str::trim);
        let Some((name, value)) = declaration.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if !name.ends_with("-domain") {
            continue;
        }
        let value = value
            .trim()
            .strip_prefix('`')
            .and_then(|value| value.strip_suffix("`."))
            .ok_or_else(|| {
                ProtocolToolError::new(format!(
                    "Recovery Scope Catalog V2 crypto domain declaration {name} is malformed"
                ))
            })?;
        if declarations
            .insert(name.to_owned(), value.to_owned())
            .is_some()
        {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 crypto domain declaration {name} is duplicated"
            )));
        }
    }
    Ok(declarations)
}

fn validate_time_and_proof_rules(cddl: &str) -> Result<(), ProtocolToolError> {
    for rule in REQUIRED_TIME_AND_PROOF_RULES {
        if !cddl.contains(rule) {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 must freeze semantic rule {rule}"
            )));
        }
    }
    Ok(())
}

fn validate_handoff_rules(cddl: &str) -> Result<(), ProtocolToolError> {
    for required in REQUIRED_HANDOFF_RULES {
        if !cddl.contains(required) {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 handoff rule drifted: {required}"
            )));
        }
    }
    let hpke_info_cddl = HPKE_INFO.replace('\0', "\\0");
    if !cddl.contains(&format!("hpke-info = `{hpke_info_cddl}`.")) {
        return Err(ProtocolToolError::new(
            "Recovery Scope Catalog V2 HPKE info literal drifted",
        ));
    }
    for (rule, expected) in EXACT_HANDOFF_MAPS {
        let actual = compact_cddl(rule_body(cddl, rule)?);
        if actual != *expected {
            return Err(ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 handoff rule {rule} field contract drifted"
            )));
        }
    }
    let compact_source = compact_cddl(cddl);
    for exact_union in [
        "recovery-scope-catalog-independent-authority-v2=recovery-scope-catalog-active-authority-v2/recovery-scope-catalog-root-authority-v2/recovery-scope-catalog-recovery-authority-v2",
        "recovery-scope-catalog-status-v2=recovery-scope-catalog-status-pending-v2/recovery-scope-catalog-status-ready-v2/recovery-scope-catalog-status-expired-v2/recovery-scope-catalog-status-cancelled-v2/recovery-scope-catalog-status-invalidated-v2",
    ] {
        if !compact_source.contains(exact_union) {
            return Err(ProtocolToolError::new(
                "Recovery Scope Catalog V2 handoff closed union drifted",
            ));
        }
    }
    Ok(())
}

fn compact_cddl(source: &str) -> String {
    source
        .lines()
        .map(|line| line.split_once(';').map_or(line, |(code, _)| code))
        .flat_map(str::chars)
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[cfg(test)]
fn validate_catalog_hiding_nonces<'a>(
    nonces: impl IntoIterator<Item = Option<&'a [u8]>>,
) -> Result<(), ProtocolToolError> {
    let mut seen = BTreeSet::new();
    let mut count = 0_usize;
    for nonce in nonces {
        count += 1;
        let nonce = nonce.ok_or_else(|| {
            ProtocolToolError::new("Recovery Scope Catalog V2 hiding nonce is absent")
        })?;
        let nonce: [u8; 32] = nonce.try_into().map_err(|_| {
            ProtocolToolError::new("Recovery Scope Catalog V2 hiding nonce must be 32 bytes")
        })?;
        if nonce == [0; 32] {
            return Err(ProtocolToolError::new(
                "Recovery Scope Catalog V2 hiding nonce must not be all zero",
            ));
        }
        if !seen.insert(nonce) {
            return Err(ProtocolToolError::new(
                "Recovery Scope Catalog V2 hiding nonce is reused within one catalog",
            ));
        }
    }
    if count == 0 {
        return Err(ProtocolToolError::new(
            "Recovery Scope Catalog V2 catalog has no hiding nonces",
        ));
    }
    Ok(())
}

fn read_openapi(root: &Path) -> Result<String, ProtocolToolError> {
    let path = root.join(OPENAPI_PATH);
    fs::read_to_string(&path).map_err(|error| {
        ProtocolToolError::new(format!(
            "read Recovery Scope Catalog V2 OpenAPI {}: {error}",
            path.display()
        ))
    })
}

fn parse_openapi(source: &str) -> Result<Value, ProtocolToolError> {
    oas3::from_yaml(source).map_err(|error| {
        ProtocolToolError::new(format!("parse Recovery Scope Catalog V2 OpenAPI: {error}"))
    })?;
    yaml_serde::from_str(source).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse Recovery Scope Catalog V2 OpenAPI tree: {error}"
        ))
    })
}

fn validate_openapi_source(source: &str) -> Result<(), ProtocolToolError> {
    let document = parse_openapi(source)?;
    validate_openapi_document(&document)
}

fn validate_openapi_document(document: &Value) -> Result<(), ProtocolToolError> {
    validate_openapi_canonical_cbor_ceilings(document)?;
    validate_openapi_http_contract(document)?;
    validate_openapi_projection_and_proof(document)?;
    validate_openapi_handoff_http_contract(document)?;
    validate_openapi_handoff_metadata(document)
}

fn validate_openapi_canonical_cbor_ceilings(document: &Value) -> Result<(), ProtocolToolError> {
    expect_value(
        document,
        "/x-dirextalk-canonical-cbor-ceilings",
        &json!({
            "signed-catalog-head": {
                "cddl-rule": "recovery-scope-catalog-head-v2",
                "maximum-bytes": MAX_SIGNED_CATALOG_HEAD_BYTES,
                "arithmetic": "map-header-1-plus-sixteen-one-byte-keys-16-plus-values-449",
                "encoded-as-bstr-maximum-bytes": MAX_SIGNED_CATALOG_HEAD_BYTES + 3
            },
            "catalog-upload": {
                "cddl-rule": "recovery-scope-catalog-upload-v2",
                "maximum-body-bytes": MAX_CATALOG_UPLOAD_BODY_BYTES,
                "arithmetic": "map-and-keys-3-plus-signed-head-466-plus-encoded-ciphertext-bstr-1048581",
                "decoder-ceiling-bytes": MAX_ENVELOPE_BYTES,
                "decoder-ceiling-is-not-valid-body-allowance": true
            },
            "provider-package": {
                "cddl-rule": "recovery-scope-catalog-provider-package-v2",
                "maximum-bytes": MAX_PROVIDER_PACKAGE_BYTES
            },
            "hpke-ciphertext": {
                "cddl-rule": "hpke-ciphertext-v2",
                "maximum-bytes": MAX_HPKE_CIPHERTEXT_BYTES,
                "arithmetic": "provider-package-1049457-plus-aead-tag-16"
            },
            "hpke-envelope": {
                "cddl-rule": "recovery-scope-catalog-hpke-envelope-v2",
                "maximum-bytes": MAX_HPKE_ENCODED_ENVELOPE_BYTES
            },
            "provider-response": {
                "cddl-rule": "recovery-scope-catalog-provider-response-v2",
                "maximum-body-bytes": MAX_PROVIDER_RESPONSE_BODY_BYTES
            },
            "ready-status": {
                "cddl-rule": "recovery-scope-catalog-status-ready-v2",
                "maximum-body-bytes": MAX_STATUS_BODY_BYTES
            }
        }),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the OpenAPI gate intentionally freezes the complete one-operation contract"
)]
fn validate_openapi_http_contract(document: &Value) -> Result<(), ProtocolToolError> {
    expect_value(document, "/openapi", &json!("3.1.0"))?;
    expect_value(document, "/info/version", &json!("2.0.0"))?;
    expect_object_keys(
        document,
        "/paths",
        &[
            OPENAPI_ROUTE,
            PREPARATION_ROUTE,
            STATUS_ROUTE,
            PROVIDER_RESPONSE_ROUTE,
        ],
    )?;
    let route_pointer = "/paths/~1v2~1recovery-scope-catalogs~1{catalog_id}";
    expect_object_keys(document, route_pointer, &["put"])?;
    expect_object_keys(
        document,
        "/paths/~1v3~1devices~1enroll~1catalog-preparations",
        &["post"],
    )?;
    expect_object_keys(
        document,
        "/paths/~1v3~1devices~1enroll~1catalog-preparations~1{request_id}",
        &["get"],
    )?;
    expect_object_keys(
        document,
        "/paths/~1v3~1devices~1enroll~1catalog-preparations~1{request_id}~1provider-response",
        &["put"],
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/operationId"),
        &json!("putRecoveryScopeCatalogV2"),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-authentication"),
        &json!({"kind": "active-device", "header": "Authorization", "required": true}),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/parameters"),
        &json!([
            {"$ref": "#/components/parameters/CatalogId"},
            {"$ref": "#/components/parameters/DeviceAuthorization"},
            {"$ref": "#/components/parameters/IdempotencyKey"}
        ]),
    )?;
    expect_value(
        document,
        "/components/parameters/CatalogId/name",
        &json!("catalog_id"),
    )?;
    expect_value(
        document,
        "/components/parameters/CatalogId/in",
        &json!("path"),
    )?;
    expect_value(
        document,
        "/components/parameters/CatalogId/required",
        &json!(true),
    )?;
    expect_value(
        document,
        "/components/parameters/CatalogId/schema/$ref",
        &json!("#/components/schemas/UuidV7"),
    )?;
    for (parameter, name) in [
        ("DeviceAuthorization", "Authorization"),
        ("IdempotencyKey", "Idempotency-Key"),
    ] {
        expect_value(
            document,
            &format!("/components/parameters/{parameter}/name"),
            &json!(name),
        )?;
        expect_value(
            document,
            &format!("/components/parameters/{parameter}/in"),
            &json!("header"),
        )?;
        expect_value(
            document,
            &format!("/components/parameters/{parameter}/required"),
            &json!(true),
        )?;
    }
    expect_value(
        document,
        "/components/parameters/IdempotencyKey/schema/minLength",
        &json!(16),
    )?;
    expect_value(
        document,
        "/components/parameters/IdempotencyKey/schema/maxLength",
        &json!(128),
    )?;
    expect_value(
        document,
        "/components/parameters/DeviceAuthorization/schema/type",
        &json!("string"),
    )?;
    expect_value(
        document,
        "/components/parameters/IdempotencyKey/schema/type",
        &json!("string"),
    )?;
    expect_value(
        document,
        "/components/schemas/UuidV7/pattern",
        &json!("^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"),
    )?;
    expect_value(
        document,
        "/components/schemas/UuidV7/type",
        &json!("string"),
    )?;
    expect_value(
        document,
        "/components/schemas/ExactCanonicalCbor/type",
        &json!("string"),
    )?;
    expect_value(
        document,
        "/components/schemas/ExactCanonicalCbor/contentEncoding",
        &json!("binary"),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/requestBody/required"),
        &json!(true),
    )?;
    expect_object_keys(
        document,
        &format!("{OPENAPI_OPERATION}/requestBody/content"),
        &[REQUEST_MEDIA],
    )?;
    let media_pointer = format!(
        "{OPENAPI_OPERATION}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog.v2+cbor"
    );
    expect_value(
        document,
        &format!("{media_pointer}/x-dirextalk-exact-cbor"),
        &json!(true),
    )?;
    expect_value(
        document,
        &format!("{media_pointer}/schema/$ref"),
        &json!("#/components/schemas/ExactCanonicalCbor"),
    )?;
    for (name, expected) in [
        (
            "x-dirextalk-max-leaf-count",
            u64::try_from(MAX_CATALOG_LEAVES).expect("catalog count fits u64"),
        ),
        ("x-dirextalk-max-ciphertext-bytes", 1_048_576),
        (
            "x-dirextalk-max-body-bytes",
            u64::try_from(MAX_CATALOG_UPLOAD_BODY_BYTES).expect("upload body maximum fits u64"),
        ),
        (
            "x-dirextalk-decoder-ceiling-bytes",
            u64::try_from(MAX_ENVELOPE_BYTES).expect("upload decoder ceiling fits u64"),
        ),
    ] {
        expect_value(
            document,
            &format!("{media_pointer}/{name}"),
            &json!(expected),
        )?;
    }
    expect_value(
        document,
        &format!("{media_pointer}/x-dirextalk-decoder-ceiling-is-not-body-allowance"),
        &json!(true),
    )?;
    let responses_pointer = format!("{OPENAPI_OPERATION}/responses");
    expect_object_keys(
        document,
        &responses_pointer,
        &["200", "201", "401", "409", "410", "412", "422"],
    )?;
    for (status, response) in [
        ("201", "CatalogCreated"),
        ("200", "CatalogReplay"),
        ("401", "DeviceAuthenticationFailed"),
        ("409", "CatalogConflict"),
        ("410", "CatalogGone"),
        ("412", "HeadOrAuthorityChanged"),
        ("422", "InvalidExactCbor"),
    ] {
        expect_value(
            document,
            &format!("{responses_pointer}/{status}/$ref"),
            &json!(format!("#/components/responses/{response}")),
        )?;
        validate_response_headers(document, response)?;
    }
    for response in ["CatalogCreated", "CatalogReplay"] {
        expect_object_keys(
            document,
            &format!("/components/responses/{response}/content"),
            &[RESPONSE_MEDIA],
        )?;
        expect_value(
            document,
            &format!(
                "/components/responses/{response}/content/application~1vnd.dirextalk.recovery-scope-catalog-head.v2+cbor/x-dirextalk-exact-cbor"
            ),
            &json!(true),
        )?;
        expect_value(
            document,
            &format!(
                "/components/responses/{response}/content/application~1vnd.dirextalk.recovery-scope-catalog-head.v2+cbor/x-dirextalk-max-body-bytes"
            ),
            &json!(MAX_SIGNED_CATALOG_HEAD_BYTES),
        )?;
        expect_value(
            document,
            &format!(
                "/components/responses/{response}/content/application~1vnd.dirextalk.recovery-scope-catalog-head.v2+cbor/schema/$ref"
            ),
            &json!("#/components/schemas/ExactCanonicalCbor"),
        )?;
    }
    for (response, description) in [
        (
            "CatalogCreated",
            "Created; returns the exact signed V2 catalog head bytes.",
        ),
        (
            "CatalogReplay",
            "Exact request replay; returns byte-identical signed V2 catalog head bytes.",
        ),
        (
            "CatalogConflict",
            "RECOVERY_CATALOG_CONFLICT or IDEMPOTENCY_CONFLICT; no write occurs.",
        ),
        ("CatalogGone", "RECOVERY_CATALOG_EXPIRED; no write occurs."),
        (
            "HeadOrAuthorityChanged",
            "CATALOG_HEAD_CHANGED or CATALOG_AUTHORITY_CHANGED; no write occurs.",
        ),
        (
            "InvalidExactCbor",
            "EXACT_CBOR_INVALID or RECOVERY_CATALOG_INVALID; no write occurs.",
        ),
    ] {
        expect_value(
            document,
            &format!("/components/responses/{response}/description"),
            &json!(description),
        )?;
    }
    expect_value(
        document,
        "/components/headers/NoStore/schema/const",
        &json!("no-store"),
    )?;
    expect_value(
        document,
        "/components/headers/NoSniff/schema/const",
        &json!("nosniff"),
    )?;
    expect_value(
        document,
        "/components/headers/XRequestId",
        &json!({"schema": {"$ref": "#/components/schemas/UuidV7"}}),
    )?;
    expect_value(
        document,
        "/components/schemas/ErrorEnvelopeV2",
        &json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["error"],
            "properties": {
                "error": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["code", "request_id", "retryable"],
                    "properties": {
                        "code": {"type": "string"},
                        "request_id": {"$ref": "#/components/headers/XRequestId/schema"},
                        "retryable": {"type": "boolean"}
                    }
                }
            }
        }),
    )?;
    for (response, schema, codes) in [
        (
            "DeviceAuthenticationFailed",
            "DeviceAuthenticationErrorV2",
            &["DEVICE_AUTHENTICATION_FAILED"][..],
        ),
        (
            "CatalogConflict",
            "CatalogConflictErrorV2",
            &["RECOVERY_CATALOG_CONFLICT", "IDEMPOTENCY_CONFLICT"][..],
        ),
        (
            "CatalogGone",
            "CatalogGoneErrorV2",
            &["RECOVERY_CATALOG_EXPIRED"][..],
        ),
        (
            "HeadOrAuthorityChanged",
            "CatalogPreconditionErrorV2",
            &["CATALOG_HEAD_CHANGED", "CATALOG_AUTHORITY_CHANGED"][..],
        ),
        (
            "InvalidExactCbor",
            "InvalidCatalogErrorV2",
            &["EXACT_CBOR_INVALID", "RECOVERY_CATALOG_INVALID"][..],
        ),
    ] {
        validate_error_response(document, response, schema, codes)?;
    }
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-path-coordinate-binding"),
        &json!({
            "reject": "reject-before-durable-writes",
            "coordinates": {
                "catalog_id": {
                    "source": "signed-request-cbor",
                    "cddl-rule": "recovery-scope-catalog-upload-v2",
                    "cbor-path": [1, 2],
                    "comparison": "exact"
                }
            }
        }),
    )
}

fn validate_response_headers(document: &Value, response: &str) -> Result<(), ProtocolToolError> {
    let pointer = format!("/components/responses/{response}/headers");
    expect_object_keys(
        document,
        &pointer,
        &["Cache-Control", "X-Content-Type-Options", "X-Request-Id"],
    )?;
    expect_value(
        document,
        &format!("{pointer}/Cache-Control/$ref"),
        &json!("#/components/headers/NoStore"),
    )?;
    expect_value(
        document,
        &format!("{pointer}/X-Content-Type-Options/$ref"),
        &json!("#/components/headers/NoSniff"),
    )?;
    expect_value(
        document,
        &format!("{pointer}/X-Request-Id/$ref"),
        &json!("#/components/headers/XRequestId"),
    )
}

fn validate_error_response(
    document: &Value,
    response: &str,
    schema: &str,
    codes: &[&str],
) -> Result<(), ProtocolToolError> {
    let response_pointer = format!("/components/responses/{response}");
    expect_object_keys(
        document,
        &response_pointer,
        &[
            "description",
            "x-dirextalk-request-id-header-matches-body",
            "headers",
            "content",
        ],
    )?;
    expect_value(
        document,
        &format!("{response_pointer}/x-dirextalk-request-id-header-matches-body"),
        &json!(true),
    )?;
    validate_response_headers(document, response)?;
    expect_value(
        document,
        &format!("{response_pointer}/content"),
        &json!({
            "application/json": {
                "schema": {"$ref": format!("#/components/schemas/{schema}")}
            }
        }),
    )?;
    expect_value(
        document,
        &format!("/components/schemas/{schema}"),
        &json!({
            "allOf": [
                {"$ref": "#/components/schemas/ErrorEnvelopeV2"},
                {
                    "type": "object",
                    "properties": {
                        "error": {
                            "type": "object",
                            "properties": {
                                "code": {"type": "string", "enum": codes},
                                "retryable": {"type": "boolean", "const": false}
                            }
                        }
                    }
                }
            ]
        }),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the privacy, crypto, validity, and proof metadata are one exact contract object"
)]
fn validate_openapi_projection_and_proof(document: &Value) -> Result<(), ProtocolToolError> {
    let allowed_paths = (1..=16)
        .map(|field| json!([1, field]))
        .chain(std::iter::once(json!([2])))
        .collect::<Vec<_>>();
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-server-visible-projection"),
        &json!({
            "signed-head-cddl-rule": "recovery-scope-catalog-head-v2",
            "opaque-ciphertext-cbor-path": [2],
            "allowed-cbor-paths": allowed_paths,
            "forbidden-data": [
                "recovery-scope",
                "membership-receipt",
                "private-body",
                "hiding-nonce",
                "completion-verifier-binding",
                "verifier-origin",
                "verifier-public-key",
                "verifier-key-id",
                "verifier-epoch",
                "verifier-descriptor",
                "completion-evidence-issuer-epk",
                "completion-evidence-issuer-pop",
                "completion-evidence-issuer-origin-authorization",
                "completion-evidence-issuer-authorization-digest"
            ]
        }),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-validity"),
        &json!({
            "head-issued-at-cbor-path": [1, 14],
            "head-expires-at-cbor-path": [1, 15],
            "head-relation": "issued-at-before-expires-at",
            "candidate-post-decryption-binding-validity-contained-in-head": true,
            "candidate-validates-every-verifier-binding-against-current-origin-authenticated-descriptor-before-leaf-acceptance-or-delivery": true,
            "candidate-verifier-rotation-before-child-issuance": "stops-new-child-issuance",
            "committed-child-certificate-and-evidence": "non-retroactive-across-routine-descriptor-rotation-or-head-advance",
            "identity-server-hidden-verifier-enforcement": "impossible-ciphertext-only"
        }),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-crypto-domains"),
        &json!({
            "membership-receipt": "dirextalk.recovery-scope-membership-receipt.v1\0",
            "recovery-scope": "dirextalk.recovery-scope.v1\0",
            "private-body": "dirextalk.recovery-scope-catalog-private-body.v2\0",
            "opening": "dirextalk.recovery-scope-catalog-opening.v2\0",
            "verifier-binding": "dirextalk.recovery-scope-catalog-verifier-binding.v1\0",
            "verifier-binding-signature": "dirextalk.recovery-scope-catalog-verifier-binding-signature.v1\0",
            "completion-verifier-descriptor": "dirextalk.recovery-scope-catalog-completion-verifier-descriptor.v1\0",
            "completion-verifier-descriptor-signature": "dirextalk.recovery-scope-catalog-completion-verifier-descriptor-signature.v1\0",
            "completion-evidence-pop": "dirextalk.recovery-scope-catalog-completion-evidence-pop.v1\0",
            "completion-evidence-origin-authorization": "dirextalk.recovery-scope-catalog-completion-evidence-origin-authorization.v1\0",
            "completion-evidence-authorization-digest": "dirextalk.recovery-scope-catalog-completion-evidence-authorization-digest.v1\0",
            "leaf-commitment": "dirextalk.recovery-scope-catalog-leaf-commitment.v2\0",
            "ciphertext": "dirextalk.recovery-scope-catalog-ciphertext.v2\0",
            "head": "dirextalk.recovery-scope-catalog-head.v2\0",
            "head-signature": "dirextalk.recovery-scope-catalog-head-signature.v2\0",
            "merkle-node": "dirextalk.recovery-scope-catalog-node.v2\0"
        }),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-opening-digest"),
        &json!({
            "algorithm": "SHA-256",
            "domain": "dirextalk.recovery-scope-catalog-opening.v2\0",
            "cddl-rule": "recovery-scope-catalog-opening-v2",
            "input": "exact-deterministic-canonical-cbor-complete-opening",
            "complete-cbor-fields": {
                "private-body": [1],
                "full-signed-issuer-binding": [2],
                "public-leaf": [3]
            },
            "subset-or-reencoding": "forbidden"
        }),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-private-body-derived-digests"),
        &json!({
            "membership-receipt": {
                "algorithm": "SHA-256",
                "domain": "dirextalk.recovery-scope-membership-receipt.v1\0",
                "output-cbor-path": [7],
                "input-cbor-path": [6],
                "input-encoding": "exact raw bstr bytes"
            },
            "recovery-scope": {
                "algorithm": "SHA-256",
                "domain": "dirextalk.recovery-scope.v1\0",
                "output-cbor-path": [9],
                "input-cbor-path": [5],
                "input-encoding": "exact deterministic canonical CBOR"
            }
        }),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-merkle-proof"),
        &json!({
            "cddl-rule": "catalog-merkle-proof-v2",
            "leaf-cddl-rule": "recovery-scope-catalog-leaf-commitment-v2",
            "leaf-digest-domain": "dirextalk.recovery-scope-catalog-leaf-commitment.v2\0",
            "node-digest-domain": "dirextalk.recovery-scope-catalog-node.v2\0",
            "sibling-order": "bottom-up",
            "index-base": 1,
            "count-minimum": 1,
            "count-maximum": 1_023,
            "maximum-siblings": 10,
            "odd-node-rule": "duplicate-last",
            "odd-final-node-consumes-sibling": false,
            "sibling-count-rule": "exact-count-index-height",
            "reject-surplus-or-missing-siblings": true,
            "field-bindings": {
                "version": {"cbor-path": [1], "const": 2},
                "catalog_id": {"cbor-path": [2], "signed-head-cbor-path": [2], "comparison": "exact"},
                "generation": {"cbor-path": [3], "signed-head-cbor-path": [4], "comparison": "exact"},
                "count": {"cbor-path": [4], "signed-head-cbor-path": [6], "comparison": "exact"},
                "index": {"cbor-path": [5], "minimum": 1, "maximum-from": "count"},
                "siblings": {"cbor-path": [6], "maximum-items": 10, "order": "bottom-up"}
            }
        }),
    )?;
    expect_value(
        document,
        &format!("{OPENAPI_OPERATION}/x-dirextalk-catalog-count-boundary"),
        &json!({
            "count-minimum": 1,
            "count-maximum": 1_023,
            "exact-plaintext-ceiling-bytes": 1_048_576,
            "minimum-valid-opening-bytes": 1_019,
            "minimum-outer-plaintext-overhead-bytes": 147,
            "index-occurrences-per-opening": 3,
            "one-byte-index-maximum": 23,
            "two-byte-index-maximum": 255,
            "indices-24-through-255-count": 232,
            "indices-24-through-255-extra-bytes-per-opening": 3,
            "indices-256-through-1023-count": 768,
            "indices-256-plus-extra-bytes-per-opening": 6,
            "consecutive-one-based-indices-required": true,
            "count-maximum-minimum-bytes": 1_047_888,
            "count-maximum-plus-one": 1_024,
            "count-maximum-plus-one-minimum-bytes": 1_048_913,
            "count-maximum-fits-ceiling": true,
            "count-maximum-plus-one-exceeds-ceiling": true,
            "validation-classification": "structural-cddl-and-consecutive-index-semantic-size-model",
            "full-cryptographic-1023-opening-fixture": "intentionally-not-claimed"
        }),
    )?;
    expect_value(
        document,
        &format!(
            "{OPENAPI_OPERATION}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog.v2+cbor/x-dirextalk-max-leaf-count"
        ),
        &json!(1_023),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the additive handoff freezes three operations, five media, receipts, status, and uniform failures"
)]
fn validate_openapi_handoff_http_contract(document: &Value) -> Result<(), ProtocolToolError> {
    for (operation, expected) in [
        (
            PREPARATION_OPERATION,
            "createRecoveryScopeCatalogPreparationV2",
        ),
        (STATUS_OPERATION, "getRecoveryScopeCatalogStatusV2"),
        (
            PROVIDER_RESPONSE_OPERATION,
            "putRecoveryScopeCatalogProviderResponseV2",
        ),
    ] {
        expect_value(
            document,
            &format!("{operation}/operationId"),
            &json!(expected),
        )?;
    }
    expect_value(
        document,
        &format!("{PREPARATION_OPERATION}/parameters"),
        &json!([
            {"$ref": "#/components/parameters/EnrollmentCapability"},
            {"$ref": "#/components/parameters/ResponseCapability"},
            {"$ref": "#/components/parameters/IdempotencyKey"}
        ]),
    )?;
    expect_value(
        document,
        &format!("{STATUS_OPERATION}/parameters"),
        &json!([
            {"$ref": "#/components/parameters/RequestId"},
            {"$ref": "#/components/parameters/ResponseCapability"},
            {"$ref": "#/components/parameters/StatusAccept"}
        ]),
    )?;
    expect_value(
        document,
        &format!("{PROVIDER_RESPONSE_OPERATION}/parameters"),
        &json!([
            {"$ref": "#/components/parameters/RequestId"},
            {"$ref": "#/components/parameters/DeviceAuthorization"},
            {"$ref": "#/components/parameters/IdempotencyKey"},
            {"$ref": "#/components/parameters/ProviderReceiptAccept"}
        ]),
    )?;
    for (parameter, name, location) in [
        ("RequestId", "request_id", "path"),
        (
            "EnrollmentCapability",
            "DTX-Enrollment-Capability",
            "header",
        ),
        (
            "ResponseCapability",
            "DTX-Recovery-Response-Capability",
            "header",
        ),
        ("StatusAccept", "Accept", "header"),
        ("ProviderReceiptAccept", "Accept", "header"),
    ] {
        let base = format!("/components/parameters/{parameter}");
        expect_value(document, &format!("{base}/name"), &json!(name))?;
        expect_value(document, &format!("{base}/in"), &json!(location))?;
        expect_value(document, &format!("{base}/required"), &json!(true))?;
    }
    for capability in ["EnrollmentCapability", "ResponseCapability"] {
        expect_value(
            document,
            &format!("/components/parameters/{capability}/schema/pattern"),
            &json!("^[A-Za-z0-9_-]{43}$"),
        )?;
    }
    expect_value(
        document,
        "/components/parameters/RequestId/schema/$ref",
        &json!("#/components/schemas/UuidV7"),
    )?;
    expect_value(
        document,
        "/components/parameters/StatusAccept/schema/const",
        &json!(STATUS_MEDIA),
    )?;
    expect_value(
        document,
        "/components/parameters/ProviderReceiptAccept/schema/const",
        &json!(PROVIDER_RESPONSE_RECEIPT_MEDIA),
    )?;
    expect_value(
        document,
        "/components/parameters/IdempotencyKey/schema/pattern",
        &json!("^[A-Za-z0-9_-]{16,128}$"),
    )?;
    if document
        .pointer(&format!("{STATUS_OPERATION}/requestBody"))
        .is_some()
    {
        return Err(ProtocolToolError::new(
            "Recovery Scope Catalog V2 status GET must not declare a request body",
        ));
    }
    validate_handoff_request_media(
        document,
        PREPARATION_OPERATION,
        PREPARATION_MEDIA,
        "recovery-scope-catalog-preparation-v2",
        MAX_PREPARATION_BODY_BYTES,
    )?;
    validate_handoff_request_media(
        document,
        PROVIDER_RESPONSE_OPERATION,
        PROVIDER_RESPONSE_MEDIA,
        "recovery-scope-catalog-provider-response-v2",
        MAX_PROVIDER_RESPONSE_BODY_BYTES,
    )?;
    let provider_media = format!(
        "{PROVIDER_RESPONSE_OPERATION}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog-provider-response.v2+cbor"
    );
    expect_value(
        document,
        &format!("{provider_media}/x-dirextalk-max-device-add-bytes"),
        &json!(MAX_DEVICE_ADD_BYTES),
    )?;
    expect_value(
        document,
        &format!("{provider_media}/x-dirextalk-max-hpke-envelope-bytes"),
        &json!(MAX_HPKE_ENCODED_ENVELOPE_BYTES),
    )?;
    for (operation, expected) in [
        (
            PREPARATION_OPERATION,
            &[
                ("200", "PreparationReplay"),
                ("201", "PreparationCreated"),
                ("401", "HandoffCapabilityRejected"),
                ("409", "HandoffConflict"),
                ("410", "HandoffGone"),
                ("412", "HandoffPreconditionFailed"),
                ("413", "HandoffTooLarge"),
                ("415", "HandoffUnsupportedMedia"),
                ("422", "HandoffInvalidExactCbor"),
            ][..],
        ),
        (
            STATUS_OPERATION,
            &[
                ("200", "HandoffStatus"),
                ("401", "HandoffCapabilityRejected"),
                ("406", "HandoffNotAcceptable"),
            ][..],
        ),
        (
            PROVIDER_RESPONSE_OPERATION,
            &[
                ("200", "ProviderResponseReplay"),
                ("201", "ProviderResponseCreated"),
                ("401", "DeviceAuthenticationFailed"),
                ("403", "HandoffProviderForbidden"),
                ("406", "HandoffNotAcceptable"),
                ("409", "HandoffConflict"),
                ("410", "HandoffGone"),
                ("412", "HandoffProviderPreconditionFailed"),
                ("413", "HandoffTooLarge"),
                ("415", "HandoffUnsupportedMedia"),
                ("422", "HandoffInvalidExactCbor"),
            ][..],
        ),
    ] {
        let responses = format!("{operation}/responses");
        expect_object_keys(
            document,
            &responses,
            &expected
                .iter()
                .map(|(status, _)| *status)
                .collect::<Vec<_>>(),
        )?;
        for (status, response) in expected {
            expect_value(
                document,
                &format!("{responses}/{status}/$ref"),
                &json!(format!("#/components/responses/{response}")),
            )?;
        }
    }
    let all_responses = [
        "CatalogCreated",
        "CatalogReplay",
        "DeviceAuthenticationFailed",
        "CatalogConflict",
        "CatalogGone",
        "HeadOrAuthorityChanged",
        "InvalidExactCbor",
        "PreparationCreated",
        "PreparationReplay",
        "ProviderResponseCreated",
        "ProviderResponseReplay",
        "HandoffStatus",
        "HandoffCapabilityRejected",
        "HandoffProviderForbidden",
        "HandoffNotAcceptable",
        "HandoffConflict",
        "HandoffGone",
        "HandoffPreconditionFailed",
        "HandoffProviderPreconditionFailed",
        "HandoffTooLarge",
        "HandoffUnsupportedMedia",
        "HandoffInvalidExactCbor",
    ];
    expect_object_keys(document, "/components/responses", &all_responses)?;
    for response in all_responses {
        validate_response_headers(document, response)?;
    }
    for (response, media, rule, cap) in [
        (
            "PreparationCreated",
            PREPARATION_RECEIPT_MEDIA,
            "recovery-scope-catalog-preparation-receipt-v2",
            87,
        ),
        (
            "PreparationReplay",
            PREPARATION_RECEIPT_MEDIA,
            "recovery-scope-catalog-preparation-receipt-v2",
            87,
        ),
        (
            "ProviderResponseCreated",
            PROVIDER_RESPONSE_RECEIPT_MEDIA,
            "recovery-scope-catalog-provider-response-receipt-v2",
            87,
        ),
        (
            "ProviderResponseReplay",
            PROVIDER_RESPONSE_RECEIPT_MEDIA,
            "recovery-scope-catalog-provider-response-receipt-v2",
            87,
        ),
        (
            "HandoffStatus",
            STATUS_MEDIA,
            "recovery-scope-catalog-status-v2",
            MAX_STATUS_BODY_BYTES,
        ),
    ] {
        validate_handoff_response_media(document, response, media, rule, cap)?;
    }
    for (response, schema, codes) in [
        (
            "HandoffCapabilityRejected",
            "HandoffCapabilityErrorV2",
            &["RECOVERY_RESPONSE_CAPABILITY_REJECTED"][..],
        ),
        (
            "HandoffProviderForbidden",
            "HandoffProviderForbiddenErrorV2",
            &["RECOVERY_PROVIDER_FORBIDDEN"][..],
        ),
        (
            "HandoffNotAcceptable",
            "HandoffNotAcceptableErrorV2",
            &["RECOVERY_HANDOFF_NOT_ACCEPTABLE"][..],
        ),
        (
            "HandoffConflict",
            "HandoffConflictErrorV2",
            &["IDEMPOTENCY_CONFLICT", "RECOVERY_PREPARATION_CONFLICT"][..],
        ),
        (
            "HandoffGone",
            "HandoffGoneErrorV2",
            &[
                "RECOVERY_PREPARATION_EXPIRED",
                "RECOVERY_PREPARATION_REVOKED",
            ][..],
        ),
        (
            "HandoffPreconditionFailed",
            "HandoffPreconditionErrorV2",
            &[
                "IDENTITY_HEAD_CHANGED",
                "CATALOG_HEAD_CHANGED",
                "CATALOG_AUTHORITY_CHANGED",
                "CANDIDATE_KEY_CHANGED",
            ][..],
        ),
        (
            "HandoffProviderPreconditionFailed",
            "HandoffProviderPreconditionErrorV2",
            &[
                "IDENTITY_HEAD_CHANGED",
                "CATALOG_HEAD_CHANGED",
                "CATALOG_AUTHORITY_CHANGED",
                "CANDIDATE_KEY_CHANGED",
                "PROVIDER_KEY_CHANGED",
                "AUTHORITY_CHANGED",
            ][..],
        ),
        (
            "HandoffTooLarge",
            "HandoffTooLargeErrorV2",
            &["RECOVERY_HANDOFF_TOO_LARGE"][..],
        ),
        (
            "HandoffUnsupportedMedia",
            "HandoffUnsupportedMediaErrorV2",
            &["RECOVERY_HANDOFF_UNSUPPORTED_MEDIA_TYPE"][..],
        ),
        (
            "HandoffInvalidExactCbor",
            "InvalidCatalogErrorV2",
            &["EXACT_CBOR_INVALID", "RECOVERY_CATALOG_INVALID"][..],
        ),
    ] {
        validate_error_response(document, response, schema, codes)?;
    }
    Ok(())
}

fn validate_handoff_request_media(
    document: &Value,
    operation: &str,
    media: &str,
    rule: &str,
    cap: usize,
) -> Result<(), ProtocolToolError> {
    expect_value(
        document,
        &format!("{operation}/requestBody/required"),
        &json!(true),
    )?;
    expect_object_keys(
        document,
        &format!("{operation}/requestBody/content"),
        &[media],
    )?;
    let pointer = format!(
        "{operation}/requestBody/content/{}",
        media.replace('/', "~1")
    );
    expect_value(
        document,
        &format!("{pointer}/x-dirextalk-exact-cbor"),
        &json!(true),
    )?;
    expect_value(
        document,
        &format!("{pointer}/x-dirextalk-cddl-rule"),
        &json!(rule),
    )?;
    expect_value(
        document,
        &format!("{pointer}/x-dirextalk-max-body-bytes"),
        &json!(cap),
    )?;
    expect_value(
        document,
        &format!("{pointer}/schema/$ref"),
        &json!("#/components/schemas/ExactCanonicalCbor"),
    )
}

fn validate_handoff_response_media(
    document: &Value,
    response: &str,
    media: &str,
    rule: &str,
    cap: usize,
) -> Result<(), ProtocolToolError> {
    let content = format!("/components/responses/{response}/content");
    expect_object_keys(document, &content, &[media])?;
    let pointer = format!("{content}/{}", media.replace('/', "~1"));
    expect_value(
        document,
        &format!("{pointer}/x-dirextalk-exact-cbor"),
        &json!(true),
    )?;
    expect_value(
        document,
        &format!("{pointer}/x-dirextalk-cddl-rule"),
        &json!(rule),
    )?;
    expect_value(
        document,
        &format!("{pointer}/x-dirextalk-max-body-bytes"),
        &json!(cap),
    )?;
    expect_value(
        document,
        &format!("{pointer}/schema/$ref"),
        &json!("#/components/schemas/ExactCanonicalCbor"),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the handoff metadata is a closed security and state-machine contract"
)]
fn validate_openapi_handoff_metadata(document: &Value) -> Result<(), ProtocolToolError> {
    expect_value(
        document,
        "/x-dirextalk-handoff-crypto-domains",
        &json!({
            "response-capability": "dirextalk.recovery-response-capability.v1\0",
            "recipient-key": "dirextalk.recovery-recipient-key.v1\0",
            "device-history-authority-id": "dirextalk.device-history-authority-id.v1\0",
            "identity-device-add": "dirextalk.identity-device-add.v1\0",
            "preparation-idempotency": "dirextalk.recovery-scope-catalog-handoff-preparation-idempotency.v2\0",
            "response-idempotency": "dirextalk.recovery-scope-catalog-handoff-response-idempotency.v2\0",
            "preparation-signature": "dirextalk.recovery-scope-catalog-handoff-preparation-signature.v2\0",
            "preparation-digest": "dirextalk.recovery-scope-catalog-handoff-preparation-digest.v2\0",
            "provider-package": "dirextalk.recovery-scope-catalog-handoff-provider-package.v2\0",
            "provider-aad": "dirextalk.recovery-scope-catalog-handoff-provider-aad.v2\0",
            "provider-envelope": "dirextalk.recovery-scope-catalog-handoff-provider-envelope.v2\0",
            "provider-signature": "dirextalk.recovery-scope-catalog-handoff-provider-signature.v2\0",
            "provider-authority-signature": "dirextalk.recovery-scope-catalog-handoff-provider-authority-signature.v2\0",
            "provider-response": "dirextalk.recovery-scope-catalog-handoff-provider-response.v2\0",
        }),
    )?;
    expect_value(
        document,
        "/x-dirextalk-handoff-hpke",
        &json!({
            "mode": "base",
            "kem": {"id": 32, "name": "X25519-HKDF-SHA256"},
            "kdf": {"id": 1, "name": "HKDF-SHA256"},
            "aead": {"id": 3, "name": "ChaCha20Poly1305"},
            "info": HPKE_INFO,
            "info-kind": "exact-literal-not-hash-domain-alias",
            "encapsulation": "fresh-only-on-first-accepted-response",
            "exact-replay": "return-stored-byte-identical-envelope",
            "package-cddl-rule": "recovery-scope-catalog-provider-package-v2",
            "package-max-bytes": MAX_PROVIDER_PACKAGE_BYTES,
            "public-aad-cddl-rule": "recovery-scope-catalog-provider-public-aad-v2",
            "aad-input": "exact-deterministic-canonical-cbor-bytes-of-recovery-scope-catalog-provider-public-aad-v2",
            "aad-input-not": ["response-field-18-digest", "provider-aad-domain-prefixed", "json", "hex", "alternate-cbor-encoding"],
            "deterministic-hpke-vector-required-in": "C1b-B",
            "envelope-cddl-rule": "recovery-scope-catalog-hpke-envelope-v2",
            "ciphertext-max-bytes": MAX_HPKE_CIPHERTEXT_BYTES,
            "encoded-envelope-max-bytes": MAX_HPKE_ENCODED_ENVELOPE_BYTES,
            "decoder-ceiling-bytes": MAX_ENVELOPE_BYTES,
            "decoder-ceiling-is-not-envelope-allowance": true,
            "envelope-digest-input": "exact-deterministic-canonical-envelope-not-ciphertext-alone",
            "dh-rejection": "reject-all-zero-and-low-order-at-semantic-runtime-stage",
        }),
    )?;
    expect_value(
        document,
        "/x-dirextalk-handoff-currentness",
        &json!({
            "portable-signatures": "issuance-evidence-only",
            "first-admission-and-status": "origin-authenticated-exact-identity-log-state-at-h-plus-1",
            "authenticated-committed-exact-replay": "before-mutable-business-currentness",
            "transition": "exact-direct-device-add",
            "no-h-plus-2": true,
            "portable-checkpoint-claimed": false,
            "first-admission-and-status-current-provider-and-authority-required": true,
            "candidate-can-never-be-provider": true,
            "server-visible-invalidation-drift": ["identity-head", "public-catalog-head-or-authority", "candidate", "provider", "authority"],
            "hidden-verifier-currentness": "candidate-only-never-server-admission-cas-replay-or-status",
            "hidden-verifier-status": "only-transitive-via-new-or-invalid-public-catalog-head",
            "availability-cost": "independent-authority-required-for-first-accepted-response",
        }),
    )?;
    expect_value(
        document,
        "/x-dirextalk-handoff-signers",
        &json!({
            "provider-descriptor": {
                "cddl-rule": "recovery-scope-catalog-provider-descriptor-v2",
                "fields": {"version": 1, "device-id": 2, "ed25519-public-key": 3},
                "key-id-present": false,
            },
            "independent-authority": {
                "closed-union": true,
                "unknown-kind": "rejected",
                "free-form-descriptor": "forbidden",
                "kinds": {
                    "active-device": {"kind": 1, "fields": ["kind", "device-id", "ed25519-public-key"]},
                    "identity-root": {"kind": 2, "fields": ["kind", "authority-id", "ed25519-public-key"]},
                    "recovery-authority": {"kind": 3, "fields": ["kind", "authority-id", "ed25519-public-key"]},
                },
            },
            "key-separation": {
                "candidate-provider-and-authority-ed25519-public-keys": "pairwise-distinct",
                "candidate-ed25519-and-x25519-public-key-bytes": "distinct",
                "candidate-provider-and-active-authority-device-ids": "pairwise-distinct",
            },
        }),
    )?;
    expect_value(
        document,
        "/x-dirextalk-handoff-equality-validity",
        &json!({
            "highwater": {
                "h": "0..9007199254740990",
                "h-plus-1": "positive-and-exactly-h-plus-1",
                "repeated-h-head-pairs": "byte-equal",
            },
            "duplicate-coordinates": {
                "preparation-to-response": [
                    {"request-id": "preparation-2-equals-response-2"},
                    {"identity": "preparation-3-equals-response-4"},
                    {"catalog-id": "preparation-4-equals-response-5"},
                    {"generation": "preparation-5-equals-response-6"},
                    {"signed-head-digest": "preparation-6-equals-response-7"},
                    {"candidate-device-id": "preparation-7-equals-response-8"},
                    {"h": "preparation-10-equals-response-10"},
                    {"head-at-h": "preparation-11-equals-response-11"},
                    {"signed-preparation-digest": "digest-exact-preparation-1-through-17-equals-response-3"},
                    {"recipient-key-digest": "digest-exact-preparation-9-x25519-bytes-equals-response-9"},
                ],
                "response-to-package": [
                    {"request-id": "response-2-equals-package-2"},
                    {"signed-preparation-digest": "response-3-equals-package-3"},
                    {"identity": "response-4-equals-package-6"},
                    {"catalog-id": "response-5-equals-package-7"},
                    {"generation": "response-6-equals-package-8"},
                    {"candidate-device-id": "response-8-equals-package-9"},
                    {"h": "response-10-equals-package-11"},
                    {"head-at-h": "response-11-equals-package-12"},
                    {"h-plus-1": "response-12-equals-package-13"},
                    {"head-at-h-plus-1": "response-13-equals-package-14"},
                    {"device-add-digest": "response-14-equals-package-15"},
                    {"recipient-key": "package-10-equals-preparation-9"},
                ],
                "response-to-public-aad": [
                    {"fields-2-through-17": "byte-equal-same-numbered-fields"},
                    {"idempotency-digest": "response-20-equals-aad-18"},
                    {"issued-at": "response-21-equals-aad-19"},
                    {"expires-at": "response-22-equals-aad-20"},
                    {"aad-digest": "digest-exact-aad-1-through-20-equals-response-18"},
                    {"envelope-digest": "digest-exact-envelope-equals-response-19"},
                ],
                "response-to-package-times": [
                    {"issued-at": "response-21-equals-package-16"},
                    {"expires-at": "response-22-equals-package-17"},
                ],
                "preparation-to-device-add": [
                    {"candidate-device-id": "preparation-7-equals-certificate-3"},
                    {"candidate-ed25519-key": "preparation-8-equals-certificate-4"},
                    {"candidate-x25519-key": "preparation-9-equals-certificate-5"},
                ],
            },
            "signed-head": {
                "package-field-4": "exact-signed-head-cbor",
                "digest-equals": ["preparation-field-6", "response-field-7", "aad-field-7"],
            },
            "catalog-plaintext": {
                "package-field-5": "exact-catalog-plaintext-cbor",
                "validates-against-signed-head": ["identity", "catalog-id", "generation", "previous-head", "count", "merkle-root", "h", "head-at-h"],
            },
            "device-add": {
                "cddl-rule": "identity-log-device-add-event-v1-1",
                "canonical-kind": "device-add",
                "validates": ["identity", "sequence-exact-h-plus-1", "predecessor-head-at-h", "candidate-device-id", "candidate-ed25519-key", "candidate-x25519-key", "certificate-signature", "event-signature"],
                "digest-domain": "dirextalk.identity-device-add.v1\0",
                "digest-equals": ["response-field-14", "package-field-15", "aad-field-14"],
            },
            "validity": {
                "every-issued-at-before-expires-at": true,
                "response-package-aad-times": "byte-equal",
                "response-contained-by": ["preparation-validity", "signed-catalog-validity"],
                "preparation-accepted-at": "stored-once",
                "provider-accepted-at": "stored-once",
            },
            "identity-server-validation": {
                "validates": ["public-aad-structure-and-digest", "hpke-envelope-structure-and-digest", "provider-signature", "authority-signature", "public-signed-catalog-id-generation-head-root-count-authority-validity", "current-identity-candidate-provider-independent-authority"],
                "never": ["decrypt-package", "recompute-package-digest", "validate-catalog-plaintext", "observe-or-fence-completion-verifier-origin-key-epoch-or-descriptor"],
            },
            "candidate-post-decryption-validation": {
                "validates": [
                    "package-digest", "exact-signed-head", "exact-catalog-plaintext",
                    "complete-equality-validity-matrix",
                    "exact-current-origin-authenticated-completion-verifier-descriptor-signature-and-digest",
                    "every-verifier-binding-exact-origin-key-id-public-key-epoch-and-descriptor-digest",
                    "every-completion-evidence-algorithm-purpose-validity-and-globally-unique-issuer-epk",
                    "every-completion-evidence-pop-origin-authorization-and-catalog-countersignature",
                    "every-completion-evidence-authorization-digest-a-full-binding-digest-b-and-leaf-copy",
                    "all-completion-evidence-before-any-catalog-leaf-acceptance-or-delivery"
                ],
                "verifier-rotation-before-child-issuance": "stops-new-child-issuance",
                "committed-child-certificate-and-evidence": "non-retroactive-across-routine-descriptor-rotation-or-head-advance",
            },
        }),
    )?;
    expect_value(
        document,
        "/x-dirextalk-handoff-replay-order",
        &json!({
            "prerequisite": "successful-caller-capability-or-session-authentication",
            "before-claim-resolution": ["static-media-size-path", "idempotency-key-shape-and-lookup", "exact-body-and-signature-match"],
            "committed-exact-claim": "return-stored-byte-identical-receipt-no-writes-before-mutable-currentness",
            "committed-conflict": "409-no-writes",
            "mutable-currentness-and-final-cas": "first-admission-only",
            "get-currentness": "revalidated-read-only",
        }),
    )?;
    expect_value(
        document,
        "/x-dirextalk-handoff-state-machine",
        &json!({
            "status-codes": {"pending": 1, "ready": 2, "expired": 3, "cancelled": 4, "invalidated": 5},
            "reason-codes": {
                "expired": {"expiry": 1},
                "cancelled": {"challenge-cancellation": 2},
                "invalidated-priority": {
                    "identity-head-or-h-plus-2": 1,
                    "catalog-id-generation-or-head": 2,
                    "public-catalog-authority-or-head": 3,
                    "candidate-device-add-or-key": 4,
                    "provider-session-or-key": 5,
                    "independent-authority": 6,
                },
            },
            "only-ready-embeds-response": true,
            "pending-to-ready": "exact-direct-h-plus-1-device-add-only",
            "cancellation-truth": "enrollment-challenge-delete-only",
            "preparation-delete": "forbidden",
            "receipts-remain-immutable-after-get-invalidation": true,
            "state-changed-at": {
                "pending": "preparation-accepted-at",
                "ready": "provider-accepted-at",
                "expired": "earliest-exact-expiry",
                "cancelled": "challenge-cancellation-time",
                "invalidated": "exact-first-invalidating-public-event-or-head-time",
            },
            "terminal-selection": {
                "primary": "earliest-exact-transition-timestamp",
                "equal-time-state-priority": ["cancelled", "invalidated", "expired"],
                "equal-time-invalidated-reason": "lowest-numeric-priority",
            },
            "get-semantics": "authoritative-derived-read-only-never-writes-transition",
        }),
    )?;
    expect_value(
        document,
        "/x-dirextalk-handoff-privacy",
        &json!({
            "forbidden-persistence-and-responses": [
                "raw-enrollment-capability", "raw-response-capability", "raw-idempotency-key",
                "catalog-plaintext", "recovery-scope", "membership-receipt", "private-body",
                "catalog-opening", "hiding-nonce", "completion-verifier-origin",
                "completion-verifier-key", "completion-verifier-key-id",
                "completion-verifier-epoch", "completion-verifier-descriptor",
                "completion-evidence-issuer-epk", "completion-evidence-issuer-pop",
                "completion-evidence-issuer-origin-authorization",
                "completion-evidence-issuer-authorization-digest"
            ],
            "http-visible-provider-response": [
                "signed-public-coordinates-and-descriptors", "exact-device-add-cbor",
                "opaque-hpke-envelope"
            ],
        }),
    )?;
    expect_value(
        document,
        "/x-dirextalk-completion-evidence",
        &json!({
            "descriptor": {
                "cddl-rule": "recovery-scope-catalog-completion-verifier-descriptor-v1",
                "source": "candidate-fetches-current-descriptor-over-origin-authenticated-channel",
                "identity-home-endpoint": "forbidden",
                "signature-key": "exact-descriptor-field-4-current-verifier-key",
                "digest-input": "exact-full-signed-descriptor",
                "binding-equality": ["origin", "key-id", "public-key", "epoch", "descriptor-digest", "issued-at", "expires-at"],
            },
            "issuer-authorization": {
                "algorithm": {"value": 1, "name": "Ed25519"},
                "purpose": {"value": 1, "name": "history-recovery-completion-evidence-issuer-v2"},
                "issuer-epk-cbor-path": [18],
                "key-id-handle-or-uuid": "forbidden",
                "generation-owner": "scope-origin-service",
                "caller-supplied-issuer-epk-or-pop": "forbidden",
                "issuer-esk-custody": "persistent-non-exportable-scope-origin-service-only",
                "issuer-esk-retained-through": "signed-catalog-validity",
                "candidate-receives-issuer-esk": false,
                "exact-tuple-retry": "byte-identical-issuer-epk-pop-origin-authorization",
                "issuer-pop-input": "terminal-nul-pop-domain-plus-exact-binding-fields-1-through-20",
                "origin-authorization-input": "terminal-nul-origin-authorization-domain-plus-exact-binding-fields-1-through-21",
                "catalog-countersignature-input": "existing-terminal-nul-binding-signature-domain-plus-exact-binding-fields-1-through-22",
                "authorization-digest-a-input": "terminal-nul-authorization-digest-domain-plus-exact-binding-fields-1-through-22",
                "full-binding-digest-b-input": "existing-binding-domain-plus-exact-full-fields-1-through-23",
                "pre-freeze-cycle-forbidden-inputs": ["authorization-digest-a", "full-binding-digest-b", "leaf-digest", "merkle-root", "signed-head", "ciphertext-digest", "completion-digest"],
            },
            "validity": {
                "nonempty": true,
                "contained-by": ["current-origin-verifier-descriptor", "binding-validity", "signed-catalog-validity"],
                "catalog-wide-exact-issuer-authorization-window-for-every-leaf": true,
                "later-completion-runtime-validity-may-be-shorter": true,
            },
            "key-separation": {
                "issuer-epk-globally-unique-across-all-retained-catalog-v2-bindings-and-generations": true,
                "issuer-epk-distinct-from": ["candidate", "provider", "catalog-authority", "origin-verifier", "identity-root", "recovery-authority", "every-other-visible-key"],
            },
            "downstream-child-evidence": {
                "encoded-in-catalog-v2": false,
                "issuer-fields-a-b-and-leaf-request-dependent-data": "forbidden",
                "signed-catalog-head-allows-multiple-preparations-and-recovery-requests": true,
                "new-child-issuance-stops-on": ["descriptor-invalidation", "catalog-invalidation"],
                "per-request": ["globally-fresh-child-epk", "child-pop", "issuer-signed-certificate"],
                "child-esk": "signs-exactly-one-evidence-then-destroyed",
                "linearization-point": "child-issuance-transaction-validates-current-descriptor-and-normal-mls-currentness",
                "committed-child-certificate-and-evidence": "non-retroactive-across-routine-descriptor-rotation-or-head-advance",
                "exact-replay-after-commit": "valid",
                "single-use-catalog-head-reservation": "forbidden",
                "identity-later-verifies-only": ["committed-issuer-delegation", "child-signature"],
                "identity-cannot-prove": ["hidden-origin-currentness", "hsm-custody"],
            },
            "leaf-public-binding": {
                "cddl-rule": "recovery-scope-catalog-leaf-commitment-v2",
                "fields": {
                    "algorithm": {"cbor-path": [7], "binding-cbor-path": [16], "comparison": "exact"},
                    "purpose": {"cbor-path": [8], "binding-cbor-path": [17], "comparison": "exact"},
                    "issuer-epk": {"cbor-path": [9], "binding-cbor-path": [18], "comparison": "exact"},
                    "issuer-authorization-not-before": {"cbor-path": [10], "binding-cbor-path": [19], "comparison": "exact"},
                    "issuer-authorization-expires": {"cbor-path": [11], "binding-cbor-path": [20], "comparison": "exact"},
                    "issuer-authorization-digest-a": {"cbor-path": [12], "derivation": "exact-binding-fields-1-through-22"},
                },
                "leaf-digest": "existing-leaf-v2-domain-over-exact-full-leaf",
            },
            "visibility": {
                "candidate-private": ["full-descriptor", "full-binding", "issuer-pop", "issuer-origin-authorization"],
                "hidden-from-upload-and-handoff-server-projections": ["issuer-epk", "issuer-authorization-not-before", "issuer-authorization-expires", "issuer-authorization-digest-a"],
                "later-redacted-completion-v2-leaf-disclosure-only": ["issuer-epk", "issuer-authorization-not-before", "issuer-authorization-expires", "issuer-authorization-digest-a"],
                "identity-server-upload-handoff-projection": "unchanged-and-blind",
            },
        }),
    )?;

    for (operation, pointer, expected) in [
        (
            "preparation authentication",
            &format!("{PREPARATION_OPERATION}/x-dirextalk-authentication"),
            json!({
                "kind": "distinct-capability-pair",
                "required-headers": ["DTX-Enrollment-Capability", "DTX-Recovery-Response-Capability"],
                "authorization-header": "forbidden",
                "unknown-or-wrong-capability-status": 401,
            }),
        ),
        (
            "preparation binding",
            &format!("{PREPARATION_OPERATION}/x-dirextalk-path-body-binding"),
            json!({
                "request-id-cbor-path": [2],
                "request-id-equals-enrollment-challenge-id": true,
                "candidate-recipient-key-cbor-path": [9],
                "candidate-recipient-key-equals-enrollment-candidate-field-5": true,
                "candidate-recipient-key-equals-device-add-certificate-field-5": true,
                "recipient-key-source": "protected-candidate-x25519-secret",
                "arbitrary-recovery-key": "rejected",
            }),
        ),
        (
            "status authentication",
            &format!("{STATUS_OPERATION}/x-dirextalk-authentication"),
            json!({
                "kind": "response-capability",
                "required-header": "DTX-Recovery-Response-Capability",
                "authorization-header": "forbidden",
                "unknown-or-wrong-capability-status": 401,
            }),
        ),
        (
            "status currentness",
            &format!("{STATUS_OPERATION}/x-dirextalk-currentness"),
            json!({
                "required-state": "origin-authenticated-exact-identity-log-h-plus-1",
                "ready-transition": "exact-direct-device-add-only",
                "no-h-plus-2": true,
                "portable-checkpoint-claimed": false,
                "invalidates-on": ["identity-head", "public-catalog-head-or-authority", "candidate", "provider", "authority"],
                "hidden-verifier-status": "only-transitive-via-new-or-invalid-public-catalog-head",
                "status-result": "authoritative-200-one-of-five",
                "transition-write": "forbidden",
            }),
        ),
        (
            "provider authentication",
            &format!("{PROVIDER_RESPONSE_OPERATION}/x-dirextalk-authentication"),
            json!({
                "kind": "active-device", "header": "Authorization", "required": true,
                "authenticated-session-equals-provider-descriptor": true,
                "candidate-can-never-be-provider": true, "provider-mismatch-status": 403,
            }),
        ),
        (
            "provider binding",
            &format!("{PROVIDER_RESPONSE_OPERATION}/x-dirextalk-path-body-binding"),
            json!({
                "request-id-path": "request_id", "request-id-cbor-path": [2],
                "comparison": "exact", "reject": "reject-before-durable-writes",
            }),
        ),
        (
            "portable evidence",
            &format!("{PROVIDER_RESPONSE_OPERATION}/x-dirextalk-portable-evidence"),
            json!({
                "dual-signatures": "issuance-evidence-only",
                "first-admission-and-get-require": "origin-authenticated-exact-identity-log-state-at-h-plus-1",
                "authenticated-committed-exact-replay": "before-mutable-currentness",
                "exact-transition": "direct-device-add",
                "first-admission-and-get-current-provider-and-authority-required": true,
                "no-h-plus-2": true,
                "portable-checkpoint-claimed": false,
            }),
        ),
    ] {
        expect_value(document, pointer, &expected).map_err(|error| {
            ProtocolToolError::new(format!("{operation} metadata drift: {error}"))
        })?;
    }
    for (operation, domain) in [
        (
            PREPARATION_OPERATION,
            "dirextalk.recovery-scope-catalog-handoff-preparation-idempotency.v2\0",
        ),
        (
            PROVIDER_RESPONSE_OPERATION,
            "dirextalk.recovery-scope-catalog-handoff-response-idempotency.v2\0",
        ),
    ] {
        expect_value(
            document,
            &format!("{operation}/x-dirextalk-idempotency"),
            &json!({
                "digest-domain": domain,
                "scope": "operation+identity+request",
                "same-key-identical-body": "byte-identical-original-receipt-no-writes",
                "same-key-changed-body": 409,
                "different-key-after-existence": 409,
                "raw-key-persisted-or-returned": false,
                "key-pattern": "^[A-Za-z0-9_-]{16,128}$",
                "committed-exact-replay-currentness": "not-rechecked",
            }),
        )?;
    }
    expect_value(
        document,
        &format!("{PREPARATION_OPERATION}/x-dirextalk-reject-before-write-order"),
        &json!([
            "media-and-size",
            "exact-canonical-cbor",
            "capabilities",
            "path-and-challenge-binding",
            "idempotency-key-shape-and-claim-lookup",
            "exact-body-candidate-signature-and-digest-match",
            "committed-exact-claim-resolution-before-mutable-currentness",
            "mutable-identity-public-catalog-candidate-currentness-first-admission-only",
            "one-final-cas-first-admission-only"
        ]),
    )?;
    expect_value(
        document,
        &format!("{PROVIDER_RESPONSE_OPERATION}/x-dirextalk-reject-before-write-order"),
        &json!([
            "media-accept-and-size",
            "exact-canonical-cbor",
            "authorization-and-provider-session",
            "path-and-preparation-binding",
            "idempotency-key-shape-and-claim-lookup",
            "exact-body-dual-signatures-typed-authority-and-public-digest-match",
            "public-aad-and-envelope-structure-validation-no-package-decryption",
            "committed-exact-claim-resolution-before-mutable-currentness",
            "mutable-device-add-identity-public-catalog-candidate-provider-authority-currentness-first-admission-only",
            "one-final-cas-first-admission-only"
        ]),
    )?;
    expect_value(
        document,
        &format!("{PREPARATION_OPERATION}/x-dirextalk-cas-transaction"),
        &json!({
            "count": "one",
            "lock-order": ["identity", "challenge", "preparation"],
            "final-predicate-fences": [
                "exact-identity-h-and-head-at-h",
                "exact-enrollment-challenge-and-capabilities",
                "preparation-absence-or-committed-exact-claim",
                "public-signed-catalog-id-generation-head-root-count-authority-and-validity",
                "candidate-device-signing-and-x25519-keys",
                "idempotency-claim-key-and-body-digest",
            ],
            "first-acceptance-writes": ["preparation", "immutable-preparation-receipt"],
            "exact-replay-writes": "none",
            "partial-write": "forbidden",
        }),
    )?;
    expect_value(
        document,
        &format!("{PROVIDER_RESPONSE_OPERATION}/x-dirextalk-cas-transaction"),
        &json!({
            "count": "one",
            "lock-order": ["identity", "challenge", "preparation"],
            "final-predicate-fences": [
                "exact-identity-h-head-at-h-h-plus-1-and-head-at-h-plus-1",
                "exact-enrollment-challenge",
                "exact-signed-preparation-and-stored-preparation-receipt",
                "public-signed-catalog-id-generation-head-root-count-authority-and-validity",
                "provider-session-device-id-ed25519-key-and-currentness",
                "authority-kind-id-ed25519-key-and-currentness",
                "candidate-device-ed25519-x25519-and-device-add",
                "idempotency-claim-key-and-exact-body-digest",
            ],
            "first-acceptance-writes": ["provider-response", "hpke-envelope", "immutable-provider-response-receipt"],
            "exact-replay-writes": "none",
            "partial-write": "forbidden",
        }),
    )?;
    Ok(())
}

fn expect_object_keys(
    document: &Value,
    pointer: &str,
    expected: &[&str],
) -> Result<(), ProtocolToolError> {
    let object = document
        .pointer(pointer)
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ProtocolToolError::new(format!(
                "Recovery Scope Catalog V2 OpenAPI {pointer} must be an object"
            ))
        })?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(ProtocolToolError::new(format!(
            "Recovery Scope Catalog V2 OpenAPI {pointer} keys do not match the frozen contract"
        )))
    }
}

fn expect_value(
    document: &Value,
    pointer: &str,
    expected: &Value,
) -> Result<(), ProtocolToolError> {
    if document.pointer(pointer) == Some(expected) {
        Ok(())
    } else {
        Err(ProtocolToolError::new(format!(
            "Recovery Scope Catalog V2 OpenAPI {pointer} does not match the frozen contract"
        )))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogVectorContext {
    identity_id: String,
    catalog_id: String,
    generation: u64,
    previous_head: [u8; 32],
    identity_sequence: u64,
    identity_head: [u8; 32],
    authority_device_id: String,
    authority_key_id: String,
    authority_public_key: [u8; 32],
    head_issued_at: u64,
    head_expires_at: u64,
    validation_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifierTuple {
    origin: String,
    key_id: String,
    public_key: [u8; 32],
    epoch: u64,
    descriptor_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompletionEvidenceFacts {
    algorithm: u64,
    purpose: u64,
    issuer_epk: [u8; 32],
    issuer_authorization_not_before: u64,
    issuer_authorization_expires_at: u64,
    issuer_authorization_digest: [u8; 32],
}

struct BindingFacts {
    digest: [u8; 32],
    evidence: CompletionEvidenceFacts,
}

#[derive(Clone)]
struct CatalogOpeningFacts {
    value: CanonicalValue,
    opening_digest: [u8; 32],
    private_digest: [u8; 32],
    binding_digest: [u8; 32],
    evidence: CompletionEvidenceFacts,
    leaf_digest: [u8; 32],
    scope_exact: Vec<u8>,
    nonce: [u8; 32],
}

struct PrivateBodyFacts {
    digest: [u8; 32],
    scope_exact: Vec<u8>,
    nonce: [u8; 32],
}

struct CatalogPositiveFacts {
    context: CatalogVectorContext,
    verifier: VerifierTuple,
    openings: Vec<CatalogOpeningFacts>,
    plaintext_exact: Vec<u8>,
    merkle_root: [u8; 32],
    signed_head: CanonicalValue,
}

/// The complete Catalog surface available to identity-server admission.
///
/// This deliberately contains exact signed/public data only. Candidate
/// plaintext, openings, recovery scopes, verifier descriptors, and decryption
/// material have no representation in this type.
#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogServerProjection {
    signed_head_exact: Vec<u8>,
    signed_head_digest: [u8; 32],
    identity_id: String,
    catalog_id: String,
    generation: u64,
    previous_head_digest: [u8; 32],
    leaf_count: u64,
    merkle_root: [u8; 32],
    identity_sequence: u64,
    identity_head_digest: [u8; 32],
    authority_device_id: String,
    authority_key_id: String,
    authority_public_key: [u8; 32],
    head_issued_at: u64,
    head_expires_at: u64,
    validation_time: u64,
    ciphertext: Vec<u8>,
    ciphertext_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OriginActiveDevice {
    device_id: String,
    signing_public_key: [u8; 32],
    encryption_public_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OriginIdentityState {
    sequence: u64,
    head_digest: [u8; 32],
    current_root_public_key: [u8; 32],
    current_recovery_public_key: [u8; 32],
    active_devices: Vec<OriginActiveDevice>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OriginAuthenticatedIdentityLog {
    origin: String,
    at_h: OriginIdentityState,
    at_h_plus_1: OriginIdentityState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OriginAuthenticatedCurrentIdentitySnapshot {
    origin: String,
    state: OriginIdentityState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ServerVisibleHandoffInput {
    preparation: Value,
    origin_authenticated_identity_log: Value,
    device_add: Value,
    provider_response: Value,
    public_aad: Value,
    hpke_envelope: Value,
    mutation_receipts: Value,
    statuses: Value,
    enrollment_candidate_recipient_public_key: [u8; 32],
    response_capability: [u8; 32],
    preparation_idempotency_key: Vec<u8>,
    response_idempotency_key: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OriginAuthenticatedVerifierDescriptor {
    origin: String,
    key_id: String,
    public_key: [u8; 32],
    epoch: u64,
    descriptor_digest: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    signed_exact: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OriginAuthenticatedVerifierOracle {
    by_origin: BTreeMap<String, OriginAuthenticatedVerifierDescriptor>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndependentAuthorityKind {
    ActiveDevice,
    CurrentRoot,
    CurrentRecovery,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ServerVisibleHandoffFacts {
    request_id: String,
    candidate_device_id: String,
    candidate_signing_public_key: [u8; 32],
    candidate_recipient_public_key: [u8; 32],
    preparation_exact: Vec<u8>,
    preparation_digest: [u8; 32],
    identity_log: OriginAuthenticatedIdentityLog,
    device_add_exact: Vec<u8>,
    device_add_digest: [u8; 32],
    public_aad_exact: Vec<u8>,
    envelope_exact: Vec<u8>,
    envelope_enc: [u8; 32],
    envelope_ciphertext: Vec<u8>,
    provider_response_exact: Vec<u8>,
    provider_response_digest: [u8; 32],
    independent_authority_kind: IndependentAuthorityKind,
    independent_authority_key: [u8; 32],
    preparation_receipt_exact: Vec<u8>,
    provider_response_receipt_exact: Vec<u8>,
    status_exact: [Vec<u8>; 5],
}

struct DecodedHandoffEnvelope {
    exact: Vec<u8>,
    enc: [u8; 32],
    ciphertext: Vec<u8>,
}

fn validate_catalog_vector(
    root: &Path,
    cddl: &str,
    openapi: &str,
) -> Result<(), ProtocolToolError> {
    let vector = read_catalog_vector(root)?;
    validate_vector_metadata(&vector, cddl, openapi)?;
    let catalog_projection = validate_catalog_server_projection(&vector, cddl)?;
    let handoff_input = parse_server_visible_handoff_input(&vector)?;
    let server_visible =
        validate_server_visible_handoff(cddl, &catalog_projection, &handoff_input)?;
    let facts = validate_positive_vector(&vector, cddl)?;
    validate_candidate_handoff(&vector, cddl, &server_visible, &facts)?;
    validate_handoff_authority_variants(
        &vector,
        cddl,
        &catalog_projection,
        &server_visible,
        &facts,
    )?;
    validate_handoff_hpke_alternates(&vector, cddl, &server_visible)?;
    validate_handoff_signature_alternates(&vector, cddl, &server_visible)?;
    validate_handoff_b2b_families(&vector, cddl, &catalog_projection, &server_visible, &facts)?;
    validate_negative_vector_family(&vector, cddl, &facts)?;
    validate_completion_evidence_negative_vector_family(&vector, cddl, &facts)
}

fn read_catalog_vector(root: &Path) -> Result<Value, ProtocolToolError> {
    let path = root.join(VECTOR_PATH);
    let source = fs::read_to_string(&path).map_err(|error| {
        ProtocolToolError::new(format!(
            "read Recovery Scope Catalog V2 vector {}: {error}",
            path.display()
        ))
    })?;
    serde_json::from_str(&source).map_err(|error| {
        ProtocolToolError::new(format!(
            "parse Recovery Scope Catalog V2 vector {}: {error}",
            path.display()
        ))
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "vector metadata must exactly cross-check JSON, CDDL, and OpenAPI in one gate"
)]
fn validate_vector_metadata(
    vector: &Value,
    cddl: &str,
    openapi: &str,
) -> Result<(), ProtocolToolError> {
    require_json_keys(
        vector,
        &[
            "baseline",
            "catalog",
            "catalog_authority_public_key_hex",
            "domains",
            "hpke_aad",
            "hpke_info",
            "handoff",
            "handoff_alternate_constructions",
            "handoff_authority_variants",
            "handoff_b2b",
            "limits",
            "media_types",
            "negative_cbor",
            "negative_completion_evidence",
            "origin_authenticated_completion_verifier_descriptors",
            "rotated_verifier_public_key_hex",
            "verifier_public_key_hex",
            "version",
            "wrong_authority_public_key_hex",
        ],
        "Catalog V2 vector",
    )?;
    if json_u64(vector, "version")? != 2 || json_u64(vector, "baseline")? != 42 {
        return Err(ProtocolToolError::new(
            "Catalog V2 vector version or baseline drift",
        ));
    }
    let limits = json_field(vector, "limits", "Catalog V2 vector")?;
    require_json_keys(
        limits,
        &[
            "catalog_plaintext_ceiling_bytes",
            "consecutive_one_based_indices_required",
            "count_boundary_classification",
            "index_occurrences_per_opening",
            "indices_24_through_255_count",
            "indices_24_through_255_extra_bytes_per_opening",
            "indices_256_plus_extra_bytes_per_opening",
            "indices_256_through_1023_count",
            "max_catalog_upload_body_bytes",
            "max_ciphertext_bytes",
            "max_device_add_bytes",
            "max_envelope_bytes",
            "max_hpke_ciphertext_bytes",
            "max_hpke_encoded_envelope_bytes",
            "max_leaf_count",
            "max_leaf_count_minimum_bytes",
            "max_leaf_count_plus_one",
            "max_leaf_count_plus_one_minimum_bytes",
            "max_preparation_body_bytes",
            "max_proof_siblings",
            "max_provider_package_bytes",
            "max_provider_response_body_bytes",
            "max_signed_catalog_head_bytes",
            "max_status_body_bytes",
            "minimum_outer_plaintext_overhead_bytes",
            "minimum_valid_opening_bytes",
            "one_byte_index_maximum",
            "two_byte_index_maximum",
        ],
        "Catalog V2 limits",
    )?;
    let derived_maximum_bytes = MIN_CATALOG_PLAINTEXT_OVERHEAD_BYTES
        + MAX_CATALOG_LEAVES * MIN_CATALOG_OPENING_BYTES
        + CATALOG_MIDDLE_INDEX_COUNT * CATALOG_MIDDLE_INDEX_EXTRA_BYTES
        + CATALOG_LARGE_INDEX_COUNT * CATALOG_LARGE_INDEX_EXTRA_BYTES;
    let derived_overflow_bytes = MIN_CATALOG_PLAINTEXT_OVERHEAD_BYTES
        + (MAX_CATALOG_LEAVES + 1) * MIN_CATALOG_OPENING_BYTES
        + CATALOG_MIDDLE_INDEX_COUNT * CATALOG_MIDDLE_INDEX_EXTRA_BYTES
        + (CATALOG_LARGE_INDEX_COUNT + 1) * CATALOG_LARGE_INDEX_EXTRA_BYTES;
    if CATALOG_MIDDLE_INDEX_COUNT != CATALOG_TWO_BYTE_INDEX_MAXIMUM - CATALOG_ONE_BYTE_INDEX_MAXIMUM
        || CATALOG_LARGE_INDEX_COUNT != MAX_CATALOG_LEAVES - CATALOG_TWO_BYTE_INDEX_MAXIMUM
        || CATALOG_MIDDLE_INDEX_EXTRA_BYTES != CATALOG_INDEX_OCCURRENCES_PER_OPENING
        || CATALOG_LARGE_INDEX_EXTRA_BYTES != 2 * CATALOG_INDEX_OCCURRENCES_PER_OPENING
        || derived_maximum_bytes != MAX_MINIMAL_CATALOG_BYTES
        || derived_overflow_bytes != MIN_OVERFLOW_CATALOG_BYTES
        || limits
            .get("consecutive_one_based_indices_required")
            .and_then(Value::as_bool)
            != Some(true)
        || json_u64(limits, "index_occurrences_per_opening")?
            != u64::try_from(CATALOG_INDEX_OCCURRENCES_PER_OPENING)
                .expect("index occurrence count fits u64")
        || json_u64(limits, "one_byte_index_maximum")?
            != u64::try_from(CATALOG_ONE_BYTE_INDEX_MAXIMUM)
                .expect("one-byte index maximum fits u64")
        || json_u64(limits, "two_byte_index_maximum")?
            != u64::try_from(CATALOG_TWO_BYTE_INDEX_MAXIMUM)
                .expect("two-byte index maximum fits u64")
        || json_u64(limits, "indices_24_through_255_count")?
            != u64::try_from(CATALOG_MIDDLE_INDEX_COUNT).expect("middle index count fits u64")
        || json_u64(limits, "indices_24_through_255_extra_bytes_per_opening")?
            != u64::try_from(CATALOG_MIDDLE_INDEX_EXTRA_BYTES)
                .expect("middle index extra bytes fit u64")
        || json_u64(limits, "indices_256_through_1023_count")?
            != u64::try_from(CATALOG_LARGE_INDEX_COUNT).expect("large index count fits u64")
        || json_u64(limits, "indices_256_plus_extra_bytes_per_opening")?
            != u64::try_from(CATALOG_LARGE_INDEX_EXTRA_BYTES)
                .expect("large index extra bytes fit u64")
        || json_u64(limits, "max_leaf_count")?
            != u64::try_from(MAX_CATALOG_LEAVES).expect("catalog count fits u64")
        || json_u64(limits, "max_leaf_count_plus_one")?
            != u64::try_from(MAX_CATALOG_LEAVES + 1).expect("catalog max+1 fits u64")
        || json_u64(limits, "catalog_plaintext_ceiling_bytes")?
            != u64::try_from(MAX_CIPHERTEXT_BYTES).expect("plaintext ceiling fits u64")
        || json_u64(limits, "minimum_valid_opening_bytes")?
            != u64::try_from(MIN_CATALOG_OPENING_BYTES).expect("opening minimum fits u64")
        || json_u64(limits, "minimum_outer_plaintext_overhead_bytes")?
            != u64::try_from(MIN_CATALOG_PLAINTEXT_OVERHEAD_BYTES)
                .expect("plaintext overhead fits u64")
        || json_u64(limits, "max_leaf_count_minimum_bytes")?
            != u64::try_from(MAX_MINIMAL_CATALOG_BYTES).expect("catalog maximum fits u64")
        || json_u64(limits, "max_leaf_count_plus_one_minimum_bytes")?
            != u64::try_from(MIN_OVERFLOW_CATALOG_BYTES).expect("catalog overflow fits u64")
        || json_string(limits, "count_boundary_classification")?
            != "structural_cddl_and_consecutive_index_semantic_size_model_not_1023_opening_full_crypto"
        || json_u64(limits, "max_ciphertext_bytes")?
            != u64::try_from(MAX_CIPHERTEXT_BYTES).expect("ciphertext limit fits u64")
        || json_u64(limits, "max_catalog_upload_body_bytes")?
            != u64::try_from(MAX_CATALOG_UPLOAD_BODY_BYTES)
                .expect("Catalog upload body limit fits u64")
        || json_u64(limits, "max_envelope_bytes")?
            != u64::try_from(MAX_ENVELOPE_BYTES).expect("envelope limit fits u64")
        || json_u64(limits, "max_proof_siblings")?
            != u64::try_from(MAX_PROOF_SIBLINGS).expect("proof sibling maximum fits u64")
        || json_u64(limits, "max_preparation_body_bytes")?
            != u64::try_from(MAX_PREPARATION_BODY_BYTES).expect("preparation limit fits u64")
        || json_u64(limits, "max_provider_package_bytes")?
            != u64::try_from(MAX_PROVIDER_PACKAGE_BYTES).expect("package limit fits u64")
        || json_u64(limits, "max_hpke_ciphertext_bytes")?
            != u64::try_from(MAX_HPKE_CIPHERTEXT_BYTES).expect("HPKE limit fits u64")
        || json_u64(limits, "max_hpke_encoded_envelope_bytes")?
            != u64::try_from(MAX_HPKE_ENCODED_ENVELOPE_BYTES).expect("HPKE envelope limit fits u64")
        || json_u64(limits, "max_device_add_bytes")?
            != u64::try_from(MAX_DEVICE_ADD_BYTES).expect("DeviceAdd limit fits u64")
        || json_u64(limits, "max_provider_response_body_bytes")?
            != u64::try_from(MAX_PROVIDER_RESPONSE_BODY_BYTES).expect("response limit fits u64")
        || json_u64(limits, "max_signed_catalog_head_bytes")?
            != u64::try_from(MAX_SIGNED_CATALOG_HEAD_BYTES)
                .expect("signed Catalog head limit fits u64")
        || json_u64(limits, "max_status_body_bytes")?
            != u64::try_from(MAX_STATUS_BODY_BYTES).expect("status limit fits u64")
    {
        return Err(ProtocolToolError::new("Catalog V2 vector limit drift"));
    }
    let media = json_field(vector, "media_types", "Catalog V2 vector")?;
    require_json_keys(
        media,
        &[
            "catalog_head",
            "catalog_upload",
            "preparation",
            "preparation_receipt",
            "provider_response",
            "provider_response_receipt",
            "status",
        ],
        "Catalog V2 media types",
    )?;
    if json_string(media, "catalog_upload")? != REQUEST_MEDIA
        || json_string(media, "catalog_head")? != RESPONSE_MEDIA
        || json_string(media, "preparation")? != PREPARATION_MEDIA
        || json_string(media, "preparation_receipt")? != PREPARATION_RECEIPT_MEDIA
        || json_string(media, "provider_response")? != PROVIDER_RESPONSE_MEDIA
        || json_string(media, "provider_response_receipt")? != PROVIDER_RESPONSE_RECEIPT_MEDIA
        || json_string(media, "status")? != STATUS_MEDIA
    {
        return Err(ProtocolToolError::new("Catalog V2 vector media type drift"));
    }
    let expected_domains = json!({
        "membership_receipt": String::from_utf8_lossy(MEMBERSHIP_RECEIPT_DOMAIN),
        "recovery_scope": String::from_utf8_lossy(RECOVERY_SCOPE_DOMAIN),
        "private_body": String::from_utf8_lossy(PRIVATE_BODY_DOMAIN),
        "opening": String::from_utf8_lossy(OPENING_DOMAIN),
        "verifier_binding": String::from_utf8_lossy(VERIFIER_BINDING_DOMAIN),
        "verifier_binding_signature": String::from_utf8_lossy(VERIFIER_BINDING_SIGNATURE_DOMAIN),
        "completion_verifier_descriptor": String::from_utf8_lossy(COMPLETION_VERIFIER_DESCRIPTOR_DOMAIN),
        "completion_verifier_descriptor_signature": String::from_utf8_lossy(COMPLETION_VERIFIER_DESCRIPTOR_SIGNATURE_DOMAIN),
        "completion_evidence_pop": String::from_utf8_lossy(COMPLETION_EVIDENCE_POP_DOMAIN),
        "completion_evidence_origin_authorization": String::from_utf8_lossy(COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN),
        "completion_evidence_authorization_digest": String::from_utf8_lossy(COMPLETION_EVIDENCE_AUTHORIZATION_DIGEST_DOMAIN),
        "leaf_commitment": String::from_utf8_lossy(LEAF_COMMITMENT_DOMAIN),
        "ciphertext": String::from_utf8_lossy(CIPHERTEXT_DOMAIN),
        "head": String::from_utf8_lossy(HEAD_DOMAIN),
        "head_signature": String::from_utf8_lossy(HEAD_SIGNATURE_DOMAIN),
        "merkle_node": String::from_utf8_lossy(MERKLE_NODE_DOMAIN),
        "response_capability": "dirextalk.recovery-response-capability.v1\0",
        "recipient_key": "dirextalk.recovery-recipient-key.v1\0",
        "device_history_authority_id": "dirextalk.device-history-authority-id.v1\0",
        "identity_device_add": "dirextalk.identity-device-add.v1\0",
        "preparation_idempotency": "dirextalk.recovery-scope-catalog-handoff-preparation-idempotency.v2\0",
        "response_idempotency": "dirextalk.recovery-scope-catalog-handoff-response-idempotency.v2\0",
        "preparation_signature": "dirextalk.recovery-scope-catalog-handoff-preparation-signature.v2\0",
        "preparation_digest": "dirextalk.recovery-scope-catalog-handoff-preparation-digest.v2\0",
        "provider_package": "dirextalk.recovery-scope-catalog-handoff-provider-package.v2\0",
        "provider_aad": "dirextalk.recovery-scope-catalog-handoff-provider-aad.v2\0",
        "provider_envelope": "dirextalk.recovery-scope-catalog-handoff-provider-envelope.v2\0",
        "provider_signature": "dirextalk.recovery-scope-catalog-handoff-provider-signature.v2\0",
        "provider_authority_signature": "dirextalk.recovery-scope-catalog-handoff-provider-authority-signature.v2\0",
        "provider_response": "dirextalk.recovery-scope-catalog-handoff-provider-response.v2\0",
    });
    if vector.get("domains") != Some(&expected_domains) {
        return Err(ProtocolToolError::new(
            "Catalog V2 vector domain assertions drifted",
        ));
    }
    let cddl_domains = parse_crypto_domain_declarations(cddl)?;
    if json_string(vector, "hpke_info")? != HPKE_INFO {
        return Err(ProtocolToolError::new(
            "Catalog V2 HPKE info metadata drifted",
        ));
    }
    let expected_hpke_aad = json!({
        "cddl_rule": "recovery-scope-catalog-provider-public-aad-v2",
        "input": "exact_deterministic_canonical_cbor_bytes",
        "forbidden_inputs": [
            "response_field_18_digest",
            "provider_aad_domain_prefixed",
            "json",
            "hex",
            "alternate_cbor_encoding",
        ],
        "deterministic_vector_required_in": "C1b-B",
    });
    if vector.get("hpke_aad") != Some(&expected_hpke_aad) {
        return Err(ProtocolToolError::new(
            "Catalog V2 HPKE AAD byte-selection metadata drifted",
        ));
    }
    if cddl_domains.len() != 30
        || cddl_domains.values().any(|domain| {
            let actual = domain.replace("\\0", "\0");
            !expected_domains.as_object().is_some_and(|domains| {
                domains
                    .values()
                    .any(|value| value.as_str() == Some(&actual))
            })
        })
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 vector domains do not equal CDDL declarations",
        ));
    }
    let openapi_document = parse_openapi(openapi)?;
    let openapi_domains = openapi_document
        .pointer(&format!("{OPENAPI_OPERATION}/x-dirextalk-crypto-domains"))
        .and_then(Value::as_object)
        .ok_or_else(|| ProtocolToolError::new("Catalog V2 OpenAPI crypto domains missing"))?;
    let openapi_handoff_domains = openapi_document
        .pointer("/x-dirextalk-handoff-crypto-domains")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ProtocolToolError::new("Catalog V2 OpenAPI handoff crypto domains missing")
        })?;
    let openapi_domain_values = openapi_domains
        .values()
        .chain(openapi_handoff_domains.values())
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| ProtocolToolError::new("Catalog V2 OpenAPI domain must be a string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected_domain_values = expected_domains
        .as_object()
        .expect("frozen domains are an object")
        .values()
        .map(|value| value.as_str().expect("frozen domain must be a string"))
        .collect::<BTreeSet<_>>();
    if openapi_domains.len() != 16
        || openapi_handoff_domains.len() != 14
        || openapi_domain_values != expected_domain_values
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 vector domains do not equal OpenAPI metadata",
        ));
    }
    if openapi_document.pointer("/x-dirextalk-handoff-hpke/info") != vector.get("hpke_info")
        || openapi_domain_values
            .iter()
            .any(|domain| *domain == HPKE_INFO)
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 HPKE info must be exact and separate from hash domains",
        ));
    }
    let hpke_aad = vector
        .get("hpke_aad")
        .expect("frozen HPKE AAD metadata was validated");
    if openapi_document.pointer("/x-dirextalk-handoff-hpke/public-aad-cddl-rule")
        != hpke_aad.get("cddl_rule")
        || openapi_document
            .pointer("/x-dirextalk-handoff-hpke/deterministic-hpke-vector-required-in")
            != hpke_aad.get("deterministic_vector_required_in")
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 HPKE AAD metadata does not match OpenAPI",
        ));
    }
    for field in [
        "catalog_authority_public_key_hex",
        "wrong_authority_public_key_hex",
        "verifier_public_key_hex",
        "rotated_verifier_public_key_hex",
    ] {
        decode_json_fixed::<32>(vector, field)?;
    }
    Ok(())
}

fn validate_handoff_b2b_families(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    let b2b = json_field(vector, "handoff_b2b", "Catalog V2 vector")?;
    require_json_keys(
        b2b,
        &[
            "classification",
            "currentness_drifts",
            "decoder_privacy_closure",
            "get_state_traces",
            "limitations",
            "recipient_bindings",
            "sealed_package_mismatches",
            "state_idempotency_traces",
            "time_boundaries",
            "verifier_rotation",
        ],
        "Catalog V2 C1b-B2b families",
    )?;
    require_handoff(
        json_string(b2b, "classification")?
            == "public-deterministic-authentic-handoff-boundary-fixtures-not-credentials",
        "B2b fixture classification drifted",
    )?;
    validate_b2b_recipient_bindings(vector, cddl, catalog_projection, base, catalog, b2b)?;
    validate_b2b_sealed_package_mismatches(vector, cddl, catalog_projection, base, catalog, b2b)?;
    validate_b2b_verifier_rotation(vector, cddl, catalog_projection, base, catalog, b2b)?;
    validate_b2b_state_idempotency(vector, cddl, catalog_projection, base, catalog, b2b)?;
    validate_b2b_get_states(vector, cddl, base, b2b)?;
    validate_b2b_currentness(vector, cddl, catalog_projection, base, b2b)?;
    validate_b2b_time_boundaries(vector, cddl, catalog_projection, base, catalog, b2b)?;
    validate_b2b_decoder_privacy(vector, cddl, catalog_projection, b2b)?;
    validate_b2b_limitations(b2b)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct B2bPreparationFacts {
    exact: Vec<u8>,
    digest: [u8; 32],
    request_id: String,
    candidate_device_id: String,
    signing_public_key: [u8; 32],
    recipient_public_key: [u8; 32],
    signed_head_digest: [u8; 32],
    response_capability_digest: [u8; 32],
    idempotency_digest: [u8; 32],
    issued_at: u64,
    expires_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct B2bCryptoFacts {
    preparation: B2bPreparationFacts,
    package_exact: Vec<u8>,
    package: CanonicalValue,
    public_aad_exact: Vec<u8>,
    envelope_exact: Vec<u8>,
    provider_response_exact: Vec<u8>,
    provider_response_digest: [u8; 32],
    preparation_receipt_exact: Vec<u8>,
    provider_response_receipt_exact: Vec<u8>,
    status_exact: [Vec<u8>; 5],
}

fn expect_b2b_target_error<T>(
    result: Result<T, ProtocolToolError>,
    label: &str,
    expected: &str,
) -> Result<(), ProtocolToolError> {
    match result {
        Err(error) if error.to_string().contains(expected) => Ok(()),
        Err(error) => Err(handoff_error(&format!(
            "B2b {label} reached the wrong target check: {error}"
        ))),
        Ok(_) => Err(handoff_error(&format!("B2b {label} was accepted"))),
    }
}

fn require_b2b_handoff_shape(handoff: &Value, label: &str) -> Result<(), ProtocolToolError> {
    require_json_keys(
        handoff,
        &[
            "device_add",
            "hpke_envelope",
            "mutation_receipts",
            "origin_authenticated_identity_log",
            "package",
            "preparation",
            "provider_response",
            "public_aad",
            "statuses",
            "test_only_inputs",
        ],
        label,
    )
}

/// Applies the RFC 7748 contributory-behaviour check used by preparation
/// admission.  The validation scalar is public and deterministic: this is a
/// semantic public-key check, not a key-generation or credential path.
fn validate_recipient_public_key_semantics(
    recipient_public_key: [u8; 32],
) -> Result<(), ProtocolToolError> {
    type Kem = X25519HkdfSha256;

    let validation_private_key =
        <Kem as KemTrait>::PrivateKey::from_bytes(&X25519_PUBLIC_VALIDATION_SCALAR)
            .map_err(|_| handoff_error("fixed public X25519 validation scalar is invalid"))?;
    let candidate = <Kem as KemTrait>::EncappedKey::from_bytes(&recipient_public_key)
        .map_err(|_| handoff_error("all-zero or low-order X25519 recipient key rejected"))?;
    <Kem as KemTrait>::decap(&validation_private_key, None, &candidate)
        .map(|_| ())
        .map_err(|_| handoff_error("all-zero or low-order X25519 recipient key rejected"))
}

fn validate_b2b_preparation_artifact(
    cddl: &str,
    catalog: &CatalogServerProjection,
    artifact: &Value,
    response_capability: [u8; 32],
    idempotency_key: &[u8],
) -> Result<B2bPreparationFacts, ProtocolToolError> {
    require_json_keys(
        artifact,
        &[
            "candidate_device_id",
            "candidate_signing_public_key_hex",
            "cbor_hex",
            "digest_hex",
            "recipient_public_key_hex",
            "request_id",
            "signature_hex",
            "unsigned_cbor_hex",
        ],
        "Catalog V2 B2b preparation artifact",
    )?;
    let (exact, value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-preparation-v2",
        json_string(artifact, "cbor_hex")?,
        "Catalog V2 B2b preparation artifact",
    )?;
    require_handoff(
        exact.len() <= MAX_PREPARATION_BODY_BYTES,
        "B2b preparation exceeds its body bound",
    )?;
    let fields = numbered_fields(&value, 17, "Catalog V2 B2b preparation")?;
    let unsigned = encoded_unsigned_prefix(&value, 16, "Catalog V2 B2b preparation")?;
    let request_id = cbor_text(fields[1], "B2b preparation request")?.to_owned();
    let candidate_device_id = cbor_text(fields[6], "B2b preparation candidate")?.to_owned();
    let signing_public_key = cbor_fixed(fields[7], "B2b preparation signing key")?;
    let recipient_public_key = cbor_fixed(fields[8], "B2b preparation recipient key")?;
    let signed_head_digest = cbor_fixed(fields[5], "B2b preparation head digest")?;
    let response_capability_digest =
        cbor_fixed(fields[12], "B2b preparation response capability digest")?;
    let idempotency_digest = cbor_fixed(fields[13], "B2b preparation idempotency digest")?;
    let issued_at = cbor_unsigned(fields[14], "B2b preparation issued_at")?;
    let expires_at = cbor_unsigned(fields[15], "B2b preparation expires_at")?;
    let signature = cbor_fixed(fields[16], "B2b preparation signature")?;
    verify_signature(
        signing_public_key,
        PREPARATION_SIGNATURE_DOMAIN,
        &unsigned,
        signature,
        "B2b preparation",
    )?;
    validate_recipient_public_key_semantics(recipient_public_key)?;
    let preparation_digest = domain_digest(PREPARATION_DIGEST_DOMAIN, &exact);
    require_handoff(
        cbor_unsigned(fields[0], "B2b preparation version")? == 2
            && valid_uuid_v7(&request_id)
            && valid_uuid_v7(&candidate_device_id)
            && cbor_text(fields[2], "B2b preparation identity")? == catalog.identity_id
            && cbor_text(fields[3], "B2b preparation catalog")? == catalog.catalog_id
            && cbor_unsigned(fields[4], "B2b preparation generation")? == catalog.generation
            && signed_head_digest == catalog.signed_head_digest
            && cbor_unsigned(fields[9], "B2b preparation H")? == catalog.identity_sequence
            && cbor_fixed::<32>(fields[10], "B2b preparation head at H")?
                == catalog.identity_head_digest
            && cbor_fixed::<32>(fields[11], "B2b preparation nonce")? != [0; 32]
            && response_capability_digest
                == domain_digest(RESPONSE_CAPABILITY_DOMAIN, &response_capability)
            && idempotency_digest == domain_digest(PREPARATION_IDEMPOTENCY_DOMAIN, idempotency_key)
            && decode_lower_hex(json_string(artifact, "unsigned_cbor_hex")?)? == unsigned
            && decode_json_fixed::<64>(artifact, "signature_hex")? == signature
            && decode_json_fixed::<32>(artifact, "digest_hex")? == preparation_digest
            && json_string(artifact, "request_id")? == request_id
            && json_string(artifact, "candidate_device_id")? == candidate_device_id
            && decode_json_fixed::<32>(artifact, "candidate_signing_public_key_hex")?
                == signing_public_key
            && decode_json_fixed::<32>(artifact, "recipient_public_key_hex")?
                == recipient_public_key,
        "B2b preparation lower structural, coordinate, header-digest, signature, or JSON proof drifted",
    )?;
    Ok(B2bPreparationFacts {
        exact,
        digest: preparation_digest,
        request_id,
        candidate_device_id,
        signing_public_key,
        recipient_public_key,
        signed_head_digest,
        response_capability_digest,
        idempotency_digest,
        issued_at,
        expires_at,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "B2b negative fixtures must prove every lower crypto, receipt, and status layer before their target semantic"
)]
fn validate_b2b_authentic_crypto_handoff(
    cddl: &str,
    catalog: &CatalogServerProjection,
    handoff: &Value,
    label: &str,
) -> Result<B2bCryptoFacts, ProtocolToolError> {
    type Kem = X25519HkdfSha256;
    type Aead = ChaCha20Poly1305;
    type Kdf = HkdfSha256;

    require_b2b_handoff_shape(handoff, label)?;
    let inputs = json_field(handoff, "test_only_inputs", label)?;
    require_json_keys(
        inputs,
        &[
            "classification",
            "enrollment_candidate_recipient_public_key_hex",
            "preparation_idempotency_key_ascii",
            "response_capability_hex",
            "response_idempotency_key_ascii",
            "x25519_recipient_private_key_hex",
        ],
        &format!("{label} test inputs"),
    )?;
    require_handoff(
        json_string(inputs, "classification")?
            == "public-deterministic-test-fixture-not-a-credential",
        &format!("{label} test-input classification drifted"),
    )?;
    let response_capability = decode_json_fixed(inputs, "response_capability_hex")?;
    let preparation_idempotency_key =
        json_string(inputs, "preparation_idempotency_key_ascii")?.as_bytes();
    let preparation = validate_b2b_preparation_artifact(
        cddl,
        catalog,
        json_field(handoff, "preparation", label)?,
        response_capability,
        preparation_idempotency_key,
    )?;
    require_handoff(
        decode_json_fixed::<32>(inputs, "enrollment_candidate_recipient_public_key_hex")?
            == preparation.recipient_public_key,
        &format!("{label} enrollment/preparation recipient binding drifted"),
    )?;

    let response_json = json_field(handoff, "provider_response", label)?;
    require_json_keys(
        response_json,
        &[
            "authority_signature_hex",
            "cbor_hex",
            "digest_hex",
            "provider_signature_hex",
            "unsigned_cbor_hex",
        ],
        &format!("{label} provider response"),
    )?;
    let (provider_response_exact, response_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-provider-response-v2",
        json_string(response_json, "cbor_hex")?,
        &format!("{label} provider response"),
    )?;
    require_handoff(
        provider_response_exact.len() <= MAX_PROVIDER_RESPONSE_BODY_BYTES,
        &format!("{label} response exceeds its bound"),
    )?;
    let response = numbered_fields(&response_value, 26, &format!("{label} response"))?;
    let response_unsigned = encoded_unsigned_prefix(&response_value, 22, label)?;
    let provider_descriptor = numbered_fields(response[14], 3, label)?;
    let authority_descriptor = numbered_fields(response[15], 3, label)?;
    let provider_key = cbor_fixed(provider_descriptor[2], "B2b provider key")?;
    let authority_key = cbor_fixed(authority_descriptor[2], "B2b authority key")?;
    let provider_signature = cbor_fixed(response[22], "B2b provider signature")?;
    let authority_signature = cbor_fixed(response[23], "B2b authority signature")?;
    verify_signature(
        provider_key,
        PROVIDER_SIGNATURE_DOMAIN,
        &response_unsigned,
        provider_signature,
        label,
    )?;
    verify_signature(
        authority_key,
        PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
        &response_unsigned,
        authority_signature,
        label,
    )?;
    let provider_response_digest =
        domain_digest(PROVIDER_RESPONSE_DOMAIN, &provider_response_exact);
    require_handoff(
        cbor_unsigned(provider_descriptor[0], "B2b provider version")? == 2
            && provider_key != preparation.signing_public_key
            && authority_key != preparation.signing_public_key
            && authority_key != provider_key
            && cbor_text(response[1], "B2b response request")? == preparation.request_id
            && cbor_fixed::<32>(response[2], "B2b response preparation digest")?
                == preparation.digest
            && cbor_text(response[3], "B2b response identity")? == catalog.identity_id
            && cbor_text(response[4], "B2b response catalog")? == catalog.catalog_id
            && cbor_unsigned(response[5], "B2b response generation")? == catalog.generation
            && cbor_fixed::<32>(response[6], "B2b response Catalog head")?
                == catalog.signed_head_digest
            && cbor_text(response[7], "B2b response candidate")? == preparation.candidate_device_id
            && cbor_fixed::<32>(response[8], "B2b response recipient digest")?
                == domain_digest(RECIPIENT_KEY_DOMAIN, &preparation.recipient_public_key)
            && cbor_fixed::<32>(response[19], "B2b response idempotency digest")?
                == domain_digest(
                    RESPONSE_IDEMPOTENCY_DOMAIN,
                    json_string(inputs, "response_idempotency_key_ascii")?.as_bytes(),
                )
            && decode_lower_hex(json_string(response_json, "unsigned_cbor_hex")?)?
                == response_unsigned
            && decode_json_fixed::<64>(response_json, "provider_signature_hex")?
                == provider_signature
            && decode_json_fixed::<64>(response_json, "authority_signature_hex")?
                == authority_signature
            && decode_json_fixed::<32>(response_json, "digest_hex")? == provider_response_digest,
        &format!("{label} response lower coordinates, signatures, or JSON proof drifted"),
    )?;

    let aad_json = json_field(handoff, "public_aad", label)?;
    require_json_keys(
        aad_json,
        &["cbor_hex", "digest_hex"],
        &format!("{label} AAD"),
    )?;
    let (public_aad_exact, aad_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-provider-public-aad-v2",
        json_string(aad_json, "cbor_hex")?,
        &format!("{label} AAD"),
    )?;
    let expected_aad = CanonicalValue::Map(
        response[..17]
            .iter()
            .chain(response[19..22].iter())
            .enumerate()
            .map(|(index, value)| {
                (
                    CanonicalValue::Unsigned(
                        u64::try_from(index + 1).expect("bounded B2b AAD field"),
                    ),
                    (*value).clone(),
                )
            })
            .collect(),
    );
    let aad_digest = domain_digest(PROVIDER_AAD_DOMAIN, &public_aad_exact);
    require_handoff(
        aad_value == expected_aad
            && cbor_fixed::<32>(response[17], "B2b response AAD digest")? == aad_digest
            && decode_json_fixed::<32>(aad_json, "digest_hex")? == aad_digest,
        &format!("{label} raw canonical AAD proof drifted"),
    )?;

    let envelope_json = json_field(handoff, "hpke_envelope", label)?;
    require_json_keys(
        envelope_json,
        &["cbor_hex", "ciphertext_hex", "digest_hex", "enc_hex"],
        &format!("{label} envelope"),
    )?;
    let envelope = decode_handoff_envelope(
        cddl,
        json_string(envelope_json, "cbor_hex")?,
        &format!("{label} envelope"),
    )?;
    let envelope_value = decode_exact_bytes(&envelope.exact, label)?;
    let envelope_digest = domain_digest(PROVIDER_ENVELOPE_DOMAIN, &envelope.exact);
    require_handoff(
        envelope_value == *response[25]
            && decode_json_fixed::<32>(envelope_json, "enc_hex")? == envelope.enc
            && decode_lower_hex(json_string(envelope_json, "ciphertext_hex")?)?
                == envelope.ciphertext
            && decode_json_fixed::<32>(envelope_json, "digest_hex")? == envelope_digest
            && cbor_fixed::<32>(response[18], "B2b response envelope digest")? == envelope_digest,
        &format!("{label} exact envelope proof drifted"),
    )?;

    let recipient_private = decode_json_fixed::<32>(inputs, "x25519_recipient_private_key_hex")?;
    let private_key = <Kem as KemTrait>::PrivateKey::from_bytes(&recipient_private)
        .map_err(|error| handoff_error(&format!("{label} recipient private invalid: {error}")))?;
    require_handoff(
        Kem::sk_to_pk(&private_key).to_bytes().as_slice() == preparation.recipient_public_key,
        &format!("{label} protected recipient secret does not derive the preparation key"),
    )?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&envelope.enc)
        .map_err(|error| handoff_error(&format!("{label} HPKE enc invalid: {error}")))?;
    let mut receiver = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &private_key,
        &encapped,
        HPKE_INFO.as_bytes(),
    )
    .map_err(|error| handoff_error(&format!("{label} HPKE receiver setup failed: {error}")))?;
    let package_exact = receiver
        .open(&envelope.ciphertext, &public_aad_exact)
        .map_err(|error| handoff_error(&format!("{label} HPKE open failed: {error}")))?;
    require_handoff(
        package_exact.len() <= MAX_PROVIDER_PACKAGE_BYTES,
        &format!("{label} package exceeds its bound"),
    )?;
    let package = decode_exact_bytes(&package_exact, &format!("{label} package"))?;
    cddl_cat::validate_cbor_bytes(
        "recovery-scope-catalog-provider-package-v2",
        cddl,
        &package_exact,
    )
    .map_err(|error| handoff_error(&format!("CDDL rejected {label} package: {error}")))?;
    let package_json = json_field(handoff, "package", label)?;
    require_json_keys(
        package_json,
        &["cbor_hex", "digest_hex"],
        &format!("{label} package assertions"),
    )?;
    let package_digest = domain_digest(PROVIDER_PACKAGE_DOMAIN, &package_exact);
    require_handoff(
        decode_lower_hex(json_string(package_json, "cbor_hex")?)? == package_exact
            && decode_json_fixed::<32>(package_json, "digest_hex")? == package_digest
            && cbor_fixed::<32>(response[16], "B2b response package digest")? == package_digest,
        &format!("{label} decrypted package digest proof drifted"),
    )?;

    let receipts = json_field(handoff, "mutation_receipts", label)?;
    require_json_keys(receipts, &["preparation", "provider_response"], label)?;
    let preparation_receipt_json = json_field(receipts, "preparation", label)?;
    require_json_keys(
        preparation_receipt_json,
        &["accepted_at", "cbor_hex", "request_digest_hex"],
        label,
    )?;
    let (preparation_receipt_exact, preparation_receipt_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-preparation-receipt-v2",
        json_string(preparation_receipt_json, "cbor_hex")?,
        label,
    )?;
    let preparation_receipt = numbered_fields(&preparation_receipt_value, 4, label)?;
    require_handoff(
        cbor_unsigned(preparation_receipt[0], label)? == 2
            && cbor_text(preparation_receipt[1], label)? == preparation.request_id
            && cbor_fixed::<32>(preparation_receipt[2], label)? == preparation.digest
            && decode_json_fixed::<32>(preparation_receipt_json, "request_digest_hex")?
                == preparation.digest
            && json_u64(preparation_receipt_json, "accepted_at")?
                == cbor_unsigned(preparation_receipt[3], label)?,
        &format!("{label} preparation receipt is not the exact immutable receipt"),
    )?;
    let provider_receipt_json = json_field(receipts, "provider_response", label)?;
    require_json_keys(
        provider_receipt_json,
        &["accepted_at", "cbor_hex", "response_digest_hex"],
        label,
    )?;
    let (provider_response_receipt_exact, provider_receipt_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-provider-response-receipt-v2",
        json_string(provider_receipt_json, "cbor_hex")?,
        label,
    )?;
    let provider_receipt = numbered_fields(&provider_receipt_value, 4, label)?;
    require_handoff(
        cbor_unsigned(provider_receipt[0], label)? == 2
            && cbor_text(provider_receipt[1], label)? == preparation.request_id
            && cbor_fixed::<32>(provider_receipt[2], label)? == provider_response_digest
            && decode_json_fixed::<32>(provider_receipt_json, "response_digest_hex")?
                == provider_response_digest
            && json_u64(provider_receipt_json, "accepted_at")?
                == cbor_unsigned(provider_receipt[3], label)?,
        &format!("{label} provider receipt is not the exact immutable receipt"),
    )?;

    let statuses = json_field(handoff, "statuses", label)?;
    require_json_keys(
        statuses,
        &["cancelled", "expired", "invalidated", "pending", "ready"],
        label,
    )?;
    let mut status_exact = Vec::with_capacity(5);
    for (name, rule, code, reason, embeds_response) in [
        (
            "pending",
            "recovery-scope-catalog-status-pending-v2",
            1,
            None,
            false,
        ),
        (
            "ready",
            "recovery-scope-catalog-status-ready-v2",
            2,
            None,
            true,
        ),
        (
            "expired",
            "recovery-scope-catalog-status-expired-v2",
            3,
            Some(1),
            false,
        ),
        (
            "cancelled",
            "recovery-scope-catalog-status-cancelled-v2",
            4,
            Some(2),
            false,
        ),
        (
            "invalidated",
            "recovery-scope-catalog-status-invalidated-v2",
            5,
            Some(3),
            false,
        ),
    ] {
        let status_json = json_field(statuses, name, label)?;
        let keys = if reason.is_some() {
            &["cbor_hex", "reason_code", "state_changed_at"][..]
        } else {
            &["cbor_hex", "state_changed_at"][..]
        };
        require_json_keys(status_json, keys, label)?;
        let (exact, value) =
            decode_exact_cddl(cddl, rule, json_string(status_json, "cbor_hex")?, label)?;
        let status = numbered_fields(&value, 6, label)?;
        let response_matches = if embeds_response {
            status[3] == &response_value
        } else {
            status[3] == &CanonicalValue::Null
        };
        let reason_matches = if let Some(reason) = reason {
            cbor_unsigned(status[4], label)? == reason
                && json_u64(status_json, "reason_code")? == reason
        } else {
            status[4] == &CanonicalValue::Null
        };
        require_handoff(
            cbor_unsigned(status[0], label)? == 2
                && cbor_text(status[1], label)? == preparation.request_id
                && cbor_unsigned(status[2], label)? == code
                && response_matches
                && reason_matches
                && cbor_unsigned(status[5], label)? == json_u64(status_json, "state_changed_at")?
                && exact.len() <= MAX_STATUS_BODY_BYTES,
            &format!("{label} {name} status lower proof drifted"),
        )?;
        status_exact.push(exact);
    }
    Ok(B2bCryptoFacts {
        preparation,
        package_exact,
        package,
        public_aad_exact,
        envelope_exact: envelope.exact,
        provider_response_exact,
        provider_response_digest,
        preparation_receipt_exact,
        provider_response_receipt_exact,
        status_exact: status_exact.try_into().expect("five B2b status encodings"),
    })
}

fn validate_b2b_recipient_bindings(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "recipient_bindings", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &[
            "alternate_recipient_device_add_mismatch",
            "enrollment_oracle_mismatch_public_key_hex",
            "protected_secret_mismatch_private_key_hex",
        ],
        "Catalog V2 B2b recipient bindings",
    )?;
    let alternate = json_field(
        family,
        "alternate_recipient_device_add_mismatch",
        "Catalog V2 B2b recipient bindings",
    )?;
    let alternate_crypto = validate_b2b_authentic_crypto_handoff(
        cddl,
        catalog_projection,
        alternate,
        "B2b alternate recipient",
    )?;
    require_handoff(
        alternate_crypto.preparation.recipient_public_key != base.candidate_recipient_public_key
            && alternate_crypto.preparation.request_id == base.request_id
            && alternate_crypto.preparation.candidate_device_id == base.candidate_device_id
            && alternate_crypto.envelope_exact != base.envelope_exact
            && alternate_crypto.provider_response_exact != base.provider_response_exact,
        "B2b alternate recipient did not rebuild a distinct valid downstream crypto transcript",
    )?;
    let alternate_vector = vector_with_handoff(vector, alternate)?;
    let alternate_input = parse_server_visible_handoff_input(&alternate_vector)?;
    expect_b2b_target_error(
        validate_server_visible_handoff(cddl, catalog_projection, &alternate_input),
        "alternate recipient versus DeviceAdd",
        "DeviceAdd transition or candidate key binding drifted",
    )?;

    let mismatched_enrollment =
        decode_json_fixed::<32>(family, "enrollment_oracle_mismatch_public_key_hex")?;
    require_handoff(
        mismatched_enrollment == alternate_crypto.preparation.recipient_public_key
            && mismatched_enrollment != base.candidate_recipient_public_key,
        "B2b enrollment mismatch is not the independently valid alternate X25519 key",
    )?;
    let base_input = parse_server_visible_handoff_input(vector)?;
    let mut enrollment_input = base_input.clone();
    enrollment_input.enrollment_candidate_recipient_public_key = mismatched_enrollment;
    expect_b2b_target_error(
        validate_server_visible_handoff(cddl, catalog_projection, &enrollment_input),
        "preparation versus enrollment candidate",
        "preparation JSON assertions do not match independently decoded bytes",
    )?;

    let protected_secret =
        decode_json_fixed::<32>(family, "protected_secret_mismatch_private_key_hex")?;
    let mut protected_vector = vector.clone();
    *protected_vector
        .pointer_mut("/handoff/test_only_inputs/x25519_recipient_private_key_hex")
        .ok_or_else(|| handoff_error("B2b protected-secret mutation path missing"))? =
        json!(encode_lower_hex(&protected_secret));
    let server = validate_server_visible_handoff(cddl, catalog_projection, &base_input)?;
    require_handoff(
        server == *base,
        "B2b protected-secret case changed server-visible bytes",
    )?;
    expect_b2b_target_error(
        validate_candidate_handoff(&protected_vector, cddl, &server, catalog),
        "protected secret versus enrolled recipient",
        "candidate protected X25519 secret does not derive the enrolled recipient key",
    )
}

fn validate_b2b_sealed_package_mismatches(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "sealed_package_mismatches", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &["request_coordinate", "response_time", "signed_head"],
        "Catalog V2 B2b sealed-package mismatches",
    )?;
    let mut envelopes = BTreeSet::from([base.envelope_exact.clone()]);
    let mut responses = BTreeSet::from([base.provider_response_exact.clone()]);
    let base_package_exact = decode_lower_hex(json_string(
        json_field(
            json_field(vector, "handoff", "Catalog V2 vector")?,
            "package",
            "Catalog V2 handoff",
        )?,
        "cbor_hex",
    )?)?;
    let base_package = decode_exact_bytes(&base_package_exact, "B2b base package")?;
    let base_package_fields = numbered_fields(&base_package, 17, "B2b base package")?;
    for name in ["request_coordinate", "signed_head", "response_time"] {
        let handoff = json_field(family, name, "Catalog V2 B2b sealed-package mismatches")?;
        let crypto = validate_b2b_authentic_crypto_handoff(
            cddl,
            catalog_projection,
            handoff,
            &format!("B2b sealed-package {name}"),
        )?;
        let package_fields =
            numbered_fields(&crypto.package, 17, &format!("B2b sealed-package {name}"))?;
        let changed_fields = package_fields
            .iter()
            .zip(&base_package_fields)
            .enumerate()
            .filter_map(|(index, (observed, expected))| (observed != expected).then_some(index))
            .collect::<Vec<_>>();
        let expected_changed_field = match name {
            "request_coordinate" => 1,
            "signed_head" => 3,
            "response_time" => 15,
            _ => unreachable!("closed B2b sealed-package mismatch family"),
        };
        require_handoff(
            crypto.preparation.exact == base.preparation_exact
                && crypto.public_aad_exact != base.public_aad_exact
                && crypto.package_exact != base_package_exact
                && changed_fields == [expected_changed_field]
                && envelopes.insert(crypto.envelope_exact.clone())
                && responses.insert(crypto.provider_response_exact.clone())
                && crypto.preparation_receipt_exact == base.preparation_receipt_exact
                && crypto.provider_response_receipt_exact != base.provider_response_receipt_exact
                && crypto.status_exact[0] == base.status_exact[0]
                && crypto.status_exact[1] != base.status_exact[1]
                && crypto.status_exact[2] == base.status_exact[2]
                && crypto.status_exact[3] == base.status_exact[3]
                && crypto.status_exact[4] == base.status_exact[4],
            &format!("B2b {name} did not rebuild every dependent outer crypto artifact"),
        )?;
        let variant = vector_with_handoff(vector, handoff)?;
        let input = parse_server_visible_handoff_input(&variant)?;
        let server = validate_server_visible_handoff(cddl, catalog_projection, &input)?;
        expect_b2b_target_error(
            validate_candidate_handoff(&variant, cddl, &server, catalog),
            &format!("sealed-package {name}"),
            "decrypted package/head/plaintext/public-coordinate equality drifted",
        )?;
    }
    Ok(())
}

fn validate_b2b_verifier_rotation(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "verifier_rotation", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &[
            "rotated_origin_authenticated_oracle",
            "server_visible_exact_bytes_sha256_hex",
        ],
        "Catalog V2 B2b verifier rotation",
    )?;
    let handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let mut serialized = serde_json::to_vec(json_field(
        handoff,
        "origin_authenticated_identity_log",
        "Catalog V2 handoff",
    )?)
    .map_err(|error| handoff_error(&format!("serialize B2b identity oracle: {error}")))?;
    for exact in [
        base.preparation_exact.as_slice(),
        base.device_add_exact.as_slice(),
        base.public_aad_exact.as_slice(),
        base.envelope_exact.as_slice(),
        base.provider_response_exact.as_slice(),
        base.preparation_receipt_exact.as_slice(),
        base.provider_response_receipt_exact.as_slice(),
    ] {
        serialized.extend_from_slice(exact);
    }
    for exact in &base.status_exact {
        serialized.extend_from_slice(exact);
    }
    require_handoff(
        decode_json_fixed::<32>(family, "server_visible_exact_bytes_sha256_hex")?
            == Sha256::digest(&serialized).as_slice(),
        "B2b verifier rotation server-projection hash drifted",
    )?;
    let mut rotated = vector.clone();
    rotated
        .as_object_mut()
        .ok_or_else(|| handoff_error("B2b rotated vector root is not an object"))?
        .insert(
            "origin_authenticated_completion_verifier_descriptors".to_owned(),
            json_field(
                family,
                "rotated_origin_authenticated_oracle",
                "Catalog V2 B2b verifier rotation",
            )?
            .clone(),
        );
    let rotated_oracle = parse_origin_authenticated_verifier_oracle(
        &rotated,
        cddl,
        catalog.context.validation_time,
    )?;
    let current_oracle =
        parse_origin_authenticated_verifier_oracle(vector, cddl, catalog.context.validation_time)?;
    require_handoff(
        rotated_oracle != current_oracle,
        "B2b rotated hidden verifier oracle equals the current oracle",
    )?;
    let input = parse_server_visible_handoff_input(&rotated)?;
    let rotated_server = validate_server_visible_handoff(cddl, catalog_projection, &input)?;
    require_handoff(
        rotated_server == *base
            && rotated_server.preparation_receipt_exact == base.preparation_receipt_exact
            && rotated_server.provider_response_receipt_exact
                == base.provider_response_receipt_exact
            && rotated_server.status_exact == base.status_exact,
        "B2b hidden verifier rotation changed server-visible response, receipt, status, or projection bytes",
    )?;
    expect_b2b_target_error(
        validate_candidate_handoff(&rotated, cddl, &rotated_server, catalog),
        "hidden verifier rotation",
        "candidate-only verifier binding does not match the current signed origin-authenticated descriptor",
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "the paired preparation/provider trace gate keeps authentic artifacts adjacent to their state-machine assertions"
)]
fn validate_b2b_state_idempotency(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    type Kem = X25519HkdfSha256;

    let family = json_field(b2b, "state_idempotency_traces", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &[
            "preparation",
            "preparation_reject_before_write_order",
            "provider_response",
            "provider_response_reject_before_write_order",
        ],
        "Catalog V2 B2b state/idempotency traces",
    )?;
    validate_b2b_reject_order(
        json_field(
            family,
            "preparation_reject_before_write_order",
            "B2b preparation order",
        )?,
        &[
            "media_and_size",
            "exact_canonical_cbor",
            "capabilities",
            "path_and_static_binding",
            "idempotency_claim_lookup",
            "body_signature_and_digest",
            "committed_exact_replay",
            "mutable_currentness",
            "final_cas",
        ],
        "preparation",
    )?;
    validate_b2b_reject_order(
        json_field(
            family,
            "provider_response_reject_before_write_order",
            "B2b response order",
        )?,
        &[
            "media_and_size",
            "exact_canonical_cbor",
            "response_capability_and_provider_session",
            "path_and_static_binding",
            "idempotency_claim_lookup",
            "body_dual_signatures_and_digests",
            "committed_exact_replay",
            "mutable_currentness",
            "final_cas",
        ],
        "provider response",
    )?;

    let base_handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let base_inputs = json_field(base_handoff, "test_only_inputs", "Catalog V2 handoff")?;
    let base_preparation = validate_b2b_preparation_artifact(
        cddl,
        catalog_projection,
        json_field(base_handoff, "preparation", "Catalog V2 handoff")?,
        decode_json_fixed(base_inputs, "response_capability_hex")?,
        json_string(base_inputs, "preparation_idempotency_key_ascii")?.as_bytes(),
    )?;
    require_handoff(
        base_preparation.exact == base.preparation_exact
            && base_preparation.digest == base.preparation_digest,
        "B2b base preparation proof drifted from the accepted handoff",
    )?;

    let preparation = json_field(family, "preparation", "B2b state traces")?;
    require_json_keys(
        preparation,
        &[
            "candidate_one_enrollment_capability_hex",
            "candidate_two",
            "different_key_duplicate_target",
            "same_key_different_body",
            "trace",
        ],
        "B2b preparation state traces",
    )?;
    let candidate_two_json = json_field(preparation, "candidate_two", "B2b preparation traces")?;
    require_json_keys(
        candidate_two_json,
        &[
            "enrollment_capability_hex",
            "preparation",
            "preparation_idempotency_key_ascii",
            "receipt",
            "replay_receipt_cbor_hex",
            "replay_writes",
            "response_capability_hex",
            "status_available",
            "x25519_recipient_private_key_hex",
        ],
        "B2b second candidate preparation",
    )?;
    let candidate_two_capability =
        decode_json_fixed(candidate_two_json, "response_capability_hex")?;
    let candidate_one_enrollment_capability =
        decode_json_fixed::<32>(preparation, "candidate_one_enrollment_capability_hex")?;
    let candidate_one_response_capability =
        decode_json_fixed::<32>(base_inputs, "response_capability_hex")?;
    let candidate_two_enrollment_capability =
        decode_json_fixed::<32>(candidate_two_json, "enrollment_capability_hex")?;
    require_handoff(
        BTreeSet::from([
            candidate_one_enrollment_capability,
            candidate_one_response_capability,
            candidate_two_enrollment_capability,
            candidate_two_capability,
        ])
        .len()
            == 4,
        "B2b candidate preparations do not use four disjoint enrollment/response capabilities",
    )?;
    let candidate_two_idempotency =
        json_string(candidate_two_json, "preparation_idempotency_key_ascii")?.as_bytes();
    let candidate_two = validate_b2b_preparation_artifact(
        cddl,
        catalog_projection,
        json_field(candidate_two_json, "preparation", "B2b second candidate")?,
        candidate_two_capability,
        candidate_two_idempotency,
    )?;
    let candidate_two_private =
        decode_json_fixed::<32>(candidate_two_json, "x25519_recipient_private_key_hex")?;
    let candidate_two_private = <Kem as KemTrait>::PrivateKey::from_bytes(&candidate_two_private)
        .map_err(|error| {
        handoff_error(&format!("B2b second candidate key invalid: {error}"))
    })?;
    require_handoff(
        Kem::sk_to_pk(&candidate_two_private).to_bytes().as_slice()
            == candidate_two.recipient_public_key
            && candidate_two.signed_head_digest == base_preparation.signed_head_digest
            && candidate_two.request_id != base_preparation.request_id
            && candidate_two.candidate_device_id != base_preparation.candidate_device_id
            && candidate_two.signing_public_key != base_preparation.signing_public_key
            && candidate_two.recipient_public_key != base_preparation.recipient_public_key
            && candidate_two.response_capability_digest
                != base_preparation.response_capability_digest
            && candidate_two.idempotency_digest != base_preparation.idempotency_digest,
        "B2b two authenticated candidate preparations are not disjoint while sharing one signed Catalog head",
    )?;
    let candidate_two_receipt_json = json_field(
        candidate_two_json,
        "receipt",
        "B2b second candidate preparation",
    )?;
    require_json_keys(
        candidate_two_receipt_json,
        &["accepted_at", "cbor_hex", "request_digest_hex"],
        "B2b second candidate receipt",
    )?;
    let (candidate_two_receipt_exact, candidate_two_receipt_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-preparation-receipt-v2",
        json_string(candidate_two_receipt_json, "cbor_hex")?,
        "B2b second candidate receipt",
    )?;
    let candidate_two_receipt = numbered_fields(
        &candidate_two_receipt_value,
        4,
        "B2b second candidate receipt",
    )?;
    require_handoff(
        cbor_text(
            candidate_two_receipt[1],
            "B2b second candidate receipt request",
        )? == candidate_two.request_id
            && cbor_fixed::<32>(
                candidate_two_receipt[2],
                "B2b second candidate receipt digest",
            )? == candidate_two.digest
            && decode_json_fixed::<32>(candidate_two_receipt_json, "request_digest_hex")?
                == candidate_two.digest
            && decode_lower_hex(json_string(candidate_two_json, "replay_receipt_cbor_hex")?)?
                == candidate_two_receipt_exact
            && json_u64(candidate_two_json, "replay_writes")? == 0
            && b2b_json_bool(candidate_two_json, "status_available")?,
        "B2b second request exact replay did not return its original receipt with no writes and status available",
    )?;

    let same_key = validate_b2b_preparation_artifact(
        cddl,
        catalog_projection,
        json_field(
            preparation,
            "same_key_different_body",
            "B2b preparation traces",
        )?,
        decode_json_fixed(base_inputs, "response_capability_hex")?,
        json_string(base_inputs, "preparation_idempotency_key_ascii")?.as_bytes(),
    )?;
    require_handoff(
        same_key.idempotency_digest == base_preparation.idempotency_digest
            && same_key.exact != base_preparation.exact
            && same_key.request_id == base_preparation.request_id
            && same_key.candidate_device_id == base_preparation.candidate_device_id,
        "B2b same-key/different-preparation body is not an authentic scoped conflict",
    )?;
    let different_key_json = json_field(
        preparation,
        "different_key_duplicate_target",
        "B2b preparation traces",
    )?;
    require_json_keys(
        different_key_json,
        &["preparation", "preparation_idempotency_key_ascii"],
        "B2b preparation duplicate target",
    )?;
    let different_key = validate_b2b_preparation_artifact(
        cddl,
        catalog_projection,
        json_field(different_key_json, "preparation", "B2b duplicate target")?,
        decode_json_fixed(base_inputs, "response_capability_hex")?,
        json_string(different_key_json, "preparation_idempotency_key_ascii")?.as_bytes(),
    )?;
    require_handoff(
        different_key.idempotency_digest != base_preparation.idempotency_digest
            && different_key.request_id == base_preparation.request_id
            && different_key.candidate_device_id == base_preparation.candidate_device_id,
        "B2b different-key preparation does not target the already admitted request",
    )?;
    validate_b2b_admission_trace(
        json_field(preparation, "trace", "B2b preparation traces")?,
        "preparation",
        &base.preparation_receipt_exact,
    )?;

    let provider = json_field(family, "provider_response", "B2b state traces")?;
    require_json_keys(
        provider,
        &[
            "different_key_duplicate_target",
            "same_key_different_body",
            "trace",
        ],
        "B2b provider-response state traces",
    )?;
    let same_response_handoff = json_field(
        provider,
        "same_key_different_body",
        "B2b provider-response traces",
    )?;
    let same_response_crypto = validate_b2b_authentic_crypto_handoff(
        cddl,
        catalog_projection,
        same_response_handoff,
        "B2b same-key different provider response",
    )?;
    let same_response_vector = vector_with_handoff(vector, same_response_handoff)?;
    let same_response_input = parse_server_visible_handoff_input(&same_response_vector)?;
    let same_response_server =
        validate_server_visible_handoff(cddl, catalog_projection, &same_response_input)?;
    validate_candidate_handoff(&same_response_vector, cddl, &same_response_server, catalog)?;
    let different_response_handoff = json_field(
        provider,
        "different_key_duplicate_target",
        "B2b provider-response traces",
    )?;
    let different_response_crypto = validate_b2b_authentic_crypto_handoff(
        cddl,
        catalog_projection,
        different_response_handoff,
        "B2b different-key duplicate provider response",
    )?;
    let different_response_vector = vector_with_handoff(vector, different_response_handoff)?;
    let different_response_input = parse_server_visible_handoff_input(&different_response_vector)?;
    let different_response_server =
        validate_server_visible_handoff(cddl, catalog_projection, &different_response_input)?;
    validate_candidate_handoff(
        &different_response_vector,
        cddl,
        &different_response_server,
        catalog,
    )?;
    let base_response_value =
        decode_exact_bytes(&base.provider_response_exact, "B2b base response")?;
    let base_response_fields = numbered_fields(&base_response_value, 26, "B2b base response")?;
    let same_response_value = decode_exact_bytes(
        &same_response_crypto.provider_response_exact,
        "B2b same response",
    )?;
    let same_response_fields = numbered_fields(&same_response_value, 26, "B2b same response")?;
    let different_response_value = decode_exact_bytes(
        &different_response_crypto.provider_response_exact,
        "B2b different response",
    )?;
    let different_response_fields =
        numbered_fields(&different_response_value, 26, "B2b different response")?;
    require_handoff(
        same_response_crypto.preparation.exact == base.preparation_exact
            && different_response_crypto.preparation.exact == base.preparation_exact
            && same_response_crypto.provider_response_exact != base.provider_response_exact
            && different_response_crypto.provider_response_exact != base.provider_response_exact
            && cbor_fixed::<32>(same_response_fields[19], "B2b same response key")?
                == cbor_fixed::<32>(base_response_fields[19], "B2b base response key")?
            && cbor_fixed::<32>(different_response_fields[19], "B2b different response key")?
                != cbor_fixed::<32>(base_response_fields[19], "B2b base response key")?
            && same_response_crypto.provider_response_receipt_exact
                != base.provider_response_receipt_exact
            && different_response_crypto.provider_response_receipt_exact
                != base.provider_response_receipt_exact,
        "B2b provider-response idempotency fixtures are not authentic body/key conflicts",
    )?;
    validate_b2b_admission_trace(
        json_field(provider, "trace", "B2b provider-response traces")?,
        "provider response",
        &base.provider_response_receipt_exact,
    )
}

fn validate_b2b_reject_order(
    value: &Value,
    expected: &[&str],
    label: &str,
) -> Result<(), ProtocolToolError> {
    let observed = value
        .as_array()
        .ok_or_else(|| handoff_error(&format!("B2b {label} order must be an array")))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| handoff_error(&format!("B2b {label} order must contain strings")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    require_handoff(
        observed == expected,
        &format!("B2b {label} auth/static/body/idempotency/replay/currentness/CAS order drifted"),
    )
}

fn b2b_json_bool(value: &Value, field: &str) -> Result<bool, ProtocolToolError> {
    json_field(value, field, "Catalog V2 B2b trace")?
        .as_bool()
        .ok_or_else(|| handoff_error(&format!("B2b trace {field} must be Boolean")))
}

fn validate_b2b_admission_trace(
    value: &Value,
    label: &str,
    original_receipt: &[u8],
) -> Result<(), ProtocolToolError> {
    let entries = value
        .as_array()
        .ok_or_else(|| handoff_error(&format!("B2b {label} trace must be an array")))?;
    require_handoff(
        entries.len() == 5,
        &format!("B2b {label} trace must contain five ordered admissions"),
    )?;
    for (index, (event, outcome, writes, receipt_returned)) in [
        ("first_admission", "accepted", 1, true),
        ("same_key_same_body", "exact_replay", 0, true),
        ("same_key_different_body", "idempotency_conflict", 0, false),
        (
            "different_key_duplicate_target",
            "duplicate_target_conflict",
            0,
            false,
        ),
        ("final_cas", "first_admission_only", 1, true),
    ]
    .into_iter()
    .enumerate()
    {
        let entry = &entries[index];
        let has_currentness = (1..=3).contains(&index);
        let keys = if index <= 1 && has_currentness {
            &[
                "event",
                "mutable_currentness_checked",
                "outcome",
                "receipt_cbor_hex",
                "receipt_returned",
                "status_available",
                "writes",
            ][..]
        } else if index == 0 {
            &[
                "event",
                "outcome",
                "receipt_cbor_hex",
                "receipt_returned",
                "status_available",
                "writes",
            ][..]
        } else if index == 4 {
            &[
                "cas_loser_writes",
                "event",
                "outcome",
                "partial_write",
                "receipt_returned",
                "status_available",
                "writes",
            ][..]
        } else {
            &[
                "event",
                "mutable_currentness_checked",
                "outcome",
                "receipt_returned",
                "status_available",
                "writes",
            ][..]
        };
        require_json_keys(entry, keys, &format!("B2b {label} trace entry"))?;
        require_handoff(
            json_string(entry, "event")? == event
                && json_string(entry, "outcome")? == outcome
                && json_u64(entry, "writes")? == writes
                && b2b_json_bool(entry, "receipt_returned")? == receipt_returned
                && b2b_json_bool(entry, "status_available")?
                && (!has_currentness || !b2b_json_bool(entry, "mutable_currentness_checked")?)
                && (index > 1
                    || decode_lower_hex(json_string(entry, "receipt_cbor_hex")?)?
                        == original_receipt)
                && (index != 4
                    || json_u64(entry, "cas_loser_writes")? == 0
                        && !b2b_json_bool(entry, "partial_write")?),
            &format!("B2b {label} {event} trace outcome/order/write/receipt/status drifted"),
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "five exact status encodings, terminal tie reduction, and immutable receipts form one GET contract"
)]
fn validate_b2b_get_states(
    vector: &Value,
    cddl: &str,
    base: &ServerVisibleHandoffFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "get_state_traces", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &[
            "http_status",
            "invalidation_reason_priority",
            "preparation_receipt_cbor_hex",
            "provider_response_receipt_cbor_hex",
            "read_only_no_writes",
            "receipts_remain_immutable",
            "state_changed_at",
            "states",
            "tie_priority",
            "valid_response_capability_hex",
        ],
        "Catalog V2 B2b GET-state traces",
    )?;
    let base_inputs = json_field(
        json_field(vector, "handoff", "Catalog V2 vector")?,
        "test_only_inputs",
        "Catalog V2 handoff",
    )?;
    require_handoff(
        json_u64(family, "http_status")? == 200
            && b2b_json_bool(family, "read_only_no_writes")?
            && b2b_json_bool(family, "receipts_remain_immutable")?
            && decode_json_fixed::<32>(family, "valid_response_capability_hex")?
                == decode_json_fixed::<32>(base_inputs, "response_capability_hex")?,
        "B2b GET must require the valid response capability and return HTTP 200 without writes",
    )?;
    let states = json_field(family, "states", "B2b GET-state traces")?
        .as_array()
        .ok_or_else(|| handoff_error("B2b GET states must be an array"))?;
    let state_names = states
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| handoff_error("B2b GET state name must be text"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    require_handoff(
        state_names == ["pending", "ready", "expired", "cancelled", "invalidated"],
        "B2b GET five-state closure drifted",
    )?;
    let changed = json_field(family, "state_changed_at", "B2b GET-state traces")?;
    require_json_keys(
        changed,
        &["cancelled", "expired", "invalidated", "pending", "ready"],
        "B2b GET stable timestamps",
    )?;
    for (index, name) in state_names.iter().enumerate() {
        let value = decode_exact_bytes(&base.status_exact[index], &format!("B2b {name} status"))?;
        cddl_cat::validate_cbor_bytes(
            match *name {
                "pending" => "recovery-scope-catalog-status-pending-v2",
                "ready" => "recovery-scope-catalog-status-ready-v2",
                "expired" => "recovery-scope-catalog-status-expired-v2",
                "cancelled" => "recovery-scope-catalog-status-cancelled-v2",
                "invalidated" => "recovery-scope-catalog-status-invalidated-v2",
                _ => unreachable!("closed B2b GET states"),
            },
            cddl,
            &base.status_exact[index],
        )
        .map_err(|error| handoff_error(&format!("B2b {name} status CDDL failed: {error}")))?;
        let fields = numbered_fields(&value, 6, &format!("B2b {name} status"))?;
        require_handoff(
            cbor_text(fields[1], "B2b GET request")? == base.request_id
                && cbor_unsigned(fields[5], "B2b GET stable timestamp")?
                    == json_u64(changed, name)?,
            &format!("B2b {name} GET timestamp/request changed across reads"),
        )?;
    }
    let tie_priority = json_field(family, "tie_priority", "B2b GET-state traces")?
        .as_array()
        .ok_or_else(|| handoff_error("B2b GET tie priority must be an array"))?;
    require_handoff(
        tie_priority == &[json!("cancelled"), json!("invalidated"), json!("expired")],
        "B2b equal-time terminal priority must be cancelled > invalidated > expired",
    )?;
    let selected = [("expired", 3_u8), ("invalidated", 2), ("cancelled", 1)]
        .into_iter()
        .min_by_key(|(_, priority)| *priority)
        .map(|(name, _)| name);
    require_handoff(
        selected == Some("cancelled"),
        "B2b equal-time state reducer did not select cancelled",
    )?;
    let invalidation = json_field(
        family,
        "invalidation_reason_priority",
        "B2b GET-state traces",
    )?
    .as_array()
    .ok_or_else(|| handoff_error("B2b invalidation priority must be an array"))?;
    let expected = [
        "identity_head_or_h_plus_2",
        "catalog_id_generation_or_head",
        "public_catalog_authority_or_head",
        "candidate_device_add_or_key",
        "provider_session_or_key",
        "independent_authority",
    ];
    require_handoff(
        invalidation
            .iter()
            .map(Value::as_str)
            .eq(expected.into_iter().map(Some)),
        "B2b invalidated reason order must use the lowest numeric priority",
    )?;
    require_handoff(
        decode_lower_hex(json_string(family, "preparation_receipt_cbor_hex")?)?
            == base.preparation_receipt_exact
            && decode_lower_hex(json_string(family, "provider_response_receipt_cbor_hex")?)?
                == base.provider_response_receipt_exact,
        "B2b GET rewrote an immutable mutation receipt",
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "H+2, provider session, and all three authority kinds share one lower-signature-first currentness gate"
)]
fn validate_b2b_currentness(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "currentness_drifts", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &[
            "authenticated_snapshot_rejections",
            "authority_kinds",
            "exact_first_admission",
            "h_plus_2_origin_authenticated_identity_log",
            "provider_session_drift",
        ],
        "Catalog V2 B2b currentness drifts",
    )?;
    let first = json_field(family, "exact_first_admission", "B2b currentness")?;
    require_json_keys(first, &["h", "h_plus_1", "writes"], "B2b first admission")?;
    require_handoff(
        json_u64(first, "h")? == base.identity_log.at_h.sequence
            && json_u64(first, "h_plus_1")? == base.identity_log.at_h.sequence + 1
            && json_u64(first, "h_plus_1")? == base.identity_log.at_h_plus_1.sequence
            && json_u64(first, "writes")? == 1,
        "B2b first admission is not the exact H to H+1 DeviceAdd CAS",
    )?;

    let mut h_plus_2_vector = vector.clone();
    *h_plus_2_vector
        .pointer_mut("/handoff/origin_authenticated_identity_log")
        .ok_or_else(|| handoff_error("B2b H+2 oracle mutation path missing"))? = json_field(
        family,
        "h_plus_2_origin_authenticated_identity_log",
        "B2b currentness",
    )?
    .clone();
    let h_plus_2_input = parse_server_visible_handoff_input(&h_plus_2_vector)?;
    expect_b2b_target_error(
        validate_server_visible_handoff(cddl, catalog_projection, &h_plus_2_input),
        "origin-authenticated H+2",
        "origin-authenticated H/H+1 oracle drifted",
    )?;

    let base_handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let base_crypto = validate_b2b_authentic_crypto_handoff(
        cddl,
        catalog_projection,
        base_handoff,
        "B2b base currentness transcript",
    )?;
    let response_value = decode_exact_bytes(
        &base_crypto.provider_response_exact,
        "B2b provider-session response",
    )?;
    let response = numbered_fields(&response_value, 26, "B2b provider-session response")?;
    let provider_descriptor = numbered_fields(response[14], 3, "B2b provider descriptor")?;
    let provider_session = json_field(family, "provider_session_drift", "B2b currentness")?;
    require_json_keys(
        provider_session,
        &[
            "authenticated_device_id",
            "authenticated_signing_public_key_hex",
        ],
        "B2b provider-session drift",
    )?;
    let authenticated_provider_key =
        decode_json_fixed::<32>(provider_session, "authenticated_signing_public_key_hex")?;
    VerifyingKey::from_bytes(&authenticated_provider_key).map_err(|error| {
        handoff_error(&format!(
            "B2b authenticated provider-session drift key is not Ed25519: {error}"
        ))
    })?;
    require_handoff(
        origin_has_device(
            &base.identity_log.at_h_plus_1,
            json_string(provider_session, "authenticated_device_id")?,
            authenticated_provider_key,
        ) && (cbor_text(provider_descriptor[1], "B2b response provider id")?
            != json_string(provider_session, "authenticated_device_id")?
            || cbor_fixed::<32>(provider_descriptor[2], "B2b response provider key")?
                != authenticated_provider_key),
        "B2b provider-session drift is not an authentic current session distinct from the signed response descriptor",
    )?;
    expect_b2b_target_error(
        require_handoff(
            cbor_text(provider_descriptor[1], "B2b response provider id")?
                == json_string(provider_session, "authenticated_device_id")?
                && cbor_fixed::<32>(provider_descriptor[2], "B2b response provider key")?
                    == authenticated_provider_key,
            "provider authenticated session does not equal the signed provider descriptor",
        ),
        "provider descriptor/session drift",
        "provider authenticated session does not equal the signed provider descriptor",
    )?;

    let authority_cases = json_field(family, "authority_kinds", "B2b currentness")?
        .as_array()
        .ok_or_else(|| handoff_error("B2b authority currentness cases must be an array"))?;
    require_handoff(
        authority_cases.len() == 3,
        "B2b authority currentness must cover all three closed kinds",
    )?;
    let variants = json_field(vector, "handoff_authority_variants", "Catalog V2 vector")?;
    for (index, (name, handoff, expected_kind)) in [
        (
            "active_device",
            base_handoff,
            IndependentAuthorityKind::ActiveDevice,
        ),
        (
            "current_root",
            json_field(variants, "current_root", "B2b authority variants")?,
            IndependentAuthorityKind::CurrentRoot,
        ),
        (
            "current_recovery",
            json_field(variants, "current_recovery", "B2b authority variants")?,
            IndependentAuthorityKind::CurrentRecovery,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = &authority_cases[index];
        require_json_keys(
            fixture,
            &["current_identity_snapshot", "kind"],
            "B2b authority currentness fixture",
        )?;
        let crypto = validate_b2b_authentic_crypto_handoff(
            cddl,
            catalog_projection,
            handoff,
            &format!("B2b {name} currentness transcript"),
        )?;
        let value = decode_exact_bytes(
            &crypto.provider_response_exact,
            &format!("B2b {name} response"),
        )?;
        let fields = numbered_fields(&value, 26, &format!("B2b {name} response"))?;
        let candidate_device_id = cbor_text(fields[7], "B2b response candidate")?;
        let provider = numbered_fields(fields[14], 3, &format!("B2b {name} provider"))?;
        let provider_id = cbor_text(provider[1], "B2b response provider id")?;
        let provider_key = cbor_fixed::<32>(provider[2], "B2b response provider key")?;
        let authority = numbered_fields(fields[15], 3, &format!("B2b {name} authority"))?;
        let observed_kind = match cbor_unsigned(authority[0], "B2b authority kind")? {
            1 => IndependentAuthorityKind::ActiveDevice,
            2 => IndependentAuthorityKind::CurrentRoot,
            3 => IndependentAuthorityKind::CurrentRecovery,
            _ => return Err(handoff_error("B2b authority kind is not closed")),
        };
        let signed_key = cbor_fixed::<32>(authority[2], "B2b signed authority key")?;
        let current_snapshot = parse_origin_authenticated_current_identity_snapshot(
            json_field(
                fixture,
                "current_identity_snapshot",
                "B2b authority currentness fixture",
            )?,
            &format!("B2b {name} origin-authenticated current identity snapshot"),
        )?;
        require_handoff(
            json_string(fixture, "kind")? == name
                && observed_kind == expected_kind
                && current_snapshot.origin == base.identity_log.origin
                && current_snapshot.state.sequence == base.identity_log.at_h_plus_1.sequence + 1
                && current_snapshot.state.head_digest != base.identity_log.at_h_plus_1.head_digest
                && origin_has_device(&current_snapshot.state, provider_id, provider_key)
                && origin_has_device(
                    &current_snapshot.state,
                    candidate_device_id,
                    crypto.preparation.signing_public_key,
                ),
            &format!(
                "B2b {name} currentness fixture did not preserve a valid lower transcript and authenticated forward current snapshot"
            ),
        )?;
        let target_error = match expected_kind {
            IndependentAuthorityKind::ActiveDevice => {
                let authority_id = cbor_text(authority[1], "B2b authority device")?;
                require_handoff(
                    current_snapshot.state.active_devices.iter().any(|device| {
                        device.device_id == authority_id && device.signing_public_key != signed_key
                    }),
                    "B2b active-device current snapshot did not rotate the signed authority device key",
                )?;
                "active independent authority is not current and distinct in authenticated identity state"
            }
            IndependentAuthorityKind::CurrentRoot => {
                require_handoff(
                    current_snapshot.state.current_root_public_key != signed_key,
                    "B2b current-root snapshot did not rotate the signed root authority key",
                )?;
                "root independent authority id/key is not current in authenticated identity state"
            }
            IndependentAuthorityKind::CurrentRecovery => {
                require_handoff(
                    current_snapshot.state.current_recovery_public_key != signed_key,
                    "B2b current-recovery snapshot did not rotate the signed recovery authority key",
                )?;
                "recovery independent authority id/key is not current in authenticated identity state"
            }
        };
        expect_b2b_target_error(
            validate_independent_authority_currentness(
                &current_snapshot.state,
                candidate_device_id,
                provider_id,
                &authority,
            ),
            &format!("{name} authority currentness"),
            target_error,
        )?;
    }
    let snapshot_rejections = json_field(
        family,
        "authenticated_snapshot_rejections",
        "B2b currentness",
    )?;
    require_json_keys(
        snapshot_rejections,
        &[
            "arbitrary_untrusted_signer",
            "invalid_current_key",
            "invalid_head",
            "invalid_signature",
        ],
        "B2b authenticated-current-snapshot rejection closure",
    )?;
    for (name, expected) in [
        ("arbitrary_untrusted_signer", "origin trust anchor drifted"),
        ("invalid_current_key", "current root key is invalid"),
        ("invalid_head", "sequence/head is invalid"),
        ("invalid_signature", "signature invalid"),
    ] {
        expect_b2b_target_error(
            parse_origin_authenticated_current_identity_snapshot(
                json_field(snapshot_rejections, name, "B2b snapshot rejection closure")?,
                &format!("B2b {name} current identity snapshot"),
            ),
            &format!("{name} current identity snapshot"),
            expected,
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "preparation and freshly re-sealed response boundaries are one outer handoff validity portfolio"
)]
fn validate_b2b_time_boundaries(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "time_boundaries", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &["catalog", "descriptor", "issuer", "preparation", "response"],
        "Catalog V2 B2b time boundaries",
    )?;
    let base_handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let base_inputs = json_field(base_handoff, "test_only_inputs", "Catalog V2 handoff")?;
    let base_preparation_value = decode_exact_bytes(
        &base.preparation_exact,
        "B2b base preparation time comparison",
    )?;
    let base_preparation_fields = numbered_fields(
        &base_preparation_value,
        17,
        "B2b base preparation time comparison",
    )?;
    let base_package_exact = decode_lower_hex(json_string(
        json_field(base_handoff, "package", "B2b base handoff")?,
        "cbor_hex",
    )?)?;
    let base_package_value =
        decode_exact_bytes(&base_package_exact, "B2b base response-time package")?;
    let base_package_fields =
        numbered_fields(&base_package_value, 17, "B2b base response-time package")?;

    let preparation_cases = json_field(family, "preparation", "B2b time boundaries")?;
    require_json_keys(
        preparation_cases,
        &[
            "empty_interval",
            "expires_after_catalog",
            "expires_at_catalog_boundary",
            "issued_at_catalog_boundary",
            "issued_before_catalog",
        ],
        "B2b preparation time cases",
    )?;
    for (name, expected_valid) in [
        ("issued_at_catalog_boundary", true),
        ("expires_at_catalog_boundary", true),
        ("issued_before_catalog", false),
        ("expires_after_catalog", false),
        ("empty_interval", false),
    ] {
        let fixture = json_field(preparation_cases, name, "B2b preparation time cases")?;
        require_json_keys(
            fixture,
            &["expected_valid", "preparation"],
            "B2b preparation time fixture",
        )?;
        require_handoff(
            b2b_json_bool(fixture, "expected_valid")? == expected_valid,
            &format!("B2b preparation {name} expected-valid label drifted"),
        )?;
        let facts = validate_b2b_preparation_artifact(
            cddl,
            catalog_projection,
            json_field(fixture, "preparation", "B2b preparation time fixture")?,
            decode_json_fixed(base_inputs, "response_capability_hex")?,
            json_string(base_inputs, "preparation_idempotency_key_ascii")?.as_bytes(),
        )?;
        let preparation_value =
            decode_exact_bytes(&facts.exact, &format!("B2b preparation time {name}"))?;
        let preparation_fields =
            numbered_fields(&preparation_value, 17, "B2b preparation time comparison")?;
        let changed = preparation_fields
            .iter()
            .zip(&base_preparation_fields)
            .enumerate()
            .filter_map(|(index, (observed, expected))| (observed != expected).then_some(index))
            .collect::<BTreeSet<_>>();
        require_handoff(
            !changed.is_empty()
                && changed.iter().all(|index| [14, 15, 16].contains(index))
                && changed.iter().any(|index| [14, 15].contains(index)),
            &format!(
                "B2b preparation {name} changed bytes outside validity times and the dependent signature"
            ),
        )?;
        let valid = facts.issued_at < facts.expires_at
            && facts.issued_at >= catalog_projection.head_issued_at
            && facts.expires_at <= catalog_projection.head_expires_at;
        require_handoff(
            valid == expected_valid,
            &format!(
                "B2b preparation {name} did not fail only after its valid signature/header proof"
            ),
        )?;
        if name == "issued_at_catalog_boundary" {
            require_handoff(
                facts.issued_at == catalog_projection.head_issued_at,
                "B2b preparation issued_at boundary is not exact",
            )?;
        }
        if name == "expires_at_catalog_boundary" {
            require_handoff(
                facts.expires_at == catalog_projection.head_expires_at,
                "B2b preparation expires_at boundary is not exact",
            )?;
        }
    }

    let response_cases = json_field(family, "response", "B2b time boundaries")?;
    require_json_keys(
        response_cases,
        &[
            "empty_interval",
            "expires_after_preparation",
            "expires_at_preparation_boundary",
            "issued_at_preparation_boundary",
            "issued_before_preparation",
        ],
        "B2b response time cases",
    )?;
    for (name, expected_valid) in [
        ("issued_at_preparation_boundary", true),
        ("expires_at_preparation_boundary", true),
        ("issued_before_preparation", false),
        ("expires_after_preparation", false),
        ("empty_interval", false),
    ] {
        let fixture = json_field(response_cases, name, "B2b response time cases")?;
        require_json_keys(
            fixture,
            &["expected_valid", "handoff"],
            "B2b response time fixture",
        )?;
        require_handoff(
            b2b_json_bool(fixture, "expected_valid")? == expected_valid,
            &format!("B2b response {name} expected-valid label drifted"),
        )?;
        let handoff = json_field(fixture, "handoff", "B2b response time fixture")?;
        let crypto = validate_b2b_authentic_crypto_handoff(
            cddl,
            catalog_projection,
            handoff,
            &format!("B2b response time {name}"),
        )?;
        let package_fields =
            numbered_fields(&crypto.package, 17, "B2b response-time package comparison")?;
        let package_changed = package_fields
            .iter()
            .zip(&base_package_fields)
            .enumerate()
            .filter_map(|(index, (observed, expected))| (observed != expected).then_some(index))
            .collect::<BTreeSet<_>>();
        require_handoff(
            crypto.provider_response_exact != base.provider_response_exact
                && crypto.envelope_exact != base.envelope_exact,
            &format!("B2b response time {name} was not freshly signed and re-sealed"),
        )?;
        require_handoff(
            !package_changed.is_empty()
                && package_changed.iter().all(|index| [15, 16].contains(index)),
            &format!(
                "B2b response time {name} changed decrypted package bytes outside its two validity fields"
            ),
        )?;
        let variant = vector_with_handoff(vector, handoff)?;
        let input = parse_server_visible_handoff_input(&variant)?;
        if expected_valid {
            let server = validate_server_visible_handoff(cddl, catalog_projection, &input)?;
            validate_candidate_handoff(&variant, cddl, &server, catalog)?;
            let response_value = decode_exact_bytes(
                &crypto.provider_response_exact,
                &format!("B2b response {name}"),
            )?;
            let fields = numbered_fields(&response_value, 26, "B2b response boundary")?;
            if name == "issued_at_preparation_boundary" {
                require_handoff(
                    cbor_unsigned(fields[20], "B2b response issued_at")?
                        == crypto.preparation.issued_at,
                    "B2b response issued_at boundary is not exact",
                )?;
            } else {
                require_handoff(
                    cbor_unsigned(fields[21], "B2b response expires_at")?
                        == crypto.preparation.expires_at,
                    "B2b response expires_at boundary is not exact",
                )?;
            }
        } else {
            expect_b2b_target_error(
                validate_server_visible_handoff(cddl, catalog_projection, &input),
                &format!("response time {name}"),
                "provider response public coordinates or validity drifted",
            )?;
        }
    }

    validate_b2b_catalog_times(cddl, catalog_projection, family)?;
    validate_b2b_descriptor_times(vector, cddl, catalog, family)?;
    validate_b2b_issuer_times(cddl, catalog, family)
}

fn validate_b2b_catalog_times(
    cddl: &str,
    catalog: &CatalogServerProjection,
    time_family: &Value,
) -> Result<(), ProtocolToolError> {
    let cases = json_field(time_family, "catalog", "B2b time boundaries")?;
    let base_value = decode_exact_bytes(
        &catalog.signed_head_exact,
        "B2b base Catalog time comparison",
    )?;
    let base_fields = numbered_fields(&base_value, 16, "B2b base Catalog time comparison")?;
    require_json_keys(
        cases,
        &[
            "empty_interval",
            "validation_at_expires",
            "validation_at_issued",
            "validation_before_expires",
            "validation_before_issued",
        ],
        "B2b Catalog time cases",
    )?;
    for (name, expected_valid) in [
        ("validation_at_issued", true),
        ("validation_before_expires", true),
        ("validation_before_issued", false),
        ("validation_at_expires", false),
        ("empty_interval", false),
    ] {
        let fixture = json_field(cases, name, "B2b Catalog time cases")?;
        require_json_keys(
            fixture,
            &["expected_valid", "signed_head_cbor_hex", "validation_time"],
            "B2b Catalog time fixture",
        )?;
        let (_, value) = decode_exact_cddl(
            cddl,
            "recovery-scope-catalog-head-v2",
            json_string(fixture, "signed_head_cbor_hex")?,
            &format!("B2b Catalog time {name}"),
        )?;
        let fields = numbered_fields(&value, 16, "B2b signed Catalog time head")?;
        let changed = fields
            .iter()
            .zip(&base_fields)
            .enumerate()
            .filter_map(|(index, (observed, expected))| (observed != expected).then_some(index))
            .collect::<BTreeSet<_>>();
        require_handoff(
            changed.iter().all(|index| [13, 14, 15].contains(index))
                && (!changed.contains(&15) || changed.iter().any(|index| [13, 14].contains(index))),
            &format!("B2b Catalog {name} changed bytes outside validity times and their signature"),
        )?;
        let unsigned = encoded_unsigned_prefix(&value, 15, "B2b signed Catalog time head")?;
        verify_signature(
            catalog.authority_public_key,
            HEAD_SIGNATURE_DOMAIN,
            &unsigned,
            cbor_fixed(fields[15], "B2b Catalog head signature")?,
            &format!("B2b Catalog time {name}"),
        )?;
        let issued_at = cbor_unsigned(fields[13], "B2b Catalog issued_at")?;
        let expires_at = cbor_unsigned(fields[14], "B2b Catalog expires_at")?;
        let validation_time = json_u64(fixture, "validation_time")?;
        let valid =
            issued_at < expires_at && validation_time >= issued_at && validation_time < expires_at;
        require_handoff(
            b2b_json_bool(fixture, "expected_valid")? == expected_valid && valid == expected_valid,
            &format!("B2b re-signed Catalog {name} did not reach only its target time predicate"),
        )?;
    }
    Ok(())
}

fn validate_b2b_descriptor_crypto(
    cddl: &str,
    descriptor: &Value,
    label: &str,
) -> Result<(u64, u64), ProtocolToolError> {
    require_json_keys(
        descriptor,
        &[
            "descriptor_digest_hex",
            "epoch",
            "expires_at",
            "issued_at",
            "key_id",
            "origin",
            "public_key_hex",
            "signature_hex",
            "signed_cbor_hex",
            "unsigned_cbor_hex",
        ],
        label,
    )?;
    let (exact, value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-completion-verifier-descriptor-v1",
        json_string(descriptor, "signed_cbor_hex")?,
        label,
    )?;
    let fields = numbered_fields(&value, 8, label)?;
    let unsigned = encoded_unsigned_prefix(&value, 7, label)?;
    let public_key = cbor_fixed(fields[3], label)?;
    let signature = cbor_fixed(fields[7], label)?;
    verify_signature(
        public_key,
        COMPLETION_VERIFIER_DESCRIPTOR_SIGNATURE_DOMAIN,
        &unsigned,
        signature,
        label,
    )?;
    let issued_at = cbor_unsigned(fields[5], label)?;
    let expires_at = cbor_unsigned(fields[6], label)?;
    require_handoff(
        decode_lower_hex(json_string(descriptor, "unsigned_cbor_hex")?)? == unsigned
            && decode_json_fixed::<64>(descriptor, "signature_hex")? == signature
            && decode_json_fixed::<32>(descriptor, "descriptor_digest_hex")?
                == domain_digest(COMPLETION_VERIFIER_DESCRIPTOR_DOMAIN, &exact)
            && decode_json_fixed::<32>(descriptor, "public_key_hex")? == public_key
            && json_u64(descriptor, "issued_at")? == issued_at
            && json_u64(descriptor, "expires_at")? == expires_at,
        &format!("{label} lower descriptor signature/digest assertions drifted"),
    )?;
    Ok((issued_at, expires_at))
}

fn validate_b2b_descriptor_times(
    vector: &Value,
    cddl: &str,
    catalog: &CatalogPositiveFacts,
    time_family: &Value,
) -> Result<(), ProtocolToolError> {
    let cases = json_field(time_family, "descriptor", "B2b time boundaries")?;
    require_json_keys(
        cases,
        &[
            "current_exact_boundaries",
            "expired_at_validation",
            "issued_after_validation",
            "validation_at_issued",
        ],
        "B2b descriptor time cases",
    )?;
    let base_descriptor = json_field(
        cases,
        "current_exact_boundaries",
        "B2b descriptor time cases",
    )?;
    let (_, base_descriptor_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-completion-verifier-descriptor-v1",
        json_string(base_descriptor, "signed_cbor_hex")?,
        "B2b base descriptor time comparison",
    )?;
    let base_descriptor_fields = numbered_fields(
        &base_descriptor_value,
        8,
        "B2b base descriptor time comparison",
    )?;
    for (name, expected_valid) in [
        ("current_exact_boundaries", true),
        ("validation_at_issued", true),
        ("expired_at_validation", false),
        ("issued_after_validation", false),
    ] {
        let descriptor = json_field(cases, name, "B2b descriptor time cases")?;
        let (issued_at, expires_at) =
            validate_b2b_descriptor_crypto(cddl, descriptor, &format!("B2b descriptor {name}"))?;
        let (_, descriptor_value) = decode_exact_cddl(
            cddl,
            "recovery-scope-catalog-completion-verifier-descriptor-v1",
            json_string(descriptor, "signed_cbor_hex")?,
            &format!("B2b descriptor {name} comparison"),
        )?;
        let descriptor_fields =
            numbered_fields(&descriptor_value, 8, "B2b descriptor time comparison")?;
        let changed = descriptor_fields
            .iter()
            .zip(&base_descriptor_fields)
            .enumerate()
            .filter_map(|(index, (observed, expected))| (observed != expected).then_some(index))
            .collect::<BTreeSet<_>>();
        require_handoff(
            changed.iter().all(|index| [5, 6, 7].contains(index))
                && (!changed.contains(&7) || changed.iter().any(|index| [5, 6].contains(index))),
            &format!(
                "B2b descriptor {name} changed bytes outside validity times and their signature"
            ),
        )?;
        let valid = issued_at < expires_at
            && catalog.context.validation_time >= issued_at
            && catalog.context.validation_time < expires_at;
        require_handoff(
            valid == expected_valid,
            &format!(
                "B2b signed descriptor {name} did not reach only its target currentness predicate"
            ),
        )?;
        let mut variant = vector.clone();
        let oracle = json!({
            "by_origin": {"https://recovery.example.test": descriptor.clone()},
            "classification": "trusted-origin-authenticated-completion-verifier-test-oracle-not-portable-wire-proof",
        });
        variant
            .as_object_mut()
            .ok_or_else(|| handoff_error("B2b descriptor vector root is not an object"))?
            .insert(
                "origin_authenticated_completion_verifier_descriptors".to_owned(),
                oracle,
            );
        let parsed = parse_origin_authenticated_verifier_oracle(
            &variant,
            cddl,
            catalog.context.validation_time,
        );
        if expected_valid {
            parsed?;
        } else {
            expect_b2b_target_error(parsed, name, "descriptor syntax or currentness drifted")?;
        }
    }
    Ok(())
}

fn validate_b2b_issuer_times(
    cddl: &str,
    catalog: &CatalogPositiveFacts,
    time_family: &Value,
) -> Result<(), ProtocolToolError> {
    let cases = json_field(time_family, "issuer", "B2b time boundaries")?;
    require_json_keys(
        cases,
        &[
            "after_catalog_signed_binding_cbor_hex",
            "before_catalog_signed_binding_cbor_hex",
            "empty_signed_binding_cbor_hex",
            "exact_boundary_signed_binding_cbor_hex",
        ],
        "B2b issuer time cases",
    )?;
    let (_, base_binding_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-completion-verifier-binding-v1",
        json_string(cases, "exact_boundary_signed_binding_cbor_hex")?,
        "B2b base issuer time comparison",
    )?;
    let base_binding_fields =
        numbered_fields(&base_binding_value, 23, "B2b base issuer time comparison")?;
    for (field, expected_valid) in [
        ("exact_boundary_signed_binding_cbor_hex", true),
        ("before_catalog_signed_binding_cbor_hex", false),
        ("after_catalog_signed_binding_cbor_hex", false),
        ("empty_signed_binding_cbor_hex", false),
    ] {
        let (_, value) = decode_exact_cddl(
            cddl,
            "recovery-scope-catalog-completion-verifier-binding-v1",
            json_string(cases, field)?,
            &format!("B2b issuer time {field}"),
        )?;
        let fields = numbered_fields(&value, 23, "B2b issuer time binding")?;
        let changed = fields
            .iter()
            .zip(&base_binding_fields)
            .enumerate()
            .filter_map(|(index, (observed, expected))| (observed != expected).then_some(index))
            .collect::<BTreeSet<_>>();
        require_handoff(
            changed
                .iter()
                .all(|index| [18, 19, 20, 21, 22].contains(index))
                && (changed.is_empty() || changed.iter().any(|index| [18, 19].contains(index))),
            &format!(
                "B2b issuer {field} changed bytes outside issuer times and three dependent signatures"
            ),
        )?;
        verify_signature(
            cbor_fixed(fields[17], "B2b issuer EPK")?,
            COMPLETION_EVIDENCE_POP_DOMAIN,
            &encoded_unsigned_prefix(&value, 20, "B2b issuer PoP")?,
            cbor_fixed(fields[20], "B2b issuer PoP signature")?,
            field,
        )?;
        verify_signature(
            cbor_fixed(fields[8], "B2b verifier key")?,
            COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN,
            &encoded_unsigned_prefix(&value, 21, "B2b origin authorization")?,
            cbor_fixed(fields[21], "B2b origin authorization signature")?,
            field,
        )?;
        verify_signature(
            catalog.context.authority_public_key,
            VERIFIER_BINDING_SIGNATURE_DOMAIN,
            &encoded_unsigned_prefix(&value, 22, "B2b Catalog countersignature")?,
            cbor_fixed(fields[22], "B2b Catalog countersignature")?,
            field,
        )?;
        let binding_issued = cbor_unsigned(fields[11], "B2b binding issued_at")?;
        let binding_expires = cbor_unsigned(fields[12], "B2b binding expires_at")?;
        let issuer_not_before = cbor_unsigned(fields[18], "B2b issuer not_before")?;
        let issuer_expires = cbor_unsigned(fields[19], "B2b issuer expires_at")?;
        let valid = issuer_not_before < issuer_expires
            && issuer_not_before >= binding_issued
            && issuer_expires <= binding_expires
            && issuer_not_before >= catalog.context.head_issued_at
            && issuer_expires <= catalog.context.head_expires_at;
        require_handoff(
            valid == expected_valid,
            &format!(
                "B2b triple-signed issuer time {field} did not reach only its target interval predicate"
            ),
        )?;
        if expected_valid {
            require_handoff(
                issuer_not_before == catalog.context.head_issued_at
                    && issuer_expires == catalog.context.head_expires_at,
                "B2b issuer exact authorization boundaries drifted",
            )?;
        }
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "strict decoding and closed server-visible JSON types are one pre-business privacy boundary"
)]
fn validate_b2b_decoder_privacy(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    b2b: &Value,
) -> Result<(), ProtocolToolError> {
    let family = json_field(b2b, "decoder_privacy_closure", "Catalog V2 B2b")?;
    require_json_keys(
        family,
        &[
            "closed_server_visible_injections",
            "low_order_recipient_preparations",
            "noncanonical_preparation_cbor_hex",
            "size_count_index_sibling_status_boundaries",
            "trailing_preparation_cbor_hex",
        ],
        "Catalog V2 B2b decoder/privacy closure",
    )?;
    for field in [
        "noncanonical_preparation_cbor_hex",
        "trailing_preparation_cbor_hex",
    ] {
        expect_b2b_target_error(
            decode_exact_cddl(
                cddl,
                "recovery-scope-catalog-preparation-v2",
                json_string(family, field)?,
                field,
            ),
            field,
            "not deterministic canonical CBOR",
        )?;
    }

    let base_handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let base_inputs = json_field(base_handoff, "test_only_inputs", "Catalog V2 handoff")?;
    let low_order = json_field(
        family,
        "low_order_recipient_preparations",
        "B2b decoder/privacy closure",
    )?;
    require_json_keys(
        low_order,
        &["all_zero", "u_coordinate_one"],
        "B2b low-order X25519 preparations",
    )?;
    for name in ["all_zero", "u_coordinate_one"] {
        expect_b2b_target_error(
            validate_b2b_preparation_artifact(
                cddl,
                catalog_projection,
                json_field(low_order, name, "B2b low-order X25519 preparations")?,
                decode_json_fixed(base_inputs, "response_capability_hex")?,
                json_string(base_inputs, "preparation_idempotency_key_ascii")?.as_bytes(),
            ),
            &format!("{name} X25519 recipient"),
            "all-zero or low-order X25519 recipient key rejected",
        )?;
    }

    validate_b2b_shape_and_size_boundaries(cddl, family, base_handoff)?;
    let injections = json_field(
        family,
        "closed_server_visible_injections",
        "B2b decoder/privacy closure",
    )?
    .as_array()
    .ok_or_else(|| handoff_error("B2b closed-type injections must be an array"))?;
    require_handoff(
        injections.len() == 4,
        "B2b closed server-visible type portfolio must cover four private-field classes",
    )?;
    let mut observed = BTreeSet::new();
    for fixture in injections {
        require_json_keys(
            fixture,
            &["field", "target"],
            "B2b server-visible private-field injection",
        )?;
        let target = json_string(fixture, "target")?;
        let field = json_string(fixture, "field")?;
        require_handoff(
            observed.insert((target.to_owned(), field.to_owned())),
            "B2b server-visible injection portfolio contains a duplicate",
        )?;
        let mut handoff = base_handoff.clone();
        let pointer = match target {
            "preparation" => "/preparation",
            "provider_response" => "/provider_response",
            "public_aad" => "/public_aad",
            "statuses.ready" => "/statuses/ready",
            _ => {
                return Err(handoff_error(
                    "B2b closed-type injection target is not closed",
                ));
            }
        };
        handoff
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| handoff_error("B2b injection target is not an object"))?
            .insert(field.to_owned(), json!("forbidden-private-value"));
        let variant = vector_with_handoff(vector, &handoff)?;
        let input = parse_server_visible_handoff_input(&variant)?;
        expect_b2b_target_error(
            validate_server_visible_handoff(cddl, catalog_projection, &input),
            &format!("closed {target} private field {field}"),
            "exact JSON key set drifted",
        )?;
    }
    let expected = BTreeSet::from([
        (
            "preparation".to_owned(),
            "x25519_recipient_private_key_hex".to_owned(),
        ),
        (
            "provider_response".to_owned(),
            "plaintext_cbor_hex".to_owned(),
        ),
        (
            "public_aad".to_owned(),
            "verifier_public_key_hex".to_owned(),
        ),
        (
            "statuses.ready".to_owned(),
            "completion_evidence_issuer_epk_hex".to_owned(),
        ),
    ]);
    require_handoff(
        observed == expected,
        "B2b closed server-visible types did not cover every private material class",
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "byte, count, index, sibling, status, and safe-integer max/max+1 checks form one shape portfolio"
)]
fn validate_b2b_shape_and_size_boundaries(
    cddl: &str,
    family: &Value,
    base_handoff: &Value,
) -> Result<(), ProtocolToolError> {
    let bounds = json_field(
        family,
        "size_count_index_sibling_status_boundaries",
        "B2b decoder/privacy closure",
    )?;
    require_json_keys(
        bounds,
        &[
            "max_catalog_upload_body_bytes",
            "max_leaf_count",
            "max_leaf_count_plus_one",
            "max_preparation_body_bytes",
            "max_proof_siblings",
            "max_proof_siblings_plus_one",
            "max_signed_catalog_head_bytes",
            "max_status_body_bytes",
            "safe_highwater_max",
            "safe_successor_max",
        ],
        "B2b shape and size boundaries",
    )?;
    require_handoff(
        json_u64(bounds, "max_catalog_upload_body_bytes")?
            == u64::try_from(MAX_CATALOG_UPLOAD_BODY_BYTES).expect("upload body bound fits")
            && json_u64(bounds, "max_leaf_count")?
                == u64::try_from(MAX_CATALOG_LEAVES).expect("catalog count fits")
            && json_u64(bounds, "max_leaf_count_plus_one")?
                == u64::try_from(MAX_CATALOG_LEAVES + 1).expect("catalog max+1 fits")
            && json_u64(bounds, "max_preparation_body_bytes")?
                == u64::try_from(MAX_PREPARATION_BODY_BYTES).expect("preparation bound fits")
            && json_u64(bounds, "max_proof_siblings")?
                == u64::try_from(MAX_PROOF_SIBLINGS).expect("proof siblings fit")
            && json_u64(bounds, "max_proof_siblings_plus_one")?
                == u64::try_from(MAX_PROOF_SIBLINGS + 1).expect("proof max+1 fits")
            && json_u64(bounds, "max_signed_catalog_head_bytes")?
                == u64::try_from(MAX_SIGNED_CATALOG_HEAD_BYTES)
                    .expect("signed Catalog head bound fits")
            && json_u64(bounds, "max_status_body_bytes")?
                == u64::try_from(MAX_STATUS_BODY_BYTES).expect("status bound fits")
            && json_u64(bounds, "safe_highwater_max")? == 9_007_199_254_740_990
            && json_u64(bounds, "safe_successor_max")? == 9_007_199_254_740_991,
        "B2b shape/size boundary metadata drifted",
    )?;
    let encoded_bstr = |length: usize| {
        let length = u32::try_from(length).expect("B2b byte boundary fits u32");
        let mut encoded = Vec::with_capacity(length as usize + 5);
        encoded.push(0x5a);
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.resize(length as usize + 5, 0);
        encoded
    };
    for (rule, maximum) in [
        (
            "exact-signed-catalog-head-v2",
            MAX_SIGNED_CATALOG_HEAD_BYTES,
        ),
        ("exact-provider-package-v2", MAX_PROVIDER_PACKAGE_BYTES),
        ("exact-ready-status-v2", MAX_STATUS_BODY_BYTES),
    ] {
        cddl_cat::validate_cbor_bytes(rule, cddl, &encoded_bstr(maximum)).map_err(|error| {
            handoff_error(&format!("B2b {rule} rejected its exact maximum: {error}"))
        })?;
        require_handoff(
            cddl_cat::validate_cbor_bytes(rule, cddl, &encoded_bstr(maximum + 1)).is_err(),
            &format!("B2b {rule} accepted max+1 bytes"),
        )?;
    }

    let proof = |count: u64, index: u64, siblings: usize| {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(2)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-0123456789a2".to_owned()),
            ),
            (CanonicalValue::Unsigned(3), CanonicalValue::Unsigned(8)),
            (CanonicalValue::Unsigned(4), CanonicalValue::Unsigned(count)),
            (CanonicalValue::Unsigned(5), CanonicalValue::Unsigned(index)),
            (
                CanonicalValue::Unsigned(6),
                CanonicalValue::Array(
                    (0..siblings)
                        .map(|_| CanonicalValue::Bytes(vec![0; 32]))
                        .collect(),
                ),
            ),
        ])
    };
    for (label, value, accepted) in [
        ("count max", proof(1_023, 1_023, 0), true),
        ("count max+1", proof(1_024, 1_023, 0), false),
        ("index max", proof(1_023, 1_023, 0), true),
        ("index max+1", proof(1_023, 1_024, 0), false),
        ("siblings max", proof(1_023, 1, 10), true),
        ("siblings max+1", proof(1_023, 1, 11), false),
    ] {
        let exact = encode_deterministic_cbor(&value)
            .map_err(|error| handoff_error(&format!("encode B2b {label}: {error}")))?;
        require_handoff(
            cddl_cat::validate_cbor_bytes("catalog-merkle-proof-v2", cddl, &exact).is_ok()
                == accepted,
            &format!("B2b proof {label} boundary result drifted"),
        )?;
    }
    let base_preparation = decode_exact_bytes(
        &decode_lower_hex(json_string(
            json_field(base_handoff, "preparation", "B2b base handoff")?,
            "cbor_hex",
        )?)?,
        "B2b base preparation bound",
    )?;
    let CanonicalValue::Map(base_fields) = base_preparation else {
        return Err(handoff_error("B2b base preparation must be a map"));
    };
    for (label, highwater, accepted) in [
        ("safe highwater max", 9_007_199_254_740_990, true),
        ("safe highwater max+1", 9_007_199_254_740_991, false),
    ] {
        let mut fields = base_fields.clone();
        fields[9].1 = CanonicalValue::Unsigned(highwater);
        let exact = encode_deterministic_cbor(&CanonicalValue::Map(fields))
            .map_err(|error| handoff_error(&format!("encode B2b {label}: {error}")))?;
        require_handoff(
            cddl_cat::validate_cbor_bytes("recovery-scope-catalog-preparation-v2", cddl, &exact)
                .is_ok()
                == accepted,
            &format!("B2b {label} boundary result drifted"),
        )?;
    }
    let base_response = decode_exact_bytes(
        &decode_lower_hex(json_string(
            json_field(base_handoff, "provider_response", "B2b base handoff")?,
            "cbor_hex",
        )?)?,
        "B2b base response successor bound",
    )?;
    let CanonicalValue::Map(base_response_fields) = base_response else {
        return Err(handoff_error("B2b base provider response must be a map"));
    };
    for (label, successor, accepted) in [
        ("safe successor max", 9_007_199_254_740_991, true),
        ("safe successor max+1", 9_007_199_254_740_992, false),
    ] {
        let mut fields = base_response_fields.clone();
        fields[11].1 = CanonicalValue::Unsigned(successor);
        let exact = encode_deterministic_cbor(&CanonicalValue::Map(fields))
            .map_err(|error| handoff_error(&format!("encode B2b {label}: {error}")))?;
        require_handoff(
            cddl_cat::validate_cbor_bytes(
                "recovery-scope-catalog-provider-response-v2",
                cddl,
                &exact,
            )
            .is_ok()
                == accepted,
            &format!("B2b {label} boundary result drifted"),
        )?;
    }
    Ok(())
}

fn validate_b2b_limitations(b2b: &Value) -> Result<(), ProtocolToolError> {
    let limitations = json_field(b2b, "limitations", "Catalog V2 B2b")?;
    require_json_keys(
        limitations,
        &[
            "generic_counter_is_wire",
            "provider_session_is_wire",
            "represented_by",
        ],
        "Catalog V2 B2b limitations",
    )?;
    let represented = json_field(limitations, "represented_by", "B2b limitations")?
        .as_array()
        .ok_or_else(|| handoff_error("B2b limitation representation must be an array"))?;
    require_handoff(
        !b2b_json_bool(limitations, "generic_counter_is_wire")?
            && !b2b_json_bool(limitations, "provider_session_is_wire")?
            && represented
                == &[
                    json!("identity_log_h_to_h_plus_1"),
                    json!("safe_highwater_max"),
                    json!("leaf_count_index_and_sibling_bounds"),
                ],
        "B2b must not invent a generic wire counter or provider-session field",
    )
}

fn require_json_keys(
    value: &Value,
    expected: &[&str],
    label: &str,
) -> Result<(), ProtocolToolError> {
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolToolError::new(format!("{label} must be an object")))?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual == expected {
        Ok(())
    } else {
        Err(ProtocolToolError::new(format!(
            "{label} exact JSON key set drifted"
        )))
    }
}

fn json_field<'a>(
    value: &'a Value,
    field: &str,
    label: &str,
) -> Result<&'a Value, ProtocolToolError> {
    value
        .get(field)
        .ok_or_else(|| ProtocolToolError::new(format!("{label} missing {field}")))
}

fn json_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, ProtocolToolError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ProtocolToolError::new(format!("Catalog V2 JSON {field} must be text")))
}

fn json_u64(value: &Value, field: &str) -> Result<u64, ProtocolToolError> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| ProtocolToolError::new(format!("Catalog V2 JSON {field} must be unsigned")))
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, ProtocolToolError> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 vector hex must be even-length lower-case hexadecimal",
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]);
            let low = hex_nibble(pair[1]);
            Ok((high << 4) | low)
        })
        .collect()
}

fn encode_lower_hex(value: &[u8]) -> String {
    value.iter().fold(
        String::with_capacity(value.len() * 2),
        |mut encoded, byte| {
            write!(encoded, "{byte:02x}").expect("writing to String cannot fail");
            encoded
        },
    )
}

const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn decode_json_fixed<const LENGTH: usize>(
    value: &Value,
    field: &str,
) -> Result<[u8; LENGTH], ProtocolToolError> {
    decode_lower_hex(json_string(value, field)?)?
        .try_into()
        .map_err(|_| ProtocolToolError::new(format!("Catalog V2 JSON {field} length drifted")))
}

fn decode_exact_cddl(
    cddl: &str,
    rule: &str,
    encoded: &str,
    label: &str,
) -> Result<(Vec<u8>, CanonicalValue), ProtocolToolError> {
    let bytes = decode_lower_hex(encoded)?;
    let value = decode_exact_bytes(&bytes, label)?;
    cddl_cat::validate_cbor_bytes(rule, cddl, &bytes)
        .map_err(|error| ProtocolToolError::new(format!("CDDL rejected {label}: {error}")))?;
    Ok((bytes, value))
}

fn decode_exact_upload_cddl(
    cddl: &str,
    encoded: &str,
    label: &str,
) -> Result<(Vec<u8>, CanonicalValue), ProtocolToolError> {
    let bytes = decode_lower_hex(encoded)?;
    let value = decode_exact_upload_bytes(cddl, &bytes, label)?;
    Ok((bytes, value))
}

fn decode_exact_upload_bytes(
    cddl: &str,
    bytes: &[u8],
    label: &str,
) -> Result<CanonicalValue, ProtocolToolError> {
    let value = decode_exact_bytes_with_limit(bytes, label, MAX_ENVELOPE_BYTES)?;
    cddl_cat::validate_cbor_bytes("recovery-scope-catalog-upload-v2", cddl, bytes)
        .map_err(|error| ProtocolToolError::new(format!("CDDL rejected {label}: {error}")))?;
    Ok(value)
}

fn decode_exact_bytes(bytes: &[u8], label: &str) -> Result<CanonicalValue, ProtocolToolError> {
    let value = decode_deterministic_cbor(bytes).map_err(|error| {
        ProtocolToolError::new(format!(
            "{label} is not deterministic canonical CBOR: {error}"
        ))
    })?;
    let reencoded = encode_deterministic_cbor(&value)
        .map_err(|error| ProtocolToolError::new(format!("re-encode {label}: {error}")))?;
    if reencoded != bytes {
        return Err(ProtocolToolError::new(format!(
            "{label} changed under deterministic re-encoding"
        )));
    }
    Ok(value)
}

fn decode_exact_bytes_with_limit(
    bytes: &[u8],
    label: &str,
    limit: usize,
) -> Result<CanonicalValue, ProtocolToolError> {
    let value = decode_deterministic_cbor_with_limit(bytes, limit).map_err(|error| {
        ProtocolToolError::new(format!(
            "{label} is not deterministic canonical CBOR: {error}"
        ))
    })?;
    let reencoded = encode_deterministic_cbor_with_limit(&value, limit)
        .map_err(|error| ProtocolToolError::new(format!("re-encode {label}: {error}")))?;
    if reencoded != bytes {
        return Err(ProtocolToolError::new(format!(
            "{label} changed under deterministic re-encoding"
        )));
    }
    Ok(value)
}

fn numbered_fields<'a>(
    value: &'a CanonicalValue,
    expected: usize,
    label: &str,
) -> Result<Vec<&'a CanonicalValue>, ProtocolToolError> {
    let CanonicalValue::Map(entries) = value else {
        return Err(ProtocolToolError::new(format!(
            "{label} must be a numbered map"
        )));
    };
    if entries.len() != expected {
        return Err(ProtocolToolError::new(format!(
            "{label} field count drifted"
        )));
    }
    entries
        .iter()
        .enumerate()
        .map(|(index, (key, value))| {
            let expected =
                CanonicalValue::Unsigned(u64::try_from(index + 1).expect("bounded field index"));
            if key == &expected {
                Ok(value)
            } else {
                Err(ProtocolToolError::new(format!(
                    "{label} field keys drifted"
                )))
            }
        })
        .collect()
}

fn cbor_unsigned(value: &CanonicalValue, label: &str) -> Result<u64, ProtocolToolError> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(ProtocolToolError::new(format!("{label} must be unsigned")));
    };
    Ok(*value)
}

fn cbor_text<'a>(value: &'a CanonicalValue, label: &str) -> Result<&'a str, ProtocolToolError> {
    let CanonicalValue::Text(value) = value else {
        return Err(ProtocolToolError::new(format!("{label} must be text")));
    };
    Ok(value)
}

fn cbor_bytes<'a>(value: &'a CanonicalValue, label: &str) -> Result<&'a [u8], ProtocolToolError> {
    let CanonicalValue::Bytes(value) = value else {
        return Err(ProtocolToolError::new(format!("{label} must be bytes")));
    };
    Ok(value)
}

fn cbor_fixed<const LENGTH: usize>(
    value: &CanonicalValue,
    label: &str,
) -> Result<[u8; LENGTH], ProtocolToolError> {
    cbor_bytes(value, label)?
        .try_into()
        .map_err(|_| ProtocolToolError::new(format!("{label} must be exactly {LENGTH} bytes")))
}

fn cbor_array<'a>(
    value: &'a CanonicalValue,
    label: &str,
) -> Result<&'a [CanonicalValue], ProtocolToolError> {
    let CanonicalValue::Array(value) = value else {
        return Err(ProtocolToolError::new(format!("{label} must be an array")));
    };
    Ok(value)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn verify_signature(
    public_key: [u8; 32],
    domain: &[u8],
    unsigned: &[u8],
    signature: [u8; 64],
    label: &str,
) -> Result<(), ProtocolToolError> {
    let mut transcript = Vec::with_capacity(domain.len() + unsigned.len());
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(unsigned);
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ProtocolToolError::new(format!("{label} public key invalid")))?
        .verify_strict(&transcript, &Signature::from_bytes(&signature))
        .map_err(|_| ProtocolToolError::new(format!("{label} signature invalid")))
}

fn encoded_unsigned_prefix(
    value: &CanonicalValue,
    count: usize,
    label: &str,
) -> Result<Vec<u8>, ProtocolToolError> {
    let CanonicalValue::Map(entries) = value else {
        return Err(ProtocolToolError::new(format!("{label} must be a map")));
    };
    encode_deterministic_cbor(&CanonicalValue::Map(entries[..count].to_vec()))
        .map_err(|error| ProtocolToolError::new(format!("encode {label} unsigned: {error}")))
}

fn handoff_error(label: &str) -> ProtocolToolError {
    ProtocolToolError::new(format!("Catalog V2 C1b-B1 handoff {label}"))
}

fn require_handoff(condition: bool, label: &str) -> Result<(), ProtocolToolError> {
    if condition {
        Ok(())
    } else {
        Err(handoff_error(label))
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the server projection must be derived exclusively from one exact signed head and ciphertext upload"
)]
fn validate_catalog_server_projection(
    vector: &Value,
    cddl: &str,
) -> Result<CatalogServerProjection, ProtocolToolError> {
    let catalog = json_field(vector, "catalog", "Catalog V2 vector")?;
    let (signed_head_exact, signed_head) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-head-v2",
        json_string(catalog, "head_signed_cbor_hex")?,
        "Catalog V2 server signed head",
    )?;
    let head = numbered_fields(&signed_head, 16, "Catalog V2 server signed head")?;
    let context = CatalogVectorContext {
        identity_id: cbor_text(head[2], "server head identity")?.to_owned(),
        catalog_id: cbor_text(head[1], "server head catalog")?.to_owned(),
        generation: cbor_unsigned(head[3], "server head generation")?,
        previous_head: cbor_fixed(head[4], "server head previous digest")?,
        identity_sequence: cbor_unsigned(head[8], "server head identity H")?,
        identity_head: cbor_fixed(head[9], "server head identity digest")?,
        authority_device_id: cbor_text(head[10], "server head authority device")?.to_owned(),
        authority_key_id: cbor_text(head[11], "server head authority key")?.to_owned(),
        authority_public_key: cbor_fixed(head[12], "server head authority public key")?,
        head_issued_at: cbor_unsigned(head[13], "server head issued_at")?,
        head_expires_at: cbor_unsigned(head[14], "server head expires_at")?,
        validation_time: json_u64(catalog, "validation_time")?,
    };
    validate_context_syntax(&context)?;
    let leaf_count = cbor_unsigned(head[5], "server head leaf count")?;
    let leaf_count_usize = usize::try_from(leaf_count)
        .map_err(|_| ProtocolToolError::new("Catalog V2 server leaf count does not fit usize"))?;
    let merkle_root = cbor_fixed(head[6], "server head Merkle root")?;
    let ciphertext_digest = cbor_fixed(head[7], "server head ciphertext digest")?;
    validate_head_value(
        &signed_head,
        &context,
        merkle_root,
        ciphertext_digest,
        leaf_count_usize,
    )?;
    if context.head_issued_at >= context.head_expires_at
        || context.validation_time < context.head_issued_at
        || context.validation_time >= context.head_expires_at
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 server head validity invalid",
        ));
    }
    let signed_head_digest = domain_digest(HEAD_DOMAIN, &signed_head_exact);
    let ciphertext = decode_lower_hex(json_string(catalog, "ciphertext_hex")?)?;
    if ciphertext.is_empty()
        || ciphertext.len() > MAX_CIPHERTEXT_BYTES
        || domain_digest(CIPHERTEXT_DOMAIN, &ciphertext) != ciphertext_digest
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 server ciphertext binding invalid",
        ));
    }
    let (_, upload) = decode_exact_upload_cddl(
        cddl,
        json_string(catalog, "upload_cbor_hex")?,
        "Catalog V2 server upload",
    )?;
    let upload_fields = numbered_fields(&upload, 2, "Catalog V2 server upload")?;
    if upload_fields[0] != &signed_head
        || cbor_bytes(upload_fields[1], "server upload ciphertext")? != ciphertext
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 server upload/head/ciphertext mismatch",
        ));
    }
    let identity_head = json_field(catalog, "identity_head", "Catalog V2 catalog")?;
    require_json_keys(
        identity_head,
        &["digest_hex", "sequence"],
        "Catalog V2 server identity head",
    )?;
    if json_string(catalog, "identity_id")? != context.identity_id
        || json_string(catalog, "catalog_id")? != context.catalog_id
        || json_u64(catalog, "generation")? != context.generation
        || decode_json_fixed::<32>(catalog, "previous_head_digest_hex")? != context.previous_head
        || json_u64(identity_head, "sequence")? != context.identity_sequence
        || decode_json_fixed::<32>(identity_head, "digest_hex")? != context.identity_head
        || json_string(catalog, "authority_device_id")? != context.authority_device_id
        || json_string(catalog, "authority_key_id")? != context.authority_key_id
        || decode_json_fixed::<32>(vector, "catalog_authority_public_key_hex")?
            != context.authority_public_key
        || json_u64(catalog, "head_issued_at")? != context.head_issued_at
        || json_u64(catalog, "head_expires_at")? != context.head_expires_at
        || decode_json_fixed::<32>(catalog, "merkle_root_hex")? != merkle_root
        || decode_json_fixed::<32>(catalog, "ciphertext_digest_hex")? != ciphertext_digest
        || decode_json_fixed::<32>(catalog, "head_digest_hex")? != signed_head_digest
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 server public assertion mismatch",
        ));
    }
    Ok(CatalogServerProjection {
        signed_head_exact,
        signed_head_digest,
        identity_id: context.identity_id,
        catalog_id: context.catalog_id,
        generation: context.generation,
        previous_head_digest: context.previous_head,
        leaf_count,
        merkle_root,
        identity_sequence: context.identity_sequence,
        identity_head_digest: context.identity_head,
        authority_device_id: context.authority_device_id,
        authority_key_id: context.authority_key_id,
        authority_public_key: context.authority_public_key,
        head_issued_at: context.head_issued_at,
        head_expires_at: context.head_expires_at,
        validation_time: context.validation_time,
        ciphertext,
        ciphertext_digest,
    })
}

fn parse_server_visible_handoff_input(
    vector: &Value,
) -> Result<ServerVisibleHandoffInput, ProtocolToolError> {
    let handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let inputs = json_field(handoff, "test_only_inputs", "Catalog V2 handoff")?;
    require_handoff(
        json_string(inputs, "classification")?
            == "public-deterministic-test-fixture-not-a-credential",
        "test-only input classification drifted",
    )?;
    Ok(ServerVisibleHandoffInput {
        preparation: json_field(handoff, "preparation", "Catalog V2 handoff")?.clone(),
        origin_authenticated_identity_log: json_field(
            handoff,
            "origin_authenticated_identity_log",
            "Catalog V2 handoff",
        )?
        .clone(),
        device_add: json_field(handoff, "device_add", "Catalog V2 handoff")?.clone(),
        provider_response: json_field(handoff, "provider_response", "Catalog V2 handoff")?.clone(),
        public_aad: json_field(handoff, "public_aad", "Catalog V2 handoff")?.clone(),
        hpke_envelope: json_field(handoff, "hpke_envelope", "Catalog V2 handoff")?.clone(),
        mutation_receipts: json_field(handoff, "mutation_receipts", "Catalog V2 handoff")?.clone(),
        statuses: json_field(handoff, "statuses", "Catalog V2 handoff")?.clone(),
        enrollment_candidate_recipient_public_key: decode_json_fixed(
            inputs,
            "enrollment_candidate_recipient_public_key_hex",
        )?,
        response_capability: decode_json_fixed(inputs, "response_capability_hex")?,
        preparation_idempotency_key: json_string(inputs, "preparation_idempotency_key_ascii")?
            .as_bytes()
            .to_vec(),
        response_idempotency_key: json_string(inputs, "response_idempotency_key_ascii")?
            .as_bytes()
            .to_vec(),
    })
}

fn parse_origin_active_devices(
    value: &Value,
    label: &str,
) -> Result<Vec<OriginActiveDevice>, ProtocolToolError> {
    value
        .as_array()
        .ok_or_else(|| handoff_error(&format!("{label} active_devices must be an array")))?
        .iter()
        .map(|device| {
            require_json_keys(
                device,
                &[
                    "device_id",
                    "encryption_public_key_hex",
                    "signing_public_key_hex",
                ],
                label,
            )?;
            Ok(OriginActiveDevice {
                device_id: json_string(device, "device_id")?.to_owned(),
                signing_public_key: decode_json_fixed(device, "signing_public_key_hex")?,
                encryption_public_key: decode_json_fixed(device, "encryption_public_key_hex")?,
            })
        })
        .collect()
}

fn parse_origin_identity_state(
    value: &Value,
    label: &str,
) -> Result<OriginIdentityState, ProtocolToolError> {
    require_json_keys(
        value,
        &[
            "active_devices",
            "current_recovery_public_key_hex",
            "current_root_public_key_hex",
            "head_digest_hex",
            "sequence",
        ],
        label,
    )?;
    Ok(OriginIdentityState {
        sequence: json_u64(value, "sequence")?,
        head_digest: decode_json_fixed(value, "head_digest_hex")?,
        current_root_public_key: decode_json_fixed(value, "current_root_public_key_hex")?,
        current_recovery_public_key: decode_json_fixed(value, "current_recovery_public_key_hex")?,
        active_devices: parse_origin_active_devices(
            json_field(value, "active_devices", label)?,
            label,
        )?,
    })
}

fn parse_origin_active_devices_cbor(
    value: &CanonicalValue,
    label: &str,
) -> Result<Vec<OriginActiveDevice>, ProtocolToolError> {
    cbor_array(value, label)?
        .iter()
        .map(|device| {
            let fields = numbered_fields(device, 3, label)?;
            Ok(OriginActiveDevice {
                device_id: cbor_text(fields[0], label)?.to_owned(),
                signing_public_key: cbor_fixed(fields[1], label)?,
                encryption_public_key: cbor_fixed(fields[2], label)?,
            })
        })
        .collect()
}

fn validate_origin_identity_state_semantics(
    state: &OriginIdentityState,
    label: &str,
) -> Result<(), ProtocolToolError> {
    require_handoff(
        state.sequence > 0 && state.head_digest != [0; 32],
        &format!("{label} sequence/head is invalid"),
    )?;
    let current_root = VerifyingKey::from_bytes(&state.current_root_public_key)
        .map_err(|_| handoff_error(&format!("{label} current root key is invalid")))?;
    require_handoff(
        !current_root.is_weak(),
        &format!("{label} current root key is invalid"),
    )?;
    let current_recovery = VerifyingKey::from_bytes(&state.current_recovery_public_key)
        .map_err(|_| handoff_error(&format!("{label} current recovery key is invalid")))?;
    require_handoff(
        !current_recovery.is_weak(),
        &format!("{label} current recovery key is invalid"),
    )?;
    let devices = indexed_active_devices(state, label)?;
    require_handoff(
        !devices.is_empty(),
        &format!("{label} has no active devices"),
    )?;
    for device in devices.values() {
        let signing_key = VerifyingKey::from_bytes(&device.signing_public_key)
            .map_err(|_| handoff_error(&format!("{label} active-device key is invalid")))?;
        require_handoff(
            !signing_key.is_weak(),
            &format!("{label} active-device key is invalid"),
        )?;
        validate_recipient_public_key_semantics(device.encryption_public_key)?;
    }
    Ok(())
}

fn parse_origin_authenticated_current_identity_snapshot(
    snapshot: &Value,
    label: &str,
) -> Result<OriginAuthenticatedCurrentIdentitySnapshot, ProtocolToolError> {
    require_json_keys(
        snapshot,
        &[
            "active_devices",
            "classification",
            "current_recovery_public_key_hex",
            "current_root_public_key_hex",
            "head_digest_hex",
            "origin",
            "origin_authentication_public_key_hex",
            "sequence",
            "signature_hex",
            "signed_cbor_hex",
            "unsigned_cbor_hex",
        ],
        label,
    )?;
    let signed_exact = decode_lower_hex(json_string(snapshot, "signed_cbor_hex")?)?;
    let signed_value = decode_exact_bytes(&signed_exact, label)?;
    let fields = numbered_fields(&signed_value, 10, label)?;
    let unsigned = encoded_unsigned_prefix(&signed_value, 9, label)?;
    let authentication_public_key = cbor_fixed::<32>(fields[8], label)?;
    let signature = cbor_fixed::<64>(fields[9], label)?;
    require_handoff(
        authentication_public_key == ORIGIN_IDENTITY_SNAPSHOT_AUTHENTICATION_PUBLIC_KEY,
        &format!("{label} origin trust anchor drifted"),
    )?;
    verify_signature(
        authentication_public_key,
        ORIGIN_IDENTITY_SNAPSHOT_SIGNATURE_DOMAIN,
        &unsigned,
        signature,
        label,
    )?;

    let classification = cbor_text(fields[1], label)?;
    let origin = cbor_text(fields[2], label)?.to_owned();
    let state = OriginIdentityState {
        sequence: cbor_unsigned(fields[3], label)?,
        head_digest: cbor_fixed(fields[4], label)?,
        current_root_public_key: cbor_fixed(fields[5], label)?,
        current_recovery_public_key: cbor_fixed(fields[6], label)?,
        active_devices: parse_origin_active_devices_cbor(fields[7], label)?,
    };
    validate_origin_identity_state_semantics(&state, label)?;
    let json_devices =
        parse_origin_active_devices(json_field(snapshot, "active_devices", label)?, label)?;
    require_handoff(
        cbor_unsigned(fields[0], label)? == 1
            && classification
                == "trusted-origin-authenticated-current-identity-snapshot-not-portable-wire-proof"
            && valid_https_origin(&origin)
            && json_string(snapshot, "classification")? == classification
            && json_string(snapshot, "origin")? == origin
            && json_u64(snapshot, "sequence")? == state.sequence
            && decode_json_fixed::<32>(snapshot, "head_digest_hex")? == state.head_digest
            && decode_json_fixed::<32>(snapshot, "current_root_public_key_hex")?
                == state.current_root_public_key
            && decode_json_fixed::<32>(snapshot, "current_recovery_public_key_hex")?
                == state.current_recovery_public_key
            && json_devices == state.active_devices
            && decode_json_fixed::<32>(snapshot, "origin_authentication_public_key_hex")?
                == authentication_public_key
            && decode_lower_hex(json_string(snapshot, "unsigned_cbor_hex")?)? == unsigned
            && decode_json_fixed::<64>(snapshot, "signature_hex")? == signature,
        &format!("{label} authenticated bytes/JSON/head assertions drifted"),
    )?;
    Ok(OriginAuthenticatedCurrentIdentitySnapshot { origin, state })
}

fn origin_has_device(state: &OriginIdentityState, device_id: &str, signing_key: [u8; 32]) -> bool {
    state
        .active_devices
        .iter()
        .any(|device| device.device_id == device_id && device.signing_public_key == signing_key)
}

fn origin_has_device_id(state: &OriginIdentityState, device_id: &str) -> bool {
    state
        .active_devices
        .iter()
        .any(|device| device.device_id == device_id)
}

fn indexed_active_devices(
    state: &OriginIdentityState,
    label: &str,
) -> Result<BTreeMap<String, OriginActiveDevice>, ProtocolToolError> {
    let mut indexed = BTreeMap::new();
    for device in &state.active_devices {
        if !valid_uuid_v7(&device.device_id)
            || indexed
                .insert(device.device_id.clone(), device.clone())
                .is_some()
        {
            return Err(handoff_error(&format!(
                "{label} has an invalid or duplicate active device"
            )));
        }
    }
    Ok(indexed)
}

fn validate_exact_device_add_reduction(
    identity_log: &OriginAuthenticatedIdentityLog,
    candidate_device_id: &str,
    candidate_signing_public_key: [u8; 32],
    candidate_encryption_public_key: [u8; 32],
) -> Result<(), ProtocolToolError> {
    let mut expected = indexed_active_devices(&identity_log.at_h, "origin state at H")?;
    require_handoff(
        expected
            .insert(
                candidate_device_id.to_owned(),
                OriginActiveDevice {
                    device_id: candidate_device_id.to_owned(),
                    signing_public_key: candidate_signing_public_key,
                    encryption_public_key: candidate_encryption_public_key,
                },
            )
            .is_none(),
        "candidate device id already existed at H",
    )?;
    let observed = indexed_active_devices(&identity_log.at_h_plus_1, "origin state at H+1")?;
    require_handoff(
        observed == expected,
        "origin-authenticated H+1 is not exactly H plus the direct DeviceAdd candidate",
    )
}

fn validate_independent_authority_currentness(
    current_state: &OriginIdentityState,
    candidate_device_id: &str,
    provider_id: &str,
    authority_descriptor: &[&CanonicalValue],
) -> Result<(IndependentAuthorityKind, [u8; 32]), ProtocolToolError> {
    let authority_key = cbor_fixed(authority_descriptor[2], "handoff authority key")?;
    let authority_kind = match cbor_unsigned(authority_descriptor[0], "handoff authority kind")? {
        1 => {
            let authority_id = cbor_text(authority_descriptor[1], "handoff authority device")?;
            require_handoff(
                authority_id != candidate_device_id
                    && authority_id != provider_id
                    && origin_has_device(current_state, authority_id, authority_key),
                "active independent authority is not current and distinct in authenticated identity state",
            )?;
            IndependentAuthorityKind::ActiveDevice
        }
        2 => {
            require_handoff(
                cbor_fixed::<32>(authority_descriptor[1], "handoff root authority id")?
                    == domain_digest(DEVICE_HISTORY_AUTHORITY_ID_DOMAIN, &authority_key)
                    && authority_key == current_state.current_root_public_key,
                "root independent authority id/key is not current in authenticated identity state",
            )?;
            IndependentAuthorityKind::CurrentRoot
        }
        3 => {
            require_handoff(
                cbor_fixed::<32>(authority_descriptor[1], "handoff recovery authority id")?
                    == domain_digest(DEVICE_HISTORY_AUTHORITY_ID_DOMAIN, &authority_key)
                    && authority_key == current_state.current_recovery_public_key,
                "recovery independent authority id/key is not current in authenticated identity state",
            )?;
            IndependentAuthorityKind::CurrentRecovery
        }
        _ => return Err(handoff_error("independent authority kind is not closed")),
    };
    Ok((authority_kind, authority_key))
}

#[allow(
    clippy::too_many_lines,
    reason = "the positive server-visible handoff projection is one closed admission and status contract"
)]
fn validate_server_visible_handoff(
    cddl: &str,
    catalog: &CatalogServerProjection,
    input: &ServerVisibleHandoffInput,
) -> Result<ServerVisibleHandoffFacts, ProtocolToolError> {
    let preparation_json = &input.preparation;
    require_json_keys(
        preparation_json,
        &[
            "candidate_device_id",
            "candidate_signing_public_key_hex",
            "cbor_hex",
            "digest_hex",
            "recipient_public_key_hex",
            "request_id",
            "signature_hex",
            "unsigned_cbor_hex",
        ],
        "Catalog V2 handoff preparation",
    )?;
    let (preparation_exact, preparation_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-preparation-v2",
        json_string(preparation_json, "cbor_hex")?,
        "Catalog V2 handoff preparation",
    )?;
    require_handoff(
        preparation_exact.len() <= MAX_PREPARATION_BODY_BYTES,
        "preparation exceeds its body bound",
    )?;
    let preparation = numbered_fields(&preparation_value, 17, "Catalog V2 handoff preparation")?;
    let preparation_unsigned =
        encoded_unsigned_prefix(&preparation_value, 16, "Catalog V2 handoff preparation")?;
    let request_id = cbor_text(preparation[1], "handoff preparation request_id")?.to_owned();
    let candidate_device_id =
        cbor_text(preparation[6], "handoff preparation candidate device")?.to_owned();
    let candidate_signing_public_key =
        cbor_fixed(preparation[7], "handoff preparation candidate signing key")?;
    let candidate_recipient_public_key =
        cbor_fixed(preparation[8], "handoff preparation recipient key")?;
    let preparation_digest = domain_digest(PREPARATION_DIGEST_DOMAIN, &preparation_exact);
    require_handoff(
        cbor_unsigned(preparation[0], "handoff preparation version")? == 2
            && cbor_text(preparation[2], "handoff preparation identity")? == catalog.identity_id
            && cbor_text(preparation[3], "handoff preparation catalog")? == catalog.catalog_id
            && cbor_unsigned(preparation[4], "handoff preparation generation")?
                == catalog.generation
            && cbor_fixed::<32>(preparation[5], "handoff preparation head digest")?
                == catalog.signed_head_digest
            && cbor_unsigned(preparation[9], "handoff preparation H")? == catalog.identity_sequence
            && cbor_fixed::<32>(preparation[10], "handoff preparation head at H")?
                == catalog.identity_head_digest,
        "preparation Catalog coordinates drifted",
    )?;
    let candidate_nonce = cbor_fixed::<32>(preparation[11], "handoff candidate nonce")?;
    require_handoff(
        candidate_nonce != [0; 32]
            && cbor_fixed::<32>(preparation[12], "handoff response capability digest")?
                == domain_digest(RESPONSE_CAPABILITY_DOMAIN, &input.response_capability)
            && cbor_fixed::<32>(preparation[13], "handoff preparation idempotency digest")?
                == domain_digest(
                    PREPARATION_IDEMPOTENCY_DOMAIN,
                    &input.preparation_idempotency_key,
                ),
        "preparation nonce or header digest drifted",
    )?;
    let preparation_issued = cbor_unsigned(preparation[14], "handoff preparation issued_at")?;
    let preparation_expires = cbor_unsigned(preparation[15], "handoff preparation expires_at")?;
    require_handoff(
        preparation_issued < preparation_expires
            && preparation_issued >= catalog.head_issued_at
            && preparation_expires <= catalog.head_expires_at,
        "preparation validity is not contained by the signed Catalog head",
    )?;
    let preparation_signature = cbor_fixed(preparation[16], "handoff preparation signature")?;
    verify_signature(
        candidate_signing_public_key,
        PREPARATION_SIGNATURE_DOMAIN,
        &preparation_unsigned,
        preparation_signature,
        "handoff preparation",
    )?;
    validate_recipient_public_key_semantics(candidate_recipient_public_key)?;
    require_handoff(
        decode_lower_hex(json_string(preparation_json, "unsigned_cbor_hex")?)?
            == preparation_unsigned
            && decode_json_fixed::<64>(preparation_json, "signature_hex")? == preparation_signature
            && decode_json_fixed::<32>(preparation_json, "digest_hex")? == preparation_digest
            && json_string(preparation_json, "request_id")? == request_id
            && json_string(preparation_json, "candidate_device_id")? == candidate_device_id
            && decode_json_fixed::<32>(preparation_json, "candidate_signing_public_key_hex")?
                == candidate_signing_public_key
            && decode_json_fixed::<32>(preparation_json, "recipient_public_key_hex")?
                == candidate_recipient_public_key
            && input.enrollment_candidate_recipient_public_key == candidate_recipient_public_key,
        "preparation JSON assertions do not match independently decoded bytes",
    )?;

    let oracle_json = &input.origin_authenticated_identity_log;
    require_json_keys(
        oracle_json,
        &["at_h", "at_h_plus_1", "classification", "origin"],
        "Catalog V2 handoff origin oracle",
    )?;
    require_handoff(
        json_string(oracle_json, "classification")?
            == "trusted-test-oracle-not-portable-wire-proof",
        "origin oracle classification drifted",
    )?;
    let identity_log = OriginAuthenticatedIdentityLog {
        origin: json_string(oracle_json, "origin")?.to_owned(),
        at_h: parse_origin_identity_state(
            json_field(oracle_json, "at_h", "Catalog V2 origin oracle")?,
            "Catalog V2 origin oracle at H",
        )?,
        at_h_plus_1: parse_origin_identity_state(
            json_field(oracle_json, "at_h_plus_1", "Catalog V2 origin oracle")?,
            "Catalog V2 origin oracle at H+1",
        )?,
    };
    require_handoff(
        identity_log.origin.starts_with("https://")
            && identity_log.at_h.sequence == catalog.identity_sequence
            && identity_log.at_h.head_digest == catalog.identity_head_digest
            && identity_log.at_h_plus_1.sequence == identity_log.at_h.sequence + 1
            && identity_log.at_h.current_root_public_key
                == identity_log.at_h_plus_1.current_root_public_key
            && identity_log.at_h.current_recovery_public_key
                == identity_log.at_h_plus_1.current_recovery_public_key,
        "origin-authenticated H/H+1 oracle drifted",
    )?;

    let device_add_json = &input.device_add;
    require_json_keys(
        device_add_json,
        &["cbor_hex", "digest_hex"],
        "Catalog V2 handoff DeviceAdd",
    )?;
    let device_add_exact = decode_lower_hex(json_string(device_add_json, "cbor_hex")?)?;
    require_handoff(
        device_add_exact.len() <= MAX_DEVICE_ADD_BYTES,
        "DeviceAdd exceeds its exact bound",
    )?;
    let device_add = IdentityLogEventV1::decode_and_verify(&device_add_exact)
        .map_err(|error| handoff_error(&format!("DeviceAdd V1.1 invalid: {error}")))?;
    let device_add_digest = domain_digest(IDENTITY_DEVICE_ADD_DOMAIN, &device_add_exact);
    let IdentityLogEventPayloadV1::DeviceAdd { certificate } = device_add.payload() else {
        return Err(handoff_error("identity event is not DeviceAdd"));
    };
    require_handoff(
        device_add.wire() == IDENTITY_LOG_WIRE_VERSION
            && device_add.identity_id().to_string() == catalog.identity_id
            && device_add.sequence().get() == identity_log.at_h_plus_1.sequence
            && device_add
                .previous_event_hash()
                .is_some_and(|digest| digest.as_bytes() == &identity_log.at_h.head_digest)
            && device_add.signer().as_bytes() == &identity_log.at_h.current_root_public_key
            && device_add
                .entry_hash()
                .is_ok_and(|digest| digest.as_bytes() == &identity_log.at_h_plus_1.head_digest)
            && certificate.identity_id() == device_add.identity_id()
            && certificate.device_id().to_string() == candidate_device_id
            && certificate.device_signing_key().as_bytes() == &candidate_signing_public_key
            && certificate.device_encryption_key().as_bytes() == &candidate_recipient_public_key
            && certificate.issuer_root_key().as_bytes()
                == &identity_log.at_h.current_root_public_key,
        "DeviceAdd transition or candidate key binding drifted",
    )?;
    require_handoff(
        !origin_has_device_id(&identity_log.at_h, &candidate_device_id)
            && origin_has_device(
                &identity_log.at_h_plus_1,
                &candidate_device_id,
                candidate_signing_public_key,
            )
            && decode_json_fixed::<32>(device_add_json, "digest_hex")? == device_add_digest,
        "DeviceAdd currentness or JSON digest assertion drifted",
    )?;
    validate_exact_device_add_reduction(
        &identity_log,
        &candidate_device_id,
        candidate_signing_public_key,
        candidate_recipient_public_key,
    )?;

    let response_json = &input.provider_response;
    require_json_keys(
        response_json,
        &[
            "authority_signature_hex",
            "cbor_hex",
            "digest_hex",
            "provider_signature_hex",
            "unsigned_cbor_hex",
        ],
        "Catalog V2 handoff provider response",
    )?;
    let (provider_response_exact, provider_response_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-provider-response-v2",
        json_string(response_json, "cbor_hex")?,
        "Catalog V2 handoff provider response",
    )?;
    require_handoff(
        provider_response_exact.len() <= MAX_PROVIDER_RESPONSE_BODY_BYTES,
        "provider response exceeds its body bound",
    )?;
    let response = numbered_fields(
        &provider_response_value,
        26,
        "Catalog V2 handoff provider response",
    )?;
    let response_unsigned = encoded_unsigned_prefix(
        &provider_response_value,
        22,
        "Catalog V2 handoff provider response",
    )?;
    let provider_descriptor = numbered_fields(response[14], 3, "handoff provider descriptor")?;
    let authority_descriptor = numbered_fields(response[15], 3, "handoff authority descriptor")?;
    let provider_id = cbor_text(provider_descriptor[1], "handoff provider device")?;
    let provider_key = cbor_fixed(provider_descriptor[2], "handoff provider key")?;
    let (authority_kind, authority_key) = validate_independent_authority_currentness(
        &identity_log.at_h_plus_1,
        &candidate_device_id,
        provider_id,
        &authority_descriptor,
    )?;
    require_handoff(
        cbor_unsigned(provider_descriptor[0], "handoff provider version")? == 2
            && provider_id != candidate_device_id
            && provider_key != candidate_signing_public_key
            && authority_key != candidate_signing_public_key
            && authority_key != provider_key
            && origin_has_device(&identity_log.at_h_plus_1, provider_id, provider_key),
        "provider or independent authority key is not current and distinct",
    )?;
    let response_provider_signature = cbor_fixed(response[22], "provider response signature")?;
    let response_authority_signature = cbor_fixed(response[23], "provider authority signature")?;
    verify_signature(
        provider_key,
        PROVIDER_SIGNATURE_DOMAIN,
        &response_unsigned,
        response_provider_signature,
        "handoff provider response provider",
    )?;
    verify_signature(
        authority_key,
        PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
        &response_unsigned,
        response_authority_signature,
        "handoff provider response authority",
    )?;
    let response_digest = domain_digest(PROVIDER_RESPONSE_DOMAIN, &provider_response_exact);
    let response_issued = cbor_unsigned(response[20], "handoff response issued_at")?;
    let response_expires = cbor_unsigned(response[21], "handoff response expires_at")?;
    require_handoff(
        cbor_unsigned(response[0], "handoff response version")? == 2
            && cbor_text(response[1], "handoff response request")? == request_id
            && cbor_fixed::<32>(response[2], "handoff response preparation digest")?
                == preparation_digest
            && cbor_text(response[3], "handoff response identity")? == catalog.identity_id
            && cbor_text(response[4], "handoff response catalog")? == catalog.catalog_id
            && cbor_unsigned(response[5], "handoff response generation")? == catalog.generation
            && cbor_fixed::<32>(response[6], "handoff response head digest")?
                == cbor_fixed::<32>(preparation[5], "preparation head digest")?
            && cbor_text(response[7], "handoff response candidate")? == candidate_device_id
            && cbor_fixed::<32>(response[8], "handoff recipient digest")?
                == domain_digest(RECIPIENT_KEY_DOMAIN, &candidate_recipient_public_key)
            && cbor_unsigned(response[9], "handoff response H")? == identity_log.at_h.sequence
            && cbor_fixed::<32>(response[10], "handoff response head at H")?
                == identity_log.at_h.head_digest
            && cbor_unsigned(response[11], "handoff response H+1")?
                == identity_log.at_h_plus_1.sequence
            && cbor_fixed::<32>(response[12], "handoff response head at H+1")?
                == identity_log.at_h_plus_1.head_digest
            && cbor_fixed::<32>(response[13], "handoff response DeviceAdd digest")?
                == device_add_digest
            && cbor_fixed::<32>(response[19], "handoff response idempotency digest")?
                == domain_digest(RESPONSE_IDEMPOTENCY_DOMAIN, &input.response_idempotency_key)
            && preparation_issued <= response_issued
            && response_issued < response_expires
            && response_expires <= preparation_expires,
        "provider response public coordinates or validity drifted",
    )?;
    require_handoff(
        decode_lower_hex(json_string(response_json, "unsigned_cbor_hex")?)? == response_unsigned
            && decode_json_fixed::<64>(response_json, "provider_signature_hex")?
                == response_provider_signature
            && decode_json_fixed::<64>(response_json, "authority_signature_hex")?
                == response_authority_signature
            && decode_json_fixed::<32>(response_json, "digest_hex")? == response_digest,
        "provider response JSON assertions drifted",
    )?;

    let aad_json = &input.public_aad;
    require_json_keys(
        aad_json,
        &["cbor_hex", "digest_hex"],
        "Catalog V2 handoff public AAD",
    )?;
    let (public_aad_exact, public_aad_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-provider-public-aad-v2",
        json_string(aad_json, "cbor_hex")?,
        "Catalog V2 handoff public AAD",
    )?;
    let aad = numbered_fields(&public_aad_value, 20, "Catalog V2 handoff public AAD")?;
    let expected_aad = CanonicalValue::Map(
        response[..17]
            .iter()
            .chain(response[19..22].iter())
            .enumerate()
            .map(|(index, value)| {
                (
                    CanonicalValue::Unsigned(
                        u64::try_from(index + 1).expect("bounded AAD field index"),
                    ),
                    (*value).clone(),
                )
            })
            .collect(),
    );
    require_handoff(
        public_aad_value == expected_aad
            && cbor_fixed::<32>(aad[17], "handoff AAD idempotency digest")?
                == cbor_fixed::<32>(response[19], "handoff response idempotency digest")?,
        "raw public AAD is not exactly reconstructed from public response coordinates",
    )?;
    let aad_digest = domain_digest(PROVIDER_AAD_DOMAIN, &public_aad_exact);
    require_handoff(
        cbor_fixed::<32>(response[17], "handoff response AAD digest")? == aad_digest
            && decode_json_fixed::<32>(aad_json, "digest_hex")? == aad_digest,
        "public AAD digest assertion drifted",
    )?;

    let envelope_json = &input.hpke_envelope;
    require_json_keys(
        envelope_json,
        &["cbor_hex", "ciphertext_hex", "digest_hex", "enc_hex"],
        "Catalog V2 handoff HPKE envelope",
    )?;
    let (envelope_exact, envelope_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-hpke-envelope-v2",
        json_string(envelope_json, "cbor_hex")?,
        "Catalog V2 handoff HPKE envelope",
    )?;
    require_handoff(
        envelope_exact.len() <= MAX_HPKE_ENCODED_ENVELOPE_BYTES && envelope_value == *response[25],
        "nested HPKE envelope is not exact or exceeds its bound",
    )?;
    let envelope = numbered_fields(&envelope_value, 3, "Catalog V2 handoff HPKE envelope")?;
    let envelope_enc = cbor_fixed(envelope[1], "handoff HPKE enc")?;
    let envelope_ciphertext = cbor_bytes(envelope[2], "handoff HPKE ciphertext")?.to_vec();
    let envelope_digest = domain_digest(PROVIDER_ENVELOPE_DOMAIN, &envelope_exact);
    require_handoff(
        envelope_ciphertext.len() <= MAX_HPKE_CIPHERTEXT_BYTES
            && envelope_ciphertext.len() >= 17
            && cbor_unsigned(envelope[0], "handoff envelope version")? == 2
            && decode_json_fixed::<32>(envelope_json, "enc_hex")? == envelope_enc
            && decode_lower_hex(json_string(envelope_json, "ciphertext_hex")?)?
                == envelope_ciphertext
            && decode_json_fixed::<32>(envelope_json, "digest_hex")? == envelope_digest
            && cbor_fixed::<32>(response[18], "handoff response envelope digest")?
                == envelope_digest
            && cbor_bytes(response[24], "handoff response DeviceAdd")? == device_add_exact,
        "HPKE envelope or embedded DeviceAdd assertion drifted",
    )?;

    let receipts = &input.mutation_receipts;
    require_json_keys(
        receipts,
        &["preparation", "provider_response"],
        "Catalog V2 handoff receipts",
    )?;
    let preparation_receipt_json =
        json_field(receipts, "preparation", "Catalog V2 handoff receipts")?;
    require_json_keys(
        preparation_receipt_json,
        &["accepted_at", "cbor_hex", "request_digest_hex"],
        "Catalog V2 preparation receipt",
    )?;
    let (preparation_receipt_exact, preparation_receipt_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-preparation-receipt-v2",
        json_string(preparation_receipt_json, "cbor_hex")?,
        "Catalog V2 preparation receipt",
    )?;
    let preparation_receipt = numbered_fields(
        &preparation_receipt_value,
        4,
        "Catalog V2 preparation receipt",
    )?;
    let preparation_accepted =
        cbor_unsigned(preparation_receipt[3], "preparation receipt accepted_at")?;
    require_handoff(
        cbor_unsigned(preparation_receipt[0], "preparation receipt version")? == 2
            && cbor_text(preparation_receipt[1], "preparation receipt request")? == request_id
            && cbor_fixed::<32>(preparation_receipt[2], "preparation receipt digest")?
                == preparation_digest
            && decode_json_fixed::<32>(preparation_receipt_json, "request_digest_hex")?
                == preparation_digest
            && json_u64(preparation_receipt_json, "accepted_at")? == preparation_accepted,
        "immutable preparation receipt drifted",
    )?;
    let provider_receipt_json =
        json_field(receipts, "provider_response", "Catalog V2 handoff receipts")?;
    require_json_keys(
        provider_receipt_json,
        &["accepted_at", "cbor_hex", "response_digest_hex"],
        "Catalog V2 provider receipt",
    )?;
    let (provider_response_receipt_exact, provider_receipt_value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-provider-response-receipt-v2",
        json_string(provider_receipt_json, "cbor_hex")?,
        "Catalog V2 provider receipt",
    )?;
    let provider_receipt =
        numbered_fields(&provider_receipt_value, 4, "Catalog V2 provider receipt")?;
    let provider_accepted = cbor_unsigned(provider_receipt[3], "provider receipt accepted_at")?;
    require_handoff(
        cbor_unsigned(provider_receipt[0], "provider receipt version")? == 2
            && cbor_text(provider_receipt[1], "provider receipt request")? == request_id
            && cbor_fixed::<32>(provider_receipt[2], "provider receipt digest")? == response_digest
            && decode_json_fixed::<32>(provider_receipt_json, "response_digest_hex")?
                == response_digest
            && json_u64(provider_receipt_json, "accepted_at")? == provider_accepted,
        "immutable provider receipt drifted",
    )?;

    let statuses = &input.statuses;
    require_json_keys(
        statuses,
        &["cancelled", "expired", "invalidated", "pending", "ready"],
        "Catalog V2 handoff statuses",
    )?;
    let mut status_exact = Vec::with_capacity(5);
    for (name, rule, code, embedded, reason, changed_at) in [
        (
            "pending",
            "recovery-scope-catalog-status-pending-v2",
            1,
            false,
            None,
            preparation_accepted,
        ),
        (
            "ready",
            "recovery-scope-catalog-status-ready-v2",
            2,
            true,
            None,
            provider_accepted,
        ),
        (
            "expired",
            "recovery-scope-catalog-status-expired-v2",
            3,
            false,
            Some(1),
            response_expires,
        ),
        (
            "cancelled",
            "recovery-scope-catalog-status-cancelled-v2",
            4,
            false,
            Some(2),
            1_701_000_400_000,
        ),
        (
            "invalidated",
            "recovery-scope-catalog-status-invalidated-v2",
            5,
            false,
            Some(3),
            1_701_000_500_000,
        ),
    ] {
        let status_json = json_field(statuses, name, "Catalog V2 handoff statuses")?;
        let keys = if reason.is_some() {
            &["cbor_hex", "reason_code", "state_changed_at"][..]
        } else {
            &["cbor_hex", "state_changed_at"][..]
        };
        require_json_keys(status_json, keys, &format!("Catalog V2 {name} status"))?;
        let (exact, value) = decode_exact_cddl(
            cddl,
            rule,
            json_string(status_json, "cbor_hex")?,
            &format!("Catalog V2 {name} status"),
        )?;
        let fields = numbered_fields(&value, 6, &format!("Catalog V2 {name} status"))?;
        let embedded_matches = if embedded {
            fields[3] == &provider_response_value
        } else {
            fields[3] == &CanonicalValue::Null
        };
        let reason_matches = match reason {
            Some(expected) => {
                cbor_unsigned(fields[4], "handoff status reason")? == expected
                    && json_u64(status_json, "reason_code")? == expected
            }
            None => fields[4] == &CanonicalValue::Null,
        };
        require_handoff(
            cbor_unsigned(fields[0], "handoff status version")? == 2
                && cbor_text(fields[1], "handoff status request")? == request_id
                && cbor_unsigned(fields[2], "handoff status code")? == code
                && embedded_matches
                && reason_matches
                && cbor_unsigned(fields[5], "handoff status changed_at")? == changed_at
                && json_u64(status_json, "state_changed_at")? == changed_at
                && exact.len() <= MAX_STATUS_BODY_BYTES,
            &format!("{name} status drifted"),
        )?;
        status_exact.push(exact);
    }

    Ok(ServerVisibleHandoffFacts {
        request_id,
        candidate_device_id,
        candidate_signing_public_key,
        candidate_recipient_public_key,
        preparation_exact,
        preparation_digest,
        identity_log,
        device_add_exact,
        device_add_digest,
        public_aad_exact,
        envelope_exact,
        envelope_enc,
        envelope_ciphertext,
        provider_response_exact,
        provider_response_digest: response_digest,
        independent_authority_kind: authority_kind,
        independent_authority_key: authority_key,
        preparation_receipt_exact,
        provider_response_receipt_exact,
        status_exact: status_exact
            .try_into()
            .expect("five closed handoff status encodings"),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the trusted verifier fixture closes descriptor authenticity, exact bytes, and currentness in one parser"
)]
fn parse_origin_authenticated_verifier_oracle(
    vector: &Value,
    cddl: &str,
    validation_time: u64,
) -> Result<OriginAuthenticatedVerifierOracle, ProtocolToolError> {
    let oracle = json_field(
        vector,
        "origin_authenticated_completion_verifier_descriptors",
        "Catalog V2 vector",
    )?;
    require_json_keys(
        oracle,
        &["by_origin", "classification"],
        "Catalog V2 verifier oracle",
    )?;
    require_handoff(
        json_string(oracle, "classification")?
            == "trusted-origin-authenticated-completion-verifier-test-oracle-not-portable-wire-proof",
        "verifier oracle classification drifted",
    )?;
    let by_origin_json = json_field(oracle, "by_origin", "Catalog V2 verifier oracle")?
        .as_object()
        .ok_or_else(|| handoff_error("verifier oracle by_origin must be an object"))?;
    require_handoff(
        !by_origin_json.is_empty(),
        "verifier oracle must contain at least one origin-authenticated descriptor",
    )?;
    let mut by_origin = BTreeMap::new();
    for (origin_key, descriptor_json) in by_origin_json {
        require_json_keys(
            descriptor_json,
            &[
                "descriptor_digest_hex",
                "epoch",
                "expires_at",
                "issued_at",
                "key_id",
                "origin",
                "public_key_hex",
                "signature_hex",
                "signed_cbor_hex",
                "unsigned_cbor_hex",
            ],
            "Catalog V2 origin-authenticated verifier descriptor",
        )?;
        let (signed_exact, descriptor_value) = decode_exact_cddl(
            cddl,
            "recovery-scope-catalog-completion-verifier-descriptor-v1",
            json_string(descriptor_json, "signed_cbor_hex")?,
            "Catalog V2 origin-authenticated completion-verifier descriptor",
        )?;
        let fields = numbered_fields(
            &descriptor_value,
            8,
            "Catalog V2 origin-authenticated completion-verifier descriptor",
        )?;
        let origin = cbor_text(fields[1], "completion-verifier descriptor origin")?.to_owned();
        let key_id = cbor_text(fields[2], "completion-verifier descriptor key id")?.to_owned();
        let public_key = cbor_fixed(fields[3], "completion-verifier descriptor public key")?;
        let epoch = cbor_unsigned(fields[4], "completion-verifier descriptor epoch")?;
        let issued_at = cbor_unsigned(fields[5], "completion-verifier descriptor issued_at")?;
        let expires_at = cbor_unsigned(fields[6], "completion-verifier descriptor expires_at")?;
        let unsigned =
            encoded_unsigned_prefix(&descriptor_value, 7, "completion-verifier descriptor")?;
        let signature = cbor_fixed::<64>(fields[7], "completion-verifier descriptor signature")?;
        verify_signature(
            public_key,
            COMPLETION_VERIFIER_DESCRIPTOR_SIGNATURE_DOMAIN,
            &unsigned,
            signature,
            "Catalog V2 completion-verifier descriptor",
        )?;
        let descriptor_digest = domain_digest(COMPLETION_VERIFIER_DESCRIPTOR_DOMAIN, &signed_exact);
        require_handoff(
            cbor_unsigned(fields[0], "completion-verifier descriptor version")? == 1
                && origin_key == &origin
                && valid_https_origin(&origin)
                && valid_uuid_v7(&key_id)
                && epoch > 0
                && issued_at < expires_at
                && validation_time >= issued_at
                && validation_time < expires_at
                && json_string(descriptor_json, "origin")? == origin
                && json_string(descriptor_json, "key_id")? == key_id
                && decode_json_fixed::<32>(descriptor_json, "public_key_hex")? == public_key
                && json_u64(descriptor_json, "epoch")? == epoch
                && json_u64(descriptor_json, "issued_at")? == issued_at
                && json_u64(descriptor_json, "expires_at")? == expires_at
                && decode_lower_hex(json_string(descriptor_json, "unsigned_cbor_hex")?)?
                    == unsigned
                && decode_json_fixed::<64>(descriptor_json, "signature_hex")? == signature
                && decode_json_fixed::<32>(descriptor_json, "descriptor_digest_hex")?
                    == descriptor_digest,
            "origin-authenticated verifier descriptor syntax or currentness drifted",
        )?;
        require_handoff(
            by_origin
                .insert(
                    origin.clone(),
                    OriginAuthenticatedVerifierDescriptor {
                        origin,
                        key_id,
                        public_key,
                        epoch,
                        descriptor_digest,
                        issued_at,
                        expires_at,
                        signed_exact,
                    },
                )
                .is_none(),
            "verifier oracle contains a duplicate canonical origin",
        )?;
    }
    Ok(OriginAuthenticatedVerifierOracle { by_origin })
}

#[allow(
    clippy::too_many_lines,
    reason = "candidate-only decryption, exact package validation, and hidden verifier currentness form one privacy boundary"
)]
fn validate_candidate_handoff(
    vector: &Value,
    cddl: &str,
    server: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    type Kem = X25519HkdfSha256;
    type Aead = ChaCha20Poly1305;
    type Kdf = HkdfSha256;

    let verifier_oracle =
        parse_origin_authenticated_verifier_oracle(vector, cddl, catalog.context.validation_time)?;

    let handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let inputs = json_field(handoff, "test_only_inputs", "Catalog V2 handoff")?;
    let recipient_private = decode_json_fixed::<32>(inputs, "x25519_recipient_private_key_hex")?;
    let recipient_private_key = <Kem as KemTrait>::PrivateKey::from_bytes(&recipient_private)
        .map_err(|error| handoff_error(&format!("candidate private key invalid: {error}")))?;
    let derived_public = Kem::sk_to_pk(&recipient_private_key);
    require_handoff(
        derived_public.to_bytes().as_slice() == server.candidate_recipient_public_key,
        "candidate protected X25519 secret does not derive the enrolled recipient key",
    )?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&server.envelope_enc)
        .map_err(|error| handoff_error(&format!("HPKE enc invalid: {error}")))?;
    let mut receiver = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &recipient_private_key,
        &encapped,
        HPKE_INFO.as_bytes(),
    )
    .map_err(|error| handoff_error(&format!("HPKE receiver setup failed: {error}")))?;
    let package_exact = receiver
        .open(&server.envelope_ciphertext, &server.public_aad_exact)
        .map_err(|error| handoff_error(&format!("HPKE open failed: {error}")))?;
    require_handoff(
        package_exact.len() <= MAX_PROVIDER_PACKAGE_BYTES,
        "decrypted provider package exceeds its bound",
    )?;
    let package_value = decode_exact_bytes(&package_exact, "Catalog V2 decrypted package")?;
    cddl_cat::validate_cbor_bytes(
        "recovery-scope-catalog-provider-package-v2",
        cddl,
        &package_exact,
    )
    .map_err(|error| handoff_error(&format!("CDDL rejected decrypted package: {error}")))?;
    let package = numbered_fields(&package_value, 17, "Catalog V2 decrypted package")?;
    let response_value = decode_exact_bytes(
        &server.provider_response_exact,
        "Catalog V2 candidate provider response",
    )?;
    let response = numbered_fields(
        &response_value,
        26,
        "Catalog V2 candidate provider response",
    )?;
    let signed_head_exact = encode_deterministic_cbor(&catalog.signed_head)
        .map_err(|error| handoff_error(&format!("signed head encode failed: {error}")))?;
    require_handoff(
        cbor_unsigned(package[0], "candidate package version")? == 2
            && cbor_text(package[1], "candidate package request")? == server.request_id
            && cbor_fixed::<32>(package[2], "candidate package preparation digest")?
                == server.preparation_digest
            && cbor_bytes(package[3], "candidate package signed head")? == signed_head_exact
            && cbor_bytes(package[4], "candidate package Catalog plaintext")?
                == catalog.plaintext_exact
            && cbor_text(package[5], "candidate package identity")? == catalog.context.identity_id
            && cbor_text(package[6], "candidate package catalog")? == catalog.context.catalog_id
            && cbor_unsigned(package[7], "candidate package generation")?
                == catalog.context.generation
            && cbor_text(package[8], "candidate package candidate")? == server.candidate_device_id
            && cbor_fixed::<32>(package[9], "candidate package recipient key")?
                == server.candidate_recipient_public_key
            && cbor_unsigned(package[10], "candidate package H")?
                == server.identity_log.at_h.sequence
            && cbor_fixed::<32>(package[11], "candidate package head at H")?
                == server.identity_log.at_h.head_digest
            && cbor_unsigned(package[12], "candidate package H+1")?
                == server.identity_log.at_h_plus_1.sequence
            && cbor_fixed::<32>(package[13], "candidate package head at H+1")?
                == server.identity_log.at_h_plus_1.head_digest
            && cbor_fixed::<32>(package[14], "candidate package DeviceAdd digest")?
                == server.device_add_digest
            && cbor_unsigned(package[15], "candidate package issued_at")?
                == cbor_unsigned(response[20], "candidate response issued_at")?
            && cbor_unsigned(package[16], "candidate package expires_at")?
                == cbor_unsigned(response[21], "candidate response expires_at")?
            && domain_digest(PROVIDER_PACKAGE_DOMAIN, &package_exact)
                == cbor_fixed::<32>(response[16], "candidate response package digest")?,
        "decrypted package/head/plaintext/public-coordinate equality drifted",
    )?;

    let package_json = json_field(handoff, "package", "Catalog V2 handoff")?;
    require_json_keys(
        package_json,
        &["cbor_hex", "digest_hex"],
        "Catalog V2 handoff package",
    )?;
    require_handoff(
        decode_lower_hex(json_string(package_json, "cbor_hex")?)? == package_exact
            && decode_json_fixed::<32>(package_json, "digest_hex")?
                == domain_digest(PROVIDER_PACKAGE_DOMAIN, &package_exact),
        "decrypted package JSON assertions drifted",
    )?;

    let mut visible_keys = BTreeSet::from([
        server.candidate_signing_public_key,
        server.candidate_recipient_public_key,
        catalog.context.authority_public_key,
        server.identity_log.at_h.current_root_public_key,
        server.identity_log.at_h.current_recovery_public_key,
        server.identity_log.at_h_plus_1.current_root_public_key,
        server.identity_log.at_h_plus_1.current_recovery_public_key,
    ]);
    for state in [&server.identity_log.at_h, &server.identity_log.at_h_plus_1] {
        for device in &state.active_devices {
            visible_keys.insert(device.signing_public_key);
            visible_keys.insert(device.encryption_public_key);
        }
    }
    let mut issuer_keys = BTreeSet::new();
    for opening in &catalog.openings {
        let opening_fields = numbered_fields(&opening.value, 3, "candidate Catalog opening")?;
        let binding = numbered_fields(opening_fields[1], 23, "candidate Catalog verifier binding")?;
        let origin = cbor_text(binding[6], "candidate verifier origin")?;
        let descriptor = verifier_oracle.by_origin.get(origin).ok_or_else(|| {
            handoff_error("candidate verifier origin is absent from the trusted oracle")
        })?;
        let issuer_authorization_not_before =
            cbor_unsigned(binding[18], "candidate evidence authorization not_before")?;
        let issuer_authorization_expires_at =
            cbor_unsigned(binding[19], "candidate evidence authorization expires_at")?;
        require_handoff(
            descriptor.origin == origin
                && cbor_text(binding[7], "candidate verifier key id")? == descriptor.key_id
                && cbor_fixed::<32>(binding[8], "candidate verifier public key")?
                    == descriptor.public_key
                && cbor_unsigned(binding[9], "candidate verifier epoch")? == descriptor.epoch
                && cbor_fixed::<32>(binding[10], "candidate verifier descriptor digest")?
                    == descriptor.descriptor_digest
                && issuer_authorization_not_before >= descriptor.issued_at
                && issuer_authorization_expires_at <= descriptor.expires_at
                && !descriptor.signed_exact.is_empty(),
            "candidate-only verifier binding does not match the current signed origin-authenticated descriptor",
        )?;
        require_handoff(
            !visible_keys.contains(&opening.evidence.issuer_epk)
                && issuer_keys.insert(opening.evidence.issuer_epk),
            "candidate-only completion evidence issuer EPK was reused or collides with a visible key",
        )?;
        visible_keys.insert(opening.evidence.issuer_epk);
    }
    Ok(())
}

fn vector_with_handoff(vector: &Value, handoff: &Value) -> Result<Value, ProtocolToolError> {
    let mut variant = vector.clone();
    variant
        .as_object_mut()
        .ok_or_else(|| ProtocolToolError::new("Catalog V2 vector root must be an object"))?
        .insert("handoff".to_owned(), handoff.clone());
    Ok(variant)
}

fn validate_handoff_authority_variants(
    vector: &Value,
    cddl: &str,
    catalog_projection: &CatalogServerProjection,
    base: &ServerVisibleHandoffFacts,
    catalog: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    let variants = json_field(
        vector,
        "handoff_authority_variants",
        "Catalog V2 B2a authority variants",
    )?;
    require_json_keys(
        variants,
        &["current_recovery", "current_root"],
        "Catalog V2 B2a authority variants",
    )?;
    require_handoff(
        base.independent_authority_kind == IndependentAuthorityKind::ActiveDevice,
        "B2a base handoff must use the independent active-device authority",
    )?;

    let mut distinct_responses = BTreeSet::new();
    let mut distinct_envelopes = BTreeSet::new();
    distinct_responses.insert(base.provider_response_exact.clone());
    distinct_envelopes.insert(base.envelope_exact.clone());
    for (name, expected_kind) in [
        ("current_root", IndependentAuthorityKind::CurrentRoot),
        (
            "current_recovery",
            IndependentAuthorityKind::CurrentRecovery,
        ),
    ] {
        let handoff = json_field(variants, name, "Catalog V2 B2a authority variants")?;
        require_json_keys(
            handoff,
            &[
                "device_add",
                "hpke_envelope",
                "mutation_receipts",
                "origin_authenticated_identity_log",
                "package",
                "preparation",
                "provider_response",
                "public_aad",
                "statuses",
                "test_only_inputs",
            ],
            &format!("Catalog V2 B2a {name} handoff"),
        )?;
        let variant_vector = vector_with_handoff(vector, handoff)?;
        let input = parse_server_visible_handoff_input(&variant_vector)?;
        let facts = validate_server_visible_handoff(cddl, catalog_projection, &input)?;
        require_handoff(
            facts.independent_authority_kind == expected_kind
                && facts.preparation_exact == base.preparation_exact
                && facts.device_add_exact == base.device_add_exact
                && facts.public_aad_exact != base.public_aad_exact
                && facts.envelope_exact != base.envelope_exact
                && facts.provider_response_exact != base.provider_response_exact
                && facts.provider_response_receipt_exact != base.provider_response_receipt_exact
                && facts.status_exact[1] != base.status_exact[1]
                && distinct_responses.insert(facts.provider_response_exact.clone())
                && distinct_envelopes.insert(facts.envelope_exact.clone()),
            &format!("B2a {name} is not a full, fresh authority-specific handoff construction"),
        )?;
        let expected_key = match expected_kind {
            IndependentAuthorityKind::CurrentRoot => {
                facts.identity_log.at_h_plus_1.current_root_public_key
            }
            IndependentAuthorityKind::CurrentRecovery => {
                facts.identity_log.at_h_plus_1.current_recovery_public_key
            }
            IndependentAuthorityKind::ActiveDevice => unreachable!("closed B2a variant table"),
        };
        require_handoff(
            facts.independent_authority_key == expected_key,
            &format!("B2a {name} did not use the current identity authority key"),
        )?;
        validate_candidate_handoff(&variant_vector, cddl, &facts, catalog)?;
    }
    Ok(())
}

fn decode_handoff_envelope(
    cddl: &str,
    encoded: &str,
    label: &str,
) -> Result<DecodedHandoffEnvelope, ProtocolToolError> {
    let (exact, value) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-hpke-envelope-v2",
        encoded,
        label,
    )?;
    let fields = numbered_fields(&value, 3, label)?;
    require_handoff(
        exact.len() <= MAX_HPKE_ENCODED_ENVELOPE_BYTES && cbor_unsigned(fields[0], label)? == 2,
        &format!("{label} envelope version or size drifted"),
    )?;
    let enc = cbor_fixed(fields[1], label)?;
    let ciphertext = cbor_bytes(fields[2], label)?.to_vec();
    require_handoff(
        (17..=MAX_HPKE_CIPHERTEXT_BYTES).contains(&ciphertext.len()),
        &format!("{label} ciphertext size drifted"),
    )?;
    Ok(DecodedHandoffEnvelope {
        exact,
        enc,
        ciphertext,
    })
}

fn open_handoff_hpke_fixture(
    cddl: &str,
    encoded_envelope: &str,
    recipient_private: [u8; 32],
    info: &[u8],
    aad: &[u8],
    psk: bool,
    label: &str,
) -> Result<(Vec<u8>, Vec<u8>), ProtocolToolError> {
    type Kem = X25519HkdfSha256;
    type Aead = ChaCha20Poly1305;
    type Kdf = HkdfSha256;

    let envelope = decode_handoff_envelope(cddl, encoded_envelope, label)?;
    let private_key = <Kem as KemTrait>::PrivateKey::from_bytes(&recipient_private)
        .map_err(|error| handoff_error(&format!("{label} private key invalid: {error}")))?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&envelope.enc)
        .map_err(|error| handoff_error(&format!("{label} enc invalid: {error}")))?;
    let mode = if psk {
        OpModeR::Psk(
            PskBundle::new(&PUBLIC_TEST_PSK, PUBLIC_TEST_PSK_ID)
                .map_err(|error| handoff_error(&format!("{label} PSK invalid: {error}")))?,
        )
    } else {
        OpModeR::Base
    };
    let mut receiver = hpke::setup_receiver::<Aead, Kdf, Kem>(&mode, &private_key, &encapped, info)
        .map_err(|error| handoff_error(&format!("{label} receiver setup failed: {error}")))?;
    let plaintext = receiver
        .open(&envelope.ciphertext, aad)
        .map_err(|error| handoff_error(&format!("{label} open failed: {error}")))?;
    Ok((envelope.exact, plaintext))
}

#[allow(
    clippy::too_many_lines,
    reason = "the alternate HPKE portfolio proves each complete transcript before the production rejection"
)]
fn validate_handoff_hpke_alternates(
    vector: &Value,
    cddl: &str,
    base: &ServerVisibleHandoffFacts,
) -> Result<(), ProtocolToolError> {
    let alternates = json_field(
        vector,
        "handoff_alternate_constructions",
        "Catalog V2 B2a alternate constructions",
    )?;
    require_json_keys(
        alternates,
        &[
            "classification",
            "hpke",
            "preparation_signatures",
            "provider_response_signatures",
        ],
        "Catalog V2 B2a alternate constructions",
    )?;
    require_handoff(
        json_string(alternates, "classification")?
            == "public-deterministic-negative-crypto-fixtures-not-credentials",
        "B2a alternate construction classification drifted",
    )?;
    let hpke = json_field(alternates, "hpke", "Catalog V2 B2a alternates")?;
    require_json_keys(
        hpke,
        &[
            "alternate_canonical_cbor_aad",
            "digest_as_aad",
            "domain_prefixed_aad",
            "hex_aad",
            "json_aad",
            "missing_nul_info",
            "psk_mode",
        ],
        "Catalog V2 B2a HPKE alternates",
    )?;

    let handoff = json_field(vector, "handoff", "Catalog V2 vector")?;
    let inputs = json_field(handoff, "test_only_inputs", "Catalog V2 handoff")?;
    let recipient_private = decode_json_fixed(inputs, "x25519_recipient_private_key_hex")?;
    let package_json = json_field(handoff, "package", "Catalog V2 handoff")?;
    let package_exact = decode_lower_hex(json_string(package_json, "cbor_hex")?)?;
    let aad_value = decode_exact_bytes(&base.public_aad_exact, "Catalog V2 B2a base AAD")?;
    let CanonicalValue::Map(aad_entries) = aad_value else {
        return Err(handoff_error("B2a base public AAD must be a map"));
    };
    let alternate_canonical_aad = encode_deterministic_cbor(&CanonicalValue::Array(
        aad_entries.into_iter().map(|(_, value)| value).collect(),
    ))
    .map_err(|error| handoff_error(&format!("B2a alternate AAD encode failed: {error}")))?;
    let mut domain_prefixed_aad = PROVIDER_AAD_DOMAIN.to_vec();
    domain_prefixed_aad.extend_from_slice(&base.public_aad_exact);
    let json_aad = serde_json::to_vec(&json!({
        "public_aad_cbor_hex": encode_lower_hex(&base.public_aad_exact),
    }))
    .map_err(|error| handoff_error(&format!("B2a JSON AAD encode failed: {error}")))?;
    let cases = vec![
        (
            "alternate_canonical_cbor_aad",
            alternate_canonical_aad,
            HPKE_INFO.as_bytes().to_vec(),
            false,
        ),
        (
            "digest_as_aad",
            domain_digest(PROVIDER_AAD_DOMAIN, &base.public_aad_exact).to_vec(),
            HPKE_INFO.as_bytes().to_vec(),
            false,
        ),
        (
            "domain_prefixed_aad",
            domain_prefixed_aad,
            HPKE_INFO.as_bytes().to_vec(),
            false,
        ),
        (
            "hex_aad",
            encode_lower_hex(&base.public_aad_exact).into_bytes(),
            HPKE_INFO.as_bytes().to_vec(),
            false,
        ),
        ("json_aad", json_aad, HPKE_INFO.as_bytes().to_vec(), false),
        (
            "missing_nul_info",
            base.public_aad_exact.clone(),
            HPKE_INFO.as_bytes()[..HPKE_INFO.len() - 1].to_vec(),
            false,
        ),
        (
            "psk_mode",
            base.public_aad_exact.clone(),
            HPKE_INFO.as_bytes().to_vec(),
            true,
        ),
    ];
    let mut distinct_envelopes = BTreeSet::new();
    distinct_envelopes.insert(base.envelope_exact.clone());
    for (name, aad, info, psk) in cases {
        let artifact = json_field(hpke, name, "Catalog V2 B2a HPKE alternates")?;
        if psk {
            require_json_keys(
                artifact,
                &[
                    "envelope_cbor_hex",
                    "public_test_psk_hex",
                    "public_test_psk_id_hex",
                ],
                "Catalog V2 B2a PSK alternate",
            )?;
            require_handoff(
                decode_json_fixed::<32>(artifact, "public_test_psk_hex")? == PUBLIC_TEST_PSK
                    && decode_lower_hex(json_string(artifact, "public_test_psk_id_hex")?)?
                        == PUBLIC_TEST_PSK_ID,
                "B2a public test PSK assertions drifted",
            )?;
        } else {
            require_json_keys(
                artifact,
                &["envelope_cbor_hex"],
                &format!("Catalog V2 B2a {name} alternate"),
            )?;
        }
        let encoded = json_string(artifact, "envelope_cbor_hex")?;

        // First prove the alternate construction under its own complete
        // transcript and mode. Only then exercise the production transcript.
        let (exact, plaintext) = open_handoff_hpke_fixture(
            cddl,
            encoded,
            recipient_private,
            &info,
            &aad,
            psk,
            &format!("B2a {name} alternate"),
        )?;
        require_handoff(
            plaintext == package_exact && distinct_envelopes.insert(exact),
            &format!("B2a {name} is not a unique valid alternate HPKE construction"),
        )?;
        require_handoff(
            open_handoff_hpke_fixture(
                cddl,
                encoded,
                recipient_private,
                HPKE_INFO.as_bytes(),
                &base.public_aad_exact,
                false,
                &format!("B2a {name} production attempt"),
            )
            .is_err(),
            &format!("B2a {name} alternate was accepted by production HPKE inputs"),
        )?;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "alternate preparation and dual-signature constructions are one closed cryptographic rejection portfolio"
)]
fn validate_handoff_signature_alternates(
    vector: &Value,
    cddl: &str,
    base: &ServerVisibleHandoffFacts,
) -> Result<(), ProtocolToolError> {
    let alternates = json_field(
        vector,
        "handoff_alternate_constructions",
        "Catalog V2 B2a alternate constructions",
    )?;
    let preparation_alternates = json_field(
        alternates,
        "preparation_signatures",
        "Catalog V2 B2a signature alternates",
    )?;
    require_json_keys(
        preparation_alternates,
        &[
            "missing_nul_domain",
            "substituted_candidate_key",
            "wrong_domain",
        ],
        "Catalog V2 B2a preparation signature alternates",
    )?;
    let base_preparation =
        decode_exact_bytes(&base.preparation_exact, "Catalog V2 B2a base preparation")?;
    let base_preparation_unsigned =
        encoded_unsigned_prefix(&base_preparation, 16, "Catalog V2 B2a base preparation")?;
    let mut preparation_encodings = BTreeSet::new();
    preparation_encodings.insert(base.preparation_exact.clone());
    for (name, domain, substituted) in [
        (
            "missing_nul_domain",
            &PREPARATION_SIGNATURE_DOMAIN[..PREPARATION_SIGNATURE_DOMAIN.len() - 1],
            false,
        ),
        (
            "wrong_domain",
            PREPARATION_ALTERNATE_SIGNATURE_DOMAIN,
            false,
        ),
        (
            "substituted_candidate_key",
            PREPARATION_SIGNATURE_DOMAIN,
            true,
        ),
    ] {
        let artifact = json_field(
            preparation_alternates,
            name,
            "Catalog V2 B2a preparation signature alternates",
        )?;
        if substituted {
            require_json_keys(
                artifact,
                &["cbor_hex", "substituted_public_key_hex"],
                "Catalog V2 B2a substituted preparation key",
            )?;
        } else {
            require_json_keys(
                artifact,
                &["cbor_hex"],
                &format!("Catalog V2 B2a {name} preparation signature"),
            )?;
        }
        let (exact, value) = decode_exact_cddl(
            cddl,
            "recovery-scope-catalog-preparation-v2",
            json_string(artifact, "cbor_hex")?,
            &format!("Catalog V2 B2a {name} preparation"),
        )?;
        let fields = numbered_fields(&value, 17, "Catalog V2 B2a alternate preparation")?;
        let unsigned = encoded_unsigned_prefix(&value, 16, "Catalog V2 B2a alternate preparation")?;
        require_handoff(
            unsigned == base_preparation_unsigned && preparation_encodings.insert(exact),
            &format!("B2a {name} preparation did not preserve the exact unsigned bytes"),
        )?;
        let signature = cbor_fixed(fields[16], "B2a alternate preparation signature")?;
        let own_key = if substituted {
            let key = decode_json_fixed(artifact, "substituted_public_key_hex")?;
            require_handoff(
                key != base.candidate_signing_public_key,
                "B2a substituted candidate key equals the production key",
            )?;
            key
        } else {
            base.candidate_signing_public_key
        };

        // Prove the alternate key/domain transcript, then reject it with the
        // production candidate key and exact NUL-terminated domain.
        verify_signature(own_key, domain, &unsigned, signature, name)?;
        require_handoff(
            verify_signature(
                base.candidate_signing_public_key,
                PREPARATION_SIGNATURE_DOMAIN,
                &unsigned,
                signature,
                name,
            )
            .is_err(),
            &format!("B2a {name} preparation signature passed production verification"),
        )?;
    }

    let response_alternates = json_field(
        alternates,
        "provider_response_signatures",
        "Catalog V2 B2a signature alternates",
    )?;
    require_json_keys(
        response_alternates,
        &["substituted_keys", "swapped_keys", "wrong_domains"],
        "Catalog V2 B2a provider response signature alternates",
    )?;
    let base_response = decode_exact_bytes(
        &base.provider_response_exact,
        "Catalog V2 B2a base provider response",
    )?;
    let base_response_fields = numbered_fields(&base_response, 26, "B2a base response")?;
    let base_response_unsigned =
        encoded_unsigned_prefix(&base_response, 22, "Catalog V2 B2a base response")?;
    let provider_descriptor = numbered_fields(base_response_fields[14], 3, "B2a provider")?;
    let provider_key = cbor_fixed(provider_descriptor[2], "B2a provider key")?;
    let authority_key = base.independent_authority_key;
    let mut response_encodings = BTreeSet::new();
    response_encodings.insert(base.provider_response_exact.clone());
    for name in ["wrong_domains", "swapped_keys", "substituted_keys"] {
        let artifact = json_field(
            response_alternates,
            name,
            "Catalog V2 B2a provider response signature alternates",
        )?;
        if name == "substituted_keys" {
            require_json_keys(
                artifact,
                &[
                    "cbor_hex",
                    "substituted_authority_public_key_hex",
                    "substituted_provider_public_key_hex",
                ],
                "Catalog V2 B2a substituted response keys",
            )?;
        } else {
            require_json_keys(
                artifact,
                &["cbor_hex"],
                &format!("Catalog V2 B2a {name} response signatures"),
            )?;
        }
        let (exact, value) = decode_exact_cddl(
            cddl,
            "recovery-scope-catalog-provider-response-v2",
            json_string(artifact, "cbor_hex")?,
            &format!("Catalog V2 B2a {name} provider response"),
        )?;
        let fields = numbered_fields(&value, 26, "B2a alternate provider response")?;
        let unsigned = encoded_unsigned_prefix(&value, 22, "B2a alternate provider response")?;
        require_handoff(
            unsigned == base_response_unsigned
                && fields[24] == base_response_fields[24]
                && fields[25] == base_response_fields[25]
                && response_encodings.insert(exact),
            &format!("B2a {name} response changed bytes outside its two signatures"),
        )?;
        let provider_signature = cbor_fixed(fields[22], "B2a alternate provider signature")?;
        let authority_signature = cbor_fixed(fields[23], "B2a alternate authority signature")?;
        let (own_provider_key, own_provider_domain, own_authority_key, own_authority_domain) =
            match name {
                "wrong_domains" => (
                    provider_key,
                    PROVIDER_ALTERNATE_SIGNATURE_DOMAIN,
                    authority_key,
                    PROVIDER_AUTHORITY_ALTERNATE_SIGNATURE_DOMAIN,
                ),
                "swapped_keys" => (
                    authority_key,
                    PROVIDER_SIGNATURE_DOMAIN,
                    provider_key,
                    PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
                ),
                "substituted_keys" => {
                    let substituted_provider =
                        decode_json_fixed(artifact, "substituted_provider_public_key_hex")?;
                    let substituted_authority =
                        decode_json_fixed(artifact, "substituted_authority_public_key_hex")?;
                    require_handoff(
                        substituted_provider != provider_key
                            && substituted_provider != authority_key
                            && substituted_authority != provider_key
                            && substituted_authority != authority_key
                            && substituted_provider != substituted_authority,
                        "B2a substituted response keys are not independent",
                    )?;
                    (
                        substituted_provider,
                        PROVIDER_SIGNATURE_DOMAIN,
                        substituted_authority,
                        PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
                    )
                }
                _ => unreachable!("closed B2a response alternate table"),
            };

        // Prove both alternate signatures first, then require both exact
        // production signer/domain checks to fail.
        verify_signature(
            own_provider_key,
            own_provider_domain,
            &unsigned,
            provider_signature,
            name,
        )?;
        verify_signature(
            own_authority_key,
            own_authority_domain,
            &unsigned,
            authority_signature,
            name,
        )?;
        require_handoff(
            verify_signature(
                provider_key,
                PROVIDER_SIGNATURE_DOMAIN,
                &unsigned,
                provider_signature,
                name,
            )
            .is_err()
                && verify_signature(
                    authority_key,
                    PROVIDER_AUTHORITY_SIGNATURE_DOMAIN,
                    &unsigned,
                    authority_signature,
                    name,
                )
                .is_err(),
            &format!("B2a {name} response signatures passed production verification"),
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_positive_vector(
    vector: &Value,
    cddl: &str,
) -> Result<CatalogPositiveFacts, ProtocolToolError> {
    let catalog = json_field(vector, "catalog", "Catalog V2 vector")?;
    require_json_keys(
        catalog,
        &[
            "authority_device_id",
            "authority_key_id",
            "catalog_id",
            "ciphertext_digest_hex",
            "ciphertext_hex",
            "generation",
            "head_digest_hex",
            "head_expires_at",
            "head_issued_at",
            "head_signature_hex",
            "head_signed_cbor_hex",
            "head_unsigned_cbor_hex",
            "identity_head",
            "identity_id",
            "merkle_root_hex",
            "openings",
            "plaintext_cbor_hex",
            "previous_head_digest_hex",
            "proofs",
            "single_leaf_proof_cbor_hex",
            "single_leaf_root_hex",
            "upload_cbor_hex",
            "validation_time",
            "verifier_descriptor",
        ],
        "Catalog V2 positive catalog",
    )?;
    let (plaintext_exact, plaintext) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-plaintext-v2",
        json_string(catalog, "plaintext_cbor_hex")?,
        "Catalog V2 plaintext",
    )?;
    let plaintext_fields = numbered_fields(&plaintext, 8, "Catalog V2 plaintext")?;
    let (_, signed_head) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-head-v2",
        json_string(catalog, "head_signed_cbor_hex")?,
        "Catalog V2 signed head",
    )?;
    let head_fields = numbered_fields(&signed_head, 16, "Catalog V2 signed head")?;
    if cbor_unsigned(plaintext_fields[0], "plaintext version")? != 2
        || cbor_unsigned(head_fields[0], "head version")? != 2
    {
        return Err(ProtocolToolError::new("Catalog V2 version drift"));
    }
    let context = CatalogVectorContext {
        identity_id: cbor_text(plaintext_fields[1], "plaintext identity")?.to_owned(),
        catalog_id: cbor_text(plaintext_fields[2], "plaintext catalog id")?.to_owned(),
        generation: cbor_unsigned(plaintext_fields[3], "plaintext generation")?,
        previous_head: cbor_fixed(plaintext_fields[4], "plaintext previous head")?,
        identity_sequence: cbor_unsigned(plaintext_fields[5], "plaintext identity H")?,
        identity_head: cbor_fixed(plaintext_fields[6], "plaintext identity head")?,
        authority_device_id: cbor_text(head_fields[10], "head authority device")?.to_owned(),
        authority_key_id: cbor_text(head_fields[11], "head authority key")?.to_owned(),
        authority_public_key: cbor_fixed(head_fields[12], "head authority public key")?,
        head_issued_at: cbor_unsigned(head_fields[13], "head issued_at")?,
        head_expires_at: cbor_unsigned(head_fields[14], "head expires_at")?,
        validation_time: json_u64(catalog, "validation_time")?,
    };
    validate_context_syntax(&context)?;
    if context.head_issued_at >= context.head_expires_at
        || context.validation_time < context.head_issued_at
        || context.validation_time >= context.head_expires_at
    {
        return Err(ProtocolToolError::new("Catalog V2 head validity invalid"));
    }
    if json_string(catalog, "identity_id")? != context.identity_id
        || json_string(catalog, "catalog_id")? != context.catalog_id
        || json_u64(catalog, "generation")? != context.generation
        || decode_json_fixed::<32>(catalog, "previous_head_digest_hex")? != context.previous_head
        || json_string(catalog, "authority_device_id")? != context.authority_device_id
        || json_string(catalog, "authority_key_id")? != context.authority_key_id
        || json_u64(catalog, "head_issued_at")? != context.head_issued_at
        || json_u64(catalog, "head_expires_at")? != context.head_expires_at
        || decode_json_fixed::<32>(vector, "catalog_authority_public_key_hex")?
            != context.authority_public_key
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 JSON coordinate assertion mismatch",
        ));
    }
    let identity_head = json_field(catalog, "identity_head", "Catalog V2 catalog")?;
    require_json_keys(
        identity_head,
        &["digest_hex", "sequence"],
        "Catalog V2 identity head",
    )?;
    if json_u64(identity_head, "sequence")? != context.identity_sequence
        || decode_json_fixed::<32>(identity_head, "digest_hex")? != context.identity_head
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 JSON identity-head assertion mismatch",
        ));
    }
    let opening_values = cbor_array(plaintext_fields[7], "Catalog V2 openings")?;
    let opening_json = json_field(catalog, "openings", "Catalog V2 catalog")?
        .as_array()
        .ok_or_else(|| ProtocolToolError::new("Catalog V2 opening assertions must be an array"))?;
    if opening_values.len() != 3 || opening_json.len() != 3 {
        return Err(ProtocolToolError::new(
            "Catalog V2 positive vector must contain exactly three openings",
        ));
    }
    let first_binding = numbered_fields(
        numbered_fields(&opening_values[0], 3, "first opening")?[1],
        23,
        "first verifier binding",
    )?;
    let verifier = VerifierTuple {
        origin: cbor_text(first_binding[6], "verifier origin")?.to_owned(),
        key_id: cbor_text(first_binding[7], "verifier key id")?.to_owned(),
        public_key: cbor_fixed(first_binding[8], "verifier public key")?,
        epoch: cbor_unsigned(first_binding[9], "verifier epoch")?,
        descriptor_digest: cbor_fixed(first_binding[10], "verifier descriptor digest")?,
    };
    validate_verifier_assertions(vector, catalog, &verifier)?;
    let mut openings = Vec::with_capacity(3);
    let mut previous_scope: Option<Vec<u8>> = None;
    let mut nonces = BTreeSet::new();
    let mut issuer_keys = Vec::with_capacity(opening_values.len());
    let mut issuer_window = None;
    for (position, (value, assertion)) in opening_values.iter().zip(opening_json).enumerate() {
        let index = u64::try_from(position + 1).expect("three openings fit u64");
        let facts = validate_opening_value(value, &context, &verifier, index)?;
        let opening_fields = numbered_fields(value, 3, "Catalog V2 validity opening")?;
        let binding_fields = numbered_fields(opening_fields[1], 23, "Catalog V2 validity binding")?;
        if cbor_unsigned(binding_fields[11], "fixture binding issued_at")? != context.head_issued_at
            || cbor_unsigned(binding_fields[12], "fixture binding expires_at")?
                != context.head_expires_at
        {
            return Err(ProtocolToolError::new(
                "Catalog V2 outer validity equality fixture drift",
            ));
        }
        if previous_scope
            .as_ref()
            .is_some_and(|previous| previous >= &facts.scope_exact)
        {
            return Err(ProtocolToolError::new(
                "Catalog V2 scopes are not strictly canonical-sorted and unique",
            ));
        }
        previous_scope = Some(facts.scope_exact.clone());
        if !nonces.insert(facts.nonce) {
            return Err(ProtocolToolError::new(
                "Catalog V2 hiding nonce reused within catalog",
            ));
        }
        issuer_keys.push(facts.evidence.issuer_epk);
        let window = (
            facts.evidence.issuer_authorization_not_before,
            facts.evidence.issuer_authorization_expires_at,
        );
        if issuer_window
            .replace(window)
            .is_some_and(|first| first != window)
        {
            return Err(ProtocolToolError::new(
                "Catalog V2 catalog-wide issuer authorization window drifted across leaves",
            ));
        }
        validate_opening_json_assertions(assertion, &facts, index)?;
        if value != &facts.value {
            return Err(ProtocolToolError::new("Catalog V2 opening value drift"));
        }
        openings.push(facts);
    }
    validate_global_issuer_epk_uniqueness(issuer_keys)?;
    let merkle_root =
        derive_merkle_root(openings.iter().map(|opening| opening.leaf_digest).collect())?;
    if decode_json_fixed::<32>(catalog, "merkle_root_hex")? != merkle_root {
        return Err(ProtocolToolError::new(
            "Catalog V2 JSON Merkle-root assertion mismatch",
        ));
    }
    let ciphertext = decode_lower_hex(json_string(catalog, "ciphertext_hex")?)?;
    if ciphertext.is_empty() || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(ProtocolToolError::new(
            "Catalog V2 ciphertext bound invalid",
        ));
    }
    let ciphertext_digest = domain_digest(CIPHERTEXT_DOMAIN, &ciphertext);
    if decode_json_fixed::<32>(catalog, "ciphertext_digest_hex")? != ciphertext_digest {
        return Err(ProtocolToolError::new(
            "Catalog V2 JSON ciphertext digest assertion mismatch",
        ));
    }
    validate_head_value(
        &signed_head,
        &context,
        merkle_root,
        ciphertext_digest,
        openings.len(),
    )?;
    let head_unsigned = encoded_unsigned_prefix(&signed_head, 15, "Catalog V2 head")?;
    if decode_lower_hex(json_string(catalog, "head_unsigned_cbor_hex")?)? != head_unsigned
        || decode_json_fixed::<64>(catalog, "head_signature_hex")?
            != cbor_fixed(head_fields[15], "head signature")?
        || decode_json_fixed::<32>(catalog, "head_digest_hex")?
            != domain_digest(
                HEAD_DOMAIN,
                &encode_deterministic_cbor(&signed_head).map_err(|error| {
                    ProtocolToolError::new(format!("encode signed head: {error}"))
                })?,
            )
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 JSON head derived assertion mismatch",
        ));
    }
    validate_upload_assertion(
        cddl,
        catalog,
        &signed_head,
        &ciphertext,
        &plaintext_exact,
        &openings,
    )?;
    validate_positive_proofs(cddl, catalog, &context, &openings, merkle_root)?;
    Ok(CatalogPositiveFacts {
        context,
        verifier,
        openings,
        plaintext_exact,
        merkle_root,
        signed_head,
    })
}

fn validate_context_syntax(context: &CatalogVectorContext) -> Result<(), ProtocolToolError> {
    if !valid_identity_id(&context.identity_id)
        || !valid_uuid_v7(&context.catalog_id)
        || !valid_uuid_v7(&context.authority_device_id)
        || !valid_uuid_v7(&context.authority_key_id)
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 canonical identity or UUIDv7 syntax invalid",
        ));
    }
    Ok(())
}

fn valid_uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index)
                || byte.is_ascii_digit()
                || matches!(*byte, b'a'..=b'f')
        })
}

fn valid_identity_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 57
        && bytes.starts_with(b"dtxi1")
        && bytes[5..]
            .iter()
            .all(|byte| matches!(*byte, b'a'..=b'z' | b'2'..=b'7'))
        && matches!(bytes[56], b'a' | b'q')
}

fn validate_verifier_assertions(
    vector: &Value,
    catalog: &Value,
    verifier: &VerifierTuple,
) -> Result<(), ProtocolToolError> {
    let descriptor = json_field(catalog, "verifier_descriptor", "Catalog V2 catalog")?;
    require_json_keys(
        descriptor,
        &[
            "binding_expires_at",
            "binding_issued_at",
            "digest_hex",
            "epoch",
            "key_id",
            "origin",
        ],
        "Catalog V2 verifier descriptor",
    )?;
    if json_string(descriptor, "origin")? != verifier.origin
        || json_string(descriptor, "key_id")? != verifier.key_id
        || json_u64(descriptor, "epoch")? != verifier.epoch
        || decode_json_fixed::<32>(descriptor, "digest_hex")? != verifier.descriptor_digest
        || decode_json_fixed::<32>(vector, "verifier_public_key_hex")? != verifier.public_key
        || json_u64(descriptor, "binding_issued_at")? != json_u64(catalog, "head_issued_at")?
        || json_u64(descriptor, "binding_expires_at")? != json_u64(catalog, "head_expires_at")?
        || !valid_uuid_v7(&verifier.key_id)
        || !valid_https_origin(&verifier.origin)
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 current verifier descriptor assertion mismatch",
        ));
    }
    Ok(())
}

fn valid_https_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if !(9..=2_048).contains(&value.len())
        || !value.is_ascii()
        || authority.is_empty()
        || authority.contains(['/', '?', '#', '@', '\\', '%', '[', ']'])
        || authority.matches(':').count() > 1
        || value.bytes().any(|byte| !byte.is_ascii_graphic())
    {
        return false;
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    valid_canonical_dns_host(host) && port.is_none_or(valid_canonical_port)
}

// Keep this byte parser aligned with the repository's strict public-origin
// contracts: URL-library normalization must never turn an alternate spelling
// or an IP-looking authority into a different verifier endpoint.
fn valid_canonical_dns_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.ends_with('.')
        && host.bytes().any(|byte| byte.is_ascii_lowercase())
        && !looks_like_whatwg_ipv4_host(host)
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

fn looks_like_whatwg_ipv4_host(host: &str) -> bool {
    host.split('.')
        .next_back()
        .is_some_and(is_whatwg_ipv4_number)
}

fn is_whatwg_ipv4_number(part: &str) -> bool {
    !part.is_empty()
        && (part.bytes().all(|byte| byte.is_ascii_digit())
            || part.strip_prefix("0x").is_some_and(|hex| {
                !hex.is_empty()
                    && hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }))
}

fn valid_canonical_port(port: &str) -> bool {
    !port.is_empty()
        && !port.starts_with('0')
        && port.bytes().all(|byte| byte.is_ascii_digit())
        && port
            .parse::<u16>()
            .is_ok_and(|parsed| parsed != 0 && parsed != 443)
}

fn validate_opening_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    verifier: &VerifierTuple,
    expected_index: u64,
) -> Result<CatalogOpeningFacts, ProtocolToolError> {
    let fields = numbered_fields(value, 3, "Catalog V2 opening")?;
    let private = validate_private_body_value(fields[0], context, expected_index)?;
    let binding =
        validate_binding_value(fields[1], context, verifier, expected_index, private.digest)?;
    let leaf_digest = validate_commitment_value(
        fields[2],
        context,
        expected_index,
        private.digest,
        binding.digest,
        &binding.evidence,
    )?;
    let opening_exact = encode_deterministic_cbor(value)
        .map_err(|error| ProtocolToolError::new(format!("encode complete opening: {error}")))?;
    Ok(CatalogOpeningFacts {
        value: value.clone(),
        opening_digest: domain_digest(OPENING_DOMAIN, &opening_exact),
        private_digest: private.digest,
        binding_digest: binding.digest,
        evidence: binding.evidence,
        leaf_digest,
        scope_exact: private.scope_exact,
        nonce: private.nonce,
    })
}

fn validate_private_body_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    expected_index: u64,
) -> Result<PrivateBodyFacts, ProtocolToolError> {
    let fields = numbered_fields(value, 10, "Catalog V2 private body")?;
    if cbor_unsigned(fields[0], "private-body version")? != 2
        || cbor_text(fields[1], "private-body catalog id")? != context.catalog_id
        || cbor_unsigned(fields[2], "private-body generation")? != context.generation
        || cbor_unsigned(fields[3], "private-body index")? != expected_index
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 private-body coordinate mismatch",
        ));
    }
    let receipt = cbor_bytes(fields[5], "private-body membership receipt")?;
    if receipt.is_empty()
        || cbor_fixed::<32>(fields[6], "private-body receipt digest")?
            != domain_digest(MEMBERSHIP_RECEIPT_DOMAIN, receipt)
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 membership-receipt digest mismatch",
        ));
    }
    let scope_exact = encode_deterministic_cbor(fields[4])
        .map_err(|error| ProtocolToolError::new(format!("encode recovery scope: {error}")))?;
    if cbor_fixed::<32>(fields[8], "private-body recovery-scope digest")?
        != domain_digest(RECOVERY_SCOPE_DOMAIN, &scope_exact)
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 recovery-scope digest mismatch",
        ));
    }
    let nonce = cbor_fixed::<32>(fields[9], "private-body hiding nonce")?;
    if nonce == [0; 32] {
        return Err(ProtocolToolError::new(
            "Catalog V2 hiding nonce must not be all zero",
        ));
    }
    let exact = encode_deterministic_cbor(value)
        .map_err(|error| ProtocolToolError::new(format!("encode private body: {error}")))?;
    Ok(PrivateBodyFacts {
        digest: domain_digest(PRIVATE_BODY_DOMAIN, &exact),
        scope_exact,
        nonce,
    })
}

fn validate_binding_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    verifier: &VerifierTuple,
    expected_index: u64,
    private_digest: [u8; 32],
) -> Result<BindingFacts, ProtocolToolError> {
    let fields = numbered_fields(value, 23, "Catalog V2 verifier binding")?;
    if cbor_unsigned(fields[0], "binding version")? != 1
        || cbor_text(fields[1], "binding identity")? != context.identity_id
        || cbor_text(fields[2], "binding catalog id")? != context.catalog_id
        || cbor_unsigned(fields[3], "binding generation")? != context.generation
        || cbor_unsigned(fields[4], "binding index")? != expected_index
        || cbor_fixed::<32>(fields[5], "binding private digest")? != private_digest
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 verifier binding coordinate/private mismatch",
        ));
    }
    let observed = VerifierTuple {
        origin: cbor_text(fields[6], "binding verifier origin")?.to_owned(),
        key_id: cbor_text(fields[7], "binding verifier key id")?.to_owned(),
        public_key: cbor_fixed(fields[8], "binding verifier public key")?,
        epoch: cbor_unsigned(fields[9], "binding verifier epoch")?,
        descriptor_digest: cbor_fixed(fields[10], "binding descriptor digest")?,
    };
    if observed != *verifier {
        return Err(ProtocolToolError::new(
            "Catalog V2 verifier binding current descriptor tuple mismatch",
        ));
    }
    let issued_at = cbor_unsigned(fields[11], "binding issued_at")?;
    let expires_at = cbor_unsigned(fields[12], "binding expires_at")?;
    if issued_at >= expires_at {
        return Err(ProtocolToolError::new(
            "Catalog V2 verifier binding inner validity invalid",
        ));
    }
    if issued_at < context.head_issued_at || expires_at > context.head_expires_at {
        return Err(ProtocolToolError::new(
            "Catalog V2 verifier binding validity escapes head",
        ));
    }
    if context.validation_time < issued_at || context.validation_time >= expires_at {
        return Err(ProtocolToolError::new(
            "Catalog V2 verifier binding expired at use",
        ));
    }
    if cbor_text(fields[13], "binding authority device")? != context.authority_device_id
        || cbor_text(fields[14], "binding authority key")? != context.authority_key_id
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 binding/head authority mismatch",
        ));
    }
    let (evidence, unsigned) = validate_completion_evidence_issuer_binding(
        value, &fields, context, verifier, issued_at, expires_at,
    )?;
    verify_signature(
        context.authority_public_key,
        VERIFIER_BINDING_SIGNATURE_DOMAIN,
        &unsigned,
        cbor_fixed(fields[22], "binding catalog countersignature")?,
        "Catalog V2 verifier binding",
    )?;
    let exact = encode_deterministic_cbor(value)
        .map_err(|error| ProtocolToolError::new(format!("encode verifier binding: {error}")))?;
    Ok(BindingFacts {
        digest: domain_digest(VERIFIER_BINDING_DOMAIN, &exact),
        evidence,
    })
}

fn validate_completion_evidence_issuer_binding(
    value: &CanonicalValue,
    fields: &[&CanonicalValue],
    context: &CatalogVectorContext,
    verifier: &VerifierTuple,
    issued_at: u64,
    expires_at: u64,
) -> Result<(CompletionEvidenceFacts, Vec<u8>), ProtocolToolError> {
    let algorithm = cbor_unsigned(fields[15], "completion evidence algorithm")?;
    let purpose = cbor_unsigned(fields[16], "completion evidence purpose")?;
    if algorithm != 1 || purpose != 1 {
        return Err(ProtocolToolError::new(
            "Catalog V2 completion evidence algorithm or purpose is not the closed value",
        ));
    }
    let issuer_epk = cbor_fixed::<32>(fields[17], "completion evidence issuer EPK")?;
    if issuer_epk == verifier.public_key || issuer_epk == context.authority_public_key {
        return Err(ProtocolToolError::new(
            "Catalog V2 completion evidence issuer EPK violates key separation",
        ));
    }
    let issuer_authorization_not_before = cbor_unsigned(
        fields[18],
        "completion evidence issuer authorization not_before",
    )?;
    let issuer_authorization_expires_at = cbor_unsigned(
        fields[19],
        "completion evidence issuer authorization expires_at",
    )?;
    if issuer_authorization_not_before >= issuer_authorization_expires_at {
        return Err(ProtocolToolError::new(
            "Catalog V2 completion evidence issuer authorization validity is empty",
        ));
    }
    if issuer_authorization_not_before < issued_at
        || issuer_authorization_expires_at > expires_at
        || issuer_authorization_not_before < context.head_issued_at
        || issuer_authorization_expires_at > context.head_expires_at
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 completion evidence issuer authorization validity escapes binding or catalog",
        ));
    }
    verify_signature(
        issuer_epk,
        COMPLETION_EVIDENCE_POP_DOMAIN,
        &encoded_unsigned_prefix(value, 20, "Catalog V2 completion evidence PoP")?,
        cbor_fixed(fields[20], "completion evidence PoP signature")?,
        "Catalog V2 completion evidence PoP",
    )?;
    verify_signature(
        verifier.public_key,
        COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN,
        &encoded_unsigned_prefix(value, 21, "Catalog V2 completion evidence authorization")?,
        cbor_fixed(
            fields[21],
            "completion evidence origin authorization signature",
        )?,
        "Catalog V2 completion evidence origin authorization",
    )?;
    let unsigned = encoded_unsigned_prefix(value, 22, "Catalog V2 verifier binding")?;
    Ok((
        CompletionEvidenceFacts {
            algorithm,
            purpose,
            issuer_epk,
            issuer_authorization_not_before,
            issuer_authorization_expires_at,
            issuer_authorization_digest: domain_digest(
                COMPLETION_EVIDENCE_AUTHORIZATION_DIGEST_DOMAIN,
                &unsigned,
            ),
        },
        unsigned,
    ))
}

fn validate_commitment_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    expected_index: u64,
    private_digest: [u8; 32],
    binding_digest: [u8; 32],
    evidence: &CompletionEvidenceFacts,
) -> Result<[u8; 32], ProtocolToolError> {
    let fields = numbered_fields(value, 12, "Catalog V2 leaf commitment")?;
    if cbor_unsigned(fields[0], "commitment version")? != 2
        || cbor_text(fields[1], "commitment catalog id")? != context.catalog_id
        || cbor_unsigned(fields[2], "commitment generation")? != context.generation
        || cbor_unsigned(fields[3], "commitment index")? != expected_index
        || cbor_fixed::<32>(fields[4], "commitment private digest")? != private_digest
        || cbor_fixed::<32>(fields[5], "commitment binding digest")? != binding_digest
        || cbor_unsigned(fields[6], "commitment evidence algorithm")? != evidence.algorithm
        || cbor_unsigned(fields[7], "commitment evidence purpose")? != evidence.purpose
        || cbor_fixed::<32>(fields[8], "commitment evidence issuer EPK")? != evidence.issuer_epk
        || cbor_unsigned(fields[9], "commitment authorization not_before")?
            != evidence.issuer_authorization_not_before
        || cbor_unsigned(fields[10], "commitment authorization expires_at")?
            != evidence.issuer_authorization_expires_at
        || cbor_fixed::<32>(fields[11], "commitment authorization digest")?
            != evidence.issuer_authorization_digest
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 leaf commitment binding mismatch",
        ));
    }
    let exact = encode_deterministic_cbor(value)
        .map_err(|error| ProtocolToolError::new(format!("encode leaf commitment: {error}")))?;
    Ok(domain_digest(LEAF_COMMITMENT_DOMAIN, &exact))
}

#[allow(clippy::too_many_lines)]
fn validate_opening_json_assertions(
    assertion: &Value,
    facts: &CatalogOpeningFacts,
    expected_index: u64,
) -> Result<(), ProtocolToolError> {
    require_json_keys(
        assertion,
        &[
            "issuer_authorization_expires_at_ms",
            "issuer_authorization_not_before_ms",
            "catalog_countersignature_hex",
            "completion_evidence_algorithm",
            "completion_evidence_issuer_authorization_digest_hex",
            "completion_evidence_issuer_epk_hex",
            "completion_evidence_issuer_origin_authorization_signature_hex",
            "completion_evidence_issuer_origin_authorization_unsigned_cbor_hex",
            "completion_evidence_issuer_pop_signature_hex",
            "completion_evidence_issuer_pop_unsigned_cbor_hex",
            "completion_evidence_purpose",
            "hiding_nonce_hex",
            "index",
            "leaf_commitment_cbor_hex",
            "leaf_digest_hex",
            "membership_receipt_digest_hex",
            "membership_receipt_hex",
            "opening_cbor_hex",
            "opening_digest_hex",
            "private_body_cbor_hex",
            "private_body_digest_hex",
            "recovery_scope_cbor_hex",
            "recovery_scope_digest_hex",
            "verifier_binding_digest_hex",
            "verifier_binding_signed_cbor_hex",
            "verifier_binding_unsigned_cbor_hex",
        ],
        "Catalog V2 opening assertion",
    )?;
    let fields = numbered_fields(&facts.value, 3, "Catalog V2 opening assertion source")?;
    let private_fields = numbered_fields(fields[0], 10, "Catalog V2 private assertion source")?;
    let binding_fields = numbered_fields(fields[1], 23, "Catalog V2 binding assertion source")?;
    let opening_exact = encode_deterministic_cbor(&facts.value)
        .map_err(|error| ProtocolToolError::new(format!("encode opening assertion: {error}")))?;
    let private_exact = encode_deterministic_cbor(fields[0])
        .map_err(|error| ProtocolToolError::new(format!("encode private assertion: {error}")))?;
    let binding_exact = encode_deterministic_cbor(fields[1])
        .map_err(|error| ProtocolToolError::new(format!("encode binding assertion: {error}")))?;
    let commitment_exact = encode_deterministic_cbor(fields[2])
        .map_err(|error| ProtocolToolError::new(format!("encode commitment assertion: {error}")))?;
    let scope_exact = encode_deterministic_cbor(private_fields[4])
        .map_err(|error| ProtocolToolError::new(format!("encode scope assertion: {error}")))?;
    if json_u64(assertion, "index")? != expected_index
        || decode_lower_hex(json_string(assertion, "hiding_nonce_hex")?)? != facts.nonce
        || decode_lower_hex(json_string(assertion, "membership_receipt_hex")?)?
            != cbor_bytes(private_fields[5], "asserted membership receipt")?
        || decode_json_fixed::<32>(assertion, "membership_receipt_digest_hex")?
            != cbor_fixed(private_fields[6], "asserted receipt digest")?
        || decode_lower_hex(json_string(assertion, "recovery_scope_cbor_hex")?)? != scope_exact
        || decode_json_fixed::<32>(assertion, "recovery_scope_digest_hex")?
            != cbor_fixed(private_fields[8], "asserted scope digest")?
        || decode_lower_hex(json_string(assertion, "private_body_cbor_hex")?)? != private_exact
        || decode_json_fixed::<32>(assertion, "private_body_digest_hex")? != facts.private_digest
        || decode_lower_hex(json_string(
            assertion,
            "verifier_binding_unsigned_cbor_hex",
        )?)? != encoded_unsigned_prefix(fields[1], 22, "binding assertion")?
        || decode_json_fixed::<64>(assertion, "catalog_countersignature_hex")?
            != cbor_fixed(binding_fields[22], "asserted catalog countersignature")?
        || json_u64(assertion, "completion_evidence_algorithm")? != facts.evidence.algorithm
        || json_u64(assertion, "completion_evidence_purpose")? != facts.evidence.purpose
        || decode_json_fixed::<32>(assertion, "completion_evidence_issuer_epk_hex")?
            != facts.evidence.issuer_epk
        || json_u64(assertion, "issuer_authorization_not_before_ms")?
            != facts.evidence.issuer_authorization_not_before
        || json_u64(assertion, "issuer_authorization_expires_at_ms")?
            != facts.evidence.issuer_authorization_expires_at
        || decode_lower_hex(json_string(
            assertion,
            "completion_evidence_issuer_pop_unsigned_cbor_hex",
        )?)? != encoded_unsigned_prefix(fields[1], 20, "completion evidence PoP assertion")?
        || decode_json_fixed::<64>(assertion, "completion_evidence_issuer_pop_signature_hex")?
            != cbor_fixed(binding_fields[20], "asserted completion evidence PoP")?
        || decode_lower_hex(json_string(
            assertion,
            "completion_evidence_issuer_origin_authorization_unsigned_cbor_hex",
        )?)? != encoded_unsigned_prefix(
            fields[1],
            21,
            "completion evidence authorization assertion",
        )?
        || decode_json_fixed::<64>(
            assertion,
            "completion_evidence_issuer_origin_authorization_signature_hex",
        )? != cbor_fixed(binding_fields[21], "asserted origin authorization")?
        || decode_json_fixed::<32>(
            assertion,
            "completion_evidence_issuer_authorization_digest_hex",
        )? != facts.evidence.issuer_authorization_digest
        || decode_lower_hex(json_string(assertion, "verifier_binding_signed_cbor_hex")?)?
            != binding_exact
        || decode_json_fixed::<32>(assertion, "verifier_binding_digest_hex")?
            != facts.binding_digest
        || decode_lower_hex(json_string(assertion, "leaf_commitment_cbor_hex")?)?
            != commitment_exact
        || decode_json_fixed::<32>(assertion, "leaf_digest_hex")? != facts.leaf_digest
        || decode_lower_hex(json_string(assertion, "opening_cbor_hex")?)? != opening_exact
        || decode_json_fixed::<32>(assertion, "opening_digest_hex")? != facts.opening_digest
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 opening JSON derived assertion mismatch",
        ));
    }
    Ok(())
}

fn derive_merkle_root(mut level: Vec<[u8; 32]>) -> Result<[u8; 32], ProtocolToolError> {
    if level.is_empty() {
        return Err(ProtocolToolError::new("Catalog V2 Merkle tree is empty"));
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).copied().unwrap_or(pair[0]);
            next.push(merkle_node(pair[0], right));
        }
        level = next;
    }
    Ok(level[0])
}

fn merkle_node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut children = [0_u8; 64];
    children[..32].copy_from_slice(&left);
    children[32..].copy_from_slice(&right);
    domain_digest(MERKLE_NODE_DOMAIN, &children)
}

fn validate_head_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    merkle_root: [u8; 32],
    ciphertext_digest: [u8; 32],
    leaf_count: usize,
) -> Result<(), ProtocolToolError> {
    if !(1..=MAX_CATALOG_LEAVES).contains(&leaf_count) {
        return Err(ProtocolToolError::new(
            "Catalog V2 signed head leaf count exceeds owner bound",
        ));
    }
    let fields = numbered_fields(value, 16, "Catalog V2 signed head")?;
    if cbor_unsigned(fields[0], "head version")? != 2
        || cbor_text(fields[1], "head catalog id")? != context.catalog_id
        || cbor_text(fields[2], "head identity")? != context.identity_id
        || cbor_unsigned(fields[3], "head generation")? != context.generation
        || cbor_fixed::<32>(fields[4], "head previous head")? != context.previous_head
        || cbor_unsigned(fields[5], "head leaf count")?
            != u64::try_from(leaf_count).expect("leaf count fits u64")
        || cbor_fixed::<32>(fields[6], "head Merkle root")? != merkle_root
        || cbor_fixed::<32>(fields[7], "head ciphertext digest")? != ciphertext_digest
        || cbor_unsigned(fields[8], "head identity H")? != context.identity_sequence
        || cbor_fixed::<32>(fields[9], "head identity digest")? != context.identity_head
        || cbor_text(fields[10], "head authority device")? != context.authority_device_id
        || cbor_text(fields[11], "head authority key")? != context.authority_key_id
        || cbor_fixed::<32>(fields[12], "head authority public key")?
            != context.authority_public_key
        || cbor_unsigned(fields[13], "head issued_at")? != context.head_issued_at
        || cbor_unsigned(fields[14], "head expires_at")? != context.head_expires_at
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 signed head relational binding mismatch",
        ));
    }
    verify_signature(
        context.authority_public_key,
        HEAD_SIGNATURE_DOMAIN,
        &encoded_unsigned_prefix(value, 15, "Catalog V2 head")?,
        cbor_fixed(fields[15], "head signature")?,
        "Catalog V2 head",
    )
}

fn validate_upload_assertion(
    cddl: &str,
    catalog: &Value,
    signed_head: &CanonicalValue,
    ciphertext: &[u8],
    plaintext_exact: &[u8],
    openings: &[CatalogOpeningFacts],
) -> Result<(), ProtocolToolError> {
    let (_, upload) = decode_exact_upload_cddl(
        cddl,
        json_string(catalog, "upload_cbor_hex")?,
        "Catalog V2 upload",
    )?;
    let fields = numbered_fields(&upload, 2, "Catalog V2 upload")?;
    if fields[0] != signed_head || cbor_bytes(fields[1], "upload ciphertext")? != ciphertext {
        return Err(ProtocolToolError::new(
            "Catalog V2 upload head/ciphertext binding mismatch",
        ));
    }
    if ciphertext == plaintext_exact
        || openings.iter().any(|opening| {
            encode_deterministic_cbor(
                numbered_fields(&opening.value, 3, "privacy opening")
                    .expect("validated opening has three fields")[0],
            )
            .is_ok_and(|private| private == ciphertext)
        })
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 upload exposed plaintext or private body",
        ));
    }
    Ok(())
}

fn validate_positive_proofs(
    cddl: &str,
    catalog: &Value,
    context: &CatalogVectorContext,
    openings: &[CatalogOpeningFacts],
    root: [u8; 32],
) -> Result<(), ProtocolToolError> {
    let assertions = json_field(catalog, "proofs", "Catalog V2 catalog")?
        .as_array()
        .ok_or_else(|| ProtocolToolError::new("Catalog V2 proofs must be an array"))?;
    if assertions.len() != openings.len() {
        return Err(ProtocolToolError::new("Catalog V2 proof count drift"));
    }
    for (position, (assertion, opening)) in assertions.iter().zip(openings).enumerate() {
        require_json_keys(
            assertion,
            &["index", "proof_cbor_hex"],
            "Catalog V2 proof assertion",
        )?;
        let index = u64::try_from(position + 1).expect("three proofs fit u64");
        if json_u64(assertion, "index")? != index {
            return Err(ProtocolToolError::new("Catalog V2 proof JSON index drift"));
        }
        let (_, proof) = decode_exact_cddl(
            cddl,
            "catalog-merkle-proof-v2",
            json_string(assertion, "proof_cbor_hex")?,
            "Catalog V2 Merkle proof",
        )?;
        validate_proof_value(
            &proof,
            context,
            u64::try_from(openings.len()).expect("opening count fits u64"),
            index,
            opening.leaf_digest,
            root,
        )?;
        let sibling_count = cbor_array(
            numbered_fields(&proof, 6, "Catalog V2 proof")?[5],
            "Catalog V2 proof siblings",
        )?
        .len();
        let expected = if index == 3 { 1 } else { 2 };
        if sibling_count != expected {
            return Err(ProtocolToolError::new(
                "Catalog V2 three-leaf proof sibling count drift",
            ));
        }
    }
    let (_, single) = decode_exact_cddl(
        cddl,
        "catalog-merkle-proof-v2",
        json_string(catalog, "single_leaf_proof_cbor_hex")?,
        "Catalog V2 single-leaf proof",
    )?;
    let single_root = decode_json_fixed::<32>(catalog, "single_leaf_root_hex")?;
    if single_root != openings[0].leaf_digest {
        return Err(ProtocolToolError::new(
            "Catalog V2 single-leaf root assertion mismatch",
        ));
    }
    validate_proof_value(&single, context, 1, 1, openings[0].leaf_digest, single_root)
}

fn validate_proof_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    expected_count: u64,
    expected_index: u64,
    leaf: [u8; 32],
    root: [u8; 32],
) -> Result<(), ProtocolToolError> {
    let fields = numbered_fields(value, 6, "Catalog V2 Merkle proof")?;
    let mut count = cbor_unsigned(fields[3], "proof count")?;
    let mut index = cbor_unsigned(fields[4], "proof index")?;
    if cbor_unsigned(fields[0], "proof version")? != 2
        || cbor_text(fields[1], "proof catalog id")? != context.catalog_id
        || cbor_unsigned(fields[2], "proof generation")? != context.generation
        || count != expected_count
        || index != expected_index
        || count == 0
        || count > u64::try_from(MAX_CATALOG_LEAVES).expect("catalog count fits u64")
        || index == 0
        || index > count
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 Merkle proof coordinate mismatch",
        ));
    }
    let siblings = cbor_array(fields[5], "proof siblings")?;
    if siblings.len() > MAX_PROOF_SIBLINGS {
        return Err(ProtocolToolError::new(
            "Catalog V2 Merkle proof exceeds sibling cap",
        ));
    }
    let mut sibling_index = 0_usize;
    let mut current = leaf;
    while count > 1 {
        if count % 2 == 1 && index == count {
            current = merkle_node(current, current);
        } else {
            let sibling = siblings.get(sibling_index).ok_or_else(|| {
                ProtocolToolError::new("Catalog V2 Merkle proof is missing a sibling")
            })?;
            sibling_index += 1;
            let sibling = cbor_fixed(sibling, "proof sibling")?;
            current = if index % 2 == 1 {
                merkle_node(current, sibling)
            } else {
                merkle_node(sibling, current)
            };
        }
        count = count.div_ceil(2);
        index = index.div_ceil(2);
    }
    if sibling_index != siblings.len() {
        return Err(ProtocolToolError::new(
            "Catalog V2 Merkle proof has surplus or implicit-duplicate sibling",
        ));
    }
    if current != root {
        return Err(ProtocolToolError::new(
            "Catalog V2 Merkle proof reconstructed wrong root or sibling side",
        ));
    }
    Ok(())
}

fn validate_plaintext_value(
    value: &CanonicalValue,
    context: &CatalogVectorContext,
    verifier: &VerifierTuple,
) -> Result<Vec<CatalogOpeningFacts>, ProtocolToolError> {
    let fields = numbered_fields(value, 8, "Catalog V2 plaintext")?;
    if cbor_unsigned(fields[0], "plaintext version")? != 2
        || cbor_text(fields[1], "plaintext identity")? != context.identity_id
        || cbor_text(fields[2], "plaintext catalog id")? != context.catalog_id
        || cbor_unsigned(fields[3], "plaintext generation")? != context.generation
        || cbor_fixed::<32>(fields[4], "plaintext previous head")? != context.previous_head
        || cbor_unsigned(fields[5], "plaintext identity H")? != context.identity_sequence
        || cbor_fixed::<32>(fields[6], "plaintext identity head")? != context.identity_head
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 plaintext coordinate/head mismatch",
        ));
    }
    let values = cbor_array(fields[7], "Catalog V2 plaintext openings")?;
    if values.is_empty() || values.len() > MAX_CATALOG_LEAVES {
        return Err(ProtocolToolError::new("Catalog V2 plaintext count invalid"));
    }
    let mut facts = Vec::with_capacity(values.len());
    let mut previous_scope: Option<Vec<u8>> = None;
    let mut nonces = BTreeSet::new();
    let mut issuer_keys = Vec::with_capacity(values.len());
    let mut issuer_window = None;
    for (position, value) in values.iter().enumerate() {
        let index = u64::try_from(position + 1).expect("catalog count fits u64");
        let opening = validate_opening_value(value, context, verifier, index)?;
        if previous_scope
            .as_ref()
            .is_some_and(|previous| previous >= &opening.scope_exact)
        {
            return Err(ProtocolToolError::new(
                "Catalog V2 scopes are not strictly canonical-sorted and unique",
            ));
        }
        previous_scope = Some(opening.scope_exact.clone());
        if !nonces.insert(opening.nonce) {
            return Err(ProtocolToolError::new(
                "Catalog V2 hiding nonce reused within catalog",
            ));
        }
        issuer_keys.push(opening.evidence.issuer_epk);
        let window = (
            opening.evidence.issuer_authorization_not_before,
            opening.evidence.issuer_authorization_expires_at,
        );
        if issuer_window
            .replace(window)
            .is_some_and(|first| first != window)
        {
            return Err(ProtocolToolError::new(
                "Catalog V2 catalog-wide issuer authorization window drifted across leaves",
            ));
        }
        facts.push(opening);
    }
    validate_global_issuer_epk_uniqueness(issuer_keys)?;
    Ok(facts)
}

fn validate_global_issuer_epk_uniqueness(
    issuer_keys: impl IntoIterator<Item = [u8; 32]>,
) -> Result<(), ProtocolToolError> {
    let mut seen = BTreeSet::new();
    for issuer_epk in issuer_keys {
        if !seen.insert(issuer_epk) {
            return Err(ProtocolToolError::new(
                "Catalog V2 completion evidence issuer EPK reused across retained Catalog V2 bindings or generations",
            ));
        }
    }
    Ok(())
}

fn validate_upload_value(
    value: &CanonicalValue,
    facts: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    let fields = numbered_fields(value, 2, "Catalog V2 upload")?;
    if fields[0] != &facts.signed_head {
        return Err(ProtocolToolError::new(
            "Catalog V2 upload path/head catalog or signed-head mismatch",
        ));
    }
    let ciphertext = cbor_bytes(fields[1], "Catalog V2 upload ciphertext")?;
    if ciphertext == facts.plaintext_exact
        || facts.openings.iter().any(|opening| {
            encode_deterministic_cbor(
                numbered_fields(&opening.value, 3, "privacy opening")
                    .expect("validated opening has three fields")[0],
            )
            .is_ok_and(|private| private == ciphertext)
        })
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 upload exposed plaintext or private body",
        ));
    }
    let head_fields = numbered_fields(&facts.signed_head, 16, "positive signed head")?;
    if domain_digest(CIPHERTEXT_DOMAIN, ciphertext)
        != cbor_fixed(head_fields[7], "positive ciphertext digest")?
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 upload ciphertext digest mismatch",
        ));
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the completion-evidence adversarial portfolio freezes one cryptographic and privacy boundary"
)]
fn validate_completion_evidence_negative_vector_family(
    vector: &Value,
    cddl: &str,
    facts: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    let negative = json_field(vector, "negative_completion_evidence", "Catalog V2 vector")?;
    require_json_keys(
        negative,
        &[
            "catalog_countersignature_omitted_binding",
            "catalog_countersignature_substituted_binding",
            "full_binding_digest_cross_binding_leaf",
            "issuer_authorization_after_catalog_binding",
            "issuer_authorization_before_catalog_binding",
            "issuer_authorization_digest_cross_binding_leaf",
            "issuer_authorization_empty_binding",
            "issuer_authorization_window_cross_binding_leaf",
            "issuer_authorization_window_per_leaf_drift_plaintext",
            "issuer_epk_catalog_authority_collision_binding",
            "issuer_epk_cross_binding_leaf",
            "issuer_epk_reused_across_catalogs",
            "issuer_epk_substitution_breaks_origin_authorization_binding",
            "issuer_origin_authorization_missing_nul_domain_binding",
            "issuer_origin_authorization_wrong_descriptor_key_binding",
            "issuer_origin_authorization_wrong_signature_binding",
            "issuer_pop_missing_nul_domain_binding",
            "issuer_pop_substituted_epk_binding",
            "issuer_pop_wrong_signature_binding",
            "projection_attempt_upload",
            "reused_issuer_epk_plaintext",
            "wrong_algorithm_binding",
            "wrong_purpose_binding",
        ],
        "Catalog V2 completion-evidence negative family",
    )?;

    for (field, rule) in [
        (
            "wrong_algorithm_binding",
            "recovery-scope-catalog-completion-verifier-binding-v1",
        ),
        (
            "wrong_purpose_binding",
            "recovery-scope-catalog-completion-verifier-binding-v1",
        ),
        (
            "catalog_countersignature_omitted_binding",
            "recovery-scope-catalog-completion-verifier-binding-v1",
        ),
        (
            "projection_attempt_upload",
            "recovery-scope-catalog-upload-v2",
        ),
    ] {
        let bytes = decode_lower_hex(json_string(negative, field)?)?;
        decode_exact_bytes(&bytes, field)?;
        if cddl_cat::validate_cbor_bytes(rule, cddl, &bytes).is_ok() {
            return Err(ProtocolToolError::new(format!(
                "Catalog V2 completion-evidence structural negative {field} passed CDDL"
            )));
        }
    }

    for (field, expected) in [
        (
            "issuer_authorization_empty_binding",
            "issuer authorization validity is empty",
        ),
        (
            "issuer_authorization_before_catalog_binding",
            "issuer authorization validity escapes binding or catalog",
        ),
        (
            "issuer_authorization_after_catalog_binding",
            "issuer authorization validity escapes binding or catalog",
        ),
        ("issuer_pop_wrong_signature_binding", "signature invalid"),
        ("issuer_pop_missing_nul_domain_binding", "signature invalid"),
        ("issuer_pop_substituted_epk_binding", "signature invalid"),
        (
            "issuer_epk_substitution_breaks_origin_authorization_binding",
            "signature invalid",
        ),
        (
            "issuer_epk_catalog_authority_collision_binding",
            "issuer EPK violates key separation",
        ),
        (
            "issuer_origin_authorization_wrong_signature_binding",
            "signature invalid",
        ),
        (
            "issuer_origin_authorization_missing_nul_domain_binding",
            "signature invalid",
        ),
        (
            "issuer_origin_authorization_wrong_descriptor_key_binding",
            "signature invalid",
        ),
        (
            "catalog_countersignature_substituted_binding",
            "signature invalid",
        ),
    ] {
        let (_, value) = decode_negative_cddl(
            negative,
            cddl,
            field,
            "recovery-scope-catalog-completion-verifier-binding-v1",
        )?;
        expect_negative_error(
            validate_binding_value(
                &value,
                &facts.context,
                &facts.verifier,
                1,
                facts.openings[0].private_digest,
            )
            .map(|_| ()),
            field,
            expected,
        )?;
    }

    for field in [
        "issuer_authorization_digest_cross_binding_leaf",
        "full_binding_digest_cross_binding_leaf",
        "issuer_epk_cross_binding_leaf",
        "issuer_authorization_window_cross_binding_leaf",
    ] {
        let (_, value) = decode_negative_cddl(
            negative,
            cddl,
            field,
            "recovery-scope-catalog-leaf-commitment-v2",
        )?;
        expect_negative_error(
            validate_commitment_value(
                &value,
                &facts.context,
                1,
                facts.openings[0].private_digest,
                facts.openings[0].binding_digest,
                &facts.openings[0].evidence,
            )
            .map(|_| ()),
            field,
            "commitment binding mismatch",
        )?;
    }

    let (_, reused) = decode_negative_cddl(
        negative,
        cddl,
        "reused_issuer_epk_plaintext",
        "recovery-scope-catalog-plaintext-v2",
    )?;
    expect_negative_error(
        validate_plaintext_value(&reused, &facts.context, &facts.verifier).map(|_| ()),
        "reused_issuer_epk_plaintext",
        "issuer EPK reused across retained Catalog V2 bindings or generations",
    )?;

    let (_, drifted_window) = decode_negative_cddl(
        negative,
        cddl,
        "issuer_authorization_window_per_leaf_drift_plaintext",
        "recovery-scope-catalog-plaintext-v2",
    )?;
    expect_negative_error(
        validate_plaintext_value(&drifted_window, &facts.context, &facts.verifier).map(|_| ()),
        "issuer_authorization_window_per_leaf_drift_plaintext",
        "catalog-wide issuer authorization window drifted across leaves",
    )?;

    let cross_catalog = json_field(
        negative,
        "issuer_epk_reused_across_catalogs",
        "Catalog V2 completion-evidence negative family",
    )?;
    require_json_keys(
        cross_catalog,
        &["catalog_id", "generation", "opening_cbor_hex"],
        "Catalog V2 cross-catalog issuer-EPK reuse fixture",
    )?;
    let cross_catalog_id = json_string(cross_catalog, "catalog_id")?;
    let cross_generation = json_u64(cross_catalog, "generation")?;
    if cross_catalog_id == facts.context.catalog_id || cross_generation == facts.context.generation
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 cross-catalog issuer-EPK reuse fixture did not change both catalog coordinates",
        ));
    }
    let (_, cross_opening) = decode_exact_cddl(
        cddl,
        "recovery-scope-catalog-opening-v2",
        json_string(cross_catalog, "opening_cbor_hex")?,
        "Catalog V2 cross-catalog issuer-EPK reuse opening",
    )?;
    let mut cross_context = facts.context.clone();
    cross_catalog_id.clone_into(&mut cross_context.catalog_id);
    cross_context.generation = cross_generation;
    validate_context_syntax(&cross_context)?;
    let cross_facts = validate_opening_value(&cross_opening, &cross_context, &facts.verifier, 1)?;
    if cross_facts.evidence.issuer_epk != facts.openings[0].evidence.issuer_epk {
        return Err(ProtocolToolError::new(
            "Catalog V2 cross-catalog issuer-EPK reuse fixture did not reuse the positive issuer EPK",
        ));
    }
    expect_negative_error(
        validate_global_issuer_epk_uniqueness(
            facts
                .openings
                .iter()
                .map(|opening| opening.evidence.issuer_epk)
                .chain(std::iter::once(cross_facts.evidence.issuer_epk)),
        ),
        "issuer_epk_reused_across_catalogs",
        "issuer EPK reused across retained Catalog V2 bindings or generations",
    )
}

#[allow(clippy::too_many_lines)]
fn validate_negative_vector_family(
    vector: &Value,
    cddl: &str,
    facts: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    let negative = json_field(vector, "negative_cbor", "Catalog V2 vector")?;
    require_json_keys(
        negative,
        &[
            "binding_expired_at_use",
            "binding_outside_head_validity",
            "duplicate_plaintext",
            "head_leakage",
            "invalid_binding_validity",
            "missing_nonce_private_body",
            "missing_nul_binding_signature",
            "mixed_opening",
            "noncanonical_cbor",
            "nonconsecutive_plaintext",
            "path_catalog_mismatch_head",
            "plaintext_as_ciphertext_upload",
            "private_body_as_ciphertext_upload",
            "proof_extra_siblings",
            "proof_index_above_count",
            "proof_index_zero",
            "proof_odd_final_supplied_sibling",
            "proof_reordered_siblings",
            "proof_short_siblings",
            "proof_wrong_catalog",
            "proof_wrong_count",
            "proof_wrong_generation",
            "proof_wrong_sibling",
            "proof_wrong_side",
            "proof_wrong_version",
            "reused_nonce_plaintext",
            "self_consistent_wrong_domain_opening",
            "stale_private_digest_opening",
            "stale_receipt_digest_private_body",
            "stale_scope_digest_private_body",
            "substituted_authority_device_binding",
            "substituted_authority_key_binding",
            "substituted_binding_expires_at",
            "substituted_binding_issued_at",
            "substituted_catalog_private_body",
            "substituted_generation_private_body",
            "substituted_index_private_body",
            "substituted_verifier_descriptor_binding",
            "substituted_verifier_epoch_binding",
            "substituted_verifier_key_id_binding",
            "substituted_verifier_origin_binding",
            "substituted_verifier_public_key_binding",
            "unsorted_plaintext",
            "upload_leakage",
            "valid_signature_authority_id_mismatch_binding",
            "valid_signature_coordinate_mismatch_binding",
            "valid_signature_descriptor_mismatch_binding",
            "valid_signature_private_mismatch_binding",
            "wrong_authority_signer_binding",
            "wrong_binding_digest_commitment",
            "wrong_ciphertext_digest_head",
            "wrong_ciphertext_upload",
            "wrong_head_signature",
            "wrong_identity_head_digest",
            "wrong_identity_height_head",
            "wrong_leaf_count_head",
            "wrong_merkle_root_head",
            "wrong_private_digest_commitment",
            "wrong_scope_digest_encoding_private_body",
            "zero_nonce_private_body",
        ],
        "Catalog V2 negative family",
    )?;

    let noncanonical = decode_lower_hex(json_string(negative, "noncanonical_cbor")?)?;
    if decode_exact_bytes(&noncanonical, "noncanonical negative").is_ok() {
        return Err(ProtocolToolError::new(
            "Catalog V2 noncanonical negative was accepted",
        ));
    }
    for (field, rule) in [
        (
            "missing_nonce_private_body",
            "recovery-scope-catalog-private-body-v2",
        ),
        ("head_leakage", "recovery-scope-catalog-head-v2"),
        ("proof_index_zero", "catalog-merkle-proof-v2"),
        ("proof_wrong_version", "catalog-merkle-proof-v2"),
    ] {
        let bytes = decode_lower_hex(json_string(negative, field)?)?;
        decode_exact_bytes(&bytes, field)?;
        if cddl_cat::validate_cbor_bytes(rule, cddl, &bytes).is_ok() {
            return Err(ProtocolToolError::new(format!(
                "Catalog V2 structural negative {field} passed CDDL"
            )));
        }
    }
    let upload_leakage = decode_lower_hex(json_string(negative, "upload_leakage")?)?;
    decode_exact_bytes_with_limit(&upload_leakage, "upload_leakage", MAX_ENVELOPE_BYTES)?;
    if cddl_cat::validate_cbor_bytes("recovery-scope-catalog-upload-v2", cddl, &upload_leakage)
        .is_ok()
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 structural negative upload_leakage passed CDDL",
        ));
    }
    validate_independent_negative_constructions(vector, negative, cddl)?;
    for (field, expected) in [
        ("zero_nonce_private_body", "hiding nonce"),
        (
            "stale_receipt_digest_private_body",
            "membership-receipt digest",
        ),
        ("stale_scope_digest_private_body", "recovery-scope digest"),
        (
            "wrong_scope_digest_encoding_private_body",
            "recovery-scope digest",
        ),
        ("substituted_catalog_private_body", "coordinate mismatch"),
        ("substituted_generation_private_body", "coordinate mismatch"),
        ("substituted_index_private_body", "coordinate mismatch"),
    ] {
        let (_, value) = decode_negative_cddl(
            negative,
            cddl,
            field,
            "recovery-scope-catalog-private-body-v2",
        )?;
        expect_negative_error(
            validate_private_body_value(&value, &facts.context, 1).map(|_| ()),
            field,
            expected,
        )?;
    }
    validate_negative_signature_fixtures(vector, negative)?;
    for (field, expected) in [
        ("substituted_verifier_origin_binding", "descriptor tuple"),
        ("substituted_verifier_key_id_binding", "descriptor tuple"),
        (
            "substituted_verifier_public_key_binding",
            "descriptor tuple",
        ),
        ("substituted_verifier_epoch_binding", "descriptor tuple"),
        (
            "substituted_verifier_descriptor_binding",
            "descriptor tuple",
        ),
        ("substituted_binding_issued_at", "signature invalid"),
        ("substituted_binding_expires_at", "escapes head"),
        ("substituted_authority_device_binding", "authority mismatch"),
        ("substituted_authority_key_binding", "authority mismatch"),
        ("wrong_authority_signer_binding", "signature invalid"),
        ("invalid_binding_validity", "inner validity"),
        ("binding_outside_head_validity", "escapes head"),
        ("binding_expired_at_use", "expired at use"),
        (
            "valid_signature_authority_id_mismatch_binding",
            "authority mismatch",
        ),
        (
            "valid_signature_coordinate_mismatch_binding",
            "coordinate/private mismatch",
        ),
        (
            "valid_signature_private_mismatch_binding",
            "coordinate/private mismatch",
        ),
        (
            "valid_signature_descriptor_mismatch_binding",
            "descriptor tuple",
        ),
        ("missing_nul_binding_signature", "signature invalid"),
    ] {
        let (_, value) = decode_negative_cddl(
            negative,
            cddl,
            field,
            "recovery-scope-catalog-completion-verifier-binding-v1",
        )?;
        expect_negative_error(
            validate_binding_value(
                &value,
                &facts.context,
                &facts.verifier,
                1,
                facts.openings[0].private_digest,
            )
            .map(|_| ()),
            field,
            expected,
        )?;
    }
    for (field, expected) in [
        (
            "wrong_private_digest_commitment",
            "commitment binding mismatch",
        ),
        (
            "wrong_binding_digest_commitment",
            "commitment binding mismatch",
        ),
    ] {
        let (_, value) = decode_negative_cddl(
            negative,
            cddl,
            field,
            "recovery-scope-catalog-leaf-commitment-v2",
        )?;
        expect_negative_error(
            validate_commitment_value(
                &value,
                &facts.context,
                1,
                facts.openings[0].private_digest,
                facts.openings[0].binding_digest,
                &facts.openings[0].evidence,
            )
            .map(|_| ()),
            field,
            expected,
        )?;
    }
    for (field, expected) in [
        (
            "stale_private_digest_opening",
            "coordinate/private mismatch",
        ),
        (
            "self_consistent_wrong_domain_opening",
            "coordinate/private mismatch",
        ),
        ("mixed_opening", "coordinate mismatch"),
    ] {
        let (_, value) =
            decode_negative_cddl(negative, cddl, field, "recovery-scope-catalog-opening-v2")?;
        expect_negative_error(
            validate_opening_value(&value, &facts.context, &facts.verifier, 1).map(|_| ()),
            field,
            expected,
        )?;
    }
    for (field, expected) in [
        ("reused_nonce_plaintext", "nonce reused"),
        ("unsorted_plaintext", "canonical-sorted"),
        ("duplicate_plaintext", "canonical-sorted"),
        ("nonconsecutive_plaintext", "coordinate mismatch"),
    ] {
        let (_, value) =
            decode_negative_cddl(negative, cddl, field, "recovery-scope-catalog-plaintext-v2")?;
        expect_negative_error(
            validate_plaintext_value(&value, &facts.context, &facts.verifier).map(|_| ()),
            field,
            expected,
        )?;
    }
    let positive_head_fields = numbered_fields(&facts.signed_head, 16, "positive head")?;
    let ciphertext_digest = cbor_fixed(positive_head_fields[7], "positive ciphertext digest")?;
    for (field, expected) in [
        ("wrong_merkle_root_head", "relational binding"),
        ("wrong_ciphertext_digest_head", "relational binding"),
        ("wrong_leaf_count_head", "relational binding"),
        ("wrong_identity_height_head", "relational binding"),
        ("wrong_identity_head_digest", "relational binding"),
        ("wrong_head_signature", "signature invalid"),
        ("path_catalog_mismatch_head", "relational binding"),
    ] {
        let (_, value) =
            decode_negative_cddl(negative, cddl, field, "recovery-scope-catalog-head-v2")?;
        expect_negative_error(
            validate_head_value(
                &value,
                &facts.context,
                facts.merkle_root,
                ciphertext_digest,
                facts.openings.len(),
            ),
            field,
            expected,
        )?;
    }
    for (field, expected) in [
        ("wrong_ciphertext_upload", "ciphertext digest mismatch"),
        ("plaintext_as_ciphertext_upload", "exposed plaintext"),
        ("private_body_as_ciphertext_upload", "exposed plaintext"),
    ] {
        let (_, value) = decode_exact_upload_cddl(cddl, json_string(negative, field)?, field)?;
        expect_negative_error(validate_upload_value(&value, facts), field, expected)?;
    }
    validate_negative_proofs(negative, cddl, facts)?;
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the four reviewed adversarial constructions are proved together before rejection"
)]
fn validate_independent_negative_constructions(
    vector: &Value,
    negative: &Value,
    cddl: &str,
) -> Result<(), ProtocolToolError> {
    let authority = decode_json_fixed::<32>(vector, "catalog_authority_public_key_hex")?;
    let wrong_authority = decode_json_fixed::<32>(vector, "wrong_authority_public_key_hex")?;

    let (_, opening) = decode_negative_cddl(
        negative,
        cddl,
        "self_consistent_wrong_domain_opening",
        "recovery-scope-catalog-opening-v2",
    )?;
    let opening_fields = numbered_fields(&opening, 3, "wrong-domain construction")?;
    let private_exact = encode_deterministic_cbor(opening_fields[0]).map_err(|error| {
        ProtocolToolError::new(format!("encode wrong-domain private body: {error}"))
    })?;
    let alternate_private_digest = domain_digest(PRIVATE_BODY_DOMAIN_WITHOUT_NUL, &private_exact);
    let binding_fields = numbered_fields(opening_fields[1], 23, "wrong-domain binding")?;
    if cbor_fixed::<32>(binding_fields[5], "wrong-domain private digest")?
        != alternate_private_digest
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 wrong-domain opening does not use the exact missing-NUL private-body domain",
        ));
    }
    verify_signature(
        cbor_fixed(binding_fields[17], "wrong-domain evidence EPK")?,
        COMPLETION_EVIDENCE_POP_DOMAIN,
        &encoded_unsigned_prefix(opening_fields[1], 20, "wrong-domain evidence PoP")?,
        cbor_fixed(binding_fields[20], "wrong-domain evidence PoP signature")?,
        "Catalog V2 wrong-domain evidence PoP construction",
    )?;
    verify_signature(
        cbor_fixed(binding_fields[8], "wrong-domain origin verifier")?,
        COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN,
        &encoded_unsigned_prefix(opening_fields[1], 21, "wrong-domain origin authorization")?,
        cbor_fixed(
            binding_fields[21],
            "wrong-domain origin authorization signature",
        )?,
        "Catalog V2 wrong-domain origin authorization construction",
    )?;
    verify_signature(
        authority,
        VERIFIER_BINDING_SIGNATURE_DOMAIN,
        &encoded_unsigned_prefix(opening_fields[1], 22, "wrong-domain binding")?,
        cbor_fixed(binding_fields[22], "wrong-domain binding signature")?,
        "Catalog V2 wrong-domain binding construction",
    )?;
    let binding_exact = encode_deterministic_cbor(opening_fields[1]).map_err(|error| {
        ProtocolToolError::new(format!("encode wrong-domain signed binding: {error}"))
    })?;
    let alternate_binding_digest = domain_digest(VERIFIER_BINDING_DOMAIN, &binding_exact);
    let commitment_fields = numbered_fields(opening_fields[2], 12, "wrong-domain commitment")?;
    if cbor_fixed::<32>(
        commitment_fields[4],
        "wrong-domain commitment private digest",
    )? != alternate_private_digest
        || cbor_fixed::<32>(
            commitment_fields[5],
            "wrong-domain commitment binding digest",
        )? != alternate_binding_digest
        || cbor_fixed::<32>(commitment_fields[11], "wrong-domain authorization digest")?
            != domain_digest(
                COMPLETION_EVIDENCE_AUTHORIZATION_DIGEST_DOMAIN,
                &encoded_unsigned_prefix(
                    opening_fields[1],
                    22,
                    "wrong-domain authorization digest",
                )?,
            )
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 wrong-domain opening descendants were not recomputed consistently",
        ));
    }

    let (_, missing_nul_binding) = decode_negative_cddl(
        negative,
        cddl,
        "missing_nul_binding_signature",
        "recovery-scope-catalog-completion-verifier-binding-v1",
    )?;
    let missing_nul_fields = numbered_fields(&missing_nul_binding, 23, "missing-NUL binding")?;
    let missing_nul_unsigned =
        encoded_unsigned_prefix(&missing_nul_binding, 22, "missing-NUL binding")?;
    let missing_nul_signature = cbor_fixed(missing_nul_fields[22], "missing-NUL signature")?;
    verify_signature(
        authority,
        VERIFIER_BINDING_SIGNATURE_DOMAIN_WITHOUT_NUL,
        &missing_nul_unsigned,
        missing_nul_signature,
        "Catalog V2 missing-NUL binding construction",
    )?;
    if verify_signature(
        authority,
        VERIFIER_BINDING_SIGNATURE_DOMAIN,
        &missing_nul_unsigned,
        missing_nul_signature,
        "Catalog V2 frozen binding transcript",
    )
    .is_ok()
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 missing-NUL binding signature also verifies under the frozen transcript",
        ));
    }

    let (_, raw_scope_body) = decode_negative_cddl(
        negative,
        cddl,
        "wrong_scope_digest_encoding_private_body",
        "recovery-scope-catalog-private-body-v2",
    )?;
    let raw_scope_fields = numbered_fields(&raw_scope_body, 10, "raw-scope-digest body")?;
    let scope_fields = numbered_fields(raw_scope_fields[4], 2, "raw-scope recovery scope")?;
    let raw_scope_text = cbor_text(scope_fields[1], "raw recovery-scope text")?;
    let raw_scope_digest = domain_digest(RECOVERY_SCOPE_DOMAIN, raw_scope_text.as_bytes());
    let canonical_scope = encode_deterministic_cbor(raw_scope_fields[4]).map_err(|error| {
        ProtocolToolError::new(format!("encode canonical recovery scope: {error}"))
    })?;
    if cbor_fixed::<32>(raw_scope_fields[8], "raw recovery-scope digest")? != raw_scope_digest
        || raw_scope_digest == domain_digest(RECOVERY_SCOPE_DOMAIN, &canonical_scope)
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 raw-scope negative does not prove raw text versus canonical field-5 CBOR",
        ));
    }

    let (_, wrong_head) = decode_negative_cddl(
        negative,
        cddl,
        "wrong_head_signature",
        "recovery-scope-catalog-head-v2",
    )?;
    let wrong_head_fields = numbered_fields(&wrong_head, 16, "wrong-authority head")?;
    let wrong_head_unsigned = encoded_unsigned_prefix(&wrong_head, 15, "wrong-authority head")?;
    let wrong_head_signature = cbor_fixed(wrong_head_fields[15], "wrong-authority signature")?;
    verify_signature(
        wrong_authority,
        HEAD_SIGNATURE_DOMAIN,
        &wrong_head_unsigned,
        wrong_head_signature,
        "Catalog V2 unrelated-authority head construction",
    )?;
    if verify_signature(
        authority,
        HEAD_SIGNATURE_DOMAIN,
        &wrong_head_unsigned,
        wrong_head_signature,
        "Catalog V2 frozen head authority",
    )
    .is_ok()
    {
        return Err(ProtocolToolError::new(
            "Catalog V2 wrong-head signature also verifies under the frozen authority",
        ));
    }
    Ok(())
}

fn validate_negative_signature_fixtures(
    vector: &Value,
    negative: &Value,
) -> Result<(), ProtocolToolError> {
    let authority = decode_json_fixed::<32>(vector, "catalog_authority_public_key_hex")?;
    let wrong_authority = decode_json_fixed::<32>(vector, "wrong_authority_public_key_hex")?;
    let rotated_verifier = decode_json_fixed::<32>(vector, "rotated_verifier_public_key_hex")?;
    if authority == wrong_authority {
        return Err(ProtocolToolError::new(
            "Catalog V2 wrong-authority fixture equals catalog authority",
        ));
    }
    for (field, signer) in [
        ("wrong_authority_signer_binding", wrong_authority),
        ("valid_signature_authority_id_mismatch_binding", authority),
        ("valid_signature_coordinate_mismatch_binding", authority),
        ("valid_signature_private_mismatch_binding", authority),
        ("valid_signature_descriptor_mismatch_binding", authority),
    ] {
        let bytes = decode_lower_hex(json_string(negative, field)?)?;
        let value = decode_exact_bytes(&bytes, field)?;
        let fields = numbered_fields(&value, 23, field)?;
        verify_signature(
            signer,
            VERIFIER_BINDING_SIGNATURE_DOMAIN,
            &encoded_unsigned_prefix(&value, 22, field)?,
            cbor_fixed(fields[22], "negative binding signature")?,
            field,
        )?;
        if field == "valid_signature_descriptor_mismatch_binding"
            && cbor_fixed::<32>(fields[8], "rotated verifier fixture")? != rotated_verifier
        {
            return Err(ProtocolToolError::new(
                "Catalog V2 rotated-verifier fixture assertion mismatch",
            ));
        }
    }
    Ok(())
}

fn decode_negative_cddl(
    negative: &Value,
    cddl: &str,
    field: &str,
    rule: &str,
) -> Result<(Vec<u8>, CanonicalValue), ProtocolToolError> {
    decode_exact_cddl(cddl, rule, json_string(negative, field)?, field)
}

fn expect_negative_error(
    result: Result<(), ProtocolToolError>,
    field: &str,
    expected: &str,
) -> Result<(), ProtocolToolError> {
    match result {
        Err(error) if error.to_string().contains(expected) => Ok(()),
        Err(error) => Err(ProtocolToolError::new(format!(
            "Catalog V2 negative {field} reached wrong check: {error}"
        ))),
        Ok(()) => Err(ProtocolToolError::new(format!(
            "Catalog V2 negative {field} was accepted"
        ))),
    }
}

fn validate_negative_proofs(
    negative: &Value,
    cddl: &str,
    facts: &CatalogPositiveFacts,
) -> Result<(), ProtocolToolError> {
    for (field, index, leaf, expected) in [
        (
            "proof_wrong_catalog",
            1,
            facts.openings[0].leaf_digest,
            "coordinate mismatch",
        ),
        (
            "proof_wrong_generation",
            1,
            facts.openings[0].leaf_digest,
            "coordinate mismatch",
        ),
        (
            "proof_wrong_count",
            1,
            facts.openings[0].leaf_digest,
            "coordinate mismatch",
        ),
        (
            "proof_index_above_count",
            1,
            facts.openings[0].leaf_digest,
            "coordinate mismatch",
        ),
        (
            "proof_wrong_sibling",
            1,
            facts.openings[0].leaf_digest,
            "wrong root",
        ),
        (
            "proof_short_siblings",
            1,
            facts.openings[0].leaf_digest,
            "missing a sibling",
        ),
        (
            "proof_extra_siblings",
            1,
            facts.openings[0].leaf_digest,
            "surplus",
        ),
        (
            "proof_reordered_siblings",
            1,
            facts.openings[0].leaf_digest,
            "wrong root",
        ),
        (
            "proof_wrong_side",
            2,
            facts.openings[1].leaf_digest,
            "wrong root",
        ),
        (
            "proof_odd_final_supplied_sibling",
            3,
            facts.openings[2].leaf_digest,
            "surplus",
        ),
    ] {
        let (_, value) = decode_negative_cddl(negative, cddl, field, "catalog-merkle-proof-v2")?;
        expect_negative_error(
            validate_proof_value(&value, &facts.context, 3, index, leaf, facts.merkle_root),
            field,
            expected,
        )?;
    }
    Ok(())
}

fn rule_body<'a>(cddl: &'a str, rule: &str) -> Result<&'a str, ProtocolToolError> {
    let declaration = format!("{rule} = {{");
    let declaration_start = cddl.find(&declaration).ok_or_else(|| {
        ProtocolToolError::new(format!(
            "Recovery Scope Catalog V2 rule {rule} is not an inline map"
        ))
    })?;
    let body_start = declaration_start + declaration.len() - 1;
    let mut depth = 0_u32;
    for (offset, character) in cddl[body_start..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(&cddl[body_start..=body_start + offset]);
                }
            }
            _ => {}
        }
    }
    Err(ProtocolToolError::new(format!(
        "Recovery Scope Catalog V2 rule {rule} has an unterminated map"
    )))
}

fn numbered_map_keys(body: &str) -> Vec<usize> {
    let bytes = body.as_bytes();
    let mut keys = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !bytes[cursor].is_ascii_digit() || cursor > 0 && bytes[cursor - 1].is_ascii_digit() {
            cursor += 1;
            continue;
        }
        let start = cursor;
        while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if bytes.get(cursor) == Some(&b':') {
            let key = body[start..cursor]
                .parse()
                .expect("ASCII decimal map key must parse as usize");
            keys.push(key);
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use ed25519_dalek::{Signature, VerifyingKey};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    fn cddl() -> String {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        super::read_cddl(&root).expect("Recovery Scope Catalog V2 CDDL must be readable")
    }

    fn openapi() -> String {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        super::read_openapi(&root).expect("Recovery Scope Catalog V2 OpenAPI must be readable")
    }

    fn openapi_document() -> Value {
        super::parse_openapi(&openapi()).expect("Recovery Scope Catalog V2 OpenAPI must parse")
    }

    fn vector() -> Value {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        super::read_catalog_vector(&root).expect("Recovery Scope Catalog V2 vector must parse")
    }

    fn positive_handoff(
        value: &Value,
    ) -> (
        super::CatalogPositiveFacts,
        super::ServerVisibleHandoffFacts,
    ) {
        let cddl = cddl();
        let server =
            validate_server_handoff(value).expect("C1b-B1 server-visible fixture must validate");
        let catalog = super::validate_positive_vector(value, &cddl)
            .expect("Catalog V2 core positive fixture must validate");
        (catalog, server)
    }

    fn validate_server_handoff(
        value: &Value,
    ) -> Result<super::ServerVisibleHandoffFacts, super::ProtocolToolError> {
        let cddl = cddl();
        let catalog = super::validate_catalog_server_projection(value, &cddl)?;
        let input = super::parse_server_visible_handoff_input(value)?;
        super::validate_server_visible_handoff(&cddl, &catalog, &input)
    }

    fn assert_openapi_document_rejected(label: &str, document: &Value) {
        assert!(
            super::validate_openapi_document(document).is_err(),
            "OpenAPI validator must reject {label}"
        );
    }

    fn replace_openapi_value(document: &mut Value, pointer: &str, replacement: Value) {
        *document
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("mutation pointer must exist: {pointer}")) = replacement;
    }

    fn mutate_cddl_rule(source: &str, rule: &str, mutation: impl FnOnce(&str) -> String) -> String {
        let declaration = format!("{rule} = {{");
        let declaration_start = source
            .find(&declaration)
            .unwrap_or_else(|| panic!("rule declaration must exist: {rule}"));
        let body = super::rule_body(source, rule)
            .unwrap_or_else(|_| panic!("rule body must exist: {rule}"));
        let body_offset = source[declaration_start..]
            .find(body)
            .expect("rule body must follow its declaration")
            + declaration_start;
        let mut mutated = source.to_owned();
        mutated.replace_range(body_offset..body_offset + body.len(), &mutation(body));
        mutated
    }

    fn independent_digest(domain: &[u8], exact: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(exact);
        hasher.finalize().into()
    }

    fn canonical_map(
        fields: impl IntoIterator<Item = (u64, dtx_wire::CanonicalValue)>,
    ) -> dtx_wire::CanonicalValue {
        dtx_wire::CanonicalValue::Map(
            fields
                .into_iter()
                .map(|(key, value)| (dtx_wire::CanonicalValue::Unsigned(key), value))
                .collect(),
        )
    }

    fn minimum_structural_catalog_opening(index: u64) -> dtx_wire::CanonicalValue {
        use dtx_wire::CanonicalValue::{Bytes, Text, Unsigned};

        let identity = Text("dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la".to_owned());
        let catalog_id = Text("0190f2a5-7b1c-7abc-8def-0123456789a2".to_owned());
        let private_body = canonical_map([
            (1, Unsigned(2)),
            (2, catalog_id.clone()),
            (3, Unsigned(1)),
            (4, Unsigned(index)),
            (
                5,
                canonical_map([(1, Unsigned(1)), (2, catalog_id.clone())]),
            ),
            (6, Bytes(vec![0; 1])),
            (7, Bytes(vec![0; 32])),
            (8, Bytes(vec![0; 32])),
            (9, Bytes(vec![0; 32])),
            (10, Bytes(vec![0; 32])),
        ]);
        let binding = canonical_map([
            (1, Unsigned(1)),
            (2, identity),
            (3, catalog_id.clone()),
            (4, Unsigned(1)),
            (5, Unsigned(index)),
            (6, Bytes(vec![0; 32])),
            (7, Text("https://a".to_owned())),
            (8, catalog_id.clone()),
            (9, Bytes(vec![0; 32])),
            (10, Unsigned(1)),
            (11, Bytes(vec![0; 32])),
            (12, Unsigned(0)),
            (13, Unsigned(1)),
            (14, catalog_id.clone()),
            (15, catalog_id.clone()),
            (16, Unsigned(1)),
            (17, Unsigned(1)),
            (18, Bytes(vec![0; 32])),
            (19, Unsigned(0)),
            (20, Unsigned(1)),
            (21, Bytes(vec![0; 64])),
            (22, Bytes(vec![0; 64])),
            (23, Bytes(vec![0; 64])),
        ]);
        let leaf = canonical_map([
            (1, Unsigned(2)),
            (2, catalog_id),
            (3, Unsigned(1)),
            (4, Unsigned(index)),
            (5, Bytes(vec![0; 32])),
            (6, Bytes(vec![0; 32])),
            (7, Unsigned(1)),
            (8, Unsigned(1)),
            (9, Bytes(vec![0; 32])),
            (10, Unsigned(0)),
            (11, Unsigned(1)),
            (12, Bytes(vec![0; 32])),
        ]);
        canonical_map([(1, private_body), (2, binding), (3, leaf)])
    }

    fn structural_opening_indices(value: &dtx_wire::CanonicalValue) -> [u64; 3] {
        let opening = super::numbered_fields(value, 3, "structural opening")
            .expect("structural opening must contain three members");
        let private = super::numbered_fields(opening[0], 10, "structural private body")
            .expect("structural private body must contain ten fields");
        let binding = super::numbered_fields(opening[1], 23, "structural signed binding")
            .expect("structural signed binding must contain twenty-three fields");
        let leaf = super::numbered_fields(opening[2], 12, "structural public leaf")
            .expect("structural public leaf must contain twelve fields");
        [
            super::cbor_unsigned(private[3], "structural private index")
                .expect("structural private index must be unsigned"),
            super::cbor_unsigned(binding[4], "structural binding index")
                .expect("structural binding index must be unsigned"),
            super::cbor_unsigned(leaf[3], "structural leaf index")
                .expect("structural leaf index must be unsigned"),
        ]
    }

    fn consecutive_index_structural_catalog_plaintext_exact(count: usize) -> Vec<u8> {
        let count = u16::try_from(count).expect("Catalog structural boundary count fits u16");
        let mut exact = Vec::with_capacity(
            super::MIN_CATALOG_PLAINTEXT_OVERHEAD_BYTES
                + usize::from(count) * (super::MIN_CATALOG_OPENING_BYTES + 6),
        );
        exact.extend_from_slice(&[0xa8, 0x01, 0x02, 0x02, 0x78, 0x39]);
        exact.extend_from_slice(b"dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la");
        exact.extend_from_slice(&[0x03, 0x78, 0x24]);
        exact.extend_from_slice(b"0190f2a5-7b1c-7abc-8def-0123456789a2");
        exact.extend_from_slice(&[0x04, 0x01, 0x05, 0xf6, 0x06, 0x00, 0x07, 0x58, 0x20]);
        exact.extend_from_slice(&[0; 32]);
        exact.extend_from_slice(&[0x08, 0x99]);
        exact.extend_from_slice(&count.to_be_bytes());
        for index in 1..=count {
            let index = u64::from(index);
            let opening = minimum_structural_catalog_opening(index);
            assert_eq!(structural_opening_indices(&opening), [index; 3]);
            exact.extend_from_slice(
                &dtx_wire::encode_deterministic_cbor(&opening)
                    .expect("consecutive-index structural opening must encode"),
            );
        }
        exact
    }

    fn canonical_bstr_exact(bytes: &[u8]) -> Vec<u8> {
        let length = u32::try_from(bytes.len()).expect("Catalog structural boundary fits u32");
        let mut encoded = Vec::with_capacity(bytes.len() + 5);
        encoded.push(0x5a);
        encoded.extend_from_slice(&length.to_be_bytes());
        encoded.extend_from_slice(bytes);
        encoded
    }

    fn proof_value(count: u64, index: u64, siblings: &[[u8; 32]]) -> dtx_wire::CanonicalValue {
        use dtx_wire::CanonicalValue::{Array, Bytes, Text, Unsigned};

        canonical_map([
            (1, Unsigned(2)),
            (2, Text("0190f2a5-7b1c-7abc-8def-0123456789a2".to_owned())),
            (3, Unsigned(8)),
            (4, Unsigned(count)),
            (5, Unsigned(index)),
            (
                6,
                Array(
                    siblings
                        .iter()
                        .map(|sibling| Bytes(sibling.to_vec()))
                        .collect(),
                ),
            ),
        ])
    }

    fn independent_proof_root(
        mut count: u64,
        mut index: u64,
        mut current: [u8; 32],
        siblings: &[[u8; 32]],
    ) -> [u8; 32] {
        let mut sibling_index = 0;
        while count > 1 {
            let (left, right) = if count % 2 == 1 && index == count {
                (current, current)
            } else {
                let sibling = siblings[sibling_index];
                sibling_index += 1;
                if index % 2 == 1 {
                    (current, sibling)
                } else {
                    (sibling, current)
                }
            };
            let mut children = [0; 64];
            children[..32].copy_from_slice(&left);
            children[32..].copy_from_slice(&right);
            current = independent_digest(super::MERKLE_NODE_DOMAIN, &children);
            count = count.div_ceil(2);
            index = index.div_ceil(2);
        }
        assert_eq!(sibling_index, siblings.len());
        current
    }

    fn independent_unsigned_prefix(value: &dtx_wire::CanonicalValue, count: usize) -> Vec<u8> {
        let dtx_wire::CanonicalValue::Map(fields) = value else {
            panic!("signed fixture must be a map");
        };
        dtx_wire::encode_deterministic_cbor(&dtx_wire::CanonicalValue::Map(
            fields[..count].to_vec(),
        ))
        .expect("unsigned fixture must encode canonically")
    }

    fn independently_verifies(
        public_key: [u8; 32],
        domain: &[u8],
        unsigned: &[u8],
        signature: [u8; 64],
    ) -> bool {
        let Ok(key) = VerifyingKey::from_bytes(&public_key) else {
            return false;
        };
        let mut transcript = Vec::with_capacity(domain.len() + unsigned.len());
        transcript.extend_from_slice(domain);
        transcript.extend_from_slice(unsigned);
        key.verify_strict(&transcript, &Signature::from_bytes(&signature))
            .is_ok()
    }

    #[test]
    fn v42_catalog_v2_cddl_parses() {
        super::validate_parse(&cddl()).expect("Recovery Scope Catalog V2 CDDL must parse");
    }

    #[test]
    fn v42_catalog_v2_cddl_core_rule_names_are_frozen() {
        super::validate_rule_names(&cddl())
            .expect("Recovery Scope Catalog V2 must expose exactly the core rules");
    }

    #[test]
    fn v42_catalog_v2_cddl_numbered_field_counts_are_frozen() {
        super::validate_field_counts(&cddl())
            .expect("Recovery Scope Catalog V2 field counts must remain frozen");
    }

    #[test]
    fn v42_catalog_v2_cddl_wire_bounds_are_frozen() {
        super::validate_bounds(&cddl())
            .expect("Recovery Scope Catalog V2 wire bounds must remain frozen");
    }

    #[test]
    fn v42_catalog_v2_count_ceiling_is_consecutive_index_and_size_derived() {
        let cddl = cddl();
        assert_eq!(super::MAX_CATALOG_LEAVES, 1_023);
        for (index, extra_bytes, accepted) in [
            (1, 0, true),
            (23, 0, true),
            (24, 3, true),
            (255, 3, true),
            (256, 6, true),
            (1_023, 6, true),
            (1_024, 6, false),
        ] {
            let opening = minimum_structural_catalog_opening(index);
            assert_eq!(structural_opening_indices(&opening), [index; 3]);
            let opening_exact = dtx_wire::encode_deterministic_cbor(&opening)
                .expect("index-aware structural opening must encode");
            assert_eq!(
                opening_exact.len(),
                super::MIN_CATALOG_OPENING_BYTES + extra_bytes
            );
            assert_eq!(
                cddl_cat::validate_cbor_bytes(
                    "recovery-scope-catalog-opening-v2",
                    &cddl,
                    &opening_exact,
                )
                .is_ok(),
                accepted,
                "structural opening index {index} owner-bound result drifted"
            );
        }

        let maximum =
            consecutive_index_structural_catalog_plaintext_exact(super::MAX_CATALOG_LEAVES);
        assert_eq!(
            maximum.len(),
            super::MIN_CATALOG_PLAINTEXT_OVERHEAD_BYTES
                + super::MAX_CATALOG_LEAVES * super::MIN_CATALOG_OPENING_BYTES
                + 232 * 3
                + 768 * 6
        );
        assert_eq!(maximum.len(), super::MAX_MINIMAL_CATALOG_BYTES);
        assert_eq!(maximum.len(), 1_047_888);
        assert!(maximum.len() <= super::MAX_CIPHERTEXT_BYTES);
        cddl_cat::validate_cbor_bytes("recovery-scope-catalog-plaintext-v2", &cddl, &maximum)
            .expect("1,023-opening consecutive-index structural plaintext must satisfy CDDL");
        let maximum_bstr = canonical_bstr_exact(&maximum);
        cddl_cat::validate_cbor_bytes("exact-catalog-plaintext-v2", &cddl, &maximum_bstr)
            .expect("minimum-sized 1,023-opening consecutive-index plaintext must fit 1 MiB");

        let overflow =
            consecutive_index_structural_catalog_plaintext_exact(super::MAX_CATALOG_LEAVES + 1);
        assert_eq!(overflow.len(), super::MIN_OVERFLOW_CATALOG_BYTES);
        assert_eq!(overflow.len(), 1_048_913);
        assert!(overflow.len() > super::MAX_CIPHERTEXT_BYTES);
        assert!(
            cddl_cat::validate_cbor_bytes("recovery-scope-catalog-plaintext-v2", &cddl, &overflow,)
                .is_err(),
            "1,024 consecutive-index openings must fail the owner count rule"
        );
        let overflow_bstr = canonical_bstr_exact(&overflow);
        assert!(
            cddl_cat::validate_cbor_bytes("exact-catalog-plaintext-v2", &cddl, &overflow_bstr)
                .is_err(),
            "minimum-sized 1,024-opening consecutive-index plaintext must exceed 1 MiB"
        );
    }

    #[test]
    fn v42_catalog_v2_proof_boundary_is_exact_and_mathematically_required() {
        let cddl = cddl();
        let vector = vector();
        let facts = super::validate_positive_vector(&vector, &cddl)
            .expect("positive Catalog V2 vector must validate");
        let leaf = [0x41; 32];
        let siblings = (0..super::MAX_PROOF_SIBLINGS)
            .map(|index| [u8::try_from(index + 1).expect("proof depth fits u8"); 32])
            .collect::<Vec<_>>();
        let root = independent_proof_root(
            u64::try_from(super::MAX_CATALOG_LEAVES).expect("count fits u64"),
            1,
            leaf,
            &siblings,
        );
        let proof = proof_value(
            u64::try_from(super::MAX_CATALOG_LEAVES).expect("count fits u64"),
            1,
            &siblings,
        );
        assert_eq!(super::MAX_PROOF_SIBLINGS, 10);
        let proof_exact = dtx_wire::encode_deterministic_cbor(&proof)
            .expect("10-sibling proof must encode canonically");
        cddl_cat::validate_cbor_bytes("catalog-merkle-proof-v2", &cddl, &proof_exact)
            .expect("mathematically required 10-sibling proof must satisfy CDDL");
        super::validate_proof_value(
            &proof,
            &facts.context,
            u64::try_from(super::MAX_CATALOG_LEAVES).expect("count fits u64"),
            1,
            leaf,
            root,
        )
        .expect("mathematically required 10-sibling proof must verify");

        let mut surplus = siblings.clone();
        surplus.push([0xff; 32]);
        let surplus_proof = proof_value(
            u64::try_from(super::MAX_CATALOG_LEAVES).expect("count fits u64"),
            1,
            &surplus,
        );
        let surplus_exact = dtx_wire::encode_deterministic_cbor(&surplus_proof)
            .expect("11-sibling proof must encode canonically");
        assert!(
            cddl_cat::validate_cbor_bytes("catalog-merkle-proof-v2", &cddl, &surplus_exact)
                .is_err()
        );
        assert!(
            super::validate_proof_value(
                &surplus_proof,
                &facts.context,
                u64::try_from(super::MAX_CATALOG_LEAVES).expect("count fits u64"),
                1,
                leaf,
                root,
            )
            .is_err()
        );

        let max_plus_one =
            u64::try_from(super::MAX_CATALOG_LEAVES + 1).expect("max+1 count fits u64");
        let max_plus_one_root = independent_proof_root(max_plus_one, 1, leaf, &siblings);
        let max_plus_one_proof = proof_value(max_plus_one, 1, &siblings);
        assert!(
            super::validate_proof_value(
                &max_plus_one_proof,
                &facts.context,
                max_plus_one,
                1,
                leaf,
                max_plus_one_root,
            )
            .is_err(),
            "semantic owner seam must reject count 1,024"
        );

        let single = proof_value(1, 1, &[]);
        super::validate_proof_value(&single, &facts.context, 1, 1, leaf, leaf)
            .expect("one-leaf proof must consume zero siblings");
    }

    #[test]
    fn v42_catalog_v2_opening_digest_covers_complete_exact_opening() {
        let vector = vector();
        let openings = vector
            .pointer("/catalog/openings")
            .and_then(Value::as_array)
            .expect("positive openings must exist");
        assert_eq!(openings.len(), 3);
        for opening in openings {
            let exact = super::decode_lower_hex(
                super::json_string(opening, "opening_cbor_hex")
                    .expect("opening exact bytes must exist"),
            )
            .expect("opening exact bytes must decode");
            let claimed = super::decode_json_fixed::<32>(opening, "opening_digest_hex")
                .expect("opening digest assertion must exist");
            assert_eq!(
                claimed,
                independent_digest(super::OPENING_DOMAIN, &exact),
                "opening digest must cover private body, full signed binding, and public leaf"
            );
        }
    }

    #[test]
    fn v42_catalog_v2_device_add_v1_1_exact_maximum_is_533_bytes() {
        use dtx_wire::CanonicalValue::{Bytes, Map, Text, Unsigned};

        fn map(fields: Vec<(u64, dtx_wire::CanonicalValue)>) -> dtx_wire::CanonicalValue {
            Map(fields
                .into_iter()
                .map(|(key, value)| (Unsigned(key), value))
                .collect())
        }

        fn protocol_version(minor: u64) -> dtx_wire::CanonicalValue {
            map(vec![(1, Unsigned(1)), (2, Unsigned(minor))])
        }

        fn wire_version(minor: u64) -> dtx_wire::CanonicalValue {
            map(vec![
                (1, protocol_version(minor)),
                (2, protocol_version(minor)),
            ])
        }

        fn maximal_device_add(minor: u64) -> dtx_wire::CanonicalValue {
            let identity =
                Text("dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la".to_owned());
            let certificate = map(vec![
                (1, wire_version(minor)),
                (2, identity.clone()),
                (3, Text("0190f2a5-7b1c-7abc-8def-0123456789b4".to_owned())),
                (4, Bytes(vec![0x44; 32])),
                (5, Bytes(vec![0x55; 32])),
                (6, Bytes(vec![0x66; 32])),
                (7, Unsigned(253_402_300_799_999)),
                (8, Bytes(vec![0x77; 64])),
            ]);
            map(vec![
                (1, wire_version(minor)),
                (2, identity),
                (3, Unsigned(9_007_199_254_740_991)),
                (4, Bytes(vec![0x33; 32])),
                (5, Unsigned(253_402_300_799_999)),
                (6, Unsigned(2)),
                (7, map(vec![(1, certificate)])),
                (8, Bytes(vec![0x88; 32])),
                (9, Bytes(vec![0x99; 64])),
            ])
        }

        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let identity_cddl = std::fs::read_to_string(
            root.join("protocol/cddl/identity-log/v1_1/identity-log-v1-1.cddl"),
        )
        .expect("owning Identity Log V1.1 CDDL must be readable");
        let exact_value = maximal_device_add(1);
        let exact = dtx_wire::encode_deterministic_cbor(&exact_value)
            .expect("maximum DeviceAdd must encode canonically");
        assert_eq!(exact.len(), super::MAX_DEVICE_ADD_BYTES);
        assert_eq!(
            dtx_wire::decode_deterministic_cbor(&exact).expect("maximum DeviceAdd must decode"),
            exact_value
        );
        assert_eq!(
            dtx_wire::encode_deterministic_cbor(
                &dtx_wire::decode_deterministic_cbor(&exact)
                    .expect("maximum DeviceAdd must decode before re-encoding")
            )
            .expect("maximum DeviceAdd must re-encode"),
            exact
        );
        cddl_cat::validate_cbor_bytes("identity-log-device-add-event-v1-1", &identity_cddl, &exact)
            .expect("owning Identity Log V1.1 CDDL must accept the exact 533-byte maximum");
        let exact_bstr = dtx_wire::encode_deterministic_cbor(&Bytes(exact.clone()))
            .expect("exact DeviceAdd bstr must encode");
        cddl_cat::validate_cbor_bytes("exact-device-add-event-v1", &cddl(), &exact_bstr)
            .expect("Catalog V2 must accept the exact 533-byte DeviceAdd bstr boundary");

        let altered_version = dtx_wire::encode_deterministic_cbor(&maximal_device_add(2))
            .expect("altered version fixture must encode");
        assert!(
            cddl_cat::validate_cbor_bytes(
                "identity-log-device-add-event-v1-1",
                &identity_cddl,
                &altered_version,
            )
            .is_err()
        );

        let mut maximum_plus_one = exact;
        maximum_plus_one.push(0);
        assert_eq!(maximum_plus_one.len(), super::MAX_DEVICE_ADD_BYTES + 1);
        assert!(dtx_wire::decode_deterministic_cbor(&maximum_plus_one).is_err());
        let maximum_plus_one_bstr = dtx_wire::encode_deterministic_cbor(&Bytes(maximum_plus_one))
            .expect("oversized DeviceAdd bstr fixture must encode");
        assert!(
            cddl_cat::validate_cbor_bytes(
                "exact-device-add-event-v1",
                &cddl(),
                &maximum_plus_one_bstr,
            )
            .is_err()
        );
    }

    #[test]
    fn v42_catalog_v2_cddl_crypto_domains_and_transcripts_are_frozen() {
        super::validate_crypto_transcripts(&cddl())
            .expect("Recovery Scope Catalog V2 crypto transcripts must remain frozen");
    }

    #[test]
    fn v42_catalog_v2_cddl_handoff_maps_unions_and_semantics_are_frozen() {
        let source = cddl();
        super::validate_handoff_rules(&source)
            .expect("Recovery Scope Catalog V2 handoff maps and semantics must remain frozen");

        for (rule, _) in super::EXACT_HANDOFF_MAPS {
            let wrong_field = mutate_cddl_rule(&source, rule, |body| body.replacen("1:", "99:", 1));
            assert!(
                super::validate_field_counts(&wrong_field).is_err()
                    || super::validate_handoff_rules(&wrong_field).is_err(),
                "handoff validator must reject a field-number mutation in {rule}"
            );

            let wrong_version = mutate_cddl_rule(&source, rule, |body| {
                for discriminant in ["1: 1", "1: 2", "1: 3"] {
                    if body.contains(discriminant) {
                        return body.replacen(discriminant, "1: 99", 1);
                    }
                }
                panic!("handoff map must have a frozen field-1 discriminant: {rule}");
            });
            assert!(
                super::validate_handoff_rules(&wrong_version).is_err(),
                "handoff validator must reject a version mutation in {rule}"
            );

            let widened_type = mutate_cddl_rule(&source, rule, |body| {
                let closing = body.rfind('}').expect("map body must close");
                format!("{} / null{}", &body[..closing], &body[closing..])
            });
            assert!(
                super::validate_handoff_rules(&widened_type).is_err(),
                "handoff validator must reject a type mutation in {rule}"
            );
        }

        for union_member in [
            "recovery-scope-catalog-recovery-authority-v2",
            "recovery-scope-catalog-status-invalidated-v2",
        ] {
            let mutated = source.replacen(union_member, "unknown-union-member-v2", 1);
            assert!(super::validate_handoff_rules(&mutated).is_err());
        }
        for required in super::REQUIRED_HANDOFF_RULES {
            let mutated = source.replacen(required, "drifted-semantic-contract", 1);
            assert!(
                super::validate_handoff_rules(&mutated).is_err(),
                "handoff validator must reject semantic drift: {required}"
            );
        }
    }

    #[test]
    fn v42_catalog_v2_cddl_all_domains_and_hpke_info_are_exact_and_separate() {
        let source = cddl();
        for (name, domain) in super::REQUIRED_CRYPTO_DOMAIN_DECLARATIONS {
            let declaration = format!("{name} = `{domain}`.");
            let replacement = format!("{name} = `{domain}.drift`.");
            let mutated = source.replacen(&declaration, &replacement, 1);
            assert_ne!(mutated, source, "domain declaration must exist: {name}");
            assert!(
                super::validate_crypto_transcripts(&mutated).is_err(),
                "crypto validator must reject domain drift: {name}"
            );
        }
        let alternate_info = source.replacen(
            &format!("hpke-info = `{}`.", super::HPKE_INFO.replace('\0', "\\0")),
            "hpke-info = `dirextalk.recovery-scope-catalog-handoff-hpke.v2-alternate\\0`.",
            1,
        );
        assert!(super::validate_handoff_rules(&alternate_info).is_err());
        let aliased_info = format!(
            "{source}\n; hpke-info-alias-domain = `dirextalk.recovery-scope-catalog-handoff-hpke.v2\\0`.\n"
        );
        assert!(super::validate_crypto_transcripts(&aliased_info).is_err());
    }

    #[test]
    fn v42_catalog_v2_cddl_rejects_extra_alias_and_alternate_domain_declarations() {
        let source = cddl();
        for (label, declaration) in [
            (
                "thirty-first domain",
                "; thirty-first-domain = `dirextalk.recovery-scope-catalog-thirty-first.v2\\0`.\n",
            ),
            (
                "domain alias",
                "; private-body-alias-domain = `dirextalk.recovery-scope-catalog-private-body.v2\\0`.\n",
            ),
            (
                "alternate domain transcript",
                "; private-body-domain = `dirextalk.recovery-scope-catalog-private-body.alternate\\0`.\n",
            ),
        ] {
            let mutated = format!("{source}\n{declaration}");
            assert!(
                super::validate_crypto_transcripts(&mutated).is_err(),
                "crypto validator must reject {label}"
            );
        }

        let prose = format!(
            "{source}\n; Prose may mention an eleventh-domain or {} without declaring either.\n",
            "dirextalk.recovery-scope-catalog-private-body.v2\\0"
        );
        super::validate_crypto_transcripts(&prose)
            .expect("non-declaration prose must not affect the exact domain set");
    }

    #[test]
    fn v42_catalog_v2_cddl_timestamp_and_proof_rules_are_frozen() {
        super::validate_time_and_proof_rules(&cddl())
            .expect("Recovery Scope Catalog V2 timestamp and proof rules must remain frozen");
    }

    #[test]
    fn v42_catalog_v2_cddl_hiding_nonce_policy_rejects_invalid_catalogs() {
        let first = [1_u8; 32];
        let second = [2_u8; 32];
        let zero = [0_u8; 32];
        super::validate_catalog_hiding_nonces([Some(first.as_slice()), Some(second.as_slice())])
            .expect("unique unpredictable hiding nonces must validate");
        assert!(super::validate_catalog_hiding_nonces(std::iter::empty()).is_err());
        assert!(super::validate_catalog_hiding_nonces([None]).is_err());
        assert!(super::validate_catalog_hiding_nonces([Some(zero.as_slice())]).is_err());
        assert!(
            super::validate_catalog_hiding_nonces([Some(first.as_slice()), Some(first.as_slice())])
                .is_err()
        );
    }

    #[test]
    fn v42_catalog_v2_openapi_parses() {
        super::parse_openapi(&openapi()).expect("Recovery Scope Catalog V2 OpenAPI must parse");
    }

    #[test]
    fn v42_catalog_v2_openapi_handoff_contract_is_frozen() {
        let document = openapi_document();
        super::validate_openapi_handoff_http_contract(&document)
            .expect("handoff HTTP contract must remain frozen");
        super::validate_openapi_handoff_metadata(&document)
            .expect("handoff metadata must remain frozen");
    }

    #[test]
    fn v42_catalog_v2_reviewer_repair_caps_get_truth_and_idempotency_are_frozen() {
        assert_eq!(super::MAX_SIGNED_CATALOG_HEAD_BYTES, 466);
        assert_eq!(super::MAX_CATALOG_UPLOAD_BODY_BYTES, 1_049_050);
        assert_eq!(super::MAX_PROVIDER_PACKAGE_BYTES, 1_049_457);
        assert_eq!(super::MAX_HPKE_CIPHERTEXT_BYTES, 1_049_473);
        assert_eq!(super::MAX_HPKE_ENCODED_ENVELOPE_BYTES, 1_049_517);
        assert_eq!(super::MAX_PROVIDER_RESPONSE_BODY_BYTES, 1_050_929);
        assert_eq!(super::MAX_STATUS_BODY_BYTES, 1_050_986);
        assert_eq!(super::MAX_DEVICE_ADD_BYTES, 533);
        assert_eq!(super::MAX_ENVELOPE_BYTES, 1_065_984);
        assert_eq!(
            super::MAX_SIGNED_CATALOG_HEAD_BYTES,
            1 + 16 + 449,
            "signed head is map header + sixteen one-byte keys + values"
        );
        assert_eq!(
            super::MAX_CATALOG_UPLOAD_BODY_BYTES,
            3 + super::MAX_SIGNED_CATALOG_HEAD_BYTES + 5 + super::MAX_CIPHERTEXT_BYTES,
            "upload is map/key bytes + raw signed head + encoded ciphertext bstr"
        );
        assert_eq!(
            super::MAX_PROVIDER_PACKAGE_BYTES,
            18 + 1
                + 38
                + 34
                + 3
                + super::MAX_SIGNED_CATALOG_HEAD_BYTES
                + 5
                + super::MAX_CIPHERTEXT_BYTES
                + 59
                + 38
                + 9
                + 38
                + 34
                + 9
                + 34
                + 9
                + 34
                + 34
                + 18,
            "provider package arithmetic must include both nested bstr headers"
        );
        assert_eq!(
            super::MAX_HPKE_CIPHERTEXT_BYTES,
            super::MAX_PROVIDER_PACKAGE_BYTES + 16
        );
        assert_eq!(
            super::MAX_HPKE_ENCODED_ENVELOPE_BYTES,
            1 + 2 + 35 + 1 + 5 + super::MAX_HPKE_CIPHERTEXT_BYTES
        );
        assert_eq!(
            super::MAX_PROVIDER_RESPONSE_BODY_BYTES,
            31 + 1
                + 38
                + 34
                + 59
                + 38
                + 9
                + 34
                + 38
                + 34
                + 9
                + 34
                + 9
                + 34
                + 34
                + 77
                + 77
                + 136
                + 18
                + 132
                + 3
                + super::MAX_DEVICE_ADD_BYTES
                + super::MAX_HPKE_ENCODED_ENVELOPE_BYTES,
            "provider response arithmetic must include map/key and DeviceAdd bstr headers"
        );
        assert_eq!(
            super::MAX_STATUS_BODY_BYTES,
            super::MAX_PROVIDER_RESPONSE_BODY_BYTES + 57
        );

        let document = openapi_document();
        let responses = document
            .pointer(&format!("{}/responses", super::STATUS_OPERATION))
            .and_then(Value::as_object)
            .expect("status responses must be an object");
        assert_eq!(
            responses.keys().map(String::as_str).collect::<Vec<_>>(),
            ["200", "401", "406"]
        );
        assert_eq!(
            document.pointer("/components/parameters/IdempotencyKey/schema/pattern"),
            Some(&json!("^[A-Za-z0-9_-]{16,128}$"))
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the exhaustive maximum-object matrix keeps all dependent protocol ceilings together"
    )]
    fn v42_catalog_v2_actual_max_objects_match_every_dependent_ceiling() {
        use dtx_wire::CanonicalValue::{Bytes, Map, Null, Text, Unsigned};

        let entry = |key, value| (Unsigned(key), value);
        let uuid = || Text("0".repeat(36));
        let identity = || Text("a".repeat(57));
        let digest = || Bytes(vec![0; 32]);
        let signature = || Bytes(vec![0; 64]);
        let maximum = || Unsigned(9_007_199_254_740_991);
        let highwater = || Unsigned(9_007_199_254_740_990);
        let encode = |value: &dtx_wire::CanonicalValue| {
            dtx_wire::encode_deterministic_cbor_with_limit(value, 2_000_000)
                .expect("maximum Catalog object must encode canonically")
        };
        let cddl = cddl();

        let signed_head = Map(vec![
            entry(1, Unsigned(2)),
            entry(2, uuid()),
            entry(3, identity()),
            entry(4, maximum()),
            entry(5, digest()),
            entry(6, Unsigned(1_023)),
            entry(7, digest()),
            entry(8, digest()),
            entry(9, maximum()),
            entry(10, digest()),
            entry(11, uuid()),
            entry(12, uuid()),
            entry(13, digest()),
            entry(14, maximum()),
            entry(15, maximum()),
            entry(16, signature()),
        ]);
        let signed_head_exact = encode(&signed_head);
        assert_eq!(
            signed_head_exact.len(),
            super::MAX_SIGNED_CATALOG_HEAD_BYTES
        );
        cddl_cat::validate_cbor_bytes("recovery-scope-catalog-head-v2", &cddl, &signed_head_exact)
            .expect("actual maximum signed head must satisfy its closed CDDL map");

        let upload = Map(vec![
            entry(1, signed_head.clone()),
            entry(2, Bytes(vec![0; super::MAX_CIPHERTEXT_BYTES])),
        ]);
        let upload_exact = encode(&upload);
        assert_eq!(upload_exact.len(), super::MAX_CATALOG_UPLOAD_BODY_BYTES);
        assert!(upload_exact.len() < super::MAX_ENVELOPE_BYTES);
        cddl_cat::validate_cbor_bytes("recovery-scope-catalog-upload-v2", &cddl, &upload_exact)
            .expect("actual maximum upload must satisfy its closed CDDL map");

        let provider_package = Map(vec![
            entry(1, Unsigned(2)),
            entry(2, uuid()),
            entry(3, digest()),
            entry(4, Bytes(signed_head_exact)),
            entry(5, Bytes(vec![0; super::MAX_CIPHERTEXT_BYTES])),
            entry(6, identity()),
            entry(7, uuid()),
            entry(8, maximum()),
            entry(9, uuid()),
            entry(10, digest()),
            entry(11, highwater()),
            entry(12, digest()),
            entry(13, maximum()),
            entry(14, digest()),
            entry(15, digest()),
            entry(16, maximum()),
            entry(17, maximum()),
        ]);
        let provider_package_exact = encode(&provider_package);
        assert_eq!(
            provider_package_exact.len(),
            super::MAX_PROVIDER_PACKAGE_BYTES
        );
        cddl_cat::validate_cbor_bytes(
            "recovery-scope-catalog-provider-package-v2",
            &cddl,
            &provider_package_exact,
        )
        .expect("actual maximum provider package must satisfy its closed CDDL map");

        let hpke_ciphertext = Bytes(vec![0; super::MAX_HPKE_CIPHERTEXT_BYTES]);
        let hpke_ciphertext_exact = encode(&hpke_ciphertext);
        assert_eq!(
            hpke_ciphertext_exact.len(),
            super::MAX_HPKE_CIPHERTEXT_BYTES + 5
        );
        cddl_cat::validate_cbor_bytes("hpke-ciphertext-v2", &cddl, &hpke_ciphertext_exact)
            .expect("actual maximum HPKE ciphertext must satisfy its CDDL bound");

        let hpke_envelope = Map(vec![
            entry(1, Unsigned(2)),
            entry(2, digest()),
            entry(3, hpke_ciphertext),
        ]);
        let hpke_envelope_exact = encode(&hpke_envelope);
        assert_eq!(
            hpke_envelope_exact.len(),
            super::MAX_HPKE_ENCODED_ENVELOPE_BYTES
        );
        cddl_cat::validate_cbor_bytes(
            "recovery-scope-catalog-hpke-envelope-v2",
            &cddl,
            &hpke_envelope_exact,
        )
        .expect("actual maximum HPKE envelope must satisfy its closed CDDL map");

        let provider_descriptor = Map(vec![
            entry(1, Unsigned(2)),
            entry(2, uuid()),
            entry(3, digest()),
        ]);
        let independent_authority = Map(vec![
            entry(1, Unsigned(1)),
            entry(2, uuid()),
            entry(3, digest()),
        ]);
        let provider_response = Map(vec![
            entry(1, Unsigned(2)),
            entry(2, uuid()),
            entry(3, digest()),
            entry(4, identity()),
            entry(5, uuid()),
            entry(6, maximum()),
            entry(7, digest()),
            entry(8, uuid()),
            entry(9, digest()),
            entry(10, highwater()),
            entry(11, digest()),
            entry(12, maximum()),
            entry(13, digest()),
            entry(14, digest()),
            entry(15, provider_descriptor),
            entry(16, independent_authority),
            entry(17, digest()),
            entry(18, digest()),
            entry(19, digest()),
            entry(20, digest()),
            entry(21, maximum()),
            entry(22, maximum()),
            entry(23, signature()),
            entry(24, signature()),
            entry(25, Bytes(vec![0; super::MAX_DEVICE_ADD_BYTES])),
            entry(26, hpke_envelope),
        ]);
        let provider_response_exact = encode(&provider_response);
        assert_eq!(
            provider_response_exact.len(),
            super::MAX_PROVIDER_RESPONSE_BODY_BYTES
        );
        cddl_cat::validate_cbor_bytes(
            "recovery-scope-catalog-provider-response-v2",
            &cddl,
            &provider_response_exact,
        )
        .expect("actual maximum provider response must satisfy its closed CDDL map");

        let ready_status = Map(vec![
            entry(1, Unsigned(2)),
            entry(2, uuid()),
            entry(3, Unsigned(2)),
            entry(4, provider_response),
            entry(5, Null),
            entry(6, maximum()),
        ]);
        let ready_status_exact = encode(&ready_status);
        assert_eq!(ready_status_exact.len(), super::MAX_STATUS_BODY_BYTES);
        cddl_cat::validate_cbor_bytes(
            "recovery-scope-catalog-status-ready-v2",
            &cddl,
            &ready_status_exact,
        )
        .expect("actual maximum ready status must satisfy its closed CDDL map");
    }

    #[test]
    fn v42_catalog_v2_reviewer_repair_exact_size_boundaries_reject_max_plus_one() {
        fn encoded_bstr(length: usize) -> Vec<u8> {
            let length = u32::try_from(length).expect("boundary length must fit u32");
            let mut encoded = Vec::with_capacity(length as usize + 5);
            encoded.push(0x5a);
            encoded.extend_from_slice(&length.to_be_bytes());
            encoded.resize(length as usize + 5, 0);
            encoded
        }

        let cddl = cddl();
        for (rule, maximum) in [
            (
                "exact-signed-catalog-head-v2",
                super::MAX_SIGNED_CATALOG_HEAD_BYTES,
            ),
            (
                "exact-provider-package-v2",
                super::MAX_PROVIDER_PACKAGE_BYTES,
            ),
            ("hpke-ciphertext-v2", super::MAX_HPKE_CIPHERTEXT_BYTES),
            (
                "exact-hpke-envelope-v2",
                super::MAX_HPKE_ENCODED_ENVELOPE_BYTES,
            ),
            (
                "exact-provider-response-v2",
                super::MAX_PROVIDER_RESPONSE_BODY_BYTES,
            ),
            ("exact-ready-status-v2", super::MAX_STATUS_BODY_BYTES),
        ] {
            cddl_cat::validate_cbor_bytes(rule, &cddl, &encoded_bstr(maximum))
                .unwrap_or_else(|error| panic!("{rule} must accept exact maximum: {error}"));
            assert!(
                cddl_cat::validate_cbor_bytes(rule, &cddl, &encoded_bstr(maximum + 1)).is_err(),
                "{rule} must reject max+1"
            );
        }
    }

    #[test]
    fn v42_catalog_v2_reviewer_repair_vector_metadata_rejects_limit_and_domain_drift() {
        let original = vector();
        for limit in [
            "catalog_plaintext_ceiling_bytes",
            "index_occurrences_per_opening",
            "indices_24_through_255_count",
            "indices_24_through_255_extra_bytes_per_opening",
            "indices_256_plus_extra_bytes_per_opening",
            "indices_256_through_1023_count",
            "max_catalog_upload_body_bytes",
            "max_ciphertext_bytes",
            "max_envelope_bytes",
            "max_provider_package_bytes",
            "max_hpke_ciphertext_bytes",
            "max_hpke_encoded_envelope_bytes",
            "max_leaf_count",
            "max_leaf_count_minimum_bytes",
            "max_leaf_count_plus_one",
            "max_leaf_count_plus_one_minimum_bytes",
            "max_proof_siblings",
            "max_device_add_bytes",
            "max_provider_response_body_bytes",
            "max_signed_catalog_head_bytes",
            "max_status_body_bytes",
            "minimum_outer_plaintext_overhead_bytes",
            "minimum_valid_opening_bytes",
            "one_byte_index_maximum",
            "two_byte_index_maximum",
        ] {
            let pointer = format!("/limits/{limit}");
            let current = original
                .pointer(&pointer)
                .and_then(Value::as_u64)
                .expect("frozen limit must be an integer");
            let mut mutated = original.clone();
            replace_openapi_value(&mut mutated, &pointer, json!(current + 1));
            assert!(
                super::validate_vector_metadata(&mutated, &cddl(), &openapi()).is_err(),
                "vector metadata must reject {limit} max+1"
            );
        }
        let mut consecutive_indices = original.clone();
        replace_openapi_value(
            &mut consecutive_indices,
            "/limits/consecutive_one_based_indices_required",
            json!(false),
        );
        assert!(
            super::validate_vector_metadata(&consecutive_indices, &cddl(), &openapi()).is_err()
        );
        let mut classification = original.clone();
        replace_openapi_value(
            &mut classification,
            "/limits/count_boundary_classification",
            json!("full_crypto_fixture"),
        );
        assert!(super::validate_vector_metadata(&classification, &cddl(), &openapi()).is_err());
        let mut domain = original.clone();
        replace_openapi_value(
            &mut domain,
            "/domains/identity_device_add",
            json!("dirextalk.identity-log-event.v1\0"),
        );
        assert!(super::validate_vector_metadata(&domain, &cddl(), &openapi()).is_err());
        let mut opening_domain = original;
        replace_openapi_value(
            &mut opening_domain,
            "/domains/opening",
            json!("dirextalk.recovery-scope-catalog-opening.v2"),
        );
        assert!(super::validate_vector_metadata(&opening_domain, &cddl(), &openapi()).is_err());
    }

    #[test]
    fn v42_catalog_v2_final_hidden_verifier_privacy_boundary_is_frozen() {
        let document = openapi_document();
        assert_eq!(
            document.pointer("/x-dirextalk-handoff-currentness/hidden-verifier-currentness"),
            Some(&json!(
                "candidate-only-never-server-admission-cas-replay-or-status"
            ))
        );
        for operation in [
            super::PREPARATION_OPERATION,
            super::PROVIDER_RESPONSE_OPERATION,
        ] {
            let fences = document
                .pointer(&format!(
                    "{operation}/x-dirextalk-cas-transaction/final-predicate-fences"
                ))
                .and_then(Value::as_array)
                .expect("final CAS fences must be arrays");
            assert!(
                fences
                    .iter()
                    .all(|fence| !fence.as_str().is_some_and(|text| text.contains("verifier"))),
                "server CAS must not fence hidden verifier tuples"
            );
        }

        let mut server_tuple = document.clone();
        server_tuple
            .pointer_mut("/x-dirextalk-handoff-currentness")
            .and_then(Value::as_object_mut)
            .expect("handoff currentness must be mutable")
            .insert("server-visible-verifier-tuple".to_owned(), json!(true));
        assert_openapi_document_rejected("server-visible hidden verifier tuple", &server_tuple);

        for (label, pointer, replacement) in [
            (
                "server verifier invalidation drift",
                "/x-dirextalk-handoff-currentness/server-visible-invalidation-drift/1".to_owned(),
                json!("verifier"),
            ),
            (
                "server direct verifier status",
                format!(
                    "{}/x-dirextalk-currentness/hidden-verifier-status",
                    super::STATUS_OPERATION
                ),
                json!("direct-hidden-tuple-comparison"),
            ),
            (
                "server may observe verifier tuple",
                "/x-dirextalk-handoff-equality-validity/identity-server-validation/never/3"
                    .to_owned(),
                json!("observe-completion-verifier-origin-key-epoch-descriptor"),
            ),
        ] {
            let mut mutated = document.clone();
            replace_openapi_value(&mut mutated, &pointer, replacement);
            assert_openapi_document_rejected(label, &mutated);
        }
        for operation in [
            super::PREPARATION_OPERATION,
            super::PROVIDER_RESPONSE_OPERATION,
        ] {
            let mut mutated = document.clone();
            replace_openapi_value(
                &mut mutated,
                &format!("{operation}/x-dirextalk-cas-transaction/final-predicate-fences/3"),
                json!("catalog-head-and-all-verifier-tuples-with-rotation-epochs"),
            );
            assert_openapi_document_rejected("server CAS verifier tuple reintroduction", &mutated);
        }
    }

    #[test]
    fn v42_catalog_v2_final_hpke_raw_canonical_aad_boundary_is_frozen() {
        let document = openapi_document();
        assert_eq!(
            document.pointer("/x-dirextalk-handoff-hpke/aad-input"),
            Some(&json!(
                "exact-deterministic-canonical-cbor-bytes-of-recovery-scope-catalog-provider-public-aad-v2"
            ))
        );
        assert_eq!(
            vector().pointer("/hpke_aad/input"),
            Some(&json!("exact_deterministic_canonical_cbor_bytes"))
        );

        for forbidden in [
            "response-field-18-digest",
            "provider-aad-domain-prefixed",
            "json",
            "hex",
            "alternate-cbor-encoding",
        ] {
            let mut mutated = document.clone();
            replace_openapi_value(
                &mut mutated,
                "/x-dirextalk-handoff-hpke/aad-input",
                json!(forbidden),
            );
            assert_openapi_document_rejected(
                &format!("HPKE aad must reject {forbidden}"),
                &mutated,
            );
        }
        for (pointer, replacement) in [
            (
                "/x-dirextalk-handoff-hpke/public-aad-cddl-rule",
                json!("recovery-scope-catalog-provider-aad-v2"),
            ),
            (
                "/x-dirextalk-handoff-hpke/deterministic-hpke-vector-required-in",
                json!("optional"),
            ),
        ] {
            let mut mutated = document.clone();
            replace_openapi_value(&mut mutated, pointer, replacement);
            assert_openapi_document_rejected("HPKE aad metadata drift", &mutated);
        }

        for forbidden in [
            "response_field_18_digest",
            "provider_aad_domain_prefixed",
            "json",
            "hex",
            "alternate_cbor_encoding",
        ] {
            let mut mutated = vector();
            replace_openapi_value(&mut mutated, "/hpke_aad/input", json!(forbidden));
            assert!(
                super::validate_vector_metadata(&mutated, &cddl(), &openapi()).is_err(),
                "vector HPKE aad must reject {forbidden}"
            );
        }
        for (pointer, replacement) in [
            (
                "/hpke_aad/cddl_rule",
                json!("recovery-scope-catalog-provider-aad-v2"),
            ),
            (
                "/hpke_aad/deterministic_vector_required_in",
                json!("optional"),
            ),
        ] {
            let mut mutated = vector();
            replace_openapi_value(&mut mutated, pointer, replacement);
            assert!(super::validate_vector_metadata(&mutated, &cddl(), &openapi()).is_err());
        }
    }

    #[test]
    fn v42_catalog_v2_c1bb_positive_handoff_fixture_is_present() {
        let handoff = vector()
            .get("handoff")
            .cloned()
            .expect("C1b-B1 must freeze one complete deterministic handoff fixture");
        assert_eq!(
            handoff.pointer("/test_only_inputs/classification"),
            Some(&json!("public-deterministic-test-fixture-not-a-credential"))
        );
        assert!(handoff.pointer("/preparation/cbor_hex").is_some());
        assert!(handoff.pointer("/hpke_envelope/cbor_hex").is_some());
        assert!(handoff.pointer("/provider_response/cbor_hex").is_some());
        assert!(handoff.pointer("/statuses/ready/cbor_hex").is_some());
    }

    #[test]
    fn v42_catalog_v2_c1bb_positive_bytes_and_crypto_are_independently_derived() {
        let value = vector();
        let cddl = cddl();
        let (catalog, server) = positive_handoff(&value);
        super::validate_candidate_handoff(&value, &cddl, &server, &catalog)
            .expect("candidate must open and validate the exact positive package");
        assert_eq!(server.preparation_exact.len(), 517);
        assert_eq!(server.device_add_exact.len(), 526);
        assert_eq!(server.envelope_exact.len(), 4_479);
        assert_eq!(server.provider_response_exact.len(), 5_862);
        assert_eq!(server.status_exact[1].len(), 5_919);
    }

    #[test]
    fn v42_catalog_v2_c1bb_server_visible_projection_never_decrypts() {
        let original = vector();
        let (catalog, server) = positive_handoff(&original);
        let mut wrong_private = original.clone();
        replace_openapi_value(
            &mut wrong_private,
            "/handoff/test_only_inputs/x25519_recipient_private_key_hex",
            json!("00"),
        );
        validate_server_handoff(&wrong_private)
            .expect("server-visible admission must not parse or use candidate private material");
        assert!(
            super::validate_candidate_handoff(&wrong_private, &cddl(), &server, &catalog).is_err()
        );

        let source = include_str!("recovery_scope_catalog_v2.rs");
        let declaration = source
            .split("struct ServerVisibleHandoffFacts")
            .nth(1)
            .expect("typed server-visible facts declaration")
            .split("}\n")
            .next()
            .expect("typed declaration end");
        for forbidden in ["private_key", "package_exact", "plaintext", "verifier"] {
            assert!(
                !declaration.contains(forbidden),
                "server-visible type must not contain {forbidden}"
            );
        }
    }

    #[test]
    fn v42_catalog_v2_c1bb_hpke_uses_exact_raw_aad_and_info() {
        use hpke::{Deserializable as _, OpModeR};

        type Kem = hpke::kem::X25519HkdfSha256;
        type Aead = hpke::aead::ChaCha20Poly1305;
        type Kdf = hpke::kdf::HkdfSha256;

        let value = vector();
        let (catalog, server) = positive_handoff(&value);
        super::validate_candidate_handoff(&value, &cddl(), &server, &catalog)
            .expect("exact raw AAD and NUL-terminated info must open");

        let mut prefixed_aad = server.clone();
        let mut bytes = super::PROVIDER_AAD_DOMAIN.to_vec();
        bytes.extend_from_slice(&prefixed_aad.public_aad_exact);
        prefixed_aad.public_aad_exact = bytes;
        assert!(
            super::validate_candidate_handoff(&value, &cddl(), &prefixed_aad, &catalog).is_err(),
            "domain-prefixed AAD must not open"
        );

        let mut altered_raw_aad = server.clone();
        altered_raw_aad.public_aad_exact[0] ^= 1;
        assert!(
            super::validate_candidate_handoff(&value, &cddl(), &altered_raw_aad, &catalog).is_err(),
            "alternate raw AAD bytes must not open"
        );

        let private = super::decode_json_fixed::<32>(
            value
                .pointer("/handoff/test_only_inputs")
                .expect("test-only inputs"),
            "x25519_recipient_private_key_hex",
        )
        .expect("candidate private test input");
        let private_key =
            <Kem as hpke::Kem>::PrivateKey::from_bytes(&private).expect("candidate private key");
        let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(&server.envelope_enc)
            .expect("exact encapped key");
        let mut wrong_info = hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &private_key,
            &encapped,
            b"dirextalk.recovery-scope-catalog-handoff-hpke.v2",
        )
        .expect("well-formed alternate-info receiver context");
        assert!(
            wrong_info
                .open(&server.envelope_ciphertext, &server.public_aad_exact)
                .is_err(),
            "missing-NUL HPKE info must not open"
        );
    }

    #[test]
    fn v42_catalog_v2_c1bb_identity_log_v1_1_transition_is_current() {
        let original = vector();
        let (_catalog, server) = positive_handoff(&original);
        assert_eq!(
            server.identity_log.at_h_plus_1.sequence,
            server.identity_log.at_h.sequence + 1
        );
        let event =
            dtx_identity_log::IdentityLogEventV1::decode_and_verify(&server.device_add_exact)
                .expect("exact DeviceAdd must verify");
        assert_eq!(event.wire(), dtx_identity_log::IDENTITY_LOG_WIRE_VERSION);
        assert_eq!(
            event.entry_hash().expect("event hash").as_bytes(),
            &server.identity_log.at_h_plus_1.head_digest
        );

        let mut drifted = original;
        replace_openapi_value(
            &mut drifted,
            "/handoff/origin_authenticated_identity_log/at_h_plus_1/head_digest_hex",
            json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        );
        assert!(validate_server_handoff(&drifted).is_err());
    }

    #[test]
    fn v42_catalog_v2_c1bb_h_plus_1_is_exact_device_add_reduction() {
        let original = vector();
        let response_before = original
            .pointer("/handoff/provider_response/cbor_hex")
            .cloned();
        let receipt_before = original
            .pointer("/handoff/mutation_receipts/provider_response/cbor_hex")
            .cloned();
        let assert_rejected = |drifted: &Value, label: &str| {
            assert_eq!(
                drifted.pointer("/handoff/provider_response/cbor_hex"),
                response_before.as_ref(),
                "{label} must not rewrite portable response bytes"
            );
            assert_eq!(
                drifted.pointer("/handoff/mutation_receipts/provider_response/cbor_hex"),
                receipt_before.as_ref(),
                "{label} must not rewrite the immutable receipt"
            );
            assert!(
                validate_server_handoff(drifted).is_err(),
                "{label} must fail origin-authenticated first admission/currentness"
            );
        };
        for (label, index) in [
            ("provider removed only at H+1", 0),
            ("authority removed only at H+1", 1),
        ] {
            let mut drifted = original.clone();
            drifted
                .pointer_mut(
                    "/handoff/origin_authenticated_identity_log/at_h_plus_1/active_devices",
                )
                .and_then(Value::as_array_mut)
                .expect("H+1 active devices")
                .remove(index);
            assert_rejected(&drifted, label);
        }
        for (label, pointer, replacement) in [
            (
                "provider rekeyed only at H+1",
                "/handoff/origin_authenticated_identity_log/at_h_plus_1/active_devices/0/signing_public_key_hex",
                json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
            ),
            (
                "authority rekeyed only at H+1",
                "/handoff/origin_authenticated_identity_log/at_h_plus_1/active_devices/1/signing_public_key_hex",
                json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
            ),
        ] {
            let mut drifted = original.clone();
            replace_openapi_value(&mut drifted, pointer, replacement);
            assert_rejected(&drifted, label);
        }
        let mut extra = original;
        extra
            .pointer_mut(
                "/handoff/origin_authenticated_identity_log/at_h_plus_1/active_devices",
            )
            .and_then(Value::as_array_mut)
            .expect("H+1 active devices")
            .push(json!({
                "device_id": "0190f2a5-7b1c-7abc-8def-0123456789d5",
                "encryption_public_key_hex": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "signing_public_key_hex": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
            }));
        assert_rejected(&extra, "unrelated extra mutation only at H+1");
    }

    #[test]
    fn v42_catalog_v2_c1bb_candidate_uses_independent_verifier_oracle() {
        let original = vector();
        assert_eq!(
            original
                .pointer("/origin_authenticated_completion_verifier_descriptors/classification"),
            Some(&json!(
                "trusted-origin-authenticated-completion-verifier-test-oracle-not-portable-wire-proof"
            ))
        );
        let response_before = original
            .pointer("/handoff/provider_response/cbor_hex")
            .cloned();
        let receipt_before = original
            .pointer("/handoff/mutation_receipts/provider_response/cbor_hex")
            .cloned();
        let status_before = original
            .pointer("/handoff/statuses/ready/cbor_hex")
            .cloned();
        let (catalog, server) = positive_handoff(&original);
        for (label, pointer, replacement) in [
            (
                "origin mismatch",
                "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/origin",
                json!("https://other.example.test"),
            ),
            (
                "key id rotation",
                "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/key_id",
                json!("0190f2a5-7b1c-7abc-8def-0123456789c2"),
            ),
            (
                "public key rotation",
                "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/public_key_hex",
                json!("2012cb90ca60e8e5d8daf66e2272d2233e0486d557e8c66141ed8920177d7eb7"),
            ),
            (
                "epoch rotation",
                "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/epoch",
                json!(5),
            ),
            (
                "descriptor digest rotation",
                "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/descriptor_digest_hex",
                json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
            ),
            (
                "stale descriptor validity",
                "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/expires_at",
                json!(1_701_003_500_000_u64),
            ),
            (
                "descriptor signature substitution",
                "/origin_authenticated_completion_verifier_descriptors/by_origin/https:~1~1recovery.example.test/signature_hex",
                json!("00".repeat(64)),
            ),
        ] {
            let mut drifted = original.clone();
            replace_openapi_value(&mut drifted, pointer, replacement);
            assert_eq!(
                drifted
                    .pointer("/handoff/provider_response/cbor_hex")
                    .cloned(),
                response_before,
                "{label} must not rewrite portable response bytes"
            );
            assert_eq!(
                drifted
                    .pointer("/handoff/mutation_receipts/provider_response/cbor_hex")
                    .cloned(),
                receipt_before,
                "{label} must not rewrite the immutable server receipt"
            );
            assert_eq!(
                drifted.pointer("/handoff/statuses/ready/cbor_hex").cloned(),
                status_before,
                "{label} must not rewrite server status"
            );
            validate_server_handoff(&drifted)
                .unwrap_or_else(|error| panic!("server must not observe {label}: {error}"));
            assert!(
                super::validate_candidate_handoff(&drifted, &cddl(), &server, &catalog).is_err(),
                "candidate must reject {label} against the trusted nonportable oracle"
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "exact destructuring and private-mutation checks freeze one closed server projection boundary"
    )]
    fn v42_catalog_v2_c1bb_server_catalog_projection_type_is_closed() {
        let projection = super::validate_catalog_server_projection(&vector(), &cddl())
            .expect("server projection must derive from signed public bytes");
        let super::CatalogServerProjection {
            signed_head_exact,
            signed_head_digest,
            identity_id,
            catalog_id,
            generation,
            previous_head_digest,
            leaf_count,
            merkle_root,
            identity_sequence,
            identity_head_digest,
            authority_device_id,
            authority_key_id,
            authority_public_key,
            head_issued_at,
            head_expires_at,
            validation_time,
            ciphertext,
            ciphertext_digest,
        } = projection;
        assert!(!signed_head_exact.is_empty());
        assert_ne!(signed_head_digest, [0; 32]);
        assert!(!identity_id.is_empty() && !catalog_id.is_empty());
        assert!(generation > 0 && leaf_count > 0 && identity_sequence > 0);
        assert_ne!(previous_head_digest, [0; 32]);
        assert_ne!(merkle_root, [0; 32]);
        assert_ne!(identity_head_digest, [0; 32]);
        assert!(!authority_device_id.is_empty() && !authority_key_id.is_empty());
        assert_ne!(authority_public_key, [0; 32]);
        assert!(head_issued_at <= validation_time && validation_time < head_expires_at);
        assert!(!ciphertext.is_empty() && ciphertext_digest != [0; 32]);

        let input = super::parse_server_visible_handoff_input(&vector())
            .expect("server-visible handoff input must parse");
        let super::ServerVisibleHandoffInput {
            preparation,
            origin_authenticated_identity_log,
            device_add,
            provider_response,
            public_aad,
            hpke_envelope,
            mutation_receipts,
            statuses,
            enrollment_candidate_recipient_public_key,
            response_capability,
            preparation_idempotency_key,
            response_idempotency_key,
        } = input;
        for public_state in [
            preparation,
            origin_authenticated_identity_log,
            device_add,
            provider_response,
            public_aad,
            hpke_envelope,
            mutation_receipts,
            statuses,
        ] {
            assert!(public_state.is_object());
        }
        assert_ne!(enrollment_candidate_recipient_public_key, [0; 32]);
        assert_ne!(response_capability, [0; 32]);
        assert!(!preparation_idempotency_key.is_empty());
        assert!(!response_idempotency_key.is_empty());

        let source = include_str!("recovery_scope_catalog_v2.rs");
        let declaration = source
            .split("struct CatalogServerProjection")
            .nth(1)
            .expect("dedicated Catalog server projection declaration")
            .split("}\n")
            .next()
            .expect("Catalog server projection declaration end");
        for forbidden in [
            "plaintext",
            "opening",
            "scope",
            "verifier",
            "private_key",
            "package",
        ] {
            assert!(
                !declaration.contains(forbidden),
                "Catalog server projection must not contain {forbidden}"
            );
        }
        let pipeline = source
            .split("fn validate_catalog_vector")
            .nth(1)
            .expect("Catalog validation pipeline")
            .split("fn read_catalog_vector")
            .next()
            .expect("pipeline end");
        let server = pipeline
            .find("validate_server_visible_handoff")
            .expect("server validation in pipeline");
        let private = pipeline
            .find("validate_positive_vector")
            .expect("candidate-private validation in pipeline");
        assert!(
            server < private,
            "server admission must complete before candidate-private Catalog validation"
        );

        let original = vector();
        for (pointer, replacement) in [
            ("/catalog/plaintext_cbor_hex", json!("00")),
            ("/catalog/openings", json!({"hidden": true})),
            (
                "/catalog/verifier_descriptor/origin",
                json!("not-a-canonical-origin"),
            ),
            ("/handoff/package/cbor_hex", json!("00")),
            (
                "/handoff/test_only_inputs/x25519_recipient_private_key_hex",
                json!("00"),
            ),
            (
                "/origin_authenticated_completion_verifier_descriptors/classification",
                json!("not-trusted"),
            ),
        ] {
            let mut private_drift = original.clone();
            replace_openapi_value(&mut private_drift, pointer, replacement);
            validate_server_handoff(&private_drift).unwrap_or_else(|error| {
                panic!("server projection accessed candidate-private {pointer}: {error}")
            });
        }
    }

    #[test]
    fn v42_catalog_v2_c1bb_receipts_statuses_and_read_only_drift_are_exact() {
        let original = vector();
        let response_before = original
            .pointer("/handoff/provider_response/cbor_hex")
            .cloned();
        let receipt_before = original
            .pointer("/handoff/mutation_receipts/provider_response/cbor_hex")
            .cloned();
        let (_catalog, server) = positive_handoff(&original);
        assert_eq!(server.status_exact.len(), 5);
        assert_ne!(
            server.preparation_receipt_exact,
            server.provider_response_receipt_exact
        );

        let mut drifted = original;
        replace_openapi_value(
            &mut drifted,
            "/handoff/origin_authenticated_identity_log/at_h/active_devices/0/signing_public_key_hex",
            json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        );
        assert_eq!(
            drifted
                .pointer("/handoff/provider_response/cbor_hex")
                .cloned(),
            response_before
        );
        assert_eq!(
            drifted
                .pointer("/handoff/mutation_receipts/provider_response/cbor_hex")
                .cloned(),
            receipt_before
        );
        assert!(
            validate_server_handoff(&drifted).is_err(),
            "origin currentness drift must affect admission/GET without rewriting portable bytes"
        );
    }

    #[test]
    fn v42_catalog_v2_c1bb_json_labels_are_assertions_not_trusted_inputs() {
        let original = vector();
        let (catalog, server) = positive_handoff(&original);
        let mut package_label = original.clone();
        replace_openapi_value(
            &mut package_label,
            "/handoff/package/digest_hex",
            json!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
        );
        assert!(
            super::validate_candidate_handoff(&package_label, &cddl(), &server, &catalog).is_err(),
            "candidate must derive rather than trust the package digest label"
        );

        let mut preparation_label = original;
        replace_openapi_value(
            &mut preparation_label,
            "/handoff/preparation/signature_hex",
            json!("00"),
        );
        assert!(
            validate_server_handoff(&preparation_label).is_err(),
            "server must derive rather than trust the preparation signature label"
        );
    }

    #[test]
    fn v42_catalog_v2_c1b_b2a_all_authority_modes_are_full_crypto() {
        let value = vector();
        let cddl = cddl();
        let projection = super::validate_catalog_server_projection(&value, &cddl)
            .expect("Catalog projection must validate");
        let (catalog, base) = positive_handoff(&value);
        super::validate_handoff_authority_variants(&value, &cddl, &projection, &base, &catalog)
            .expect(
                "current-root and current-recovery must each pass full server and candidate crypto",
            );

        let mut drifted = value.clone();
        let base_response = value
            .pointer("/handoff/provider_response/cbor_hex")
            .cloned()
            .expect("base provider response");
        replace_openapi_value(
            &mut drifted,
            "/handoff_authority_variants/current_root/provider_response/cbor_hex",
            base_response,
        );
        assert!(
            super::validate_handoff_authority_variants(
                &drifted,
                &cddl,
                &projection,
                &base,
                &catalog,
            )
            .is_err(),
            "an authority label with stale response bytes must fail full validation"
        );
    }

    #[test]
    fn v42_catalog_v2_c1b_b2a_hpke_alternates_are_independently_valid_then_rejected() {
        let value = vector();
        let (_catalog, base) = positive_handoff(&value);
        super::validate_handoff_hpke_alternates(&value, &cddl(), &base)
            .expect("every alternate HPKE transcript must open itself then fail production inputs");

        let mut drifted = value.clone();
        let base_envelope = value
            .pointer("/handoff/hpke_envelope/cbor_hex")
            .cloned()
            .expect("base HPKE envelope");
        replace_openapi_value(
            &mut drifted,
            "/handoff_alternate_constructions/hpke/missing_nul_info/envelope_cbor_hex",
            base_envelope,
        );
        assert!(
            super::validate_handoff_hpke_alternates(&drifted, &cddl(), &base).is_err(),
            "an alternate label with a production envelope must not count as a crypto proof"
        );
    }

    #[test]
    fn v42_catalog_v2_c1b_b2a_signature_alternates_are_independently_valid_then_rejected() {
        let value = vector();
        let (_catalog, base) = positive_handoff(&value);
        super::validate_handoff_signature_alternates(&value, &cddl(), &base)
            .expect("every alternate signature must verify itself then fail production checks");

        let mut drifted = value.clone();
        let base_response = value
            .pointer("/handoff/provider_response/cbor_hex")
            .cloned()
            .expect("base provider response");
        replace_openapi_value(
            &mut drifted,
            "/handoff_alternate_constructions/provider_response_signatures/wrong_domains/cbor_hex",
            base_response,
        );
        assert!(
            super::validate_handoff_signature_alternates(&drifted, &cddl(), &base).is_err(),
            "a production signature relabeled as an alternate must fail its own-domain proof"
        );
    }

    #[test]
    fn v42_catalog_v2_c1b_b2b_authentic_boundary_families_are_closed() {
        let value = vector();
        let cddl = cddl();
        let projection = super::validate_catalog_server_projection(&value, &cddl)
            .expect("Catalog projection must validate");
        let (catalog, base) = positive_handoff(&value);
        super::validate_handoff_b2b_families(&value, &cddl, &projection, &base, &catalog).expect(
            "all B2b families must prove authentic lower layers and exact target rejection",
        );

        let mut drifted = value;
        replace_openapi_value(
            &mut drifted,
            "/handoff_b2b/classification",
            json!("untrusted"),
        );
        assert!(
            super::validate_handoff_b2b_families(&drifted, &cddl, &projection, &base, &catalog,)
                .is_err(),
            "B2b family labels must not weaken fixture provenance"
        );
    }

    #[test]
    fn v42_catalog_v2_c1b_b2b_cross_bindings_and_hidden_rotation_reject_stale_artifacts() {
        let original = vector();
        let cddl = cddl();
        let projection = super::validate_catalog_server_projection(&original, &cddl)
            .expect("Catalog projection");
        let (catalog, base) = positive_handoff(&original);

        let mut recipient = original.clone();
        let base_recipient = original
            .pointer("/handoff/preparation/recipient_public_key_hex")
            .cloned()
            .expect("base recipient");
        replace_openapi_value(
            &mut recipient,
            "/handoff_b2b/recipient_bindings/alternate_recipient_device_add_mismatch/test_only_inputs/enrollment_candidate_recipient_public_key_hex",
            base_recipient,
        );
        assert!(
            super::validate_b2b_recipient_bindings(
                &recipient,
                &cddl,
                &projection,
                &base,
                &catalog,
                recipient.get("handoff_b2b").expect("B2b"),
            )
            .is_err(),
            "alternate recipient label must not survive a stale enrollment binding"
        );

        let mut sealed = original.clone();
        let base_envelope = original
            .pointer("/handoff/hpke_envelope")
            .cloned()
            .expect("base envelope");
        replace_openapi_value(
            &mut sealed,
            "/handoff_b2b/sealed_package_mismatches/request_coordinate/hpke_envelope",
            base_envelope,
        );
        assert!(
            super::validate_b2b_sealed_package_mismatches(
                &sealed,
                &cddl,
                &projection,
                &base,
                &catalog,
                sealed.get("handoff_b2b").expect("B2b"),
            )
            .is_err(),
            "re-sealed mismatch must reject a stale envelope"
        );

        let mut rotation = original.clone();
        let current_oracle = original
            .get("origin_authenticated_completion_verifier_descriptors")
            .cloned()
            .expect("current oracle");
        replace_openapi_value(
            &mut rotation,
            "/handoff_b2b/verifier_rotation/rotated_origin_authenticated_oracle",
            current_oracle,
        );
        assert!(
            super::validate_b2b_verifier_rotation(
                &rotation,
                &cddl,
                &projection,
                &base,
                &catalog,
                rotation.get("handoff_b2b").expect("B2b"),
            )
            .is_err(),
            "hidden rotation fixture must contain a genuinely different signed descriptor"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "state, GET, and authenticated-currentness mutations form one closed B2b boundary portfolio"
    )]
    fn v42_catalog_v2_c1b_b2b_state_get_and_currentness_traces_fail_closed() {
        let original = vector();
        let cddl = cddl();
        let projection = super::validate_catalog_server_projection(&original, &cddl)
            .expect("Catalog projection");
        let (catalog, base) = positive_handoff(&original);

        let mut state = original.clone();
        replace_openapi_value(
            &mut state,
            "/handoff_b2b/state_idempotency_traces/preparation/trace/1/writes",
            json!(1),
        );
        assert!(
            super::validate_b2b_state_idempotency(
                &state,
                &cddl,
                &projection,
                &base,
                &catalog,
                state.get("handoff_b2b").expect("B2b"),
            )
            .is_err(),
            "exact replay must never acquire a write"
        );

        let mut get = original.clone();
        replace_openapi_value(
            &mut get,
            "/handoff_b2b/get_state_traces/tie_priority",
            json!(["invalidated", "cancelled", "expired"]),
        );
        assert!(
            super::validate_b2b_get_states(
                &get,
                &cddl,
                &base,
                get.get("handoff_b2b").expect("B2b"),
            )
            .is_err(),
            "equal-time terminal selection must stay cancelled-first"
        );

        super::validate_b2b_currentness(
            &original,
            &cddl,
            &projection,
            &base,
            original.get("handoff_b2b").expect("B2b"),
        )
        .expect("authenticated current snapshots must drive all three currentness negatives");

        for (label, pointer, replacement) in [
            (
                "relabeled authority kind",
                "/handoff_b2b/currentness_drifts/authority_kinds/0/kind",
                json!("current_root"),
            ),
            (
                "invalid snapshot head assertion",
                "/handoff_b2b/currentness_drifts/authority_kinds/1/current_identity_snapshot/head_digest_hex",
                json!(super::encode_lower_hex(&[0; 32])),
            ),
            (
                "arbitrary current-key assertion",
                "/handoff_b2b/currentness_drifts/authority_kinds/1/current_identity_snapshot/current_root_public_key_hex",
                json!(super::encode_lower_hex(&base.candidate_signing_public_key)),
            ),
        ] {
            let mut mutation = original.clone();
            replace_openapi_value(&mut mutation, pointer, replacement);
            assert!(
                super::validate_b2b_currentness(
                    &mutation,
                    &cddl,
                    &projection,
                    &base,
                    mutation.get("handoff_b2b").expect("B2b"),
                )
                .is_err(),
                "{label} must not satisfy an authenticated currentness case"
            );
        }

        let mut invalid_signature = original.clone();
        let signed_pointer = "/handoff_b2b/currentness_drifts/authority_kinds/2/current_identity_snapshot/signed_cbor_hex";
        let signature_pointer = "/handoff_b2b/currentness_drifts/authority_kinds/2/current_identity_snapshot/signature_hex";
        let mut signed = super::decode_lower_hex(
            invalid_signature
                .pointer(signed_pointer)
                .and_then(Value::as_str)
                .expect("signed current snapshot"),
        )
        .expect("signed snapshot hex");
        let mut signature = super::decode_lower_hex(
            invalid_signature
                .pointer(signature_pointer)
                .and_then(Value::as_str)
                .expect("current snapshot signature"),
        )
        .expect("snapshot signature hex");
        *signed.last_mut().expect("signed snapshot byte") ^= 1;
        *signature.last_mut().expect("snapshot signature byte") ^= 1;
        replace_openapi_value(
            &mut invalid_signature,
            signed_pointer,
            json!(super::encode_lower_hex(&signed)),
        );
        replace_openapi_value(
            &mut invalid_signature,
            signature_pointer,
            json!(super::encode_lower_hex(&signature)),
        );
        let error = super::validate_b2b_currentness(
            &invalid_signature,
            &cddl,
            &projection,
            &base,
            invalid_signature.get("handoff_b2b").expect("B2b"),
        )
        .expect_err("invalid authenticated-current-snapshot signature must reject");
        assert!(error.to_string().contains("signature invalid"));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "time, decoder, X25519 semantics, privacy, and wire limitations form one closed B2b boundary portfolio"
    )]
    fn v42_catalog_v2_c1b_b2b_time_decoder_privacy_and_limitations_fail_closed() {
        let original = vector();
        let cddl = cddl();
        let projection = super::validate_catalog_server_projection(&original, &cddl)
            .expect("Catalog projection");
        let (catalog, base) = positive_handoff(&original);

        super::validate_b2b_decoder_privacy(
            &original,
            &cddl,
            &projection,
            original.get("handoff_b2b").expect("B2b"),
        )
        .expect("authentic low-order preparations must reach the shared recipient-key seam");
        for encoded in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let key: [u8; 32] = super::decode_lower_hex(encoded)
                .expect("low-order hex")
                .try_into()
                .expect("32-byte low-order encoding");
            let error = super::validate_recipient_public_key_semantics(key)
                .expect_err("every X25519 low-order point must reject");
            assert!(
                error
                    .to_string()
                    .contains("all-zero or low-order X25519 recipient key rejected")
            );
        }
        super::validate_recipient_public_key_semantics(base.candidate_recipient_public_key)
            .expect("base recipient key must pass the production semantic seam");
        let alternate_recipient: [u8; 32] = super::decode_lower_hex(
            original
                .pointer("/handoff_b2b/recipient_bindings/alternate_recipient_device_add_mismatch/preparation/recipient_public_key_hex")
                .and_then(Value::as_str)
                .expect("authentic alternate recipient key"),
        )
        .expect("alternate recipient hex")
        .try_into()
        .expect("32-byte alternate recipient key");
        super::validate_recipient_public_key_semantics(alternate_recipient)
            .expect("authentic alternate recipient key must pass the production semantic seam");

        let all_zero_path =
            "/handoff_b2b/decoder_privacy_closure/low_order_recipient_preparations/all_zero";
        let one_path = "/handoff_b2b/decoder_privacy_closure/low_order_recipient_preparations/u_coordinate_one";
        let all_zero = original
            .pointer(all_zero_path)
            .cloned()
            .expect("all-zero fixture");
        let one = original.pointer(one_path).cloned().expect("u=1 fixture");
        let mut one_key = [0; 32];
        one_key[0] = 1;
        for (name, preparation, recipient_key) in [
            ("all_zero", &all_zero, [0; 32]),
            ("u_coordinate_one", &one, one_key),
        ] {
            let mut input = super::parse_server_visible_handoff_input(&original)
                .expect("base server-visible handoff input");
            input.preparation = preparation.clone();
            input.enrollment_candidate_recipient_public_key = recipient_key;
            let error = super::validate_server_visible_handoff(&cddl, &projection, &input)
                .expect_err("normal preparation admission must reject low-order X25519 keys");
            assert!(
                error
                    .to_string()
                    .contains("all-zero or low-order X25519 recipient key rejected"),
                "{name} did not reach the shared normal-admission recipient semantic seam"
            );
        }
        let mut relabeled = original.clone();
        replace_openapi_value(&mut relabeled, all_zero_path, one);
        replace_openapi_value(&mut relabeled, one_path, all_zero);
        super::validate_b2b_decoder_privacy(
            &relabeled,
            &cddl,
            &projection,
            relabeled.get("handoff_b2b").expect("B2b"),
        )
        .expect("fixture labels must not decide low-order recipient rejection");
        let mut valid_key_under_negative_label = original.clone();
        replace_openapi_value(
            &mut valid_key_under_negative_label,
            all_zero_path,
            original
                .pointer("/handoff/preparation")
                .cloned()
                .expect("base preparation"),
        );
        let error = super::validate_b2b_decoder_privacy(
            &valid_key_under_negative_label,
            &cddl,
            &projection,
            valid_key_under_negative_label
                .get("handoff_b2b")
                .expect("B2b"),
        )
        .expect_err("a valid recipient key must not reject because of a fixture label");
        assert!(
            error
                .to_string()
                .contains("all_zero X25519 recipient was accepted")
        );

        let mut time = original.clone();
        replace_openapi_value(
            &mut time,
            "/handoff_b2b/time_boundaries/preparation/issued_before_catalog/expected_valid",
            json!(true),
        );
        assert!(
            super::validate_b2b_time_boundaries(
                &time,
                &cddl,
                &projection,
                &base,
                &catalog,
                time.get("handoff_b2b").expect("B2b"),
            )
            .is_err(),
            "a re-signed out-of-window preparation must not be relabeled valid"
        );

        let mut decoder = original.clone();
        let canonical = original
            .pointer("/handoff/preparation/cbor_hex")
            .cloned()
            .expect("canonical preparation");
        replace_openapi_value(
            &mut decoder,
            "/handoff_b2b/decoder_privacy_closure/noncanonical_preparation_cbor_hex",
            canonical,
        );
        assert!(
            super::validate_b2b_decoder_privacy(
                &decoder,
                &cddl,
                &projection,
                decoder.get("handoff_b2b").expect("B2b"),
            )
            .is_err(),
            "canonical bytes must not count as a noncanonical decoder negative"
        );

        let mut limitations = original;
        replace_openapi_value(
            &mut limitations,
            "/handoff_b2b/limitations/generic_counter_is_wire",
            json!(true),
        );
        assert!(
            super::validate_b2b_limitations(limitations.get("handoff_b2b").expect("B2b")).is_err(),
            "B2b must not invent a generic counter wire field"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one table-driven mutation portfolio freezes the complete handoff security contract"
    )]
    fn v42_catalog_v2_openapi_rejects_handoff_contract_mutations() {
        let original = openapi_document();
        let mutations = vec![
            ("preparation operation", format!("{}/operationId", super::PREPARATION_OPERATION), json!("driftedOperation")),
            ("preparation authentication", format!("{}/x-dirextalk-authentication/authorization-header", super::PREPARATION_OPERATION), json!("optional")),
            ("candidate protected recipient key", format!("{}/x-dirextalk-path-body-binding/recipient-key-source", super::PREPARATION_OPERATION), json!("caller-supplied")),
            ("preparation idempotency", format!("{}/x-dirextalk-idempotency/same-key-identical-body", super::PREPARATION_OPERATION), json!("recompute")),
            ("preparation reject order", format!("{}/x-dirextalk-reject-before-write-order/0", super::PREPARATION_OPERATION), json!("capabilities")),
            ("preparation CAS", format!("{}/x-dirextalk-cas-transaction/count", super::PREPARATION_OPERATION), json!(2)),
            ("preparation media", format!("{}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog-preparation.v2+cbor/x-dirextalk-cddl-rule", super::PREPARATION_OPERATION), json!("alternate-rule")),
            ("preparation cap", format!("{}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog-preparation.v2+cbor/x-dirextalk-max-body-bytes", super::PREPARATION_OPERATION), json!(534)),
            ("status response auth", format!("{}/x-dirextalk-authentication/kind", super::STATUS_OPERATION), json!("bearer")),
            ("status currentness", format!("{}/x-dirextalk-currentness/required-state", super::STATUS_OPERATION), json!("portable-signatures")),
            ("status H+2", format!("{}/x-dirextalk-currentness/no-h-plus-2", super::STATUS_OPERATION), json!(false)),
            ("status checkpoint", format!("{}/x-dirextalk-currentness/portable-checkpoint-claimed", super::STATUS_OPERATION), json!(true)),
            ("provider authorization", format!("{}/x-dirextalk-authentication/authenticated-session-equals-provider-descriptor", super::PROVIDER_RESPONSE_OPERATION), json!(false)),
            ("candidate provider", format!("{}/x-dirextalk-authentication/candidate-can-never-be-provider", super::PROVIDER_RESPONSE_OPERATION), json!(false)),
            ("provider path binding", format!("{}/x-dirextalk-path-body-binding/request-id-cbor-path", super::PROVIDER_RESPONSE_OPERATION), json!([3])),
            ("response idempotency", format!("{}/x-dirextalk-idempotency/different-key-after-existence", super::PROVIDER_RESPONSE_OPERATION), json!(201)),
            ("provider reject order", format!("{}/x-dirextalk-reject-before-write-order/4", super::PROVIDER_RESPONSE_OPERATION), json!("single-signature")),
            ("provider CAS lock order", format!("{}/x-dirextalk-cas-transaction/lock-order", super::PROVIDER_RESPONSE_OPERATION), json!(["preparation", "identity", "challenge"])),
            ("portable signatures wording", format!("{}/x-dirextalk-portable-evidence/dual-signatures", super::PROVIDER_RESPONSE_OPERATION), json!("portable-currentness-proof")),
            ("provider DeviceAdd cap", format!("{}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog-provider-response.v2+cbor/x-dirextalk-max-device-add-bytes", super::PROVIDER_RESPONSE_OPERATION), json!(549)),
            ("provider body cap", format!("{}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog-provider-response.v2+cbor/x-dirextalk-max-body-bytes", super::PROVIDER_RESPONSE_OPERATION), json!(super::MAX_PROVIDER_RESPONSE_BODY_BYTES + 1)),
            ("HPKE mode", "/x-dirextalk-handoff-hpke/mode".to_owned(), json!("auth")),
            ("HPKE KEM", "/x-dirextalk-handoff-hpke/kem/id".to_owned(), json!(33)),
            ("HPKE info", "/x-dirextalk-handoff-hpke/info".to_owned(), json!("alternate\0")),
            ("HPKE replay", "/x-dirextalk-handoff-hpke/exact-replay".to_owned(), json!("re-encrypt")),
            ("HPKE envelope digest", "/x-dirextalk-handoff-hpke/envelope-digest-input".to_owned(), json!("ciphertext-alone")),
            ("package max", "/x-dirextalk-handoff-hpke/package-max-bytes".to_owned(), json!(super::MAX_PROVIDER_PACKAGE_BYTES + 1)),
            ("HPKE ciphertext max", "/x-dirextalk-handoff-hpke/ciphertext-max-bytes".to_owned(), json!(super::MAX_HPKE_CIPHERTEXT_BYTES + 1)),
            ("exact envelope max", "/x-dirextalk-handoff-hpke/encoded-envelope-max-bytes".to_owned(), json!(super::MAX_HPKE_ENCODED_ENVELOPE_BYTES + 1)),
            ("decoder ceiling separation", "/x-dirextalk-handoff-hpke/decoder-ceiling-is-not-envelope-allowance".to_owned(), json!(false)),
            ("provider key id", "/x-dirextalk-handoff-signers/provider-descriptor/key-id-present".to_owned(), json!(true)),
            ("authority open union", "/x-dirextalk-handoff-signers/independent-authority/closed-union".to_owned(), json!(false)),
            ("authority unknown kind", "/x-dirextalk-handoff-signers/independent-authority/unknown-kind".to_owned(), json!("accepted")),
            ("authority kind", "/x-dirextalk-handoff-signers/independent-authority/kinds/recovery-authority/kind".to_owned(), json!(4)),
            ("pairwise signer key", "/x-dirextalk-handoff-signers/key-separation/candidate-provider-and-authority-ed25519-public-keys".to_owned(), json!("may-match")),
            ("candidate cross-algorithm key bytes", "/x-dirextalk-handoff-signers/key-separation/candidate-ed25519-and-x25519-public-key-bytes".to_owned(), json!("may-match")),
            ("active signer ids", "/x-dirextalk-handoff-signers/key-separation/candidate-provider-and-active-authority-device-ids".to_owned(), json!("may-match")),
            ("H highwater", "/x-dirextalk-handoff-equality-validity/highwater/h".to_owned(), json!("0..9007199254740991")),
            ("H+1 equality", "/x-dirextalk-handoff-equality-validity/highwater/h-plus-1".to_owned(), json!("positive-but-not-successor")),
            ("duplicate coordinate", "/x-dirextalk-handoff-equality-validity/duplicate-coordinates/preparation-to-response/0/request-id".to_owned(), json!("partial-coordinate-set")),
            ("signed head exact bytes", "/x-dirextalk-handoff-equality-validity/signed-head/package-field-4".to_owned(), json!("reencoded-head")),
            ("signed head digest equality", "/x-dirextalk-handoff-equality-validity/signed-head/digest-equals/1".to_owned(), json!("wrong-field")),
            ("Catalog plaintext count/root", "/x-dirextalk-handoff-equality-validity/catalog-plaintext/validates-against-signed-head/4".to_owned(), json!("ciphertext-digest")),
            ("DeviceAdd kind", "/x-dirextalk-handoff-equality-validity/device-add/canonical-kind".to_owned(), json!("any-event")),
            ("DeviceAdd sequence", "/x-dirextalk-handoff-equality-validity/device-add/validates/1".to_owned(), json!("sequence-at-least-h-plus-1")),
            ("DeviceAdd signature", "/x-dirextalk-handoff-equality-validity/device-add/validates/6".to_owned(), json!("certificate-signature-optional")),
            ("DeviceAdd digest domain", "/x-dirextalk-handoff-equality-validity/device-add/digest-domain".to_owned(), json!("dirextalk.identity-log-event.v1\0")),
            ("issued/expires", "/x-dirextalk-handoff-equality-validity/validity/every-issued-at-before-expires-at".to_owned(), json!(false)),
            ("repeated times", "/x-dirextalk-handoff-equality-validity/validity/response-package-aad-times".to_owned(), json!("independent")),
            ("acceptance time", "/x-dirextalk-handoff-equality-validity/validity/provider-accepted-at".to_owned(), json!("recomputed")),
            ("server projection", "/x-dirextalk-handoff-equality-validity/identity-server-validation/never/0".to_owned(), json!("decrypt-package-allowed")),
            ("candidate post-decryption", "/x-dirextalk-handoff-equality-validity/candidate-post-decryption-validation/validates/0".to_owned(), json!("package-digest-optional")),
            ("replay authentication", "/x-dirextalk-handoff-replay-order/prerequisite".to_owned(), json!("none")),
            ("replay static order", "/x-dirextalk-handoff-replay-order/before-claim-resolution/1".to_owned(), json!("mutable-currentness")),
            ("committed replay order", "/x-dirextalk-handoff-replay-order/committed-exact-claim".to_owned(), json!("after-mutable-currentness")),
            ("first-admission gates", "/x-dirextalk-handoff-replay-order/mutable-currentness-and-final-cas".to_owned(), json!("every-replay")),
            ("status enum", "/x-dirextalk-handoff-state-machine/status-codes/invalidated".to_owned(), json!(6)),
            ("state_changed_at", "/x-dirextalk-handoff-state-machine/state-changed-at/invalidated".to_owned(), json!("get-time")),
            ("terminal earliest", "/x-dirextalk-handoff-state-machine/terminal-selection/primary".to_owned(), json!("latest")),
            ("terminal tie priority", "/x-dirextalk-handoff-state-machine/terminal-selection/equal-time-state-priority/0".to_owned(), json!("expired")),
            ("invalidation reason priority", "/x-dirextalk-handoff-state-machine/reason-codes/invalidated-priority/provider-session-or-key".to_owned(), json!(1)),
            ("GET read-only", "/x-dirextalk-handoff-state-machine/get-semantics".to_owned(), json!("writes-transition")),
            ("ready response", "/x-dirextalk-handoff-state-machine/only-ready-embeds-response".to_owned(), json!(false)),
            ("receipt immutability", "/x-dirextalk-handoff-state-machine/receipts-remain-immutable-after-get-invalidation".to_owned(), json!(false)),
            ("privacy", "/x-dirextalk-handoff-privacy/forbidden-persistence-and-responses/0".to_owned(), json!("raw-capability-is-safe")),
            ("preparation receipt cap", "/components/responses/PreparationCreated/content/application~1vnd.dirextalk.recovery-scope-catalog-preparation-receipt.v2+cbor/x-dirextalk-max-body-bytes".to_owned(), json!(88)),
            ("provider receipt rule", "/components/responses/ProviderResponseReplay/content/application~1vnd.dirextalk.recovery-scope-catalog-provider-response-receipt.v2+cbor/x-dirextalk-cddl-rule".to_owned(), json!("alternate-receipt")),
            ("status cap", "/components/responses/HandoffStatus/content/application~1vnd.dirextalk.recovery-scope-catalog-status.v2+cbor/x-dirextalk-max-body-bytes".to_owned(), json!(super::MAX_STATUS_BODY_BYTES + 1)),
            ("idempotency ASCII pattern", "/components/parameters/IdempotencyKey/schema/pattern".to_owned(), json!("^.{16,128}$")),
        ];
        for (label, pointer, replacement) in mutations {
            let mut mutated = original.clone();
            replace_openapi_value(&mut mutated, &pointer, replacement);
            assert_openapi_document_rejected(label, &mutated);
        }

        for operation in [
            super::PREPARATION_OPERATION,
            super::PROVIDER_RESPONSE_OPERATION,
        ] {
            let pointer = format!("{operation}/x-dirextalk-cas-transaction/final-predicate-fences");
            let fence_count = original
                .pointer(&pointer)
                .and_then(Value::as_array)
                .expect("CAS fences must be an array")
                .len();
            for index in 0..fence_count {
                let mut mutated = original.clone();
                mutated
                    .pointer_mut(&pointer)
                    .and_then(Value::as_array_mut)
                    .expect("CAS fences must be mutable")
                    .remove(index);
                assert_openapi_document_rejected(
                    &format!("omitted CAS fence {operation} index {index}"),
                    &mutated,
                );
            }
        }
        for mapping in [
            "preparation-to-response",
            "response-to-package",
            "response-to-public-aad",
            "response-to-package-times",
            "preparation-to-device-add",
        ] {
            let pointer =
                format!("/x-dirextalk-handoff-equality-validity/duplicate-coordinates/{mapping}");
            let mapping_count = original
                .pointer(&pointer)
                .and_then(Value::as_array)
                .expect("coordinate mappings must be arrays")
                .len();
            for index in 0..mapping_count {
                let mut mutated = original.clone();
                mutated
                    .pointer_mut(&pointer)
                    .and_then(Value::as_array_mut)
                    .expect("coordinate mappings must be mutable")
                    .remove(index);
                assert_openapi_document_rejected(
                    &format!("omitted equality mapping {mapping} index {index}"),
                    &mutated,
                );
            }
        }
        for forbidden_status in ["410", "412"] {
            let mut mutated = original.clone();
            mutated
                .pointer_mut(&format!("{}/responses", super::STATUS_OPERATION))
                .and_then(Value::as_object_mut)
                .expect("GET responses must be mutable")
                .insert(
                    forbidden_status.to_owned(),
                    json!({"$ref": "#/components/responses/HandoffGone"}),
                );
            assert_openapi_document_rejected(
                &format!("GET must not expose {forbidden_status}"),
                &mutated,
            );
        }

        for route in [
            super::PREPARATION_ROUTE,
            super::STATUS_ROUTE,
            super::PROVIDER_RESPONSE_ROUTE,
        ] {
            let mut mutated = original.clone();
            mutated
                .pointer_mut("/paths")
                .and_then(Value::as_object_mut)
                .expect("paths must be an object")
                .remove(route);
            assert_openapi_document_rejected(route, &mutated);
        }
        let domains = original
            .pointer("/x-dirextalk-handoff-crypto-domains")
            .and_then(Value::as_object)
            .expect("handoff domains must be an object");
        for domain in domains.keys() {
            let mut mutated = original.clone();
            replace_openapi_value(
                &mut mutated,
                &format!("/x-dirextalk-handoff-crypto-domains/{domain}"),
                json!("alternate-domain\0"),
            );
            assert_openapi_document_rejected(domain, &mutated);
        }
    }

    #[test]
    fn v42_catalog_v2_openapi_http_contract_is_frozen() {
        let document = super::parse_openapi(&openapi()).expect("OpenAPI must parse");
        super::validate_openapi_http_contract(&document)
            .expect("Recovery Scope Catalog V2 HTTP contract must remain frozen");
    }

    #[test]
    fn v42_catalog_v2_openapi_projection_and_proof_are_frozen() {
        let document = super::parse_openapi(&openapi()).expect("OpenAPI must parse");
        super::validate_openapi_projection_and_proof(&document)
            .expect("Recovery Scope Catalog V2 privacy and proof metadata must remain frozen");
    }

    #[test]
    fn v42_catalog_v2_openapi_rejects_path_and_privacy_drift() {
        let original = openapi_document();

        let mut missing = original.clone();
        missing
            .pointer_mut("/paths")
            .and_then(Value::as_object_mut)
            .expect("paths must be an object")
            .remove(super::OPENAPI_ROUTE);
        assert_openapi_document_rejected("missing path declaration", &missing);

        let mut extra = original.clone();
        let route = extra
            .pointer("/paths/~1v2~1recovery-scope-catalogs~1{catalog_id}")
            .expect("frozen route must exist")
            .clone();
        extra
            .pointer_mut("/paths")
            .and_then(Value::as_object_mut)
            .expect("paths must be an object")
            .insert(
                "/v2/recovery-scope-catalogs/{catalog_id}/{generation}".to_owned(),
                route,
            );
        assert_openapi_document_rejected("extra path declaration", &extra);

        let mut mismatched = original.clone();
        let paths = mismatched
            .pointer_mut("/paths")
            .and_then(Value::as_object_mut)
            .expect("paths must be an object");
        let route = paths
            .remove(super::OPENAPI_ROUTE)
            .expect("frozen route must exist");
        paths.insert(
            "/v2/recovery-scope-catalogs/{wrong_catalog_id}".to_owned(),
            route,
        );
        assert_openapi_document_rejected("mismatched path declaration", &mismatched);

        let mut binding = original.clone();
        replace_openapi_value(
            &mut binding,
            &format!(
                "{}/x-dirextalk-path-coordinate-binding/coordinates/catalog_id/cbor-path",
                super::OPENAPI_OPERATION
            ),
            json!([1, 3]),
        );
        assert_openapi_document_rejected("mismatched signed binding", &binding);

        let mut leakage = original.clone();
        leakage
            .pointer_mut(&format!(
                "{}/x-dirextalk-server-visible-projection/allowed-cbor-paths",
                super::OPENAPI_OPERATION
            ))
            .and_then(Value::as_array_mut)
            .expect("allowed projection paths must be an array")
            .push(json!([3]));
        assert_openapi_document_rejected("forbidden projection leakage", &leakage);
    }

    #[test]
    fn v42_catalog_v2_openapi_rejects_v2_response_contract_mutations() {
        const PREPARATION_RESPONSES: &str =
            "/paths/~1v3~1devices~1enroll~1catalog-preparations/post/responses";

        let original = openapi_document();
        super::validate_openapi_document(&original)
            .expect("the frozen V2 response contract must validate before mutations");

        let mut missing_required = original.clone();
        missing_required
            .pointer_mut(
                "/paths/~1v3~1devices~1enroll~1catalog-preparations~1{request_id}/get/parameters",
            )
            .and_then(Value::as_array_mut)
            .expect("GET parameters must be an array")
            .remove(1);
        assert_openapi_document_rejected(
            "a missing required response capability parameter",
            &missing_required,
        );

        let mut extra_field = original.clone();
        extra_field
            .pointer_mut("/components/schemas/ErrorEnvelopeV2/properties")
            .and_then(Value::as_object_mut)
            .expect("error envelope properties must be an object")
            .insert("details".to_owned(), json!({"type": "string"}));
        assert_openapi_document_rejected("an extra error-envelope field", &extra_field);

        let mut wrong_status = original.clone();
        *wrong_status
            .pointer_mut(&format!("{PREPARATION_RESPONSES}/201/$ref"))
            .expect("preparation 201 response reference") =
            json!("#/components/responses/PreparationReplay");
        assert_openapi_document_rejected("a wrong mutation status mapping", &wrong_status);

        let mut wrong_code = original.clone();
        *wrong_code
            .pointer_mut(
                "/components/schemas/HandoffGoneErrorV2/allOf/1/properties/error/properties/code/enum/0",
            )
            .expect("HandoffGone stable error code") = json!("RECOVERY_CATALOG_EXPIRED");
        assert_openapi_document_rejected("a wrong stable error code", &wrong_code);

        let mut wrong_body = original.clone();
        *wrong_body
            .pointer_mut("/components/responses/HandoffConflict/content")
            .expect("mutation error response content") = json!({
            "application/vnd.dirextalk.recovery-scope-catalog-status.v2+cbor": {
                "x-dirextalk-exact-cbor": true,
                "x-dirextalk-cddl-rule": "recovery-scope-catalog-status-v2",
                "x-dirextalk-max-body-bytes": super::MAX_STATUS_BODY_BYTES,
                "schema": {"$ref": "#/components/schemas/ExactCanonicalCbor"}
            }
        });
        assert_openapi_document_rejected(
            "a mutation error with terminal-CBOR body shape",
            &wrong_body,
        );

        let mut wrong_envelope = original.clone();
        wrong_envelope
            .pointer_mut("/components/schemas/ErrorEnvelopeV2/required")
            .and_then(Value::as_array_mut)
            .expect("error envelope required fields")
            .retain(|field| field != "error");
        assert_openapi_document_rejected("a malformed error envelope", &wrong_envelope);

        let mut missing_header = original.clone();
        missing_header
            .pointer_mut("/components/responses/HandoffConflict/headers")
            .and_then(Value::as_object_mut)
            .expect("mutation response headers")
            .remove("X-Request-Id");
        assert_openapi_document_rejected("a missing required response header", &missing_header);

        let mut wrong_header = original;
        *wrong_header
            .pointer_mut("/components/responses/HandoffConflict/headers/X-Request-Id/$ref")
            .expect("mutation response request-id header") = json!("#/components/headers/NoStore");
        assert_openapi_document_rejected("a wrong required response header binding", &wrong_header);
    }

    #[test]
    fn v42_catalog_v2_openapi_get_errors_remain_separate_from_mutation_and_terminal_cbor() {
        const STATUS_RESPONSES: &str =
            "/paths/~1v3~1devices~1enroll~1catalog-preparations~1{request_id}/get/responses";

        let original = openapi_document();
        super::validate_openapi_document(&original)
            .expect("the frozen V2 GET contract must validate before mutations");

        let status_responses = original
            .pointer(STATUS_RESPONSES)
            .and_then(Value::as_object)
            .expect("GET response map must be an object");
        assert_eq!(
            status_responses.keys().collect::<Vec<_>>(),
            vec!["200", "401", "406"]
        );
        for status in ["401", "406"] {
            let component = status_responses
                .get(status)
                .and_then(|value| value.get("$ref"))
                .and_then(Value::as_str)
                .expect("GET error must reference a response component")
                .strip_prefix("#/components/responses/")
                .expect("GET error reference must be local");
            assert!(
                original
                    .pointer(&format!(
                        "/components/responses/{component}/content/application~1json"
                    ))
                    .is_some(),
                "GET {status} must use the JSON error envelope"
            );
        }
        assert!(
            original
                .pointer(
                    "/components/responses/HandoffStatus/content/application~1vnd.dirextalk.recovery-scope-catalog-status.v2+cbor",
                )
                .is_some(),
            "the successful GET status must remain terminal status CBOR"
        );

        let mut extra_terminal_status = original.clone();
        extra_terminal_status
            .pointer_mut(STATUS_RESPONSES)
            .and_then(Value::as_object_mut)
            .expect("GET response map must be mutable")
            .insert(
                "410".to_owned(),
                json!({"$ref": "#/components/responses/HandoffGone"}),
            );
        assert_openapi_document_rejected(
            "an extra mutation terminal status on GET",
            &extra_terminal_status,
        );

        let mut mutation_error_on_get = original.clone();
        *mutation_error_on_get
            .pointer_mut(&format!("{STATUS_RESPONSES}/401/$ref"))
            .expect("GET capability error reference") =
            json!("#/components/responses/HandoffConflict");
        assert_openapi_document_rejected(
            "a mutation error substituted for GET 401",
            &mutation_error_on_get,
        );

        let mut terminal_cbor_on_get_error = original.clone();
        *terminal_cbor_on_get_error
            .pointer_mut(&format!("{STATUS_RESPONSES}/406/$ref"))
            .expect("GET not-acceptable error reference") =
            json!("#/components/responses/HandoffStatus");
        assert_openapi_document_rejected(
            "terminal status CBOR substituted for GET 406 error",
            &terminal_cbor_on_get_error,
        );

        let mut mutation_receipt_on_get_success = original.clone();
        *mutation_receipt_on_get_success
            .pointer_mut(&format!("{STATUS_RESPONSES}/200/$ref"))
            .expect("GET success response reference") =
            json!("#/components/responses/ProviderResponseCreated");
        assert_openapi_document_rejected(
            "mutation receipt substituted for GET terminal status",
            &mutation_receipt_on_get_success,
        );

        let mut json_status = original;
        *json_status
            .pointer_mut("/components/responses/HandoffStatus/content")
            .expect("terminal status content") = json!({
            "application/json": {
                "schema": {"$ref": "#/components/schemas/HandoffCapabilityErrorV2"}
            }
        });
        assert_openapi_document_rejected(
            "JSON body substituted for terminal GET status CBOR",
            &json_status,
        );
    }

    #[test]
    fn v42_catalog_v2_openapi_rejects_frozen_field_drift() {
        let original = openapi_document();
        let request_schema = format!(
            "{}/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog.v2+cbor/schema/$ref",
            super::OPENAPI_OPERATION
        );
        let created_schema = "/components/responses/CatalogCreated/content/application~1vnd.dirextalk.recovery-scope-catalog-head.v2+cbor/schema/$ref";
        let replay_schema = "/components/responses/CatalogReplay/content/application~1vnd.dirextalk.recovery-scope-catalog-head.v2+cbor/schema/$ref";
        let membership_domain = format!(
            "{}/x-dirextalk-crypto-domains/membership-receipt",
            super::OPENAPI_OPERATION
        );
        let scope_domain = format!(
            "{}/x-dirextalk-crypto-domains/recovery-scope",
            super::OPENAPI_OPERATION
        );
        let mutations = [
            ("info.version", "/info/version", json!("2.0.1")),
            (
                "signed head ceiling",
                "/x-dirextalk-canonical-cbor-ceilings/signed-catalog-head/maximum-bytes",
                json!(467),
            ),
            (
                "upload body ceiling",
                "/paths/~1v2~1recovery-scope-catalogs~1{catalog_id}/put/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog.v2+cbor/x-dirextalk-max-body-bytes",
                json!(super::MAX_CATALOG_UPLOAD_BODY_BYTES + 1),
            ),
            (
                "upload decoder separation",
                "/paths/~1v2~1recovery-scope-catalogs~1{catalog_id}/put/requestBody/content/application~1vnd.dirextalk.recovery-scope-catalog.v2+cbor/x-dirextalk-decoder-ceiling-is-not-body-allowance",
                json!(false),
            ),
            (
                "created signed head response ceiling",
                "/components/responses/CatalogCreated/content/application~1vnd.dirextalk.recovery-scope-catalog-head.v2+cbor/x-dirextalk-max-body-bytes",
                json!(467),
            ),
            (
                "request schema ref",
                request_schema.as_str(),
                json!("#/components/schemas/UuidV7"),
            ),
            (
                "created schema ref",
                created_schema,
                json!("#/components/schemas/UuidV7"),
            ),
            (
                "replay schema ref",
                replay_schema,
                json!("#/components/schemas/UuidV7"),
            ),
            (
                "exact CBOR type",
                "/components/schemas/ExactCanonicalCbor/type",
                json!("object"),
            ),
            (
                "exact CBOR content encoding",
                "/components/schemas/ExactCanonicalCbor/contentEncoding",
                json!("base64"),
            ),
            (
                "UUIDv7 type",
                "/components/schemas/UuidV7/type",
                json!("integer"),
            ),
            (
                "Authorization type",
                "/components/parameters/DeviceAuthorization/schema/type",
                json!("integer"),
            ),
            (
                "Idempotency-Key type",
                "/components/parameters/IdempotencyKey/schema/type",
                json!("integer"),
            ),
            (
                "membership receipt domain",
                membership_domain.as_str(),
                json!("dirextalk.recovery-scope-membership-receipt.v2\0"),
            ),
            (
                "recovery scope domain",
                scope_domain.as_str(),
                json!("dirextalk.recovery-scope.v2\0"),
            ),
        ];
        for (label, pointer, replacement) in mutations {
            let mut mutated = original.clone();
            replace_openapi_value(&mut mutated, pointer, replacement);
            assert_openapi_document_rejected(label, &mutated);
        }
    }

    #[test]
    fn v42_catalog_v2_openapi_rejects_each_private_verifier_projection() {
        let original = openapi_document();
        let pointer = format!(
            "{}/x-dirextalk-server-visible-projection/forbidden-data",
            super::OPENAPI_OPERATION
        );
        for token in [
            "verifier-public-key",
            "verifier-key-id",
            "verifier-epoch",
            "completion-evidence-issuer-epk",
            "completion-evidence-issuer-pop",
            "completion-evidence-issuer-origin-authorization",
            "completion-evidence-issuer-authorization-digest",
        ] {
            let mut mutated = original.clone();
            let forbidden = mutated
                .pointer_mut(&pointer)
                .and_then(Value::as_array_mut)
                .expect("forbidden projection data must be an array");
            let item = forbidden
                .iter_mut()
                .find(|value| value.as_str() == Some(token))
                .unwrap_or_else(|| panic!("frozen privacy token must exist: {token}"));
            *item = json!(format!("{token}-drift"));
            assert_openapi_document_rejected(token, &mutated);
        }
    }

    #[test]
    fn v42_catalog_v2_openapi_rejects_private_body_digest_metadata_drift() {
        let original = openapi_document();
        let base = format!(
            "{}/x-dirextalk-private-body-derived-digests",
            super::OPENAPI_OPERATION
        );
        for (digest, wrong_domain) in [
            (
                "membership-receipt",
                "dirextalk.recovery-scope-membership-receipt.v2\0",
            ),
            ("recovery-scope", "dirextalk.recovery-scope.v2\0"),
        ] {
            for (field, replacement) in [
                ("algorithm", json!("SHA-512")),
                ("domain", json!(wrong_domain)),
                ("output-cbor-path", json!([99])),
                ("input-cbor-path", json!([99])),
                ("input-encoding", json!("implementation-defined")),
            ] {
                let mut mutated = original.clone();
                replace_openapi_value(
                    &mut mutated,
                    &format!("{base}/{digest}/{field}"),
                    replacement,
                );
                assert_openapi_document_rejected(
                    &format!("{digest} derived digest {field} drift"),
                    &mutated,
                );
            }

            let mut extra = original.clone();
            extra
                .pointer_mut(&format!("{base}/{digest}"))
                .and_then(Value::as_object_mut)
                .expect("derived digest metadata must be an object")
                .insert("extra".to_owned(), json!(true));
            assert_openapi_document_rejected(&format!("{digest} derived digest extra key"), &extra);
        }
    }

    #[test]
    fn v42_catalog_v2_vector_positive_bytes_are_independently_derived() {
        super::validate_positive_vector(&vector(), &cddl())
            .expect("Catalog V2 positive bytes, digests, and signatures must derive exactly");
    }

    #[test]
    fn v42_catalog_v2_vector_negative_family_fails_closed() {
        let vector = vector();
        let cddl = cddl();
        let facts = super::validate_positive_vector(&vector, &cddl)
            .expect("positive Catalog V2 vector must validate first");
        super::validate_negative_vector_family(&vector, &cddl, &facts)
            .expect("Catalog V2 fixed negative family must reach exact failure checks");
    }

    #[test]
    fn v42_catalog_v2_completion_evidence_negatives_fail_closed() {
        let vector = vector();
        let cddl = cddl();
        let facts = super::validate_positive_vector(&vector, &cddl)
            .expect("positive Catalog V2 vector must validate first");
        super::validate_completion_evidence_negative_vector_family(&vector, &cddl, &facts)
            .expect("completion-evidence negatives must reach exact failure checks");
        let negative = vector
            .get("negative_completion_evidence")
            .expect("completion-evidence negatives");

        let binding = |name| {
            super::decode_negative_cddl(
                negative,
                &cddl,
                name,
                "recovery-scope-catalog-completion-verifier-binding-v1",
            )
            .unwrap_or_else(|error| panic!("{name} must be canonical and structural: {error}"))
            .1
        };
        let pop = binding("issuer_pop_missing_nul_domain_binding");
        let pop_fields = super::numbered_fields(&pop, 23, "missing-NUL PoP").unwrap();
        let pop_unsigned = independent_unsigned_prefix(&pop, 20);
        let epk = super::cbor_fixed(pop_fields[17], "missing-NUL PoP EPK").unwrap();
        let pop_signature = super::cbor_fixed(pop_fields[20], "missing-NUL PoP signature").unwrap();
        assert!(independently_verifies(
            epk,
            &super::COMPLETION_EVIDENCE_POP_DOMAIN
                [..super::COMPLETION_EVIDENCE_POP_DOMAIN.len() - 1],
            &pop_unsigned,
            pop_signature,
        ));
        assert!(!independently_verifies(
            epk,
            super::COMPLETION_EVIDENCE_POP_DOMAIN,
            &pop_unsigned,
            pop_signature,
        ));

        let origin = binding("issuer_origin_authorization_missing_nul_domain_binding");
        let origin_fields = super::numbered_fields(&origin, 23, "missing-NUL origin auth").unwrap();
        let origin_unsigned = independent_unsigned_prefix(&origin, 21);
        let verifier = super::cbor_fixed(origin_fields[8], "origin verifier").unwrap();
        let origin_signature =
            super::cbor_fixed(origin_fields[21], "missing-NUL origin signature").unwrap();
        assert!(independently_verifies(
            verifier,
            &super::COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN
                [..super::COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN.len() - 1],
            &origin_unsigned,
            origin_signature,
        ));
        assert!(!independently_verifies(
            verifier,
            super::COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN,
            &origin_unsigned,
            origin_signature,
        ));

        let wrong_descriptor = binding("issuer_origin_authorization_wrong_descriptor_key_binding");
        let wrong_descriptor_fields =
            super::numbered_fields(&wrong_descriptor, 23, "wrong descriptor key").unwrap();
        let wrong_descriptor_unsigned = independent_unsigned_prefix(&wrong_descriptor, 21);
        let wrong_descriptor_signature = super::cbor_fixed(
            wrong_descriptor_fields[21],
            "wrong descriptor authorization signature",
        )
        .unwrap();
        let rotated =
            super::decode_json_fixed::<32>(&vector, "rotated_verifier_public_key_hex").unwrap();
        assert!(independently_verifies(
            rotated,
            super::COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN,
            &wrong_descriptor_unsigned,
            wrong_descriptor_signature,
        ));
        assert!(!independently_verifies(
            verifier,
            super::COMPLETION_EVIDENCE_ORIGIN_AUTHORIZATION_DOMAIN,
            &wrong_descriptor_unsigned,
            wrong_descriptor_signature,
        ));
    }

    #[test]
    fn v42_catalog_v2_vector_odd_duplicate_last_proofs_are_exact() {
        let vector = vector();
        let cddl = cddl();
        let facts = super::validate_positive_vector(&vector, &cddl)
            .expect("positive Catalog V2 vector must validate");
        let catalog =
            super::json_field(&vector, "catalog", "Catalog V2 vector").expect("catalog must exist");
        let proofs = super::json_field(catalog, "proofs", "Catalog V2 catalog")
            .and_then(|value| {
                value.as_array().ok_or_else(|| {
                    super::ProtocolToolError::new("Catalog V2 proofs must be an array")
                })
            })
            .expect("proof assertions must be an array");
        let sibling_counts = proofs
            .iter()
            .map(|proof| {
                let (_, value) = super::decode_exact_cddl(
                    &cddl,
                    "catalog-merkle-proof-v2",
                    super::json_string(proof, "proof_cbor_hex").expect("proof bytes must exist"),
                    "proof sibling-count test",
                )
                .expect("proof must decode");
                super::numbered_fields(&value, 6, "proof")
                    .and_then(|fields| super::cbor_array(fields[5], "siblings"))
                    .map(<[dtx_wire::CanonicalValue]>::len)
                    .expect("proof siblings must decode")
            })
            .collect::<Vec<_>>();
        assert_eq!(sibling_counts, [2, 2, 1]);
        super::validate_positive_proofs(
            &cddl,
            catalog,
            &facts.context,
            &facts.openings,
            facts.merkle_root,
        )
        .expect("three-leaf and zero-sibling single-leaf proofs must validate");
    }

    #[test]
    fn v42_catalog_v2_vector_json_claims_are_not_trusted() {
        let cddl = cddl();
        let mut derived_claim = vector();
        replace_openapi_value(
            &mut derived_claim,
            "/catalog/head_digest_hex",
            json!("00".repeat(32)),
        );
        let Err(derived_error) = super::validate_positive_vector(&derived_claim, &cddl) else {
            panic!("tampered derived JSON claim must fail");
        };
        assert!(
            derived_error
                .to_string()
                .contains("derived assertion mismatch")
        );

        let mut exact_bytes = vector();
        let corrupted = exact_bytes
            .pointer("/negative_cbor/wrong_head_signature")
            .cloned()
            .expect("wrong-head-signature bytes must exist");
        replace_openapi_value(&mut exact_bytes, "/catalog/head_signed_cbor_hex", corrupted);
        let Err(bytes_error) = super::validate_positive_vector(&exact_bytes, &cddl) else {
            panic!("corrupted exact CBOR with unchanged JSON claims must fail");
        };
        assert!(bytes_error.to_string().contains("signature invalid"));
    }

    #[test]
    fn v42_catalog_v2_upload_decoder_honors_ciphertext_and_envelope_boundaries() {
        let vector = vector();
        let cddl = cddl();
        let facts = super::validate_positive_vector(&vector, &cddl)
            .expect("positive Catalog V2 vector must validate");
        let upload = |ciphertext_len| {
            dtx_wire::CanonicalValue::Map(vec![
                (
                    dtx_wire::CanonicalValue::Unsigned(1),
                    facts.signed_head.clone(),
                ),
                (
                    dtx_wire::CanonicalValue::Unsigned(2),
                    dtx_wire::CanonicalValue::Bytes(vec![0x5a; ciphertext_len]),
                ),
            ])
        };

        let maximum = dtx_wire::encode_deterministic_cbor_with_limit(&upload(1_048_576), 1_065_984)
            .expect("maximum ciphertext upload must fit the frozen envelope");
        let maximum_value = super::decode_exact_upload_bytes(&cddl, &maximum, "maximum upload")
            .expect("maximum ciphertext upload must pass canonical decoding and CDDL");
        assert!(
            super::validate_upload_value(&maximum_value, &facts)
                .is_err_and(|error| error.to_string().contains("ciphertext digest mismatch")),
            "maximum ciphertext upload must reach semantic validation"
        );

        let maximum_plus_one =
            dtx_wire::encode_deterministic_cbor_with_limit(&upload(1_048_577), 1_065_984)
                .expect("max-plus-one ciphertext still fits the outer envelope");
        assert!(
            super::decode_exact_upload_bytes(
                &cddl,
                &maximum_plus_one,
                "max-plus-one ciphertext upload",
            )
            .is_err_and(|error| error.to_string().contains("CDDL rejected")),
            "max-plus-one ciphertext must decode canonically, then fail its field bound"
        );

        let envelope_overflow =
            dtx_wire::encode_deterministic_cbor_with_limit(&upload(1_065_984), 1_070_080)
                .expect("test must construct a canonical over-limit envelope");
        assert!(envelope_overflow.len() > 1_065_984);
        assert!(
            super::decode_exact_upload_bytes(
                &cddl,
                &envelope_overflow,
                "over-limit upload envelope",
            )
            .is_err_and(|error| error.to_string().contains("configured byte limit")),
            "over-limit envelope must fail before CDDL or semantic validation"
        );
    }

    #[test]
    fn v42_catalog_v2_verifier_origin_is_one_canonical_https_dns_authority() {
        for accepted in [
            "https://a",
            "https://a.co",
            "https://verifier.example",
            "https://verifier.example:80",
            "https://node-1.recovery.example:8443",
            "https://a1.b2:65535",
        ] {
            assert!(super::valid_https_origin(accepted), "rejected {accepted}");
        }
        for rejected in [
            "http://a.co",
            "HTTPS://a.co",
            "https://A.co",
            "https://bücher.example",
            "https://a..co",
            "https://-a.co",
            "https://a-.co",
            "https://a.co.",
            "https://127.0.0.1",
            "https://127.1",
            "https://2130706433",
            "https://017700000001",
            "https://0x7f000001",
            "https://a.1",
            "https://[::1]",
            "https://user@a.co",
            "https://a.co/",
            "https://a.co/path",
            "https://a.co?query",
            "https://a.co#fragment",
            "https://a.co:443",
            "https://a.co:0443",
            "https://a.co:0444",
            "https://a.co:0",
            "https://a.co:65536",
            "https://a.co:notaport",
            "https://a.co:",
        ] {
            assert!(!super::valid_https_origin(rejected), "accepted {rejected}");
        }
        assert!(!super::valid_https_origin(&format!(
            "https://{}.example",
            "a".repeat(2_040)
        )));
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the four independent construction proofs mirror one production pre-rejection gate"
    )]
    fn v42_catalog_v2_negative_constructions_are_independently_proven() {
        const PRIVATE_BODY_WITHOUT_NUL: &[u8] = b"dirextalk.recovery-scope-catalog-private-body.v2";
        const BINDING_SIGNATURE_WITHOUT_NUL: &[u8] =
            b"dirextalk.recovery-scope-catalog-verifier-binding-signature.v1";

        let vector = vector();
        let cddl = cddl();
        let facts = super::validate_positive_vector(&vector, &cddl)
            .expect("positive Catalog V2 vector must validate");
        let negative = super::json_field(&vector, "negative_cbor", "Catalog V2 vector")
            .expect("negative family must exist");
        let authority = super::decode_json_fixed::<32>(&vector, "catalog_authority_public_key_hex")
            .expect("authority public key must decode");
        let wrong_authority =
            super::decode_json_fixed::<32>(&vector, "wrong_authority_public_key_hex")
                .expect("unrelated authority public key must decode");

        let (_, wrong_domain_opening) = super::decode_negative_cddl(
            negative,
            &cddl,
            "self_consistent_wrong_domain_opening",
            "recovery-scope-catalog-opening-v2",
        )
        .expect("wrong-domain opening must be canonical and structural");
        let opening_fields =
            super::numbered_fields(&wrong_domain_opening, 3, "wrong-domain opening")
                .expect("wrong-domain opening fields");
        let private_exact = dtx_wire::encode_deterministic_cbor(opening_fields[0])
            .expect("wrong-domain private body must encode");
        let alternate_private_digest = independent_digest(PRIVATE_BODY_WITHOUT_NUL, &private_exact);
        let binding_fields = super::numbered_fields(opening_fields[1], 23, "wrong-domain binding")
            .expect("wrong-domain binding fields");
        assert_eq!(
            super::cbor_fixed::<32>(binding_fields[5], "wrong-domain private digest")
                .expect("wrong-domain private digest"),
            alternate_private_digest
        );
        let binding_unsigned = independent_unsigned_prefix(opening_fields[1], 22);
        assert!(independently_verifies(
            authority,
            super::VERIFIER_BINDING_SIGNATURE_DOMAIN,
            &binding_unsigned,
            super::cbor_fixed(binding_fields[22], "wrong-domain binding signature")
                .expect("wrong-domain binding signature"),
        ));
        let binding_exact = dtx_wire::encode_deterministic_cbor(opening_fields[1])
            .expect("wrong-domain signed binding must encode");
        let alternate_binding_digest =
            independent_digest(super::VERIFIER_BINDING_DOMAIN, &binding_exact);
        let commitment_fields =
            super::numbered_fields(opening_fields[2], 12, "wrong-domain commitment")
                .expect("wrong-domain commitment fields");
        assert_eq!(
            super::cbor_fixed::<32>(commitment_fields[4], "commitment private digest")
                .expect("commitment private digest"),
            alternate_private_digest
        );
        assert_eq!(
            super::cbor_fixed::<32>(commitment_fields[5], "commitment binding digest")
                .expect("commitment binding digest"),
            alternate_binding_digest
        );
        assert!(
            super::validate_opening_value(
                &wrong_domain_opening,
                &facts.context,
                &facts.verifier,
                1,
            )
            .is_err()
        );

        let (_, missing_nul_binding) = super::decode_negative_cddl(
            negative,
            &cddl,
            "missing_nul_binding_signature",
            "recovery-scope-catalog-completion-verifier-binding-v1",
        )
        .expect("missing-NUL binding must be canonical and structural");
        let missing_nul_fields =
            super::numbered_fields(&missing_nul_binding, 23, "missing-NUL binding")
                .expect("missing-NUL binding fields");
        let missing_nul_unsigned = independent_unsigned_prefix(&missing_nul_binding, 22);
        let missing_nul_signature =
            super::cbor_fixed(missing_nul_fields[22], "missing-NUL signature")
                .expect("missing-NUL signature");
        assert!(independently_verifies(
            authority,
            BINDING_SIGNATURE_WITHOUT_NUL,
            &missing_nul_unsigned,
            missing_nul_signature,
        ));
        assert!(!independently_verifies(
            authority,
            super::VERIFIER_BINDING_SIGNATURE_DOMAIN,
            &missing_nul_unsigned,
            missing_nul_signature,
        ));
        assert!(
            super::validate_binding_value(
                &missing_nul_binding,
                &facts.context,
                &facts.verifier,
                1,
                facts.openings[0].private_digest,
            )
            .is_err()
        );

        let (_, raw_scope_digest_body) = super::decode_negative_cddl(
            negative,
            &cddl,
            "wrong_scope_digest_encoding_private_body",
            "recovery-scope-catalog-private-body-v2",
        )
        .expect("raw-scope-digest body must be canonical and structural");
        let private_fields =
            super::numbered_fields(&raw_scope_digest_body, 10, "raw-scope-digest body")
                .expect("raw-scope-digest private fields");
        let scope_fields = super::numbered_fields(private_fields[4], 2, "recovery scope")
            .expect("recovery scope fields");
        let raw_scope_text =
            super::cbor_text(scope_fields[1], "recovery scope text").expect("recovery scope text");
        let raw_scope_digest =
            independent_digest(super::RECOVERY_SCOPE_DOMAIN, raw_scope_text.as_bytes());
        let canonical_scope = dtx_wire::encode_deterministic_cbor(private_fields[4])
            .expect("canonical recovery scope must encode");
        assert_eq!(
            super::cbor_fixed::<32>(private_fields[8], "raw scope digest")
                .expect("raw scope digest"),
            raw_scope_digest
        );
        assert_ne!(
            raw_scope_digest,
            independent_digest(super::RECOVERY_SCOPE_DOMAIN, &canonical_scope)
        );
        assert!(
            super::validate_private_body_value(&raw_scope_digest_body, &facts.context, 1).is_err()
        );

        let (_, wrong_head) = super::decode_negative_cddl(
            negative,
            &cddl,
            "wrong_head_signature",
            "recovery-scope-catalog-head-v2",
        )
        .expect("unrelated-authority head must be canonical and structural");
        let wrong_head_fields = super::numbered_fields(&wrong_head, 16, "unrelated-authority head")
            .expect("unrelated-authority head fields");
        let wrong_head_unsigned = independent_unsigned_prefix(&wrong_head, 15);
        let wrong_head_signature =
            super::cbor_fixed(wrong_head_fields[15], "unrelated-authority head signature")
                .expect("unrelated-authority head signature");
        assert!(independently_verifies(
            wrong_authority,
            super::HEAD_SIGNATURE_DOMAIN,
            &wrong_head_unsigned,
            wrong_head_signature,
        ));
        assert!(!independently_verifies(
            authority,
            super::HEAD_SIGNATURE_DOMAIN,
            &wrong_head_unsigned,
            wrong_head_signature,
        ));
        let positive_head_fields = super::numbered_fields(&facts.signed_head, 16, "positive head")
            .expect("positive head fields");
        assert!(
            super::validate_head_value(
                &wrong_head,
                &facts.context,
                facts.merkle_root,
                super::cbor_fixed(positive_head_fields[7], "positive ciphertext digest")
                    .expect("positive ciphertext digest"),
                facts.openings.len(),
            )
            .is_err()
        );
    }

    #[test]
    fn v42_catalog_v2_vector_metadata_equals_cddl_and_openapi() {
        super::validate_vector_metadata(&vector(), &cddl(), &openapi())
            .expect("Catalog V2 vector metadata must equal CDDL and OpenAPI");
    }
}
