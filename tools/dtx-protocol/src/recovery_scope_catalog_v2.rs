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
    Deserializable, Kem as KemTrait, OpModeR, Serializable, aead::ChaCha20Poly1305,
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

mod b2b_crypto;
mod b2b_limits;
mod b2b_proofs;
mod b2b_state;
mod candidate;
mod codec;
mod negative;
mod openapi;
mod openapi_handoff;
mod openapi_metadata;
mod origin;
mod origin_handoff;
mod positive_core;
mod positive_merkle;
mod schema;
#[cfg(test)]
mod tests;
mod vector;

pub(super) use b2b_crypto::*;
pub(super) use b2b_limits::*;
pub(super) use b2b_proofs::*;
pub(super) use b2b_state::*;
pub(super) use candidate::*;
pub(super) use codec::*;
pub(super) use negative::*;
pub(super) use openapi::*;
pub(super) use openapi_handoff::*;
pub(super) use openapi_metadata::*;
pub(super) use origin::*;
pub(super) use origin_handoff::*;
pub(super) use positive_core::*;
pub(super) use positive_merkle::*;
pub(super) use schema::*;
pub(super) use vector::*;
