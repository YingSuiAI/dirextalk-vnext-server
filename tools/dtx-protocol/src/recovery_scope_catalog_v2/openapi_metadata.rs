use super::{
    BTreeSet, HPKE_INFO, MAX_ENVELOPE_BYTES, MAX_HPKE_CIPHERTEXT_BYTES,
    MAX_HPKE_ENCODED_ENVELOPE_BYTES, MAX_PROVIDER_PACKAGE_BYTES, PREPARATION_OPERATION,
    PROVIDER_RESPONSE_OPERATION, ProtocolToolError, STATUS_OPERATION, Value, json,
};
#[allow(
    clippy::too_many_lines,
    reason = "the handoff metadata is a closed security and state-machine contract"
)]
pub(crate) fn validate_openapi_handoff_metadata(document: &Value) -> Result<(), ProtocolToolError> {
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

pub(crate) fn expect_object_keys(
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

pub(crate) fn expect_value(
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
