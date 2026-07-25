use std::path::Path;

use serde_json::Value;

use crate::ProtocolToolError;

mod cddl;
mod helpers;
mod openapi;
mod semantics;
const CDDL_RELATIVE: &str = "protocol/cddl/mls-sequencer/v7/mls-sequencer-v7.cddl";
const OPENAPI_RELATIVE: &str = "protocol/openapi/mls-sequencer/v7/openapi.yaml";
const CDDL_SHA256: &str = "6420b0dcc8ea6976ab85cce71dcf6410eb26c298eae81dfcaa34df46394aa761";
const OPENAPI_SHA256: &str = "71959152f6f8dea1d005d7550706db1b1024a7ae7cef9db3136675c7f5a3191c";

const DOMAINS: &[(&str, &str)] = &[
    (
        "issuer-authorization-request-signature",
        "dirextalk.mls-recovery.issuer-authorization-request-signature.v1\0",
    ),
    (
        "issuer-authorization-request",
        "dirextalk.mls-recovery.issuer-authorization-request.v1\0",
    ),
    (
        "issuer-authorization-idempotency",
        "dirextalk.mls-recovery.issuer-authorization-idempotency.v1\0",
    ),
    (
        "route-signature",
        "dirextalk.mls-recovery.route-signature.v1\0",
    ),
    ("route", "dirextalk.mls-recovery.route.v1\0"),
    (
        "controller-proof-signature",
        "dirextalk.mls-recovery.controller-proof-signature.v1\0",
    ),
    (
        "controller-proof",
        "dirextalk.mls-recovery.controller-proof.v1\0",
    ),
    (
        "raw-mls-commit",
        "dirextalk.mls-recovery.raw-mls-commit.v7\0",
    ),
    (
        "raw-mls-welcome",
        "dirextalk.mls-recovery.raw-mls-welcome.v7\0",
    ),
    ("add-signature", "dirextalk.mls-recovery.add-signature.v7\0"),
    ("add", "dirextalk.mls-recovery.add.v7\0"),
    (
        "add-idempotency",
        "dirextalk.mls-recovery.add-idempotency.v7\0",
    ),
    ("add-receipt", "dirextalk.mls-recovery.add-receipt.v7\0"),
    (
        "add-receipt-signature",
        "dirextalk.mls-recovery.add-receipt-signature.v7\0",
    ),
    (
        "confirmation-signature",
        "dirextalk.mls-recovery.confirmation-signature.v2\0",
    ),
    ("confirmation", "dirextalk.mls-recovery.confirmation.v2\0"),
    (
        "confirmation-idempotency",
        "dirextalk.mls-recovery.confirmation-idempotency.v2\0",
    ),
    (
        "confirmation-receipt",
        "dirextalk.mls-recovery.confirmation-receipt.v2\0",
    ),
    (
        "confirmation-receipt-signature",
        "dirextalk.mls-recovery.confirmation-receipt-signature.v2\0",
    ),
    (
        "activation-signature",
        "dirextalk.mls-recovery.activation-signature.v2\0",
    ),
    ("activation", "dirextalk.mls-recovery.activation.v2\0"),
    (
        "activation-idempotency",
        "dirextalk.mls-recovery.activation-idempotency.v2\0",
    ),
    (
        "activation-receipt",
        "dirextalk.mls-recovery.activation-receipt.v2\0",
    ),
    (
        "activation-receipt-signature",
        "dirextalk.mls-recovery.activation-receipt-signature.v2\0",
    ),
    (
        "activation-readback-signature",
        "dirextalk.mls-recovery.activation-readback-signature.v2\0",
    ),
    (
        "activation-readback",
        "dirextalk.mls-recovery.activation-readback.v2\0",
    ),
    (
        "child-pop",
        "dirextalk.mls-recovery.completion-child-pop.v1\0",
    ),
    (
        "child-certificate-signature",
        "dirextalk.mls-recovery.completion-child-certificate-signature.v1\0",
    ),
    (
        "child-certificate",
        "dirextalk.mls-recovery.completion-child-certificate.v1\0",
    ),
    (
        "redacted-evidence-signature",
        "dirextalk.mls-recovery.redacted-evidence-signature.v1\0",
    ),
    (
        "redacted-evidence",
        "dirextalk.mls-recovery.redacted-evidence.v1\0",
    ),
    (
        "evidence-issuance-signature",
        "dirextalk.mls-recovery.evidence-issuance-signature.v1\0",
    ),
    (
        "evidence-issuance",
        "dirextalk.mls-recovery.evidence-issuance.v1\0",
    ),
    (
        "evidence-issuance-idempotency",
        "dirextalk.mls-recovery.evidence-issuance-idempotency.v1\0",
    ),
    (
        "evidence-issuance-receipt",
        "dirextalk.mls-recovery.evidence-issuance-receipt.v1\0",
    ),
    (
        "completion-cache-signature",
        "dirextalk.mls-recovery.completion-cache-signature.v2\0",
    ),
    (
        "completion-cache",
        "dirextalk.mls-recovery.completion-cache.v2\0",
    ),
    (
        "completion-cache-idempotency",
        "dirextalk.mls-recovery.completion-cache-idempotency.v2\0",
    ),
    (
        "completion-cache-receipt",
        "dirextalk.mls-recovery.completion-cache-receipt.v2\0",
    ),
    (
        "completion-cache-receipt-signature",
        "dirextalk.mls-recovery.completion-cache-receipt-signature.v2\0",
    ),
];

const RULES: &[&str] = &[
    "digest",
    "signature",
    "ed25519-public-key",
    "uuid-v7",
    "identity-id",
    "channel-id",
    "https-authority-origin",
    "safe-sequence",
    "safe-parent",
    "positive-uint",
    "utc-millis",
    "catalog-exhaustive-count",
    "scope",
    "welcome-pending",
    "candidate-confirmed",
    "activated-fenced",
    "exact-catalog-completion-verifier-descriptor-v1",
    "exact-catalog-private-body-v2",
    "exact-catalog-verifier-binding-fields-1-through-22-v1",
    "exact-catalog-opening-v2",
    "exact-signed-catalog-head-v2",
    "exact-catalog-proof-v2",
    "exact-history-recovery-request-v4",
    "exact-history-recovery-manifest-v2",
    "exact-history-recovery-grant-v5",
    "exact-recipient-history-offer-v3",
    "exact-history-recovery-delivery-fact-v2",
    "exact-key-package-publish-receipt-v4",
    "exact-key-package-claim-receipt-v4",
    "exact-history-recovery-completion-presentation-v2",
    "mls-recovery-issuer-authorization-request-v1",
    "mls-recovery-issuer-authorization-v1",
    "mls-recovery-route-v1",
    "mls-recovery-controller-proof-v1",
    "mls-recovery-add-request-v7",
    "mls-recovery-add-receipt-v7",
    "signed-mls-recovery-add-receipt-v7",
    "exact-signed-mls-recovery-add-receipt-v7",
    "mls-recovery-confirmation-v2",
    "mls-recovery-confirmation-receipt-v2",
    "signed-mls-recovery-confirmation-receipt-v2",
    "exact-signed-mls-recovery-confirmation-receipt-v2",
    "mls-recovery-activation-command-v2",
    "mls-recovery-activation-receipt-v2",
    "signed-mls-recovery-activation-receipt-v2",
    "exact-signed-mls-recovery-activation-receipt-v2",
    "mls-recovery-activation-readback-v2",
    "exact-mls-recovery-activation-readback-v2",
    "mls-recovery-completion-child-certificate-v1",
    "exact-mls-recovery-completion-child-certificate-v1",
    "mls-recovery-redacted-completion-evidence-v1",
    "exact-mls-recovery-redacted-completion-evidence-v1",
    "mls-recovery-evidence-issuance-command-v1",
    "mls-recovery-evidence-issuance-receipt-v1",
    "exact-mls-recovery-evidence-issuance-receipt-v1",
    "mls-recovery-completion-cache-command-v2",
    "mls-recovery-completion-cache-receipt-v2",
    "signed-mls-recovery-completion-cache-receipt-v2",
];

// Tokens are exact field types in numeric-key order. Decimal tokens are literal uints;
// `bstr:N` is an inclusive 1..N byte string.
const MAP_LAYOUTS: &[(&str, &str)] = &[
    (
        "mls-recovery-issuer-authorization-request-v1",
        "1 scope identity-id uuid-v7 positive-uint catalog-exhaustive-count exact-catalog-private-body-v2 digest digest uuid-v7 uuid-v7 1 1 utc-millis utc-millis digest bstr:4096 digest signature",
    ),
    (
        "mls-recovery-route-v1",
        "1 https-authority-origin uuid-v7 uuid-v7 uuid-v7 positive-uint digest utc-millis utc-millis signature",
    ),
    (
        "mls-recovery-controller-proof-v1",
        "1 scope identity-id uuid-v7 uuid-v7 ed25519-public-key bstr:4096 digest positive-uint digest utc-millis utc-millis signature",
    ),
    (
        "mls-recovery-add-request-v7",
        "7 uuid-v7 scope identity-id identity-id uuid-v7 ed25519-public-key uuid-v7 exact-history-recovery-request-v4 digest exact-history-recovery-manifest-v2 digest exact-history-recovery-grant-v5 digest exact-recipient-history-offer-v3 digest exact-history-recovery-delivery-fact-v2 digest uuid-v7 positive-uint exact-signed-catalog-head-v2 digest catalog-exhaustive-count catalog-exhaustive-count exact-catalog-opening-v2 digest exact-catalog-proof-v2 digest exact-key-package-publish-receipt-v4 digest exact-key-package-claim-receipt-v4 digest safe-parent digest positive-uint digest safe-parent positive-uint digest bstr:1048576 digest bstr:1048576 digest mls-recovery-route-v1 digest mls-recovery-controller-proof-v1 digest utc-millis utc-millis digest signature",
    ),
    (
        "mls-recovery-add-receipt-v7",
        "7 uuid-v7 scope identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest positive-uint digest positive-uint digest digest digest digest welcome-pending utc-millis",
    ),
    (
        "signed-mls-recovery-add-receipt-v7",
        "mls-recovery-add-receipt-v7 digest uuid-v7 ed25519-public-key signature",
    ),
    (
        "mls-recovery-confirmation-v2",
        "2 uuid-v7 scope identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest positive-uint digest positive-uint digest digest digest exact-signed-mls-recovery-add-receipt-v7 digest utc-millis digest signature",
    ),
    (
        "mls-recovery-confirmation-receipt-v2",
        "2 uuid-v7 scope identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest positive-uint digest positive-uint digest digest digest digest candidate-confirmed utc-millis",
    ),
    (
        "signed-mls-recovery-confirmation-receipt-v2",
        "mls-recovery-confirmation-receipt-v2 digest uuid-v7 ed25519-public-key signature",
    ),
    (
        "mls-recovery-activation-command-v2",
        "2 uuid-v7 uuid-v7 scope identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest positive-uint digest positive-uint digest exact-signed-mls-recovery-confirmation-receipt-v2 digest mls-recovery-controller-proof-v1 digest utc-millis digest signature",
    ),
    (
        "mls-recovery-activation-receipt-v2",
        "2 uuid-v7 uuid-v7 scope identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest positive-uint digest positive-uint digest digest digest digest digest digest activated-fenced utc-millis",
    ),
    (
        "signed-mls-recovery-activation-receipt-v2",
        "mls-recovery-activation-receipt-v2 digest uuid-v7 ed25519-public-key signature",
    ),
    (
        "mls-recovery-activation-readback-v2",
        "2 scope uuid-v7 uuid-v7 identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest positive-uint digest positive-uint digest activated-fenced exact-signed-mls-recovery-activation-receipt-v2 digest utc-millis signature",
    ),
    (
        "mls-recovery-completion-child-certificate-v1",
        "1 ed25519-public-key digest positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest digest 1 1 ed25519-public-key utc-millis utc-millis signature signature",
    ),
    (
        "mls-recovery-redacted-completion-evidence-v1",
        "1 digest digest positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest activated-fenced utc-millis utc-millis signature",
    ),
    (
        "mls-recovery-evidence-issuance-command-v1",
        "1 uuid-v7 uuid-v7 uuid-v7 scope identity-id uuid-v7 uuid-v7 digest uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count exact-catalog-opening-v2 digest exact-catalog-completion-verifier-descriptor-v1 digest exact-signed-mls-recovery-activation-receipt-v2 digest exact-mls-recovery-activation-readback-v2 digest utc-millis utc-millis digest signature",
    ),
    (
        "mls-recovery-evidence-issuance-receipt-v1",
        "1 uuid-v7 digest mls-recovery-completion-child-certificate-v1 digest mls-recovery-redacted-completion-evidence-v1 digest digest digest digest digest digest utc-millis activated-fenced",
    ),
    (
        "mls-recovery-completion-cache-command-v2",
        "2 uuid-v7 scope uuid-v7 uuid-v7 identity-id uuid-v7 uuid-v7 digest uuid-v7 positive-uint digest catalog-exhaustive-count catalog-exhaustive-count digest exact-catalog-opening-v2 digest exact-signed-mls-recovery-activation-receipt-v2 digest exact-mls-recovery-activation-readback-v2 digest exact-mls-recovery-evidence-issuance-receipt-v1 digest exact-history-recovery-completion-presentation-v2 digest utc-millis digest signature",
    ),
    (
        "mls-recovery-completion-cache-receipt-v2",
        "2 uuid-v7 scope uuid-v7 uuid-v7 uuid-v7 digest digest digest digest digest digest digest activated-fenced true utc-millis",
    ),
    (
        "signed-mls-recovery-completion-cache-receipt-v2",
        "mls-recovery-completion-cache-receipt-v2 digest uuid-v7 ed25519-public-key signature",
    ),
];

const MAP_MAXIMA: &[(&str, u64)] = &[
    ("mls-recovery-issuer-authorization-request-v1", 8_953),
    ("mls-recovery-route-v1", 2_304),
    ("mls-recovery-controller-proof-v1", 4_507),
    ("mls-recovery-add-request-v7", 4_489_217),
    ("mls-recovery-add-receipt-v7", 613),
    ("signed-mls-recovery-add-receipt-v7", 791),
    ("mls-recovery-confirmation-v2", 1_510),
    ("mls-recovery-confirmation-receipt-v2", 613),
    ("signed-mls-recovery-confirmation-receipt-v2", 791),
    ("mls-recovery-activation-command-v2", 6_023),
    ("mls-recovery-activation-receipt-v2", 725),
    ("signed-mls-recovery-activation-receipt-v2", 903),
    ("mls-recovery-activation-readback-v2", 1_556),
    ("mls-recovery-completion-child-certificate-v1", 389),
    ("mls-recovery-redacted-completion-evidence-v1", 250),
    ("mls-recovery-evidence-issuance-command-v1", 12_756),
    ("mls-recovery-evidence-issuance-receipt-v1", 975),
    ("mls-recovery-completion-cache-command-v2", 17_155),
    ("mls-recovery-completion-cache-receipt-v2", 482),
    ("signed-mls-recovery-completion-cache-receipt-v2", 660),
];

pub(crate) fn validate(root: &Path) -> Result<(), ProtocolToolError> {
    let cddl = std::fs::read_to_string(root.join(CDDL_RELATIVE))
        .map_err(|error| ProtocolToolError::new(format!("read {CDDL_RELATIVE}: {error}")))?;
    let openapi = std::fs::read_to_string(root.join(OPENAPI_RELATIVE))
        .map_err(|error| ProtocolToolError::new(format!("read {OPENAPI_RELATIVE}: {error}")))?;
    validate_sources(&cddl, &openapi)
}

fn validate_sources(cddl_source: &str, openapi_source: &str) -> Result<(), ProtocolToolError> {
    let cddl = cddl_cat::parse_cddl(cddl_source)
        .map_err(|error| ProtocolToolError::new(format!("parse MLS Sequencer V7 CDDL: {error}")))?;
    cddl::validate_contract(cddl_source, &cddl)?;

    let spec = oas3::from_yaml(openapi_source).map_err(|error| {
        ProtocolToolError::new(format!("parse MLS Sequencer V7 OpenAPI: {error}"))
    })?;
    if spec.openapi != "3.1.0" {
        return Err(ProtocolToolError::new(
            "MLS Sequencer V7 OpenAPI must declare 3.1.0",
        ));
    }
    let document: Value = yaml_serde::from_str(openapi_source).map_err(|error| {
        ProtocolToolError::new(format!("parse MLS Sequencer V7 OpenAPI tree: {error}"))
    })?;
    openapi::validate_contract(&document)?;

    helpers::require_sha256(cddl_source, CDDL_SHA256, "MLS Sequencer V7 CDDL")?;
    helpers::require_sha256(openapi_source, OPENAPI_SHA256, "MLS Sequencer V7 OpenAPI")
}

#[cfg(test)]
mod tests;
