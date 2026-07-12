use std::fmt::Write as _;

use dtx_domain::RequestId;
use dtx_wire::{
    ApiError, ApiErrorCode, ApiErrorResponse, CanonicalEncode, KnownApiErrorCode,
    PublicDetailValue, encode_deterministic_cbor,
};

const REQUEST_ID: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";

#[test]
fn registered_error_uses_stable_defaults_and_bounded_public_details() {
    let request_id: RequestId = REQUEST_ID.parse().unwrap();
    let error = ApiError::new(KnownApiErrorCode::PlanRevisionConflict, request_id)
        .with_detail("current_revision", PublicDetailValue::integer(5).unwrap())
        .expect("safe detail");

    assert_eq!(error.code().as_str(), "PLAN_REVISION_CONFLICT");
    assert_eq!(error.message(), "The job plan changed before approval.");
    assert!(!error.retryable());
    assert_eq!(
        error.code().known(),
        Some(KnownApiErrorCode::PlanRevisionConflict)
    );

    let response = ApiErrorResponse::new(error);
    let json = serde_json::to_value(&response).unwrap();
    assert_eq!(json["error"]["request_id"], REQUEST_ID);
    assert_eq!(json["error"]["details"]["current_revision"], 5);
}

#[test]
fn api_error_matches_the_cross_language_canonical_cbor_vector() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/v1/api-errors.json"
    ))
    .unwrap();
    let request_id: RequestId = REQUEST_ID.parse().unwrap();
    let error = ApiError::new(KnownApiErrorCode::PlanRevisionConflict, request_id)
        .with_detail("current_revision", PublicDetailValue::integer(5).unwrap())
        .unwrap();

    assert_eq!(serde_json::to_value(&error).unwrap(), vector["error"]);
    let encoded = encode_deterministic_cbor(&error.to_canonical_value()).unwrap();
    let mut actual_hex = String::with_capacity(encoded.len() * 2);
    for byte in encoded {
        write!(&mut actual_hex, "{byte:02x}").unwrap();
    }
    assert_eq!(actual_hex, vector["canonical_cbor_hex"]);
}

#[test]
fn decoder_preserves_a_valid_unknown_future_error_code() {
    let json = format!(
        r#"{{"error":{{"code":"FUTURE_SERVER_BUSY","message":"A future condition occurred.","request_id":"{REQUEST_ID}","retryable":true,"details":{{}}}}}}"#
    );

    let response: ApiErrorResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(response.error().code().as_str(), "FUTURE_SERVER_BUSY");
    assert_eq!(response.error().code().known(), None);
    assert!(response.error().retryable());
}

#[test]
fn typed_error_rejects_unknown_fields_invalid_codes_and_nested_details() {
    let unknown_field = format!(
        r#"{{"error":{{"code":"FORBIDDEN","message":"This operation is not allowed.","request_id":"{REQUEST_ID}","retryable":false,"details":{{}},"provider_response":"not allowed"}}}}"#
    );
    let lowercase_code = format!(
        r#"{{"error":{{"code":"future_error","message":"Invalid.","request_id":"{REQUEST_ID}","retryable":false,"details":{{}}}}}}"#
    );
    let nested_details = format!(
        r#"{{"error":{{"code":"FORBIDDEN","message":"This operation is not allowed.","request_id":"{REQUEST_ID}","retryable":false,"details":{{"nested":{{"value":"not allowed"}}}}}}}}"#
    );
    let unsafe_integer = format!(
        r#"{{"error":{{"code":"FORBIDDEN","message":"This operation is not allowed.","request_id":"{REQUEST_ID}","retryable":false,"details":{{"sequence":9007199254740992}}}}}}"#
    );
    let ambiguous_empty_list = format!(
        r#"{{"error":{{"code":"FORBIDDEN","message":"This operation is not allowed.","request_id":"{REQUEST_ID}","retryable":false,"details":{{"values":[]}}}}}}"#
    );

    assert!(serde_json::from_str::<ApiErrorResponse>(&unknown_field).is_err());
    assert!(serde_json::from_str::<ApiErrorResponse>(&lowercase_code).is_err());
    assert!(serde_json::from_str::<ApiErrorResponse>(&nested_details).is_err());
    assert!(serde_json::from_str::<ApiErrorResponse>(&unsafe_integer).is_err());
    assert!(serde_json::from_str::<ApiErrorResponse>(&ambiguous_empty_list).is_err());
}

#[test]
fn public_detail_bounds_are_enforced_before_serialization() {
    const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

    assert!(PublicDetailValue::text("x".repeat(257)).is_err());
    assert!(PublicDetailValue::text("line\nbreak").is_err());
    assert!(PublicDetailValue::text_list(Vec::new()).is_err());
    assert!(PublicDetailValue::text_list(vec!["x".to_owned(); 17]).is_err());
    assert!(PublicDetailValue::integer(MAX_SAFE_INTEGER).is_ok());
    assert!(PublicDetailValue::integer(-MAX_SAFE_INTEGER).is_ok());
    assert!(PublicDetailValue::integer(MAX_SAFE_INTEGER + 1).is_err());
    assert!(PublicDetailValue::integer(-MAX_SAFE_INTEGER - 1).is_err());
    assert!(PublicDetailValue::integer_list(Vec::new()).is_err());
    assert!(PublicDetailValue::integer_list(vec![MAX_SAFE_INTEGER; 16]).is_ok());
    assert!(PublicDetailValue::integer_list(vec![0; 17]).is_err());

    let request_id: RequestId = REQUEST_ID.parse().unwrap();
    let error = ApiError::new(KnownApiErrorCode::Forbidden, request_id);
    assert!(
        error
            .with_detail("Invalid-Key", PublicDetailValue::boolean(true))
            .is_err()
    );
}

#[test]
fn known_error_code_set_contains_every_required_v1_code() {
    let required = [
        "UNAUTHENTICATED",
        "DEVICE_REVOKED",
        "FORBIDDEN",
        "POLICY_DENIED",
        "CONSENT_REQUIRED",
        "APPROVAL_REQUIRED",
        "APPROVAL_EXPIRED",
        "REVISION_CONFLICT",
        "IDEMPOTENCY_CONFLICT",
        "CONNECTOR_OFFLINE",
        "CONNECTOR_UNHEALTHY",
        "CAPABILITY_UNAVAILABLE",
        "STALE_LEASE",
        "PLAN_REVISION_CONFLICT",
        "BUDGET_EXCEEDED",
        "CLOUD_CONNECTION_INVALID",
        "CLOUD_CONNECTION_IN_USE",
        "CLOUD_PERMISSION_MISSING",
        "CLOUD_RATE_LIMITED",
        "RESOURCE_DISPOSITION_BLOCKED",
        "RESOURCE_ORPHANED",
        "VERIFICATION_FAILED",
        "HANDOFF_REQUIRED",
        "CURSOR_EXPIRED",
        "PROTOCOL_VERSION_UNSUPPORTED",
    ];

    assert_eq!(KnownApiErrorCode::ALL.len(), required.len());
    for code in required {
        assert!(
            KnownApiErrorCode::ALL
                .iter()
                .any(|candidate| candidate.as_str() == code),
            "missing {code}"
        );
        assert!(ApiErrorCode::parse(code).is_ok());
    }
}
