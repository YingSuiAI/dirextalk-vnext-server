use dtx_domain::{ConnectorId, DeviceId, IdParseError};

const UUID_V7: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";

#[test]
fn device_id_accepts_and_round_trips_uuid_v7() {
    let id: DeviceId = UUID_V7.parse().expect("valid UUIDv7 device ID");

    assert_eq!(id.to_string(), UUID_V7);
    assert_eq!(id.as_uuid().get_version_num(), 7);
}

#[test]
fn generated_connector_id_is_uuid_v7() {
    let id = ConnectorId::new();

    assert_eq!(id.as_uuid().get_version_num(), 7);
}

#[test]
fn device_id_rejects_a_different_uuid_version() {
    let error = "550e8400-e29b-41d4-a716-446655440000"
        .parse::<DeviceId>()
        .expect_err("UUIDv4 must not enter a UUIDv7 domain field");

    assert!(matches!(
        error,
        IdParseError::UnsupportedVersion {
            actual: Some(4),
            ..
        }
    ));
}

#[test]
fn device_id_rejects_a_non_rfc_uuid_variant() {
    let error = "0190f2a5-7b1c-7abc-0def-0123456789ab"
        .parse::<DeviceId>()
        .expect_err("UUIDv7 identifiers require the RFC variant");

    assert!(matches!(error, IdParseError::UnsupportedVariant { .. }));
}
