
use std::net::IpAddr;

use super::*;

#[tokio::test]
async fn readiness_is_fixed_and_only_reports_after_router_startup() {
    assert_eq!(LIVE_PATH, "/local/live");
    assert_eq!(READY_PATH, "/local/ready");
    let health = OutboxHealth::starting();
    assert!(!health.ready(Instant::now()));
    let mut health = health;
    health.succeeded(Instant::now());
    assert!(health.ready(Instant::now()));
    health.failed();
    health.failed();
    health.failed();
    assert!(!health.ready(Instant::now()));
}

#[test]
fn rejects_textual_or_capability_bearing_frames() {
    let invalid = encode_map(vec![
        (1, CanonicalValue::Unsigned(1)),
        (2, CanonicalValue::Unsigned(2)),
        (3, CanonicalValue::Text("plaintext-room-name".to_owned())),
        (4, CanonicalValue::Unsigned(1)),
    ]);
    assert!(decode_client_frame(&invalid, WireLine::V1).is_err());
}

#[test]
fn ephemeral_requires_bounded_typed_signal() {
    let frame = encode_map(vec![
        (1, CanonicalValue::Unsigned(1)),
        (2, CanonicalValue::Unsigned(4)),
        (3, CanonicalValue::Unsigned(1)),
        (4, CanonicalValue::Bytes(vec![7; 32])),
        (5, CanonicalValue::Unsigned(10_000)),
        (6, CanonicalValue::Bool(false)),
    ]);
    assert!(matches!(
        decode_client_frame(&frame, WireLine::V1),
        Ok(ClientFrame::Ephemeral { kind: 1, .. })
    ));
}

#[test]
fn ephemeral_expiry_is_strict() {
    let source_identity = "dtxi1l7a4yw7wcc5nlo6p74d3oorsb5fgkpvrphihkgqxexrisc5h43ka"
        .parse::<IdentityId>()
        .expect("valid test identity");
    let target_identity = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la"
        .parse::<IdentityId>()
        .expect("valid target identity");
    let source_connection_id = Uuid::now_v7();
    let target_connection_id = Uuid::now_v7();
    let registry = EphemeralRegistry::default();
    assert!(registry.subscribe(
        target_connection_id,
        target_identity,
        [7; 32],
        10_000,
        true,
        UtcMillis::new(9_000).expect("valid test time"),
    ));
    let signal = EphemeralSignal {
        source_connection_id,
        source_identity_id: source_identity,
        source_actor_digest: Sha256Digest::from_bytes([8; 32]),
        kind: 1,
        scope_digest: [7; 32],
        expires_at_ms: 10_000,
    };
    assert!(registry.is_visible(
        signal,
        target_connection_id,
        target_identity,
        UtcMillis::new(9_999).expect("valid test time")
    ));
    assert!(!registry.is_visible(
        signal,
        target_connection_id,
        target_identity,
        UtcMillis::new(10_000).expect("valid test time")
    ));
}

#[test]
fn v2_scope_subscription_routes_only_to_intended_active_peer() {
    let source_identity = "dtxi1l7a4yw7wcc5nlo6p74d3oorsb5fgkpvrphihkgqxexrisc5h43ka"
        .parse::<IdentityId>()
        .expect("valid source identity");
    let target_identity = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la"
        .parse::<IdentityId>()
        .expect("valid target identity");
    let source_connection_id = Uuid::now_v7();
    let target_connection_id = Uuid::now_v7();
    let outsider_connection_id = Uuid::now_v7();
    let now = UtcMillis::new(1_000).expect("valid now");
    let registry = EphemeralRegistry::default();
    assert!(registry.subscribe(
        source_connection_id,
        source_identity,
        [9; 32],
        2_000,
        true,
        now,
    ));
    assert!(registry.subscribe(
        target_connection_id,
        target_identity,
        [9; 32],
        2_000,
        true,
        now,
    ));
    assert!(registry.subscribe(
        outsider_connection_id,
        target_identity,
        [10; 32],
        2_000,
        true,
        now,
    ));
    let signal = EphemeralSignal {
        source_connection_id,
        source_identity_id: source_identity,
        source_actor_digest: Sha256Digest::from_bytes([11; 32]),
        kind: 1,
        scope_digest: [9; 32],
        expires_at_ms: 1_500,
    };
    assert!(registry.is_visible(signal, target_connection_id, target_identity, now));
    assert!(!registry.is_visible(signal, source_connection_id, source_identity, now));
    assert!(!registry.is_visible(signal, outsider_connection_id, target_identity, now));
}

#[test]
fn admission_is_globally_and_per_source_bounded_and_released() {
    let gate = Arc::new(AdmissionGate::new(2, 1));
    let first_source: IpAddr = "192.0.2.1".parse().expect("valid source");
    let second_source: IpAddr = "192.0.2.2".parse().expect("valid source");
    let first = gate.try_acquire(first_source).expect("first admitted");
    assert!(gate.try_acquire(first_source).is_none());
    let second = gate.try_acquire(second_source).expect("second admitted");
    assert!(
        gate.try_acquire("192.0.2.3".parse().expect("valid source"))
            .is_none()
    );
    drop(first);
    assert!(gate.try_acquire(first_source).is_some());
    drop(second);
}

#[test]
fn v2_is_preferred_and_hello_deadline_is_five_seconds() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        format!("{SUBPROTOCOL_V1}, {SUBPROTOCOL_V2}")
            .parse()
            .expect("valid header"),
    );
    assert_eq!(negotiated_wire(&headers), Some(WireLine::V2));
    assert_eq!(HELLO_TIMEOUT, Duration::from_secs(5));
}
