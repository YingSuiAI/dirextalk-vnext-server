use dtx_agent_control::{
    ApplyConfigCommand, CloseStreamCommand, CloseStreamReason, ConfigEntry,
    DeliverAgentProvisioningCommand, DeliverAgentRouteBootstrap, OpaqueAgentRouteBytes,
    PrepareAgentRouteRecipient, RevokeAgentProvisioningCommand, RotateCredentialCommand,
    ServerCommandPayload, Sha256Digest, command_payload_digest,
};
use dtx_agent_control_proto::v1;
use dtx_agent_control_server::{ProtobufDurableCommandDecoder, ProtobufDurableCommandEncoder};
use dtx_agent_persistence::DurableCommandDecoder as _;
use dtx_connect_registry::ConnectorDesiredState;
use dtx_domain::{
    AgentDeviceId, AgentRouteBootstrapId, AgentRouteDeliveryId, AgentRouteRecipientId, ApprovalId,
    BindingId, ConversationId, DeviceId, IdentityId, InstallationId, ProvisioningDeliveryId,
    ProvisioningRecipientKeyId, RequestId, Revision, TenantId,
};
use prost::Message as _;

const OPERATION_ID: &str = "01890f47-3a5b-7c1d-8e2f-123456789abc";
const OWNER_IDENTITY_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

#[test]
fn decodes_the_exact_nested_payload_including_unknown_fields() {
    let mut payload = v1::ApplyConfig {
        config_revision: 8,
        desired_state: v1::DesiredConnectorState::Running as i32,
        adapter_config: vec![v1::ConfigEntry {
            key: "endpoint".to_owned(),
            value: "local".to_owned(),
        }],
        runtime_config: vec![v1::ConfigEntry {
            key: "model".to_owned(),
            value: "agent-v1".to_owned(),
        }],
    }
    .encode_to_vec();
    put_varint_field(&mut payload, 99, 42);
    let expected_digest = command_payload_digest(&payload).expect("bounded payload");
    let mut exact = encode_command(10, &payload, expected_digest.as_bytes());
    put_varint_field(&mut exact, 100, 1);

    let decoded = ProtobufDurableCommandDecoder
        .decode(&exact)
        .expect("exact payload should decode");

    assert_eq!(decoded.sequence, 1);
    assert_eq!(decoded.operation_id.to_string(), OPERATION_ID);
    assert_eq!(decoded.generation, 3);
    assert_eq!(decoded.spec_revision.get(), 7);
    assert_eq!(decoded.payload_digest, expected_digest);
    let ServerCommandPayload::ApplyConfig(command) = decoded.payload else {
        panic!("expected ApplyConfig");
    };
    assert_eq!(command.config_revision().get(), 8);
    assert_eq!(command.desired_state(), ConnectorDesiredState::Running);
    assert_eq!(command.adapter_config()[0].key(), "endpoint");
    assert_eq!(command.adapter_config()[0].value(), "local");
    assert_eq!(command.runtime_config()[0].key(), "model");
    assert_eq!(command.runtime_config()[0].value(), "agent-v1");
}

#[test]
fn rejects_payload_tampering_even_when_the_known_message_is_unchanged() {
    let mut payload = v1::CloseStream {
        reason: v1::CloseStreamReason::Drained as i32,
        stable_code: "DRAINED".to_owned(),
        redacted_detail: String::new(),
    }
    .encode_to_vec();
    put_varint_field(&mut payload, 99, 1);
    let digest = command_payload_digest(&payload)
        .expect("bounded payload")
        .as_bytes();
    let mut tampered_payload = payload;
    *tampered_payload.last_mut().expect("unknown value byte") = 2;
    let exact = encode_command(12, &tampered_payload, digest);

    assert!(ProtobufDurableCommandDecoder.decode(&exact).is_err());
}

#[test]
fn rejects_duplicate_or_wrong_wire_command_selection() {
    let payload = v1::CloseStream {
        reason: v1::CloseStreamReason::Reconnect as i32,
        stable_code: "RECONNECT".to_owned(),
        redacted_detail: String::new(),
    }
    .encode_to_vec();
    let digest = command_payload_digest(&payload)
        .expect("bounded payload")
        .as_bytes();
    let mut duplicate = encode_command(12, &payload, digest);
    put_length_delimited_field(&mut duplicate, 12, &payload);
    assert!(ProtobufDurableCommandDecoder.decode(&duplicate).is_err());

    let mut wrong_wire = encode_command(12, &payload, digest);
    put_varint_field(&mut wrong_wire, 12, 1);
    assert!(ProtobufDurableCommandDecoder.decode(&wrong_wire).is_err());
}

#[test]
fn rejects_unknown_or_secret_bearing_configuration_on_rehydration() {
    for (key, value) in [
        ("future-unregistered-key", "public"),
        ("profile", "secret://connector/token"),
        ("profile", "my-opaque-token-123"),
    ] {
        let payload = v1::ApplyConfig {
            config_revision: 8,
            desired_state: v1::DesiredConnectorState::Running as i32,
            adapter_config: vec![v1::ConfigEntry {
                key: key.to_owned(),
                value: value.to_owned(),
            }],
            runtime_config: Vec::new(),
        }
        .encode_to_vec();
        let digest = command_payload_digest(&payload)
            .expect("bounded payload")
            .as_bytes();

        assert!(
            ProtobufDurableCommandDecoder
                .decode(&encode_command(10, &payload, digest))
                .is_err()
        );
    }
}

#[test]
fn maps_rotate_and_close_commands_without_losing_fields() {
    let rotate = v1::RotateCredential {
        rotation_nonce: vec![7; 32],
        successor_revision: 8,
        deadline_millis: 2_000,
    }
    .encode_to_vec();
    let rotate_digest = command_payload_digest(&rotate)
        .expect("bounded payload")
        .as_bytes();
    let rotate = ProtobufDurableCommandDecoder
        .decode(&encode_command(11, &rotate, rotate_digest))
        .expect("RotateCredential should decode");
    let ServerCommandPayload::RotateCredential(rotate) = rotate.payload else {
        panic!("expected RotateCredential");
    };
    assert_eq!(rotate.nonce(), [7; 32]);
    assert_eq!(rotate.successor_revision().get(), 8);
    assert_eq!(rotate.deadline_millis(), 2_000);

    let close = v1::CloseStream {
        reason: v1::CloseStreamReason::ProtocolUpgrade as i32,
        stable_code: "PROTOCOL_UPGRADE".to_owned(),
        redacted_detail: "client update required".to_owned(),
    }
    .encode_to_vec();
    let close_digest = command_payload_digest(&close)
        .expect("bounded payload")
        .as_bytes();
    let close = ProtobufDurableCommandDecoder
        .decode(&encode_command(12, &close, close_digest))
        .expect("CloseStream should decode");
    let ServerCommandPayload::CloseStream(close) = close.payload else {
        panic!("expected CloseStream");
    };
    assert_eq!(close.reason(), CloseStreamReason::ProtocolUpgrade);
    assert_eq!(close.stable_code(), "PROTOCOL_UPGRADE");
    assert_eq!(close.redacted_detail(), "client update required");
}

#[test]
fn production_encoder_round_trips_every_closed_command_without_reconstruction() {
    let revision = Revision::new(7).unwrap();
    let operation_id = OPERATION_ID.parse::<RequestId>().unwrap();
    let payloads = [
        ServerCommandPayload::ApplyConfig(
            ApplyConfigCommand::new(
                revision.checked_next().unwrap(),
                ConnectorDesiredState::Running,
                vec![ConfigEntry::new("endpoint".to_owned(), "local".to_owned()).unwrap()],
                vec![ConfigEntry::new("model".to_owned(), "agent-v1".to_owned()).unwrap()],
            )
            .unwrap(),
        ),
        ServerCommandPayload::RotateCredential(
            RotateCredentialCommand::new([7; 32], revision.checked_next().unwrap(), 2_000).unwrap(),
        ),
        ServerCommandPayload::CloseStream(CloseStreamCommand::protocol_upgrade()),
        ServerCommandPayload::DeliverAgentProvisioning(
            DeliverAgentProvisioningCommand::new(
                "01890f47-3a5b-7c1d-8e2f-123456789ab1"
                    .parse::<ProvisioningDeliveryId>()
                    .unwrap(),
                "01890f47-3a5b-7c1d-8e2f-123456789ab2"
                    .parse::<ApprovalId>()
                    .unwrap(),
                "01890f47-3a5b-7c1d-8e2f-123456789ab3"
                    .parse::<BindingId>()
                    .unwrap(),
                "01890f47-3a5b-7c1d-8e2f-123456789ab4"
                    .parse::<InstallationId>()
                    .unwrap(),
                "01890f47-3a5b-7c1d-8e2f-123456789ab5"
                    .parse::<AgentDeviceId>()
                    .unwrap(),
                Revision::new(8).unwrap(),
                "01890f47-3a5b-7c1d-8e2f-123456789ab6"
                    .parse::<ProvisioningRecipientKeyId>()
                    .unwrap(),
                Sha256Digest::from_bytes([0x11; 32]),
                Sha256Digest::from_bytes([0x22; 32]),
                vec![0xa5; 64],
                2_000,
            )
            .unwrap(),
        ),
        ServerCommandPayload::RevokeAgentProvisioning(
            RevokeAgentProvisioningCommand::new(
                operation_id,
                "01890f47-3a5b-7c1d-8e2f-123456789ab4"
                    .parse::<InstallationId>()
                    .unwrap(),
                "01890f47-3a5b-7c1d-8e2f-123456789ab3"
                    .parse::<BindingId>()
                    .unwrap(),
                Some(
                    "01890f47-3a5b-7c1d-8e2f-123456789ab5"
                        .parse::<AgentDeviceId>()
                        .unwrap(),
                ),
                Revision::new(9).unwrap(),
                2_000,
            )
            .unwrap(),
        ),
        ServerCommandPayload::PrepareAgentRouteRecipient(PrepareAgentRouteRecipient {
            bootstrap_id: "01890f47-3a5b-7c1d-8e2f-123456789ac1"
                .parse::<AgentRouteBootstrapId>()
                .unwrap(),
            tenant_id: "01890f47-3a5b-7c1d-8e2f-123456789ac2"
                .parse::<TenantId>()
                .unwrap(),
            installation_id: "01890f47-3a5b-7c1d-8e2f-123456789ab4"
                .parse::<InstallationId>()
                .unwrap(),
            binding_id: "01890f47-3a5b-7c1d-8e2f-123456789ab3"
                .parse::<BindingId>()
                .unwrap(),
            agent_control_device_id: "01890f47-3a5b-7c1d-8e2f-123456789ab5"
                .parse::<AgentDeviceId>()
                .unwrap(),
            owner_identity_id: OWNER_IDENTITY_ID.parse::<IdentityId>().unwrap(),
            owner_device_id: "01890f47-3a5b-7c1d-8e2f-123456789ac4"
                .parse::<DeviceId>()
                .unwrap(),
            owner_signed_intent: OpaqueAgentRouteBytes::new(b"private-owner-intent".to_vec())
                .unwrap(),
            expires_at_millis: 2_000,
        }),
        ServerCommandPayload::DeliverAgentRouteBootstrap(DeliverAgentRouteBootstrap {
            bootstrap_id: "01890f47-3a5b-7c1d-8e2f-123456789ac1"
                .parse::<AgentRouteBootstrapId>()
                .unwrap(),
            delivery_id: "01890f47-3a5b-7c1d-8e2f-123456789ac5"
                .parse::<AgentRouteDeliveryId>()
                .unwrap(),
            route_id: "01890f47-3a5b-7c1d-8e2f-123456789ac6"
                .parse::<ConversationId>()
                .unwrap(),
            recipient_id: "01890f47-3a5b-7c1d-8e2f-123456789ac7"
                .parse::<AgentRouteRecipientId>()
                .unwrap(),
            capsule_digest: Sha256Digest::from_bytes([0x33; 32]),
            opaque_sealed_bootstrap: OpaqueAgentRouteBytes::new(
                b"private-sealed-bootstrap".to_vec(),
            )
            .unwrap(),
            expires_at_millis: 2_000,
            installation_id: "01890f47-3a5b-7c1d-8e2f-123456789ab4"
                .parse::<InstallationId>()
                .unwrap(),
            binding_id: "01890f47-3a5b-7c1d-8e2f-123456789ab3"
                .parse::<BindingId>()
                .unwrap(),
            agent_control_device_id: "01890f47-3a5b-7c1d-8e2f-123456789ab5"
                .parse::<AgentDeviceId>()
                .unwrap(),
            route_health_key_id: None,
            route_health_public_key_digest: None,
        }),
    ];
    for payload in payloads {
        let encoded = ProtobufDurableCommandEncoder
            .encode(1, operation_id, 3, revision, &payload)
            .expect("closed payload encodes");
        let decoded = ProtobufDurableCommandDecoder
            .decode(encoded.exact_bytes().as_slice())
            .expect("production encoding passes the strict decoder");
        assert_eq!(decoded.payload, payload);
        assert_eq!(decoded.payload_digest, encoded.payload_digest());
        let repeated = ProtobufDurableCommandEncoder
            .encode(1, operation_id, 3, revision, &decoded.payload)
            .expect("canonical retry encodes");
        assert_eq!(
            repeated.exact_bytes().as_slice(),
            encoded.exact_bytes().as_slice(),
            "the encoder is byte deterministic"
        );
    }
}

#[test]
fn rejects_malformed_route_bootstrap_payloads_without_logging_opaque_bytes() {
    let invalid_digest_payload = v1::DeliverAgentRouteBootstrap {
        bootstrap_id: "01890f47-3a5b-7c1d-8e2f-123456789ac1".to_owned(),
        delivery_id: "01890f47-3a5b-7c1d-8e2f-123456789ac5".to_owned(),
        route_id: "01890f47-3a5b-7c1d-8e2f-123456789ac6".to_owned(),
        recipient_id: "01890f47-3a5b-7c1d-8e2f-123456789ac7".to_owned(),
        capsule_digest: vec![0x33; 31],
        opaque_sealed_bootstrap: b"private-sealed-bootstrap".to_vec(),
        expires_at_millis: 2_000,
        installation_id: "01890f47-3a5b-7c1d-8e2f-123456789ab4".to_owned(),
        binding_id: "01890f47-3a5b-7c1d-8e2f-123456789ab3".to_owned(),
        agent_control_device_id: "01890f47-3a5b-7c1d-8e2f-123456789ab5".to_owned(),
        route_health_key_id: String::new(),
        route_health_public_key_digest: Vec::new(),
    }
    .encode_to_vec();
    let invalid_digest = command_payload_digest(&invalid_digest_payload)
        .expect("bounded payload")
        .as_bytes();
    assert!(
        ProtobufDurableCommandDecoder
            .decode(&encode_command(16, &invalid_digest_payload, invalid_digest))
            .is_err()
    );

    let invalid_health_pair_payload = v1::DeliverAgentRouteBootstrap {
        bootstrap_id: "01890f47-3a5b-7c1d-8e2f-123456789ac1".to_owned(),
        delivery_id: "01890f47-3a5b-7c1d-8e2f-123456789ac5".to_owned(),
        route_id: "01890f47-3a5b-7c1d-8e2f-123456789ac6".to_owned(),
        recipient_id: "01890f47-3a5b-7c1d-8e2f-123456789ac7".to_owned(),
        capsule_digest: vec![0x33; 32],
        opaque_sealed_bootstrap: b"private-sealed-bootstrap".to_vec(),
        expires_at_millis: 2_000,
        installation_id: "01890f47-3a5b-7c1d-8e2f-123456789ab4".to_owned(),
        binding_id: "01890f47-3a5b-7c1d-8e2f-123456789ab3".to_owned(),
        agent_control_device_id: "01890f47-3a5b-7c1d-8e2f-123456789ab5".to_owned(),
        route_health_key_id: "01890f47-3a5b-7c1d-8e2f-123456789ac1".to_owned(),
        route_health_public_key_digest: Vec::new(),
    }
    .encode_to_vec();
    let invalid_health_pair_digest = command_payload_digest(&invalid_health_pair_payload)
        .expect("bounded payload")
        .as_bytes();
    assert!(
        ProtobufDurableCommandDecoder
            .decode(&encode_command(
                16,
                &invalid_health_pair_payload,
                invalid_health_pair_digest,
            ))
            .is_err()
    );

    let invalid_expiry_payload = v1::PrepareAgentRouteRecipient {
        bootstrap_id: "01890f47-3a5b-7c1d-8e2f-123456789ac1".to_owned(),
        tenant_id: "01890f47-3a5b-7c1d-8e2f-123456789ac2".to_owned(),
        installation_id: "01890f47-3a5b-7c1d-8e2f-123456789ab4".to_owned(),
        binding_id: "01890f47-3a5b-7c1d-8e2f-123456789ab3".to_owned(),
        agent_control_device_id: "01890f47-3a5b-7c1d-8e2f-123456789ab5".to_owned(),
        owner_identity_id: OWNER_IDENTITY_ID.to_owned(),
        owner_device_id: "01890f47-3a5b-7c1d-8e2f-123456789ac4".to_owned(),
        owner_signed_intent: b"private-owner-intent".to_vec(),
        expires_at_millis: 0,
    }
    .encode_to_vec();
    let invalid_expiry = command_payload_digest(&invalid_expiry_payload)
        .expect("bounded payload")
        .as_bytes();
    assert!(
        ProtobufDurableCommandDecoder
            .decode(&encode_command(15, &invalid_expiry_payload, invalid_expiry))
            .is_err()
    );

    let payload = PrepareAgentRouteRecipient {
        bootstrap_id: "01890f47-3a5b-7c1d-8e2f-123456789ac1"
            .parse::<AgentRouteBootstrapId>()
            .unwrap(),
        tenant_id: "01890f47-3a5b-7c1d-8e2f-123456789ac2"
            .parse::<TenantId>()
            .unwrap(),
        installation_id: "01890f47-3a5b-7c1d-8e2f-123456789ab4"
            .parse::<InstallationId>()
            .unwrap(),
        binding_id: "01890f47-3a5b-7c1d-8e2f-123456789ab3"
            .parse::<BindingId>()
            .unwrap(),
        agent_control_device_id: "01890f47-3a5b-7c1d-8e2f-123456789ab5"
            .parse::<AgentDeviceId>()
            .unwrap(),
        owner_identity_id: OWNER_IDENTITY_ID.parse::<IdentityId>().unwrap(),
        owner_device_id: "01890f47-3a5b-7c1d-8e2f-123456789ac4"
            .parse::<DeviceId>()
            .unwrap(),
        owner_signed_intent: OpaqueAgentRouteBytes::new(b"private-owner-intent".to_vec()).unwrap(),
        expires_at_millis: 2_000,
    };
    let debug = format!("{payload:?}");
    assert!(!debug.contains("private-owner-intent"));

    let mut zero_expiry = payload;
    zero_expiry.expires_at_millis = 0;
    assert!(
        ProtobufDurableCommandEncoder
            .encode(
                1,
                OPERATION_ID.parse::<RequestId>().unwrap(),
                3,
                Revision::new(7).unwrap(),
                &ServerCommandPayload::PrepareAgentRouteRecipient(zero_expiry),
            )
            .is_err()
    );
}

fn encode_command(payload_field: u32, payload: &[u8], payload_digest: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    put_varint_field(&mut bytes, 1, 1);
    put_length_delimited_field(&mut bytes, 2, OPERATION_ID.as_bytes());
    put_varint_field(&mut bytes, 3, 3);
    put_varint_field(&mut bytes, 4, 7);
    put_length_delimited_field(&mut bytes, 5, &payload_digest);
    put_length_delimited_field(&mut bytes, payload_field, payload);
    bytes
}

fn put_varint_field(bytes: &mut Vec<u8>, number: u32, value: u64) {
    put_varint(bytes, u64::from(number) << 3);
    put_varint(bytes, value);
}

fn put_length_delimited_field(bytes: &mut Vec<u8>, number: u32, value: &[u8]) {
    put_varint(bytes, (u64::from(number) << 3) | 2);
    put_varint(bytes, value.len() as u64);
    bytes.extend_from_slice(value);
}

fn put_varint(bytes: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        bytes.push(u8::try_from(value & 0x7f).expect("seven bits fit u8") | 0x80);
        value >>= 7;
    }
    bytes.push(u8::try_from(value).expect("final varint byte fits u8"));
}
