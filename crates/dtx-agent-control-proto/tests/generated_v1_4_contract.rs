use dtx_agent_control_proto::AGENT_CONTROL_WIRE_PROTOCOL_V1_5;
use prost::Message;
use prost_types::{
    DescriptorProto, FileDescriptorProto, FileDescriptorSet, field_descriptor_proto::Type,
};

#[test]
fn v1_5_descriptor_keeps_the_existing_service_and_closed_additive_surface() {
    assert_eq!(AGENT_CONTROL_WIRE_PROTOCOL_V1_5, "agent-control/1.5");
    let descriptor = FileDescriptorSet::decode(dtx_agent_control_proto::v1::FILE_DESCRIPTOR_SET)
        .expect("generated V1.4 descriptor is valid");
    let file = descriptor
        .file
        .iter()
        .find(|file| file.package.as_deref() == Some("dirextalk.agent_control.v1"))
        .expect("agent-control v1 package is generated");
    assert_eq!(
        file.service
            .iter()
            .filter_map(|service| service.name.as_deref())
            .collect::<Vec<_>>(),
        ["ConnectorEnrollment", "ConnectorControl"]
    );
    let enrollment = file
        .service
        .iter()
        .find(|service| service.name.as_deref() == Some("ConnectorEnrollment"))
        .expect("ConnectorEnrollment exists");
    assert_eq!(
        enrollment
            .method
            .iter()
            .filter_map(|method| method.name.as_deref())
            .collect::<Vec<_>>(),
        ["EnrollConnector", "ReissueConnectorCredential"],
    );
    assert_fields(
        file,
        "ReissueConnectorCredentialRequest",
        &[
            ("operation_id", 1, Type::String),
            ("intent_id", 2, Type::String),
            ("reissue_token", 3, Type::Bytes),
            ("tenant_id", 4, Type::String),
            ("host_id", 5, Type::String),
            ("connector_id", 6, Type::String),
            ("current_credential_id", 7, Type::String),
            ("current_leaf_fingerprint_sha256", 8, Type::Bytes),
            ("connector_generation", 9, Type::Uint64),
            ("spec_revision", 10, Type::Uint64),
            ("new_control_public_key", 11, Type::Bytes),
            ("current_control_signature", 12, Type::Bytes),
            ("new_control_signature", 13, Type::Bytes),
        ],
    );
    assert_eq!(
        oneof_fields(message(file, "ClientFrame"), "kind"),
        [
            ("hello", 1),
            ("ready", 2),
            ("heartbeat", 3),
            ("command_acknowledgement", 4),
            ("credential_rotation_proof", 5),
            ("run_claim", 6),
            ("run_release", 7),
            ("run_checkpoint", 8),
            ("run_output", 9),
            ("run_completed", 10),
            ("run_failed", 11),
            ("provisioning_recipient_announcement", 12),
            ("agent_provisioning_installed", 13),
            ("agent_provisioning_rejected", 14),
            ("agent_route_recipient_ready", 15),
            ("agent_route_bootstrap_installed", 16),
            ("agent_route_bootstrap_rejected", 17),
        ]
    );
    assert_eq!(
        oneof_fields(message(file, "DurableCommand"), "command"),
        [
            ("apply_config", 10),
            ("rotate_credential", 11),
            ("close_stream", 12),
            ("deliver_agent_provisioning", 13),
            ("revoke_agent_provisioning", 14),
            ("prepare_agent_route_recipient", 15),
            ("deliver_agent_route_bootstrap", 16),
        ]
    );
    assert!(
        file.message_type
            .iter()
            .flat_map(|message| &message.field)
            .all(|field| !matches!(
                field.type_name.as_deref(),
                Some(".google.protobuf.Any" | ".google.protobuf.Struct")
            ))
    );
}

#[test]
fn v1_4_route_bootstrap_messages_keep_exact_names_numbers_and_types() {
    let descriptor = FileDescriptorSet::decode(dtx_agent_control_proto::v1::FILE_DESCRIPTOR_SET)
        .expect("generated V1.4 descriptor is valid");
    let file = descriptor
        .file
        .iter()
        .find(|file| file.package.as_deref() == Some("dirextalk.agent_control.v1"))
        .expect("agent-control v1 package is generated");

    assert_fields(
        file,
        "AgentRouteRecipientReady",
        &[
            ("connector_fence", 1, Type::Message),
            ("bootstrap_id", 2, Type::String),
            ("command_sequence", 3, Type::Uint64),
            ("command_payload_digest", 4, Type::Bytes),
            ("encoded_command_digest", 5, Type::Bytes),
            ("installation_id", 6, Type::String),
            ("binding_id", 7, Type::String),
            ("agent_control_device_id", 8, Type::String),
            ("recipient_id", 9, Type::String),
            ("recipient_capsule_digest", 10, Type::Bytes),
            ("opaque_recipient_capsule", 11, Type::Bytes),
            ("expires_at_millis", 12, Type::Uint64),
            ("result_digest", 13, Type::Bytes),
            ("route_health_key_id", 14, Type::String),
            ("route_health_public_key", 15, Type::Bytes),
        ],
    );
    assert_fields(
        file,
        "AgentRouteBootstrapInstalled",
        &[
            ("connector_fence", 1, Type::Message),
            ("bootstrap_id", 2, Type::String),
            ("delivery_id", 3, Type::String),
            ("route_id", 4, Type::String),
            ("command_sequence", 5, Type::Uint64),
            ("command_payload_digest", 6, Type::Bytes),
            ("encoded_command_digest", 7, Type::Bytes),
            ("installation_id", 8, Type::String),
            ("binding_id", 9, Type::String),
            ("agent_control_device_id", 10, Type::String),
            ("recipient_id", 11, Type::String),
            ("capsule_digest", 12, Type::Bytes),
            ("route_fence", 13, Type::Bytes),
            ("installed_at_millis", 14, Type::Uint64),
            ("result_digest", 15, Type::Bytes),
            ("route_health_key_id", 16, Type::String),
            ("route_health_public_key_digest", 17, Type::Bytes),
        ],
    );
    assert_fields(
        file,
        "AgentRouteBootstrapRejected",
        &[
            ("connector_fence", 1, Type::Message),
            ("bootstrap_id", 2, Type::String),
            ("delivery_id", 3, Type::String),
            ("route_id", 4, Type::String),
            ("command_sequence", 5, Type::Uint64),
            ("command_payload_digest", 6, Type::Bytes),
            ("encoded_command_digest", 7, Type::Bytes),
            ("installation_id", 8, Type::String),
            ("binding_id", 9, Type::String),
            ("agent_control_device_id", 10, Type::String),
            ("recipient_id", 11, Type::String),
            ("capsule_digest", 12, Type::Bytes),
            ("stable_error_code", 13, Type::String),
            ("rejected_at_millis", 14, Type::Uint64),
            ("result_digest", 15, Type::Bytes),
            ("route_health_key_id", 16, Type::String),
            ("route_health_public_key_digest", 17, Type::Bytes),
        ],
    );
    assert_fields(
        file,
        "PrepareAgentRouteRecipient",
        &[
            ("bootstrap_id", 1, Type::String),
            ("tenant_id", 2, Type::String),
            ("installation_id", 3, Type::String),
            ("binding_id", 4, Type::String),
            ("agent_control_device_id", 5, Type::String),
            ("owner_identity_id", 6, Type::String),
            ("owner_device_id", 7, Type::String),
            ("owner_signed_intent", 8, Type::Bytes),
            ("expires_at_millis", 9, Type::Uint64),
        ],
    );
    assert_fields(
        file,
        "DeliverAgentRouteBootstrap",
        &[
            ("bootstrap_id", 1, Type::String),
            ("delivery_id", 2, Type::String),
            ("route_id", 3, Type::String),
            ("recipient_id", 4, Type::String),
            ("capsule_digest", 5, Type::Bytes),
            ("opaque_sealed_bootstrap", 6, Type::Bytes),
            ("expires_at_millis", 7, Type::Uint64),
            ("installation_id", 8, Type::String),
            ("binding_id", 9, Type::String),
            ("agent_control_device_id", 10, Type::String),
            ("route_health_key_id", 11, Type::String),
            ("route_health_public_key_digest", 12, Type::Bytes),
        ],
    );

    for name in [
        "AgentRouteRecipientReady",
        "AgentRouteBootstrapInstalled",
        "AgentRouteBootstrapRejected",
    ] {
        assert_eq!(
            message(file, name).field[0].type_name.as_deref(),
            Some(".dirextalk.agent_control.v1.LeaseFence")
        );
    }
}

fn assert_fields(file: &FileDescriptorProto, name: &str, expected: &[(&str, i32, Type)]) {
    let actual = message(file, name)
        .field
        .iter()
        .map(|field| {
            (
                field.name.as_deref().expect("field name"),
                field.number.expect("field number"),
                Type::try_from(field.r#type.expect("field type")).expect("known field type"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected, "{name} fields drifted");
}

fn message<'a>(file: &'a FileDescriptorProto, name: &str) -> &'a DescriptorProto {
    file.message_type
        .iter()
        .find(|message| message.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("{name} is generated"))
}

fn oneof_fields<'a>(message: &'a DescriptorProto, name: &str) -> Vec<(&'a str, i32)> {
    let index = message
        .oneof_decl
        .iter()
        .position(|oneof| oneof.name.as_deref() == Some(name))
        .and_then(|index| i32::try_from(index).ok())
        .unwrap_or_else(|| panic!("{name} oneof is generated"));
    message
        .field
        .iter()
        .filter(|field| field.oneof_index == Some(index))
        .map(|field| {
            (
                field.name.as_deref().expect("oneof field name"),
                field.number.expect("oneof field number"),
            )
        })
        .collect()
}
