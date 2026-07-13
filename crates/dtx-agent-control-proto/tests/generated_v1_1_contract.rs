use dtx_agent_control_proto::v1::{
    ClientFrame, RunAvailable, RunClaim, RunLeaseGranted, RunRelease, ServerFrame, client_frame,
    server_frame,
};
use prost::Message;
use prost_types::{DescriptorProto, FileDescriptorProto, FileDescriptorSet};

#[test]
fn additive_frames_are_generated_on_the_existing_v1_service() {
    let client = ClientFrame {
        kind: Some(client_frame::Kind::RunClaim(RunClaim::default())),
    };
    assert!(matches!(client.kind, Some(client_frame::Kind::RunClaim(_))));

    let release = ClientFrame {
        kind: Some(client_frame::Kind::RunRelease(RunRelease::default())),
    };
    assert!(matches!(
        release.kind,
        Some(client_frame::Kind::RunRelease(_))
    ));

    let available = ServerFrame {
        kind: Some(server_frame::Kind::RunAvailable(RunAvailable::default())),
    };
    assert!(matches!(
        available.kind,
        Some(server_frame::Kind::RunAvailable(_))
    ));

    let granted = ServerFrame {
        kind: Some(server_frame::Kind::RunLeaseGranted(
            RunLeaseGranted::default(),
        )),
    };
    assert!(matches!(
        granted.kind,
        Some(server_frame::Kind::RunLeaseGranted(_))
    ));
}

#[test]
fn descriptor_keeps_offer_ack_distinct_from_execution_authority() {
    let descriptor = FileDescriptorSet::decode(dtx_agent_control_proto::v1::FILE_DESCRIPTOR_SET)
        .expect("generated v1.1 descriptor is valid");
    let file = descriptor
        .file
        .iter()
        .find(|file| file.package.as_deref() == Some("dirextalk.agent_control.v1"))
        .expect("additive agent-control v1 package is generated");

    assert_eq!(
        oneof_fields(message(file, "ClientFrame"), "kind"),
        [
            "hello",
            "ready",
            "heartbeat",
            "command_acknowledgement",
            "credential_rotation_proof",
            "run_claim",
            "run_release",
        ]
    );
    assert_eq!(
        oneof_fields(message(file, "ServerFrame"), "kind"),
        [
            "connect_lease",
            "heartbeat_acknowledgement",
            "durable_command",
            "credential_rotation_result",
            "run_available",
            "run_lease_granted",
        ]
    );
    assert_run_fields(file);

    for deferred in ["RunCheckpoint", "RunOutput", "RunCompleted", "RunFailed"] {
        assert!(
            file.message_type
                .iter()
                .all(|message| message.name.as_deref() != Some(deferred)),
            "{deferred} belongs to AR3, not the MC3 additive artifact",
        );
    }
}

fn assert_run_fields(file: &FileDescriptorProto) {
    assert_eq!(
        field_names(message(file, "RunAvailable")),
        [
            "connector_fence",
            "run_id",
            "request_id",
            "installation_id",
            "binding_id",
            "connector_id",
            "offer_attempt",
            "offered_at_millis",
            "offer_deadline_millis",
            "required_capabilities",
        ]
    );
    assert_eq!(
        field_names(message(file, "RunClaim")),
        [
            "connector_fence",
            "run_id",
            "request_id",
            "installation_id",
            "binding_id",
            "connector_id",
            "offer_attempt",
            "offer_deadline_millis",
            "required_capabilities",
        ]
    );
    assert_eq!(
        field_names(message(file, "RunLeaseGranted")),
        [
            "connector_fence",
            "run_id",
            "request_id",
            "installation_id",
            "binding_id",
            "connector_id",
            "offer_attempt",
            "run_lease_id",
            "run_lease_epoch",
            "granted_at_millis",
            "run_lease_deadline_millis",
            "required_capabilities",
        ]
    );
    assert_eq!(
        field_names(message(file, "RunRelease")),
        [
            "connector_fence",
            "run_id",
            "request_id",
            "installation_id",
            "binding_id",
            "connector_id",
            "offer_attempt",
            "run_lease_id",
            "run_lease_epoch",
            "run_lease_deadline_millis",
            "stable_reason",
        ]
    );

    let available = field_names(message(file, "RunAvailable"));
    assert!(!available.contains(&"run_lease_id"));
    assert!(!available.contains(&"run_lease_epoch"));
    let granted = field_names(message(file, "RunLeaseGranted"));
    assert!(granted.contains(&"run_lease_id"));
    assert!(granted.contains(&"run_lease_epoch"));
}

fn message<'a>(file: &'a FileDescriptorProto, name: &str) -> &'a DescriptorProto {
    file.message_type
        .iter()
        .find(|message| message.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("{name} is generated"))
}

fn field_names(message: &DescriptorProto) -> Vec<&str> {
    message
        .field
        .iter()
        .filter_map(|field| field.name.as_deref())
        .collect()
}

fn oneof_fields<'a>(message: &'a DescriptorProto, name: &str) -> Vec<&'a str> {
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
        .filter_map(|field| field.name.as_deref())
        .collect()
}
