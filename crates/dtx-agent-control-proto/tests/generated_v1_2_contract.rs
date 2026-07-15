use dtx_agent_control_proto::v1::{
    ClientFrame, RunAvailable, RunCancelRequested, RunCheckpoint, RunClaim, RunCompleted,
    RunFailed, RunLeaseGranted, RunOutput, RunRelease, RunReportAcknowledged, ServerFrame,
    client_frame, server_frame,
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

    for kind in [
        client_frame::Kind::RunCheckpoint(RunCheckpoint::default()),
        client_frame::Kind::RunOutput(RunOutput::default()),
        client_frame::Kind::RunCompleted(RunCompleted::default()),
        client_frame::Kind::RunFailed(RunFailed::default()),
    ] {
        assert!(ClientFrame { kind: Some(kind) }.kind.is_some());
    }

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

    let cancel = ServerFrame {
        kind: Some(server_frame::Kind::RunCancelRequested(
            RunCancelRequested::default(),
        )),
    };
    assert!(matches!(
        cancel.kind,
        Some(server_frame::Kind::RunCancelRequested(_))
    ));
    assert!(
        ServerFrame {
            kind: Some(server_frame::Kind::RunReportAcknowledged(
                RunReportAcknowledged::default(),
            )),
        }
        .kind
        .is_some()
    );
}

#[test]
fn descriptor_keeps_offer_ack_distinct_from_execution_authority() {
    let descriptor = FileDescriptorSet::decode(dtx_agent_control_proto::v1::FILE_DESCRIPTOR_SET)
        .expect("generated v1.2 descriptor is valid");
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
            "run_checkpoint",
            "run_output",
            "run_completed",
            "run_failed",
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
            "run_cancel_requested",
            "run_report_acknowledged",
        ]
    );
    assert_run_fields(file);
    assert_privacy_preserving_execution_fields(file);
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
            "conversation_id",
            "input_event_id",
            "grant_version",
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

fn assert_privacy_preserving_execution_fields(file: &FileDescriptorProto) {
    assert_eq!(
        field_names(message(file, "RunExecutionFence")),
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
        ]
    );
    assert_eq!(
        field_names(message(file, "RunCheckpoint")),
        [
            "execution_fence",
            "checkpoint_sequence",
            "checkpoint_artifact_id",
            "checkpoint_digest",
        ]
    );
    assert_eq!(
        field_names(message(file, "RunOutput")),
        [
            "execution_fence",
            "output_sequence",
            "output_event_id",
            "output_digest",
        ]
    );
    assert_eq!(
        field_names(message(file, "RunCompleted")),
        [
            "execution_fence",
            "terminal_sequence",
            "result_event_id",
            "result_digest",
        ]
    );
    assert_eq!(
        field_names(message(file, "RunFailed")),
        [
            "execution_fence",
            "terminal_sequence",
            "stable_error_code",
            "evidence_artifact_id",
            "evidence_digest",
        ]
    );
    assert_eq!(
        field_names(message(file, "RunCancelRequested")),
        [
            "execution_fence",
            "stable_reason",
            "requested_at_millis",
            "cancel_deadline_millis",
        ]
    );
    assert_eq!(
        field_names(message(file, "RunReportAcknowledged")),
        [
            "run_id",
            "run_lease_id",
            "run_lease_epoch",
            "report_kind",
            "report_sequence",
            "report_digest",
        ]
    );

    let forbidden = [
        "prompt",
        "plaintext",
        "content",
        "output_bytes",
        "checkpoint_bytes",
        "provider_response",
    ];
    for name in [
        "RunLeaseGranted",
        "RunCheckpoint",
        "RunOutput",
        "RunCompleted",
        "RunFailed",
        "RunCancelRequested",
        "RunReportAcknowledged",
    ] {
        let fields = field_names(message(file, name));
        assert!(
            forbidden
                .iter()
                .all(|forbidden| !fields.contains(forbidden)),
            "{name} must carry references and digests only",
        );
    }
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
