use std::pin::Pin;

use dtx_agent_control_proto::v1::{
    ClientFrame, ConnectorCredential, CredentialRotationResult, DurableCommand,
    DurableCommandFrame, EnrollConnectorRequest, EnrollConnectorResponse, Hello,
    ReissueConnectorCredentialRequest, ReissueConnectorCredentialResponse, ServerFrame,
    client_frame, connector_control_client::ConnectorControlClient,
    connector_control_server::ConnectorControl,
    connector_enrollment_client::ConnectorEnrollmentClient,
    connector_enrollment_server::ConnectorEnrollment, server_frame,
};
use dtx_agent_control_proto::{
    AGENT_CONTROL_WIRE_PROTOCOL, MAX_AGENT_CONTROL_MESSAGE_BYTES, MAX_ENCODED_DURABLE_COMMAND_BYTES,
};
use futures_core::Stream;
use prost::Message;
use prost_types::{DescriptorProto, EnumDescriptorProto, FileDescriptorProto, FileDescriptorSet};
use tonic::{Request, Response, Status, Streaming, transport::Channel};

#[test]
fn descriptor_exposes_unary_enrollment_and_bidirectional_control() {
    let descriptor = FileDescriptorSet::decode(dtx_agent_control_proto::v1::FILE_DESCRIPTOR_SET)
        .expect("generated descriptor is valid");
    let file = descriptor
        .file
        .iter()
        .find(|file| file.package.as_deref() == Some("dirextalk.agent_control.v1"))
        .expect("agent-control package is generated");
    assert_eq!(file.service.len(), 2);
    let enrollment_service = file
        .service
        .iter()
        .find(|service| service.name.as_deref() == Some("ConnectorEnrollment"))
        .expect("ConnectorEnrollment service is generated");
    assert_eq!(
        enrollment_service
            .method
            .iter()
            .filter_map(|method| method.name.as_deref())
            .collect::<Vec<_>>(),
        ["EnrollConnector", "ReissueConnectorCredential"]
    );

    let enroll = enrollment_service
        .method
        .iter()
        .find(|method| method.name.as_deref() == Some("EnrollConnector"))
        .expect("enrollment RPC is generated");
    assert!(!enroll.client_streaming.unwrap_or(false));
    assert!(!enroll.server_streaming.unwrap_or(false));

    let control_service = file
        .service
        .iter()
        .find(|service| service.name.as_deref() == Some("ConnectorControl"))
        .expect("ConnectorControl service is generated");
    assert_eq!(
        control_service
            .method
            .iter()
            .filter_map(|method| method.name.as_deref())
            .collect::<Vec<_>>(),
        ["Control"]
    );
    let control = control_service
        .method
        .iter()
        .find(|method| method.name.as_deref() == Some("Control"))
        .expect("control RPC is generated");
    assert!(control.client_streaming.unwrap_or(false));
    assert!(control.server_streaming.unwrap_or(false));
}

#[test]
fn rust_transport_limits_match_the_reviewed_wire_contract() {
    assert_eq!(AGENT_CONTROL_WIRE_PROTOCOL, "agent-control/1");
    assert_eq!(MAX_AGENT_CONTROL_MESSAGE_BYTES, 262_144);
    assert_eq!(MAX_ENCODED_DURABLE_COMMAND_BYTES, 196_608);
}

#[test]
fn generated_frames_use_closed_known_oneof_variants() {
    let client = ClientFrame {
        kind: Some(client_frame::Kind::Hello(Hello::default())),
    };
    assert!(matches!(client.kind, Some(client_frame::Kind::Hello(_))));

    let server = ServerFrame {
        kind: Some(server_frame::Kind::CredentialRotationResult(
            CredentialRotationResult::default(),
        )),
    };
    assert!(matches!(
        server.kind,
        Some(server_frame::Kind::CredentialRotationResult(_))
    ));
}

#[test]
fn descriptor_keeps_frames_commands_and_public_credentials_closed() {
    let descriptor = FileDescriptorSet::decode(dtx_agent_control_proto::v1::FILE_DESCRIPTOR_SET)
        .expect("generated descriptor is valid");
    let file = agent_control_file(&descriptor);

    assert!(
        oneof_fields(message(file, "ClientFrame"), "kind").starts_with(&[
            "hello",
            "ready",
            "heartbeat",
            "command_acknowledgement",
            "credential_rotation_proof",
            "run_claim",
            "run_release",
        ])
    );
    assert!(
        oneof_fields(message(file, "ServerFrame"), "kind").starts_with(&[
            "connect_lease",
            "heartbeat_acknowledgement",
            "durable_command",
            "credential_rotation_result",
            "run_available",
            "run_lease_granted",
        ])
    );
    assert!(
        oneof_fields(message(file, "DurableCommand"), "command").starts_with(&[
            "apply_config",
            "rotate_credential",
            "close_stream",
        ])
    );
    assert_eq!(
        field_names(message(file, "ConnectorCredential")),
        [
            "credential_id",
            "credential_revision",
            "certificate_chain_der",
            "leaf_fingerprint",
            "valid_from_millis",
            "valid_until_millis",
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
fn descriptor_preserves_raw_durable_commands_and_live_capacity() {
    let descriptor = FileDescriptorSet::decode(dtx_agent_control_proto::v1::FILE_DESCRIPTOR_SET)
        .expect("generated descriptor is valid");
    let file = agent_control_file(&descriptor);

    let durable_arm = message(file, "ServerFrame")
        .field
        .iter()
        .find(|field| field.name.as_deref() == Some("durable_command"))
        .expect("ServerFrame durable command arm is generated");
    assert_eq!(
        durable_arm.type_name.as_deref(),
        Some(".dirextalk.agent_control.v1.DurableCommandFrame")
    );
    assert_eq!(
        field_names(message(file, "DurableCommandFrame")),
        ["encoded_command", "encoded_command_digest"]
    );
    assert_eq!(
        field_names(message(file, "CommandAcknowledgement")),
        [
            "fence",
            "command_sequence",
            "payload_digest",
            "encoded_command_digest",
        ]
    );
    assert_eq!(
        field_names(message(file, "CredentialRotationProof")),
        [
            "fence",
            "request_id",
            "command_sequence",
            "command_payload_digest",
            "encoded_command_digest",
            "successor_revision",
            "new_control_public_key",
            "current_refresh_signature",
            "new_control_signature",
        ]
    );
    assert_eq!(
        field_names(message(file, "Capacity")),
        [
            "maximum_concurrent_runs",
            "available_concurrent_runs",
            "maximum_queue_depth",
        ]
    );
    assert!(field_names(message(file, "Heartbeat")).contains(&"capacity"));
    assert_eq!(
        enum_value_names(enumeration(file, "DesiredConnectorState")),
        [
            "DESIRED_CONNECTOR_STATE_UNSPECIFIED",
            "DESIRED_CONNECTOR_STATE_RUNNING",
            "DESIRED_CONNECTOR_STATE_DRAINING",
            "DESIRED_CONNECTOR_STATE_STOPPED",
        ]
    );
}

#[test]
fn durable_command_frame_round_trips_future_command_bytes_exactly() {
    // command_sequence = 1 followed by future field 100 = 1. Prost correctly
    // drops that unknown field if DurableCommand itself is decoded/re-encoded.
    let encoded_command = vec![0x08, 0x01, 0xa0, 0x06, 0x01];
    let decoded_command = DurableCommand::decode(encoded_command.as_slice()).unwrap();
    assert_ne!(decoded_command.encode_to_vec(), encoded_command);

    let frame = ServerFrame {
        kind: Some(server_frame::Kind::DurableCommand(DurableCommandFrame {
            encoded_command: encoded_command.clone(),
            encoded_command_digest: vec![9; 32],
        })),
    };
    let replayed = ServerFrame::decode(frame.encode_to_vec().as_slice()).unwrap();
    let Some(server_frame::Kind::DurableCommand(replayed)) = replayed.kind else {
        panic!("durable command frame is preserved");
    };
    assert_eq!(replayed.encoded_command, encoded_command);
    assert_eq!(replayed.encoded_command_digest, vec![9; 32]);
}

#[test]
fn enrollment_result_contains_only_public_credential_material() {
    let request = EnrollConnectorRequest {
        enrollment_token: vec![7; 32],
        control_public_key: vec![8; 32],
        refresh_public_key: vec![9; 32],
        control_signature: vec![10; 64],
        refresh_signature: vec![11; 64],
        ..EnrollConnectorRequest::default()
    };
    let response = EnrollConnectorResponse {
        credential: Some(ConnectorCredential {
            certificate_chain_der: vec![vec![1, 2, 3]],
            leaf_fingerprint: vec![12; 32],
            ..ConnectorCredential::default()
        }),
        request_digest: vec![13; 32],
        result_digest: vec![14; 32],
        route_health_receipt_key_id: String::new(),
        route_health_receipt_public_key: Vec::new(),
    };

    assert!(request.encoded_len() > 0);
    assert!(response.encoded_len() > 0);
}

#[test]
fn generated_tonic_client_and_server_types_are_usable() {
    let control_client = std::any::type_name::<ConnectorControlClient<Channel>>();
    let enrollment_client = std::any::type_name::<ConnectorEnrollmentClient<Channel>>();
    assert!(control_client.contains("ConnectorControlClient"));
    assert!(enrollment_client.contains("ConnectorEnrollmentClient"));
    assert_control_service::<StubService>();
    assert_enrollment_service::<StubService>();
}

fn assert_control_service<T: ConnectorControl>() {}

fn assert_enrollment_service<T: ConnectorEnrollment>() {}

fn agent_control_file(descriptor: &FileDescriptorSet) -> &FileDescriptorProto {
    descriptor
        .file
        .iter()
        .find(|file| file.package.as_deref() == Some("dirextalk.agent_control.v1"))
        .expect("agent-control package is generated")
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

fn enumeration<'a>(file: &'a FileDescriptorProto, name: &str) -> &'a EnumDescriptorProto {
    file.enum_type
        .iter()
        .find(|enumeration| enumeration.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("{name} is generated"))
}

fn enum_value_names(enumeration: &EnumDescriptorProto) -> Vec<&str> {
    enumeration
        .value
        .iter()
        .filter_map(|value| value.name.as_deref())
        .collect()
}

struct StubService;

#[tonic::async_trait]
impl ConnectorEnrollment for StubService {
    async fn enroll_connector(
        &self,
        _request: Request<EnrollConnectorRequest>,
    ) -> Result<Response<EnrollConnectorResponse>, Status> {
        Err(Status::unimplemented("contract-only stub"))
    }

    async fn reissue_connector_credential(
        &self,
        _request: Request<ReissueConnectorCredentialRequest>,
    ) -> Result<Response<ReissueConnectorCredentialResponse>, Status> {
        Err(Status::unimplemented("contract-only stub"))
    }
}

#[tonic::async_trait]
impl ConnectorControl for StubService {
    type ControlStream = Pin<Box<dyn Stream<Item = Result<ServerFrame, Status>> + Send + 'static>>;

    async fn control(
        &self,
        _request: Request<Streaming<ClientFrame>>,
    ) -> Result<Response<Self::ControlStream>, Status> {
        Err(Status::unimplemented("contract-only stub"))
    }
}
