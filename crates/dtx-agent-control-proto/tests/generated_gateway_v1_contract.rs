use dtx_agent_control_proto::{
    AGENT_GATEWAY_WIRE_PROTOCOL, MAX_AGENT_GATEWAY_MESSAGE_BYTES,
    gateway_v1::{
        CreateAgentRunRequest, CreateAgentRunResponse, DispatchMode, RunRoutingState,
        agent_run_ingress_client::AgentRunIngressClient, agent_run_ingress_server::AgentRunIngress,
    },
};
use prost::Message;
use prost_types::{DescriptorProto, EnumDescriptorProto, FileDescriptorProto, FileDescriptorSet};
use tonic::{Request, Response, Status, transport::Channel};

#[test]
fn descriptor_exposes_only_unary_agent_run_ingress() {
    let descriptor =
        FileDescriptorSet::decode(dtx_agent_control_proto::gateway_v1::FILE_DESCRIPTOR_SET)
            .expect("generated Gateway descriptor is valid");
    let file = gateway_file(&descriptor);
    assert_eq!(file.service.len(), 1);
    let service = &file.service[0];
    assert_eq!(service.name.as_deref(), Some("AgentRunIngress"));
    assert_eq!(service.method.len(), 1);
    let method = &service.method[0];
    assert_eq!(method.name.as_deref(), Some("CreateAgentRun"));
    assert!(!method.client_streaming.unwrap_or(false));
    assert!(!method.server_streaming.unwrap_or(false));
}

#[test]
fn request_is_digest_only_and_cannot_select_tenant_or_carry_matrix_data() {
    let descriptor =
        FileDescriptorSet::decode(dtx_agent_control_proto::gateway_v1::FILE_DESCRIPTOR_SET)
            .expect("generated Gateway descriptor is valid");
    let file = gateway_file(&descriptor);
    assert_eq!(
        field_names(message(file, "CreateAgentRunRequest")),
        [
            "request_id",
            "idempotency_digest",
            "request_digest",
            "installation_id",
            "conversation_id",
            "request_event_id",
            "preferred_connector_id",
            "required_capabilities",
            "dispatch_mode",
            "grant_version",
        ]
    );
    for forbidden in [
        "tenant_id",
        "prompt",
        "input",
        "body",
        "room_id",
        "matrix_room_id",
        "matrix_event_id",
    ] {
        assert!(
            file.message_type
                .iter()
                .flat_map(|message| &message.field)
                .all(|field| field.name.as_deref() != Some(forbidden)),
            "{forbidden} must not cross the Gateway ingress boundary",
        );
    }
    let preferred = message(file, "CreateAgentRunRequest")
        .field
        .iter()
        .find(|field| field.name.as_deref() == Some("preferred_connector_id"))
        .expect("preferred Connector field is generated");
    assert!(preferred.proto3_optional.unwrap_or(false));
}

#[test]
fn response_is_limited_to_creation_and_current_routing_state() {
    let descriptor =
        FileDescriptorSet::decode(dtx_agent_control_proto::gateway_v1::FILE_DESCRIPTOR_SET)
            .expect("generated Gateway descriptor is valid");
    let file = gateway_file(&descriptor);
    assert_eq!(
        field_names(message(file, "CreateAgentRunResponse")),
        ["request_id", "run_id", "inserted", "routing_state"]
    );
    for deferred in [
        "RunResult",
        "RunCheckpoint",
        "RunOutput",
        "RunCompleted",
        "RunFailed",
    ] {
        assert!(
            file.message_type
                .iter()
                .all(|message| message.name.as_deref() != Some(deferred)),
            "{deferred} is not part of the minimal run-ingress artifact",
        );
    }
}

#[test]
fn dispatch_and_routing_enums_are_closed_to_current_domain_states() {
    let descriptor =
        FileDescriptorSet::decode(dtx_agent_control_proto::gateway_v1::FILE_DESCRIPTOR_SET)
            .expect("generated Gateway descriptor is valid");
    let file = gateway_file(&descriptor);
    assert_eq!(
        enum_value_names(enumeration(file, "DispatchMode")),
        [
            "DISPATCH_MODE_UNSPECIFIED",
            "DISPATCH_MODE_SINGLE",
            "DISPATCH_MODE_FAILOVER",
        ]
    );
    assert_eq!(
        enum_value_names(enumeration(file, "RunRoutingState")),
        [
            "RUN_ROUTING_STATE_UNSPECIFIED",
            "RUN_ROUTING_STATE_QUEUED",
            "RUN_ROUTING_STATE_OFFERED",
            "RUN_ROUTING_STATE_LEASED",
            "RUN_ROUTING_STATE_RECONCILE_REQUIRED",
            "RUN_ROUTING_STATE_EXPIRED",
        ]
    );
    assert_eq!(DispatchMode::Single as i32, 1);
    assert_eq!(DispatchMode::Failover as i32, 2);
    assert_eq!(RunRoutingState::Queued as i32, 1);
}

#[test]
fn generated_tonic_types_and_wire_limits_are_usable() {
    assert_eq!(AGENT_GATEWAY_WIRE_PROTOCOL, "agent-gateway/1");
    assert_eq!(MAX_AGENT_GATEWAY_MESSAGE_BYTES, 65_536);
    assert!(
        std::any::type_name::<AgentRunIngressClient<Channel>>().contains("AgentRunIngressClient")
    );
    assert_agent_run_ingress::<StubService>();
}

fn assert_agent_run_ingress<T: AgentRunIngress>() {}

fn gateway_file(descriptor: &FileDescriptorSet) -> &FileDescriptorProto {
    descriptor
        .file
        .iter()
        .find(|file| file.package.as_deref() == Some("dirextalk.agent_gateway.v1"))
        .expect("Gateway ingress package is generated")
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
impl AgentRunIngress for StubService {
    async fn create_agent_run(
        &self,
        _request: Request<CreateAgentRunRequest>,
    ) -> Result<Response<CreateAgentRunResponse>, Status> {
        Err(Status::unimplemented("contract-only stub"))
    }
}
