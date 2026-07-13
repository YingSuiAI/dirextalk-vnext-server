#![forbid(unsafe_code)]

/// Negotiated wire protocol name for the initial Connector control contract.
pub const AGENT_CONTROL_WIRE_PROTOCOL: &str = "agent-control/1";
/// Negotiated wire protocol name for additive run offer and lease frames.
pub const AGENT_CONTROL_WIRE_PROTOCOL_V1_1: &str = "agent-control/1.1";
/// Versioned internal Legacy Matrix Gateway to Agent Control ingress contract.
pub const AGENT_GATEWAY_WIRE_PROTOCOL: &str = "agent-gateway/1";
/// Maximum encoded unary request, response, or stream frame accepted by either endpoint.
pub const MAX_AGENT_CONTROL_MESSAGE_BYTES: usize = 262_144;
/// Maximum encoded request or response accepted by the internal Gateway ingress.
pub const MAX_AGENT_GATEWAY_MESSAGE_BYTES: usize = 65_536;
/// Maximum raw [`v1::DurableCommand`] bytes carried inside one durable command frame.
pub const MAX_ENCODED_DURABLE_COMMAND_BYTES: usize = 196_608;

/// Generated `agent-control/1` messages and additive minor-1 tonic surfaces.
///
/// The source of truth is the reviewed Protobuf artifact under `protocol/`;
/// Cargo builds it with a vendored `protoc`, so no host compiler is required.
#[allow(clippy::all, clippy::pedantic)]
pub mod v1 {
    tonic::include_proto!("dirextalk.agent_control.v1");

    /// Descriptor set generated from the same frozen Protobuf source as the
    /// Rust messages and tonic service definitions.
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("agent_control_descriptor");
}

/// Generated internal `agent-gateway/1` request and tonic service surfaces.
///
/// This is a separate package and descriptor because its mTLS service identity,
/// message ceiling, and release lifecycle are independent of Connector control.
#[allow(clippy::all, clippy::pedantic)]
pub mod gateway_v1 {
    tonic::include_proto!("dirextalk.agent_gateway.v1");

    /// Descriptor set generated from the frozen v4 Gateway ingress source.
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("agent_gateway_descriptor");
}
