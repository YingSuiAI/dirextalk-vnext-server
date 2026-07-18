#![forbid(unsafe_code)]

//! Production transport and application boundary for Connector enrollment and control.
//!
//! Enrollment and control are deliberately separate tonic services and listeners:
//! enrollment uses server-authenticated TLS, while control accepts only a custom
//! rustls configuration with mandatory per-Connector cryptographic authentication.
//! Live credential authorization remains inside the `PostgreSQL`-backed application boundary.

mod agent_identity_provisioning;
mod agent_route_bootstrap;
mod application;
mod authentication;
mod authorization_index;
mod certificate;
mod command_codec;
mod command_notifications;
mod connector_projection;
mod gateway_application;
mod gateway_authentication;
mod gateway_service;
mod gateway_wire;
mod incoming;
mod mcp;
mod owner_http;
mod postgres_application;
mod provisioning;
mod run_notifications;
mod service;
mod transport_admission;
mod wire;

pub use agent_identity_provisioning::*;
pub use agent_route_bootstrap::*;
pub use application::{
    ApplicationFuture, ConnectorControlApplication, ConnectorControlApplicationError,
    CredentialReissueCompletion, CredentialRotationCompletion, EnrollmentCompletion,
    HeartbeatCompletion, OpenControlCompletion,
};
pub use authentication::{
    ControlRequestAuthenticationError, authenticate_control_request, unix_time_from_millis,
};
pub use authorization_index::{
    ConnectorAuthorizationIndexError, ConnectorCredentialAuthorizationIndex,
};
pub use certificate::{
    ConnectorCertificateAuthority, ConnectorCertificateIssueError, IssuedConnectorCertificate,
};
pub use command_codec::{
    EncodedDurableCommand, ProtobufDurableCommandDecoder, ProtobufDurableCommandEncoder,
};
pub use command_notifications::CommandNotificationSubscription;
pub use connector_projection::{
    CONNECTOR_PROJECTION_MEDIA_TYPE_V1, CONNECTOR_PROJECTION_MEDIA_TYPE_V2,
    CONNECTOR_PROJECTION_MEDIA_TYPE_V3, CONNECTOR_PROJECTION_MEDIA_TYPE_V4,
    ConnectorBindingProjectionV1, ConnectorBindingProjectionV3, ConnectorProjectionPageV1,
    ConnectorProjectionPageV3, ConnectorProjectionPageV4, ConnectorProjectionQueryV1,
    ConnectorProjectionV1, ConnectorProjectionV3, DEFAULT_CONNECTOR_PROJECTION_LIMIT,
    MAX_CONNECTOR_PROJECTION_BINDINGS, MAX_CONNECTOR_PROJECTION_LIMIT,
};
pub use dtx_agent_router::DispatchMode;
pub use gateway_application::AgentRunIngressApplication;
pub use gateway_authentication::{
    GatewayRequestAuthenticationError, authenticate_agent_gateway_request,
};
pub use gateway_service::{
    AGENT_RUN_INGRESS_OPERATION_TIMEOUT, AgentRunIngressGrpc, agent_run_ingress_service,
};
pub use gateway_wire::{
    GatewayWireError, GatewayWireErrorKind, ParsedAgentRunIngress,
    build_agent_run_ingress_response, parse_agent_run_ingress,
};
pub use incoming::{
    MAX_CONCURRENT_TLS_HANDSHAKES, TLS_HANDSHAKE_TIMEOUT, connector_tls_incoming, tls_incoming,
};
pub use owner_http::{
    AgentProvisioningOwnerBackend, AgentProvisioningOwnerError, AgentRouteRunOwnerCommand,
    CborOwnerReply, ConnectorLifecycleOwnerCommand, DeliveryOwnerCommand,
    PostgresAgentProvisioningOwnerBackend, RevocationOwnerCommand, agent_provisioning_owner_router,
};
pub use postgres_application::{
    AgentRunReconcileBatch, ApplyConnectorConfigurationRequest, CancelAgentRunRequest,
    CloseConnectorStreamRequest, ConnectorCommandFence, ConnectorControlPolicy,
    ConnectorLifecycleAction, ConnectorLifecycleCommandWrite, CreateAgentRunRequest,
    CreateConnectorEnrollmentRequest, CreatedAgentRun, CreatedConnectorCredentialReissue,
    CreatedConnectorEnrollment, PostgresConnectorControlApplication,
    PrepareConnectorCredentialReissueRequest, RotateConnectorCredentialRequest,
};
pub use provisioning::*;
pub use run_notifications::RunOfferNotificationSubscription;
pub use service::{
    COMMAND_POLL_INTERVAL, COMMAND_RECONCILE_INTERVAL, COMMAND_RECONCILE_JITTER,
    CONTROL_RESPONSE_BUFFER, CONTROL_RESPONSE_SEND_TIMEOUT, CommandReconcilePolicy,
    ConnectorControlGrpc, ConnectorEnrollmentGrpc, ENROLLMENT_OPERATION_TIMEOUT,
    FIRST_HELLO_TIMEOUT, connector_control_service, connector_enrollment_service,
};
pub use transport_admission::{
    ConnectorHelloAdmissionPermit, ConnectorTransportAdmission, ConnectorTransportAdmissionConfig,
    ConnectorTransportAdmissionConfigError, ConnectorTransportAdmissionError,
    SourceTransportAdmission, SourceTransportAdmissionConfig, SourceTransportAdmissionPermit,
    TransportAdmissionDimensionConfig,
};
pub use wire::*;
