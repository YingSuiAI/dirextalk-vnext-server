#![forbid(unsafe_code)]

//! Production transport and application boundary for Connector enrollment and control.
//!
//! Enrollment and control are deliberately separate tonic services and listeners:
//! enrollment uses server-authenticated TLS, while control accepts only a custom
//! rustls configuration with mandatory per-Connector cryptographic authentication.
//! Live credential authorization remains inside the `PostgreSQL`-backed application boundary.

mod application;
mod authentication;
mod authorization_index;
mod certificate;
mod command_codec;
mod command_notifications;
mod incoming;
mod postgres_application;
mod run_notifications;
mod service;
mod transport_admission;
mod wire;

pub use application::{
    ApplicationFuture, ConnectorControlApplication, ConnectorControlApplicationError,
    CredentialRotationCompletion, EnrollmentCompletion, HeartbeatCompletion, OpenControlCompletion,
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
pub use dtx_agent_router::DispatchMode;
pub use incoming::{MAX_CONCURRENT_TLS_HANDSHAKES, TLS_HANDSHAKE_TIMEOUT, connector_tls_incoming};
pub use postgres_application::{
    AgentRunReconcileBatch, ApplyConnectorConfigurationRequest, CloseConnectorStreamRequest,
    ConnectorCommandFence, ConnectorControlPolicy, CreateAgentRunRequest,
    CreateConnectorEnrollmentRequest, CreatedAgentRun, CreatedConnectorEnrollment,
    PostgresConnectorControlApplication, RotateConnectorCredentialRequest,
};
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
