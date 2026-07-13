use std::{error::Error, fmt, future::Future, pin::Pin};

use dtx_agent_control::{
    ConnectorCredential, CredentialRotationRequest, DurableServerCommand, EnrollmentRequest,
};
use dtx_connect_registry::{ConnectorFence, ConnectorLease, HeartbeatAck};
use dtx_domain::{ConnectorId, TenantId};
use dtx_security::AuthenticatedConnectorPeer;

use crate::CommandNotificationSubscription;
use crate::wire::{
    ParsedCommandAcknowledgement, ParsedCredentialRotationProof, ParsedEnrollment, ParsedHeartbeat,
    ParsedHello, ParsedReady,
};

/// Heap-erased application future used by the object-safe transport port.
pub type ApplicationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ConnectorControlApplicationError>> + Send + 'a>>;

/// Enrollment result published only after the one-time intent and credential commit together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentCompletion {
    pub credential: ConnectorCredential,
    pub request: EnrollmentRequest,
}

/// Durable lease and exact replay batch returned by the first accepted `Hello`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenControlCompletion {
    pub lease: ConnectorLease,
    pub protocol_minor: u32,
    pub heartbeat_interval_millis: u32,
    pub heartbeat_ttl_millis: u32,
    pub acknowledged_command_sequence: u64,
    pub replay_commands: Vec<DurableServerCommand>,
}

/// Server-clock receipt for one committed, lease-extending heartbeat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeartbeatCompletion {
    pub acknowledgement: HeartbeatAck,
    pub observed_at_millis: i64,
}

/// Pending successor result committed atomically with its `RotateCredential` ACK.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialRotationCompletion {
    pub credential: ConnectorCredential,
    pub request: CredentialRotationRequest,
}

/// Transport-independent application port for the two gRPC services.
///
/// Implementations must execute every method in a tenant-scoped transaction and
/// recheck the certificate fingerprint, generation, boot, lease, cursor, and
/// aggregate revisions before mutation. A synchronous process-local credential
/// view is advisory only and must never admit a handshake or application frame.
pub trait ConnectorControlApplication: Send + Sync + 'static {
    /// Returns server-authoritative UTC milliseconds for authentication and deadlines.
    ///
    /// # Errors
    ///
    /// Fails closed when the configured clock is unavailable or outside the supported range.
    fn now_utc_millis(&self) -> Result<i64, ConnectorControlApplicationError>;

    fn enroll(&self, request: ParsedEnrollment) -> ApplicationFuture<'_, EnrollmentCompletion>;

    fn open_control(
        &self,
        peer: AuthenticatedConnectorPeer,
        hello: ParsedHello,
    ) -> ApplicationFuture<'_, OpenControlCompletion>;

    fn ready(
        &self,
        peer: AuthenticatedConnectorPeer,
        ready: ParsedReady,
    ) -> ApplicationFuture<'_, ()>;

    fn heartbeat(
        &self,
        peer: AuthenticatedConnectorPeer,
        heartbeat: ParsedHeartbeat,
    ) -> ApplicationFuture<'_, HeartbeatCompletion>;

    fn acknowledge_command(
        &self,
        peer: AuthenticatedConnectorPeer,
        acknowledgement: ParsedCommandAcknowledgement,
    ) -> ApplicationFuture<'_, ()>;

    fn rotate_credential(
        &self,
        peer: AuthenticatedConnectorPeer,
        proof: ParsedCredentialRotationProof,
    ) -> ApplicationFuture<'_, CredentialRotationCompletion>;

    /// Subscribes to lossy command-availability hints for one exact Connector.
    ///
    /// Callers must subscribe before querying the durable suffix and must retain
    /// a bounded reconciliation poll because notifications can be lost.
    fn subscribe_commands(
        &self,
        _tenant_id: TenantId,
        _connector_id: ConnectorId,
    ) -> CommandNotificationSubscription {
        CommandNotificationSubscription::never()
    }

    /// Returns commands not yet delivered on this live stream after a transient
    /// per-stream delivery cursor. The cursor never advances the durable ACK.
    fn poll_commands(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _fence: ConnectorFence,
        _after_sequence: u64,
    ) -> ApplicationFuture<'_, Vec<DurableServerCommand>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

/// Stable, non-secret failure classes exposed by the control transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorControlApplicationError {
    InvalidRequest,
    AuthenticationFailed,
    PermissionDenied,
    NotFound,
    Conflict,
    StaleFence,
    ResourceExhausted,
    Unavailable,
    Internal,
}

impl ConnectorControlApplicationError {
    #[must_use]
    pub const fn stable_code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict => "CONFLICT",
            Self::StaleFence => "STALE_FENCE",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::Unavailable => "UNAVAILABLE",
            Self::Internal => "INTERNAL",
        }
    }
}

impl fmt::Display for ConnectorControlApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.stable_code())
    }
}

impl Error for ConnectorControlApplicationError {}
