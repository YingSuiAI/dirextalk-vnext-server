use std::{error::Error, fmt, future::Future, pin::Pin};

use dtx_agent_control::{
    ConnectorCredential, CredentialReissueRequest, CredentialRotationRequest, DurableServerCommand,
    EnrollmentRequest,
};
use dtx_connect_registry::{ConnectorFence, ConnectorLease, HeartbeatAck};
use dtx_domain::{ConnectorId, TenantId};
use dtx_security::AuthenticatedConnectorPeer;

use crate::wire::{
    ParsedAgentProvisioningInstalled, ParsedAgentProvisioningRejected,
    ParsedAgentRouteBootstrapInstalled, ParsedAgentRouteBootstrapRejected,
    ParsedAgentRouteRecipientReady, ParsedCommandAcknowledgement, ParsedCredentialReissue,
    ParsedCredentialRotationProof, ParsedEnrollment, ParsedHeartbeat, ParsedHello,
    ParsedProvisioningRecipientAnnouncement, ParsedReady, ParsedRunCheckpoint, ParsedRunClaim,
    ParsedRunCompleted, ParsedRunFailed, ParsedRunOutput, ParsedRunRelease, RunAvailableWire,
    RunCancelRequestedWire, RunLeaseGrantedWire,
};
use crate::{CommandNotificationSubscription, RunOfferNotificationSubscription};

/// Heap-erased application future used by the object-safe transport port.
pub type ApplicationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ConnectorControlApplicationError>> + Send + 'a>>;

/// Enrollment result published only after the one-time intent and credential commit together.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentCompletion {
    pub credential: ConnectorCredential,
    pub request: EnrollmentRequest,
}

/// Certificate-only recovery result committed together with the exact consumed reissue intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialReissueCompletion {
    pub credential: ConnectorCredential,
    pub request: CredentialReissueRequest,
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

    fn reissue_credential(
        &self,
        _request: ParsedCredentialReissue,
    ) -> ApplicationFuture<'_, CredentialReissueCompletion> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
    }

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

    /// Acknowledges a command on the live control session that negotiated `protocol_minor`.
    ///
    /// The default preserves implementations whose acknowledgement semantics do not vary by
    /// protocol minor. Applications with minor-gated transitions must override this method and
    /// fail closed when the session did not negotiate the required contract.
    fn acknowledge_command_on_session(
        &self,
        peer: AuthenticatedConnectorPeer,
        acknowledgement: ParsedCommandAcknowledgement,
        _protocol_minor: u32,
    ) -> ApplicationFuture<'_, ()> {
        self.acknowledge_command(peer, acknowledgement)
    }

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

    /// Returns only the durable suffix eligible for the negotiated protocol.
    ///
    /// Implementations that persist delivery transitions must not mutate an
    /// ineligible command or any later command in the same suffix.
    fn poll_commands_for_protocol(
        &self,
        peer: AuthenticatedConnectorPeer,
        fence: ConnectorFence,
        after_sequence: u64,
        _protocol_minor: u32,
    ) -> ApplicationFuture<'_, Vec<DurableServerCommand>> {
        self.poll_commands(peer, fence, after_sequence)
    }

    /// Subscribes before the stream queries its durable active-offer page.
    fn subscribe_run_offers(
        &self,
        _tenant_id: TenantId,
        _connector_id: ConnectorId,
    ) -> RunOfferNotificationSubscription {
        RunOfferNotificationSubscription::never()
    }

    /// Returns bounded active offers for the exact live Connector fence.
    fn poll_run_offers(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _fence: ConnectorFence,
        _after_sequence: u64,
    ) -> ApplicationFuture<'_, Vec<RunAvailableWire>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    /// Returns all still-live durable cancellation intents for this exact v1.2 stream fence.
    /// Intents may be replayed until the Run reaches a terminal state or the deadline passes.
    fn poll_run_cancellations(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _fence: ConnectorFence,
        _after_sequence: u64,
    ) -> ApplicationFuture<'_, Vec<RunCancelRequestedWire>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    /// Reconciles at most `limit` due Router timeouts for one exact tenant.
    ///
    /// The transport invokes one bounded batch on its low-frequency durable
    /// reconciliation tick. Implementations must reject zero or unsupported
    /// bounds and must not scan or mutate another tenant. The default fails
    /// closed so a production Router cannot silently omit timeout progress.
    fn reconcile_agent_run_timeouts(
        &self,
        _tenant_id: TenantId,
        _limit: usize,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async { Err(ConnectorControlApplicationError::Unavailable) })
    }

    /// Atomically acknowledges one offer and grants its sole execution lease.
    fn claim_run(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _claim: ParsedRunClaim,
    ) -> ApplicationFuture<'_, RunLeaseGrantedWire> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
    }

    /// Fences a released execution lease for reconciliation.
    fn release_run(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _release: ParsedRunRelease,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
    }

    fn record_run_checkpoint(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _checkpoint: ParsedRunCheckpoint,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
    }

    fn record_run_output(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _output: ParsedRunOutput,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
    }

    fn complete_run(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _completed: ParsedRunCompleted,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
    }

    fn fail_run(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _failed: ParsedRunFailed,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
    }

    fn announce_provisioning_recipient(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _announcement: ParsedProvisioningRecipientAnnouncement,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
    }

    fn complete_agent_provisioning(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _installed: ParsedAgentProvisioningInstalled,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
    }

    fn reject_agent_provisioning(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _rejected: ParsedAgentProvisioningRejected,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
    }

    /// Commits one exact opaque RouteBootstrap recipient result after its
    /// durable Prepare command has been authenticated and acknowledged.
    fn record_agent_route_recipient_ready(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _ready: ParsedAgentRouteRecipientReady,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
    }

    /// Commits one exact terminal RouteBootstrap install and its Run-eligible
    /// binding head in the same transaction as the durable command ACK.
    fn complete_agent_route_bootstrap(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _installed: ParsedAgentRouteBootstrapInstalled,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
    }

    /// Commits one exact category-only RouteBootstrap refusal in the same
    /// transaction as its durable command ACK; it never creates a binding head.
    fn reject_agent_route_bootstrap(
        &self,
        _peer: AuthenticatedConnectorPeer,
        _rejected: ParsedAgentRouteBootstrapRejected,
    ) -> ApplicationFuture<'_, ()> {
        Box::pin(async { Err(ConnectorControlApplicationError::PermissionDenied) })
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
    StaleLease,
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
            Self::StaleLease => "STALE_LEASE",
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
