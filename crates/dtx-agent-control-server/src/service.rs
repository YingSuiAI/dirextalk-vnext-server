use std::{fmt, pin::Pin, sync::Arc, time::Duration};

use dtx_agent_control_proto::{MAX_AGENT_CONTROL_MESSAGE_BYTES, v1};
use dtx_security::{
    AuthenticatedConnectorPeer, ConnectorMtlsClientVerifier, ConnectorWorkloadIdentity,
};
use futures_core::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::{
    ConnectorControlApplication, ConnectorControlApplicationError, ConnectorHelloAdmissionPermit,
    ConnectorTransportAdmission, ConnectorTransportAdmissionConfig, ParsedClientFrame,
    SourceTransportAdmission, SourceTransportAdmissionConfig, authenticate_control_request,
    build_connect_lease, build_credential_rotation_result, build_durable_command_frame,
    build_enrollment_response, build_heartbeat_acknowledgement, parse_client_frame,
    parse_enrollment_request, unix_time_from_millis,
};

/// Maximum time an authenticated control RPC may remain silent before its first `Hello`.
pub const FIRST_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum time an admitted enrollment may occupy application resources.
pub const ENROLLMENT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_PUBLIC_RPC_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_PUBLIC_RPC_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounded response queue; replay naturally backpressures instead of buffering the whole backlog.
pub const CONTROL_RESPONSE_BUFFER: usize = 16;
/// Maximum time a control task may wait for a slow client to consume one response.
pub const CONTROL_RESPONSE_SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Default low-frequency durable reconciliation interval for lost notifications
/// and bounded idle-stream revocation detection.
pub const COMMAND_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);
/// Default per-stream spread added to the reconciliation interval.
pub const COMMAND_RECONCILE_JITTER: Duration = Duration::from_secs(15);
/// Backward-compatible name for the durable reconciliation cadence.
pub const COMMAND_POLL_INTERVAL: Duration = COMMAND_RECONCILE_INTERVAL;

/// Validated bounded fallback policy for lossy command notifications.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandReconcilePolicy {
    interval: Duration,
    maximum_jitter: Duration,
}

impl CommandReconcilePolicy {
    /// Creates a bounded low-frequency reconciliation policy.
    ///
    /// # Errors
    ///
    /// Rejects intervals below five seconds, a worst-case delay above five
    /// minutes, or jitter larger than the base interval.
    pub fn new(
        interval: Duration,
        maximum_jitter: Duration,
    ) -> Result<Self, ConnectorControlApplicationError> {
        if interval < Duration::from_secs(5)
            || maximum_jitter > interval
            || interval.saturating_add(maximum_jitter) > Duration::from_mins(5)
        {
            return Err(ConnectorControlApplicationError::InvalidRequest);
        }
        Ok(Self {
            interval,
            maximum_jitter,
        })
    }

    fn delay(self, fence: dtx_connect_registry::ConnectorFence) -> Duration {
        let maximum_jitter_nanos = self.maximum_jitter.as_nanos();
        if maximum_jitter_nanos == 0 {
            return self.interval;
        }
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in format!(
            "{}:{}:{}:{}",
            fence.tenant_id(),
            fence.connector_id(),
            fence.generation().get(),
            fence.lease_id(),
        )
        .bytes()
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let bound = u64::try_from(maximum_jitter_nanos)
            .expect("validated command reconcile jitter fits in nanoseconds");
        let jitter = hash % bound.saturating_add(1);
        self.interval.saturating_add(Duration::from_nanos(jitter))
    }
}

impl Default for CommandReconcilePolicy {
    fn default() -> Self {
        Self::new(COMMAND_RECONCILE_INTERVAL, COMMAND_RECONCILE_JITTER)
            .expect("built-in command reconciliation policy is valid")
    }
}

/// Ordinary-TLS gRPC adapter for one-time Connector enrollment.
#[derive(Clone)]
pub struct ConnectorEnrollmentGrpc {
    application: Arc<dyn ConnectorControlApplication>,
    transport_admission: SourceTransportAdmission,
    operation_timeout: Duration,
}

impl ConnectorEnrollmentGrpc {
    #[must_use]
    pub fn new(application: Arc<dyn ConnectorControlApplication>) -> Self {
        Self {
            application,
            transport_admission: SourceTransportAdmission::new(
                SourceTransportAdmissionConfig::default(),
            ),
            operation_timeout: ENROLLMENT_OPERATION_TIMEOUT,
        }
    }

    /// Replaces the anonymous enrollment admission guard.
    #[must_use]
    pub fn with_transport_admission(mut self, admission: SourceTransportAdmission) -> Self {
        self.transport_admission = admission;
        self
    }

    /// Replaces the enrollment application deadline, clamped to one through thirty seconds.
    #[must_use]
    pub fn with_operation_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout = clamp_public_rpc_timeout(timeout);
        self
    }
}

impl fmt::Debug for ConnectorEnrollmentGrpc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorEnrollmentGrpc")
            .field("application", &"[APPLICATION PORT]")
            .field("transport_admission", &self.transport_admission)
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

#[tonic::async_trait]
impl v1::connector_enrollment_server::ConnectorEnrollment for ConnectorEnrollmentGrpc {
    async fn enroll_connector(
        &self,
        request: Request<v1::EnrollConnectorRequest>,
    ) -> Result<Response<v1::EnrollConnectorResponse>, Status> {
        let _admission_permit = self
            .transport_admission
            .try_acquire_request(&request)
            .map_err(|_| Status::resource_exhausted("RESOURCE_EXHAUSTED"))?;
        let request = parse_enrollment_request(request.into_inner()).map_err(wire_status)?;
        let completion =
            tokio::time::timeout(self.operation_timeout, self.application.enroll(request))
                .await
                .map_err(|_| Status::deadline_exceeded("ENROLLMENT_TIMEOUT"))?
                .map_err(application_status)?;
        Ok(Response::new(build_enrollment_response(
            &completion.request,
            &completion.credential,
        )))
    }
}

/// Mandatory-mTLS bidirectional gRPC adapter for Connector control.
#[derive(Clone)]
pub struct ConnectorControlGrpc {
    application: Arc<dyn ConnectorControlApplication>,
    verifier: Arc<ConnectorMtlsClientVerifier>,
    transport_admission: ConnectorTransportAdmission,
    first_hello_timeout: Duration,
    command_reconcile_policy: CommandReconcilePolicy,
}

impl ConnectorControlGrpc {
    #[must_use]
    pub fn new(
        application: Arc<dyn ConnectorControlApplication>,
        verifier: Arc<ConnectorMtlsClientVerifier>,
    ) -> Self {
        Self {
            application,
            verifier,
            transport_admission: ConnectorTransportAdmission::new(
                ConnectorTransportAdmissionConfig::default(),
            ),
            first_hello_timeout: FIRST_HELLO_TIMEOUT,
            command_reconcile_policy: CommandReconcilePolicy::default(),
        }
    }

    #[must_use]
    pub fn with_first_hello_timeout(mut self, timeout: Duration) -> Self {
        self.first_hello_timeout = clamp_public_rpc_timeout(timeout);
        self
    }

    #[must_use]
    pub fn with_transport_admission(mut self, admission: ConnectorTransportAdmission) -> Self {
        self.transport_admission = admission;
        self
    }

    #[must_use]
    pub const fn with_command_reconcile_policy(mut self, policy: CommandReconcilePolicy) -> Self {
        self.command_reconcile_policy = policy;
        self
    }
}

impl fmt::Debug for ConnectorControlGrpc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorControlGrpc")
            .field("application", &"[APPLICATION PORT]")
            .field("verifier", &self.verifier)
            .field("transport_admission", &self.transport_admission)
            .field("first_hello_timeout", &self.first_hello_timeout)
            .field("command_reconcile_policy", &self.command_reconcile_policy)
            .finish()
    }
}

type ControlResponseStream =
    Pin<Box<dyn Stream<Item = Result<v1::ServerFrame, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl v1::connector_control_server::ConnectorControl for ConnectorControlGrpc {
    type ControlStream = ControlResponseStream;

    async fn control(
        &self,
        request: Request<Streaming<v1::ClientFrame>>,
    ) -> Result<Response<Self::ControlStream>, Status> {
        let now = self
            .application
            .now_utc_millis()
            .map_err(application_status)?;
        let peer = authenticate_control_request(
            &request,
            self.verifier.as_ref(),
            unix_time_from_millis(now).map_err(|_| authentication_status())?,
        )
        .map_err(|_| authentication_status())?;
        let first_hello_permit = self
            .transport_admission
            .try_acquire_control_request(&request, peer)
            .map_err(|_| Status::resource_exhausted("RESOURCE_EXHAUSTED"))?;
        let inbound = request.into_inner();
        let (sender, receiver) = mpsc::channel(CONTROL_RESPONSE_BUFFER);
        let application = Arc::clone(&self.application);
        let verifier = Arc::clone(&self.verifier);
        let timeout = self.first_hello_timeout;
        let command_reconcile_policy = self.command_reconcile_policy;
        tokio::spawn(async move {
            drive_control(
                application,
                verifier,
                peer,
                first_hello_permit,
                inbound,
                sender,
                timeout,
                command_reconcile_policy,
            )
            .await;
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }
}

/// Builds the enrollment service with the frozen protobuf size ceiling.
#[must_use]
pub fn connector_enrollment_service(
    application: Arc<dyn ConnectorControlApplication>,
) -> v1::connector_enrollment_server::ConnectorEnrollmentServer<ConnectorEnrollmentGrpc> {
    v1::connector_enrollment_server::ConnectorEnrollmentServer::new(ConnectorEnrollmentGrpc::new(
        application,
    ))
    .max_decoding_message_size(MAX_AGENT_CONTROL_MESSAGE_BYTES)
    .max_encoding_message_size(MAX_AGENT_CONTROL_MESSAGE_BYTES)
}

/// Builds the control service with mandatory cryptographic Connector mTLS authentication.
#[must_use]
pub fn connector_control_service(
    application: Arc<dyn ConnectorControlApplication>,
    verifier: Arc<ConnectorMtlsClientVerifier>,
) -> v1::connector_control_server::ConnectorControlServer<ConnectorControlGrpc> {
    v1::connector_control_server::ConnectorControlServer::new(ConnectorControlGrpc::new(
        application,
        verifier,
    ))
    .max_decoding_message_size(MAX_AGENT_CONTROL_MESSAGE_BYTES)
    .max_encoding_message_size(MAX_AGENT_CONTROL_MESSAGE_BYTES)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One visible fail-closed audit boundary.
async fn drive_control(
    application: Arc<dyn ConnectorControlApplication>,
    verifier: Arc<ConnectorMtlsClientVerifier>,
    peer: AuthenticatedConnectorPeer,
    first_hello_permit: ConnectorHelloAdmissionPermit,
    mut inbound: Streaming<v1::ClientFrame>,
    sender: mpsc::Sender<Result<v1::ServerFrame, Status>>,
    first_hello_timeout: Duration,
    command_reconcile_policy: CommandReconcilePolicy,
) {
    let first = match tokio::time::timeout(first_hello_timeout, inbound.message()).await {
        Ok(Ok(Some(frame))) => frame,
        Ok(Ok(None)) => return,
        Ok(Err(_)) => {
            send_status(&sender, Status::invalid_argument("INVALID_WIRE_FRAME")).await;
            return;
        }
        Err(_) => {
            send_status(&sender, Status::deadline_exceeded("HELLO_TIMEOUT")).await;
            return;
        }
    };
    let hello = match parse_client_frame(first) {
        Ok(ParsedClientFrame::Hello(hello)) => hello,
        Ok(_) => {
            send_status(&sender, Status::failed_precondition("HELLO_REQUIRED")).await;
            return;
        }
        Err(error) => {
            send_status(&sender, wire_status(error)).await;
            return;
        }
    };
    let now = match application.now_utc_millis() {
        Ok(now) => now,
        Err(error) => {
            send_status(&sender, application_status(error)).await;
            return;
        }
    };
    let Ok(now) = unix_time_from_millis(now) else {
        send_status(&sender, authentication_status()).await;
        return;
    };
    let Ok(peer) = verifier.authorize_first_hello(
        peer,
        ConnectorWorkloadIdentity::new(hello.tenant_id, hello.connector_id),
        now.as_secs(),
    ) else {
        send_status(&sender, authentication_status()).await;
        return;
    };
    let opened = match application.open_control(peer, hello).await {
        Ok(opened) => opened,
        Err(error) => {
            send_status(&sender, application_status(error)).await;
            return;
        }
    };
    let stream_fence = opened.lease.fence();
    // Subscribe before the final durable suffix query. This ordering closes the
    // commit-between-replay-and-wait race while allowing lossy/coalesced hints.
    let mut command_notifications =
        application.subscribe_commands(stream_fence.tenant_id(), stream_fence.connector_id());
    let lease = match build_connect_lease(
        opened.lease,
        opened.protocol_minor,
        opened.heartbeat_interval_millis,
        opened.heartbeat_ttl_millis,
        opened.acknowledged_command_sequence,
    ) {
        Ok(lease) => lease,
        Err(error) => {
            send_status(&sender, wire_status(error)).await;
            return;
        }
    };
    if !send_frame(&sender, v1::server_frame::Kind::ConnectLease(lease)).await {
        return;
    }
    // This quota protects only the bounded authentication/first-Hello window.
    // A separately configured active-stream policy may be added at the server
    // boundary; retaining these small pending limits would cap legitimate NATs.
    drop(first_hello_permit);
    let mut last_delivered_sequence = opened.acknowledged_command_sequence;
    for command in opened.replay_commands {
        last_delivered_sequence = command.sequence();
        if !send_frame(
            &sender,
            v1::server_frame::Kind::DurableCommand(build_durable_command_frame(&command)),
        )
        .await
        {
            return;
        }
    }

    // Durable replay after subscription is mandatory even when the initial
    // Hello transaction returned no backlog.
    if !poll_and_deliver_commands(
        application.as_ref(),
        peer,
        stream_fence,
        &mut last_delivered_sequence,
        &sender,
    )
    .await
    {
        return;
    }
    let reconcile_delay = command_reconcile_policy.delay(stream_fence);
    let reconcile = tokio::time::sleep(reconcile_delay);
    tokio::pin!(reconcile);
    loop {
        tokio::select! {
            inbound_frame = inbound.message() => {
                let Ok(frame) = inbound_frame else {
                    send_status(&sender, Status::invalid_argument("INVALID_WIRE_FRAME")).await;
                    return;
                };
                let Some(frame) = frame else {
                    return;
                };
                let frame = match parse_client_frame(frame) {
                    Ok(frame) => frame,
                    Err(error) => {
                        send_status(&sender, wire_status(error)).await;
                        return;
                    }
                };
                let result = match frame {
                    ParsedClientFrame::Hello(_) => {
                        send_status(
                            &sender,
                            Status::failed_precondition("HELLO_ALREADY_ACCEPTED"),
                        )
                        .await;
                        return;
                    }
                    ParsedClientFrame::Ready(ready) => application.ready(peer, ready).await,
                    ParsedClientFrame::Heartbeat(heartbeat) => {
                        match application.heartbeat(peer, heartbeat).await {
                            Ok(completion) => {
                                match build_heartbeat_acknowledgement(
                                    completion.acknowledgement,
                                    completion.observed_at_millis,
                                ) {
                                    Ok(acknowledgement) => {
                                        if !send_frame(
                                            &sender,
                                            v1::server_frame::Kind::HeartbeatAcknowledgement(
                                                acknowledgement,
                                            ),
                                        )
                                        .await
                                        {
                                            return;
                                        }
                                        Ok(())
                                    }
                                    Err(error) => Err(wire_into_application(error)),
                                }
                            }
                            Err(error) => Err(error),
                        }
                    }
                    ParsedClientFrame::CommandAcknowledgement(acknowledgement) => {
                        application
                            .acknowledge_command(peer, acknowledgement)
                            .await
                    }
                    ParsedClientFrame::CredentialRotationProof(proof) => {
                        match application.rotate_credential(peer, proof).await {
                            Ok(completion) => {
                                if !send_frame(
                                    &sender,
                                    v1::server_frame::Kind::CredentialRotationResult(
                                        build_credential_rotation_result(
                                            &completion.request,
                                            &completion.credential,
                                        ),
                                    ),
                                )
                                .await
                                {
                                    return;
                                }
                                Ok(())
                            }
                            Err(error) => Err(error),
                        }
                    }
                };
                if let Err(error) = result {
                    send_status(&sender, application_status(error)).await;
                    return;
                }
            }
            () = command_notifications.changed() => {
                if !poll_and_deliver_commands(
                    application.as_ref(),
                    peer,
                    stream_fence,
                    &mut last_delivered_sequence,
                    &sender,
                ).await {
                    return;
                }
            }
            () = &mut reconcile => {
                if !poll_and_deliver_commands(
                    application.as_ref(),
                    peer,
                    stream_fence,
                    &mut last_delivered_sequence,
                    &sender,
                ).await {
                    return;
                }
                reconcile.as_mut().reset(tokio::time::Instant::now() + reconcile_delay);
            }
        }
    }
}

async fn poll_and_deliver_commands(
    application: &dyn ConnectorControlApplication,
    peer: AuthenticatedConnectorPeer,
    stream_fence: dtx_connect_registry::ConnectorFence,
    last_delivered_sequence: &mut u64,
    sender: &mpsc::Sender<Result<v1::ServerFrame, Status>>,
) -> bool {
    loop {
        let commands = match application
            .poll_commands(peer, stream_fence, *last_delivered_sequence)
            .await
        {
            Ok(commands) => commands,
            Err(error) => {
                send_status(sender, application_status(error)).await;
                return false;
            }
        };
        if commands.is_empty() {
            return true;
        }
        for command in commands {
            if command.sequence() != last_delivered_sequence.saturating_add(1) {
                send_status(sender, Status::internal("INTERNAL")).await;
                return false;
            }
            *last_delivered_sequence = command.sequence();
            if !send_frame(
                sender,
                v1::server_frame::Kind::DurableCommand(build_durable_command_frame(&command)),
            )
            .await
            {
                return false;
            }
        }
        tokio::task::yield_now().await;
    }
}

async fn send_frame(
    sender: &mpsc::Sender<Result<v1::ServerFrame, Status>>,
    kind: v1::server_frame::Kind,
) -> bool {
    send_result(sender, Ok(v1::ServerFrame { kind: Some(kind) })).await
}

async fn send_status(sender: &mpsc::Sender<Result<v1::ServerFrame, Status>>, status: Status) {
    let _ = send_result(sender, Err(status)).await;
}

async fn send_result(
    sender: &mpsc::Sender<Result<v1::ServerFrame, Status>>,
    response: Result<v1::ServerFrame, Status>,
) -> bool {
    send_result_with_timeout(sender, response, CONTROL_RESPONSE_SEND_TIMEOUT).await
}

async fn send_result_with_timeout(
    sender: &mpsc::Sender<Result<v1::ServerFrame, Status>>,
    response: Result<v1::ServerFrame, Status>,
    timeout: Duration,
) -> bool {
    tokio::time::timeout(timeout, sender.send(response))
        .await
        .is_ok_and(|result| result.is_ok())
}

fn wire_status(_: crate::WireError) -> Status {
    Status::invalid_argument("INVALID_WIRE_FRAME")
}

const fn wire_into_application(_: crate::WireError) -> ConnectorControlApplicationError {
    ConnectorControlApplicationError::Internal
}

fn authentication_status() -> Status {
    Status::unauthenticated("AUTHENTICATION_FAILED")
}

fn clamp_public_rpc_timeout(timeout: Duration) -> Duration {
    timeout.clamp(MIN_PUBLIC_RPC_TIMEOUT, MAX_PUBLIC_RPC_TIMEOUT)
}

fn application_status(error: ConnectorControlApplicationError) -> Status {
    let message = error.stable_code();
    match error {
        ConnectorControlApplicationError::InvalidRequest => Status::invalid_argument(message),
        ConnectorControlApplicationError::AuthenticationFailed => Status::unauthenticated(message),
        ConnectorControlApplicationError::PermissionDenied => Status::permission_denied(message),
        ConnectorControlApplicationError::NotFound => Status::not_found(message),
        ConnectorControlApplicationError::Conflict => Status::aborted(message),
        ConnectorControlApplicationError::StaleFence => Status::failed_precondition(message),
        ConnectorControlApplicationError::ResourceExhausted => Status::resource_exhausted(message),
        ConnectorControlApplicationError::Unavailable => Status::unavailable(message),
        ConnectorControlApplicationError::Internal => Status::internal(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NeverCalledApplication;

    impl ConnectorControlApplication for NeverCalledApplication {
        fn now_utc_millis(&self) -> Result<i64, ConnectorControlApplicationError> {
            panic!("invalid enrollment must not reach the application")
        }

        fn enroll(
            &self,
            _request: crate::ParsedEnrollment,
        ) -> crate::ApplicationFuture<'_, crate::EnrollmentCompletion> {
            panic!("invalid enrollment must not reach the application")
        }

        fn open_control(
            &self,
            _peer: AuthenticatedConnectorPeer,
            _hello: crate::ParsedHello,
        ) -> crate::ApplicationFuture<'_, crate::OpenControlCompletion> {
            panic!("enrollment test does not open control")
        }

        fn ready(
            &self,
            _peer: AuthenticatedConnectorPeer,
            _ready: crate::ParsedReady,
        ) -> crate::ApplicationFuture<'_, ()> {
            panic!("enrollment test does not report readiness")
        }

        fn heartbeat(
            &self,
            _peer: AuthenticatedConnectorPeer,
            _heartbeat: crate::ParsedHeartbeat,
        ) -> crate::ApplicationFuture<'_, crate::HeartbeatCompletion> {
            panic!("enrollment test does not report heartbeats")
        }

        fn acknowledge_command(
            &self,
            _peer: AuthenticatedConnectorPeer,
            _acknowledgement: crate::ParsedCommandAcknowledgement,
        ) -> crate::ApplicationFuture<'_, ()> {
            panic!("enrollment test does not acknowledge commands")
        }

        fn rotate_credential(
            &self,
            _peer: AuthenticatedConnectorPeer,
            _proof: crate::ParsedCredentialRotationProof,
        ) -> crate::ApplicationFuture<'_, crate::CredentialRotationCompletion> {
            panic!("enrollment test does not rotate credentials")
        }
    }

    #[tokio::test]
    async fn anonymous_enrollment_is_admitted_before_parsing_even_without_a_remote_ip() {
        let admission = SourceTransportAdmission::new(
            SourceTransportAdmissionConfig::new(
                crate::TransportAdmissionDimensionConfig::new(1, 1, Duration::from_secs(30))
                    .expect("global policy is valid"),
                crate::TransportAdmissionDimensionConfig::new(1, 1, Duration::from_secs(30))
                    .expect("source policy is valid"),
                Duration::from_secs(30),
                1,
            )
            .expect("enrollment admission config is valid"),
        );
        let service = ConnectorEnrollmentGrpc::new(Arc::new(NeverCalledApplication))
            .with_transport_admission(admission);

        let first = v1::connector_enrollment_server::ConnectorEnrollment::enroll_connector(
            &service,
            Request::new(v1::EnrollConnectorRequest::default()),
        )
        .await
        .expect_err("malformed first request is rejected by the wire boundary");
        assert_eq!(first.code(), tonic::Code::InvalidArgument);

        let second = v1::connector_enrollment_server::ConnectorEnrollment::enroll_connector(
            &service,
            Request::new(v1::EnrollConnectorRequest::default()),
        )
        .await
        .expect_err("the consumed global burst token rate-limits the next request");
        assert_eq!(second.code(), tonic::Code::ResourceExhausted);
    }

    #[test]
    fn public_rpc_deadlines_are_clamped_to_the_safe_window() {
        assert_eq!(
            clamp_public_rpc_timeout(Duration::ZERO),
            Duration::from_secs(1)
        );
        assert_eq!(
            clamp_public_rpc_timeout(Duration::from_secs(10)),
            Duration::from_secs(10)
        );
        assert_eq!(
            clamp_public_rpc_timeout(Duration::from_mins(1)),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn command_reconciliation_is_bounded_and_never_restores_one_hertz_polling() {
        assert!(CommandReconcilePolicy::new(Duration::from_secs(1), Duration::ZERO).is_err());
        assert!(
            CommandReconcilePolicy::new(Duration::from_secs(30), Duration::from_secs(31)).is_err()
        );
        assert!(
            CommandReconcilePolicy::new(Duration::from_secs(250), Duration::from_mins(1)).is_err()
        );
        assert_eq!(COMMAND_POLL_INTERVAL, Duration::from_secs(30));
        assert_eq!(
            CommandReconcilePolicy::default().interval,
            Duration::from_secs(30)
        );
    }

    #[tokio::test]
    async fn a_slow_control_client_cannot_pin_a_response_sender_forever() {
        let (sender, _receiver) = mpsc::channel(1);
        sender
            .send(Err(Status::internal("occupied")))
            .await
            .expect("fixture fills the bounded response queue");

        assert!(
            !send_result_with_timeout(
                &sender,
                Err(Status::internal("blocked")),
                Duration::from_millis(1),
            )
            .await
        );
    }
}
