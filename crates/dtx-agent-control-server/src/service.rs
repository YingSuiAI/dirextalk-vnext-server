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
    build_connect_lease_with_capabilities, build_credential_reissue_response,
    build_credential_rotation_result, build_durable_command_frame, build_enrollment_response,
    build_heartbeat_acknowledgement, build_run_available, build_run_checkpoint_ack,
    build_run_completed_ack, build_run_failed_ack, build_run_lease_granted, build_run_output_ack,
    parse_client_frame, parse_credential_reissue_request, parse_enrollment_request,
    unix_time_from_millis,
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
/// Maximum tenant-local Router timeout rows processed by one control-stream tick.
pub const AGENT_RUN_TIMEOUT_RECONCILE_BATCH_LIMIT: usize =
    dtx_agent_persistence::MAX_AGENT_RUN_EXPIRY_BATCH;
/// Router offers expire after 15 seconds, so active streams reconcile well
/// inside that window even when a wakeup notification is lost.
pub const AGENT_RUN_RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
/// Bound one Run-offer drain slice so Heartbeat and `RunClaim` frames regain the
/// control loop; a coalesced local wake immediately continues the next slice.
pub const AGENT_RUN_OFFER_DRAIN_PAGE_BUDGET: usize = 2;

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

    /// Adds the public Route Health receipt pin to fresh enrollment responses.
    /// The private signing key remains outside the protocol object.
    #[must_use]
    pub fn with_route_health_receipt_pin(
        self,
        _key_id: impl Into<String>,
        _public_key: [u8; 32],
    ) -> Self {
        self
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
        let response = build_enrollment_response(&completion.request, &completion.credential);
        Ok(Response::new(response))
    }

    async fn reissue_connector_credential(
        &self,
        request: Request<v1::ReissueConnectorCredentialRequest>,
    ) -> Result<Response<v1::ReissueConnectorCredentialResponse>, Status> {
        let _admission_permit = self
            .transport_admission
            .try_acquire_request(&request)
            .map_err(|_| Status::resource_exhausted("RESOURCE_EXHAUSTED"))?;
        let request =
            parse_credential_reissue_request(request.into_inner()).map_err(wire_status)?;
        let completion = tokio::time::timeout(
            self.operation_timeout,
            self.application.reissue_credential(request),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("REISSUE_TIMEOUT"))?
        .map_err(application_status)?;
        Ok(Response::new(build_credential_reissue_response(
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

/// Builds enrollment with the additive public Route Health receipt pin.
#[must_use]
pub fn connector_enrollment_service_with_route_health_pin(
    application: Arc<dyn ConnectorControlApplication>,
    key_id: impl Into<String>,
    public_key: [u8; 32],
) -> v1::connector_enrollment_server::ConnectorEnrollmentServer<ConnectorEnrollmentGrpc> {
    v1::connector_enrollment_server::ConnectorEnrollmentServer::new(
        ConnectorEnrollmentGrpc::new(application).with_route_health_receipt_pin(key_id, public_key),
    )
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
    let protocol_minor = opened.protocol_minor;
    let router_enabled = protocol_minor >= 1;
    let execution_reporting_enabled = protocol_minor >= 2;
    let agent_provisioning_enabled = protocol_minor >= 3;
    let agent_route_bootstrap_enabled = protocol_minor >= 4;
    let agent_route_health_enabled = protocol_minor >= 6
        && opened
            .server_capabilities
            .iter()
            .any(|capability| capability == "agent-route-health.v1");
    // Subscribe before the final durable suffix query. This ordering closes the
    // commit-between-replay-and-wait race while allowing lossy/coalesced hints.
    let mut command_notifications =
        application.subscribe_commands(stream_fence.tenant_id(), stream_fence.connector_id());
    let mut run_offer_notifications = if router_enabled {
        application.subscribe_run_offers(stream_fence.tenant_id(), stream_fence.connector_id())
    } else {
        crate::RunOfferNotificationSubscription::never()
    };
    let lease = match build_connect_lease_with_capabilities(
        opened.lease,
        protocol_minor,
        opened.heartbeat_interval_millis,
        opened.heartbeat_ttl_millis,
        opened.acknowledged_command_sequence,
        &opened.server_capabilities,
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
    let initial_replay = deliver_replay_commands(
        opened.replay_commands,
        protocol_minor,
        &mut last_delivered_sequence,
        &sender,
    )
    .await;
    if initial_replay == ReplayDelivery::Closed {
        return;
    }

    // Durable replay after subscription is mandatory even when the initial
    // Hello transaction returned no backlog.
    if initial_replay != ReplayDelivery::Held {
        if !poll_and_deliver_commands(
            application.as_ref(),
            peer,
            stream_fence,
            protocol_minor,
            &mut last_delivered_sequence,
            &sender,
        )
        .await
        {
            return;
        }
    }
    let mut run_offer_cursor = 0;
    let mut run_cancel_cursor = 0;
    let (run_offer_drain_sender, mut run_offer_drain_receiver) = mpsc::channel(1);
    if router_enabled {
        if !reconcile_agent_run_timeouts_on_tick(
            application.as_ref(),
            stream_fence.tenant_id(),
            protocol_minor,
            &sender,
        )
        .await
        {
            return;
        }
        if !poll_and_deliver_run_offers(
            application.as_ref(),
            peer,
            stream_fence,
            &mut run_offer_cursor,
            &sender,
            &run_offer_drain_sender,
        )
        .await
        {
            return;
        }
        if execution_reporting_enabled
            && !poll_and_deliver_run_cancellations(
                application.as_ref(),
                peer,
                stream_fence,
                &mut run_cancel_cursor,
                &sender,
                &run_offer_drain_sender,
            )
            .await
        {
            return;
        }
    }
    let reconcile_delay = command_reconcile_policy.delay(stream_fence);
    let reconcile = tokio::time::sleep(reconcile_delay);
    tokio::pin!(reconcile);
    let run_reconcile = tokio::time::sleep(AGENT_RUN_RECONCILE_INTERVAL);
    tokio::pin!(run_reconcile);
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
                            .acknowledge_command_on_session(
                                peer,
                                acknowledgement,
                                protocol_minor,
                            )
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
                    ParsedClientFrame::RunClaim(claim) => {
                        if router_enabled {
                            match application.claim_run(peer, claim).await {
                                Ok(completion) => match build_run_lease_granted(completion) {
                                    Ok(granted) => {
                                        if !send_frame(
                                            &sender,
                                            v1::server_frame::Kind::RunLeaseGranted(granted),
                                        )
                                        .await
                                        {
                                            return;
                                        }
                                        Ok(())
                                    }
                                    Err(error) => Err(wire_into_application(error)),
                                },
                                Err(error) => Err(error),
                            }
                        } else {
                            Err(ConnectorControlApplicationError::PermissionDenied)
                        }
                    }
                    ParsedClientFrame::RunRelease(release) => {
                        if router_enabled {
                            application.release_run(peer, release).await
                        } else {
                            Err(ConnectorControlApplicationError::PermissionDenied)
                        }
                    }
                    ParsedClientFrame::RunCheckpoint(checkpoint) => {
                        if execution_reporting_enabled {
                            let acknowledgement = build_run_checkpoint_ack(&checkpoint);
                            match application.record_run_checkpoint(peer, checkpoint).await {
                                Ok(()) => {
                                    if !send_frame(&sender, v1::server_frame::Kind::RunReportAcknowledged(acknowledgement)).await {
                                        return;
                                    }
                                    Ok(())
                                }
                                Err(error) => Err(error),
                            }
                        } else {
                            Err(ConnectorControlApplicationError::PermissionDenied)
                        }
                    }
                    ParsedClientFrame::RunOutput(output) => {
                        if execution_reporting_enabled {
                            let acknowledgement = build_run_output_ack(&output);
                            match application.record_run_output(peer, output).await {
                                Ok(()) => {
                                    if !send_frame(&sender, v1::server_frame::Kind::RunReportAcknowledged(acknowledgement)).await {
                                        return;
                                    }
                                    Ok(())
                                }
                                Err(error) => Err(error),
                            }
                        } else {
                            Err(ConnectorControlApplicationError::PermissionDenied)
                        }
                    }
                    ParsedClientFrame::RunCompleted(completed) => {
                        if execution_reporting_enabled {
                            let acknowledgement = build_run_completed_ack(&completed);
                            match application.complete_run(peer, completed).await {
                                Ok(()) => {
                                    if !send_frame(&sender, v1::server_frame::Kind::RunReportAcknowledged(acknowledgement)).await {
                                        return;
                                    }
                                    Ok(())
                                }
                                Err(error) => Err(error),
                            }
                        } else {
                            Err(ConnectorControlApplicationError::PermissionDenied)
                        }
                    }
                    ParsedClientFrame::RunFailed(failed) => {
                        if execution_reporting_enabled {
                            let acknowledgement = build_run_failed_ack(&failed);
                            match application.fail_run(peer, failed).await {
                                Ok(()) => {
                                    if !send_frame(&sender, v1::server_frame::Kind::RunReportAcknowledged(acknowledgement)).await {
                                        return;
                                    }
                                    Ok(())
                                }
                                Err(error) => Err(error),
                            }
                        } else {
                            Err(ConnectorControlApplicationError::PermissionDenied)
                        }
                    }
                    ParsedClientFrame::ProvisioningRecipientAnnouncement(announcement) => {
                        if agent_provisioning_enabled {
                            application
                                .announce_provisioning_recipient(peer, announcement)
                                .await
                        } else {
                            Err(ConnectorControlApplicationError::PermissionDenied)
                        }
                    }
                    ParsedClientFrame::AgentProvisioningInstalled(installed) => {
                        if agent_provisioning_enabled {
                            application
                                .complete_agent_provisioning(peer, installed)
                                .await
                        } else {
                            Err(ConnectorControlApplicationError::PermissionDenied)
                        }
                    }
                    ParsedClientFrame::AgentProvisioningRejected(rejected) => {
                        if agent_provisioning_enabled {
                            application
                                .reject_agent_provisioning(peer, rejected)
                                .await
                        } else {
                            Err(ConnectorControlApplicationError::PermissionDenied)
                        }
                    }
                    ParsedClientFrame::AgentRouteRecipientReady(ready) => {
                        if agent_route_bootstrap_enabled
                            && (ready.route_health_key_id.is_some() == agent_route_health_enabled)
                            && (ready.route_health_public_key.is_some() == agent_route_health_enabled)
                        {
                            application.record_agent_route_recipient_ready(peer, ready).await
                        } else {
                            Err(ConnectorControlApplicationError::PermissionDenied)
                        }
                    }
                    ParsedClientFrame::AgentRouteBootstrapInstalled(installed) => {
                        if agent_route_bootstrap_enabled
                            && (installed.route_health_key_id.is_some() == agent_route_health_enabled)
                            && (installed.route_health_public_key_digest.is_some() == agent_route_health_enabled)
                        {
                            application.complete_agent_route_bootstrap(peer, installed).await
                        } else {
                            Err(ConnectorControlApplicationError::PermissionDenied)
                        }
                    }
                    ParsedClientFrame::AgentRouteBootstrapRejected(rejected) => {
                        if agent_route_bootstrap_enabled
                            && (rejected.route_health_key_id.is_some() == agent_route_health_enabled)
                            && (rejected.route_health_public_key_digest.is_some() == agent_route_health_enabled)
                        {
                            application.reject_agent_route_bootstrap(peer, rejected).await
                        } else {
                            Err(ConnectorControlApplicationError::PermissionDenied)
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
                    protocol_minor,
                    &mut last_delivered_sequence,
                    &sender,
                ).await {
                    return;
                }
            }
            () = run_offer_notifications.changed() => {
                if !poll_and_deliver_run_offers(
                    application.as_ref(),
                    peer,
                    stream_fence,
                    &mut run_offer_cursor,
                    &sender,
                    &run_offer_drain_sender,
                ).await {
                    return;
                }
                if execution_reporting_enabled && !poll_and_deliver_run_cancellations(
                    application.as_ref(), peer, stream_fence, &mut run_cancel_cursor,
                    &sender, &run_offer_drain_sender,
                ).await {
                    return;
                }
            }
            drain = run_offer_drain_receiver.recv() => {
                if drain.is_none() || !poll_and_deliver_run_offers(
                    application.as_ref(),
                    peer,
                    stream_fence,
                    &mut run_offer_cursor,
                    &sender,
                    &run_offer_drain_sender,
                ).await {
                    return;
                }
                if execution_reporting_enabled && !poll_and_deliver_run_cancellations(
                    application.as_ref(), peer, stream_fence, &mut run_cancel_cursor,
                    &sender, &run_offer_drain_sender,
                ).await {
                    return;
                }
            }
            () = &mut reconcile => {
                if !poll_and_deliver_commands(
                    application.as_ref(),
                    peer,
                    stream_fence,
                    protocol_minor,
                    &mut last_delivered_sequence,
                    &sender,
                ).await {
                    return;
                }
                reconcile.as_mut().reset(tokio::time::Instant::now() + reconcile_delay);
            }
            () = &mut run_reconcile => {
                if !reconcile_agent_run_timeouts_on_tick(
                    application.as_ref(),
                    stream_fence.tenant_id(),
                    protocol_minor,
                    &sender,
                ).await {
                    return;
                }
                if router_enabled && !poll_and_deliver_run_offers(
                    application.as_ref(),
                    peer,
                    stream_fence,
                    &mut run_offer_cursor,
                    &sender,
                    &run_offer_drain_sender,
                ).await {
                    return;
                }
                if execution_reporting_enabled && !poll_and_deliver_run_cancellations(
                    application.as_ref(), peer, stream_fence, &mut run_cancel_cursor,
                    &sender, &run_offer_drain_sender,
                ).await {
                    return;
                }
                run_reconcile.as_mut().reset(
                    tokio::time::Instant::now() + AGENT_RUN_RECONCILE_INTERVAL,
                );
            }
        }
    }
}

async fn reconcile_agent_run_timeouts_on_tick(
    application: &dyn ConnectorControlApplication,
    tenant_id: dtx_domain::TenantId,
    protocol_minor: u32,
    sender: &mpsc::Sender<Result<v1::ServerFrame, Status>>,
) -> bool {
    if protocol_minor < 1 {
        return true;
    }
    match application
        .reconcile_agent_run_timeouts(tenant_id, AGENT_RUN_TIMEOUT_RECONCILE_BATCH_LIMIT)
        .await
    {
        Ok(()) => true,
        Err(error) => {
            send_status(sender, application_status(error)).await;
            false
        }
    }
}

async fn poll_and_deliver_run_offers(
    application: &dyn ConnectorControlApplication,
    peer: AuthenticatedConnectorPeer,
    stream_fence: dtx_connect_registry::ConnectorFence,
    after_sequence: &mut u64,
    sender: &mpsc::Sender<Result<v1::ServerFrame, Status>>,
    drain_wakeup: &mpsc::Sender<()>,
) -> bool {
    for page in 0..AGENT_RUN_OFFER_DRAIN_PAGE_BUDGET {
        let offers = match application
            .poll_run_offers(peer, stream_fence, *after_sequence)
            .await
        {
            Ok(offers) => offers,
            Err(error) => {
                send_status(sender, application_status(error)).await;
                return false;
            }
        };
        if offers.is_empty() {
            return true;
        }
        for offer in offers {
            if offer.connector_offer_sequence <= *after_sequence {
                send_status(
                    sender,
                    application_status(ConnectorControlApplicationError::Internal),
                )
                .await;
                return false;
            }
            *after_sequence = offer.connector_offer_sequence;
            let frame = match build_run_available(offer) {
                Ok(frame) => frame,
                Err(error) => {
                    send_status(sender, wire_status(error)).await;
                    return false;
                }
            };
            if !send_frame(sender, v1::server_frame::Kind::RunAvailable(frame)).await {
                return false;
            }
        }
        if page + 1 == AGENT_RUN_OFFER_DRAIN_PAGE_BUDGET {
            let _ = drain_wakeup.try_send(());
            return true;
        }
        tokio::task::yield_now().await;
    }
    true
}

async fn poll_and_deliver_run_cancellations(
    application: &dyn ConnectorControlApplication,
    peer: AuthenticatedConnectorPeer,
    stream_fence: dtx_connect_registry::ConnectorFence,
    after_sequence: &mut u64,
    sender: &mpsc::Sender<Result<v1::ServerFrame, Status>>,
    drain_wakeup: &mpsc::Sender<()>,
) -> bool {
    for page in 0..AGENT_RUN_OFFER_DRAIN_PAGE_BUDGET {
        let cancellations = match application
            .poll_run_cancellations(peer, stream_fence, *after_sequence)
            .await
        {
            Ok(cancellations) => cancellations,
            Err(error) => {
                send_status(sender, application_status(error)).await;
                return false;
            }
        };
        if cancellations.is_empty() {
            return true;
        }
        for cancellation in cancellations {
            if cancellation.connector_cancel_sequence <= *after_sequence {
                send_status(
                    sender,
                    application_status(ConnectorControlApplicationError::Internal),
                )
                .await;
                return false;
            }
            *after_sequence = cancellation.connector_cancel_sequence;
            let frame = match crate::build_run_cancel_requested(cancellation) {
                Ok(frame) => frame,
                Err(error) => {
                    send_status(sender, wire_status(error)).await;
                    return false;
                }
            };
            if !send_frame(sender, v1::server_frame::Kind::RunCancelRequested(frame)).await {
                return false;
            }
        }
        if page + 1 == AGENT_RUN_OFFER_DRAIN_PAGE_BUDGET {
            let _ = drain_wakeup.try_send(());
            return true;
        }
        tokio::task::yield_now().await;
    }
    true
}

async fn poll_and_deliver_commands(
    application: &dyn ConnectorControlApplication,
    peer: AuthenticatedConnectorPeer,
    stream_fence: dtx_connect_registry::ConnectorFence,
    protocol_minor: u32,
    last_delivered_sequence: &mut u64,
    sender: &mpsc::Sender<Result<v1::ServerFrame, Status>>,
) -> bool {
    loop {
        let commands = match application
            .poll_commands_for_protocol(
                peer,
                stream_fence,
                *last_delivered_sequence,
                protocol_minor,
            )
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
            if !command_is_delivery_eligible(protocol_minor, &command) {
                // RouteBootstrap commands intentionally remain at the durable
                // head until this Connector upgrades and negotiates Control
                // v1.4. Advancing past one would break the exact command cursor.
                return true;
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayDelivery {
    Complete,
    Held,
    Closed,
}

async fn deliver_replay_commands(
    commands: Vec<dtx_agent_control::DurableServerCommand>,
    protocol_minor: u32,
    last_delivered_sequence: &mut u64,
    sender: &mpsc::Sender<Result<v1::ServerFrame, Status>>,
) -> ReplayDelivery {
    for command in commands {
        if !command_is_delivery_eligible(protocol_minor, &command) {
            // RouteBootstrap commands remain at the durable head until this
            // Connector negotiates Control v1.4. Do not advance the transient
            // cursor: a later command must not bypass the retained frame.
            return ReplayDelivery::Held;
        }
        *last_delivered_sequence = command.sequence();
        if !send_frame(
            sender,
            v1::server_frame::Kind::DurableCommand(build_durable_command_frame(&command)),
        )
        .await
        {
            return ReplayDelivery::Closed;
        }
    }
    ReplayDelivery::Complete
}

fn command_is_delivery_eligible(
    protocol_minor: u32,
    command: &dtx_agent_control::DurableServerCommand,
) -> bool {
    protocol_minor >= 4
        || !matches!(
            command.payload(),
            dtx_agent_control::ServerCommandPayload::PrepareAgentRouteRecipient(_)
                | dtx_agent_control::ServerCommandPayload::DeliverAgentRouteBootstrap(_)
        )
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
        ConnectorControlApplicationError::StaleFence
        | ConnectorControlApplicationError::StaleLease => Status::failed_precondition(message),
        ConnectorControlApplicationError::ResourceExhausted => Status::resource_exhausted(message),
        ConnectorControlApplicationError::Unavailable => Status::unavailable(message),
        ConnectorControlApplicationError::Internal => Status::internal(message),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use dtx_agent_control::{
        CloseStreamCommand, CommandLog, DurableServerCommand, DurableServerCommandSnapshot,
        OpaqueAgentRouteBytes, PrepareAgentRouteRecipient, ServerCommandPayload,
    };
    use dtx_domain::{
        AgentDeviceId, AgentRouteBootstrapId, BindingId, ConnectorId, DeviceId, IdentityId,
        InstallationId, RequestId, Revision, TenantId,
    };

    use super::*;

    fn durable_command(
        sequence: u64,
        payload: ServerCommandPayload,
    ) -> (DurableServerCommand, Vec<u8>) {
        let operation_id = RequestId::new();
        let encoded = crate::ProtobufDurableCommandEncoder
            .encode(sequence, operation_id, 1, Revision::INITIAL, &payload)
            .expect("fixture command encodes");
        let payload_digest = encoded.payload_digest();
        let exact_bytes = encoded.into_exact_bytes();
        let expected = exact_bytes.as_slice().to_vec();
        let command = DurableServerCommand::try_from_snapshot(DurableServerCommandSnapshot {
            sequence,
            operation_id,
            generation: 1,
            spec_revision: Revision::INITIAL,
            payload,
            payload_digest,
            encoded_command_digest: exact_bytes.encoded_command_digest(),
            exact_bytes,
        })
        .expect("fixture command snapshot is valid");
        (command, expected)
    }

    fn route_bootstrap_prepare(sequence: u64) -> (DurableServerCommand, Vec<u8>) {
        durable_command(
            sequence,
            ServerCommandPayload::PrepareAgentRouteRecipient(PrepareAgentRouteRecipient {
                bootstrap_id: AgentRouteBootstrapId::new(),
                tenant_id: TenantId::new(),
                installation_id: InstallationId::new(),
                binding_id: BindingId::new(),
                agent_control_device_id: AgentDeviceId::new(),
                owner_identity_id: "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la"
                    .parse::<IdentityId>()
                    .expect("fixture identity ID is canonical"),
                owner_device_id: DeviceId::new(),
                owner_signed_intent: OpaqueAgentRouteBytes::new(b"opaque-owner-intent".to_vec())
                    .expect("fixture opaque intent is bounded"),
                expires_at_millis: 2_000,
            }),
        )
    }

    struct ReconcileTickApplication {
        calls: AtomicUsize,
        expected_tenant_id: dtx_domain::TenantId,
        fail: bool,
    }

    impl ReconcileTickApplication {
        fn new(expected_tenant_id: dtx_domain::TenantId, fail: bool) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                expected_tenant_id,
                fail,
            }
        }
    }

    impl ConnectorControlApplication for ReconcileTickApplication {
        fn now_utc_millis(&self) -> Result<i64, ConnectorControlApplicationError> {
            panic!("reconcile tick fixture does not read the clock")
        }

        fn enroll(
            &self,
            _request: crate::ParsedEnrollment,
        ) -> crate::ApplicationFuture<'_, crate::EnrollmentCompletion> {
            panic!("reconcile tick fixture does not enroll")
        }

        fn open_control(
            &self,
            _peer: AuthenticatedConnectorPeer,
            _hello: crate::ParsedHello,
        ) -> crate::ApplicationFuture<'_, crate::OpenControlCompletion> {
            panic!("reconcile tick fixture does not open control")
        }

        fn ready(
            &self,
            _peer: AuthenticatedConnectorPeer,
            _ready: crate::ParsedReady,
        ) -> crate::ApplicationFuture<'_, ()> {
            panic!("reconcile tick fixture does not report readiness")
        }

        fn heartbeat(
            &self,
            _peer: AuthenticatedConnectorPeer,
            _heartbeat: crate::ParsedHeartbeat,
        ) -> crate::ApplicationFuture<'_, crate::HeartbeatCompletion> {
            panic!("reconcile tick fixture does not report heartbeats")
        }

        fn acknowledge_command(
            &self,
            _peer: AuthenticatedConnectorPeer,
            _acknowledgement: crate::ParsedCommandAcknowledgement,
        ) -> crate::ApplicationFuture<'_, ()> {
            panic!("reconcile tick fixture does not acknowledge commands")
        }

        fn rotate_credential(
            &self,
            _peer: AuthenticatedConnectorPeer,
            _proof: crate::ParsedCredentialRotationProof,
        ) -> crate::ApplicationFuture<'_, crate::CredentialRotationCompletion> {
            panic!("reconcile tick fixture does not rotate credentials")
        }

        fn reconcile_agent_run_timeouts(
            &self,
            tenant_id: dtx_domain::TenantId,
            limit: usize,
        ) -> crate::ApplicationFuture<'_, ()> {
            assert_eq!(tenant_id, self.expected_tenant_id);
            assert_eq!(limit, AGENT_RUN_TIMEOUT_RECONCILE_BATCH_LIMIT);
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = if self.fail {
                Err(ConnectorControlApplicationError::Unavailable)
            } else {
                Ok(())
            };
            Box::pin(async move { result })
        }
    }

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

    #[tokio::test]
    async fn run_timeout_reconciliation_tick_is_minor_gated_bounded_and_fail_closed() {
        let tenant_id = dtx_domain::TenantId::new();
        let (sender, mut receiver) = mpsc::channel(1);
        let application = ReconcileTickApplication::new(tenant_id, false);

        assert!(
            reconcile_agent_run_timeouts_on_tick(&application, tenant_id, 0, &sender).await,
            "minor zero keeps its pre-Router tick behavior",
        );
        assert_eq!(application.calls.load(Ordering::SeqCst), 0);

        assert!(
            reconcile_agent_run_timeouts_on_tick(&application, tenant_id, 1, &sender).await,
            "minor one invokes one bounded tenant reconciliation batch",
        );
        assert_eq!(application.calls.load(Ordering::SeqCst), 1);

        let failing_application = ReconcileTickApplication::new(tenant_id, true);
        assert!(
            !reconcile_agent_run_timeouts_on_tick(&failing_application, tenant_id, 1, &sender,)
                .await,
            "a reconciliation failure closes the control loop",
        );
        let status = receiver
            .recv()
            .await
            .expect("failure emits a stable transport status")
            .expect_err("failure is not a successful frame");
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(status.message(), "UNAVAILABLE");
    }

    #[tokio::test]
    async fn route_bootstrap_replay_holds_at_head_before_v1_4_and_replays_exactly_at_v1_4() {
        let (route_bootstrap, exact_route_bootstrap) = route_bootstrap_prepare(1);
        let (later_command, _) = durable_command(
            2,
            ServerCommandPayload::CloseStream(CloseStreamCommand::reconnect()),
        );
        let (sender, mut receiver) = mpsc::channel(2);
        let mut cursor = 0;
        let mut durable_log =
            CommandLog::new(TenantId::new(), ConnectorId::new(), 1, Revision::INITIAL)
                .expect("fixture command log is valid");
        durable_log
            .append(
                1,
                Revision::INITIAL,
                route_bootstrap.operation_id(),
                route_bootstrap.payload().clone(),
                route_bootstrap.payload_digest(),
                route_bootstrap.exact_bytes().clone(),
            )
            .expect("fixture RouteBootstrap command appends");

        assert_eq!(
            deliver_replay_commands(
                vec![route_bootstrap.clone(), later_command],
                3,
                &mut cursor,
                &sender,
            )
            .await,
            ReplayDelivery::Held,
            "a v1.3 replay stays open while the RouteBootstrap durable head is retained",
        );
        assert_eq!(
            cursor, 0,
            "the transient cursor must remain before the blocked head"
        );
        assert_eq!(
            durable_log.acknowledged_sequence(),
            0,
            "delivery eligibility never advances the durable ACK",
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), receiver.recv())
                .await
                .is_err(),
            "the blocked RouteBootstrap frame and every later frame stay unsent",
        );

        assert_eq!(
            deliver_replay_commands(vec![route_bootstrap], 4, &mut cursor, &sender).await,
            ReplayDelivery::Complete,
            "v1.4 makes the retained RouteBootstrap frame eligible",
        );
        assert_eq!(cursor, 1);
        assert_eq!(
            durable_log.acknowledged_sequence(),
            0,
            "sending a replayed frame still requires a separate durable ACK",
        );
        let frame = receiver
            .recv()
            .await
            .expect("eligible replay emits one frame")
            .expect("eligible replay is not a status");
        let Some(v1::server_frame::Kind::DurableCommand(frame)) = frame.kind else {
            panic!("eligible replay emits a durable command");
        };
        assert_eq!(
            frame.encoded_command, exact_route_bootstrap,
            "v1.4 replay forwards the exact retained durable bytes",
        );
    }
}
