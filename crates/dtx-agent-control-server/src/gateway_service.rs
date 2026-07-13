use std::{fmt, sync::Arc, time::Duration};

use dtx_agent_control_proto::{MAX_AGENT_GATEWAY_MESSAGE_BYTES, gateway_v1};
use dtx_security::InternalServiceMtlsClientVerifier;
use tonic::{Request, Response, Status};

use crate::{
    AgentRunIngressApplication, ConnectorControlApplicationError, SourceTransportAdmission,
    SourceTransportAdmissionConfig, authenticate_agent_gateway_request,
    build_agent_run_ingress_response, parse_agent_run_ingress, unix_time_from_millis,
};

/// Maximum time an admitted Gateway create request may occupy application resources.
pub const AGENT_RUN_INGRESS_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_GATEWAY_RPC_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_GATEWAY_RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Mandatory-mTLS unary ingress from the Legacy Matrix Gateway into Router persistence.
#[derive(Clone)]
pub struct AgentRunIngressGrpc {
    application: Arc<dyn AgentRunIngressApplication>,
    verifier: Arc<InternalServiceMtlsClientVerifier>,
    transport_admission: SourceTransportAdmission,
    operation_timeout: Duration,
}

impl AgentRunIngressGrpc {
    #[must_use]
    pub fn new(
        application: Arc<dyn AgentRunIngressApplication>,
        verifier: Arc<InternalServiceMtlsClientVerifier>,
    ) -> Self {
        Self {
            application,
            verifier,
            transport_admission: SourceTransportAdmission::new(
                SourceTransportAdmissionConfig::default(),
            ),
            operation_timeout: AGENT_RUN_INGRESS_OPERATION_TIMEOUT,
        }
    }

    /// Replaces the direct-source admission guard.
    #[must_use]
    pub fn with_transport_admission(mut self, admission: SourceTransportAdmission) -> Self {
        self.transport_admission = admission;
        self
    }

    /// Replaces the application deadline, clamped to one through thirty seconds.
    #[must_use]
    pub fn with_operation_timeout(mut self, timeout: Duration) -> Self {
        self.operation_timeout = timeout.clamp(MIN_GATEWAY_RPC_TIMEOUT, MAX_GATEWAY_RPC_TIMEOUT);
        self
    }
}

impl fmt::Debug for AgentRunIngressGrpc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentRunIngressGrpc")
            .field("application", &"[APPLICATION PORT]")
            .field("verifier", &self.verifier)
            .field("transport_admission", &self.transport_admission)
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

#[tonic::async_trait]
impl gateway_v1::agent_run_ingress_server::AgentRunIngress for AgentRunIngressGrpc {
    async fn create_agent_run(
        &self,
        request: Request<gateway_v1::CreateAgentRunRequest>,
    ) -> Result<Response<gateway_v1::CreateAgentRunResponse>, Status> {
        let _admission_permit = self
            .transport_admission
            .try_acquire_request(&request)
            .map_err(|_| Status::resource_exhausted("RESOURCE_EXHAUSTED"))?;
        let now = self
            .application
            .now_utc_millis()
            .map_err(application_status)?;
        let peer = authenticate_agent_gateway_request(
            &request,
            self.verifier.as_ref(),
            unix_time_from_millis(now).map_err(|_| authentication_status())?,
        )
        .map_err(|_| authentication_status())?;
        let parsed = parse_agent_run_ingress(request.into_inner(), peer.tenant_id())
            .map_err(|_| Status::invalid_argument("INVALID_REQUEST"))?;
        let completion = tokio::time::timeout(
            self.operation_timeout,
            self.application.create_agent_run(parsed.request),
        )
        .await
        .map_err(|_| Status::deadline_exceeded("AGENT_RUN_INGRESS_TIMEOUT"))?
        .map_err(application_status)?;
        Ok(Response::new(build_agent_run_ingress_response(
            parsed.request_id,
            &completion,
        )))
    }
}

/// Builds the internal Gateway service with its independently frozen size ceiling.
#[must_use]
pub fn agent_run_ingress_service(
    application: Arc<dyn AgentRunIngressApplication>,
    verifier: Arc<InternalServiceMtlsClientVerifier>,
) -> gateway_v1::agent_run_ingress_server::AgentRunIngressServer<AgentRunIngressGrpc> {
    gateway_v1::agent_run_ingress_server::AgentRunIngressServer::new(AgentRunIngressGrpc::new(
        application,
        verifier,
    ))
    .max_decoding_message_size(MAX_AGENT_GATEWAY_MESSAGE_BYTES)
    .max_encoding_message_size(MAX_AGENT_GATEWAY_MESSAGE_BYTES)
}

fn authentication_status() -> Status {
    Status::unauthenticated("AUTHENTICATION_FAILED")
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
