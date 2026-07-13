use crate::{
    ApplicationFuture, ConnectorControlApplication, ConnectorControlApplicationError,
    CreateAgentRunRequest, CreatedAgentRun, PostgresConnectorControlApplication,
};

/// Transport-independent ingress port for authenticated internal Agent Run requests.
pub trait AgentRunIngressApplication: Send + Sync + 'static {
    /// Returns server-authoritative UTC milliseconds for certificate validation.
    ///
    /// # Errors
    ///
    /// Fails closed when the configured clock is unavailable or outside the supported range.
    fn now_utc_millis(&self) -> Result<i64, ConnectorControlApplicationError>;

    /// Persists and best-effort routes one exact, explicitly targeted Agent Run.
    fn create_agent_run(
        &self,
        request: CreateAgentRunRequest,
    ) -> ApplicationFuture<'_, CreatedAgentRun>;
}

impl AgentRunIngressApplication for PostgresConnectorControlApplication {
    fn now_utc_millis(&self) -> Result<i64, ConnectorControlApplicationError> {
        ConnectorControlApplication::now_utc_millis(self)
    }

    fn create_agent_run(
        &self,
        request: CreateAgentRunRequest,
    ) -> ApplicationFuture<'_, CreatedAgentRun> {
        Box::pin(PostgresConnectorControlApplication::create_agent_run(
            self, request,
        ))
    }
}
