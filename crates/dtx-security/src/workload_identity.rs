use std::{error::Error, fmt, str::FromStr};

use dtx_domain::{ConnectorId, HostId, JobId, TenantId, WorkerId};

/// Fixed workload URI namespace. It is never used for DNS or relay discovery.
pub const WORKLOAD_TRUST_DOMAIN: &str = "dirextalk.internal";
/// Fixed prefix for every v1 Dirextalk workload URI.
pub const WORKLOAD_URI_PREFIX: &str = "spiffe://dirextalk.internal/v1/";

/// Closed internal service identities represented by the workload URI schema.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InternalServiceKind {
    AgentControl,
    AgentOrchestrator,
    CloudBroker,
    ResultVerifier,
}

impl InternalServiceKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AgentControl => "agent-control",
            Self::AgentOrchestrator => "agent-orchestrator",
            Self::CloudBroker => "cloud-broker",
            Self::ResultVerifier => "result-verifier",
        }
    }
}

impl FromStr for InternalServiceKind {
    type Err = WorkloadIdentityParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "agent-control" => Ok(Self::AgentControl),
            "agent-orchestrator" => Ok(Self::AgentOrchestrator),
            "cloud-broker" => Ok(Self::CloudBroker),
            "result-verifier" => Ok(Self::ResultVerifier),
            _ => Err(WorkloadIdentityParseError),
        }
    }
}

/// Strict Host identity carried by one exact URI SAN.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HostWorkloadIdentity {
    tenant_id: TenantId,
    host_id: HostId,
}

impl HostWorkloadIdentity {
    #[must_use]
    pub const fn new(tenant_id: TenantId, host_id: HostId) -> Self {
        Self { tenant_id, host_id }
    }

    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn host_id(self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub fn uri(self) -> String {
        WorkloadIdentity::from(self).uri()
    }
}

impl fmt::Display for HostWorkloadIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.uri())
    }
}

impl FromStr for HostWorkloadIdentity {
    type Err = WorkloadIdentityParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match WorkloadIdentity::from_str(value)? {
            WorkloadIdentity::Host { tenant_id, host_id } => Ok(Self::new(tenant_id, host_id)),
            WorkloadIdentity::Connector { .. }
            | WorkloadIdentity::Executor { .. }
            | WorkloadIdentity::InternalService { .. }
            | WorkloadIdentity::ControlServer { .. } => Err(WorkloadIdentityParseError),
        }
    }
}

/// Strict Connector identity carried by one exact URI SAN.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectorWorkloadIdentity {
    tenant_id: TenantId,
    connector_id: ConnectorId,
}

impl ConnectorWorkloadIdentity {
    #[must_use]
    pub const fn new(tenant_id: TenantId, connector_id: ConnectorId) -> Self {
        Self {
            tenant_id,
            connector_id,
        }
    }

    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn connector_id(self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub fn uri(self) -> String {
        WorkloadIdentity::from(self).uri()
    }
}

impl fmt::Display for ConnectorWorkloadIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.uri())
    }
}

impl FromStr for ConnectorWorkloadIdentity {
    type Err = WorkloadIdentityParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match WorkloadIdentity::from_str(value)? {
            WorkloadIdentity::Connector {
                tenant_id,
                connector_id,
            } => Ok(Self::new(tenant_id, connector_id)),
            WorkloadIdentity::Host { .. }
            | WorkloadIdentity::Executor { .. }
            | WorkloadIdentity::InternalService { .. }
            | WorkloadIdentity::ControlServer { .. } => Err(WorkloadIdentityParseError),
        }
    }
}

/// Closed workload identity variants used in URI SANs.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum WorkloadIdentity {
    Connector {
        tenant_id: TenantId,
        connector_id: ConnectorId,
    },
    Host {
        tenant_id: TenantId,
        host_id: HostId,
    },
    Executor {
        tenant_id: TenantId,
        job_id: JobId,
        worker_id: WorkerId,
    },
    InternalService {
        tenant_id: TenantId,
        service: InternalServiceKind,
    },
    ControlServer {
        dns_name: String,
    },
}

impl WorkloadIdentity {
    #[must_use]
    pub fn uri(&self) -> String {
        match self {
            Self::Connector {
                tenant_id,
                connector_id,
            } => format!("{WORKLOAD_URI_PREFIX}tenants/{tenant_id}/connectors/{connector_id}"),
            Self::Host { tenant_id, host_id } => {
                format!("{WORKLOAD_URI_PREFIX}tenants/{tenant_id}/hosts/{host_id}")
            }
            Self::Executor {
                tenant_id,
                job_id,
                worker_id,
            } => format!(
                "{WORKLOAD_URI_PREFIX}tenants/{tenant_id}/jobs/{job_id}/executors/{worker_id}"
            ),
            Self::InternalService { tenant_id, service } => format!(
                "{WORKLOAD_URI_PREFIX}tenants/{tenant_id}/services/{}",
                service.as_str()
            ),
            Self::ControlServer { dns_name } => {
                format!("{WORKLOAD_URI_PREFIX}control-servers/{dns_name}")
            }
        }
    }
}

impl From<HostWorkloadIdentity> for WorkloadIdentity {
    fn from(value: HostWorkloadIdentity) -> Self {
        Self::Host {
            tenant_id: value.tenant_id,
            host_id: value.host_id,
        }
    }
}

impl From<ConnectorWorkloadIdentity> for WorkloadIdentity {
    fn from(value: ConnectorWorkloadIdentity) -> Self {
        Self::Connector {
            tenant_id: value.tenant_id,
            connector_id: value.connector_id,
        }
    }
}

impl fmt::Display for WorkloadIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.uri())
    }
}

impl FromStr for WorkloadIdentity {
    type Err = WorkloadIdentityParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let path = value
            .strip_prefix(WORKLOAD_URI_PREFIX)
            .ok_or(WorkloadIdentityParseError)?;
        if path.is_empty()
            || path
                .bytes()
                .any(|byte| matches!(byte, b'%' | b'?' | b'#' | b'\\') || !byte.is_ascii())
        {
            return Err(WorkloadIdentityParseError);
        }
        let segments = path.split('/').collect::<Vec<_>>();
        let identity = match segments.as_slice() {
            ["tenants", tenant, "hosts", host] => Self::Host {
                tenant_id: tenant.parse().map_err(|_| WorkloadIdentityParseError)?,
                host_id: host.parse().map_err(|_| WorkloadIdentityParseError)?,
            },
            ["tenants", tenant, "connectors", connector] => Self::Connector {
                tenant_id: tenant.parse().map_err(|_| WorkloadIdentityParseError)?,
                connector_id: connector.parse().map_err(|_| WorkloadIdentityParseError)?,
            },
            ["tenants", tenant, "jobs", job, "executors", worker] => Self::Executor {
                tenant_id: tenant.parse().map_err(|_| WorkloadIdentityParseError)?,
                job_id: job.parse().map_err(|_| WorkloadIdentityParseError)?,
                worker_id: worker.parse().map_err(|_| WorkloadIdentityParseError)?,
            },
            ["tenants", tenant, "services", service] => Self::InternalService {
                tenant_id: tenant.parse().map_err(|_| WorkloadIdentityParseError)?,
                service: service.parse()?,
            },
            ["control-servers", dns_name] if is_canonical_dns_name(dns_name) => {
                Self::ControlServer {
                    dns_name: (*dns_name).to_owned(),
                }
            }
            _ => return Err(WorkloadIdentityParseError),
        };
        if identity.uri() == value {
            Ok(identity)
        } else {
            Err(WorkloadIdentityParseError)
        }
    }
}

fn is_canonical_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

/// A workload URI was not the exact canonical v1 representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkloadIdentityParseError;

impl fmt::Display for WorkloadIdentityParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("workload identity URI is not canonical")
    }
}

impl Error for WorkloadIdentityParseError {}
