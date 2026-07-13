use std::str::FromStr;

use dtx_agent_host::AgentHost;
use dtx_connect_registry::{AdapterKind, Connector};
use dtx_domain::{ConnectorId, HostCredentialId, HostId, IdentityId, Revision, TenantId};

const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

pub fn awaiting_host(tenant_id: TenantId) -> AgentHost {
    AgentHost::register(
        tenant_id,
        HostId::new(),
        IdentityId::from_str(OWNER_ID).unwrap(),
    )
}

pub fn active_host(tenant_id: TenantId) -> AgentHost {
    let mut host = awaiting_host(tenant_id);
    host.enroll(Revision::INITIAL, HostCredentialId::new())
        .unwrap();
    host
}

pub fn registered_connector(
    tenant_id: TenantId,
    connector_id: ConnectorId,
    adapter_kind: AdapterKind,
    max_concurrency: u32,
) -> Connector {
    Connector::register(
        &active_host(tenant_id),
        connector_id,
        adapter_kind,
        max_concurrency,
    )
    .unwrap()
}
