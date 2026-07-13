use std::str::FromStr;

use dtx_agent_host::{AgentHost, AgentHostSnapshotError, HostLifecycle, ReportedHealth};
use dtx_domain::{HostCredentialId, HostId, IdentityId, Revision, TenantId};

const OWNER: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

#[test]
fn host_snapshot_round_trips_retired_ids_and_heartbeat_high_water() {
    let mut host = AgentHost::register(
        TenantId::new(),
        HostId::new(),
        IdentityId::from_str(OWNER).unwrap(),
    );
    let first = HostCredentialId::new();
    host.enroll(Revision::INITIAL, first).unwrap();
    let current = HostCredentialId::new();
    host.rotate_credential(host.revision(), current).unwrap();
    host.record_heartbeat(
        host.revision(),
        current,
        host.desired_revision(),
        ReportedHealth::Healthy,
        1_000,
        100,
    )
    .unwrap();
    host.quarantine(host.revision()).unwrap();
    host.record_heartbeat(
        host.revision(),
        current,
        host.desired_revision(),
        ReportedHealth::Healthy,
        1_001,
        100,
    )
    .unwrap();

    assert_eq!(AgentHost::try_from_snapshot(host.snapshot()).unwrap(), host);

    let mut malformed = host.snapshot();
    malformed.retired_credentials.insert(current);
    assert_eq!(
        AgentHost::try_from_snapshot(malformed),
        Err(AgentHostSnapshotError::CurrentCredentialRetired)
    );
}

#[test]
fn host_snapshot_rejects_lifecycle_and_observation_contradictions() {
    let host = AgentHost::register(
        TenantId::new(),
        HostId::new(),
        IdentityId::from_str(OWNER).unwrap(),
    );
    let mut malformed = host.snapshot();
    malformed.lifecycle = HostLifecycle::Active;
    assert_eq!(
        AgentHost::try_from_snapshot(malformed),
        Err(AgentHostSnapshotError::CredentialLifecycleMismatch)
    );
}
