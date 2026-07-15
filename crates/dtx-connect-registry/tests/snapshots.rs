mod support;

use std::str::FromStr;

use dtx_agent_registry::{
    AgentDevice, AgentDeviceCommand, AgentInstallation, DescriptorDigest,
    DeviceCredentialFingerprint, ExecutionMode,
};
use dtx_connect_registry::{
    AdapterConformance, AdapterKind, BindingSet, BindingSetSnapshotError, BindingSpec, Connector,
    ConnectorObservedState, ConnectorSnapshotError, RoutingPolicy, TenantRef,
};
use dtx_domain::{
    AgentDeviceId, AgentId, BindingId, BootId, ConnectorId, IdentityId, InstallationId, LeaseId,
    Revision, TenantId,
};
use support::registered_connector;

const AGENT_ID: &str = "dtxa17sv7zwzpr7aduy467sdm3pkmxe6if34eoarhaxdnau44fjwfseda";
const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

fn active_entities(tenant_id: TenantId) -> (AgentInstallation, AgentDevice) {
    let installation = AgentInstallation::new(
        tenant_id,
        InstallationId::new(),
        AgentId::from_str(AGENT_ID).unwrap(),
        IdentityId::from_str(OWNER_ID).unwrap(),
        ExecutionMode::ConnectorManaged,
        Revision::INITIAL,
        DescriptorDigest::from_bytes([1; 32]),
    );
    let mut device = AgentDevice::enroll(
        &installation,
        AgentDeviceId::new(),
        dtx_domain::DeviceId::new(),
        DeviceCredentialFingerprint::from_bytes([2; 32]),
    )
    .unwrap();
    device
        .apply(
            &installation,
            Revision::INITIAL,
            AgentDeviceCommand::Activate,
        )
        .unwrap();
    (installation, device)
}

#[test]
fn connector_snapshot_round_trips_all_histories_and_replay_fences() {
    let tenant_id = TenantId::new();
    let mut connector = registered_connector(tenant_id, ConnectorId::new(), AdapterKind::Codex, 4);
    let boot_id = BootId::new();
    connector.begin_boot(boot_id, 1_000).unwrap();
    let fence = connector
        .issue_lease(LeaseId::new(), boot_id, 1_000, 1_100)
        .unwrap();
    connector
        .record_heartbeat(&fence, 7, 1_050, ConnectorObservedState::Ready, 3, 1)
        .unwrap();

    assert_eq!(
        Connector::try_from_snapshot(connector.snapshot()).unwrap(),
        connector
    );

    let mut invalid_pointer = connector.snapshot();
    invalid_pointer.active_lease_index = None;
    assert_eq!(
        Connector::try_from_snapshot(invalid_pointer),
        Err(ConnectorSnapshotError::InvalidActiveLease)
    );

    let mut invalid_heartbeat = connector.snapshot();
    invalid_heartbeat
        .leases
        .last_mut()
        .unwrap()
        .last_heartbeat
        .as_mut()
        .unwrap()
        .sequence += 1;
    assert_eq!(
        Connector::try_from_snapshot(invalid_heartbeat),
        Err(ConnectorSnapshotError::InvalidHeartbeat)
    );

    let mut invalid_high_water = connector.snapshot();
    invalid_high_water.server_time_high_water_millis = Some(999);
    assert_eq!(
        Connector::try_from_snapshot(invalid_high_water),
        Err(ConnectorSnapshotError::InvalidServerTimeHighWater)
    );

    connector.expire_lease(&fence, 1_150, 1_150).unwrap();
    assert_eq!(
        Connector::try_from_snapshot(connector.snapshot()).unwrap(),
        connector,
        "terminal lease history retains its heartbeat replay fence"
    );
}

#[test]
fn replacement_lease_snapshot_preserves_each_streams_replay_fence() {
    let mut connector =
        registered_connector(TenantId::new(), ConnectorId::new(), AdapterKind::Codex, 2);
    let boot_id = BootId::new();
    connector.begin_boot(boot_id, 1_000).unwrap();
    let first = connector
        .issue_lease(LeaseId::new(), boot_id, 1_000, 1_100)
        .unwrap();
    connector
        .record_heartbeat(&first, 7, 1_050, ConnectorObservedState::Ready, 1, 1)
        .unwrap();
    let second = connector
        .issue_lease(LeaseId::new(), boot_id, 1_051, 1_151)
        .unwrap();
    connector
        .record_heartbeat(&second, 1, 1_060, ConnectorObservedState::Busy, 0, 1)
        .unwrap();

    let snapshot = connector.snapshot();
    assert_eq!(snapshot.leases[0].last_heartbeat.unwrap().sequence, 7);
    assert_eq!(snapshot.leases[0].last_heartbeat_at_millis, Some(1_050));
    assert_eq!(snapshot.leases[1].last_heartbeat.unwrap().sequence, 1);
    assert_eq!(snapshot.leases[1].last_heartbeat_at_millis, Some(1_060));
    assert_eq!(Connector::try_from_snapshot(snapshot).unwrap(), connector);
}

#[test]
fn binding_set_snapshot_round_trips_and_rejects_global_identity_reuse() {
    let tenant_id = TenantId::new();
    let connector = registered_connector(tenant_id, ConnectorId::new(), AdapterKind::Codex, 4);
    let (installation, device) = active_entities(tenant_id);
    let mut set = BindingSet::new(tenant_id);
    set.register_connector_conformance(
        &connector,
        AdapterConformance::trusted_multi_session(AdapterKind::Codex, Revision::INITIAL),
    )
    .unwrap();
    let spec = BindingSpec::for_entities(
        TenantRef::new(tenant_id, BindingId::new()),
        &installation,
        &device,
        &connector,
        7,
        1,
    )
    .unwrap();
    let binding_ref = spec.binding_ref();
    set.create_binding(spec, RoutingPolicy::OrderedFailover)
        .unwrap();
    set.revoke(binding_ref, Revision::INITIAL).unwrap();
    set.set_routing_policy(
        TenantRef::new(tenant_id, installation.installation_id()),
        Revision::INITIAL,
        RoutingPolicy::Exclusive,
    )
    .unwrap();

    assert_eq!(BindingSet::try_from_snapshot(set.snapshot()).unwrap(), set);

    let mut malformed = set.snapshot();
    let mut duplicate = malformed.bindings[0];
    duplicate.binding_id = BindingId::new();
    let mut second_connector = malformed.connector_conformance[0];
    second_connector.connector_id = ConnectorId::new();
    duplicate.connector_id = second_connector.connector_id;
    malformed.connector_conformance.push(second_connector);
    malformed.bindings.push(duplicate);
    assert_eq!(
        BindingSet::try_from_snapshot(malformed),
        Err(BindingSetSnapshotError::AgentDeviceReused)
    );
}
