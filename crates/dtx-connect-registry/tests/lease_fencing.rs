mod support;

use dtx_connect_registry::{
    AdapterKind, Connector, ConnectorError, ConnectorHeartbeatHead, ConnectorHeartbeatHeadSnapshot,
    ConnectorObservedState, LeaseStatus, MAX_LEASE_TTL_MILLIS,
};
use dtx_domain::Revision;
use dtx_domain::{BootId, ConnectorId, LeaseId, TenantId};
use support::registered_connector;

const NOW: i64 = 1_800_000_000_000;

fn connector() -> Connector {
    registered_connector(TenantId::new(), ConnectorId::new(), AdapterKind::Codex, 2)
}

#[test]
fn compact_heartbeat_head_preserves_full_aggregate_semantics() {
    let mut connector = connector();
    let boot_id = BootId::new();
    connector.begin_boot(boot_id, NOW).expect("boot starts");
    let fence = connector
        .issue_lease(LeaseId::new(), boot_id, NOW, NOW + 20_000)
        .expect("lease starts");
    connector
        .record_heartbeat(
            &fence,
            1,
            NOW + 5_000,
            ConnectorObservedState::Ready,
            1,
            5_000,
        )
        .expect("initial heartbeat advances");

    let before = connector.snapshot();
    let mut compact = ConnectorHeartbeatHead::try_from_snapshot(ConnectorHeartbeatHeadSnapshot {
        tenant_id: before.tenant_id,
        connector_id: before.connector_id,
        generation: before.generation,
        adapter_kind: before.adapter_kind,
        spec_revision: before.spec_revision,
        desired_state: before.desired_state,
        observed_state: before.observed_state,
        max_concurrency: before.max_concurrency,
        current_boot_id: before.current_boot_id.expect("active boot"),
        highest_lease_epoch: before.highest_lease_epoch.expect("active lease epoch"),
        server_time_high_water_millis: before.server_time_high_water_millis,
        active_lease: *before.leases.last().expect("active lease"),
    })
    .expect("compact durable head validates");

    let full_ack = connector
        .record_heartbeat(
            &fence,
            2,
            NOW + 10_000,
            ConnectorObservedState::Busy,
            0,
            5_000,
        )
        .expect("full aggregate advances");
    let compact_ack = compact
        .record_heartbeat(
            &fence,
            2,
            NOW + 10_000,
            ConnectorObservedState::Busy,
            0,
            5_000,
        )
        .expect("compact head advances");
    assert_eq!(compact_ack, full_ack);

    let full = connector.snapshot();
    let compact_snapshot = compact.snapshot();
    assert_eq!(compact_snapshot.observed_state, full.observed_state);
    assert_eq!(
        compact_snapshot.server_time_high_water_millis,
        full.server_time_high_water_millis
    );
    assert_eq!(
        compact_snapshot.active_lease,
        *full.leases.last().expect("active lease remains")
    );
    let replay_before = compact_snapshot;
    assert_eq!(
        compact
            .record_heartbeat(
                &fence,
                2,
                NOW + 11_000,
                ConnectorObservedState::Busy,
                0,
                5_000,
            )
            .expect("exact retry replays"),
        full_ack
    );
    assert_eq!(compact.snapshot(), replay_before);
}

#[test]
fn compact_heartbeat_head_accepts_owner_draining_overlay() {
    let mut connector = connector();
    let boot_id = BootId::new();
    connector.begin_boot(boot_id, NOW).expect("boot starts");
    let fence = connector
        .issue_lease(LeaseId::new(), boot_id, NOW, NOW + 20_000)
        .expect("lease starts");
    connector
        .record_heartbeat(
            &fence,
            1,
            NOW + 5_000,
            ConnectorObservedState::Ready,
            1,
            5_000,
        )
        .expect("heartbeat advances");
    connector
        .set_desired_state(
            Revision::INITIAL,
            dtx_connect_registry::ConnectorDesiredState::Draining,
            NOW + 6_000,
        )
        .expect("owner begins draining");
    let snapshot = connector.snapshot();
    ConnectorHeartbeatHead::try_from_snapshot(ConnectorHeartbeatHeadSnapshot {
        tenant_id: snapshot.tenant_id,
        connector_id: snapshot.connector_id,
        generation: snapshot.generation,
        adapter_kind: snapshot.adapter_kind,
        spec_revision: snapshot.spec_revision,
        desired_state: snapshot.desired_state,
        observed_state: snapshot.observed_state,
        max_concurrency: snapshot.max_concurrency,
        current_boot_id: snapshot.current_boot_id.expect("active boot"),
        highest_lease_epoch: snapshot.highest_lease_epoch.expect("active epoch"),
        server_time_high_water_millis: snapshot.server_time_high_water_millis,
        active_lease: *snapshot.leases.last().expect("active lease"),
    })
    .expect("server-derived draining state remains a valid compact head");
}

#[test]
fn a_new_boot_and_lease_fence_every_older_process() {
    let mut connector = connector();
    let first_boot = BootId::new();
    connector
        .begin_boot(first_boot, NOW)
        .expect("first process boot starts");
    let first = connector
        .issue_lease(LeaseId::new(), first_boot, NOW, NOW + 90_000)
        .expect("first lease issued");
    connector
        .validate_fence(&first, NOW + 1)
        .expect("current fence is accepted");

    let second_boot = BootId::new();
    connector
        .begin_boot(second_boot, NOW + 2)
        .expect("restart replaces the current boot");
    assert_eq!(
        connector.validate_fence(&first, NOW + 2),
        Err(ConnectorError::StaleLease)
    );
    let second = connector
        .issue_lease(LeaseId::new(), second_boot, NOW + 2, NOW + 92_000)
        .expect("replacement lease issued");
    assert!(second.lease_epoch() > first.lease_epoch());
    connector
        .validate_fence(&second, NOW + 3)
        .expect("replacement fence is current");
}

#[test]
fn heartbeat_sequence_is_monotonic_and_expiry_is_server_derived() {
    let mut connector = connector();
    let boot_id = BootId::new();
    connector.begin_boot(boot_id, NOW).unwrap();
    let fence = connector
        .issue_lease(LeaseId::new(), boot_id, NOW, NOW + 90_000)
        .unwrap();

    let first_ack = connector
        .record_heartbeat(
            &fence,
            1,
            NOW + 1_000,
            ConnectorObservedState::Ready,
            1,
            5_000,
        )
        .expect("first heartbeat accepted");
    assert_eq!(
        connector
            .record_heartbeat(
                &fence,
                1,
                NOW + 2_000,
                ConnectorObservedState::Ready,
                1,
                5_000,
            )
            .expect("identical heartbeat replay returns its cached ACK"),
        first_ack
    );
    assert_eq!(
        connector.record_heartbeat(
            &fence,
            1,
            NOW + 2_000,
            ConnectorObservedState::Degraded,
            1,
            5_000,
        ),
        Err(ConnectorError::HeartbeatConflict)
    );
    assert_eq!(
        connector.record_heartbeat(
            &fence,
            2,
            NOW + 2_000,
            ConnectorObservedState::Ready,
            1,
            5_000,
        ),
        Err(ConnectorError::HeartbeatTooFrequent),
    );
    assert_eq!(connector.validate_fence(&fence, NOW + 90_000), Ok(()));
    assert_eq!(
        connector.validate_fence(&fence, first_ack.lease_expires_at_millis()),
        Err(ConnectorError::LeaseExpired)
    );
    assert_eq!(
        connector.effective_observed_state(first_ack.lease_expires_at_millis()),
        ConnectorObservedState::Offline
    );
}

#[test]
fn replacement_lease_on_same_boot_starts_a_fresh_heartbeat_stream() {
    let mut connector = connector();
    let boot_id = BootId::new();
    connector.begin_boot(boot_id, NOW).unwrap();
    let first_fence = connector
        .issue_lease(LeaseId::new(), boot_id, NOW, NOW + 15_000)
        .unwrap();
    connector
        .record_heartbeat(
            &first_fence,
            7,
            NOW + 1,
            ConnectorObservedState::Ready,
            1,
            1,
        )
        .unwrap();

    let second_fence = connector
        .issue_lease(LeaseId::new(), boot_id, NOW + 2, NOW + 15_002)
        .unwrap();
    assert_eq!(
        connector.effective_observed_state(NOW + 2),
        ConnectorObservedState::Starting,
        "a new lease must not inherit the prior lease's readiness"
    );
    connector
        .record_heartbeat(
            &second_fence,
            1,
            NOW + 3,
            ConnectorObservedState::Ready,
            1,
            1,
        )
        .expect("heartbeat sequence is scoped to the replacement lease");
}

#[test]
fn lease_issue_time_never_predates_the_boot_or_latest_heartbeat() {
    let mut connector = connector();
    let boot_id = BootId::new();
    connector.begin_boot(boot_id, NOW).unwrap();
    let before_first = connector.clone();
    assert_eq!(
        connector.issue_lease(LeaseId::new(), boot_id, NOW - 1, NOW + 15_000),
        Err(ConnectorError::LeaseTimeRegressed)
    );
    assert_eq!(connector, before_first);

    let first_lease_id = LeaseId::new();
    let first = connector
        .issue_lease(first_lease_id, boot_id, NOW, NOW + 15_000)
        .unwrap();
    connector
        .record_heartbeat(&first, 1, NOW + 100, ConnectorObservedState::Ready, 1, 1)
        .unwrap();
    assert_eq!(
        connector
            .issue_lease(first_lease_id, boot_id, NOW, NOW + 15_000)
            .unwrap(),
        first,
        "exact lease replay remains idempotent after later heartbeats"
    );
    let before_regression = connector.clone();
    assert_eq!(
        connector.issue_lease(LeaseId::new(), boot_id, NOW + 99, NOW + 15_099),
        Err(ConnectorError::LeaseTimeRegressed)
    );
    assert_eq!(connector, before_regression);
}

#[test]
fn lease_ttl_is_bounded_by_the_shared_persistence_contract() {
    let mut connector = connector();
    let boot_id = BootId::new();
    connector.begin_boot(boot_id, NOW).unwrap();
    let before = connector.clone();
    assert_eq!(
        connector.issue_lease(LeaseId::new(), boot_id, NOW, NOW + MAX_LEASE_TTL_MILLIS + 1,),
        Err(ConnectorError::InvalidLeaseWindow)
    );
    assert_eq!(connector, before);
}

#[test]
fn a_fence_from_another_connector_is_rejected() {
    let current = connector();
    let mut other = registered_connector(
        current.tenant_id(),
        ConnectorId::new(),
        AdapterKind::Codex,
        2,
    );
    let boot_id = BootId::new();
    other.begin_boot(boot_id, NOW).unwrap();
    let foreign = other
        .issue_lease(LeaseId::new(), boot_id, NOW, NOW + 90_000)
        .unwrap();

    assert_eq!(
        current.validate_fence(&foreign, NOW),
        Err(ConnectorError::WrongConnector)
    );
}

#[test]
fn connector_boot_history_is_append_only_and_boot_ids_cannot_be_reused() {
    let mut connector = connector();
    let first = BootId::new();
    connector.begin_boot(first, NOW).unwrap();
    connector
        .begin_boot(first, NOW)
        .expect("an exact current-boot replay is idempotent");
    assert_eq!(
        connector.begin_boot(first, NOW + 1),
        Err(ConnectorError::BootConflict)
    );

    let second = BootId::new();
    connector.begin_boot(second, NOW + 2).unwrap();
    assert_eq!(connector.boots().len(), 2);
    assert_eq!(connector.boots()[0].boot_id(), first);
    assert_eq!(connector.boots()[0].ended_at_millis(), Some(NOW + 2));
    assert_eq!(connector.boots()[1].boot_id(), second);
    assert_eq!(connector.boots()[1].ended_at_millis(), None);
    assert_eq!(
        connector.begin_boot(first, NOW + 3),
        Err(ConnectorError::BootConflict)
    );
}

#[test]
fn beginning_a_boot_never_rewrites_an_already_closed_boot_boundary() {
    let mut connector = connector();
    let first = BootId::new();
    connector.begin_boot(first, NOW).unwrap();
    connector
        .advance_generation(connector.spec_revision(), NOW + 10)
        .unwrap();

    let before = connector.clone();
    assert_eq!(
        connector.begin_boot(BootId::new(), NOW + 9),
        Err(ConnectorError::BootTimeRegressed)
    );
    assert_eq!(connector, before);

    connector.begin_boot(BootId::new(), NOW + 20).unwrap();
    assert_eq!(connector.boots()[0].ended_at_millis(), Some(NOW + 10));
}

#[test]
fn connector_server_time_high_water_never_resets_across_lifecycle_boundaries() {
    let mut connector = connector();
    let first_boot = BootId::new();
    connector.begin_boot(first_boot, NOW).unwrap();
    let first_lease = connector
        .issue_lease(LeaseId::new(), first_boot, NOW, NOW + 15_000)
        .unwrap();
    connector
        .record_heartbeat(
            &first_lease,
            1,
            NOW + 50,
            ConnectorObservedState::Ready,
            1,
            1,
        )
        .unwrap();

    let before_boot = connector.clone();
    assert_eq!(
        connector.begin_boot(BootId::new(), NOW + 49),
        Err(ConnectorError::ServerTimeRegressed)
    );
    assert_eq!(connector, before_boot);
    assert_eq!(
        connector.advance_generation(connector.spec_revision(), NOW + 49),
        Err(ConnectorError::ServerTimeRegressed)
    );
    assert_eq!(connector, before_boot);
    assert_eq!(
        connector.set_desired_state(
            connector.spec_revision(),
            dtx_connect_registry::ConnectorDesiredState::Stopped,
            NOW + 49,
        ),
        Err(ConnectorError::ServerTimeRegressed)
    );
    assert_eq!(connector, before_boot);

    connector.begin_boot(BootId::new(), NOW + 50).unwrap();
    assert_eq!(connector.boots()[0].ended_at_millis(), Some(NOW + 50));
}

#[test]
fn heartbeat_sequence_stays_exact_for_web_and_wire_consumers() {
    let mut connector = connector();
    let boot_id = BootId::new();
    connector.begin_boot(boot_id, NOW).unwrap();
    let fence = connector
        .issue_lease(LeaseId::new(), boot_id, NOW, NOW + 90_000)
        .unwrap();

    let before = connector.clone();
    assert_eq!(
        connector.record_heartbeat(&fence, 1, NOW - 1, ConnectorObservedState::Ready, 1, 1,),
        Err(ConnectorError::InvalidHeartbeatTime)
    );
    assert_eq!(connector, before);

    assert_eq!(
        connector.record_heartbeat(
            &fence,
            Revision::MAX + 1,
            NOW + 1,
            ConnectorObservedState::Ready,
            1,
            1,
        ),
        Err(ConnectorError::InvalidHeartbeatSequence)
    );
}

#[test]
fn lease_history_preserves_supersede_expire_and_revoke_terminal_facts() {
    let mut connector = connector();
    let first_boot = BootId::new();
    connector.begin_boot(first_boot, NOW).unwrap();
    let first = connector
        .issue_lease(LeaseId::new(), first_boot, NOW, NOW + 15_000)
        .unwrap();
    let second_boot = BootId::new();
    connector.begin_boot(second_boot, NOW + 1).unwrap();
    let second = connector
        .issue_lease(LeaseId::new(), second_boot, NOW + 1, NOW + 15_001)
        .unwrap();

    assert_eq!(connector.leases().len(), 2);
    assert_eq!(connector.leases()[0].fence(), first);
    assert_eq!(connector.leases()[0].status(), LeaseStatus::Superseded);
    assert_eq!(connector.leases()[1].fence(), second);
    assert_eq!(connector.leases()[1].status(), LeaseStatus::Active);
    assert_eq!(
        connector.expire_lease(&second, NOW + 15_000, NOW + 15_001),
        Err(ConnectorError::LeaseConflict)
    );
    assert_eq!(
        connector.expire_lease(&second, NOW + 15_001, NOW + 15_000),
        Err(ConnectorError::LeaseNotExpired)
    );
    connector
        .expire_lease(&second, NOW + 15_001, NOW + 15_001)
        .unwrap();
    assert_eq!(connector.leases()[1].status(), LeaseStatus::Expired);

    let third = connector
        .issue_lease(LeaseId::new(), second_boot, NOW + 15_001, NOW + 30_001)
        .unwrap();
    connector.revoke_lease(&third).unwrap();
    assert_eq!(connector.leases()[2].status(), LeaseStatus::Revoked);
    assert_eq!(
        connector.revoke_lease(&third),
        Err(ConnectorError::LeaseRevoked)
    );
}
