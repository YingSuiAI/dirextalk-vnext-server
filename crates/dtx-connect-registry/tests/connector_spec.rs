mod support;

use dtx_connect_registry::{
    AdapterKind, Connector, ConnectorDesiredState, ConnectorError, ConnectorObservedState,
};
use dtx_domain::{BootId, ConnectorId, LeaseId, Revision, TenantId};
use support::{active_host, awaiting_host, registered_connector};

const NOW: i64 = 1_800_000_000_000;

fn connector() -> Connector {
    registered_connector(
        TenantId::new(),
        ConnectorId::new(),
        AdapterKind::OpenClawAcp,
        4,
    )
}

#[test]
fn connector_registration_requires_an_active_host_entity() {
    let tenant_id = TenantId::new();
    let awaiting = awaiting_host(tenant_id);
    assert_eq!(
        Connector::register(&awaiting, ConnectorId::new(), AdapterKind::Codex, 1),
        Err(ConnectorError::HostNotActive)
    );

    let mut quarantined = active_host(tenant_id);
    quarantined.quarantine(quarantined.revision()).unwrap();
    assert_eq!(
        Connector::register(&quarantined, ConnectorId::new(), AdapterKind::Codex, 1,),
        Err(ConnectorError::HostNotActive)
    );
}

#[test]
fn desired_state_changes_use_spec_revision_cas_and_revocation_is_terminal() {
    let mut connector = connector();
    let initial = connector.spec_revision();
    assert_eq!(initial, Revision::INITIAL);
    assert_eq!(
        connector
            .set_desired_state(initial, ConnectorDesiredState::Draining, NOW)
            .unwrap(),
        Revision::new(2).unwrap()
    );
    let snapshot = connector.clone();
    assert_eq!(
        connector.set_desired_state(initial, ConnectorDesiredState::Stopped, NOW + 1),
        Err(ConnectorError::RevisionConflict)
    );
    assert_eq!(
        connector, snapshot,
        "failed CAS cannot mutate the aggregate"
    );

    let current = connector.spec_revision();
    connector
        .set_desired_state(current, ConnectorDesiredState::Revoked, NOW + 2)
        .unwrap();
    assert_eq!(connector.desired_state(), ConnectorDesiredState::Revoked);
    assert_eq!(
        connector.set_desired_state(
            connector.spec_revision(),
            ConnectorDesiredState::Running,
            NOW + 3,
        ),
        Err(ConnectorError::ConnectorRevoked)
    );
    assert_eq!(
        connector.begin_boot(BootId::new(), NOW),
        Err(ConnectorError::ConnectorRevoked)
    );
    assert_eq!(
        connector.effective_observed_state(NOW),
        ConnectorObservedState::Revoked
    );
}

#[test]
fn connector_spec_revisions_are_append_only_and_failed_cas_does_not_append() {
    let mut connector = connector();
    assert_eq!(connector.revisions().len(), 1);
    let initial = connector.revisions()[0];
    assert_eq!(initial.revision(), Revision::INITIAL);
    assert_eq!(initial.desired_state(), ConnectorDesiredState::Running);

    connector
        .set_desired_state(Revision::INITIAL, ConnectorDesiredState::Draining, NOW)
        .unwrap();
    assert_eq!(connector.revisions().len(), 2);
    assert_eq!(connector.revisions()[0], initial);
    assert_eq!(
        connector.revisions()[1].desired_state(),
        ConnectorDesiredState::Draining
    );

    let before_stale = connector.clone();
    assert_eq!(
        connector.set_desired_state(Revision::INITIAL, ConnectorDesiredState::Stopped, NOW + 1,),
        Err(ConnectorError::RevisionConflict)
    );
    assert_eq!(connector, before_stale);

    connector
        .advance_generation(connector.spec_revision(), NOW + 2)
        .unwrap();
    assert_eq!(connector.revisions().len(), 3);
    assert_eq!(
        connector.revisions()[2].generation(),
        connector.generation()
    );
}

#[test]
fn generation_advance_immediately_fences_the_old_boot_and_lease() {
    let mut connector = connector();
    let boot = BootId::new();
    connector.begin_boot(boot, NOW).unwrap();
    let old_fence = connector
        .issue_lease(LeaseId::new(), boot, NOW, NOW + 15_000)
        .unwrap();
    let old_generation = connector.generation();

    let new_generation = connector
        .advance_generation(connector.spec_revision(), NOW + 1)
        .expect("generation advances under the current spec revision");
    assert!(new_generation > old_generation);
    assert_eq!(
        connector.validate_fence(&old_fence, NOW + 1),
        Err(ConnectorError::StaleLease)
    );
    assert_eq!(
        connector.advance_generation(Revision::INITIAL, NOW + 2),
        Err(ConnectorError::RevisionConflict)
    );
}

#[test]
fn stopping_a_connector_fences_execution_until_a_new_boot_and_lease() {
    let mut connector = connector();
    let boot = BootId::new();
    connector.begin_boot(boot, NOW).unwrap();
    let fence = connector
        .issue_lease(LeaseId::new(), boot, NOW, NOW + 15_000)
        .unwrap();

    connector
        .set_desired_state(
            connector.spec_revision(),
            ConnectorDesiredState::Stopped,
            NOW + 1,
        )
        .unwrap();
    assert_eq!(
        connector.validate_fence(&fence, NOW + 1),
        Err(ConnectorError::StaleLease)
    );
    assert_eq!(
        connector.issue_lease(LeaseId::new(), boot, NOW + 1, NOW + 15_001),
        Err(ConnectorError::ConnectorNotRunning)
    );
}
