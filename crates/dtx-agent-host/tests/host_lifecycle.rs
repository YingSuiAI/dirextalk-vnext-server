use std::str::FromStr;

use dtx_agent_host::{AgentHost, EffectiveHostState, HostError, HostLifecycle, ReportedHealth};
use dtx_domain::{HostCredentialId, HostId, IdentityId, Revision, TenantId};

const NOW: i64 = 1_800_000_000_000;
const HEARTBEAT_TTL: i64 = 90_000;
const OWNER: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

fn owner() -> IdentityId {
    IdentityId::from_str(OWNER).expect("fixture owner ID is canonical")
}

fn host() -> AgentHost {
    AgentHost::register(TenantId::new(), HostId::new(), owner())
}

fn enrolled_host() -> (AgentHost, HostCredentialId) {
    let mut host = host();
    let credential = HostCredentialId::new();
    host.enroll(host.revision(), credential)
        .expect("first enrollment succeeds");
    (host, credential)
}

#[test]
fn enrollment_is_one_time_and_preserves_owner_boundary() {
    let tenant_id = TenantId::new();
    let host_id = HostId::new();
    let owner_id = owner();
    let mut host = AgentHost::register(tenant_id, host_id, owner_id);

    assert_eq!(host.tenant_id(), tenant_id);
    assert_eq!(host.host_id(), host_id);
    assert_eq!(host.owner_id(), owner_id);
    assert_eq!(host.lifecycle(), HostLifecycle::AwaitingEnrollment);
    assert_eq!(host.desired_revision(), Revision::INITIAL);
    assert_eq!(host.observed_revision(), None);
    assert_eq!(
        host.effective_state(NOW),
        EffectiveHostState::AwaitingEnrollment
    );

    let credential = HostCredentialId::new();
    host.enroll(host.revision(), credential).unwrap();
    assert_eq!(host.lifecycle(), HostLifecycle::Active);
    assert_eq!(host.credential_id(), Some(credential));
    assert_eq!(host.effective_state(NOW), EffectiveHostState::Offline);

    let before = host.clone();
    assert_eq!(
        host.enroll(host.revision(), HostCredentialId::new()),
        Err(HostError::AlreadyEnrolled)
    );
    assert_eq!(host, before);
}

#[test]
fn heartbeat_ack_is_monotonic_bounded_by_desired_and_expiry_is_server_derived() {
    let (mut host, credential) = enrolled_host();
    let initial_desired = host.desired_revision();
    let desired = host
        .advance_desired_revision(host.revision())
        .expect("server advances desired configuration");
    assert!(desired > initial_desired);
    assert_ne!(host.revision(), host.desired_revision());

    let expiry = host
        .record_heartbeat(
            host.revision(),
            credential,
            desired,
            ReportedHealth::Healthy,
            NOW,
            HEARTBEAT_TTL,
        )
        .expect("host acknowledges current desired revision");
    assert_eq!(expiry, NOW + HEARTBEAT_TTL);
    assert_eq!(host.observed_revision(), Some(desired));
    assert_eq!(host.effective_state(expiry - 1), EffectiveHostState::Online);
    assert_eq!(host.effective_state(expiry), EffectiveHostState::Offline);

    let before = host.clone();
    assert_eq!(
        host.record_heartbeat(
            host.revision(),
            credential,
            initial_desired,
            ReportedHealth::Healthy,
            NOW + 1,
            HEARTBEAT_TTL,
        ),
        Err(HostError::ObservedRevisionRegressed { current: desired })
    );
    assert_eq!(host, before);

    let future = desired.checked_next().unwrap();
    assert_eq!(
        host.record_heartbeat(
            host.revision(),
            credential,
            future,
            ReportedHealth::Healthy,
            NOW + 1,
            HEARTBEAT_TTL,
        ),
        Err(HostError::ObservedRevisionAhead { desired })
    );
}

#[test]
fn credential_rotation_invalidates_old_heartbeats_and_requires_fresh_liveness() {
    let (mut host, old_credential) = enrolled_host();
    host.record_heartbeat(
        host.revision(),
        old_credential,
        host.desired_revision(),
        ReportedHealth::Healthy,
        NOW,
        HEARTBEAT_TTL,
    )
    .unwrap();

    let new_credential = HostCredentialId::new();
    let returned_old = host
        .rotate_credential(host.revision(), new_credential)
        .expect("credential rotation succeeds");
    assert_eq!(returned_old, old_credential);
    assert_eq!(host.credential_id(), Some(new_credential));
    assert_eq!(host.effective_state(NOW + 1), EffectiveHostState::Offline);

    let before = host.clone();
    assert_eq!(
        host.record_heartbeat(
            host.revision(),
            old_credential,
            host.desired_revision(),
            ReportedHealth::Healthy,
            NOW + 1,
            HEARTBEAT_TTL,
        ),
        Err(HostError::CredentialMismatch)
    );
    assert_eq!(host, before);
}

#[test]
fn quarantine_precedes_health_and_revoke_is_terminal() {
    let (mut host, credential) = enrolled_host();
    host.record_heartbeat(
        host.revision(),
        credential,
        host.desired_revision(),
        ReportedHealth::Degraded,
        NOW,
        HEARTBEAT_TTL,
    )
    .unwrap();
    assert_eq!(host.effective_state(NOW + 1), EffectiveHostState::Degraded);

    host.quarantine(host.revision()).unwrap();
    assert_eq!(host.lifecycle(), HostLifecycle::Quarantined);
    assert_eq!(
        host.effective_state(NOW + 1),
        EffectiveHostState::Quarantined
    );
    host.record_heartbeat(
        host.revision(),
        credential,
        host.desired_revision(),
        ReportedHealth::Healthy,
        NOW + 2,
        HEARTBEAT_TTL,
    )
    .expect("quarantined host health may be observed without overriding quarantine");
    assert_eq!(
        host.effective_state(NOW + 3),
        EffectiveHostState::Quarantined
    );

    host.clear_quarantine(host.revision()).unwrap();
    assert_eq!(host.lifecycle(), HostLifecycle::Active);
    assert_eq!(host.effective_state(NOW + 1), EffectiveHostState::Offline);

    host.revoke(host.revision()).unwrap();
    assert_eq!(host.lifecycle(), HostLifecycle::Revoked);
    assert_eq!(host.credential_id(), None);
    assert_eq!(host.effective_state(NOW + 1), EffectiveHostState::Revoked);

    let before = host.clone();
    assert_eq!(
        host.advance_desired_revision(host.revision()),
        Err(HostError::HostRevoked)
    );
    assert_eq!(
        host.rotate_credential(host.revision(), HostCredentialId::new()),
        Err(HostError::HostRevoked)
    );
    assert_eq!(host, before);
}

#[test]
fn every_mutation_requires_the_exact_aggregate_revision() {
    let (mut host, _) = enrolled_host();
    let stale = Revision::INITIAL;
    let before = host.clone();

    assert_eq!(
        host.advance_desired_revision(stale),
        Err(HostError::RevisionConflict {
            current: host.revision(),
        })
    );
    assert_eq!(host, before);
}

#[test]
fn retired_host_credentials_can_never_be_resurrected() {
    let (mut host, first) = enrolled_host();
    let second = HostCredentialId::new();
    host.rotate_credential(host.revision(), second).unwrap();
    let before = host.clone();

    assert_eq!(
        host.rotate_credential(host.revision(), first),
        Err(HostError::CredentialReused)
    );
    assert_eq!(host, before);
}
