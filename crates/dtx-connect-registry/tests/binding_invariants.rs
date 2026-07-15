mod support;

use std::str::FromStr;

use dtx_agent_registry::{
    AgentDevice, AgentDeviceCommand, AgentInstallation, DescriptorDigest,
    DeviceCredentialFingerprint, ExecutionMode,
};
use dtx_connect_registry::{
    AdapterConformance, AdapterKind, BindingError, BindingSet, BindingSpec, BindingState,
    RoutingPolicy, TenantRef,
};
use dtx_domain::{
    AgentDeviceId, AgentId, BindingId, ConnectorId, IdentityId, InstallationId, Revision, TenantId,
};
use proptest::prelude::*;
use support::registered_connector;

const AGENT_ID: &str = "dtxa17sv7zwzpr7aduy467sdm3pkmxe6if34eoarhaxdnau44fjwfseda";
const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

fn scoped<T>(tenant_id: TenantId, id: T) -> TenantRef<T> {
    TenantRef::new(tenant_id, id)
}

fn single_session() -> AdapterConformance {
    AdapterConformance::trusted_single_session(AdapterKind::Codex, Revision::INITIAL)
}

fn multi_session() -> AdapterConformance {
    AdapterConformance::trusted_multi_session(AdapterKind::Codex, Revision::INITIAL)
}

fn register_connector(
    set: &mut BindingSet,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    conformance: AdapterConformance,
) {
    let connector = registered_connector(tenant_id, connector_id, conformance.adapter_kind(), 4);
    set.register_connector_conformance(&connector, conformance)
        .expect("trusted connector conformance is registered");
}

fn build_spec(
    binding_tenant_id: TenantId,
    entity_tenant_id: TenantId,
    installation_id: InstallationId,
    connector_tenant_id: TenantId,
    connector_id: ConnectorId,
    agent_device_id: AgentDeviceId,
    priority: u16,
) -> Result<BindingSpec, BindingError> {
    let (installation, device) =
        active_entities(entity_tenant_id, installation_id, agent_device_id);
    let connector = registered_connector(connector_tenant_id, connector_id, AdapterKind::Codex, 4);
    BindingSpec::for_entities(
        scoped(binding_tenant_id, BindingId::new()),
        &installation,
        &device,
        &connector,
        priority,
        1,
    )
}

fn active_entities(
    tenant_id: TenantId,
    installation_id: InstallationId,
    agent_device_id: AgentDeviceId,
) -> (AgentInstallation, AgentDevice) {
    let installation = AgentInstallation::new(
        tenant_id,
        installation_id,
        AgentId::from_str(AGENT_ID).unwrap(),
        IdentityId::from_str(OWNER_ID).unwrap(),
        ExecutionMode::ConnectorManaged,
        Revision::INITIAL,
        DescriptorDigest::from_bytes([1; 32]),
    );
    let mut device = AgentDevice::enroll(
        &installation,
        agent_device_id,
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

fn enable_binding(
    set: &mut BindingSet,
    binding_ref: TenantRef<BindingId>,
    expected_revision: Revision,
) -> Result<Revision, BindingError> {
    let binding = *set.binding(binding_ref)?;
    let (installation, device) = active_entities(
        binding_ref.tenant_id(),
        binding.installation_id(),
        binding.agent_device_id(),
    );
    set.enable(binding_ref, expected_revision, &installation, &device)
}

fn spec(
    tenant_id: TenantId,
    installation_id: InstallationId,
    connector_id: ConnectorId,
    agent_device_id: AgentDeviceId,
    priority: u16,
) -> BindingSpec {
    build_spec(
        tenant_id,
        tenant_id,
        installation_id,
        tenant_id,
        connector_id,
        agent_device_id,
        priority,
    )
    .unwrap()
}

#[test]
fn every_reference_is_tenant_scoped_and_rejection_is_atomic() {
    let tenant_id = TenantId::new();
    let foreign_tenant = TenantId::new();
    let connector_id = ConnectorId::new();
    let mut set = BindingSet::new(tenant_id);
    register_connector(&mut set, tenant_id, connector_id, single_session());

    let before = set.clone();

    assert_eq!(
        build_spec(
            tenant_id,
            foreign_tenant,
            InstallationId::new(),
            tenant_id,
            connector_id,
            AgentDeviceId::new(),
            0,
        ),
        Err(BindingError::WrongTenant)
    );
    assert_eq!(set, before);
    let foreign_connector =
        registered_connector(foreign_tenant, ConnectorId::new(), AdapterKind::Codex, 4);
    assert_eq!(
        set.register_connector_conformance(&foreign_connector, single_session()),
        Err(BindingError::WrongTenant)
    );
    assert_eq!(set, before);
}

#[test]
fn entity_relationship_adapter_and_binding_capacity_are_verified() {
    let tenant_id = TenantId::new();
    let installation_id = InstallationId::new();
    let other_installation_id = InstallationId::new();
    let installation = AgentInstallation::new(
        tenant_id,
        installation_id,
        AgentId::from_str(AGENT_ID).unwrap(),
        IdentityId::from_str(OWNER_ID).unwrap(),
        ExecutionMode::ConnectorManaged,
        Revision::INITIAL,
        DescriptorDigest::from_bytes([1; 32]),
    );
    let other_installation = AgentInstallation::new(
        tenant_id,
        other_installation_id,
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
        DeviceCredentialFingerprint::from_bytes([3; 32]),
    )
    .unwrap();
    let connector = registered_connector(tenant_id, ConnectorId::new(), AdapterKind::Codex, 4);
    assert_eq!(
        BindingSpec::for_entities(
            scoped(tenant_id, BindingId::new()),
            &other_installation,
            &device,
            &connector,
            0,
            1,
        ),
        Err(BindingError::AgentDeviceScopeMismatch)
    );
    assert_eq!(
        BindingSpec::for_entities(
            scoped(tenant_id, BindingId::new()),
            &installation,
            &device,
            &connector,
            0,
            1,
        ),
        Err(BindingError::AgentDeviceNotActive)
    );
    device
        .apply(
            &installation,
            Revision::INITIAL,
            AgentDeviceCommand::Activate,
        )
        .unwrap();
    for invalid_capacity in [0, 5] {
        assert_eq!(
            BindingSpec::for_entities(
                scoped(tenant_id, BindingId::new()),
                &installation,
                &device,
                &connector,
                0,
                invalid_capacity,
            ),
            Err(BindingError::InvalidBindingCapacity)
        );
    }

    let mut set = BindingSet::new(tenant_id);
    assert_eq!(
        set.register_connector_conformance(
            &connector,
            AdapterConformance::trusted_single_session(AdapterKind::Eino, Revision::INITIAL),
        ),
        Err(BindingError::ConformanceAdapterMismatch)
    );
}

#[test]
fn revoked_device_or_installation_cannot_enable_or_route_a_binding() {
    let tenant_id = TenantId::new();
    let installation_id = InstallationId::new();
    let device_id = AgentDeviceId::new();
    let connector = registered_connector(tenant_id, ConnectorId::new(), AdapterKind::Codex, 4);
    let (mut installation, mut device) = active_entities(tenant_id, installation_id, device_id);
    let spec = BindingSpec::for_entities(
        scoped(tenant_id, BindingId::new()),
        &installation,
        &device,
        &connector,
        0,
        1,
    )
    .unwrap();
    let binding_ref = spec.binding_ref();
    let mut set = BindingSet::new(tenant_id);
    set.register_connector_conformance(&connector, single_session())
        .unwrap();
    set.create_binding(spec, RoutingPolicy::Exclusive).unwrap();

    let mut revoked_before_enable = device.clone();
    revoked_before_enable
        .apply(
            &installation,
            revoked_before_enable.revision(),
            AgentDeviceCommand::Revoke,
        )
        .unwrap();
    let before = set.clone();
    assert_eq!(
        set.enable(
            binding_ref,
            Revision::INITIAL,
            &installation,
            &revoked_before_enable,
        ),
        Err(BindingError::AgentDeviceNotActive)
    );
    assert_eq!(set, before);

    set.enable(binding_ref, Revision::INITIAL, &installation, &device)
        .unwrap();
    device
        .apply(&installation, device.revision(), AgentDeviceCommand::Revoke)
        .unwrap();
    assert_eq!(
        set.eligible_route_order(&installation, &[&device]),
        Err(BindingError::AgentDeviceNotActive)
    );

    installation
        .apply(
            installation.revision(),
            dtx_agent_registry::InstallationCommand::Disable,
        )
        .unwrap();
    assert_eq!(
        set.eligible_route_order(&installation, &[&device]),
        Err(BindingError::InstallationNotActive)
    );
}

#[test]
fn binding_transitions_use_revision_cas_and_revocation_is_terminal() {
    let tenant_id = TenantId::new();
    let connector_id = ConnectorId::new();
    let mut set = BindingSet::new(tenant_id);
    register_connector(&mut set, tenant_id, connector_id, single_session());
    let binding = spec(
        tenant_id,
        InstallationId::new(),
        connector_id,
        AgentDeviceId::new(),
        0,
    );
    let binding_ref = binding.binding_ref();

    assert_eq!(
        set.create_binding(binding, RoutingPolicy::Exclusive),
        Ok(Revision::INITIAL)
    );
    assert_eq!(
        set.binding(binding_ref).unwrap().state(),
        BindingState::Disabled
    );

    let before_stale = set.clone();
    assert_eq!(
        enable_binding(&mut set, binding_ref, Revision::new(2).unwrap()),
        Err(BindingError::RevisionConflict {
            current: Revision::INITIAL,
        })
    );
    assert_eq!(set, before_stale);

    let enabled = enable_binding(&mut set, binding_ref, Revision::INITIAL).unwrap();
    assert_eq!(enabled, Revision::new(2).unwrap());
    assert_eq!(
        set.binding(binding_ref).unwrap().state(),
        BindingState::Enabled
    );
    let disabled = set.disable(binding_ref, enabled).unwrap();
    assert_eq!(disabled, Revision::new(3).unwrap());
    assert_eq!(
        set.binding(binding_ref).unwrap().state(),
        BindingState::Disabled
    );
    let revoked = set.revoke(binding_ref, disabled).unwrap();
    assert_eq!(revoked, Revision::new(4).unwrap());
    assert_eq!(
        set.binding(binding_ref).unwrap().state(),
        BindingState::Revoked
    );

    let before_reenable = set.clone();
    assert_eq!(
        enable_binding(&mut set, binding_ref, revoked),
        Err(BindingError::InvalidTransition)
    );
    assert_eq!(set, before_reenable);
}

#[test]
fn exclusive_policy_requires_priority_zero_and_at_most_one_enabled_binding() {
    let tenant_id = TenantId::new();
    let installation_id = InstallationId::new();
    let first_connector = ConnectorId::new();
    let second_connector = ConnectorId::new();
    let mut set = BindingSet::new(tenant_id);
    register_connector(&mut set, tenant_id, first_connector, single_session());
    register_connector(&mut set, tenant_id, second_connector, single_session());

    let invalid = spec(
        tenant_id,
        installation_id,
        first_connector,
        AgentDeviceId::new(),
        1,
    );
    let before_invalid = set.clone();
    assert_eq!(
        set.create_binding(invalid, RoutingPolicy::Exclusive),
        Err(BindingError::ExclusivePriorityMustBeZero)
    );
    assert_eq!(set, before_invalid);

    let first = spec(
        tenant_id,
        installation_id,
        first_connector,
        AgentDeviceId::new(),
        0,
    );
    let first_ref = first.binding_ref();
    set.create_binding(first, RoutingPolicy::Exclusive).unwrap();
    enable_binding(&mut set, first_ref, Revision::INITIAL).unwrap();

    let second = spec(
        tenant_id,
        installation_id,
        second_connector,
        AgentDeviceId::new(),
        0,
    );
    let second_ref = second.binding_ref();
    set.create_binding(second, RoutingPolicy::Exclusive)
        .unwrap();
    let before_second_enable = set.clone();
    assert_eq!(
        enable_binding(&mut set, second_ref, Revision::INITIAL),
        Err(BindingError::ExclusiveAlreadyEnabled)
    );
    assert_eq!(set, before_second_enable);
    assert_eq!(
        set.configured_route_order(scoped(tenant_id, installation_id))
            .unwrap(),
        vec![first_ref.id()]
    );
}

#[test]
fn routing_policy_is_installation_set_scoped_and_changes_atomically() {
    let tenant_id = TenantId::new();
    let installation_id = InstallationId::new();
    let first_connector = ConnectorId::new();
    let second_connector = ConnectorId::new();
    let mut set = BindingSet::new(tenant_id);
    register_connector(&mut set, tenant_id, first_connector, single_session());
    register_connector(&mut set, tenant_id, second_connector, single_session());

    let first = spec(
        tenant_id,
        installation_id,
        first_connector,
        AgentDeviceId::new(),
        0,
    );
    set.create_binding(first, RoutingPolicy::Exclusive).unwrap();
    let conflicting = spec(
        tenant_id,
        installation_id,
        second_connector,
        AgentDeviceId::new(),
        0,
    );
    let before_conflict = set.clone();
    assert_eq!(
        set.create_binding(conflicting, RoutingPolicy::OrderedFailover),
        Err(BindingError::RoutingPolicyConflict)
    );
    assert_eq!(set, before_conflict);

    let policy_revision = set
        .set_routing_policy(
            scoped(tenant_id, installation_id),
            Revision::INITIAL,
            RoutingPolicy::OrderedFailover,
        )
        .unwrap();
    assert_eq!(policy_revision, Revision::new(2).unwrap());
    let policy = set
        .routing_policy(scoped(tenant_id, installation_id))
        .unwrap();
    assert_eq!(policy.policy(), RoutingPolicy::OrderedFailover);
    assert_eq!(policy.revision(), policy_revision);
}

#[test]
fn policy_and_priorities_can_be_reconfigured_in_one_atomic_cas() {
    let tenant_id = TenantId::new();
    let installation_id = InstallationId::new();
    let mut set = BindingSet::new(tenant_id);
    let mut refs = Vec::new();
    for _ in 0..2 {
        let connector_id = ConnectorId::new();
        register_connector(&mut set, tenant_id, connector_id, single_session());
        let binding = spec(
            tenant_id,
            installation_id,
            connector_id,
            AgentDeviceId::new(),
            0,
        );
        refs.push(binding.binding_ref());
        set.create_binding(binding, RoutingPolicy::Exclusive)
            .unwrap();
    }

    let next_policy = set
        .reconfigure_routing_policy(
            scoped(tenant_id, installation_id),
            Revision::INITIAL,
            RoutingPolicy::OrderedFailover,
            &[(refs[1], Revision::INITIAL, 1)],
        )
        .unwrap();
    assert_eq!(next_policy, Revision::new(2).unwrap());
    assert_eq!(set.binding(refs[0]).unwrap().priority(), 0);
    assert_eq!(set.binding(refs[1]).unwrap().priority(), 1);
    assert_eq!(
        set.binding(refs[1]).unwrap().revision(),
        Revision::new(2).unwrap()
    );
}

#[test]
fn revoked_binding_history_does_not_block_a_valid_exclusive_policy() {
    let tenant_id = TenantId::new();
    let installation_id = InstallationId::new();
    let mut set = BindingSet::new(tenant_id);
    let mut refs = Vec::new();
    for priority in [0, 1] {
        let connector_id = ConnectorId::new();
        register_connector(&mut set, tenant_id, connector_id, single_session());
        let binding = spec(
            tenant_id,
            installation_id,
            connector_id,
            AgentDeviceId::new(),
            priority,
        );
        refs.push(binding.binding_ref());
        set.create_binding(binding, RoutingPolicy::OrderedFailover)
            .unwrap();
    }
    enable_binding(&mut set, refs[0], Revision::INITIAL).unwrap();
    set.revoke(refs[1], Revision::INITIAL).unwrap();

    set.set_routing_policy(
        scoped(tenant_id, installation_id),
        Revision::INITIAL,
        RoutingPolicy::Exclusive,
    )
    .expect("revoked history does not constrain the active routing set");
}

#[test]
fn ordered_failover_has_unique_priorities_and_deterministic_order() {
    let tenant_id = TenantId::new();
    let installation_id = InstallationId::new();
    let mut set = BindingSet::new(tenant_id);
    let mut expected = Vec::new();
    for priority in [9_u16, 2, u16::MAX, 5] {
        let connector_id = ConnectorId::new();
        register_connector(&mut set, tenant_id, connector_id, single_session());
        let binding = spec(
            tenant_id,
            installation_id,
            connector_id,
            AgentDeviceId::new(),
            priority,
        );
        let binding_ref = binding.binding_ref();
        set.create_binding(binding, RoutingPolicy::OrderedFailover)
            .unwrap();
        enable_binding(&mut set, binding_ref, Revision::INITIAL).unwrap();
        expected.push((priority, binding_ref.id()));
    }
    expected.sort_unstable_by_key(|(priority, _)| *priority);

    assert_eq!(
        set.configured_route_order(scoped(tenant_id, installation_id))
            .unwrap(),
        expected.into_iter().map(|(_, id)| id).collect::<Vec<_>>()
    );

    let duplicate_connector = ConnectorId::new();
    register_connector(&mut set, tenant_id, duplicate_connector, single_session());
    let duplicate = spec(
        tenant_id,
        installation_id,
        duplicate_connector,
        AgentDeviceId::new(),
        5,
    );
    let before_duplicate = set.clone();
    assert_eq!(
        set.create_binding(duplicate, RoutingPolicy::OrderedFailover),
        Err(BindingError::PriorityConflict)
    );
    assert_eq!(set, before_duplicate);
}

#[test]
fn only_trusted_multi_session_conformance_allows_global_connector_reuse() {
    let tenant_id = TenantId::new();
    let single_connector = ConnectorId::new();
    let mut single = BindingSet::new(tenant_id);
    register_connector(&mut single, tenant_id, single_connector, single_session());

    let first = spec(
        tenant_id,
        InstallationId::new(),
        single_connector,
        AgentDeviceId::new(),
        0,
    );
    let first_ref = first.binding_ref();
    single
        .create_binding(first, RoutingPolicy::Exclusive)
        .unwrap();
    enable_binding(&mut single, first_ref, Revision::INITIAL).unwrap();
    let second = spec(
        tenant_id,
        InstallationId::new(),
        single_connector,
        AgentDeviceId::new(),
        0,
    );
    let second_ref = second.binding_ref();
    single
        .create_binding(second, RoutingPolicy::Exclusive)
        .unwrap();
    let before = single.clone();
    assert_eq!(
        enable_binding(&mut single, second_ref, Revision::INITIAL),
        Err(BindingError::ConnectorSingleSession)
    );
    assert_eq!(single, before);

    let multi_connector = ConnectorId::new();
    let mut multi = BindingSet::new(tenant_id);
    register_connector(&mut multi, tenant_id, multi_connector, multi_session());
    for _ in 0..3 {
        let binding = spec(
            tenant_id,
            InstallationId::new(),
            multi_connector,
            AgentDeviceId::new(),
            0,
        );
        let binding_ref = binding.binding_ref();
        multi
            .create_binding(binding, RoutingPolicy::Exclusive)
            .unwrap();
        enable_binding(&mut multi, binding_ref, Revision::INITIAL).unwrap();
    }
    assert_eq!(
        multi
            .enabled_count_for_connector(scoped(tenant_id, multi_connector))
            .unwrap(),
        3
    );
}

#[test]
fn device_and_installation_connector_identity_are_never_reused() {
    let tenant_id = TenantId::new();
    let installation_id = InstallationId::new();
    let connector_id = ConnectorId::new();
    let other_connector = ConnectorId::new();
    let device_id = AgentDeviceId::new();
    let mut set = BindingSet::new(tenant_id);
    register_connector(&mut set, tenant_id, connector_id, multi_session());
    register_connector(&mut set, tenant_id, other_connector, multi_session());

    let first = spec(tenant_id, installation_id, connector_id, device_id, 0);
    let first_ref = first.binding_ref();
    set.create_binding(first, RoutingPolicy::OrderedFailover)
        .unwrap();
    set.revoke(first_ref, Revision::INITIAL).unwrap();

    let reused_pair = spec(
        tenant_id,
        installation_id,
        connector_id,
        AgentDeviceId::new(),
        1,
    );
    let before_pair = set.clone();
    assert_eq!(
        set.create_binding(reused_pair, RoutingPolicy::OrderedFailover),
        Err(BindingError::DuplicateInstallationConnector)
    );
    assert_eq!(set, before_pair);

    let reused_device = spec(
        tenant_id,
        InstallationId::new(),
        other_connector,
        device_id,
        2,
    );
    let before_device = set.clone();
    assert_eq!(
        set.create_binding(reused_device, RoutingPolicy::OrderedFailover),
        Err(BindingError::AgentDeviceReused)
    );
    assert_eq!(set, before_device);
}

#[test]
fn failed_policy_and_priority_changes_leave_every_binding_unchanged() {
    let tenant_id = TenantId::new();
    let installation_id = InstallationId::new();
    let mut set = BindingSet::new(tenant_id);
    let mut refs = Vec::new();
    for priority in [0_u16, 1] {
        let connector_id = ConnectorId::new();
        register_connector(&mut set, tenant_id, connector_id, single_session());
        let binding = spec(
            tenant_id,
            installation_id,
            connector_id,
            AgentDeviceId::new(),
            priority,
        );
        refs.push(binding.binding_ref());
        set.create_binding(binding, RoutingPolicy::OrderedFailover)
            .unwrap();
    }
    for binding_ref in &refs {
        enable_binding(&mut set, *binding_ref, Revision::INITIAL).unwrap();
    }

    let before_policy = set.clone();
    assert_eq!(
        set.set_routing_policy(
            scoped(tenant_id, installation_id),
            Revision::INITIAL,
            RoutingPolicy::Exclusive,
        ),
        Err(BindingError::ExclusiveAlreadyEnabled)
    );
    assert_eq!(set, before_policy);

    let before_priority = set.clone();
    assert_eq!(
        set.set_priority(refs[1], Revision::new(2).unwrap(), 0),
        Err(BindingError::PriorityConflict)
    );
    assert_eq!(set, before_priority);
}

proptest! {
    #[test]
    fn entity_backed_specs_never_cross_a_generated_tenant_boundary(
        binding_is_current in any::<bool>(),
        installation_is_current in any::<bool>(),
        connector_is_current in any::<bool>(),
    ) {
        let current = TenantId::new();
        let binding_tenant = if binding_is_current { current } else { TenantId::new() };
        let installation_tenant = if installation_is_current { current } else { TenantId::new() };
        let connector_tenant = if connector_is_current { current } else { TenantId::new() };
        let result = build_spec(
            binding_tenant,
            installation_tenant,
            InstallationId::new(),
            connector_tenant,
            ConnectorId::new(),
            AgentDeviceId::new(),
            0,
        );

        prop_assert_eq!(
            result.is_ok(),
            binding_is_current && installation_is_current && connector_is_current
        );
    }

    #[test]
    fn ordered_failover_routes_every_unique_priority_in_ascending_order(
        priorities in prop::collection::btree_set(any::<u16>(), 1..32),
    ) {
        let tenant_id = TenantId::new();
        let installation_id = InstallationId::new();
        let mut set = BindingSet::new(tenant_id);
        let mut expected = Vec::with_capacity(priorities.len());
        for priority in &priorities {
            let connector_id = ConnectorId::new();
            register_connector(&mut set, tenant_id, connector_id, single_session());
            let binding = spec(
                tenant_id,
                installation_id,
                connector_id,
                AgentDeviceId::new(),
                *priority,
            );
            let binding_ref = binding.binding_ref();
            set.create_binding(binding, RoutingPolicy::OrderedFailover).unwrap();
            enable_binding(&mut set, binding_ref, Revision::INITIAL).unwrap();
            expected.push((*priority, binding_ref.id()));
        }
        expected.sort_unstable_by_key(|(priority, _)| *priority);

        prop_assert_eq!(
            set.configured_route_order(scoped(tenant_id, installation_id))
                .unwrap(),
            expected.into_iter().map(|(_, id)| id).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn a_single_session_connector_never_has_more_than_one_enabled_binding(
        installation_count in 1_usize..24,
        enable_order in prop::collection::vec(any::<usize>(), 1..64),
    ) {
        let tenant_id = TenantId::new();
        let connector_id = ConnectorId::new();
        let mut set = BindingSet::new(tenant_id);
        register_connector(&mut set, tenant_id, connector_id, single_session());
        let mut refs = Vec::with_capacity(installation_count);
        for _ in 0..installation_count {
            let binding = spec(
                tenant_id,
                InstallationId::new(),
                connector_id,
                AgentDeviceId::new(),
                0,
            );
            refs.push(binding.binding_ref());
            set.create_binding(binding, RoutingPolicy::Exclusive).unwrap();
        }

        for index in enable_order {
            let binding_ref = refs[index % refs.len()];
            let revision = set.binding(binding_ref).unwrap().revision();
            let _ = enable_binding(&mut set, binding_ref, revision);
            prop_assert!(
                set.enabled_count_for_connector(scoped(tenant_id, connector_id)).unwrap() <= 1,
            );
        }
    }
}
