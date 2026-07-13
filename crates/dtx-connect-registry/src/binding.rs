//! Tenant-scoped connector binding state machine.

use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    error::Error,
    fmt,
};

use dtx_agent_registry::{
    AgentDevice, AgentDeviceState, AgentInstallation, InstallationDesiredState,
};
use dtx_domain::{AgentDeviceId, BindingId, ConnectorId, InstallationId, Revision, TenantId};

use crate::{AdapterKind, Connector};

/// An identifier paired with the tenant authority under which it was resolved.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TenantRef<T> {
    tenant_id: TenantId,
    id: T,
}

impl<T> TenantRef<T> {
    /// Binds an identifier to its authenticated tenant boundary.
    #[must_use]
    pub const fn new(tenant_id: TenantId, id: T) -> Self {
        Self { tenant_id, id }
    }

    /// Returns the authenticated tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

impl<T: Copy> TenantRef<T> {
    /// Returns the tenant-scoped identifier.
    #[must_use]
    pub const fn id(&self) -> T {
        self.id
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionCardinality {
    Single,
    Multi,
}

/// Adapter capability admitted by the trusted conformance registry.
///
/// Connector heartbeats and runtime capability reports cannot construct this value through a
/// boolean conversion. The application boundary must choose one of the explicit trusted-registry
/// constructors after verifying the adapter conformance record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterConformance {
    adapter_kind: AdapterKind,
    registry_revision: Revision,
    cardinality: SessionCardinality,
}

impl AdapterConformance {
    /// Records a trusted conformance result for a single-session adapter.
    #[must_use]
    pub const fn trusted_single_session(
        adapter_kind: AdapterKind,
        registry_revision: Revision,
    ) -> Self {
        Self {
            adapter_kind,
            registry_revision,
            cardinality: SessionCardinality::Single,
        }
    }

    /// Records a trusted conformance result for a multi-session adapter.
    #[must_use]
    pub const fn trusted_multi_session(
        adapter_kind: AdapterKind,
        registry_revision: Revision,
    ) -> Self {
        Self {
            adapter_kind,
            registry_revision,
            cardinality: SessionCardinality::Multi,
        }
    }

    /// Returns the adapter schema covered by this conformance record.
    #[must_use]
    pub const fn adapter_kind(self) -> AdapterKind {
        self.adapter_kind
    }

    /// Returns the trusted registry revision that supplied this record.
    #[must_use]
    pub const fn registry_revision(self) -> Revision {
        self.registry_revision
    }

    /// Reports whether the trusted record permits concurrent installation sessions.
    #[must_use]
    pub const fn supports_multi_session(self) -> bool {
        matches!(self.cardinality, SessionCardinality::Multi)
    }
}

/// Lifecycle of one immutable installation-to-connector relationship.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BindingState {
    Disabled,
    Enabled,
    Revoked,
}

/// Routing policy shared by every binding in one installation's binding set.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RoutingPolicy {
    Exclusive,
    OrderedFailover,
}

/// Input for creating one disabled binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingSpec {
    binding_ref: TenantRef<BindingId>,
    installation_ref: TenantRef<InstallationId>,
    connector_ref: TenantRef<ConnectorId>,
    connector_adapter_kind: AdapterKind,
    agent_device_ref: TenantRef<AgentDeviceId>,
    priority: u16,
    max_concurrency: u32,
}

impl BindingSpec {
    /// Creates a binding specification from resolved domain entities.
    ///
    /// # Errors
    ///
    /// Rejects caller-supplied references that do not match the entities' real
    /// tenant/installation/device relationships or an inactive Agent Device.
    pub fn for_entities(
        binding_ref: TenantRef<BindingId>,
        installation: &AgentInstallation,
        agent_device: &AgentDevice,
        connector: &Connector,
        priority: u16,
        max_concurrency: u32,
    ) -> Result<Self, BindingError> {
        let tenant_id = installation.tenant_id();
        if binding_ref.tenant_id() != tenant_id || connector.tenant_id() != tenant_id {
            return Err(BindingError::WrongTenant);
        }
        if agent_device.tenant_id() != tenant_id
            || agent_device.installation_id() != installation.installation_id()
        {
            return Err(BindingError::AgentDeviceScopeMismatch);
        }
        if installation.desired_state() != InstallationDesiredState::Enabled
            || agent_device.state() != AgentDeviceState::Active
        {
            return Err(BindingError::AgentDeviceNotActive);
        }
        if max_concurrency == 0 || max_concurrency > connector.max_concurrency() {
            return Err(BindingError::InvalidBindingCapacity);
        }
        Ok(Self {
            binding_ref,
            installation_ref: TenantRef::new(tenant_id, installation.installation_id()),
            connector_ref: TenantRef::new(tenant_id, connector.connector_id()),
            connector_adapter_kind: connector.adapter_kind(),
            agent_device_ref: TenantRef::new(tenant_id, agent_device.agent_device_id()),
            priority,
            max_concurrency,
        })
    }

    /// Returns the binding identity.
    #[must_use]
    pub const fn binding_ref(self) -> TenantRef<BindingId> {
        self.binding_ref
    }
}

/// One durable connector binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Binding {
    id: BindingId,
    installation_id: InstallationId,
    connector_id: ConnectorId,
    agent_device_id: AgentDeviceId,
    priority: u16,
    max_concurrency: u32,
    state: BindingState,
    revision: Revision,
}

impl Binding {
    /// Returns the binding identity.
    #[must_use]
    pub const fn binding_id(&self) -> BindingId {
        self.id
    }

    /// Returns the installation owning this route.
    #[must_use]
    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }

    /// Returns the connector endpoint.
    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        self.connector_id
    }

    /// Returns the Agent Device dedicated to this binding.
    #[must_use]
    pub const fn agent_device_id(&self) -> AgentDeviceId {
        self.agent_device_id
    }

    /// Returns the failover priority.
    #[must_use]
    pub const fn priority(&self) -> u16 {
        self.priority
    }

    /// Returns the per-binding concurrency ceiling.
    #[must_use]
    pub const fn max_concurrency(&self) -> u32 {
        self.max_concurrency
    }

    /// Returns the lifecycle state.
    #[must_use]
    pub const fn state(&self) -> BindingState {
        self.state
    }

    /// Returns the optimistic concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
}

/// Versioned routing policy for one installation binding set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingPolicyRecord {
    policy: RoutingPolicy,
    revision: Revision,
}

impl RoutingPolicyRecord {
    /// Returns the set-wide routing policy.
    #[must_use]
    pub const fn policy(self) -> RoutingPolicy {
        self.policy
    }

    /// Returns the policy's optimistic concurrency revision.
    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }
}

/// Tenant-wide aggregate that can enforce connector-global binding invariants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingSet {
    tenant_id: TenantId,
    connector_conformance: BTreeMap<ConnectorId, ConnectorConformanceRecord>,
    routing_policies: BTreeMap<InstallationId, RoutingPolicyRecord>,
    bindings: BTreeMap<BindingId, Binding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConnectorConformanceRecord {
    conformance: AdapterConformance,
    max_concurrency: u32,
}

/// Durable non-secret trusted conformance record for one connector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorConformanceSnapshot {
    pub connector_id: ConnectorId,
    pub adapter_kind: AdapterKind,
    pub registry_revision: Revision,
    pub supports_multi_session: bool,
    pub max_concurrency: u32,
}

/// Durable non-secret routing policy record keyed by installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingPolicySnapshot {
    pub installation_id: InstallationId,
    pub policy: RoutingPolicy,
    pub revision: Revision,
}

/// Durable non-secret connector binding record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindingRecordSnapshot {
    pub binding_id: BindingId,
    pub installation_id: InstallationId,
    pub connector_id: ConnectorId,
    pub agent_device_id: AgentDeviceId,
    pub priority: u16,
    pub max_concurrency: u32,
    pub state: BindingState,
    pub revision: Revision,
}

/// Complete non-secret persistence image of one tenant-wide binding registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingSetSnapshot {
    pub tenant_id: TenantId,
    pub connector_conformance: Vec<ConnectorConformanceSnapshot>,
    pub routing_policies: Vec<RoutingPolicySnapshot>,
    pub bindings: Vec<BindingRecordSnapshot>,
}

impl BindingSet {
    /// Creates an empty tenant binding registry.
    #[must_use]
    pub const fn new(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            connector_conformance: BTreeMap::new(),
            routing_policies: BTreeMap::new(),
            bindings: BTreeMap::new(),
        }
    }

    /// Captures trusted connector facts, routing policies, and identity reservations.
    #[must_use]
    pub fn snapshot(&self) -> BindingSetSnapshot {
        BindingSetSnapshot {
            tenant_id: self.tenant_id,
            connector_conformance: self
                .connector_conformance
                .iter()
                .map(|(&connector_id, record)| ConnectorConformanceSnapshot {
                    connector_id,
                    adapter_kind: record.conformance.adapter_kind(),
                    registry_revision: record.conformance.registry_revision(),
                    supports_multi_session: record.conformance.supports_multi_session(),
                    max_concurrency: record.max_concurrency,
                })
                .collect(),
            routing_policies: self
                .routing_policies
                .iter()
                .map(|(&installation_id, record)| RoutingPolicySnapshot {
                    installation_id,
                    policy: record.policy,
                    revision: record.revision,
                })
                .collect(),
            bindings: self
                .bindings
                .values()
                .map(|binding| BindingRecordSnapshot {
                    binding_id: binding.id,
                    installation_id: binding.installation_id,
                    connector_id: binding.connector_id,
                    agent_device_id: binding.agent_device_id,
                    priority: binding.priority,
                    max_concurrency: binding.max_concurrency,
                    state: binding.state,
                    revision: binding.revision,
                })
                .collect(),
        }
    }

    /// Rehydrates a binding registry after validating all tenant-wide invariants.
    ///
    /// # Errors
    ///
    /// Rejects duplicate identities, missing conformance/policies, impossible
    /// lifecycle revisions, capacity violations, and routing/cardinality conflicts.
    #[allow(clippy::too_many_lines)] // Keeping the full validation transaction in one audit boundary is intentional.
    pub fn try_from_snapshot(
        snapshot: BindingSetSnapshot,
    ) -> Result<Self, BindingSetSnapshotError> {
        let mut connector_conformance = BTreeMap::new();
        for connector in snapshot.connector_conformance {
            if connector.max_concurrency == 0 {
                return Err(BindingSetSnapshotError::InvalidCapacity);
            }
            let conformance = if connector.supports_multi_session {
                AdapterConformance::trusted_multi_session(
                    connector.adapter_kind,
                    connector.registry_revision,
                )
            } else {
                AdapterConformance::trusted_single_session(
                    connector.adapter_kind,
                    connector.registry_revision,
                )
            };
            if connector_conformance
                .insert(
                    connector.connector_id,
                    ConnectorConformanceRecord {
                        conformance,
                        max_concurrency: connector.max_concurrency,
                    },
                )
                .is_some()
            {
                return Err(BindingSetSnapshotError::DuplicateConnector);
            }
        }

        let mut routing_policies = BTreeMap::new();
        for policy in snapshot.routing_policies {
            if routing_policies
                .insert(
                    policy.installation_id,
                    RoutingPolicyRecord {
                        policy: policy.policy,
                        revision: policy.revision,
                    },
                )
                .is_some()
            {
                return Err(BindingSetSnapshotError::DuplicateRoutingPolicy);
            }
        }

        let mut bindings = BTreeMap::new();
        let mut installation_connectors = BTreeSet::new();
        let mut agent_devices = BTreeSet::new();
        for record in snapshot.bindings {
            let connector = connector_conformance
                .get(&record.connector_id)
                .ok_or(BindingSetSnapshotError::MissingConnector)?;
            let policy = routing_policies
                .get(&record.installation_id)
                .ok_or(BindingSetSnapshotError::MissingRoutingPolicy)?;
            if record.max_concurrency == 0 || record.max_concurrency > connector.max_concurrency {
                return Err(BindingSetSnapshotError::InvalidCapacity);
            }
            if !installation_connectors.insert((record.installation_id, record.connector_id)) {
                return Err(BindingSetSnapshotError::DuplicateInstallationConnector);
            }
            if !agent_devices.insert(record.agent_device_id) {
                return Err(BindingSetSnapshotError::AgentDeviceReused);
            }
            let reachable = match record.state {
                BindingState::Disabled => true,
                BindingState::Enabled | BindingState::Revoked => record.revision.get() >= 2,
            };
            if !reachable {
                return Err(BindingSetSnapshotError::UnreachableBindingState);
            }
            if policy.policy == RoutingPolicy::Exclusive
                && record.state != BindingState::Revoked
                && record.priority != 0
            {
                return Err(BindingSetSnapshotError::RoutingPolicyViolation);
            }
            let binding = Binding {
                id: record.binding_id,
                installation_id: record.installation_id,
                connector_id: record.connector_id,
                agent_device_id: record.agent_device_id,
                priority: record.priority,
                max_concurrency: record.max_concurrency,
                state: record.state,
                revision: record.revision,
            };
            if bindings.insert(record.binding_id, binding).is_some() {
                return Err(BindingSetSnapshotError::DuplicateBinding);
            }
        }
        if routing_policies.keys().any(|installation_id| {
            !bindings
                .values()
                .any(|binding| binding.installation_id == *installation_id)
        }) {
            return Err(BindingSetSnapshotError::OrphanRoutingPolicy);
        }
        for (&installation_id, policy) in &routing_policies {
            let members = bindings
                .values()
                .filter(|binding| binding.installation_id == installation_id)
                .collect::<Vec<_>>();
            match policy.policy {
                RoutingPolicy::Exclusive => {
                    if members
                        .iter()
                        .filter(|binding| binding.state == BindingState::Enabled)
                        .count()
                        > 1
                    {
                        return Err(BindingSetSnapshotError::RoutingPolicyViolation);
                    }
                }
                RoutingPolicy::OrderedFailover => {
                    let mut priorities = BTreeSet::new();
                    if members
                        .iter()
                        .filter(|binding| binding.state != BindingState::Revoked)
                        .any(|binding| !priorities.insert(binding.priority))
                    {
                        return Err(BindingSetSnapshotError::RoutingPolicyViolation);
                    }
                }
            }
        }
        for (&connector_id, conformance) in &connector_conformance {
            if !conformance.conformance.supports_multi_session()
                && bindings
                    .values()
                    .filter(|binding| {
                        binding.connector_id == connector_id
                            && binding.state == BindingState::Enabled
                    })
                    .count()
                    > 1
            {
                return Err(BindingSetSnapshotError::ConnectorCardinalityViolation);
            }
        }
        Ok(Self {
            tenant_id: snapshot.tenant_id,
            connector_conformance,
            routing_policies,
            bindings,
        })
    }

    /// Registers immutable conformance admitted by the trusted adapter registry.
    ///
    /// # Errors
    ///
    /// Rejects a foreign tenant or a conflicting record for the same connector.
    pub fn register_connector_conformance(
        &mut self,
        connector: &Connector,
        conformance: AdapterConformance,
    ) -> Result<(), BindingError> {
        self.ensure_tenant(connector.tenant_id())?;
        if connector.adapter_kind() != conformance.adapter_kind() {
            return Err(BindingError::ConformanceAdapterMismatch);
        }
        let record = ConnectorConformanceRecord {
            conformance,
            max_concurrency: connector.max_concurrency(),
        };
        match self.connector_conformance.entry(connector.connector_id()) {
            Entry::Vacant(slot) => {
                slot.insert(record);
                Ok(())
            }
            Entry::Occupied(slot) if *slot.get() == record => Ok(()),
            Entry::Occupied(_) => Err(BindingError::ConformanceConflict),
        }
    }

    /// Creates an initially disabled binding under an installation-wide routing policy.
    ///
    /// # Errors
    ///
    /// Rejects tenant mismatches, identity reuse, unknown conformance, or inconsistent policies.
    pub fn create_binding(
        &mut self,
        spec: BindingSpec,
        policy: RoutingPolicy,
    ) -> Result<Revision, BindingError> {
        self.validate_spec_tenants(spec)?;
        let connector_record = self
            .connector_conformance
            .get(&spec.connector_ref.id())
            .ok_or(BindingError::MissingConnectorConformance)?;
        if spec.max_concurrency > connector_record.max_concurrency {
            return Err(BindingError::InvalidBindingCapacity);
        }
        if spec.connector_adapter_kind != connector_record.conformance.adapter_kind() {
            return Err(BindingError::ConformanceAdapterMismatch);
        }
        if self.bindings.contains_key(&spec.binding_ref.id()) {
            return Err(BindingError::BindingIdConflict);
        }
        if self.bindings.values().any(|binding| {
            binding.installation_id == spec.installation_ref.id()
                && binding.connector_id == spec.connector_ref.id()
        }) {
            return Err(BindingError::DuplicateInstallationConnector);
        }
        if self
            .bindings
            .values()
            .any(|binding| binding.agent_device_id == spec.agent_device_ref.id())
        {
            return Err(BindingError::AgentDeviceReused);
        }
        if let Some(existing) = self.routing_policies.get(&spec.installation_ref.id())
            && existing.policy != policy
        {
            return Err(BindingError::RoutingPolicyConflict);
        }
        Self::validate_priority_for_policy(policy, spec.priority)?;
        if policy == RoutingPolicy::OrderedFailover
            && self.bindings.values().any(|binding| {
                binding.installation_id == spec.installation_ref.id()
                    && binding.state != BindingState::Revoked
                    && binding.priority == spec.priority
            })
        {
            return Err(BindingError::PriorityConflict);
        }

        let binding = Binding {
            id: spec.binding_ref.id(),
            installation_id: spec.installation_ref.id(),
            connector_id: spec.connector_ref.id(),
            agent_device_id: spec.agent_device_ref.id(),
            priority: spec.priority,
            max_concurrency: spec.max_concurrency,
            state: BindingState::Disabled,
            revision: Revision::INITIAL,
        };
        self.routing_policies
            .entry(spec.installation_ref.id())
            .or_insert(RoutingPolicyRecord {
                policy,
                revision: Revision::INITIAL,
            });
        self.bindings.insert(spec.binding_ref.id(), binding);
        Ok(Revision::INITIAL)
    }

    /// Enables a binding after enforcing installation and connector-global cardinality.
    ///
    /// # Errors
    ///
    /// Rejects stale revisions, revoked bindings, duplicate priorities, or cardinality conflicts.
    pub fn enable(
        &mut self,
        binding_ref: TenantRef<BindingId>,
        expected_revision: Revision,
        installation: &AgentInstallation,
        agent_device: &AgentDevice,
    ) -> Result<Revision, BindingError> {
        let binding = self.binding_snapshot(binding_ref)?;
        Self::ensure_revision(binding.revision, expected_revision)?;
        self.ensure_tenant(installation.tenant_id())?;
        Self::validate_current_entities(binding, installation, agent_device)?;
        match binding.state {
            BindingState::Enabled => return Ok(binding.revision),
            BindingState::Revoked => return Err(BindingError::InvalidTransition),
            BindingState::Disabled => {}
        }
        let policy = self
            .routing_policies
            .get(&binding.installation_id)
            .ok_or(BindingError::RoutingPolicyNotFound)?
            .policy;
        Self::validate_priority_for_policy(policy, binding.priority)?;
        match policy {
            RoutingPolicy::Exclusive => {
                if self.bindings.values().any(|candidate| {
                    candidate.id != binding.id
                        && candidate.installation_id == binding.installation_id
                        && candidate.state == BindingState::Enabled
                }) {
                    return Err(BindingError::ExclusiveAlreadyEnabled);
                }
            }
            RoutingPolicy::OrderedFailover => {
                if self.bindings.values().any(|candidate| {
                    candidate.id != binding.id
                        && candidate.installation_id == binding.installation_id
                        && candidate.state == BindingState::Enabled
                        && candidate.priority == binding.priority
                }) {
                    return Err(BindingError::PriorityConflict);
                }
            }
        }
        let conformance = self
            .connector_conformance
            .get(&binding.connector_id)
            .ok_or(BindingError::MissingConnectorConformance)?;
        if !conformance.conformance.supports_multi_session()
            && self.bindings.values().any(|candidate| {
                candidate.id != binding.id
                    && candidate.connector_id == binding.connector_id
                    && candidate.state == BindingState::Enabled
            })
        {
            return Err(BindingError::ConnectorSingleSession);
        }

        let next = Self::next_revision(binding.revision)?;
        let target = self
            .bindings
            .get_mut(&binding.id)
            .ok_or(BindingError::BindingNotFound)?;
        target.state = BindingState::Enabled;
        target.revision = next;
        Ok(next)
    }

    /// Disables an enabled binding without releasing any immutable identity reservation.
    ///
    /// # Errors
    ///
    /// Rejects tenant mismatches, stale revisions, unknown bindings, or revoked bindings.
    pub fn disable(
        &mut self,
        binding_ref: TenantRef<BindingId>,
        expected_revision: Revision,
    ) -> Result<Revision, BindingError> {
        self.transition_state(binding_ref, expected_revision, BindingState::Disabled)
    }

    /// Permanently revokes a binding while retaining its connector/device uniqueness record.
    ///
    /// # Errors
    ///
    /// Rejects tenant mismatches, stale revisions, or unknown bindings.
    pub fn revoke(
        &mut self,
        binding_ref: TenantRef<BindingId>,
        expected_revision: Revision,
    ) -> Result<Revision, BindingError> {
        self.transition_state(binding_ref, expected_revision, BindingState::Revoked)
    }

    /// Changes one binding priority under its set-wide routing policy.
    ///
    /// # Errors
    ///
    /// Rejects stale revisions, revoked bindings, invalid exclusive priorities, or collisions.
    pub fn set_priority(
        &mut self,
        binding_ref: TenantRef<BindingId>,
        expected_revision: Revision,
        priority: u16,
    ) -> Result<Revision, BindingError> {
        let binding = self.binding_snapshot(binding_ref)?;
        Self::ensure_revision(binding.revision, expected_revision)?;
        if binding.state == BindingState::Revoked {
            return Err(BindingError::InvalidTransition);
        }
        let policy = self
            .routing_policies
            .get(&binding.installation_id)
            .ok_or(BindingError::RoutingPolicyNotFound)?
            .policy;
        Self::validate_priority_for_policy(policy, priority)?;
        if policy == RoutingPolicy::OrderedFailover
            && self.bindings.values().any(|candidate| {
                candidate.id != binding.id
                    && candidate.installation_id == binding.installation_id
                    && candidate.state != BindingState::Revoked
                    && candidate.priority == priority
            })
        {
            return Err(BindingError::PriorityConflict);
        }
        if binding.priority == priority {
            return Ok(binding.revision);
        }
        let next = Self::next_revision(binding.revision)?;
        let target = self
            .bindings
            .get_mut(&binding.id)
            .ok_or(BindingError::BindingNotFound)?;
        target.priority = priority;
        target.revision = next;
        Ok(next)
    }

    /// Atomically changes the policy governing every binding of an installation.
    ///
    /// # Errors
    ///
    /// Rejects tenant/revision mismatches or a binding set incompatible with the new policy.
    pub fn set_routing_policy(
        &mut self,
        installation_ref: TenantRef<InstallationId>,
        expected_revision: Revision,
        policy: RoutingPolicy,
    ) -> Result<Revision, BindingError> {
        self.reconfigure_routing_policy(installation_ref, expected_revision, policy, &[])
    }

    /// Atomically changes routing policy and the priority mapping required by it.
    ///
    /// Each priority update carries the binding's own expected revision. No
    /// policy or binding is mutated unless the complete target set is valid.
    ///
    /// # Errors
    ///
    /// Rejects tenant/scope/revision mismatches, duplicate updates, revoked
    /// bindings, counter exhaustion, or a target set that violates its policy.
    pub fn reconfigure_routing_policy(
        &mut self,
        installation_ref: TenantRef<InstallationId>,
        expected_revision: Revision,
        policy: RoutingPolicy,
        priority_updates: &[(TenantRef<BindingId>, Revision, u16)],
    ) -> Result<Revision, BindingError> {
        self.ensure_tenant(installation_ref.tenant_id())?;
        let current = *self
            .routing_policies
            .get(&installation_ref.id())
            .ok_or(BindingError::RoutingPolicyNotFound)?;
        Self::ensure_revision(current.revision, expected_revision)?;

        let mut updates = BTreeMap::new();
        for (binding_ref, expected_binding_revision, priority) in priority_updates {
            self.ensure_tenant(binding_ref.tenant_id())?;
            if updates
                .insert(binding_ref.id(), (*expected_binding_revision, *priority))
                .is_some()
            {
                return Err(BindingError::PriorityUpdateConflict);
            }
            let binding = self.binding_snapshot(*binding_ref)?;
            if binding.installation_id != installation_ref.id() {
                return Err(BindingError::BindingInstallationMismatch);
            }
            if binding.state == BindingState::Revoked {
                return Err(BindingError::InvalidTransition);
            }
            Self::ensure_revision(binding.revision, *expected_binding_revision)?;
        }

        let mut members = self
            .bindings
            .values()
            .filter(|binding| binding.installation_id == installation_ref.id())
            .copied()
            .collect::<Vec<_>>();
        for binding in &mut members {
            if let Some((_, priority)) = updates.get(&binding.id) {
                binding.priority = *priority;
            }
        }
        match policy {
            RoutingPolicy::Exclusive => {
                if members
                    .iter()
                    .filter(|binding| binding.state == BindingState::Enabled)
                    .count()
                    > 1
                {
                    return Err(BindingError::ExclusiveAlreadyEnabled);
                }
                if members
                    .iter()
                    .filter(|binding| binding.state != BindingState::Revoked)
                    .any(|binding| binding.priority != 0)
                {
                    return Err(BindingError::ExclusivePriorityMustBeZero);
                }
            }
            RoutingPolicy::OrderedFailover => {
                let mut priorities = BTreeSet::new();
                if members
                    .iter()
                    .filter(|binding| binding.state != BindingState::Revoked)
                    .any(|binding| !priorities.insert(binding.priority))
                {
                    return Err(BindingError::PriorityConflict);
                }
            }
        }

        let next_policy_revision = if current.policy == policy {
            current.revision
        } else {
            Self::next_revision(current.revision)?
        };
        let mut binding_changes = Vec::new();
        for (binding_id, (_, priority)) in &updates {
            let binding = self
                .bindings
                .get(binding_id)
                .ok_or(BindingError::BindingNotFound)?;
            if binding.priority != *priority {
                binding_changes.push((
                    *binding_id,
                    *priority,
                    Self::next_revision(binding.revision)?,
                ));
            }
        }

        for (binding_id, priority, revision) in binding_changes {
            let binding = self
                .bindings
                .get_mut(&binding_id)
                .ok_or(BindingError::BindingNotFound)?;
            binding.priority = priority;
            binding.revision = revision;
        }
        if current.policy != policy {
            let target = self
                .routing_policies
                .get_mut(&installation_ref.id())
                .ok_or(BindingError::RoutingPolicyNotFound)?;
            target.policy = policy;
            target.revision = next_policy_revision;
        }
        Ok(next_policy_revision)
    }

    /// Returns configured enabled binding IDs without runtime eligibility proof.
    ///
    /// Router code must use [`Self::eligible_route_order`]. This view exists for
    /// configuration management and deterministic policy inspection only.
    ///
    /// # Errors
    ///
    /// Rejects a foreign tenant or an installation without a binding policy.
    pub fn configured_route_order(
        &self,
        installation_ref: TenantRef<InstallationId>,
    ) -> Result<Vec<BindingId>, BindingError> {
        self.ensure_tenant(installation_ref.tenant_id())?;
        if !self.routing_policies.contains_key(&installation_ref.id()) {
            return Err(BindingError::RoutingPolicyNotFound);
        }
        let mut enabled = self
            .bindings
            .values()
            .filter(|binding| {
                binding.installation_id == installation_ref.id()
                    && binding.state == BindingState::Enabled
            })
            .collect::<Vec<_>>();
        enabled.sort_unstable_by_key(|binding| (binding.priority, binding.id));
        Ok(enabled.into_iter().map(|binding| binding.id).collect())
    }

    /// Returns only routes proven against the current Installation and Agent Devices.
    ///
    /// # Errors
    ///
    /// Rejects a disabled/revoked Installation, incomplete device resolution,
    /// stale device ownership, or a non-active Agent Device. On any such error
    /// no routing candidate is returned.
    pub fn eligible_route_order(
        &self,
        installation: &AgentInstallation,
        agent_devices: &[&AgentDevice],
    ) -> Result<Vec<BindingId>, BindingError> {
        self.ensure_tenant(installation.tenant_id())?;
        if installation.desired_state() != InstallationDesiredState::Enabled {
            return Err(BindingError::InstallationNotActive);
        }
        if !self
            .routing_policies
            .contains_key(&installation.installation_id())
        {
            return Err(BindingError::RoutingPolicyNotFound);
        }
        let mut enabled = self
            .bindings
            .values()
            .filter(|binding| {
                binding.installation_id == installation.installation_id()
                    && binding.state == BindingState::Enabled
            })
            .copied()
            .collect::<Vec<_>>();
        for binding in &enabled {
            let agent_device = agent_devices
                .iter()
                .copied()
                .find(|device| device.agent_device_id() == binding.agent_device_id)
                .ok_or(BindingError::AgentDeviceNotResolved)?;
            Self::validate_current_entities(*binding, installation, agent_device)?;
        }
        enabled.sort_unstable_by_key(|binding| (binding.priority, binding.id));
        Ok(enabled.into_iter().map(|binding| binding.id).collect())
    }

    /// Returns the number of globally enabled bindings using one connector.
    ///
    /// # Errors
    ///
    /// Rejects a foreign tenant or a connector without trusted conformance.
    pub fn enabled_count_for_connector(
        &self,
        connector_ref: TenantRef<ConnectorId>,
    ) -> Result<usize, BindingError> {
        self.ensure_tenant(connector_ref.tenant_id())?;
        if !self.connector_conformance.contains_key(&connector_ref.id()) {
            return Err(BindingError::MissingConnectorConformance);
        }
        Ok(self
            .bindings
            .values()
            .filter(|binding| {
                binding.connector_id == connector_ref.id() && binding.state == BindingState::Enabled
            })
            .count())
    }

    /// Looks up one binding through a tenant-scoped reference.
    ///
    /// # Errors
    ///
    /// Rejects a foreign tenant or an unknown binding.
    pub fn binding(&self, binding_ref: TenantRef<BindingId>) -> Result<&Binding, BindingError> {
        self.ensure_tenant(binding_ref.tenant_id())?;
        self.bindings
            .get(&binding_ref.id())
            .ok_or(BindingError::BindingNotFound)
    }

    /// Looks up one installation's set-wide routing policy.
    ///
    /// # Errors
    ///
    /// Rejects a foreign tenant or an installation without bindings.
    pub fn routing_policy(
        &self,
        installation_ref: TenantRef<InstallationId>,
    ) -> Result<RoutingPolicyRecord, BindingError> {
        self.ensure_tenant(installation_ref.tenant_id())?;
        self.routing_policies
            .get(&installation_ref.id())
            .copied()
            .ok_or(BindingError::RoutingPolicyNotFound)
    }

    /// Returns the aggregate tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    fn validate_spec_tenants(&self, spec: BindingSpec) -> Result<(), BindingError> {
        for tenant_id in [
            spec.binding_ref.tenant_id(),
            spec.installation_ref.tenant_id(),
            spec.connector_ref.tenant_id(),
            spec.agent_device_ref.tenant_id(),
        ] {
            self.ensure_tenant(tenant_id)?;
        }
        Ok(())
    }

    fn validate_current_entities(
        binding: Binding,
        installation: &AgentInstallation,
        agent_device: &AgentDevice,
    ) -> Result<(), BindingError> {
        if installation.tenant_id() != agent_device.tenant_id()
            || installation.installation_id() != binding.installation_id
            || agent_device.installation_id() != binding.installation_id
            || agent_device.agent_device_id() != binding.agent_device_id
        {
            return Err(BindingError::AgentDeviceScopeMismatch);
        }
        if installation.desired_state() != InstallationDesiredState::Enabled {
            return Err(BindingError::InstallationNotActive);
        }
        if agent_device.state() != AgentDeviceState::Active {
            return Err(BindingError::AgentDeviceNotActive);
        }
        Ok(())
    }

    fn ensure_tenant(&self, tenant_id: TenantId) -> Result<(), BindingError> {
        if self.tenant_id == tenant_id {
            Ok(())
        } else {
            Err(BindingError::WrongTenant)
        }
    }

    fn binding_snapshot(&self, binding_ref: TenantRef<BindingId>) -> Result<Binding, BindingError> {
        self.binding(binding_ref).copied()
    }

    fn ensure_revision(actual: Revision, expected: Revision) -> Result<(), BindingError> {
        if actual == expected {
            Ok(())
        } else {
            Err(BindingError::RevisionConflict { current: actual })
        }
    }

    fn next_revision(current: Revision) -> Result<Revision, BindingError> {
        current
            .checked_next()
            .map_err(|_| BindingError::CounterExhausted)
    }

    fn validate_priority_for_policy(
        policy: RoutingPolicy,
        priority: u16,
    ) -> Result<(), BindingError> {
        if policy == RoutingPolicy::Exclusive && priority != 0 {
            Err(BindingError::ExclusivePriorityMustBeZero)
        } else {
            Ok(())
        }
    }

    fn transition_state(
        &mut self,
        binding_ref: TenantRef<BindingId>,
        expected_revision: Revision,
        target_state: BindingState,
    ) -> Result<Revision, BindingError> {
        let binding = self.binding_snapshot(binding_ref)?;
        Self::ensure_revision(binding.revision, expected_revision)?;
        if binding.state == target_state {
            return Ok(binding.revision);
        }
        if binding.state == BindingState::Revoked {
            return Err(BindingError::InvalidTransition);
        }
        let next = Self::next_revision(binding.revision)?;
        let target = self
            .bindings
            .get_mut(&binding.id)
            .ok_or(BindingError::BindingNotFound)?;
        target.state = target_state;
        target.revision = next;
        Ok(next)
    }
}

/// Stable rejection from the connector binding state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    WrongTenant,
    MissingConnectorConformance,
    ConformanceConflict,
    ConformanceAdapterMismatch,
    BindingIdConflict,
    DuplicateInstallationConnector,
    AgentDeviceReused,
    AgentDeviceScopeMismatch,
    AgentDeviceNotActive,
    AgentDeviceNotResolved,
    InstallationNotActive,
    InvalidBindingCapacity,
    RoutingPolicyConflict,
    RoutingPolicyNotFound,
    ExclusivePriorityMustBeZero,
    ExclusiveAlreadyEnabled,
    PriorityConflict,
    PriorityUpdateConflict,
    BindingInstallationMismatch,
    ConnectorSingleSession,
    BindingNotFound,
    InvalidTransition,
    RevisionConflict { current: Revision },
    CounterExhausted,
}

impl fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongTenant => "binding reference belongs to another tenant",
            Self::MissingConnectorConformance => {
                "connector has no trusted adapter conformance record"
            }
            Self::ConformanceConflict => {
                "connector conformance conflicts with its trusted immutable record"
            }
            Self::ConformanceAdapterMismatch => {
                "connector conformance adapter does not match the connector"
            }
            Self::BindingIdConflict => "binding ID is already reserved",
            Self::DuplicateInstallationConnector => "installation and connector are already bound",
            Self::AgentDeviceReused => "Agent Device is already reserved by another binding",
            Self::AgentDeviceScopeMismatch => {
                "Agent Device does not belong to the binding installation"
            }
            Self::AgentDeviceNotActive => "Agent Device is not active for binding",
            Self::AgentDeviceNotResolved => "Agent Device was not resolved for routing",
            Self::InstallationNotActive => "Agent installation is not active for binding",
            Self::InvalidBindingCapacity => "binding concurrency limit is invalid",
            Self::RoutingPolicyConflict => {
                "binding routing policy differs from its installation binding set"
            }
            Self::RoutingPolicyNotFound => "installation has no binding routing policy",
            Self::ExclusivePriorityMustBeZero => "exclusive binding priority must be zero",
            Self::ExclusiveAlreadyEnabled => "exclusive routing already has an enabled binding",
            Self::PriorityConflict => {
                "ordered failover already has an enabled binding at this priority"
            }
            Self::PriorityUpdateConflict => "binding priority update is duplicated",
            Self::BindingInstallationMismatch => {
                "binding does not belong to the routing-policy installation"
            }
            Self::ConnectorSingleSession => {
                "connector conformance permits only one enabled binding"
            }
            Self::BindingNotFound => "binding does not exist in this tenant",
            Self::InvalidTransition => "binding state transition is not allowed",
            Self::RevisionConflict { .. } => "binding revision is stale",
            Self::CounterExhausted => "binding revision counter is exhausted",
        })
    }
}

impl Error for BindingError {}

/// Stable rejection for an invalid durable tenant binding-registry image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingSetSnapshotError {
    InvalidCapacity,
    DuplicateConnector,
    DuplicateRoutingPolicy,
    DuplicateBinding,
    MissingConnector,
    MissingRoutingPolicy,
    OrphanRoutingPolicy,
    DuplicateInstallationConnector,
    AgentDeviceReused,
    UnreachableBindingState,
    RoutingPolicyViolation,
    ConnectorCardinalityViolation,
}

impl fmt::Display for BindingSetSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCapacity => "binding-set snapshot capacity is invalid",
            Self::DuplicateConnector => "binding-set snapshot repeats a connector",
            Self::DuplicateRoutingPolicy => "binding-set snapshot repeats a routing policy",
            Self::DuplicateBinding => "binding-set snapshot repeats a binding ID",
            Self::MissingConnector => "binding-set snapshot omits connector conformance",
            Self::MissingRoutingPolicy => "binding-set snapshot omits a routing policy",
            Self::OrphanRoutingPolicy => "binding-set snapshot has an orphan routing policy",
            Self::DuplicateInstallationConnector => {
                "binding-set snapshot repeats an installation/connector pair"
            }
            Self::AgentDeviceReused => "binding-set snapshot reuses an Agent Device",
            Self::UnreachableBindingState => "binding-set snapshot binding state is unreachable",
            Self::RoutingPolicyViolation => "binding-set snapshot violates routing policy",
            Self::ConnectorCardinalityViolation => {
                "binding-set snapshot violates connector session cardinality"
            }
        })
    }
}

impl Error for BindingSetSnapshotError {}
