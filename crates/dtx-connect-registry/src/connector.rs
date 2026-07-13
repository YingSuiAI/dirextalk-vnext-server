use std::{error::Error, fmt};

use dtx_agent_host::{AgentHost, HostLifecycle};
use dtx_domain::{BootId, ConnectorId, HostId, LeaseId, Revision, TenantId};

/// Allowlisted runtime adapter schema selected for one connector process.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdapterKind {
    Codex,
    OpenClawAcp,
    Eino,
    Rig,
    ClaudeCode,
    CustomAcp,
}

/// Owner-controlled target state for one connector process.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConnectorDesiredState {
    Running,
    Draining,
    Stopped,
    Revoked,
}

/// Server-observed connector state. Offline is derived from the current lease.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConnectorObservedState {
    Enrolling,
    Starting,
    Ready,
    Busy,
    Degraded,
    Draining,
    Offline,
    Failed,
    Quarantined,
    Revoked,
}

/// Positive connector generation fenced across credential/spec replacement.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectorGeneration(u64);

impl ConnectorGeneration {
    pub const INITIAL: Self = Self(1);

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn checked_next(self) -> Result<Self, ConnectorError> {
        if self.0 == Revision::MAX {
            Err(ConnectorError::CounterExhausted)
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

/// Positive, monotonically increasing lease fencing epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LeaseEpoch(u64);

impl LeaseEpoch {
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn checked_next(current: Option<Self>) -> Result<Self, ConnectorError> {
        let next = current.map_or(1, |value| value.0.saturating_add(1));
        if next == 0 || next > Revision::MAX {
            Err(ConnectorError::CounterExhausted)
        } else {
            Ok(Self(next))
        }
    }
}

/// Complete fencing coordinates that every connector mutation must echo.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectorFence {
    tenant_id: TenantId,
    connector_id: ConnectorId,
    generation: ConnectorGeneration,
    boot_id: BootId,
    lease_id: LeaseId,
    lease_epoch: LeaseEpoch,
}

impl ConnectorFence {
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn generation(&self) -> ConnectorGeneration {
        self.generation
    }

    #[must_use]
    pub const fn boot_id(&self) -> BootId {
        self.boot_id
    }

    #[must_use]
    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    #[must_use]
    pub const fn lease_epoch(&self) -> LeaseEpoch {
        self.lease_epoch
    }
}

/// Durable lifecycle of a connector lease record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LeaseStatus {
    Active,
    Expired,
    Revoked,
    Superseded,
}

/// Append-only lease record; only its status and heartbeat expiry may advance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorLease {
    fence: ConnectorFence,
    issued_at_millis: i64,
    expires_at_millis: i64,
    ttl_millis: i64,
    status: LeaseStatus,
}

impl ConnectorLease {
    #[must_use]
    pub const fn fence(&self) -> ConnectorFence {
        self.fence
    }

    #[must_use]
    pub const fn issued_at_millis(&self) -> i64 {
        self.issued_at_millis
    }

    #[must_use]
    pub const fn expires_at_millis(&self) -> i64 {
        self.expires_at_millis
    }

    #[must_use]
    pub const fn status(&self) -> LeaseStatus {
        self.status
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HeartbeatRecord {
    sequence: u64,
    state: ConnectorObservedState,
    capacity_available: u32,
    ack: HeartbeatAck,
}

/// Append-only record for one connector process incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorBoot {
    tenant_id: TenantId,
    parent_id: ConnectorId,
    boot_id: BootId,
    generation: ConnectorGeneration,
    started_at_millis: i64,
    ended_at_millis: Option<i64>,
}

impl ConnectorBoot {
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        self.parent_id
    }

    #[must_use]
    pub const fn boot_id(&self) -> BootId {
        self.boot_id
    }

    #[must_use]
    pub const fn generation(&self) -> ConnectorGeneration {
        self.generation
    }

    #[must_use]
    pub const fn started_at_millis(&self) -> i64 {
        self.started_at_millis
    }

    #[must_use]
    pub const fn ended_at_millis(&self) -> Option<i64> {
        self.ended_at_millis
    }
}

/// Server acknowledgement cached for idempotent heartbeat replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeartbeatAck {
    sequence: u64,
    lease_expires_at_millis: i64,
}

impl HeartbeatAck {
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn lease_expires_at_millis(self) -> i64 {
        self.lease_expires_at_millis
    }
}

/// Immutable specification snapshot for one connector revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorRevision {
    tenant_id: TenantId,
    connector_id: ConnectorId,
    revision: Revision,
    generation: ConnectorGeneration,
    adapter_kind: AdapterKind,
    desired_state: ConnectorDesiredState,
    max_concurrency: u32,
}

impl ConnectorRevision {
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn connector_id(self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn generation(self) -> ConnectorGeneration {
        self.generation
    }

    #[must_use]
    pub const fn adapter_kind(self) -> AdapterKind {
        self.adapter_kind
    }

    #[must_use]
    pub const fn desired_state(self) -> ConnectorDesiredState {
        self.desired_state
    }

    #[must_use]
    pub const fn max_concurrency(self) -> u32 {
        self.max_concurrency
    }
}

/// Aggregate for one isolated connector process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Connector {
    tenant_id: TenantId,
    id: ConnectorId,
    host_id: HostId,
    adapter_kind: AdapterKind,
    generation: ConnectorGeneration,
    desired_state: ConnectorDesiredState,
    observed_state: ConnectorObservedState,
    max_concurrency: u32,
    boots: Vec<ConnectorBoot>,
    current_boot_id: Option<BootId>,
    leases: Vec<ConnectorLease>,
    active_lease_index: Option<usize>,
    highest_lease_epoch: Option<LeaseEpoch>,
    last_heartbeat: Option<HeartbeatRecord>,
    last_heartbeat_at_millis: Option<i64>,
    server_time_high_water_millis: Option<i64>,
    spec_revision: Revision,
    revisions: Vec<ConnectorRevision>,
}

impl Connector {
    /// Registers one connector under an enrolled, active host aggregate.
    ///
    /// # Errors
    ///
    /// Rejects an inactive host or zero concurrency.
    pub fn register(
        host: &AgentHost,
        connector_id: ConnectorId,
        adapter_kind: AdapterKind,
        max_concurrency: u32,
    ) -> Result<Self, ConnectorError> {
        if host.lifecycle() != HostLifecycle::Active {
            return Err(ConnectorError::HostNotActive);
        }
        if max_concurrency == 0 {
            return Err(ConnectorError::InvalidCapacity);
        }
        let tenant_id = host.tenant_id();
        let host_id = host.host_id();
        let initial_revision = ConnectorRevision {
            tenant_id,
            connector_id,
            revision: Revision::INITIAL,
            generation: ConnectorGeneration::INITIAL,
            adapter_kind,
            desired_state: ConnectorDesiredState::Running,
            max_concurrency,
        };
        Ok(Self {
            tenant_id,
            id: connector_id,
            host_id,
            adapter_kind,
            generation: ConnectorGeneration::INITIAL,
            desired_state: ConnectorDesiredState::Running,
            observed_state: ConnectorObservedState::Enrolling,
            max_concurrency,
            boots: Vec::new(),
            current_boot_id: None,
            leases: Vec::new(),
            active_lease_index: None,
            highest_lease_epoch: None,
            last_heartbeat: None,
            last_heartbeat_at_millis: None,
            server_time_high_water_millis: None,
            spec_revision: Revision::INITIAL,
            revisions: vec![initial_revision],
        })
    }

    /// Records the current process boot. Replaying the same boot is idempotent.
    ///
    /// # Errors
    ///
    /// A revoked connector cannot boot.
    pub fn begin_boot(
        &mut self,
        boot_id: BootId,
        started_at_millis: i64,
    ) -> Result<(), ConnectorError> {
        if self.desired_state == ConnectorDesiredState::Revoked {
            return Err(ConnectorError::ConnectorRevoked);
        }
        if self.desired_state == ConnectorDesiredState::Stopped {
            return Err(ConnectorError::ConnectorNotRunning);
        }
        if let Some(existing) = self.boots.iter().find(|boot| boot.boot_id == boot_id) {
            return if existing.ended_at_millis.is_none()
                && existing.generation == self.generation
                && existing.started_at_millis == started_at_millis
                && self.current_boot_id == Some(boot_id)
            {
                Ok(())
            } else {
                Err(ConnectorError::BootConflict)
            };
        }
        if let Some(current) = self.boots.last() {
            let earliest_start = current.ended_at_millis.unwrap_or(current.started_at_millis);
            if started_at_millis < earliest_start {
                return Err(ConnectorError::BootTimeRegressed);
            }
        }
        self.ensure_server_time_not_regressed(started_at_millis)?;
        if let Some(current) = self.boots.last_mut()
            && current.ended_at_millis.is_none()
        {
            current.ended_at_millis = Some(started_at_millis);
        }
        self.boots.push(ConnectorBoot {
            tenant_id: self.tenant_id,
            parent_id: self.id,
            boot_id,
            generation: self.generation,
            started_at_millis,
            ended_at_millis: None,
        });
        self.current_boot_id = Some(boot_id);
        self.terminalize_active_lease(LeaseStatus::Superseded);
        self.last_heartbeat = None;
        self.last_heartbeat_at_millis = None;
        self.observed_state = ConnectorObservedState::Starting;
        self.advance_server_time_high_water(started_at_millis);
        Ok(())
    }

    /// Issues the only active lease and monotonically advances its fencing epoch.
    ///
    /// # Errors
    ///
    /// Rejects an obsolete boot, invalid time window, conflicting lease replay, or revoked state.
    pub fn issue_lease(
        &mut self,
        lease_id: LeaseId,
        boot_id: BootId,
        issued_at_millis: i64,
        expires_at_millis: i64,
    ) -> Result<ConnectorFence, ConnectorError> {
        if self.desired_state == ConnectorDesiredState::Revoked {
            return Err(ConnectorError::ConnectorRevoked);
        }
        if self.desired_state == ConnectorDesiredState::Stopped {
            return Err(ConnectorError::ConnectorNotRunning);
        }
        if self.current_boot_id != Some(boot_id) {
            return Err(ConnectorError::StaleBoot);
        }
        if expires_at_millis <= issued_at_millis {
            return Err(ConnectorError::InvalidLeaseWindow);
        }
        let ttl_millis = expires_at_millis
            .checked_sub(issued_at_millis)
            .ok_or(ConnectorError::InvalidLeaseWindow)?;
        if let Some(current) = self
            .leases
            .iter()
            .find(|lease| lease.fence.lease_id == lease_id)
        {
            return if current.fence.boot_id == boot_id
                && current.issued_at_millis == issued_at_millis
                && current.ttl_millis == ttl_millis
            {
                Ok(current.fence)
            } else {
                Err(ConnectorError::LeaseConflict)
            };
        }
        let boot_started_at_millis = self
            .boots
            .last()
            .filter(|boot| boot.boot_id == boot_id)
            .map(|boot| boot.started_at_millis)
            .ok_or(ConnectorError::StaleBoot)?;
        let last_lease_issued_at_millis = self
            .leases
            .last()
            .map_or(boot_started_at_millis, |lease| lease.issued_at_millis);
        let not_before_millis = self
            .last_heartbeat_at_millis
            .unwrap_or(last_lease_issued_at_millis)
            .max(last_lease_issued_at_millis)
            .max(boot_started_at_millis);
        if issued_at_millis < not_before_millis {
            return Err(ConnectorError::LeaseTimeRegressed);
        }
        self.ensure_server_time_not_regressed(issued_at_millis)?;
        let lease_epoch = LeaseEpoch::checked_next(self.highest_lease_epoch)?;
        let fence = ConnectorFence {
            tenant_id: self.tenant_id,
            connector_id: self.id,
            generation: self.generation,
            boot_id,
            lease_id,
            lease_epoch,
        };
        self.terminalize_active_lease(LeaseStatus::Superseded);
        self.highest_lease_epoch = Some(lease_epoch);
        self.leases.push(ConnectorLease {
            fence,
            issued_at_millis,
            expires_at_millis,
            ttl_millis,
            status: LeaseStatus::Active,
        });
        self.active_lease_index = Some(self.leases.len() - 1);
        self.last_heartbeat = None;
        self.last_heartbeat_at_millis = None;
        self.observed_state = ConnectorObservedState::Starting;
        self.advance_server_time_high_water(issued_at_millis);
        Ok(fence)
    }

    /// Validates all connector, generation, boot, lease, epoch, revoke, and expiry coordinates.
    ///
    /// # Errors
    ///
    /// Returns a stable fencing error for any stale or inactive coordinate.
    pub fn validate_fence(
        &self,
        fence: &ConnectorFence,
        now_millis: i64,
    ) -> Result<(), ConnectorError> {
        let current = self.validate_fence_coordinates(fence)?;
        if now_millis >= current.expires_at_millis {
            return Err(ConnectorError::LeaseExpired);
        }
        Ok(())
    }

    fn validate_fence_coordinates(
        &self,
        fence: &ConnectorFence,
    ) -> Result<&ConnectorLease, ConnectorError> {
        if fence.tenant_id != self.tenant_id {
            return Err(ConnectorError::WrongTenant);
        }
        if fence.connector_id != self.id {
            return Err(ConnectorError::WrongConnector);
        }
        if fence.generation != self.generation || self.current_boot_id != Some(fence.boot_id) {
            return Err(ConnectorError::StaleLease);
        }
        let index = self
            .leases
            .iter()
            .position(|lease| lease.fence == *fence)
            .ok_or(ConnectorError::StaleLease)?;
        let current = &self.leases[index];
        match current.status {
            LeaseStatus::Active if self.active_lease_index == Some(index) => Ok(current),
            LeaseStatus::Expired => Err(ConnectorError::LeaseExpired),
            LeaseStatus::Revoked => Err(ConnectorError::LeaseRevoked),
            LeaseStatus::Superseded | LeaseStatus::Active => Err(ConnectorError::StaleLease),
        }
    }

    /// Applies an idempotency/fencing checked heartbeat with a strictly increasing sequence.
    ///
    /// # Errors
    ///
    /// Rejects stale fences/sequences, server-derived states, and impossible capacity.
    pub fn record_heartbeat(
        &mut self,
        fence: &ConnectorFence,
        sequence: u64,
        observed_at_millis: i64,
        state: ConnectorObservedState,
        capacity_available: u32,
    ) -> Result<HeartbeatAck, ConnectorError> {
        let issued_at_millis = self.validate_fence_coordinates(fence)?.issued_at_millis;
        if observed_at_millis < issued_at_millis {
            return Err(ConnectorError::InvalidHeartbeatTime);
        }
        if sequence == 0 || sequence > Revision::MAX {
            return Err(ConnectorError::InvalidHeartbeatSequence);
        }
        if matches!(
            state,
            ConnectorObservedState::Offline | ConnectorObservedState::Revoked
        ) {
            return Err(ConnectorError::InvalidObservedState);
        }
        if capacity_available > self.max_concurrency {
            return Err(ConnectorError::InvalidCapacity);
        }
        if let Some(previous) = self.last_heartbeat {
            if sequence < previous.sequence {
                return Err(ConnectorError::StaleHeartbeat);
            }
            if sequence == previous.sequence {
                return if previous.state == state
                    && previous.capacity_available == capacity_available
                {
                    Ok(previous.ack)
                } else {
                    Err(ConnectorError::HeartbeatConflict)
                };
            }
            if self
                .last_heartbeat_at_millis
                .is_some_and(|last_seen| observed_at_millis < last_seen)
            {
                return Err(ConnectorError::InvalidHeartbeatTime);
            }
        }
        self.ensure_server_time_not_regressed(observed_at_millis)?;
        self.validate_fence(fence, observed_at_millis)?;
        let lease = self
            .active_lease_index
            .and_then(|index| self.leases.get_mut(index))
            .ok_or(ConnectorError::StaleLease)?;
        let lease_expires_at_millis = observed_at_millis
            .checked_add(lease.ttl_millis)
            .ok_or(ConnectorError::InvalidHeartbeatTime)?;
        lease.expires_at_millis = lease_expires_at_millis;
        let ack = HeartbeatAck {
            sequence,
            lease_expires_at_millis,
        };
        self.last_heartbeat = Some(HeartbeatRecord {
            sequence,
            state,
            capacity_available,
            ack,
        });
        self.last_heartbeat_at_millis = Some(observed_at_millis);
        self.observed_state = state;
        self.advance_server_time_high_water(observed_at_millis);
        Ok(ack)
    }

    /// Returns liveness derived from the current lease rather than a connector-supplied boolean.
    #[must_use]
    pub fn effective_observed_state(&self, now_millis: i64) -> ConnectorObservedState {
        if self.desired_state == ConnectorDesiredState::Revoked {
            return ConnectorObservedState::Revoked;
        }
        if self
            .active_lease_index
            .and_then(|index| self.leases.get(index))
            .is_some_and(|lease| {
                lease.status == LeaseStatus::Active && now_millis < lease.expires_at_millis
            })
        {
            self.observed_state
        } else {
            ConnectorObservedState::Offline
        }
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn connector_id(&self) -> ConnectorId {
        self.id
    }

    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    #[must_use]
    pub const fn adapter_kind(&self) -> AdapterKind {
        self.adapter_kind
    }

    #[must_use]
    pub const fn generation(&self) -> ConnectorGeneration {
        self.generation
    }

    #[must_use]
    pub const fn spec_revision(&self) -> Revision {
        self.spec_revision
    }

    #[must_use]
    pub const fn max_concurrency(&self) -> u32 {
        self.max_concurrency
    }

    /// Returns append-only process boot history in start order.
    #[must_use]
    pub fn boots(&self) -> &[ConnectorBoot] {
        &self.boots
    }

    /// Returns append-only lease history in fencing-epoch order.
    #[must_use]
    pub fn leases(&self) -> &[ConnectorLease] {
        &self.leases
    }

    /// Returns immutable connector specification history in revision order.
    #[must_use]
    pub fn revisions(&self) -> &[ConnectorRevision] {
        &self.revisions
    }

    /// Marks the exact active lease expired using an observed-expiry CAS.
    ///
    /// # Errors
    ///
    /// Rejects a stale fence, changed expiry, or a lease that is not yet due.
    pub fn expire_lease(
        &mut self,
        fence: &ConnectorFence,
        expected_expires_at_millis: i64,
        now_millis: i64,
    ) -> Result<(), ConnectorError> {
        self.validate_fence_coordinates(fence)?;
        let index = self.active_lease_index.ok_or(ConnectorError::StaleLease)?;
        let lease = &self.leases[index];
        if lease.expires_at_millis != expected_expires_at_millis {
            return Err(ConnectorError::LeaseConflict);
        }
        if now_millis < lease.expires_at_millis {
            return Err(ConnectorError::LeaseNotExpired);
        }
        self.ensure_server_time_not_regressed(now_millis)?;
        self.leases[index].status = LeaseStatus::Expired;
        self.active_lease_index = None;
        self.observed_state = ConnectorObservedState::Offline;
        self.advance_server_time_high_water(now_millis);
        Ok(())
    }

    /// Revokes the exact active lease without deleting its durable history.
    ///
    /// # Errors
    ///
    /// Rejects a stale or already terminal fence.
    pub fn revoke_lease(&mut self, fence: &ConnectorFence) -> Result<(), ConnectorError> {
        self.validate_fence_coordinates(fence)?;
        let index = self.active_lease_index.ok_or(ConnectorError::StaleLease)?;
        self.leases[index].status = LeaseStatus::Revoked;
        self.active_lease_index = None;
        self.observed_state = ConnectorObservedState::Offline;
        Ok(())
    }

    /// Advances generation and invalidates the prior process and lease.
    ///
    /// # Errors
    ///
    /// Rejects a stale aggregate revision or exhausted counter.
    pub fn advance_generation(
        &mut self,
        expected_revision: Revision,
        changed_at_millis: i64,
    ) -> Result<ConnectorGeneration, ConnectorError> {
        if self.spec_revision != expected_revision {
            return Err(ConnectorError::RevisionConflict);
        }
        if self.desired_state == ConnectorDesiredState::Revoked {
            return Err(ConnectorError::ConnectorRevoked);
        }
        self.ensure_server_time_not_regressed(changed_at_millis)?;
        self.validate_boot_close_time(changed_at_millis)?;
        let next_generation = self.generation.checked_next()?;
        let next_revision = self
            .spec_revision
            .checked_next()
            .map_err(|_| ConnectorError::CounterExhausted)?;
        self.close_current_boot(changed_at_millis);
        self.generation = next_generation;
        self.spec_revision = next_revision;
        self.current_boot_id = None;
        self.terminalize_active_lease(LeaseStatus::Superseded);
        self.last_heartbeat = None;
        self.last_heartbeat_at_millis = None;
        self.observed_state = ConnectorObservedState::Offline;
        self.advance_server_time_high_water(changed_at_millis);
        self.append_current_revision();
        Ok(self.generation)
    }

    /// Changes owner intent under spec-revision compare-and-swap.
    ///
    /// # Errors
    ///
    /// Rejects stale revisions, invalid transitions, terminal revocation, or regressed time.
    pub fn set_desired_state(
        &mut self,
        expected_revision: Revision,
        desired_state: ConnectorDesiredState,
        changed_at_millis: i64,
    ) -> Result<Revision, ConnectorError> {
        if self.spec_revision != expected_revision {
            return Err(ConnectorError::RevisionConflict);
        }
        if self.desired_state == ConnectorDesiredState::Revoked {
            return Err(ConnectorError::ConnectorRevoked);
        }
        if self.desired_state == desired_state {
            return Ok(self.spec_revision);
        }
        self.ensure_server_time_not_regressed(changed_at_millis)?;
        let allowed = matches!(
            (self.desired_state, desired_state),
            (
                ConnectorDesiredState::Running,
                ConnectorDesiredState::Draining
                    | ConnectorDesiredState::Stopped
                    | ConnectorDesiredState::Revoked
            ) | (
                ConnectorDesiredState::Draining,
                ConnectorDesiredState::Running
                    | ConnectorDesiredState::Stopped
                    | ConnectorDesiredState::Revoked
            ) | (
                ConnectorDesiredState::Stopped,
                ConnectorDesiredState::Running | ConnectorDesiredState::Revoked
            )
        );
        if !allowed {
            return Err(ConnectorError::InvalidDesiredTransition);
        }
        if matches!(
            desired_state,
            ConnectorDesiredState::Stopped | ConnectorDesiredState::Revoked
        ) {
            self.validate_boot_close_time(changed_at_millis)?;
        }
        let next_revision = self
            .spec_revision
            .checked_next()
            .map_err(|_| ConnectorError::CounterExhausted)?;
        self.spec_revision = next_revision;
        self.desired_state = desired_state;
        match desired_state {
            ConnectorDesiredState::Draining => {
                self.observed_state = ConnectorObservedState::Draining;
            }
            ConnectorDesiredState::Stopped => {
                self.close_current_boot(changed_at_millis);
                self.current_boot_id = None;
                self.terminalize_active_lease(LeaseStatus::Revoked);
                self.last_heartbeat = None;
                self.last_heartbeat_at_millis = None;
                self.observed_state = ConnectorObservedState::Offline;
            }
            ConnectorDesiredState::Revoked => {
                self.close_current_boot(changed_at_millis);
                self.current_boot_id = None;
                self.terminalize_active_lease(LeaseStatus::Revoked);
                self.last_heartbeat = None;
                self.last_heartbeat_at_millis = None;
                self.observed_state = ConnectorObservedState::Revoked;
            }
            ConnectorDesiredState::Running => {}
        }
        self.advance_server_time_high_water(changed_at_millis);
        self.append_current_revision();
        Ok(next_revision)
    }

    #[must_use]
    pub const fn desired_state(&self) -> ConnectorDesiredState {
        self.desired_state
    }

    fn validate_boot_close_time(&self, ended_at_millis: i64) -> Result<(), ConnectorError> {
        if self.boots.last().is_some_and(|boot| {
            boot.ended_at_millis.is_none() && ended_at_millis < boot.started_at_millis
        }) {
            Err(ConnectorError::BootTimeRegressed)
        } else {
            Ok(())
        }
    }

    fn close_current_boot(&mut self, ended_at_millis: i64) {
        if let Some(boot) = self.boots.last_mut()
            && boot.ended_at_millis.is_none()
        {
            boot.ended_at_millis = Some(ended_at_millis);
        }
    }

    fn ensure_server_time_not_regressed(
        &self,
        candidate_millis: i64,
    ) -> Result<(), ConnectorError> {
        if self
            .server_time_high_water_millis
            .is_some_and(|high_water| candidate_millis < high_water)
        {
            Err(ConnectorError::ServerTimeRegressed)
        } else {
            Ok(())
        }
    }

    fn advance_server_time_high_water(&mut self, candidate_millis: i64) {
        self.server_time_high_water_millis = Some(
            self.server_time_high_water_millis
                .map_or(candidate_millis, |high_water| {
                    high_water.max(candidate_millis)
                }),
        );
    }

    fn terminalize_active_lease(&mut self, status: LeaseStatus) {
        if let Some(index) = self.active_lease_index.take()
            && let Some(lease) = self.leases.get_mut(index)
            && lease.status == LeaseStatus::Active
        {
            lease.status = status;
        }
    }

    fn append_current_revision(&mut self) {
        self.revisions.push(ConnectorRevision {
            tenant_id: self.tenant_id,
            connector_id: self.id,
            revision: self.spec_revision,
            generation: self.generation,
            adapter_kind: self.adapter_kind,
            desired_state: self.desired_state,
            max_concurrency: self.max_concurrency,
        });
    }
}

/// Stable rejection from the connector lifecycle and fencing boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorError {
    InvalidCapacity,
    HostNotActive,
    ServerTimeRegressed,
    InvalidLeaseWindow,
    LeaseTimeRegressed,
    StaleBoot,
    BootConflict,
    BootTimeRegressed,
    StaleLease,
    LeaseExpired,
    LeaseRevoked,
    LeaseConflict,
    LeaseNotExpired,
    StaleHeartbeat,
    InvalidHeartbeatSequence,
    HeartbeatConflict,
    InvalidHeartbeatTime,
    InvalidObservedState,
    WrongConnector,
    WrongTenant,
    ConnectorRevoked,
    ConnectorNotRunning,
    InvalidDesiredTransition,
    RevisionConflict,
    CounterExhausted,
}

impl fmt::Display for ConnectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCapacity => "connector capacity is invalid",
            Self::HostNotActive => "connector host is not active",
            Self::ServerTimeRegressed => "connector server time regressed",
            Self::InvalidLeaseWindow => "connector lease window is invalid",
            Self::LeaseTimeRegressed => "connector lease issue time regressed",
            Self::StaleBoot => "connector boot is stale",
            Self::BootConflict => "connector boot ID was reused with different input",
            Self::BootTimeRegressed => "connector boot time regressed",
            Self::StaleLease => "connector lease fence is stale",
            Self::LeaseExpired => "connector lease has expired",
            Self::LeaseRevoked => "connector lease has been revoked",
            Self::LeaseConflict => "connector lease ID was reused with different input",
            Self::LeaseNotExpired => "connector lease is not yet expired",
            Self::StaleHeartbeat => "connector heartbeat sequence is stale",
            Self::InvalidHeartbeatSequence => "connector heartbeat sequence is outside bounds",
            Self::HeartbeatConflict => {
                "connector heartbeat sequence was reused with different input"
            }
            Self::InvalidHeartbeatTime => "connector heartbeat time is invalid",
            Self::InvalidObservedState => "connector cannot report a server-derived state",
            Self::WrongConnector => "connector fence belongs to another connector",
            Self::WrongTenant => "connector fence belongs to another tenant",
            Self::ConnectorRevoked => "connector has been revoked",
            Self::ConnectorNotRunning => "connector is not allowed to run",
            Self::InvalidDesiredTransition => "connector desired-state transition is invalid",
            Self::RevisionConflict => "connector revision is stale",
            Self::CounterExhausted => "connector monotonic counter is exhausted",
        })
    }
}

impl Error for ConnectorError {}
