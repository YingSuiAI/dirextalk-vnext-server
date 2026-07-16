use std::{error::Error, fmt};

use dtx_agent_host::{AgentHost, HostLifecycle};
use dtx_domain::{BootId, ConnectorId, HostId, LeaseId, Revision, TenantId};

/// Maximum server-issued Connector lease TTL shared with `PostgreSQL` constraints.
pub const MAX_LEASE_TTL_MILLIS: i64 = 86_400_000;

/// Allowlisted runtime adapter schema selected for one connector process.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdapterKind {
    Codex,
    OpenClawAcp,
    Eino,
    Rig,
    ClaudeCode,
    CustomAcp,
    HermesAcp,
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

/// Append-only lease record; only status, heartbeat expiry, and its replay fence may advance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorLease {
    fence: ConnectorFence,
    issued_at_millis: i64,
    expires_at_millis: i64,
    ttl_millis: i64,
    status: LeaseStatus,
    last_heartbeat: Option<HeartbeatRecord>,
    last_heartbeat_at_millis: Option<i64>,
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
    server_time_high_water_millis: Option<i64>,
    spec_revision: Revision,
    revisions: Vec<ConnectorRevision>,
}

/// Durable non-secret heartbeat replay fence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeartbeatRecordSnapshot {
    pub sequence: u64,
    pub state: ConnectorObservedState,
    pub capacity_available: u32,
    pub ack: HeartbeatAckSnapshot,
}

/// Constructible durable form of the cached heartbeat acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeartbeatAckSnapshot {
    pub sequence: u64,
    pub lease_expires_at_millis: i64,
}

/// Durable non-secret process-incarnation history record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorBootSnapshot {
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub boot_id: BootId,
    pub generation: u64,
    pub started_at_millis: i64,
    pub ended_at_millis: Option<i64>,
}

/// Durable non-secret lease history record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorLeaseSnapshot {
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub generation: u64,
    pub boot_id: BootId,
    pub lease_id: LeaseId,
    pub lease_epoch: u64,
    pub issued_at_millis: i64,
    pub expires_at_millis: i64,
    pub ttl_millis: i64,
    pub status: LeaseStatus,
    pub last_heartbeat: Option<HeartbeatRecordSnapshot>,
    pub last_heartbeat_at_millis: Option<i64>,
}

/// Durable immutable connector specification history record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorRevisionSnapshot {
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub revision: Revision,
    pub generation: u64,
    pub adapter_kind: AdapterKind,
    pub desired_state: ConnectorDesiredState,
    pub max_concurrency: u32,
}

/// Complete non-secret persistence image of a connector aggregate and all fences.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorSnapshot {
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub host_id: HostId,
    pub adapter_kind: AdapterKind,
    pub generation: u64,
    pub desired_state: ConnectorDesiredState,
    pub observed_state: ConnectorObservedState,
    pub max_concurrency: u32,
    pub boots: Vec<ConnectorBootSnapshot>,
    pub current_boot_id: Option<BootId>,
    pub leases: Vec<ConnectorLeaseSnapshot>,
    pub active_lease_index: Option<usize>,
    pub highest_lease_epoch: Option<u64>,
    pub server_time_high_water_millis: Option<i64>,
    pub spec_revision: Revision,
    pub revisions: Vec<ConnectorRevisionSnapshot>,
}

/// Constant-size durable projection for Connector control-plane mutations.
///
/// The complete aggregate remains the audit boundary. Online control paths need
/// only the current specification revision, current boot, and active lease; old
/// immutable history must not make authorization or fencing proportional to the
/// Connector lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorControlHeadSnapshot {
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub host_id: HostId,
    pub adapter_kind: AdapterKind,
    pub generation: u64,
    pub desired_state: ConnectorDesiredState,
    pub observed_state: ConnectorObservedState,
    pub max_concurrency: u32,
    pub spec_revision: Revision,
    pub latest_revision: ConnectorRevisionSnapshot,
    pub current_boot: Option<ConnectorBootSnapshot>,
    pub active_lease: Option<ConnectorLeaseSnapshot>,
    pub highest_lease_epoch: Option<u64>,
    pub server_time_high_water_millis: Option<i64>,
}

/// Validated, fixed-size Connector state used by online control operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorControlHead {
    snapshot: ConnectorControlHeadSnapshot,
}

impl ConnectorControlHead {
    /// Rehydrates a bounded head after checking every current fence coordinate.
    ///
    /// # Errors
    ///
    /// Rejects malformed counters, an inconsistent latest revision, invalid
    /// current boot/lease pointers, terminal-state leakage, or regressed time.
    pub fn try_from_snapshot(
        snapshot: ConnectorControlHeadSnapshot,
    ) -> Result<Self, ConnectorSnapshotError> {
        snapshot_generation(snapshot.generation)?;
        if snapshot.max_concurrency == 0 {
            return Err(ConnectorSnapshotError::InvalidCapacity);
        }
        let revision = snapshot.latest_revision;
        if revision.tenant_id != snapshot.tenant_id
            || revision.connector_id != snapshot.connector_id
            || revision.revision != snapshot.spec_revision
            || revision.generation != snapshot.generation
            || revision.adapter_kind != snapshot.adapter_kind
            || revision.desired_state != snapshot.desired_state
            || revision.max_concurrency != snapshot.max_concurrency
        {
            return Err(ConnectorSnapshotError::InvalidRevisionHistory);
        }
        if let Some(boot) = snapshot.current_boot
            && (boot.tenant_id != snapshot.tenant_id
                || boot.connector_id != snapshot.connector_id
                || boot.generation != snapshot.generation
                || boot.ended_at_millis.is_some())
        {
            return Err(ConnectorSnapshotError::InvalidCurrentBoot);
        }
        if let Some(lease) = snapshot.active_lease {
            let highest = snapshot
                .highest_lease_epoch
                .ok_or(ConnectorSnapshotError::InvalidActiveLease)?;
            snapshot_epoch(highest)?;
            if lease.tenant_id != snapshot.tenant_id
                || lease.connector_id != snapshot.connector_id
                || lease.generation != snapshot.generation
                || lease.status != LeaseStatus::Active
                || lease.lease_epoch != highest
                || snapshot.current_boot.map(|boot| boot.boot_id) != Some(lease.boot_id)
                || !(1..=MAX_LEASE_TTL_MILLIS).contains(&lease.ttl_millis)
            {
                return Err(ConnectorSnapshotError::InvalidActiveLease);
            }
            snapshot_heartbeat(&lease, snapshot.max_concurrency)?;
        }
        if snapshot
            .highest_lease_epoch
            .is_some_and(|epoch| snapshot_epoch(epoch).is_err())
        {
            return Err(ConnectorSnapshotError::InvalidActiveLease);
        }
        if matches!(
            snapshot.desired_state,
            ConnectorDesiredState::Stopped | ConnectorDesiredState::Revoked
        ) && (snapshot.current_boot.is_some() || snapshot.active_lease.is_some())
        {
            return Err(ConnectorSnapshotError::InvalidTerminalState);
        }
        if (snapshot.desired_state == ConnectorDesiredState::Revoked
            && snapshot.observed_state != ConnectorObservedState::Revoked)
            || (snapshot.desired_state == ConnectorDesiredState::Stopped
                && snapshot.observed_state != ConnectorObservedState::Offline)
        {
            return Err(ConnectorSnapshotError::InvalidTerminalState);
        }
        if snapshot.active_lease.is_some() && snapshot.current_boot.is_none() {
            return Err(ConnectorSnapshotError::InvalidActiveLease);
        }
        let high_water = snapshot.server_time_high_water_millis;
        if snapshot
            .current_boot
            .is_some_and(|boot| high_water.is_none_or(|high| boot.started_at_millis > high))
            || snapshot.active_lease.is_some_and(|lease| {
                high_water.is_none_or(|high| {
                    lease.issued_at_millis > high
                        || lease
                            .last_heartbeat_at_millis
                            .is_some_and(|observed| observed > high)
                })
            })
        {
            return Err(ConnectorSnapshotError::InvalidServerTimeHighWater);
        }
        Ok(Self { snapshot })
    }

    #[must_use]
    pub const fn snapshot(self) -> ConnectorControlHeadSnapshot {
        self.snapshot
    }

    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.snapshot.tenant_id
    }

    #[must_use]
    pub const fn connector_id(self) -> ConnectorId {
        self.snapshot.connector_id
    }

    #[must_use]
    pub const fn host_id(self) -> HostId {
        self.snapshot.host_id
    }

    #[must_use]
    pub const fn adapter_kind(self) -> AdapterKind {
        self.snapshot.adapter_kind
    }

    #[must_use]
    pub const fn generation(self) -> u64 {
        self.snapshot.generation
    }

    #[must_use]
    pub const fn spec_revision(self) -> Revision {
        self.snapshot.spec_revision
    }

    #[must_use]
    pub const fn desired_state(self) -> ConnectorDesiredState {
        self.snapshot.desired_state
    }

    #[must_use]
    pub const fn max_concurrency(self) -> u32 {
        self.snapshot.max_concurrency
    }

    #[must_use]
    pub const fn current_boot_id(self) -> Option<BootId> {
        match self.snapshot.current_boot {
            Some(boot) => Some(boot.boot_id),
            None => None,
        }
    }

    /// Returns the exact active fence, when a live control lease exists.
    #[must_use]
    pub fn active_fence(self) -> Option<ConnectorFence> {
        self.heartbeat_head()
            .ok()
            .map(ConnectorHeartbeatHead::fence)
    }

    /// Returns the active lease without materializing historical leases.
    #[must_use]
    pub fn active_lease(self) -> Option<ConnectorLease> {
        self.heartbeat_head()
            .ok()
            .map(ConnectorHeartbeatHead::active_lease)
    }

    /// Validates the exact active lease and its expiry.
    ///
    /// # Errors
    ///
    /// Returns the same stable lease errors as the complete aggregate.
    pub fn validate_fence(
        &self,
        fence: &ConnectorFence,
        now_millis: i64,
    ) -> Result<(), ConnectorError> {
        self.heartbeat_head()
            .map_err(|_| ConnectorError::StaleLease)?
            .validate_fence(fence, now_millis)
    }

    /// Starts a new current boot while terminalizing the prior live lease.
    ///
    /// # Errors
    ///
    /// Rejects terminal state, a conflicting replay, or regressed server time.
    pub fn begin_boot(
        &mut self,
        boot_id: BootId,
        started_at_millis: i64,
    ) -> Result<(), ConnectorError> {
        if self.snapshot.desired_state == ConnectorDesiredState::Revoked {
            return Err(ConnectorError::ConnectorRevoked);
        }
        if self.snapshot.desired_state == ConnectorDesiredState::Stopped {
            return Err(ConnectorError::ConnectorNotRunning);
        }
        if let Some(current) = self.snapshot.current_boot {
            if current.boot_id == boot_id {
                return if current.started_at_millis == started_at_millis {
                    Ok(())
                } else {
                    Err(ConnectorError::BootConflict)
                };
            }
            if started_at_millis < current.started_at_millis {
                return Err(ConnectorError::BootTimeRegressed);
            }
        }
        self.ensure_server_time_not_regressed(started_at_millis)?;
        self.snapshot.current_boot = Some(ConnectorBootSnapshot {
            tenant_id: self.snapshot.tenant_id,
            connector_id: self.snapshot.connector_id,
            boot_id,
            generation: self.snapshot.generation,
            started_at_millis,
            ended_at_millis: None,
        });
        self.snapshot.active_lease = None;
        self.snapshot.observed_state = ConnectorObservedState::Starting;
        self.advance_server_time_high_water(started_at_millis);
        Ok(())
    }

    /// Issues the next active lease for the current boot.
    ///
    /// # Errors
    ///
    /// Rejects terminal/stale boots, invalid windows, replay conflicts, regressed
    /// time, or an exhausted lease epoch.
    pub fn issue_lease(
        &mut self,
        lease_id: LeaseId,
        boot_id: BootId,
        issued_at_millis: i64,
        expires_at_millis: i64,
    ) -> Result<ConnectorFence, ConnectorError> {
        if self.snapshot.desired_state == ConnectorDesiredState::Revoked {
            return Err(ConnectorError::ConnectorRevoked);
        }
        if self.snapshot.desired_state == ConnectorDesiredState::Stopped {
            return Err(ConnectorError::ConnectorNotRunning);
        }
        if self.current_boot_id() != Some(boot_id) {
            return Err(ConnectorError::StaleBoot);
        }
        if expires_at_millis <= issued_at_millis {
            return Err(ConnectorError::InvalidLeaseWindow);
        }
        let ttl_millis = expires_at_millis
            .checked_sub(issued_at_millis)
            .ok_or(ConnectorError::InvalidLeaseWindow)?;
        if ttl_millis > MAX_LEASE_TTL_MILLIS {
            return Err(ConnectorError::InvalidLeaseWindow);
        }
        if let Some(current) = self.snapshot.active_lease
            && current.lease_id == lease_id
        {
            return if current.boot_id == boot_id
                && current.issued_at_millis == issued_at_millis
                && current.ttl_millis == ttl_millis
            {
                self.active_fence().ok_or(ConnectorError::StaleLease)
            } else {
                Err(ConnectorError::LeaseConflict)
            };
        }
        self.ensure_server_time_not_regressed(issued_at_millis)?;
        let lease_epoch = LeaseEpoch::checked_next(
            self.snapshot
                .highest_lease_epoch
                .map(snapshot_epoch)
                .transpose()
                .map_err(|_| ConnectorError::CounterExhausted)?,
        )?;
        let generation = snapshot_generation(self.snapshot.generation)
            .map_err(|_| ConnectorError::CounterExhausted)?;
        let fence = ConnectorFence {
            tenant_id: self.snapshot.tenant_id,
            connector_id: self.snapshot.connector_id,
            generation,
            boot_id,
            lease_id,
            lease_epoch,
        };
        self.snapshot.highest_lease_epoch = Some(lease_epoch.get());
        self.snapshot.active_lease = Some(ConnectorLeaseSnapshot {
            tenant_id: self.snapshot.tenant_id,
            connector_id: self.snapshot.connector_id,
            generation: self.snapshot.generation,
            boot_id,
            lease_id,
            lease_epoch: lease_epoch.get(),
            issued_at_millis,
            expires_at_millis,
            ttl_millis,
            status: LeaseStatus::Active,
            last_heartbeat: None,
            last_heartbeat_at_millis: None,
        });
        self.snapshot.observed_state = ConnectorObservedState::Starting;
        self.advance_server_time_high_water(issued_at_millis);
        Ok(fence)
    }

    /// Advances the generation and current revision while fencing the old process.
    ///
    /// # Errors
    ///
    /// Rejects a stale revision, revocation, regressed time, or exhausted counters.
    pub fn advance_generation(
        &mut self,
        expected_revision: Revision,
        changed_at_millis: i64,
    ) -> Result<u64, ConnectorError> {
        if self.snapshot.spec_revision != expected_revision {
            return Err(ConnectorError::RevisionConflict);
        }
        if self.snapshot.desired_state == ConnectorDesiredState::Revoked {
            return Err(ConnectorError::ConnectorRevoked);
        }
        self.ensure_server_time_not_regressed(changed_at_millis)?;
        if self
            .snapshot
            .current_boot
            .is_some_and(|boot| changed_at_millis < boot.started_at_millis)
        {
            return Err(ConnectorError::BootTimeRegressed);
        }
        let generation = self
            .snapshot
            .generation
            .checked_add(1)
            .filter(|value| *value <= Revision::MAX)
            .ok_or(ConnectorError::CounterExhausted)?;
        let revision = self
            .snapshot
            .spec_revision
            .checked_next()
            .map_err(|_| ConnectorError::CounterExhausted)?;
        self.snapshot.generation = generation;
        self.snapshot.spec_revision = revision;
        self.snapshot.current_boot = None;
        self.snapshot.active_lease = None;
        self.snapshot.observed_state = ConnectorObservedState::Offline;
        self.advance_server_time_high_water(changed_at_millis);
        self.refresh_latest_revision();
        Ok(generation)
    }

    /// Advances one non-terminal configuration revision.
    ///
    /// # Errors
    ///
    /// Rejects stale/terminal transitions, revocation, regressed time, or an
    /// exhausted revision.
    pub fn revise_live_configuration(
        &mut self,
        expected_revision: Revision,
        desired_state: ConnectorDesiredState,
        changed_at_millis: i64,
    ) -> Result<Revision, ConnectorError> {
        if self.snapshot.spec_revision != expected_revision {
            return Err(ConnectorError::RevisionConflict);
        }
        if self.snapshot.desired_state == ConnectorDesiredState::Revoked {
            return Err(ConnectorError::ConnectorRevoked);
        }
        if !matches!(
            desired_state,
            ConnectorDesiredState::Running | ConnectorDesiredState::Draining
        ) || (self.snapshot.desired_state != desired_state
            && !valid_desired_transition(self.snapshot.desired_state, desired_state))
        {
            return Err(ConnectorError::InvalidDesiredTransition);
        }
        self.ensure_server_time_not_regressed(changed_at_millis)?;
        self.snapshot.spec_revision = self
            .snapshot
            .spec_revision
            .checked_next()
            .map_err(|_| ConnectorError::CounterExhausted)?;
        self.snapshot.desired_state = desired_state;
        if desired_state == ConnectorDesiredState::Draining {
            self.snapshot.observed_state = ConnectorObservedState::Draining;
        }
        self.advance_server_time_high_water(changed_at_millis);
        self.refresh_latest_revision();
        Ok(self.snapshot.spec_revision)
    }

    /// Applies an owner lifecycle transition under the current revision fence.
    ///
    /// # Errors
    ///
    /// Rejects stale/invalid transitions, revocation, regressed time, or an
    /// exhausted revision.
    pub fn set_desired_state(
        &mut self,
        expected_revision: Revision,
        desired_state: ConnectorDesiredState,
        changed_at_millis: i64,
    ) -> Result<Revision, ConnectorError> {
        if self.snapshot.spec_revision != expected_revision {
            return Err(ConnectorError::RevisionConflict);
        }
        if self.snapshot.desired_state == ConnectorDesiredState::Revoked {
            return Err(ConnectorError::ConnectorRevoked);
        }
        if self.snapshot.desired_state == desired_state {
            return Ok(self.snapshot.spec_revision);
        }
        if !valid_desired_transition(self.snapshot.desired_state, desired_state) {
            return Err(ConnectorError::InvalidDesiredTransition);
        }
        self.ensure_server_time_not_regressed(changed_at_millis)?;
        if matches!(
            desired_state,
            ConnectorDesiredState::Stopped | ConnectorDesiredState::Revoked
        ) && self
            .snapshot
            .current_boot
            .is_some_and(|boot| changed_at_millis < boot.started_at_millis)
        {
            return Err(ConnectorError::BootTimeRegressed);
        }
        self.snapshot.spec_revision = self
            .snapshot
            .spec_revision
            .checked_next()
            .map_err(|_| ConnectorError::CounterExhausted)?;
        self.snapshot.desired_state = desired_state;
        match desired_state {
            ConnectorDesiredState::Draining => {
                self.snapshot.observed_state = ConnectorObservedState::Draining;
            }
            ConnectorDesiredState::Stopped => {
                self.snapshot.current_boot = None;
                self.snapshot.active_lease = None;
                self.snapshot.observed_state = ConnectorObservedState::Offline;
            }
            ConnectorDesiredState::Revoked => {
                self.snapshot.current_boot = None;
                self.snapshot.active_lease = None;
                self.snapshot.observed_state = ConnectorObservedState::Revoked;
            }
            ConnectorDesiredState::Running => {}
        }
        self.advance_server_time_high_water(changed_at_millis);
        self.refresh_latest_revision();
        Ok(self.snapshot.spec_revision)
    }

    fn heartbeat_head(self) -> Result<ConnectorHeartbeatHead, ConnectorSnapshotError> {
        let current_boot_id = self
            .current_boot_id()
            .ok_or(ConnectorSnapshotError::InvalidCurrentBoot)?;
        let active_lease = self
            .snapshot
            .active_lease
            .ok_or(ConnectorSnapshotError::InvalidActiveLease)?;
        ConnectorHeartbeatHead::try_from_snapshot(ConnectorHeartbeatHeadSnapshot {
            tenant_id: self.snapshot.tenant_id,
            connector_id: self.snapshot.connector_id,
            generation: self.snapshot.generation,
            adapter_kind: self.snapshot.adapter_kind,
            spec_revision: self.snapshot.spec_revision,
            desired_state: self.snapshot.desired_state,
            observed_state: self.snapshot.observed_state,
            max_concurrency: self.snapshot.max_concurrency,
            current_boot_id,
            highest_lease_epoch: self
                .snapshot
                .highest_lease_epoch
                .ok_or(ConnectorSnapshotError::InvalidActiveLease)?,
            server_time_high_water_millis: self.snapshot.server_time_high_water_millis,
            active_lease,
        })
    }

    fn ensure_server_time_not_regressed(self, candidate_millis: i64) -> Result<(), ConnectorError> {
        if self
            .snapshot
            .server_time_high_water_millis
            .is_some_and(|high_water| candidate_millis < high_water)
        {
            Err(ConnectorError::ServerTimeRegressed)
        } else {
            Ok(())
        }
    }

    fn advance_server_time_high_water(&mut self, candidate_millis: i64) {
        self.snapshot.server_time_high_water_millis = Some(
            self.snapshot
                .server_time_high_water_millis
                .map_or(candidate_millis, |high_water| {
                    high_water.max(candidate_millis)
                }),
        );
    }

    fn refresh_latest_revision(&mut self) {
        self.snapshot.latest_revision = ConnectorRevisionSnapshot {
            tenant_id: self.snapshot.tenant_id,
            connector_id: self.snapshot.connector_id,
            revision: self.snapshot.spec_revision,
            generation: self.snapshot.generation,
            adapter_kind: self.snapshot.adapter_kind,
            desired_state: self.snapshot.desired_state,
            max_concurrency: self.snapshot.max_concurrency,
        };
    }
}

/// Bounded durable projection used by the high-frequency heartbeat path.
///
/// Unlike [`ConnectorSnapshot`], this projection intentionally contains only
/// the current Connector head and active lease. Immutable boot, lease, and
/// specification histories remain available to audit/owner workflows without
/// making every heartbeat proportional to the Connector lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorHeartbeatHeadSnapshot {
    pub tenant_id: TenantId,
    pub connector_id: ConnectorId,
    pub generation: u64,
    pub adapter_kind: AdapterKind,
    pub spec_revision: Revision,
    pub desired_state: ConnectorDesiredState,
    pub observed_state: ConnectorObservedState,
    pub max_concurrency: u32,
    pub current_boot_id: BootId,
    pub highest_lease_epoch: u64,
    pub server_time_high_water_millis: Option<i64>,
    pub active_lease: ConnectorLeaseSnapshot,
}

/// Validated, constant-size Connector heartbeat state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorHeartbeatHead {
    tenant_id: TenantId,
    connector_id: ConnectorId,
    generation: ConnectorGeneration,
    adapter_kind: AdapterKind,
    spec_revision: Revision,
    desired_state: ConnectorDesiredState,
    observed_state: ConnectorObservedState,
    max_concurrency: u32,
    current_boot_id: BootId,
    highest_lease_epoch: LeaseEpoch,
    server_time_high_water_millis: Option<i64>,
    active_lease: ConnectorLease,
}

impl ConnectorHeartbeatHead {
    /// Rehydrates the bounded heartbeat projection after fail-closed invariant checks.
    ///
    /// # Errors
    ///
    /// Rejects terminal Connector state, mismatched fence coordinates, malformed
    /// heartbeat replay state, or regressed server time.
    pub fn try_from_snapshot(
        snapshot: ConnectorHeartbeatHeadSnapshot,
    ) -> Result<Self, ConnectorSnapshotError> {
        let generation = snapshot_generation(snapshot.generation)?;
        let highest_lease_epoch = snapshot_epoch(snapshot.highest_lease_epoch)?;
        let lease = snapshot.active_lease;
        if snapshot.max_concurrency == 0 {
            return Err(ConnectorSnapshotError::InvalidCapacity);
        }
        if !matches!(
            snapshot.desired_state,
            ConnectorDesiredState::Running | ConnectorDesiredState::Draining
        ) || lease.status != LeaseStatus::Active
            || lease.tenant_id != snapshot.tenant_id
            || lease.connector_id != snapshot.connector_id
            || lease.generation != snapshot.generation
            || lease.boot_id != snapshot.current_boot_id
            || lease.lease_epoch != snapshot.highest_lease_epoch
            || !(1..=MAX_LEASE_TTL_MILLIS).contains(&lease.ttl_millis)
        {
            return Err(ConnectorSnapshotError::InvalidActiveLease);
        }
        let last_heartbeat = snapshot_heartbeat(&lease, snapshot.max_concurrency)?;
        let owner_draining_overlay = snapshot.desired_state == ConnectorDesiredState::Draining
            && snapshot.observed_state == ConnectorObservedState::Draining;
        if !owner_draining_overlay
            && (last_heartbeat.is_some_and(|heartbeat| heartbeat.state != snapshot.observed_state)
                || (last_heartbeat.is_none()
                    && snapshot.observed_state != ConnectorObservedState::Starting))
        {
            return Err(ConnectorSnapshotError::InvalidHeartbeat);
        }
        if snapshot
            .server_time_high_water_millis
            .is_none_or(|high_water| {
                high_water < lease.issued_at_millis
                    || lease
                        .last_heartbeat_at_millis
                        .is_some_and(|observed_at| high_water < observed_at)
            })
        {
            return Err(ConnectorSnapshotError::InvalidServerTimeHighWater);
        }
        Ok(Self {
            tenant_id: snapshot.tenant_id,
            connector_id: snapshot.connector_id,
            generation,
            adapter_kind: snapshot.adapter_kind,
            spec_revision: snapshot.spec_revision,
            desired_state: snapshot.desired_state,
            observed_state: snapshot.observed_state,
            max_concurrency: snapshot.max_concurrency,
            current_boot_id: snapshot.current_boot_id,
            highest_lease_epoch,
            server_time_high_water_millis: snapshot.server_time_high_water_millis,
            active_lease: ConnectorLease {
                fence: ConnectorFence {
                    tenant_id: lease.tenant_id,
                    connector_id: lease.connector_id,
                    generation,
                    boot_id: lease.boot_id,
                    lease_id: lease.lease_id,
                    lease_epoch: highest_lease_epoch,
                },
                issued_at_millis: lease.issued_at_millis,
                expires_at_millis: lease.expires_at_millis,
                ttl_millis: lease.ttl_millis,
                status: lease.status,
                last_heartbeat,
                last_heartbeat_at_millis: lease.last_heartbeat_at_millis,
            },
        })
    }

    #[must_use]
    pub const fn snapshot(self) -> ConnectorHeartbeatHeadSnapshot {
        ConnectorHeartbeatHeadSnapshot {
            tenant_id: self.tenant_id,
            connector_id: self.connector_id,
            generation: self.generation.get(),
            adapter_kind: self.adapter_kind,
            spec_revision: self.spec_revision,
            desired_state: self.desired_state,
            observed_state: self.observed_state,
            max_concurrency: self.max_concurrency,
            current_boot_id: self.current_boot_id,
            highest_lease_epoch: self.highest_lease_epoch.get(),
            server_time_high_water_millis: self.server_time_high_water_millis,
            active_lease: ConnectorLeaseSnapshot {
                tenant_id: self.active_lease.fence.tenant_id,
                connector_id: self.active_lease.fence.connector_id,
                generation: self.active_lease.fence.generation.get(),
                boot_id: self.active_lease.fence.boot_id,
                lease_id: self.active_lease.fence.lease_id,
                lease_epoch: self.active_lease.fence.lease_epoch.get(),
                issued_at_millis: self.active_lease.issued_at_millis,
                expires_at_millis: self.active_lease.expires_at_millis,
                ttl_millis: self.active_lease.ttl_millis,
                status: self.active_lease.status,
                last_heartbeat: match self.active_lease.last_heartbeat {
                    Some(heartbeat) => Some(HeartbeatRecordSnapshot {
                        sequence: heartbeat.sequence,
                        state: heartbeat.state,
                        capacity_available: heartbeat.capacity_available,
                        ack: HeartbeatAckSnapshot {
                            sequence: heartbeat.ack.sequence,
                            lease_expires_at_millis: heartbeat.ack.lease_expires_at_millis,
                        },
                    }),
                    None => None,
                },
                last_heartbeat_at_millis: self.active_lease.last_heartbeat_at_millis,
            },
        }
    }

    #[must_use]
    pub const fn fence(self) -> ConnectorFence {
        self.active_lease.fence
    }

    #[must_use]
    pub const fn active_lease(self) -> ConnectorLease {
        self.active_lease
    }

    #[must_use]
    pub const fn adapter_kind(self) -> AdapterKind {
        self.adapter_kind
    }

    #[must_use]
    pub const fn spec_revision(self) -> Revision {
        self.spec_revision
    }

    #[must_use]
    pub const fn desired_state(self) -> ConnectorDesiredState {
        self.desired_state
    }

    /// Validates the compact active lease against an exact fence and server time.
    ///
    /// # Errors
    ///
    /// Returns the same stable fencing failures as [`Connector::validate_fence`].
    pub fn validate_fence(
        &self,
        fence: &ConnectorFence,
        now_millis: i64,
    ) -> Result<(), ConnectorError> {
        self.validate_fence_coordinates(fence)?;
        if now_millis >= self.active_lease.expires_at_millis {
            Err(ConnectorError::LeaseExpired)
        } else {
            Ok(())
        }
    }

    /// Applies the same heartbeat state machine as the full aggregate in constant space.
    ///
    /// # Errors
    ///
    /// Rejects stale fences/sequences, excessive cadence, server-derived states,
    /// expired leases, and impossible capacity.
    pub fn record_heartbeat(
        &mut self,
        fence: &ConnectorFence,
        sequence: u64,
        observed_at_millis: i64,
        state: ConnectorObservedState,
        capacity_available: u32,
        minimum_interval_millis: i64,
    ) -> Result<HeartbeatAck, ConnectorError> {
        self.validate_fence_coordinates(fence)?;
        match evaluate_heartbeat(
            &self.active_lease,
            sequence,
            observed_at_millis,
            state,
            capacity_available,
            self.max_concurrency,
            minimum_interval_millis,
            self.server_time_high_water_millis,
        )? {
            HeartbeatDisposition::Replay(ack) => Ok(ack),
            HeartbeatDisposition::Advance(ack) => {
                self.active_lease.expires_at_millis = ack.lease_expires_at_millis;
                self.active_lease.last_heartbeat = Some(HeartbeatRecord {
                    sequence,
                    state,
                    capacity_available,
                    ack,
                });
                self.active_lease.last_heartbeat_at_millis = Some(observed_at_millis);
                self.observed_state = state;
                self.server_time_high_water_millis = Some(observed_at_millis);
                Ok(ack)
            }
        }
    }

    fn validate_fence_coordinates(&self, fence: &ConnectorFence) -> Result<(), ConnectorError> {
        if fence.tenant_id != self.tenant_id {
            return Err(ConnectorError::WrongTenant);
        }
        if fence.connector_id != self.connector_id {
            return Err(ConnectorError::WrongConnector);
        }
        if fence.generation != self.generation
            || fence.boot_id != self.current_boot_id
            || *fence != self.active_lease.fence
        {
            return Err(ConnectorError::StaleLease);
        }
        Ok(())
    }
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
            server_time_high_water_millis: None,
            spec_revision: Revision::INITIAL,
            revisions: vec![initial_revision],
        })
    }

    /// Captures the connector specification, runtime replay fences, and append-only histories.
    #[must_use]
    pub fn snapshot(&self) -> ConnectorSnapshot {
        ConnectorSnapshot {
            tenant_id: self.tenant_id,
            connector_id: self.id,
            host_id: self.host_id,
            adapter_kind: self.adapter_kind,
            generation: self.generation.get(),
            desired_state: self.desired_state,
            observed_state: self.observed_state,
            max_concurrency: self.max_concurrency,
            boots: self
                .boots
                .iter()
                .map(|boot| ConnectorBootSnapshot {
                    tenant_id: boot.tenant_id,
                    connector_id: boot.parent_id,
                    boot_id: boot.boot_id,
                    generation: boot.generation.get(),
                    started_at_millis: boot.started_at_millis,
                    ended_at_millis: boot.ended_at_millis,
                })
                .collect(),
            current_boot_id: self.current_boot_id,
            leases: self
                .leases
                .iter()
                .map(|lease| ConnectorLeaseSnapshot {
                    tenant_id: lease.fence.tenant_id,
                    connector_id: lease.fence.connector_id,
                    generation: lease.fence.generation.get(),
                    boot_id: lease.fence.boot_id,
                    lease_id: lease.fence.lease_id,
                    lease_epoch: lease.fence.lease_epoch.get(),
                    issued_at_millis: lease.issued_at_millis,
                    expires_at_millis: lease.expires_at_millis,
                    ttl_millis: lease.ttl_millis,
                    status: lease.status,
                    last_heartbeat: lease
                        .last_heartbeat
                        .map(|heartbeat| HeartbeatRecordSnapshot {
                            sequence: heartbeat.sequence,
                            state: heartbeat.state,
                            capacity_available: heartbeat.capacity_available,
                            ack: HeartbeatAckSnapshot {
                                sequence: heartbeat.ack.sequence,
                                lease_expires_at_millis: heartbeat.ack.lease_expires_at_millis,
                            },
                        }),
                    last_heartbeat_at_millis: lease.last_heartbeat_at_millis,
                })
                .collect(),
            active_lease_index: self.active_lease_index,
            highest_lease_epoch: self.highest_lease_epoch.map(LeaseEpoch::get),
            server_time_high_water_millis: self.server_time_high_water_millis,
            spec_revision: self.spec_revision,
            revisions: self
                .revisions
                .iter()
                .map(|revision| ConnectorRevisionSnapshot {
                    tenant_id: revision.tenant_id,
                    connector_id: revision.connector_id,
                    revision: revision.revision,
                    generation: revision.generation.get(),
                    adapter_kind: revision.adapter_kind,
                    desired_state: revision.desired_state,
                    max_concurrency: revision.max_concurrency,
                })
                .collect(),
        }
    }

    /// Rehydrates a connector only after validating every structural and fencing invariant.
    ///
    /// # Errors
    ///
    /// Rejects invalid counters/capacity, broken immutable histories, incorrect
    /// current pointers, impossible heartbeat replay state, or regressed high-water time.
    #[allow(clippy::too_many_lines, clippy::needless_pass_by_value)] // One fail-closed audit boundary consumes the durable image.
    pub fn try_from_snapshot(snapshot: ConnectorSnapshot) -> Result<Self, ConnectorSnapshotError> {
        let generation = snapshot_generation(snapshot.generation)?;
        if snapshot.max_concurrency == 0 {
            return Err(ConnectorSnapshotError::InvalidCapacity);
        }
        if snapshot.revisions.len() as u64 != snapshot.spec_revision.get()
            || snapshot.revisions.is_empty()
        {
            return Err(ConnectorSnapshotError::InvalidRevisionHistory);
        }
        let mut revisions = Vec::with_capacity(snapshot.revisions.len());
        for (index, revision) in snapshot.revisions.iter().enumerate() {
            if revision.tenant_id != snapshot.tenant_id
                || revision.connector_id != snapshot.connector_id
                || revision.revision.get() != index as u64 + 1
                || revision.adapter_kind != snapshot.adapter_kind
                || revision.max_concurrency != snapshot.max_concurrency
                || revision.generation == 0
                || revision.generation > snapshot.generation
            {
                return Err(ConnectorSnapshotError::InvalidRevisionHistory);
            }
            if index == 0
                && (revision.generation != ConnectorGeneration::INITIAL.get()
                    || revision.desired_state != ConnectorDesiredState::Running)
            {
                return Err(ConnectorSnapshotError::InvalidRevisionHistory);
            }
            if index > 0 {
                let previous = snapshot.revisions[index - 1];
                let valid_transition = if revision.generation == previous.generation {
                    (previous.desired_state == revision.desired_state
                        && matches!(
                            revision.desired_state,
                            ConnectorDesiredState::Running | ConnectorDesiredState::Draining
                        ))
                        || valid_desired_transition(previous.desired_state, revision.desired_state)
                } else {
                    previous
                        .generation
                        .checked_add(1)
                        .is_some_and(|next| revision.generation == next)
                        && revision.desired_state == previous.desired_state
                };
                if !valid_transition {
                    return Err(ConnectorSnapshotError::InvalidRevisionHistory);
                }
            }
            revisions.push(ConnectorRevision {
                tenant_id: revision.tenant_id,
                connector_id: revision.connector_id,
                revision: revision.revision,
                generation: snapshot_generation(revision.generation)?,
                adapter_kind: revision.adapter_kind,
                desired_state: revision.desired_state,
                max_concurrency: revision.max_concurrency,
            });
        }
        let current_revision = snapshot
            .revisions
            .last()
            .ok_or(ConnectorSnapshotError::InvalidRevisionHistory)?;
        if current_revision.generation != snapshot.generation
            || current_revision.desired_state != snapshot.desired_state
        {
            return Err(ConnectorSnapshotError::InvalidRevisionHistory);
        }

        let mut seen_boot_ids = std::collections::BTreeSet::new();
        let mut boots = Vec::with_capacity(snapshot.boots.len());
        for (index, boot) in snapshot.boots.iter().enumerate() {
            if boot.tenant_id != snapshot.tenant_id
                || boot.connector_id != snapshot.connector_id
                || boot.generation == 0
                || boot.generation > snapshot.generation
                || !seen_boot_ids.insert(boot.boot_id)
                || boot
                    .ended_at_millis
                    .is_some_and(|ended| ended < boot.started_at_millis)
                || (index + 1 < snapshot.boots.len() && boot.ended_at_millis.is_none())
            {
                return Err(ConnectorSnapshotError::InvalidBootHistory);
            }
            if let Some(previous) = snapshot.boots.get(index.wrapping_sub(1))
                && index > 0
                && (boot.generation < previous.generation
                    || boot.started_at_millis
                        < previous
                            .ended_at_millis
                            .unwrap_or(previous.started_at_millis))
            {
                return Err(ConnectorSnapshotError::InvalidBootHistory);
            }
            boots.push(ConnectorBoot {
                tenant_id: boot.tenant_id,
                parent_id: boot.connector_id,
                boot_id: boot.boot_id,
                generation: snapshot_generation(boot.generation)?,
                started_at_millis: boot.started_at_millis,
                ended_at_millis: boot.ended_at_millis,
            });
        }
        let open_boot_id = snapshot
            .boots
            .last()
            .filter(|boot| boot.ended_at_millis.is_none())
            .map(|boot| boot.boot_id);
        if snapshot.current_boot_id != open_boot_id
            || open_boot_id.is_some_and(|_| {
                !matches!(
                    snapshot.desired_state,
                    ConnectorDesiredState::Running | ConnectorDesiredState::Draining
                ) || snapshot
                    .boots
                    .last()
                    .is_none_or(|boot| boot.generation != snapshot.generation)
            })
        {
            return Err(ConnectorSnapshotError::InvalidCurrentBoot);
        }

        let mut seen_lease_ids = std::collections::BTreeSet::new();
        let mut leases = Vec::with_capacity(snapshot.leases.len());
        let mut active_index = None;
        for (index, lease) in snapshot.leases.iter().enumerate() {
            let matching_boot = snapshot
                .boots
                .iter()
                .find(|boot| boot.boot_id == lease.boot_id && boot.generation == lease.generation);
            if lease.tenant_id != snapshot.tenant_id
                || lease.connector_id != snapshot.connector_id
                || lease.generation == 0
                || lease.generation > snapshot.generation
                || lease.lease_epoch != index as u64 + 1
                || !(1..=MAX_LEASE_TTL_MILLIS).contains(&lease.ttl_millis)
                || lease.expires_at_millis
                    < lease
                        .issued_at_millis
                        .checked_add(lease.ttl_millis)
                        .ok_or(ConnectorSnapshotError::InvalidLeaseHistory)?
                || !seen_lease_ids.insert(lease.lease_id)
                || matching_boot.is_none()
                || matching_boot.is_some_and(|boot| lease.issued_at_millis < boot.started_at_millis)
                || matching_boot.is_some_and(|boot| {
                    boot.ended_at_millis
                        .is_some_and(|ended| lease.issued_at_millis > ended)
                })
                || snapshot
                    .leases
                    .get(index.wrapping_sub(1))
                    .is_some_and(|previous| {
                        index > 0 && lease.issued_at_millis < previous.issued_at_millis
                    })
            {
                return Err(ConnectorSnapshotError::InvalidLeaseHistory);
            }
            if lease.status == LeaseStatus::Active && active_index.replace(index).is_some() {
                return Err(ConnectorSnapshotError::InvalidActiveLease);
            }
            let fence = ConnectorFence {
                tenant_id: lease.tenant_id,
                connector_id: lease.connector_id,
                generation: snapshot_generation(lease.generation)?,
                boot_id: lease.boot_id,
                lease_id: lease.lease_id,
                lease_epoch: snapshot_epoch(lease.lease_epoch)?,
            };
            let last_heartbeat = snapshot_heartbeat(lease, snapshot.max_concurrency)?;
            leases.push(ConnectorLease {
                fence,
                issued_at_millis: lease.issued_at_millis,
                expires_at_millis: lease.expires_at_millis,
                ttl_millis: lease.ttl_millis,
                status: lease.status,
                last_heartbeat,
                last_heartbeat_at_millis: lease.last_heartbeat_at_millis,
            });
        }
        if snapshot.active_lease_index != active_index
            || snapshot.highest_lease_epoch
                != (!snapshot.leases.is_empty()).then_some(snapshot.leases.len() as u64)
        {
            return Err(ConnectorSnapshotError::InvalidActiveLease);
        }
        if active_index.is_some_and(|index| index + 1 != snapshot.leases.len()) {
            return Err(ConnectorSnapshotError::InvalidActiveLease);
        }
        if let Some(index) = active_index {
            let lease = &snapshot.leases[index];
            if snapshot.current_boot_id != Some(lease.boot_id)
                || lease.generation != snapshot.generation
            {
                return Err(ConnectorSnapshotError::InvalidActiveLease);
            }
        }
        if matches!(
            snapshot.desired_state,
            ConnectorDesiredState::Stopped | ConnectorDesiredState::Revoked
        ) && (snapshot.current_boot_id.is_some() || active_index.is_some())
        {
            return Err(ConnectorSnapshotError::InvalidTerminalState);
        }
        if snapshot.desired_state == ConnectorDesiredState::Revoked
            && snapshot.observed_state != ConnectorObservedState::Revoked
        {
            return Err(ConnectorSnapshotError::InvalidTerminalState);
        }
        if snapshot.desired_state == ConnectorDesiredState::Stopped
            && snapshot.observed_state != ConnectorObservedState::Offline
        {
            return Err(ConnectorSnapshotError::InvalidTerminalState);
        }

        let high_water = snapshot.server_time_high_water_millis;
        let time_exceeds_high_water = snapshot
            .boots
            .iter()
            .flat_map(|boot| [Some(boot.started_at_millis), boot.ended_at_millis])
            .flatten()
            .chain(snapshot.leases.iter().map(|lease| lease.issued_at_millis))
            .chain(
                snapshot
                    .leases
                    .iter()
                    .filter_map(|lease| lease.last_heartbeat_at_millis),
            )
            .any(|time| high_water.is_none_or(|high| time > high));
        if time_exceeds_high_water {
            return Err(ConnectorSnapshotError::InvalidServerTimeHighWater);
        }
        if snapshot.leases.iter().any(|lease| {
            lease.status == LeaseStatus::Expired
                && high_water.is_none_or(|high| high < lease.expires_at_millis)
        }) {
            return Err(ConnectorSnapshotError::InvalidServerTimeHighWater);
        }

        Ok(Self {
            tenant_id: snapshot.tenant_id,
            id: snapshot.connector_id,
            host_id: snapshot.host_id,
            adapter_kind: snapshot.adapter_kind,
            generation,
            desired_state: snapshot.desired_state,
            observed_state: snapshot.observed_state,
            max_concurrency: snapshot.max_concurrency,
            boots,
            current_boot_id: snapshot.current_boot_id,
            leases,
            active_lease_index: snapshot.active_lease_index,
            highest_lease_epoch: snapshot
                .highest_lease_epoch
                .map(snapshot_epoch)
                .transpose()?,
            server_time_high_water_millis: snapshot.server_time_high_water_millis,
            spec_revision: snapshot.spec_revision,
            revisions,
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
        if ttl_millis > MAX_LEASE_TTL_MILLIS {
            return Err(ConnectorError::InvalidLeaseWindow);
        }
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
            .leases
            .last()
            .and_then(|lease| lease.last_heartbeat_at_millis)
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
            last_heartbeat: None,
            last_heartbeat_at_millis: None,
        });
        self.active_lease_index = Some(self.leases.len() - 1);
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
        minimum_interval_millis: i64,
    ) -> Result<HeartbeatAck, ConnectorError> {
        let current = self.validate_fence_coordinates(fence)?;
        let ack = match evaluate_heartbeat(
            current,
            sequence,
            observed_at_millis,
            state,
            capacity_available,
            self.max_concurrency,
            minimum_interval_millis,
            self.server_time_high_water_millis,
        )? {
            HeartbeatDisposition::Replay(ack) => return Ok(ack),
            HeartbeatDisposition::Advance(ack) => ack,
        };
        let lease = self
            .active_lease_index
            .and_then(|index| self.leases.get_mut(index))
            .ok_or(ConnectorError::StaleLease)?;
        lease.expires_at_millis = ack.lease_expires_at_millis;
        lease.last_heartbeat = Some(HeartbeatRecord {
            sequence,
            state,
            capacity_available,
            ack,
        });
        lease.last_heartbeat_at_millis = Some(observed_at_millis);
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
        self.observed_state = ConnectorObservedState::Offline;
        self.advance_server_time_high_water(changed_at_millis);
        self.append_current_revision();
        Ok(self.generation)
    }

    /// Advances a non-terminal configuration revision while preserving the active lease.
    ///
    /// The exact adapter/runtime configuration is retained by the durable control-command
    /// log. This aggregate owns only its monotonic spec fence and desired lifecycle state.
    /// Stop and revoke are deliberately excluded because their transition is completed only
    /// after the Connector acknowledges the durable terminal command.
    ///
    /// # Errors
    ///
    /// Rejects stale revisions, terminal targets, invalid lifecycle transitions, revocation,
    /// exhausted counters, or regressed server time.
    pub fn revise_live_configuration(
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
        if !matches!(
            desired_state,
            ConnectorDesiredState::Running | ConnectorDesiredState::Draining
        ) || (self.desired_state != desired_state
            && !valid_desired_transition(self.desired_state, desired_state))
        {
            return Err(ConnectorError::InvalidDesiredTransition);
        }
        self.ensure_server_time_not_regressed(changed_at_millis)?;
        let next_revision = self
            .spec_revision
            .checked_next()
            .map_err(|_| ConnectorError::CounterExhausted)?;
        self.spec_revision = next_revision;
        self.desired_state = desired_state;
        if desired_state == ConnectorDesiredState::Draining {
            self.observed_state = ConnectorObservedState::Draining;
        }
        self.advance_server_time_high_water(changed_at_millis);
        self.append_current_revision();
        Ok(next_revision)
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
                self.observed_state = ConnectorObservedState::Offline;
            }
            ConnectorDesiredState::Revoked => {
                self.close_current_boot(changed_at_millis);
                self.current_boot_id = None;
                self.terminalize_active_lease(LeaseStatus::Revoked);
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
    HeartbeatTooFrequent,
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
            Self::HeartbeatTooFrequent => "connector heartbeat cadence exceeded the server limit",
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

fn snapshot_generation(value: u64) -> Result<ConnectorGeneration, ConnectorSnapshotError> {
    if value == 0 || value > Revision::MAX {
        Err(ConnectorSnapshotError::InvalidGeneration)
    } else {
        Ok(ConnectorGeneration(value))
    }
}

fn valid_desired_transition(
    previous: ConnectorDesiredState,
    current: ConnectorDesiredState,
) -> bool {
    matches!(
        (previous, current),
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
    )
}

fn snapshot_epoch(value: u64) -> Result<LeaseEpoch, ConnectorSnapshotError> {
    if value == 0 || value > Revision::MAX {
        Err(ConnectorSnapshotError::InvalidLeaseHistory)
    } else {
        Ok(LeaseEpoch(value))
    }
}

fn snapshot_heartbeat(
    lease: &ConnectorLeaseSnapshot,
    max_concurrency: u32,
) -> Result<Option<HeartbeatRecord>, ConnectorSnapshotError> {
    match (lease.last_heartbeat, lease.last_heartbeat_at_millis) {
        (None, None) => {
            if lease
                .issued_at_millis
                .checked_add(lease.ttl_millis)
                .is_none_or(|initial_expiry| initial_expiry != lease.expires_at_millis)
            {
                return Err(ConnectorSnapshotError::InvalidHeartbeat);
            }
            Ok(None)
        }
        (Some(heartbeat), Some(observed_at)) => {
            if heartbeat.sequence == 0
                || heartbeat.sequence > Revision::MAX
                || heartbeat.capacity_available > max_concurrency
                || matches!(
                    heartbeat.state,
                    ConnectorObservedState::Offline | ConnectorObservedState::Revoked
                )
                || observed_at < lease.issued_at_millis
                || heartbeat.ack.sequence != heartbeat.sequence
                || heartbeat.ack.lease_expires_at_millis != lease.expires_at_millis
                || observed_at
                    .checked_add(lease.ttl_millis)
                    .is_none_or(|expected| expected != lease.expires_at_millis)
            {
                return Err(ConnectorSnapshotError::InvalidHeartbeat);
            }
            Ok(Some(HeartbeatRecord {
                sequence: heartbeat.sequence,
                state: heartbeat.state,
                capacity_available: heartbeat.capacity_available,
                ack: HeartbeatAck {
                    sequence: heartbeat.ack.sequence,
                    lease_expires_at_millis: heartbeat.ack.lease_expires_at_millis,
                },
            }))
        }
        _ => Err(ConnectorSnapshotError::InvalidHeartbeat),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeartbeatDisposition {
    Replay(HeartbeatAck),
    Advance(HeartbeatAck),
}

#[allow(clippy::too_many_arguments)]
fn evaluate_heartbeat(
    current: &ConnectorLease,
    sequence: u64,
    observed_at_millis: i64,
    state: ConnectorObservedState,
    capacity_available: u32,
    max_concurrency: u32,
    minimum_interval_millis: i64,
    server_time_high_water_millis: Option<i64>,
) -> Result<HeartbeatDisposition, ConnectorError> {
    if observed_at_millis < current.issued_at_millis || minimum_interval_millis <= 0 {
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
    if capacity_available > max_concurrency {
        return Err(ConnectorError::InvalidCapacity);
    }
    if let Some(previous) = current.last_heartbeat {
        if sequence < previous.sequence {
            return Err(ConnectorError::StaleHeartbeat);
        }
        if sequence == previous.sequence {
            return if previous.state == state && previous.capacity_available == capacity_available {
                Ok(HeartbeatDisposition::Replay(previous.ack))
            } else {
                Err(ConnectorError::HeartbeatConflict)
            };
        }
        if current
            .last_heartbeat_at_millis
            .is_some_and(|last_seen| observed_at_millis < last_seen)
        {
            return Err(ConnectorError::InvalidHeartbeatTime);
        }
        if current.last_heartbeat_at_millis.is_some_and(|last_seen| {
            observed_at_millis
                .checked_sub(last_seen)
                .is_none_or(|elapsed| elapsed < minimum_interval_millis)
        }) {
            return Err(ConnectorError::HeartbeatTooFrequent);
        }
    }
    if server_time_high_water_millis.is_some_and(|high_water| observed_at_millis < high_water) {
        return Err(ConnectorError::ServerTimeRegressed);
    }
    if observed_at_millis >= current.expires_at_millis {
        return Err(ConnectorError::LeaseExpired);
    }
    let lease_expires_at_millis = observed_at_millis
        .checked_add(current.ttl_millis)
        .ok_or(ConnectorError::InvalidHeartbeatTime)?;
    Ok(HeartbeatDisposition::Advance(HeartbeatAck {
        sequence,
        lease_expires_at_millis,
    }))
}

/// Stable rejection for an invalid durable connector image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorSnapshotError {
    InvalidGeneration,
    InvalidCapacity,
    InvalidRevisionHistory,
    InvalidBootHistory,
    InvalidCurrentBoot,
    InvalidLeaseHistory,
    InvalidActiveLease,
    InvalidHeartbeat,
    InvalidTerminalState,
    InvalidServerTimeHighWater,
}

impl fmt::Display for ConnectorSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGeneration => "connector snapshot generation is invalid",
            Self::InvalidCapacity => "connector snapshot capacity is invalid",
            Self::InvalidRevisionHistory => "connector snapshot revision history is invalid",
            Self::InvalidBootHistory => "connector snapshot boot history is invalid",
            Self::InvalidCurrentBoot => "connector snapshot current boot pointer is invalid",
            Self::InvalidLeaseHistory => "connector snapshot lease history is invalid",
            Self::InvalidActiveLease => "connector snapshot active lease pointer is invalid",
            Self::InvalidHeartbeat => "connector snapshot heartbeat replay fence is invalid",
            Self::InvalidTerminalState => "connector snapshot terminal state is invalid",
            Self::InvalidServerTimeHighWater => {
                "connector snapshot server time high-water is invalid"
            }
        })
    }
}

impl Error for ConnectorSnapshotError {}
