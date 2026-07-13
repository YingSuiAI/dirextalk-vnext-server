#![forbid(unsafe_code)]

//! Storage-independent routing state for one explicitly targeted Agent Run.
//!
//! An offer is never execution authority. A Connector may execute only after
//! the server atomically grants a [`RunLease`]. Losing that lease fences the
//! Run into reconciliation; MC3 deliberately does not auto-fail over work that
//! might already have executed.

use std::{collections::BTreeSet, error::Error, fmt};

use dtx_connect_registry::{BindingSet, BindingState, ConnectorFence, RoutingPolicy};
use dtx_domain::{
    BindingId, BootId, ConnectorId, ConversationId, EventId, InstallationId, LeaseId, RequestId,
    Revision, RunId, RunLeaseId, RunOfferId, TenantId,
};

/// Maximum immutable routes captured for one Run.
pub const MAX_ROUTE_CANDIDATES: usize = 64;
/// Maximum capability codes required by one Run.
pub const MAX_REQUIRED_CAPABILITIES: usize = 64;
/// Maximum offer or Run-lease lifetime accepted by the domain.
pub const MAX_ROUTING_LEASE_TTL_MILLIS: i64 = 300_000;

/// The only implicit dispatch modes admitted by MC3.
///
/// Broadcast, race, and workflow are intentionally not representable here.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DispatchMode {
    Single,
    Failover,
}

/// Durable routing lifecycle owned by MC3.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RunRoutingState {
    Queued,
    Offered,
    Leased,
    ReconcileRequired,
    Expired,
}

/// Complete current Connector-control fence copied into every Run mutation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectorLeaseFence {
    tenant_id: TenantId,
    connector_id: ConnectorId,
    boot_id: BootId,
    connector_generation: u64,
    connector_lease_id: LeaseId,
    connector_lease_epoch: u64,
}

impl ConnectorLeaseFence {
    /// Rehydrates a validated Connector-control fence.
    ///
    /// # Errors
    ///
    /// Rejects zero or non-portable generation and epoch values.
    pub const fn new(
        tenant_id: TenantId,
        connector_id: ConnectorId,
        boot_id: BootId,
        connector_generation: u64,
        connector_lease_id: LeaseId,
        connector_lease_epoch: u64,
    ) -> Result<Self, RouterError> {
        if connector_generation == 0
            || connector_generation > Revision::MAX
            || connector_lease_epoch == 0
            || connector_lease_epoch > Revision::MAX
        {
            return Err(RouterError::InvalidConnectorFence);
        }
        Ok(Self {
            tenant_id,
            connector_id,
            boot_id,
            connector_generation,
            connector_lease_id,
            connector_lease_epoch,
        })
    }

    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn connector_id(self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn boot_id(self) -> BootId {
        self.boot_id
    }

    #[must_use]
    pub const fn connector_generation(self) -> u64 {
        self.connector_generation
    }

    #[must_use]
    pub const fn connector_lease_id(self) -> LeaseId {
        self.connector_lease_id
    }

    #[must_use]
    pub const fn connector_lease_epoch(self) -> u64 {
        self.connector_lease_epoch
    }
}

impl From<ConnectorFence> for ConnectorLeaseFence {
    fn from(value: ConnectorFence) -> Self {
        Self {
            tenant_id: value.tenant_id(),
            connector_id: value.connector_id(),
            boot_id: value.boot_id(),
            connector_generation: value.generation().get(),
            connector_lease_id: value.lease_id(),
            connector_lease_epoch: value.lease_epoch().get(),
        }
    }
}

/// One immutable Binding candidate captured when the Run is created.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RouteCandidate {
    binding_id: BindingId,
    connector_id: ConnectorId,
    priority: u16,
    max_concurrency: u32,
}

impl RouteCandidate {
    /// Creates one bounded route candidate.
    ///
    /// # Errors
    ///
    /// Rejects a zero concurrency ceiling.
    pub const fn new(
        binding_id: BindingId,
        connector_id: ConnectorId,
        priority: u16,
        max_concurrency: u32,
    ) -> Result<Self, RouterError> {
        if max_concurrency == 0 {
            return Err(RouterError::InvalidCandidate);
        }
        Ok(Self {
            binding_id,
            connector_id,
            priority,
            max_concurrency,
        })
    }

    #[must_use]
    pub const fn binding_id(self) -> BindingId {
        self.binding_id
    }

    #[must_use]
    pub const fn connector_id(self) -> ConnectorId {
        self.connector_id
    }

    #[must_use]
    pub const fn priority(self) -> u16 {
        self.priority
    }

    #[must_use]
    pub const fn max_concurrency(self) -> u32 {
        self.max_concurrency
    }
}

/// Immutable routing policy and ordered candidate snapshot resolved at Run creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePlan {
    routing_policy: RoutingPolicy,
    routing_policy_revision: Revision,
    candidates: Vec<RouteCandidate>,
}

impl RoutePlan {
    #[must_use]
    pub const fn routing_policy(&self) -> RoutingPolicy {
        self.routing_policy
    }

    #[must_use]
    pub const fn routing_policy_revision(&self) -> Revision {
        self.routing_policy_revision
    }

    #[must_use]
    pub fn candidates(&self) -> &[RouteCandidate] {
        &self.candidates
    }

    #[must_use]
    pub fn into_candidates(self) -> Vec<RouteCandidate> {
        self.candidates
    }
}

/// Resolves one explicit Installation target into an immutable candidate plan.
///
/// Single dispatch snapshots exactly one route. Ordered failover snapshots only
/// enabled routes in strict priority order. When a preferred Connector is
/// supplied, it becomes the first candidate; lower-priority predecessors are
/// deliberately excluded so an explicit preference is never silently ignored.
///
/// # Errors
///
/// Rejects a foreign tenant, absent/disabled target, incompatible failover
/// policy, or a preferred Connector outside the Installation binding set.
pub fn resolve_route_plan(
    binding_set: &BindingSet,
    tenant_id: TenantId,
    installation_id: InstallationId,
    preferred_connector_id: Option<ConnectorId>,
    dispatch_mode: DispatchMode,
) -> Result<RoutePlan, RouterError> {
    let snapshot = binding_set.snapshot();
    if snapshot.tenant_id != tenant_id {
        return Err(RouterError::InvalidCandidate);
    }
    let policy = snapshot
        .routing_policies
        .into_iter()
        .find(|candidate| candidate.installation_id == installation_id)
        .ok_or(RouterError::InvalidCandidate)?;
    if dispatch_mode == DispatchMode::Failover && policy.policy != RoutingPolicy::OrderedFailover {
        return Err(RouterError::PolicyMismatch);
    }

    let mut candidates = snapshot
        .bindings
        .into_iter()
        .filter(|binding| {
            binding.installation_id == installation_id && binding.state == BindingState::Enabled
        })
        .map(|binding| {
            RouteCandidate::new(
                binding.binding_id,
                binding.connector_id,
                binding.priority,
                binding.max_concurrency,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    candidates.sort_unstable_by_key(|candidate| (candidate.priority(), candidate.binding_id()));
    if candidates.is_empty() || candidates.len() > MAX_ROUTE_CANDIDATES {
        return Err(RouterError::InvalidCandidate);
    }

    let preferred_index = preferred_connector_id
        .map(|preferred| {
            candidates
                .iter()
                .position(|candidate| candidate.connector_id() == preferred)
                .ok_or(RouterError::InvalidCandidate)
        })
        .transpose()?;
    candidates = match dispatch_mode {
        DispatchMode::Single => vec![candidates[preferred_index.unwrap_or(0)]],
        DispatchMode::Failover => candidates.split_off(preferred_index.unwrap_or(0)),
    };

    Ok(RoutePlan {
        routing_policy: policy.policy,
        routing_policy_revision: policy.revision,
        candidates,
    })
}

/// Immutable, digest-only routing request. Prompt and output bytes live elsewhere.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRequest {
    tenant_id: TenantId,
    run_id: RunId,
    request_id: RequestId,
    idempotency_digest: [u8; 32],
    request_digest: [u8; 32],
    installation_id: InstallationId,
    conversation_id: ConversationId,
    request_event_id: EventId,
    preferred_connector_id: Option<ConnectorId>,
    required_capabilities: Vec<String>,
    dispatch_mode: DispatchMode,
    routing_policy: RoutingPolicy,
    routing_policy_revision: Revision,
    grant_version: u64,
    queue_deadline_millis: i64,
    created_at_millis: i64,
}

impl RunRequest {
    /// Creates one explicit, bounded, idempotent Run routing request.
    ///
    /// # Errors
    ///
    /// Rejects invalid server time, grant version, or capability names.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        run_id: RunId,
        request_id: RequestId,
        idempotency_digest: [u8; 32],
        request_digest: [u8; 32],
        installation_id: InstallationId,
        conversation_id: ConversationId,
        request_event_id: EventId,
        preferred_connector_id: Option<ConnectorId>,
        mut required_capabilities: Vec<String>,
        dispatch_mode: DispatchMode,
        routing_policy: RoutingPolicy,
        routing_policy_revision: Revision,
        grant_version: u64,
        queue_deadline_millis: i64,
        created_at_millis: i64,
    ) -> Result<Self, RouterError> {
        if !valid_time(created_at_millis)
            || !valid_time(queue_deadline_millis)
            || queue_deadline_millis <= created_at_millis
            || grant_version == 0
            || grant_version > Revision::MAX
            || required_capabilities.len() > MAX_REQUIRED_CAPABILITIES
            || required_capabilities
                .iter()
                .any(|capability| !valid_stable_name(capability))
        {
            return Err(RouterError::InvalidRequest);
        }
        required_capabilities.sort_unstable();
        if required_capabilities
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(RouterError::InvalidRequest);
        }
        Ok(Self {
            tenant_id,
            run_id,
            request_id,
            idempotency_digest,
            request_digest,
            installation_id,
            conversation_id,
            request_event_id,
            preferred_connector_id,
            required_capabilities,
            dispatch_mode,
            routing_policy,
            routing_policy_revision,
            grant_version,
            queue_deadline_millis,
            created_at_millis,
        })
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    #[must_use]
    pub const fn idempotency_digest(&self) -> [u8; 32] {
        self.idempotency_digest
    }

    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    #[must_use]
    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }

    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    #[must_use]
    pub const fn request_event_id(&self) -> EventId {
        self.request_event_id
    }

    #[must_use]
    pub const fn preferred_connector_id(&self) -> Option<ConnectorId> {
        self.preferred_connector_id
    }

    #[must_use]
    pub fn required_capabilities(&self) -> &[String] {
        &self.required_capabilities
    }

    #[must_use]
    pub const fn dispatch_mode(&self) -> DispatchMode {
        self.dispatch_mode
    }

    #[must_use]
    pub const fn routing_policy(&self) -> RoutingPolicy {
        self.routing_policy
    }

    #[must_use]
    pub const fn routing_policy_revision(&self) -> Revision {
        self.routing_policy_revision
    }

    #[must_use]
    pub const fn grant_version(&self) -> u64 {
        self.grant_version
    }

    #[must_use]
    pub const fn queue_deadline_millis(&self) -> i64 {
        self.queue_deadline_millis
    }

    #[must_use]
    pub const fn created_at_millis(&self) -> i64 {
        self.created_at_millis
    }
}

/// One durable offer. Receiving it does not authorize execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunOffer {
    offer_id: RunOfferId,
    attempt: u64,
    candidate_index: u16,
    connector_fence: ConnectorLeaseFence,
    offered_at_millis: i64,
    expires_at_millis: i64,
}

/// Storage representation of one validated Run offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunOfferSnapshot {
    pub offer_id: RunOfferId,
    pub attempt: u64,
    pub candidate_index: u16,
    pub connector_fence: ConnectorLeaseFence,
    pub offered_at_millis: i64,
    pub expires_at_millis: i64,
}

impl RunOffer {
    /// Rehydrates one structurally valid offer; the owning Run validates its
    /// candidate, tenant, deadline, and monotonic counters.
    ///
    /// # Errors
    ///
    /// Rejects invalid counters or an invalid bounded offer window.
    pub fn try_from_snapshot(snapshot: RunOfferSnapshot) -> Result<Self, RouterError> {
        if snapshot.attempt == 0
            || snapshot.attempt > Revision::MAX
            || !valid_time(snapshot.offered_at_millis)
            || !valid_time(snapshot.expires_at_millis)
            || snapshot.expires_at_millis <= snapshot.offered_at_millis
            || snapshot.expires_at_millis - snapshot.offered_at_millis
                > MAX_ROUTING_LEASE_TTL_MILLIS
        {
            return Err(RouterError::InvalidSnapshot);
        }
        Ok(Self {
            offer_id: snapshot.offer_id,
            attempt: snapshot.attempt,
            candidate_index: snapshot.candidate_index,
            connector_fence: snapshot.connector_fence,
            offered_at_millis: snapshot.offered_at_millis,
            expires_at_millis: snapshot.expires_at_millis,
        })
    }

    #[must_use]
    pub const fn snapshot(self) -> RunOfferSnapshot {
        RunOfferSnapshot {
            offer_id: self.offer_id,
            attempt: self.attempt,
            candidate_index: self.candidate_index,
            connector_fence: self.connector_fence,
            offered_at_millis: self.offered_at_millis,
            expires_at_millis: self.expires_at_millis,
        }
    }

    #[must_use]
    pub const fn offer_id(self) -> RunOfferId {
        self.offer_id
    }

    #[must_use]
    pub const fn attempt(self) -> u64 {
        self.attempt
    }

    #[must_use]
    pub const fn candidate_index(self) -> u16 {
        self.candidate_index
    }

    #[must_use]
    pub const fn connector_fence(self) -> ConnectorLeaseFence {
        self.connector_fence
    }

    #[must_use]
    pub const fn offered_at_millis(self) -> i64 {
        self.offered_at_millis
    }

    #[must_use]
    pub const fn expires_at_millis(self) -> i64 {
        self.expires_at_millis
    }
}

/// The only execution authority for one Run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunLease {
    id: RunLeaseId,
    epoch: u64,
    offer_id: RunOfferId,
    offer_attempt: u64,
    candidate_index: u16,
    connector_fence: ConnectorLeaseFence,
    issued_at_millis: i64,
    expires_at_millis: i64,
}

/// Storage representation of one validated Run execution lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunLeaseSnapshot {
    pub run_lease_id: RunLeaseId,
    pub run_lease_epoch: u64,
    pub offer_id: RunOfferId,
    pub offer_attempt: u64,
    pub candidate_index: u16,
    pub connector_fence: ConnectorLeaseFence,
    pub issued_at_millis: i64,
    pub expires_at_millis: i64,
}

impl RunLease {
    /// Rehydrates one structurally valid execution lease; the owning Run
    /// validates its corresponding offer, candidate, and high-water counters.
    ///
    /// # Errors
    ///
    /// Rejects invalid counters or an invalid bounded lease window.
    pub fn try_from_snapshot(snapshot: RunLeaseSnapshot) -> Result<Self, RouterError> {
        if snapshot.run_lease_epoch == 0
            || snapshot.run_lease_epoch > Revision::MAX
            || snapshot.offer_attempt == 0
            || snapshot.offer_attempt > Revision::MAX
            || !valid_time(snapshot.issued_at_millis)
            || !valid_time(snapshot.expires_at_millis)
            || snapshot.expires_at_millis <= snapshot.issued_at_millis
            || snapshot.expires_at_millis - snapshot.issued_at_millis > MAX_ROUTING_LEASE_TTL_MILLIS
        {
            return Err(RouterError::InvalidSnapshot);
        }
        Ok(Self {
            id: snapshot.run_lease_id,
            epoch: snapshot.run_lease_epoch,
            offer_id: snapshot.offer_id,
            offer_attempt: snapshot.offer_attempt,
            candidate_index: snapshot.candidate_index,
            connector_fence: snapshot.connector_fence,
            issued_at_millis: snapshot.issued_at_millis,
            expires_at_millis: snapshot.expires_at_millis,
        })
    }

    #[must_use]
    pub const fn snapshot(self) -> RunLeaseSnapshot {
        RunLeaseSnapshot {
            run_lease_id: self.id,
            run_lease_epoch: self.epoch,
            offer_id: self.offer_id,
            offer_attempt: self.offer_attempt,
            candidate_index: self.candidate_index,
            connector_fence: self.connector_fence,
            issued_at_millis: self.issued_at_millis,
            expires_at_millis: self.expires_at_millis,
        }
    }

    #[must_use]
    pub const fn run_lease_id(self) -> RunLeaseId {
        self.id
    }

    #[must_use]
    pub const fn run_lease_epoch(self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub const fn offer_id(self) -> RunOfferId {
        self.offer_id
    }

    #[must_use]
    pub const fn offer_attempt(self) -> u64 {
        self.offer_attempt
    }

    #[must_use]
    pub const fn candidate_index(self) -> u16 {
        self.candidate_index
    }

    #[must_use]
    pub const fn connector_fence(self) -> ConnectorLeaseFence {
        self.connector_fence
    }

    #[must_use]
    pub const fn issued_at_millis(self) -> i64 {
        self.issued_at_millis
    }

    #[must_use]
    pub const fn expires_at_millis(self) -> i64 {
        self.expires_at_millis
    }
}

/// Exact retry disposition for an offer or claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteDisposition<T> {
    Inserted(T),
    Existing(T),
}

impl<T: Copy> WriteDisposition<T> {
    #[must_use]
    pub const fn value(self) -> T {
        match self {
            Self::Inserted(value) | Self::Existing(value) => value,
        }
    }
}

/// Durable image used by the `PostgreSQL` adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRunSnapshot {
    pub request: RunRequest,
    pub candidates: Vec<RouteCandidate>,
    pub state: RunRoutingState,
    pub candidate_cursor: u16,
    pub current_offer: Option<RunOffer>,
    pub current_lease: Option<RunLease>,
    pub highest_offer_attempt: u64,
    pub highest_run_lease_epoch: u64,
    pub revision: Revision,
    pub updated_at_millis: i64,
    pub server_time_high_water_millis: i64,
}

/// Aggregate enforcing single-offer and single-lease routing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentRun {
    request: RunRequest,
    candidates: Vec<RouteCandidate>,
    state: RunRoutingState,
    candidate_cursor: u16,
    current_offer: Option<RunOffer>,
    current_lease: Option<RunLease>,
    highest_offer_attempt: u64,
    highest_run_lease_epoch: u64,
    revision: Revision,
    updated_at_millis: i64,
    server_time_high_water_millis: i64,
}

impl AgentRun {
    /// Persists a queued Run before any Connector can see an offer.
    ///
    /// # Errors
    ///
    /// Rejects ambiguous, duplicate, out-of-order, or policy-incompatible routes.
    pub fn create(
        request: RunRequest,
        candidates: Vec<RouteCandidate>,
    ) -> Result<Self, RouterError> {
        validate_candidates(&request, &candidates)?;
        let created_at_millis = request.created_at_millis;
        Ok(Self {
            request,
            candidates,
            state: RunRoutingState::Queued,
            candidate_cursor: 0,
            current_offer: None,
            current_lease: None,
            highest_offer_attempt: 0,
            highest_run_lease_epoch: 0,
            revision: Revision::INITIAL,
            updated_at_millis: created_at_millis,
            server_time_high_water_millis: created_at_millis,
        })
    }

    /// Rehydrates and validates a durable Run head and immutable candidates.
    ///
    /// # Errors
    ///
    /// Rejects any unreachable or internally inconsistent image.
    pub fn try_from_snapshot(snapshot: AgentRunSnapshot) -> Result<Self, RouterError> {
        validate_candidates(&snapshot.request, &snapshot.candidates)?;
        if usize::from(snapshot.candidate_cursor) >= snapshot.candidates.len()
            || snapshot.revision.get() == 0
            || snapshot.updated_at_millis < snapshot.request.created_at_millis
            || snapshot.server_time_high_water_millis < snapshot.updated_at_millis
            || !valid_time(snapshot.server_time_high_water_millis)
        {
            return Err(RouterError::InvalidSnapshot);
        }
        validate_state_image(&snapshot)?;
        Ok(Self {
            request: snapshot.request,
            candidates: snapshot.candidates,
            state: snapshot.state,
            candidate_cursor: snapshot.candidate_cursor,
            current_offer: snapshot.current_offer,
            current_lease: snapshot.current_lease,
            highest_offer_attempt: snapshot.highest_offer_attempt,
            highest_run_lease_epoch: snapshot.highest_run_lease_epoch,
            revision: snapshot.revision,
            updated_at_millis: snapshot.updated_at_millis,
            server_time_high_water_millis: snapshot.server_time_high_water_millis,
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> AgentRunSnapshot {
        AgentRunSnapshot {
            request: self.request.clone(),
            candidates: self.candidates.clone(),
            state: self.state,
            candidate_cursor: self.candidate_cursor,
            current_offer: self.current_offer,
            current_lease: self.current_lease,
            highest_offer_attempt: self.highest_offer_attempt,
            highest_run_lease_epoch: self.highest_run_lease_epoch,
            revision: self.revision,
            updated_at_millis: self.updated_at_millis,
            server_time_high_water_millis: self.server_time_high_water_millis,
        }
    }

    #[must_use]
    pub const fn request(&self) -> &RunRequest {
        &self.request
    }

    #[must_use]
    pub fn candidates(&self) -> &[RouteCandidate] {
        &self.candidates
    }

    #[must_use]
    pub const fn state(&self) -> RunRoutingState {
        self.state
    }

    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    #[must_use]
    pub const fn current_offer(&self) -> Option<RunOffer> {
        self.current_offer
    }

    #[must_use]
    pub const fn current_lease(&self) -> Option<RunLease> {
        self.current_lease
    }

    #[must_use]
    pub const fn candidate_cursor(&self) -> u16 {
        self.candidate_cursor
    }

    #[must_use]
    pub fn current_candidate(&self) -> RouteCandidate {
        self.candidates[self.candidate_cursor as usize]
    }

    /// Advances ordered failover after the Router proves the current candidate
    /// ineligible before an offer exists.
    ///
    /// # Errors
    ///
    /// Rejects single dispatch, a non-queued Run, or server-time rollback.
    pub fn skip_ineligible_candidate(&mut self, now_millis: i64) -> Result<(), RouterError> {
        self.ensure_time(now_millis)?;
        if self.state != RunRoutingState::Queued
            || self.request.dispatch_mode != DispatchMode::Failover
        {
            return Err(RouterError::InvalidTransition);
        }
        self.candidate_cursor = self
            .candidate_cursor
            .checked_add(1)
            .filter(|cursor| usize::from(*cursor) < self.candidates.len())
            .unwrap_or(0);
        self.advance(now_millis)
    }

    /// Records one bounded unavailable routing attempt without changing the
    /// immutable single-dispatch target.
    ///
    /// This advances the durable queue cursor timestamp so an unavailable old
    /// Run cannot permanently starve newer queued work in a fair sweep.
    ///
    /// # Errors
    ///
    /// Rejects a non-queued Run or server-time rollback.
    pub fn defer_unavailable(&mut self, now_millis: i64) -> Result<(), RouterError> {
        self.ensure_time(now_millis)?;
        if self.state != RunRoutingState::Queued {
            return Err(RouterError::InvalidTransition);
        }
        self.advance(now_millis)
    }

    /// Creates or exactly replays the only live offer for this Run.
    ///
    /// # Errors
    ///
    /// Rejects non-queued state, a wrong Connector fence, rollback time, or an
    /// offer extending beyond the queue deadline.
    pub fn offer(
        &mut self,
        offer_id: RunOfferId,
        connector_fence: ConnectorLeaseFence,
        offered_at_millis: i64,
        expires_at_millis: i64,
    ) -> Result<WriteDisposition<RunOffer>, RouterError> {
        if let Some(existing) = self.current_offer
            && self.state == RunRoutingState::Offered
            && existing.offer_id == offer_id
            && existing.connector_fence == connector_fence
            && existing.expires_at_millis == expires_at_millis
        {
            return Ok(WriteDisposition::Existing(existing));
        }
        self.ensure_time(offered_at_millis)?;
        if self.state != RunRoutingState::Queued
            || connector_fence.tenant_id != self.request.tenant_id
            || connector_fence.connector_id != self.current_candidate().connector_id
            || expires_at_millis <= offered_at_millis
            || expires_at_millis > self.request.queue_deadline_millis
            || expires_at_millis - offered_at_millis > MAX_ROUTING_LEASE_TTL_MILLIS
        {
            return Err(RouterError::InvalidTransition);
        }
        let attempt = checked_counter(self.highest_offer_attempt)?;
        let offer = RunOffer {
            offer_id,
            attempt,
            candidate_index: self.candidate_cursor,
            connector_fence,
            offered_at_millis,
            expires_at_millis,
        };
        self.highest_offer_attempt = attempt;
        self.current_offer = Some(offer);
        self.current_lease = None;
        self.state = RunRoutingState::Offered;
        self.advance(offered_at_millis)?;
        Ok(WriteDisposition::Inserted(offer))
    }

    /// Atomically accepts an offer and grants the only execution lease.
    ///
    /// Exact duplicate claims return the original server-generated lease.
    ///
    /// # Errors
    ///
    /// Rejects stale offers/fences, expired offers, invalid lease lifetimes, or
    /// a second competing claim.
    #[allow(clippy::too_many_arguments)]
    pub fn claim(
        &mut self,
        offer_id: RunOfferId,
        offer_attempt: u64,
        connector_fence: ConnectorLeaseFence,
        run_lease_id: RunLeaseId,
        claimed_at_millis: i64,
        lease_expires_at_millis: i64,
    ) -> Result<WriteDisposition<RunLease>, RouterError> {
        self.ensure_time(claimed_at_millis)?;
        if let Some(existing) = self.current_lease
            && self.state == RunRoutingState::Leased
            && existing.offer_id == offer_id
            && existing.offer_attempt == offer_attempt
            && existing.connector_fence == connector_fence
        {
            return if claimed_at_millis < existing.expires_at_millis {
                Ok(WriteDisposition::Existing(existing))
            } else {
                Err(RouterError::StaleRunLease)
            };
        }
        let offer = self.current_offer.ok_or(RouterError::StaleOffer)?;
        if self.state != RunRoutingState::Offered
            || offer.offer_id != offer_id
            || offer.attempt != offer_attempt
            || offer.connector_fence != connector_fence
            || claimed_at_millis >= offer.expires_at_millis
            || lease_expires_at_millis <= claimed_at_millis
            || lease_expires_at_millis - claimed_at_millis > MAX_ROUTING_LEASE_TTL_MILLIS
        {
            return Err(RouterError::StaleOffer);
        }
        let run_lease_epoch = checked_counter(self.highest_run_lease_epoch)?;
        let lease = RunLease {
            id: run_lease_id,
            epoch: run_lease_epoch,
            offer_id,
            offer_attempt,
            candidate_index: offer.candidate_index,
            connector_fence,
            issued_at_millis: claimed_at_millis,
            expires_at_millis: lease_expires_at_millis,
        };
        self.highest_run_lease_epoch = run_lease_epoch;
        self.current_lease = Some(lease);
        self.state = RunRoutingState::Leased;
        self.advance(claimed_at_millis)?;
        Ok(WriteDisposition::Inserted(lease))
    }

    /// Requeues an offer that provably expired before execution was authorized.
    ///
    /// Ordered failover advances exactly one candidate at a time; exhausting the
    /// list returns to its first candidate until the request deadline.
    ///
    /// # Errors
    ///
    /// Rejects a non-offered Run, an early timeout, or server-time rollback.
    pub fn expire_offer(&mut self, now_millis: i64) -> Result<RunRoutingState, RouterError> {
        self.ensure_time(now_millis)?;
        let offer = self.current_offer.ok_or(RouterError::InvalidTransition)?;
        if self.state != RunRoutingState::Offered || now_millis < offer.expires_at_millis {
            return Err(RouterError::InvalidTransition);
        }
        self.current_offer = None;
        if now_millis >= self.request.queue_deadline_millis {
            self.state = RunRoutingState::Expired;
        } else {
            if self.request.dispatch_mode == DispatchMode::Failover {
                self.candidate_cursor = self
                    .candidate_cursor
                    .checked_add(1)
                    .filter(|cursor| usize::from(*cursor) < self.candidates.len())
                    .unwrap_or(0);
            }
            self.state = RunRoutingState::Queued;
        }
        self.advance(now_millis)?;
        Ok(self.state)
    }

    /// Expires a still-queued request at its server-owned deadline.
    ///
    /// # Errors
    ///
    /// Rejects a non-queued Run, an early expiry, or server-time rollback.
    pub fn expire_queue(&mut self, now_millis: i64) -> Result<(), RouterError> {
        self.ensure_time(now_millis)?;
        if self.state != RunRoutingState::Queued || now_millis < self.request.queue_deadline_millis
        {
            return Err(RouterError::InvalidTransition);
        }
        self.state = RunRoutingState::Expired;
        self.advance(now_millis)
    }

    /// Fences an expired execution lease for later reconciliation.
    ///
    /// It never auto-requeues because execution may already have occurred.
    ///
    /// # Errors
    ///
    /// Rejects a non-leased Run, an early expiry, or server-time rollback.
    pub fn expire_lease(&mut self, now_millis: i64) -> Result<(), RouterError> {
        self.ensure_time(now_millis)?;
        let lease = self.current_lease.ok_or(RouterError::StaleRunLease)?;
        if self.state != RunRoutingState::Leased || now_millis < lease.expires_at_millis {
            return Err(RouterError::InvalidTransition);
        }
        self.state = RunRoutingState::ReconcileRequired;
        self.advance(now_millis)
    }

    /// Records a Connector release without assuming the work never started.
    ///
    /// # Errors
    ///
    /// Rejects either stale fence or server-time rollback.
    pub fn release(
        &mut self,
        run_lease_id: RunLeaseId,
        run_lease_epoch: u64,
        connector_fence: ConnectorLeaseFence,
        released_at_millis: i64,
    ) -> Result<(), RouterError> {
        self.ensure_time(released_at_millis)?;
        self.validate_active_lease(run_lease_id, run_lease_epoch, connector_fence)?;
        self.state = RunRoutingState::ReconcileRequired;
        self.advance(released_at_millis)
    }

    /// Validates both the Connector-control and Run-lease fences for a future
    /// checkpoint/result mutation.
    ///
    /// # Errors
    ///
    /// Rejects a Run that is not actively leased or either stale fence.
    pub fn validate_active_lease(
        &self,
        run_lease_id: RunLeaseId,
        run_lease_epoch: u64,
        connector_fence: ConnectorLeaseFence,
    ) -> Result<RunLease, RouterError> {
        let lease = self.current_lease.ok_or(RouterError::StaleRunLease)?;
        if self.state == RunRoutingState::Leased
            && lease.id == run_lease_id
            && lease.epoch == run_lease_epoch
            && lease.connector_fence == connector_fence
        {
            Ok(lease)
        } else {
            Err(RouterError::StaleRunLease)
        }
    }

    fn ensure_time(&self, now_millis: i64) -> Result<(), RouterError> {
        if valid_time(now_millis) && now_millis >= self.server_time_high_water_millis {
            Ok(())
        } else {
            Err(RouterError::ServerTimeRollback)
        }
    }

    fn advance(&mut self, now_millis: i64) -> Result<(), RouterError> {
        self.revision = self
            .revision
            .checked_next()
            .map_err(|_| RouterError::CounterExhausted)?;
        self.updated_at_millis = now_millis;
        self.server_time_high_water_millis = now_millis;
        Ok(())
    }
}

/// Stable rejection from the Router state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouterError {
    InvalidRequest,
    InvalidCandidate,
    InvalidConnectorFence,
    InvalidTransition,
    PolicyMismatch,
    StaleOffer,
    StaleRunLease,
    ServerTimeRollback,
    CounterExhausted,
    InvalidSnapshot,
}

impl fmt::Display for RouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "Run routing request is invalid",
            Self::InvalidCandidate => "Run route candidate set is invalid",
            Self::InvalidConnectorFence => "Connector control fence is invalid",
            Self::InvalidTransition => "Run routing transition is not allowed",
            Self::PolicyMismatch => "Run dispatch mode conflicts with Binding policy",
            Self::StaleOffer => "Run offer is stale",
            Self::StaleRunLease => "Run lease is stale",
            Self::ServerTimeRollback => "Router server time moved backwards",
            Self::CounterExhausted => "Run routing counter is exhausted",
            Self::InvalidSnapshot => "Run routing snapshot is invalid",
        })
    }
}

impl Error for RouterError {}

fn validate_candidates(
    request: &RunRequest,
    candidates: &[RouteCandidate],
) -> Result<(), RouterError> {
    if candidates.is_empty() || candidates.len() > MAX_ROUTE_CANDIDATES {
        return Err(RouterError::InvalidCandidate);
    }
    match (request.dispatch_mode, request.routing_policy) {
        (DispatchMode::Single, _) if candidates.len() == 1 => {}
        (DispatchMode::Failover, RoutingPolicy::OrderedFailover) => {}
        _ => return Err(RouterError::PolicyMismatch),
    }
    if request
        .preferred_connector_id
        .is_some_and(|preferred| candidates[0].connector_id != preferred)
    {
        return Err(RouterError::InvalidCandidate);
    }
    let mut bindings = BTreeSet::new();
    let mut connectors = BTreeSet::new();
    let mut previous_priority = None;
    for candidate in candidates {
        if candidate.max_concurrency == 0
            || !bindings.insert(candidate.binding_id)
            || !connectors.insert(candidate.connector_id)
            || (request.dispatch_mode == DispatchMode::Failover
                && previous_priority.is_some_and(|previous| candidate.priority <= previous))
        {
            return Err(RouterError::InvalidCandidate);
        }
        previous_priority = Some(candidate.priority);
    }
    Ok(())
}

fn validate_state_image(snapshot: &AgentRunSnapshot) -> Result<(), RouterError> {
    let offer_valid = snapshot.current_offer.is_none_or(|offer| {
        usize::from(offer.candidate_index) < snapshot.candidates.len()
            && offer.candidate_index == snapshot.candidate_cursor
            && offer.connector_fence.tenant_id == snapshot.request.tenant_id
            && offer.connector_fence.connector_id
                == snapshot.candidates[usize::from(offer.candidate_index)].connector_id
            && offer.attempt > 0
            && offer.attempt <= snapshot.highest_offer_attempt
            && offer.expires_at_millis > offer.offered_at_millis
            && offer.expires_at_millis <= snapshot.request.queue_deadline_millis
    });
    let lease_valid = snapshot.current_lease.is_none_or(|lease| {
        usize::from(lease.candidate_index) < snapshot.candidates.len()
            && lease.candidate_index == snapshot.candidate_cursor
            && lease.connector_fence.tenant_id == snapshot.request.tenant_id
            && lease.connector_fence.connector_id
                == snapshot.candidates[usize::from(lease.candidate_index)].connector_id
            && lease.epoch > 0
            && lease.epoch <= snapshot.highest_run_lease_epoch
            && lease.offer_attempt > 0
            && lease.offer_attempt <= snapshot.highest_offer_attempt
            && lease.expires_at_millis > lease.issued_at_millis
            && snapshot.current_offer.is_some_and(|offer| {
                offer.offer_id == lease.offer_id
                    && offer.attempt == lease.offer_attempt
                    && offer.connector_fence == lease.connector_fence
            })
    });
    let state_valid = match snapshot.state {
        RunRoutingState::Queued | RunRoutingState::Expired => {
            snapshot.current_offer.is_none() && snapshot.current_lease.is_none()
        }
        RunRoutingState::Offered => {
            snapshot.current_offer.is_some() && snapshot.current_lease.is_none()
        }
        RunRoutingState::Leased | RunRoutingState::ReconcileRequired => {
            snapshot.current_offer.is_some() && snapshot.current_lease.is_some()
        }
    };
    if offer_valid && lease_valid && state_valid {
        Ok(())
    } else {
        Err(RouterError::InvalidSnapshot)
    }
}

fn checked_counter(current: u64) -> Result<u64, RouterError> {
    current
        .checked_add(1)
        .filter(|value| *value <= Revision::MAX)
        .ok_or(RouterError::CounterExhausted)
}

const fn valid_time(value: i64) -> bool {
    value >= 0 && value <= Revision::MAX.cast_signed()
}

fn valid_stable_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(mode: DispatchMode, policy: RoutingPolicy) -> RunRequest {
        RunRequest::new(
            TenantId::new(),
            RunId::new(),
            RequestId::new(),
            [1; 32],
            [2; 32],
            InstallationId::new(),
            ConversationId::new(),
            EventId::new(),
            None,
            vec!["chat.streaming".to_owned()],
            mode,
            policy,
            Revision::INITIAL,
            1,
            10_000,
            1_000,
        )
        .unwrap()
    }

    fn candidate(priority: u16) -> RouteCandidate {
        RouteCandidate::new(BindingId::new(), ConnectorId::new(), priority, 2).unwrap()
    }

    fn fence(tenant_id: TenantId, connector_id: ConnectorId, epoch: u64) -> ConnectorLeaseFence {
        ConnectorLeaseFence::new(
            tenant_id,
            connector_id,
            BootId::new(),
            1,
            LeaseId::new(),
            epoch,
        )
        .unwrap()
    }

    #[test]
    fn single_dispatch_cannot_hide_multiple_routes() {
        let request = request(DispatchMode::Single, RoutingPolicy::Exclusive);
        assert_eq!(
            AgentRun::create(request, vec![candidate(0), candidate(1)]).unwrap_err(),
            RouterError::PolicyMismatch
        );
    }

    #[test]
    fn failover_requires_ordered_policy_and_strict_priorities() {
        let candidates = vec![candidate(0), candidate(1)];
        let exclusive = request(DispatchMode::Failover, RoutingPolicy::Exclusive);
        assert_eq!(
            AgentRun::create(exclusive, candidates.clone()).unwrap_err(),
            RouterError::PolicyMismatch
        );
        let ordered = request(DispatchMode::Failover, RoutingPolicy::OrderedFailover);
        assert!(AgentRun::create(ordered, candidates).is_ok());
    }

    #[test]
    fn offer_timeout_advances_one_ordered_candidate_without_execution_authority() {
        let request = request(DispatchMode::Failover, RoutingPolicy::OrderedFailover);
        let tenant_id = request.tenant_id();
        let candidates = vec![candidate(0), candidate(1)];
        let first = candidates[0];
        let second = candidates[1];
        let mut run = AgentRun::create(request, candidates).unwrap();
        run.offer(
            RunOfferId::new(),
            fence(tenant_id, first.connector_id(), 1),
            1_001,
            2_000,
        )
        .unwrap();
        assert_eq!(run.expire_offer(2_000).unwrap(), RunRoutingState::Queued);
        assert_eq!(run.current_candidate(), second);
        assert!(run.current_lease().is_none());
    }

    #[test]
    fn duplicate_claim_returns_the_original_lease() {
        let request = request(DispatchMode::Single, RoutingPolicy::Exclusive);
        let tenant_id = request.tenant_id();
        let route = candidate(0);
        let connector_fence = fence(tenant_id, route.connector_id(), 1);
        let mut run = AgentRun::create(request, vec![route]).unwrap();
        let offer = run
            .offer(RunOfferId::new(), connector_fence, 1_001, 2_000)
            .unwrap()
            .value();
        let first = run
            .claim(
                offer.offer_id(),
                offer.attempt(),
                connector_fence,
                RunLeaseId::new(),
                1_100,
                1_900,
            )
            .unwrap()
            .value();
        let retry = run
            .claim(
                offer.offer_id(),
                offer.attempt(),
                connector_fence,
                RunLeaseId::new(),
                1_200,
                1_950,
            )
            .unwrap();
        assert_eq!(retry, WriteDisposition::Existing(first));
    }

    #[test]
    fn duplicate_claim_cannot_revive_an_expired_execution_lease() {
        let request = request(DispatchMode::Single, RoutingPolicy::Exclusive);
        let tenant_id = request.tenant_id();
        let route = candidate(0);
        let connector_fence = fence(tenant_id, route.connector_id(), 1);
        let mut run = AgentRun::create(request, vec![route]).unwrap();
        let offer = run
            .offer(RunOfferId::new(), connector_fence, 1_001, 2_000)
            .unwrap()
            .value();
        run.claim(
            offer.offer_id(),
            offer.attempt(),
            connector_fence,
            RunLeaseId::new(),
            1_100,
            1_900,
        )
        .unwrap();
        assert_eq!(
            run.claim(
                offer.offer_id(),
                offer.attempt(),
                connector_fence,
                RunLeaseId::new(),
                1_900,
                2_000,
            )
            .unwrap_err(),
            RouterError::StaleRunLease
        );
    }

    #[test]
    fn stale_connector_fence_cannot_claim() {
        let request = request(DispatchMode::Single, RoutingPolicy::Exclusive);
        let tenant_id = request.tenant_id();
        let route = candidate(0);
        let current = fence(tenant_id, route.connector_id(), 2);
        let stale = fence(tenant_id, route.connector_id(), 1);
        let mut run = AgentRun::create(request, vec![route]).unwrap();
        let offer = run
            .offer(RunOfferId::new(), current, 1_001, 2_000)
            .unwrap()
            .value();
        assert_eq!(
            run.claim(
                offer.offer_id(),
                offer.attempt(),
                stale,
                RunLeaseId::new(),
                1_100,
                1_900,
            )
            .unwrap_err(),
            RouterError::StaleOffer
        );
    }

    #[test]
    fn expired_execution_lease_requires_reconciliation_not_failover() {
        let request = request(DispatchMode::Failover, RoutingPolicy::OrderedFailover);
        let tenant_id = request.tenant_id();
        let candidates = vec![candidate(0), candidate(1)];
        let first = candidates[0];
        let connector_fence = fence(tenant_id, first.connector_id(), 1);
        let mut run = AgentRun::create(request, candidates).unwrap();
        let offer = run
            .offer(RunOfferId::new(), connector_fence, 1_001, 2_000)
            .unwrap()
            .value();
        run.claim(
            offer.offer_id(),
            offer.attempt(),
            connector_fence,
            RunLeaseId::new(),
            1_100,
            1_500,
        )
        .unwrap();
        run.expire_lease(1_500).unwrap();
        assert_eq!(run.state(), RunRoutingState::ReconcileRequired);
        assert_eq!(run.current_candidate(), first);
    }

    #[test]
    fn old_run_epoch_is_fenced_after_grant() {
        let request = request(DispatchMode::Single, RoutingPolicy::Exclusive);
        let tenant_id = request.tenant_id();
        let route = candidate(0);
        let connector_fence = fence(tenant_id, route.connector_id(), 1);
        let mut run = AgentRun::create(request, vec![route]).unwrap();
        let offer = run
            .offer(RunOfferId::new(), connector_fence, 1_001, 2_000)
            .unwrap()
            .value();
        let lease = run
            .claim(
                offer.offer_id(),
                offer.attempt(),
                connector_fence,
                RunLeaseId::new(),
                1_100,
                1_900,
            )
            .unwrap()
            .value();
        assert_eq!(
            run.validate_active_lease(
                lease.run_lease_id(),
                lease.run_lease_epoch() + 1,
                connector_fence,
            )
            .unwrap_err(),
            RouterError::StaleRunLease
        );
    }

    #[test]
    fn server_time_cannot_move_backwards() {
        let request = request(DispatchMode::Single, RoutingPolicy::Exclusive);
        let tenant_id = request.tenant_id();
        let route = candidate(0);
        let mut run = AgentRun::create(request, vec![route]).unwrap();
        assert_eq!(
            run.offer(
                RunOfferId::new(),
                fence(tenant_id, route.connector_id(), 1),
                999,
                2_000,
            )
            .unwrap_err(),
            RouterError::ServerTimeRollback
        );
    }

    #[test]
    fn snapshot_rejects_a_lease_without_its_offer() {
        let request = request(DispatchMode::Single, RoutingPolicy::Exclusive);
        let tenant_id = request.tenant_id();
        let route = candidate(0);
        let connector_fence = fence(tenant_id, route.connector_id(), 1);
        let mut run = AgentRun::create(request, vec![route]).unwrap();
        let offer = run
            .offer(RunOfferId::new(), connector_fence, 1_001, 2_000)
            .unwrap()
            .value();
        run.claim(
            offer.offer_id(),
            offer.attempt(),
            connector_fence,
            RunLeaseId::new(),
            1_100,
            1_900,
        )
        .unwrap();
        let mut snapshot = run.snapshot();
        snapshot.current_offer = None;
        assert_eq!(
            AgentRun::try_from_snapshot(snapshot).unwrap_err(),
            RouterError::InvalidSnapshot
        );
    }
}
