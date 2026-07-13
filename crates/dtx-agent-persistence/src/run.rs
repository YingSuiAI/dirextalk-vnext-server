use std::collections::{BTreeMap, BTreeSet};

use dtx_agent_router::{
    AgentRun, AgentRunSnapshot, ConnectorLeaseFence, DispatchMode, RouteCandidate, RouterError,
    RunLease, RunLeaseSnapshot, RunOffer, RunOfferSnapshot, RunRequest, RunRoutingState,
    WriteDisposition,
};
use dtx_connect_registry::RoutingPolicy;
use dtx_domain::{
    BindingId, BootId, Clock, ConnectorId, ConversationId, EventId, InstallationId, LeaseId,
    RequestId, Revision, RunId, RunLeaseId, RunOfferId, TenantId,
};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

use crate::{
    AgentPersistenceError,
    registry::{revision_from_i64, revision_to_i64},
};

/// Fixed `PostgreSQL` channel used only as an at-most-once Run-offer wakeup hint.
pub const AGENT_RUN_OFFER_NOTIFY_CHANNEL: &str = "dtx_agent_run_offer_v1";
/// Maximum offers returned by one Connector poll.
pub const MAX_AGENT_RUN_OFFER_PAGE: usize = 128;
/// Maximum due Runs fenced by one timeout sweep transaction.
pub const MAX_AGENT_RUN_EXPIRY_BATCH: usize = 128;

/// Exact-create disposition for one immutable Run request and candidate set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRunCreate {
    Inserted,
    Existing,
}

/// Bounded ordered-routing result for one queued Run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentRunOfferNext {
    Offered(WriteDisposition<RunOffer>),
    Unavailable,
}

/// One bounded, durable offer selected for an exact Connector control fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingAgentRunOffer {
    connector_offer_sequence: u64,
    run: AgentRun,
}

impl PendingAgentRunOffer {
    #[must_use]
    pub const fn connector_offer_sequence(&self) -> u64 {
        self.connector_offer_sequence
    }

    #[must_use]
    pub const fn run(&self) -> &AgentRun {
        &self.run
    }
}

/// `PostgreSQL` adapter for the bounded MC3 routing aggregate.
#[derive(Clone, Copy, Debug, Default)]
pub struct AgentRunRepository;

impl AgentRunRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Creates one immutable request/candidate set exactly once.
    ///
    /// # Errors
    ///
    /// Rejects conflicting request/idempotency identities, invalid snapshots,
    /// or database failures.
    #[allow(clippy::too_many_lines)]
    pub async fn create(
        self,
        connection: &mut PgConnection,
        run: &AgentRun,
    ) -> Result<(AgentRunCreate, AgentRun), AgentPersistenceError> {
        let snapshot = run.snapshot();
        if snapshot.state != RunRoutingState::Queued
            || snapshot.revision != Revision::INITIAL
            || snapshot.current_offer.is_some()
            || snapshot.current_lease.is_some()
        {
            return Err(AgentPersistenceError::SnapshotRejected("new Agent Run"));
        }
        let mut transaction = connection.begin().await?;
        if let Some(existing) = load_matching_identity(
            &mut transaction,
            snapshot.request.tenant_id(),
            snapshot.request.request_id(),
            snapshot.request.idempotency_digest(),
        )
        .await?
        {
            if run_create_retry_matches(&existing, run) {
                transaction.commit().await?;
                return Ok((AgentRunCreate::Existing, existing));
            }
            transaction.rollback().await?;
            return Err(AgentPersistenceError::ImmutableConflict(
                "Agent Run request",
            ));
        }

        let request = &snapshot.request;
        let inserted = sqlx::query(
            "INSERT INTO agent.agent_runs (
                 tenant_id, run_id, request_id, idempotency_digest, request_digest,
                 installation_id, conversation_id, request_event_id, preferred_connector_id,
                 required_capability_codes, dispatch_mode, routing_policy,
                 routing_policy_revision, grant_version, queue_deadline_ms, state,
                 candidate_cursor, candidate_count, highest_offer_attempt,
                 highest_run_lease_epoch, current_offer_id, current_run_lease_id,
                 aggregate_revision, server_time_high_water_ms, created_at_ms, updated_at_ms
             ) VALUES (
                 $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,
                 $17,$18,$19,$20,NULL,NULL,$21,$22,$23,$24
             ) ON CONFLICT DO NOTHING",
        )
        .bind(Uuid::from(request.tenant_id()))
        .bind(Uuid::from(request.run_id()))
        .bind(Uuid::from(request.request_id()))
        .bind(request.idempotency_digest().to_vec())
        .bind(request.request_digest().to_vec())
        .bind(Uuid::from(request.installation_id()))
        .bind(Uuid::from(request.conversation_id()))
        .bind(Uuid::from(request.request_event_id()))
        .bind(request.preferred_connector_id().map(Uuid::from))
        .bind(request.required_capabilities())
        .bind(dispatch_code(request.dispatch_mode()))
        .bind(policy_code(request.routing_policy()))
        .bind(revision_to_i64(request.routing_policy_revision())?)
        .bind(to_i64(request.grant_version(), "Run grant version")?)
        .bind(request.queue_deadline_millis())
        .bind(state_code(snapshot.state))
        .bind(i32::from(snapshot.candidate_cursor))
        .bind(
            i32::try_from(snapshot.candidates.len())
                .map_err(|_| AgentPersistenceError::CorruptData("Agent Run candidate count"))?,
        )
        .bind(to_i64(snapshot.highest_offer_attempt, "Run offer attempt")?)
        .bind(to_i64(snapshot.highest_run_lease_epoch, "Run lease epoch")?)
        .bind(revision_to_i64(snapshot.revision)?)
        .bind(snapshot.server_time_high_water_millis)
        .bind(request.created_at_millis())
        .bind(snapshot.updated_at_millis)
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() == 0 {
            let existing = load_matching_identity(
                &mut transaction,
                request.tenant_id(),
                request.request_id(),
                request.idempotency_digest(),
            )
            .await?
            .ok_or(AgentPersistenceError::CorruptData(
                "Agent Run create conflict",
            ))?;
            if run_create_retry_matches(&existing, run) {
                transaction.commit().await?;
                return Ok((AgentRunCreate::Existing, existing));
            }
            transaction.rollback().await?;
            return Err(AgentPersistenceError::ImmutableConflict(
                "Agent Run request",
            ));
        }

        for (ordinal, candidate) in snapshot.candidates.iter().copied().enumerate() {
            sqlx::query(
                "INSERT INTO agent.agent_run_candidates (
                     tenant_id, run_id, candidate_ordinal, binding_id, connector_id,
                     priority, max_concurrency
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(Uuid::from(request.tenant_id()))
            .bind(Uuid::from(request.run_id()))
            .bind(
                i32::try_from(ordinal).map_err(|_| {
                    AgentPersistenceError::CorruptData("Agent Run candidate ordinal")
                })?,
            )
            .bind(Uuid::from(candidate.binding_id()))
            .bind(Uuid::from(candidate.connector_id()))
            .bind(i32::from(candidate.priority()))
            .bind(i64::from(candidate.max_concurrency()))
            .execute(&mut *transaction)
            .await?;
            initialize_capacity_heads(
                &mut transaction,
                request.tenant_id(),
                candidate,
                request.created_at_millis(),
            )
            .await?;
        }
        transaction.commit().await?;
        Ok((AgentRunCreate::Inserted, run.clone()))
    }

    /// Loads the current bounded head and immutable candidates.
    ///
    /// # Errors
    ///
    /// Rejects corrupt rows, an invalid rehydrated snapshot, or database failures.
    pub async fn load(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        run_id: RunId,
    ) -> Result<Option<AgentRun>, AgentPersistenceError> {
        load_run(connection, tenant_id, run_id, false).await
    }

    /// Loads an existing Run by both caller-owned idempotency identities.
    ///
    /// # Errors
    ///
    /// Fails closed when the request ID and digest resolve to different rows,
    /// or when stored state is corrupt or unavailable.
    pub async fn load_by_identity(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        request_id: RequestId,
        idempotency_digest: [u8; 32],
    ) -> Result<Option<AgentRun>, AgentPersistenceError> {
        let rows = sqlx::query(
            "SELECT run_id, request_id, idempotency_digest
               FROM agent.agent_runs
              WHERE tenant_id=$1 AND (request_id=$2 OR idempotency_digest=$3)",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(request_id))
        .bind(idempotency_digest.to_vec())
        .fetch_all(&mut *connection)
        .await?;
        if rows.len() > 1 {
            return Err(AgentPersistenceError::ImmutableConflict(
                "Agent Run idempotency identity",
            ));
        }
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let stored_request: Uuid = row.try_get("request_id")?;
        let stored_digest: Vec<u8> = row.try_get("idempotency_digest")?;
        if stored_request != Uuid::from(request_id)
            || stored_digest.as_slice() != idempotency_digest
        {
            return Err(AgentPersistenceError::ImmutableConflict(
                "Agent Run idempotency identity",
            ));
        }
        load_run(
            connection,
            tenant_id,
            run_id(row.try_get("run_id")?)?,
            false,
        )
        .await
    }

    /// Selects the current immutable candidate and persists its only live offer.
    ///
    /// # Errors
    ///
    /// Rejects stale revisions, malformed routing state, or database failures.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn offer_next(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        run_id: RunId,
        expected_revision: Revision,
        offer_id: RunOfferId,
        offered_at_millis: i64,
        expires_at_millis: i64,
    ) -> Result<(AgentRunOfferNext, AgentRun), AgentPersistenceError> {
        self.offer_next_with_timing(
            connection,
            tenant_id,
            run_id,
            expected_revision,
            offer_id,
            ClaimTiming::Fixed {
                claimed_at_millis: offered_at_millis,
                lease_expires_at_millis: expires_at_millis,
            },
        )
        .await
    }

    /// Offers using server time sampled after each candidate's capacity rows are locked.
    ///
    /// # Errors
    ///
    /// Rejects clock rollback, stale policy/fence state, or an invalid offer lifetime.
    #[allow(clippy::too_many_arguments)]
    pub async fn offer_next_current(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        run_id: RunId,
        expected_revision: Revision,
        offer_id: RunOfferId,
        clock: &dyn Clock,
        offer_ttl_millis: i64,
    ) -> Result<(AgentRunOfferNext, AgentRun), AgentPersistenceError> {
        self.offer_next_with_timing(
            connection,
            tenant_id,
            run_id,
            expected_revision,
            offer_id,
            ClaimTiming::Current {
                clock,
                lease_ttl_millis: offer_ttl_millis,
            },
        )
        .await
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn offer_next_with_timing(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        run_id: RunId,
        expected_revision: Revision,
        offer_id: RunOfferId,
        timing: ClaimTiming<'_>,
    ) -> Result<(AgentRunOfferNext, AgentRun), AgentPersistenceError> {
        let mut transaction = connection.begin().await?;
        let mut run = load_run(&mut transaction, tenant_id, run_id, true)
            .await?
            .ok_or(AgentPersistenceError::RevisionConflict { current: None })?;
        ensure_revision(&run, expected_revision)?;
        let mut stored_revision = expected_revision;
        let candidate_count = run.candidates().len();
        // Multi-candidate failover must acquire every shared head in one global
        // key order. Per-candidate locking can deadlock when two installations
        // define the same Connectors in opposite priority order.
        let connector_ids = run
            .candidates()
            .iter()
            .map(|candidate| candidate.connector_id())
            .collect::<BTreeSet<_>>();
        let mut connector_capacities = BTreeMap::new();
        for connector_id in connector_ids {
            connector_capacities.insert(
                connector_id,
                lock_connector_capacity(&mut transaction, tenant_id, connector_id).await?,
            );
        }
        let binding_ids = run
            .candidates()
            .iter()
            .map(|candidate| candidate.binding_id())
            .collect::<BTreeSet<_>>();
        let mut binding_capacities = BTreeMap::new();
        for binding_id in binding_ids {
            binding_capacities.insert(
                binding_id,
                lock_binding_capacity(&mut transaction, tenant_id, binding_id).await?,
            );
        }
        for _ in 0..candidate_count {
            let candidate = run.current_candidate();
            // The only eligibility decision is made after the shared capacity
            // heads are locked, so a concurrent claim cannot turn a successful
            // probe into a transaction-aborting second check.
            let connector_capacity = connector_capacities
                .get(&candidate.connector_id())
                .copied()
                .ok_or(AgentPersistenceError::CorruptData(
                    "Run Connector capacity plan",
                ))?;
            let binding_capacity = binding_capacities
                .get(&candidate.binding_id())
                .copied()
                .ok_or(AgentPersistenceError::CorruptData(
                    "Run Binding capacity plan",
                ))?;
            let probe = probe_route_eligibility(
                &mut transaction,
                &run,
                candidate,
                connector_capacity,
                binding_capacity.active,
                timing,
            )
            .await;
            let eligibility = match probe {
                Ok(eligibility) => eligibility,
                Err(
                    AgentPersistenceError::FenceConflict
                    | AgentPersistenceError::ClaimRejected(_)
                    | AgentPersistenceError::AuthorizationRejected(_),
                ) if run.request().dispatch_mode() == DispatchMode::Failover => {
                    run.skip_ineligible_candidate(timing.now()?)
                        .map_err(transition_error)?;
                    save_head(&mut transaction, &run, stored_revision).await?;
                    stored_revision = run.revision();
                    continue;
                }
                Err(
                    AgentPersistenceError::FenceConflict
                    | AgentPersistenceError::ClaimRejected(_)
                    | AgentPersistenceError::AuthorizationRejected(_),
                ) => {
                    run.defer_unavailable(timing.now()?)
                        .map_err(transition_error)?;
                    save_head(&mut transaction, &run, stored_revision).await?;
                    transaction.commit().await?;
                    return Ok((AgentRunOfferNext::Unavailable, run));
                }
                Err(error) => return Err(error),
            };
            let connector_fence = eligibility.fence;
            let offered_at_millis = eligibility.evaluated_at_millis;
            let effective_expires_at_millis = eligibility
                .proposed_expires_at_millis
                .min(eligibility.control_expires_at_millis)
                .min(run.request().queue_deadline_millis());
            if effective_expires_at_millis <= offered_at_millis {
                if run.request().dispatch_mode() == DispatchMode::Failover {
                    run.skip_ineligible_candidate(offered_at_millis)
                        .map_err(transition_error)?;
                    save_head(&mut transaction, &run, stored_revision).await?;
                    stored_revision = run.revision();
                    continue;
                }
                run.defer_unavailable(offered_at_millis)
                    .map_err(transition_error)?;
                save_head(&mut transaction, &run, stored_revision).await?;
                transaction.commit().await?;
                return Ok((AgentRunOfferNext::Unavailable, run));
            }

            let disposition = run
                .offer(
                    offer_id,
                    connector_fence,
                    offered_at_millis,
                    effective_expires_at_millis,
                )
                .map_err(transition_error)?;
            if let WriteDisposition::Inserted(offer) = disposition {
                let sequence = connector_capacity
                    .last_offer_sequence
                    .checked_add(1)
                    .filter(|value| *value <= Revision::MAX)
                    .ok_or(AgentPersistenceError::CorruptData(
                        "Connector offer sequence",
                    ))?;
                advance_connector_capacity(
                    &mut transaction,
                    tenant_id,
                    candidate.connector_id(),
                    connector_capacity,
                    ConnectorCapacity {
                        last_offer_sequence: sequence,
                        ..eligibility.connector_capacity
                    },
                    offered_at_millis,
                )
                .await?;
                insert_offer(
                    &mut transaction,
                    tenant_id,
                    run_id,
                    candidate,
                    offer,
                    sequence,
                )
                .await?;
                save_head(&mut transaction, &run, stored_revision).await?;
            }
            timing.ensure_commit_before(effective_expires_at_millis)?;
            transaction.commit().await?;
            return Ok((AgentRunOfferNext::Offered(disposition), run));
        }
        transaction.commit().await?;
        Ok((AgentRunOfferNext::Unavailable, run))
    }

    /// Returns a bounded page of live offers for one exact Connector control fence.
    ///
    /// # Errors
    ///
    /// Rejects an invalid page bound, corrupt Run state, or database failures.
    pub async fn poll_offers(
        self,
        connection: &mut PgConnection,
        connector_fence: ConnectorLeaseFence,
        after_sequence: u64,
        now_millis: i64,
        limit: usize,
    ) -> Result<Vec<PendingAgentRunOffer>, AgentPersistenceError> {
        if limit == 0 || limit > MAX_AGENT_RUN_OFFER_PAGE {
            return Err(AgentPersistenceError::MaterializationLimitExceeded(
                "Agent Run offer page",
            ));
        }
        let rows = sqlx::query(
            "SELECT o.run_id, o.connector_offer_sequence
               FROM agent.agent_run_offers o
               JOIN agent.agent_runs r
                 ON r.tenant_id=o.tenant_id AND r.run_id=o.run_id
               JOIN agent.connector_leases l
                 ON l.tenant_id=o.tenant_id AND l.connector_id=o.connector_id
                AND l.lease_id=o.connector_lease_id
              WHERE o.tenant_id=$1 AND o.connector_id=$2
                AND o.connector_boot_id=$3 AND o.connector_generation=$4
                AND o.connector_lease_id=$5 AND o.connector_lease_epoch=$6
                AND o.status='offered' AND r.state='offered'
                AND l.status='active' AND l.expires_at_ms>$7
                AND r.current_offer_id=o.offer_id AND o.expires_at_ms>$7
                AND o.connector_offer_sequence>$8
              ORDER BY o.connector_offer_sequence
              LIMIT $9",
        )
        .bind(Uuid::from(connector_fence.tenant_id()))
        .bind(Uuid::from(connector_fence.connector_id()))
        .bind(Uuid::from(connector_fence.boot_id()))
        .bind(to_i64(
            connector_fence.connector_generation(),
            "Connector generation",
        )?)
        .bind(Uuid::from(connector_fence.connector_lease_id()))
        .bind(to_i64(
            connector_fence.connector_lease_epoch(),
            "Connector lease epoch",
        )?)
        .bind(now_millis)
        .bind(to_i64(after_sequence, "Connector offer cursor")?)
        .bind(
            i64::try_from(limit)
                .map_err(|_| AgentPersistenceError::CorruptData("Agent Run offer page limit"))?,
        )
        .fetch_all(&mut *connection)
        .await?;
        let mut offers = Vec::with_capacity(rows.len());
        for row in rows {
            let run_id = run_id(row.try_get("run_id")?)?;
            let run = load_run(connection, connector_fence.tenant_id(), run_id, false)
                .await?
                .ok_or(AgentPersistenceError::CorruptData("polled Agent Run"))?;
            offers.push(PendingAgentRunOffer {
                connector_offer_sequence: positive_u64(
                    row.try_get("connector_offer_sequence")?,
                    "Connector offer sequence",
                )?,
                run,
            });
        }
        Ok(offers)
    }

    /// Loads a bounded fair page of non-expired queued Runs for reconciliation.
    ///
    /// # Errors
    ///
    /// Rejects an invalid page bound/time, corrupt rows, or database failures.
    pub async fn load_queued(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        now_millis: i64,
        limit: usize,
    ) -> Result<Vec<AgentRun>, AgentPersistenceError> {
        if limit == 0 || limit > MAX_AGENT_RUN_EXPIRY_BATCH {
            return Err(AgentPersistenceError::MaterializationLimitExceeded(
                "queued Agent Run page",
            ));
        }
        let rows = sqlx::query(
            "SELECT run_id
               FROM agent.agent_runs
              WHERE tenant_id=$1 AND state='queued' AND queue_deadline_ms>$2
              ORDER BY updated_at_ms, run_id
              LIMIT $3",
        )
        .bind(Uuid::from(tenant_id))
        .bind(now_millis)
        .bind(
            i64::try_from(limit)
                .map_err(|_| AgentPersistenceError::CorruptData("queued Run page limit"))?,
        )
        .fetch_all(&mut *connection)
        .await?;
        let mut queued = Vec::with_capacity(rows.len());
        for row in rows {
            let run_id = run_id(row.try_get("run_id")?)?;
            if let Some(run) = load_run(connection, tenant_id, run_id, false).await?
                && run.state() == RunRoutingState::Queued
            {
                queued.push(run);
            }
        }
        Ok(queued)
    }

    /// Claims one offer atomically while reserving Connector and Binding capacity.
    ///
    /// # Errors
    ///
    /// Rejects stale fences/revisions, unavailable capacity/capabilities, or database failures.
    #[allow(clippy::too_many_arguments)]
    pub async fn claim(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        run_id: RunId,
        expected_revision: Revision,
        offer_id: RunOfferId,
        offer_attempt: u64,
        connector_fence: ConnectorLeaseFence,
        run_lease_id: RunLeaseId,
        claimed_at_millis: i64,
        lease_expires_at_millis: i64,
    ) -> Result<(WriteDisposition<RunLease>, AgentRun), AgentPersistenceError> {
        self.claim_with_timing(
            connection,
            tenant_id,
            run_id,
            expected_revision,
            offer_id,
            offer_attempt,
            connector_fence,
            run_lease_id,
            ClaimTiming::Fixed {
                claimed_at_millis,
                lease_expires_at_millis,
            },
        )
        .await
    }

    /// Claims using a clock sampled only after the Run, capacity, authorization,
    /// and current Connector rows are locked.
    ///
    /// # Errors
    ///
    /// Rejects a stale/deadline-crossed claim or an invalid lease lifetime.
    #[allow(clippy::too_many_arguments)]
    pub async fn claim_current(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        run_id: RunId,
        expected_revision: Revision,
        offer_id: RunOfferId,
        offer_attempt: u64,
        connector_fence: ConnectorLeaseFence,
        run_lease_id: RunLeaseId,
        clock: &dyn Clock,
        lease_ttl_millis: i64,
    ) -> Result<(WriteDisposition<RunLease>, AgentRun), AgentPersistenceError> {
        self.claim_with_timing(
            connection,
            tenant_id,
            run_id,
            expected_revision,
            offer_id,
            offer_attempt,
            connector_fence,
            run_lease_id,
            ClaimTiming::Current {
                clock,
                lease_ttl_millis,
            },
        )
        .await
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn claim_with_timing(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        run_id: RunId,
        expected_revision: Revision,
        offer_id: RunOfferId,
        offer_attempt: u64,
        connector_fence: ConnectorLeaseFence,
        run_lease_id: RunLeaseId,
        timing: ClaimTiming<'_>,
    ) -> Result<(WriteDisposition<RunLease>, AgentRun), AgentPersistenceError> {
        let mut transaction = connection.begin().await?;
        let mut run = load_run(&mut transaction, tenant_id, run_id, true)
            .await?
            .ok_or(AgentPersistenceError::RevisionConflict { current: None })?;
        if run.revision() != expected_revision && run.state() != RunRoutingState::Leased {
            return Err(AgentPersistenceError::RevisionConflict {
                current: Some(run.revision().get()),
            });
        }
        if run.state() == RunRoutingState::Leased {
            let existing = run
                .current_lease()
                .ok_or(AgentPersistenceError::CorruptData("leased Agent Run"))?;
            let control_expires_at_millis =
                lock_current_control_expiry(&mut transaction, connector_fence).await?;
            let (claimed_at_millis, lease_expires_at_millis) =
                timing.resolve(control_expires_at_millis)?;
            if claimed_at_millis >= control_expires_at_millis {
                return Err(AgentPersistenceError::FenceConflict);
            }
            let disposition = run
                .claim(
                    offer_id,
                    offer_attempt,
                    connector_fence,
                    run_lease_id,
                    claimed_at_millis,
                    lease_expires_at_millis,
                )
                .map_err(transition_error)?;
            timing.ensure_commit_before(
                existing.expires_at_millis().min(control_expires_at_millis),
            )?;
            transaction.commit().await?;
            return Ok((disposition, run));
        }
        let candidate = run.current_candidate();

        // Deadlock prevention: never acquire these heads in another order.
        let connector_capacity =
            lock_connector_capacity(&mut transaction, tenant_id, candidate.connector_id()).await?;
        let binding_capacity =
            lock_binding_capacity(&mut transaction, tenant_id, candidate.binding_id()).await?;
        let admission = validate_route_eligibility(
            &mut transaction,
            &run,
            candidate,
            connector_fence,
            connector_capacity,
            binding_capacity.active,
            timing,
        )
        .await?;
        let disposition = run
            .claim(
                offer_id,
                offer_attempt,
                connector_fence,
                run_lease_id,
                admission.evaluated_at_millis,
                admission.lease_expires_at_millis,
            )
            .map_err(transition_error)?;
        let lease = disposition.value();
        mark_offer_claimed(&mut transaction, tenant_id, run_id, offer_id).await?;
        insert_lease(&mut transaction, tenant_id, run_id, candidate, lease).await?;
        advance_connector_capacity(
            &mut transaction,
            tenant_id,
            candidate.connector_id(),
            connector_capacity,
            ConnectorCapacity {
                active: connector_capacity.active.checked_add(1).ok_or(
                    AgentPersistenceError::CorruptData("Connector reservation count"),
                )?,
                ..admission.connector_capacity
            },
            admission.evaluated_at_millis,
        )
        .await?;
        advance_binding_capacity(
            &mut transaction,
            tenant_id,
            candidate.binding_id(),
            binding_capacity,
            binding_capacity
                .active
                .checked_add(1)
                .ok_or(AgentPersistenceError::CorruptData(
                    "Binding reservation count",
                ))?,
            admission.evaluated_at_millis,
        )
        .await?;
        save_head(&mut transaction, &run, expected_revision).await?;
        timing.ensure_commit_before(admission.commit_deadline_millis())?;
        transaction.commit().await?;
        Ok((disposition, run))
    }

    /// Expires the next due queue, offer, or execution lease.
    ///
    /// Expired execution leases are fenced into reconciliation and are never
    /// automatically requeued because execution may already have occurred.
    ///
    /// # Errors
    ///
    /// Rejects invalid time, inconsistent reservations, corrupt Run state, or
    /// database failures.
    #[allow(clippy::too_many_lines)]
    pub async fn expire_next_due(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        now_millis: i64,
    ) -> Result<Option<AgentRun>, AgentPersistenceError> {
        self.expire_next_due_with_timing(connection, tenant_id, ReleaseTiming::Fixed(now_millis))
            .await
    }

    /// Expires the next due Run using time sampled after its shared capacity locks.
    ///
    /// # Errors
    ///
    /// Rejects invalid time, corrupt reservation state, or database failures.
    pub async fn expire_next_due_current(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        clock: &dyn Clock,
    ) -> Result<Option<AgentRun>, AgentPersistenceError> {
        self.expire_next_due_with_timing(connection, tenant_id, ReleaseTiming::Current(clock))
            .await
    }

    #[allow(clippy::too_many_lines)]
    async fn expire_next_due_with_timing(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        timing: ReleaseTiming<'_>,
    ) -> Result<Option<AgentRun>, AgentPersistenceError> {
        let selection_now_millis = timing.now()?;
        if !(0..=Revision::MAX.cast_signed()).contains(&selection_now_millis) {
            return Err(AgentPersistenceError::SnapshotRejected(
                "Agent Run expiry time",
            ));
        }
        let mut transaction = connection.begin().await?;
        let due_run_id: Option<Uuid> = sqlx::query_scalar(
            "WITH due AS MATERIALIZED (
                 (SELECT r.run_id, r.updated_at_ms
                    FROM agent.agent_runs r
                   WHERE r.tenant_id=$1 AND r.state='queued'
                     AND r.queue_deadline_ms<=$2
                   ORDER BY r.queue_deadline_ms, r.updated_at_ms, r.run_id
                   LIMIT 1)
                 UNION ALL
                 (SELECT o.run_id, r.updated_at_ms
                    FROM agent.agent_run_offers o
                    JOIN agent.agent_runs r
                      ON r.tenant_id=o.tenant_id AND r.run_id=o.run_id
                     AND r.state='offered' AND r.current_offer_id=o.offer_id
                   WHERE o.tenant_id=$1 AND o.status='offered'
                     AND o.expires_at_ms<=$2
                   ORDER BY o.expires_at_ms, o.run_id, o.offer_id
                   LIMIT 1)
                 UNION ALL
                 (SELECT l.run_id, r.updated_at_ms
                    FROM agent.agent_run_leases l
                    JOIN agent.agent_runs r
                      ON r.tenant_id=l.tenant_id AND r.run_id=l.run_id
                     AND r.state='leased' AND r.current_run_lease_id=l.run_lease_id
                   WHERE l.tenant_id=$1 AND l.status='active'
                     AND l.expires_at_ms<=$2
                   ORDER BY l.expires_at_ms, l.run_id, l.run_lease_id
                   LIMIT 1)
             )
             SELECT r.run_id
               FROM due
               JOIN agent.agent_runs r
                 ON r.tenant_id=$1 AND r.run_id=due.run_id
              ORDER BY due.updated_at_ms, due.run_id
              FOR UPDATE OF r SKIP LOCKED
              LIMIT 1",
        )
        .bind(Uuid::from(tenant_id))
        .bind(selection_now_millis)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some(due_run_id) = due_run_id else {
            transaction.commit().await?;
            return Ok(None);
        };
        let run_id = run_id(due_run_id)?;
        let mut run = load_run(&mut transaction, tenant_id, run_id, false)
            .await?
            .ok_or(AgentPersistenceError::CorruptData("due Agent Run"))?;
        let expected_revision = run.revision();
        match run.state() {
            RunRoutingState::Queued => {
                let expired_at_millis = timing.now()?;
                if expired_at_millis < run.request().queue_deadline_millis() {
                    transaction.commit().await?;
                    return Ok(None);
                }
                run.expire_queue(expired_at_millis)
                    .map_err(transition_error)?;
            }
            RunRoutingState::Offered => {
                let offer = run
                    .current_offer()
                    .ok_or(AgentPersistenceError::CorruptData("due Run offer"))?;
                let expired_at_millis = timing.now()?;
                if expired_at_millis < offer.expires_at_millis() {
                    transaction.commit().await?;
                    return Ok(None);
                }
                run.expire_offer(expired_at_millis)
                    .map_err(transition_error)?;
                mark_offer_expired(&mut transaction, tenant_id, run_id, offer.offer_id()).await?;
            }
            RunRoutingState::Leased => {
                let lease = run
                    .current_lease()
                    .ok_or(AgentPersistenceError::CorruptData("due Run lease"))?;
                let candidate = run.current_candidate();

                // Global reservation lock order: Run -> Connector -> Binding.
                let connector_capacity =
                    lock_connector_capacity(&mut transaction, tenant_id, candidate.connector_id())
                        .await?;
                let binding_capacity =
                    lock_binding_capacity(&mut transaction, tenant_id, candidate.binding_id())
                        .await?;
                if connector_capacity.active == 0 || binding_capacity.active == 0 {
                    return Err(AgentPersistenceError::CorruptData(
                        "expired Run reservation",
                    ));
                }
                let expired_at_millis = timing.now()?;
                if expired_at_millis < lease.expires_at_millis() {
                    transaction.commit().await?;
                    return Ok(None);
                }
                run.expire_lease(expired_at_millis)
                    .map_err(transition_error)?;
                mark_lease_expired(&mut transaction, tenant_id, run_id, lease.run_lease_id())
                    .await?;
                advance_connector_capacity(
                    &mut transaction,
                    tenant_id,
                    candidate.connector_id(),
                    connector_capacity,
                    ConnectorCapacity {
                        active: connector_capacity.active - 1,
                        ..connector_capacity
                    },
                    expired_at_millis,
                )
                .await?;
                advance_binding_capacity(
                    &mut transaction,
                    tenant_id,
                    candidate.binding_id(),
                    binding_capacity,
                    binding_capacity.active - 1,
                    expired_at_millis,
                )
                .await?;
            }
            RunRoutingState::ReconcileRequired | RunRoutingState::Expired => {
                transaction.commit().await?;
                return Ok(None);
            }
        }
        save_head(&mut transaction, &run, expected_revision).await?;
        transaction.commit().await?;
        Ok(Some(run))
    }

    /// Releases one exact Run lease into reconciliation and frees both reservations.
    ///
    /// # Errors
    ///
    /// Rejects stale fences/revisions, inconsistent reservations, or database failures.
    #[allow(clippy::too_many_arguments)]
    pub async fn release(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        run_id: RunId,
        expected_revision: Revision,
        run_lease_id: RunLeaseId,
        run_lease_epoch: u64,
        connector_fence: ConnectorLeaseFence,
        released_at_millis: i64,
    ) -> Result<AgentRun, AgentPersistenceError> {
        self.release_with_timing(
            connection,
            tenant_id,
            run_id,
            expected_revision,
            run_lease_id,
            run_lease_epoch,
            connector_fence,
            ReleaseTiming::Fixed(released_at_millis),
        )
        .await
    }

    /// Releases using a clock sampled after all routing and control rows are locked.
    ///
    /// # Errors
    ///
    /// Rejects a release whose Run or Connector lease expires while waiting for locks.
    #[allow(clippy::too_many_arguments)]
    pub async fn release_current(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        run_id: RunId,
        expected_revision: Revision,
        run_lease_id: RunLeaseId,
        run_lease_epoch: u64,
        connector_fence: ConnectorLeaseFence,
        clock: &dyn Clock,
    ) -> Result<AgentRun, AgentPersistenceError> {
        self.release_with_timing(
            connection,
            tenant_id,
            run_id,
            expected_revision,
            run_lease_id,
            run_lease_epoch,
            connector_fence,
            ReleaseTiming::Current(clock),
        )
        .await
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn release_with_timing(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        run_id: RunId,
        expected_revision: Revision,
        run_lease_id: RunLeaseId,
        run_lease_epoch: u64,
        connector_fence: ConnectorLeaseFence,
        timing: ReleaseTiming<'_>,
    ) -> Result<AgentRun, AgentPersistenceError> {
        let mut transaction = connection.begin().await?;
        let mut run = load_run(&mut transaction, tenant_id, run_id, true)
            .await?
            .ok_or(AgentPersistenceError::RevisionConflict { current: None })?;
        if run.state() == RunRoutingState::ReconcileRequired {
            let lease = run
                .current_lease()
                .ok_or(AgentPersistenceError::CorruptData("terminal Run lease"))?;
            let status: String = sqlx::query_scalar(
                "SELECT status FROM agent.agent_run_leases
                  WHERE tenant_id=$1 AND run_id=$2 AND run_lease_id=$3",
            )
            .bind(Uuid::from(tenant_id))
            .bind(Uuid::from(run_id))
            .bind(Uuid::from(lease.run_lease_id()))
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(AgentPersistenceError::CorruptData("terminal Run lease"))?;
            let exact = lease.run_lease_id() == run_lease_id
                && lease.run_lease_epoch() == run_lease_epoch
                && lease.connector_fence() == connector_fence;
            match classify_terminal_release_retry(exact, &status)? {
                TerminalReleaseRetry::Existing => {
                    let control_expires_at_millis =
                        lock_current_control_expiry(&mut transaction, connector_fence).await?;
                    if timing.now()? >= control_expires_at_millis {
                        return Err(AgentPersistenceError::FenceConflict);
                    }
                    timing.ensure_before(control_expires_at_millis)?;
                    transaction.commit().await?;
                    return Ok(run);
                }
                TerminalReleaseRetry::Stale => {
                    return Err(AgentPersistenceError::FenceConflict);
                }
            }
        }
        ensure_revision(&run, expected_revision)?;
        let candidate = run.current_candidate();
        let connector_capacity =
            lock_connector_capacity(&mut transaction, tenant_id, candidate.connector_id()).await?;
        let binding_capacity =
            lock_binding_capacity(&mut transaction, tenant_id, candidate.binding_id()).await?;
        let control_expires_at_millis =
            lock_current_control_expiry(&mut transaction, connector_fence).await?;
        let released_at_millis = timing.now()?;
        let run_expires_at_millis = run
            .current_lease()
            .ok_or(AgentPersistenceError::CorruptData("active Run lease"))?
            .expires_at_millis();
        let release_deadline = control_expires_at_millis.min(run_expires_at_millis);
        if released_at_millis >= release_deadline {
            return Err(AgentPersistenceError::FenceConflict);
        }
        run.release(
            run_lease_id,
            run_lease_epoch,
            connector_fence,
            released_at_millis,
        )
        .map_err(transition_error)?;
        let lease_update = sqlx::query(
            "UPDATE agent.agent_run_leases SET status='released'
              WHERE tenant_id=$1 AND run_id=$2 AND run_lease_id=$3 AND status='active'",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(run_id))
        .bind(Uuid::from(run_lease_id))
        .execute(&mut *transaction)
        .await?;
        if lease_update.rows_affected() != 1
            || connector_capacity.active == 0
            || binding_capacity.active == 0
        {
            return Err(AgentPersistenceError::FenceConflict);
        }
        advance_connector_capacity(
            &mut transaction,
            tenant_id,
            candidate.connector_id(),
            connector_capacity,
            ConnectorCapacity {
                active: connector_capacity.active - 1,
                ..connector_capacity
            },
            released_at_millis,
        )
        .await?;
        advance_binding_capacity(
            &mut transaction,
            tenant_id,
            candidate.binding_id(),
            binding_capacity,
            binding_capacity.active - 1,
            released_at_millis,
        )
        .await?;
        save_head(&mut transaction, &run, expected_revision).await?;
        timing.ensure_before(release_deadline)?;
        transaction.commit().await?;
        Ok(run)
    }
}

/// Encodes the non-secret tenant/Connector key carried by Run-offer notifications.
#[must_use]
pub fn agent_run_offer_notification_payload(
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> String {
    format!("{tenant_id}:{connector_id}")
}

/// Parses one Run-offer wakeup hint. Malformed notifications are ignored.
#[must_use]
pub fn parse_agent_run_offer_notification_payload(
    payload: &str,
) -> Option<(TenantId, ConnectorId)> {
    let (tenant_id, connector_id) = payload.split_once(':')?;
    Some((
        TenantId::try_from(Uuid::parse_str(tenant_id).ok()?).ok()?,
        ConnectorId::try_from(Uuid::parse_str(connector_id).ok()?).ok()?,
    ))
}

#[derive(Clone, Copy)]
struct ConnectorCapacity {
    last_offer_sequence: u64,
    active: u64,
    observation_lease_id: Option<LeaseId>,
    observation_heartbeat_sequence: u64,
    observation_claim_revision: u64,
    observation_reservation_baseline: u64,
    observation_available: u64,
    revision: u64,
}

#[derive(Clone, Copy)]
struct BindingCapacity {
    active: u64,
    revision: u64,
}

#[derive(Clone, Copy)]
struct RouteEligibility {
    fence: ConnectorLeaseFence,
    control_expires_at_millis: i64,
    connector_capacity: ConnectorCapacity,
    evaluated_at_millis: i64,
    proposed_expires_at_millis: i64,
}

#[derive(Clone, Copy)]
struct RouteAdmission {
    connector_capacity: ConnectorCapacity,
    evaluated_at_millis: i64,
    control_expires_at_millis: i64,
    lease_expires_at_millis: i64,
    authorization_expires_at_millis: Option<i64>,
}

impl RouteAdmission {
    fn commit_deadline_millis(self) -> i64 {
        self.lease_expires_at_millis
            .min(self.control_expires_at_millis)
            .min(self.authorization_expires_at_millis.unwrap_or(i64::MAX))
    }
}

#[derive(Clone, Copy)]
enum ClaimTiming<'a> {
    Fixed {
        claimed_at_millis: i64,
        lease_expires_at_millis: i64,
    },
    Current {
        clock: &'a dyn Clock,
        lease_ttl_millis: i64,
    },
}

impl ClaimTiming<'_> {
    fn now(self) -> Result<i64, AgentPersistenceError> {
        match self {
            Self::Fixed {
                claimed_at_millis, ..
            } => Ok(claimed_at_millis),
            Self::Current { clock, .. } => clock
                .now_utc_millis()
                .map_err(|_| AgentPersistenceError::CorruptData("Agent Run claim clock")),
        }
    }

    fn resolve(self, control_expires_at_millis: i64) -> Result<(i64, i64), AgentPersistenceError> {
        match self {
            Self::Fixed {
                claimed_at_millis,
                lease_expires_at_millis,
            } => Ok((claimed_at_millis, lease_expires_at_millis)),
            Self::Current {
                lease_ttl_millis, ..
            } => {
                let claimed_at_millis = self.now()?;
                let lease_expires_at_millis = claimed_at_millis
                    .checked_add(lease_ttl_millis)
                    .map(|deadline| deadline.min(control_expires_at_millis))
                    .filter(|deadline| *deadline > claimed_at_millis)
                    .ok_or(AgentPersistenceError::FenceConflict)?;
                Ok((claimed_at_millis, lease_expires_at_millis))
            }
        }
    }

    fn ensure_commit_before(self, deadline_millis: i64) -> Result<(), AgentPersistenceError> {
        if let Self::Current { clock, .. } = self
            && clock
                .now_utc_millis()
                .map_err(|_| AgentPersistenceError::CorruptData("Agent Run claim clock"))?
                >= deadline_millis
        {
            return Err(AgentPersistenceError::FenceConflict);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum ReleaseTiming<'a> {
    Fixed(i64),
    Current(&'a dyn Clock),
}

impl ReleaseTiming<'_> {
    fn now(self) -> Result<i64, AgentPersistenceError> {
        match self {
            Self::Fixed(now_millis) => Ok(now_millis),
            Self::Current(clock) => clock
                .now_utc_millis()
                .map_err(|_| AgentPersistenceError::CorruptData("Agent Run release clock")),
        }
    }

    fn ensure_before(self, deadline_millis: i64) -> Result<(), AgentPersistenceError> {
        if let Self::Current(clock) = self
            && clock
                .now_utc_millis()
                .map_err(|_| AgentPersistenceError::CorruptData("Agent Run release clock"))?
                >= deadline_millis
        {
            return Err(AgentPersistenceError::FenceConflict);
        }
        Ok(())
    }
}

async fn load_matching_identity(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    request_id: RequestId,
    idempotency_digest: [u8; 32],
) -> Result<Option<AgentRun>, AgentPersistenceError> {
    let rows = sqlx::query(
        "SELECT run_id FROM agent.agent_runs
          WHERE tenant_id=$1 AND (request_id=$2 OR idempotency_digest=$3)
          FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(request_id))
    .bind(idempotency_digest.to_vec())
    .fetch_all(&mut *connection)
    .await?;
    if rows.len() > 1 {
        return Err(AgentPersistenceError::ImmutableConflict(
            "Agent Run idempotency identity",
        ));
    }
    match rows.first() {
        Some(row) => {
            load_run(
                connection,
                tenant_id,
                run_id(row.try_get("run_id")?)?,
                false,
            )
            .await
        }
        None => Ok(None),
    }
}

#[allow(clippy::too_many_lines)]
async fn load_run(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    run_id: RunId,
    for_update: bool,
) -> Result<Option<AgentRun>, AgentPersistenceError> {
    let sql = if for_update {
        "SELECT * FROM agent.agent_runs WHERE tenant_id=$1 AND run_id=$2 FOR UPDATE"
    } else {
        "SELECT * FROM agent.agent_runs WHERE tenant_id=$1 AND run_id=$2"
    };
    let Some(head) = sqlx::query(sql)
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(run_id))
        .fetch_optional(&mut *connection)
        .await?
    else {
        return Ok(None);
    };
    let request = RunRequest::new(
        tenant_id,
        run_id,
        request_id(head.try_get("request_id")?)?,
        bytes_32(
            head.try_get("idempotency_digest")?,
            "Run idempotency digest",
        )?,
        bytes_32(head.try_get("request_digest")?, "Run request digest")?,
        installation_id(head.try_get("installation_id")?)?,
        conversation_id(head.try_get("conversation_id")?)?,
        event_id(head.try_get("request_event_id")?)?,
        optional_connector_id(head.try_get("preferred_connector_id")?)?,
        head.try_get("required_capability_codes")?,
        parse_dispatch(&head.try_get::<String, _>("dispatch_mode")?)?,
        parse_policy(&head.try_get::<String, _>("routing_policy")?)?,
        revision_from_i64(head.try_get("routing_policy_revision")?)?,
        positive_u64(head.try_get("grant_version")?, "Run grant version")?,
        head.try_get("queue_deadline_ms")?,
        head.try_get("created_at_ms")?,
    )
    .map_err(|_| AgentPersistenceError::SnapshotRejected("Agent Run request"))?;
    let candidate_rows = sqlx::query(
        "SELECT candidate_ordinal, binding_id, connector_id, priority, max_concurrency
           FROM agent.agent_run_candidates
          WHERE tenant_id=$1 AND run_id=$2 ORDER BY candidate_ordinal",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(run_id))
    .fetch_all(&mut *connection)
    .await?;
    let expected_count: i32 = head.try_get("candidate_count")?;
    if usize::try_from(expected_count).ok() != Some(candidate_rows.len()) {
        return Err(AgentPersistenceError::SnapshotRejected(
            "Agent Run candidate count",
        ));
    }
    let mut candidates = Vec::with_capacity(candidate_rows.len());
    for (expected, row) in candidate_rows.into_iter().enumerate() {
        let ordinal: i32 = row.try_get("candidate_ordinal")?;
        if usize::try_from(ordinal).ok() != Some(expected) {
            return Err(AgentPersistenceError::SnapshotRejected(
                "Agent Run candidate ordinal",
            ));
        }
        candidates.push(
            RouteCandidate::new(
                binding_id(row.try_get("binding_id")?)?,
                connector_id(row.try_get("connector_id")?)?,
                u16::try_from(row.try_get::<i32, _>("priority")?).map_err(|_| {
                    AgentPersistenceError::CorruptData("Agent Run candidate priority")
                })?,
                u32::try_from(row.try_get::<i64, _>("max_concurrency")?).map_err(|_| {
                    AgentPersistenceError::CorruptData("Agent Run candidate capacity")
                })?,
            )
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Agent Run candidate"))?,
        );
    }
    let current_offer_id: Option<Uuid> = head.try_get("current_offer_id")?;
    let current_offer = match current_offer_id {
        Some(id) => Some(load_offer(connection, tenant_id, run_id, id).await?),
        None => None,
    };
    let current_lease_id: Option<Uuid> = head.try_get("current_run_lease_id")?;
    let current_lease = match current_lease_id {
        Some(id) => Some(load_lease(connection, tenant_id, run_id, id).await?),
        None => None,
    };
    AgentRun::try_from_snapshot(AgentRunSnapshot {
        request,
        candidates,
        state: parse_state(&head.try_get::<String, _>("state")?)?,
        candidate_cursor: u16::try_from(head.try_get::<i32, _>("candidate_cursor")?)
            .map_err(|_| AgentPersistenceError::CorruptData("Run candidate cursor"))?,
        current_offer,
        current_lease,
        highest_offer_attempt: nonnegative_u64(
            head.try_get("highest_offer_attempt")?,
            "Run offer attempt",
        )?,
        highest_run_lease_epoch: nonnegative_u64(
            head.try_get("highest_run_lease_epoch")?,
            "Run lease epoch",
        )?,
        revision: revision_from_i64(head.try_get("aggregate_revision")?)?,
        updated_at_millis: head.try_get("updated_at_ms")?,
        server_time_high_water_millis: head.try_get("server_time_high_water_ms")?,
    })
    .map(Some)
    .map_err(|_| AgentPersistenceError::SnapshotRejected("Agent Run"))
}

async fn load_offer(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    run_id: RunId,
    offer_id_value: Uuid,
) -> Result<RunOffer, AgentPersistenceError> {
    let row = sqlx::query(
        "SELECT offer_id, offer_attempt, candidate_ordinal, connector_id,
                connector_boot_id, connector_generation, connector_lease_id,
                connector_lease_epoch, offered_at_ms, expires_at_ms
           FROM agent.agent_run_offers
          WHERE tenant_id=$1 AND run_id=$2 AND offer_id=$3",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(run_id))
    .bind(offer_id_value)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(AgentPersistenceError::CorruptData("current Run offer"))?;
    RunOffer::try_from_snapshot(RunOfferSnapshot {
        offer_id: run_offer_id(row.try_get("offer_id")?)?,
        attempt: positive_u64(row.try_get("offer_attempt")?, "Run offer attempt")?,
        candidate_index: u16::try_from(row.try_get::<i32, _>("candidate_ordinal")?)
            .map_err(|_| AgentPersistenceError::CorruptData("Run offer candidate"))?,
        connector_fence: fence_from_row(&row, tenant_id)?,
        offered_at_millis: row.try_get("offered_at_ms")?,
        expires_at_millis: row.try_get("expires_at_ms")?,
    })
    .map_err(|_| AgentPersistenceError::SnapshotRejected("Run offer"))
}

async fn load_lease(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    run_id: RunId,
    lease_id_value: Uuid,
) -> Result<RunLease, AgentPersistenceError> {
    let row = sqlx::query(
        "SELECT run_lease_id, run_lease_epoch, offer_id, offer_attempt,
                candidate_ordinal, connector_id, connector_boot_id,
                connector_generation, connector_lease_id, connector_lease_epoch,
                issued_at_ms, expires_at_ms
           FROM agent.agent_run_leases
          WHERE tenant_id=$1 AND run_id=$2 AND run_lease_id=$3",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(run_id))
    .bind(lease_id_value)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(AgentPersistenceError::CorruptData("current Run lease"))?;
    RunLease::try_from_snapshot(RunLeaseSnapshot {
        run_lease_id: run_lease_id(row.try_get("run_lease_id")?)?,
        run_lease_epoch: positive_u64(row.try_get("run_lease_epoch")?, "Run lease epoch")?,
        offer_id: run_offer_id(row.try_get("offer_id")?)?,
        offer_attempt: positive_u64(row.try_get("offer_attempt")?, "Run offer attempt")?,
        candidate_index: u16::try_from(row.try_get::<i32, _>("candidate_ordinal")?)
            .map_err(|_| AgentPersistenceError::CorruptData("Run lease candidate"))?,
        connector_fence: fence_from_row(&row, tenant_id)?,
        issued_at_millis: row.try_get("issued_at_ms")?,
        expires_at_millis: row.try_get("expires_at_ms")?,
    })
    .map_err(|_| AgentPersistenceError::SnapshotRejected("Run lease"))
}

fn fence_from_row(
    row: &sqlx::postgres::PgRow,
    tenant_id: TenantId,
) -> Result<ConnectorLeaseFence, AgentPersistenceError> {
    ConnectorLeaseFence::new(
        tenant_id,
        connector_id(row.try_get("connector_id")?)?,
        boot_id(row.try_get("connector_boot_id")?)?,
        positive_u64(row.try_get("connector_generation")?, "Connector generation")?,
        lease_id(row.try_get("connector_lease_id")?)?,
        positive_u64(
            row.try_get("connector_lease_epoch")?,
            "Connector lease epoch",
        )?,
    )
    .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector lease fence"))
}

async fn initialize_capacity_heads(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    candidate: RouteCandidate,
    created_at_millis: i64,
) -> Result<(), AgentPersistenceError> {
    sqlx::query(
        "INSERT INTO agent.connector_run_capacity_heads (
             tenant_id, connector_id, capacity_revision, created_at_ms, updated_at_ms
         ) VALUES ($1,$2,1,$3,$3) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(candidate.connector_id()))
    .bind(created_at_millis)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO agent.binding_run_capacity_heads (
             tenant_id, binding_id, capacity_revision, created_at_ms, updated_at_ms
         ) VALUES ($1,$2,1,$3,$3) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(candidate.binding_id()))
    .bind(created_at_millis)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn lock_connector_capacity(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> Result<ConnectorCapacity, AgentPersistenceError> {
    let row = sqlx::query(
        "SELECT last_offer_sequence, active_reservation_count,
                observation_lease_id, observation_heartbeat_sequence,
                observation_claim_revision, observation_reservation_baseline,
                observation_available_count, capacity_revision
           FROM agent.connector_run_capacity_heads
          WHERE tenant_id=$1 AND connector_id=$2 FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(AgentPersistenceError::CorruptData(
        "Connector Run capacity head",
    ))?;
    Ok(ConnectorCapacity {
        last_offer_sequence: nonnegative_u64(
            row.try_get("last_offer_sequence")?,
            "Connector offer sequence",
        )?,
        active: nonnegative_u64(
            row.try_get("active_reservation_count")?,
            "Connector reservation count",
        )?,
        observation_lease_id: row
            .try_get::<Option<Uuid>, _>("observation_lease_id")?
            .map(lease_id)
            .transpose()?,
        observation_heartbeat_sequence: nonnegative_u64(
            row.try_get("observation_heartbeat_sequence")?,
            "capacity heartbeat observation",
        )?,
        observation_claim_revision: nonnegative_u64(
            row.try_get("observation_claim_revision")?,
            "capacity claim observation",
        )?,
        observation_reservation_baseline: nonnegative_u64(
            row.try_get("observation_reservation_baseline")?,
            "capacity reservation baseline",
        )?,
        observation_available: nonnegative_u64(
            row.try_get("observation_available_count")?,
            "observed available capacity",
        )?,
        revision: positive_u64(row.try_get("capacity_revision")?, "capacity revision")?,
    })
}

async fn lock_binding_capacity(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    binding_id: BindingId,
) -> Result<BindingCapacity, AgentPersistenceError> {
    let row = sqlx::query(
        "SELECT active_reservation_count, capacity_revision
           FROM agent.binding_run_capacity_heads
          WHERE tenant_id=$1 AND binding_id=$2 FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(binding_id))
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(AgentPersistenceError::CorruptData(
        "Binding Run capacity head",
    ))?;
    Ok(BindingCapacity {
        active: nonnegative_u64(
            row.try_get("active_reservation_count")?,
            "Binding reservation count",
        )?,
        revision: positive_u64(row.try_get("capacity_revision")?, "capacity revision")?,
    })
}

#[allow(clippy::too_many_lines)]
async fn validate_route_eligibility(
    connection: &mut PgConnection,
    run: &AgentRun,
    candidate: RouteCandidate,
    fence: ConnectorLeaseFence,
    mut connector_capacity: ConnectorCapacity,
    binding_reservations: u64,
    timing: ClaimTiming<'_>,
) -> Result<RouteAdmission, AgentPersistenceError> {
    if fence.tenant_id() != run.request().tenant_id()
        || fence.connector_id() != candidate.connector_id()
    {
        return Err(AgentPersistenceError::FenceConflict);
    }
    let row = sqlx::query(
        "SELECT i.desired_state, i.max_concurrency, l.status, l.boot_id,
                l.generation, l.lease_epoch, l.expires_at_ms, l.observed_state,
                l.capacity_available, l.last_heartbeat_sequence,
                b.state AS binding_state,
                b.max_concurrency AS binding_max_concurrency,
                installation.desired_state AS installation_state,
                device.state AS agent_device_state,
                grant_head.current_grant_version,
                grant_version.approved_at_ms AS grant_approved_at_ms,
                grant_version.expires_at_ms AS grant_expires_at_ms,
                grant_version.revoked_at_ms AS grant_revoked_at_ms,
                c.lease_id AS claim_lease_id, c.boot_id AS claim_boot_id,
                c.connector_generation AS claim_generation,
                c.capability_codes, c.maximum_concurrent_runs,
                c.available_concurrent_runs, h.current_claim_revision
           FROM agent.connector_instances i
           JOIN agent.connector_leases l
             ON l.tenant_id=i.tenant_id AND l.connector_id=i.connector_id
            AND l.lease_id=$3
           JOIN agent.connector_bindings b
             ON b.tenant_id=i.tenant_id AND b.binding_id=$4
            AND b.installation_id=$5
           JOIN agent.installations installation
             ON installation.tenant_id=b.tenant_id
            AND installation.installation_id=b.installation_id
           JOIN agent.agent_devices device
             ON device.tenant_id=b.tenant_id
            AND device.agent_device_id=b.agent_device_id
            AND device.installation_id=b.installation_id
           JOIN agent.conversation_grant_heads grant_head
             ON grant_head.tenant_id=b.tenant_id
            AND grant_head.conversation_id=$6
            AND grant_head.installation_id=b.installation_id
           JOIN agent.conversation_grant_versions grant_version
             ON grant_version.tenant_id=grant_head.tenant_id
            AND grant_version.conversation_id=grant_head.conversation_id
            AND grant_version.installation_id=grant_head.installation_id
            AND grant_version.grant_version=grant_head.current_grant_version
            AND grant_version.grant_id=grant_head.current_grant_id
           JOIN agent.connector_runtime_claim_heads h
             ON h.tenant_id=i.tenant_id AND h.connector_id=i.connector_id
           JOIN agent.connector_runtime_claims c
             ON c.tenant_id=h.tenant_id AND c.connector_id=h.connector_id
            AND c.claim_revision=h.current_claim_revision
          WHERE i.tenant_id=$1 AND i.connector_id=$2
          FOR SHARE OF i,l,b,installation,device,grant_head,h",
    )
    .bind(Uuid::from(run.request().tenant_id()))
    .bind(Uuid::from(candidate.connector_id()))
    .bind(Uuid::from(fence.connector_lease_id()))
    .bind(Uuid::from(candidate.binding_id()))
    .bind(Uuid::from(run.request().installation_id()))
    .bind(Uuid::from(run.request().conversation_id()))
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(AgentPersistenceError::FenceConflict)?;
    let control_expires_at_millis: i64 = row.try_get("expires_at_ms")?;
    let (now_millis, lease_expires_at_millis) = timing.resolve(control_expires_at_millis)?;
    let boot: Uuid = row.try_get("boot_id")?;
    let claim_boot: Uuid = row.try_get("claim_boot_id")?;
    let claim_lease: Uuid = row.try_get("claim_lease_id")?;
    let generation = positive_u64(row.try_get("generation")?, "Connector generation")?;
    let claim_generation =
        positive_u64(row.try_get("claim_generation")?, "runtime claim generation")?;
    let lease_epoch = positive_u64(row.try_get("lease_epoch")?, "Connector lease epoch")?;
    if row.try_get::<String, _>("desired_state")? != "running"
        || row.try_get::<String, _>("status")? != "active"
        || row
            .try_get::<Option<String>, _>("observed_state")?
            .as_deref()
            != Some("ready")
        || row.try_get::<i64, _>("expires_at_ms")? <= now_millis
        || boot != Uuid::from(fence.boot_id())
        || generation != fence.connector_generation()
        || lease_epoch != fence.connector_lease_epoch()
        || claim_lease != Uuid::from(fence.connector_lease_id())
        || claim_boot != Uuid::from(fence.boot_id())
        || claim_generation != fence.connector_generation()
    {
        return Err(AgentPersistenceError::FenceConflict);
    }
    if row.try_get::<String, _>("binding_state")? != "enabled"
        || row.try_get::<String, _>("installation_state")? != "enabled"
        || row.try_get::<String, _>("agent_device_state")? != "active"
        || u64::try_from(row.try_get::<i64, _>("binding_max_concurrency")?).ok()
            != Some(u64::from(candidate.max_concurrency()))
    {
        return Err(AgentPersistenceError::FenceConflict);
    }
    let current_grant_version = positive_u64(
        row.try_get("current_grant_version")?,
        "Conversation Grant version",
    )?;
    let grant_approved_at_millis: i64 = row.try_get("grant_approved_at_ms")?;
    let grant_expires_at_millis: Option<i64> = row.try_get("grant_expires_at_ms")?;
    if current_grant_version != run.request().grant_version()
        || row
            .try_get::<Option<i64>, _>("grant_revoked_at_ms")?
            .is_some()
        || now_millis < grant_approved_at_millis
        || grant_expires_at_millis.is_some_and(|expires_at| now_millis >= expires_at)
    {
        return Err(AgentPersistenceError::AuthorizationRejected(
            "Conversation Grant unavailable",
        ));
    }
    let capabilities: Vec<String> = row.try_get("capability_codes")?;
    if run
        .request()
        .required_capabilities()
        .iter()
        .any(|required| capabilities.binary_search(required).is_err())
    {
        return Err(AgentPersistenceError::ClaimRejected(
            "Connector capability unavailable",
        ));
    }
    let configured = nonnegative_u64(row.try_get("max_concurrency")?, "Connector capacity")?;
    let runtime_max = nonnegative_u64(
        row.try_get("maximum_concurrent_runs")?,
        "runtime maximum capacity",
    )?;
    let runtime_available = nonnegative_u64(
        row.try_get("available_concurrent_runs")?,
        "runtime available capacity",
    )?;
    let heartbeat_available = row
        .try_get::<Option<i64>, _>("capacity_available")?
        .map(|value| nonnegative_u64(value, "heartbeat capacity"))
        .transpose()?
        .unwrap_or(0);
    let heartbeat_sequence = positive_u64(
        row.try_get("last_heartbeat_sequence")?,
        "Connector heartbeat sequence",
    )?;
    let claim_revision = positive_u64(
        row.try_get("current_claim_revision")?,
        "runtime claim revision",
    )?;
    let observation_available = runtime_available.min(heartbeat_available);
    if connector_capacity.observation_lease_id != Some(fence.connector_lease_id())
        || connector_capacity.observation_heartbeat_sequence != heartbeat_sequence
        || connector_capacity.observation_claim_revision != claim_revision
    {
        connector_capacity.observation_lease_id = Some(fence.connector_lease_id());
        connector_capacity.observation_heartbeat_sequence = heartbeat_sequence;
        connector_capacity.observation_claim_revision = claim_revision;
        connector_capacity.observation_reservation_baseline = connector_capacity.active;
        connector_capacity.observation_available = observation_available;
    }
    let observed_ceiling = connector_capacity
        .observation_reservation_baseline
        .checked_add(connector_capacity.observation_available)
        .ok_or(AgentPersistenceError::CorruptData(
            "Connector capacity observation",
        ))?;
    let admission_ceiling = configured.min(runtime_max).min(observed_ceiling);
    if connector_capacity.active >= admission_ceiling
        || binding_reservations >= u64::from(candidate.max_concurrency())
    {
        return Err(AgentPersistenceError::ClaimRejected(
            "Connector or Binding capacity unavailable",
        ));
    }
    Ok(RouteAdmission {
        connector_capacity,
        evaluated_at_millis: now_millis,
        control_expires_at_millis,
        lease_expires_at_millis: grant_expires_at_millis
            .map_or(lease_expires_at_millis, |grant_expires_at| {
                lease_expires_at_millis.min(grant_expires_at)
            }),
        authorization_expires_at_millis: grant_expires_at_millis,
    })
}

async fn lock_current_control_expiry(
    connection: &mut PgConnection,
    fence: ConnectorLeaseFence,
) -> Result<i64, AgentPersistenceError> {
    let expires_at_millis = sqlx::query_scalar(
        "SELECT expires_at_ms
           FROM agent.connector_leases
          WHERE tenant_id=$1 AND connector_id=$2 AND lease_id=$3
            AND boot_id=$4 AND generation=$5 AND lease_epoch=$6
            AND status='active'
          FOR SHARE",
    )
    .bind(Uuid::from(fence.tenant_id()))
    .bind(Uuid::from(fence.connector_id()))
    .bind(Uuid::from(fence.connector_lease_id()))
    .bind(Uuid::from(fence.boot_id()))
    .bind(to_i64(
        fence.connector_generation(),
        "Connector generation",
    )?)
    .bind(to_i64(
        fence.connector_lease_epoch(),
        "Connector lease epoch",
    )?)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(AgentPersistenceError::FenceConflict)?;
    Ok(expires_at_millis)
}

async fn probe_route_eligibility(
    connection: &mut PgConnection,
    run: &AgentRun,
    candidate: RouteCandidate,
    connector_capacity: ConnectorCapacity,
    binding_reservations: u64,
    timing: ClaimTiming<'_>,
) -> Result<RouteEligibility, AgentPersistenceError> {
    let row = sqlx::query(
        "SELECT l.boot_id, l.generation, l.lease_id, l.lease_epoch, l.expires_at_ms
           FROM agent.connector_leases l
          WHERE l.tenant_id=$1 AND l.connector_id=$2 AND l.status='active'",
    )
    .bind(Uuid::from(run.request().tenant_id()))
    .bind(Uuid::from(candidate.connector_id()))
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(AgentPersistenceError::FenceConflict)?;
    let fence = ConnectorLeaseFence::new(
        run.request().tenant_id(),
        candidate.connector_id(),
        boot_id(row.try_get("boot_id")?)?,
        positive_u64(row.try_get("generation")?, "Connector generation")?,
        lease_id(row.try_get("lease_id")?)?,
        positive_u64(row.try_get("lease_epoch")?, "Connector lease epoch")?,
    )
    .map_err(|_| AgentPersistenceError::FenceConflict)?;
    let admission = validate_route_eligibility(
        connection,
        run,
        candidate,
        fence,
        connector_capacity,
        binding_reservations,
        timing,
    )
    .await?;
    Ok(RouteEligibility {
        fence,
        control_expires_at_millis: row.try_get("expires_at_ms")?,
        connector_capacity: admission.connector_capacity,
        evaluated_at_millis: admission.evaluated_at_millis,
        proposed_expires_at_millis: admission.commit_deadline_millis(),
    })
}

async fn advance_connector_capacity(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    previous: ConnectorCapacity,
    next: ConnectorCapacity,
    updated_at_millis: i64,
) -> Result<(), AgentPersistenceError> {
    let updated = sqlx::query(
        "UPDATE agent.connector_run_capacity_heads
            SET last_offer_sequence=$4, active_reservation_count=$5,
                observation_lease_id=$6, observation_heartbeat_sequence=$7,
                observation_claim_revision=$8, observation_reservation_baseline=$9,
                observation_available_count=$10,
                capacity_revision=$3+1, updated_at_ms=$11
          WHERE tenant_id=$1 AND connector_id=$2 AND capacity_revision=$3",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .bind(to_i64(previous.revision, "capacity revision")?)
    .bind(to_i64(
        next.last_offer_sequence,
        "Connector offer sequence",
    )?)
    .bind(to_i64(next.active, "Connector reservation count")?)
    .bind(next.observation_lease_id.map(Uuid::from))
    .bind(to_i64(
        next.observation_heartbeat_sequence,
        "capacity heartbeat observation",
    )?)
    .bind(to_i64(
        next.observation_claim_revision,
        "capacity claim observation",
    )?)
    .bind(to_i64(
        next.observation_reservation_baseline,
        "capacity reservation baseline",
    )?)
    .bind(to_i64(
        next.observation_available,
        "observed available capacity",
    )?)
    .bind(updated_at_millis)
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::RevisionConflict {
            current: Some(previous.revision),
        })
    }
}

async fn advance_binding_capacity(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    binding_id: BindingId,
    previous: BindingCapacity,
    active: u64,
    updated_at_millis: i64,
) -> Result<(), AgentPersistenceError> {
    let updated = sqlx::query(
        "UPDATE agent.binding_run_capacity_heads
            SET active_reservation_count=$4, capacity_revision=$3+1, updated_at_ms=$5
          WHERE tenant_id=$1 AND binding_id=$2 AND capacity_revision=$3",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(binding_id))
    .bind(to_i64(previous.revision, "capacity revision")?)
    .bind(to_i64(active, "Binding reservation count")?)
    .bind(updated_at_millis)
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::RevisionConflict {
            current: Some(previous.revision),
        })
    }
}

async fn insert_offer(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    run_id: RunId,
    candidate: RouteCandidate,
    offer: RunOffer,
    connector_sequence: u64,
) -> Result<(), AgentPersistenceError> {
    let offer = offer.snapshot();
    let fence = offer.connector_fence;
    sqlx::query(
        "INSERT INTO agent.agent_run_offers (
             tenant_id, run_id, offer_id, offer_attempt, connector_offer_sequence,
             candidate_ordinal, binding_id, connector_id, connector_boot_id,
             connector_generation, connector_lease_id, connector_lease_epoch,
             offered_at_ms, expires_at_ms, status
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'offered')",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(run_id))
    .bind(Uuid::from(offer.offer_id))
    .bind(to_i64(offer.attempt, "Run offer attempt")?)
    .bind(to_i64(connector_sequence, "Connector offer sequence")?)
    .bind(i32::from(offer.candidate_index))
    .bind(Uuid::from(candidate.binding_id()))
    .bind(Uuid::from(candidate.connector_id()))
    .bind(Uuid::from(fence.boot_id()))
    .bind(to_i64(
        fence.connector_generation(),
        "Connector generation",
    )?)
    .bind(Uuid::from(fence.connector_lease_id()))
    .bind(to_i64(
        fence.connector_lease_epoch(),
        "Connector lease epoch",
    )?)
    .bind(offer.offered_at_millis)
    .bind(offer.expires_at_millis)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn mark_offer_claimed(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    run_id: RunId,
    offer_id: RunOfferId,
) -> Result<(), AgentPersistenceError> {
    let updated = sqlx::query(
        "UPDATE agent.agent_run_offers SET status='claimed'
          WHERE tenant_id=$1 AND run_id=$2 AND offer_id=$3 AND status='offered'",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(run_id))
    .bind(Uuid::from(offer_id))
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::FenceConflict)
    }
}

async fn mark_offer_expired(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    run_id: RunId,
    offer_id: RunOfferId,
) -> Result<(), AgentPersistenceError> {
    let updated = sqlx::query(
        "UPDATE agent.agent_run_offers SET status='expired'
          WHERE tenant_id=$1 AND run_id=$2 AND offer_id=$3 AND status='offered'",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(run_id))
    .bind(Uuid::from(offer_id))
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::CorruptData("due Run offer"))
    }
}

async fn mark_lease_expired(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    run_id: RunId,
    run_lease_id: RunLeaseId,
) -> Result<(), AgentPersistenceError> {
    let updated = sqlx::query(
        "UPDATE agent.agent_run_leases SET status='expired'
          WHERE tenant_id=$1 AND run_id=$2 AND run_lease_id=$3 AND status='active'",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(run_id))
    .bind(Uuid::from(run_lease_id))
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::CorruptData("due Run lease"))
    }
}

async fn insert_lease(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    run_id: RunId,
    candidate: RouteCandidate,
    lease: RunLease,
) -> Result<(), AgentPersistenceError> {
    let lease = lease.snapshot();
    let fence = lease.connector_fence;
    sqlx::query(
        "INSERT INTO agent.agent_run_leases (
             tenant_id, run_id, run_lease_id, run_lease_epoch, offer_id,
             offer_attempt, candidate_ordinal, binding_id, connector_id,
             connector_boot_id, connector_generation, connector_lease_id,
             connector_lease_epoch, issued_at_ms, expires_at_ms, status
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'active')",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(run_id))
    .bind(Uuid::from(lease.run_lease_id))
    .bind(to_i64(lease.run_lease_epoch, "Run lease epoch")?)
    .bind(Uuid::from(lease.offer_id))
    .bind(to_i64(lease.offer_attempt, "Run offer attempt")?)
    .bind(i32::from(lease.candidate_index))
    .bind(Uuid::from(candidate.binding_id()))
    .bind(Uuid::from(candidate.connector_id()))
    .bind(Uuid::from(fence.boot_id()))
    .bind(to_i64(
        fence.connector_generation(),
        "Connector generation",
    )?)
    .bind(Uuid::from(fence.connector_lease_id()))
    .bind(to_i64(
        fence.connector_lease_epoch(),
        "Connector lease epoch",
    )?)
    .bind(lease.issued_at_millis)
    .bind(lease.expires_at_millis)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn save_head(
    connection: &mut PgConnection,
    run: &AgentRun,
    expected_revision: Revision,
) -> Result<(), AgentPersistenceError> {
    let snapshot = run.snapshot();
    let updated = sqlx::query(
        "UPDATE agent.agent_runs
            SET state=$4, candidate_cursor=$5, highest_offer_attempt=$6,
                highest_run_lease_epoch=$7, current_offer_id=$8,
                current_run_lease_id=$9, aggregate_revision=$10,
                server_time_high_water_ms=$11, updated_at_ms=$12
          WHERE tenant_id=$1 AND run_id=$2 AND aggregate_revision=$3",
    )
    .bind(Uuid::from(snapshot.request.tenant_id()))
    .bind(Uuid::from(snapshot.request.run_id()))
    .bind(revision_to_i64(expected_revision)?)
    .bind(state_code(snapshot.state))
    .bind(i32::from(snapshot.candidate_cursor))
    .bind(to_i64(snapshot.highest_offer_attempt, "Run offer attempt")?)
    .bind(to_i64(snapshot.highest_run_lease_epoch, "Run lease epoch")?)
    .bind(
        snapshot
            .current_offer
            .map(|offer| Uuid::from(offer.offer_id())),
    )
    .bind(
        snapshot
            .current_lease
            .map(|lease| Uuid::from(lease.run_lease_id())),
    )
    .bind(revision_to_i64(snapshot.revision)?)
    .bind(snapshot.server_time_high_water_millis)
    .bind(snapshot.updated_at_millis)
    .execute(&mut *connection)
    .await?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::RevisionConflict {
            current: Some(expected_revision.get()),
        })
    }
}

fn ensure_revision(run: &AgentRun, expected: Revision) -> Result<(), AgentPersistenceError> {
    if run.revision() == expected {
        Ok(())
    } else {
        Err(AgentPersistenceError::RevisionConflict {
            current: Some(run.revision().get()),
        })
    }
}

fn transition_error(error: RouterError) -> AgentPersistenceError {
    match error {
        RouterError::StaleOffer | RouterError::StaleRunLease => {
            AgentPersistenceError::FenceConflict
        }
        RouterError::InvalidTransition | RouterError::ServerTimeRollback => {
            AgentPersistenceError::RevisionConflict { current: None }
        }
        _ => AgentPersistenceError::SnapshotRejected("Agent Run transition"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminalReleaseRetry {
    Existing,
    Stale,
}

fn classify_terminal_release_retry(
    exact: bool,
    status: &str,
) -> Result<TerminalReleaseRetry, AgentPersistenceError> {
    match status {
        "released" if exact => Ok(TerminalReleaseRetry::Existing),
        "released" | "expired" => Ok(TerminalReleaseRetry::Stale),
        _ => Err(AgentPersistenceError::CorruptData(
            "terminal Run lease status",
        )),
    }
}

const fn dispatch_code(mode: DispatchMode) -> &'static str {
    match mode {
        DispatchMode::Single => "single",
        DispatchMode::Failover => "failover",
    }
}

const fn policy_code(policy: RoutingPolicy) -> &'static str {
    match policy {
        RoutingPolicy::Exclusive => "exclusive",
        RoutingPolicy::OrderedFailover => "ordered_failover",
    }
}

const fn state_code(state: RunRoutingState) -> &'static str {
    match state {
        RunRoutingState::Queued => "queued",
        RunRoutingState::Offered => "offered",
        RunRoutingState::Leased => "leased",
        RunRoutingState::ReconcileRequired => "reconcile_required",
        RunRoutingState::Expired => "expired",
    }
}

fn parse_dispatch(value: &str) -> Result<DispatchMode, AgentPersistenceError> {
    match value {
        "single" => Ok(DispatchMode::Single),
        "failover" => Ok(DispatchMode::Failover),
        _ => Err(AgentPersistenceError::CorruptData("Run dispatch mode")),
    }
}

fn parse_policy(value: &str) -> Result<RoutingPolicy, AgentPersistenceError> {
    match value {
        "exclusive" => Ok(RoutingPolicy::Exclusive),
        "ordered_failover" => Ok(RoutingPolicy::OrderedFailover),
        _ => Err(AgentPersistenceError::CorruptData("Run routing policy")),
    }
}

fn parse_state(value: &str) -> Result<RunRoutingState, AgentPersistenceError> {
    match value {
        "queued" => Ok(RunRoutingState::Queued),
        "offered" => Ok(RunRoutingState::Offered),
        "leased" => Ok(RunRoutingState::Leased),
        "reconcile_required" => Ok(RunRoutingState::ReconcileRequired),
        "expired" => Ok(RunRoutingState::Expired),
        _ => Err(AgentPersistenceError::CorruptData("Run routing state")),
    }
}

fn bytes_32(value: Vec<u8>, field: &'static str) -> Result<[u8; 32], AgentPersistenceError> {
    value
        .try_into()
        .map_err(|_| AgentPersistenceError::CorruptData(field))
}

fn positive_u64(value: i64, field: &'static str) -> Result<u64, AgentPersistenceError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0 && *value <= Revision::MAX)
        .ok_or(AgentPersistenceError::CorruptData(field))
}

fn nonnegative_u64(value: i64, field: &'static str) -> Result<u64, AgentPersistenceError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= Revision::MAX)
        .ok_or(AgentPersistenceError::CorruptData(field))
}

fn to_i64(value: u64, field: &'static str) -> Result<i64, AgentPersistenceError> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value >= 0)
        .ok_or(AgentPersistenceError::CorruptData(field))
}

macro_rules! uuid_id {
    ($name:ident, $ty:ty, $field:literal) => {
        fn $name(value: Uuid) -> Result<$ty, AgentPersistenceError> {
            <$ty>::try_from(value).map_err(|_| AgentPersistenceError::CorruptData($field))
        }
    };
}

uuid_id!(run_id, RunId, "Run ID");
uuid_id!(request_id, RequestId, "Run request ID");
uuid_id!(installation_id, InstallationId, "Installation ID");
uuid_id!(conversation_id, ConversationId, "Conversation ID");
uuid_id!(event_id, EventId, "request Event ID");
uuid_id!(connector_id, ConnectorId, "Connector ID");
uuid_id!(binding_id, BindingId, "Binding ID");
uuid_id!(boot_id, BootId, "Connector Boot ID");
uuid_id!(lease_id, LeaseId, "Connector Lease ID");
uuid_id!(run_offer_id, RunOfferId, "Run Offer ID");
uuid_id!(run_lease_id, RunLeaseId, "Run Lease ID");

fn optional_connector_id(
    value: Option<Uuid>,
) -> Result<Option<ConnectorId>, AgentPersistenceError> {
    value.map(connector_id).transpose()
}

fn run_create_retry_matches(existing: &AgentRun, incoming: &AgentRun) -> bool {
    let left_request = existing.request();
    let right_request = incoming.request();
    left_request.tenant_id() == right_request.tenant_id()
        && left_request.request_id() == right_request.request_id()
        && left_request.idempotency_digest() == right_request.idempotency_digest()
        && left_request.request_digest() == right_request.request_digest()
        && left_request.installation_id() == right_request.installation_id()
        && left_request.conversation_id() == right_request.conversation_id()
        && left_request.request_event_id() == right_request.request_event_id()
        && left_request.preferred_connector_id() == right_request.preferred_connector_id()
        && left_request.required_capabilities() == right_request.required_capabilities()
        && left_request.dispatch_mode() == right_request.dispatch_mode()
        && left_request.grant_version() == right_request.grant_version()
        && left_request
            .queue_deadline_millis()
            .checked_sub(left_request.created_at_millis())
            == right_request
                .queue_deadline_millis()
                .checked_sub(right_request.created_at_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_payload_round_trips_and_rejects_malformed_input() {
        let tenant_id = TenantId::new();
        let connector_id = ConnectorId::new();
        let payload = agent_run_offer_notification_payload(tenant_id, connector_id);
        assert_eq!(
            parse_agent_run_offer_notification_payload(&payload),
            Some((tenant_id, connector_id))
        );
        assert_eq!(
            parse_agent_run_offer_notification_payload("not-a-route"),
            None
        );
    }

    #[test]
    fn terminal_release_retry_accepts_released_but_rejects_expired() {
        assert_eq!(
            classify_terminal_release_retry(true, "released").unwrap(),
            TerminalReleaseRetry::Existing
        );
        assert_eq!(
            classify_terminal_release_retry(true, "expired").unwrap(),
            TerminalReleaseRetry::Stale
        );
        assert_eq!(
            classify_terminal_release_retry(false, "released").unwrap(),
            TerminalReleaseRetry::Stale
        );
    }
}
