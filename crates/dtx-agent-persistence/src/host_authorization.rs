use std::collections::BTreeMap;

use dtx_agent_host::{AgentHost, HostLifecycle};
use dtx_domain::{HostCredentialId, HostId, Revision, TenantId};
use dtx_security::{
    CertificateFingerprint, HostCredentialAuthorizationSnapshot, HostCredentialAuthorizer,
    HostCredentialBinding, HostCredentialBindingError, HostWorkloadIdentity, RetiredHostCredential,
};
use sha2::{Digest, Sha256};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

use crate::{
    AgentHostRepository, AgentPersistenceError, CurrentWrite,
    registry::{bytes_32, revision_from_i64, revision_to_i64},
};

const SNAPSHOT_DIGEST_DOMAIN: &[u8] = b"dtx.host-credential-authorization.snapshot.v1\0";

/// Durable per-tenant Host certificate authorization head and append-only history.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostCredentialAuthorizationRepository;

impl HostCredentialAuthorizationRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Atomically stores an initial image or one exact monotonic successor.
    ///
    /// The tenant stream-head row serializes first creation as well as later
    /// successors. Existing exact images are idempotent; every different image
    /// must be the exact next revision accepted by [`HostCredentialAuthorizer`].
    /// Credential-changing Host writes must be committed in the same outer
    /// transaction, or use [`Self::save_with_host`], so another transaction can
    /// never observe a stale authorization head beside newer base Host state.
    ///
    /// # Errors
    ///
    /// Rejects cross-tenant, stale, rollback, incomplete-history, immutable
    /// credential, corrupt stored-state, and database/RLS/constraint failures.
    pub async fn save(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        snapshot: &HostCredentialAuthorizationSnapshot,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let proposed = canonical_snapshot(tenant_id, snapshot)?;
        let mut transaction = connection.begin().await?;
        let result = self
            .save_in_transaction(&mut transaction, tenant_id, &proposed, stored_at_ms)
            .await;
        match result {
            Ok(write) => {
                transaction.commit().await?;
                Ok(write)
            }
            Err(error) => {
                transaction.rollback().await?;
                Err(error)
            }
        }
    }

    /// Atomically stores one credential-changing Host image and its tenant-wide
    /// authorization successor.
    ///
    /// Use this path for enrollment, rotation, or revocation of one Host. A
    /// caller changing multiple Hosts together must compose their Host writes
    /// and [`Self::save`] inside one explicit outer tenant transaction.
    ///
    /// # Errors
    ///
    /// Rolls back both images and returns any Host, authorization, RLS, or
    /// database contract failure.
    pub async fn save_with_host(
        self,
        connection: &mut PgConnection,
        host: &AgentHost,
        snapshot: &HostCredentialAuthorizationSnapshot,
        stored_at_ms: i64,
    ) -> Result<(CurrentWrite, CurrentWrite), AgentPersistenceError> {
        let tenant_id = host.tenant_id();
        let proposed = canonical_snapshot(tenant_id, snapshot)?;
        let mut transaction = connection.begin().await?;
        let host_write = AgentHostRepository::new()
            .save(&mut transaction, host, stored_at_ms)
            .await;
        let result = match host_write {
            Ok(host_write) => self
                .save_in_transaction(&mut transaction, tenant_id, &proposed, stored_at_ms)
                .await
                .map(|authorization_write| (host_write, authorization_write)),
            Err(error) => Err(error),
        };
        match result {
            Ok(writes) => {
                transaction.commit().await?;
                Ok(writes)
            }
            Err(error) => {
                transaction.rollback().await?;
                Err(error)
            }
        }
    }

    async fn save_in_transaction(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        proposed: &HostCredentialAuthorizationSnapshot,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        lock_tenant(connection, tenant_id).await?;

        let head = load_head_revision(connection, tenant_id).await?;

        let (facts, write, previous_revision) = if let Some(head) = head {
            let current = load_history(connection, tenant_id, head).await?;
            if current.snapshot == *proposed {
                validate_current_base_state(connection, tenant_id, &current.facts).await?;
                return Ok(CurrentWrite::Existing);
            }
            let expected_revision = head
                .checked_next()
                .map_err(|_| AgentPersistenceError::SnapshotRejected("authorization revision"))?;
            if proposed.revision() != expected_revision {
                return Err(AgentPersistenceError::RevisionConflict {
                    current: Some(head.get()),
                });
            }
            let validator = HostCredentialAuthorizer::try_from_snapshot(&current.snapshot)
                .map_err(snapshot_rejected)?;
            validator
                .replace(head, proposed.current().iter().copied())
                .map_err(snapshot_rejected)?;
            let expected = validator.snapshot().map_err(snapshot_rejected)?;
            if expected != *proposed {
                return Err(AgentPersistenceError::SnapshotRejected(
                    "Host credential authorization successor",
                ));
            }
            (
                successor_facts(proposed, &current.facts)?,
                CurrentWrite::Advanced,
                Some(head),
            )
        } else {
            if proposed.revision() != Revision::INITIAL || !proposed.retired().is_empty() {
                return Err(AgentPersistenceError::RevisionConflict { current: None });
            }
            (initial_facts(proposed), CurrentWrite::Inserted, None)
        };

        validate_current_base_state(connection, tenant_id, &facts).await?;

        for fact in &facts {
            ensure_credential(
                connection,
                tenant_id,
                proposed.revision(),
                *fact,
                stored_at_ms,
            )
            .await?;
        }
        insert_revision(
            connection,
            tenant_id,
            proposed.revision(),
            &facts,
            stored_at_ms,
        )
        .await?;
        insert_states(connection, tenant_id, proposed.revision(), &facts).await?;

        if let Some(previous_revision) = previous_revision {
            let updated = sqlx::query(
                "UPDATE agent.host_credential_authorization_heads
                    SET current_revision=$3, updated_at_ms=$4
                  WHERE tenant_id=$1 AND current_revision=$2",
            )
            .bind(Uuid::from(tenant_id))
            .bind(revision_to_i64(previous_revision)?)
            .bind(revision_to_i64(proposed.revision())?)
            .bind(stored_at_ms)
            .execute(&mut *connection)
            .await?;
            if updated.rows_affected() != 1 {
                return Err(AgentPersistenceError::RevisionConflict {
                    current: Some(previous_revision.get()),
                });
            }
        } else {
            sqlx::query(
                "INSERT INTO agent.host_credential_authorization_heads
                     (tenant_id, current_revision, created_at_ms, updated_at_ms)
                 VALUES ($1,$2,$3,$3)",
            )
            .bind(Uuid::from(tenant_id))
            .bind(revision_to_i64(proposed.revision())?)
            .bind(stored_at_ms)
            .execute(&mut *connection)
            .await?;
        }

        let persisted = load_history(connection, tenant_id, proposed.revision()).await?;
        if persisted.snapshot != *proposed {
            return Err(AgentPersistenceError::SnapshotRejected(
                "persisted Host credential authorization image",
            ));
        }
        Ok(write)
    }

    /// Loads the current per-tenant authorization head after validating every
    /// historical digest, exact semantic successor, and current base Host state.
    ///
    /// # Errors
    ///
    /// Returns database/RLS failures or rejects incomplete, modified, invalid,
    /// rolled-back, or base-state-inconsistent facts.
    pub async fn load(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
    ) -> Result<Option<HostCredentialAuthorizationSnapshot>, AgentPersistenceError> {
        let head = load_head_revision(connection, tenant_id).await?;
        let Some(revision) = head else {
            return Ok(None);
        };
        let loaded = load_history(connection, tenant_id, revision).await?;
        validate_current_base_state(connection, tenant_id, &loaded.facts).await?;
        Ok(Some(loaded.snapshot))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialStatus {
    Current,
    Retired,
}

impl CredentialStatus {
    const fn code(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Retired => "retired",
        }
    }

    fn parse(value: &str) -> Result<Self, AgentPersistenceError> {
        match value {
            "current" => Ok(Self::Current),
            "retired" => Ok(Self::Retired),
            _ => Err(AgentPersistenceError::CorruptData(
                "Host credential authorization status",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StoredFact {
    host_id: HostId,
    credential_id: HostCredentialId,
    fingerprint: CertificateFingerprint,
    not_before: u64,
    not_after: u64,
    revoked_at: Option<u64>,
    status: CredentialStatus,
}

impl StoredFact {
    fn from_current(binding: HostCredentialBinding) -> Self {
        Self {
            host_id: binding.identity().host_id(),
            credential_id: binding.credential_id(),
            fingerprint: binding.certificate_fingerprint(),
            not_before: binding.not_before_unix_seconds(),
            not_after: binding.not_after_unix_seconds(),
            revoked_at: binding.revoked_at_unix_seconds(),
            status: CredentialStatus::Current,
        }
    }
}

struct LoadedRevision {
    snapshot: HostCredentialAuthorizationSnapshot,
    facts: Vec<StoredFact>,
}

#[derive(Default)]
struct BaseHostState {
    lifecycle: Option<HostLifecycle>,
    current: Option<HostCredentialId>,
    retired: Vec<HostCredentialId>,
}

async fn validate_current_base_state(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    facts: &[StoredFact],
) -> Result<(), AgentPersistenceError> {
    let hosts = load_base_host_states(connection, tenant_id).await?;
    let mut authorization_current = BTreeMap::new();
    for fact in facts {
        let Some(host) = hosts.get(&fact.host_id) else {
            return Err(AgentPersistenceError::SnapshotRejected(
                "Host credential authorization/base state",
            ));
        };
        match fact.status {
            CredentialStatus::Current => {
                if host.current != Some(fact.credential_id)
                    || authorization_current
                        .insert(fact.host_id, fact.credential_id)
                        .is_some()
                {
                    return Err(AgentPersistenceError::SnapshotRejected(
                        "Host credential authorization/base state",
                    ));
                }
            }
            CredentialStatus::Retired if !host.retired.contains(&fact.credential_id) => {
                return Err(AgentPersistenceError::SnapshotRejected(
                    "Host credential authorization/base state",
                ));
            }
            CredentialStatus::Retired => {}
        }
    }

    for (host_id, host) in hosts {
        let lifecycle = host
            .lifecycle
            .ok_or(AgentPersistenceError::CorruptData("Host lifecycle"))?;
        match lifecycle {
            HostLifecycle::Active | HostLifecycle::Quarantined => {
                let current = host.current.ok_or(AgentPersistenceError::CorruptData(
                    "Host credential lifecycle",
                ))?;
                if authorization_current.get(&host_id) != Some(&current) {
                    return Err(AgentPersistenceError::SnapshotRejected(
                        "Host credential authorization/base state",
                    ));
                }
            }
            HostLifecycle::AwaitingEnrollment => {
                if host.current.is_some()
                    || !host.retired.is_empty()
                    || authorization_current.contains_key(&host_id)
                {
                    return Err(AgentPersistenceError::CorruptData(
                        "Host credential lifecycle",
                    ));
                }
            }
            HostLifecycle::Revoked => {
                if host.current.is_some() || authorization_current.contains_key(&host_id) {
                    return Err(AgentPersistenceError::CorruptData(
                        "Host credential lifecycle",
                    ));
                }
            }
        }
    }
    Ok(())
}

async fn load_base_host_states(
    connection: &mut PgConnection,
    tenant_id: TenantId,
) -> Result<BTreeMap<HostId, BaseHostState>, AgentPersistenceError> {
    let rows = sqlx::query(
        "SELECT host.host_id, host.lifecycle,
                credential.credential_id, credential.status
           FROM agent.hosts AS host
           LEFT JOIN agent.host_credentials AS credential
             ON credential.tenant_id=host.tenant_id
            AND credential.host_id=host.host_id
          WHERE host.tenant_id=$1
          ORDER BY host.host_id, credential.credential_id",
    )
    .bind(Uuid::from(tenant_id))
    .fetch_all(&mut *connection)
    .await?;

    let mut hosts = BTreeMap::<HostId, BaseHostState>::new();
    for row in rows {
        let raw_host_id: Uuid = row.try_get("host_id")?;
        let host_id = HostId::try_from(raw_host_id)
            .map_err(|_| AgentPersistenceError::CorruptData("Host ID"))?;
        let lifecycle = parse_base_lifecycle(row.try_get("lifecycle")?)?;
        let state = hosts.entry(host_id).or_default();
        if state
            .lifecycle
            .replace(lifecycle)
            .is_some_and(|known| known != lifecycle)
        {
            return Err(AgentPersistenceError::CorruptData("Host lifecycle"));
        }
        let raw_credential_id: Option<Uuid> = row.try_get("credential_id")?;
        let status: Option<String> = row.try_get("status")?;
        match (raw_credential_id, status.as_deref()) {
            (None, None) => {}
            (Some(raw_credential_id), Some(status)) => {
                let credential_id = HostCredentialId::try_from(raw_credential_id)
                    .map_err(|_| AgentPersistenceError::CorruptData("Host credential ID"))?;
                match CredentialStatus::parse(status)? {
                    CredentialStatus::Current if state.current.replace(credential_id).is_none() => {
                    }
                    CredentialStatus::Retired if !state.retired.contains(&credential_id) => {
                        state.retired.push(credential_id);
                    }
                    CredentialStatus::Current | CredentialStatus::Retired => {
                        return Err(AgentPersistenceError::CorruptData(
                            "Host credential history",
                        ));
                    }
                }
            }
            _ => {
                return Err(AgentPersistenceError::CorruptData(
                    "Host credential base state",
                ));
            }
        }
    }
    Ok(hosts)
}

fn parse_base_lifecycle(value: &str) -> Result<HostLifecycle, AgentPersistenceError> {
    match value {
        "awaiting_enrollment" => Ok(HostLifecycle::AwaitingEnrollment),
        "active" => Ok(HostLifecycle::Active),
        "quarantined" => Ok(HostLifecycle::Quarantined),
        "revoked" => Ok(HostLifecycle::Revoked),
        _ => Err(AgentPersistenceError::CorruptData("Host lifecycle")),
    }
}

async fn load_head_revision(
    connection: &mut PgConnection,
    tenant_id: TenantId,
) -> Result<Option<Revision>, AgentPersistenceError> {
    let head: Option<i64> = sqlx::query_scalar(
        "SELECT current_revision
           FROM agent.host_credential_authorization_heads
          WHERE tenant_id=$1",
    )
    .bind(Uuid::from(tenant_id))
    .fetch_optional(&mut *connection)
    .await?;
    let history: (Option<i64>, Option<i64>, i64) = sqlx::query_as(
        "SELECT min(authorization_revision), max(authorization_revision), count(*)
           FROM agent.host_credential_authorization_revisions
          WHERE tenant_id=$1",
    )
    .bind(Uuid::from(tenant_id))
    .fetch_one(&mut *connection)
    .await?;
    match (head, history) {
        (None, (None, None, 0)) => Ok(None),
        (Some(head), (Some(low_water), Some(high_water), count)) => {
            let head = revision_from_i64(head)?;
            let low_water = revision_from_i64(low_water)?;
            let high_water = revision_from_i64(high_water)?;
            let expected_count = i64::try_from(head.get()).map_err(|_| {
                AgentPersistenceError::CorruptData("Host authorization revision count")
            })?;
            if low_water == Revision::INITIAL && head == high_water && count == expected_count {
                Ok(Some(head))
            } else {
                Err(AgentPersistenceError::CorruptData(
                    "Host authorization revision high-water",
                ))
            }
        }
        _ => Err(AgentPersistenceError::CorruptData(
            "Host authorization head/history",
        )),
    }
}

async fn load_history(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    head: Revision,
) -> Result<LoadedRevision, AgentPersistenceError> {
    let mut previous: Option<LoadedRevision> = None;
    for value in Revision::INITIAL.get()..=head.get() {
        let revision = Revision::new(value)
            .map_err(|_| AgentPersistenceError::CorruptData("Host authorization revision"))?;
        let current = load_revision(connection, tenant_id, revision).await?;
        if let Some(predecessor) = previous.as_ref() {
            let validator = HostCredentialAuthorizer::try_from_snapshot(&predecessor.snapshot)
                .map_err(|_| {
                    AgentPersistenceError::CorruptData("Host authorization predecessor snapshot")
                })?;
            validator
                .replace(
                    predecessor.snapshot.revision(),
                    current.snapshot.current().iter().copied(),
                )
                .map_err(|_| {
                    AgentPersistenceError::CorruptData("Host authorization semantic successor")
                })?;
            let expected = validator.snapshot().map_err(|_| {
                AgentPersistenceError::CorruptData("Host authorization semantic successor")
            })?;
            if expected != current.snapshot {
                return Err(AgentPersistenceError::CorruptData(
                    "Host authorization semantic successor",
                ));
            }
        } else if !current.snapshot.retired().is_empty() {
            return Err(AgentPersistenceError::CorruptData(
                "Host authorization initial snapshot",
            ));
        }
        previous = Some(current);
    }
    previous.ok_or(AgentPersistenceError::CorruptData(
        "Host authorization history",
    ))
}

async fn lock_tenant(
    connection: &mut PgConnection,
    tenant_id: TenantId,
) -> Result<(), AgentPersistenceError> {
    let tenant_lock: Option<Uuid> = sqlx::query_scalar(
        "SELECT tenant_id FROM system.tenant_stream_heads
          WHERE tenant_id=$1 FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .fetch_optional(&mut *connection)
    .await?;
    tenant_lock
        .map(|_| ())
        .ok_or(AgentPersistenceError::RevisionConflict { current: None })
}

fn canonical_snapshot(
    tenant_id: TenantId,
    snapshot: &HostCredentialAuthorizationSnapshot,
) -> Result<HostCredentialAuthorizationSnapshot, AgentPersistenceError> {
    let authorizer =
        HostCredentialAuthorizer::try_from_snapshot(snapshot).map_err(snapshot_rejected)?;
    let canonical = authorizer.snapshot().map_err(snapshot_rejected)?;
    if canonical
        .current()
        .iter()
        .any(|binding| binding.identity().tenant_id() != tenant_id)
    {
        return Err(AgentPersistenceError::SnapshotRejected(
            "cross-tenant Host credential authorization",
        ));
    }
    Ok(canonical)
}

fn snapshot_rejected(_error: HostCredentialBindingError) -> AgentPersistenceError {
    AgentPersistenceError::SnapshotRejected("Host credential authorization")
}

fn initial_facts(snapshot: &HostCredentialAuthorizationSnapshot) -> Vec<StoredFact> {
    let mut facts = snapshot
        .current()
        .iter()
        .copied()
        .map(StoredFact::from_current)
        .collect::<Vec<_>>();
    facts.sort_unstable_by_key(|fact| fact.credential_id);
    facts
}

fn successor_facts(
    snapshot: &HostCredentialAuthorizationSnapshot,
    previous: &[StoredFact],
) -> Result<Vec<StoredFact>, AgentPersistenceError> {
    let previous = previous
        .iter()
        .map(|fact| (fact.credential_id, *fact))
        .collect::<BTreeMap<_, _>>();
    let mut facts = snapshot
        .current()
        .iter()
        .copied()
        .map(StoredFact::from_current)
        .collect::<Vec<_>>();
    for retired in snapshot.retired() {
        let mut fact = previous.get(&retired.credential_id()).copied().ok_or(
            AgentPersistenceError::SnapshotRejected(
                "Host credential retirement has no predecessor",
            ),
        )?;
        if fact.fingerprint != retired.certificate_fingerprint() {
            return Err(AgentPersistenceError::SnapshotRejected(
                "Host credential retirement fingerprint",
            ));
        }
        fact.status = CredentialStatus::Retired;
        facts.push(fact);
    }
    facts.sort_unstable_by_key(|fact| fact.credential_id);
    Ok(facts)
}

async fn ensure_credential(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    revision: Revision,
    fact: StoredFact,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    sqlx::query(
        "INSERT INTO agent.host_credential_authorization_credentials (
             tenant_id, host_id, credential_id, certificate_fingerprint,
             not_before_unix_seconds, not_after_unix_seconds,
             first_authorization_revision, registered_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(fact.host_id))
    .bind(Uuid::from(fact.credential_id))
    .bind(fact.fingerprint.as_bytes().as_slice())
    .bind(seconds_to_i64(fact.not_before)?)
    .bind(seconds_to_i64(fact.not_after)?)
    .bind(revision_to_i64(revision)?)
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;

    let row = sqlx::query(
        "SELECT host_id, certificate_fingerprint,
                not_before_unix_seconds, not_after_unix_seconds
           FROM agent.host_credential_authorization_credentials
          WHERE tenant_id=$1 AND credential_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(fact.credential_id))
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(AgentPersistenceError::ImmutableConflict(
        "Host authorization credential or fingerprint",
    ))?;
    let stored_host: Uuid = row.try_get("host_id")?;
    let stored_fingerprint: Vec<u8> = row.try_get("certificate_fingerprint")?;
    let stored_not_before: i64 = row.try_get("not_before_unix_seconds")?;
    let stored_not_after: i64 = row.try_get("not_after_unix_seconds")?;
    if HostId::try_from(stored_host).ok() != Some(fact.host_id)
        || bytes_32(stored_fingerprint, "Host certificate fingerprint")?
            != *fact.fingerprint.as_bytes()
        || seconds_from_i64(stored_not_before)? != fact.not_before
        || seconds_from_i64(stored_not_after)? != fact.not_after
    {
        return Err(AgentPersistenceError::ImmutableConflict(
            "Host authorization credential",
        ));
    }
    Ok(())
}

async fn insert_revision(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    revision: Revision,
    facts: &[StoredFact],
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let current_count = facts
        .iter()
        .filter(|fact| fact.status == CredentialStatus::Current)
        .count();
    let retired_count = facts.len() - current_count;
    sqlx::query(
        "INSERT INTO agent.host_credential_authorization_revisions (
             tenant_id, authorization_revision, credential_count,
             current_count, retired_count, snapshot_digest, recorded_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(revision_to_i64(revision)?)
    .bind(usize_to_i64(facts.len())?)
    .bind(usize_to_i64(current_count)?)
    .bind(usize_to_i64(retired_count)?)
    .bind(snapshot_digest(tenant_id, revision, facts).as_slice())
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn insert_states(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    revision: Revision,
    facts: &[StoredFact],
) -> Result<(), AgentPersistenceError> {
    for fact in facts {
        sqlx::query(
            "INSERT INTO agent.host_credential_authorization_states (
                 tenant_id, authorization_revision, host_id, credential_id,
                 certificate_fingerprint, status, revoked_at_unix_seconds
             ) VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(Uuid::from(tenant_id))
        .bind(revision_to_i64(revision)?)
        .bind(Uuid::from(fact.host_id))
        .bind(Uuid::from(fact.credential_id))
        .bind(fact.fingerprint.as_bytes().as_slice())
        .bind(fact.status.code())
        .bind(fact.revoked_at.map(seconds_to_i64).transpose()?)
        .execute(&mut *connection)
        .await?;
    }
    Ok(())
}

async fn load_revision(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    revision: Revision,
) -> Result<LoadedRevision, AgentPersistenceError> {
    let revision_row = sqlx::query(
        "SELECT credential_count, current_count, retired_count, snapshot_digest
           FROM agent.host_credential_authorization_revisions
          WHERE tenant_id=$1 AND authorization_revision=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(revision_to_i64(revision)?)
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(AgentPersistenceError::CorruptData(
        "Host authorization head revision",
    ))?;
    let credential_count = count_from_i64(revision_row.try_get("credential_count")?)?;
    let current_count = count_from_i64(revision_row.try_get("current_count")?)?;
    let retired_count = count_from_i64(revision_row.try_get("retired_count")?)?;
    let expected_digest = bytes_32(
        revision_row.try_get("snapshot_digest")?,
        "Host authorization snapshot digest",
    )?;

    let rows = sqlx::query(
        "SELECT state.host_id, state.credential_id,
                state.certificate_fingerprint, state.status,
                state.revoked_at_unix_seconds,
                credential.not_before_unix_seconds,
                credential.not_after_unix_seconds
           FROM agent.host_credential_authorization_states AS state
           JOIN agent.host_credential_authorization_credentials AS credential
             ON credential.tenant_id=state.tenant_id
            AND credential.host_id=state.host_id
            AND credential.credential_id=state.credential_id
            AND credential.certificate_fingerprint=state.certificate_fingerprint
          WHERE state.tenant_id=$1 AND state.authorization_revision=$2
          ORDER BY state.credential_id",
    )
    .bind(Uuid::from(tenant_id))
    .bind(revision_to_i64(revision)?)
    .fetch_all(&mut *connection)
    .await?;

    let mut facts = Vec::with_capacity(rows.len());
    let mut current = Vec::new();
    let mut retired = Vec::new();
    for row in rows {
        let host_id: Uuid = row.try_get("host_id")?;
        let credential_id: Uuid = row.try_get("credential_id")?;
        let fingerprint = CertificateFingerprint::from_bytes(bytes_32(
            row.try_get("certificate_fingerprint")?,
            "Host certificate fingerprint",
        )?);
        let status = CredentialStatus::parse(row.try_get("status")?)?;
        let revoked_at: Option<i64> = row.try_get("revoked_at_unix_seconds")?;
        let fact = StoredFact {
            host_id: HostId::try_from(host_id)
                .map_err(|_| AgentPersistenceError::CorruptData("Host ID"))?,
            credential_id: HostCredentialId::try_from(credential_id)
                .map_err(|_| AgentPersistenceError::CorruptData("Host credential ID"))?,
            fingerprint,
            not_before: seconds_from_i64(row.try_get("not_before_unix_seconds")?)?,
            not_after: seconds_from_i64(row.try_get("not_after_unix_seconds")?)?,
            revoked_at: revoked_at.map(seconds_from_i64).transpose()?,
            status,
        };
        let binding = HostCredentialBinding::new(
            HostWorkloadIdentity::new(tenant_id, fact.host_id),
            fact.credential_id,
            fact.fingerprint,
            fact.not_before,
            fact.not_after,
            fact.revoked_at,
        )
        .map_err(|_| AgentPersistenceError::CorruptData("Host credential binding"))?;
        match status {
            CredentialStatus::Current => current.push(binding),
            CredentialStatus::Retired => retired.push(RetiredHostCredential::new(
                fact.credential_id,
                fact.fingerprint,
            )),
        }
        facts.push(fact);
    }

    facts.sort_unstable_by_key(|fact| fact.credential_id);
    if facts.len() != credential_count
        || current.len() != current_count
        || retired.len() != retired_count
    {
        return Err(AgentPersistenceError::CorruptData(
            "Host authorization snapshot counts",
        ));
    }
    let actual_digest = snapshot_digest(tenant_id, revision, &facts);
    if actual_digest != expected_digest {
        return Err(AgentPersistenceError::CorruptData(
            "Host authorization snapshot digest",
        ));
    }
    let snapshot = HostCredentialAuthorizationSnapshot::try_new(revision, current, retired)
        .map_err(|_| AgentPersistenceError::SnapshotRejected("Host credential authorization"))?;
    let snapshot = canonical_snapshot(tenant_id, &snapshot)?;
    Ok(LoadedRevision { snapshot, facts })
}

fn snapshot_digest(tenant_id: TenantId, revision: Revision, facts: &[StoredFact]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_DIGEST_DOMAIN);
    hasher.update(Uuid::from(tenant_id).as_bytes());
    hasher.update(revision.get().to_be_bytes());
    hasher.update(u64::try_from(facts.len()).unwrap_or(u64::MAX).to_be_bytes());
    for fact in facts {
        hasher.update([match fact.status {
            CredentialStatus::Current => 1,
            CredentialStatus::Retired => 2,
        }]);
        hasher.update(Uuid::from(fact.host_id).as_bytes());
        hasher.update(Uuid::from(fact.credential_id).as_bytes());
        hasher.update(fact.fingerprint.as_bytes());
        hasher.update(fact.not_before.to_be_bytes());
        hasher.update(fact.not_after.to_be_bytes());
        match fact.revoked_at {
            Some(revoked_at) => {
                hasher.update([1]);
                hasher.update(revoked_at.to_be_bytes());
            }
            None => hasher.update([0]),
        }
    }
    hasher.finalize().into()
}

fn seconds_to_i64(value: u64) -> Result<i64, AgentPersistenceError> {
    i64::try_from(value)
        .map_err(|_| AgentPersistenceError::CorruptData("Host credential timestamp"))
}

fn seconds_from_i64(value: i64) -> Result<u64, AgentPersistenceError> {
    u64::try_from(value)
        .map_err(|_| AgentPersistenceError::CorruptData("Host credential timestamp"))
}

fn usize_to_i64(value: usize) -> Result<i64, AgentPersistenceError> {
    i64::try_from(value)
        .map_err(|_| AgentPersistenceError::CorruptData("authorization credential count"))
}

fn count_from_i64(value: i64) -> Result<usize, AgentPersistenceError> {
    usize::try_from(value)
        .map_err(|_| AgentPersistenceError::CorruptData("authorization credential count"))
}
