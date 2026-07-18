use dtx_agent_control::{
    AcceptedRotationSnapshot, ConnectorCredential, ConnectorCredentialAuthorization,
    ConnectorCredentialAuthorizationSnapshot, ConnectorCredentialAuthorizationState,
    ConnectorCredentialEntrySnapshot, ConnectorCredentialStatus, EnrollmentIntentSnapshot,
    EnrollmentIntentSnapshotState, Sha256Digest,
};
use dtx_domain::{
    ConnectorCredentialId, ConnectorId, Ed25519PublicKey, RequestId, Revision, TenantId,
};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

use crate::{AgentPersistenceError, CurrentWrite, registry::revision_from_i64};

/// Maximum number of append-only authorization rows an explicit audit materialization may load.
///
/// Production authorization, owner-command, rotation, and `Hello` paths use the bounded head
/// projection instead. This limit only protects diagnostics and tests that intentionally request
/// the complete historical aggregate.
pub const MAX_CONNECTOR_CREDENTIAL_AUDIT_ROWS: u64 = 8_192;

/// Bounded durable credential authorization projection used by production decision paths.
///
/// The embedded domain aggregate contains only the exact current credential and, when present,
/// its one pending successor plus that successor's accepted rotation record. The durable revision
/// and rotation high-water marks provide the CAS and append fences without materializing retired
/// credentials or historical rotations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectorCredentialAuthorizationHead {
    authorization_revision: u64,
    rotation_high_water: u64,
    authorization: ConnectorCredentialAuthorization,
}

impl ConnectorCredentialAuthorizationHead {
    #[must_use]
    pub const fn authorization_revision(&self) -> u64 {
        self.authorization_revision
    }

    #[must_use]
    pub const fn rotation_high_water(&self) -> u64 {
        self.rotation_high_water
    }

    #[must_use]
    pub const fn authorization(&self) -> &ConnectorCredentialAuthorization {
        &self.authorization
    }

    #[must_use]
    pub fn into_authorization(self) -> ConnectorCredentialAuthorization {
        self.authorization
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectorCredentialAuthorizationRepository;

impl ConnectorCredentialAuthorizationRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns whether one Connector already has a durable credential authorization head.
    ///
    /// # Errors
    ///
    /// Returns a database error when the bounded existence query cannot be completed.
    pub async fn exists(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> Result<bool, AgentPersistenceError> {
        sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1
                   FROM agent.connector_control_credential_heads
                  WHERE tenant_id=$1 AND connector_id=$2
             )",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_one(&mut *connection)
        .await
        .map_err(AgentPersistenceError::from)
    }

    /// Loads only the durable current credential head and optional pending successor.
    ///
    /// The query count and decoded row count are constant for the Connector's lifetime. Retired
    /// credentials and completed rotations are deliberately excluded; the latest rotation
    /// sequence remains available as an append fence.
    ///
    /// # Errors
    ///
    /// Returns an error when the bounded head is internally inconsistent or unavailable.
    pub async fn load_head(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> Result<Option<ConnectorCredentialAuthorizationHead>, AgentPersistenceError> {
        let Some(head) = load_authorization_head_row(connection, tenant_id, connector_id).await?
        else {
            return Ok(None);
        };
        let (current, pending) =
            load_authorization_head_credentials(connection, tenant_id, connector_id, head).await?;
        let (rotation_high_water, rotations) =
            load_authorization_head_rotation(connection, tenant_id, connector_id, pending.as_ref())
                .await?;
        let authorization = rehydrate_authorization_head(
            tenant_id,
            connector_id,
            head,
            current,
            pending,
            rotations,
        )?;
        Ok(Some(ConnectorCredentialAuthorizationHead {
            authorization_revision: head.authorization_revision,
            rotation_high_water,
            authorization,
        }))
    }

    /// Checks whether this Connector has already used an online control key.
    ///
    /// This indexed, single-result lookup preserves historical key-reuse rejection without
    /// loading retired credentials into the rotation hot path.
    ///
    /// # Errors
    ///
    /// Returns a database error when the bounded lookup cannot be completed.
    pub async fn control_key_exists(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        control_key: Ed25519PublicKey,
    ) -> Result<bool, AgentPersistenceError> {
        sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1
                   FROM agent.connector_control_credentials
                  WHERE tenant_id=$1 AND connector_id=$2 AND online_public_key=$3
             )",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(control_key.as_bytes().to_vec())
        .fetch_one(&mut *connection)
        .await
        .map_err(AgentPersistenceError::from)
    }

    /// Authorizes one ordinary Connector frame against the exact durable current credential.
    ///
    /// This is a bounded hot-path projection: one scalar query joins the credential head to
    /// its current authorization revision and exact current credential. It never loads or
    /// decodes credential or rotation history. Pending, retired, revoked, expired, foreign,
    /// and malformed presentations all fail closed.
    ///
    /// # Errors
    ///
    /// Returns a database error when durable authorization state cannot be queried. Invalid
    /// presentation coordinates return `false` without querying `PostgreSQL`.
    pub async fn authorize_current(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
        connector_generation: u64,
        certificate_fingerprint: Sha256Digest,
        now_millis: i64,
    ) -> Result<bool, AgentPersistenceError> {
        let Ok(connector_generation) = i64::try_from(connector_generation) else {
            return Ok(false);
        };
        if !(1..=Revision::MAX.cast_signed()).contains(&connector_generation)
            || !(0..=Revision::MAX.cast_signed()).contains(&now_millis)
        {
            return Ok(false);
        }

        sqlx::query_scalar(
            "SELECT EXISTS (
                 SELECT 1
                   FROM agent.connector_control_credential_heads AS head
                   JOIN agent.connector_control_credential_revisions AS revision
                     ON revision.tenant_id=head.tenant_id
                    AND revision.connector_id=head.connector_id
                    AND revision.authorization_revision=head.current_revision
                   JOIN agent.connector_control_credentials AS credential
                     ON credential.tenant_id=revision.tenant_id
                    AND credential.connector_id=revision.connector_id
                    AND credential.credential_id=revision.current_credential_id
                  WHERE head.tenant_id=$1
                    AND head.connector_id=$2
                    AND revision.lifecycle='active'
                    AND revision.connector_generation=$3
                    AND credential.connector_generation=$3
                    AND credential.certificate_fingerprint=$4
                    AND credential.not_before_ms <= $5
                    AND $5 < credential.not_after_ms
             )",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(connector_generation)
        .bind(certificate_fingerprint.as_bytes().to_vec())
        .bind(now_millis)
        .fetch_one(&mut *connection)
        .await
        .map_err(AgentPersistenceError::from)
    }

    /// Appends one exact rotation, promotion, or terminal revocation under snapshot CAS.
    ///
    /// The caller may compose this savepoint with Connector and command-log writes
    /// inside one outer tenant transaction. `PostgreSQL` row locks remain held until
    /// that outer transaction commits.
    ///
    /// # Errors
    ///
    /// Returns an error when the expected snapshot is stale, the transition is
    /// invalid, persisted history is corrupt, or the database rejects the write.
    pub async fn save(
        self,
        connection: &mut PgConnection,
        authorization: &ConnectorCredentialAuthorization,
        expected: &ConnectorCredentialAuthorizationSnapshot,
        operation_id: RequestId,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let proposed = authorization.snapshot();
        ConnectorCredentialAuthorization::try_from_snapshot(proposed.clone()).map_err(|_| {
            AgentPersistenceError::SnapshotRejected("Connector credential authorization")
        })?;
        let mut transaction = connection.begin().await?;
        let result = self
            .save_in_transaction(
                &mut transaction,
                &proposed,
                expected,
                operation_id,
                stored_at_ms,
            )
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

    /// Appends one transition under the bounded durable head CAS projection.
    ///
    /// The proposed aggregate must have been derived from `expected.authorization()`. Only the
    /// current credential, optional pending successor, and exact pending rotation are compared;
    /// the durable revision and rotation high-water marks prevent stale or non-contiguous writes.
    ///
    /// # Errors
    ///
    /// Returns an error for stale heads, invalid transitions, changed retries, corrupt bounded
    /// state, or a rejected database write.
    pub async fn save_head(
        self,
        connection: &mut PgConnection,
        authorization: &ConnectorCredentialAuthorization,
        expected: &ConnectorCredentialAuthorizationHead,
        operation_id: RequestId,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let proposed = authorization.snapshot();
        ConnectorCredentialAuthorization::try_from_snapshot(proposed.clone()).map_err(|_| {
            AgentPersistenceError::SnapshotRejected("Connector credential authorization head")
        })?;
        if proposed.tenant_id != expected.authorization.tenant_id()
            || proposed.connector_id != expected.authorization.connector_id()
        {
            return Err(AgentPersistenceError::ImmutableConflict(
                "Connector credential authorization identity",
            ));
        }
        let mut transaction = connection.begin().await?;
        let result = self
            .save_head_in_transaction(
                &mut transaction,
                &proposed,
                expected,
                operation_id,
                stored_at_ms,
            )
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

    async fn save_head_in_transaction(
        self,
        connection: &mut PgConnection,
        proposed: &ConnectorCredentialAuthorizationSnapshot,
        expected: &ConnectorCredentialAuthorizationHead,
        operation_id: RequestId,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        lock_connector_control_state(connection, proposed.tenant_id, proposed.connector_id).await?;
        let head_revision =
            lock_authorization_head(connection, proposed.tenant_id, proposed.connector_id)
                .await?
                .ok_or(AgentPersistenceError::RevisionConflict { current: None })?;
        let current = self
            .load_head(connection, proposed.tenant_id, proposed.connector_id)
            .await?
            .ok_or(AgentPersistenceError::CorruptData(
                "Connector credential authorization head",
            ))?;
        if current.authorization.snapshot() == *proposed {
            return Ok(CurrentWrite::Existing);
        }
        if current != *expected || head_revision != expected.authorization_revision {
            return Err(AgentPersistenceError::RevisionConflict {
                current: Some(head_revision),
            });
        }

        let current_snapshot = current.authorization.snapshot();
        let transition = classify_transition(&current_snapshot, proposed)?;
        let next_revision = head_revision
            .checked_add(1)
            .filter(|revision| *revision <= Revision::MAX)
            .ok_or(AgentPersistenceError::CorruptData(
                "Connector credential authorization revision",
            ))?;
        let rotation_sequence =
            matches!(&transition, AuthorizationTransition::RotationStarted { .. })
                .then(|| {
                    current
                        .rotation_high_water
                        .checked_add(1)
                        .filter(|sequence| *sequence <= Revision::MAX)
                        .ok_or(AgentPersistenceError::CorruptData(
                            "Connector rotation sequence",
                        ))
                })
                .transpose()?;
        persist_authorization_transition(
            connection,
            proposed,
            next_revision,
            transition,
            rotation_sequence,
            operation_id,
            stored_at_ms,
        )
        .await?;
        advance_authorization_head(
            connection,
            proposed.tenant_id,
            proposed.connector_id,
            head_revision,
            next_revision,
            stored_at_ms,
        )
        .await?;
        Ok(CurrentWrite::Advanced)
    }

    async fn save_in_transaction(
        self,
        connection: &mut PgConnection,
        proposed: &ConnectorCredentialAuthorizationSnapshot,
        expected: &ConnectorCredentialAuthorizationSnapshot,
        operation_id: RequestId,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        lock_connector_control_state(connection, proposed.tenant_id, proposed.connector_id).await?;
        let head_revision =
            lock_authorization_head(connection, proposed.tenant_id, proposed.connector_id)
                .await?
                .ok_or(AgentPersistenceError::RevisionConflict { current: None })?;
        let current = self
            .load(connection, proposed.tenant_id, proposed.connector_id)
            .await?
            .ok_or(AgentPersistenceError::CorruptData(
                "Connector credential authorization head",
            ))?
            .snapshot();
        if current == *proposed {
            return Ok(CurrentWrite::Existing);
        }
        if current != *expected {
            return Err(AgentPersistenceError::RevisionConflict {
                current: Some(head_revision),
            });
        }

        let transition = classify_transition(&current, proposed)?;
        let next_revision = head_revision
            .checked_add(1)
            .filter(|revision| *revision <= Revision::MAX)
            .ok_or(AgentPersistenceError::CorruptData(
                "Connector credential authorization revision",
            ))?;
        let rotation_sequence =
            matches!(&transition, AuthorizationTransition::RotationStarted { .. })
                .then(|| {
                    u64::try_from(proposed.rotations.len())
                        .map_err(|_| AgentPersistenceError::CorruptData("rotation count"))
                })
                .transpose()?;
        persist_authorization_transition(
            connection,
            proposed,
            next_revision,
            transition,
            rotation_sequence,
            operation_id,
            stored_at_ms,
        )
        .await?;
        advance_authorization_head(
            connection,
            proposed.tenant_id,
            proposed.connector_id,
            head_revision,
            next_revision,
            stored_at_ms,
        )
        .await?;
        Ok(CurrentWrite::Advanced)
    }

    /// Loads and validates a bounded complete credential and rotation history for audits/tests.
    ///
    /// Production decision paths must use [`Self::load_head`]. This diagnostic materialization
    /// rejects histories beyond [`MAX_CONNECTOR_CREDENTIAL_AUDIT_ROWS`] before allocating them.
    ///
    /// # Errors
    ///
    /// Returns an error when stored revisions, credentials, or rotations are
    /// inconsistent, or when the database read fails.
    #[allow(clippy::too_many_lines)]
    pub async fn load(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> Result<Option<ConnectorCredentialAuthorization>, AgentPersistenceError> {
        let head: Option<i64> = sqlx::query_scalar(
            "SELECT current_revision
               FROM agent.connector_control_credential_heads
              WHERE tenant_id=$1 AND connector_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .fetch_optional(&mut *connection)
        .await?;
        let Some(head) = head else {
            return Ok(None);
        };
        let head = positive_u64(head, "Connector credential authorization head")?;
        if head > MAX_CONNECTOR_CREDENTIAL_AUDIT_ROWS {
            return Err(AgentPersistenceError::MaterializationLimitExceeded(
                "Connector credential authorization audit",
            ));
        }
        let query_limit = i64::try_from(MAX_CONNECTOR_CREDENTIAL_AUDIT_ROWS + 1).map_err(|_| {
            AgentPersistenceError::CorruptData("Connector credential audit row limit")
        })?;

        let revision_rows = sqlx::query(
            "SELECT authorization_revision, connector_generation, lifecycle,
                    current_credential_id, pending_credential_id,
                    cause_kind, cause_operation_id
               FROM agent.connector_control_credential_revisions
              WHERE tenant_id=$1 AND connector_id=$2
              ORDER BY authorization_revision
              LIMIT $3",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(query_limit)
        .fetch_all(&mut *connection)
        .await?;
        reject_oversized_audit_rows(revision_rows.len())?;
        let revisions = parse_revision_history(revision_rows)?;
        validate_revision_history(head, &revisions)?;
        let latest = revisions.last().ok_or(AgentPersistenceError::CorruptData(
            "Connector credential authorization history",
        ))?;

        let credential_rows = sqlx::query(
            "SELECT credential_id, connector_generation, credential_revision,
                    online_public_key, refresh_public_key, certificate_fingerprint,
                    certificate_chain_der, not_before_ms, not_after_ms
               FROM agent.connector_control_credentials
              WHERE tenant_id=$1 AND connector_id=$2
              ORDER BY connector_generation
              LIMIT $3",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(query_limit)
        .fetch_all(&mut *connection)
        .await?;
        reject_oversized_audit_rows(credential_rows.len())?;
        let mut credentials = Vec::with_capacity(credential_rows.len());
        for row in credential_rows {
            credentials.push(load_credential_row(tenant_id, connector_id, &row)?);
        }
        if credentials.is_empty() {
            return Err(AgentPersistenceError::CorruptData(
                "Connector credential history",
            ));
        }

        let rotation_rows = sqlx::query(
            "SELECT rotation_sequence, request_id, request_digest, result_digest,
                    current_credential_id, successor_credential_id,
                    command_sequence, command_payload_digest, nonce
               FROM agent.connector_control_credential_rotations
              WHERE tenant_id=$1 AND connector_id=$2
              ORDER BY rotation_sequence
              LIMIT $3",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(connector_id))
        .bind(query_limit)
        .fetch_all(&mut *connection)
        .await?;
        reject_oversized_audit_rows(rotation_rows.len())?;
        let mut rotations = Vec::with_capacity(rotation_rows.len());
        for (index, row) in rotation_rows.into_iter().enumerate() {
            let stored_sequence: i64 = row.try_get("rotation_sequence")?;
            if stored_sequence
                != i64::try_from(index + 1).map_err(|_| {
                    AgentPersistenceError::CorruptData("Connector rotation sequence")
                })?
            {
                return Err(AgentPersistenceError::CorruptData(
                    "Connector rotation sequence",
                ));
            }
            rotations.push(load_rotation_row(&row)?);
        }

        validate_revision_credentials(&revisions, &credentials, &rotations)?;
        let state = parse_authorization_state(&latest.lifecycle)?;
        let history = credentials
            .into_iter()
            .map(|credential| {
                let id = credential.credential_id();
                let status = match state {
                    ConnectorCredentialAuthorizationState::Active => {
                        if id == latest.current_credential_id {
                            ConnectorCredentialStatus::Current
                        } else if Some(id) == latest.pending_credential_id {
                            ConnectorCredentialStatus::Pending
                        } else {
                            ConnectorCredentialStatus::Retired
                        }
                    }
                    ConnectorCredentialAuthorizationState::Revoked => {
                        if id == latest.current_credential_id
                            || Some(id) == latest.pending_credential_id
                        {
                            ConnectorCredentialStatus::Revoked
                        } else {
                            ConnectorCredentialStatus::Retired
                        }
                    }
                };
                ConnectorCredentialEntrySnapshot { credential, status }
            })
            .collect();
        let snapshot = ConnectorCredentialAuthorizationSnapshot {
            tenant_id,
            connector_id,
            state,
            current_credential_id: (state == ConnectorCredentialAuthorizationState::Active)
                .then_some(latest.current_credential_id),
            pending_credential_id: (state == ConnectorCredentialAuthorizationState::Active)
                .then_some(latest.pending_credential_id)
                .flatten(),
            history,
            rotations,
        };
        ConnectorCredentialAuthorization::try_from_snapshot(snapshot)
            .map(Some)
            .map_err(|_| {
                AgentPersistenceError::SnapshotRejected("Connector credential authorization")
            })
    }
}

#[derive(Clone, Copy)]
struct AuthorizationHeadRow {
    authorization_revision: u64,
    generation: u64,
    state: ConnectorCredentialAuthorizationState,
    current_credential_id: ConnectorCredentialId,
    pending_credential_id: Option<ConnectorCredentialId>,
}

async fn load_authorization_head_row(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> Result<Option<AuthorizationHeadRow>, AgentPersistenceError> {
    let row = sqlx::query(
        "SELECT head.current_revision, revision.connector_generation,
                revision.lifecycle, revision.current_credential_id,
                revision.pending_credential_id
           FROM agent.connector_control_credential_heads AS head
           JOIN agent.connector_control_credential_revisions AS revision
             ON revision.tenant_id=head.tenant_id
            AND revision.connector_id=head.connector_id
            AND revision.authorization_revision=head.current_revision
          WHERE head.tenant_id=$1 AND head.connector_id=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .fetch_optional(&mut *connection)
    .await?;
    row.map(|row| {
        Ok(AuthorizationHeadRow {
            authorization_revision: positive_u64(
                row.try_get("current_revision")?,
                "Connector credential authorization head",
            )?,
            generation: positive_u64(
                row.try_get("connector_generation")?,
                "Connector credential authorization generation",
            )?,
            state: parse_authorization_state(row.try_get("lifecycle")?)?,
            current_credential_id: credential_id(row.try_get("current_credential_id")?)?,
            pending_credential_id: row
                .try_get::<Option<Uuid>, _>("pending_credential_id")?
                .map(credential_id)
                .transpose()?,
        })
    })
    .transpose()
}

async fn load_authorization_head_credentials(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    head: AuthorizationHeadRow,
) -> Result<(ConnectorCredential, Option<ConnectorCredential>), AgentPersistenceError> {
    let mut selected_ids = vec![Uuid::from(head.current_credential_id)];
    if let Some(pending_id) = head.pending_credential_id {
        selected_ids.push(Uuid::from(pending_id));
    }
    let rows = sqlx::query(
        "SELECT credential_id, connector_generation, credential_revision,
                online_public_key, refresh_public_key, certificate_fingerprint,
                certificate_chain_der, not_before_ms, not_after_ms
           FROM agent.connector_control_credentials
          WHERE tenant_id=$1 AND connector_id=$2 AND credential_id = ANY($3)
          ORDER BY connector_generation",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .bind(selected_ids)
    .fetch_all(&mut *connection)
    .await?;
    if rows.len() != 1 + usize::from(head.pending_credential_id.is_some()) {
        return Err(AgentPersistenceError::CorruptData(
            "Connector credential authorization selection",
        ));
    }
    let credentials = rows
        .iter()
        .map(|row| load_credential_row(tenant_id, connector_id, row))
        .collect::<Result<Vec<_>, _>>()?;
    let current = credentials
        .iter()
        .find(|credential| credential.credential_id() == head.current_credential_id)
        .cloned()
        .ok_or(AgentPersistenceError::CorruptData(
            "Connector credential current head",
        ))?;
    if current.generation() != head.generation {
        return Err(AgentPersistenceError::CorruptData(
            "Connector credential authorization generation",
        ));
    }
    let pending = head
        .pending_credential_id
        .map(|pending_id| {
            credentials
                .iter()
                .find(|credential| credential.credential_id() == pending_id)
                .cloned()
                .ok_or(AgentPersistenceError::CorruptData(
                    "Connector credential pending head",
                ))
        })
        .transpose()?;
    Ok((current, pending))
}

async fn load_authorization_head_rotation(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    pending: Option<&ConnectorCredential>,
) -> Result<(u64, Vec<AcceptedRotationSnapshot>), AgentPersistenceError> {
    let high_water = sqlx::query_scalar::<_, i64>(
        "SELECT rotation_sequence
           FROM agent.connector_control_credential_rotations
          WHERE tenant_id=$1 AND connector_id=$2
          ORDER BY rotation_sequence DESC
          LIMIT 1",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .fetch_optional(&mut *connection)
    .await?
    .map(|value| positive_u64(value, "Connector rotation sequence"))
    .transpose()?
    .unwrap_or(0);
    let Some(pending) = pending else {
        return Ok((high_water, Vec::new()));
    };
    let row = sqlx::query(
        "SELECT rotation_sequence, request_id, request_digest, result_digest,
                current_credential_id, successor_credential_id,
                command_sequence, command_payload_digest, nonce
           FROM agent.connector_control_credential_rotations
          WHERE tenant_id=$1 AND connector_id=$2 AND successor_credential_id=$3",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .bind(Uuid::from(pending.credential_id()))
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        // Certificate-only reissue has no live RotateCredential record. Its operation is
        // independently bound by the reissue intent and its pending status is still fenced by
        // the authorization head.
        return Ok((high_water, Vec::new()));
    };
    let sequence = positive_u64(
        row.try_get("rotation_sequence")?,
        "Connector rotation sequence",
    )?;
    if sequence != high_water {
        return Err(AgentPersistenceError::CorruptData(
            "Connector pending credential rotation sequence",
        ));
    }
    Ok((high_water, vec![load_rotation_row(&row)?]))
}

fn rehydrate_authorization_head(
    tenant_id: TenantId,
    connector_id: ConnectorId,
    head: AuthorizationHeadRow,
    current: ConnectorCredential,
    pending: Option<ConnectorCredential>,
    rotations: Vec<AcceptedRotationSnapshot>,
) -> Result<ConnectorCredentialAuthorization, AgentPersistenceError> {
    let (current_status, pending_status, current_head, pending_head) = match head.state {
        ConnectorCredentialAuthorizationState::Active => (
            ConnectorCredentialStatus::Current,
            ConnectorCredentialStatus::Pending,
            Some(head.current_credential_id),
            head.pending_credential_id,
        ),
        ConnectorCredentialAuthorizationState::Revoked => (
            ConnectorCredentialStatus::Revoked,
            ConnectorCredentialStatus::Revoked,
            None,
            None,
        ),
    };
    let mut history = vec![ConnectorCredentialEntrySnapshot {
        credential: current,
        status: current_status,
    }];
    if let Some(pending) = pending {
        history.push(ConnectorCredentialEntrySnapshot {
            credential: pending,
            status: pending_status,
        });
    }
    ConnectorCredentialAuthorization::try_from_snapshot(ConnectorCredentialAuthorizationSnapshot {
        tenant_id,
        connector_id,
        state: head.state,
        current_credential_id: current_head,
        pending_credential_id: pending_head,
        history,
        rotations,
    })
    .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector credential authorization head"))
}

pub(crate) async fn lock_connector_control_state(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> Result<(), AgentPersistenceError> {
    let connector: Option<Uuid> = sqlx::query_scalar(
        "SELECT connector_id
           FROM agent.connector_instances
          WHERE tenant_id=$1 AND connector_id=$2
          FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .fetch_optional(&mut *connection)
    .await?;
    if connector.is_some() {
        Ok(())
    } else {
        Err(AgentPersistenceError::FenceConflict)
    }
}

pub(crate) async fn insert_initial_authorization(
    connection: &mut PgConnection,
    intent: &EnrollmentIntentSnapshot,
    authorization: &ConnectorCredentialAuthorizationSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let EnrollmentIntentSnapshotState::Consumed {
        consumed_at_millis,
        request_digest,
        result_digest,
        result,
        ..
    } = &intent.state
    else {
        return Err(AgentPersistenceError::SnapshotRejected(
            "consumed Connector enrollment",
        ));
    };
    let expected = ConnectorCredentialAuthorization::new((**result).clone())
        .map_err(|_| AgentPersistenceError::SnapshotRejected("initial Connector credential"))?
        .snapshot();
    if expected != *authorization {
        return Err(AgentPersistenceError::SnapshotRejected(
            "initial Connector credential authorization",
        ));
    }
    insert_credential(
        connection,
        result,
        CredentialOrigin::Enrollment {
            intent_id: intent.intent_id,
            operation_id: intent.request_id,
            request_digest: *request_digest,
            result_digest: *result_digest,
        },
        *consumed_at_millis,
    )
    .await?;
    insert_authorization_revision(
        connection,
        authorization,
        1,
        "enrollment",
        intent.request_id,
        stored_at_ms,
    )
    .await?;
    sqlx::query(
        "INSERT INTO agent.connector_control_credential_heads (
             tenant_id, connector_id, current_revision, created_at_ms, updated_at_ms
         ) VALUES ($1,$2,1,$3,$3)",
    )
    .bind(Uuid::from(intent.tenant_id))
    .bind(Uuid::from(intent.connector_id))
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

enum CredentialOrigin {
    Enrollment {
        intent_id: dtx_domain::EnrollmentIntentId,
        operation_id: RequestId,
        request_digest: Sha256Digest,
        result_digest: Sha256Digest,
    },
    Rotation {
        predecessor_id: ConnectorCredentialId,
        operation_id: RequestId,
        request_digest: Sha256Digest,
        result_digest: Sha256Digest,
    },
    Reissue {
        predecessor_id: ConnectorCredentialId,
        operation_id: RequestId,
        request_digest: Sha256Digest,
        result_digest: Sha256Digest,
    },
}

async fn insert_credential(
    connection: &mut PgConnection,
    credential: &ConnectorCredential,
    origin: CredentialOrigin,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let (origin_kind, intent_id, predecessor_id, operation_id, request_digest, result_digest) =
        match origin {
            CredentialOrigin::Enrollment {
                intent_id,
                operation_id,
                request_digest,
                result_digest,
            } => (
                "enrollment",
                Some(Uuid::from(intent_id)),
                None,
                operation_id,
                request_digest,
                result_digest,
            ),
            CredentialOrigin::Rotation {
                predecessor_id,
                operation_id,
                request_digest,
                result_digest,
            } => (
                "rotation",
                None,
                Some(Uuid::from(predecessor_id)),
                operation_id,
                request_digest,
                result_digest,
            ),
            CredentialOrigin::Reissue {
                predecessor_id,
                operation_id,
                request_digest,
                result_digest,
            } => (
                "reissue",
                None,
                Some(Uuid::from(predecessor_id)),
                operation_id,
                request_digest,
                result_digest,
            ),
        };
    sqlx::query(
        "INSERT INTO agent.connector_control_credentials (
             tenant_id, connector_id, credential_id, connector_generation,
             credential_revision, origin_kind, enrollment_intent_id,
             predecessor_credential_id, origin_operation_id,
             online_public_key, refresh_public_key, certificate_fingerprint,
             certificate_chain_der, not_before_ms, not_after_ms,
             request_digest, result_digest, issued_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
    )
    .bind(Uuid::from(credential.tenant_id()))
    .bind(Uuid::from(credential.connector_id()))
    .bind(Uuid::from(credential.credential_id()))
    .bind(to_i64(credential.generation(), "credential generation")?)
    .bind(to_i64(credential.revision().get(), "credential revision")?)
    .bind(origin_kind)
    .bind(intent_id)
    .bind(predecessor_id)
    .bind(Uuid::from(operation_id))
    .bind(credential.control_key().as_bytes().to_vec())
    .bind(credential.refresh_key().as_bytes().to_vec())
    .bind(credential.certificate_fingerprint().as_bytes().to_vec())
    .bind(credential.certificate_chain().to_vec())
    .bind(credential.not_before_millis())
    .bind(credential.not_after_millis())
    .bind(request_digest.as_bytes().to_vec())
    .bind(result_digest.as_bytes().to_vec())
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn insert_rotation(
    connection: &mut PgConnection,
    proposed: &ConnectorCredentialAuthorizationSnapshot,
    rotation_sequence: u64,
    rotation: &AcceptedRotationSnapshot,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    sqlx::query(
        "INSERT INTO agent.connector_control_credential_rotations (
             tenant_id, connector_id, rotation_sequence, request_id,
             request_digest, result_digest, current_credential_id,
             successor_credential_id, command_sequence,
             command_payload_digest, nonce, accepted_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(Uuid::from(proposed.tenant_id))
    .bind(Uuid::from(proposed.connector_id))
    .bind(to_i64(rotation_sequence, "rotation sequence")?)
    .bind(Uuid::from(rotation.request_id))
    .bind(rotation.request_digest.as_bytes().to_vec())
    .bind(rotation.result_digest.as_bytes().to_vec())
    .bind(Uuid::from(rotation.current_credential_id))
    .bind(Uuid::from(rotation.successor_credential_id))
    .bind(to_i64(
        rotation.command_sequence,
        "rotation command sequence",
    )?)
    .bind(rotation.command_payload_digest.as_bytes().to_vec())
    .bind(rotation.nonce.to_vec())
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn insert_authorization_revision(
    connection: &mut PgConnection,
    snapshot: &ConnectorCredentialAuthorizationSnapshot,
    authorization_revision: u64,
    cause_kind: &'static str,
    operation_id: RequestId,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let (current_id, pending_id, generation) = authorization_head_facts(snapshot)?;
    sqlx::query(
        "INSERT INTO agent.connector_control_credential_revisions (
             tenant_id, connector_id, authorization_revision,
             connector_generation, lifecycle, current_credential_id,
             pending_credential_id, cause_kind, cause_operation_id, recorded_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(Uuid::from(snapshot.tenant_id))
    .bind(Uuid::from(snapshot.connector_id))
    .bind(to_i64(authorization_revision, "authorization revision")?)
    .bind(to_i64(generation, "authorization generation")?)
    .bind(authorization_state_code(snapshot.state))
    .bind(Uuid::from(current_id))
    .bind(pending_id.map(Uuid::from))
    .bind(cause_kind)
    .bind(Uuid::from(operation_id))
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

fn authorization_head_facts(
    snapshot: &ConnectorCredentialAuthorizationSnapshot,
) -> Result<(ConnectorCredentialId, Option<ConnectorCredentialId>, u64), AgentPersistenceError> {
    let (current_id, pending_id) =
        if snapshot.state == ConnectorCredentialAuthorizationState::Revoked {
            let trailing_revoked = snapshot
                .history
                .iter()
                .rev()
                .take_while(|entry| entry.status == ConnectorCredentialStatus::Revoked)
                .collect::<Vec<_>>();
            match trailing_revoked.as_slice() {
                [current] => (current.credential.credential_id(), None),
                [pending, current] => (
                    current.credential.credential_id(),
                    Some(pending.credential.credential_id()),
                ),
                _ => {
                    return Err(AgentPersistenceError::SnapshotRejected(
                        "revoked Connector credential heads",
                    ));
                }
            }
        } else {
            (
                snapshot
                    .current_credential_id
                    .ok_or(AgentPersistenceError::SnapshotRejected(
                        "Connector credential current head",
                    ))?,
                snapshot.pending_credential_id,
            )
        };
    let generation = snapshot
        .history
        .iter()
        .find(|entry| entry.credential.credential_id() == current_id)
        .map(|entry| entry.credential.generation())
        .ok_or(AgentPersistenceError::SnapshotRejected(
            "Connector credential current generation",
        ))?;
    Ok((current_id, pending_id, generation))
}

async fn lock_authorization_head(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
) -> Result<Option<u64>, AgentPersistenceError> {
    let value: Option<i64> = sqlx::query_scalar(
        "SELECT current_revision
           FROM agent.connector_control_credential_heads
          WHERE tenant_id=$1 AND connector_id=$2 FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .fetch_optional(&mut *connection)
    .await?;
    value
        .map(|value| positive_u64(value, "authorization revision"))
        .transpose()
}

async fn advance_authorization_head(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    connector_id: ConnectorId,
    expected_revision: u64,
    next_revision: u64,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let result = sqlx::query(
        "UPDATE agent.connector_control_credential_heads
            SET current_revision=$4, updated_at_ms=$5
          WHERE tenant_id=$1 AND connector_id=$2 AND current_revision=$3",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(connector_id))
    .bind(to_i64(expected_revision, "authorization revision")?)
    .bind(to_i64(next_revision, "authorization revision")?)
    .bind(stored_at_ms)
    .execute(&mut *connection)
    .await?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(AgentPersistenceError::RevisionConflict {
            current: Some(expected_revision),
        })
    }
}

enum AuthorizationTransition<'a> {
    RotationStarted {
        rotation: &'a AcceptedRotationSnapshot,
        successor: &'a ConnectorCredential,
    },
    ReissueStarted {
        successor: &'a ConnectorCredential,
    },
    Promoted,
    Revoked,
}

async fn persist_authorization_transition(
    connection: &mut PgConnection,
    proposed: &ConnectorCredentialAuthorizationSnapshot,
    next_revision: u64,
    transition: AuthorizationTransition<'_>,
    rotation_sequence: Option<u64>,
    operation_id: RequestId,
    stored_at_ms: i64,
) -> Result<(), AgentPersistenceError> {
    let cause_kind =
        match transition {
            AuthorizationTransition::RotationStarted {
                rotation,
                successor,
            } => {
                if rotation.request_id != operation_id {
                    return Err(AgentPersistenceError::ImmutableConflict(
                        "Connector rotation operation",
                    ));
                }
                insert_credential(
                    connection,
                    successor,
                    CredentialOrigin::Rotation {
                        predecessor_id: rotation.current_credential_id,
                        operation_id,
                        request_digest: rotation.request_digest,
                        result_digest: rotation.result_digest,
                    },
                    stored_at_ms,
                )
                .await?;
                insert_rotation(
                    connection,
                    proposed,
                    rotation_sequence.ok_or(AgentPersistenceError::CorruptData(
                        "Connector rotation sequence",
                    ))?,
                    rotation,
                    stored_at_ms,
                )
                .await?;
                "rotation_started"
            }
            AuthorizationTransition::ReissueStarted { successor } => {
                let row = sqlx::query(
                    "SELECT current_credential_id, request_digest, result_digest
                   FROM agent.connector_credential_reissue_intents
                  WHERE tenant_id=$1 AND operation_id=$2 AND connector_id=$3 AND status='consumed'",
                )
                .bind(Uuid::from(proposed.tenant_id))
                .bind(Uuid::from(operation_id))
                .bind(Uuid::from(proposed.connector_id))
                .fetch_optional(&mut *connection)
                .await?
                .ok_or(AgentPersistenceError::ImmutableConflict(
                    "Connector credential reissue operation",
                ))?;
                let predecessor_id = credential_id(row.try_get("current_credential_id")?)?;
                let request_digest =
                    digest(row.try_get("request_digest")?, "reissue request digest")?;
                let result_digest = digest(row.try_get("result_digest")?, "reissue result digest")?;
                insert_credential(
                    connection,
                    successor,
                    CredentialOrigin::Reissue {
                        predecessor_id,
                        operation_id,
                        request_digest,
                        result_digest,
                    },
                    stored_at_ms,
                )
                .await?;
                "reissue_started"
            }
            AuthorizationTransition::Promoted => {
                let promoted = proposed.current_credential_id.ok_or(
                    AgentPersistenceError::SnapshotRejected("promoted Connector credential"),
                )?;
                let is_reissue: bool = sqlx::query_scalar(
                    "SELECT EXISTS (
                    SELECT 1 FROM agent.connector_credential_reissue_intents
                     WHERE tenant_id=$1 AND connector_id=$2 AND credential_id=$3
                )",
                )
                .bind(Uuid::from(proposed.tenant_id))
                .bind(Uuid::from(proposed.connector_id))
                .bind(Uuid::from(promoted))
                .fetch_one(&mut *connection)
                .await?;
                if is_reissue {
                    "reissue_promoted"
                } else {
                    "rotation_promoted"
                }
            }
            AuthorizationTransition::Revoked => "revoked",
        };
    insert_authorization_revision(
        connection,
        proposed,
        next_revision,
        cause_kind,
        operation_id,
        stored_at_ms,
    )
    .await
}

fn classify_transition<'a>(
    current: &ConnectorCredentialAuthorizationSnapshot,
    proposed: &'a ConnectorCredentialAuthorizationSnapshot,
) -> Result<AuthorizationTransition<'a>, AgentPersistenceError> {
    if current.tenant_id != proposed.tenant_id || current.connector_id != proposed.connector_id {
        return Err(AgentPersistenceError::ImmutableConflict(
            "Connector credential authorization identity",
        ));
    }
    if proposed.history.len() == current.history.len() + 1
        && proposed.rotations.len() == current.rotations.len() + 1
        && proposed.history[..current.history.len()] == current.history
        && proposed.rotations[..current.rotations.len()] == current.rotations
        && current.state == ConnectorCredentialAuthorizationState::Active
        && current.pending_credential_id.is_none()
        && proposed.state == ConnectorCredentialAuthorizationState::Active
        && proposed.current_credential_id == current.current_credential_id
    {
        let successor = proposed
            .history
            .last()
            .ok_or(AgentPersistenceError::SnapshotRejected(
                "rotation successor",
            ))?;
        let rotation = proposed
            .rotations
            .last()
            .ok_or(AgentPersistenceError::SnapshotRejected("rotation record"))?;
        if successor.status == ConnectorCredentialStatus::Pending
            && proposed.pending_credential_id == Some(successor.credential.credential_id())
            && rotation.successor_credential_id == successor.credential.credential_id()
        {
            return Ok(AuthorizationTransition::RotationStarted {
                rotation,
                successor: &successor.credential,
            });
        }
    }

    if proposed.history.len() == current.history.len() + 1
        && proposed.rotations == current.rotations
        && current.state == ConnectorCredentialAuthorizationState::Active
        && current.pending_credential_id.is_none()
        && proposed.state == ConnectorCredentialAuthorizationState::Active
        && proposed.current_credential_id == current.current_credential_id
    {
        let successor = proposed
            .history
            .last()
            .ok_or(AgentPersistenceError::SnapshotRejected("reissue successor"))?;
        let current_credential = current
            .history
            .iter()
            .find(|entry| entry.status == ConnectorCredentialStatus::Current)
            .ok_or(AgentPersistenceError::SnapshotRejected(
                "reissue current credential",
            ))?;
        if successor.status == ConnectorCredentialStatus::Pending
            && proposed.pending_credential_id == Some(successor.credential.credential_id())
            && successor.credential.generation() == current_credential.credential.generation()
            && successor.credential.revision() == current_credential.credential.revision()
        {
            return Ok(AuthorizationTransition::ReissueStarted {
                successor: &successor.credential,
            });
        }
    }

    let mut aggregate = ConnectorCredentialAuthorization::try_from_snapshot(current.clone())
        .map_err(|_| AgentPersistenceError::SnapshotRejected("current credential authorization"))?;
    if let Some(pending_id) = current.pending_credential_id
        && aggregate.promote_successor(pending_id).is_ok()
        && aggregate.snapshot() == *proposed
    {
        return Ok(AuthorizationTransition::Promoted);
    }
    let mut aggregate = ConnectorCredentialAuthorization::try_from_snapshot(current.clone())
        .map_err(|_| AgentPersistenceError::SnapshotRejected("current credential authorization"))?;
    if aggregate.revoke().is_ok() && aggregate.snapshot() == *proposed {
        return Ok(AuthorizationTransition::Revoked);
    }
    Err(AgentPersistenceError::SnapshotRejected(
        "Connector credential authorization successor",
    ))
}

struct AuthorizationRevisionRow {
    revision: u64,
    generation: u64,
    lifecycle: String,
    current_credential_id: ConnectorCredentialId,
    pending_credential_id: Option<ConnectorCredentialId>,
    cause_kind: String,
    cause_operation_id: RequestId,
}

fn parse_revision_history(
    rows: Vec<sqlx::postgres::PgRow>,
) -> Result<Vec<AuthorizationRevisionRow>, AgentPersistenceError> {
    rows.into_iter()
        .map(|row| {
            let pending: Option<Uuid> = row.try_get("pending_credential_id")?;
            Ok(AuthorizationRevisionRow {
                revision: positive_u64(
                    row.try_get("authorization_revision")?,
                    "authorization revision",
                )?,
                generation: positive_u64(
                    row.try_get("connector_generation")?,
                    "authorization generation",
                )?,
                lifecycle: row.try_get("lifecycle")?,
                current_credential_id: credential_id(row.try_get("current_credential_id")?)?,
                pending_credential_id: pending.map(credential_id).transpose()?,
                cause_kind: row.try_get("cause_kind")?,
                cause_operation_id: request_id(row.try_get("cause_operation_id")?)?,
            })
        })
        .collect()
}

fn validate_revision_history(
    head: u64,
    revisions: &[AuthorizationRevisionRow],
) -> Result<(), AgentPersistenceError> {
    if revisions.len() as u64 != head || revisions.is_empty() {
        return Err(AgentPersistenceError::CorruptData(
            "Connector credential authorization revision count",
        ));
    }
    for (index, revision) in revisions.iter().enumerate() {
        if revision.revision != index as u64 + 1 {
            return Err(AgentPersistenceError::CorruptData(
                "Connector credential authorization revision sequence",
            ));
        }
        if index == 0 {
            if revision.lifecycle != "active"
                || revision.pending_credential_id.is_some()
                || revision.cause_kind != "enrollment"
            {
                return Err(AgentPersistenceError::CorruptData(
                    "initial Connector credential authorization",
                ));
            }
            continue;
        }
        let previous = &revisions[index - 1];
        if previous.lifecycle == "revoked" {
            return Err(AgentPersistenceError::CorruptData(
                "revoked Connector credential authorization advanced",
            ));
        }
        let valid = match revision.cause_kind.as_str() {
            "rotation_started" => {
                revision.lifecycle == "active"
                    && revision.generation == previous.generation
                    && revision.current_credential_id == previous.current_credential_id
                    && previous.pending_credential_id.is_none()
                    && revision.pending_credential_id.is_some()
            }
            "rotation_promoted" => {
                revision.lifecycle == "active"
                    && revision.generation == previous.generation + 1
                    && Some(revision.current_credential_id) == previous.pending_credential_id
                    && revision.pending_credential_id.is_none()
            }
            "revoked" => {
                revision.lifecycle == "revoked"
                    && revision.generation == previous.generation
                    && revision.current_credential_id == previous.current_credential_id
                    && revision.pending_credential_id == previous.pending_credential_id
            }
            _ => false,
        };
        if !valid {
            return Err(AgentPersistenceError::CorruptData(
                "Connector credential authorization transition",
            ));
        }
    }
    Ok(())
}

fn validate_revision_credentials(
    revisions: &[AuthorizationRevisionRow],
    credentials: &[ConnectorCredential],
    rotations: &[AcceptedRotationSnapshot],
) -> Result<(), AgentPersistenceError> {
    if rotations.len() + 1 != credentials.len() {
        return Err(AgentPersistenceError::CorruptData(
            "Connector credential rotation count",
        ));
    }
    for (index, credential) in credentials.iter().enumerate() {
        if index > 0 {
            let previous = &credentials[index - 1];
            if credential.generation() != previous.generation() + 1
                || credential.revision() <= previous.revision()
            {
                return Err(AgentPersistenceError::CorruptData(
                    "Connector credential sequence",
                ));
            }
        }
    }
    for (index, rotation) in rotations.iter().enumerate() {
        if rotation.current_credential_id != credentials[index].credential_id()
            || rotation.successor_credential_id != credentials[index + 1].credential_id()
        {
            return Err(AgentPersistenceError::CorruptData(
                "Connector credential rotation chain",
            ));
        }
        let matching_revision = revisions.iter().any(|revision| {
            revision.cause_kind == "rotation_started"
                && revision.cause_operation_id == rotation.request_id
                && revision.current_credential_id == rotation.current_credential_id
                && revision.pending_credential_id == Some(rotation.successor_credential_id)
        });
        if !matching_revision {
            return Err(AgentPersistenceError::CorruptData(
                "Connector credential rotation authorization",
            ));
        }
    }
    Ok(())
}

fn reject_oversized_audit_rows(row_count: usize) -> Result<(), AgentPersistenceError> {
    if u64::try_from(row_count).is_ok_and(|count| count <= MAX_CONNECTOR_CREDENTIAL_AUDIT_ROWS) {
        Ok(())
    } else {
        Err(AgentPersistenceError::MaterializationLimitExceeded(
            "Connector credential authorization audit",
        ))
    }
}

fn load_rotation_row(
    row: &sqlx::postgres::PgRow,
) -> Result<AcceptedRotationSnapshot, AgentPersistenceError> {
    Ok(AcceptedRotationSnapshot {
        request_id: request_id(row.try_get("request_id")?)?,
        request_digest: digest(row.try_get("request_digest")?, "rotation request digest")?,
        result_digest: digest(row.try_get("result_digest")?, "rotation result digest")?,
        current_credential_id: credential_id(row.try_get("current_credential_id")?)?,
        successor_credential_id: credential_id(row.try_get("successor_credential_id")?)?,
        command_sequence: positive_u64(
            row.try_get("command_sequence")?,
            "rotation command sequence",
        )?,
        command_payload_digest: digest(
            row.try_get("command_payload_digest")?,
            "rotation command payload digest",
        )?,
        nonce: bytes_32(row.try_get("nonce")?, "rotation nonce")?,
    })
}

fn load_credential_row(
    tenant_id: TenantId,
    connector_id: ConnectorId,
    row: &sqlx::postgres::PgRow,
) -> Result<ConnectorCredential, AgentPersistenceError> {
    let control_key = Ed25519PublicKey::try_from(bytes_32(
        row.try_get("online_public_key")?,
        "Connector control public key",
    )?)
    .map_err(|_| AgentPersistenceError::CorruptData("Connector control public key"))?;
    let refresh_key = Ed25519PublicKey::try_from(bytes_32(
        row.try_get("refresh_public_key")?,
        "Connector refresh public key",
    )?)
    .map_err(|_| AgentPersistenceError::CorruptData("Connector refresh public key"))?;
    ConnectorCredential::new(
        credential_id(row.try_get("credential_id")?)?,
        tenant_id,
        connector_id,
        positive_u64(
            row.try_get("connector_generation")?,
            "credential generation",
        )?,
        revision_from_i64(row.try_get("credential_revision")?)?,
        control_key,
        refresh_key,
        digest(
            row.try_get("certificate_fingerprint")?,
            "certificate fingerprint",
        )?,
        row.try_get("certificate_chain_der")?,
        row.try_get("not_before_ms")?,
        row.try_get("not_after_ms")?,
    )
    .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector credential"))
}

fn authorization_state_code(state: ConnectorCredentialAuthorizationState) -> &'static str {
    match state {
        ConnectorCredentialAuthorizationState::Active => "active",
        ConnectorCredentialAuthorizationState::Revoked => "revoked",
    }
}

fn parse_authorization_state(
    state: &str,
) -> Result<ConnectorCredentialAuthorizationState, AgentPersistenceError> {
    match state {
        "active" => Ok(ConnectorCredentialAuthorizationState::Active),
        "revoked" => Ok(ConnectorCredentialAuthorizationState::Revoked),
        _ => Err(AgentPersistenceError::CorruptData(
            "Connector credential authorization lifecycle",
        )),
    }
}

fn credential_id(value: Uuid) -> Result<ConnectorCredentialId, AgentPersistenceError> {
    ConnectorCredentialId::try_from(value)
        .map_err(|_| AgentPersistenceError::CorruptData("Connector credential ID"))
}

fn request_id(value: Uuid) -> Result<RequestId, AgentPersistenceError> {
    RequestId::try_from(value).map_err(|_| AgentPersistenceError::CorruptData("request ID"))
}

pub(crate) fn digest(
    value: Vec<u8>,
    field: &'static str,
) -> Result<Sha256Digest, AgentPersistenceError> {
    Ok(Sha256Digest::from_bytes(bytes_32(value, field)?))
}

pub(crate) fn bytes_32(
    value: Vec<u8>,
    field: &'static str,
) -> Result<[u8; 32], AgentPersistenceError> {
    value
        .try_into()
        .map_err(|_| AgentPersistenceError::CorruptData(field))
}

pub(crate) fn positive_u64(value: i64, field: &'static str) -> Result<u64, AgentPersistenceError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0 && *value <= Revision::MAX)
        .ok_or(AgentPersistenceError::CorruptData(field))
}

pub(crate) fn nonnegative_u64(
    value: i64,
    field: &'static str,
) -> Result<u64, AgentPersistenceError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value <= Revision::MAX)
        .ok_or(AgentPersistenceError::CorruptData(field))
}

pub(crate) fn to_i64(value: u64, field: &'static str) -> Result<i64, AgentPersistenceError> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value >= 0)
        .ok_or(AgentPersistenceError::CorruptData(field))
}
