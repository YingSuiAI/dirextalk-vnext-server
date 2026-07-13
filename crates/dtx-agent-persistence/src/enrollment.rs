use dtx_agent_control::{
    ConnectorCredentialAuthorization, EnrollmentIntent, EnrollmentIntentSnapshot,
    EnrollmentIntentSnapshotState, Sha256Digest,
};
use dtx_domain::{ConnectorId, EnrollmentIntentId, HostId, RequestId, TenantId};
use sqlx::{Connection, PgConnection, Row};
use uuid::Uuid;

use crate::{
    AgentPersistenceError, ConnectorCredentialAuthorizationRepository, CurrentWrite,
    connector_credential::{
        digest, insert_initial_authorization, lock_connector_control_state, positive_u64,
    },
    registry::{revision_from_i64, revision_to_i64},
};

#[derive(Clone, Copy, Debug, Default)]
pub struct EnrollmentIntentRepository;

impl EnrollmentIntentRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Creates one open intent. The raw enrollment token is never accepted here.
    ///
    /// # Errors
    ///
    /// Returns an error for a non-open snapshot, an immutable identifier conflict,
    /// or a database failure.
    pub async fn create(
        self,
        connection: &mut PgConnection,
        intent: &EnrollmentIntent,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let snapshot = intent.snapshot();
        if !matches!(snapshot.state, EnrollmentIntentSnapshotState::Open) {
            return Err(AgentPersistenceError::SnapshotRejected(
                "new Connector enrollment intent",
            ));
        }
        lock_connector_control_state(connection, snapshot.tenant_id, snapshot.connector_id).await?;
        if let Some(existing) = self
            .load_by_request_id(connection, snapshot.tenant_id, snapshot.request_id)
            .await?
        {
            return if existing.matches_creation_candidate(intent) {
                Ok(CurrentWrite::Existing)
            } else {
                Err(AgentPersistenceError::ImmutableConflict(
                    "Connector enrollment creation request",
                ))
            };
        }
        if ConnectorCredentialAuthorizationRepository::new()
            .load(connection, snapshot.tenant_id, snapshot.connector_id)
            .await?
            .is_some()
        {
            return Err(AgentPersistenceError::ImmutableConflict(
                "enrolled Connector authorization",
            ));
        }
        let inserted =
            sqlx::query(
                "INSERT INTO agent.connector_enrollment_intents (
                 tenant_id, enrollment_intent_id, connector_id, host_id,
                 request_id, connector_generation, spec_revision, token_digest,
                 status, expires_at_ms, created_at_ms
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active',$9,$10)
             ON CONFLICT DO NOTHING",
            )
            .bind(Uuid::from(snapshot.tenant_id))
            .bind(Uuid::from(snapshot.intent_id))
            .bind(Uuid::from(snapshot.connector_id))
            .bind(Uuid::from(snapshot.host_id))
            .bind(Uuid::from(snapshot.request_id))
            .bind(i64::try_from(snapshot.generation).map_err(|_| {
                AgentPersistenceError::CorruptData("Connector enrollment generation")
            })?)
            .bind(revision_to_i64(snapshot.spec_revision)?)
            .bind(snapshot.token_digest.as_bytes().to_vec())
            .bind(snapshot.expires_at_millis)
            .bind(snapshot.created_at_millis)
            .execute(&mut *connection)
            .await?;
        if inserted.rows_affected() == 1 {
            return Ok(CurrentWrite::Inserted);
        }
        if let Some(existing) = self
            .load_by_request_id(connection, snapshot.tenant_id, snapshot.request_id)
            .await?
            && existing.matches_creation_candidate(intent)
        {
            return Ok(CurrentWrite::Existing);
        }
        Err(AgentPersistenceError::ImmutableConflict(
            "Connector enrollment intent",
        ))
    }

    /// Atomically persists a consumed token, public credential, and initial authorization head.
    ///
    /// # Errors
    ///
    /// Returns an error when the open snapshot is stale, an exact retry differs,
    /// credential authorization is invalid, or the database transaction fails.
    pub async fn consume_with_authorization(
        self,
        connection: &mut PgConnection,
        consumed: &EnrollmentIntent,
        authorization: &ConnectorCredentialAuthorization,
        expected_open: &EnrollmentIntentSnapshot,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let proposed = consumed.snapshot();
        if !matches!(
            proposed.state,
            EnrollmentIntentSnapshotState::Consumed { .. }
        ) {
            return Err(AgentPersistenceError::SnapshotRejected(
                "consumed Connector enrollment intent",
            ));
        }
        let authorization = authorization.snapshot();
        let mut transaction = connection.begin().await?;
        let result = self
            .consume_in_transaction(
                &mut transaction,
                &proposed,
                &authorization,
                expected_open,
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

    async fn consume_in_transaction(
        self,
        connection: &mut PgConnection,
        proposed: &EnrollmentIntentSnapshot,
        authorization: &dtx_agent_control::ConnectorCredentialAuthorizationSnapshot,
        expected_open: &EnrollmentIntentSnapshot,
        stored_at_ms: i64,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        lock_connector_control_state(connection, proposed.tenant_id, proposed.connector_id).await?;
        lock_intent(connection, proposed.tenant_id, proposed.intent_id).await?;
        let current = self
            .load(connection, proposed.tenant_id, proposed.intent_id)
            .await?
            .ok_or(AgentPersistenceError::RevisionConflict { current: None })?
            .snapshot();
        if current == *proposed {
            let persisted_authorization = ConnectorCredentialAuthorizationRepository::new()
                .load(connection, proposed.tenant_id, proposed.connector_id)
                .await?
                .ok_or(AgentPersistenceError::CorruptData(
                    "consumed Connector credential authorization",
                ))?;
            return if persisted_authorization.snapshot() == *authorization {
                Ok(CurrentWrite::Existing)
            } else {
                Err(AgentPersistenceError::ImmutableConflict(
                    "consumed Connector credential authorization",
                ))
            };
        }
        if matches!(
            current.state,
            EnrollmentIntentSnapshotState::Consumed { .. }
        ) {
            return Err(AgentPersistenceError::ImmutableConflict(
                "consumed Connector enrollment intent",
            ));
        }
        if current != *expected_open
            || !matches!(current.state, EnrollmentIntentSnapshotState::Open)
        {
            return Err(AgentPersistenceError::RevisionConflict {
                current: Some(current.spec_revision.get()),
            });
        }
        insert_initial_authorization(connection, proposed, authorization, stored_at_ms).await?;
        let EnrollmentIntentSnapshotState::Consumed {
            consumed_at_millis,
            request_digest,
            result_digest,
            result,
        } = &proposed.state
        else {
            unreachable!("consumed state checked above");
        };
        let updated = sqlx::query(
            "UPDATE agent.connector_enrollment_intents
                SET status='consumed', transitioned_at_ms=$3,
                    enrollment_request_digest=$4, enrollment_result_digest=$5,
                    credential_id=$6
              WHERE tenant_id=$1 AND enrollment_intent_id=$2 AND status='active'",
        )
        .bind(Uuid::from(proposed.tenant_id))
        .bind(Uuid::from(proposed.intent_id))
        .bind(*consumed_at_millis)
        .bind(request_digest.as_bytes().to_vec())
        .bind(result_digest.as_bytes().to_vec())
        .bind(Uuid::from(result.credential_id()))
        .execute(&mut *connection)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(AgentPersistenceError::RevisionConflict {
                current: Some(current.spec_revision.get()),
            });
        }
        Ok(CurrentWrite::Advanced)
    }

    /// Persists one open-to-expired or open-to-revoked terminal transition.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale open snapshot, an invalid terminal transition,
    /// or a database failure.
    pub async fn transition(
        self,
        connection: &mut PgConnection,
        terminal: &EnrollmentIntent,
        expected_open: &EnrollmentIntentSnapshot,
    ) -> Result<CurrentWrite, AgentPersistenceError> {
        let proposed = terminal.snapshot();
        let (status, transitioned_at_ms) = match proposed.state {
            EnrollmentIntentSnapshotState::Expired { expired_at_millis } => {
                ("expired", expired_at_millis)
            }
            EnrollmentIntentSnapshotState::Revoked { revoked_at_millis } => {
                ("revoked", revoked_at_millis)
            }
            EnrollmentIntentSnapshotState::Open
            | EnrollmentIntentSnapshotState::Consumed { .. } => {
                return Err(AgentPersistenceError::SnapshotRejected(
                    "terminal Connector enrollment intent",
                ));
            }
        };
        let mut transaction = connection.begin().await?;
        lock_intent(&mut transaction, proposed.tenant_id, proposed.intent_id).await?;
        let current = self
            .load(&mut transaction, proposed.tenant_id, proposed.intent_id)
            .await?
            .ok_or(AgentPersistenceError::RevisionConflict { current: None })?
            .snapshot();
        let result = if current == proposed {
            Ok(CurrentWrite::Existing)
        } else if current != *expected_open
            || !matches!(current.state, EnrollmentIntentSnapshotState::Open)
        {
            Err(AgentPersistenceError::RevisionConflict {
                current: Some(current.spec_revision.get()),
            })
        } else {
            let updated = sqlx::query(
                "UPDATE agent.connector_enrollment_intents
                    SET status=$3, transitioned_at_ms=$4
                  WHERE tenant_id=$1 AND enrollment_intent_id=$2 AND status='active'",
            )
            .bind(Uuid::from(proposed.tenant_id))
            .bind(Uuid::from(proposed.intent_id))
            .bind(status)
            .bind(transitioned_at_ms)
            .execute(&mut *transaction)
            .await?;
            if updated.rows_affected() == 1 {
                Ok(CurrentWrite::Advanced)
            } else {
                Err(AgentPersistenceError::RevisionConflict {
                    current: Some(current.spec_revision.get()),
                })
            }
        };
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

    /// Looks up an enrollment intent by its one-way token digest.
    ///
    /// # Errors
    ///
    /// Returns an error when persisted state is corrupt or the database read fails.
    pub async fn load_by_token_digest(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        token_digest: Sha256Digest,
    ) -> Result<Option<EnrollmentIntent>, AgentPersistenceError> {
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT enrollment_intent_id
               FROM agent.connector_enrollment_intents
              WHERE tenant_id=$1 AND token_digest=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(token_digest.as_bytes().to_vec())
        .fetch_optional(&mut *connection)
        .await?;
        match id {
            Some(id) => {
                self.load(connection, tenant_id, enrollment_intent_id(id)?)
                    .await
            }
            None => Ok(None),
        }
    }

    /// Loads one enrollment creation operation by its caller-owned request identity.
    ///
    /// # Errors
    ///
    /// Returns an error when persisted state is corrupt or the database read fails.
    pub async fn load_by_request_id(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        request_id: RequestId,
    ) -> Result<Option<EnrollmentIntent>, AgentPersistenceError> {
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT enrollment_intent_id
               FROM agent.connector_enrollment_intents
              WHERE tenant_id=$1 AND request_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(request_id))
        .fetch_optional(&mut *connection)
        .await?;
        match id {
            Some(id) => {
                self.load(connection, tenant_id, enrollment_intent_id(id)?)
                    .await
            }
            None => Ok(None),
        }
    }

    /// Loads and validates an enrollment intent and its public consumed result.
    ///
    /// # Errors
    ///
    /// Returns an error when persisted state is corrupt or the database read fails.
    pub async fn load(
        self,
        connection: &mut PgConnection,
        tenant_id: TenantId,
        intent_id: EnrollmentIntentId,
    ) -> Result<Option<EnrollmentIntent>, AgentPersistenceError> {
        let row = sqlx::query(
            "SELECT connector_id, host_id, request_id, connector_generation,
                    spec_revision, token_digest, status, expires_at_ms, created_at_ms,
                    transitioned_at_ms, enrollment_request_digest,
                    enrollment_result_digest, credential_id
               FROM agent.connector_enrollment_intents
              WHERE tenant_id=$1 AND enrollment_intent_id=$2",
        )
        .bind(Uuid::from(tenant_id))
        .bind(Uuid::from(intent_id))
        .fetch_optional(&mut *connection)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let connector_id = connector_id(row.try_get("connector_id")?)?;
        let transitioned_at: Option<i64> = row.try_get("transitioned_at_ms")?;
        let request_digest: Option<Vec<u8>> = row.try_get("enrollment_request_digest")?;
        let result_digest: Option<Vec<u8>> = row.try_get("enrollment_result_digest")?;
        let credential_id: Option<Uuid> = row.try_get("credential_id")?;
        let status: String = row.try_get("status")?;
        let state = match status.as_str() {
            "active" => EnrollmentIntentSnapshotState::Open,
            "expired" => EnrollmentIntentSnapshotState::Expired {
                expired_at_millis: transitioned_at.ok_or(AgentPersistenceError::CorruptData(
                    "Connector enrollment expiration time",
                ))?,
            },
            "revoked" => EnrollmentIntentSnapshotState::Revoked {
                revoked_at_millis: transitioned_at.ok_or(AgentPersistenceError::CorruptData(
                    "Connector enrollment revocation time",
                ))?,
            },
            "consumed" => {
                let id = credential_id
                    .map(credential_id_from_uuid)
                    .transpose()?
                    .ok_or(AgentPersistenceError::CorruptData(
                        "Connector enrollment credential ID",
                    ))?;
                let authorization = ConnectorCredentialAuthorizationRepository::new()
                    .load(connection, tenant_id, connector_id)
                    .await?
                    .ok_or(AgentPersistenceError::CorruptData(
                        "Connector enrollment credential authorization",
                    ))?;
                let result = authorization.credential(id).cloned().ok_or(
                    AgentPersistenceError::CorruptData("Connector enrollment credential result"),
                )?;
                EnrollmentIntentSnapshotState::Consumed {
                    consumed_at_millis: transitioned_at.ok_or(
                        AgentPersistenceError::CorruptData("Connector enrollment consumption time"),
                    )?,
                    request_digest: digest(
                        request_digest.ok_or(AgentPersistenceError::CorruptData(
                            "Connector enrollment request digest",
                        ))?,
                        "Connector enrollment request digest",
                    )?,
                    result_digest: digest(
                        result_digest.ok_or(AgentPersistenceError::CorruptData(
                            "Connector enrollment result digest",
                        ))?,
                        "Connector enrollment result digest",
                    )?,
                    result: Box::new(result),
                }
            }
            _ => {
                return Err(AgentPersistenceError::CorruptData(
                    "Connector enrollment status",
                ));
            }
        };
        let snapshot = EnrollmentIntentSnapshot {
            intent_id,
            tenant_id,
            host_id: host_id(row.try_get("host_id")?)?,
            connector_id,
            generation: positive_u64(
                row.try_get("connector_generation")?,
                "Connector enrollment generation",
            )?,
            spec_revision: revision_from_i64(row.try_get("spec_revision")?)?,
            request_id: request_id(row.try_get("request_id")?)?,
            token_digest: digest(row.try_get("token_digest")?, "enrollment token digest")?,
            created_at_millis: row.try_get("created_at_ms")?,
            expires_at_millis: row.try_get("expires_at_ms")?,
            state,
        };
        EnrollmentIntent::try_from_snapshot(snapshot)
            .map(Some)
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Connector enrollment intent"))
    }
}

async fn lock_intent(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    intent_id: EnrollmentIntentId,
) -> Result<(), AgentPersistenceError> {
    let locked: Option<Uuid> = sqlx::query_scalar(
        "SELECT enrollment_intent_id
           FROM agent.connector_enrollment_intents
          WHERE tenant_id=$1 AND enrollment_intent_id=$2 FOR UPDATE",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(intent_id))
    .fetch_optional(&mut *connection)
    .await?;
    if locked.is_some() {
        Ok(())
    } else {
        Err(AgentPersistenceError::RevisionConflict { current: None })
    }
}

fn enrollment_intent_id(value: Uuid) -> Result<EnrollmentIntentId, AgentPersistenceError> {
    EnrollmentIntentId::try_from(value)
        .map_err(|_| AgentPersistenceError::CorruptData("Connector enrollment intent ID"))
}

fn credential_id_from_uuid(
    value: Uuid,
) -> Result<dtx_domain::ConnectorCredentialId, AgentPersistenceError> {
    dtx_domain::ConnectorCredentialId::try_from(value)
        .map_err(|_| AgentPersistenceError::CorruptData("Connector credential ID"))
}

fn connector_id(value: Uuid) -> Result<ConnectorId, AgentPersistenceError> {
    ConnectorId::try_from(value).map_err(|_| AgentPersistenceError::CorruptData("Connector ID"))
}

fn host_id(value: Uuid) -> Result<HostId, AgentPersistenceError> {
    HostId::try_from(value).map_err(|_| AgentPersistenceError::CorruptData("Agent Host ID"))
}

fn request_id(value: Uuid) -> Result<RequestId, AgentPersistenceError> {
    RequestId::try_from(value).map_err(|_| AgentPersistenceError::CorruptData("request ID"))
}
