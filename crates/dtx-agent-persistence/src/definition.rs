use std::{collections::BTreeSet, str::FromStr};

use dtx_agent_registry::{
    AgentDefinitionRegistry, AgentDefinitionRegistrySnapshot, DescriptorDigest,
    VerifiedAgentDefinition,
};
use dtx_domain::{AgentId, IdentityId, Revision};
use sqlx::{Connection, PgConnection, Row};

use crate::AgentPersistenceError;

/// Result of idempotently inserting one immutable Agent definition version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefinitionInsert {
    /// This call inserted the immutable version.
    Inserted,
    /// The exact immutable version was already present.
    Existing,
}

/// `PostgreSQL` adapter for globally public, append-only Agent definitions.
#[derive(Clone, Copy, Debug, Default)]
pub struct AgentDefinitionRepository;

impl AgentDefinitionRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Inserts a verified definition version idempotently.
    ///
    /// # Errors
    ///
    /// Returns an immutable conflict if the Agent/version key already denotes
    /// different content, or a database/corrupt-data error.
    pub async fn insert(
        self,
        connection: &mut PgConnection,
        definition: &VerifiedAgentDefinition,
        admitted_at_ms: i64,
    ) -> Result<DefinitionInsert, AgentPersistenceError> {
        let mut transaction = connection.begin().await?;
        let result = self
            .insert_in_transaction(&mut transaction, definition, admitted_at_ms)
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

    async fn insert_in_transaction(
        self,
        connection: &mut PgConnection,
        definition: &VerifiedAgentDefinition,
        admitted_at_ms: i64,
    ) -> Result<DefinitionInsert, AgentPersistenceError> {
        if let Some(existing) = self
            .load(connection, definition.agent_id(), definition.version())
            .await?
        {
            return if existing == *definition {
                Ok(DefinitionInsert::Existing)
            } else {
                Err(AgentPersistenceError::ImmutableConflict(
                    "Agent definition version",
                ))
            };
        }
        let result = sqlx::query(
            "INSERT INTO agent.agent_definitions (
                 agent_id, definition_version, publisher_id,
                 descriptor_hash, expires_at_ms, admitted_at_ms
             ) VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (agent_id, definition_version) DO NOTHING",
        )
        .bind(definition.agent_id().to_string())
        .bind(revision_to_i64(definition.version())?)
        .bind(definition.publisher_id().to_string())
        .bind(definition.descriptor_hash().as_bytes().to_vec())
        .bind(definition.expires_at_ms())
        .bind(admitted_at_ms)
        .execute(&mut *connection)
        .await?;
        if result.rows_affected() == 1 {
            return Ok(DefinitionInsert::Inserted);
        }
        let existing = self
            .load(connection, definition.agent_id(), definition.version())
            .await?
            .ok_or(AgentPersistenceError::CorruptData(
                "conflicting definition disappeared",
            ))?;
        if &existing == definition {
            Ok(DefinitionInsert::Existing)
        } else {
            Err(AgentPersistenceError::ImmutableConflict(
                "Agent definition version",
            ))
        }
    }

    /// Loads one exact immutable Agent definition version.
    ///
    /// # Errors
    ///
    /// Returns a database error or rejects malformed stored domain values.
    pub async fn load(
        self,
        connection: &mut PgConnection,
        agent_id: AgentId,
        version: Revision,
    ) -> Result<Option<VerifiedAgentDefinition>, AgentPersistenceError> {
        let row = sqlx::query(
            "SELECT publisher_id, descriptor_hash, expires_at_ms
               FROM agent.agent_definitions
              WHERE agent_id = $1 AND definition_version = $2",
        )
        .bind(agent_id.to_string())
        .bind(revision_to_i64(version)?)
        .fetch_optional(&mut *connection)
        .await?;
        row.map(|row| {
            let publisher: String = row.try_get("publisher_id")?;
            let descriptor_hash: Vec<u8> = row.try_get("descriptor_hash")?;
            let expires_at_ms: i64 = row.try_get("expires_at_ms")?;
            let descriptor_hash: [u8; 32] = descriptor_hash
                .try_into()
                .map_err(|_| AgentPersistenceError::CorruptData("descriptor hash length"))?;
            let publisher_id = IdentityId::from_str(&publisher)
                .map_err(|_| AgentPersistenceError::CorruptData("publisher ID"))?;
            Ok(VerifiedAgentDefinition::new(
                agent_id,
                publisher_id,
                version,
                DescriptorDigest::from_bytes(descriptor_hash),
                expires_at_ms,
            ))
        })
        .transpose()
    }

    /// Rehydrates and validates the complete admitted Agent definition registry.
    ///
    /// # Errors
    ///
    /// Returns database/corrupt-data errors or rejects publisher/history/head
    /// contradictions instead of deriving a partial registry.
    pub async fn load_registry(
        self,
        connection: &mut PgConnection,
    ) -> Result<AgentDefinitionRegistry, AgentPersistenceError> {
        let rows = sqlx::query(
            "SELECT agent_id, definition_version, publisher_id,
                    descriptor_hash, expires_at_ms
               FROM agent.agent_definitions
              ORDER BY agent_id, definition_version",
        )
        .fetch_all(&mut *connection)
        .await?;
        let mut definitions = Vec::with_capacity(rows.len());
        let mut agents = BTreeSet::new();
        for row in rows {
            let agent_id: String = row.try_get("agent_id")?;
            let publisher_id: String = row.try_get("publisher_id")?;
            let descriptor_hash: Vec<u8> = row.try_get("descriptor_hash")?;
            let agent_id = AgentId::from_str(&agent_id)
                .map_err(|_| AgentPersistenceError::CorruptData("Agent ID"))?;
            agents.insert(agent_id);
            definitions.push(VerifiedAgentDefinition::new(
                agent_id,
                IdentityId::from_str(&publisher_id)
                    .map_err(|_| AgentPersistenceError::CorruptData("publisher ID"))?,
                revision_from_i64(row.try_get("definition_version")?)?,
                DescriptorDigest::from_bytes(bytes_32(descriptor_hash)?),
                row.try_get("expires_at_ms")?,
            ));
        }
        let registry =
            AgentDefinitionRegistry::try_from_snapshot(AgentDefinitionRegistrySnapshot {
                definitions,
            })
            .map_err(|_| AgentPersistenceError::SnapshotRejected("Agent definition registry"))?;

        let head_rows = sqlx::query(
            "SELECT agent_id, publisher_id, current_version
               FROM agent.agent_definition_heads ORDER BY agent_id",
        )
        .fetch_all(&mut *connection)
        .await?;
        if head_rows.len() != agents.len() {
            return Err(AgentPersistenceError::CorruptData(
                "Agent definition head count",
            ));
        }
        for row in head_rows {
            let agent_id: String = row.try_get("agent_id")?;
            let publisher_id: String = row.try_get("publisher_id")?;
            let agent_id = AgentId::from_str(&agent_id)
                .map_err(|_| AgentPersistenceError::CorruptData("Agent ID"))?;
            let publisher_id = IdentityId::from_str(&publisher_id)
                .map_err(|_| AgentPersistenceError::CorruptData("publisher ID"))?;
            let version = revision_from_i64(row.try_get("current_version")?)?;
            let head = registry
                .head(agent_id)
                .ok_or(AgentPersistenceError::CorruptData(
                    "Agent definition head target",
                ))?;
            if head.publisher_id() != publisher_id || head.version() != version {
                return Err(AgentPersistenceError::SnapshotRejected(
                    "Agent definition head",
                ));
            }
        }
        Ok(registry)
    }
}

fn revision_to_i64(revision: Revision) -> Result<i64, AgentPersistenceError> {
    i64::try_from(revision.get())
        .map_err(|_| AgentPersistenceError::CorruptData("revision exceeds PostgreSQL bigint"))
}

fn revision_from_i64(value: i64) -> Result<Revision, AgentPersistenceError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| Revision::new(value).ok())
        .ok_or(AgentPersistenceError::CorruptData("definition version"))
}

fn bytes_32(value: Vec<u8>) -> Result<[u8; 32], AgentPersistenceError> {
    value
        .try_into()
        .map_err(|_| AgentPersistenceError::CorruptData("descriptor hash length"))
}
