use std::fmt;

use sqlx::{
    PgConnection, PgPool, Postgres, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use crate::IdentityPersistenceError;

/// Validated non-owner pool dedicated to self-certifying identity-log storage.
#[derive(Clone)]
pub struct IdentityPgStore {
    pool: PgPool,
}

impl fmt::Debug for IdentityPgStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityPgStore")
            .field("pool", &self.pool)
            .finish()
    }
}

impl IdentityPgStore {
    /// Opens an identity-only pool after enforcing the non-owner writer-role boundary.
    ///
    /// The caller must provision the `dtx_identity_runtime` group membership
    /// separately from tenant-scoped service roles. Connection options are not
    /// retained in a debuggable field.
    ///
    /// # Errors
    ///
    /// Returns an error when the pool cannot connect or the configured role is
    /// unauthorized, privileged, or lacks a required identity relation grant.
    pub async fn connect(
        options: PgConnectOptions,
        max_connections: u32,
    ) -> Result<Self, IdentityPersistenceError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect_with(options)
            .await?;
        validate_identity_runtime_role(&pool).await?;
        Ok(Self { pool })
    }

    /// Revalidates the current role and the exact fresh-only schema epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when the database cannot be reached, the runtime role
    /// no longer satisfies the identity boundary, or the schema epoch differs
    /// from the Product Core Alpha baseline.
    pub async fn readiness_check(&self) -> Result<bool, IdentityPersistenceError> {
        validate_identity_runtime_role(&self.pool).await?;
        dtx_storage::PgStore::readiness_check_schema(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Begins a transaction isolated from tenant-scoped RLS context.
    ///
    /// # Errors
    ///
    /// Returns an error for a database failure or a leaked tenant setting on a
    /// pooled connection.
    pub async fn begin(&self) -> Result<IdentitySession<'_>, IdentityPersistenceError> {
        let mut transaction = self.pool.begin().await?;
        let existing: Option<String> =
            sqlx::query_scalar("SELECT NULLIF(current_setting('dtx.tenant_id', true), '')")
                .fetch_one(&mut *transaction)
                .await?;
        if existing.is_some() {
            transaction.rollback().await?;
            return Err(IdentityPersistenceError::TenantContextLeak);
        }
        Ok(IdentitySession { transaction })
    }

    /// Begins a read-only repeatable-read transaction for a coherent durable
    /// observation that must never contend with identity writers.
    ///
    /// # Errors
    ///
    /// Returns a persistence error when the database cannot establish the
    /// requested snapshot or a tenant setting leaked onto the pooled session.
    pub async fn begin_readonly_repeatable(
        &self,
    ) -> Result<IdentitySession<'_>, IdentityPersistenceError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let existing: Option<String> =
            sqlx::query_scalar("SELECT NULLIF(current_setting('dtx.tenant_id', true), '')")
                .fetch_one(&mut *transaction)
                .await?;
        if existing.is_some() {
            transaction.rollback().await?;
            return Err(IdentityPersistenceError::TenantContextLeak);
        }
        Ok(IdentitySession { transaction })
    }
}

#[allow(clippy::too_many_lines)] // One fail-closed audit must list every relation and privilege together.
async fn validate_identity_runtime_role(pool: &PgPool) -> Result<(), IdentityPersistenceError> {
    if session_principal_can_escalate_role(pool).await? {
        return Err(IdentityPersistenceError::RuntimeRoleOverprivileged);
    }

    let authorized: bool = sqlx::query_scalar(
        "SELECT identity.identity_runtime_authorized() \
             AND has_schema_privilege(current_user, 'identity', 'USAGE') \
             AND has_schema_privilege(current_user, 'realtime', 'USAGE') \
             AND has_table_privilege(current_user, 'identity.log_heads', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.log_heads', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.log_heads', 'UPDATE') \
             AND has_table_privilege(current_user, 'identity.log_entries', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.log_entries', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.command_receipts', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.command_receipts', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.command_receipts', 'UPDATE') \
             AND has_table_privilege(current_user, 'identity.bootstrap_idempotency_claims', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.bootstrap_idempotency_claims', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.device_session_challenges', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.device_session_challenges', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.device_session_challenges', 'UPDATE') \
             AND has_table_privilege(current_user, 'identity.device_sessions', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.device_sessions', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.device_session_idempotency_claims', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.device_session_idempotency_claims', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.device_session_receipts', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.device_session_receipts', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.device_enrollment_challenges', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.device_enrollment_challenges', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.device_enrollment_challenges', 'UPDATE') \
             AND has_table_privilege(current_user, 'identity.key_packages', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.key_packages', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.key_packages', 'UPDATE') \
             AND has_table_privilege(current_user, 'identity.key_package_publish_claims', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.key_package_publish_claims', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.key_package_claims', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.key_package_claims', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.key_package_claim_receipts', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.key_package_claim_receipts', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.contact_invites', 'SELECT,INSERT,UPDATE') \
             AND has_table_privilege(current_user, 'identity.contact_requests', 'SELECT,INSERT,UPDATE') \
             AND has_table_privilege(current_user, 'identity.contact_delivery_outbox', 'SELECT,INSERT') \
             AND has_table_privilege(current_user, 'identity.contact_owner_commands', 'SELECT,INSERT') \
             AND has_table_privilege(current_user, 'identity.contact_rate_limits', 'SELECT,INSERT,UPDATE') \
             AND has_table_privilege(current_user, 'identity.recovery_scope_catalogs', 'SELECT,INSERT') \
             AND has_table_privilege(current_user, 'identity.recovery_scope_catalog_preparations', 'SELECT,INSERT') \
             AND has_table_privilege(current_user, 'identity.history_recovery_requests', 'SELECT,INSERT') \
             AND has_table_privilege(current_user, 'identity.history_recovery_completion_descriptors', 'SELECT,INSERT') \
             AND has_table_privilege(current_user, 'identity.history_recovery_completion_key_head', 'SELECT,INSERT,UPDATE') \
             AND has_table_privilege(current_user, 'identity.history_recovery_completions_v2', 'SELECT,INSERT') \
             AND has_table_privilege(current_user, 'identity.client_bindings', 'SELECT,INSERT,UPDATE') \
             AND has_schema_privilege(current_user, 'messaging', 'USAGE') \
             AND has_function_privilege(current_user, 'messaging.is_uuid_v7(uuid)', 'EXECUTE') \
             AND has_column_privilege(current_user, 'identity.recovery_scope_catalog_preparations', 'provider_response_bytes', 'UPDATE') \
             AND has_column_privilege(current_user, 'identity.recovery_scope_catalog_preparations', 'provider_response_digest', 'UPDATE') \
             AND has_column_privilege(current_user, 'identity.recovery_scope_catalog_preparations', 'provider_device_id', 'UPDATE') \
             AND has_column_privilege(current_user, 'identity.recovery_scope_catalog_preparations', 'provider_signing_key', 'UPDATE') \
             AND has_column_privilege(current_user, 'identity.recovery_scope_catalog_preparations', 'provider_ciphertext_digest', 'UPDATE') \
             AND has_column_privilege(current_user, 'identity.recovery_scope_catalog_preparations', 'provider_expires_at_ms', 'UPDATE') \
             AND has_column_privilege(current_user, 'identity.recovery_scope_catalog_preparations', 'provider_idempotency_key_hash', 'UPDATE') \
             AND has_column_privilege(current_user, 'identity.recovery_scope_catalog_preparations', 'provider_recorded_at_ms', 'UPDATE') \
             AND has_function_privilege( \
                 current_user, \
                 'identity.prune_expired_device_sessions(bigint, integer)', \
                 'EXECUTE' \
             ) \
             AND has_function_privilege( \
                 current_user, \
                 'identity.prune_expired_device_enrollment_challenges(bigint, integer)', \
                 'EXECUTE' \
             ) \
             AND has_function_privilege( \
                 current_user, \
                 'identity.prune_expired_key_packages(bigint, integer)', \
                 'EXECUTE' \
             ) \
             AND has_function_privilege( \
                 current_user, \
                 'realtime.append_identity_invalidation(text,text,bytea)', \
                 'EXECUTE' \
             ) \
             AND has_function_privilege( \
                 current_user, \
                 'identity.mls_v5_recovery_authorization_projection(text,uuid,uuid,uuid,bytea,bytea,bytea,bytea,bigint)', \
                 'EXECUTE' \
             ) \
             AND has_table_privilege(current_user, 'identity.fork_evidence', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.fork_evidence', 'INSERT') \
             AND has_table_privilege(current_user, 'identity.log_outbox', 'SELECT') \
             AND has_table_privilege(current_user, 'identity.log_outbox', 'INSERT')",
    )
    .fetch_one(pool)
    .await?;
    if !authorized {
        return Err(IdentityPersistenceError::RuntimeRoleUnauthorized);
    }
    if role_has_cross_scope_access(pool).await? || role_has_excess_identity_privileges(pool).await?
    {
        return Err(IdentityPersistenceError::RuntimeRoleOverprivileged);
    }

    let unsafe_role: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
             SELECT 1 FROM pg_roles AS candidate \
             WHERE pg_has_role(current_user, candidate.oid, 'MEMBER') \
               AND (candidate.rolsuper OR candidate.rolbypassrls \
                 OR candidate.rolcreatedb OR candidate.rolcreaterole \
                 OR candidate.rolreplication OR left(candidate.rolname, 3) = 'pg_' \
                 OR EXISTS (\
                     SELECT 1 FROM pg_database \
                     WHERE datname = current_database() AND datdba = candidate.oid\
                 ) \
                 OR EXISTS (\
                     SELECT 1 FROM pg_namespace AS namespace \
                     WHERE namespace.nspname = 'identity' \
                       AND (namespace.nspowner = candidate.oid \
                         OR has_schema_privilege(candidate.oid, namespace.oid, 'CREATE'))\
                 ) OR EXISTS (\
                     SELECT 1 FROM pg_class AS relation \
                     JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace \
                     WHERE namespace.nspname = 'identity' \
                       AND relation.relowner = candidate.oid\
                 ) OR EXISTS (\
                     SELECT 1 FROM pg_proc AS procedure \
                     JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace \
                     WHERE namespace.nspname = 'identity' \
                       AND procedure.proowner = candidate.oid\
                 ) OR EXISTS (\
                     SELECT 1 FROM pg_type AS data_type \
                     JOIN pg_namespace AS namespace ON namespace.oid = data_type.typnamespace \
                     WHERE namespace.nspname = 'identity' \
                       AND data_type.typowner = candidate.oid\
                 ))\
         )",
    )
    .fetch_one(pool)
    .await?;
    if unsafe_role {
        Err(IdentityPersistenceError::UnsafeRuntimeRole)
    } else {
        Ok(())
    }
}

async fn session_principal_can_escalate_role(
    pool: &PgPool,
) -> Result<bool, IdentityPersistenceError> {
    sqlx::query_scalar(
        "WITH RECURSIVE reachable_role(role_oid) AS (\
             SELECT candidate.oid \
               FROM pg_roles AS candidate \
              WHERE candidate.rolname = session_user \
             UNION \
             SELECT membership.roleid \
               FROM pg_auth_members AS membership \
               JOIN reachable_role AS parent ON parent.role_oid = membership.member\
         ) \
         SELECT current_user <> session_user \
             OR EXISTS (\
                 SELECT 1 \
                   FROM reachable_role \
                  WHERE role_oid <> (\
                      SELECT candidate.oid FROM pg_roles AS candidate \
                       WHERE candidate.rolname = session_user\
                  ) \
                    AND role_oid <> to_regrole('dtx_identity_runtime')\
             ) \
             OR EXISTS (\
                 SELECT 1 \
                   FROM pg_auth_members AS membership \
                   JOIN reachable_role AS member_role \
                     ON member_role.role_oid = membership.member \
                  WHERE membership.admin_option\
             )",
    )
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

async fn role_has_cross_scope_access(pool: &PgPool) -> Result<bool, IdentityPersistenceError> {
    sqlx::query_scalar(
        "SELECT has_schema_privilege(current_user, 'system', 'CREATE') \
             OR has_schema_privilege(current_user, 'agent', 'USAGE') \
             OR has_schema_privilege(current_user, 'agent', 'CREATE') \
             OR EXISTS (\
                 SELECT 1 \
                   FROM pg_class AS relation \
                   JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace \
                  WHERE namespace.nspname IN ('system', 'agent') \
                    AND relation.relkind IN ('r', 'p', 'v', 'm', 'f') \
                    AND (\
                        (namespace.nspname = 'system' \
                         AND relation.relname NOT IN ('schema_epoch', 'schema_versions') \
                         AND has_table_privilege(current_user, relation.oid, 'SELECT')) \
                        OR (namespace.nspname = 'agent' \
                            AND has_table_privilege(current_user, relation.oid, 'SELECT')) \
                        OR has_table_privilege(current_user, relation.oid, 'INSERT') \
                        OR has_table_privilege(current_user, relation.oid, 'UPDATE') \
                        OR has_table_privilege(current_user, relation.oid, 'DELETE') \
                        OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                        OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                        OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                        OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                    )\
             ) \
             OR EXISTS (\
                 SELECT 1 \
                   FROM pg_class AS relation \
                   JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace \
                  WHERE namespace.nspname IN ('system', 'agent') \
                    AND relation.relkind = 'S' \
                    AND (\
                        has_sequence_privilege(current_user, relation.oid, 'USAGE') \
                        OR has_sequence_privilege(current_user, relation.oid, 'SELECT') \
                        OR has_sequence_privilege(current_user, relation.oid, 'UPDATE')\
                    )\
             )",
    )
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

#[allow(
    clippy::too_many_lines,
    reason = "one SQL privilege matrix is the identity runtime's auditable source of truth"
)]
async fn role_has_excess_identity_privileges(
    pool: &PgPool,
) -> Result<bool, IdentityPersistenceError> {
    sqlx::query_scalar(
        "SELECT has_schema_privilege(current_user, 'identity', 'CREATE') \
             OR EXISTS (\
                 SELECT 1 \
                   FROM pg_class AS relation \
                   JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace \
                  WHERE namespace.nspname = 'identity' \
                    AND relation.relkind IN ('r', 'p', 'v', 'm', 'f') \
                    AND (\
                        (relation.relname = 'log_heads' AND (\
                            has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname = 'log_entries' AND (\
                            has_table_privilege(current_user, relation.oid, 'UPDATE') \
                            OR has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname = 'command_receipts' AND (\
                            has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname = 'bootstrap_idempotency_claims' AND (\
                            has_table_privilege(current_user, relation.oid, 'UPDATE') \
                            OR has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname = 'device_session_challenges' AND (\
                            has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname = 'device_enrollment_challenges' AND (\
                            has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname IN (\
                            'key_packages', 'contact_invites', 'contact_requests', \
                            'contact_rate_limits'\
                        ) AND (\
                            has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname = 'recovery_scope_catalogs' AND (\
                            has_table_privilege(current_user, relation.oid, 'UPDATE') \
                            OR has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname = 'recovery_scope_catalog_preparations' AND (\
                            has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname = 'history_recovery_requests' AND (\
                            has_table_privilege(current_user, relation.oid, 'UPDATE') \
                            OR has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname = 'history_recovery_completion_key_head' AND (\
                            has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname = 'client_bindings' AND (\
                            has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname IN (\
                            'device_sessions', 'device_session_idempotency_claims', \
                            'device_session_receipts', 'key_package_publish_claims', \
                            'key_package_claims', 'key_package_claim_receipts', \
                            'contact_delivery_outbox', 'contact_owner_commands'\
                        ) AND (\
                            has_table_privilege(current_user, relation.oid, 'UPDATE') \
                            OR has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname = 'fork_evidence' AND (\
                            has_table_privilege(current_user, relation.oid, 'UPDATE') \
                            OR has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname = 'log_outbox' AND (\
                            has_table_privilege(current_user, relation.oid, 'UPDATE') \
                            OR has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        )) \
                        OR (relation.relname NOT IN (\
                            'log_heads', 'log_entries', 'command_receipts', \
                            'bootstrap_idempotency_claims', 'device_session_challenges', \
                            'device_sessions', 'device_session_idempotency_claims', \
                            'device_session_receipts', 'device_enrollment_challenges', \
                            'key_packages', 'key_package_publish_claims', \
                            'key_package_claims', 'key_package_claim_receipts', \
                            'contact_invites', 'contact_requests', \
                            'contact_delivery_outbox', 'contact_owner_commands', \
                            'contact_rate_limits', \
                            'recovery_scope_catalogs', \
                            'recovery_scope_catalog_preparations', \
                            'history_recovery_requests', \
                            'history_recovery_completion_descriptors', \
                            'history_recovery_completion_key_head', \
                            'history_recovery_completions_v2', \
                            'history_recovery_completion_key_head', \
                            'client_bindings', \
                            'fork_evidence', 'log_outbox'\
                        ) AND (\
                            has_table_privilege(current_user, relation.oid, 'SELECT') \
                            OR has_table_privilege(current_user, relation.oid, 'INSERT') \
                            OR has_table_privilege(current_user, relation.oid, 'UPDATE') \
                            OR has_table_privilege(current_user, relation.oid, 'DELETE') \
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE') \
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES') \
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER') \
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')\
                        ))\
                    )\
             ) \
             OR EXISTS (\
                 SELECT 1 \
                   FROM pg_attribute AS attribute \
                  WHERE attribute.attrelid='identity.recovery_scope_catalog_preparations'::regclass \
                    AND attribute.attnum>0 AND NOT attribute.attisdropped \
                    AND attribute.attname NOT IN (\
                        'provider_response_bytes','provider_response_digest',\
                        'provider_device_id','provider_signing_key',\
                        'provider_ciphertext_digest','provider_expires_at_ms',\
                        'provider_idempotency_key_hash','provider_recorded_at_ms'\
                    ) \
                    AND has_column_privilege(current_user,attribute.attrelid,attribute.attname,'UPDATE')\
             ) \
             OR EXISTS (\
                 SELECT 1 \
                   FROM pg_class AS relation \
                   JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace \
                  WHERE namespace.nspname = 'identity' \
                    AND relation.relkind = 'S' \
                    AND (\
                        has_sequence_privilege(current_user, relation.oid, 'USAGE') \
                        OR has_sequence_privilege(current_user, relation.oid, 'SELECT') \
                        OR has_sequence_privilege(current_user, relation.oid, 'UPDATE')\
                    )\
             )",
    )
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

/// Non-cloneable identity-log database transaction.
pub struct IdentitySession<'pool> {
    transaction: Transaction<'pool, Postgres>,
}

impl IdentitySession<'_> {
    /// Gives the repository access to this already role-validated transaction.
    pub fn connection(&mut self) -> &mut PgConnection {
        &mut self.transaction
    }

    /// Commits all immutable log, head, receipt, and outbox changes atomically.
    ///
    /// # Errors
    ///
    /// Returns a database or deferred-constraint failure.
    pub async fn commit(self) -> Result<(), IdentityPersistenceError> {
        self.transaction.commit().await.map_err(Into::into)
    }

    /// Explicitly abandons the current identity transaction.
    ///
    /// # Errors
    ///
    /// Returns a database error if rollback itself cannot complete.
    pub async fn rollback(self) -> Result<(), IdentityPersistenceError> {
        self.transaction.rollback().await.map_err(Into::into)
    }
}
