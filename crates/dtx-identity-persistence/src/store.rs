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
}

async fn validate_identity_runtime_role(pool: &PgPool) -> Result<(), IdentityPersistenceError> {
    if session_principal_can_escalate_role(pool).await? {
        return Err(IdentityPersistenceError::RuntimeRoleOverprivileged);
    }

    let authorized: bool = sqlx::query_scalar(
        "SELECT identity.identity_runtime_authorized() \
             AND has_schema_privilege(current_user, 'identity', 'USAGE') \
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
        "SELECT has_schema_privilege(current_user, 'system', 'USAGE') \
             OR has_schema_privilege(current_user, 'system', 'CREATE') \
             OR has_schema_privilege(current_user, 'agent', 'USAGE') \
             OR has_schema_privilege(current_user, 'agent', 'CREATE') \
             OR EXISTS (\
                 SELECT 1 \
                   FROM pg_class AS relation \
                   JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace \
                  WHERE namespace.nspname IN ('system', 'agent') \
                    AND relation.relkind IN ('r', 'p', 'v', 'm', 'f') \
                    AND (\
                        has_table_privilege(current_user, relation.oid, 'SELECT') \
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
                            'bootstrap_idempotency_claims', 'fork_evidence', 'log_outbox'\
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
