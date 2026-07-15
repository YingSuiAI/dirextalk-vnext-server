use std::fmt;

use dtx_domain::TenantId;
use sqlx::{
    PgConnection, PgPool, Postgres, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use crate::GroupPersistenceError;

/// Validated non-owner pool dedicated to normalized group-membership storage.
#[derive(Clone)]
pub struct GroupPgStore {
    pool: PgPool,
}

impl fmt::Debug for GroupPgStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupPgStore")
            .field("pool", &self.pool)
            .finish()
    }
}

impl GroupPgStore {
    /// Opens a group-only pool after enforcing its non-owner role boundary.
    ///
    /// The database operator provisions the `dtx_group_runtime` membership.
    /// The supplied authenticated tenant is bound transaction-locally for every
    /// operation. The role can additionally read only the identity projection
    /// required to authenticate a device session in this same transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the pool cannot connect or the configured role is
    /// unauthorized, overprivileged, or has a leaked tenant setting.
    pub async fn connect(
        options: PgConnectOptions,
        max_connections: u32,
    ) -> Result<Self, GroupPersistenceError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect_with(options)
            .await?;
        validate_group_runtime_role(&pool).await?;
        Ok(Self { pool })
    }

    /// Begins one transaction bound to an authenticated tenant-scoped RLS context.
    ///
    /// # Errors
    ///
    /// Returns an error for database failures or an inherited tenant setting.
    pub async fn begin(
        &self,
        tenant_id: TenantId,
    ) -> Result<GroupSession<'_>, GroupPersistenceError> {
        let mut transaction = self.pool.begin().await?;
        let existing: Option<String> =
            sqlx::query_scalar("SELECT NULLIF(current_setting('dtx.tenant_id', true), '')")
                .fetch_one(&mut *transaction)
                .await?;
        if existing.is_some() {
            transaction.rollback().await?;
            return Err(GroupPersistenceError::TenantContextLeak);
        }
        sqlx::query("SELECT set_config('dtx.tenant_id', $1, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *transaction)
            .await?;
        Ok(GroupSession {
            tenant_id,
            transaction,
        })
    }
}

/// One non-cloneable group-storage transaction.
pub struct GroupSession<'pool> {
    tenant_id: TenantId,
    transaction: Transaction<'pool, Postgres>,
}

impl GroupSession<'_> {
    /// Returns the authenticated tenant bound to this transaction.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the isolated `PostgreSQL` connection for one repository operation.
    pub(crate) fn connection(&mut self) -> &mut PgConnection {
        &mut self.transaction
    }

    /// Commits all policy, command, workflow, and outbox facts together.
    ///
    /// # Errors
    ///
    /// Returns a database error when the transaction cannot commit.
    pub async fn commit(self) -> Result<(), GroupPersistenceError> {
        self.transaction.commit().await.map_err(Into::into)
    }

    /// Rolls back the incomplete local saga transaction.
    ///
    /// # Errors
    ///
    /// Returns a database error when the transaction cannot roll back.
    pub async fn rollback(self) -> Result<(), GroupPersistenceError> {
        self.transaction.rollback().await.map_err(Into::into)
    }
}

async fn validate_group_runtime_role(pool: &PgPool) -> Result<(), GroupPersistenceError> {
    let schema_usage: bool =
        sqlx::query_scalar("SELECT has_schema_privilege(current_user, 'groups', 'USAGE')")
            .fetch_one(pool)
            .await?;
    if !schema_usage {
        return Err(GroupPersistenceError::RuntimeRoleUnauthorized);
    }
    let can_execute_authorizer: bool = sqlx::query_scalar(
        "SELECT has_function_privilege(\
             current_user,\
             'groups.group_runtime_authorized()'::regprocedure,\
             'EXECUTE'\
         )",
    )
    .fetch_one(pool)
    .await?;
    if !can_execute_authorizer {
        return Err(GroupPersistenceError::RuntimeRoleUnauthorized);
    }
    let can_execute_tenant_boundary: bool = sqlx::query_scalar(
        "SELECT has_schema_privilege(current_user, 'system', 'USAGE')
             AND has_function_privilege(
                 current_user,
                 'system.current_tenant_id()'::regprocedure,
                 'EXECUTE'
             )
             AND has_function_privilege(
                 current_user,
                 'system.is_uuid_v7(uuid)'::regprocedure,
                 'EXECUTE'
             )",
    )
    .fetch_one(pool)
    .await?;
    if !can_execute_tenant_boundary {
        return Err(GroupPersistenceError::RuntimeRoleUnauthorized);
    }
    let can_read_identity_session_projection: bool = sqlx::query_scalar(
        r"SELECT has_schema_privilege(current_user, 'identity', 'USAGE')
             AND has_function_privilege(
                 current_user,
                 'identity.identity_group_reader_authorized()'::regprocedure,
                 'EXECUTE'
             )
             AND has_table_privilege(current_user, 'identity.device_sessions', 'SELECT')
             AND has_table_privilege(current_user, 'identity.log_heads', 'SELECT')
             AND has_table_privilege(current_user, 'identity.log_entries', 'SELECT')",
    )
    .fetch_one(pool)
    .await?;
    if !can_read_identity_session_projection {
        return Err(GroupPersistenceError::RuntimeRoleUnauthorized);
    }
    let authorized: bool = sqlx::query_scalar(
        r"SELECT groups.group_runtime_authorized()
             AND has_schema_privilege(current_user, 'groups', 'USAGE')
             AND has_table_privilege(current_user, 'groups.policy_heads', 'SELECT')
             AND has_table_privilege(current_user, 'groups.policy_heads', 'INSERT')
             AND has_table_privilege(current_user, 'groups.policy_heads', 'UPDATE')
             AND has_table_privilege(current_user, 'groups.admin_terms', 'SELECT')
             AND has_table_privilege(current_user, 'groups.admin_terms', 'INSERT')
             AND has_table_privilege(current_user, 'groups.admin_terms', 'UPDATE')
             AND has_table_privilege(current_user, 'groups.members', 'SELECT')
             AND has_table_privilege(current_user, 'groups.members', 'INSERT')
             AND has_table_privilege(current_user, 'groups.invites', 'SELECT')
             AND has_table_privilege(current_user, 'groups.invites', 'INSERT')
             AND has_table_privilege(current_user, 'groups.invites', 'UPDATE')
             AND has_table_privilege(current_user, 'groups.join_records', 'SELECT')
             AND has_table_privilege(current_user, 'groups.join_records', 'INSERT')
             AND has_table_privilege(current_user, 'groups.join_records', 'UPDATE')
             AND has_table_privilege(current_user, 'groups.membership_commands', 'SELECT')
             AND has_table_privilege(current_user, 'groups.membership_commands', 'INSERT')
             AND has_table_privilege(current_user, 'groups.membership_workflows', 'SELECT')
             AND has_table_privilege(current_user, 'groups.membership_workflows', 'INSERT')
             AND has_table_privilege(current_user, 'groups.membership_workflows', 'UPDATE')
             AND has_table_privilege(current_user, 'groups.sequencer_outbox', 'SELECT')
             AND has_table_privilege(current_user, 'groups.sequencer_outbox', 'INSERT')
             AND has_table_privilege(current_user, 'groups.sequencer_outbox', 'UPDATE')
             AND has_table_privilege(current_user, 'groups.control_commands', 'SELECT')
             AND has_table_privilege(current_user, 'groups.control_commands', 'INSERT')",
    )
    .fetch_one(pool)
    .await?;
    if !authorized {
        return Err(GroupPersistenceError::RuntimeRoleUnauthorized);
    }
    if session_principal_can_escalate_role(pool).await?
        || role_has_cross_scope_access(pool).await?
        || role_has_excess_group_privileges(pool).await?
    {
        return Err(GroupPersistenceError::RuntimeRoleOverprivileged);
    }
    Ok(())
}

async fn session_principal_can_escalate_role(pool: &PgPool) -> Result<bool, GroupPersistenceError> {
    sqlx::query_scalar(
        r"WITH RECURSIVE reachable_role(role_oid) AS (
             SELECT candidate.oid
               FROM pg_roles AS candidate
              WHERE candidate.rolname = session_user
             UNION
             SELECT role_membership.roleid
               FROM pg_auth_members AS role_membership
               JOIN reachable_role AS parent
                 ON parent.role_oid = role_membership.member
         )
         SELECT current_user <> session_user
             OR EXISTS (
                 SELECT 1 FROM reachable_role
                  WHERE role_oid <> (
                      SELECT candidate.oid FROM pg_roles AS candidate
                       WHERE candidate.rolname = session_user
                  )
                    AND role_oid <> to_regrole('dtx_group_runtime')
             )
             OR EXISTS (
                 SELECT 1
                   FROM pg_auth_members AS role_membership
                   JOIN reachable_role AS member_role
                     ON member_role.role_oid = role_membership.member
                  WHERE role_membership.admin_option
             )",
    )
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

async fn role_has_cross_scope_access(pool: &PgPool) -> Result<bool, GroupPersistenceError> {
    sqlx::query_scalar(
        r"SELECT has_schema_privilege(current_user, 'system', 'CREATE')
             OR has_schema_privilege(current_user, 'agent', 'USAGE')
             OR has_schema_privilege(current_user, 'agent', 'CREATE')
             OR has_schema_privilege(current_user, 'identity', 'CREATE')
             OR EXISTS (
                 SELECT 1
                   FROM pg_class AS relation
                   JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                  WHERE namespace.nspname IN ('system', 'agent')
                    AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                    AND (has_table_privilege(current_user, relation.oid, 'SELECT')
                      OR has_table_privilege(current_user, relation.oid, 'INSERT')
                      OR has_table_privilege(current_user, relation.oid, 'UPDATE')
                      OR has_table_privilege(current_user, relation.oid, 'DELETE')
                      OR has_table_privilege(current_user, relation.oid, 'TRUNCATE')
                      OR has_table_privilege(current_user, relation.oid, 'REFERENCES')
                      OR has_table_privilege(current_user, relation.oid, 'TRIGGER')
                      OR has_table_privilege(current_user, relation.oid, 'MAINTAIN'))
             )
             OR EXISTS (
                 SELECT 1
                   FROM pg_class AS relation
                   JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                  WHERE namespace.nspname = 'identity'
                    AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                    AND (
                        (relation.relname NOT IN ('device_sessions', 'log_heads', 'log_entries')
                         AND has_table_privilege(current_user, relation.oid, 'SELECT'))
                        OR has_table_privilege(current_user, relation.oid, 'INSERT')
                        OR has_table_privilege(current_user, relation.oid, 'UPDATE')
                        OR has_table_privilege(current_user, relation.oid, 'DELETE')
                        OR has_table_privilege(current_user, relation.oid, 'TRUNCATE')
                        OR has_table_privilege(current_user, relation.oid, 'REFERENCES')
                        OR has_table_privilege(current_user, relation.oid, 'TRIGGER')
                        OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')
                    )
             )
             OR EXISTS (
                 SELECT 1
                   FROM pg_proc AS procedure
                   JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
                  WHERE namespace.nspname = 'system'
                    AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')
                    AND procedure.oid NOT IN (
                        'system.current_tenant_id()'::regprocedure,
                        'system.is_uuid_v7(uuid)'::regprocedure
                    )
             )
             OR EXISTS (
                 SELECT 1
                   FROM pg_proc AS procedure
                   JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
                  WHERE namespace.nspname = 'identity'
                    AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')
                    AND procedure.oid <> 'identity.identity_group_reader_authorized()'::regprocedure
             )
             OR EXISTS (
                 SELECT 1
                   FROM pg_roles AS candidate
                  WHERE pg_has_role(current_user, candidate.oid, 'MEMBER')
                    AND EXISTS (
                        SELECT 1
                          FROM pg_proc AS procedure
                          JOIN pg_namespace AS namespace
                            ON namespace.oid = procedure.pronamespace
                         WHERE namespace.nspname IN ('system', 'identity')
                           AND procedure.proowner = candidate.oid
                    )
             )",
    )
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

async fn role_has_excess_group_privileges(pool: &PgPool) -> Result<bool, GroupPersistenceError> {
    sqlx::query_scalar(
        r"SELECT has_schema_privilege(current_user, 'groups', 'CREATE')
             OR EXISTS (
                 SELECT 1
                   FROM pg_roles AS candidate
                  WHERE pg_has_role(current_user, candidate.oid, 'MEMBER')
                    AND (candidate.rolsuper OR candidate.rolbypassrls
                      OR candidate.rolcreatedb OR candidate.rolcreaterole
                      OR candidate.rolreplication OR left(candidate.rolname, 3) = 'pg_'
                      OR EXISTS (
                          SELECT 1 FROM pg_database
                           WHERE datname = current_database() AND datdba = candidate.oid
                      )
                      OR EXISTS (
                          SELECT 1 FROM pg_namespace AS namespace
                           WHERE namespace.nspname = 'groups'
                             AND (namespace.nspowner = candidate.oid
                               OR has_schema_privilege(candidate.oid, namespace.oid, 'CREATE'))
                      )
                      OR EXISTS (
                          SELECT 1
                            FROM pg_class AS relation
                            JOIN pg_namespace AS namespace
                              ON namespace.oid = relation.relnamespace
                           WHERE namespace.nspname = 'groups'
                             AND relation.relowner = candidate.oid
                      ))
             )
             OR EXISTS (
                 SELECT 1
                   FROM pg_class AS relation
                   JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                  WHERE namespace.nspname = 'groups'
                    AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                    AND ((relation.relname IN ('policy_heads', 'admin_terms', 'members', 'invites',
                                                'join_records', 'membership_commands',
                                                'membership_workflows', 'sequencer_outbox',
                                                'control_commands')
                          AND (has_table_privilege(current_user, relation.oid, 'DELETE')
                            OR has_table_privilege(current_user, relation.oid, 'TRUNCATE')
                            OR has_table_privilege(current_user, relation.oid, 'REFERENCES')
                            OR has_table_privilege(current_user, relation.oid, 'TRIGGER')
                            OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')
                            OR (relation.relname IN ('members', 'membership_commands',
                                                     'control_commands')
                                AND has_table_privilege(current_user, relation.oid, 'UPDATE'))))
                         OR (relation.relname NOT IN ('policy_heads', 'admin_terms', 'members', 'invites',
                                                     'join_records', 'membership_commands',
                                                     'membership_workflows', 'sequencer_outbox',
                                                     'control_commands')
                             AND (has_table_privilege(current_user, relation.oid, 'SELECT')
                               OR has_table_privilege(current_user, relation.oid, 'INSERT')
                               OR has_table_privilege(current_user, relation.oid, 'UPDATE')
                               OR has_table_privilege(current_user, relation.oid, 'DELETE')
                               OR has_table_privilege(current_user, relation.oid, 'TRUNCATE')
                               OR has_table_privilege(current_user, relation.oid, 'REFERENCES')
                               OR has_table_privilege(current_user, relation.oid, 'TRIGGER')
                               OR has_table_privilege(current_user, relation.oid, 'MAINTAIN'))))
             )",
    )
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}
