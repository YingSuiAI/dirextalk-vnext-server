use std::fmt;

use sqlx::{
    PgConnection, PgPool, Postgres, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use crate::MailboxPersistenceError;

/// Validated non-owner pool for opaque mailbox delivery rows only.
#[derive(Clone)]
pub struct MailboxPgStore {
    pool: PgPool,
}

impl fmt::Debug for MailboxPgStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MailboxPgStore")
            .field("pool", &self.pool)
            .finish()
    }
}

impl MailboxPgStore {
    /// Opens a non-owner mailbox pool after checking that it cannot write
    /// identity state or access unrelated system/agent relations.
    ///
    /// # Errors
    ///
    /// Returns an error for connection failures or an unauthorized/
    /// overprivileged database principal.
    pub async fn connect(
        options: PgConnectOptions,
        max_connections: u32,
    ) -> Result<Self, MailboxPersistenceError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect_with(options)
            .await?;
        validate_mailbox_runtime_role(&pool).await?;
        Ok(Self { pool })
    }

    /// Revalidates the current role and the exact fresh-only schema epoch.
    ///
    /// # Errors
    ///
    /// Returns an error when the database is unavailable, the Mailbox runtime
    /// role is invalid, or the schema epoch differs from the Alpha baseline.
    pub async fn readiness_check(&self) -> Result<bool, MailboxPersistenceError> {
        validate_mailbox_runtime_role(&self.pool).await?;
        dtx_storage::PgStore::readiness_check_schema(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Starts a transaction with no inherited tenant context.
    ///
    /// # Errors
    ///
    /// Returns an error for database failures or a leaked tenant setting.
    pub async fn begin(&self) -> Result<MailboxSession<'_>, MailboxPersistenceError> {
        let mut transaction = self.pool.begin().await?;
        let existing: Option<String> =
            sqlx::query_scalar("SELECT NULLIF(current_setting('dtx.tenant_id', true), '')")
                .fetch_one(&mut *transaction)
                .await?;
        if existing.is_some() {
            transaction.rollback().await?;
            return Err(MailboxPersistenceError::TenantContextLeak);
        }
        Ok(MailboxSession { transaction })
    }
}

/// One non-cloneable opaque-mailbox transaction.
pub struct MailboxSession<'pool> {
    transaction: Transaction<'pool, Postgres>,
}

impl MailboxSession<'_> {
    /// Returns the connection for one mailbox repository operation.
    pub(crate) fn connection(&mut self) -> &mut PgConnection {
        &mut self.transaction
    }

    /// Commits all mailbox operation facts atomically.
    ///
    /// # Errors
    ///
    /// Returns a database error when the commit cannot be persisted.
    pub async fn commit(self) -> Result<(), MailboxPersistenceError> {
        self.transaction.commit().await.map_err(Into::into)
    }

    /// Rolls back an incomplete mailbox operation.
    ///
    /// # Errors
    ///
    /// Returns a database error when rollback cannot complete.
    pub async fn rollback(self) -> Result<(), MailboxPersistenceError> {
        self.transaction.rollback().await.map_err(Into::into)
    }
}

async fn validate_mailbox_runtime_role(pool: &PgPool) -> Result<(), MailboxPersistenceError> {
    let authorized: bool = sqlx::query_scalar(
        r"SELECT messaging.mailbox_runtime_authorized()
             AND has_schema_privilege(current_user, 'messaging', 'USAGE')
             AND has_schema_privilege(current_user, 'identity', 'USAGE')
             AND has_table_privilege(current_user, 'messaging.mailboxes', 'SELECT')
             AND has_table_privilege(current_user, 'messaging.mailboxes', 'INSERT')
             AND has_table_privilege(current_user, 'messaging.mailboxes', 'UPDATE')
             AND has_table_privilege(current_user, 'messaging.mailbox_registration_claims', 'SELECT')
             AND has_table_privilege(current_user, 'messaging.mailbox_registration_claims', 'INSERT')
             AND has_table_privilege(current_user, 'messaging.mailbox_envelopes', 'SELECT')
             AND has_table_privilege(current_user, 'messaging.mailbox_envelopes', 'INSERT')
             AND has_table_privilege(current_user, 'messaging.mailbox_envelopes', 'UPDATE')
             AND has_table_privilege(current_user, 'messaging.mailbox_enqueue_claims', 'SELECT')
             AND has_table_privilege(current_user, 'messaging.mailbox_enqueue_claims', 'INSERT')
             AND has_table_privilege(current_user, 'messaging.mailbox_ack_claims', 'SELECT')
             AND has_table_privilege(current_user, 'messaging.mailbox_ack_claims', 'INSERT')
             AND has_table_privilege(current_user, 'messaging.identity_delivery_heads', 'SELECT,INSERT,UPDATE')
             AND has_table_privilege(current_user, 'messaging.identity_delivery_journal', 'SELECT,INSERT')
             AND has_table_privilege(current_user, 'messaging.device_delivery_state', 'SELECT,INSERT,UPDATE')
             AND has_table_privilege(current_user, 'messaging.device_delivery_ack_claims', 'SELECT,INSERT')
             AND has_table_privilege(current_user, 'messaging.device_history_grants', 'SELECT,INSERT,UPDATE')
             AND has_table_privilege(current_user, 'messaging.history_recovery_offers', 'SELECT,INSERT')
             AND has_table_privilege(current_user, 'messaging.history_recovery_grants_v4', 'SELECT,INSERT')
             AND has_schema_privilege(current_user, 'realtime', 'USAGE')
             AND has_table_privilege(current_user, 'realtime.identity_heads', 'SELECT,INSERT,UPDATE')
             AND has_table_privilege(current_user, 'realtime.journal', 'SELECT,INSERT')
             AND has_table_privilege(current_user, 'realtime.outbox', 'SELECT,INSERT')
             AND has_table_privilege(current_user, 'realtime.encrypted_account_read_cursors', 'SELECT,INSERT,UPDATE')
             AND has_table_privilege(current_user, 'realtime.account_read_cursor_claims', 'SELECT,INSERT')
             AND has_table_privilege(current_user, 'messaging.attachment_objects', 'SELECT')
             AND has_table_privilege(current_user, 'messaging.attachment_objects', 'INSERT')
             AND has_table_privilege(current_user, 'messaging.attachment_objects', 'UPDATE')
             AND has_table_privilege(current_user, 'messaging.attachment_chunks', 'SELECT')
             AND has_table_privilege(current_user, 'messaging.attachment_chunks', 'INSERT')
             AND has_function_privilege(current_user, 'messaging.expire_attachment_objects(integer)'::regprocedure, 'EXECUTE')
             AND has_table_privilege(current_user, 'identity.device_sessions', 'SELECT')
             AND has_table_privilege(current_user, 'identity.log_heads', 'SELECT')
             AND has_table_privilege(current_user, 'identity.log_entries', 'SELECT')
             AND has_table_privilege(current_user, 'identity.device_enrollment_challenges', 'SELECT')
             AND has_table_privilege(current_user, 'identity.history_recovery_requests', 'SELECT')
             AND has_table_privilege(current_user, 'identity.recovery_scope_catalogs', 'SELECT')
             AND has_table_privilege(current_user, 'identity.recovery_scope_catalog_preparations', 'SELECT')
             AND has_function_privilege(
                 current_user,
                 'identity.identity_mailbox_reader_authorized()'::regprocedure,
                 'EXECUTE'
             )
             AND has_function_privilege(
                 current_user,
                 'identity.identity_realtime_reader_authorized()'::regprocedure,
                 'EXECUTE'
             )
             AND has_function_privilege(
                 current_user,
                 'identity.history_recovery_request_authorized(text,uuid,bytea,uuid,bigint)'::regprocedure,
                 'EXECUTE'
             )
             AND has_function_privilege(
                 current_user,
                 'identity.identity_runtime_authorized()'::regprocedure,
                 'EXECUTE'
             )
             AND has_function_privilege(
                 current_user,
                 'identity.identity_owner_authorized()'::regprocedure,
                 'EXECUTE'
             )
             AND has_function_privilege(
                 current_user,
                 'messaging.enqueue_opaque_push_intent(uuid,uuid,uuid)'::regprocedure,
                 'EXECUTE'
             )
             AND has_function_privilege(
                 current_user,
                 'messaging.mailbox_owner_authorized()'::regprocedure,
                 'EXECUTE'
             )",
    )
    .fetch_one(pool)
    .await?;
    if !authorized {
        return Err(MailboxPersistenceError::RuntimeRoleUnauthorized);
    }
    if session_principal_can_escalate_role(pool).await?
        || role_has_cross_scope_access(pool).await?
        || role_has_excess_mailbox_privileges(pool).await?
    {
        return Err(MailboxPersistenceError::RuntimeRoleOverprivileged);
    }
    Ok(())
}

async fn session_principal_can_escalate_role(
    pool: &PgPool,
) -> Result<bool, MailboxPersistenceError> {
    sqlx::query_scalar(
        r"WITH RECURSIVE reachable_role(role_oid) AS (
             SELECT candidate.oid
               FROM pg_roles AS candidate
              WHERE candidate.rolname = session_user
             UNION
             SELECT membership.roleid
               FROM pg_auth_members AS membership
               JOIN reachable_role AS parent ON parent.role_oid = membership.member
         )
         SELECT current_user <> session_user
             OR EXISTS (
                 SELECT 1 FROM reachable_role
                  WHERE role_oid <> (
                      SELECT candidate.oid FROM pg_roles AS candidate
                       WHERE candidate.rolname = session_user
                  )
                    AND role_oid <> to_regrole('dtx_mailbox_runtime')
             )
             OR EXISTS (
                 SELECT 1
                   FROM pg_auth_members AS membership
                   JOIN reachable_role AS member_role
                     ON member_role.role_oid = membership.member
                  WHERE membership.admin_option
             )",
    )
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

async fn role_has_cross_scope_access(pool: &PgPool) -> Result<bool, MailboxPersistenceError> {
    sqlx::query_scalar(
        r"SELECT has_schema_privilege(current_user, 'messaging', 'CREATE')
             OR has_schema_privilege(current_user, 'identity', 'CREATE')
             OR has_schema_privilege(current_user, 'system', 'USAGE')
             OR has_schema_privilege(current_user, 'system', 'CREATE')
             OR has_schema_privilege(current_user, 'agent', 'USAGE')
             OR has_schema_privilege(current_user, 'agent', 'CREATE')
             OR has_schema_privilege(current_user, 'groups', 'USAGE')
             OR has_schema_privilege(current_user, 'groups', 'CREATE')
             OR EXISTS (
                 SELECT 1
                   FROM pg_class AS relation
                   JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                  WHERE namespace.nspname IN ('system', 'agent', 'groups')
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
                  WHERE namespace.nspname = 'identity'
                    AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')
                    AND procedure.oid NOT IN (
                        'identity.identity_runtime_authorized()'::regprocedure,
                        'identity.identity_owner_authorized()'::regprocedure,
                        'identity.identity_mailbox_reader_authorized()'::regprocedure,
                        'identity.identity_realtime_reader_authorized()'::regprocedure,
                        'identity.history_recovery_request_authorized(text,uuid,bytea,uuid,bigint)'::regprocedure
                    )
             )
             OR EXISTS (
                 SELECT 1
                   FROM pg_proc AS procedure
                   JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
                  WHERE namespace.nspname = 'messaging'
                    AND has_function_privilege(current_user, procedure.oid, 'EXECUTE')
                    AND procedure.oid NOT IN (
                        'messaging.mailbox_runtime_authorized()'::regprocedure,
                        'messaging.mailbox_owner_authorized()'::regprocedure,
                        'messaging.is_uuid_v7(uuid)'::regprocedure,
                        'messaging.expire_attachment_objects(integer)'::regprocedure,
                        'messaging.enqueue_opaque_push_intent(uuid,uuid,uuid)'::regprocedure
                    )
             )",
    )
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

async fn role_has_excess_mailbox_privileges(
    pool: &PgPool,
) -> Result<bool, MailboxPersistenceError> {
    sqlx::query_scalar(
        r"SELECT EXISTS (
             SELECT 1
               FROM pg_class AS relation
               JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
              WHERE namespace.nspname = 'messaging'
                AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
                AND (
                    has_table_privilege(current_user, relation.oid, 'DELETE')
                    OR has_table_privilege(current_user, relation.oid, 'TRUNCATE')
                    OR has_table_privilege(current_user, relation.oid, 'REFERENCES')
                    OR has_table_privilege(current_user, relation.oid, 'TRIGGER')
                    OR has_table_privilege(current_user, relation.oid, 'MAINTAIN')
                    OR (relation.relname IN (
                         'mailbox_registration_claims',
                         'mailbox_enqueue_claims',
                         'mailbox_ack_claims'
                    ) AND has_table_privilege(current_user, relation.oid, 'UPDATE'))
                )
         )",
    )
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}
