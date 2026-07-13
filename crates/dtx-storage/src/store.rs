use std::fmt;

use dtx_domain::TenantId;
use sqlx::{
    PgConnection, PgPool, Postgres, Transaction,
    postgres::{PgConnectOptions, PgListener, PgPoolOptions},
};

use crate::StorageError;

/// Validated runtime `PostgreSQL` pool whose credentials cannot bypass RLS.
#[derive(Clone)]
pub struct PgStore {
    pool: PgPool,
    listener_options: PgConnectOptions,
}

impl fmt::Debug for PgStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PgStore")
            .field("pool", &self.pool)
            .field("listener_options", &"[REDACTED CONNECTION OPTIONS]")
            .finish()
    }
}

impl PgStore {
    /// Opens a bounded runtime pool and rejects privileged or table-owning roles.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if connection or runtime-role validation fails.
    pub async fn connect(
        options: PgConnectOptions,
        max_connections: u32,
    ) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections.max(1))
            .connect_with(options.clone())
            .await?;
        validate_runtime_role(&pool).await?;
        Ok(Self {
            pool,
            listener_options: options,
        })
    }

    /// Opens a dedicated auto-reconnecting `PostgreSQL` notification listener.
    ///
    /// The listener owns a separate single-connection pool so a long-lived
    /// `LISTEN` cannot consume one of the bounded request/transaction slots.
    /// It uses the same already-validated runtime role and never exposes its
    /// connection options to application code.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] when the dedicated connection cannot be opened
    /// or the configured role no longer satisfies the runtime-role boundary.
    pub async fn connect_listener(&self) -> Result<PgListener, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .max_lifetime(None)
            .idle_timeout(None)
            .connect_with(self.listener_options.clone())
            .await?;
        validate_runtime_role(&pool).await?;
        PgListener::connect_with(&pool)
            .await
            .map_err(StorageError::from)
    }

    /// Starts a transaction and binds its RLS context to one authenticated tenant.
    ///
    /// Transaction-local `set_config` is used so a pooled connection cannot retain
    /// the tenant after commit or rollback.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::TenantContextLeak`] if a borrowed connection already
    /// has context, otherwise returns a database error.
    pub async fn begin_tenant(
        &self,
        tenant_id: TenantId,
    ) -> Result<TenantSession<'_>, StorageError> {
        let mut transaction = self.pool.begin().await?;
        let existing: Option<String> =
            sqlx::query_scalar("SELECT NULLIF(current_setting('dtx.tenant_id', true), '')")
                .fetch_one(&mut *transaction)
                .await?;
        if existing.is_some() {
            transaction.rollback().await?;
            return Err(StorageError::TenantContextLeak);
        }
        sqlx::query("SELECT set_config('dtx.tenant_id', $1, true)")
            .bind(tenant_id.to_string())
            .execute(&mut *transaction)
            .await?;
        Ok(TenantSession {
            tenant_id,
            transaction,
        })
    }
}

async fn validate_runtime_role(pool: &PgPool) -> Result<(), StorageError> {
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
                     WHERE namespace.nspname IN ('system', 'agent') \
                       AND (namespace.nspowner = candidate.oid \
                         OR has_schema_privilege(candidate.oid, namespace.oid, 'CREATE'))\
                 ) OR EXISTS (\
                     SELECT 1 FROM pg_class AS relation \
                     JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace \
                     WHERE namespace.nspname IN ('system', 'agent') \
                       AND relation.relowner = candidate.oid\
                 ) OR EXISTS (\
                     SELECT 1 FROM pg_proc AS procedure \
                     JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace \
                     WHERE namespace.nspname IN ('system', 'agent') \
                       AND procedure.proowner = candidate.oid\
                 ) OR EXISTS (\
                     SELECT 1 FROM pg_type AS data_type \
                     JOIN pg_namespace AS namespace ON namespace.oid = data_type.typnamespace \
                     WHERE namespace.nspname IN ('system', 'agent') \
                       AND data_type.typowner = candidate.oid\
                 ))\
         )",
    )
    .fetch_one(pool)
    .await?;
    if unsafe_role {
        Err(StorageError::UnsafeRuntimeRole)
    } else {
        Ok(())
    }
}

/// Non-cloneable tenant-scoped `PostgreSQL` transaction.
pub struct TenantSession<'pool> {
    tenant_id: TenantId,
    transaction: Transaction<'pool, Postgres>,
}

impl TenantSession<'_> {
    /// Returns the authenticated tenant bound to this transaction.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Gives a concrete repository access to the already tenant-bound connection.
    ///
    /// Repositories must use static SQL and may not change `dtx.tenant_id`.
    pub fn connection(&mut self) -> &mut PgConnection {
        &mut self.transaction
    }

    /// Commits a tenant-scoped transaction that is not an open command session.
    ///
    /// # Errors
    ///
    /// Returns a database error, including deferred invariant violations.
    pub async fn commit(self) -> Result<(), StorageError> {
        self.transaction.commit().await.map_err(StorageError::from)
    }

    /// Explicitly rolls back the transaction.
    ///
    /// # Errors
    ///
    /// Returns a database error if rollback itself fails.
    pub async fn rollback(self) -> Result<(), StorageError> {
        self.transaction
            .rollback()
            .await
            .map_err(StorageError::from)
    }
}
