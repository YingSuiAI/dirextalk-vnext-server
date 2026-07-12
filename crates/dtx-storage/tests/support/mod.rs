#![allow(
    dead_code,
    reason = "the shared integration-test harness exposes different helpers to each test binary"
)]

use std::error::Error;

use sqlx::{
    PgPool, Postgres as SqlxPostgres, Transaction,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ContainerAsync, ImageExt, core::WaitFor, runners::AsyncRunner},
};
use uuid::Uuid;

use dtx_storage::MigrationRunner;

const ADMIN_USER: &str = "dtx_test_admin";
const DATABASE: &str = "dtx_test";
const RUNTIME_USER: &str = "dtx_runtime_test";
const POSTGRES_TAG: &str = "18.4-alpine3.24";

pub struct PostgresHarness {
    admin_pool: PgPool,
    runtime_pool: PgPool,
    runtime_options: PgConnectOptions,
    _container: ContainerAsync<Postgres>,
}

impl PostgresHarness {
    pub async fn start() -> Result<Self, Box<dyn Error>> {
        let admin_password = random_password("admin");
        let runtime_password = random_password("runtime");
        let container = Postgres::default()
            .with_db_name(DATABASE)
            .with_user(ADMIN_USER)
            .with_password(&admin_password)
            .with_tag(POSTGRES_TAG)
            // The module waits for the same startup message on both stderr and
            // stdout. PostgreSQL 18 emits it on stderr only, so override that
            // inherited condition instead of paying the stdout timeout.
            .with_ready_conditions(vec![WaitFor::message_on_stderr(
                "database system is ready to accept connections",
            )])
            .start()
            .await?;
        let host = container.get_host().await?.to_string();
        let port = container.get_host_port_ipv4(5432).await?;

        let admin_pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(connect_options(&host, port, ADMIN_USER, &admin_password))
            .await?;
        MigrationRunner::new().run(&admin_pool).await?;

        let mut role_transaction = admin_pool.begin().await?;
        sqlx::query("SELECT set_config('dtx.test_runtime_password', $1, true)")
            .bind(&runtime_password)
            .execute(&mut *role_transaction)
            .await?;
        sqlx::raw_sql(
            "DO $role$
             BEGIN
                 EXECUTE format(
                     'CREATE ROLE dtx_runtime_test LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
                     current_setting('dtx.test_runtime_password')
                 );
             END
             $role$;
             GRANT USAGE ON SCHEMA system TO dtx_runtime_test;
             GRANT EXECUTE ON FUNCTION system.current_tenant_id() TO dtx_runtime_test;
             GRANT EXECUTE ON FUNCTION system.is_uuid_v7(uuid) TO dtx_runtime_test;
             GRANT EXECUTE ON FUNCTION system.is_stable_code(text, integer) TO dtx_runtime_test;
             GRANT EXECUTE ON FUNCTION system.enforce_completed_inbox() TO dtx_runtime_test;
             GRANT EXECUTE ON FUNCTION system.enforce_inbox_transition() TO dtx_runtime_test;
             GRANT SELECT ON system.schema_versions TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON system.tenant_stream_heads TO dtx_runtime_test;
             GRANT SELECT, INSERT ON system.durable_events TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON system.outbox_events TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON system.inbox_dedup TO dtx_runtime_test;
             GRANT SELECT, INSERT ON system.audit_events TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON system.projection_cursors TO dtx_runtime_test;",
        )
        .execute(&mut *role_transaction)
        .await?;
        role_transaction.commit().await?;

        let runtime_options = connect_options(&host, port, RUNTIME_USER, &runtime_password);
        let runtime_pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(runtime_options.clone())
            .await?;

        Ok(Self {
            admin_pool,
            runtime_pool,
            runtime_options,
            _container: container,
        })
    }

    pub fn admin_pool(&self) -> &PgPool {
        &self.admin_pool
    }

    pub fn runtime_pool(&self) -> &PgPool {
        &self.runtime_pool
    }

    pub fn runtime_options(&self) -> PgConnectOptions {
        self.runtime_options.clone()
    }

    pub async fn runtime_store(
        &self,
        max_connections: u32,
    ) -> Result<dtx_storage::PgStore, dtx_storage::StorageError> {
        dtx_storage::PgStore::connect(self.runtime_options(), max_connections).await
    }

    pub async fn set_tenant(
        transaction: &mut Transaction<'_, SqlxPostgres>,
        tenant_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('dtx.tenant_id', $1, true)")
            .bind(tenant_id.to_string())
            .execute(&mut **transaction)
            .await?;
        Ok(())
    }
}

fn random_password(label: &str) -> String {
    format!("dtx-{label}-{}", Uuid::now_v7().simple())
}

fn connect_options(host: &str, port: u16, user: &str, password: &str) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(host)
        .port(port)
        .username(user)
        .password(password)
        .database(DATABASE)
}
