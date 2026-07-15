#![allow(
    dead_code,
    reason = "the shared integration-test harness exposes different helpers to each test binary"
)]

use std::{env, error::Error, io, net::IpAddr};

use sqlx::{
    Connection, PgConnection, PgPool, Postgres as SqlxPostgres, Transaction,
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
const IDENTITY_RUNTIME_USER: &str = "dtx_identity_only_test";
const GROUP_RUNTIME_USER: &str = "dtx_group_only_test";
const MAILBOX_RUNTIME_USER: &str = "dtx_mailbox_only_test";
const POSTGRES_TAG: &str = "18.4-alpine3.24";
const LOCAL_POSTGRES_MODE_ENV: &str = "DTX_TEST_LOCAL_POSTGRES";
const LOCAL_POSTGRES_HOST_ENV: &str = "DTX_TEST_LOCAL_POSTGRES_HOST";
const LOCAL_POSTGRES_PORT_ENV: &str = "DTX_TEST_LOCAL_POSTGRES_PORT";
const LOCAL_POSTGRES_USER_ENV: &str = "DTX_TEST_LOCAL_POSTGRES_USER";
const LOCAL_POSTGRES_PASSWORD_ENV: &str = "DTX_TEST_LOCAL_POSTGRES_PASSWORD";
const LOCAL_POSTGRES_MAINTENANCE_DATABASE_ENV: &str =
    "DTX_TEST_LOCAL_POSTGRES_MAINTENANCE_DATABASE";
const LOCAL_HARNESS_LOCK: &str =
    "SELECT pg_advisory_lock(hashtext('dirextalk-vnext-local-postgres-harness'))";
const LOCAL_HARNESS_UNLOCK: &str =
    "SELECT pg_advisory_unlock(hashtext('dirextalk-vnext-local-postgres-harness'))";

#[derive(Clone)]
struct LocalPostgresConfig {
    host: String,
    port: u16,
    user: String,
    password: String,
    maintenance_database: String,
}

impl LocalPostgresConfig {
    fn maintenance_options(&self) -> PgConnectOptions {
        connect_options(
            &self.host,
            self.port,
            &self.user,
            &self.password,
            &self.maintenance_database,
        )
    }
}

struct LocalPostgresDatabase {
    database_name: String,
    config: LocalPostgresConfig,
    maintenance_connection: PgConnection,
}

impl LocalPostgresDatabase {
    async fn create(config: &LocalPostgresConfig) -> Result<Self, Box<dyn Error>> {
        let mut maintenance_connection =
            PgConnection::connect_with(&config.maintenance_options()).await?;
        sqlx::query(LOCAL_HARNESS_LOCK)
            .execute(&mut maintenance_connection)
            .await?;

        let database_name = format!("dtx_test_{}", Uuid::now_v7().simple());
        let create_database = format!("CREATE DATABASE {database_name}");
        if let Err(error) = sqlx::raw_sql(sqlx::AssertSqlSafe(create_database))
            .execute(&mut maintenance_connection)
            .await
        {
            let _ = sqlx::query(LOCAL_HARNESS_UNLOCK)
                .execute(&mut maintenance_connection)
                .await;
            return Err(Box::new(error));
        }

        Ok(Self {
            database_name,
            config: config.clone(),
            maintenance_connection,
        })
    }
}

struct LocalPostgresCleanup {
    database_name: String,
    config: LocalPostgresConfig,
}

impl LocalPostgresDatabase {
    fn into_cleanup(self) -> LocalPostgresCleanup {
        let Self {
            database_name,
            config,
            maintenance_connection,
        } = self;
        // The session-scoped advisory lock deliberately covers only the test
        // body. Dropping this connection on the owning runtime releases it;
        // moving a live SQLx connection to Drop's fresh runtime can strand the
        // lock after the database itself has already been removed.
        drop(maintenance_connection);
        LocalPostgresCleanup {
            database_name,
            config,
        }
    }
}

impl LocalPostgresCleanup {
    async fn cleanup(self) -> Result<(), sqlx::Error> {
        // The name is generated from UUIDv7 and contains only a fixed prefix and
        // hexadecimal characters, so it is safe to use as a SQL identifier.
        let drop_database = format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            self.database_name
        );
        let mut maintenance_connection =
            PgConnection::connect_with(&self.config.maintenance_options()).await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(drop_database))
            .execute(&mut maintenance_connection)
            .await
            .map(|_| ())
    }
}

pub struct PostgresHarness {
    admin_pool: PgPool,
    runtime_pool: PgPool,
    runtime_options: PgConnectOptions,
    identity_runtime_pool: PgPool,
    identity_runtime_options: PgConnectOptions,
    group_runtime_pool: PgPool,
    group_runtime_options: PgConnectOptions,
    mailbox_runtime_pool: PgPool,
    mailbox_runtime_options: PgConnectOptions,
    _container: Option<ContainerAsync<Postgres>>,
    local_database: Option<LocalPostgresDatabase>,
}

impl PostgresHarness {
    #[allow(clippy::too_many_lines)]
    pub async fn start() -> Result<Self, Box<dyn Error>> {
        let runtime_password = random_password("runtime");
        let identity_runtime_password = random_password("identity-runtime");
        let group_runtime_password = random_password("group-runtime");
        let mailbox_runtime_password = random_password("mailbox-runtime");
        let local_config = local_postgres_config_from_env()?;
        let mut local_database = match local_config.as_ref() {
            Some(config) => Some(LocalPostgresDatabase::create(config).await?),
            None => None,
        };
        let mut container = None;
        let (host, port, admin_user, admin_password, database) =
            if let Some(config) = local_config.as_ref() {
                (
                    config.host.clone(),
                    config.port,
                    config.user.clone(),
                    config.password.clone(),
                    local_database
                        .as_ref()
                        .expect("local database is created with local configuration")
                        .database_name
                        .clone(),
                )
            } else {
                let admin_password = random_password("admin");
                let container_instance = Postgres::default()
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
                let host = container_instance.get_host().await?.to_string();
                let port = container_instance.get_host_port_ipv4(5432).await?;
                container = Some(container_instance);
                (
                    host,
                    port,
                    ADMIN_USER.to_owned(),
                    admin_password,
                    DATABASE.to_owned(),
                )
            };

        let setup = async {
            let admin_pool = PgPoolOptions::new()
                .max_connections(4)
                .connect_with(connect_options(
                    &host,
                    port,
                    &admin_user,
                    &admin_password,
                    &database,
                ))
                .await?;
            MigrationRunner::new().run(&admin_pool).await?;

            let mut role_transaction = admin_pool.begin().await?;
        sqlx::query(
            "SELECT set_config('dtx.test_runtime_password', $1, true), \
                    set_config('dtx.test_identity_runtime_password', $2, true), \
                    set_config('dtx.test_group_runtime_password', $3, true), \
                    set_config('dtx.test_mailbox_runtime_password', $4, true)",
        )
        .bind(&runtime_password)
        .bind(&identity_runtime_password)
        .bind(&group_runtime_password)
        .bind(&mailbox_runtime_password)
        .execute(&mut *role_transaction)
        .await?;
        sqlx::raw_sql(
             "DO $role$
              BEGIN
                  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dtx_runtime_test') THEN
                      EXECUTE format(
                          'CREATE ROLE dtx_runtime_test LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
                          current_setting('dtx.test_runtime_password')
                      );
                  ELSE
                      EXECUTE format(
                          'ALTER ROLE dtx_runtime_test LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
                          current_setting('dtx.test_runtime_password')
                      );
                  END IF;
                  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dtx_identity_only_test') THEN
                      EXECUTE format(
                          'CREATE ROLE dtx_identity_only_test LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
                          current_setting('dtx.test_identity_runtime_password')
                      );
                  ELSE
                      EXECUTE format(
                          'ALTER ROLE dtx_identity_only_test LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
                          current_setting('dtx.test_identity_runtime_password')
                      );
                  END IF;
                  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dtx_group_only_test') THEN
                      EXECUTE format(
                          'CREATE ROLE dtx_group_only_test LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
                          current_setting('dtx.test_group_runtime_password')
                      );
                  ELSE
                      EXECUTE format(
                          'ALTER ROLE dtx_group_only_test LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
                          current_setting('dtx.test_group_runtime_password')
                      );
                  END IF;
                  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dtx_mailbox_only_test') THEN
                      EXECUTE format(
                          'CREATE ROLE dtx_mailbox_only_test LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
                          current_setting('dtx.test_mailbox_runtime_password')
                      );
                  ELSE
                      EXECUTE format(
                          'ALTER ROLE dtx_mailbox_only_test LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION',
                          current_setting('dtx.test_mailbox_runtime_password')
                      );
                  END IF;
                  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dtx_identity_runtime') THEN
                      CREATE ROLE dtx_identity_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
                  ELSE
                      ALTER ROLE dtx_identity_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
                  END IF;
                  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dtx_group_runtime') THEN
                      CREATE ROLE dtx_group_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
                  ELSE
                      ALTER ROLE dtx_group_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
                  END IF;
                  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dtx_mailbox_runtime') THEN
                      CREATE ROLE dtx_mailbox_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
                  ELSE
                      ALTER ROLE dtx_mailbox_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;
                  END IF;
                  REVOKE dtx_identity_runtime FROM dtx_runtime_test;
                  REVOKE dtx_identity_runtime FROM dtx_identity_only_test;
                  REVOKE dtx_group_runtime FROM dtx_group_only_test;
                  REVOKE dtx_identity_runtime FROM dtx_mailbox_runtime;
                  REVOKE dtx_group_runtime FROM dtx_mailbox_runtime;
                  REVOKE dtx_mailbox_runtime FROM dtx_runtime_test;
                  REVOKE dtx_mailbox_runtime FROM dtx_identity_only_test;
                  REVOKE dtx_mailbox_runtime FROM dtx_group_only_test;
                  REVOKE dtx_mailbox_runtime FROM dtx_mailbox_only_test;
                  REVOKE pg_read_server_files FROM dtx_runtime_test;
                  GRANT dtx_identity_runtime TO dtx_runtime_test;
                  GRANT dtx_identity_runtime TO dtx_identity_only_test;
                  GRANT dtx_group_runtime TO dtx_group_only_test;
                  GRANT dtx_mailbox_runtime TO dtx_mailbox_only_test;
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
             GRANT SELECT, INSERT, UPDATE ON system.projection_cursors TO dtx_runtime_test;

             GRANT USAGE ON SCHEMA agent TO dtx_runtime_test;
             GRANT EXECUTE ON FUNCTION agent.is_public_id(text, text) TO dtx_runtime_test;
             GRANT EXECUTE ON FUNCTION agent.connector_certificate_chain_valid(bytea[]) TO dtx_runtime_test;
             GRANT EXECUTE ON FUNCTION agent.connector_runtime_name_valid(text, integer) TO dtx_runtime_test;
             GRANT EXECUTE ON FUNCTION agent.connector_claim_codes_valid(text[]) TO dtx_runtime_test;
             GRANT EXECUTE ON FUNCTION agent.connector_run_ids_valid(uuid[]) TO dtx_runtime_test;
             GRANT EXECUTE ON FUNCTION agent.connector_runtime_error_code_valid(text) TO dtx_runtime_test;
             GRANT EXECUTE ON FUNCTION agent.prune_connector_runtime_claim_history(uuid, uuid, integer) TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.agent_definition_heads TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.agent_definitions TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.installations TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.agent_devices TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.hosts TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.host_credentials TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.host_provisioning_operations TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.host_credential_authorization_credentials TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.host_credential_authorization_revisions TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.host_credential_authorization_states TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.host_credential_authorization_heads TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.connector_control_operations TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.connector_enrollment_intents TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.connector_control_credentials TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.connector_control_credential_revisions TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.connector_control_credential_rotations TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.connector_control_credential_heads TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.connector_runtime_claims TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.connector_runtime_claim_heads TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.connector_control_stream_heads TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.connector_control_commands TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.connector_instances TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.connector_revisions TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.connector_boots TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.connector_leases TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.connector_conformance TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.binding_set_heads TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.installation_routing_policies TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.connector_bindings TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.conversation_grant_ids TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.conversation_grant_versions TO dtx_runtime_test;
             GRANT SELECT, INSERT, UPDATE ON agent.conversation_grant_heads TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.conversation_grant_permissions TO dtx_runtime_test;
             GRANT SELECT, INSERT ON agent.conversation_grant_cloud_connections TO dtx_runtime_test;

             GRANT USAGE ON SCHEMA identity TO dtx_identity_runtime;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA identity TO dtx_identity_runtime;
             GRANT SELECT, INSERT, UPDATE ON identity.log_heads TO dtx_identity_runtime;
             GRANT SELECT, INSERT ON identity.log_entries TO dtx_identity_runtime;
             GRANT SELECT, INSERT, UPDATE ON identity.command_receipts TO dtx_identity_runtime;
             GRANT SELECT, INSERT ON identity.bootstrap_idempotency_claims TO dtx_identity_runtime;
             GRANT SELECT, INSERT, UPDATE ON identity.device_session_challenges TO dtx_identity_runtime;
             GRANT SELECT, INSERT ON identity.device_sessions TO dtx_identity_runtime;
             GRANT SELECT, INSERT ON identity.device_session_idempotency_claims TO dtx_identity_runtime;
             GRANT SELECT, INSERT ON identity.device_session_receipts TO dtx_identity_runtime;
             GRANT EXECUTE ON FUNCTION identity.prune_expired_device_sessions(bigint, integer)
                TO dtx_identity_runtime;
             GRANT SELECT, INSERT, UPDATE ON identity.device_enrollment_challenges
                TO dtx_identity_runtime;
             GRANT EXECUTE ON FUNCTION identity.prune_expired_device_enrollment_challenges(bigint, integer)
                TO dtx_identity_runtime;
             GRANT SELECT, INSERT, UPDATE ON identity.key_packages TO dtx_identity_runtime;
             GRANT SELECT, INSERT ON identity.key_package_publish_claims TO dtx_identity_runtime;
             GRANT SELECT, INSERT ON identity.key_package_claims TO dtx_identity_runtime;
             GRANT SELECT, INSERT ON identity.key_package_claim_receipts TO dtx_identity_runtime;
             GRANT EXECUTE ON FUNCTION identity.prune_expired_key_packages(bigint, integer)
                TO dtx_identity_runtime;
             GRANT SELECT, INSERT ON identity.fork_evidence TO dtx_identity_runtime;
              GRANT SELECT, INSERT ON identity.log_outbox TO dtx_identity_runtime;

             GRANT USAGE ON SCHEMA system TO dtx_group_runtime;
             GRANT EXECUTE ON FUNCTION system.current_tenant_id() TO dtx_group_runtime;
             GRANT EXECUTE ON FUNCTION system.is_uuid_v7(uuid) TO dtx_group_runtime;
             GRANT USAGE ON SCHEMA groups TO dtx_group_runtime;
             GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA groups TO dtx_group_runtime;
             GRANT SELECT, INSERT, UPDATE ON groups.policy_heads TO dtx_group_runtime;
             GRANT SELECT, INSERT, UPDATE ON groups.admin_terms TO dtx_group_runtime;
             GRANT SELECT, INSERT ON groups.members TO dtx_group_runtime;
             GRANT SELECT, INSERT, UPDATE ON groups.invites TO dtx_group_runtime;
             GRANT SELECT, INSERT, UPDATE ON groups.join_records TO dtx_group_runtime;
             GRANT SELECT, INSERT ON groups.membership_commands TO dtx_group_runtime;
             GRANT SELECT, INSERT, UPDATE ON groups.membership_workflows TO dtx_group_runtime;
             GRANT SELECT, INSERT, UPDATE ON groups.sequencer_outbox TO dtx_group_runtime;
             GRANT SELECT, INSERT ON groups.control_commands TO dtx_group_runtime;
             GRANT SELECT, INSERT, UPDATE ON groups.mls_heads TO dtx_group_runtime;
             GRANT SELECT, INSERT ON groups.mls_commit_intents TO dtx_group_runtime;
             GRANT SELECT, INSERT ON groups.mls_commit_receipts TO dtx_group_runtime;
             GRANT SELECT, INSERT ON groups.mls_sequencer_outbox TO dtx_group_runtime;
             GRANT SELECT, INSERT, UPDATE ON groups.mls_device_members TO dtx_group_runtime;
             GRANT SELECT, INSERT ON groups.mls_join_confirmations TO dtx_group_runtime;
             GRANT USAGE ON SCHEMA identity TO dtx_group_runtime;
             GRANT EXECUTE ON FUNCTION identity.identity_group_reader_authorized()
                TO dtx_group_runtime;
             GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
                TO dtx_group_runtime;

             GRANT USAGE ON SCHEMA messaging, identity TO dtx_mailbox_runtime;
             GRANT EXECUTE ON FUNCTION messaging.mailbox_runtime_authorized() TO dtx_mailbox_runtime;
             GRANT EXECUTE ON FUNCTION messaging.mailbox_owner_authorized() TO dtx_mailbox_runtime;
             GRANT EXECUTE ON FUNCTION messaging.is_uuid_v7(uuid) TO dtx_mailbox_runtime;
             GRANT EXECUTE ON FUNCTION identity.identity_runtime_authorized()
                TO dtx_mailbox_runtime;
             GRANT EXECUTE ON FUNCTION identity.identity_owner_authorized()
                TO dtx_mailbox_runtime;
             GRANT EXECUTE ON FUNCTION identity.identity_mailbox_reader_authorized()
                TO dtx_mailbox_runtime;
             GRANT SELECT, INSERT, UPDATE ON messaging.mailboxes TO dtx_mailbox_runtime;
             GRANT SELECT, INSERT ON messaging.mailbox_registration_claims TO dtx_mailbox_runtime;
             GRANT SELECT, INSERT, UPDATE ON messaging.mailbox_envelopes TO dtx_mailbox_runtime;
             GRANT SELECT, INSERT ON messaging.mailbox_enqueue_claims TO dtx_mailbox_runtime;
             GRANT SELECT, INSERT ON messaging.mailbox_ack_claims TO dtx_mailbox_runtime;
             GRANT SELECT ON identity.device_sessions, identity.log_heads, identity.log_entries
                TO dtx_mailbox_runtime;",
        )
        .execute(&mut *role_transaction)
        .await?;
            role_transaction.commit().await?;

            let runtime_options = connect_options(
                &host,
                port,
                RUNTIME_USER,
                &runtime_password,
                &database,
            );
            let runtime_pool = PgPoolOptions::new()
                .max_connections(4)
                .connect_with(runtime_options.clone())
                .await?;
            let identity_runtime_options = connect_options(
                &host,
                port,
                IDENTITY_RUNTIME_USER,
                &identity_runtime_password,
                &database,
            );
            let identity_runtime_pool = PgPoolOptions::new()
                .max_connections(4)
                .connect_with(identity_runtime_options.clone())
                .await?;
            let group_runtime_options = connect_options(
                &host,
                port,
                GROUP_RUNTIME_USER,
                &group_runtime_password,
                &database,
            );
            let group_runtime_pool = PgPoolOptions::new()
                .max_connections(4)
                .connect_with(group_runtime_options.clone())
                .await?;
            let mailbox_runtime_options = connect_options(
                &host,
                port,
                MAILBOX_RUNTIME_USER,
                &mailbox_runtime_password,
                &database,
            );
            let mailbox_runtime_pool = PgPoolOptions::new()
                .max_connections(4)
                .connect_with(mailbox_runtime_options.clone())
                .await?;

            Ok::<Self, Box<dyn Error>>(Self {
                admin_pool,
                runtime_pool,
                runtime_options,
                identity_runtime_pool,
                identity_runtime_options,
                group_runtime_pool,
                group_runtime_options,
                mailbox_runtime_pool,
                mailbox_runtime_options,
                _container: container,
                local_database: local_database.take(),
            })
        }
        .await;

        match setup {
            Ok(harness) => Ok(harness),
            Err(error) => {
                if let Some(local_database) = local_database.take() {
                    let _ = local_database.into_cleanup().cleanup().await;
                }
                Err(error)
            }
        }
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

    pub fn identity_runtime_pool(&self) -> &PgPool {
        &self.identity_runtime_pool
    }

    pub fn identity_runtime_options(&self) -> PgConnectOptions {
        self.identity_runtime_options.clone()
    }

    pub fn group_runtime_pool(&self) -> &PgPool {
        &self.group_runtime_pool
    }

    pub fn group_runtime_options(&self) -> PgConnectOptions {
        self.group_runtime_options.clone()
    }

    pub fn mailbox_runtime_pool(&self) -> &PgPool {
        &self.mailbox_runtime_pool
    }

    pub fn mailbox_runtime_options(&self) -> PgConnectOptions {
        self.mailbox_runtime_options.clone()
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

impl Drop for PostgresHarness {
    fn drop(&mut self) {
        let Some(local_database) = self.local_database.take() else {
            return;
        };
        let cleanup = local_database.into_cleanup();

        // `Drop` cannot await. The fresh connection is intentionally created
        // inside this thread; the original lock connection was dropped above on
        // its owning runtime. `WITH (FORCE)` safely disconnects target-database
        // pools before removal, while joining prevents generated databases from
        // accumulating between tests.
        let cleanup_thread = std::thread::Builder::new()
            .name("dtx-local-postgres-cleanup".to_owned())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let _ = cleanup.cleanup().await;
                });
            });
        if let Ok(cleanup_thread) = cleanup_thread {
            let _ = cleanup_thread.join();
        }
    }
}

fn local_postgres_config_from_env() -> Result<Option<LocalPostgresConfig>, Box<dyn Error>> {
    let enabled = match env::var(LOCAL_POSTGRES_MODE_ENV) {
        Err(env::VarError::NotPresent) => return Ok(None),
        Err(error) => return Err(Box::new(error)),
        Ok(value) => value,
    };
    if enabled != "1" {
        return Err(local_config_error(format!(
            "{LOCAL_POSTGRES_MODE_ENV} must be unset or exactly 1"
        )));
    }

    let host_text = required_nonempty_local_env(LOCAL_POSTGRES_HOST_ENV)?;
    let host = host_text.parse::<IpAddr>().map_err(|_| {
        local_config_error(format!(
            "{LOCAL_POSTGRES_HOST_ENV} must be a literal loopback IP address"
        ))
    })?;
    if !host.is_loopback() {
        return Err(local_config_error(format!(
            "{LOCAL_POSTGRES_HOST_ENV} must be a loopback IP address"
        )));
    }

    let port_text = required_nonempty_local_env(LOCAL_POSTGRES_PORT_ENV)?;
    let port = port_text.parse::<u16>().map_err(|_| {
        local_config_error(format!(
            "{LOCAL_POSTGRES_PORT_ENV} must be a valid TCP port"
        ))
    })?;
    if port == 0 {
        return Err(local_config_error(format!(
            "{LOCAL_POSTGRES_PORT_ENV} must not be zero"
        )));
    }

    Ok(Some(LocalPostgresConfig {
        host: host.to_string(),
        port,
        user: required_nonempty_local_env(LOCAL_POSTGRES_USER_ENV)?,
        password: required_local_env(LOCAL_POSTGRES_PASSWORD_ENV)?,
        maintenance_database: required_nonempty_local_env(LOCAL_POSTGRES_MAINTENANCE_DATABASE_ENV)?,
    }))
}

fn required_local_env(name: &'static str) -> Result<String, Box<dyn Error>> {
    env::var(name).map_err(|_| local_config_error(format!("{name} must be set in local mode")))
}

fn required_nonempty_local_env(name: &'static str) -> Result<String, Box<dyn Error>> {
    let value = required_local_env(name)?;
    if value.is_empty() {
        return Err(local_config_error(format!(
            "{name} must not be empty in local mode"
        )));
    }
    Ok(value)
}

fn local_config_error(message: String) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn random_password(label: &str) -> String {
    format!("dtx-{label}-{}", Uuid::now_v7().simple())
}

fn connect_options(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    database: &str,
) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(host)
        .port(port)
        .username(user)
        .password(password)
        .database(database)
}
