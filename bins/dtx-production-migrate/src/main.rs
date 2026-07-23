#![forbid(unsafe_code)]

//! Explicit production database boundary.
//!
//! This binary is intentionally separate from the four long-running release
//! binaries.  It accepts only URL *files*, has a closed operation set, and
//! never prints connection strings or role credentials.

use std::{
    env, fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::ExitCode,
    str::FromStr,
};

use dtx_storage::MigrationRunner;
use sqlx::{
    AssertSqlSafe, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use zeroize::Zeroizing;

const DATABASE_URL_FILE_ENV: &str = "DTX_DATABASE_URL_FILE";
const ADMIN_DATABASE_URL_FILE_ENV: &str = "DTX_ADMIN_DATABASE_URL_FILE";
const ROLE_PASSWORD_DIR: &str = "/run/dtx-production/role-passwords";
const MAX_URL_BYTES: u64 = 8 * 1024;
const MAX_PASSWORD_BYTES: u64 = 512;
const AGENT_PEER_ADMIN_ROLE: &str = "dtx_agent_peer_admin";

#[derive(Clone, Copy)]
struct RoleSpec {
    login: &'static str,
    membership: &'static str,
    inherit: bool,
}

const ROLE_SPECS: &[RoleSpec] = &[
    RoleSpec {
        login: "dtx_identity_node",
        membership: "dtx_identity_runtime",
        inherit: true,
    },
    RoleSpec {
        login: "dtx_group_node",
        membership: "dtx_group_runtime",
        inherit: true,
    },
    RoleSpec {
        login: "dtx_mailbox_node",
        membership: "dtx_mailbox_runtime",
        inherit: true,
    },
    RoleSpec {
        login: "dtx_push_registration",
        membership: "dtx_push_registration_runtime",
        inherit: true,
    },
    RoleSpec {
        login: "dtx_push_identity_auth",
        membership: "dtx_push_identity_auth_runtime",
        inherit: true,
    },
    RoleSpec {
        login: "dtx_realtime_sync_gateway",
        membership: "dtx_realtime_sync_runtime",
        inherit: true,
    },
    RoleSpec {
        login: "dtx_push_broker",
        membership: "dtx_push_broker_runtime",
        inherit: true,
    },
    // These two logins receive distinct direct grants. Membership is only the
    // RLS authorization marker, so PostgreSQL inheritance must remain off.
    RoleSpec {
        login: "dtx_public_feed_node",
        membership: "dtx_public_feed_runtime",
        inherit: false,
    },
    RoleSpec {
        login: "dtx_indexer_node",
        membership: "dtx_public_feed_runtime",
        inherit: false,
    },
    RoleSpec {
        login: "dtx_agent_control",
        membership: "dtx_agent_runtime",
        inherit: true,
    },
];

#[tokio::main]
async fn main() -> ExitCode {
    match operation().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("dtx-production-migrate: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn operation() -> Result<(), &'static str> {
    let operation = env::args().nth(1).ok_or("operation is required")?;
    if env::args().nth(2).is_some() {
        return Err("unexpected arguments");
    }
    match operation.as_str() {
        "migrate" => {
            let pool = connect_file(DATABASE_URL_FILE_ENV).await?;
            MigrationRunner::new()
                .run(&pool)
                .await
                .map_err(|_| "migration failed")?;
            pool.close().await;
            Ok(())
        }
        "bootstrap-roles" => {
            let pool = connect_file(ADMIN_DATABASE_URL_FILE_ENV).await?;
            create_roles(&pool).await?;
            pool.close().await;
            Ok(())
        }
        "grant-roles" => {
            let pool = connect_file(ADMIN_DATABASE_URL_FILE_ENV).await?;
            grant_roles(&pool).await?;
            pool.close().await;
            Ok(())
        }
        "verify-roles" => {
            let pool = connect_file(ADMIN_DATABASE_URL_FILE_ENV).await?;
            verify_roles(&pool).await?;
            pool.close().await;
            Ok(())
        }
        // Teardown is deliberately non-destructive: it revokes login access,
        // but never drops roles or owned objects. A separate reviewed process
        // is required for irreversible role removal.
        "teardown-roles"
            if env::var("DTX_ROLE_TEARDOWN_CONFIRM").as_deref()
                == Ok("I_UNDERSTAND_PRODUCTION_ROLE_TEARDOWN") =>
        {
            let pool = connect_file(ADMIN_DATABASE_URL_FILE_ENV).await?;
            let mut transaction = pool.begin().await.map_err(|_| "role teardown failed")?;
            for spec in ROLE_SPECS {
                sqlx::query(AssertSqlSafe(format!("ALTER ROLE {} NOLOGIN", spec.login)))
                    .execute(&mut *transaction)
                    .await
                    .map_err(|_| "role teardown failed")?;
            }
            transaction
                .commit()
                .await
                .map_err(|_| "role teardown failed")?;
            pool.close().await;
            Ok(())
        }
        "teardown-roles" => Err("role teardown requires explicit confirmation"),
        _ => Err("unsupported operation"),
    }
}

async fn connect_file(variable: &str) -> Result<PgPool, &'static str> {
    let path = env::var_os(variable).ok_or("database URL file is required")?;
    let options = read_url_file(Path::new(&path))?;
    PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .map_err(|_| "database connection failed")
}

fn read_url_file(path: &Path) -> Result<PgConnectOptions, &'static str> {
    let bytes = read_root_secret(path, MAX_URL_BYTES, "database URL file is invalid")?;
    let value = Zeroizing::new(
        String::from_utf8(bytes.to_vec())
            .map_err(|_| "database URL file is invalid")?
            .trim()
            .to_owned(),
    );
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("database URL file is invalid");
    }
    PgConnectOptions::from_str(&value).map_err(|_| "database URL file is invalid")
}

async fn create_roles(pool: &PgPool) -> Result<(), &'static str> {
    // Read every secret before the first database mutation. A missing or
    // malformed later password therefore leaves the entire role set unchanged.
    let passwords = preload_role_passwords()?;
    let mut transaction = pool.begin().await.map_err(|_| "role bootstrap failed")?;
    for (spec, password) in passwords {
        let inheritance = if spec.inherit { "INHERIT" } else { "NOINHERIT" };
        let membership = spec.membership;
        let role = spec.login;
        if let Err(error) = sqlx::raw_sql(AssertSqlSafe(format!(
            "DO $$ BEGIN IF to_regrole('{membership}') IS NULL THEN CREATE ROLE {membership}; END IF; END $$;\
             DO $$ BEGIN IF to_regrole('{role}') IS NULL THEN CREATE ROLE {role}; END IF; END $$;\
             ALTER ROLE {membership} NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;\
             ALTER ROLE {role} LOGIN {inheritance} NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION;\
             DO $membership$ DECLARE extra name; BEGIN FOR extra IN \
               SELECT granted.rolname FROM pg_auth_members edges \
               JOIN pg_roles granted ON granted.oid = edges.roleid \
               JOIN pg_roles member ON member.oid = edges.member \
               WHERE member.rolname = '{role}' AND granted.rolname <> '{membership}' \
             LOOP EXECUTE format('REVOKE %I FROM {role}', extra); END LOOP; END $membership$;\
             DO $membership$ DECLARE extra name; BEGIN FOR extra IN \
               SELECT granted.rolname FROM pg_auth_members edges \
               JOIN pg_roles granted ON granted.oid = edges.roleid \
               JOIN pg_roles member ON member.oid = edges.member \
               WHERE member.rolname = '{membership}' \
             LOOP EXECUTE format('REVOKE %I FROM {membership}', extra); END LOOP; END $membership$;\
             GRANT {membership} TO {role};"
        )))
        .execute(&mut *transaction)
        .await
        {
            eprintln!("dtx-production-migrate: role normalization failed for {role}: {error}");
            return Err("role bootstrap failed");
        }
        let escaped_password = Zeroizing::new(password.replace('\'', "''"));
        if sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER ROLE {role} PASSWORD '{}'",
            escaped_password.as_str()
        )))
        .execute(&mut *transaction)
        .await
        .is_err()
        {
            eprintln!("dtx-production-migrate: password update failed for {role}");
            return Err("role bootstrap failed");
        }
    }
    // This role is an authorization boundary for a local peer administration
    // path, not a database principal. It must never receive a credential or
    // inherit either runtime capabilities or arbitrary memberships.
    if let Err(error) = sqlx::raw_sql(AssertSqlSafe(format!(
        "DO $$ BEGIN IF to_regrole('{AGENT_PEER_ADMIN_ROLE}') IS NULL THEN CREATE ROLE {AGENT_PEER_ADMIN_ROLE}; END IF; END $$;\
         ALTER ROLE {AGENT_PEER_ADMIN_ROLE} NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD NULL;\
         DO $peer_admin$ DECLARE extra name; BEGIN FOR extra IN \
           SELECT granted.rolname FROM pg_auth_members edges \
           JOIN pg_roles granted ON granted.oid = edges.roleid \
           JOIN pg_roles member ON member.oid = edges.member \
           WHERE member.rolname = '{AGENT_PEER_ADMIN_ROLE}' \
         LOOP EXECUTE format('REVOKE %I FROM {AGENT_PEER_ADMIN_ROLE}', extra); END LOOP; END $peer_admin$;"
    )))
    .execute(&mut *transaction)
    .await
    {
        eprintln!("dtx-production-migrate: role normalization failed for {AGENT_PEER_ADMIN_ROLE}: {error}");
        return Err("role bootstrap failed");
    }
    transaction
        .commit()
        .await
        .map_err(|_| "role bootstrap failed")?;
    Ok(())
}

async fn grant_roles(pool: &PgPool) -> Result<(), &'static str> {
    // The grant matrix is source-controlled and intentionally explicit. It is
    // executed only after migrations and never through a shell command.
    let mut transaction = pool.begin().await.map_err(|_| "grant bootstrap failed")?;
    sqlx::raw_sql(include_str!(
        "../../../docker/local/postgres/20-local-runtime-grants.sql"
    ))
    .execute(&mut *transaction)
    .await
    .map_err(|_| "grant bootstrap failed")?;
    sqlx::raw_sql(include_str!(
        "../../../docker/production/postgres/agent-control-grants.sql"
    ))
    .execute(&mut *transaction)
    .await
    .map_err(|_| "grant bootstrap failed")?;
    transaction
        .commit()
        .await
        .map_err(|_| "grant bootstrap failed")?;
    Ok(())
}

async fn verify_roles(pool: &PgPool) -> Result<(), &'static str> {
    let mut transaction = pool.begin().await.map_err(|_| "role verification failed")?;
    sqlx::raw_sql(include_str!(
        "../../../docker/production/postgres/verify-roles.sql"
    ))
    .execute(&mut *transaction)
    .await
    .map_err(|_| "role verification failed")?;
    // Exercise the same role DDL transaction boundary and prove rollback
    // preserves the live login before declaring PostgreSQL ready.
    sqlx::query("ALTER ROLE dtx_agent_control NOLOGIN")
        .execute(&mut *transaction)
        .await
        .map_err(|_| "role verification failed")?;
    transaction
        .rollback()
        .await
        .map_err(|_| "role verification failed")?;
    let login_enabled: bool =
        sqlx::query_scalar("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'dtx_agent_control'")
            .fetch_one(pool)
            .await
            .map_err(|_| "role verification failed")?;
    if !login_enabled {
        return Err("role transaction rollback verification failed");
    }
    Ok(())
}

fn preload_role_passwords() -> Result<Vec<(RoleSpec, Zeroizing<String>)>, &'static str> {
    ROLE_SPECS
        .iter()
        .copied()
        .map(|spec| {
            let path = Path::new(ROLE_PASSWORD_DIR).join(spec.login);
            read_password_file(&path).map(|password| (spec, password))
        })
        .collect()
}

fn read_password_file(path: &Path) -> Result<Zeroizing<String>, &'static str> {
    let bytes = read_root_secret(path, MAX_PASSWORD_BYTES, "role password file is invalid")?;
    let password = Zeroizing::new(
        String::from_utf8(bytes.to_vec())
            .map_err(|_| "role password file is invalid")?
            .trim()
            .to_owned(),
    );
    if password.is_empty() || password.bytes().any(|byte| byte.is_ascii_control()) {
        return Err("role password file is invalid");
    }
    Ok(password)
}

fn read_root_secret(
    path: &Path,
    maximum: u64,
    error: &'static str,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    validate_root_ancestor_chain(path).map_err(|()| error)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| error)?;
    let before = file.metadata().map_err(|_| error)?;
    let permissions = before.permissions().mode() & 0o777;
    if !before.is_file()
        || before.uid() != 0
        || before.len() == 0
        || before.len() > maximum
        || permissions & !0o440 != 0
        || permissions & 0o400 == 0
    {
        return Err(error);
    }
    let capacity = usize::try_from(before.len()).map_err(|_| error)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error)?;
    let after = file.metadata().map_err(|_| error)?;
    if bytes.is_empty()
        || bytes.len() as u64 > maximum
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
    {
        return Err(error);
    }
    Ok(bytes)
}

fn validate_root_ancestor_chain(path: &Path) -> Result<(), ()> {
    if !path.is_absolute() {
        return Err(());
    }
    for ancestor in path.parent().ok_or(())?.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| ())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(());
        }
    }
    Ok(())
}
