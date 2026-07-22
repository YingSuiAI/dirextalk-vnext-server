#![forbid(unsafe_code)]

//! Explicit production database boundary.
//!
//! This binary is intentionally separate from the four long-running release
//! binaries.  It accepts only URL *files*, has a closed operation set, and
//! never prints connection strings or role credentials.

use std::{
    env, fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
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

const RUNTIME_ROLES: &[&str] = &[
    "dtx_identity_node",
    "dtx_group_node",
    "dtx_mailbox_node",
    "dtx_push_registration",
    "dtx_push_identity_auth",
    "dtx_realtime_sync_gateway",
    "dtx_push_broker",
    "dtx_public_feed_node",
    "dtx_indexer_node",
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
        // Teardown is deliberately non-destructive: it revokes login access,
        // but never drops roles or owned objects. A separate reviewed process
        // is required for irreversible role removal.
        "teardown-roles"
            if env::var("DTX_ROLE_TEARDOWN_CONFIRM").as_deref()
                == Ok("I_UNDERSTAND_PRODUCTION_ROLE_TEARDOWN") =>
        {
            let pool = connect_file(ADMIN_DATABASE_URL_FILE_ENV).await?;
            for role in RUNTIME_ROLES {
                sqlx::query(AssertSqlSafe(format!("ALTER ROLE {role} NOLOGIN")))
                    .execute(&pool)
                    .await
                    .map_err(|_| "role teardown failed")?;
            }
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
    let metadata = fs::symlink_metadata(path).map_err(|_| "database URL file is invalid")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.len() == 0
        || metadata.len() > MAX_URL_BYTES
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("database URL file is invalid");
    }
    let bytes = Zeroizing::new(fs::read(path).map_err(|_| "database URL file is invalid")?);
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
    for role in RUNTIME_ROLES {
        let membership = format!("{role}_runtime");
        sqlx::raw_sql(AssertSqlSafe(format!(
            "DO $$ BEGIN IF to_regrole('{membership}') IS NULL THEN CREATE ROLE {membership} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$;\
             DO $$ BEGIN IF to_regrole('{role}') IS NULL THEN CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$;\
             GRANT {membership} TO {role};"
        ))).execute(pool).await.map_err(|_| "role bootstrap failed")?;
        let password_path = Path::new(ROLE_PASSWORD_DIR).join(role);
        let password = read_password_file(&password_path)?;
        let escaped_password = password.replace('\'', "''");
        sqlx::raw_sql(AssertSqlSafe(format!(
            "ALTER ROLE {role} PASSWORD '{escaped_password}'"
        )))
        .execute(pool)
        .await
        .map_err(|_| "role bootstrap failed")?;
    }
    Ok(())
}

async fn grant_roles(pool: &PgPool) -> Result<(), &'static str> {
    // The grant matrix is source-controlled and intentionally explicit. It is
    // executed only after migrations and never through a shell command.
    sqlx::raw_sql(include_str!(
        "../../../docker/local/postgres/20-local-runtime-grants.sql"
    ))
    .execute(pool)
    .await
    .map_err(|_| "grant bootstrap failed")?;
    Ok(())
}

fn read_password_file(path: &Path) -> Result<Zeroizing<String>, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "role password file is invalid")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.len() == 0
        || metadata.len() > MAX_PASSWORD_BYTES
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("role password file is invalid");
    }
    let bytes = Zeroizing::new(fs::read(path).map_err(|_| "role password file is invalid")?);
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
