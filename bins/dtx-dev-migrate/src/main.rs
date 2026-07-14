#![forbid(unsafe_code)]

//! Local-development-only forward migration runner.
//!
//! This executable deliberately accepts only one administrator database URL
//! through `DTX_DATABASE_URL`. Docker Compose invokes it once per disposable
//! logical node before starting the corresponding unprivileged node services.

use std::{env, process::ExitCode, str::FromStr};

use dtx_storage::MigrationRunner;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

const DATABASE_URL_ENV: &str = "DTX_DATABASE_URL";

#[tokio::main]
async fn main() -> ExitCode {
    if run().await.is_ok() {
        ExitCode::SUCCESS
    } else {
        eprintln!("dtx-dev-migrate: local database migration failed");
        ExitCode::FAILURE
    }
}

async fn run() -> Result<(), ()> {
    let database_url = env::var(DATABASE_URL_ENV).map_err(|_| ())?;
    let options = PgConnectOptions::from_str(&database_url).map_err(|_| ())?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(|_| ())?;
    MigrationRunner::new().run(&pool).await.map_err(|_| ())?;
    pool.close().await;
    Ok(())
}
