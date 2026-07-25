//! Hermetic migration/preflight coverage for the Route Health HTTP boundary.
//!
//! The shared harness starts either the repository-local PostgreSQL fixture or
//! the pinned testcontainer and runs every forward migration before returning.

#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::error::Error;

use support::PostgresHarness;

#[tokio::test]
async fn route_health_migration_and_runtime_role_preflight() -> Result<(), Box<dyn Error>> {
    // `PostgresHarness::start` runs the complete forward migration set and
    // provisions the least-privilege runtime role. A failure here is a hard
    // preflight failure rather than a test skip.
    let _harness = PostgresHarness::start().await?;
    Ok(())
}
