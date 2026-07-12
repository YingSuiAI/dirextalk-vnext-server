use sqlx::{PgPool, migrate::MigrateError};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

/// Applies every pending database migration in version order.
///
/// Production startup is intentionally forward-only. The paired down scripts
/// exist for empty-database and release rollback rehearsals, not runtime use.
#[derive(Clone, Copy, Debug, Default)]
pub struct MigrationRunner;

impl MigrationRunner {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Applies pending migrations and validates checksums of prior migrations.
    ///
    /// # Errors
    ///
    /// Returns `SQLx`'s migration error when the database is unavailable, a prior
    /// migration changed, or a pending migration cannot be committed.
    pub async fn run(self, pool: &PgPool) -> Result<(), MigrateError> {
        MIGRATOR.run(pool).await
    }
}
