use sha2::{Digest, Sha256};
use sqlx::{PgPool, migrate::MigrateError};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");

pub const SCHEMA_EPOCH: &str = "product-core-alpha-20260725-history-recovery-completion-v2";

pub(crate) fn baseline_digest() -> Vec<u8> {
    let mut digest = Sha256::new();
    for migration in MIGRATOR
        .iter()
        .filter(|migration| migration.migration_type.is_up_migration())
    {
        digest.update(migration.version.to_be_bytes());
        digest.update(migration.checksum.as_ref());
    }
    digest.finalize().to_vec()
}

pub(crate) fn embedded_migrations_match(applied: &[(i64, bool, Vec<u8>)]) -> bool {
    let embedded = MIGRATOR
        .iter()
        .filter(|migration| migration.migration_type.is_up_migration())
        .collect::<Vec<_>>();

    // Product Core Alpha has one fresh-only schema epoch. Readiness must not
    // accept a database that merely contains every current baseline beside a
    // legacy, missing, failed, or altered migration record.
    applied.len() == embedded.len()
        && embedded.iter().all(|migration| {
            applied.iter().any(|(version, success, checksum)| {
                *version == migration.version
                    && *success
                    && checksum.as_slice() == migration.checksum.as_ref()
            })
        })
}

/// Applies every pending database migration in version order.
///
/// Product Core Alpha installs one current, fresh-only schema epoch.
#[derive(Clone, Copy, Debug, Default)]
pub struct MigrationRunner;

impl MigrationRunner {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Installs the current fresh-only schema epoch and validates its checksums.
    ///
    /// # Errors
    ///
    /// Returns `SQLx`'s migration error when the database is unavailable, a prior
    /// baseline changed, or a baseline statement cannot be committed.
    pub async fn run(self, pool: &PgPool) -> Result<(), MigrateError> {
        MIGRATOR.run(pool).await?;
        let digest = baseline_digest();
        sqlx::query_scalar::<_, String>(
            "INSERT INTO system.schema_epoch(singleton, epoch, baseline_digest) \
             VALUES (true, $1, $2) \
             ON CONFLICT (singleton) DO UPDATE \
                SET epoch = EXCLUDED.epoch, baseline_digest = EXCLUDED.baseline_digest \
              WHERE system.schema_epoch.epoch = EXCLUDED.epoch \
                AND system.schema_epoch.baseline_digest = EXCLUDED.baseline_digest \
             RETURNING epoch",
        )
        .bind(SCHEMA_EPOCH)
        .bind(digest)
        .fetch_one(pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{MIGRATOR, embedded_migrations_match};

    fn current_epoch() -> Vec<(i64, bool, Vec<u8>)> {
        MIGRATOR
            .iter()
            .filter(|migration| migration.migration_type.is_up_migration())
            .map(|migration| (migration.version, true, migration.checksum.to_vec()))
            .collect()
    }

    #[test]
    fn schema_epoch_rejects_extra_missing_failed_and_changed_baselines() {
        let current = current_epoch();
        assert!(embedded_migrations_match(&current));

        let mut extra = current.clone();
        extra.push((9_999_999_999_999, true, vec![0; 48]));
        assert!(!embedded_migrations_match(&extra));

        let mut missing = current.clone();
        missing.pop();
        assert!(!embedded_migrations_match(&missing));

        let mut failed = current.clone();
        failed[0].1 = false;
        assert!(!embedded_migrations_match(&failed));

        let mut changed = current;
        changed[0].2[0] ^= 1;
        assert!(!embedded_migrations_match(&changed));
    }
}
