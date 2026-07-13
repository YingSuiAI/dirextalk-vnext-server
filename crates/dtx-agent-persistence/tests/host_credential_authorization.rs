#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, str::FromStr};

use dtx_agent_host::AgentHost;
use dtx_agent_persistence::{
    AgentHostRepository, AgentPersistenceError, CurrentWrite, HostCredentialAuthorizationRepository,
};
use dtx_domain::{HostCredentialId, HostId, IdentityId, Revision, TenantId};
use dtx_security::{
    CertificateFingerprint, HostCredentialAuthorizationSnapshot, HostCredentialAuthorizer,
    HostCredentialBinding, HostWorkloadIdentity,
};
use dtx_storage::PgStore;
use sha2::{Digest, Sha256};
use sqlx::Row;
use support::PostgresHarness;
use uuid::Uuid;

const OWNER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";
const NOT_BEFORE: u64 = 1_800_000_000;
const NOT_AFTER: u64 = 1_800_000_900;

#[derive(Clone, Copy)]
struct HostFixture {
    host_id: HostId,
    initial_credential_id: HostCredentialId,
    initial_fingerprint: CertificateFingerprint,
}

#[derive(Debug)]
enum RaceResult {
    Saved,
    RevisionConflict,
    Other(String),
}

struct RawAuthorizationFact {
    host_id: Uuid,
    credential_id: Uuid,
    fingerprint: Vec<u8>,
    not_before: i64,
    not_after: i64,
    revoked_at: Option<i64>,
    status: &'static str,
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn host_authorization_snapshots_are_durable_monotonic_and_concurrency_fenced()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(4).await?;
    let tenant_id = TenantId::new();
    let foreign_tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;
    provision_tenant(&store, foreign_tenant_id).await?;

    let host_a = HostFixture {
        host_id: HostId::new(),
        initial_credential_id: HostCredentialId::new(),
        initial_fingerprint: CertificateFingerprint::from_bytes([0x11; 32]),
    };
    let host_b = HostFixture {
        host_id: HostId::new(),
        initial_credential_id: HostCredentialId::new(),
        initial_fingerprint: CertificateFingerprint::from_bytes([0x22; 32]),
    };
    let mut agent_host_a = enrolled_host(tenant_id, host_a)?;
    let agent_host_b = enrolled_host(tenant_id, host_b)?;
    let initial_a = binding(tenant_id, host_a, None)?;
    let initial_b = binding(tenant_id, host_b, None)?;
    let authorizer = HostCredentialAuthorizer::new_initial([initial_a, initial_b])?;
    let initial = authorizer.snapshot()?;
    let repository = HostCredentialAuthorizationRepository::new();

    let mut session = store.begin_tenant(tenant_id).await?;
    assert_eq!(
        AgentHostRepository::new()
            .save(session.connection(), &agent_host_a, 1_000)
            .await?,
        CurrentWrite::Inserted
    );
    assert_eq!(
        AgentHostRepository::new()
            .save(session.connection(), &agent_host_b, 1_001)
            .await?,
        CurrentWrite::Inserted
    );
    assert_eq!(
        repository
            .save(session.connection(), tenant_id, &initial, 1_002)
            .await?,
        CurrentWrite::Inserted
    );
    assert_eq!(
        repository
            .save(session.connection(), tenant_id, &initial, 1_003)
            .await?,
        CurrentWrite::Existing
    );
    session.commit().await?;

    let mut foreign = store.begin_tenant(foreign_tenant_id).await?;
    assert!(
        repository
            .load(foreign.connection(), tenant_id)
            .await?
            .is_none(),
        "RLS must hide another tenant's authorization head"
    );
    assert!(
        sqlx::query(
            "INSERT INTO agent.host_credential_authorization_heads
                 (tenant_id, current_revision, created_at_ms, updated_at_ms)
             VALUES ($1, 2, 1000, 1000)",
        )
        .bind(Uuid::from(foreign_tenant_id))
        .execute(foreign.connection())
        .await
        .is_err(),
        "the database boundary must reject an initial head above revision one"
    );
    foreign.rollback().await?;

    let mut foreign = store.begin_tenant(foreign_tenant_id).await?;
    sqlx::query(
        "INSERT INTO agent.host_credential_authorization_revisions (
             tenant_id, authorization_revision, credential_count,
             current_count, retired_count, snapshot_digest, recorded_at_ms
         ) VALUES ($1, 1, 1, 1, 0, $2, 1000)",
    )
    .bind(Uuid::from(foreign_tenant_id))
    .bind(vec![0_u8; 32])
    .execute(foreign.connection())
    .await?;
    sqlx::query(
        "INSERT INTO agent.host_credential_authorization_heads
             (tenant_id, current_revision, created_at_ms, updated_at_ms)
         VALUES ($1, 1, 1000, 1000)",
    )
    .bind(Uuid::from(foreign_tenant_id))
    .execute(foreign.connection())
    .await?;
    assert!(
        foreign.commit().await.is_err(),
        "a published revision must contain every declared state"
    );

    let mut session = store.begin_tenant(tenant_id).await?;
    assert!(
        sqlx::query(
            "INSERT INTO agent.host_credential_authorization_states (
                 tenant_id, authorization_revision, host_id, credential_id,
                 certificate_fingerprint, status, revoked_at_unix_seconds
             )
             SELECT tenant_id, authorization_revision, host_id, credential_id,
                    certificate_fingerprint, status, revoked_at_unix_seconds
               FROM agent.host_credential_authorization_states
              WHERE tenant_id=$1 AND authorization_revision=1
              LIMIT 1",
        )
        .bind(Uuid::from(tenant_id))
        .execute(session.connection())
        .await
        .is_err(),
        "published authorization state must remain append-only"
    );
    session.rollback().await?;

    let replacement_id = HostCredentialId::new();
    agent_host_a.rotate_credential(agent_host_a.revision(), replacement_id)?;
    let replacement_a = HostCredentialBinding::new(
        HostWorkloadIdentity::new(tenant_id, host_a.host_id),
        replacement_id,
        CertificateFingerprint::from_bytes([0x33; 32]),
        NOT_BEFORE,
        NOT_AFTER,
        None,
    )?;
    let rotated_revision = authorizer.replace(initial.revision(), [replacement_a, initial_b])?;
    let rotated = authorizer.snapshot()?;
    assert_eq!(rotated_revision, Revision::new(2)?);

    let mut session = store.begin_tenant(tenant_id).await?;
    assert_eq!(
        AgentHostRepository::new()
            .save(session.connection(), &agent_host_a, 1_100)
            .await?,
        CurrentWrite::Advanced
    );
    session.commit().await?;

    let mut session = store.begin_tenant(tenant_id).await?;
    assert!(matches!(
        repository.load(session.connection(), tenant_id).await,
        Err(AgentPersistenceError::SnapshotRejected(_))
    ));
    session.rollback().await?;

    let mut session = store.begin_tenant(tenant_id).await?;
    assert_eq!(
        repository
            .save_with_host(session.connection(), &agent_host_a, &rotated, 1_101)
            .await?,
        (CurrentWrite::Existing, CurrentWrite::Advanced)
    );
    session.commit().await?;

    let revoked_a = HostCredentialBinding::new(
        HostWorkloadIdentity::new(tenant_id, host_a.host_id),
        replacement_id,
        CertificateFingerprint::from_bytes([0x33; 32]),
        NOT_BEFORE,
        NOT_AFTER,
        Some(NOT_BEFORE + 700),
    )?;
    authorizer.replace(rotated.revision(), [revoked_a, initial_b])?;
    let revoked = authorizer.snapshot()?;
    let mut session = store.begin_tenant(tenant_id).await?;
    assert_eq!(
        repository
            .save(session.connection(), tenant_id, &revoked, 1_200)
            .await?,
        CurrentWrite::Advanced
    );
    session.commit().await?;

    let rollback_candidate = HostCredentialAuthorizationSnapshot::try_new(
        Revision::new(4)?,
        [initial_a, initial_b],
        [],
    )?;
    let mut session = store.begin_tenant(tenant_id).await?;
    assert!(matches!(
        repository
            .save(session.connection(), tenant_id, &rollback_candidate, 1_300,)
            .await,
        Err(AgentPersistenceError::SnapshotRejected(_))
    ));
    assert!(matches!(
        repository
            .save(session.connection(), tenant_id, &initial, 1_301)
            .await,
        Err(AgentPersistenceError::RevisionConflict { current: Some(3) })
    ));
    assert_eq!(
        repository
            .load(session.connection(), tenant_id)
            .await?
            .expect("current authorization head remains present"),
        revoked
    );
    session.rollback().await?;

    let left = successor_with_host_b_revoked(&revoked, revoked_a, host_b, NOT_BEFORE + 500)?;
    let right = successor_with_host_b_revoked(&revoked, revoked_a, host_b, NOT_BEFORE + 600)?;
    let (left_result, right_result) = tokio::join!(
        save_race(store.clone(), tenant_id, left.clone(), 1_400),
        save_race(store.clone(), tenant_id, right.clone(), 1_400),
    );
    let results = [left_result, right_result];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, RaceResult::Saved))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, RaceResult::RevisionConflict))
            .count(),
        1
    );
    let unexpected = results
        .iter()
        .filter_map(|result| match result {
            RaceResult::Other(message) => Some(message.as_str()),
            RaceResult::Saved | RaceResult::RevisionConflict => None,
        })
        .collect::<Vec<_>>();
    assert!(
        unexpected.is_empty(),
        "unexpected race result: {unexpected:?}"
    );

    let mut session = store.begin_tenant(tenant_id).await?;
    let persisted = repository
        .load(session.connection(), tenant_id)
        .await?
        .expect("one concurrent successor becomes the head");
    assert!(persisted == left || persisted == right);
    assert_eq!(persisted.revision(), Revision::new(4)?);
    session.rollback().await?;

    let current_b = persisted
        .current()
        .iter()
        .copied()
        .find(|binding| binding.identity().host_id() == host_b.host_id)
        .expect("the winning revision retains Host B as current");
    let revoked_host_authorizer = HostCredentialAuthorizer::try_from_snapshot(&persisted)?;
    revoked_host_authorizer.replace(persisted.revision(), [current_b])?;
    let revoked_host_snapshot = revoked_host_authorizer.snapshot()?;
    agent_host_a.revoke(agent_host_a.revision())?;

    let mut session = store.begin_tenant(tenant_id).await?;
    assert_eq!(
        AgentHostRepository::new()
            .save(session.connection(), &agent_host_a, 1_500)
            .await?,
        CurrentWrite::Advanced
    );
    session.commit().await?;

    let mut session = store.begin_tenant(tenant_id).await?;
    assert!(matches!(
        repository.load(session.connection(), tenant_id).await,
        Err(AgentPersistenceError::SnapshotRejected(_))
    ));
    session.rollback().await?;

    let mut session = store.begin_tenant(tenant_id).await?;
    assert_eq!(
        repository
            .save_with_host(
                session.connection(),
                &agent_host_a,
                &revoked_host_snapshot,
                1_501,
            )
            .await?,
        (CurrentWrite::Existing, CurrentWrite::Advanced)
    );
    session.commit().await?;

    let mut session = store.begin_tenant(tenant_id).await?;
    assert_eq!(
        repository
            .load(session.connection(), tenant_id)
            .await?
            .expect("revoked Host is removed from the current authorization set"),
        revoked_host_snapshot
    );
    let revision_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agent.host_credential_authorization_revisions
          WHERE tenant_id=$1",
    )
    .bind(Uuid::from(tenant_id))
    .fetch_one(session.connection())
    .await?;
    assert_eq!(
        revision_count, 5,
        "all predecessor images remain append-only"
    );
    session.rollback().await?;

    let original_revision_two_digest: Vec<u8> = sqlx::query_scalar(
        "SELECT snapshot_digest
           FROM agent.host_credential_authorization_revisions
          WHERE tenant_id=$1 AND authorization_revision=2",
    )
    .bind(Uuid::from(tenant_id))
    .fetch_one(harness.admin_pool())
    .await?;
    sqlx::raw_sql(
        "ALTER TABLE agent.host_credential_authorization_revisions DISABLE TRIGGER USER;",
    )
    .execute(harness.admin_pool())
    .await?;
    sqlx::query(
        "UPDATE agent.host_credential_authorization_revisions
            SET snapshot_digest=$3
          WHERE tenant_id=$1 AND authorization_revision=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(2_i64)
    .bind(vec![0_u8; 32])
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql("ALTER TABLE agent.host_credential_authorization_revisions ENABLE TRIGGER USER;")
        .execute(harness.admin_pool())
        .await?;

    let mut session = store.begin_tenant(tenant_id).await?;
    assert!(matches!(
        repository.load(session.connection(), tenant_id).await,
        Err(AgentPersistenceError::CorruptData(_))
    ));
    session.rollback().await?;

    sqlx::raw_sql(
        "ALTER TABLE agent.host_credential_authorization_revisions DISABLE TRIGGER USER;",
    )
    .execute(harness.admin_pool())
    .await?;
    sqlx::query(
        "UPDATE agent.host_credential_authorization_revisions
            SET snapshot_digest=$3
          WHERE tenant_id=$1 AND authorization_revision=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(2_i64)
    .bind(original_revision_two_digest)
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql("ALTER TABLE agent.host_credential_authorization_revisions ENABLE TRIGGER USER;")
        .execute(harness.admin_pool())
        .await?;
    let mut session = store.begin_tenant(tenant_id).await?;
    assert_eq!(
        repository
            .load(session.connection(), tenant_id)
            .await?
            .expect("restored immutable history validates again"),
        revoked_host_snapshot
    );
    session.rollback().await?;

    let mut session = store.begin_tenant(tenant_id).await?;
    let rows = sqlx::query(
        "SELECT state.host_id, state.credential_id,
                state.certificate_fingerprint, state.status,
                state.revoked_at_unix_seconds,
                credential.not_before_unix_seconds,
                credential.not_after_unix_seconds
           FROM agent.host_credential_authorization_states AS state
           JOIN agent.host_credential_authorization_credentials AS credential
             ON credential.tenant_id=state.tenant_id
            AND credential.host_id=state.host_id
            AND credential.credential_id=state.credential_id
            AND credential.certificate_fingerprint=state.certificate_fingerprint
          WHERE state.tenant_id=$1 AND state.authorization_revision=5
          ORDER BY state.credential_id",
    )
    .bind(Uuid::from(tenant_id))
    .fetch_all(session.connection())
    .await?;
    let mut forged_facts = Vec::new();
    for row in rows {
        let credential_id: Uuid = row.try_get("credential_id")?;
        let stored_status: String = row.try_get("status")?;
        let resurrected = credential_id == Uuid::from(replacement_id);
        forged_facts.push(RawAuthorizationFact {
            host_id: row.try_get("host_id")?,
            credential_id,
            fingerprint: row.try_get("certificate_fingerprint")?,
            not_before: row.try_get("not_before_unix_seconds")?,
            not_after: row.try_get("not_after_unix_seconds")?,
            revoked_at: if resurrected {
                None
            } else {
                row.try_get("revoked_at_unix_seconds")?
            },
            status: if resurrected {
                "current"
            } else {
                match stored_status.as_str() {
                    "current" => "current",
                    "retired" => "retired",
                    _ => panic!("unexpected persisted authorization status"),
                }
            },
        });
    }
    let forged_current_count = forged_facts
        .iter()
        .filter(|fact| fact.status == "current")
        .count();
    let forged_digest = raw_snapshot_digest(tenant_id, Revision::new(6)?, &forged_facts);
    sqlx::query(
        "INSERT INTO agent.host_credential_authorization_revisions (
             tenant_id, authorization_revision, credential_count,
             current_count, retired_count, snapshot_digest, recorded_at_ms
         ) VALUES ($1, 6, $2, $3, $4, $5, 1600)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(i64::try_from(forged_facts.len())?)
    .bind(i64::try_from(forged_current_count)?)
    .bind(i64::try_from(forged_facts.len() - forged_current_count)?)
    .bind(forged_digest.as_slice())
    .execute(session.connection())
    .await?;
    for fact in &forged_facts {
        sqlx::query(
            "INSERT INTO agent.host_credential_authorization_states (
                 tenant_id, authorization_revision, host_id, credential_id,
                 certificate_fingerprint, status, revoked_at_unix_seconds
             ) VALUES ($1, 6, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::from(tenant_id))
        .bind(fact.host_id)
        .bind(fact.credential_id)
        .bind(&fact.fingerprint)
        .bind(fact.status)
        .bind(fact.revoked_at)
        .execute(session.connection())
        .await?;
    }
    sqlx::query(
        "UPDATE agent.host_credential_authorization_heads
            SET current_revision=6, updated_at_ms=1600
          WHERE tenant_id=$1 AND current_revision=5",
    )
    .bind(Uuid::from(tenant_id))
    .execute(session.connection())
    .await?;
    session.commit().await?;

    let mut session = store.begin_tenant(tenant_id).await?;
    assert!(matches!(
        repository.load(session.connection(), tenant_id).await,
        Err(AgentPersistenceError::CorruptData(_))
    ));
    session.rollback().await?;

    sqlx::raw_sql("ALTER TABLE agent.host_credential_authorization_heads DISABLE TRIGGER USER;")
        .execute(harness.admin_pool())
        .await?;
    sqlx::query(
        "UPDATE agent.host_credential_authorization_heads
            SET current_revision=1
          WHERE tenant_id=$1",
    )
    .bind(Uuid::from(tenant_id))
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql("ALTER TABLE agent.host_credential_authorization_heads ENABLE TRIGGER USER;")
        .execute(harness.admin_pool())
        .await?;
    let mut session = store.begin_tenant(tenant_id).await?;
    assert!(matches!(
        repository.load(session.connection(), tenant_id).await,
        Err(AgentPersistenceError::CorruptData(_))
    ));
    session.rollback().await?;
    Ok(())
}

#[tokio::test]
async fn host_authorization_load_rejects_corrupt_current_head() -> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let store = harness.runtime_store(2).await?;
    let tenant_id = TenantId::new();
    provision_tenant(&store, tenant_id).await?;
    let host = HostFixture {
        host_id: HostId::new(),
        initial_credential_id: HostCredentialId::new(),
        initial_fingerprint: CertificateFingerprint::from_bytes([0x44; 32]),
    };
    let agent_host = enrolled_host(tenant_id, host)?;
    let snapshot =
        HostCredentialAuthorizer::new_initial([binding(tenant_id, host, None)?])?.snapshot()?;
    let repository = HostCredentialAuthorizationRepository::new();

    let mut session = store.begin_tenant(tenant_id).await?;
    AgentHostRepository::new()
        .save(session.connection(), &agent_host, 2_000)
        .await?;
    repository
        .save(session.connection(), tenant_id, &snapshot, 2_001)
        .await?;
    session.commit().await?;

    sqlx::raw_sql(
        "ALTER TABLE agent.host_credential_authorization_revisions DISABLE TRIGGER USER;",
    )
    .execute(harness.admin_pool())
    .await?;
    sqlx::query(
        "UPDATE agent.host_credential_authorization_revisions
            SET snapshot_digest=$3
          WHERE tenant_id=$1 AND authorization_revision=$2",
    )
    .bind(Uuid::from(tenant_id))
    .bind(1_i64)
    .bind(vec![0_u8; 32])
    .execute(harness.admin_pool())
    .await?;
    sqlx::raw_sql("ALTER TABLE agent.host_credential_authorization_revisions ENABLE TRIGGER USER;")
        .execute(harness.admin_pool())
        .await?;

    let mut session = store.begin_tenant(tenant_id).await?;
    assert!(matches!(
        repository.load(session.connection(), tenant_id).await,
        Err(AgentPersistenceError::CorruptData(_))
    ));
    session.rollback().await?;
    Ok(())
}

fn enrolled_host(tenant_id: TenantId, fixture: HostFixture) -> Result<AgentHost, Box<dyn Error>> {
    let mut host = AgentHost::register(tenant_id, fixture.host_id, IdentityId::from_str(OWNER_ID)?);
    host.enroll(host.revision(), fixture.initial_credential_id)?;
    Ok(host)
}

fn binding(
    tenant_id: TenantId,
    fixture: HostFixture,
    revoked_at: Option<u64>,
) -> Result<HostCredentialBinding, Box<dyn Error>> {
    Ok(HostCredentialBinding::new(
        HostWorkloadIdentity::new(tenant_id, fixture.host_id),
        fixture.initial_credential_id,
        fixture.initial_fingerprint,
        NOT_BEFORE,
        NOT_AFTER,
        revoked_at,
    )?)
}

fn successor_with_host_b_revoked(
    current: &HostCredentialAuthorizationSnapshot,
    host_a: HostCredentialBinding,
    host_b: HostFixture,
    revoked_at: u64,
) -> Result<HostCredentialAuthorizationSnapshot, Box<dyn Error>> {
    let authorizer = HostCredentialAuthorizer::try_from_snapshot(current)?;
    authorizer.replace(
        current.revision(),
        [
            host_a,
            binding(host_a.identity().tenant_id(), host_b, Some(revoked_at))?,
        ],
    )?;
    Ok(authorizer.snapshot()?)
}

fn raw_snapshot_digest(
    tenant_id: TenantId,
    revision: Revision,
    facts: &[RawAuthorizationFact],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"dtx.host-credential-authorization.snapshot.v1\0");
    hasher.update(Uuid::from(tenant_id).as_bytes());
    hasher.update(revision.get().to_be_bytes());
    hasher.update(
        u64::try_from(facts.len())
            .expect("test authorization fact count fits u64")
            .to_be_bytes(),
    );
    for fact in facts {
        hasher.update([match fact.status {
            "current" => 1,
            "retired" => 2,
            _ => panic!("unexpected test authorization status"),
        }]);
        hasher.update(fact.host_id.as_bytes());
        hasher.update(fact.credential_id.as_bytes());
        hasher.update(&fact.fingerprint);
        hasher.update(
            u64::try_from(fact.not_before)
                .expect("test not-before fits u64")
                .to_be_bytes(),
        );
        hasher.update(
            u64::try_from(fact.not_after)
                .expect("test not-after fits u64")
                .to_be_bytes(),
        );
        match fact.revoked_at {
            Some(revoked_at) => {
                hasher.update([1]);
                hasher.update(
                    u64::try_from(revoked_at)
                        .expect("test revoked-at fits u64")
                        .to_be_bytes(),
                );
            }
            None => hasher.update([0]),
        }
    }
    hasher.finalize().into()
}

async fn provision_tenant(store: &PgStore, tenant_id: TenantId) -> Result<(), Box<dyn Error>> {
    let mut session = store.begin_tenant(tenant_id).await?;
    sqlx::query(
        "INSERT INTO system.tenant_stream_heads (tenant_id, last_sequence)
         VALUES ($1, 0)",
    )
    .bind(Uuid::from(tenant_id))
    .execute(session.connection())
    .await?;
    session.commit().await?;
    Ok(())
}

async fn save_race(
    store: PgStore,
    tenant_id: TenantId,
    snapshot: HostCredentialAuthorizationSnapshot,
    stored_at_ms: i64,
) -> RaceResult {
    let mut session = match store.begin_tenant(tenant_id).await {
        Ok(session) => session,
        Err(error) => return RaceResult::Other(error.to_string()),
    };
    match HostCredentialAuthorizationRepository::new()
        .save(session.connection(), tenant_id, &snapshot, stored_at_ms)
        .await
    {
        Ok(CurrentWrite::Advanced) => match session.commit().await {
            Ok(()) => RaceResult::Saved,
            Err(error) => RaceResult::Other(error.to_string()),
        },
        Err(AgentPersistenceError::RevisionConflict { .. }) => {
            let _ = session.rollback().await;
            RaceResult::RevisionConflict
        }
        Ok(write) => {
            let _ = session.rollback().await;
            RaceResult::Other(format!("unexpected write disposition: {write:?}"))
        }
        Err(error) => {
            let _ = session.rollback().await;
            RaceResult::Other(error.to_string())
        }
    }
}
