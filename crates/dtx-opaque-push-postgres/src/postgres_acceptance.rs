#![allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
#![allow(clippy::manual_let_else)]

#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use super::*;
use crate::registration::TokenSealer;
use dtx_domain::{
    DeviceId, DeviceSessionId, EnvelopeId, IdentityId, MailboxId, SecretId, TenantId,
};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_persistence::{
    DeviceSessionCredential, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogHead,
    IdentityLogRepository, IdentityPgStore,
};
use dtx_opaque_push::{
    DeliveryClaim, PushError, PushPersistence, RegistrationBinding, SecretToken, TokenEnvelope,
    TokenEnvelopeParts,
};
use dtx_wire::{Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey, UtcMillis};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::{Connection, Row};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use uuid::Uuid;

struct Fixture {
    credential: DeviceSessionCredential,
    identity_id: IdentityId,
    device_id: DeviceId,
    tenant_id: TenantId,
    secret: [u8; 32],
    root: SigningKey,
    head: IdentityLogHead,
}

impl Fixture {
    async fn revoke_active_device(
        &self,
        harness: &support::PostgresHarness,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let event = signed_event(
            &self.root,
            self.identity_id,
            3,
            Some(self.head.hash()),
            IdentityLogEventPayloadV1::DeviceRevoke {
                device_id: self.device_id,
            },
        );
        let store = IdentityPgStore::connect(harness.identity_runtime_options(), 2).await?;
        let outcome = IdentityLogRepository::new()
            .append(
                &store,
                &IdentityAppendCommand::new(
                    Sha256Digest::from_bytes([3; 32]),
                    Some(self.head),
                    event.to_deterministic_cbor()?,
                )?,
                ts(2_003),
            )
            .await?;
        assert!(matches!(outcome, IdentityAppendOutcome::Committed(_)));
        Ok(())
    }
}

impl Fixture {
    fn identity_id_for_test(&self) -> IdentityId {
        self.identity_id
    }
}

struct FakeSealer {
    calls: Arc<AtomicUsize>,
    fail: Arc<AtomicBool>,
}

struct ContextBindingSealer;

impl ContextBindingSealer {
    fn open(
        &self,
        binding: RegistrationBinding,
        secret_id: SecretId,
        envelope: &TokenEnvelope,
    ) -> Result<(), PushError> {
        (envelope.registration_binding() == binding
            && envelope.encrypted_dek().opaque_bytes() == Uuid::from(secret_id).as_bytes())
        .then_some(())
        .ok_or(PushError::ContextMismatch)
    }
}

fn diagnostic_sqlstate(stage: &str, error: &PushPostgresError) {
    let code = match error {
        PushPostgresError::Database(error)
        | PushPostgresError::Identity(
            dtx_identity_persistence::IdentityPersistenceError::Database(error),
        ) => error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code),
        _ => None,
    };
    eprintln!(
        "delete diagnostic stage={stage} sqlstate={code:?} bind_signature=opaque_push_commit_delete(uuid,bytea,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea)"
    );
}

impl FakeSealer {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            fail: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl TokenSealer for FakeSealer {
    fn seal<'a>(
        &'a self,
        binding: RegistrationBinding,
        _secret_id: SecretId,
        _token: &'a SecretToken,
    ) -> Pin<Box<dyn Future<Output = Result<TokenEnvelope, PushError>> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(PushError::Encryption);
            }
            fake_envelope(binding)
        })
    }
}

impl TokenSealer for ContextBindingSealer {
    fn seal<'a>(
        &'a self,
        binding: RegistrationBinding,
        secret_id: SecretId,
        _token: &'a SecretToken,
    ) -> Pin<Box<dyn Future<Output = Result<TokenEnvelope, PushError>> + Send + 'a>> {
        Box::pin(async move {
            let mut context = b"push_token.v1\0dirextalk.opaque-push.token.v1".to_vec();
            for value in [
                binding.tenant_id.to_string(),
                binding.identity_id.to_string(),
                binding.device_id.to_string(),
                "fcm".to_owned(),
                binding.revision.get().to_string(),
            ] {
                context.extend_from_slice(&(value.len() as u32).to_be_bytes());
                context.extend_from_slice(value.as_bytes());
            }
            TokenEnvelope::try_from_parts(TokenEnvelopeParts::new(
                1,
                vec![7; 24],
                vec![8; 17],
                Uuid::from(secret_id).as_bytes().to_vec(),
                "context.binding.v1".to_owned(),
                context,
            )?)
        })
    }
}

fn fake_envelope(binding: RegistrationBinding) -> Result<TokenEnvelope, PushError> {
    let mut context = b"push_token.v1\0dirextalk.opaque-push.token.v1".to_vec();
    for value in [
        binding.tenant_id.to_string(),
        binding.identity_id.to_string(),
        binding.device_id.to_string(),
        "fcm".to_owned(),
        binding.revision.get().to_string(),
    ] {
        context.extend_from_slice(&(value.len() as u32).to_be_bytes());
        context.extend_from_slice(value.as_bytes());
    }
    TokenEnvelope::try_from_parts(TokenEnvelopeParts::new(
        1,
        vec![7; 24],
        vec![8; 17],
        vec![9],
        "local.root_key_file.v1".to_owned(),
        context,
    )?)
}

struct AdvancingSealer {
    store: IdentityPgStore,
    command: IdentityAppendCommand,
    advanced: Arc<AtomicBool>,
}

impl TokenSealer for AdvancingSealer {
    fn seal<'a>(
        &'a self,
        binding: RegistrationBinding,
        _secret_id: SecretId,
        _token: &'a SecretToken,
    ) -> Pin<Box<dyn Future<Output = Result<TokenEnvelope, PushError>> + Send + 'a>> {
        Box::pin(async move {
            if !self.advanced.swap(true, Ordering::SeqCst) {
                match IdentityLogRepository::new()
                    .append(&self.store, &self.command, ts(2_003))
                    .await
                {
                    Ok(IdentityAppendOutcome::Committed(_)) => {}
                    _ => return Err(PushError::Persistence),
                }
            }
            fake_envelope(binding)
        })
    }
}

fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).unwrap()
}
fn sig(key: &SigningKey, bytes: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(bytes).to_bytes())
}
fn ts(value: i64) -> UtcMillis {
    UtcMillis::new(value).unwrap()
}
fn safe(value: u64) -> SafeUint {
    SafeUint::new(value).unwrap()
}

fn signed_event(
    signer: &SigningKey,
    identity_id: IdentityId,
    seq: u64,
    previous: Option<Sha256Digest>,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        safe(seq),
        previous,
        ts(2_000 + seq as i64),
        payload,
        public(signer),
    )
    .unwrap();
    IdentityLogEventV1::signed(
        unsigned.clone(),
        sig(
            signer,
            &identity_log_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap()
}

async fn fixture(
    harness: &support::PostgresHarness,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = signing(1);
    let recovery = signing(2);
    let root_key = public(&root);
    let recovery_key = public(&recovery);
    let genesis_id = IdentityId::derive(root_key.as_domain_key());
    let genesis = signed_event(
        &root,
        genesis_id,
        1,
        None,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature: sig(
                &recovery,
                &genesis_recovery_acceptance_input(genesis_id, root_key, recovery_key).unwrap(),
            ),
        },
    );
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 2).await?;
    let repo = IdentityLogRepository::new();
    let first = match repo
        .append(
            &store,
            &IdentityAppendCommand::new(
                Sha256Digest::from_bytes([1; 32]),
                None,
                genesis.to_deterministic_cbor()?,
            )?,
            ts(2_000),
        )
        .await?
    {
        IdentityAppendOutcome::Committed(receipt) => receipt,
        _ => return Err("genesis not committed".into()),
    };
    let device_key = signing(3);
    let device_id = DeviceId::new();
    let unsigned_cert = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        genesis_id,
        device_id,
        public(&device_key),
        DeviceEncryptionPublicKey::try_from([31; 32]).unwrap(),
        public(&root),
        ts(2_001),
    )
    .unwrap();
    let cert = DeviceCertificateV1::signed(
        unsigned_cert.clone(),
        sig(
            &root,
            &device_certificate_signature_input(unsigned_cert.signing_digest().unwrap()),
        ),
    )
    .unwrap();
    let event = signed_event(
        &root,
        genesis_id,
        2,
        Some(first.head().hash()),
        IdentityLogEventPayloadV1::DeviceAdd { certificate: cert },
    );
    let second = match repo
        .append(
            &store,
            &IdentityAppendCommand::new(
                Sha256Digest::from_bytes([2; 32]),
                Some(first.head()),
                event.to_deterministic_cbor()?,
            )?,
            ts(2_002),
        )
        .await?
    {
        IdentityAppendOutcome::Committed(receipt) => receipt,
        _ => return Err("device not committed".into()),
    };
    let session_id = DeviceSessionId::new();
    let challenge_id = Uuid::now_v7();
    let secret = [7_u8; 32];
    let credential = DeviceSessionCredential::new(session_id, secret)?;
    sqlx::query("INSERT INTO identity.device_session_challenges(challenge_id,identity_id,device_id,nonce_hash,audience,state,created_at_ms,expires_at_ms,session_expires_at_ms) VALUES($1,$2,$3,$4,'push','open',2000,2010,9000000000000)")
        .bind(challenge_id).bind(genesis_id.to_string()).bind(Uuid::from(device_id)).bind(vec![5_u8; 32]).execute(harness.admin_pool()).await?;
    sqlx::query("INSERT INTO identity.device_sessions(session_id,identity_id,device_id,challenge_id,session_secret_hash,issued_head_sequence,issued_head_hash,issued_at_ms,expires_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7,2001,9000000000000)")
        .bind(Uuid::from(session_id)).bind(genesis_id.to_string()).bind(Uuid::from(device_id)).bind(challenge_id).bind(credential.database_secret_hash().for_database_binding().to_vec()).bind(i64::try_from(second.head().sequence().get())?).bind(second.head().hash().as_bytes().to_vec()).execute(harness.admin_pool()).await?;
    sqlx::query("UPDATE identity.device_session_challenges SET state='consumed', consumed_at_ms=2001, session_id=$1 WHERE challenge_id=$2")
        .bind(Uuid::from(session_id)).bind(challenge_id).execute(harness.admin_pool()).await?;
    Ok(Fixture {
        credential,
        identity_id: genesis_id,
        device_id,
        tenant_id: TenantId::new(),
        secret,
        root,
        head: second.head(),
    })
}

fn fixture_identity_id(fixture: &Fixture) -> String {
    fixture.identity_id.to_string()
}

fn put_request(f: &Fixture, key: &[u8]) -> RegistrationRequest {
    RegistrationRequest::put(
        DeviceSessionCredential::new(f.credential.session_id(), f.secret).unwrap(),
        "/v43/push",
        key.to_vec(),
        0,
        [3; 32],
        f.tenant_id,
        SecretToken::new(b"token-value".to_vec()).unwrap(),
    )
    .unwrap()
}

async fn insert_delivery(
    harness: &support::PostgresHarness,
    f: &Fixture,
    registration_id: Uuid,
    revision: i64,
    expires_in_ms: i64,
) -> Result<Uuid, sqlx::Error> {
    let mailbox_id = MailboxId::new();
    let envelope_id = EnvelopeId::new();
    let delivery_id = Uuid::now_v7();
    sqlx::query("INSERT INTO messaging.mailboxes(mailbox_id,owner_identity_id,owner_device_id,write_capability_hash,expires_at_ms,created_at_ms) VALUES($1,$2,$3,$4,9000000000000,2000)")
        .bind(Uuid::from(mailbox_id)).bind(fixture_identity_id(f)).bind(Uuid::from(f.device_id)).bind(vec![1_u8;32]).execute(harness.admin_pool()).await?;
    sqlx::query("INSERT INTO messaging.mailbox_envelopes(mailbox_id,envelope_id,delivery_sequence,opaque_ciphertext,request_digest,receipt_bytes,receipt_hash,expires_at_ms,created_at_ms) VALUES($1,$2,1,$3,$4,$5,$6,9000000000000,2000)")
        .bind(Uuid::from(mailbox_id)).bind(Uuid::from(envelope_id)).bind(vec![7_u8]).bind(vec![8_u8;32]).bind(vec![9_u8]).bind(vec![10_u8;32]).execute(harness.admin_pool()).await?;
    sqlx::query("WITH clock AS (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now_ms) INSERT INTO messaging.opaque_push_deliveries(delivery_id,registration_id,registration_revision,mailbox_id,envelope_id,created_at_ms,expires_at_ms) SELECT $1,$2,$3,$4,$5,clock.now_ms+$6-60000,clock.now_ms+$6 FROM clock")
        .bind(delivery_id).bind(registration_id).bind(revision).bind(Uuid::from(mailbox_id)).bind(Uuid::from(envelope_id)).bind(expires_in_ms).execute(harness.admin_pool()).await?;
    Ok(delivery_id)
}

async fn broker_fixture(
    harness: &support::PostgresHarness,
) -> Result<
    (
        Fixture,
        PushRegistrationService<FakeSealer>,
        PostgresPushPersistence,
        Uuid,
    ),
    Box<dyn std::error::Error>,
> {
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NULL THEN CREATE ROLE dtx_public_feed_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$").execute(harness.admin_pool()).await?;
    let f = fixture(harness).await?;
    let identity = IdentityAuthPool::connect(
        harness.push_identity_auth_options(),
        2,
        "dtx_push_identity_auth_only_test",
    )
    .await?;
    let registration = RegistrationPool::connect(
        harness.push_registration_options(),
        2,
        "dtx_push_registration_only_test",
    )
    .await?;
    let service =
        PushRegistrationService::new_with_sealer(identity, registration, FakeSealer::new());
    service
        .register(put_request(&f, b"outcome-revision-1"))
        .await?;
    let registration_id = sqlx::query_scalar(
        "SELECT registration_id FROM messaging.opaque_push_registrations WHERE device_id=$1",
    )
    .bind(Uuid::from(f.device_id))
    .fetch_one(harness.admin_pool())
    .await?;
    let broker = BrokerPool::connect(
        harness.push_broker_options(),
        2,
        "dtx_push_broker_only_test",
    )
    .await?;
    let tenant_id = f.tenant_id;
    Ok((
        f,
        service,
        PostgresPushPersistence::new(broker, tenant_id),
        registration_id,
    ))
}

#[tokio::test]
async fn postgres_pool_validation_fences_capability_and_session_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::PostgresHarness::start().await?;
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NULL THEN CREATE ROLE dtx_public_feed_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$")
        .execute(harness.admin_pool()).await?;
    let registration = match RegistrationPool::connect(
        harness.push_registration_options(),
        2,
        "dtx_push_registration_only_test",
    )
    .await
    {
        Ok(pool) => pool,
        Err(error) => {
            let mut raw =
                sqlx::PgConnection::connect_with(&harness.push_registration_options()).await?;
            let validation = sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(crate::pool::validation_query_for_tests("dtx_push_registration_runtime", &["messaging.opaque_push_prepare_mutation(uuid,bytea,text,text,bytea,bigint,bytea,uuid)", "messaging.opaque_push_commit_put(uuid,bytea,uuid,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea,bytea,bytea,bytea,text,bytea)", "messaging.opaque_push_commit_delete(uuid,bytea,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea)"], false)))
                .bind("dtx_push_registration_only_test")
                .fetch_one(&mut raw).await?;
            let row = sqlx::query("SELECT current_user,session_user,r.rolsuper,r.rolbypassrls,r.rolcreatedb,r.rolcreaterole,pg_has_role(current_user,'dtx_push_registration_runtime','MEMBER') AS registration_member,pg_has_role(current_user,'dtx_push_broker_runtime','MEMBER') AS broker_member FROM pg_roles r WHERE r.rolname=current_user")
                .fetch_one(&mut raw)
                .await?;
            let admin = sqlx::query("SELECT has_schema_privilege('dtx_push_registration_only_test','messaging','USAGE') AS messaging_usage,has_schema_privilege('dtx_push_registration_only_test','identity','CREATE') AS identity_create,has_schema_privilege('dtx_push_registration_only_test','messaging','CREATE') AS messaging_create,has_function_privilege('dtx_push_registration_only_test','messaging.opaque_push_prepare_mutation(uuid,bytea,text,text,bytea,bigint,bytea,uuid)','EXECUTE') AS prepare_exec,has_function_privilege('dtx_push_registration_only_test','messaging.opaque_push_commit_put(uuid,bytea,uuid,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea,bytea,bytea,bytea,text,bytea)','EXECUTE') AS put_exec,has_function_privilege('dtx_push_registration_only_test','messaging.opaque_push_commit_delete(uuid,bytea,text,text,bytea,bigint,bytea,smallint,smallint,smallint,smallint,text,bigint,bytea)','EXECUTE') AS delete_exec,has_function_privilege('dtx_push_registration_only_test','messaging.claim_opaque_push_deliveries(uuid,integer)','EXECUTE') AS claim_exec,has_table_privilege('dtx_push_registration_only_test','messaging.opaque_push_registrations','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS registration_table_write,has_table_privilege('dtx_push_registration_only_test','messaging.opaque_push_idempotency_claims','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS claims_table_write,has_table_privilege('dtx_push_registration_only_test','messaging.opaque_push_deliveries','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS deliveries_table_write,has_table_privilege('dtx_push_registration_only_test','identity.device_sessions','SELECT') AS identity_select,EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relowner=to_regrole('dtx_push_registration_only_test') AND n.nspname IN ('identity','messaging')) AS owns_push_schema")
                .fetch_one(harness.admin_pool()).await?;
            let memberships: Vec<String> = sqlx::query_scalar("SELECT COALESCE(array_agg(role_name ORDER BY role_name), ARRAY[]::text[]) FROM unnest(ARRAY['dtx_identity_runtime','dtx_group_runtime','dtx_mailbox_runtime','dtx_push_identity_auth_runtime','dtx_push_registration_runtime','dtx_push_broker_runtime','dtx_realtime_sync_runtime','dtx_public_feed_runtime']::text[]) AS role_name WHERE pg_has_role('dtx_push_registration_only_test', role_name, 'MEMBER')")
                .fetch_one(harness.admin_pool()).await?;
            eprintln!(
                "pool validation diagnostic: validation_query={} current_user={:?} session_user={:?} super={} bypassrls={} createdb={} createrole={} registration_member={} broker_member={} messaging_usage={} identity_create={} messaging_create={} prepare_exec={} put_exec={} delete_exec={} claim_exec={} registration_table_write={} claims_table_write={} deliveries_table_write={} identity_select={} owns_push_schema={} memberships={memberships:?}",
                validation,
                row.try_get::<String, _>("current_user")?,
                row.try_get::<String, _>("session_user")?,
                row.try_get::<bool, _>("rolsuper")?,
                row.try_get::<bool, _>("rolbypassrls")?,
                row.try_get::<bool, _>("rolcreatedb")?,
                row.try_get::<bool, _>("rolcreaterole")?,
                row.try_get::<bool, _>("registration_member")?,
                row.try_get::<bool, _>("broker_member")?,
                admin.try_get::<bool, _>("messaging_usage")?,
                admin.try_get::<bool, _>("identity_create")?,
                admin.try_get::<bool, _>("messaging_create")?,
                admin.try_get::<bool, _>("prepare_exec")?,
                admin.try_get::<bool, _>("put_exec")?,
                admin.try_get::<bool, _>("delete_exec")?,
                admin.try_get::<bool, _>("claim_exec")?,
                admin.try_get::<bool, _>("registration_table_write")?,
                admin.try_get::<bool, _>("claims_table_write")?,
                admin.try_get::<bool, _>("deliveries_table_write")?,
                admin.try_get::<bool, _>("identity_select")?,
                admin.try_get::<bool, _>("owns_push_schema")?
            );
            return Err(error.into());
        }
    };
    let broker = BrokerPool::connect(
        harness.push_broker_options(),
        2,
        "dtx_push_broker_only_test",
    )
    .await?;
    assert!(registration.pool().acquire().await.is_ok());
    assert!(broker.pool().acquire().await.is_ok());
    assert!(
        RegistrationPool::connect(
            harness.push_registration_options(),
            1,
            "dtx_push_broker_only_test"
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn postgres_registration_put_replays_bytes_without_resealing_and_rejects_binding_conflict()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::PostgresHarness::start().await?;
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NULL THEN CREATE ROLE dtx_public_feed_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$")
        .execute(harness.admin_pool()).await?;
    let f = fixture(&harness).await?;
    let identity = match IdentityAuthPool::connect(
        harness.push_identity_auth_options(),
        2,
        "dtx_push_identity_auth_only_test",
    )
    .await
    {
        Ok(pool) => pool,
        Err(error) => {
            let mut raw =
                sqlx::PgConnection::connect_with(&harness.push_identity_auth_options()).await?;
            let validation = sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(
                crate::pool::validation_query_for_tests(
                    "dtx_push_identity_auth_runtime",
                    &[],
                    true,
                ),
            ))
            .bind("dtx_push_identity_auth_only_test")
            .fetch_one(&mut raw)
            .await?;
            eprintln!("identity pool connect failed: {error:?}, validation={validation}");
            return Err(error.into());
        }
    };
    let registration = RegistrationPool::connect(
        harness.push_registration_options(),
        2,
        "dtx_push_registration_only_test",
    )
    .await
    .map_err(|error| {
        eprintln!("registration pool connect failed: {error:?}");
        error
    })?;
    let sealer = FakeSealer::new();
    let calls = Arc::clone(&sealer.calls);
    let service = PushRegistrationService::new_with_sealer(identity, registration, sealer);
    let first = service.register(put_request(&f, b"same-key")).await?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let replay = service.register(put_request(&f, b"same-key")).await?;
    assert_eq!(first, replay);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let conflict = RegistrationRequest::put(
        DeviceSessionCredential::new(f.credential.session_id(), f.secret).unwrap(),
        "/v43/push",
        b"same-key".to_vec(),
        0,
        [4; 32],
        f.tenant_id,
        SecretToken::new(b"different".to_vec()).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        service.register(conflict).await,
        Err(PushPostgresError::Conflict)
    ));
    Ok(())
}

#[tokio::test]
async fn postgres_registration_replacement_reuses_durable_kms_secret_id()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::PostgresHarness::start().await?;
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NULL THEN CREATE ROLE dtx_public_feed_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$").execute(harness.admin_pool()).await?;
    let fixture = fixture(&harness).await?;
    let service = PushRegistrationService::new_with_sealer(
        IdentityAuthPool::connect(
            harness.push_identity_auth_options(),
            2,
            "dtx_push_identity_auth_only_test",
        )
        .await?,
        RegistrationPool::connect(
            harness.push_registration_options(),
            2,
            "dtx_push_registration_only_test",
        )
        .await?,
        ContextBindingSealer,
    );
    service
        .register(put_request(&fixture, b"context-create"))
        .await?;
    let created_id: Uuid = sqlx::query_scalar(
        "SELECT registration_id FROM messaging.opaque_push_registrations WHERE device_id=$1",
    )
    .bind(Uuid::from(fixture.device_id))
    .fetch_one(harness.admin_pool())
    .await?;
    let mismatched_id = Uuid::now_v7();
    let rejected = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT messaging.opaque_push_commit_put($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
    )
    .bind(Uuid::from(fixture.credential.session_id()))
    .bind(fixture.credential.database_secret_hash().for_database_binding().to_vec())
    .bind(mismatched_id)
    .bind("PUT")
    .bind("/v43/push")
    .bind(b"context-mismatch".to_vec())
    .bind(1_i64)
    .bind(vec![5_u8; 32])
    .bind(i16::try_from(fixture.head.wire().protocol.major())?)
    .bind(i16::try_from(fixture.head.wire().protocol.minor())?)
    .bind(i16::try_from(fixture.head.wire().minimum_reader.major())?)
    .bind(i16::try_from(fixture.head.wire().minimum_reader.minor())?)
    .bind("active")
    .bind(i64::try_from(fixture.head.sequence().get())?)
    .bind(fixture.head.hash().as_bytes().to_vec())
    .bind(vec![8_u8; 17])
    .bind(vec![7_u8; 24])
    .bind(vec![9_u8])
    .bind("context.binding.v1")
    .bind(vec![1_u8])
    .fetch_one(
        RegistrationPool::connect(
            harness.push_registration_options(),
            1,
            "dtx_push_registration_only_test",
        )
        .await?
        .pool(),
    )
    .await;
    let rejected = rejected
        .expect_err("commit must reject a registration ID that differs from the durable row");
    assert_eq!(
        rejected
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("40001")
    );
    service
        .register(RegistrationRequest::put(
            DeviceSessionCredential::new(fixture.credential.session_id(), fixture.secret)?,
            "/v43/push",
            b"context-replace".to_vec(),
            1,
            [4; 32],
            fixture.tenant_id,
            SecretToken::new(b"replacement-token".to_vec())?,
        )?)
        .await?;
    let replacement: (Uuid, i64) = sqlx::query_as(
        "SELECT registration_id,revision FROM messaging.opaque_push_registrations WHERE device_id=$1",
    )
    .bind(Uuid::from(fixture.device_id))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(replacement, (created_id, 2));

    let delivery_id =
        insert_delivery(&harness, &fixture, replacement.0, replacement.1, 59_000).await?;
    let persistence = PostgresPushPersistence::new(
        BrokerPool::connect(
            harness.push_broker_options(),
            2,
            "dtx_push_broker_only_test",
        )
        .await?,
        fixture.tenant_id,
    );
    let claim = persistence.claim(1).await?.pop().unwrap();
    let binding_sealer = ContextBindingSealer;
    binding_sealer.open(
        claim.registration(),
        claim.registration_id(),
        claim.envelope(),
    )?;
    assert!(
        binding_sealer
            .open(claim.registration(), SecretId::new(), claim.envelope())
            .is_err()
    );
    assert!(persistence.authorize_send(&claim).await?.is_some());
    assert!(
        persistence
            .finish_accepted(claim.delivery_id(), claim.claim_token())
            .await?
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT state FROM messaging.opaque_push_deliveries WHERE delivery_id=$1",
        )
        .bind(delivery_id)
        .fetch_one(harness.admin_pool())
        .await?,
        "delivered"
    );
    Ok(())
}

#[tokio::test]
async fn postgres_registration_delete_replays_and_broker_claim_is_fenced()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::PostgresHarness::start().await?;
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NULL THEN CREATE ROLE dtx_public_feed_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$")
        .execute(harness.admin_pool()).await?;
    let f = match fixture(&harness).await {
        Ok(fixture) => fixture,
        Err(error) => {
            eprintln!("delete fixture failed: {error:?}");
            return Err(error);
        }
    };
    let identity = IdentityAuthPool::connect(
        harness.push_identity_auth_options(),
        2,
        "dtx_push_identity_auth_only_test",
    )
    .await
    .map_err(|error| {
        eprintln!("delete identity pool failed: {error:?}");
        error
    })?;
    let registration = RegistrationPool::connect(
        harness.push_registration_options(),
        2,
        "dtx_push_registration_only_test",
    )
    .await
    .map_err(|error| {
        eprintln!("delete registration pool failed: {error:?}");
        error
    })?;
    let sealer = FakeSealer::new();
    let service = PushRegistrationService::new_with_sealer(identity, registration, sealer);
    if let Err(error) = service.register(put_request(&f, b"put-key")).await {
        eprintln!("delete test initial PUT failed: {error:?}");
        return Err(error.into());
    }
    let deleted = match service
        .register(
            RegistrationRequest::delete(
                DeviceSessionCredential::new(f.credential.session_id(), f.secret).unwrap(),
                "/v43/push",
                b"delete-key".to_vec(),
                1,
                [8; 32],
                f.tenant_id,
            )
            .unwrap(),
        )
        .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            eprintln!("delete mutation failed: {error:?}");
            diagnostic_sqlstate("commit_delete", &error);
            return Err(error.into());
        }
    };
    let replay = service
        .register(
            RegistrationRequest::delete(
                DeviceSessionCredential::new(f.credential.session_id(), f.secret).unwrap(),
                "/v43/push",
                b"delete-key".to_vec(),
                1,
                [8; 32],
                f.tenant_id,
            )
            .unwrap(),
        )
        .await?;
    assert_eq!(deleted, replay);
    let state: String = sqlx::query_scalar(
        "SELECT state FROM messaging.opaque_push_registrations WHERE device_id=$1",
    )
    .bind(Uuid::from(f.device_id))
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(state, "revoked");
    Ok(())
}

#[tokio::test]
async fn postgres_registration_sealer_failure_leaves_no_durable_claim()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::PostgresHarness::start().await?;
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NULL THEN CREATE ROLE dtx_public_feed_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$").execute(harness.admin_pool()).await?;
    let f = fixture(&harness).await?;
    let sealer = FakeSealer::new();
    let calls = Arc::clone(&sealer.calls);
    let fail = Arc::clone(&sealer.fail);
    let service = PushRegistrationService::new_with_sealer(
        IdentityAuthPool::connect(
            harness.push_identity_auth_options(),
            2,
            "dtx_push_identity_auth_only_test",
        )
        .await?,
        RegistrationPool::connect(
            harness.push_registration_options(),
            2,
            "dtx_push_registration_only_test",
        )
        .await?,
        sealer,
    );
    fail.store(true, Ordering::SeqCst);
    let request = put_request(&f, b"sealer-retry");
    assert_eq!(
        service.register(request).await.unwrap_err().category(),
        ErrorCategory::Unavailable
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    for table in [
        "opaque_push_registrations",
        "opaque_push_idempotency_claims",
    ] {
        let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) FROM messaging.{table}"
        )))
        .fetch_one(harness.admin_pool())
        .await?;
        assert_eq!(count, 0, "{table}");
    }
    fail.store(false, Ordering::SeqCst);
    assert!(
        !service
            .register(put_request(&f, b"sealer-retry"))
            .await?
            .is_empty()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn postgres_registration_replay_precedes_fresh_identity_auth_and_wrong_secret_cannot_probe()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::PostgresHarness::start().await?;
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NULL THEN CREATE ROLE dtx_public_feed_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$").execute(harness.admin_pool()).await?;
    let f = fixture(&harness).await?;
    let sealer = FakeSealer::new();
    let calls = Arc::clone(&sealer.calls);
    let service = PushRegistrationService::new_with_sealer(
        IdentityAuthPool::connect(
            harness.push_identity_auth_options(),
            2,
            "dtx_push_identity_auth_only_test",
        )
        .await?,
        RegistrationPool::connect(
            harness.push_registration_options(),
            2,
            "dtx_push_registration_only_test",
        )
        .await?,
        sealer,
    );
    let receipt = service
        .register(put_request(&f, b"replay-after-revoke"))
        .await?;
    f.revoke_active_device(&harness).await?;
    assert_eq!(
        service
            .register(put_request(&f, b"replay-after-revoke"))
            .await?,
        receipt
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let fresh_after_revoke = RegistrationRequest::put(
        DeviceSessionCredential::new(f.credential.session_id(), f.secret).unwrap(),
        "/v43/push",
        b"fresh-after-revoke".to_vec(),
        1,
        [4; 32],
        f.tenant_id,
        SecretToken::new(b"token-value".to_vec()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        service
            .register(fresh_after_revoke)
            .await
            .unwrap_err()
            .category(),
        ErrorCategory::Revoked
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let wrong = RegistrationRequest::put(
        DeviceSessionCredential::new(f.credential.session_id(), [8; 32]).unwrap(),
        "/v43/push",
        b"replay-after-revoke".to_vec(),
        0,
        [3; 32],
        f.tenant_id,
        SecretToken::new(b"token-value".to_vec()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        service.register(wrong).await.unwrap_err().category(),
        ErrorCategory::Auth
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM messaging.opaque_push_registrations),(SELECT count(*) FROM messaging.opaque_push_idempotency_claims)").fetch_one(harness.admin_pool()).await?;
    assert_eq!(counts, (1, 1));
    Ok(())
}

#[tokio::test]
async fn postgres_registration_commit_rejects_stale_identity_fence_without_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::PostgresHarness::start().await?;
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NULL THEN CREATE ROLE dtx_public_feed_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$").execute(harness.admin_pool()).await?;
    let f = fixture(&harness).await?;
    let event = signed_event(
        &f.root,
        f.identity_id,
        3,
        Some(f.head.hash()),
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: f.device_id,
        },
    );
    let sealer = AdvancingSealer {
        store: IdentityPgStore::connect(harness.identity_runtime_options(), 2).await?,
        command: IdentityAppendCommand::new(
            Sha256Digest::from_bytes([4; 32]),
            Some(f.head),
            event.to_deterministic_cbor()?,
        )?,
        advanced: Arc::new(AtomicBool::new(false)),
    };
    let service = PushRegistrationService::new_with_sealer(
        IdentityAuthPool::connect(
            harness.push_identity_auth_options(),
            2,
            "dtx_push_identity_auth_only_test",
        )
        .await?,
        RegistrationPool::connect(
            harness.push_registration_options(),
            2,
            "dtx_push_registration_only_test",
        )
        .await?,
        sealer,
    );
    assert_eq!(
        service
            .register(put_request(&f, b"stale-head"))
            .await
            .unwrap_err()
            .category(),
        ErrorCategory::Fence
    );
    let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM messaging.opaque_push_registrations),(SELECT count(*) FROM messaging.opaque_push_idempotency_claims)").fetch_one(harness.admin_pool()).await?;
    assert_eq!(counts, (0, 0));
    Ok(())
}

#[tokio::test]
async fn postgres_broker_claim_reconstructs_binding_provenance_and_finishes_accepted()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::PostgresHarness::start().await?;
    sqlx::raw_sql("DO $$ BEGIN IF to_regrole('dtx_public_feed_runtime') IS NULL THEN CREATE ROLE dtx_public_feed_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION; END IF; END $$")
        .execute(harness.admin_pool()).await?;
    let f = fixture(&harness).await?;
    let identity = IdentityAuthPool::connect(
        harness.push_identity_auth_options(),
        2,
        "dtx_push_identity_auth_only_test",
    )
    .await?;
    let registration = RegistrationPool::connect(
        harness.push_registration_options(),
        2,
        "dtx_push_registration_only_test",
    )
    .await?;
    let service =
        PushRegistrationService::new_with_sealer(identity, registration, FakeSealer::new());
    service.register(put_request(&f, b"broker-put")).await?;
    let mailbox_id = MailboxId::new();
    let envelope_id = EnvelopeId::new();
    let delivery_id = Uuid::now_v7();
    sqlx::query("INSERT INTO messaging.mailboxes(mailbox_id,owner_identity_id,owner_device_id,write_capability_hash,expires_at_ms,created_at_ms) VALUES($1,$2,$3,$4,9000000000000,2000)")
        .bind(Uuid::from(mailbox_id)).bind(fixture_identity_id(&f)).bind(Uuid::from(f.device_id)).bind(vec![1_u8;32]).execute(harness.admin_pool()).await?;
    sqlx::query("INSERT INTO messaging.mailbox_envelopes(mailbox_id,envelope_id,delivery_sequence,opaque_ciphertext,request_digest,receipt_bytes,receipt_hash,expires_at_ms,created_at_ms) VALUES($1,$2,1,$3,$4,$5,$6,9000000000000,2000)")
        .bind(Uuid::from(mailbox_id)).bind(Uuid::from(envelope_id)).bind(vec![7_u8]).bind(vec![8_u8;32]).bind(vec![9_u8]).bind(vec![10_u8;32]).execute(harness.admin_pool()).await?;
    let registration_id: Uuid = sqlx::query_scalar(
        "SELECT registration_id FROM messaging.opaque_push_registrations WHERE device_id=$1",
    )
    .bind(Uuid::from(f.device_id))
    .fetch_one(harness.admin_pool())
    .await?;
    sqlx::query("WITH clock AS (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now_ms) INSERT INTO messaging.opaque_push_deliveries(delivery_id,registration_id,registration_revision,mailbox_id,envelope_id,created_at_ms,expires_at_ms) SELECT $1,$2,1,$3,$4,clock.now_ms-1000,clock.now_ms+59000 FROM clock")
        .bind(delivery_id).bind(registration_id).bind(Uuid::from(mailbox_id)).bind(Uuid::from(envelope_id)).execute(harness.admin_pool()).await?;
    let broker = BrokerPool::connect(
        harness.push_broker_options(),
        2,
        "dtx_push_broker_only_test",
    )
    .await?;
    let persistence = PostgresPushPersistence::new(broker, f.tenant_id);
    let mut claims = persistence.claim(1).await?;
    if claims.is_empty() {
        let row = sqlx::query("SELECT d.state,d.retry_at_ms,d.expires_at_ms,r.state AS registration_state,r.revision FROM messaging.opaque_push_deliveries d JOIN messaging.opaque_push_registrations r ON r.registration_id=d.registration_id WHERE d.delivery_id=$1")
            .bind(delivery_id)
            .fetch_one(harness.admin_pool()).await?;
        eprintln!(
            "broker claim diagnostic: delivery_state={:?} retry_at={:?} expires={:?} registration_state={:?} revision={:?}",
            row.try_get::<String, _>("state")?,
            row.try_get::<Option<i64>, _>("retry_at_ms")?,
            row.try_get::<i64, _>("expires_at_ms")?,
            row.try_get::<String, _>("registration_state")?,
            row.try_get::<i64, _>("revision")?
        );
    }
    assert_eq!(claims.len(), 1);
    let claim = claims.pop().unwrap();
    assert_eq!(claim.provenance(), Some((mailbox_id, envelope_id)));
    assert_eq!(claim.registration().identity_id, f.identity_id_for_test());
    assert_eq!(
        claim.envelope().registration_binding(),
        claim.registration()
    );
    assert!(persistence.authorize_send(&claim).await?.is_some());
    assert!(
        persistence
            .finish_accepted(claim.delivery_id(), claim.claim_token())
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn postgres_broker_rejects_constraint_valid_identity_binding_mismatch_before_provider() {
    let identity_a = IdentityId::derive(public(&signing(40)).as_domain_key());
    let identity_b = IdentityId::derive(public(&signing(41)).as_domain_key());
    let binding_a = RegistrationBinding {
        tenant_id: TenantId::new(),
        identity_id: identity_a,
        device_id: DeviceId::new(),
        provider: dtx_opaque_push::Provider::Fcm,
        revision: dtx_domain::Revision::new(1).unwrap(),
    };
    let binding_b = RegistrationBinding {
        identity_id: identity_b,
        ..binding_a
    };
    let sealer = FakeSealer::new();
    let envelope = sealer
        .seal(
            binding_b,
            SecretId::new(),
            &SecretToken::new(b"token".to_vec()).unwrap(),
        )
        .await
        .unwrap();
    assert!(matches!(
        DeliveryClaim::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            SecretId::new(),
            binding_a,
            envelope,
            None
        ),
        Err(PushError::EnvelopeInvalid)
    ));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_broker_outcomes_use_db_time_and_fences() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = support::PostgresHarness::start().await?;
    let (f, _service, persistence, registration_id) = broker_fixture(&harness).await?;

    let scheduled_id = insert_delivery(&harness, &f, registration_id, 1, 59_000).await?;
    let scheduled_claim = persistence.claim(1).await?.pop().unwrap();
    let schedule = persistence
        .finish_transient_before_expiry(
            scheduled_claim.delivery_id(),
            scheduled_claim.claim_token(),
            dtx_opaque_push::RetryDelay::new(1).unwrap(),
            dtx_opaque_push::RedactedFailureClass::Unavailable,
        )
        .await?;
    let retry_at = match schedule {
        dtx_opaque_push::TransientResolution::Scheduled(schedule) => schedule.next_attempt_at_ms(),
        other => panic!("expected scheduled retry, got {other:?}"),
    };
    let row = sqlx::query("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now_ms,retry_at_ms,expires_at_ms,state,error_class FROM messaging.opaque_push_deliveries WHERE delivery_id=$1")
        .bind(scheduled_id).fetch_one(harness.admin_pool()).await?;
    let now: i64 = row.try_get("now_ms")?;
    let expiry: i64 = row.try_get("expires_at_ms")?;
    assert_eq!(row.try_get::<String, _>("state")?, "pending");
    assert_eq!(row.try_get::<String, _>("error_class")?, "transient");
    assert_eq!(
        u64::try_from(row.try_get::<i64, _>("retry_at_ms")?)?,
        retry_at
    );
    assert!(i64::try_from(retry_at)? > now && i64::try_from(retry_at)? < expiry);
    sqlx::query("UPDATE messaging.opaque_push_deliveries SET retry_at_ms=expires_at_ms-1 WHERE delivery_id=$1")
        .bind(scheduled_id)
        .execute(harness.admin_pool())
        .await?;

    let expired_id = insert_delivery(&harness, &f, registration_id, 1, -1).await?;
    assert!(persistence.claim(1).await?.is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT state FROM messaging.opaque_push_deliveries WHERE delivery_id=$1"
        )
        .bind(expired_id)
        .fetch_one(harness.admin_pool())
        .await?,
        "expired"
    );

    let stale_id = insert_delivery(&harness, &f, registration_id, 1, 59_000).await?;
    let stale_claim = persistence.claim(1).await?.pop().unwrap();
    sqlx::query("UPDATE messaging.opaque_push_deliveries SET claim_expires_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint-1 WHERE delivery_id=$1")
        .bind(stale_id).execute(harness.admin_pool()).await?;
    assert_eq!(
        persistence
            .finish_transient_before_expiry(
                stale_claim.delivery_id(),
                stale_claim.claim_token(),
                dtx_opaque_push::RetryDelay::new(1).unwrap(),
                dtx_opaque_push::RedactedFailureClass::Unavailable
            )
            .await?,
        dtx_opaque_push::TransientResolution::FenceLost
    );
    sqlx::query("UPDATE messaging.opaque_push_deliveries SET retry_at_ms=expires_at_ms-1 WHERE delivery_id=$1")
        .bind(stale_id)
        .execute(harness.admin_pool())
        .await?;

    let permanent_id = insert_delivery(&harness, &f, registration_id, 1, 59_000).await?;
    let permanent_claim = persistence.claim(1).await?.pop().unwrap();
    assert!(
        persistence
            .finish_permanent_failure(permanent_claim.delivery_id(), permanent_claim.claim_token())
            .await?
    );
    assert!(
        !persistence
            .finish_permanent_failure(permanent_claim.delivery_id(), permanent_claim.claim_token())
            .await?
    );
    let permanent: (String, String) = sqlx::query_as(
        "SELECT state,error_class FROM messaging.opaque_push_deliveries WHERE delivery_id=$1",
    )
    .bind(permanent_id)
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(
        permanent,
        (
            "permanent_failure".to_owned(),
            "provider_rejected".to_owned()
        )
    );

    let recent_terminal = insert_delivery(&harness, &f, registration_id, 1, 59_000).await?;
    sqlx::query("UPDATE messaging.opaque_push_deliveries SET state='delivered',terminal_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE delivery_id=$1").bind(recent_terminal).execute(harness.admin_pool()).await?;
    let aged_terminal = insert_delivery(&harness, &f, registration_id, 1, 59_000).await?;
    sqlx::query("UPDATE messaging.opaque_push_deliveries SET state='permanent_failure',error_class='provider_rejected',terminal_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint-86400001 WHERE delivery_id=$1").bind(aged_terminal).execute(harness.admin_pool()).await?;
    assert_eq!(persistence.prune(16).await?, 1);
    assert!(
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM messaging.opaque_push_deliveries WHERE delivery_id=$1)"
        )
        .bind(recent_terminal)
        .fetch_one(harness.admin_pool())
        .await?
    );
    assert!(
        !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM messaging.opaque_push_deliveries WHERE delivery_id=$1)"
        )
        .bind(aged_terminal)
        .fetch_one(harness.admin_pool())
        .await?
    );
    Ok(())
}

#[tokio::test]
async fn postgres_invalid_token_suspends_only_pinned_revision()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = support::PostgresHarness::start().await?;
    let (f, service, persistence, registration_id) = broker_fixture(&harness).await?;
    let delivery_id = insert_delivery(&harness, &f, registration_id, 1, 59_000).await?;
    let claim = persistence.claim(1).await?.pop().unwrap();
    assert!(persistence.finish_invalid_token(&claim).await?);
    let suspended: (String, i64) = sqlx::query_as(
        "SELECT state,revision FROM messaging.opaque_push_registrations WHERE registration_id=$1",
    )
    .bind(registration_id)
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(suspended, ("suspended".to_owned(), 1));
    assert_eq!(
        sqlx::query_scalar::<_, String>(
            "SELECT state FROM messaging.opaque_push_deliveries WHERE delivery_id=$1"
        )
        .bind(delivery_id)
        .fetch_one(harness.admin_pool())
        .await?,
        "permanent_failure"
    );
    assert!(persistence.authorize_send(&claim).await?.is_none());

    service
        .register(
            RegistrationRequest::put(
                DeviceSessionCredential::new(f.credential.session_id(), f.secret).unwrap(),
                "/v43/push",
                b"outcome-revision-2".to_vec(),
                1,
                [4; 32],
                f.tenant_id,
                SecretToken::new(b"replacement".to_vec()).unwrap(),
            )
            .unwrap(),
        )
        .await?;
    let replacement: (Uuid, String, i64) = sqlx::query_as("SELECT registration_id,state,revision FROM messaging.opaque_push_registrations WHERE device_id=$1").bind(Uuid::from(f.device_id)).fetch_one(harness.admin_pool()).await?;
    assert_eq!(replacement.1, "active");
    assert_eq!(replacement.2, 2);
    let replacement_delivery = insert_delivery(&harness, &f, replacement.0, 2, 59_000).await?;
    let replacement_claim = persistence.claim(1).await?.pop().unwrap();
    assert_eq!(replacement_claim.delivery_id(), replacement_delivery);
    assert!(
        persistence
            .authorize_send(&replacement_claim)
            .await?
            .is_some()
    );
    Ok(())
}

#[test]
fn postgres_acceptance_redaction_never_formats_sql_or_credentials() {
    let error = PushPostgresError::Database(sqlx::Error::Protocol(
        "token=secret sql=DROP TABLE".to_owned(),
    ));
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains("secret"));
    assert!(!rendered.contains("DROP TABLE"));
}
