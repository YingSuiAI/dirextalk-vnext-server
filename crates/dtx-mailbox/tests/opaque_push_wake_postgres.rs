#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::error::Error;

use dtx_domain::{
    DeviceEnrollmentChallengeId, DeviceId, DeviceSessionId, EnvelopeId, IdentityId, MailboxId,
};
use dtx_identity_log::{
    DeviceCertificateV1, DeviceEncryptionPublicKey, IdentityLogEventPayloadV1, IdentityLogEventV1,
    UnsignedDeviceCertificateV1, UnsignedIdentityLogEventV1, device_certificate_signature_input,
    genesis_recovery_acceptance_input, identity_log_signature_input,
};
use dtx_identity_persistence::{
    DEVICE_SESSION_SECRET_HASH_DOMAIN, DeviceSessionCompletionCommand, DeviceSessionCredential,
    DeviceSessionRepository, IdentityAppendCommand, IdentityAppendOutcome, IdentityLogHead,
    IdentityLogRepository, IdentityPersistenceError, IdentityPgStore, device_session_proof_input,
};
use dtx_mailbox::{
    AccountReadCursorWriteCommand, DeviceHistoryGrantAuthorityV2, DeviceHistoryGrantCommandV2,
    MailboxEnvelopeCommand, MailboxPersistenceError, MailboxPgStore, MailboxRegistrationCommand,
    MailboxRepository, MailboxWriteCapability,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, SafeUint, Sha256Digest, SigningPublicKey,
    UtcMillis, encode_deterministic_cbor,
};
use ed25519_dalek::{Signer, SigningKey};
use support::PostgresHarness;
use uuid::Uuid;

const HISTORY_AUTHORITY_ID_DOMAIN: &[u8] = b"dirextalk.device-history-authority-id.v1\0";
const HISTORY_PROVIDER_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.device-history-grant-provider.v2\0";
const HISTORY_AUTHORITY_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.device-history-grant-authority.v2\0";
const HISTORY_RECIPIENT_PACKAGE_DOMAIN: &[u8] =
    b"dirextalk.history-recovery-recipient-package.v1\0";
const HISTORY_OFFER_DOMAIN: &[u8] = b"dirextalk.device-history-offer.v2\0";

#[tokio::test]
async fn postgres_mailbox_enqueue_creates_one_wake_and_exact_replay_creates_none()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let fixture = Fixture::create(&harness).await?;
    let repository = MailboxRepository;
    let envelope_id = EnvelopeId::new();
    let command = envelope_command(
        fixture.mailbox_id,
        envelope_id,
        31,
        at(fixture.now_ms + 100_000),
    )?;

    let first = repository
        .enqueue(
            &fixture.mailbox_store,
            &fixture.write_capability,
            &command,
            at(fixture.now_ms + 20),
        )
        .await?;
    assert!(!first.replayed());
    assert_eq!(
        wake_count(&harness, fixture.mailbox_id, envelope_id).await?,
        1
    );
    let wake_id: Uuid = sqlx::query_scalar(
        "SELECT delivery_id FROM messaging.opaque_push_deliveries
          WHERE mailbox_id=$1 AND envelope_id=$2",
    )
    .bind(*fixture.mailbox_id.as_uuid())
    .bind(*envelope_id.as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(wake_id.get_version_num(), 7);

    let replay = repository
        .enqueue(
            &fixture.mailbox_store,
            &fixture.write_capability,
            &command,
            at(fixture.now_ms + 21),
        )
        .await?;
    assert!(replay.replayed());
    assert_eq!(replay.receipt_bytes(), first.receipt_bytes());
    assert_eq!(
        wake_count(&harness, fixture.mailbox_id, envelope_id).await?,
        1
    );
    Ok(())
}

#[tokio::test]
async fn postgres_history_v2_delivery_creates_one_wake_and_account_cursor_creates_none()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let fixture = Fixture::create(&harness).await?;
    let repository = MailboxRepository;
    let request_id = DeviceEnrollmentChallengeId::new();
    let request_digest = Sha256Digest::from_bytes([41; 32]);
    let recipient_key = [42_u8; 32];
    install_approved_history_request(
        &harness,
        &fixture,
        request_id,
        request_digest,
        recipient_key,
    )
    .await?;
    let attachment_digest = Sha256Digest::from_bytes([43; 32]);
    install_ready_attachment(&harness, &fixture, attachment_digest).await?;

    let envelope_id = EnvelopeId::new();
    let material = HistoryGrantMaterial {
        idempotency_key: Sha256Digest::from_bytes([44; 32]),
        identity_id: fixture.identity_id,
        request_id,
        recovery_request_digest: request_digest,
        approved_head_hash: fixture.head.hash(),
        candidate_device_id: fixture.candidate_device_id,
        provider_device_id: fixture.provider_device_id,
        authority_id: Sha256Digest::hash_domain(
            HISTORY_AUTHORITY_ID_DOMAIN,
            public(&fixture.root_key).as_bytes(),
        )
        .to_string(),
        mailbox_id: fixture.mailbox_id,
        envelope_id,
        recipient_package_digest: Sha256Digest::hash_domain(
            HISTORY_RECIPIENT_PACKAGE_DOMAIN,
            &recipient_key,
        ),
        attachment_digest,
        opaque_offer: b"opaque-history-recovery-offer".to_vec(),
        granted_at: at(fixture.now_ms + 30),
        expires_at: at(fixture.now_ms + 100_000),
    };
    let command = material.command(&fixture.provider_key, &fixture.root_key)?;
    let first = repository
        .grant_device_history_v2(
            &fixture.mailbox_store,
            &fixture.provider_credential,
            &command,
            at(fixture.now_ms + 40),
        )
        .await?;
    assert!(!first.replayed());
    assert_eq!(
        wake_count(&harness, fixture.mailbox_id, envelope_id).await?,
        1
    );

    let replay = repository
        .grant_device_history_v2(
            &fixture.mailbox_store,
            &fixture.provider_credential,
            &command,
            at(fixture.now_ms + 41),
        )
        .await?;
    assert!(replay.replayed());
    assert_eq!(replay.receipt_bytes(), first.receipt_bytes());
    assert_eq!(
        wake_count(&harness, fixture.mailbox_id, envelope_id).await?,
        1
    );

    let before_cursor = all_wake_count(&harness).await?;
    let cursor = account_cursor_command(fixture.head.hash())?;
    let cursor_outcome = repository
        .write_account_read_cursor(
            &fixture.mailbox_store,
            &fixture.provider_credential,
            &cursor,
            at(fixture.now_ms + 50),
        )
        .await?;
    assert!(!cursor_outcome.replayed());
    assert_eq!(all_wake_count(&harness).await?, before_cursor);
    let read_outcome = repository
        .read_account_read_cursor(
            &fixture.mailbox_store,
            &fixture.provider_credential,
            Sha256Digest::from_bytes([61; 32]),
            at(fixture.now_ms + 51),
        )
        .await?;
    assert!(!read_outcome.replayed());
    assert_eq!(all_wake_count(&harness).await?, before_cursor);
    Ok(())
}

#[tokio::test]
async fn postgres_wake_failure_rolls_back_and_store_validator_requires_exact_grant()
-> Result<(), Box<dyn Error>> {
    let harness = PostgresHarness::start().await?;
    let fixture = Fixture::create(&harness).await?;

    let accepted_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 1).await?;
    drop(accepted_store);
    install_failing_wake_function(&harness).await?;
    let envelope_id = EnvelopeId::new();
    let command = envelope_command(
        fixture.mailbox_id,
        envelope_id,
        51,
        at(fixture.now_ms + 100_000),
    )?;
    let error = MailboxRepository
        .enqueue(
            &fixture.mailbox_store,
            &fixture.write_capability,
            &command,
            at(fixture.now_ms + 20),
        )
        .await
        .expect_err("forced wake boundary failure must propagate");
    let MailboxPersistenceError::Database(source) = error else {
        panic!("expected database failure, got {error:?}");
    };
    let database_error = source
        .as_database_error()
        .expect("forced wake failure must retain its database error");
    assert_eq!(database_error.code().as_deref(), Some("XX000"));
    assert_eq!(
        database_error.message(),
        "forced opaque push enqueue failure"
    );
    let rows: (i64, i64) = sqlx::query_as(
        "SELECT
            (SELECT count(*) FROM messaging.mailbox_envelopes
              WHERE mailbox_id=$1 AND envelope_id=$2),
            (SELECT count(*) FROM messaging.opaque_push_deliveries
              WHERE mailbox_id=$1 AND envelope_id=$2)",
    )
    .bind(*fixture.mailbox_id.as_uuid())
    .bind(*envelope_id.as_uuid())
    .fetch_one(harness.admin_pool())
    .await?;
    assert_eq!(rows, (0, 0));

    sqlx::query(
        "REVOKE EXECUTE ON FUNCTION messaging.enqueue_opaque_push_intent(uuid,uuid,uuid)
         FROM dtx_mailbox_runtime",
    )
    .execute(harness.admin_pool())
    .await?;
    assert!(matches!(
        MailboxPgStore::connect(harness.mailbox_runtime_options(), 1).await,
        Err(MailboxPersistenceError::RuntimeRoleUnauthorized)
    ));
    sqlx::query(
        "GRANT EXECUTE ON FUNCTION messaging.enqueue_opaque_push_intent(uuid,uuid,uuid)
         TO dtx_mailbox_runtime",
    )
    .execute(harness.admin_pool())
    .await?;
    sqlx::query(
        "GRANT EXECUTE ON FUNCTION messaging.opaque_push_cbor_uint(bigint)
         TO dtx_mailbox_runtime",
    )
    .execute(harness.admin_pool())
    .await?;
    assert!(matches!(
        MailboxPgStore::connect(harness.mailbox_runtime_options(), 1).await,
        Err(MailboxPersistenceError::RuntimeRoleOverprivileged)
    ));
    Ok(())
}

struct Fixture {
    mailbox_store: MailboxPgStore,
    identity_id: IdentityId,
    provider_device_id: DeviceId,
    candidate_device_id: DeviceId,
    mailbox_id: MailboxId,
    provider_credential: DeviceSessionCredential,
    write_capability: MailboxWriteCapability,
    root_key: SigningKey,
    provider_key: SigningKey,
    candidate_key: SigningKey,
    head: IdentityLogHead,
    now_ms: i64,
}

impl Fixture {
    #[allow(
        clippy::too_many_lines,
        reason = "one PostgreSQL fixture establishes the real identity, session, mailbox, and push-registration boundary"
    )]
    async fn create(harness: &PostgresHarness) -> Result<Self, Box<dyn Error>> {
        let now_ms: i64 =
            sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
                .fetch_one(harness.admin_pool())
                .await?;
        let identity_store =
            IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
        let root_key = key(1);
        let recovery_key = key(2);
        let provider_key = key(3);
        let candidate_key = key(4);
        let genesis = genesis(&root_key, &recovery_key, now_ms - 5_000);
        let identity_id = genesis.identity_id();
        let repository = IdentityLogRepository::new();
        let head1 = committed(
            repository
                .append(
                    &identity_store,
                    &append_command(1, None, &genesis)?,
                    at(now_ms - 4_999),
                )
                .await?,
        )?;
        let provider_device_id = DeviceId::new();
        let provider_add = device_add(
            &root_key,
            identity_id,
            provider_device_id,
            &provider_key,
            3,
            2,
            head1.hash(),
            now_ms - 4_000,
        );
        let head2 = committed(
            repository
                .append(
                    &identity_store,
                    &append_command(2, Some(head1), &provider_add)?,
                    at(now_ms - 3_999),
                )
                .await?,
        )?;
        let candidate_device_id = DeviceId::new();
        let candidate_add = device_add(
            &root_key,
            identity_id,
            candidate_device_id,
            &candidate_key,
            4,
            3,
            head2.hash(),
            now_ms - 3_000,
        );
        let head = committed(
            repository
                .append(
                    &identity_store,
                    &append_command(3, Some(head2), &candidate_add)?,
                    at(now_ms - 2_999),
                )
                .await?,
        )?;
        let provider_credential = session(
            &identity_store,
            identity_id,
            provider_device_id,
            &provider_key,
            10,
            at(now_ms - 1_000),
        )
        .await?;
        let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
        let mailbox_id = MailboxId::new();
        let write_capability = MailboxWriteCapability::new([21; 32])?;
        let registration = mailbox_registration_command(
            mailbox_id,
            identity_id,
            provider_device_id,
            write_capability.hash(),
            at(now_ms + 500_000),
        )?;
        MailboxRepository
            .register(
                &mailbox_store,
                &provider_credential,
                &registration,
                at(now_ms + 10),
            )
            .await?;
        register_push(harness, &provider_credential, head).await?;
        Ok(Self {
            mailbox_store,
            identity_id,
            provider_device_id,
            candidate_device_id,
            mailbox_id,
            provider_credential,
            write_capability,
            root_key,
            provider_key,
            candidate_key,
            head,
            now_ms,
        })
    }
}

struct HistoryGrantMaterial {
    idempotency_key: Sha256Digest,
    identity_id: IdentityId,
    request_id: DeviceEnrollmentChallengeId,
    recovery_request_digest: Sha256Digest,
    approved_head_hash: Sha256Digest,
    candidate_device_id: DeviceId,
    provider_device_id: DeviceId,
    authority_id: String,
    mailbox_id: MailboxId,
    envelope_id: EnvelopeId,
    recipient_package_digest: Sha256Digest,
    attachment_digest: Sha256Digest,
    opaque_offer: Vec<u8>,
    granted_at: UtcMillis,
    expires_at: UtcMillis,
}

impl HistoryGrantMaterial {
    fn command(
        &self,
        provider: &SigningKey,
        authority: &SigningKey,
    ) -> Result<DeviceHistoryGrantCommandV2, MailboxPersistenceError> {
        let mut fields = self.unsigned_fields();
        let unsigned = encode_deterministic_cbor(&CanonicalValue::Map(fields.clone()))
            .map_err(|_| MailboxPersistenceError::InvalidCommand("test history grant"))?;
        let provider_signature =
            domain_signature(provider, HISTORY_PROVIDER_SIGNATURE_DOMAIN, &unsigned);
        let authority_signature =
            domain_signature(authority, HISTORY_AUTHORITY_SIGNATURE_DOMAIN, &unsigned);
        fields.push((
            CanonicalValue::Unsigned(20),
            provider_signature.to_canonical_value(),
        ));
        fields.push((
            CanonicalValue::Unsigned(21),
            authority_signature.to_canonical_value(),
        ));
        fields.push((
            CanonicalValue::Unsigned(22),
            CanonicalValue::Bytes(self.opaque_offer.clone()),
        ));
        let exact = encode_deterministic_cbor(&CanonicalValue::Map(fields))
            .map_err(|_| MailboxPersistenceError::InvalidCommand("test history grant"))?;
        DeviceHistoryGrantCommandV2::new(
            self.idempotency_key,
            self.identity_id,
            self.request_id,
            self.recovery_request_digest,
            self.approved_head_hash,
            self.candidate_device_id,
            self.provider_device_id,
            DeviceHistoryGrantAuthorityV2::RootKey,
            self.authority_id.clone(),
            self.mailbox_id,
            self.envelope_id,
            0,
            self.recipient_package_digest,
            self.attachment_digest,
            self.opaque_offer.clone(),
            self.granted_at,
            self.expires_at,
            provider_signature,
            authority_signature,
            exact,
        )
    }

    fn unsigned_fields(&self) -> Vec<(CanonicalValue, CanonicalValue)> {
        vec![
            field(1, CanonicalValue::Unsigned(2)),
            field(2, CanonicalValue::Text(self.identity_id.to_string())),
            field(3, CanonicalValue::Text(self.request_id.to_string())),
            field(4, self.recovery_request_digest.to_canonical_value()),
            field(5, self.approved_head_hash.to_canonical_value()),
            field(
                6,
                CanonicalValue::Text(self.candidate_device_id.to_string()),
            ),
            field(7, CanonicalValue::Text(self.provider_device_id.to_string())),
            field(8, CanonicalValue::Unsigned(2)),
            field(9, CanonicalValue::Text(self.authority_id.clone())),
            field(10, CanonicalValue::Text(self.mailbox_id.to_string())),
            field(11, CanonicalValue::Text(self.envelope_id.to_string())),
            field(12, CanonicalValue::Unsigned(0)),
            field(13, CanonicalValue::Unsigned(1)),
            field(14, self.recipient_package_digest.to_canonical_value()),
            field(15, self.attachment_digest.to_canonical_value()),
            field(
                16,
                Sha256Digest::hash_domain(HISTORY_OFFER_DOMAIN, &self.opaque_offer)
                    .to_canonical_value(),
            ),
            field(17, self.granted_at.to_canonical_value()),
            field(18, self.expires_at.to_canonical_value()),
            field(19, self.idempotency_key.to_canonical_value()),
        ]
    }
}

fn mailbox_registration_command(
    mailbox_id: MailboxId,
    identity_id: IdentityId,
    device_id: DeviceId,
    capability_hash: Sha256Digest,
    expires_at: UtcMillis,
) -> Result<MailboxRegistrationCommand, MailboxPersistenceError> {
    let exact = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(mailbox_id.to_string())),
        field(3, CanonicalValue::Text(identity_id.to_string())),
        field(4, CanonicalValue::Text(device_id.to_string())),
        field(5, capability_hash.to_canonical_value()),
        field(6, expires_at.to_canonical_value()),
    ]))
    .map_err(|_| MailboxPersistenceError::InvalidCommand("test mailbox registration"))?;
    MailboxRegistrationCommand::new(
        Sha256Digest::from_bytes([22; 32]),
        mailbox_id,
        identity_id,
        device_id,
        capability_hash,
        expires_at,
        exact,
    )
}

fn envelope_command(
    mailbox_id: MailboxId,
    envelope_id: EnvelopeId,
    seed: u8,
    expires_at: UtcMillis,
) -> Result<MailboxEnvelopeCommand, MailboxPersistenceError> {
    let ciphertext = vec![seed; 32];
    let exact = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(envelope_id.to_string())),
        field(3, CanonicalValue::Bytes(ciphertext.clone())),
        field(4, expires_at.to_canonical_value()),
    ]))
    .map_err(|_| MailboxPersistenceError::InvalidCommand("test mailbox envelope"))?;
    MailboxEnvelopeCommand::new(
        Sha256Digest::from_bytes([seed; 32]),
        mailbox_id,
        envelope_id,
        ciphertext,
        expires_at,
        exact,
    )
}

fn account_cursor_command(
    identity_head: Sha256Digest,
) -> Result<AccountReadCursorWriteCommand, MailboxPersistenceError> {
    let conversation = Sha256Digest::from_bytes([61; 32]);
    let ciphertext = b"opaque-account-read-cursor".to_vec();
    let exact = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, conversation.to_canonical_value()),
        field(3, CanonicalValue::Unsigned(0)),
        field(4, CanonicalValue::Unsigned(1)),
        field(5, CanonicalValue::Bytes(ciphertext.clone())),
        field(6, identity_head.to_canonical_value()),
    ]))
    .map_err(|_| MailboxPersistenceError::InvalidCommand("test account cursor"))?;
    AccountReadCursorWriteCommand::new(
        Sha256Digest::from_bytes([62; 32]),
        conversation,
        safe(0),
        safe(1),
        ciphertext,
        identity_head,
        exact,
    )
}

async fn install_approved_history_request(
    harness: &PostgresHarness,
    fixture: &Fixture,
    request_id: DeviceEnrollmentChallengeId,
    request_digest: Sha256Digest,
    recipient_key: [u8; 32],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO identity.device_enrollment_challenges(
             challenge_id,creation_idempotency_key_hash,identity_id,target_device_id,
             target_device_signing_key,target_device_encryption_key,capability_hash,
             request_digest,state,created_at_ms,expires_at_ms,retention_until_ms,
             protocol_version,recovery_request_bytes,recovery_request_digest,
             observed_head_sequence,observed_head_hash,recovery_mode,request_issued_at_ms,
             recipient_encryption_key,candidate_request_signature
         ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'open',$9,$10,$10,2,$11,$12,$13,$14,
                  'all_current_memberships',$9,$6,$15)",
    )
    .bind(*request_id.as_uuid())
    .bind(vec![71_u8; 32])
    .bind(fixture.identity_id.to_string())
    .bind(*fixture.candidate_device_id.as_uuid())
    .bind(public(&fixture.candidate_key).as_bytes().as_slice())
    .bind(recipient_key.to_vec())
    .bind(vec![72_u8; 32])
    .bind(vec![73_u8; 32])
    .bind(fixture.now_ms)
    .bind(fixture.now_ms + 200_000)
    .bind(vec![74_u8])
    .bind(request_digest.as_bytes().as_slice())
    .bind(i64::try_from(fixture.head.sequence().get()).expect("test head sequence fits i64"))
    .bind(fixture.head.hash().as_bytes().as_slice())
    .bind(vec![75_u8; 64])
    .execute(harness.admin_pool())
    .await?;
    sqlx::query(
        "UPDATE identity.device_enrollment_challenges
            SET state='approved',approved_at_ms=$2,approval_request_digest=$3,
                approver_device_id=$4,approver_session_id=$5,
                approved_head_sequence=$6,approved_head_hash=$7,retention_until_ms=$8
          WHERE challenge_id=$1",
    )
    .bind(*request_id.as_uuid())
    .bind(fixture.now_ms + 1)
    .bind(vec![76_u8; 32])
    .bind(*fixture.provider_device_id.as_uuid())
    .bind(Uuid::from(fixture.provider_credential.session_id()))
    .bind(i64::try_from(fixture.head.sequence().get()).expect("test head sequence fits i64"))
    .bind(fixture.head.hash().as_bytes().as_slice())
    .bind(fixture.now_ms + 900_001)
    .execute(harness.admin_pool())
    .await?;
    Ok(())
}

async fn install_ready_attachment(
    harness: &PostgresHarness,
    fixture: &Fixture,
    digest: Sha256Digest,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO messaging.attachment_objects(
             object_id,owner_identity_id,owner_device_id,upload_capability_hash,
             read_capability_hash,expected_manifest_digest,expected_chunk_count,
             expected_ciphertext_bytes,uploaded_chunk_count,uploaded_ciphertext_bytes,
             manifest_bytes,state,expires_at_ms,created_at_ms,updated_at_ms
         ) VALUES($1,$2,$3,$4,$5,$6,1,17,1,17,$7,'ready',$8,$9,$9)",
    )
    .bind(Uuid::now_v7())
    .bind(fixture.identity_id.to_string())
    .bind(*fixture.provider_device_id.as_uuid())
    .bind(vec![81_u8; 32])
    .bind(vec![82_u8; 32])
    .bind(digest.as_bytes().as_slice())
    .bind(vec![0xa0_u8])
    .bind(fixture.now_ms + 200_000)
    .bind(fixture.now_ms)
    .execute(harness.admin_pool())
    .await?;
    Ok(())
}

async fn register_push(
    harness: &PostgresHarness,
    credential: &DeviceSessionCredential,
    head: IdentityLogHead,
) -> Result<(), sqlx::Error> {
    let _: Vec<u8> = sqlx::query_scalar(
        "SELECT messaging.opaque_push_commit_put(
             $1,$2,$3,'PUT','/v43/push',$4,0,$5,
             1::smallint,1::smallint,1::smallint,1::smallint,
             'active',$6,$7,$8,$9,$10,$11,$12)",
    )
    .bind(Uuid::from(credential.session_id()))
    .bind(
        credential
            .database_secret_hash()
            .for_database_binding()
            .to_vec(),
    )
    .bind(Uuid::now_v7())
    .bind(vec![91_u8])
    .bind(vec![92_u8; 32])
    .bind(i64::try_from(head.sequence().get()).expect("test head sequence fits i64"))
    .bind(head.hash().as_bytes().as_slice())
    .bind(vec![0xaa_u8; 17])
    .bind(vec![1_u8; 24])
    .bind(vec![0xbb_u8])
    .bind("kms-v1")
    .bind(vec![0xcc_u8])
    .fetch_one(harness.push_registration_pool())
    .await?;
    Ok(())
}

async fn install_failing_wake_function(harness: &PostgresHarness) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "CREATE OR REPLACE FUNCTION messaging.enqueue_opaque_push_intent(
             requested_delivery_id uuid,requested_mailbox_id uuid,requested_envelope_id uuid
         ) RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
           SET search_path=pg_catalog,messaging AS $$
         DECLARE inserted bigint; selected_device uuid; now_ms bigint;
         BEGIN
           IF NOT COALESCE(pg_has_role(session_user,to_regrole('dtx_mailbox_runtime'),'MEMBER'),false)
              OR NOT messaging.is_uuid_v7(requested_delivery_id) THEN
             RAISE EXCEPTION 'opaque push intent rejected' USING ERRCODE='42501';
           END IF;
           SELECT owner_device_id INTO selected_device FROM messaging.mailboxes
             WHERE mailbox_id=requested_mailbox_id;
           now_ms:=floor(extract(epoch FROM clock_timestamp())*1000)::bigint;
           INSERT INTO messaging.opaque_push_deliveries(
             delivery_id,registration_id,registration_revision,mailbox_id,envelope_id,
             created_at_ms,expires_at_ms
           ) SELECT requested_delivery_id,r.registration_id,r.revision,
                    requested_mailbox_id,requested_envelope_id,now_ms,now_ms+60000
               FROM messaging.opaque_push_registrations r
              WHERE r.device_id=selected_device AND r.provider='fcm' AND r.state='active';
           GET DIAGNOSTICS inserted=ROW_COUNT;
           IF inserted IS DISTINCT FROM 1 THEN
             RAISE EXCEPTION 'forced opaque push enqueue precondition failed'
               USING ERRCODE='P0002';
           END IF;
           RAISE EXCEPTION 'forced opaque push enqueue failure' USING ERRCODE='XX000';
         END $$;",
    )
    .execute(harness.admin_pool())
    .await?;
    Ok(())
}

async fn wake_count(
    harness: &PostgresHarness,
    mailbox_id: MailboxId,
    envelope_id: EnvelopeId,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM messaging.opaque_push_deliveries
          WHERE mailbox_id=$1 AND envelope_id=$2",
    )
    .bind(*mailbox_id.as_uuid())
    .bind(*envelope_id.as_uuid())
    .fetch_one(harness.admin_pool())
    .await
}

async fn all_wake_count(harness: &PostgresHarness) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM messaging.opaque_push_deliveries")
        .fetch_one(harness.admin_pool())
        .await
}

async fn session(
    store: &IdentityPgStore,
    identity_id: IdentityId,
    device_id: DeviceId,
    signing_key: &SigningKey,
    seed: u8,
    now: UtcMillis,
) -> Result<DeviceSessionCredential, IdentityPersistenceError> {
    let challenge = DeviceSessionRepository
        .issue_challenge(
            store,
            identity_id,
            device_id,
            [seed; 32],
            "https://mailbox.test",
            now,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let secret = [seed.wrapping_add(1); 32];
    let secret_hash = Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &secret);
    let proof = signature(
        signing_key,
        &device_session_proof_input(
            identity_id,
            device_id,
            challenge.challenge_id(),
            challenge.nonce(),
            challenge.audience(),
            session_id,
            secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    DeviceSessionRepository
        .complete(
            store,
            &DeviceSessionCompletionCommand::new(
                Sha256Digest::from_bytes([seed.wrapping_add(2); 32]),
                identity_id,
                device_id,
                challenge.challenge_id(),
                session_id,
                *challenge.nonce(),
                secret,
                proof,
            )?,
            at(now.get() + 1),
        )
        .await?;
    DeviceSessionCredential::new(session_id, secret)
}

fn genesis(root: &SigningKey, recovery: &SigningKey, time: i64) -> IdentityLogEventV1 {
    let root_public = public(root);
    let recovery_public = public(recovery);
    let identity_id = IdentityId::derive(root_public.as_domain_key());
    signed_event(
        root,
        identity_id,
        1,
        None,
        time,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_public,
            recovery_signing_key: recovery_public,
            recovery_acceptance_signature: signature(
                recovery,
                &genesis_recovery_acceptance_input(identity_id, root_public, recovery_public)
                    .expect("test genesis binding is valid"),
            ),
        },
    )
}

#[allow(
    clippy::too_many_arguments,
    reason = "the test fixture names each signed device certificate binding"
)]
fn device_add(
    root: &SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
    signing_key: &SigningKey,
    encryption_seed: u8,
    sequence: u64,
    previous: Sha256Digest,
    time: i64,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        device_id,
        public(signing_key),
        DeviceEncryptionPublicKey::try_from([encryption_seed; 32])
            .expect("test encryption key is valid"),
        public(root),
        at(time),
    )
    .expect("test device certificate is valid");
    let certificate = DeviceCertificateV1::signed(
        unsigned.clone(),
        signature(
            root,
            &device_certificate_signature_input(
                unsigned
                    .signing_digest()
                    .expect("test certificate digest is valid"),
            ),
        ),
    )
    .expect("test device certificate signature is valid");
    signed_event(
        root,
        identity_id,
        sequence,
        Some(previous),
        time,
        IdentityLogEventPayloadV1::DeviceAdd { certificate },
    )
}

fn signed_event(
    signer: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    time: i64,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        safe(sequence),
        previous,
        at(time),
        payload,
        public(signer),
    )
    .expect("test identity event is valid");
    IdentityLogEventV1::signed(
        unsigned.clone(),
        signature(
            signer,
            &identity_log_signature_input(
                unsigned
                    .signing_digest()
                    .expect("test identity digest is valid"),
            ),
        ),
    )
    .expect("test identity signature is valid")
}

fn append_command(
    seed: u8,
    expected: Option<IdentityLogHead>,
    event: &IdentityLogEventV1,
) -> Result<IdentityAppendCommand, IdentityPersistenceError> {
    IdentityAppendCommand::new(
        Sha256Digest::from_bytes([seed; 32]),
        expected,
        event.to_deterministic_cbor()?,
    )
}

fn committed(outcome: IdentityAppendOutcome) -> Result<IdentityLogHead, Box<dyn Error>> {
    match outcome {
        IdentityAppendOutcome::Committed(receipt) => Ok(receipt.head()),
        other => Err(format!("expected identity commit, got {other:?}").into()),
    }
}

fn domain_signature(key: &SigningKey, domain: &[u8], value: &[u8]) -> Ed25519Signature {
    let mut input = domain.to_vec();
    input.extend_from_slice(value);
    signature(key, &input)
}

fn field(key: u64, value: CanonicalValue) -> (CanonicalValue, CanonicalValue) {
    (CanonicalValue::Unsigned(key), value)
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes())
        .expect("test signing public key is valid")
}

fn signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}

fn safe(value: u64) -> SafeUint {
    SafeUint::new(value).expect("test safe uint is valid")
}

fn at(value: i64) -> UtcMillis {
    UtcMillis::new(value).expect("test timestamp is valid")
}
