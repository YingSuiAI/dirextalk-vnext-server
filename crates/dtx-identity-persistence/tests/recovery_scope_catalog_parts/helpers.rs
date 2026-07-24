async fn catalog_rows(
    harness: &support::PostgresHarness,
    identity: IdentityId,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM identity.recovery_scope_catalogs WHERE identity_id=$1")
        .bind(identity.to_string())
        .fetch_one(harness.admin_pool())
        .await
}
async fn preparation_rows(
    harness: &support::PostgresHarness,
    identity: IdentityId,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT count(*) FROM identity.recovery_scope_catalog_preparations WHERE identity_id=$1",
    )
    .bind(identity.to_string())
    .fetch_one(harness.admin_pool())
    .await
}
async fn provider_response_rows(
    harness: &support::PostgresHarness,
    identity: IdentityId,
) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM identity.recovery_scope_catalog_preparations WHERE identity_id=$1 AND provider_response_bytes IS NOT NULL")
        .bind(identity.to_string()).fetch_one(harness.admin_pool()).await
}

async fn wait_until_identity_lock_is_held(
    pool: &sqlx::PgPool,
    identity_id: IdentityId,
) -> Result<(), Box<dyn Error>> {
    let bytes = identity_id.digest_bytes();
    let lock_key = i64::from_be_bytes(bytes[..8].try_into()?);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mut probe = pool.begin().await?;
            let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
                .bind(lock_key)
                .fetch_one(&mut *probe)
                .await?;
            probe.rollback().await?;
            if !acquired {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "identity advisory lock was not acquired in time")??;
    Ok(())
}

async fn session(
    store: &IdentityPgStore,
    identity: IdentityId,
    device: DeviceId,
    signing: &SigningKey,
    seed: u8,
    now: UtcMillis,
) -> Result<DeviceSessionCredential, IdentityPersistenceError> {
    let repository = DeviceSessionRepository;
    let challenge = repository
        .issue_challenge(
            store,
            identity,
            device,
            [seed; 32],
            "https://identity.test",
            now,
        )
        .await?;
    let session_id = DeviceSessionId::new();
    let secret = [seed.wrapping_add(1); 32];
    let secret_hash = Sha256Digest::hash_domain(DEVICE_SESSION_SECRET_HASH_DOMAIN, &secret);
    let proof = sig(
        signing,
        &device_session_proof_input(
            identity,
            device,
            challenge.challenge_id(),
            challenge.nonce(),
            challenge.audience(),
            session_id,
            secret_hash,
            challenge.session_expires_at(),
        )?,
    );
    repository
        .complete(
            store,
            &DeviceSessionCompletionCommand::new(
                Sha256Digest::from_bytes([seed.wrapping_add(2); 32]),
                identity,
                device,
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

fn catalog_command(
    identity: IdentityId,
    head: IdentityLogHead,
    signer: &SigningKey,
    idempotency: Sha256Digest,
    generation: SafeUint,
    previous: Option<Sha256Digest>,
    merkle: [u8; 32],
) -> Result<CatalogUploadCommand, IdentityPersistenceError> {
    let ciphertext = b"opaque-encrypted-catalog-v1".to_vec();
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(identity.to_string())),
        field(3, generation.to_canonical_value()),
        field(
            4,
            previous.map_or(CanonicalValue::Null, |v| v.to_canonical_value()),
        ),
        field(5, CanonicalValue::Unsigned(1)),
        field(6, CanonicalValue::Bytes(merkle.to_vec())),
        field(
            7,
            Sha256Digest::hash_domain(CATALOG_CIPHERTEXT_HASH_DOMAIN, &ciphertext)
                .to_canonical_value(),
        ),
        field(8, head.sequence().to_canonical_value()),
        field(9, head.hash().to_canonical_value()),
        field(10, at(2_500).to_canonical_value()),
        field(11, at(250_000).to_canonical_value()),
    ]);
    let signature = domain_signature(signer, CATALOG_HEAD_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(12, signature.to_canonical_value()));
    let upload = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Map(signed_fields)),
        field(2, CanonicalValue::Bytes(ciphertext)),
    ]);
    let exact_upload = encode_deterministic_cbor(&upload)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("test catalog"))?;
    CatalogUploadCommand::parse(idempotency, generation, &exact_upload)
}

fn preparation_bytes(
    request: dtx_domain::DeviceEnrollmentChallengeId,
    identity: IdentityId,
    device: DeviceId,
    signer: &SigningKey,
    recipient: [u8; 32],
    head: IdentityLogHead,
    response_capability: [u8; 32],
) -> Result<Vec<u8>, IdentityPersistenceError> {
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, CanonicalValue::Text(identity.to_string())),
        field(4, CanonicalValue::Text(device.to_string())),
        field(5, public(signer).to_canonical_value()),
        field(6, CanonicalValue::Bytes(recipient.to_vec())),
        field(7, head.sequence().to_canonical_value()),
        field(8, head.hash().to_canonical_value()),
        field(9, CanonicalValue::Bytes(vec![60; 32])),
        field(10, at(4_500).to_canonical_value()),
        field(11, at(200_000).to_canonical_value()),
        field(
            12,
            Sha256Digest::hash_domain(RESPONSE_CAPABILITY_HASH_DOMAIN, &response_capability)
                .to_canonical_value(),
        ),
    ]);
    let signature = domain_signature(signer, PREPARATION_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(13, signature.to_canonical_value()));
    encode_deterministic_cbor(&CanonicalValue::Map(signed_fields))
        .map_err(|_| IdentityPersistenceError::InvalidCommand("test preparation"))
}

fn provider_command(
    request: dtx_domain::DeviceEnrollmentChallengeId,
    catalog: Sha256Digest,
    device: DeviceId,
    signer: &SigningKey,
    authority: Sha256Digest,
    recipient: [u8; 32],
    idempotency: Sha256Digest,
) -> Result<CatalogProviderResponseCommand, IdentityPersistenceError> {
    let ciphertext = b"opaque-hpke-response-v1".to_vec();
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, catalog.to_canonical_value()),
        field(4, CanonicalValue::Text(device.to_string())),
        field(5, public(signer).to_canonical_value()),
        field(6, authority.to_canonical_value()),
        field(
            7,
            Sha256Digest::hash_domain(RECIPIENT_KEY_HASH_DOMAIN, &recipient).to_canonical_value(),
        ),
        field(8, CanonicalValue::Bytes(ciphertext.clone())),
        field(
            9,
            Sha256Digest::hash_domain(PROVIDER_CIPHERTEXT_HASH_DOMAIN, &ciphertext)
                .to_canonical_value(),
        ),
        field(10, at(200_000).to_canonical_value()),
    ]);
    let signature = domain_signature(signer, PROVIDER_RESPONSE_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(11, signature.to_canonical_value()));
    CatalogProviderResponseCommand::parse(
        idempotency,
        request,
        encode_deterministic_cbor(&CanonicalValue::Map(signed_fields))
            .map_err(|_| IdentityPersistenceError::InvalidCommand("test provider"))?,
    )
}

fn genesis(root: &SigningKey, recovery: &SigningKey) -> IdentityLogEventV1 {
    let root_key = public(root);
    let recovery_key = public(recovery);
    let identity = IdentityId::derive(root_key.as_domain_key());
    signed_event(
        root,
        identity,
        1,
        None,
        1_000,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature: sig(
                recovery,
                &genesis_recovery_acceptance_input(identity, root_key, recovery_key).unwrap(),
            ),
        },
    )
}
#[allow(
    clippy::too_many_arguments,
    reason = "test fixture names every signed device-add binding explicitly"
)]
fn device_add(
    root: &SigningKey,
    identity: IdentityId,
    device: DeviceId,
    key: &SigningKey,
    encryption: u8,
    sequence: u64,
    previous: Sha256Digest,
    time: i64,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity,
        device,
        public(key),
        DeviceEncryptionPublicKey::try_from([encryption; 32]).unwrap(),
        public(root),
        at(time),
    )
    .unwrap();
    let certificate = DeviceCertificateV1::signed(
        unsigned.clone(),
        sig(
            root,
            &device_certificate_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap();
    signed_event(
        root,
        identity,
        sequence,
        Some(previous),
        time,
        IdentityLogEventPayloadV1::DeviceAdd { certificate },
    )
}

fn relay_event(
    root: &SigningKey,
    identity: IdentityId,
    sequence: u64,
    previous: Sha256Digest,
    label: &str,
    time: i64,
) -> IdentityLogEventV1 {
    let descriptor = RelayDescriptorV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        vec![format!("https://relay-{label}.example/v1")],
        at(time + 100),
    )
    .unwrap();
    signed_event(
        root,
        identity,
        sequence,
        Some(previous),
        time,
        IdentityLogEventPayloadV1::RelayDescriptor { descriptor },
    )
}

fn signed_event(
    signer: &SigningKey,
    identity: IdentityId,
    sequence: u64,
    previous: Option<Sha256Digest>,
    time: i64,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity,
        safe(sequence),
        previous,
        at(time),
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
        other => Err(format!("expected commit: {other:?}").into()),
    }
}
fn domain_signature(
    key: &SigningKey,
    domain: &[u8],
    value: &CanonicalValue,
) -> Result<Ed25519Signature, IdentityPersistenceError> {
    let encoded = encode_deterministic_cbor(value)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("test signature"))?;
    let mut input = domain.to_vec();
    input.extend_from_slice(&encoded);
    Ok(sig(key, &input))
}
fn field(key: u64, value: CanonicalValue) -> (CanonicalValue, CanonicalValue) {
    (CanonicalValue::Unsigned(key), value)
}
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn public(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).unwrap()
}
fn sig(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}
fn safe(value: u64) -> SafeUint {
    SafeUint::new(value).unwrap()
}
fn at(value: i64) -> UtcMillis {
    UtcMillis::new(value).unwrap()
}
