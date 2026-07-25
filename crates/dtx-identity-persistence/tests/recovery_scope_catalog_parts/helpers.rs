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

async fn wait_until_exact_advisory_waiters(
    pool: &sqlx::PgPool,
    lock_key: i64,
    applications: &[&str],
) -> Result<(), Box<dyn Error>> {
    let class_id = i64::from((lock_key as u64 >> 32) as u32);
    let object_id = i64::from(lock_key as u32);
    let applications: Vec<String> = applications.iter().map(ToString::to_string).collect();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let backends: Vec<(String, i32)> = sqlx::query_as(
                "SELECT application_name,pid FROM pg_stat_activity WHERE datid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND application_name=ANY($1) ORDER BY application_name",
            )
            .bind(&applications)
            .fetch_all(pool)
            .await?;
            let pids: Vec<i32> = backends.iter().map(|(_, pid)| *pid).collect();
            let waiting: Vec<i32> = if pids.len() == applications.len()
                && pids.iter().copied().collect::<std::collections::BTreeSet<_>>().len()
                    == pids.len()
            {
                sqlx::query_scalar(
                    "SELECT pid FROM pg_locks WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND locktype='advisory' AND classid=$1 AND objid=$2 AND objsubid=1 AND granted=false AND pid=ANY($3) ORDER BY pid",
                )
                .bind(class_id)
                .bind(object_id)
                .bind(&pids)
                .fetch_all(pool)
                .await?
            } else {
                Vec::new()
            };
            if pids.len() == applications.len()
                && waiting.len() == pids.len()
                && waiting.iter().copied().collect::<std::collections::BTreeSet<_>>()
                    == pids.iter().copied().collect()
            {
                return Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "exact advisory-lock gate did not observe all expected waiters")??;
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
    let ciphertext = b"opaque-encrypted-catalog-v2".to_vec();
    let catalog_id = uuid::Uuid::parse_str(match generation.get() {
        1 => "0190f2a5-7b1c-7abc-8def-0123456789b1",
        2 => "0190f2a5-7b1c-7abc-8def-0123456789b3",
        _ => "0190f2a5-7b1c-7abc-8def-0123456789b4",
    })
    .unwrap();
    let authority_device = DeviceId::from_str(AUTHORITY_DEVICE).unwrap();
    let authority_key_id = uuid::Uuid::parse_str("0190f2a5-7b1c-7abc-8def-0123456789b2").unwrap();
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(catalog_id.to_string())),
        field(3, CanonicalValue::Text(identity.to_string())),
        field(4, generation.to_canonical_value()),
        field(
            5,
            previous.map_or(CanonicalValue::Null, |v| v.to_canonical_value()),
        ),
        field(6, CanonicalValue::Unsigned(1)),
        field(7, CanonicalValue::Bytes(merkle.to_vec())),
        field(
            8,
            Sha256Digest::hash_domain(CATALOG_CIPHERTEXT_HASH_DOMAIN, &ciphertext)
                .to_canonical_value(),
        ),
        field(9, head.sequence().to_canonical_value()),
        field(10, head.hash().to_canonical_value()),
        field(11, CanonicalValue::Text(authority_device.to_string())),
        field(12, CanonicalValue::Text(authority_key_id.to_string())),
        field(13, public(signer).to_canonical_value()),
        field(14, at(2_500).to_canonical_value()),
        field(15, at(250_000).to_canonical_value()),
    ]);
    let signature = domain_signature(signer, CATALOG_HEAD_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(16, signature.to_canonical_value()));
    let upload = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Map(signed_fields)),
        field(2, CanonicalValue::Bytes(ciphertext)),
    ]);
    let exact_upload = encode_deterministic_cbor(&upload)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("test catalog"))?;
    CatalogUploadCommand::parse_v2(idempotency, catalog_id, &exact_upload)
}

fn preparation_bytes(
    request: dtx_domain::DeviceEnrollmentChallengeId,
    identity: IdentityId,
    device: DeviceId,
    signer: &SigningKey,
    recipient: [u8; 32],
    head: IdentityLogHead,
    response_capability: [u8; 32],
    catalog: &CatalogUploadCommand,
    idempotency: Sha256Digest,
) -> Result<Vec<u8>, IdentityPersistenceError> {
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, CanonicalValue::Text(identity.to_string())),
        field(4, CanonicalValue::Text(catalog.catalog_id.to_string())),
        field(5, catalog.generation.to_canonical_value()),
        field(6, catalog.head_digest.to_canonical_value()),
        field(7, CanonicalValue::Text(device.to_string())),
        field(8, public(signer).to_canonical_value()),
        field(9, CanonicalValue::Bytes(recipient.to_vec())),
        field(10, head.sequence().to_canonical_value()),
        field(11, head.hash().to_canonical_value()),
        field(12, CanonicalValue::Bytes(vec![60; 32])),
        field(13,
            Sha256Digest::hash_domain(RESPONSE_CAPABILITY_HASH_DOMAIN, &response_capability)
                .to_canonical_value(),
        ),
        field(14, idempotency.to_canonical_value()),
        field(15, at(4_500).to_canonical_value()),
        field(16, at(200_000).to_canonical_value()),
    ]);
    let signature = domain_signature(signer, PREPARATION_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    signed_fields.push(field(17, signature.to_canonical_value()));
    encode_deterministic_cbor(&CanonicalValue::Map(signed_fields))
        .map_err(|_| IdentityPersistenceError::InvalidCommand("test preparation"))
}

fn provider_command(
    request: dtx_domain::DeviceEnrollmentChallengeId,
    catalog: Sha256Digest,
    device: DeviceId,
    signer: &SigningKey,
    _authority: Sha256Digest,
    recipient: [u8; 32],
    idempotency: Sha256Digest,
    identity: IdentityId,
    catalog_id: uuid::Uuid,
    generation: SafeUint,
    prep_digest: Sha256Digest,
    observed: IdentityLogHead,
    successor: IdentityLogHead,
    candidate: DeviceId,
    _candidate_signer: &SigningKey,
    device_add: &[u8],
) -> Result<CatalogProviderResponseCommand, IdentityPersistenceError> {
    let envelope = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Bytes(vec![9; 32])),
        field(3, CanonicalValue::Bytes(vec![8; 17])),
    ]);
    let envelope_bytes = encode_deterministic_cbor(&envelope)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("test envelope"))?;
    let device_add_digest = Sha256Digest::hash_domain(b"dirextalk.identity-device-add.v1\0", device_add);
    let provider_descriptor = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(device.to_string())),
        field(3, public(signer).to_canonical_value()),
    ]);
    let authority_descriptor = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(2, CanonicalValue::Text(AUTHORITY_DEVICE.to_owned())),
        field(3, public(&key(3)).to_canonical_value()),
    ]);
    let package_digest = Sha256Digest::from_bytes([77; 32]);
    let aad_unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, prep_digest.to_canonical_value()),
        field(4, CanonicalValue::Text(identity.to_string())),
        field(5, CanonicalValue::Text(catalog_id.to_string())),
        field(6, generation.to_canonical_value()),
        field(7, catalog.to_canonical_value()),
        field(8, CanonicalValue::Text(candidate.to_string())),
        field(9, Sha256Digest::hash_domain(RECIPIENT_KEY_HASH_DOMAIN, &recipient).to_canonical_value()),
        field(10, observed.sequence().to_canonical_value()),
        field(11, observed.hash().to_canonical_value()),
        field(12, successor.sequence().to_canonical_value()),
        field(13, successor.hash().to_canonical_value()),
        field(14, device_add_digest.to_canonical_value()),
        field(15, provider_descriptor.clone()),
        field(16, authority_descriptor.clone()),
        field(17, package_digest.to_canonical_value()),
        field(18, idempotency.to_canonical_value()),
        field(19, at(7_150).to_canonical_value()),
        field(20, at(200_000).to_canonical_value()),
    ]);
    let aad_bytes = encode_deterministic_cbor(&aad_unsigned)
        .map_err(|_| IdentityPersistenceError::InvalidCommand("test aad"))?;
    let aad_digest = Sha256Digest::hash_domain(PROVIDER_AAD_DIGEST_DOMAIN, &aad_bytes);
    let envelope_digest = Sha256Digest::hash_domain(PROVIDER_CIPHERTEXT_HASH_DOMAIN, &envelope_bytes);
    let unsigned = CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(2)),
        field(2, CanonicalValue::Text(request.to_string())),
        field(3, prep_digest.to_canonical_value()), field(4, CanonicalValue::Text(identity.to_string())),
        field(5, CanonicalValue::Text(catalog_id.to_string())), field(6, generation.to_canonical_value()),
        field(7, catalog.to_canonical_value()), field(8, CanonicalValue::Text(candidate.to_string())),
        field(9, Sha256Digest::hash_domain(RECIPIENT_KEY_HASH_DOMAIN, &recipient).to_canonical_value()),
        field(10, observed.sequence().to_canonical_value()), field(11, observed.hash().to_canonical_value()),
        field(12, successor.sequence().to_canonical_value()), field(13, successor.hash().to_canonical_value()),
        field(14, device_add_digest.to_canonical_value()), field(15, provider_descriptor.clone()), field(16, authority_descriptor.clone()),
        field(17, package_digest.to_canonical_value()), field(18, aad_digest.to_canonical_value()), field(19, envelope_digest.to_canonical_value()),
        field(20, idempotency.to_canonical_value()), field(21, at(7_150).to_canonical_value()), field(22, at(200_000).to_canonical_value()),
    ]);
    let signature = domain_signature(signer, PROVIDER_RESPONSE_SIGNATURE_DOMAIN, &unsigned)?;
    let CanonicalValue::Map(mut signed_fields) = unsigned else {
        unreachable!()
    };
    let authority_signature = domain_signature(&key(3), PROVIDER_AUTHORITY_SIGNATURE_DOMAIN, &CanonicalValue::Map(signed_fields.clone()))?;
    signed_fields.push(field(23, signature.to_canonical_value()));
    signed_fields.push(field(24, authority_signature.to_canonical_value()));
    signed_fields.push(field(25, CanonicalValue::Bytes(device_add.to_vec())));
    signed_fields.push(field(26, envelope));
    CatalogProviderResponseCommand::parse_v2(
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
