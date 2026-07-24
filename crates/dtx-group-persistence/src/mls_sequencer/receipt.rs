#[allow(
    clippy::too_many_lines,
    reason = "one row decoder validates every versioned persisted receipt field before replay"
)]
fn receipt_from_row(
    submission_id: RequestId,
    scope: GroupScope,
    expected_signing_key: SigningPublicKey,
    row: &sqlx::postgres::PgRow,
) -> Result<MlsCommitReceipt, GroupPersistenceError> {
    let key: [u8; 32] = row
        .try_get::<Vec<u8>, _>("signing_public_key")?
        .try_into()
        .map_err(|_| GroupPersistenceError::CorruptData("MLS receipt key"))?;
    let signature: [u8; 64] = row
        .try_get::<Vec<u8>, _>("signature")?
        .try_into()
        .map_err(|_| GroupPersistenceError::CorruptData("MLS receipt signature"))?;
    let signing_public_key = SigningPublicKey::try_from(key)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS receipt key"))?;
    if signing_public_key != expected_signing_key {
        return Err(GroupPersistenceError::CorruptData("MLS receipt signer"));
    }
    let protocol_version = u8::try_from(row.try_get::<i16, _>("protocol_version")?)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS protocol version"))?;
    if !matches!(protocol_version, 2..=5) {
        return Err(GroupPersistenceError::CorruptData("MLS protocol version"));
    }
    let request_digest = digest(row.try_get("request_digest")?, "MLS request")?;
    let admitted_epoch = u64::try_from(row.try_get::<i64, _>("admitted_epoch")?)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS admitted epoch"))?;
    let head_digest = digest(row.try_get("result_head_digest")?, "MLS head")?;
    let commit_digest = digest(row.try_get("commit_digest")?, "MLS commit")?;
    let welcome_digest = digest(row.try_get("welcome_digest")?, "MLS Welcome")?;
    let candidate_identity_id = row
        .try_get::<String, _>("candidate_identity_id")?
        .parse()
        .map_err(|_| GroupPersistenceError::CorruptData("MLS candidate identity"))?;
    let candidate_device_id = DeviceId::try_from(row.try_get::<Uuid, _>("candidate_device_id")?)
        .map_err(|_| GroupPersistenceError::CorruptData("MLS candidate device"))?;
    let candidate_key_package_digest = digest(
        row.try_get("candidate_key_package_digest")?,
        "MLS candidate KeyPackage",
    )?;
    let join_request_digest = row
        .try_get::<Option<Vec<u8>>, _>("join_request_digest")?
        .map(|value| digest(value, "MLS join request"))
        .transpose()?;
    let approval_request_digest = row
        .try_get::<Option<Vec<u8>>, _>("approval_request_digest")?
        .map(|value| digest(value, "MLS approval request"))
        .transpose()?;
    let expected_policy_revision = row
        .try_get::<Option<i64>, _>("expected_policy_revision")?
        .map(|value| {
            Revision::new(
                u64::try_from(value)
                    .map_err(|_| GroupPersistenceError::CorruptData("removal policy revision"))?,
            )
            .map_err(|_| GroupPersistenceError::CorruptData("removal policy revision"))
        })
        .transpose()?;
    let result_policy_revision = row
        .try_get::<Option<i64>, _>("result_policy_revision")?
        .map(|value| {
            Revision::new(
                u64::try_from(value)
                    .map_err(|_| GroupPersistenceError::CorruptData("removal policy revision"))?,
            )
            .map_err(|_| GroupPersistenceError::CorruptData("removal policy revision"))
        })
        .transpose()?;
    let removal_policy_revisions = match (expected_policy_revision, result_policy_revision) {
        (Some(expected), Some(result)) if protocol_version == 4 => Some((expected, result)),
        (None, None) if protocol_version != 4 => None,
        _ => {
            return Err(GroupPersistenceError::CorruptData(
                "MLS removal policy revisions",
            ));
        }
    };
    let canonical_cbor: Vec<u8> = row.try_get("receipt_cbor")?;
    let expected_cbor = receipt_cbor_facts(
        protocol_version,
        submission_id,
        scope,
        request_digest,
        admitted_epoch,
        head_digest,
        commit_digest,
        welcome_digest,
        candidate_identity_id,
        candidate_device_id,
        candidate_key_package_digest,
        join_request_digest,
        approval_request_digest,
        removal_policy_revisions,
    )?;
    if canonical_cbor != expected_cbor {
        return Err(GroupPersistenceError::CorruptData(
            "MLS receipt canonical bytes",
        ));
    }
    let receipt_digest = digest(row.try_get("receipt_digest")?, "MLS receipt")?;
    if receipt_digest
        != Sha256Digest::hash_domain(
            match protocol_version {
                3 => V3_RECEIPT_DIGEST_DOMAIN,
                4 => V4_RECEIPT_DIGEST_DOMAIN,
                5 => V5_RECEIPT_DIGEST_DOMAIN,
                _ => RECEIPT_DIGEST_DOMAIN,
            },
            &canonical_cbor,
        )
    {
        return Err(GroupPersistenceError::CorruptData("MLS receipt digest"));
    }
    let signature = Ed25519Signature::from_bytes(signature);
    verify_signature(
        signing_public_key,
        &receipt_signature_input(protocol_version, receipt_digest),
        signature,
    )?;
    Ok(MlsCommitReceipt {
        protocol_version,
        submission_id,
        request_digest,
        admitted_epoch,
        head_digest,
        commit_digest,
        welcome_digest,
        candidate_key_package_digest,
        join_request_digest,
        approval_request_digest,
        removal_policy_revisions,
        canonical_cbor,
        receipt_digest,
        signing_public_key,
        signature,
    })
}
