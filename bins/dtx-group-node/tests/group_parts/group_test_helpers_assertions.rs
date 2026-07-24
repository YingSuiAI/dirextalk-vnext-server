fn numbered_map(values: Vec<CanonicalValue>) -> CanonicalValue {
    CanonicalValue::Map(
        values
            .into_iter()
            .enumerate()
            .map(|(index, value)| (CanonicalValue::Unsigned((index + 1) as u64), value))
            .collect(),
    )
}

fn utc_value(value: i64) -> CanonicalValue {
    if value >= 0 {
        CanonicalValue::Unsigned(u64::try_from(value).expect("non-negative test time fits u64"))
    } else {
        CanonicalValue::Negative(value)
    }
}

fn encode(value: &CanonicalValue) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(encode_deterministic_cbor(value)?)
}

fn device_session_authorization(session_id: DeviceSessionId, session_secret: [u8; 32]) -> String {
    format!(
        "{DEVICE_SESSION_AUTHORIZATION_SCHEME} {session_id}.{}",
        Base64UrlUnpadded::encode_string(&session_secret)
    )
}

fn assert_content_type(response: &axum::response::Response, expected: &str) {
    assert_eq!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some(expected)
    );
}

async fn response_bytes(response: axum::response::Response) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(to_bytes(response.into_body(), 64_000).await?.to_vec())
}

async fn assert_safe_group_error(
    response: axum::response::Response,
    expected_code: &str,
) -> Result<(), Box<dyn Error>> {
    assert_content_type(&response, "application/json");
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    let body = to_bytes(response.into_body(), 16_384).await?;
    let value: serde_json::Value = serde_json::from_slice(&body)?;
    let object = value
        .as_object()
        .ok_or("Group error must be a JSON object")?;
    assert_eq!(object.len(), 1);
    let error = object
        .get("error")
        .and_then(serde_json::Value::as_object)
        .ok_or("Group error must contain one error object")?;
    assert_eq!(error.len(), 3);
    assert_eq!(
        error.get("code").and_then(serde_json::Value::as_str),
        Some(expected_code)
    );
    assert!(
        error
            .get("request_id")
            .and_then(serde_json::Value::as_str)
            .is_some()
    );
    assert_eq!(
        error.get("retryable").and_then(serde_json::Value::as_bool),
        Some(false)
    );
    Ok(())
}

fn replace_numbered_map_field(
    bytes: &[u8],
    field: u64,
    replacement: CanonicalValue,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let CanonicalValue::Map(mut fields) = decode_deterministic_cbor(bytes)? else {
        return Err("canonical request must be a map".into());
    };
    let value = fields
        .iter_mut()
        .find(|(key, _)| key == &CanonicalValue::Unsigned(field))
        .map(|(_, value)| value)
        .ok_or("canonical request field missing")?;
    *value = replacement;
    Ok(encode_deterministic_cbor(&CanonicalValue::Map(fields))?)
}

async fn v5_intent_count(pool: &sqlx::PgPool, tenant_id: TenantId) -> Result<i64, Box<dyn Error>> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM groups.mls_commit_intents
          WHERE tenant_id=$1 AND protocol_version=5",
    )
    .bind(uuid::Uuid::from(tenant_id))
    .fetch_one(pool)
    .await?)
}

type DecodedDiscoveryPage = (Vec<(String, String)>, Option<String>);

fn decode_discovery_page(bytes: &[u8]) -> Result<DecodedDiscoveryPage, Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("discovery page must be a map".into());
    };
    if fields.len() != 7 || fields[0].1 != CanonicalValue::Unsigned(1) {
        return Err("discovery page fields are invalid".into());
    }
    let CanonicalValue::Array(items) = &fields[5].1 else {
        return Err("discovery items must be an array".into());
    };
    let items = items
        .iter()
        .map(|item| {
            let CanonicalValue::Map(item) = item else {
                return Err("discovery item must be a map".into());
            };
            let CanonicalValue::Text(join_request_id) = &item[0].1 else {
                return Err("discovery request ID must be text".into());
            };
            let CanonicalValue::Text(origin) = &item[3].1 else {
                return Err("discovery candidate origin must be text".into());
            };
            Ok((join_request_id.clone(), origin.clone()))
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let next_after = match &fields[6].1 {
        CanonicalValue::Null => None,
        CanonicalValue::Text(value) => {
            let decoded = Base64UrlUnpadded::decode_vec(value)?;
            let CanonicalValue::Map(cursor) = decode_deterministic_cbor(&decoded)? else {
                return Err("discovery cursor must be a canonical map".into());
            };
            if cursor.len() != 2 {
                return Err("discovery cursor field count is invalid".into());
            }
            Some(value.clone())
        }
        _ => return Err("discovery next_after must be text or null".into()),
    };
    Ok((items, next_after))
}

fn decode_v2_pending_package(bytes: &[u8]) -> Result<(String, Sha256Digest), Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("V2 discovery page must be a map".into());
    };
    if fields.len() != 7 || fields[0].1 != CanonicalValue::Unsigned(2) {
        return Err("V2 discovery page fields are invalid".into());
    }
    let CanonicalValue::Array(items) = &fields[5].1 else {
        return Err("V2 discovery items must be an array".into());
    };
    let [CanonicalValue::Map(item)] = items.as_slice() else {
        return Err("V2 discovery page must contain exactly one item".into());
    };
    if item.len() != 9 {
        return Err("V2 discovery item fields are invalid".into());
    }
    let CanonicalValue::Text(join_request_id) = &item[0].1 else {
        return Err("V2 discovery request ID must be text".into());
    };
    let CanonicalValue::Bytes(candidate_key_package_digest) = &item[8].1 else {
        return Err("V2 candidate KeyPackage digest must be bytes".into());
    };
    Ok((
        join_request_id.clone(),
        Sha256Digest::from_bytes(candidate_key_package_digest.as_slice().try_into()?),
    ))
}

fn assert_membership_phase(bytes: &[u8], expected_phase: u64) -> Result<(), Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("membership receipt must be a map".into());
    };
    assert!(matches!(fields[0].1, CanonicalValue::Unsigned(1 | 2)));
    assert_eq!(fields[3].1, CanonicalValue::Unsigned(expected_phase));
    Ok(())
}

fn membership_receipt_request_digest(bytes: &[u8]) -> Result<Sha256Digest, Box<dyn Error>> {
    let CanonicalValue::Map(fields) = decode_deterministic_cbor(bytes)? else {
        return Err("membership receipt must be a map".into());
    };
    let CanonicalValue::Bytes(digest) = &fields[2].1 else {
        return Err("membership request digest must be bytes".into());
    };
    Ok(Sha256Digest::from_bytes(digest.as_slice().try_into()?))
}

fn test_candidate_key_package_digest(candidate: &ActiveDevice) -> Sha256Digest {
    Sha256Digest::hash_domain(
        b"test-mls-key-package\0",
        candidate.device.verifying_key().as_bytes(),
    )
}

fn genesis(
    root: &SigningKey,
    recovery: &SigningKey,
    occurred_at: i64,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let root_key = public_key(root)?;
    let recovery_key = public_key(recovery)?;
    let identity_id = IdentityId::derive(root_key.as_domain_key());
    let recovery_acceptance_signature = signature(
        recovery,
        &genesis_recovery_acceptance_input(identity_id, root_key, recovery_key)?,
    );
    signed_event(
        root,
        identity_id,
        1,
        None,
        occurred_at,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn device_add(
    root: &SigningKey,
    device: &SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
    previous_hash: Sha256Digest,
    sequence: u64,
    occurred_at: i64,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    device_add_with_encryption(
        root,
        device,
        identity_id,
        device_id,
        previous_hash,
        sequence,
        occurred_at,
        DeviceEncryptionPublicKey::try_from([7_u8; 32])?,
    )
}

#[allow(clippy::too_many_arguments)]
fn device_add_with_encryption(
    root: &SigningKey,
    device: &SigningKey,
    identity_id: IdentityId,
    device_id: DeviceId,
    previous_hash: Sha256Digest,
    sequence: u64,
    occurred_at: i64,
    encryption_key: DeviceEncryptionPublicKey,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let root_key = public_key(root)?;
    let device_key = public_key(device)?;
    let certificate_unsigned = UnsignedDeviceCertificateV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        device_id,
        device_key,
        encryption_key,
        root_key,
        UtcMillis::new(occurred_at - 1)?,
    )?;
    let certificate = DeviceCertificateV1::signed(
        certificate_unsigned.clone(),
        signature(
            root,
            &device_certificate_signature_input(certificate_unsigned.signing_digest()?),
        ),
    )?;
    signed_event(
        root,
        identity_id,
        sequence,
        Some(previous_hash),
        occurred_at,
        IdentityLogEventPayloadV1::DeviceAdd { certificate },
    )
}

fn signed_event(
    signer: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous_hash: Option<Sha256Digest>,
    occurred_at: i64,
    payload: IdentityLogEventPayloadV1,
) -> Result<IdentityLogEventV1, Box<dyn Error>> {
    let signer_key = public_key(signer)?;
    let unsigned = UnsignedIdentityLogEventV1::new(
        dtx_identity_log::IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        dtx_wire::SafeUint::new(sequence)?,
        previous_hash,
        UtcMillis::new(occurred_at)?,
        payload,
        signer_key,
    )?;
    Ok(IdentityLogEventV1::signed(
        unsigned.clone(),
        signature(
            signer,
            &identity_log_signature_input(unsigned.signing_digest()?),
        ),
    )?)
}

fn public_key(key: &SigningKey) -> Result<SigningPublicKey, Box<dyn Error>> {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).map_err(Into::into)
}

fn signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}

struct FixedClock(i64);

impl Clock for FixedClock {
    fn now_utc_millis(&self) -> Result<i64, ClockError> {
        Ok(self.0)
    }
}
