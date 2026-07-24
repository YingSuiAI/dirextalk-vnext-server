fn action_proof(
    action: u64,
    active: &ActiveDevice,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    signable: &CanonicalValue,
    issued_at: i64,
) -> Result<CanonicalValue, Box<dyn Error>> {
    let expires_at = issued_at
        .checked_add(120_000)
        .ok_or("action proof expiry overflow")?;
    let idempotency_key_hash =
        Sha256Digest::hash_domain(IDEMPOTENCY_HASH_DOMAIN, idempotency_key.as_bytes());
    let business_fields_digest = Sha256Digest::hash_domain(
        BUSINESS_FIELDS_HASH_DOMAIN,
        &encode_deterministic_cbor(signable)?,
    );
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(action),
        CanonicalValue::Text(path.to_owned()),
        scope_value(scope),
        CanonicalValue::Text(active.identity_id.to_string()),
        CanonicalValue::Text(active.device_id.to_string()),
        CanonicalValue::Bytes(idempotency_key_hash.as_bytes().to_vec()),
        CanonicalValue::Bytes(business_fields_digest.as_bytes().to_vec()),
        utc_value(issued_at),
        utc_value(expires_at),
    ]);
    let binding_digest = Sha256Digest::hash_domain(
        ACTION_BINDING_HASH_DOMAIN,
        &encode_deterministic_cbor(&binding)?,
    );
    let mut signature_input = ACTION_SIGNATURE_DOMAIN.to_vec();
    signature_input.extend_from_slice(binding_digest.as_bytes());
    let signature = active.device.sign(&signature_input).to_bytes();
    Ok(numbered_map(vec![
        CanonicalValue::Unsigned(1),
        binding,
        CanonicalValue::Bytes(signature.to_vec()),
    ]))
}

#[allow(clippy::too_many_arguments)]
fn federated_action_proof(
    action: u64,
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    idempotency_key: &str,
    signable: &CanonicalValue,
    issued_at: i64,
) -> Result<CanonicalValue, Box<dyn Error>> {
    let expires_at = issued_at
        .checked_add(120_000)
        .ok_or("federated action proof expiry overflow")?;
    let idempotency_key_hash =
        Sha256Digest::hash_domain(IDEMPOTENCY_HASH_DOMAIN, idempotency_key.as_bytes());
    let business_fields_digest = Sha256Digest::hash_domain(
        BUSINESS_FIELDS_HASH_DOMAIN,
        &encode_deterministic_cbor(signable)?,
    );
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Unsigned(action),
        CanonicalValue::Text(path.to_owned()),
        scope_value(scope),
        CanonicalValue::Text(active.identity_id.to_string()),
        CanonicalValue::Text(active.device_id.to_string()),
        CanonicalValue::Bytes(idempotency_key_hash.as_bytes().to_vec()),
        CanonicalValue::Bytes(business_fields_digest.as_bytes().to_vec()),
        utc_value(issued_at),
        utc_value(expires_at),
        CanonicalValue::Text(identity_origin.to_owned()),
    ]);
    let binding_digest = Sha256Digest::hash_domain(
        FEDERATED_ACTION_BINDING_HASH_DOMAIN,
        &encode_deterministic_cbor(&binding)?,
    );
    let mut signature_input = FEDERATED_ACTION_SIGNATURE_DOMAIN.to_vec();
    signature_input.extend_from_slice(binding_digest.as_bytes());
    let signature = active.device.sign(&signature_input).to_bytes();
    Ok(numbered_map(vec![
        CanonicalValue::Unsigned(2),
        binding,
        CanonicalValue::Bytes(signature.to_vec()),
    ]))
}

fn receipt_query_proof(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    path: &str,
    command_id: RequestId,
    issued_at: i64,
) -> Result<String, Box<dyn Error>> {
    let expires_at = issued_at
        .checked_add(120_000)
        .ok_or("receipt query proof expiry overflow")?;
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        CanonicalValue::Unsigned(8),
        CanonicalValue::Text(path.to_owned()),
        scope_value(scope),
        CanonicalValue::Text(command_id.to_string()),
        CanonicalValue::Text(active.identity_id.to_string()),
        CanonicalValue::Text(active.device_id.to_string()),
        utc_value(issued_at),
        utc_value(expires_at),
        CanonicalValue::Text(identity_origin.to_owned()),
    ]);
    let binding_digest = Sha256Digest::hash_domain(
        b"dirextalk.membership-receipt-query-binding.v2\0",
        &encode_deterministic_cbor(&binding)?,
    );
    let mut signature_input = b"dirextalk.membership-receipt-query-signature.v2\0".to_vec();
    signature_input.extend_from_slice(binding_digest.as_bytes());
    let proof = numbered_map(vec![
        CanonicalValue::Unsigned(2),
        binding,
        CanonicalValue::Bytes(active.device.sign(&signature_input).to_bytes().to_vec()),
    ]);
    Ok(Base64UrlUnpadded::encode_string(
        &encode_deterministic_cbor(&proof)?,
    ))
}

fn group_query_proof(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    canonical_target: &str,
    issued_at: i64,
) -> Result<String, Box<dyn Error>> {
    group_query_proof_for_action(
        active,
        identity_origin,
        scope,
        canonical_target,
        1,
        issued_at,
    )
}

fn group_query_proof_for_action(
    active: &ActiveDevice,
    identity_origin: &str,
    scope: GroupScope,
    canonical_target: &str,
    action: u64,
    issued_at: i64,
) -> Result<String, Box<dyn Error>> {
    let expires_at = issued_at
        .checked_add(120_000)
        .ok_or("group query proof expiry overflow")?;
    let binding = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        CanonicalValue::Unsigned(action),
        CanonicalValue::Text(canonical_target.to_owned()),
        scope_value(scope),
        CanonicalValue::Text(active.identity_id.to_string()),
        CanonicalValue::Text(active.device_id.to_string()),
        utc_value(issued_at),
        utc_value(expires_at),
        CanonicalValue::Text(identity_origin.to_owned()),
    ]);
    let digest = Sha256Digest::hash_domain(
        GROUP_QUERY_BINDING_HASH_DOMAIN,
        &encode_deterministic_cbor(&binding)?,
    );
    let mut signature_input = GROUP_QUERY_SIGNATURE_DOMAIN.to_vec();
    signature_input.extend_from_slice(digest.as_bytes());
    let proof = numbered_map(vec![
        CanonicalValue::Unsigned(1),
        binding,
        CanonicalValue::Bytes(active.device.sign(&signature_input).to_bytes().to_vec()),
    ]);
    Ok(Base64UrlUnpadded::encode_string(
        &encode_deterministic_cbor(&proof)?,
    ))
}

async fn send_mutation(
    app: axum::Router,
    method: &str,
    path: &str,
    content_type: &str,
    idempotency_key: &str,
    active: &ActiveDevice,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, content_type)
            .header("idempotency-key", idempotency_key)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(active.session_id, active.session_secret),
            )
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_mutation(
    app: axum::Router,
    method: &str,
    path: &str,
    content_type: &str,
    idempotency_key: &str,
    identity_origin: &str,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, content_type)
            .header("idempotency-key", idempotency_key)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_confirmation(
    app: axum::Router,
    path: &str,
    identity_origin: &str,
    proof: String,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, MLS_CONFIRMATION_V3_CONTENT_TYPE)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .header(MLS_CONFIRMATION_PROOF_HEADER, proof)
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_mls_commit(
    app: axum::Router,
    path: &str,
    idempotency_key: &str,
    identity_origin: &str,
    proof: String,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, MLS_COMMIT_V3_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .header(MLS_COMMIT_PROOF_HEADER, proof)
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_mls_commit_v5(
    app: axum::Router,
    path: &str,
    idempotency_key: &str,
    identity_origin: &str,
    proof: String,
    body: Vec<u8>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, MLS_COMMIT_V5_CONTENT_TYPE)
            .header("idempotency-key", idempotency_key)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .header(MLS_COMMIT_PROOF_HEADER, proof)
            .body(Body::from(body))?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_mls_receipt_query(
    app: axum::Router,
    path: &str,
    identity_origin: &str,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(path)
            .header(header::ACCEPT, MLS_COMMIT_RECEIPT_V3_CONTENT_TYPE)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .header(MLS_COMMIT_PROOF_HEADER, proof)
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_mls_receipt_query_v5(
    app: axum::Router,
    path: &str,
    identity_origin: &str,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(path)
            .header(header::ACCEPT, MLS_COMMIT_RECEIPT_V5_CONTENT_TYPE)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .header(MLS_COMMIT_PROOF_HEADER, proof)
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
}

async fn send_federated_get(
    app: axum::Router,
    path: &str,
    identity_origin: &str,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(path)
            .header(IDENTITY_ORIGIN_HEADER, identity_origin)
            .header(RECEIPT_QUERY_PROOF_HEADER, proof)
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
}

async fn send_group_query(
    app: axum::Router,
    target: &str,
    active: &ActiveDevice,
    identity_origin: &str,
    federated: bool,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let mut request = Request::builder()
        .method("GET")
        .uri(target)
        .header(GROUP_QUERY_PROOF_HEADER, proof);
    if federated {
        request = request.header(IDENTITY_ORIGIN_HEADER, identity_origin);
    } else {
        request = request.header(
            header::AUTHORIZATION,
            device_session_authorization(active.session_id, active.session_secret),
        );
    }
    app.oneshot(request.body(Body::empty())?)
        .await
        .map_err(Into::into)
}

async fn send_local_commit_feed(
    app: axum::Router,
    target: &str,
    active: &ActiveDevice,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(target)
            .header(header::ACCEPT, MLS_COMMIT_FEED_CONTENT_TYPE)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(active.session_id, active.session_secret),
            )
            .header(GROUP_QUERY_PROOF_HEADER, proof)
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
}

async fn send_local_commit_feed_v2(
    app: axum::Router,
    target: &str,
    active: &ActiveDevice,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(target)
            .header(header::ACCEPT, MLS_COMMIT_FEED_V2_CONTENT_TYPE)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(active.session_id, active.session_secret),
            )
            .header(GROUP_QUERY_PROOF_HEADER, proof)
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
}

async fn send_local_commit_feed_v3(
    app: axum::Router,
    target: &str,
    active: &ActiveDevice,
    proof: String,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(target)
            .header(header::ACCEPT, MLS_COMMIT_FEED_V3_CONTENT_TYPE)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(active.session_id, active.session_secret),
            )
            .header(GROUP_QUERY_PROOF_HEADER, proof)
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
}

#[allow(clippy::too_many_arguments)]
async fn send_network_mutation(
    client: &reqwest::Client,
    group_origin: &str,
    method: reqwest::Method,
    path: &str,
    content_type: &str,
    idempotency_key: &str,
    authorization: Option<String>,
    identity_origin: Option<&str>,
    body: Vec<u8>,
) -> Result<reqwest::Response, Box<dyn Error>> {
    if authorization.is_some() && identity_origin.is_some() {
        return Err(
            "network acceptance request cannot mix local and federated authentication".into(),
        );
    }
    let mut request = client
        .request(method, format!("{group_origin}{path}"))
        .header(header::CONTENT_TYPE.as_str(), content_type)
        .header("idempotency-key", idempotency_key)
        .body(body);
    if let Some(authorization) = authorization {
        request = request.header(header::AUTHORIZATION.as_str(), authorization);
    }
    if let Some(identity_origin) = identity_origin {
        request = request.header(IDENTITY_ORIGIN_HEADER, identity_origin);
    }
    Ok(request.send().await?)
}

async fn send_network_federated_confirmation(
    client: &reqwest::Client,
    group_origin: &str,
    path: &str,
    identity_origin: &str,
    proof: String,
    body: Vec<u8>,
) -> Result<reqwest::Response, Box<dyn Error>> {
    Ok(client
        .post(format!("{group_origin}{path}"))
        .header(
            header::CONTENT_TYPE.as_str(),
            MLS_CONFIRMATION_V3_CONTENT_TYPE,
        )
        .header(IDENTITY_ORIGIN_HEADER, identity_origin)
        .header(MLS_CONFIRMATION_PROOF_HEADER, proof)
        .body(body)
        .send()
        .await?)
}

async fn send_network_receipt_query(
    client: &reqwest::Client,
    group_origin: &str,
    path: &str,
    identity_origin: &str,
    proof: String,
) -> Result<reqwest::Response, Box<dyn Error>> {
    Ok(client
        .get(format!("{group_origin}{path}"))
        .header(header::ACCEPT.as_str(), MEMBERSHIP_RECEIPT_V2_CONTENT_TYPE)
        .header(IDENTITY_ORIGIN_HEADER, identity_origin)
        .header(RECEIPT_QUERY_PROOF_HEADER, proof)
        .send()
        .await?)
}

async fn send_get(
    app: axum::Router,
    path: &str,
    active: &ActiveDevice,
) -> Result<axum::response::Response, Box<dyn Error>> {
    app.oneshot(
        Request::builder()
            .method("GET")
            .uri(path)
            .header(
                header::AUTHORIZATION,
                device_session_authorization(active.session_id, active.session_secret),
            )
            .body(Body::empty())?,
    )
    .await
    .map_err(Into::into)
}

fn control_command(
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    operation: GroupControlOperation,
    seed: &[u8],
) -> GroupControlCommand {
    GroupControlCommand::new(
        RequestId::new(),
        Sha256Digest::hash_domain(b"test-group-control-key\0", seed),
        actor_identity_id,
        actor_device_id,
        operation,
        Sha256Digest::hash_domain(b"test-group-control-request\0", seed),
        Sha256Digest::hash_domain(b"test-group-control-binding\0", seed),
    )
}

fn identity_from_seed(seed: u8) -> Result<IdentityId, Box<dyn Error>> {
    let key = SigningKey::from_bytes(&[seed; 32]);
    Ok(IdentityId::derive(public_key(&key)?.as_domain_key()))
}
