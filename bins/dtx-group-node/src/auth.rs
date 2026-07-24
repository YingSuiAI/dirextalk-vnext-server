#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MlsCommitProofAction {
    Submit,
    Query,
}

impl MlsCommitProofAction {
    const fn code(self) -> u64 {
        match self {
            Self::Submit => 1,
            Self::Query => 2,
        }
    }
}

#[derive(Clone)]
struct MlsCommitProof {
    action: MlsCommitProofAction,
    path: String,
    scope: GroupScope,
    submission_id: RequestId,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    request_digest: Sha256Digest,
    idempotency_key_hash: Sha256Digest,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    identity_origin: String,
    signature: [u8; 64],
}

impl MlsCommitProof {
    fn binding_value(&self) -> CanonicalValue {
        numbered_map(vec![
            CanonicalValue::Unsigned(3),
            CanonicalValue::Unsigned(self.action.code()),
            CanonicalValue::Text(self.path.clone()),
            scope_value(self.scope),
            CanonicalValue::Text(self.submission_id.to_string()),
            CanonicalValue::Text(self.actor_identity_id.to_string()),
            CanonicalValue::Text(self.actor_device_id.to_string()),
            self.request_digest.to_canonical_value(),
            self.idempotency_key_hash.to_canonical_value(),
            utc_value(self.issued_at),
            utc_value(self.expires_at),
            CanonicalValue::Text(self.identity_origin.clone()),
        ])
    }

    #[allow(clippy::too_many_arguments)]
    fn verify(
        &self,
        expected_action: MlsCommitProofAction,
        expected_path: &str,
        expected_scope: GroupScope,
        expected_submission_id: RequestId,
        expected_actor_identity_id: IdentityId,
        expected_actor_device_id: DeviceId,
        expected_request_digest: Sha256Digest,
        expected_idempotency_key_hash: Sha256Digest,
        expected_identity_origin: &str,
        now: UtcMillis,
        signing_key: SigningPublicKey,
    ) -> Result<(), GroupPersistenceError> {
        let lifetime = self
            .expires_at
            .get()
            .checked_sub(self.issued_at.get())
            .ok_or(GroupPersistenceError::ActionProofRejected)?;
        if self.action != expected_action
            || self.path != expected_path
            || self.scope != expected_scope
            || self.submission_id != expected_submission_id
            || self.actor_identity_id != expected_actor_identity_id
            || self.actor_device_id != expected_actor_device_id
            || self.request_digest != expected_request_digest
            || self.idempotency_key_hash != expected_idempotency_key_hash
            || self.identity_origin != expected_identity_origin
            || self.issued_at > now
            || now >= self.expires_at
            || !(1..=MAX_ACTION_PROOF_LIFETIME_MS).contains(&lifetime)
        {
            return Err(GroupPersistenceError::ActionProofRejected);
        }
        let binding = encode_deterministic_cbor(&self.binding_value())
            .map_err(|_| GroupPersistenceError::ActionProofRejected)?;
        let digest = Sha256Digest::hash_domain(MLS_COMMIT_FEDERATED_BINDING_HASH_DOMAIN, &binding);
        let mut signature_input = Vec::with_capacity(
            MLS_COMMIT_FEDERATED_PROOF_SIGNATURE_DOMAIN.len() + digest.as_bytes().len(),
        );
        signature_input.extend_from_slice(MLS_COMMIT_FEDERATED_PROOF_SIGNATURE_DOMAIN);
        signature_input.extend_from_slice(digest.as_bytes());
        let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
            .map_err(|_| GroupPersistenceError::ActionProofRejected)?;
        verifying_key
            .verify_strict(&signature_input, &Signature::from_bytes(&self.signature))
            .map_err(|_| GroupPersistenceError::ActionProofRejected)
    }
}

fn parse_mls_commit_proof_header(headers: &HeaderMap) -> Result<MlsCommitProof, GroupFailure> {
    let encoded = single_optional_header(headers, MLS_COMMIT_PROOF_HEADER)?
        .ok_or(GroupFailure::ActionProofInvalid)?;
    if encoded.len() > MAX_GROUP_QUERY_PROOF_BYTES || !encoded.bytes().all(is_base64url_byte) {
        return Err(GroupFailure::InvalidRequest);
    }
    let mut decoded = vec![0_u8; encoded.len()];
    let exact = Base64UrlUnpadded::decode(encoded, &mut decoded)
        .map_err(|_| GroupFailure::InvalidRequest)?;
    if Base64UrlUnpadded::encode_string(exact) != encoded {
        return Err(GroupFailure::InvalidRequest);
    }
    let value = decode_deterministic_cbor(exact).map_err(|_| GroupFailure::InvalidRequest)?;
    let fields = exact_fields(&value, 3)?;
    require_numeric_version(field(fields, 1)?, 3)?;
    let binding = exact_fields(field(fields, 2)?, 12)?;
    require_numeric_version(field(binding, 1)?, 3)?;
    let action = match field(binding, 2)? {
        CanonicalValue::Unsigned(1) => MlsCommitProofAction::Submit,
        CanonicalValue::Unsigned(2) => MlsCommitProofAction::Query,
        _ => return Err(GroupFailure::InvalidRequest),
    };
    Ok(MlsCommitProof {
        action,
        path: parse_text(field(binding, 3)?, 1, 512)?,
        scope: parse_scope_value(field(binding, 4)?)?,
        submission_id: parse_request_id_value(field(binding, 5)?)?,
        actor_identity_id: parse_identity_id_value(field(binding, 6)?)?,
        actor_device_id: parse_device_id_value(field(binding, 7)?)?,
        request_digest: parse_digest(field(binding, 8)?)?,
        idempotency_key_hash: parse_digest(field(binding, 9)?)?,
        issued_at: parse_utc_millis(field(binding, 10)?)?,
        expires_at: parse_utc_millis(field(binding, 11)?)?,
        identity_origin: parse_text(field(binding, 12)?, 10, 512)?,
        signature: parse_exact_bytes(field(fields, 3)?)?,
    })
}

#[derive(Clone)]
struct MlsConfirmationProof {
    path: String,
    scope: GroupScope,
    submission_id: RequestId,
    identity_id: IdentityId,
    device_id: DeviceId,
    body_digest: Sha256Digest,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    identity_origin: String,
    signature: [u8; 64],
}

impl MlsConfirmationProof {
    fn binding_value(&self) -> CanonicalValue {
        numbered_map(vec![
            CanonicalValue::Unsigned(3),
            CanonicalValue::Unsigned(1),
            CanonicalValue::Text(self.path.clone()),
            scope_value(self.scope),
            CanonicalValue::Text(self.submission_id.to_string()),
            CanonicalValue::Text(self.identity_id.to_string()),
            CanonicalValue::Text(self.device_id.to_string()),
            self.body_digest.to_canonical_value(),
            utc_value(self.issued_at),
            utc_value(self.expires_at),
            CanonicalValue::Text(self.identity_origin.clone()),
        ])
    }

    #[allow(clippy::too_many_arguments)]
    fn verify(
        &self,
        expected_path: &str,
        expected_scope: GroupScope,
        expected_submission_id: RequestId,
        expected_body_digest: Sha256Digest,
        now: UtcMillis,
        signing_key: SigningPublicKey,
    ) -> Result<(), GroupPersistenceError> {
        let lifetime = self
            .expires_at
            .get()
            .checked_sub(self.issued_at.get())
            .ok_or(GroupPersistenceError::ActionProofRejected)?;
        if self.path != expected_path
            || self.scope != expected_scope
            || self.submission_id != expected_submission_id
            || self.body_digest != expected_body_digest
            || self.issued_at > now
            || now >= self.expires_at
            || !(1..=MAX_ACTION_PROOF_LIFETIME_MS).contains(&lifetime)
        {
            return Err(GroupPersistenceError::ActionProofRejected);
        }
        let binding = encode_deterministic_cbor(&self.binding_value())
            .map_err(|_| GroupPersistenceError::ActionProofRejected)?;
        let digest = Sha256Digest::hash_domain(MLS_CONFIRMATION_BINDING_HASH_DOMAIN, &binding);
        let mut signature_input = Vec::with_capacity(
            MLS_CONFIRMATION_PROOF_SIGNATURE_DOMAIN.len() + digest.as_bytes().len(),
        );
        signature_input.extend_from_slice(MLS_CONFIRMATION_PROOF_SIGNATURE_DOMAIN);
        signature_input.extend_from_slice(digest.as_bytes());
        let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
            .map_err(|_| GroupPersistenceError::ActionProofRejected)?;
        verifying_key
            .verify_strict(&signature_input, &Signature::from_bytes(&self.signature))
            .map_err(|_| GroupPersistenceError::ActionProofRejected)
    }
}

fn parse_mls_confirmation_proof_header(
    headers: &HeaderMap,
) -> Result<MlsConfirmationProof, GroupFailure> {
    let encoded = single_optional_header(headers, MLS_CONFIRMATION_PROOF_HEADER)?
        .ok_or(GroupFailure::ActionProofInvalid)?;
    if encoded.len() > MAX_GROUP_QUERY_PROOF_BYTES || !encoded.bytes().all(is_base64url_byte) {
        return Err(GroupFailure::InvalidRequest);
    }
    let mut decoded = vec![0_u8; encoded.len()];
    let exact = Base64UrlUnpadded::decode(encoded, &mut decoded)
        .map_err(|_| GroupFailure::InvalidRequest)?;
    if Base64UrlUnpadded::encode_string(exact) != encoded {
        return Err(GroupFailure::InvalidRequest);
    }
    let value = decode_deterministic_cbor(exact).map_err(|_| GroupFailure::InvalidRequest)?;
    let fields = exact_fields(&value, 3)?;
    require_numeric_version(field(fields, 1)?, 3)?;
    let binding = exact_fields(field(fields, 2)?, 11)?;
    require_numeric_version(field(binding, 1)?, 3)?;
    if field(binding, 2)? != &CanonicalValue::Unsigned(1) {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(MlsConfirmationProof {
        path: parse_text(field(binding, 3)?, 1, 512)?,
        scope: parse_scope_value(field(binding, 4)?)?,
        submission_id: parse_request_id_value(field(binding, 5)?)?,
        identity_id: parse_identity_id_value(field(binding, 6)?)?,
        device_id: parse_device_id_value(field(binding, 7)?)?,
        body_digest: parse_digest(field(binding, 8)?)?,
        issued_at: parse_utc_millis(field(binding, 9)?)?,
        expires_at: parse_utc_millis(field(binding, 10)?)?,
        identity_origin: parse_text(field(binding, 11)?, 10, 512)?,
        signature: parse_exact_bytes(field(fields, 3)?)?,
    })
}

#[derive(Clone)]
struct GroupQueryProof {
    action: GroupQueryAction,
    canonical_target: String,
    scope: GroupScope,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    identity_origin: String,
    signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GroupQueryAction {
    ListJoinRequests,
    ListMlsCommits,
}

impl GroupQueryAction {
    const fn code(self) -> u64 {
        match self {
            Self::ListJoinRequests => 1,
            Self::ListMlsCommits => 2,
        }
    }
}

impl GroupQueryProof {
    fn binding_value(&self) -> CanonicalValue {
        numbered_map(vec![
            CanonicalValue::Unsigned(1),
            CanonicalValue::Unsigned(self.action.code()),
            CanonicalValue::Text(self.canonical_target.clone()),
            scope_value(self.scope),
            CanonicalValue::Text(self.actor_identity_id.to_string()),
            CanonicalValue::Text(self.actor_device_id.to_string()),
            utc_value(self.issued_at),
            utc_value(self.expires_at),
            CanonicalValue::Text(self.identity_origin.clone()),
        ])
    }

    fn verify(
        &self,
        expected_action: GroupQueryAction,
        expected_target: &str,
        expected_scope: GroupScope,
        now: UtcMillis,
        signing_key: SigningPublicKey,
    ) -> Result<(), GroupPersistenceError> {
        let lifetime = self
            .expires_at
            .get()
            .checked_sub(self.issued_at.get())
            .ok_or(GroupPersistenceError::ActionProofRejected)?;
        if self.action != expected_action
            || self.canonical_target != expected_target
            || self.scope != expected_scope
            || self.issued_at > now
            || now >= self.expires_at
            || !(1..=MAX_ACTION_PROOF_LIFETIME_MS).contains(&lifetime)
        {
            return Err(GroupPersistenceError::ActionProofRejected);
        }
        let binding = encode_deterministic_cbor(&self.binding_value())
            .map_err(|_| GroupPersistenceError::ActionProofRejected)?;
        let digest = Sha256Digest::hash_domain(GROUP_QUERY_BINDING_HASH_DOMAIN, &binding);
        let mut signature_input =
            Vec::with_capacity(GROUP_QUERY_SIGNATURE_DOMAIN.len() + digest.as_bytes().len());
        signature_input.extend_from_slice(GROUP_QUERY_SIGNATURE_DOMAIN);
        signature_input.extend_from_slice(digest.as_bytes());
        let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
            .map_err(|_| GroupPersistenceError::ActionProofRejected)?;
        verifying_key
            .verify_strict(&signature_input, &Signature::from_bytes(&self.signature))
            .map_err(|_| GroupPersistenceError::ActionProofRejected)
    }
}

fn parse_group_query_proof_header(headers: &HeaderMap) -> Result<GroupQueryProof, GroupFailure> {
    let encoded = single_optional_header(headers, GROUP_QUERY_PROOF_HEADER)?
        .ok_or(GroupFailure::ActionProofInvalid)?;
    if encoded.len() > MAX_GROUP_QUERY_PROOF_BYTES || !encoded.bytes().all(is_base64url_byte) {
        return Err(GroupFailure::InvalidRequest);
    }
    let mut decoded = vec![0_u8; encoded.len()];
    let exact = Base64UrlUnpadded::decode(encoded, &mut decoded)
        .map_err(|_| GroupFailure::InvalidRequest)?;
    if Base64UrlUnpadded::encode_string(exact) != encoded {
        return Err(GroupFailure::InvalidRequest);
    }
    let value = decode_deterministic_cbor(exact).map_err(|_| GroupFailure::InvalidRequest)?;
    let fields = exact_fields(&value, 3)?;
    if field(fields, 1)? != &CanonicalValue::Unsigned(1) {
        return Err(GroupFailure::InvalidRequest);
    }
    let binding = exact_fields(field(fields, 2)?, 9)?;
    if field(binding, 1)? != &CanonicalValue::Unsigned(1) {
        return Err(GroupFailure::InvalidRequest);
    }
    let action = match field(binding, 2)? {
        CanonicalValue::Unsigned(1) => GroupQueryAction::ListJoinRequests,
        CanonicalValue::Unsigned(2) => GroupQueryAction::ListMlsCommits,
        _ => return Err(GroupFailure::InvalidRequest),
    };
    Ok(GroupQueryProof {
        action,
        canonical_target: parse_text(field(binding, 3)?, 1, 768)?,
        scope: parse_scope_value(field(binding, 4)?)?,
        actor_identity_id: parse_identity_id_value(field(binding, 5)?)?,
        actor_device_id: parse_device_id_value(field(binding, 6)?)?,
        issued_at: parse_utc_millis(field(binding, 7)?)?,
        expires_at: parse_utc_millis(field(binding, 8)?)?,
        identity_origin: parse_text(field(binding, 9)?, 10, 512)?,
        signature: parse_exact_bytes(field(fields, 3)?)?,
    })
}

#[derive(Clone)]
struct ActionProof {
    action: GroupAction,
    path: String,
    scope: GroupScope,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    idempotency_key_hash: Sha256Digest,
    business_fields_digest: Sha256Digest,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    identity_origin: Option<String>,
    signature: [u8; 64],
}

impl ActionProof {
    fn binding_value(&self) -> CanonicalValue {
        let mut fields = vec![
            CanonicalValue::Unsigned(if self.identity_origin.is_some() { 2 } else { 1 }),
            CanonicalValue::Unsigned(self.action.code()),
            CanonicalValue::Text(self.path.clone()),
            scope_value(self.scope),
            CanonicalValue::Text(self.actor_identity_id.to_string()),
            CanonicalValue::Text(self.actor_device_id.to_string()),
            CanonicalValue::Bytes(self.idempotency_key_hash.as_bytes().to_vec()),
            CanonicalValue::Bytes(self.business_fields_digest.as_bytes().to_vec()),
            utc_value(self.issued_at),
            utc_value(self.expires_at),
        ];
        if let Some(origin) = &self.identity_origin {
            fields.push(CanonicalValue::Text(origin.clone()));
        }
        numbered_map(fields)
    }

    fn binding_digest(&self) -> Result<Sha256Digest, GroupFailure> {
        canonical_hash(self.binding_hash_domain(), &self.binding_value())
    }

    const fn binding_hash_domain(&self) -> &'static [u8] {
        if self.identity_origin.is_some() {
            FEDERATED_ACTION_BINDING_HASH_DOMAIN
        } else {
            ACTION_BINDING_HASH_DOMAIN
        }
    }

    const fn signature_domain(&self) -> &'static [u8] {
        if self.identity_origin.is_some() {
            FEDERATED_ACTION_SIGNATURE_DOMAIN
        } else {
            ACTION_SIGNATURE_DOMAIN
        }
    }

    #[allow(clippy::too_many_arguments)] // All independently bound proof coordinates are intentionally visible at the verification call site.
    fn verify(
        &self,
        expected_action: GroupAction,
        expected_path: &str,
        expected_scope: GroupScope,
        expected_idempotency_key_hash: Sha256Digest,
        expected_business_fields_digest: Sha256Digest,
        now: UtcMillis,
        signing_key: SigningPublicKey,
    ) -> Result<(), GroupPersistenceError> {
        let lifetime = self
            .expires_at
            .get()
            .checked_sub(self.issued_at.get())
            .ok_or(GroupPersistenceError::ActionProofRejected)?;
        if self.action != expected_action
            || self.path != expected_path
            || self.scope != expected_scope
            || self.idempotency_key_hash != expected_idempotency_key_hash
            || self.business_fields_digest != expected_business_fields_digest
            || self.issued_at > now
            || now >= self.expires_at
            || !(1..=MAX_ACTION_PROOF_LIFETIME_MS).contains(&lifetime)
        {
            return Err(GroupPersistenceError::ActionProofRejected);
        }
        let binding = encode_deterministic_cbor(&self.binding_value())
            .map_err(|_| GroupPersistenceError::ActionProofRejected)?;
        let binding_digest = Sha256Digest::hash_domain(self.binding_hash_domain(), &binding);
        let mut signature_input =
            Vec::with_capacity(self.signature_domain().len() + binding_digest.as_bytes().len());
        signature_input.extend_from_slice(self.signature_domain());
        signature_input.extend_from_slice(binding_digest.as_bytes());
        let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
            .map_err(|_| GroupPersistenceError::ActionProofRejected)?;
        verifying_key
            .verify_strict(&signature_input, &Signature::from_bytes(&self.signature))
            .map_err(|_| GroupPersistenceError::ActionProofRejected)
    }
}

struct ReceiptQueryProof {
    path: String,
    scope: GroupScope,
    command_id: MembershipCommandId,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    issued_at: UtcMillis,
    expires_at: UtcMillis,
    identity_origin: String,
    signature: [u8; 64],
}

impl ReceiptQueryProof {
    fn binding_value(&self) -> CanonicalValue {
        numbered_map(vec![
            CanonicalValue::Unsigned(2),
            CanonicalValue::Unsigned(8),
            CanonicalValue::Text(self.path.clone()),
            scope_value(self.scope),
            CanonicalValue::Text(self.command_id.request_id().to_string()),
            CanonicalValue::Text(self.actor_identity_id.to_string()),
            CanonicalValue::Text(self.actor_device_id.to_string()),
            utc_value(self.issued_at),
            utc_value(self.expires_at),
            CanonicalValue::Text(self.identity_origin.clone()),
        ])
    }

    fn verify(
        &self,
        expected_path: &str,
        expected_scope: GroupScope,
        expected_command_id: MembershipCommandId,
        now: UtcMillis,
        signing_key: SigningPublicKey,
    ) -> Result<(), GroupFailure> {
        let lifetime = self
            .expires_at
            .get()
            .checked_sub(self.issued_at.get())
            .ok_or(GroupFailure::ActionProofInvalid)?;
        if self.path != expected_path
            || self.scope != expected_scope
            || self.command_id != expected_command_id
            || self.issued_at > now
            || now >= self.expires_at
            || !(1..=MAX_ACTION_PROOF_LIFETIME_MS).contains(&lifetime)
        {
            return Err(GroupFailure::ActionProofInvalid);
        }
        let binding = encode_deterministic_cbor(&self.binding_value())
            .map_err(|_| GroupFailure::ActionProofInvalid)?;
        let digest = Sha256Digest::hash_domain(RECEIPT_QUERY_BINDING_HASH_DOMAIN, &binding);
        let mut signature_input =
            Vec::with_capacity(RECEIPT_QUERY_SIGNATURE_DOMAIN.len() + digest.as_bytes().len());
        signature_input.extend_from_slice(RECEIPT_QUERY_SIGNATURE_DOMAIN);
        signature_input.extend_from_slice(digest.as_bytes());
        let verifying_key = VerifyingKey::from_bytes(signing_key.as_bytes())
            .map_err(|_| GroupFailure::ActionProofInvalid)?;
        verifying_key
            .verify_strict(&signature_input, &Signature::from_bytes(&self.signature))
            .map_err(|_| GroupFailure::ActionProofInvalid)
    }
}

fn parse_receipt_query_proof_header(
    headers: &HeaderMap,
) -> Result<Option<ReceiptQueryProof>, GroupFailure> {
    let Some(encoded) = single_optional_header(headers, RECEIPT_QUERY_PROOF_HEADER)? else {
        return Ok(None);
    };
    if encoded.len() > 1_024 || !encoded.bytes().all(is_base64url_byte) {
        return Err(GroupFailure::InvalidRequest);
    }
    let mut decoded = vec![0_u8; encoded.len()];
    let exact = Base64UrlUnpadded::decode(encoded, &mut decoded)
        .map_err(|_| GroupFailure::InvalidRequest)?;
    let value = decode_deterministic_cbor(exact).map_err(|_| GroupFailure::InvalidRequest)?;
    let fields = exact_fields(&value, 3)?;
    if parse_proof_version(field(fields, 1)?)? != 2 {
        return Err(GroupFailure::InvalidRequest);
    }
    let binding = exact_fields(field(fields, 2)?, 10)?;
    if parse_proof_version(field(binding, 1)?)? != 2
        || field(binding, 2)? != &CanonicalValue::Unsigned(8)
    {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(Some(ReceiptQueryProof {
        path: parse_text(field(binding, 3)?, 1, 512)?,
        scope: parse_scope_value(field(binding, 4)?)?,
        command_id: MembershipCommandId::new(parse_request_id(&parse_text(
            field(binding, 5)?,
            36,
            36,
        )?)?),
        actor_identity_id: parse_identity_id_value(field(binding, 6)?)?,
        actor_device_id: parse_device_id_value(field(binding, 7)?)?,
        issued_at: parse_utc_millis(field(binding, 8)?)?,
        expires_at: parse_utc_millis(field(binding, 9)?)?,
        identity_origin: parse_text(field(binding, 10)?, 10, 512)?,
        signature: parse_exact_bytes(field(fields, 3)?)?,
    }))
}

fn parse_action_proof(value: &CanonicalValue) -> Result<ActionProof, GroupFailure> {
    let fields = exact_fields(value, 3)?;
    let proof_version = parse_proof_version(field(fields, 1)?)?;
    let binding = exact_fields(field(fields, 2)?, if proof_version == 2 { 11 } else { 10 })?;
    if parse_proof_version(field(binding, 1)?)? != proof_version {
        return Err(GroupFailure::InvalidRequest);
    }
    Ok(ActionProof {
        action: GroupAction::parse(field(binding, 2)?)?,
        path: parse_text(field(binding, 3)?, 1, 512)?,
        scope: parse_scope_value(field(binding, 4)?)?,
        actor_identity_id: parse_identity_id_value(field(binding, 5)?)?,
        actor_device_id: parse_device_id_value(field(binding, 6)?)?,
        idempotency_key_hash: parse_digest(field(binding, 7)?)?,
        business_fields_digest: parse_digest(field(binding, 8)?)?,
        issued_at: parse_utc_millis(field(binding, 9)?)?,
        expires_at: parse_utc_millis(field(binding, 10)?)?,
        identity_origin: if proof_version == 2 {
            Some(parse_text(field(binding, 11)?, 10, 512)?)
        } else {
            None
        },
        signature: parse_exact_bytes(field(fields, 3)?)?,
    })
}

fn parse_proof_version(value: &CanonicalValue) -> Result<u64, GroupFailure> {
    match value {
        CanonicalValue::Unsigned(version @ (1 | 2)) => Ok(*version),
        _ => Err(GroupFailure::InvalidRequest),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GroupAction {
    CreateGroup,
    GrantAdmin,
    RevokeAdmin,
    IssueInvite,
    RevokeInvite,
    RequestJoin,
    ApproveJoin,
}

impl GroupAction {
    const fn code(self) -> u64 {
        match self {
            Self::CreateGroup => 1,
            Self::GrantAdmin => 2,
            Self::RevokeAdmin => 3,
            Self::IssueInvite => 4,
            Self::RevokeInvite => 5,
            Self::RequestJoin => 6,
            Self::ApproveJoin => 7,
        }
    }

    fn parse(value: &CanonicalValue) -> Result<Self, GroupFailure> {
        match value {
            CanonicalValue::Unsigned(1) => Ok(Self::CreateGroup),
            CanonicalValue::Unsigned(2) => Ok(Self::GrantAdmin),
            CanonicalValue::Unsigned(3) => Ok(Self::RevokeAdmin),
            CanonicalValue::Unsigned(4) => Ok(Self::IssueInvite),
            CanonicalValue::Unsigned(5) => Ok(Self::RevokeInvite),
            CanonicalValue::Unsigned(6) => Ok(Self::RequestJoin),
            CanonicalValue::Unsigned(7) => Ok(Self::ApproveJoin),
            _ => Err(GroupFailure::InvalidRequest),
        }
    }
}
