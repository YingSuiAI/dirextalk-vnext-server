use dtx_domain::{DeviceId, IdentityId};
use dtx_identity_persistence::{
    DeviceSessionCredential, DeviceSessionRepository, IdentityPersistenceError,
    lock_and_load_active_snapshot,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, Ed25519Signature, MAX_SAFE_UINT, Sha256Digest,
    SigningPublicKey, UtcMillis, encode_deterministic_cbor,
};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    MailboxOperationOutcome, MailboxPersistenceError, MailboxPgStore,
    repository::finish_transaction,
};

const GRANT_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.device-history-grant.v1\0";
const NEW_DEVICE_POP_SIGNATURE_DOMAIN: &[u8] = b"dirextalk.device-history-grant-pop.v1\0";
const GRANT_DIGEST_DOMAIN: &[u8] = b"dirextalk.device-history-grant-digest.v1\0";
const AUTHORITY_ID_DOMAIN: &[u8] = b"dirextalk.device-history-authority-id.v1\0";

/// Authority that signs a V37 device-history grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceHistoryAuthorization {
    ActiveDevice,
    RecoveryKey,
    RootKey,
}

impl DeviceHistoryAuthorization {
    const fn wire_kind(self) -> u64 {
        match self {
            Self::ActiveDevice => 1,
            Self::RecoveryKey => 2,
            Self::RootKey => 3,
        }
    }

    const fn database_kind(self) -> &'static str {
        match self {
            Self::ActiveDevice => "grantor_device",
            Self::RecoveryKey => "recovery",
            Self::RootKey => "root",
        }
    }
}

/// Exact V37 active-device history authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceHistoryGrantCommand {
    identity_id: IdentityId,
    new_device_id: DeviceId,
    identity_head: Sha256Digest,
    earliest_sequence: u64,
    encrypted_history_digest: Sha256Digest,
    authorization: DeviceHistoryAuthorization,
    authorizer_id: String,
    new_device_pop_digest: Sha256Digest,
    granted_at: UtcMillis,
    signature: Ed25519Signature,
    new_device_pop_signature: Ed25519Signature,
    exact_bytes: Vec<u8>,
}

impl DeviceHistoryGrantCommand {
    /// Builds an exact canonical active-device history grant.
    ///
    /// # Errors
    ///
    /// Rejects an invalid sequence or non-canonical encoded request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        identity_id: IdentityId,
        new_device_id: DeviceId,
        identity_head: Sha256Digest,
        earliest_sequence: u64,
        encrypted_history_digest: Sha256Digest,
        authorization: DeviceHistoryAuthorization,
        authorizer_id: String,
        new_device_pop_digest: Sha256Digest,
        granted_at: UtcMillis,
        signature: Ed25519Signature,
        new_device_pop_signature: Ed25519Signature,
        exact_bytes: Vec<u8>,
    ) -> Result<Self, MailboxPersistenceError> {
        if earliest_sequence == 0 || earliest_sequence > MAX_SAFE_UINT {
            return Err(MailboxPersistenceError::InvalidCommand(
                "history grant earliest sequence",
            ));
        }
        let command = Self {
            identity_id,
            new_device_id,
            identity_head,
            earliest_sequence,
            encrypted_history_digest,
            authorization,
            authorizer_id,
            new_device_pop_digest,
            granted_at,
            signature,
            new_device_pop_signature,
            exact_bytes,
        };
        if command.exact_bytes != command.canonical_full()? {
            return Err(MailboxPersistenceError::InvalidCommand(
                "history grant canonical bytes",
            ));
        }
        Ok(command)
    }

    fn unsigned_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Text(self.identity_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Text(self.new_device_id.to_string()),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.identity_head.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Unsigned(self.earliest_sequence),
            ),
            (
                CanonicalValue::Unsigned(6),
                self.encrypted_history_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(7),
                CanonicalValue::Unsigned(self.authorization.wire_kind()),
            ),
            (
                CanonicalValue::Unsigned(8),
                CanonicalValue::Text(self.authorizer_id.clone()),
            ),
            (
                CanonicalValue::Unsigned(9),
                self.new_device_pop_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(10),
                self.granted_at.to_canonical_value(),
            ),
        ])
    }

    fn canonical_unsigned(&self) -> Result<Vec<u8>, MailboxPersistenceError> {
        encode_deterministic_cbor(&self.unsigned_value())
            .map_err(|_| MailboxPersistenceError::InvalidCommand("history grant encoding"))
    }

    fn canonical_full(&self) -> Result<Vec<u8>, MailboxPersistenceError> {
        let CanonicalValue::Map(mut fields) = self.unsigned_value() else {
            unreachable!()
        };
        fields.push((
            CanonicalValue::Unsigned(11),
            self.signature.to_canonical_value(),
        ));
        fields.push((
            CanonicalValue::Unsigned(12),
            self.new_device_pop_signature.to_canonical_value(),
        ));
        encode_deterministic_cbor(&CanonicalValue::Map(fields))
            .map_err(|_| MailboxPersistenceError::InvalidCommand("history grant encoding"))
    }
}

impl crate::MailboxRepository {
    /// Verifies both current grantor authority and new-device proof of possession,
    /// then stores no key material—only the canonical signed authorization.
    ///
    /// # Errors
    ///
    /// Rejects invalid/revoked sessions, stale identity heads, invalid proofs,
    /// conflicting grants, and durable storage failures.
    pub async fn grant_device_history(
        self,
        store: &MailboxPgStore,
        credential: &DeviceSessionCredential,
        command: &DeviceHistoryGrantCommand,
        now: UtcMillis,
    ) -> Result<MailboxOperationOutcome, MailboxPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            let grantor = DeviceSessionRepository::authenticate_with_signing_key_in_transaction(
                session.connection(), credential, now,
            ).await.map_err(map_identity_error)?;
            if grantor.session().identity_id() != command.identity_id
                || command.granted_at > now
                || now.get().saturating_sub(command.granted_at.get()) > 300_000
            {
                return Err(MailboxPersistenceError::DeviceAuthenticationRejected);
            }
            let snapshot = lock_and_load_active_snapshot(session.connection(), command.identity_id)
                .await.map_err(map_identity_error)?;
            if snapshot.head().hash() != command.identity_head {
                return Err(MailboxPersistenceError::DeviceAuthenticationRejected);
            }
            let authorizer_key = match command.authorization {
                DeviceHistoryAuthorization::ActiveDevice => {
                    if command.authorizer_id != grantor.session().device_id().to_string() {
                        return Err(MailboxPersistenceError::DeviceAuthenticationRejected);
                    }
                    grantor.signing_key()
                }
                DeviceHistoryAuthorization::RecoveryKey => require_authority_key(
                    snapshot.projection().current_recovery_key(),
                    &command.authorizer_id,
                )?,
                DeviceHistoryAuthorization::RootKey => require_authority_key(
                    snapshot.projection().current_root_key(),
                    &command.authorizer_id,
                )?,
            };
            let new_device_key = DeviceSessionRepository::active_device_signing_key_in_transaction(
                session.connection(), command.identity_id, command.new_device_id,
            ).await.map_err(map_identity_error)?;
            let unsigned = command.canonical_unsigned()?;
            verify(authorizer_key.as_bytes(), GRANT_SIGNATURE_DOMAIN, &unsigned, command.signature)?;
            verify(new_device_key.as_bytes(), NEW_DEVICE_POP_SIGNATURE_DOMAIN, &unsigned, command.new_device_pop_signature)?;
            let grant_digest = Sha256Digest::hash_domain(GRANT_DIGEST_DOMAIN, &command.exact_bytes);
            if let Some(existing) = sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT grant_digest FROM messaging.device_history_grants WHERE identity_id=$1 AND new_device_id=$2",
            ).bind(command.identity_id.to_string()).bind(*command.new_device_id.as_uuid())
                .fetch_optional(&mut *session.connection()).await?
            {
                if digest(existing)? == grant_digest {
                    return Ok(MailboxOperationOutcome::new(encode_receipt(command, grant_digest)?, true));
                }
                return Err(MailboxPersistenceError::MailboxConflict);
            }
            sqlx::query(
                "INSERT INTO messaging.device_history_grants(
                    identity_id,new_device_id,identity_head,earliest_sequence,encrypted_history_digest,
                    authorization_kind,authorizer_id,new_device_pop_digest,canonical_grant,grant_digest,
                    signature,new_device_pop_signature,granted_at_ms
                 ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
            ).bind(command.identity_id.to_string()).bind(*command.new_device_id.as_uuid())
                .bind(command.identity_head.as_bytes().as_slice())
                .bind(i64::try_from(command.earliest_sequence).map_err(|_| MailboxPersistenceError::InvalidCommand("history grant sequence"))?)
                .bind(command.encrypted_history_digest.as_bytes().as_slice())
                .bind(command.authorization.database_kind()).bind(&command.authorizer_id)
                .bind(command.new_device_pop_digest.as_bytes().as_slice()).bind(&command.exact_bytes)
                .bind(grant_digest.as_bytes().as_slice()).bind(command.signature.as_bytes().as_slice())
                .bind(command.new_device_pop_signature.as_bytes().as_slice()).bind(command.granted_at.get())
                .execute(&mut *session.connection()).await?;
            Ok(MailboxOperationOutcome::new(encode_receipt(command, grant_digest)?, false))
        }.await;
        finish_transaction(session, result).await
    }
}

fn require_authority_key(
    key: SigningPublicKey,
    authorizer_id: &str,
) -> Result<SigningPublicKey, MailboxPersistenceError> {
    let expected = Sha256Digest::hash_domain(AUTHORITY_ID_DOMAIN, key.as_bytes()).to_string();
    if authorizer_id == expected {
        Ok(key)
    } else {
        Err(MailboxPersistenceError::DeviceAuthenticationRejected)
    }
}

fn verify(
    key: &[u8; 32],
    domain: &[u8],
    unsigned: &[u8],
    signature: Ed25519Signature,
) -> Result<(), MailboxPersistenceError> {
    let mut input = Vec::with_capacity(domain.len() + unsigned.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(unsigned);
    VerifyingKey::from_bytes(key)
        .map_err(|_| MailboxPersistenceError::DeviceAuthenticationRejected)?
        .verify_strict(&input, &Signature::from_bytes(signature.as_bytes()))
        .map_err(|_| MailboxPersistenceError::DeviceAuthenticationRejected)
}

fn encode_receipt(
    command: &DeviceHistoryGrantCommand,
    digest: Sha256Digest,
) -> Result<Vec<u8>, MailboxPersistenceError> {
    encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (CanonicalValue::Unsigned(1), CanonicalValue::Unsigned(1)),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Text(command.identity_id.to_string()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(command.new_device_id.to_string()),
        ),
        (CanonicalValue::Unsigned(4), digest.to_canonical_value()),
    ]))
    .map_err(|_| MailboxPersistenceError::CorruptData("history grant receipt"))
}

fn digest(bytes: Vec<u8>) -> Result<Sha256Digest, MailboxPersistenceError> {
    Ok(Sha256Digest::from_bytes(bytes.try_into().map_err(
        |_| MailboxPersistenceError::CorruptData("history grant digest"),
    )?))
}

fn map_identity_error(error: IdentityPersistenceError) -> MailboxPersistenceError {
    match error {
        IdentityPersistenceError::Database(error) => MailboxPersistenceError::Database(error),
        _ => MailboxPersistenceError::DeviceAuthenticationRejected,
    }
}
