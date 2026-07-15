use dtx_domain::{DeviceId, IdentityId};
use dtx_identity_persistence::{DeviceSessionCredential, DeviceSessionRepository};
use dtx_wire::{Sha256Digest, UtcMillis};
use sha2::{Digest, Sha256};
use sqlx::{Row, postgres::PgRow};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::MailboxPgStore;

const CAPABILITY_DOMAIN: &[u8] = b"dirextalk.opaque-attachment-capability.v1\0";
const MAX_TTL_MILLIS: i64 = 86_400_000;
const MAX_CHUNK_BYTES: usize = 1_048_576;
const MAX_MANIFEST_BYTES: usize = 1_048_576;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AttachmentCapability([u8; 32]);

impl AttachmentCapability {
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CAPABILITY_DOMAIN);
        hasher.update(self.0);
        hasher.finalize().into()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentCreate {
    pub object_id: Uuid,
    pub owner_identity_id: IdentityId,
    pub owner_device_id: DeviceId,
    pub manifest_digest: Sha256Digest,
    pub chunk_count: u16,
    pub ciphertext_bytes: u64,
    pub expires_at: UtcMillis,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentChunkReference {
    pub index: u16,
    pub digest: Sha256Digest,
    pub size: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentManifest {
    pub canonical_bytes: Vec<u8>,
    pub chunks: Vec<AttachmentChunkReference>,
}

impl AttachmentManifest {
    /// Parses the canonical opaque attachment manifest.
    ///
    /// # Errors
    ///
    /// Returns [`AttachmentError::Invalid`] when the bytes are malformed or non-canonical.
    pub fn parse(canonical_bytes: Vec<u8>) -> Result<Self, AttachmentError> {
        if canonical_bytes.len() < 11
            || canonical_bytes.len() > MAX_MANIFEST_BYTES
            || &canonical_bytes[..5] != b"DTXA1"
        {
            return Err(AttachmentError::Invalid);
        }
        let count = usize::from(u16::from_be_bytes([canonical_bytes[5], canonical_bytes[6]]));
        if count == 0 || count > 4096 {
            return Err(AttachmentError::Invalid);
        }
        let refs_end = 7usize
            .checked_add(count.checked_mul(38).ok_or(AttachmentError::Invalid)?)
            .ok_or(AttachmentError::Invalid)?;
        if canonical_bytes.len() < refs_end + 4 {
            return Err(AttachmentError::Invalid);
        }
        let mut chunks = Vec::with_capacity(count);
        for position in 0..count {
            let offset = 7 + position * 38;
            let index = u16::from_be_bytes([canonical_bytes[offset], canonical_bytes[offset + 1]]);
            if usize::from(index) != position {
                return Err(AttachmentError::Invalid);
            }
            let size = u32::from_be_bytes(
                canonical_bytes[offset + 2..offset + 6]
                    .try_into()
                    .map_err(|_| AttachmentError::Invalid)?,
            );
            let digest = Sha256Digest::from_bytes(
                canonical_bytes[offset + 6..offset + 38]
                    .try_into()
                    .map_err(|_| AttachmentError::Invalid)?,
            );
            chunks.push(AttachmentChunkReference {
                index,
                digest,
                size,
            });
        }
        let encrypted_len = usize::try_from(u32::from_be_bytes(
            canonical_bytes[refs_end..refs_end + 4]
                .try_into()
                .map_err(|_| AttachmentError::Invalid)?,
        ))
        .map_err(|_| AttachmentError::Invalid)?;
        if encrypted_len < 17 || refs_end + 4 + encrypted_len != canonical_bytes.len() {
            return Err(AttachmentError::Invalid);
        }
        Ok(Self {
            canonical_bytes,
            chunks,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentChunk {
    pub digest: Sha256Digest,
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentStatus {
    Created,
    Replay,
    Ready,
    Cancelled,
}

#[derive(Debug)]
pub enum AttachmentError {
    Invalid,
    Unavailable,
    Conflict,
    Authentication,
    Database(sqlx::Error),
}

impl From<sqlx::Error> for AttachmentError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AttachmentRepository;

impl AttachmentRepository {
    /// Creates an opaque attachment object or recognizes an exact replay.
    ///
    /// # Errors
    ///
    /// Returns an attachment error when authentication, validation, quota, or persistence fails.
    pub async fn create(
        self,
        store: &MailboxPgStore,
        credential: &DeviceSessionCredential,
        request: &AttachmentCreate,
        upload: &AttachmentCapability,
        read: &AttachmentCapability,
        now: UtcMillis,
    ) -> Result<AttachmentStatus, AttachmentError> {
        if request.object_id.get_version_num() != 7
            || request.chunk_count == 0
            || request.chunk_count > 4096
            || request.ciphertext_bytes == 0
            || request.ciphertext_bytes > 1_073_741_824
            || request.expires_at.get() <= now.get()
            || request.expires_at.get() - now.get() > MAX_TTL_MILLIS
        {
            return Err(AttachmentError::Invalid);
        }
        let mut session = store
            .begin()
            .await
            .map_err(|_| AttachmentError::Authentication)?;
        let authenticated = DeviceSessionRepository::authenticate_in_transaction(
            session.connection(),
            credential,
            now,
        )
        .await
        .map_err(|_| AttachmentError::Authentication)?;
        if authenticated.identity_id() != request.owner_identity_id
            || authenticated.device_id() != request.owner_device_id
        {
            return Err(AttachmentError::Authentication);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(request.owner_identity_id.to_string())
            .execute(session.connection())
            .await?;
        let existing = sqlx::query("SELECT owner_identity_id,owner_device_id,upload_capability_hash,read_capability_hash,expected_manifest_digest,expected_chunk_count,expected_ciphertext_bytes,expires_at_ms FROM messaging.attachment_objects WHERE object_id=$1")
            .bind(request.object_id).fetch_optional(session.connection()).await?;
        if let Some(row) = existing {
            if !is_exact_create(&row, request, upload, read)? {
                return Err(AttachmentError::Conflict);
            }
            session
                .commit()
                .await
                .map_err(|_| AttachmentError::Unavailable)?;
            return Ok(AttachmentStatus::Replay);
        }
        let active_count: i64 = sqlx::query_scalar("SELECT count(*) FROM messaging.attachment_objects WHERE owner_identity_id=$1 AND state IN ('uploading','ready') AND expires_at_ms>$2")
            .bind(request.owner_identity_id.to_string()).bind(now.get()).fetch_one(session.connection()).await?;
        if active_count >= 64 {
            return Err(AttachmentError::Unavailable);
        }
        let result = sqlx::query(
            "INSERT INTO messaging.attachment_objects (object_id,owner_identity_id,owner_device_id,upload_capability_hash,read_capability_hash,expected_manifest_digest,expected_chunk_count,expected_ciphertext_bytes,expires_at_ms,created_at_ms,updated_at_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10) ON CONFLICT (object_id) DO NOTHING")
            .bind(request.object_id).bind(request.owner_identity_id.to_string()).bind(*request.owner_device_id.as_uuid())
            .bind(upload.hash().to_vec()).bind(read.hash().to_vec()).bind(request.manifest_digest.as_bytes().to_vec())
            .bind(i32::from(request.chunk_count)).bind(i64::try_from(request.ciphertext_bytes).map_err(|_| AttachmentError::Invalid)?)
            .bind(request.expires_at.get()).bind(now.get()).execute(session.connection()).await?;
        let status = if result.rows_affected() == 1 {
            AttachmentStatus::Created
        } else {
            let row = sqlx::query("SELECT owner_identity_id,owner_device_id,upload_capability_hash,read_capability_hash,expected_manifest_digest,expected_chunk_count,expected_ciphertext_bytes,expires_at_ms FROM messaging.attachment_objects WHERE object_id=$1")
                .bind(request.object_id).fetch_one(session.connection()).await?;
            if !is_exact_create(&row, request, upload, read)? {
                return Err(AttachmentError::Conflict);
            }
            AttachmentStatus::Replay
        };
        session
            .commit()
            .await
            .map_err(|_| AttachmentError::Unavailable)?;
        Ok(status)
    }

    #[allow(clippy::too_many_arguments)]
    /// Stores one ciphertext chunk with exact idempotency semantics.
    ///
    /// # Errors
    ///
    /// Returns an attachment error when authorization, validation, replay, or persistence fails.
    pub async fn put_chunk(
        self,
        store: &MailboxPgStore,
        object_id: Uuid,
        index: u16,
        capability: &AttachmentCapability,
        idempotency_hash: Sha256Digest,
        claimed_digest: Sha256Digest,
        ciphertext: &[u8],
        now: UtcMillis,
    ) -> Result<AttachmentStatus, AttachmentError> {
        if ciphertext.len() < 17
            || ciphertext.len() > MAX_CHUNK_BYTES
            || digest(ciphertext) != claimed_digest
        {
            return Err(AttachmentError::Invalid);
        }
        let mut session = store
            .begin()
            .await
            .map_err(|_| AttachmentError::Unavailable)?;
        let row = sqlx::query("SELECT upload_capability_hash,expected_chunk_count,expected_ciphertext_bytes,uploaded_ciphertext_bytes,state,expires_at_ms FROM messaging.attachment_objects WHERE object_id=$1 FOR UPDATE")
            .bind(object_id).fetch_optional(session.connection()).await?.ok_or(AttachmentError::Unavailable)?;
        authorize(&row.get::<Vec<u8>, _>("upload_capability_hash"), capability)?;
        if row.get::<String, _>("state") != "uploading"
            || row.get::<i64, _>("expires_at_ms") <= now.get()
            || i32::from(index) >= row.get::<i32, _>("expected_chunk_count")
        {
            return Err(AttachmentError::Unavailable);
        }
        let request_digest =
            digest_parts(&[&index.to_be_bytes(), claimed_digest.as_bytes(), ciphertext]);
        if let Some(existing) = sqlx::query("SELECT ciphertext_digest,ciphertext_bytes,idempotency_key_hash,request_digest FROM messaging.attachment_chunks WHERE object_id=$1 AND chunk_index=$2")
            .bind(object_id).bind(i32::from(index)).fetch_optional(session.connection()).await? {
            let exact = existing.get::<Vec<u8>,_>("ciphertext_digest").ct_eq(claimed_digest.as_bytes()).into()
                && existing.get::<Vec<u8>,_>("ciphertext_bytes").ct_eq(ciphertext).into()
                && existing.get::<Vec<u8>,_>("idempotency_key_hash").ct_eq(idempotency_hash.as_bytes()).into()
                && existing.get::<Vec<u8>,_>("request_digest").ct_eq(&request_digest).into();
            if !exact { return Err(AttachmentError::Conflict); }
            session.commit().await.map_err(|_| AttachmentError::Unavailable)?;
            return Ok(AttachmentStatus::Replay);
        }
        if sqlx::query_scalar::<_, i32>("SELECT chunk_index FROM messaging.attachment_chunks WHERE object_id=$1 AND idempotency_key_hash=$2")
            .bind(object_id)
            .bind(idempotency_hash.as_bytes().as_slice())
            .fetch_optional(session.connection())
            .await?
            .is_some()
        {
            return Err(AttachmentError::Conflict);
        }
        let new_bytes = row.get::<i64, _>("uploaded_ciphertext_bytes")
            + i64::try_from(ciphertext.len()).map_err(|_| AttachmentError::Invalid)?;
        if new_bytes > row.get::<i64, _>("expected_ciphertext_bytes") {
            return Err(AttachmentError::Invalid);
        }
        sqlx::query("INSERT INTO messaging.attachment_chunks(object_id,chunk_index,ciphertext_digest,ciphertext_bytes,idempotency_key_hash,request_digest,created_at_ms) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(object_id).bind(i32::from(index)).bind(claimed_digest.as_bytes().to_vec()).bind(ciphertext)
            .bind(idempotency_hash.as_bytes().to_vec()).bind(request_digest.to_vec()).bind(now.get()).execute(session.connection()).await?;
        sqlx::query("UPDATE messaging.attachment_objects SET uploaded_chunk_count=uploaded_chunk_count+1,uploaded_ciphertext_bytes=$2,updated_at_ms=$3 WHERE object_id=$1")
            .bind(object_id).bind(new_bytes).bind(now.get()).execute(session.connection()).await?;
        session
            .commit()
            .await
            .map_err(|_| AttachmentError::Unavailable)?;
        Ok(AttachmentStatus::Created)
    }

    /// Finalizes an upload after verifying the canonical manifest and all chunks.
    ///
    /// # Errors
    ///
    /// Returns an attachment error when authorization, integrity validation, or persistence fails.
    pub async fn finalize(
        self,
        store: &MailboxPgStore,
        object_id: Uuid,
        capability: &AttachmentCapability,
        manifest: &AttachmentManifest,
        now: UtcMillis,
    ) -> Result<AttachmentStatus, AttachmentError> {
        let manifest = AttachmentManifest::parse(manifest.canonical_bytes.clone())?;
        let mut session = store
            .begin()
            .await
            .map_err(|_| AttachmentError::Unavailable)?;
        let row = sqlx::query("SELECT upload_capability_hash,expected_manifest_digest,expected_chunk_count,expected_ciphertext_bytes,uploaded_chunk_count,uploaded_ciphertext_bytes,state,expires_at_ms,manifest_bytes FROM messaging.attachment_objects WHERE object_id=$1 FOR UPDATE")
            .bind(object_id).fetch_optional(session.connection()).await?.ok_or(AttachmentError::Unavailable)?;
        authorize(&row.get::<Vec<u8>, _>("upload_capability_hash"), capability)?;
        let state = row.get::<String, _>("state");
        if state == "ready" {
            return if row.get::<Option<Vec<u8>>, _>("manifest_bytes").as_deref()
                == Some(manifest.canonical_bytes.as_slice())
            {
                Ok(AttachmentStatus::Replay)
            } else {
                Err(AttachmentError::Conflict)
            };
        }
        if state != "uploading"
            || row.get::<i64, _>("expires_at_ms") <= now.get()
            || row.get::<Vec<u8>, _>("expected_manifest_digest")
                != digest(&manifest.canonical_bytes).as_bytes()
            || manifest.chunks.len()
                != usize::try_from(row.get::<i32, _>("expected_chunk_count")).unwrap_or(0)
            || row.get::<i32, _>("uploaded_chunk_count")
                != row.get::<i32, _>("expected_chunk_count")
            || row.get::<i64, _>("uploaded_ciphertext_bytes")
                != row.get::<i64, _>("expected_ciphertext_bytes")
        {
            return Err(AttachmentError::Invalid);
        }
        let chunks = sqlx::query("SELECT chunk_index,ciphertext_digest,octet_length(ciphertext_bytes) AS size FROM messaging.attachment_chunks WHERE object_id=$1 ORDER BY chunk_index")
            .bind(object_id).fetch_all(session.connection()).await?;
        for (expected, stored) in manifest.chunks.iter().zip(chunks.iter()) {
            if i32::from(expected.index) != stored.get::<i32, _>("chunk_index")
                || i32::try_from(expected.size).ok() != Some(stored.get::<i32, _>("size"))
                || !bool::from(
                    stored
                        .get::<Vec<u8>, _>("ciphertext_digest")
                        .ct_eq(expected.digest.as_bytes()),
                )
            {
                return Err(AttachmentError::Invalid);
            }
        }
        sqlx::query("UPDATE messaging.attachment_objects SET manifest_bytes=$2,state='ready',updated_at_ms=$3 WHERE object_id=$1")
            .bind(object_id).bind(&manifest.canonical_bytes).bind(now.get()).execute(session.connection()).await?;
        session
            .commit()
            .await
            .map_err(|_| AttachmentError::Unavailable)?;
        Ok(AttachmentStatus::Ready)
    }

    /// Reads a ready object's opaque canonical manifest.
    ///
    /// # Errors
    ///
    /// Returns an attachment error when the read capability is invalid or the object unavailable.
    pub async fn read_manifest(
        self,
        store: &MailboxPgStore,
        object_id: Uuid,
        capability: &AttachmentCapability,
        now: UtcMillis,
    ) -> Result<Vec<u8>, AttachmentError> {
        let mut session = store
            .begin()
            .await
            .map_err(|_| AttachmentError::Unavailable)?;
        let row = sqlx::query("SELECT read_capability_hash,state,expires_at_ms,manifest_bytes FROM messaging.attachment_objects WHERE object_id=$1")
            .bind(object_id).fetch_optional(session.connection()).await?.ok_or(AttachmentError::Unavailable)?;
        authorize(&row.get::<Vec<u8>, _>("read_capability_hash"), capability)?;
        if row.get::<String, _>("state") != "ready"
            || row.get::<i64, _>("expires_at_ms") <= now.get()
        {
            return Err(AttachmentError::Unavailable);
        }
        row.get::<Option<Vec<u8>>, _>("manifest_bytes")
            .ok_or(AttachmentError::Unavailable)
    }

    /// Reads one ciphertext chunk from a ready object.
    ///
    /// # Errors
    ///
    /// Returns an attachment error when the read capability is invalid or data is unavailable.
    pub async fn read_chunk(
        self,
        store: &MailboxPgStore,
        object_id: Uuid,
        index: u16,
        capability: &AttachmentCapability,
        now: UtcMillis,
    ) -> Result<AttachmentChunk, AttachmentError> {
        let mut session = store
            .begin()
            .await
            .map_err(|_| AttachmentError::Unavailable)?;
        let object = sqlx::query("SELECT read_capability_hash,state,expires_at_ms FROM messaging.attachment_objects WHERE object_id=$1")
            .bind(object_id).fetch_optional(session.connection()).await?.ok_or(AttachmentError::Unavailable)?;
        authorize(
            &object.get::<Vec<u8>, _>("read_capability_hash"),
            capability,
        )?;
        if object.get::<String, _>("state") != "ready"
            || object.get::<i64, _>("expires_at_ms") <= now.get()
        {
            return Err(AttachmentError::Unavailable);
        }
        let row = sqlx::query("SELECT ciphertext_digest,ciphertext_bytes FROM messaging.attachment_chunks WHERE object_id=$1 AND chunk_index=$2")
            .bind(object_id).bind(i32::from(index)).fetch_optional(session.connection()).await?.ok_or(AttachmentError::Unavailable)?;
        let raw = row.get::<Vec<u8>, _>("ciphertext_digest");
        let digest_bytes: [u8; 32] = raw.try_into().map_err(|_| AttachmentError::Invalid)?;
        let digest = Sha256Digest::from_bytes(digest_bytes);
        Ok(AttachmentChunk {
            digest,
            ciphertext: row.get("ciphertext_bytes"),
        })
    }

    /// Cancels an attachment owned by the authenticated device.
    ///
    /// # Errors
    ///
    /// Returns an attachment error when authentication, ownership, or persistence fails.
    pub async fn cancel(
        self,
        store: &MailboxPgStore,
        credential: &DeviceSessionCredential,
        object_id: Uuid,
        now: UtcMillis,
    ) -> Result<AttachmentStatus, AttachmentError> {
        let mut session = store
            .begin()
            .await
            .map_err(|_| AttachmentError::Authentication)?;
        let authenticated = DeviceSessionRepository::authenticate_in_transaction(
            session.connection(),
            credential,
            now,
        )
        .await
        .map_err(|_| AttachmentError::Authentication)?;
        let row = sqlx::query("SELECT owner_identity_id,owner_device_id,state FROM messaging.attachment_objects WHERE object_id=$1 FOR UPDATE")
            .bind(object_id)
            .fetch_optional(session.connection())
            .await?
            .ok_or(AttachmentError::Unavailable)?;
        if row.get::<String, _>("owner_identity_id") != authenticated.identity_id().to_string()
            || row.get::<Uuid, _>("owner_device_id") != *authenticated.device_id().as_uuid()
        {
            return Err(AttachmentError::Unavailable);
        }
        let status = match row.get::<String, _>("state").as_str() {
            "cancelled" => AttachmentStatus::Replay,
            "uploading" | "ready" => {
                sqlx::query("UPDATE messaging.attachment_objects SET state='cancelled',updated_at_ms=$2 WHERE object_id=$1")
                    .bind(object_id)
                    .bind(now.get())
                    .execute(session.connection())
                    .await?;
                AttachmentStatus::Cancelled
            }
            _ => return Err(AttachmentError::Unavailable),
        };
        session
            .commit()
            .await
            .map_err(|_| AttachmentError::Unavailable)?;
        Ok(status)
    }
}

fn is_exact_create(
    row: &PgRow,
    request: &AttachmentCreate,
    upload: &AttachmentCapability,
    read: &AttachmentCapability,
) -> Result<bool, AttachmentError> {
    Ok(
        row.get::<String, _>("owner_identity_id") == request.owner_identity_id.to_string()
            && row.get::<Uuid, _>("owner_device_id") == *request.owner_device_id.as_uuid()
            && bool::from(
                row.get::<Vec<u8>, _>("upload_capability_hash")
                    .ct_eq(&upload.hash()),
            )
            && bool::from(
                row.get::<Vec<u8>, _>("read_capability_hash")
                    .ct_eq(&read.hash()),
            )
            && bool::from(
                row.get::<Vec<u8>, _>("expected_manifest_digest")
                    .ct_eq(request.manifest_digest.as_bytes()),
            )
            && row.get::<i32, _>("expected_chunk_count") == i32::from(request.chunk_count)
            && row.get::<i64, _>("expected_ciphertext_bytes")
                == i64::try_from(request.ciphertext_bytes).map_err(|_| AttachmentError::Invalid)?
            && row.get::<i64, _>("expires_at_ms") == request.expires_at.get(),
    )
}

fn authorize(stored: &[u8], capability: &AttachmentCapability) -> Result<(), AttachmentError> {
    if stored.len() != 32 || !bool::from(stored.ct_eq(&capability.hash())) {
        return Err(AttachmentError::Unavailable);
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}
fn digest_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"dirextalk.opaque-attachment-chunk.v1\0");
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}
