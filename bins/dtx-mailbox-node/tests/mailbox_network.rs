#[path = "mailbox_support.rs"]
mod common;
use common::*;

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one end-to-end attachment lifecycle keeps replay assertions together"
)]
async fn opaque_attachment_is_exact_idempotent_and_cancel_revokes_read()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let mailbox_store = MailboxPgStore::connect(harness.mailbox_runtime_options(), 4).await?;
    let owner = enroll_active_device(&identity_store, 91, 92, 93, [94; 32]).await?;
    let credential = DeviceSessionCredential::new(owner.session_id, owner.session_secret)?;
    let object_id = Uuid::now_v7();
    let ciphertext = (0_u8..64).collect::<Vec<_>>();
    let chunk_digest = Sha256Digest::from_bytes(Sha256::digest(&ciphertext).into());
    let mut manifest_bytes = b"DTXA1".to_vec();
    manifest_bytes.extend_from_slice(&1_u16.to_be_bytes());
    manifest_bytes.extend_from_slice(&0_u16.to_be_bytes());
    manifest_bytes.extend_from_slice(&u32::try_from(ciphertext.len())?.to_be_bytes());
    manifest_bytes.extend_from_slice(chunk_digest.as_bytes());
    manifest_bytes.extend_from_slice(&17_u32.to_be_bytes());
    manifest_bytes.extend_from_slice(&[7; 17]);
    let manifest = AttachmentManifest::parse(manifest_bytes.clone()).unwrap();
    let request = AttachmentCreate {
        object_id,
        owner_identity_id: owner.identity_id,
        owner_device_id: owner.device_id,
        manifest_digest: Sha256Digest::from_bytes(Sha256::digest(&manifest_bytes).into()),
        chunk_count: 1,
        ciphertext_bytes: ciphertext.len() as u64,
        expires_at: UtcMillis::new(EXPIRY)?,
    };
    let upload = AttachmentCapability::new([95; 32]);
    let read = AttachmentCapability::new([96; 32]);
    assert_eq!(
        AttachmentRepository
            .create(
                &mailbox_store,
                &credential,
                &request,
                &upload,
                &read,
                UtcMillis::new(NOW)?
            )
            .await
            .unwrap(),
        AttachmentStatus::Created
    );
    assert_eq!(
        AttachmentRepository
            .create(
                &mailbox_store,
                &credential,
                &request,
                &upload,
                &read,
                UtcMillis::new(NOW + 1)?
            )
            .await
            .unwrap(),
        AttachmentStatus::Replay
    );
    let idempotency = Sha256Digest::hash_domain(b"attachment-test-idempotency\0", b"chunk-0");
    assert_eq!(
        AttachmentRepository
            .put_chunk(
                &mailbox_store,
                object_id,
                0,
                &upload,
                idempotency,
                chunk_digest,
                &ciphertext,
                UtcMillis::new(NOW + 1)?
            )
            .await
            .unwrap(),
        AttachmentStatus::Created
    );
    assert_eq!(
        AttachmentRepository
            .put_chunk(
                &mailbox_store,
                object_id,
                0,
                &upload,
                idempotency,
                chunk_digest,
                &ciphertext,
                UtcMillis::new(NOW + 2)?
            )
            .await
            .unwrap(),
        AttachmentStatus::Replay
    );
    let mut changed = ciphertext.clone();
    changed[0] ^= 1;
    assert!(matches!(
        AttachmentRepository
            .put_chunk(
                &mailbox_store,
                object_id,
                0,
                &upload,
                idempotency,
                Sha256Digest::from_bytes(Sha256::digest(&changed).into()),
                &changed,
                UtcMillis::new(NOW + 3)?
            )
            .await,
        Err(AttachmentError::Conflict)
    ));
    let second_object_id = Uuid::now_v7();
    let second_request = AttachmentCreate {
        object_id: second_object_id,
        owner_identity_id: owner.identity_id,
        owner_device_id: owner.device_id,
        manifest_digest: request.manifest_digest,
        chunk_count: 2,
        ciphertext_bytes: (ciphertext.len() * 2) as u64,
        expires_at: UtcMillis::new(EXPIRY)?,
    };
    assert_eq!(
        AttachmentRepository
            .create(
                &mailbox_store,
                &credential,
                &second_request,
                &upload,
                &read,
                UtcMillis::new(NOW + 3)?,
            )
            .await
            .unwrap(),
        AttachmentStatus::Created
    );
    AttachmentRepository
        .put_chunk(
            &mailbox_store,
            second_object_id,
            0,
            &upload,
            idempotency,
            chunk_digest,
            &ciphertext,
            UtcMillis::new(NOW + 3)?,
        )
        .await
        .unwrap();
    assert!(matches!(
        AttachmentRepository
            .put_chunk(
                &mailbox_store,
                second_object_id,
                1,
                &upload,
                idempotency,
                chunk_digest,
                &ciphertext,
                UtcMillis::new(NOW + 3)?,
            )
            .await,
        Err(AttachmentError::Conflict)
    ));
    assert_eq!(
        AttachmentRepository
            .finalize(
                &mailbox_store,
                object_id,
                &upload,
                &manifest,
                UtcMillis::new(NOW + 4)?
            )
            .await
            .unwrap(),
        AttachmentStatus::Ready
    );
    assert_eq!(
        AttachmentRepository
            .read_chunk(
                &mailbox_store,
                object_id,
                0,
                &read,
                UtcMillis::new(NOW + 5)?
            )
            .await
            .unwrap()
            .ciphertext,
        ciphertext
    );
    let cancel_credential = DeviceSessionCredential::new(owner.session_id, owner.session_secret)?;
    assert_eq!(
        AttachmentRepository
            .cancel(
                &mailbox_store,
                &cancel_credential,
                object_id,
                UtcMillis::new(NOW + 6)?,
            )
            .await
            .unwrap(),
        AttachmentStatus::Cancelled
    );
    assert_eq!(
        AttachmentRepository
            .cancel(
                &mailbox_store,
                &cancel_credential,
                object_id,
                UtcMillis::new(NOW + 7)?,
            )
            .await
            .unwrap(),
        AttachmentStatus::Replay
    );
    assert!(matches!(
        AttachmentRepository
            .read_manifest(&mailbox_store, object_id, &read, UtcMillis::new(NOW + 8)?)
            .await,
        Err(AttachmentError::Unavailable)
    ));
    Ok(())
}

struct RecoveredDevice {
    active: ActiveDevice,
    request_id: DeviceEnrollmentChallengeId,
    request_digest: Sha256Digest,
    approved_head: IdentityLogHead,
    recipient_package_digest: Sha256Digest,
}
