use super::*;
use dtx_domain::{DeviceId, IdentityId, Revision, SecretId, TenantId};
use dtx_security::{
    EncryptedDataKey, GeneratedDataKey, KeyManagement, KeyManagementError, KmsContext,
    KmsKeyVersion, SecretBytes,
};
use dtx_wire::StableCode;
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

fn identity() -> IdentityId {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/v1/public-ids.json"
    ))
    .unwrap();
    vector["identity_id"].as_str().unwrap().parse().unwrap()
}

fn hex_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[derive(Clone)]
struct FakeKms {
    keys: Arc<Mutex<HashMap<Vec<u8>, Vec<u8>>>>,
    contexts: Arc<Mutex<Vec<KmsContext>>>,
}
impl FakeKms {
    fn new() -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashMap::new())),
            contexts: Arc::new(Mutex::new(Vec::new())),
        }
    }
}
impl KeyManagement for FakeKms {
    fn generate_data_key<'a>(
        &'a self,
        context: &'a KmsContext,
    ) -> Pin<Box<dyn Future<Output = Result<GeneratedDataKey, KeyManagementError>> + Send + 'a>>
    {
        Box::pin(async move {
            self.contexts.lock().unwrap().push(context.clone());
            let ordinal = u8::try_from(self.keys.lock().unwrap().len()).unwrap() + 1;
            let key = vec![ordinal; 32];
            let wrapped = vec![ordinal];
            self.keys
                .lock()
                .unwrap()
                .insert(wrapped.clone(), key.clone());
            Ok(GeneratedDataKey {
                plaintext: SecretBytes::new(key).unwrap(),
                encrypted: EncryptedDataKey::new(
                    KmsKeyVersion::new(StableCode::parse("fake.v1").unwrap()),
                    wrapped,
                )
                .unwrap(),
            })
        })
    }
    fn decrypt_data_key<'a>(
        &'a self,
        encrypted: &'a EncryptedDataKey,
        context: &'a KmsContext,
    ) -> Pin<Box<dyn Future<Output = Result<SecretBytes, KeyManagementError>> + Send + 'a>> {
        Box::pin(async move {
            self.contexts.lock().unwrap().push(context.clone());
            self.keys
                .lock()
                .unwrap()
                .get(encrypted.opaque_bytes())
                .cloned()
                .map(SecretBytes::new)
                .transpose()
                .unwrap()
                .ok_or(KeyManagementError::InvalidCiphertext)
        })
    }
}

#[test]
fn model_and_payload_contracts() {
    for (length, valid) in [(0, false), (1, true), (4096, true), (4097, false)] {
        assert_eq!(
            SecretToken::new(vec![1; length]).is_ok(),
            valid,
            "length {length}"
        );
    }
    let receipt = RedactedReceipt::new(2, RegistrationState::Active).unwrap();
    assert_eq!(
        receipt.canonical_cbor(),
        hex_bytes("a40101026366636d03020466616374697665")
    );
    let id = WakeDeliveryId::parse("0190f2a5-7b1c-7abc-8def-0123456789ab").unwrap();
    assert_eq!(
        WakePayload::new(id).canonical_json(),
        br#"{"version":1,"wake_delivery_id":"0190f2a5-7b1c-7abc-8def-0123456789ab"}"#
    );
    assert_eq!(
        RedactedReceipt::from_canonical_cbor(&receipt.canonical_cbor()).unwrap(),
        receipt
    );
    let payload_text = String::from_utf8(WakePayload::new(id).canonical_json()).unwrap();
    assert!(!payload_text.contains("ttl"));
    assert!(!payload_text.contains("priority"));
    assert!(WakeDeliveryId::parse("0190f2a5-7b1c-6abc-8def-0123456789ab").is_err());
}

#[test]
fn retry_schedule_is_strictly_bounded() {
    assert!(RetryDelay::new(0).is_none());
    assert_eq!(RetryDelay::new(1).unwrap().seconds(), 1);
    assert_eq!(RetryDelay::new(60).unwrap().seconds(), 60);
    assert_eq!(RetryDelay::new(61).unwrap().seconds(), 60);
    assert!(RetrySchedule::new(10, 10, 12).is_none());
    assert!(RetrySchedule::new(10, 12, 12).is_none());
    assert_eq!(
        RetrySchedule::new(10, 11, 12).unwrap().next_attempt_at_ms(),
        11
    );
}

#[test]
fn receipt_matches_v43_and_rejects_noncanonical_forms() {
    let active = RedactedReceipt::new(1, RegistrationState::Active).unwrap();
    let frozen = hex_bytes("a40101026366636d03010466616374697665");
    assert_eq!(active.canonical_cbor(), frozen);
    assert_eq!(
        RedactedReceipt::from_canonical_cbor(&frozen).unwrap(),
        active
    );
    for invalid in [
        hex_bytes("bf0101026366636d03010466616374697665ff"),
        hex_bytes("a50101026366636d0301046661637469766505f4"),
        hex_bytes("a40101026366636d0318010466616374697665"),
        hex_bytes("a40101026366636d03000466616374697665"),
        hex_bytes("a40101026366636d03010467696e76616c6964"),
    ] {
        assert!(RedactedReceipt::from_canonical_cbor(&invalid).is_err());
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn encryption_round_trip_and_framing_rejects_tamper() {
    let kms = FakeKms::new();
    let service = TokenEncryptionService::new_for_tests(kms.clone());
    let tenant_id = TenantId::new();
    let binding = RegistrationBinding {
        tenant_id,
        identity_id: identity(),
        device_id: DeviceId::new(),
        provider: Provider::Fcm,
        revision: Revision::new(1).unwrap(),
    };
    let secret = SecretId::new();
    let token = SecretToken::new(b"secret-token".to_vec()).unwrap();
    let envelope = service.encrypt(binding, secret, &token).await.unwrap();
    assert!(
        service
            .decrypt(binding, secret, &envelope)
            .await
            .unwrap()
            .expose(|b| b == b"secret-token")
    );
    let frame = envelope.to_frame();
    assert_eq!(TokenEnvelope::from_frame(&frame).unwrap(), envelope);
    let parts = envelope.clone().into_parts();
    assert_eq!(parts.registration_binding(), binding);
    assert_eq!(
        TokenEnvelope::try_from_parts(parts.clone()).unwrap(),
        envelope
    );
    assert_eq!(
        TokenEnvelope::try_from_parts(parts.clone())
            .unwrap()
            .to_frame(),
        frame
    );
    for (nonce, ciphertext, encrypted_dek, key_version, context) in [
        (
            vec![0; 23],
            parts.ciphertext().to_vec(),
            parts.encrypted_dek().to_vec(),
            parts.key_version().to_owned(),
            parts.context().to_vec(),
        ),
        (
            parts.nonce().to_vec(),
            vec![0; 16],
            parts.encrypted_dek().to_vec(),
            parts.key_version().to_owned(),
            parts.context().to_vec(),
        ),
        (
            parts.nonce().to_vec(),
            vec![0; 4113],
            parts.encrypted_dek().to_vec(),
            parts.key_version().to_owned(),
            parts.context().to_vec(),
        ),
        (
            parts.nonce().to_vec(),
            parts.ciphertext().to_vec(),
            Vec::new(),
            parts.key_version().to_owned(),
            parts.context().to_vec(),
        ),
        (
            parts.nonce().to_vec(),
            parts.ciphertext().to_vec(),
            parts.encrypted_dek().to_vec(),
            String::new(),
            parts.context().to_vec(),
        ),
        (
            parts.nonce().to_vec(),
            parts.ciphertext().to_vec(),
            parts.encrypted_dek().to_vec(),
            parts.key_version().to_owned(),
            b"invalid".to_vec(),
        ),
    ] {
        assert!(
            TokenEnvelopeParts::new(1, nonce, ciphertext, encrypted_dek, key_version, context)
                .is_err()
        );
    }
    let checked_claim = DeliveryClaim::new(
        Uuid::now_v7(),
        Uuid::now_v7(),
        secret,
        binding,
        envelope.clone(),
        None,
    )
    .unwrap();
    assert_eq!(checked_claim.registration(), binding);
    assert_eq!(checked_claim.envelope().registration_binding(), binding);
    assert!(checked_claim.provenance().is_none());
    assert!(
        DeliveryClaim::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            secret,
            RegistrationBinding {
                device_id: DeviceId::new(),
                ..binding
            },
            envelope.clone(),
            None,
        )
        .is_err()
    );
    let second = service.encrypt(binding, secret, &token).await.unwrap();
    assert_ne!(envelope.nonce(), second.nonce());
    assert_ne!(
        envelope.encrypted_dek().opaque_bytes(),
        second.encrypted_dek().opaque_bytes()
    );
    assert_eq!(
        kms.contexts.lock().unwrap().as_slice(),
        &[
            KmsContext::new(tenant_id, secret, StableCode::parse(TOKEN_PURPOSE).unwrap()),
            KmsContext::new(tenant_id, secret, StableCode::parse(TOKEN_PURPOSE).unwrap()),
            KmsContext::new(tenant_id, secret, StableCode::parse(TOKEN_PURPOSE).unwrap())
        ]
    );
    for index in 0..frame.len() {
        assert!(
            TokenEnvelope::from_frame(&frame[..index]).is_err(),
            "truncated {index}"
        );
    }
    let mut unknown_version = frame.clone();
    unknown_version[0] = 2;
    assert!(TokenEnvelope::from_frame(&unknown_version).is_err());
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(TokenEnvelope::from_frame(&trailing).is_err());
    let mut malformed = envelope.to_frame();
    let context_offset = malformed.len() - envelope.encryption_context().len();
    malformed[context_offset + TOKEN_PURPOSE.len()] = b'x';
    assert!(TokenEnvelope::from_frame(&malformed).is_err());
    let mut invalid_provider = frame.clone();
    let provider_in_context = envelope
        .encryption_context()
        .windows(3)
        .position(|field| field == b"fcm")
        .unwrap();
    invalid_provider[context_offset + provider_in_context] = b'x';
    assert!(TokenEnvelope::from_frame(&invalid_provider).is_err());

    // The wire layout has two u16 fields, a fixed nonce, then two u32 fields.
    let version_end = 1 + 2 + usize::from(u16::from_be_bytes(frame[1..3].try_into().unwrap()));
    let opaque_end = version_end
        + 2
        + usize::from(u16::from_be_bytes(
            frame[version_end..version_end + 2].try_into().unwrap(),
        ));
    let nonce_end = opaque_end + 24;
    let ciphertext_end = nonce_end
        + 4
        + usize::try_from(u32::from_be_bytes(
            frame[nonce_end..nonce_end + 4].try_into().unwrap(),
        ))
        .unwrap();
    for boundary in [0, 1, 3, version_end, opaque_end, nonce_end, ciphertext_end] {
        assert!(
            TokenEnvelope::from_frame(&frame[..boundary]).is_err(),
            "boundary {boundary}"
        );
    }
    for offset in [1, version_end] {
        let mut zero_length = frame.clone();
        zero_length[offset] = 0;
        zero_length[offset + 1] = 0;
        assert!(TokenEnvelope::from_frame(&zero_length).is_err());
    }
    for offset in [nonce_end, ciphertext_end] {
        let mut zero_length = frame.clone();
        zero_length[offset..offset + 4].copy_from_slice(&0_u32.to_be_bytes());
        assert!(TokenEnvelope::from_frame(&zero_length).is_err());
    }
    for (label, offset) in [
        ("encrypted_dek", version_end + 2),
        ("nonce", opaque_end),
        ("ciphertext", nonce_end + 4),
        ("tag", ciphertext_end - 1),
    ] {
        let mut tampered = frame.clone();
        tampered[offset] ^= 1;
        let parsed = TokenEnvelope::from_frame(&tampered).unwrap();
        assert!(
            service.decrypt(binding, secret, &parsed).await.is_err(),
            "{label}"
        );
    }
    for mismatch in [
        RegistrationBinding {
            tenant_id: TenantId::new(),
            ..binding
        },
        RegistrationBinding {
            identity_id: format!(
                "{}b{}",
                &identity().to_string()[..55],
                &identity().to_string()[56..]
            )
            .parse()
            .unwrap(),
            ..binding
        },
        RegistrationBinding {
            device_id: DeviceId::new(),
            ..binding
        },
        RegistrationBinding {
            revision: Revision::new(2).unwrap(),
            ..binding
        },
    ] {
        assert!(matches!(
            service.decrypt(mismatch, secret, &envelope).await,
            Err(PushError::ContextMismatch)
        ));
    }
}

struct RecordingPersistence {
    claim: Mutex<Option<DeliveryClaim>>,
    events: Arc<Mutex<Vec<&'static str>>>,
    permit: Result<Option<SendPermit>, PushError>,
    finish_result: Result<bool, PushError>,
    transient_result: Result<TransientResolution, PushError>,
}
impl PushPersistence for RecordingPersistence {
    fn claim<'a>(
        &'a self,
        _maximum_rows: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<DeliveryClaim>, PushError>> + Send + 'a>> {
        Box::pin(async move { Ok(self.claim.lock().unwrap().take().into_iter().collect()) })
    }
    fn authorize_send<'a>(
        &'a self,
        _claim: &'a DeliveryClaim,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SendPermit>, PushError>> + Send + 'a>> {
        Box::pin(async move {
            self.events.lock().unwrap().push("authorize");
            self.permit
        })
    }
    fn finish_accepted<'a>(
        &'a self,
        _delivery_id: Uuid,
        _claim_token: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<bool, PushError>> + Send + 'a>> {
        Box::pin(async move {
            self.events.lock().unwrap().push("finish");
            self.finish_result
        })
    }
    fn finish_permanent_failure<'a>(
        &'a self,
        _delivery_id: Uuid,
        _claim_token: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<bool, PushError>> + Send + 'a>> {
        Box::pin(async move {
            self.events.lock().unwrap().push("finish");
            self.finish_result
        })
    }
    fn finish_transient_before_expiry<'a>(
        &'a self,
        _delivery_id: Uuid,
        _claim_token: Uuid,
        _retry_after: RetryDelay,
        _class: RedactedFailureClass,
    ) -> Pin<Box<dyn Future<Output = Result<TransientResolution, PushError>> + Send + 'a>> {
        Box::pin(async move {
            self.events.lock().unwrap().push("finish");
            self.transient_result
        })
    }
    fn finish_invalid_token<'a>(
        &'a self,
        _claim: &'a DeliveryClaim,
    ) -> Pin<Box<dyn Future<Output = Result<bool, PushError>> + Send + 'a>> {
        Box::pin(async move {
            self.events.lock().unwrap().push("invalid_atomic");
            self.finish_result
        })
    }
}
struct RecordingProvider {
    events: Arc<Mutex<Vec<&'static str>>>,
    outcome: ProviderOutcome,
}
impl PushProvider for RecordingProvider {
    fn send<'a>(
        &'a self,
        _provider: Provider,
        _token: &'a SecretToken,
        _payload: &'a WakePayload,
        _policy: TransportPolicy,
    ) -> Pin<Box<dyn Future<Output = ProviderOutcome> + Send + 'a>> {
        Box::pin(async move {
            self.events.lock().unwrap().push("send");
            self.outcome
        })
    }
}

struct WakeRecordingProvider(Arc<Mutex<Vec<Uuid>>>);
impl PushProvider for WakeRecordingProvider {
    fn send<'a>(
        &'a self,
        _provider: Provider,
        _token: &'a SecretToken,
        payload: &'a WakePayload,
        _policy: TransportPolicy,
    ) -> Pin<Box<dyn Future<Output = ProviderOutcome> + Send + 'a>> {
        Box::pin(async move {
            self.0
                .lock()
                .unwrap()
                .push(*payload.wake_delivery_id.as_uuid());
            ProviderOutcome::Accepted
        })
    }
}

#[tokio::test]
async fn broker_fences_before_send() {
    let kms = FakeKms::new();
    let binding = RegistrationBinding {
        tenant_id: TenantId::new(),
        identity_id: identity(),
        device_id: DeviceId::new(),
        provider: Provider::Fcm,
        revision: Revision::new(1).unwrap(),
    };
    let registration_id = SecretId::new();
    let envelope = TokenEncryptionService::new_for_tests(kms.clone())
        .encrypt(
            binding,
            registration_id,
            &SecretToken::new(b"token".to_vec()).unwrap(),
        )
        .await
        .unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let claim = DeliveryClaim {
        delivery_id: Uuid::now_v7(),
        claim_token: Uuid::now_v7(),
        registration_id,
        registration: binding,
        envelope,
        mailbox_id: Some(dtx_domain::MailboxId::new()),
        envelope_id: Some(dtx_domain::EnvelopeId::new()),
    };
    let persistence = RecordingPersistence {
        claim: Mutex::new(Some(claim)),
        events: events.clone(),
        permit: Ok(Some(SendPermit {
            registration_revision: 1,
        })),
        finish_result: Ok(true),
        transient_result: Ok(TransientResolution::Scheduled(
            RetrySchedule::new(10, 11, 12).unwrap(),
        )),
    };
    let provider = RecordingProvider {
        events: events.clone(),
        outcome: ProviderOutcome::Accepted,
    };
    let broker = Broker::new(persistence, kms, provider);
    broker.process_once(1).await.unwrap();
    assert_eq!(&*events.lock().unwrap(), &["authorize", "send", "finish"]);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn broker_outcomes_and_authorization_never_send_unfenced_claims() {
    let kms = FakeKms::new();
    let binding = RegistrationBinding {
        tenant_id: TenantId::new(),
        identity_id: identity(),
        device_id: DeviceId::new(),
        provider: Provider::Fcm,
        revision: Revision::new(1).unwrap(),
    };
    let registration_id = SecretId::new();
    let envelope = TokenEncryptionService::new_for_tests(kms.clone())
        .encrypt(
            binding,
            registration_id,
            &SecretToken::new(b"token".to_vec()).unwrap(),
        )
        .await
        .unwrap();
    let claim = DeliveryClaim {
        delivery_id: Uuid::now_v7(),
        claim_token: Uuid::now_v7(),
        registration_id,
        registration: binding,
        envelope,
        mailbox_id: Some(dtx_domain::MailboxId::new()),
        envelope_id: Some(dtx_domain::EnvelopeId::new()),
    };
    for (outcome, expected) in [
        (
            ProviderOutcome::Accepted,
            vec!["authorize", "send", "finish"],
        ),
        (
            ProviderOutcome::PermanentTokenInvalid,
            vec!["authorize", "send", "invalid_atomic"],
        ),
        (
            ProviderOutcome::PermanentFailure {
                redacted_class: RedactedFailureClass::Rejected,
            },
            vec!["authorize", "send", "finish"],
        ),
        (
            ProviderOutcome::Transient {
                retry_after: RetryDelay::new(1).unwrap(),
                redacted_class: RedactedFailureClass::Unavailable,
            },
            vec!["authorize", "send", "finish"],
        ),
        (
            ProviderOutcome::Transient {
                retry_after: RetryDelay::new(60).unwrap(),
                redacted_class: RedactedFailureClass::Throttled,
            },
            vec!["authorize", "send", "finish"],
        ),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let broker = Broker::new(
            RecordingPersistence {
                claim: Mutex::new(Some(claim.clone())),
                events: events.clone(),
                permit: Ok(Some(SendPermit {
                    registration_revision: 1,
                })),
                finish_result: Ok(true),
                transient_result: Ok(TransientResolution::Scheduled(
                    RetrySchedule::new(10, 11, 12).unwrap(),
                )),
            },
            kms.clone(),
            RecordingProvider {
                events: events.clone(),
                outcome,
            },
        );
        assert_eq!(broker.process_once(1).await.unwrap(), 1);
        assert_eq!(*events.lock().unwrap(), expected);
    }
    for permit in [
        Ok(None),
        Ok(Some(SendPermit {
            registration_revision: 2,
        })),
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let broker = Broker::new(
            RecordingPersistence {
                claim: Mutex::new(Some(claim.clone())),
                events: events.clone(),
                permit,
                finish_result: Ok(true),
                transient_result: Ok(TransientResolution::Scheduled(
                    RetrySchedule::new(10, 11, 12).unwrap(),
                )),
            },
            kms.clone(),
            RecordingProvider {
                events: events.clone(),
                outcome: ProviderOutcome::Accepted,
            },
        );
        assert_eq!(broker.process_once(1).await.unwrap(), 1);
        assert_eq!(*events.lock().unwrap(), vec!["authorize"]);
    }
    for resolution in [
        TransientResolution::Scheduled(RetrySchedule::new(10, 11, 12).unwrap()),
        TransientResolution::Expired,
        TransientResolution::FenceLost,
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let broker = Broker::new(
            RecordingPersistence {
                claim: Mutex::new(Some(claim.clone())),
                events: events.clone(),
                permit: Ok(Some(SendPermit {
                    registration_revision: 1,
                })),
                finish_result: Ok(true),
                transient_result: Ok(resolution),
            },
            kms.clone(),
            RecordingProvider {
                events: events.clone(),
                outcome: ProviderOutcome::Transient {
                    retry_after: RetryDelay::new(1).unwrap(),
                    redacted_class: RedactedFailureClass::Unavailable,
                },
            },
        );
        assert_eq!(broker.process_once(1).await.unwrap(), 1);
        assert_eq!(*events.lock().unwrap(), vec!["authorize", "send", "finish"]);
    }
    let events = Arc::new(Mutex::new(Vec::new()));
    let broker = Broker::new(
        RecordingPersistence {
            claim: Mutex::new(Some(claim.clone())),
            events: events.clone(),
            permit: Ok(Some(SendPermit {
                registration_revision: 1,
            })),
            finish_result: Ok(true),
            transient_result: Err(PushError::Persistence),
        },
        kms.clone(),
        RecordingProvider {
            events: events.clone(),
            outcome: ProviderOutcome::Transient {
                retry_after: RetryDelay::new(1).unwrap(),
                redacted_class: RedactedFailureClass::Unavailable,
            },
        },
    );
    assert_eq!(broker.process_once(1).await, Err(PushError::Persistence));
    assert_eq!(*events.lock().unwrap(), vec!["authorize", "send", "finish"]);
    for outcome in [
        ProviderOutcome::Accepted,
        ProviderOutcome::PermanentTokenInvalid,
        ProviderOutcome::PermanentFailure {
            redacted_class: RedactedFailureClass::Rejected,
        },
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let broker = Broker::new(
            RecordingPersistence {
                claim: Mutex::new(Some(claim.clone())),
                events: events.clone(),
                permit: Ok(Some(SendPermit {
                    registration_revision: 1,
                })),
                finish_result: Err(PushError::Persistence),
                transient_result: Ok(TransientResolution::Scheduled(
                    RetrySchedule::new(10, 11, 12).unwrap(),
                )),
            },
            kms.clone(),
            RecordingProvider {
                events: events.clone(),
                outcome,
            },
        );
        assert_eq!(broker.process_once(1).await, Err(PushError::Persistence));
        assert!(events.lock().unwrap().contains(&"send"));
    }
    let events = Arc::new(Mutex::new(Vec::new()));
    let broker = Broker::new(
        RecordingPersistence {
            claim: Mutex::new(Some(claim)),
            events: events.clone(),
            permit: Err(PushError::Persistence),
            finish_result: Ok(true),
            transient_result: Ok(TransientResolution::Scheduled(
                RetrySchedule::new(10, 11, 12).unwrap(),
            )),
        },
        kms,
        RecordingProvider {
            events: events.clone(),
            outcome: ProviderOutcome::Accepted,
        },
    );
    assert_eq!(broker.process_once(1).await, Err(PushError::Persistence));
    assert_eq!(*events.lock().unwrap(), vec!["authorize"]);
}

#[tokio::test]
async fn accepted_mark_failure_reclaim_replays_same_wake_id() {
    let kms = FakeKms::new();
    let binding = RegistrationBinding {
        tenant_id: TenantId::new(),
        identity_id: identity(),
        device_id: DeviceId::new(),
        provider: Provider::Fcm,
        revision: Revision::new(1).unwrap(),
    };
    let registration_id = SecretId::new();
    let envelope = TokenEncryptionService::new_for_tests(kms.clone())
        .encrypt(
            binding,
            registration_id,
            &SecretToken::new(b"token".to_vec()).unwrap(),
        )
        .await
        .unwrap();
    let claim = DeliveryClaim {
        delivery_id: Uuid::now_v7(),
        claim_token: Uuid::now_v7(),
        registration_id,
        registration: binding,
        envelope,
        mailbox_id: Some(dtx_domain::MailboxId::new()),
        envelope_id: Some(dtx_domain::EnvelopeId::new()),
    };
    let wake_ids = Arc::new(Mutex::new(Vec::new()));
    for finish_result in [Err(PushError::Persistence), Ok(true)] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let broker = Broker::new(
            RecordingPersistence {
                claim: Mutex::new(Some(claim.clone())),
                events,
                permit: Ok(Some(SendPermit {
                    registration_revision: 1,
                })),
                finish_result,
                transient_result: Ok(TransientResolution::FenceLost),
            },
            kms.clone(),
            WakeRecordingProvider(wake_ids.clone()),
        );
        let result = broker.process_once(1).await;
        assert_eq!(result.is_err(), finish_result.is_err());
    }
    assert_eq!(
        *wake_ids.lock().unwrap(),
        vec![claim.delivery_id, claim.delivery_id]
    );
}

#[test]
fn production_constructor_bounds_resolve_for_sealed_adapter() {
    use dtx_security::LocalRootKeyFileKms;
    let _: fn(LocalRootKeyFileKms) -> ProductionTokenEncryptionService<LocalRootKeyFileKms> =
        ProductionTokenEncryptionService::new;
    let _: fn(
        RecordingPersistence,
        LocalRootKeyFileKms,
        RecordingProvider,
    )
        -> ProductionBroker<RecordingPersistence, LocalRootKeyFileKms, RecordingProvider> =
        ProductionBroker::new;
}
