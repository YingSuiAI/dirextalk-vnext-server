use crate::{
    Provider, ProviderOutcome, PushError, PushProvider, RegistrationBinding,
    TokenEncryptionService, TokenEnvelope, TransportPolicy, WakePayload,
};
use dtx_domain::{EnvelopeId, MailboxId, Revision, SecretId};
use dtx_security::KeyManagement;
use std::{future::Future, pin::Pin};
use uuid::Uuid;

pub const MAX_CLAIM_BATCH: u16 = 128;
pub const LEASE_SECONDS: u64 = 30;
pub const DELIVERY_TTL_SECONDS: u64 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryDelay(u64);
impl RetryDelay {
    pub fn new(seconds: u64) -> Option<Self> {
        let seconds = seconds.min(60);
        (seconds > 0).then_some(Self(seconds))
    }
    pub const fn seconds(self) -> u64 {
        self.0
    }
}

/// A database-authoritative retry appointment.  It cannot be manufactured
/// without proving that it remains strictly inside the delivery lifetime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetrySchedule {
    next_attempt_at_ms: u64,
}
impl RetrySchedule {
    pub fn new(db_now_ms: u64, next_attempt_at_ms: u64, expires_at_ms: u64) -> Option<Self> {
        (db_now_ms < next_attempt_at_ms && next_attempt_at_ms < expires_at_ms)
            .then_some(Self { next_attempt_at_ms })
    }
    pub const fn next_attempt_at_ms(self) -> u64 {
        self.next_attempt_at_ms
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransientResolution {
    Scheduled(RetrySchedule),
    Expired,
    FenceLost,
}

#[derive(Clone)]
pub struct DeliveryClaim {
    pub(crate) delivery_id: Uuid,
    pub(crate) claim_token: Uuid,
    pub(crate) registration_id: SecretId,
    pub(crate) registration: RegistrationBinding,
    pub(crate) envelope: TokenEnvelope,
    pub(crate) mailbox_id: Option<MailboxId>,
    pub(crate) envelope_id: Option<EnvelopeId>,
}
impl DeliveryClaim {
    pub fn new(
        delivery_id: Uuid,
        claim_token: Uuid,
        registration_id: SecretId,
        registration: RegistrationBinding,
        envelope: TokenEnvelope,
        provenance: Option<(MailboxId, EnvelopeId)>,
    ) -> Result<Self, PushError> {
        if delivery_id.get_version_num() != 7
            || claim_token.get_version_num() != 7
            || envelope.registration_binding() != registration
        {
            return Err(PushError::EnvelopeInvalid);
        }
        let (mailbox_id, envelope_id) =
            provenance.map_or((None, None), |(m, e)| (Some(m), Some(e)));
        Ok(Self {
            delivery_id,
            claim_token,
            registration_id,
            registration,
            envelope,
            mailbox_id,
            envelope_id,
        })
    }
    pub const fn delivery_id(&self) -> Uuid {
        self.delivery_id
    }
    pub const fn claim_token(&self) -> Uuid {
        self.claim_token
    }
    pub const fn registration_id(&self) -> SecretId {
        self.registration_id
    }
    pub const fn registration(&self) -> RegistrationBinding {
        self.registration
    }
    pub const fn envelope(&self) -> &TokenEnvelope {
        &self.envelope
    }
    pub const fn provenance(&self) -> Option<(MailboxId, EnvelopeId)> {
        match (self.mailbox_id, self.envelope_id) {
            (Some(mailbox), Some(envelope)) => Some((mailbox, envelope)),
            _ => None,
        }
    }
}

/// DB-time permit returned by an authoritative fenced recheck immediately before provider I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendPermit {
    pub registration_revision: u64,
}
impl SendPermit {
    pub fn new(registration_revision: u64) -> Result<Self, PushError> {
        Revision::new(registration_revision).map_err(|_| PushError::RevisionOutOfRange)?;
        Ok(Self {
            registration_revision,
        })
    }
    pub const fn registration_revision(self) -> u64 {
        self.registration_revision
    }
}

/// Durable operations use database-authoritative time.  In particular, every
/// finish operation atomically checks the claim fence and delivery expiry; a
/// transient finish must calculate and cap its appointment in that same SQL
/// operation rather than accepting caller time.
pub trait PushPersistence: Send + Sync {
    fn claim<'a>(
        &'a self,
        maximum_rows: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<DeliveryClaim>, PushError>> + Send + 'a>>;
    fn authorize_send<'a>(
        &'a self,
        claim: &'a DeliveryClaim,
    ) -> Pin<Box<dyn Future<Output = Result<Option<SendPermit>, PushError>> + Send + 'a>>;
    fn finish_accepted<'a>(
        &'a self,
        delivery_id: Uuid,
        claim_token: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<bool, PushError>> + Send + 'a>>;
    fn finish_permanent_failure<'a>(
        &'a self,
        delivery_id: Uuid,
        claim_token: Uuid,
    ) -> Pin<Box<dyn Future<Output = Result<bool, PushError>> + Send + 'a>>;
    fn finish_transient_before_expiry<'a>(
        &'a self,
        delivery_id: Uuid,
        claim_token: Uuid,
        retry_after: RetryDelay,
        redacted_class: crate::RedactedFailureClass,
    ) -> Pin<Box<dyn Future<Output = Result<TransientResolution, PushError>> + Send + 'a>>;
    fn finish_invalid_token<'a>(
        &'a self,
        claim: &'a DeliveryClaim,
    ) -> Pin<Box<dyn Future<Output = Result<bool, PushError>> + Send + 'a>>;
}

pub struct Broker<S, K, P> {
    persistence: S,
    crypto: TokenEncryptionService<K>,
    provider: P,
    transport: TransportPolicy,
}

impl<S: PushPersistence, K: KeyManagement, P: PushProvider> Broker<S, K, P> {
    pub(crate) fn new(persistence: S, kms: K, provider: P) -> Self {
        Self {
            persistence,
            crypto: TokenEncryptionService::new(kms),
            provider,
            transport: TransportPolicy::default(),
        }
    }

    pub async fn process_once(&self, maximum_rows: u16) -> Result<usize, PushError> {
        let rows = self
            .persistence
            .claim(maximum_rows.min(MAX_CLAIM_BATCH))
            .await?;
        let mut processed = 0;
        for claim in rows {
            processed += 1;
            let Ok(token) = self
                .crypto
                .decrypt(claim.registration, claim.registration_id, &claim.envelope)
                .await
            else {
                let _ = self
                    .persistence
                    .finish_permanent_failure(claim.delivery_id, claim.claim_token)
                    .await?;
                continue;
            };
            let permit = match self.persistence.authorize_send(&claim).await {
                Ok(Some(permit)) => permit,
                Ok(None) => continue,
                Err(error) => return Err(error),
            };
            if permit.registration_revision() != claim.registration.revision.get() {
                continue;
            }
            let payload = WakePayload::new(
                crate::WakeDeliveryId::parse(&claim.delivery_id.hyphenated().to_string())
                    .map_err(|_| PushError::InvalidWakeDeliveryId)?,
            );
            let outcome = self
                .provider
                .send(Provider::Fcm, &token, &payload, self.transport)
                .await;
            match outcome {
                ProviderOutcome::Accepted => {
                    let _ = self
                        .persistence
                        .finish_accepted(claim.delivery_id, claim.claim_token)
                        .await?;
                }
                ProviderOutcome::PermanentTokenInvalid => {
                    let _ = self.persistence.finish_invalid_token(&claim).await?;
                }
                ProviderOutcome::PermanentFailure { .. } => {
                    let _ = self
                        .persistence
                        .finish_permanent_failure(claim.delivery_id, claim.claim_token)
                        .await?;
                }
                ProviderOutcome::Transient {
                    retry_after,
                    redacted_class,
                } => {
                    match self
                        .persistence
                        .finish_transient_before_expiry(
                            claim.delivery_id,
                            claim.claim_token,
                            retry_after,
                            redacted_class,
                        )
                        .await?
                    {
                        TransientResolution::Scheduled(_)
                        | TransientResolution::Expired
                        | TransientResolution::FenceLost => {}
                    }
                }
            }
        }
        Ok(processed)
    }
}

/// Production assembly is only available for sealed production KMS adapters.
pub struct ProductionBroker<S, K, P>(Broker<S, K, P>);
impl<S: PushPersistence, K: dtx_security::ProductionKeyManagement, P: PushProvider>
    ProductionBroker<S, K, P>
{
    pub fn new(persistence: S, kms: K, provider: P) -> Self {
        Self(Broker::new(persistence, kms, provider))
    }
    pub fn into_inner(self) -> Broker<S, K, P> {
        self.0
    }
}
