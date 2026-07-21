use crate::{Provider, PushError, RetryDelay, SecretToken, TransportPolicy, WakePayload};
use std::{future::Future, pin::Pin};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedactedFailureClass {
    Unavailable,
    Throttled,
    Rejected,
    InvalidRequest,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderOutcome {
    Accepted,
    Transient {
        retry_after: RetryDelay,
        redacted_class: RedactedFailureClass,
    },
    PermanentTokenInvalid,
    PermanentFailure {
        redacted_class: RedactedFailureClass,
    },
}

pub trait PushProvider: Send + Sync {
    fn send<'a>(
        &'a self,
        provider: Provider,
        token: &'a SecretToken,
        payload: &'a WakePayload,
        policy: TransportPolicy,
    ) -> Pin<Box<dyn Future<Output = ProviderOutcome> + Send + 'a>>;
}

impl From<ProviderOutcome> for Result<(), PushError> {
    fn from(outcome: ProviderOutcome) -> Self {
        match outcome {
            ProviderOutcome::Accepted => Ok(()),
            ProviderOutcome::Transient { .. } | ProviderOutcome::PermanentFailure { .. } => {
                Err(PushError::ProviderUnavailable)
            }
            ProviderOutcome::PermanentTokenInvalid => Err(PushError::RegistrationRevoked),
        }
    }
}
