#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]

mod broker;
mod error;
mod pool;
mod registration;

#[cfg(test)]
mod postgres_acceptance;

pub use broker::PostgresPushPersistence;
pub use error::{ErrorCategory, PushPostgresError};
pub type AdapterError = PushPostgresError;
pub use pool::{BrokerPool, IdentityAuthPool, RegistrationPool};
pub use registration::{
    PushRegistrationService, RegistrationAction, RegistrationRequest, RegistrationResult,
    TokenSealer,
};
