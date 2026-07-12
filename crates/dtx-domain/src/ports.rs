use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use uuid::{Uuid, Variant};

/// Source of UTC Unix timestamps in whole milliseconds.
pub trait Clock: Send + Sync {
    /// Returns the current UTC Unix timestamp in milliseconds.
    ///
    /// # Errors
    ///
    /// Returns [`ClockError`] when the platform time cannot fit in an `i64` millisecond value.
    fn now_utc_millis(&self) -> Result<i64, ClockError>;
}

/// Production wall-clock provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc_millis(&self) -> Result<i64, ClockError> {
        system_time_to_unix_millis(SystemTime::now())
    }
}

fn system_time_to_unix_millis(time: SystemTime) -> Result<i64, ClockError> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).map_err(|_| ClockError::OutOfRange),
        Err(error) => {
            let duration = error.duration();
            let partial_millisecond = u128::from(duration.subsec_nanos() % 1_000_000 != 0);
            let magnitude = duration
                .as_millis()
                .checked_add(partial_millisecond)
                .and_then(|value| i64::try_from(value).ok())
                .ok_or(ClockError::OutOfRange)?;
            magnitude.checked_neg().ok_or(ClockError::OutOfRange)
        }
    }
}

/// The platform clock was outside the supported integer range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClockError {
    /// UTC milliseconds could not fit in a signed 64-bit integer.
    OutOfRange,
}

impl fmt::Display for ClockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("system clock is outside the supported UTC millisecond range")
    }
}

impl Error for ClockError {}

/// Source of validated, lifecycle-scoped `UUIDv7` identifiers.
pub trait IdGenerator: Send + Sync {
    /// Returns a `UUIDv7` using the RFC 4122/9562 variant.
    ///
    /// # Errors
    ///
    /// Returns [`IdGenerationError`] if generation fails or produces an invalid value.
    fn next_uuid_v7(&self) -> Result<Uuid, IdGenerationError>;
}

/// Production `UUIDv7` generator.
#[derive(Clone, Copy, Debug, Default)]
pub struct UuidV7Generator;

impl IdGenerator for UuidV7Generator {
    fn next_uuid_v7(&self) -> Result<Uuid, IdGenerationError> {
        let value = Uuid::now_v7();
        validate_uuid_v7(value)?;
        Ok(value)
    }
}

fn validate_uuid_v7(value: Uuid) -> Result<(), IdGenerationError> {
    if value.get_version_num() == 7 && value.get_variant() == Variant::RFC4122 {
        Ok(())
    } else {
        Err(IdGenerationError::InvalidUuidV7)
    }
}

/// A `UUIDv7` provider failed without retaining or exposing the rejected value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdGenerationError {
    /// A configured or generated value was not an RFC `UUIDv7`.
    InvalidUuidV7,
    /// A deterministic test sequence had no values left.
    SequenceExhausted,
    /// Generator state could not be accessed.
    StateUnavailable,
}

impl fmt::Display for IdGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUuidV7 => "identifier is not a valid UUIDv7",
            Self::SequenceExhausted => "deterministic identifier sequence is exhausted",
            Self::StateUnavailable => "identifier generator state is unavailable",
        })
    }
}

impl Error for IdGenerationError {}

/// Deterministic providers for tests and local harnesses; do not wire these in production.
pub mod test_support {
    use super::{Clock, ClockError, IdGenerationError, IdGenerator, Mutex, Uuid, VecDeque};

    /// Clock that always returns one explicitly configured UTC millisecond value.
    #[derive(Clone, Copy, Debug)]
    pub struct FixedClock {
        utc_millis: i64,
    }

    impl FixedClock {
        /// Creates a deterministic clock for tests.
        #[must_use]
        pub const fn new(utc_millis: i64) -> Self {
            Self { utc_millis }
        }
    }

    impl Clock for FixedClock {
        fn now_utc_millis(&self) -> Result<i64, ClockError> {
            Ok(self.utc_millis)
        }
    }

    /// Thread-safe deterministic `UUIDv7` sequence for tests.
    pub struct SequenceIdGenerator {
        values: Mutex<VecDeque<Uuid>>,
    }

    impl SequenceIdGenerator {
        /// Creates a generator after validating every configured value.
        ///
        /// # Errors
        ///
        /// Returns [`IdGenerationError::InvalidUuidV7`] without exposing the rejected value.
        pub fn try_new(values: impl IntoIterator<Item = Uuid>) -> Result<Self, IdGenerationError> {
            let values = values.into_iter().collect::<VecDeque<_>>();
            for value in &values {
                super::validate_uuid_v7(*value)?;
            }
            Ok(Self {
                values: Mutex::new(values),
            })
        }
    }

    impl std::fmt::Debug for SequenceIdGenerator {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("SequenceIdGenerator")
                .finish_non_exhaustive()
        }
    }

    impl IdGenerator for SequenceIdGenerator {
        fn next_uuid_v7(&self) -> Result<Uuid, IdGenerationError> {
            self.values
                .lock()
                .map_err(|_| IdGenerationError::StateUnavailable)?
                .pop_front()
                .ok_or(IdGenerationError::SequenceExhausted)
        }
    }
}
