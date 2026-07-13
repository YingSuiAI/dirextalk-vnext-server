use std::{collections::VecDeque, sync::Mutex};

use dtx_domain::{Clock, ClockError, IdGenerationError, IdGenerator};
use uuid::{Uuid, Variant};

/// Clock that always returns one explicitly configured UTC millisecond value.
#[derive(Clone, Copy, Debug)]
pub struct FixedClock {
    utc_millis: i64,
}

impl FixedClock {
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
    /// Rejects a non-v7/non-RFC fixture without including its value in the error.
    pub fn try_new(values: impl IntoIterator<Item = Uuid>) -> Result<Self, IdGenerationError> {
        let values = values.into_iter().collect::<VecDeque<_>>();
        if values
            .iter()
            .any(|value| value.get_version_num() != 7 || value.get_variant() != Variant::RFC4122)
        {
            return Err(IdGenerationError::InvalidUuidV7);
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
