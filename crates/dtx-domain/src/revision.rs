use std::{error::Error, fmt};

/// Monotonically increasing aggregate revision that is exact on JSON/web clients.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Revision(u64);

impl Revision {
    /// First persisted aggregate revision.
    pub const INITIAL: Self = Self(1);

    /// Largest revision represented exactly by all supported clients (`2^53 - 1`).
    pub const MAX: u64 = (1_u64 << 53) - 1;

    /// Validates a persisted revision.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionError::OutOfRange`] for zero or values above [`Self::MAX`].
    pub const fn new(value: u64) -> Result<Self, RevisionError> {
        if value == 0 || value > Self::MAX {
            Err(RevisionError::OutOfRange)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the stored integer value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Produces the next revision without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`RevisionError::Overflow`] at [`Self::MAX`].
    pub const fn checked_next(self) -> Result<Self, RevisionError> {
        if self.0 == Self::MAX {
            Err(RevisionError::Overflow)
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

impl TryFrom<u64> for Revision {
    type Error = RevisionError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Revision> for u64 {
    fn from(value: Revision) -> Self {
        value.get()
    }
}

/// A revision was invalid or could not advance safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevisionError {
    /// Revisions are restricted to `1..=2^53-1`.
    OutOfRange,
    /// The maximum revision cannot advance.
    Overflow,
}

impl fmt::Display for RevisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OutOfRange => "revision must be between 1 and 2^53-1",
            Self::Overflow => "revision cannot advance beyond 2^53-1",
        })
    }
}

impl Error for RevisionError {}
