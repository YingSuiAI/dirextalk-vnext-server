use std::{error::Error, fmt};

use dtx_domain::RequestId;
use dtx_wire::StableCode;

/// Stable external-effect checkpoint owned by the adapter declaring the effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultPoint(StableCode);

impl FaultPoint {
    /// Parses a bounded stable checkpoint name.
    ///
    /// # Errors
    ///
    /// Returns the stable-code validation error for malformed names.
    pub fn parse(value: &str) -> Result<Self, dtx_wire::TextPrimitiveError> {
        StableCode::parse(value).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Crash windows surrounding a durable external side effect.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExternalEffectPhase {
    BeforeInvoke,
    AfterRemoteCommitBeforeReturn,
    AfterReturnBeforeReceipt,
    AfterReceiptBeforePublish,
}

/// Non-secret coordinates supplied to a failure-injection hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultCheckpoint {
    point: FaultPoint,
    phase: ExternalEffectPhase,
    operation_id: RequestId,
    attempt: u32,
}

impl FaultCheckpoint {
    /// Creates a checkpoint for a positive attempt number.
    ///
    /// # Errors
    ///
    /// Rejects attempt zero so retries have a canonical monotonic sequence.
    pub fn new(
        point: FaultPoint,
        phase: ExternalEffectPhase,
        operation_id: RequestId,
        attempt: u32,
    ) -> Result<Self, FaultCheckpointError> {
        if attempt == 0 {
            Err(FaultCheckpointError)
        } else {
            Ok(Self {
                point,
                phase,
                operation_id,
                attempt,
            })
        }
    }

    #[must_use]
    pub const fn point(&self) -> &FaultPoint {
        &self.point
    }

    #[must_use]
    pub const fn phase(&self) -> ExternalEffectPhase {
        self.phase
    }

    #[must_use]
    pub const fn operation_id(&self) -> RequestId {
        self.operation_id
    }

    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultCheckpointError;

impl fmt::Display for FaultCheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fault checkpoint attempt must be positive")
    }
}

impl Error for FaultCheckpointError {}

/// Crash signal that must propagate to a worker/process boundary unchanged.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrashRequested {
    checkpoint: FaultCheckpoint,
}

impl CrashRequested {
    #[must_use]
    pub const fn new(checkpoint: FaultCheckpoint) -> Self {
        Self { checkpoint }
    }

    #[must_use]
    pub const fn checkpoint(&self) -> &FaultCheckpoint {
        &self.checkpoint
    }
}

impl fmt::Display for CrashRequested {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "injected crash at {} {:?}",
            self.checkpoint.point().as_str(),
            self.checkpoint.phase()
        )
    }
}

impl Error for CrashRequested {}

/// Failure-injection seam. Production wiring uses [`NoFaults`].
pub trait FaultHook: Send + Sync {
    /// Evaluates one non-secret checkpoint.
    ///
    /// # Errors
    ///
    /// Test implementations return [`CrashRequested`] when an armed point is reached.
    fn checkpoint(&self, checkpoint: &FaultCheckpoint) -> Result<(), CrashRequested>;
}

/// Production implementation that cannot request a crash.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFaults;

impl FaultHook for NoFaults {
    fn checkpoint(&self, _: &FaultCheckpoint) -> Result<(), CrashRequested> {
        Ok(())
    }
}
