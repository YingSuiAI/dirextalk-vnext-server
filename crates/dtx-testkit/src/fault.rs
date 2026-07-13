use std::{
    error::Error,
    fmt,
    sync::{Mutex, MutexGuard},
};

use dtx_domain::RequestId;
use dtx_security::{
    CrashRequested, ExternalEffectPhase, FaultCheckpoint, FaultCheckpointError, FaultHook,
};

/// Mandatory crash windows from development specification section 18.5.
///
/// The enum lives only in the test kit; production adapters own their concrete fault points.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RequiredFaultPoint {
    CommandBeforeTransactionCommit,
    ResourceIntentCommittedBeforeProviderInvoke,
    ProviderCommittedBeforeResponse,
    ProviderResponseBeforeLedger,
    LedgerCommittedBeforeOutbox,
    ConnectorToolExecutedBeforeCheckpoint,
    LeaseExpiredBeforeStaleSubmission,
    ArtifactUploadedBeforeVerification,
    ResultVerifiedBeforeEphemeralDestroy,
    TerminateSucceededBeforeTerminalObservation,
    JobCompletedBeforePersistentHandoff,
    ProviderAheadOfRecoveredControlPlane,
    JanitorRunningWithControlPlaneOffline,
    ManagedServiceDeployFailedBeforeRollback,
}

impl RequiredFaultPoint {
    pub const ALL: [Self; 14] = [
        Self::CommandBeforeTransactionCommit,
        Self::ResourceIntentCommittedBeforeProviderInvoke,
        Self::ProviderCommittedBeforeResponse,
        Self::ProviderResponseBeforeLedger,
        Self::LedgerCommittedBeforeOutbox,
        Self::ConnectorToolExecutedBeforeCheckpoint,
        Self::LeaseExpiredBeforeStaleSubmission,
        Self::ArtifactUploadedBeforeVerification,
        Self::ResultVerifiedBeforeEphemeralDestroy,
        Self::TerminateSucceededBeforeTerminalObservation,
        Self::JobCompletedBeforePersistentHandoff,
        Self::ProviderAheadOfRecoveredControlPlane,
        Self::JanitorRunningWithControlPlaneOffline,
        Self::ManagedServiceDeployFailedBeforeRollback,
    ];

    /// Returns the stable owner-facing checkpoint identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommandBeforeTransactionCommit => "command.before_transaction_commit",
            Self::ResourceIntentCommittedBeforeProviderInvoke => {
                "resource_intent.after_commit_before_provider"
            }
            Self::ProviderCommittedBeforeResponse => "provider.after_remote_commit_before_return",
            Self::ProviderResponseBeforeLedger => "provider.after_return_before_ledger",
            Self::LedgerCommittedBeforeOutbox => "ledger.after_commit_before_outbox",
            Self::ConnectorToolExecutedBeforeCheckpoint => "connector.after_tool_before_checkpoint",
            Self::LeaseExpiredBeforeStaleSubmission => "lease.after_expiry_before_stale_submit",
            Self::ArtifactUploadedBeforeVerification => "artifact.after_upload_before_verification",
            Self::ResultVerifiedBeforeEphemeralDestroy => {
                "job.after_verification_before_ephemeral_destroy"
            }
            Self::TerminateSucceededBeforeTerminalObservation => {
                "provider.after_terminate_before_terminal_observation"
            }
            Self::JobCompletedBeforePersistentHandoff => {
                "job.after_completion_before_persistent_handoff"
            }
            Self::ProviderAheadOfRecoveredControlPlane => {
                "recovery.provider_ahead_of_control_plane"
            }
            Self::JanitorRunningWithControlPlaneOffline => "janitor.control_plane_offline",
            Self::ManagedServiceDeployFailedBeforeRollback => {
                "managed_service.after_deploy_failure_before_rollback"
            }
        }
    }

    /// Returns the only valid external-effect phase for this required crash window.
    #[must_use]
    pub const fn phase(self) -> ExternalEffectPhase {
        match self {
            Self::CommandBeforeTransactionCommit
            | Self::ResourceIntentCommittedBeforeProviderInvoke
            | Self::LeaseExpiredBeforeStaleSubmission
            | Self::ResultVerifiedBeforeEphemeralDestroy
            | Self::JanitorRunningWithControlPlaneOffline
            | Self::ManagedServiceDeployFailedBeforeRollback => ExternalEffectPhase::BeforeInvoke,
            Self::ProviderCommittedBeforeResponse
            | Self::ConnectorToolExecutedBeforeCheckpoint
            | Self::ArtifactUploadedBeforeVerification
            | Self::TerminateSucceededBeforeTerminalObservation
            | Self::ProviderAheadOfRecoveredControlPlane => {
                ExternalEffectPhase::AfterRemoteCommitBeforeReturn
            }
            Self::ProviderResponseBeforeLedger => ExternalEffectPhase::AfterReturnBeforeReceipt,
            Self::LedgerCommittedBeforeOutbox | Self::JobCompletedBeforePersistentHandoff => {
                ExternalEffectPhase::AfterReceiptBeforePublish
            }
        }
    }

    /// Creates a checkpoint with the registry-owned name and phase.
    ///
    /// # Errors
    ///
    /// Returns [`FaultCheckpointError`] when `attempt` is zero.
    ///
    /// # Panics
    ///
    /// Panics only if one of this enum's compile-time stable names is invalid.
    pub fn checkpoint(
        self,
        operation_id: RequestId,
        attempt: u32,
    ) -> Result<FaultCheckpoint, FaultCheckpointError> {
        let point = dtx_security::FaultPoint::parse(self.as_str())
            .expect("required fault point names are compile-time valid stable codes");
        FaultCheckpoint::new(point, self.phase(), operation_id, attempt)
    }
}

/// Observable outcome of one failure-injection checkpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultDisposition {
    Continued,
    CrashRequested,
}

/// Redacted checkpoint observation retained by [`ScriptedFaults`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultTranscriptEntry {
    checkpoint: FaultCheckpoint,
    disposition: FaultDisposition,
}

impl FaultTranscriptEntry {
    #[must_use]
    pub const fn checkpoint(&self) -> &FaultCheckpoint {
        &self.checkpoint
    }

    #[must_use]
    pub const fn disposition(&self) -> FaultDisposition {
        self.disposition
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArmedFault {
    checkpoint: FaultCheckpoint,
    consumed: bool,
}

#[derive(Default)]
struct ScriptedFaultState {
    plans: Vec<ArmedFault>,
    transcript: Vec<FaultTranscriptEntry>,
}

/// Thread-safe, exact-match, one-shot crash injector for recovery tests.
#[derive(Default)]
pub struct ScriptedFaults {
    state: Mutex<ScriptedFaultState>,
}

impl ScriptedFaults {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(ScriptedFaultState {
                plans: Vec::new(),
                transcript: Vec::new(),
            }),
        }
    }

    /// Arms one exact checkpoint. An identical unconsumed plan is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`FaultPlanError`] when the same checkpoint is already armed.
    pub fn arm_once(&self, checkpoint: FaultCheckpoint) -> Result<(), FaultPlanError> {
        let mut state = self.state();
        if state
            .plans
            .iter()
            .any(|plan| !plan.consumed && plan.checkpoint == checkpoint)
        {
            return Err(FaultPlanError::DuplicateCheckpoint);
        }
        state.plans.push(ArmedFault {
            checkpoint,
            consumed: false,
        });
        Ok(())
    }

    /// Returns a redacted snapshot in checkpoint observation order.
    #[must_use]
    pub fn transcript(&self) -> Vec<FaultTranscriptEntry> {
        self.state().transcript.clone()
    }

    /// Verifies that every armed crash point was reached exactly once.
    ///
    /// # Errors
    ///
    /// Returns a count-only error when one or more plans were not consumed.
    pub fn assert_consumed(&self) -> Result<(), UnconsumedFaults> {
        let remaining = self
            .state()
            .plans
            .iter()
            .filter(|plan| !plan.consumed)
            .count();
        if remaining == 0 {
            Ok(())
        } else {
            Err(UnconsumedFaults { remaining })
        }
    }

    fn state(&self) -> MutexGuard<'_, ScriptedFaultState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl fmt::Debug for ScriptedFaults {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state();
        formatter
            .debug_struct("ScriptedFaults")
            .field("plan_count", &state.plans.len())
            .field("transcript_count", &state.transcript.len())
            .finish()
    }
}

impl FaultHook for ScriptedFaults {
    fn checkpoint(&self, checkpoint: &FaultCheckpoint) -> Result<(), CrashRequested> {
        let mut state = self.state();
        let disposition = if let Some(plan) = state
            .plans
            .iter_mut()
            .find(|plan| !plan.consumed && plan.checkpoint == *checkpoint)
        {
            plan.consumed = true;
            FaultDisposition::CrashRequested
        } else {
            FaultDisposition::Continued
        };
        state.transcript.push(FaultTranscriptEntry {
            checkpoint: checkpoint.clone(),
            disposition,
        });
        match disposition {
            FaultDisposition::Continued => Ok(()),
            FaultDisposition::CrashRequested => Err(CrashRequested::new(checkpoint.clone())),
        }
    }
}

/// Invalid deterministic crash plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultPlanError {
    DuplicateCheckpoint,
}

impl fmt::Display for FaultPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fault checkpoint is already armed")
    }
}

impl Error for FaultPlanError {}

/// One or more armed crash points were never reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnconsumedFaults {
    remaining: usize,
}

impl UnconsumedFaults {
    #[must_use]
    pub const fn remaining(self) -> usize {
        self.remaining
    }
}

impl fmt::Display for UnconsumedFaults {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} armed fault checkpoint(s) were not consumed",
            self.remaining
        )
    }
}

impl Error for UnconsumedFaults {}
