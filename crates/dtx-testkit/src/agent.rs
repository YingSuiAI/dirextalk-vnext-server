#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    fmt,
    sync::{Arc, Mutex},
};

use dtx_domain::{ApprovalId, RequestId, RunId};
use dtx_security::{
    CrashRequested, ExternalEffectPhase, FaultCheckpoint, FaultHook, FaultPoint, NoFaults,
};

/// Opaque digest used by the fake instead of prompts, tool arguments, or result bodies.
pub type RuntimeDigest = [u8; 32];

/// A deterministic runtime step configured by a test.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ScriptedAgentOutput {
    /// Commit a resumable runtime checkpoint.
    Checkpoint { state_digest: RuntimeDigest },
    /// Propose a typed tool call without executing it.
    ToolCallProposed {
        tool_call_id: RequestId,
        capability_digest: RuntimeDigest,
        arguments_digest: RuntimeDigest,
    },
    /// Suspend until a separately authorized approval is available.
    AwaitingApproval {
        approval_id: ApprovalId,
        plan_digest: RuntimeDigest,
    },
    /// Complete with a digest of the separately stored result.
    Completed { result_digest: RuntimeDigest },
    /// Fail with a stable, non-secret reason digest.
    Failed { reason_digest: RuntimeDigest },
}

/// A committed checkpoint that is safe to persist and later resume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeCheckpoint {
    run_id: RunId,
    lease_epoch: u64,
    sequence: u64,
    state_digest: RuntimeDigest,
}

impl RuntimeCheckpoint {
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    #[must_use]
    pub const fn lease_epoch(&self) -> u64 {
        self.lease_epoch
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn state_digest(&self) -> RuntimeDigest {
        self.state_digest
    }
}

/// Observable output from the deterministic runtime adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentRuntimeOutput {
    Checkpoint(RuntimeCheckpoint),
    ToolCallProposed {
        tool_call_id: RequestId,
        capability_digest: RuntimeDigest,
        arguments_digest: RuntimeDigest,
    },
    AwaitingApproval {
        approval_id: ApprovalId,
        plan_digest: RuntimeDigest,
    },
    Completed {
        result_digest: RuntimeDigest,
    },
    Failed {
        reason_digest: RuntimeDigest,
    },
    Cancelled,
}

/// Typed start command containing no prompt or plaintext request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartRun {
    operation_id: RequestId,
    run_id: RunId,
    lease_epoch: u64,
    request_digest: RuntimeDigest,
}

impl StartRun {
    /// Creates a start command with a positive fencing epoch.
    pub fn new(
        operation_id: RequestId,
        run_id: RunId,
        lease_epoch: u64,
        request_digest: RuntimeDigest,
    ) -> Result<Self, AgentRuntimeError> {
        validate_epoch(lease_epoch)?;
        Ok(Self {
            operation_id,
            run_id,
            lease_epoch,
            request_digest,
        })
    }

    #[must_use]
    pub const fn operation_id(&self) -> RequestId {
        self.operation_id
    }
}

/// Typed resume command bound to one committed checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeRun {
    operation_id: RequestId,
    run_id: RunId,
    lease_epoch: u64,
    checkpoint: RuntimeCheckpoint,
}

impl ResumeRun {
    /// Creates a resume command with a positive fencing epoch.
    pub fn new(
        operation_id: RequestId,
        run_id: RunId,
        lease_epoch: u64,
        checkpoint: RuntimeCheckpoint,
    ) -> Result<Self, AgentRuntimeError> {
        validate_epoch(lease_epoch)?;
        Ok(Self {
            operation_id,
            run_id,
            lease_epoch,
            checkpoint,
        })
    }
}

/// Typed cancellation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelRun {
    operation_id: RequestId,
    run_id: RunId,
    lease_epoch: u64,
}

impl CancelRun {
    /// Creates a cancellation command with a positive fencing epoch.
    pub fn new(
        operation_id: RequestId,
        run_id: RunId,
        lease_epoch: u64,
    ) -> Result<Self, AgentRuntimeError> {
        validate_epoch(lease_epoch)?;
        Ok(Self {
            operation_id,
            run_id,
            lease_epoch,
        })
    }
}

fn validate_epoch(lease_epoch: u64) -> Result<(), AgentRuntimeError> {
    if lease_epoch == 0 {
        Err(AgentRuntimeError::InvalidLeaseEpoch)
    } else {
        Ok(())
    }
}

/// Stable failures exposed by the fake runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentRuntimeError {
    InvalidLeaseEpoch,
    IdempotencyConflict,
    StaleLease,
    RunAlreadyStarted,
    RunNotFound,
    CheckpointMismatch,
    NoScriptedOutput,
    StateUnavailable,
    CrashRequested(CrashRequested),
}

impl fmt::Display for AgentRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLeaseEpoch => "lease epoch must be positive",
            Self::IdempotencyConflict => "runtime idempotency key was reused with different input",
            Self::StaleLease => "runtime command used a stale lease",
            Self::RunAlreadyStarted => "run already started and must be resumed",
            Self::RunNotFound => "run was not started",
            Self::CheckpointMismatch => "checkpoint does not match the committed runtime state",
            Self::NoScriptedOutput => "fake runtime script is exhausted",
            Self::StateUnavailable => "fake runtime state is unavailable",
            Self::CrashRequested(_) => "fake runtime crash requested",
        })
    }
}

impl Error for AgentRuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::CrashRequested(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RuntimeCommand {
    Start(StartRun),
    Resume(ResumeRun),
    Cancel(CancelRun),
}

impl RuntimeCommand {
    const fn operation_id(&self) -> RequestId {
        match self {
            Self::Start(value) => value.operation_id,
            Self::Resume(value) => value.operation_id,
            Self::Cancel(value) => value.operation_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CachedRuntimeResult {
    command: RuntimeCommand,
    output: AgentRuntimeOutput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RunState {
    lease_epoch: u64,
    checkpoint: Option<RuntimeCheckpoint>,
    cancelled: bool,
    terminal: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AgentWorldState {
    script: VecDeque<ScriptedAgentOutput>,
    runs: HashMap<RunId, RunState>,
    results: HashMap<RequestId, CachedRuntimeResult>,
    attempts: HashMap<RequestId, u32>,
    applied_steps: usize,
}

/// Durable fake-runtime snapshot used to simulate a process restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeAgentWorldSnapshot(AgentWorldState);

/// External runtime state that survives dropping and recreating an adapter handle.
#[derive(Clone, Debug)]
pub struct FakeAgentWorld {
    state: Arc<Mutex<AgentWorldState>>,
}

impl FakeAgentWorld {
    #[must_use]
    pub fn new(script: impl IntoIterator<Item = ScriptedAgentOutput>) -> Self {
        Self {
            state: Arc::new(Mutex::new(AgentWorldState {
                script: script.into_iter().collect(),
                runs: HashMap::new(),
                results: HashMap::new(),
                attempts: HashMap::new(),
                applied_steps: 0,
            })),
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> FakeAgentWorldSnapshot {
        FakeAgentWorldSnapshot(
            self.state
                .lock()
                .expect("fake agent world mutex poisoned")
                .clone(),
        )
    }

    #[must_use]
    pub fn from_snapshot(snapshot: FakeAgentWorldSnapshot) -> Self {
        Self {
            state: Arc::new(Mutex::new(snapshot.0)),
        }
    }

    #[must_use]
    pub fn applied_step_count(&self) -> usize {
        self.state
            .lock()
            .expect("fake agent world mutex poisoned")
            .applied_steps
    }
}

/// Re-creatable adapter handle over a durable [`FakeAgentWorld`].
pub struct FakeAgentRuntime {
    world: FakeAgentWorld,
    fault_hook: Arc<dyn FaultHook>,
}

impl fmt::Debug for FakeAgentRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeAgentRuntime")
            .field("world", &self.world)
            .field("fault_hook", &"<fault-hook>")
            .finish()
    }
}

impl FakeAgentRuntime {
    #[must_use]
    pub fn new(world: FakeAgentWorld) -> Self {
        Self::with_fault_hook(world, Arc::new(NoFaults))
    }

    #[must_use]
    pub fn with_fault_hook(world: FakeAgentWorld, fault_hook: Arc<dyn FaultHook>) -> Self {
        Self { world, fault_hook }
    }

    /// Starts a run exactly once for a given operation ID.
    pub fn start(&self, request: &StartRun) -> Result<AgentRuntimeOutput, AgentRuntimeError> {
        self.execute(RuntimeCommand::Start(request.clone()))
    }

    /// Resumes only from the exact committed checkpoint.
    pub fn resume(&self, request: &ResumeRun) -> Result<AgentRuntimeOutput, AgentRuntimeError> {
        self.execute(RuntimeCommand::Resume(request.clone()))
    }

    /// Cancels a run idempotently under the current fencing epoch.
    pub fn cancel(&self, request: &CancelRun) -> Result<AgentRuntimeOutput, AgentRuntimeError> {
        self.execute(RuntimeCommand::Cancel(request.clone()))
    }

    fn execute(&self, command: RuntimeCommand) -> Result<AgentRuntimeOutput, AgentRuntimeError> {
        let operation_id = command.operation_id();
        {
            let state = self
                .world
                .state
                .lock()
                .map_err(|_| AgentRuntimeError::StateUnavailable)?;
            if let Some(cached) = state.results.get(&operation_id) {
                return if cached.command == command {
                    Ok(cached.output.clone())
                } else {
                    Err(AgentRuntimeError::IdempotencyConflict)
                };
            }
            validate_runtime_command(&state, &command)?;
        }

        let attempt = self.next_attempt(operation_id)?;
        self.fault(operation_id, attempt, ExternalEffectPhase::BeforeInvoke)?;

        let output = {
            let mut state = self
                .world
                .state
                .lock()
                .map_err(|_| AgentRuntimeError::StateUnavailable)?;
            // Recheck after the hook because another adapter handle may have committed.
            if let Some(cached) = state.results.get(&operation_id) {
                return if cached.command == command {
                    Ok(cached.output.clone())
                } else {
                    Err(AgentRuntimeError::IdempotencyConflict)
                };
            }
            validate_runtime_command(&state, &command)?;
            let output = apply_runtime_command(&mut state, &command)?;
            state.results.insert(
                operation_id,
                CachedRuntimeResult {
                    command,
                    output: output.clone(),
                },
            );
            output
        };

        self.fault(
            operation_id,
            attempt,
            ExternalEffectPhase::AfterRemoteCommitBeforeReturn,
        )?;
        Ok(output)
    }

    fn fault(
        &self,
        operation_id: RequestId,
        attempt: u32,
        phase: ExternalEffectPhase,
    ) -> Result<(), AgentRuntimeError> {
        let point = FaultPoint::parse("fake_agent_runtime")
            .map_err(|_| AgentRuntimeError::StateUnavailable)?;
        let checkpoint = FaultCheckpoint::new(point, phase, operation_id, attempt)
            .map_err(|_| AgentRuntimeError::StateUnavailable)?;
        self.fault_hook
            .checkpoint(&checkpoint)
            .map_err(AgentRuntimeError::CrashRequested)
    }

    fn next_attempt(&self, operation_id: RequestId) -> Result<u32, AgentRuntimeError> {
        let mut state = self
            .world
            .state
            .lock()
            .map_err(|_| AgentRuntimeError::StateUnavailable)?;
        let attempt = state.attempts.entry(operation_id).or_default();
        *attempt = attempt
            .checked_add(1)
            .ok_or(AgentRuntimeError::StateUnavailable)?;
        Ok(*attempt)
    }
}

fn validate_runtime_command(
    state: &AgentWorldState,
    command: &RuntimeCommand,
) -> Result<(), AgentRuntimeError> {
    match command {
        RuntimeCommand::Start(request) => {
            if let Some(run) = state.runs.get(&request.run_id) {
                if request.lease_epoch < run.lease_epoch {
                    Err(AgentRuntimeError::StaleLease)
                } else {
                    Err(AgentRuntimeError::RunAlreadyStarted)
                }
            } else {
                Ok(())
            }
        }
        RuntimeCommand::Resume(request) => {
            let run = state
                .runs
                .get(&request.run_id)
                .ok_or(AgentRuntimeError::RunNotFound)?;
            if request.lease_epoch < run.lease_epoch {
                return Err(AgentRuntimeError::StaleLease);
            }
            if run.cancelled || run.terminal || run.checkpoint.as_ref() != Some(&request.checkpoint)
            {
                return Err(AgentRuntimeError::CheckpointMismatch);
            }
            Ok(())
        }
        RuntimeCommand::Cancel(request) => {
            let run = state
                .runs
                .get(&request.run_id)
                .ok_or(AgentRuntimeError::RunNotFound)?;
            if request.lease_epoch < run.lease_epoch {
                Err(AgentRuntimeError::StaleLease)
            } else {
                Ok(())
            }
        }
    }
}

fn apply_runtime_command(
    state: &mut AgentWorldState,
    command: &RuntimeCommand,
) -> Result<AgentRuntimeOutput, AgentRuntimeError> {
    match command {
        RuntimeCommand::Start(request) => {
            let scripted = state
                .script
                .pop_front()
                .ok_or(AgentRuntimeError::NoScriptedOutput)?;
            let mut run = RunState {
                lease_epoch: request.lease_epoch,
                checkpoint: None,
                cancelled: false,
                terminal: false,
            };
            let output = materialize_output(&mut run, request.run_id, scripted);
            state.runs.insert(request.run_id, run);
            state.applied_steps += 1;
            Ok(output)
        }
        RuntimeCommand::Resume(request) => {
            let scripted = state
                .script
                .pop_front()
                .ok_or(AgentRuntimeError::NoScriptedOutput)?;
            let run = state
                .runs
                .get_mut(&request.run_id)
                .ok_or(AgentRuntimeError::RunNotFound)?;
            run.lease_epoch = request.lease_epoch;
            let output = materialize_output(run, request.run_id, scripted);
            state.applied_steps += 1;
            Ok(output)
        }
        RuntimeCommand::Cancel(request) => {
            let run = state
                .runs
                .get_mut(&request.run_id)
                .ok_or(AgentRuntimeError::RunNotFound)?;
            run.lease_epoch = request.lease_epoch;
            run.cancelled = true;
            run.terminal = true;
            Ok(AgentRuntimeOutput::Cancelled)
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn materialize_output(
    run: &mut RunState,
    run_id: RunId,
    scripted: ScriptedAgentOutput,
) -> AgentRuntimeOutput {
    match scripted {
        ScriptedAgentOutput::Checkpoint { state_digest } => {
            let sequence = run
                .checkpoint
                .as_ref()
                .map_or(1, |checkpoint| checkpoint.sequence + 1);
            let checkpoint = RuntimeCheckpoint {
                run_id,
                lease_epoch: run.lease_epoch,
                sequence,
                state_digest,
            };
            run.checkpoint = Some(checkpoint.clone());
            AgentRuntimeOutput::Checkpoint(checkpoint)
        }
        ScriptedAgentOutput::ToolCallProposed {
            tool_call_id,
            capability_digest,
            arguments_digest,
        } => AgentRuntimeOutput::ToolCallProposed {
            tool_call_id,
            capability_digest,
            arguments_digest,
        },
        ScriptedAgentOutput::AwaitingApproval {
            approval_id,
            plan_digest,
        } => AgentRuntimeOutput::AwaitingApproval {
            approval_id,
            plan_digest,
        },
        ScriptedAgentOutput::Completed { result_digest } => {
            run.terminal = true;
            AgentRuntimeOutput::Completed { result_digest }
        }
        ScriptedAgentOutput::Failed { reason_digest } => {
            run.terminal = true;
            AgentRuntimeOutput::Failed { reason_digest }
        }
    }
}
