use std::{collections::BTreeSet, error::Error, fmt};

use dtx_connect_registry::AdapterKind;
use dtx_domain::RunId;

use crate::Sha256Digest;

/// Maximum UTF-8 bytes accepted for one reported runtime version.
pub const MAX_RUNTIME_VERSION_BYTES: usize = 128;
/// Maximum bytes accepted for one stable, redacted runtime error code.
pub const MAX_RUNTIME_ERROR_CODE_BYTES: usize = 64;
/// Maximum bytes accepted for one reported capability name.
pub const MAX_CAPABILITY_NAME_BYTES: usize = 128;
/// Maximum number of capability names accepted in one report.
pub const MAX_RUNTIME_CAPABILITIES: usize = 64;
/// Maximum number of active Run IDs accepted in one report.
pub const MAX_ACTIVE_RUN_IDS: usize = 1_024;
/// Maximum reported queue depth frozen by `agent-control/1`.
pub const MAX_RUNTIME_QUEUE_DEPTH: u32 = 1_000_000;

/// Bounded, untrusted runtime facts reported by a Connector.
///
/// These facts deliberately have no conversion to adapter conformance,
/// permissions, bindings, or routing authority. Those trust decisions belong
/// to separate aggregates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeClaims {
    adapter_kind: AdapterKind,
    runtime_version: String,
    adapter_build_digest: Sha256Digest,
    queue_depth: u32,
    active_run_ids: Vec<RunId>,
    stable_error_code: Option<String>,
    capabilities: Vec<String>,
}

/// Complete constructible persistence image for [`RuntimeClaims`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeClaimsSnapshot {
    pub adapter_kind: AdapterKind,
    pub runtime_version: String,
    pub adapter_build_digest: Sha256Digest,
    pub queue_depth: u32,
    pub active_run_ids: Vec<RunId>,
    pub stable_error_code: Option<String>,
    pub capabilities: Vec<String>,
}

impl RuntimeClaims {
    /// Validates and canonicalizes one untrusted runtime report.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeClaimsError`] when any claim exceeds its frozen bound,
    /// uses invalid stable-name syntax, or contains duplicate identities.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        adapter_kind: AdapterKind,
        runtime_version: String,
        adapter_build_digest: Sha256Digest,
        queue_depth: u32,
        mut active_run_ids: Vec<RunId>,
        stable_error_code: Option<String>,
        mut capabilities: Vec<String>,
    ) -> Result<Self, RuntimeClaimsError> {
        validate_runtime_version(&runtime_version)?;
        validate_queue_depth(queue_depth)?;
        validate_error_code(stable_error_code.as_deref())?;
        validate_active_runs(&active_run_ids)?;
        validate_capabilities(&capabilities)?;

        active_run_ids.sort_unstable();
        capabilities.sort_unstable();
        Ok(Self {
            adapter_kind,
            runtime_version,
            adapter_build_digest,
            queue_depth,
            active_run_ids,
            stable_error_code,
            capabilities,
        })
    }

    /// Rehydrates an already-canonical durable report.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeClaimsError`] for invalid bounds, duplicates, or a
    /// non-canonical persisted order.
    pub fn try_from_snapshot(snapshot: RuntimeClaimsSnapshot) -> Result<Self, RuntimeClaimsError> {
        validate_runtime_version(&snapshot.runtime_version)?;
        validate_queue_depth(snapshot.queue_depth)?;
        validate_error_code(snapshot.stable_error_code.as_deref())?;
        validate_active_runs(&snapshot.active_run_ids)?;
        validate_capabilities(&snapshot.capabilities)?;
        if !strictly_sorted(&snapshot.active_run_ids) || !strictly_sorted(&snapshot.capabilities) {
            return Err(RuntimeClaimsError::NonCanonicalOrder);
        }
        Ok(Self {
            adapter_kind: snapshot.adapter_kind,
            runtime_version: snapshot.runtime_version,
            adapter_build_digest: snapshot.adapter_build_digest,
            queue_depth: snapshot.queue_depth,
            active_run_ids: snapshot.active_run_ids,
            stable_error_code: snapshot.stable_error_code,
            capabilities: snapshot.capabilities,
        })
    }

    #[must_use]
    pub fn snapshot(&self) -> RuntimeClaimsSnapshot {
        RuntimeClaimsSnapshot {
            adapter_kind: self.adapter_kind,
            runtime_version: self.runtime_version.clone(),
            adapter_build_digest: self.adapter_build_digest,
            queue_depth: self.queue_depth,
            active_run_ids: self.active_run_ids.clone(),
            stable_error_code: self.stable_error_code.clone(),
            capabilities: self.capabilities.clone(),
        }
    }

    #[must_use]
    pub const fn adapter_kind(&self) -> AdapterKind {
        self.adapter_kind
    }

    #[must_use]
    pub fn runtime_version(&self) -> &str {
        &self.runtime_version
    }

    #[must_use]
    pub const fn adapter_build_digest(&self) -> Sha256Digest {
        self.adapter_build_digest
    }

    #[must_use]
    pub const fn queue_depth(&self) -> u32 {
        self.queue_depth
    }

    #[must_use]
    pub fn active_run_ids(&self) -> &[RunId] {
        &self.active_run_ids
    }

    #[must_use]
    pub fn stable_error_code(&self) -> Option<&str> {
        self.stable_error_code.as_deref()
    }

    #[must_use]
    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeClaimsError {
    InvalidRuntimeVersion,
    InvalidQueueDepth,
    TooManyActiveRuns,
    DuplicateActiveRun,
    InvalidErrorCode,
    TooManyCapabilities,
    InvalidCapability,
    DuplicateCapability,
    NonCanonicalOrder,
}

impl fmt::Display for RuntimeClaimsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRuntimeVersion => "runtime version is empty or outside its safe bound",
            Self::InvalidQueueDepth => "runtime queue depth is outside the JSON-safe range",
            Self::TooManyActiveRuns => "runtime report contains too many active Run IDs",
            Self::DuplicateActiveRun => "runtime report contains a duplicate active Run ID",
            Self::InvalidErrorCode => "runtime error code is not a bounded stable code",
            Self::TooManyCapabilities => "runtime report contains too many capabilities",
            Self::InvalidCapability => "runtime capability name is invalid",
            Self::DuplicateCapability => "runtime capability name is duplicated",
            Self::NonCanonicalOrder => "runtime claim snapshot is not in canonical order",
        })
    }
}

impl Error for RuntimeClaimsError {}

fn validate_runtime_version(value: &str) -> Result<(), RuntimeClaimsError> {
    if !value.is_empty()
        && value.len() <= MAX_RUNTIME_VERSION_BYTES
        && value.chars().all(|character| {
            let scalar = u32::from(character);
            !(scalar <= 0x1f || (0x7f..=0x9f).contains(&scalar))
        })
    {
        Ok(())
    } else {
        Err(RuntimeClaimsError::InvalidRuntimeVersion)
    }
}

fn validate_queue_depth(value: u32) -> Result<(), RuntimeClaimsError> {
    if value <= MAX_RUNTIME_QUEUE_DEPTH {
        Ok(())
    } else {
        Err(RuntimeClaimsError::InvalidQueueDepth)
    }
}

fn validate_error_code(value: Option<&str>) -> Result<(), RuntimeClaimsError> {
    if value.is_none_or(valid_upper_snake_code) {
        Ok(())
    } else {
        Err(RuntimeClaimsError::InvalidErrorCode)
    }
}

fn validate_active_runs(values: &[RunId]) -> Result<(), RuntimeClaimsError> {
    if values.len() > MAX_ACTIVE_RUN_IDS {
        return Err(RuntimeClaimsError::TooManyActiveRuns);
    }
    let mut unique = BTreeSet::new();
    if values.iter().all(|value| unique.insert(*value)) {
        Ok(())
    } else {
        Err(RuntimeClaimsError::DuplicateActiveRun)
    }
}

fn validate_capabilities(values: &[String]) -> Result<(), RuntimeClaimsError> {
    if values.len() > MAX_RUNTIME_CAPABILITIES {
        return Err(RuntimeClaimsError::TooManyCapabilities);
    }
    if values
        .iter()
        .any(|value| !valid_lower_stable_name(value, MAX_CAPABILITY_NAME_BYTES))
    {
        return Err(RuntimeClaimsError::InvalidCapability);
    }
    let mut unique = BTreeSet::new();
    if values.iter().all(|value| unique.insert(value.as_str())) {
        Ok(())
    } else {
        Err(RuntimeClaimsError::DuplicateCapability)
    }
}

fn valid_bounded_visible_ascii(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_lower_stable_name(value: &str, maximum: usize) -> bool {
    valid_bounded_visible_ascii(value, maximum)
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
}

fn valid_upper_snake_code(value: &str) -> bool {
    (3..=MAX_RUNTIME_ERROR_CODE_BYTES).contains(&value.len())
        && value.split('_').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        })
        && value.as_bytes().first().is_some_and(u8::is_ascii_uppercase)
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
