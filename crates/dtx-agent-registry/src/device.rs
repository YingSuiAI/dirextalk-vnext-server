use std::{error::Error, fmt};

use dtx_domain::{AgentDeviceId, InstallationId, Revision, TenantId};

use crate::{AgentInstallation, InstallationDesiredState};

/// Non-secret digest that binds an Agent Device certificate/MLS credential.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceCredentialFingerprint([u8; 32]);

impl DeviceCredentialFingerprint {
    /// Creates a verified credential fingerprint from exact digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact non-secret digest bytes for durable encoding.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for DeviceCredentialFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceCredentialFingerprint(<redacted>)")
    }
}

/// Agent Device credential lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentDeviceState {
    /// Credential proof is retained, but MLS membership is not ready.
    Provisioning,
    /// Device may represent its installation in authorized conversations.
    Active,
    /// Credential is permanently rejected.
    Revoked,
}

/// One Agent Device lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentDeviceCommand {
    /// Marks the device usable after its MLS/device proof setup completed.
    Activate,
    /// Permanently rejects the device credential.
    Revoke,
}

/// Revisioned, tenant-bound Agent Device aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentDevice {
    tenant_id: TenantId,
    installation_id: InstallationId,
    device_id: AgentDeviceId,
    credential_fingerprint: DeviceCredentialFingerprint,
    state: AgentDeviceState,
    revision: Revision,
}

/// Complete non-secret persistence image of one Agent Device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentDeviceSnapshot {
    pub tenant_id: TenantId,
    pub installation_id: InstallationId,
    pub agent_device_id: AgentDeviceId,
    pub credential_fingerprint: DeviceCredentialFingerprint,
    pub state: AgentDeviceState,
    pub revision: Revision,
}

impl AgentDevice {
    /// Enrolls a verified credential under the exact installation boundary.
    ///
    /// # Errors
    ///
    /// A disabled or revoked installation cannot enroll new devices.
    pub fn enroll(
        installation: &AgentInstallation,
        agent_device_id: AgentDeviceId,
        credential_fingerprint: DeviceCredentialFingerprint,
    ) -> Result<Self, AgentDeviceError> {
        if installation.desired_state() != InstallationDesiredState::Enabled {
            return Err(AgentDeviceError::InstallationNotUsable);
        }
        Ok(Self {
            tenant_id: installation.tenant_id(),
            installation_id: installation.installation_id(),
            device_id: agent_device_id,
            credential_fingerprint,
            state: AgentDeviceState::Provisioning,
            revision: Revision::INITIAL,
        })
    }

    /// Captures the durable credential fingerprint and lifecycle fence.
    #[must_use]
    pub const fn snapshot(&self) -> AgentDeviceSnapshot {
        AgentDeviceSnapshot {
            tenant_id: self.tenant_id,
            installation_id: self.installation_id,
            agent_device_id: self.device_id,
            credential_fingerprint: self.credential_fingerprint,
            state: self.state,
            revision: self.revision,
        }
    }

    /// Rehydrates a device after validating its reachable initial state.
    ///
    /// # Errors
    ///
    /// Rejects an active or revoked device that still claims enrollment revision one.
    pub const fn try_from_snapshot(
        snapshot: AgentDeviceSnapshot,
    ) -> Result<Self, AgentDeviceSnapshotError> {
        let reachable = match snapshot.state {
            AgentDeviceState::Provisioning => snapshot.revision.get() == 1,
            AgentDeviceState::Active => snapshot.revision.get() == 2,
            AgentDeviceState::Revoked => matches!(snapshot.revision.get(), 2 | 3),
        };
        if !reachable {
            return Err(AgentDeviceSnapshotError::UnreachableInitialState);
        }
        Ok(Self {
            tenant_id: snapshot.tenant_id,
            installation_id: snapshot.installation_id,
            device_id: snapshot.agent_device_id,
            credential_fingerprint: snapshot.credential_fingerprint,
            state: snapshot.state,
            revision: snapshot.revision,
        })
    }

    /// Returns the immutable tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the immutable installation boundary.
    #[must_use]
    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }

    /// Returns the device lifecycle ID.
    #[must_use]
    pub const fn agent_device_id(&self) -> AgentDeviceId {
        self.device_id
    }

    /// Returns the current credential lifecycle state.
    #[must_use]
    pub const fn state(&self) -> AgentDeviceState {
        self.state
    }

    /// Returns the aggregate revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Compares a verified fingerprint without exposing retained key material.
    #[must_use]
    pub fn credential_matches(&self, candidate: DeviceCredentialFingerprint) -> bool {
        self.credential_fingerprint.0 == candidate.0
    }

    /// Applies a lifecycle transition under the exact installation scope.
    ///
    /// # Errors
    ///
    /// Rejects cross-tenant/installation calls, stale revisions, activation
    /// under a disabled installation, invalid transitions, and terminal reuse.
    pub fn apply(
        &mut self,
        installation: &AgentInstallation,
        expected_revision: Revision,
        command: AgentDeviceCommand,
    ) -> Result<Revision, AgentDeviceError> {
        if self.tenant_id != installation.tenant_id()
            || self.installation_id != installation.installation_id()
        {
            return Err(AgentDeviceError::ScopeMismatch);
        }
        if self.revision != expected_revision {
            return Err(AgentDeviceError::RevisionConflict {
                actual: self.revision,
                expected: expected_revision,
            });
        }
        if self.state == AgentDeviceState::Revoked {
            return Err(AgentDeviceError::Revoked);
        }

        let next_state = match command {
            AgentDeviceCommand::Activate
                if self.state == AgentDeviceState::Provisioning
                    && installation.desired_state() == InstallationDesiredState::Enabled =>
            {
                AgentDeviceState::Active
            }
            AgentDeviceCommand::Activate
                if installation.desired_state() != InstallationDesiredState::Enabled =>
            {
                return Err(AgentDeviceError::InstallationNotUsable);
            }
            AgentDeviceCommand::Revoke => AgentDeviceState::Revoked,
            AgentDeviceCommand::Activate => return Err(AgentDeviceError::InvalidTransition),
        };
        let next_revision = self
            .revision
            .checked_next()
            .map_err(|_| AgentDeviceError::RevisionExhausted)?;
        self.state = next_state;
        self.revision = next_revision;
        Ok(next_revision)
    }
}

/// Stable Agent Device rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentDeviceError {
    /// The supplied installation was from another tenant or lifecycle.
    ScopeMismatch,
    /// The call used a stale device revision.
    RevisionConflict {
        /// Current revision.
        actual: Revision,
        /// Caller revision.
        expected: Revision,
    },
    /// The installation cannot currently admit or activate a device.
    InstallationNotUsable,
    /// The requested transition is not valid in the current state.
    InvalidTransition,
    /// Revoked is an absorbing terminal state.
    Revoked,
    /// The exact cross-platform revision range was exhausted.
    RevisionExhausted,
}

impl fmt::Display for AgentDeviceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ScopeMismatch => "Agent Device installation scope mismatch",
            Self::RevisionConflict { .. } => "Agent Device revision conflict",
            Self::InstallationNotUsable => "Agent installation is not usable",
            Self::InvalidTransition => "invalid Agent Device transition",
            Self::Revoked => "Agent Device is revoked",
            Self::RevisionExhausted => "Agent Device revision is exhausted",
        })
    }
}

impl Error for AgentDeviceError {}

/// Stable rejection for an invalid durable Agent Device image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentDeviceSnapshotError {
    /// Revision one can only be the provisioning state created by enrollment.
    UnreachableInitialState,
}

impl fmt::Display for AgentDeviceSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Agent Device snapshot has an unreachable initial state")
    }
}

impl Error for AgentDeviceSnapshotError {}
