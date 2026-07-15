use std::{error::Error, fmt};

use dtx_domain::{AgentId, IdentityId, InstallationId, Revision, TenantId};

use crate::DescriptorDigest;

/// Trust domain in which an installed Agent runtime executes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionMode {
    /// One or more explicitly bound Connector instances run the Agent.
    ConnectorManaged,
    /// The isolated server Agent orchestrator runs the Agent.
    ServerManaged,
}

/// Owner-controlled desired lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationDesiredState {
    /// Runtime bindings may be reconciled and used.
    Enabled,
    /// The owner disabled future execution without revoking identity.
    Disabled,
    /// Identity and future access are permanently revoked.
    Revoked,
}

/// Server-observed readiness state, separate from owner intent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationObservedState {
    /// Runtime/device setup has not yet reached ready state.
    Installing,
    /// At least one conforming execution route is ready.
    Ready,
    /// The installation remains usable with impaired health.
    Degraded,
    /// The pinned descriptor must be upgraded before normal use.
    UpgradeRequired,
}

/// One authorized installation state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationCommand {
    /// Permanently binds the isolated Agent identity approved by the owner.
    BindAgentIdentity {
        /// Verified identity-log subject for this installation.
        identity_id: IdentityId,
    },
    /// Reconciler observed a conforming ready route.
    MarkReady,
    /// Reconciler observed impaired health.
    MarkDegraded,
    /// Security or compatibility policy requires an upgrade.
    RequireUpgrade,
    /// Owner disables future execution.
    Disable,
    /// Owner re-enables reconciliation.
    Enable,
    /// Pins a newer, already verified descriptor snapshot.
    UpgradeDescriptor {
        /// New descriptor version; rollback is intentionally unsupported here.
        version: Revision,
        /// Exact verified descriptor digest.
        hash: DescriptorDigest,
    },
    /// Advances the owner-approved policy snapshot independently of code.
    AdvancePolicy {
        /// New policy revision; rollback and equivocation are forbidden.
        revision: Revision,
    },
    /// Permanently revokes the installation.
    Revoke,
}

/// Revisioned Agent installation aggregate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentInstallation {
    tenant_id: TenantId,
    installation_id: InstallationId,
    agent_id: AgentId,
    owner_id: IdentityId,
    agent_identity_id: Option<IdentityId>,
    execution_mode: ExecutionMode,
    descriptor_version: Revision,
    descriptor_hash: DescriptorDigest,
    policy_revision: Revision,
    desired_state: InstallationDesiredState,
    observed_state: InstallationObservedState,
    revision: Revision,
}

/// Complete non-secret persistence image of an Agent installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentInstallationSnapshot {
    pub tenant_id: TenantId,
    pub installation_id: InstallationId,
    pub agent_id: AgentId,
    pub owner_id: IdentityId,
    pub agent_identity_id: Option<IdentityId>,
    pub execution_mode: ExecutionMode,
    pub descriptor_version: Revision,
    pub descriptor_hash: DescriptorDigest,
    pub policy_revision: Revision,
    pub desired_state: InstallationDesiredState,
    pub observed_state: InstallationObservedState,
    pub revision: Revision,
}

impl AgentInstallation {
    /// Creates a newly installing aggregate at revision one.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        installation_id: InstallationId,
        agent_id: AgentId,
        owner_id: IdentityId,
        execution_mode: ExecutionMode,
        descriptor_version: Revision,
        descriptor_hash: DescriptorDigest,
    ) -> Self {
        Self {
            tenant_id,
            installation_id,
            agent_id,
            owner_id,
            agent_identity_id: None,
            execution_mode,
            descriptor_version,
            descriptor_hash,
            policy_revision: Revision::INITIAL,
            desired_state: InstallationDesiredState::Enabled,
            observed_state: InstallationObservedState::Installing,
            revision: Revision::INITIAL,
        }
    }

    /// Captures all durable installation facts without credential material.
    #[must_use]
    pub const fn snapshot(&self) -> AgentInstallationSnapshot {
        AgentInstallationSnapshot {
            tenant_id: self.tenant_id,
            installation_id: self.installation_id,
            agent_id: self.agent_id,
            owner_id: self.owner_id,
            agent_identity_id: self.agent_identity_id,
            execution_mode: self.execution_mode,
            descriptor_version: self.descriptor_version,
            descriptor_hash: self.descriptor_hash,
            policy_revision: self.policy_revision,
            desired_state: self.desired_state,
            observed_state: self.observed_state,
            revision: self.revision,
        }
    }

    /// Rehydrates a durable installation after checking reachable initial-state invariants.
    ///
    /// # Errors
    ///
    /// Rejects a revision-one image containing facts that require a transition.
    pub const fn try_from_snapshot(
        snapshot: AgentInstallationSnapshot,
    ) -> Result<Self, AgentInstallationSnapshotError> {
        if snapshot.revision.get() == Revision::INITIAL.get()
            && (snapshot.agent_identity_id.is_some()
                || snapshot.policy_revision.get() != Revision::INITIAL.get()
                || !matches!(snapshot.desired_state, InstallationDesiredState::Enabled)
                || !matches!(
                    snapshot.observed_state,
                    InstallationObservedState::Installing
                ))
        {
            return Err(AgentInstallationSnapshotError::UnreachableInitialState);
        }
        Ok(Self {
            tenant_id: snapshot.tenant_id,
            installation_id: snapshot.installation_id,
            agent_id: snapshot.agent_id,
            owner_id: snapshot.owner_id,
            agent_identity_id: snapshot.agent_identity_id,
            execution_mode: snapshot.execution_mode,
            descriptor_version: snapshot.descriptor_version,
            descriptor_hash: snapshot.descriptor_hash,
            policy_revision: snapshot.policy_revision,
            desired_state: snapshot.desired_state,
            observed_state: snapshot.observed_state,
            revision: snapshot.revision,
        })
    }

    /// Returns the immutable tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the installation lifecycle ID.
    #[must_use]
    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }

    /// Returns the public Agent definition ID.
    #[must_use]
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Returns the owning user identity.
    #[must_use]
    pub const fn owner_id(&self) -> IdentityId {
        self.owner_id
    }

    /// Returns the permanently approved isolated Agent identity, if bound.
    #[must_use]
    pub const fn agent_identity_id(&self) -> Option<IdentityId> {
        self.agent_identity_id
    }

    /// Returns the immutable execution trust domain.
    #[must_use]
    pub const fn execution_mode(&self) -> ExecutionMode {
        self.execution_mode
    }

    /// Returns the currently pinned descriptor version.
    #[must_use]
    pub const fn descriptor_version(&self) -> Revision {
        self.descriptor_version
    }

    /// Returns the exact pinned descriptor digest.
    #[must_use]
    pub const fn descriptor_hash(&self) -> DescriptorDigest {
        self.descriptor_hash
    }

    /// Returns the currently enforced owner-approved policy revision.
    #[must_use]
    pub const fn policy_revision(&self) -> Revision {
        self.policy_revision
    }

    /// Returns owner intent.
    #[must_use]
    pub const fn desired_state(&self) -> InstallationDesiredState {
        self.desired_state
    }

    /// Returns reconciled readiness.
    #[must_use]
    pub const fn observed_state(&self) -> InstallationObservedState {
        self.observed_state
    }

    /// Returns the optimistic-concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Applies one transition only at the caller's exact revision.
    ///
    /// # Errors
    ///
    /// Rejects stale revisions, invalid state transitions, descriptor downgrade
    /// or equivocation, and every transition out of revoked state.
    #[allow(clippy::too_many_lines)]
    pub fn apply(
        &mut self,
        expected_revision: Revision,
        command: InstallationCommand,
    ) -> Result<Revision, InstallationError> {
        if self.revision != expected_revision {
            return Err(InstallationError::RevisionConflict {
                actual: self.revision,
                expected: expected_revision,
            });
        }
        if self.desired_state == InstallationDesiredState::Revoked {
            return Err(InstallationError::Revoked);
        }

        let mut desired = self.desired_state;
        let mut observed = self.observed_state;
        let mut descriptor_version = self.descriptor_version;
        let mut descriptor_hash = self.descriptor_hash;
        let mut policy_revision = self.policy_revision;
        let mut agent_identity_id = self.agent_identity_id;

        match command {
            InstallationCommand::BindAgentIdentity { identity_id }
                if agent_identity_id.is_none() =>
            {
                agent_identity_id = Some(identity_id);
            }
            InstallationCommand::BindAgentIdentity { .. } => {
                return Err(InstallationError::AgentIdentityAlreadyBound);
            }
            InstallationCommand::MarkReady
                if desired == InstallationDesiredState::Enabled
                    && agent_identity_id.is_some()
                    && matches!(
                        observed,
                        InstallationObservedState::Installing | InstallationObservedState::Degraded
                    ) =>
            {
                observed = InstallationObservedState::Ready;
            }
            InstallationCommand::MarkDegraded
                if desired == InstallationDesiredState::Enabled
                    && matches!(
                        observed,
                        InstallationObservedState::Installing | InstallationObservedState::Ready
                    ) =>
            {
                observed = InstallationObservedState::Degraded;
            }
            InstallationCommand::RequireUpgrade
                if observed != InstallationObservedState::UpgradeRequired =>
            {
                observed = InstallationObservedState::UpgradeRequired;
            }
            InstallationCommand::Disable if desired == InstallationDesiredState::Enabled => {
                desired = InstallationDesiredState::Disabled;
            }
            InstallationCommand::Enable if desired == InstallationDesiredState::Disabled => {
                desired = InstallationDesiredState::Enabled;
                observed = InstallationObservedState::Installing;
            }
            InstallationCommand::UpgradeDescriptor { version, hash } => {
                if version < descriptor_version {
                    return Err(InstallationError::DescriptorVersionRegressed);
                }
                if version == descriptor_version {
                    return if hash == descriptor_hash {
                        Err(InstallationError::NoChange)
                    } else {
                        Err(InstallationError::DescriptorVersionConflict)
                    };
                }
                descriptor_version = version;
                descriptor_hash = hash;
                observed = InstallationObservedState::Installing;
            }
            InstallationCommand::AdvancePolicy { revision } => {
                if revision < policy_revision {
                    return Err(InstallationError::PolicyRevisionRegressed);
                }
                if revision == policy_revision {
                    return Err(InstallationError::NoChange);
                }
                policy_revision = revision;
            }
            InstallationCommand::Revoke => {
                desired = InstallationDesiredState::Revoked;
            }
            InstallationCommand::MarkReady if agent_identity_id.is_none() => {
                return Err(InstallationError::AgentIdentityRequired);
            }
            InstallationCommand::MarkReady
            | InstallationCommand::MarkDegraded
            | InstallationCommand::RequireUpgrade
            | InstallationCommand::Disable
            | InstallationCommand::Enable => {
                return Err(InstallationError::InvalidTransition);
            }
        }

        let next_revision = self
            .revision
            .checked_next()
            .map_err(|_| InstallationError::RevisionExhausted)?;
        self.desired_state = desired;
        self.observed_state = observed;
        self.descriptor_version = descriptor_version;
        self.descriptor_hash = descriptor_hash;
        self.policy_revision = policy_revision;
        self.agent_identity_id = agent_identity_id;
        self.revision = next_revision;
        Ok(next_revision)
    }
}

/// Stable installation transition rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationError {
    /// Readiness is impossible before owner approval binds the Agent identity.
    AgentIdentityRequired,
    /// An installation identity is immutable after its first approval.
    AgentIdentityAlreadyBound,
    /// The command was based on a stale aggregate revision.
    RevisionConflict {
        /// Current aggregate revision.
        actual: Revision,
        /// Revision supplied by the caller.
        expected: Revision,
    },
    /// The command is not valid for the current desired/observed state.
    InvalidTransition,
    /// A terminal installation cannot transition again.
    Revoked,
    /// Descriptor versions cannot decrease through normal upgrade.
    DescriptorVersionRegressed,
    /// The same descriptor version cannot identify different content.
    DescriptorVersionConflict,
    /// Policy revisions cannot decrease through normal policy updates.
    PolicyRevisionRegressed,
    /// A mutation command proposed the exact current value.
    NoChange,
    /// The exact cross-platform revision range was exhausted.
    RevisionExhausted,
}

impl fmt::Display for InstallationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AgentIdentityRequired => "Agent identity approval is required",
            Self::AgentIdentityAlreadyBound => "Agent identity is already bound",
            Self::RevisionConflict { .. } => "installation revision conflict",
            Self::InvalidTransition => "invalid installation state transition",
            Self::Revoked => "installation is revoked",
            Self::DescriptorVersionRegressed => "descriptor version regressed",
            Self::DescriptorVersionConflict => "descriptor version content conflicts",
            Self::PolicyRevisionRegressed => "installation policy revision regressed",
            Self::NoChange => "installation command would not change state",
            Self::RevisionExhausted => "installation revision is exhausted",
        })
    }
}

impl Error for InstallationError {}

/// Stable rejection for an invalid durable installation image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentInstallationSnapshotError {
    /// Revision one must still contain exactly the constructor lifecycle facts.
    UnreachableInitialState,
}

impl fmt::Display for AgentInstallationSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("installation snapshot has an unreachable initial state")
    }
}

impl Error for AgentInstallationSnapshotError {}
