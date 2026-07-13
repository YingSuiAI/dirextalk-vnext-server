use std::{collections::BTreeSet, error::Error, fmt};

use dtx_domain::{HostCredentialId, HostId, IdentityId, Revision, RevisionError, TenantId};

/// Owner-controlled lifecycle of one registered Agent Host.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HostLifecycle {
    /// The host exists but has never consumed its one-time enrollment.
    AwaitingEnrollment,
    /// The enrolled host may establish its outbound control stream.
    Active,
    /// Administrative quarantine overrides all remotely reported health.
    Quarantined,
    /// Terminal state whose credentials and observations are invalid.
    Revoked,
}

/// Health a currently authenticated supervisor may report.
///
/// Offline and revoked are deliberately absent because the server derives them.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReportedHealth {
    /// The supervisor reports no known host-level fault.
    Healthy,
    /// The supervisor reports a bounded, non-secret operational fault.
    Degraded,
}

/// Effective host state evaluated from lifecycle and heartbeat expiry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EffectiveHostState {
    /// No supervisor credential has ever been enrolled.
    AwaitingEnrollment,
    /// A healthy heartbeat remains inside its server-issued window.
    Online,
    /// A degraded heartbeat remains inside its server-issued window.
    Degraded,
    /// No current heartbeat exists or its server-issued window expired.
    Offline,
    /// Administrative quarantine overrides any fresh heartbeat.
    Quarantined,
    /// Terminal administrative revocation overrides every other state.
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostObservation {
    health: ReportedHealth,
    observed_at_millis: i64,
    heartbeat_expires_at_millis: i64,
}

/// Aggregate for one tenant-owned machine capable of hosting many Connectors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentHost {
    tenant_id: TenantId,
    host_id: HostId,
    owner_id: IdentityId,
    lifecycle: HostLifecycle,
    credential_id: Option<HostCredentialId>,
    retired_credentials: BTreeSet<HostCredentialId>,
    desired_revision: Revision,
    observed_revision: Option<Revision>,
    observation: Option<HostObservation>,
    revision: Revision,
}

impl AgentHost {
    /// Registers an immutable tenant/owner/host identity awaiting enrollment.
    #[must_use]
    pub const fn register(tenant_id: TenantId, host_id: HostId, owner_id: IdentityId) -> Self {
        Self {
            tenant_id,
            host_id,
            owner_id,
            lifecycle: HostLifecycle::AwaitingEnrollment,
            credential_id: None,
            retired_credentials: BTreeSet::new(),
            desired_revision: Revision::INITIAL,
            observed_revision: None,
            observation: None,
            revision: Revision::INITIAL,
        }
    }

    /// Consumes the host's only initial enrollment and installs its credential.
    ///
    /// Credential replacement after this transition must use
    /// [`Self::rotate_credential`].
    ///
    /// # Errors
    ///
    /// Rejects a stale aggregate revision, repeated enrollment, or revoked host.
    pub fn enroll(
        &mut self,
        expected_revision: Revision,
        credential_id: HostCredentialId,
    ) -> Result<(), HostError> {
        let next_revision = self.checked_mutation_revision(expected_revision)?;
        match self.lifecycle {
            HostLifecycle::AwaitingEnrollment => {}
            HostLifecycle::Active | HostLifecycle::Quarantined => {
                return Err(HostError::AlreadyEnrolled);
            }
            HostLifecycle::Revoked => return Err(HostError::HostRevoked),
        }
        self.lifecycle = HostLifecycle::Active;
        self.credential_id = Some(credential_id);
        self.observation = None;
        self.revision = next_revision;
        Ok(())
    }

    /// Replaces the current supervisor credential and invalidates prior liveness.
    ///
    /// # Errors
    ///
    /// Rejects stale aggregate revisions, unenrolled/revoked hosts, or reuse of
    /// the current credential ID.
    pub fn rotate_credential(
        &mut self,
        expected_revision: Revision,
        replacement: HostCredentialId,
    ) -> Result<HostCredentialId, HostError> {
        let next_revision = self.checked_mutation_revision(expected_revision)?;
        self.ensure_enrolled_and_mutable()?;
        let current = self.credential_id.ok_or(HostError::NotEnrolled)?;
        if current == replacement {
            return Err(HostError::CredentialUnchanged);
        }
        if self.retired_credentials.contains(&replacement) {
            return Err(HostError::CredentialReused);
        }
        self.retired_credentials.insert(current);
        self.credential_id = Some(replacement);
        self.observation = None;
        self.revision = next_revision;
        Ok(current)
    }

    /// Advances the desired host plan by exactly one revision.
    ///
    /// # Errors
    ///
    /// Rejects a stale aggregate revision, terminal host, or exhausted counter.
    pub fn advance_desired_revision(
        &mut self,
        expected_revision: Revision,
    ) -> Result<Revision, HostError> {
        let next_aggregate_revision = self.checked_mutation_revision(expected_revision)?;
        if self.lifecycle == HostLifecycle::Revoked {
            return Err(HostError::HostRevoked);
        }
        let next_desired = checked_next(self.desired_revision)?;
        self.desired_revision = next_desired;
        self.revision = next_aggregate_revision;
        Ok(next_desired)
    }

    /// Records a heartbeat authenticated by the current credential.
    ///
    /// The caller supplies server receive time and server policy TTL; expiry is
    /// calculated here and is never accepted from the supervisor.
    ///
    /// # Errors
    ///
    /// Rejects stale aggregate/desired revisions, a wrong credential, regressed
    /// server time, invalid TTL, or an unenrolled/revoked host.
    #[allow(clippy::too_many_arguments)]
    pub fn record_heartbeat(
        &mut self,
        expected_revision: Revision,
        credential_id: HostCredentialId,
        acknowledged_desired_revision: Revision,
        health: ReportedHealth,
        server_received_at_millis: i64,
        server_heartbeat_ttl_millis: i64,
    ) -> Result<i64, HostError> {
        let next_revision = self.checked_mutation_revision(expected_revision)?;
        self.ensure_enrolled_and_mutable()?;
        if self.credential_id != Some(credential_id) {
            return Err(HostError::CredentialMismatch);
        }
        if acknowledged_desired_revision > self.desired_revision {
            return Err(HostError::ObservedRevisionAhead {
                desired: self.desired_revision,
            });
        }
        if let Some(current) = self.observed_revision
            && acknowledged_desired_revision < current
        {
            return Err(HostError::ObservedRevisionRegressed { current });
        }
        if self
            .observation
            .is_some_and(|current| server_received_at_millis < current.observed_at_millis)
        {
            return Err(HostError::HeartbeatTimeRegressed);
        }
        if server_heartbeat_ttl_millis <= 0 {
            return Err(HostError::InvalidHeartbeatWindow);
        }
        let heartbeat_expires_at_millis = server_received_at_millis
            .checked_add(server_heartbeat_ttl_millis)
            .ok_or(HostError::InvalidHeartbeatWindow)?;

        self.observed_revision = Some(acknowledged_desired_revision);
        self.observation = Some(HostObservation {
            health,
            observed_at_millis: server_received_at_millis,
            heartbeat_expires_at_millis,
        });
        self.revision = next_revision;
        Ok(heartbeat_expires_at_millis)
    }

    /// Places an enrolled host into administrative quarantine.
    ///
    /// Quarantine invalidates liveness so clearing it requires a fresh heartbeat.
    ///
    /// # Errors
    ///
    /// Rejects stale aggregate revisions, invalid lifecycle transitions, or a
    /// revoked host.
    pub fn quarantine(&mut self, expected_revision: Revision) -> Result<(), HostError> {
        let next_revision = self.checked_mutation_revision(expected_revision)?;
        match self.lifecycle {
            HostLifecycle::Active => {}
            HostLifecycle::AwaitingEnrollment => return Err(HostError::NotEnrolled),
            HostLifecycle::Quarantined => return Err(HostError::AlreadyQuarantined),
            HostLifecycle::Revoked => return Err(HostError::HostRevoked),
        }
        self.lifecycle = HostLifecycle::Quarantined;
        self.observation = None;
        self.revision = next_revision;
        Ok(())
    }

    /// Releases administrative quarantine without manufacturing online state.
    ///
    /// # Errors
    ///
    /// Rejects stale aggregate revisions, a non-quarantined host, or revocation.
    pub fn clear_quarantine(&mut self, expected_revision: Revision) -> Result<(), HostError> {
        let next_revision = self.checked_mutation_revision(expected_revision)?;
        match self.lifecycle {
            HostLifecycle::Quarantined => {}
            HostLifecycle::Revoked => return Err(HostError::HostRevoked),
            HostLifecycle::AwaitingEnrollment | HostLifecycle::Active => {
                return Err(HostError::NotQuarantined);
            }
        }
        self.lifecycle = HostLifecycle::Active;
        self.observation = None;
        self.revision = next_revision;
        Ok(())
    }

    /// Irreversibly revokes this host and its current credential.
    ///
    /// # Errors
    ///
    /// Rejects a stale aggregate revision or an already revoked host.
    pub fn revoke(&mut self, expected_revision: Revision) -> Result<(), HostError> {
        let next_revision = self.checked_mutation_revision(expected_revision)?;
        if self.lifecycle == HostLifecycle::Revoked {
            return Err(HostError::HostRevoked);
        }
        self.lifecycle = HostLifecycle::Revoked;
        if let Some(current) = self.credential_id {
            self.retired_credentials.insert(current);
        }
        self.credential_id = None;
        self.observation = None;
        self.revision = next_revision;
        Ok(())
    }

    /// Evaluates liveness using server-issued expiry and administrative precedence.
    #[must_use]
    pub fn effective_state(&self, now_millis: i64) -> EffectiveHostState {
        match self.lifecycle {
            HostLifecycle::AwaitingEnrollment => EffectiveHostState::AwaitingEnrollment,
            HostLifecycle::Quarantined => EffectiveHostState::Quarantined,
            HostLifecycle::Revoked => EffectiveHostState::Revoked,
            HostLifecycle::Active => {
                self.observation
                    .map_or(EffectiveHostState::Offline, |observation| {
                        if now_millis >= observation.heartbeat_expires_at_millis {
                            EffectiveHostState::Offline
                        } else {
                            match observation.health {
                                ReportedHealth::Healthy => EffectiveHostState::Online,
                                ReportedHealth::Degraded => EffectiveHostState::Degraded,
                            }
                        }
                    })
            }
        }
    }

    /// Returns the immutable tenant boundary.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the immutable host identifier.
    #[must_use]
    pub const fn host_id(&self) -> HostId {
        self.host_id
    }

    /// Returns the immutable public owner identity.
    #[must_use]
    pub const fn owner_id(&self) -> IdentityId {
        self.owner_id
    }

    /// Returns the owner-controlled lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> HostLifecycle {
        self.lifecycle
    }

    /// Returns the currently accepted credential, if any.
    #[must_use]
    pub const fn credential_id(&self) -> Option<HostCredentialId> {
        self.credential_id
    }

    /// Returns the current server desired-plan revision.
    #[must_use]
    pub const fn desired_revision(&self) -> Revision {
        self.desired_revision
    }

    /// Returns the greatest desired-plan revision acknowledged by the host.
    #[must_use]
    pub const fn observed_revision(&self) -> Option<Revision> {
        self.observed_revision
    }

    /// Returns the server-calculated heartbeat expiry, if a current observation exists.
    #[must_use]
    pub const fn heartbeat_expires_at_millis(&self) -> Option<i64> {
        match self.observation {
            Some(observation) => Some(observation.heartbeat_expires_at_millis),
            None => None,
        }
    }

    /// Returns the current optimistic-concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    fn checked_mutation_revision(
        &self,
        expected_revision: Revision,
    ) -> Result<Revision, HostError> {
        if expected_revision != self.revision {
            return Err(HostError::RevisionConflict {
                current: self.revision,
            });
        }
        checked_next(self.revision)
    }

    fn ensure_enrolled_and_mutable(&self) -> Result<(), HostError> {
        match self.lifecycle {
            HostLifecycle::Active | HostLifecycle::Quarantined => Ok(()),
            HostLifecycle::AwaitingEnrollment => Err(HostError::NotEnrolled),
            HostLifecycle::Revoked => Err(HostError::HostRevoked),
        }
    }
}

fn checked_next(revision: Revision) -> Result<Revision, HostError> {
    revision.checked_next().map_err(HostError::from)
}

/// Stable rejection from the Agent Host lifecycle boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostError {
    /// The caller did not use the current aggregate revision.
    RevisionConflict {
        /// Current revision returned for a safe retry/read-refresh.
        current: Revision,
    },
    /// The one-time enrollment was already consumed.
    AlreadyEnrolled,
    /// The operation requires an enrolled supervisor credential.
    NotEnrolled,
    /// The authenticated credential is not the host's current credential.
    CredentialMismatch,
    /// Rotation attempted to reuse the current credential ID.
    CredentialUnchanged,
    /// Rotation attempted to resurrect a previously retired credential.
    CredentialReused,
    /// The host acknowledged a desired revision older than its prior ACK.
    ObservedRevisionRegressed {
        /// Highest already acknowledged desired revision.
        current: Revision,
    },
    /// The host acknowledged a desired revision the server has not issued.
    ObservedRevisionAhead {
        /// Current server-issued desired revision.
        desired: Revision,
    },
    /// Server receive time went backwards relative to the current observation.
    HeartbeatTimeRegressed,
    /// Server heartbeat TTL was non-positive or overflowed the timestamp.
    InvalidHeartbeatWindow,
    /// The host is already administratively quarantined.
    AlreadyQuarantined,
    /// The operation requires a quarantined host.
    NotQuarantined,
    /// Revocation is terminal.
    HostRevoked,
    /// A safe-integer revision cannot advance further.
    CounterExhausted,
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RevisionConflict { .. } => "agent host revision is stale",
            Self::AlreadyEnrolled => "agent host enrollment was already consumed",
            Self::NotEnrolled => "agent host is not enrolled",
            Self::CredentialMismatch => "agent host credential is stale",
            Self::CredentialUnchanged => "agent host replacement credential is unchanged",
            Self::CredentialReused => "agent host credential was already retired",
            Self::ObservedRevisionRegressed { .. } => "agent host observed revision regressed",
            Self::ObservedRevisionAhead { .. } => {
                "agent host observed revision exceeds desired revision"
            }
            Self::HeartbeatTimeRegressed => "agent host heartbeat time regressed",
            Self::InvalidHeartbeatWindow => "agent host heartbeat window is invalid",
            Self::AlreadyQuarantined => "agent host is already quarantined",
            Self::NotQuarantined => "agent host is not quarantined",
            Self::HostRevoked => "agent host is revoked",
            Self::CounterExhausted => "agent host revision counter is exhausted",
        })
    }
}

impl Error for HostError {}

impl From<RevisionError> for HostError {
    fn from(_: RevisionError) -> Self {
        Self::CounterExhausted
    }
}
