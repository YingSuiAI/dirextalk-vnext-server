use std::{collections::BTreeSet, error::Error, fmt};

use dtx_domain::{
    CloudConnectionId, ConversationId, DeviceId, GrantId, InstallationId, Revision, TenantId,
};

use crate::{AgentInstallation, InstallationDesiredState};

/// Closed, server-enforced conversation permission kind.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AgentConversationPermission {
    /// Read messages authored after the grant becomes effective.
    ReadFutureMessages,
    /// Read the separately scoped shared-history window.
    ReadSharedHistory,
    /// Read explicitly shared attachments.
    ReadAttachments,
    /// Author conversation messages.
    SendMessages,
    /// Create comments in an authorized public channel.
    CreateChannelComments,
    /// Request policy-brokered tool calls.
    InvokeTools,
    /// Create durable server jobs.
    StartServerJobs,
}

/// Typed permission set; absence always means deny.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentConversationPermissions {
    permissions: BTreeSet<AgentConversationPermission>,
    cloud_connections: BTreeSet<CloudConnectionId>,
}

impl AgentConversationPermissions {
    /// Creates a deny-all permission set.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            permissions: BTreeSet::new(),
            cloud_connections: BTreeSet::new(),
        }
    }

    /// Adds one closed permission kind.
    #[must_use]
    pub fn with(mut self, permission: AgentConversationPermission) -> Self {
        self.permissions.insert(permission);
        self
    }

    /// Adds one exact, typed cloud connection grant.
    #[must_use]
    pub fn with_cloud_connection(mut self, connection_id: CloudConnectionId) -> Self {
        self.cloud_connections.insert(connection_id);
        self
    }

    /// Reports whether one permission kind is present.
    #[must_use]
    pub fn contains(&self, permission: AgentConversationPermission) -> bool {
        self.permissions.contains(&permission)
    }

    /// Reports whether one exact cloud connection is authorized.
    #[must_use]
    pub fn contains_cloud_connection(&self, connection_id: CloudConnectionId) -> bool {
        self.cloud_connections.contains(&connection_id)
    }

    /// Iterates the closed permission kinds in stable order for persistence/audit.
    #[must_use]
    pub fn permission_kinds(
        &self,
    ) -> impl ExactSizeIterator<Item = AgentConversationPermission> + '_ {
        self.permissions.iter().copied()
    }

    /// Iterates exact cloud connection grants in stable order for persistence/audit.
    #[must_use]
    pub fn cloud_connection_ids(&self) -> impl ExactSizeIterator<Item = CloudConnectionId> + '_ {
        self.cloud_connections.iter().copied()
    }

    fn is_empty(&self) -> bool {
        self.permissions.is_empty() && self.cloud_connections.is_empty()
    }

    fn is_subset_of(&self, other: &Self) -> bool {
        self.permissions.is_subset(&other.permissions)
            && self.cloud_connections.is_subset(&other.cloud_connections)
    }
}

/// Trigger behavior for one conversation grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriggerPolicy {
    /// Only an explicit structured Agent mention may trigger a run.
    MentionOnly,
    /// Only an explicit structured command may trigger a run.
    ExplicitCommand,
    /// The user must manually start every run.
    ManualOnly,
    /// Every eligible message may trigger; this requires separate confirmation.
    AllMessages,
}

/// Digest of the exact privacy policy acknowledged with a grant.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PrivacyPolicyDigest([u8; 32]);

impl PrivacyPolicyDigest {
    /// Creates a digest from exact bytes.
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

/// Evidence marker supplied only after a fresh permission-expansion decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionExpansionConfirmation(());

impl PermissionExpansionConfirmation {
    /// Marks that the policy/application layer verified a fresh confirmation.
    #[must_use]
    pub const fn confirmed() -> Self {
        Self(())
    }
}

/// Evidence marker for the separately confirmed high-risk all-messages trigger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllMessagesConfirmation(());

impl AllMessagesConfirmation {
    /// Marks that the policy/application layer verified a fresh confirmation.
    #[must_use]
    pub const fn confirmed() -> Self {
        Self(())
    }
}

/// Complete freshly device-approved grant state proposed by an update/regrant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationGrantUpdate {
    permissions: AgentConversationPermissions,
    trigger_policy: TriggerPolicy,
    privacy_policy_hash: PrivacyPolicyDigest,
    approved_by_device: DeviceId,
    approved_at_ms: i64,
    expires_at_ms: Option<i64>,
}

impl ConversationGrantUpdate {
    /// Creates a proposed grant state from authenticated, already signed inputs.
    #[must_use]
    pub const fn new(
        permissions: AgentConversationPermissions,
        trigger_policy: TriggerPolicy,
        privacy_policy_hash: PrivacyPolicyDigest,
        approved_by_device: DeviceId,
        approved_at_ms: i64,
        expires_at_ms: Option<i64>,
    ) -> Self {
        Self {
            permissions,
            trigger_policy,
            privacy_policy_hash,
            approved_by_device,
            approved_at_ms,
            expires_at_ms,
        }
    }
}

/// One mutation of the current grant head for a conversation/installation pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConversationGrantCommand {
    /// Replaces active grant facts while retaining its lifecycle ID.
    Update {
        /// Complete newly approved state.
        update: ConversationGrantUpdate,
        /// Required when any typed permission is added.
        permission_expansion: Option<PermissionExpansionConfirmation>,
        /// Required when switching to `AllMessages`.
        all_messages: Option<AllMessagesConfirmation>,
    },
    /// Permanently revokes the current grant generation.
    Revoke {
        /// Authenticated server UTC time of revocation.
        revoked_at_ms: i64,
    },
    /// Creates a fresh lifecycle ID after revocation without resetting version fencing.
    Regrant {
        /// New lifecycle ID for the replacement grant.
        grant_id: GrantId,
        /// Complete freshly approved state.
        update: ConversationGrantUpdate,
        /// Mandatory evidence for restoring non-empty permissions.
        permission_expansion: PermissionExpansionConfirmation,
        /// Required for an `AllMessages` replacement.
        all_messages: Option<AllMessagesConfirmation>,
    },
}

/// Current grant head for one tenant/conversation/installation pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationGrant {
    tenant_id: TenantId,
    grant_id: GrantId,
    conversation_id: ConversationId,
    installation_id: InstallationId,
    permissions: AgentConversationPermissions,
    trigger_policy: TriggerPolicy,
    privacy_policy_hash: PrivacyPolicyDigest,
    grant_version: Revision,
    approved_by_device: DeviceId,
    approved_at_ms: i64,
    expires_at_ms: Option<i64>,
    revoked_at_ms: Option<i64>,
    used_grant_ids: BTreeSet<GrantId>,
}

/// Complete non-secret persistence image of one current grant head and its ID fence history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationGrantSnapshot {
    pub tenant_id: TenantId,
    pub grant_id: GrantId,
    pub conversation_id: ConversationId,
    pub installation_id: InstallationId,
    pub permissions: AgentConversationPermissions,
    pub trigger_policy: TriggerPolicy,
    pub privacy_policy_hash: PrivacyPolicyDigest,
    pub grant_version: Revision,
    pub approved_by_device: DeviceId,
    pub approved_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub revoked_at_ms: Option<i64>,
    pub used_grant_ids: BTreeSet<GrantId>,
}

impl ConversationGrant {
    /// Issues the first grant version from a freshly approved installation flow.
    ///
    /// # Errors
    ///
    /// Rejects disabled installations, empty permission sets, invalid expiry,
    /// and an unconfirmed all-messages trigger.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        installation: &AgentInstallation,
        grant_id: GrantId,
        conversation_id: ConversationId,
        permissions: AgentConversationPermissions,
        trigger_policy: TriggerPolicy,
        privacy_policy_hash: PrivacyPolicyDigest,
        approved_by_device: DeviceId,
        approved_at_ms: i64,
        expires_at_ms: Option<i64>,
        all_messages: Option<AllMessagesConfirmation>,
    ) -> Result<Self, ConversationGrantError> {
        ensure_installation_usable(installation)?;
        validate_grant_facts(&permissions, trigger_policy, approved_at_ms, expires_at_ms)?;
        if trigger_policy == TriggerPolicy::AllMessages && all_messages.is_none() {
            return Err(ConversationGrantError::AllMessagesConfirmationRequired);
        }
        let mut used_grant_ids = BTreeSet::new();
        used_grant_ids.insert(grant_id);
        Ok(Self {
            tenant_id: installation.tenant_id(),
            grant_id,
            conversation_id,
            installation_id: installation.installation_id(),
            permissions,
            trigger_policy,
            privacy_policy_hash,
            grant_version: Revision::INITIAL,
            approved_by_device,
            approved_at_ms,
            expires_at_ms,
            revoked_at_ms: None,
            used_grant_ids,
        })
    }

    /// Captures the current authorization facts and every retired lifecycle ID.
    #[must_use]
    pub fn snapshot(&self) -> ConversationGrantSnapshot {
        ConversationGrantSnapshot {
            tenant_id: self.tenant_id,
            grant_id: self.grant_id,
            conversation_id: self.conversation_id,
            installation_id: self.installation_id,
            permissions: self.permissions.clone(),
            trigger_policy: self.trigger_policy,
            privacy_policy_hash: self.privacy_policy_hash,
            grant_version: self.grant_version,
            approved_by_device: self.approved_by_device,
            approved_at_ms: self.approved_at_ms,
            expires_at_ms: self.expires_at_ms,
            revoked_at_ms: self.revoked_at_ms,
            used_grant_ids: self.used_grant_ids.clone(),
        }
    }

    /// Rehydrates a grant after validating lifecycle, time, and version fences.
    ///
    /// # Errors
    ///
    /// Rejects empty authority, invalid times, missing/reused lifecycle history,
    /// and histories that could not fit within the captured monotonic version.
    pub fn try_from_snapshot(
        snapshot: ConversationGrantSnapshot,
    ) -> Result<Self, ConversationGrantSnapshotError> {
        if snapshot.permissions.is_empty() {
            return Err(ConversationGrantSnapshotError::EmptyPermissions);
        }
        if snapshot
            .expires_at_ms
            .is_some_and(|expires_at| expires_at <= snapshot.approved_at_ms)
        {
            return Err(ConversationGrantSnapshotError::InvalidExpiry);
        }
        if snapshot
            .revoked_at_ms
            .is_some_and(|revoked_at| revoked_at < snapshot.approved_at_ms)
        {
            return Err(ConversationGrantSnapshotError::InvalidRevocationTime);
        }
        if !snapshot.used_grant_ids.contains(&snapshot.grant_id) {
            return Err(ConversationGrantSnapshotError::CurrentGrantIdMissing);
        }
        let id_count = u64::try_from(snapshot.used_grant_ids.len())
            .map_err(|_| ConversationGrantSnapshotError::ImpossibleVersionHistory)?;
        let minimum_version = id_count
            .checked_mul(2)
            .and_then(|value| value.checked_sub(1))
            .and_then(|value| value.checked_add(u64::from(snapshot.revoked_at_ms.is_some())))
            .ok_or(ConversationGrantSnapshotError::ImpossibleVersionHistory)?;
        if snapshot.grant_version.get() < minimum_version {
            return Err(ConversationGrantSnapshotError::ImpossibleVersionHistory);
        }
        if snapshot.grant_version.get() == Revision::INITIAL.get()
            && (snapshot.used_grant_ids.len() != 1 || snapshot.revoked_at_ms.is_some())
        {
            return Err(ConversationGrantSnapshotError::UnreachableInitialState);
        }
        Ok(Self {
            tenant_id: snapshot.tenant_id,
            grant_id: snapshot.grant_id,
            conversation_id: snapshot.conversation_id,
            installation_id: snapshot.installation_id,
            permissions: snapshot.permissions,
            trigger_policy: snapshot.trigger_policy,
            privacy_policy_hash: snapshot.privacy_policy_hash,
            grant_version: snapshot.grant_version,
            approved_by_device: snapshot.approved_by_device,
            approved_at_ms: snapshot.approved_at_ms,
            expires_at_ms: snapshot.expires_at_ms,
            revoked_at_ms: snapshot.revoked_at_ms,
            used_grant_ids: snapshot.used_grant_ids,
        })
    }

    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    #[must_use]
    pub const fn installation_id(&self) -> InstallationId {
        self.installation_id
    }

    /// Returns the current grant lifecycle ID.
    #[must_use]
    pub const fn grant_id(&self) -> GrantId {
        self.grant_id
    }

    /// Returns the conversation boundary.
    #[must_use]
    pub const fn conversation_id(&self) -> ConversationId {
        self.conversation_id
    }

    /// Returns the current typed permission set.
    #[must_use]
    pub const fn permissions(&self) -> &AgentConversationPermissions {
        &self.permissions
    }

    /// Returns the current trigger policy.
    #[must_use]
    pub const fn trigger_policy(&self) -> TriggerPolicy {
        self.trigger_policy
    }

    /// Returns the exact authorization-fencing version.
    #[must_use]
    pub const fn grant_version(&self) -> Revision {
        self.grant_version
    }

    /// Evaluates the current grant at an exclusive expiry boundary.
    #[must_use]
    pub fn is_active_for(&self, installation: &AgentInstallation, now_ms: i64) -> bool {
        self.scope_matches(installation)
            && installation.desired_state() == InstallationDesiredState::Enabled
            && self.revoked_at_ms.is_none()
            && now_ms >= self.approved_at_ms
            && self
                .expires_at_ms
                .is_none_or(|expires_at| now_ms < expires_at)
    }

    /// Fences a Run against both current activity and its captured grant version.
    #[must_use]
    pub fn authorizes_version_for(
        &self,
        installation: &AgentInstallation,
        now_ms: i64,
        captured_version: Revision,
    ) -> bool {
        self.grant_version == captured_version && self.is_active_for(installation, now_ms)
    }

    /// Applies one exact-version grant-head transition.
    ///
    /// # Errors
    ///
    /// Rejects scope/revision mismatches, invalid expiry/revocation time,
    /// unconfirmed authority expansion, invalid lifecycle transitions, and
    /// disabled installations for update/regrant.
    pub fn apply(
        &mut self,
        installation: &AgentInstallation,
        expected_version: Revision,
        command: ConversationGrantCommand,
    ) -> Result<Revision, ConversationGrantError> {
        if !self.scope_matches(installation) {
            return Err(ConversationGrantError::ScopeMismatch);
        }
        if self.grant_version != expected_version {
            return Err(ConversationGrantError::VersionConflict {
                actual: self.grant_version,
                expected: expected_version,
            });
        }

        let next_version = self
            .grant_version
            .checked_next()
            .map_err(|_| ConversationGrantError::VersionExhausted)?;
        match command {
            ConversationGrantCommand::Update {
                update,
                permission_expansion,
                all_messages,
            } => {
                ensure_installation_usable(installation)?;
                if self.revoked_at_ms.is_some() {
                    return Err(ConversationGrantError::Revoked);
                }
                validate_grant_facts(
                    &update.permissions,
                    update.trigger_policy,
                    update.approved_at_ms,
                    update.expires_at_ms,
                )?;
                if update.approved_at_ms <= self.approved_at_ms {
                    return Err(ConversationGrantError::InvalidApprovalTime);
                }
                if !update.permissions.is_subset_of(&self.permissions)
                    && permission_expansion.is_none()
                {
                    return Err(ConversationGrantError::PermissionExpansionConfirmationRequired);
                }
                if update.trigger_policy == TriggerPolicy::AllMessages
                    && self.trigger_policy != TriggerPolicy::AllMessages
                    && all_messages.is_none()
                {
                    return Err(ConversationGrantError::AllMessagesConfirmationRequired);
                }
                if self.matches_update(&update) {
                    return Err(ConversationGrantError::NoChange);
                }
                self.replace_facts(update);
            }
            ConversationGrantCommand::Revoke { revoked_at_ms } => {
                if self.revoked_at_ms.is_some() {
                    return Err(ConversationGrantError::Revoked);
                }
                if revoked_at_ms < self.approved_at_ms {
                    return Err(ConversationGrantError::InvalidRevocationTime);
                }
                self.revoked_at_ms = Some(revoked_at_ms);
            }
            ConversationGrantCommand::Regrant {
                grant_id,
                update,
                permission_expansion: _,
                all_messages,
            } => {
                ensure_installation_usable(installation)?;
                if self.revoked_at_ms.is_none() {
                    return Err(ConversationGrantError::InvalidTransition);
                }
                let revoked_at_ms = self
                    .revoked_at_ms
                    .ok_or(ConversationGrantError::InvalidTransition)?;
                if self.used_grant_ids.contains(&grant_id) {
                    return Err(ConversationGrantError::GrantIdReused);
                }
                validate_grant_facts(
                    &update.permissions,
                    update.trigger_policy,
                    update.approved_at_ms,
                    update.expires_at_ms,
                )?;
                if update.approved_at_ms <= revoked_at_ms {
                    return Err(ConversationGrantError::InvalidApprovalTime);
                }
                if update.trigger_policy == TriggerPolicy::AllMessages && all_messages.is_none() {
                    return Err(ConversationGrantError::AllMessagesConfirmationRequired);
                }
                self.used_grant_ids.insert(grant_id);
                self.grant_id = grant_id;
                self.replace_facts(update);
            }
        }
        self.grant_version = next_version;
        Ok(next_version)
    }

    fn scope_matches(&self, installation: &AgentInstallation) -> bool {
        self.tenant_id == installation.tenant_id()
            && self.installation_id == installation.installation_id()
    }

    fn matches_update(&self, update: &ConversationGrantUpdate) -> bool {
        self.permissions == update.permissions
            && self.trigger_policy == update.trigger_policy
            && self.privacy_policy_hash == update.privacy_policy_hash
            && self.approved_by_device == update.approved_by_device
            && self.approved_at_ms == update.approved_at_ms
            && self.expires_at_ms == update.expires_at_ms
    }

    fn replace_facts(&mut self, update: ConversationGrantUpdate) {
        self.permissions = update.permissions;
        self.trigger_policy = update.trigger_policy;
        self.privacy_policy_hash = update.privacy_policy_hash;
        self.approved_by_device = update.approved_by_device;
        self.approved_at_ms = update.approved_at_ms;
        self.expires_at_ms = update.expires_at_ms;
        self.revoked_at_ms = None;
    }
}

fn ensure_installation_usable(
    installation: &AgentInstallation,
) -> Result<(), ConversationGrantError> {
    if installation.desired_state() == InstallationDesiredState::Enabled {
        Ok(())
    } else {
        Err(ConversationGrantError::InstallationNotUsable)
    }
}

fn validate_grant_facts(
    permissions: &AgentConversationPermissions,
    _trigger_policy: TriggerPolicy,
    approved_at_ms: i64,
    expires_at_ms: Option<i64>,
) -> Result<(), ConversationGrantError> {
    if permissions.is_empty() {
        return Err(ConversationGrantError::EmptyPermissions);
    }
    if expires_at_ms.is_some_and(|expires_at| expires_at <= approved_at_ms) {
        return Err(ConversationGrantError::InvalidExpiry);
    }
    Ok(())
}

/// Stable conversation grant rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationGrantError {
    /// The supplied installation is from another tenant/lifecycle.
    ScopeMismatch,
    /// The command used an obsolete grant version.
    VersionConflict {
        /// Current grant version.
        actual: Revision,
        /// Caller-supplied version.
        expected: Revision,
    },
    /// Disabled or revoked installations cannot issue/update/regrant access.
    InstallationNotUsable,
    /// A grant with no positive authority is rejected.
    EmptyPermissions,
    /// Expiry must be strictly later than its approval.
    InvalidExpiry,
    /// Revocation cannot predate the approval being revoked.
    InvalidRevocationTime,
    /// A replacement approval must be newer than the authority it replaces.
    InvalidApprovalTime,
    /// A permission was added without a fresh confirmation marker.
    PermissionExpansionConfirmationRequired,
    /// All-messages triggering lacks its separate high-risk confirmation.
    AllMessagesConfirmationRequired,
    /// The grant generation is revoked.
    Revoked,
    /// Regrant is only valid after revocation.
    InvalidTransition,
    /// A replacement grant must receive a fresh lifecycle ID.
    GrantIdReused,
    /// The proposed update exactly matches current facts.
    NoChange,
    /// The exact cross-platform version range was exhausted.
    VersionExhausted,
}

impl fmt::Display for ConversationGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ScopeMismatch => "conversation grant installation scope mismatch",
            Self::VersionConflict { .. } => "conversation grant version conflict",
            Self::InstallationNotUsable => "Agent installation is not usable",
            Self::EmptyPermissions => "conversation grant has no permissions",
            Self::InvalidExpiry => "conversation grant expiry is invalid",
            Self::InvalidRevocationTime => "conversation grant revocation time is invalid",
            Self::InvalidApprovalTime => "conversation grant approval time is not fresh",
            Self::PermissionExpansionConfirmationRequired => {
                "permission expansion confirmation is required"
            }
            Self::AllMessagesConfirmationRequired => {
                "all-messages trigger confirmation is required"
            }
            Self::Revoked => "conversation grant is revoked",
            Self::InvalidTransition => "invalid conversation grant transition",
            Self::GrantIdReused => "regrant must use a fresh grant ID",
            Self::NoChange => "conversation grant command would not change state",
            Self::VersionExhausted => "conversation grant version is exhausted",
        })
    }
}

impl Error for ConversationGrantError {}

/// Stable rejection for an invalid durable grant image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversationGrantSnapshotError {
    EmptyPermissions,
    InvalidExpiry,
    InvalidRevocationTime,
    CurrentGrantIdMissing,
    ImpossibleVersionHistory,
    UnreachableInitialState,
}

impl fmt::Display for ConversationGrantSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyPermissions => "grant snapshot has no permissions",
            Self::InvalidExpiry => "grant snapshot expiry is invalid",
            Self::InvalidRevocationTime => "grant snapshot revocation time is invalid",
            Self::CurrentGrantIdMissing => "grant snapshot omits its current lifecycle ID",
            Self::ImpossibleVersionHistory => "grant snapshot history exceeds its version",
            Self::UnreachableInitialState => "grant snapshot has an unreachable initial state",
        })
    }
}

impl Error for ConversationGrantSnapshotError {}
