//! Durable, replay-safe group-control commands.
//!
//! Membership commands are intentionally separate because their approval
//! transitions create a Sequencer outbox. These commands cover the local
//! policy mutations that make that workflow usable: group creation, owner-only
//! administrator changes, and Owner/Admin invitation lifecycle changes.

use dtx_domain::{DeviceId, IdentityId, InviteCapabilityId, RequestId, Revision, TenantId};
use dtx_group_policy::{GroupPolicy, GroupPolicyError, GroupScope};
use dtx_identity_persistence::DeviceSessionCredential;
use dtx_wire::{Sha256Digest, SigningPublicKey};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::{
    GroupPersistenceError, GroupPgStore, VerifiedDeviceActor,
    repository::{
        ScopeKey, begin_authenticated, begin_authenticated_with_signing_key, load_policy,
        persist_policy, settle,
    },
};

const CREATE_GROUP_ACTION: &str = "create_group";
const GRANT_ADMIN_ACTION: &str = "grant_admin";
const REVOKE_ADMIN_ACTION: &str = "revoke_admin";
const ISSUE_INVITE_ACTION: &str = "issue_invite";
const REVOKE_INVITE_ACTION: &str = "revoke_invite";

const APPLIED_DISPOSITION: &str = "applied";
const ALREADY_APPLIED_DISPOSITION: &str = "already_applied";
const REJECTED_DISPOSITION: &str = "rejected";

const POLICY_DENIED_REJECTION: &str = "policy_denied";
const REVISION_CONFLICT_REJECTION: &str = "revision_conflict";
const ADMIN_LIMIT_REACHED_REJECTION: &str = "admin_limit_reached";
const INVALID_OPERATION_REJECTION: &str = "invalid_operation";
const GROUP_EXISTS_REJECTION: &str = "group_exists";

/// One typed local policy operation. The authenticated actor, command ID,
/// stable idempotency key hash, and canonical request digest are carried by
/// [`GroupControlCommand`] rather than repeating them in every variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupControlOperation {
    /// Creates a new private conversation or controlled public-channel group.
    CreateGroup {
        /// Strongly typed target group boundary.
        scope: GroupScope,
        /// The initial owner, who must be the authenticated actor.
        owner_identity_id: IdentityId,
    },
    /// Adds one of at most five additional administrators.
    GrantAdmin {
        /// Target group boundary.
        scope: GroupScope,
        /// Policy revision the owner observed.
        expected_revision: Revision,
        /// Identity receiving the administrator term.
        administrator_identity_id: IdentityId,
    },
    /// Removes an additional administrator term while preserving membership.
    RevokeAdmin {
        /// Target group boundary.
        scope: GroupScope,
        /// Policy revision the owner observed.
        expected_revision: Revision,
        /// Identity losing the administrator term.
        administrator_identity_id: IdentityId,
    },
    /// Issues a bounded invite under current Owner/Admin authority.
    IssueInvite {
        /// Target group boundary.
        scope: GroupScope,
        /// Policy revision the issuer observed.
        expected_revision: Revision,
        /// Stable invitation capability ID.
        invite_id: InviteCapabilityId,
        /// Optional identity restriction for this invite.
        target_identity_id: Option<IdentityId>,
        /// Maximum number of eventual admissions the invite may authorize.
        max_uses: u32,
        /// Exclusive server-validated invite expiry in Unix milliseconds.
        expires_at_ms: i64,
    },
    /// Revokes a currently active Owner/Admin-issued invite.
    RevokeInvite {
        /// Target group boundary.
        scope: GroupScope,
        /// Policy revision the issuer observed.
        expected_revision: Revision,
        /// Invitation to revoke.
        invite_id: InviteCapabilityId,
    },
}

impl GroupControlOperation {
    /// Returns the group boundary this operation may affect.
    #[must_use]
    pub const fn scope(self) -> GroupScope {
        match self {
            Self::CreateGroup { scope, .. }
            | Self::GrantAdmin { scope, .. }
            | Self::RevokeAdmin { scope, .. }
            | Self::IssueInvite { scope, .. }
            | Self::RevokeInvite { scope, .. } => scope,
        }
    }

    const fn action_code(self) -> &'static str {
        match self {
            Self::CreateGroup { .. } => CREATE_GROUP_ACTION,
            Self::GrantAdmin { .. } => GRANT_ADMIN_ACTION,
            Self::RevokeAdmin { .. } => REVOKE_ADMIN_ACTION,
            Self::IssueInvite { .. } => ISSUE_INVITE_ACTION,
            Self::RevokeInvite { .. } => REVOKE_INVITE_ACTION,
        }
    }
}

/// A fully authenticated and canonicalized group-control mutation.
///
/// The HTTP boundary verifies the device action proof before constructing this
/// value. The persistence layer nevertheless retains all actor and digest
/// bindings, so a response-loss replay cannot mutate another action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupControlCommand {
    command_id: RequestId,
    idempotency_key_hash: Sha256Digest,
    actor_identity_id: IdentityId,
    actor_device_id: DeviceId,
    operation: GroupControlOperation,
    request_digest: Sha256Digest,
    binding_digest: Sha256Digest,
}

impl GroupControlCommand {
    /// Creates a bounded command after transport authentication and proof verification.
    #[must_use]
    pub const fn new(
        command_id: RequestId,
        idempotency_key_hash: Sha256Digest,
        actor_identity_id: IdentityId,
        actor_device_id: DeviceId,
        operation: GroupControlOperation,
        request_digest: Sha256Digest,
        binding_digest: Sha256Digest,
    ) -> Self {
        Self {
            command_id,
            idempotency_key_hash,
            actor_identity_id,
            actor_device_id,
            operation,
            request_digest,
            binding_digest,
        }
    }

    /// Returns the stable command ID.
    #[must_use]
    pub const fn command_id(self) -> RequestId {
        self.command_id
    }

    /// Returns only the retained hash of the caller's idempotency key.
    #[must_use]
    pub const fn idempotency_key_hash(self) -> Sha256Digest {
        self.idempotency_key_hash
    }

    /// Returns the identity authenticated at the transport boundary.
    #[must_use]
    pub const fn actor_identity_id(self) -> IdentityId {
        self.actor_identity_id
    }

    /// Returns the authenticated device that signed this action.
    #[must_use]
    pub const fn actor_device_id(self) -> DeviceId {
        self.actor_device_id
    }

    /// Returns the typed local policy operation.
    #[must_use]
    pub const fn operation(self) -> GroupControlOperation {
        self.operation
    }

    /// Returns the immutable canonical body digest.
    #[must_use]
    pub const fn request_digest(self) -> Sha256Digest {
        self.request_digest
    }

    /// Returns the verified device-proof binding digest retained for the HTTP receipt.
    #[must_use]
    pub const fn binding_digest(self) -> Sha256Digest {
        self.binding_digest
    }
}

/// Stable terminal rejection for a local group-control command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupControlRejection {
    /// The authenticated actor lacks the required current role.
    PolicyDenied,
    /// The caller acted on a stale policy revision.
    RevisionConflict,
    /// A sixth additional administrator was requested.
    AdminLimitReached,
    /// The request is well-formed but impossible in current policy state.
    InvalidOperation,
    /// A different initial policy already owns this scope.
    GroupExists,
}

/// Final durable state of a group-control command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupControlDisposition {
    /// The command changed the durable policy to this revision.
    Applied { policy_revision: Revision },
    /// The same desired state was already established before this command.
    AlreadyApplied { policy_revision: Revision },
    /// The command was durably rejected and is safe to display/replay.
    Rejected(GroupControlRejection),
}

/// Exact, non-secret receipt for a local group-control command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupControlReceipt {
    command_id: RequestId,
    request_digest: Sha256Digest,
    binding_digest: Sha256Digest,
    disposition: GroupControlDisposition,
    administrator_count: u8,
}

impl GroupControlReceipt {
    /// Returns the stable command identity.
    #[must_use]
    pub const fn command_id(self) -> RequestId {
        self.command_id
    }

    /// Returns the immutable canonical request digest.
    #[must_use]
    pub const fn request_digest(self) -> Sha256Digest {
        self.request_digest
    }

    /// Returns the immutable verified device-proof binding digest from the
    /// initial accepted command. A proof refresh on an idempotent retry keeps
    /// returning this original receipt fact.
    #[must_use]
    pub const fn binding_digest(self) -> Sha256Digest {
        self.binding_digest
    }

    /// Returns the durable terminal disposition.
    #[must_use]
    pub const fn disposition(self) -> GroupControlDisposition {
        self.disposition
    }

    /// Returns the immutable Owner-excluded administrator count observed by
    /// this command. This is retained with the receipt so an exact replay does
    /// not accidentally report a later policy state.
    #[must_use]
    pub const fn administrator_count(self) -> u8 {
        self.administrator_count
    }
}

/// Result of executing one group-control mutation at the HTTP boundary.
///
/// The receipt itself is immutable. The replay marker describes only whether
/// this invocation created that receipt, allowing a transport to distinguish
/// `201 Created` from an exact `200 OK` replay without changing receipt facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupControlExecution {
    receipt: GroupControlReceipt,
    replayed: bool,
}

impl GroupControlExecution {
    /// Returns the durable receipt.
    #[must_use]
    pub const fn receipt(self) -> GroupControlReceipt {
        self.receipt
    }

    /// Reports whether this invocation replayed an existing receipt.
    #[must_use]
    pub const fn replayed(self) -> bool {
        self.replayed
    }
}

/// Durable local group-policy mutation repository.
#[derive(Clone, Copy, Debug, Default)]
pub struct GroupControlRepository;

#[allow(clippy::missing_errors_doc)] // The shared error type documents the fail-closed boundary.
impl GroupControlRepository {
    /// Executes or exactly replays one local group-control mutation.
    ///
    /// Existing receipts are checked before policy validation. Therefore, a
    /// response loss cannot turn a successful grant or invite issuance into a
    /// later stale-revision failure.
    pub async fn execute(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        command: GroupControlCommand,
        now_ms: i64,
    ) -> Result<GroupControlReceipt, GroupPersistenceError> {
        let mut session = store.begin(tenant_id).await?;
        let result =
            execute_in_transaction(session.connection(), tenant_id, &command, now_ms).await;
        settle(session, result)
            .await
            .map(GroupControlExecution::receipt)
    }

    /// Executes or exactly replays one command after revalidating the active
    /// device session in the same durable transaction.
    pub async fn execute_authenticated(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: GroupControlCommand,
        now_ms: i64,
    ) -> Result<GroupControlReceipt, GroupPersistenceError> {
        let (mut session, authenticated) =
            begin_authenticated(store, tenant_id, credential, now_ms).await?;
        let result = async {
            if authenticated.identity_id() != command.actor_identity_id()
                || authenticated.device_id() != command.actor_device_id()
            {
                return Err(GroupPersistenceError::DeviceAuthenticationRejected);
            }
            execute_in_transaction(session.connection(), tenant_id, &command, now_ms).await
        }
        .await;
        settle(session, result)
            .await
            .map(GroupControlExecution::receipt)
    }

    /// Executes a mutation only after a caller-provided proof verifier accepts
    /// the signing key resolved in the same transaction as device-session
    /// validation and durable receipt lookup.
    pub async fn execute_authenticated_with_proof<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: GroupControlCommand,
        now_ms: i64,
        verify_proof: F,
    ) -> Result<GroupControlReceipt, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        self.execute_authenticated_with_proof_outcome(
            store,
            tenant_id,
            credential,
            command,
            now_ms,
            verify_proof,
        )
        .await
        .map(GroupControlExecution::receipt)
    }

    /// Executes a proof-verified mutation and reports whether this invocation
    /// created or replayed the immutable durable receipt.
    pub async fn execute_authenticated_with_proof_outcome<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        credential: &DeviceSessionCredential,
        command: GroupControlCommand,
        now_ms: i64,
        verify_proof: F,
    ) -> Result<GroupControlExecution, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let (mut session, authenticated) =
            begin_authenticated_with_signing_key(store, tenant_id, credential, now_ms).await?;
        let result = async {
            let actor = authenticated.session();
            if actor.identity_id() != command.actor_identity_id()
                || actor.device_id() != command.actor_device_id()
            {
                return Err(GroupPersistenceError::DeviceAuthenticationRejected);
            }
            verify_proof(authenticated.signing_key())?;
            execute_in_transaction(session.connection(), tenant_id, &command, now_ms).await
        }
        .await;
        settle(session, result).await
    }

    /// Executes a remote-device mutation after the caller has resolved a
    /// current self-authenticated identity-log device key.
    pub async fn execute_verified_with_proof_outcome<F>(
        self,
        store: &GroupPgStore,
        tenant_id: TenantId,
        actor: VerifiedDeviceActor,
        command: GroupControlCommand,
        now_ms: i64,
        verify_proof: F,
    ) -> Result<GroupControlExecution, GroupPersistenceError>
    where
        F: FnOnce(SigningPublicKey) -> Result<(), GroupPersistenceError>,
    {
        let mut session = store.begin(tenant_id).await?;
        let result = async {
            if actor.identity_id() != command.actor_identity_id()
                || actor.device_id() != command.actor_device_id()
            {
                return Err(GroupPersistenceError::DeviceAuthenticationRejected);
            }
            verify_proof(actor.signing_key())?;
            execute_in_transaction(session.connection(), tenant_id, &command, now_ms).await
        }
        .await;
        settle(session, result).await
    }
}

async fn execute_in_transaction(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &GroupControlCommand,
    now_ms: i64,
) -> Result<GroupControlExecution, GroupPersistenceError> {
    let scope = command.operation().scope();
    let key = ScopeKey::from_scope(tenant_id, scope);
    lock_command_keys(connection, tenant_id, command, scope).await?;
    if let Some(receipt) = load_existing_command(connection, tenant_id, command).await? {
        return Ok(GroupControlExecution {
            receipt,
            replayed: true,
        });
    }
    if let Some(receipt) = load_existing_idempotency(connection, tenant_id, command).await? {
        return Ok(GroupControlExecution {
            receipt,
            replayed: true,
        });
    }

    let receipt = match command.operation() {
        GroupControlOperation::CreateGroup {
            scope,
            owner_identity_id,
        } => {
            let existing = load_policy(connection, key, true).await?;
            if let Some(policy) = existing {
                if policy.owner_id() == owner_identity_id
                    && command.actor_identity_id() == owner_identity_id
                {
                    GroupControlReceipt {
                        command_id: command.command_id(),
                        request_digest: command.request_digest(),
                        binding_digest: command.binding_digest(),
                        disposition: GroupControlDisposition::AlreadyApplied {
                            policy_revision: policy.revision(),
                        },
                        administrator_count: policy
                            .admin_count()
                            .try_into()
                            .expect("group administrator limit is bounded"),
                    }
                } else {
                    rejected_receipt(
                        command,
                        GroupControlRejection::GroupExists,
                        policy.admin_count(),
                    )
                }
            } else if command.actor_identity_id() != owner_identity_id {
                rejected_receipt(command, GroupControlRejection::PolicyDenied, 0)
            } else {
                let policy = GroupPolicy::new(scope, owner_identity_id);
                persist_policy(connection, tenant_id, &policy, now_ms, true).await?;
                applied_receipt(command, policy.revision(), policy.admin_count())
            }
        }
        operation => {
            let Some(mut policy) = load_policy(connection, key, true).await? else {
                return Err(GroupPersistenceError::GroupNotFound);
            };
            match apply_existing_operation(
                &mut policy,
                command.actor_identity_id(),
                operation,
                now_ms,
            ) {
                Ok(Some(policy_revision)) => {
                    persist_policy(connection, tenant_id, &policy, now_ms, false).await?;
                    applied_receipt(command, policy_revision, policy.admin_count())
                }
                Ok(None) => GroupControlReceipt {
                    command_id: command.command_id(),
                    request_digest: command.request_digest(),
                    binding_digest: command.binding_digest(),
                    disposition: GroupControlDisposition::AlreadyApplied {
                        policy_revision: policy.revision(),
                    },
                    administrator_count: policy
                        .admin_count()
                        .try_into()
                        .expect("group administrator limit is bounded"),
                },
                Err(error) => {
                    rejected_receipt(command, map_policy_rejection(error)?, policy.admin_count())
                }
            }
        }
    };
    insert_command(connection, tenant_id, command, receipt, now_ms).await?;
    Ok(GroupControlExecution {
        receipt,
        replayed: false,
    })
}

fn apply_existing_operation(
    policy: &mut GroupPolicy,
    actor_identity_id: IdentityId,
    operation: GroupControlOperation,
    now_ms: i64,
) -> Result<Option<Revision>, GroupPolicyError> {
    match operation {
        GroupControlOperation::CreateGroup { .. } => {
            unreachable!("creation is handled before policy load")
        }
        GroupControlOperation::GrantAdmin {
            expected_revision,
            administrator_identity_id,
            ..
        } => policy
            .grant_admin(
                expected_revision,
                actor_identity_id,
                administrator_identity_id,
            )
            .map(Some),
        GroupControlOperation::RevokeAdmin {
            expected_revision,
            administrator_identity_id,
            ..
        } => policy
            .revoke_admin(
                expected_revision,
                actor_identity_id,
                administrator_identity_id,
            )
            .map(Some),
        GroupControlOperation::IssueInvite {
            expected_revision,
            invite_id,
            target_identity_id,
            max_uses,
            expires_at_ms,
            ..
        } => policy
            .issue_invite(
                expected_revision,
                actor_identity_id,
                invite_id,
                target_identity_id,
                max_uses,
                expires_at_ms,
                now_ms,
            )
            .map(|_| Some(policy.revision())),
        GroupControlOperation::RevokeInvite {
            expected_revision,
            invite_id,
            ..
        } => policy
            .revoke_invite(expected_revision, actor_identity_id, invite_id)
            .map(Some),
    }
}

fn applied_receipt(
    command: &GroupControlCommand,
    policy_revision: Revision,
    administrator_count: usize,
) -> GroupControlReceipt {
    GroupControlReceipt {
        command_id: command.command_id(),
        request_digest: command.request_digest(),
        binding_digest: command.binding_digest(),
        disposition: GroupControlDisposition::Applied { policy_revision },
        administrator_count: administrator_count
            .try_into()
            .expect("group administrator limit is bounded"),
    }
}

fn rejected_receipt(
    command: &GroupControlCommand,
    rejection: GroupControlRejection,
    administrator_count: usize,
) -> GroupControlReceipt {
    GroupControlReceipt {
        command_id: command.command_id(),
        request_digest: command.request_digest(),
        binding_digest: command.binding_digest(),
        disposition: GroupControlDisposition::Rejected(rejection),
        administrator_count: administrator_count
            .try_into()
            .expect("group administrator limit is bounded"),
    }
}

fn map_policy_rejection(
    error: GroupPolicyError,
) -> Result<GroupControlRejection, GroupPersistenceError> {
    match error {
        GroupPolicyError::RevisionConflict { .. } => Ok(GroupControlRejection::RevisionConflict),
        GroupPolicyError::AdminLimitReached => Ok(GroupControlRejection::AdminLimitReached),
        GroupPolicyError::Unauthorized | GroupPolicyError::OwnerCannotBeAdmin => {
            Ok(GroupControlRejection::PolicyDenied)
        }
        GroupPolicyError::AlreadyAdmin
        | GroupPolicyError::NotAdmin
        | GroupPolicyError::InviteAlreadyExists
        | GroupPolicyError::InvalidInviteUseLimit
        | GroupPolicyError::InvalidInviteExpiry
        | GroupPolicyError::InviteNotFound
        | GroupPolicyError::InviteAlreadyRevoked
        | GroupPolicyError::AlreadyMember
        | GroupPolicyError::JoinRequestAlreadyPending
        | GroupPolicyError::CandidateJoinInFlight
        | GroupPolicyError::PendingJoinNotFound
        | GroupPolicyError::AlreadyApproved
        | GroupPolicyError::JoinAlreadyReserved
        | GroupPolicyError::ReservedJoinNotFound
        | GroupPolicyError::InviteRevoked
        | GroupPolicyError::InviteExpired
        | GroupPolicyError::InviteTargetMismatch
        | GroupPolicyError::InviteUseLimitReached
        | GroupPolicyError::InviteIssuerNoLongerAuthorized => {
            Ok(GroupControlRejection::InvalidOperation)
        }
        GroupPolicyError::CounterExhausted | GroupPolicyError::ReservationInvariantViolation => {
            Err(GroupPersistenceError::GroupPolicy(error))
        }
    }
}

async fn lock_command_keys(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &GroupControlCommand,
    scope: GroupScope,
) -> Result<(), GroupPersistenceError> {
    // All policy changes for one scope, including the initial create that has
    // no row to lock yet, must serialize under the same scope lock.  Including
    // the actor here would let two first creators race past an absent
    // `policy_heads` row and turn the losing create into a database error.
    let scope_lock = format!("{}:{}", tenant_id, scope_id(scope));
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(command.command_id().to_string())
        .execute(&mut *connection)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(scope_lock)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn load_existing_command(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &GroupControlCommand,
) -> Result<Option<GroupControlReceipt>, GroupPersistenceError> {
    let row = sqlx::query(
        "SELECT scope_kind, scope_id, actor_identity_id, actor_device_id,
                idempotency_key_hash, action, request_digest, binding_digest,
                disposition, policy_revision, rejection, administrator_count
          FROM groups.control_commands
          WHERE tenant_id=$1 AND command_id=$2
        ",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(command.command_id()))
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let scope = command.operation().scope();
    let same = row.try_get::<String, _>("scope_kind")? == scope_kind(scope)
        && row.try_get::<String, _>("scope_id")? == scope_id(scope)
        && row.try_get::<String, _>("actor_identity_id")?
            == command.actor_identity_id().to_string()
        && row.try_get::<Uuid, _>("actor_device_id")? == Uuid::from(command.actor_device_id())
        && digest(
            row.try_get("idempotency_key_hash")?,
            "control idempotency hash",
        )? == command.idempotency_key_hash()
        && row.try_get::<String, _>("action")? == command.operation().action_code()
        && digest(row.try_get("request_digest")?, "control request digest")?
            == command.request_digest();
    if !same {
        return Err(GroupPersistenceError::ControlCommandConflict);
    }
    Ok(Some(receipt_from_row(&row)?))
}

async fn load_existing_idempotency(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &GroupControlCommand,
) -> Result<Option<GroupControlReceipt>, GroupPersistenceError> {
    let row = sqlx::query(
        "SELECT command_id, actor_device_id, action, request_digest, binding_digest,
                disposition, policy_revision, rejection, administrator_count
           FROM groups.control_commands
          WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3
            AND actor_identity_id=$4 AND idempotency_key_hash=$5",
    )
    .bind(Uuid::from(tenant_id))
    .bind(scope_kind(command.operation().scope()))
    .bind(scope_id(command.operation().scope()))
    .bind(command.actor_identity_id().to_string())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let same = row.try_get::<Uuid, _>("actor_device_id")? == Uuid::from(command.actor_device_id())
        && row.try_get::<String, _>("action")? == command.operation().action_code()
        && digest(row.try_get("request_digest")?, "control request digest")?
            == command.request_digest();
    if !same {
        return Err(GroupPersistenceError::ControlCommandConflict);
    }
    Ok(Some(receipt_from_row(&row)?))
}

async fn insert_command(
    connection: &mut PgConnection,
    tenant_id: TenantId,
    command: &GroupControlCommand,
    receipt: GroupControlReceipt,
    now_ms: i64,
) -> Result<(), GroupPersistenceError> {
    let scope = command.operation().scope();
    let (disposition, policy_revision, rejection) = disposition_columns(receipt.disposition())?;
    let inserted = sqlx::query(
        "INSERT INTO groups.control_commands
             (tenant_id, command_id, scope_kind, scope_id, actor_identity_id, actor_device_id,
              idempotency_key_hash, action, request_digest, binding_digest, disposition,
              policy_revision, rejection, administrator_count, created_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(Uuid::from(tenant_id))
    .bind(Uuid::from(command.command_id()))
    .bind(scope_kind(scope))
    .bind(scope_id(scope))
    .bind(command.actor_identity_id().to_string())
    .bind(Uuid::from(command.actor_device_id()))
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(command.operation().action_code())
    .bind(command.request_digest().as_bytes().as_slice())
    .bind(receipt.binding_digest().as_bytes().as_slice())
    .bind(disposition)
    .bind(policy_revision)
    .bind(rejection)
    .bind(i16::from(receipt.administrator_count()))
    .bind(now_ms)
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted != 1 {
        return Err(GroupPersistenceError::CorruptData(
            "group control receipt was not inserted",
        ));
    }
    Ok(())
}

fn receipt_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<GroupControlReceipt, GroupPersistenceError> {
    let command_id = RequestId::try_from(row.try_get::<Uuid, _>("command_id")?)
        .map_err(|_| GroupPersistenceError::CorruptData("control command ID"))?;
    let request_digest = digest(row.try_get("request_digest")?, "control request digest")?;
    let binding_digest = digest(row.try_get("binding_digest")?, "control binding digest")?;
    let disposition = row.try_get::<String, _>("disposition")?;
    let policy_revision = row
        .try_get::<Option<i64>, _>("policy_revision")?
        .map(|value| {
            let value = u64::try_from(value)
                .map_err(|_| GroupPersistenceError::CorruptData("control policy revision"))?;
            Revision::new(value)
                .map_err(|_| GroupPersistenceError::CorruptData("control policy revision"))
        })
        .transpose()?;
    let rejection = row.try_get::<Option<String>, _>("rejection")?;
    let administrator_count = u8::try_from(row.try_get::<i16, _>("administrator_count")?)
        .map_err(|_| GroupPersistenceError::CorruptData("control administrator count"))?;
    let disposition = match disposition.as_str() {
        APPLIED_DISPOSITION => GroupControlDisposition::Applied {
            policy_revision: policy_revision.ok_or(GroupPersistenceError::CorruptData(
                "control applied revision",
            ))?,
        },
        ALREADY_APPLIED_DISPOSITION => GroupControlDisposition::AlreadyApplied {
            policy_revision: policy_revision.ok_or(GroupPersistenceError::CorruptData(
                "control already-applied revision",
            ))?,
        },
        REJECTED_DISPOSITION => GroupControlDisposition::Rejected(rejection_from_code(
            rejection
                .as_deref()
                .ok_or(GroupPersistenceError::CorruptData("control rejection"))?,
        )?),
        _ => return Err(GroupPersistenceError::CorruptData("control disposition")),
    };
    Ok(GroupControlReceipt {
        command_id,
        request_digest,
        binding_digest,
        disposition,
        administrator_count,
    })
}

fn disposition_columns(
    disposition: GroupControlDisposition,
) -> Result<(&'static str, Option<i64>, Option<&'static str>), GroupPersistenceError> {
    match disposition {
        GroupControlDisposition::Applied { policy_revision } => Ok((
            APPLIED_DISPOSITION,
            Some(revision_i64(policy_revision)?),
            None,
        )),
        GroupControlDisposition::AlreadyApplied { policy_revision } => Ok((
            ALREADY_APPLIED_DISPOSITION,
            Some(revision_i64(policy_revision)?),
            None,
        )),
        GroupControlDisposition::Rejected(rejection) => {
            Ok((REJECTED_DISPOSITION, None, Some(rejection_code(rejection))))
        }
    }
}

const fn rejection_code(rejection: GroupControlRejection) -> &'static str {
    match rejection {
        GroupControlRejection::PolicyDenied => POLICY_DENIED_REJECTION,
        GroupControlRejection::RevisionConflict => REVISION_CONFLICT_REJECTION,
        GroupControlRejection::AdminLimitReached => ADMIN_LIMIT_REACHED_REJECTION,
        GroupControlRejection::InvalidOperation => INVALID_OPERATION_REJECTION,
        GroupControlRejection::GroupExists => GROUP_EXISTS_REJECTION,
    }
}

fn rejection_from_code(value: &str) -> Result<GroupControlRejection, GroupPersistenceError> {
    match value {
        POLICY_DENIED_REJECTION => Ok(GroupControlRejection::PolicyDenied),
        REVISION_CONFLICT_REJECTION => Ok(GroupControlRejection::RevisionConflict),
        ADMIN_LIMIT_REACHED_REJECTION => Ok(GroupControlRejection::AdminLimitReached),
        INVALID_OPERATION_REJECTION => Ok(GroupControlRejection::InvalidOperation),
        GROUP_EXISTS_REJECTION => Ok(GroupControlRejection::GroupExists),
        _ => Err(GroupPersistenceError::CorruptData("control rejection")),
    }
}

fn revision_i64(value: Revision) -> Result<i64, GroupPersistenceError> {
    i64::try_from(value.get())
        .map_err(|_| GroupPersistenceError::CorruptData("control policy revision"))
}

fn digest(value: Vec<u8>, field: &'static str) -> Result<Sha256Digest, GroupPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| GroupPersistenceError::CorruptData(field))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn scope_kind(scope: GroupScope) -> &'static str {
    match scope {
        GroupScope::PrivateConversation(_) => "private_conversation",
        GroupScope::ControlledPublicChannel(_) => "controlled_public_channel",
    }
}

fn scope_id(scope: GroupScope) -> String {
    match scope {
        GroupScope::PrivateConversation(id) => id.to_string(),
        GroupScope::ControlledPublicChannel(id) => id.to_string(),
    }
}
