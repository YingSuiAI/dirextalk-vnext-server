use std::{error::Error, fmt};

use dtx_group_policy::{GroupPolicyError, GroupPolicySnapshotError};
use dtx_membership_command::MembershipCommandError;

/// Fail-closed errors at the durable group-membership boundary.
#[derive(Debug)]
pub enum GroupPersistenceError {
    /// `PostgreSQL` rejected or could not execute a storage operation.
    Database(sqlx::Error),
    /// The configured writer can bypass the isolated group-storage boundary.
    UnsafeRuntimeRole,
    /// The configured principal is not authorized to write the group schema.
    RuntimeRoleUnauthorized,
    /// The configured principal has privileges outside the group-writer boundary.
    RuntimeRoleOverprivileged,
    /// A pooled connection retained tenant-scoped state from another service.
    TenantContextLeak,
    /// The requested group scope does not yet have a durable aggregate.
    GroupNotFound,
    /// A duplicate bootstrap supplied a different initial durable policy image.
    GroupBootstrapConflict,
    /// A durable row could not rehydrate to a valid group-policy aggregate.
    GroupSnapshot(GroupPolicySnapshotError),
    /// A durable command/workflow row could not rehydrate to the pure reducer.
    MembershipCommand(MembershipCommandError),
    /// The policy reducer rejected the local authorization or reservation action.
    GroupPolicy(GroupPolicyError),
    /// A stored field was malformed, cross-linked, or exceeded the bounded contract.
    CorruptData(&'static str),
    /// The worker attempted to resolve an expired or superseded outbox lease.
    LeaseLost,
    /// A caller supplied a command whose scope does not match the loaded group.
    ScopeMismatch,
    /// A stable group-control command ID or idempotency key was reused with different facts.
    ControlCommandConflict,
    /// The caller's short-lived device session was missing, expired, revoked, or mismatched.
    DeviceAuthenticationRejected,
    /// A valid session did not have permission to read this durable receipt.
    MembershipReceiptAccessDenied,
    /// The caller's route-bound device action proof was malformed, expired, or invalid.
    ActionProofRejected,
    /// An MLS submission ID or idempotency key was reused with different canonical facts.
    MlsCommitConflict,
    /// The submitted MLS parent epoch/head is no longer current.
    StaleMlsHead,
    /// The membership approval or existing-identity controller consent is not valid.
    MlsAuthorizationRejected,
    /// The exact candidate device could not confirm the committed receipt/head.
    MlsDeviceConfirmationRejected,
}

impl fmt::Display for GroupPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Database(_) => "group persistence database operation failed",
            Self::UnsafeRuntimeRole => {
                "group runtime database role violates the ownership boundary"
            }
            Self::RuntimeRoleUnauthorized => "group runtime database role is not authorized",
            Self::RuntimeRoleOverprivileged => {
                "group runtime database role exceeds the group-only boundary"
            }
            Self::TenantContextLeak => "group transaction retained tenant context",
            Self::GroupNotFound => "group policy aggregate was not found",
            Self::GroupBootstrapConflict => "group policy bootstrap conflicts with durable state",
            Self::GroupSnapshot(_) => "group persistence contained an invalid policy image",
            Self::MembershipCommand(_) => {
                "group persistence contained an invalid membership command image"
            }
            Self::GroupPolicy(_) => "group policy rejected the requested membership action",
            Self::CorruptData(_) => "group persistence contained invalid durable data",
            Self::LeaseLost => "membership Sequencer action lease was lost",
            Self::ScopeMismatch => "membership command scope does not match the group",
            Self::ControlCommandConflict => {
                "group control command conflicts with a durable receipt"
            }
            Self::DeviceAuthenticationRejected => "device session authentication was rejected",
            Self::MembershipReceiptAccessDenied => "membership receipt access was denied",
            Self::ActionProofRejected => "group device action proof was rejected",
            Self::MlsCommitConflict => "MLS commit submission conflicts with a durable receipt",
            Self::StaleMlsHead => "MLS commit parent epoch or head is stale",
            Self::MlsAuthorizationRejected => "MLS device admission authorization was rejected",
            Self::MlsDeviceConfirmationRejected => "MLS device join confirmation was rejected",
        })
    }
}

impl Error for GroupPersistenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(source) => Some(source),
            Self::GroupSnapshot(source) => Some(source),
            Self::MembershipCommand(source) => Some(source),
            Self::GroupPolicy(source) => Some(source),
            Self::UnsafeRuntimeRole
            | Self::RuntimeRoleUnauthorized
            | Self::RuntimeRoleOverprivileged
            | Self::TenantContextLeak
            | Self::GroupNotFound
            | Self::GroupBootstrapConflict
            | Self::CorruptData(_)
            | Self::LeaseLost
            | Self::ScopeMismatch
            | Self::ControlCommandConflict
            | Self::DeviceAuthenticationRejected
            | Self::MembershipReceiptAccessDenied
            | Self::ActionProofRejected
            | Self::MlsCommitConflict
            | Self::StaleMlsHead
            | Self::MlsAuthorizationRejected
            | Self::MlsDeviceConfirmationRejected => None,
        }
    }
}

impl From<sqlx::Error> for GroupPersistenceError {
    fn from(source: sqlx::Error) -> Self {
        Self::Database(source)
    }
}

impl From<GroupPolicySnapshotError> for GroupPersistenceError {
    fn from(source: GroupPolicySnapshotError) -> Self {
        Self::GroupSnapshot(source)
    }
}

impl From<MembershipCommandError> for GroupPersistenceError {
    fn from(source: MembershipCommandError) -> Self {
        Self::MembershipCommand(source)
    }
}

impl From<GroupPolicyError> for GroupPersistenceError {
    fn from(source: GroupPolicyError) -> Self {
        Self::GroupPolicy(source)
    }
}
