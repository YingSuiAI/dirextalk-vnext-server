use dtx_membership_command::{MembershipCommandId, SequencerAction};

/// Opaque lease fencing one prepared Sequencer action to its durable outbox row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SequencerActionLease {
    pub(crate) token: uuid::Uuid,
}

/// One durable action that may be invoked only after its originating transaction commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedSequencerAction {
    /// Lease that must be supplied when resolving the remote result.
    pub lease: SequencerActionLease,
    /// Stable membership command being sent or queried.
    pub command_id: MembershipCommandId,
    /// Exact remote action. A `Query` never invents a new command identity.
    pub action: SequencerAction,
}
