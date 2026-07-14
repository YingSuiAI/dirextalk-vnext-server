use std::str::FromStr;

use dtx_domain::{
    ChannelId, ConversationId, IdentityId, InviteCapabilityId, JoinRequestId, Revision,
};
use dtx_group_policy::{GroupPolicy, GroupPolicyError, GroupRole, GroupScope, MAX_ADMINS};

const OWNER: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

fn owner() -> IdentityId {
    IdentityId::from_str(OWNER).expect("fixture owner ID is canonical")
}

fn identity(slot: u8) -> IdentityId {
    let value = format!("dtxi1{}{}", char::from(b'a' + slot), "a".repeat(51));
    IdentityId::from_str(&value).expect("fixture identity ID is canonical")
}

fn channel(slot: u8) -> ChannelId {
    let value = format!("dtxc1{}{}", char::from(b'a' + slot), "a".repeat(51));
    ChannelId::from_str(&value).expect("fixture channel ID is canonical")
}

fn private_group(owner: IdentityId) -> GroupPolicy {
    GroupPolicy::new(
        GroupScope::PrivateConversation(ConversationId::new()),
        owner,
    )
}

#[test]
fn private_conversations_and_controlled_public_channels_have_distinct_typed_scopes() {
    let owner = owner();
    let private_scope = GroupScope::PrivateConversation(ConversationId::new());
    let public_scope = GroupScope::ControlledPublicChannel(channel(0));
    let private_group = GroupPolicy::new(private_scope, owner);
    let public_group = GroupPolicy::new(public_scope, owner);

    assert_eq!(private_group.scope(), private_scope);
    assert_eq!(public_group.scope(), public_scope);
    assert_ne!(private_group.scope(), public_group.scope());
}

#[test]
fn owner_is_member_and_has_invite_and_approval_authority_without_consuming_admin_slot() {
    let owner = owner();
    let group = private_group(owner);

    assert_eq!(group.role_of(owner), Some(GroupRole::Owner));
    assert!(group.is_member(owner));
    assert!(group.can_issue_invite(owner));
    assert!(group.can_approve_join(owner));
    assert_eq!(group.admin_count(), 0);
    assert_eq!(group.revision(), Revision::INITIAL);
}

#[test]
fn only_owner_can_manage_up_to_five_additional_admins() {
    let owner = owner();
    let mut group = private_group(owner);
    let admins = (0..MAX_ADMINS)
        .map(|slot| identity(u8::try_from(slot).expect("fixture slot fits u8")))
        .collect::<Vec<_>>();

    for admin in &admins {
        group
            .grant_admin(group.revision(), owner, *admin)
            .expect("owner adds an administrator");
    }
    assert_eq!(group.admin_count(), MAX_ADMINS);
    assert!(admins.iter().all(|admin| group.can_issue_invite(*admin)));

    let sixth = identity(9);
    let before = group.clone();
    assert_eq!(
        group.grant_admin(group.revision(), owner, sixth),
        Err(GroupPolicyError::AdminLimitReached)
    );
    assert_eq!(group, before);

    assert_eq!(
        group.grant_admin(group.revision(), admins[0], sixth),
        Err(GroupPolicyError::Unauthorized)
    );
    assert_eq!(
        group.revoke_admin(group.revision(), admins[0], admins[1]),
        Err(GroupPolicyError::Unauthorized)
    );
    assert_eq!(
        group.grant_admin(group.revision(), owner, owner),
        Err(GroupPolicyError::OwnerCannotBeAdmin)
    );

    group
        .revoke_admin(group.revision(), owner, admins[0])
        .expect("owner revokes administrator");
    assert!(!group.can_issue_invite(admins[0]));
    assert_eq!(group.admin_count(), MAX_ADMINS - 1);
}

#[test]
fn sixth_admin_race_has_one_success_then_a_revision_conflict_or_current_limit() {
    let owner = owner();
    let mut group = private_group(owner);
    let concurrent_revision = group.revision();

    group
        .grant_admin(concurrent_revision, owner, identity(1))
        .expect("first concurrent grant commits");
    assert_eq!(
        group.grant_admin(concurrent_revision, owner, identity(2)),
        Err(GroupPolicyError::RevisionConflict {
            current: group.revision(),
        })
    );

    for slot in 2..=MAX_ADMINS {
        group
            .grant_admin(
                group.revision(),
                owner,
                identity(u8::try_from(slot).expect("fixture slot fits u8")),
            )
            .expect("remaining slots may be filled at current revision");
    }
    assert_eq!(group.admin_count(), MAX_ADMINS);
    assert_eq!(
        group.grant_admin(group.revision(), owner, identity(8)),
        Err(GroupPolicyError::AdminLimitReached)
    );
}

#[test]
fn owner_and_admin_issue_and_revoke_group_bound_invites() {
    let owner = owner();
    let admin = identity(1);
    let target = identity(2);
    let mut group = private_group(owner);
    group
        .grant_admin(group.revision(), owner, admin)
        .expect("owner grants the admin role");

    let issue_revision = group.revision();
    let invite_id = InviteCapabilityId::new();
    let invite = group
        .issue_invite(
            issue_revision,
            owner,
            invite_id,
            Some(target),
            2,
            10_000,
            1_000,
        )
        .expect("owner issues targeted invite");
    assert_eq!(invite.invite_id(), invite_id);
    assert_eq!(invite.scope(), group.scope());
    assert_eq!(invite.issuer_id(), owner);
    assert_eq!(invite.target_id(), Some(target));
    assert_eq!(invite.max_uses(), 2);
    assert_eq!(invite.use_count(), 0);
    assert_eq!(invite.expires_at_ms(), 10_000);
    assert_eq!(invite.policy_revision(), issue_revision);
    assert!(!invite.is_revoked());

    group
        .revoke_invite(group.revision(), admin, invite_id)
        .expect("admin revokes invite");
    assert!(
        group
            .invite(invite_id)
            .expect("invite remains auditable")
            .is_revoked()
    );
    assert_eq!(
        group.revoke_invite(group.revision(), admin, invite_id),
        Err(GroupPolicyError::InviteAlreadyRevoked)
    );

    let before = group.clone();
    assert_eq!(
        group.issue_invite(
            group.revision(),
            target,
            InviteCapabilityId::new(),
            None,
            1,
            10_000,
            1_000,
        ),
        Err(GroupPolicyError::Unauthorized)
    );
    assert_eq!(group, before);
    assert_eq!(
        group.issue_invite(
            group.revision(),
            owner,
            InviteCapabilityId::new(),
            None,
            0,
            10_000,
            1_000,
        ),
        Err(GroupPolicyError::InvalidInviteUseLimit)
    );
    assert_eq!(group, before);
    assert_eq!(
        group.issue_invite(
            group.revision(),
            owner,
            InviteCapabilityId::new(),
            None,
            1,
            1_000,
            1_000,
        ),
        Err(GroupPolicyError::InvalidInviteExpiry)
    );
    assert_eq!(group, before);
}

#[test]
fn approval_at_current_revision_admits_the_pending_candidate_and_is_not_reapplied() {
    let owner = owner();
    let admin = identity(8);
    let candidate = identity(3);
    let mut group = private_group(owner);
    group
        .grant_admin(group.revision(), owner, admin)
        .expect("owner grants current administrator role");
    let invite_id = InviteCapabilityId::new();
    group
        .issue_invite(
            group.revision(),
            owner,
            invite_id,
            Some(candidate),
            1,
            10_000,
            1_000,
        )
        .expect("owner issues invite");

    let request_id = JoinRequestId::new();
    let pending = group
        .request_join(group.revision(), candidate, request_id, invite_id, 1_500)
        .expect("candidate creates pending join request");
    assert_eq!(pending.request_id(), request_id);
    assert_eq!(pending.candidate_id(), candidate);
    assert_eq!(pending.invite_id(), invite_id);

    let approval = group
        .approve_join(group.revision(), admin, request_id, 2_000)
        .expect("administrator approves current pending request");
    assert_eq!(approval.request_id(), request_id);
    assert_eq!(approval.candidate_id(), candidate);
    assert_eq!(approval.approved_by(), admin);
    assert!(group.is_member(candidate));
    assert_eq!(
        group.invite(invite_id).expect("invite exists").use_count(),
        1
    );

    let retry_revision = group.revision();
    assert_eq!(
        group.request_join(
            retry_revision,
            candidate,
            JoinRequestId::new(),
            invite_id,
            2_001,
        ),
        Err(GroupPolicyError::AlreadyMember)
    );
    assert_eq!(
        group.approve_join(retry_revision, owner, request_id, 2_001),
        Err(GroupPolicyError::AlreadyApproved)
    );
}

#[test]
fn revoked_admin_actions_conflict_when_stale_and_are_unauthorized_when_current() {
    let owner = owner();
    let admin = identity(4);
    let candidate = identity(5);
    let mut group = private_group(owner);
    group
        .grant_admin(group.revision(), owner, admin)
        .expect("owner grants admin role");
    let invite_id = InviteCapabilityId::new();
    group
        .issue_invite(
            group.revision(),
            admin,
            invite_id,
            Some(candidate),
            1,
            10_000,
            1_000,
        )
        .expect("admin issues invitation while authorized");
    let request_id = JoinRequestId::new();
    group
        .request_join(group.revision(), candidate, request_id, invite_id, 1_500)
        .expect("candidate creates pending request");

    let stale_revision = group.revision();
    group
        .revoke_admin(stale_revision, owner, admin)
        .expect("owner revokes admin role");
    let current_revision = group.revision();
    let before = group.clone();
    assert_eq!(
        group.approve_join(stale_revision, admin, request_id, 2_000),
        Err(GroupPolicyError::RevisionConflict {
            current: current_revision,
        })
    );
    assert_eq!(group, before);
    assert_eq!(
        group.approve_join(current_revision, admin, request_id, 2_000),
        Err(GroupPolicyError::Unauthorized)
    );
    assert_eq!(group, before);
    assert_eq!(
        group.approve_join(current_revision, owner, request_id, 2_000),
        Err(GroupPolicyError::InviteIssuerNoLongerAuthorized)
    );
    assert_eq!(group, before);
    assert!(!group.is_member(candidate));
}

#[test]
fn join_and_approval_recheck_target_and_expiry() {
    let owner = owner();
    let target = identity(6);
    let other = identity(7);
    let mut group = private_group(owner);

    let targeted_invite = InviteCapabilityId::new();
    group
        .issue_invite(
            group.revision(),
            owner,
            targeted_invite,
            Some(target),
            1,
            10_000,
            1_000,
        )
        .expect("owner issues targeted invitation");
    assert_eq!(
        group.request_join(
            group.revision(),
            other,
            JoinRequestId::new(),
            targeted_invite,
            1_500,
        ),
        Err(GroupPolicyError::InviteTargetMismatch)
    );

    let expiring_invite = InviteCapabilityId::new();
    group
        .issue_invite(
            group.revision(),
            owner,
            expiring_invite,
            Some(target),
            1,
            2_000,
            1_000,
        )
        .expect("owner issues invitation before expiry");
    let expiring_request = JoinRequestId::new();
    group
        .request_join(
            group.revision(),
            target,
            expiring_request,
            expiring_invite,
            1_500,
        )
        .expect("candidate requests before expiry");
    assert_eq!(
        group.approve_join(group.revision(), owner, expiring_request, 2_000),
        Err(GroupPolicyError::InviteExpired)
    );
}

#[test]
fn join_rechecks_invitation_revocation_and_use_count() {
    let owner = owner();
    let target = identity(6);
    let other = identity(7);
    let mut group = private_group(owner);
    let revoked_invite = InviteCapabilityId::new();
    group
        .issue_invite(
            group.revision(),
            owner,
            revoked_invite,
            Some(other),
            1,
            10_000,
            1_000,
        )
        .expect("owner issues invitation to revoke");
    group
        .revoke_invite(group.revision(), owner, revoked_invite)
        .expect("owner revokes invitation");
    assert_eq!(
        group.request_join(
            group.revision(),
            other,
            JoinRequestId::new(),
            revoked_invite,
            1_500,
        ),
        Err(GroupPolicyError::InviteRevoked)
    );

    let limited_invite = InviteCapabilityId::new();
    group
        .issue_invite(
            group.revision(),
            owner,
            limited_invite,
            None,
            1,
            10_000,
            1_000,
        )
        .expect("owner issues single-use invitation");
    let limited_request = JoinRequestId::new();
    group
        .request_join(
            group.revision(),
            target,
            limited_request,
            limited_invite,
            1_500,
        )
        .expect("target submits a pending request");
    group
        .approve_join(group.revision(), owner, limited_request, 1_600)
        .expect("owner consumes first and only use");
    assert_eq!(
        group.request_join(
            group.revision(),
            other,
            JoinRequestId::new(),
            limited_invite,
            1_700,
        ),
        Err(GroupPolicyError::InviteUseLimitReached)
    );
}
