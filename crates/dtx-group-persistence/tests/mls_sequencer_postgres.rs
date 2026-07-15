#[path = "../../dtx-storage/tests/support/mod.rs"]
mod support;

use std::{error::Error, str::FromStr};

use dtx_domain::{
    ConversationId, DeviceId, IdentityId, InviteCapabilityId, JoinRequestId, RequestId, TenantId,
};
use dtx_group_persistence::{
    GroupMembershipRepository, GroupPersistenceError, GroupPgStore, MlsCommitAuthorization,
    MlsCommitCommand, MlsCommitSequencerRepository, MlsDeviceJoinConfirmation,
    mls_device_confirmation_signature_input, mls_opaque_commit_digest,
};
use dtx_group_policy::{GroupPolicy, GroupScope};
use dtx_membership_command::{
    ApproveJoinCommand, CandidateMembership, JoinRequestCommand, MembershipCommandContext,
    MembershipCommandId, MembershipFence,
};
use dtx_wire::{Ed25519Signature, Sha256Digest, SigningPublicKey};
use ed25519_dalek::{Signer, SigningKey};

const OWNER: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";
const CANDIDATE_IDENTITY_ORIGIN: &str = "https://candidate.example";

fn request(value: &str) -> RequestId {
    RequestId::from_str(value).unwrap()
}
fn device(value: &str) -> DeviceId {
    DeviceId::from_str(value).unwrap()
}
fn tenant() -> TenantId {
    TenantId::from_str("0190f2a5-7b1c-7abc-8def-0123456789a0").unwrap()
}
fn owner() -> IdentityId {
    IdentityId::from_str(OWNER).unwrap()
}
fn scope() -> GroupScope {
    GroupScope::PrivateConversation(
        ConversationId::from_str("0190f2a5-7b1c-7abc-8def-0123456789a1").unwrap(),
    )
}
fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}
fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42; 32])
}
fn public_key(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).unwrap()
}
fn sign(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}

#[allow(clippy::too_many_arguments)]
fn command(
    submission: &str,
    actor: IdentityId,
    actor_device: DeviceId,
    candidate_device: DeviceId,
    epoch: u64,
    head: Sha256Digest,
    commit_byte: u8,
    key_byte: u8,
    authorization: MlsCommitAuthorization,
) -> MlsCommitCommand {
    command_for_scope(
        scope(),
        submission,
        actor,
        actor_device,
        candidate_device,
        epoch,
        head,
        commit_byte,
        key_byte,
        authorization,
    )
}

#[allow(clippy::too_many_arguments)]
fn command_for_scope(
    target_scope: GroupScope,
    submission: &str,
    actor: IdentityId,
    actor_device: DeviceId,
    candidate_device: DeviceId,
    epoch: u64,
    head: Sha256Digest,
    commit_byte: u8,
    key_byte: u8,
    authorization: MlsCommitAuthorization,
) -> MlsCommitCommand {
    let commit = vec![commit_byte; 48];
    MlsCommitCommand::new(
        request(submission),
        target_scope,
        actor,
        actor_device,
        owner(),
        candidate_device,
        digest(key_byte),
        digest(key_byte.wrapping_add(1)),
        digest(key_byte.wrapping_add(2)),
        epoch,
        head,
        commit.clone(),
        mls_opaque_commit_digest(&commit),
        digest(commit_byte.wrapping_add(1)),
        authorization,
    )
    .unwrap()
}

async fn seeded_store() -> Result<(support::PostgresHarness, GroupPgStore), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = GroupPgStore::connect(harness.group_runtime_options(), 8).await?;
    GroupMembershipRepository
        .bootstrap(&store, tenant(), &GroupPolicy::new(scope(), owner()), 1_000)
        .await?;
    Ok((harness, store))
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn bootstrap_replay_confirmation_and_concurrent_device_add_are_fenced()
-> Result<(), Box<dyn Error>> {
    let (_harness, store) = seeded_store().await?;
    let repository = MlsCommitSequencerRepository;
    let signer = signing_key();
    let signer_public = public_key(&signer);
    let owner_device = device("0190f2a5-7b1c-7abc-8def-0123456789a2");
    let zero = digest(0);
    let bootstrap = command(
        "0190f2a5-7b1c-7abc-8def-0123456789a3",
        owner(),
        owner_device,
        owner_device,
        0,
        zero,
        0x11,
        0x21,
        MlsCommitAuthorization::OwnerBootstrap,
    );
    let execution = repository
        .submit(
            &store,
            tenant(),
            &bootstrap,
            2_000,
            signer_public,
            |_| Ok(()),
            |_| Ok(()),
            |input| Ok(sign(&signer, input)),
        )
        .await?;
    assert!(!execution.replayed());
    assert!(
        !repository
            .is_device_active(&store, tenant(), scope(), owner(), owner_device)
            .await?
    );

    let replay = repository
        .submit(
            &store,
            tenant(),
            &bootstrap,
            2_001,
            signer_public,
            |_| Ok(()),
            |_| Ok(()),
            |_| panic!("replay must not sign again"),
        )
        .await?;
    assert!(replay.replayed());
    assert_eq!(execution.receipt(), replay.receipt());
    assert_eq!(
        repository
            .receipt(
                &store,
                tenant(),
                scope(),
                bootstrap.submission_id(),
                signer_public
            )
            .await?,
        *execution.receipt()
    );
    let conflicting = command(
        "0190f2a5-7b1c-7abc-8def-0123456789a3",
        owner(),
        owner_device,
        owner_device,
        0,
        zero,
        0x12,
        0x21,
        MlsCommitAuthorization::OwnerBootstrap,
    );
    assert!(matches!(
        repository
            .submit(
                &store,
                tenant(),
                &conflicting,
                2_002,
                signer_public,
                |_| Ok(()),
                |_| Ok(()),
                |input| Ok(sign(&signer, input))
            )
            .await,
        Err(GroupPersistenceError::MlsCommitConflict)
    ));

    let unsigned = MlsDeviceJoinConfirmation {
        submission_id: bootstrap.submission_id(),
        identity_id: owner(),
        device_id: owner_device,
        receipt_digest: execution.receipt().receipt_digest(),
        head_digest: execution.receipt().head_digest(),
        signature: Ed25519Signature::from_bytes([0; 64]),
    };
    let invalid_confirmation = MlsDeviceJoinConfirmation {
        signature: Ed25519Signature::from_bytes([0x99; 64]),
        ..unsigned
    };
    assert!(matches!(
        repository
            .confirm(&store, tenant(), invalid_confirmation, 2_050, signer_public)
            .await,
        Err(GroupPersistenceError::MlsDeviceConfirmationRejected)
    ));
    assert!(
        !repository
            .is_device_active(&store, tenant(), scope(), owner(), owner_device)
            .await?
    );
    let confirmation = MlsDeviceJoinConfirmation {
        signature: sign(
            &signer,
            &mls_device_confirmation_signature_input(&unsigned)?,
        ),
        ..unsigned
    };
    let replayed_confirmation = repository
        .confirm(&store, tenant(), confirmation, 2_100, signer_public)
        .await?;
    assert!(!replayed_confirmation);
    assert!(
        repository
            .is_device_active(&store, tenant(), scope(), owner(), owner_device)
            .await?
    );

    let other_scope = GroupScope::PrivateConversation(ConversationId::from_str(
        "0190f2a5-7b1c-7abc-8def-0123456789b0",
    )?);
    GroupMembershipRepository
        .bootstrap(
            &store,
            tenant(),
            &GroupPolicy::new(other_scope, owner()),
            2_150,
        )
        .await?;
    let conflict_cases = [
        (
            "cross-scope submission reuse",
            command_for_scope(
                other_scope,
                "0190f2a5-7b1c-7abc-8def-0123456789a3",
                owner(),
                owner_device,
                owner_device,
                0,
                digest(0),
                0x91,
                0x81,
                MlsCommitAuthorization::OwnerBootstrap,
            ),
            false,
        ),
        (
            "same commit digest with changed key",
            command(
                "0190f2a5-7b1c-7abc-8def-0123456789b1",
                owner(),
                owner_device,
                device("0190f2a5-7b1c-7abc-8def-0123456789b2"),
                1,
                execution.receipt().head_digest(),
                0x11,
                0x82,
                MlsCommitAuthorization::ExistingMemberDeviceAdd {
                    controller_device_id: owner_device,
                    controller_consent_digest: digest(0x83),
                },
            ),
            false,
        ),
        (
            "same device second admission",
            command(
                "0190f2a5-7b1c-7abc-8def-0123456789b3",
                owner(),
                owner_device,
                owner_device,
                1,
                execution.receipt().head_digest(),
                0x92,
                0x84,
                MlsCommitAuthorization::ExistingMemberDeviceAdd {
                    controller_device_id: owner_device,
                    controller_consent_digest: digest(0x85),
                },
            ),
            true,
        ),
    ];
    for (name, conflicting_command, authorization_rejection) in conflict_cases {
        let error = repository
            .submit(
                &store,
                tenant(),
                &conflicting_command,
                2_160,
                signer_public,
                |_| Ok(()),
                |_| Ok(()),
                |input| Ok(sign(&signer, input)),
            )
            .await
            .expect_err(name);
        assert!(
            if authorization_rejection {
                matches!(error, GroupPersistenceError::MlsAuthorizationRejected)
            } else {
                matches!(error, GroupPersistenceError::MlsCommitConflict)
            },
            "{name}: unexpected error {error}"
        );
    }
    assert!(
        repository
            .confirm(&store, tenant(), confirmation, 2_101, signer_public)
            .await?
    );

    let second_bootstrap = command(
        "0190f2a5-7b1c-7abc-8def-0123456789a8",
        owner(),
        owner_device,
        owner_device,
        1,
        execution.receipt().head_digest(),
        0x22,
        0x23,
        MlsCommitAuthorization::OwnerBootstrap,
    );
    assert!(matches!(
        repository
            .submit(
                &store,
                tenant(),
                &second_bootstrap,
                2_200,
                signer_public,
                |_| Ok(()),
                |_| Ok(()),
                |input| Ok(sign(&signer, input))
            )
            .await,
        Err(GroupPersistenceError::MlsAuthorizationRejected)
    ));

    let second_device = device("0190f2a5-7b1c-7abc-8def-0123456789a4");
    let third_device = device("0190f2a5-7b1c-7abc-8def-0123456789a5");
    let parent = execution.receipt().head_digest();
    let add_two = command(
        "0190f2a5-7b1c-7abc-8def-0123456789a6",
        owner(),
        owner_device,
        second_device,
        1,
        parent,
        0x31,
        0x41,
        MlsCommitAuthorization::ExistingMemberDeviceAdd {
            controller_device_id: owner_device,
            controller_consent_digest: digest(0x51),
        },
    );
    let add_three = command(
        "0190f2a5-7b1c-7abc-8def-0123456789a7",
        owner(),
        owner_device,
        third_device,
        1,
        parent,
        0x32,
        0x42,
        MlsCommitAuthorization::ExistingMemberDeviceAdd {
            controller_device_id: owner_device,
            controller_consent_digest: digest(0x52),
        },
    );
    let first=repository.submit(&store,tenant(),&add_two,3_000,signer_public,|_|Ok(()),|command|{
        assert!(matches!(command.authorization(),MlsCommitAuthorization::ExistingMemberDeviceAdd{controller_device_id,..} if controller_device_id==owner_device));
        Ok(())
    },|input|Ok(sign(&signer,input)));
    let second = repository.submit(
        &store,
        tenant(),
        &add_three,
        3_000,
        signer_public,
        |_| Ok(()),
        |_| Ok(()),
        |input| Ok(sign(&signer, input)),
    );
    let (first, second) = tokio::join!(first, second);
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let ((Err(loser), Ok(_)) | (Ok(_), Err(loser))) = (first, second) else {
        panic!("exactly one concurrent commit must fail");
    };
    assert!(matches!(loser, GroupPersistenceError::StaleMlsHead));
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn bootstrap_and_proof_failures_leave_no_sequencer_facts() -> Result<(), Box<dyn Error>> {
    let (_harness, store) = seeded_store().await?;
    let repository = MlsCommitSequencerRepository;
    let signer = signing_key();
    let public = public_key(&signer);
    let owner_device = device("0190f2a5-7b1c-7abc-8def-0123456789a2");
    let bad_identity = IdentityId::from_str(&format!("dtxi1b{}", "a".repeat(51)))?;
    let non_owner = command(
        "0190f2a5-7b1c-7abc-8def-0123456789a8",
        bad_identity,
        owner_device,
        owner_device,
        0,
        digest(0),
        0x61,
        0x62,
        MlsCommitAuthorization::OwnerBootstrap,
    );
    assert!(matches!(
        repository
            .submit(
                &store,
                tenant(),
                &non_owner,
                2_000,
                public,
                |_| Ok(()),
                |_| Ok(()),
                |input| Ok(sign(&signer, input))
            )
            .await,
        Err(GroupPersistenceError::MlsAuthorizationRejected)
    ));
    let bad_proof = command(
        "0190f2a5-7b1c-7abc-8def-0123456789a9",
        owner(),
        owner_device,
        owner_device,
        0,
        digest(0),
        0x71,
        0x72,
        MlsCommitAuthorization::OwnerBootstrap,
    );
    assert!(matches!(
        repository
            .submit(
                &store,
                tenant(),
                &bad_proof,
                2_100,
                public,
                |_| Err(GroupPersistenceError::ActionProofRejected),
                |_| Ok(()),
                |input| Ok(sign(&signer, input))
            )
            .await,
        Err(GroupPersistenceError::ActionProofRejected)
    ));
    assert!(matches!(
        repository
            .receipt(&store, tenant(), scope(), bad_proof.submission_id(), public)
            .await,
        Err(GroupPersistenceError::GroupNotFound)
    ));
    let bad_signature = command(
        "0190f2a5-7b1c-7abc-8def-0123456789a7",
        owner(),
        owner_device,
        owner_device,
        0,
        digest(0),
        0x73,
        0x74,
        MlsCommitAuthorization::OwnerBootstrap,
    );
    assert!(
        repository
            .submit(
                &store,
                tenant(),
                &bad_signature,
                2_200,
                public,
                |_| Ok(()),
                |_| Ok(()),
                |_| Ok(Ed25519Signature::from_bytes([0; 64]))
            )
            .await
            .is_err()
    );
    assert!(matches!(
        repository
            .receipt(
                &store,
                tenant(),
                scope(),
                bad_signature.submission_id(),
                public
            )
            .await,
        Err(GroupPersistenceError::GroupNotFound)
    ));
    Ok(())
}

#[tokio::test]
async fn exact_device_fact_without_identity_membership_is_not_router_eligible()
-> Result<(), Box<dyn Error>> {
    let (harness, store) = seeded_store().await?;
    let outsider = IdentityId::from_str(&format!("dtxi1c{}", "a".repeat(51)))?;
    let outsider_device = device("0190f2a5-7b1c-7abc-8def-0123456789a6");
    let mut transaction = harness.admin_pool().begin().await?;
    support::PostgresHarness::set_tenant(&mut transaction, tenant().into()).await?;
    sqlx::query(
        "INSERT INTO groups.mls_device_members
          (tenant_id,scope_kind,scope_id,identity_id,device_id,admitted_epoch,commit_digest,state,updated_at_ms)
         VALUES ($1,'private_conversation',$2,$3,$4,1,$5,'active',2000)",
    ).bind(uuid::Uuid::from(tenant())).bind("0190f2a5-7b1c-7abc-8def-0123456789a1")
      .bind(outsider.to_string()).bind(uuid::Uuid::from(outsider_device)).bind(digest(0x91).as_bytes().as_slice())
      .execute(&mut *transaction).await?;
    transaction.commit().await?;
    assert!(
        !MlsCommitSequencerRepository
            .is_device_active(&store, tenant(), scope(), outsider, outsider_device)
            .await?
    );
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn confirmed_approved_device_waits_for_gm1_identity_finalize() -> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = GroupPgStore::connect(harness.group_runtime_options(), 8).await?;
    let candidate = IdentityId::from_str(&format!("dtxi1d{}", "a".repeat(51)))?;
    let candidate_device = device("0190f2a5-7b1c-7abc-8def-0123456789a4");
    let owner_device = device("0190f2a5-7b1c-7abc-8def-0123456789a2");
    let invite = InviteCapabilityId::from_str("0190f2a5-7b1c-7abc-8def-0123456789a5")?;
    let mut policy = GroupPolicy::new(scope(), owner());
    policy.issue_invite(
        policy.revision(),
        owner(),
        invite,
        Some(candidate),
        1,
        100_000,
        1_000,
    )?;
    let request_revision = policy.revision();
    GroupMembershipRepository
        .bootstrap(&store, tenant(), &policy, 1_000)
        .await?;
    let signer = signing_key();
    let public = public_key(&signer);
    let bootstrap = command(
        "0190f2a5-7b1c-7abc-8def-0123456789a3",
        owner(),
        owner_device,
        owner_device,
        0,
        digest(0),
        0x11,
        0x21,
        MlsCommitAuthorization::OwnerBootstrap,
    );
    let bootstrap_receipt = MlsCommitSequencerRepository
        .submit(
            &store,
            tenant(),
            &bootstrap,
            1_100,
            public,
            |_| Ok(()),
            |_| Ok(()),
            |input| Ok(sign(&signer, input)),
        )
        .await?;
    let unsigned = MlsDeviceJoinConfirmation {
        submission_id: bootstrap.submission_id(),
        identity_id: owner(),
        device_id: owner_device,
        receipt_digest: bootstrap_receipt.receipt().receipt_digest(),
        head_digest: bootstrap_receipt.receipt().head_digest(),
        signature: Ed25519Signature::from_bytes([0; 64]),
    };
    let bootstrap_confirmation = MlsDeviceJoinConfirmation {
        signature: sign(
            &signer,
            &mls_device_confirmation_signature_input(&unsigned)?,
        ),
        ..unsigned
    };
    MlsCommitSequencerRepository
        .confirm(&store, tenant(), bootstrap_confirmation, 1_200, public)
        .await?;

    let join_id = JoinRequestId::from_str("0190f2a5-7b1c-7abc-8def-0123456789a6")?;
    let candidate_key_package_digest = digest(0x61);
    let request_context = MembershipCommandContext::new_v2(
        MembershipCommandId::new(request("0190f2a5-7b1c-7abc-8def-0123456789a7")),
        digest(0x31),
        scope(),
        candidate,
        candidate_device,
        join_id,
        candidate,
        candidate_device,
        invite,
        MembershipFence::new(request_revision, bootstrap_receipt.receipt().head_digest()),
        candidate_key_package_digest,
    );
    let join_request_digest = JoinRequestCommand::new(request_context).request_digest();
    GroupMembershipRepository
        .request_join(
            &store,
            tenant(),
            JoinRequestCommand::new(request_context),
            CandidateMembership::NotMember,
            CANDIDATE_IDENTITY_ORIGIN,
            2_000,
        )
        .await?;
    let approval_revision = GroupMembershipRepository
        .load_policy(&store, tenant(), scope())
        .await?
        .revision();
    let approval_id = MembershipCommandId::new(request("0190f2a5-7b1c-7abc-8def-0123456789a8"));
    let authorization_digest = digest(0x44);
    let approval_context = MembershipCommandContext::new_v2(
        approval_id,
        digest(0x32),
        scope(),
        owner(),
        owner_device,
        join_id,
        candidate,
        candidate_device,
        invite,
        MembershipFence::new(approval_revision, bootstrap_receipt.receipt().head_digest()),
        candidate_key_package_digest,
    );
    let approval_request_digest =
        ApproveJoinCommand::new(approval_context, authorization_digest).request_digest();
    GroupMembershipRepository
        .approve_join(
            &store,
            tenant(),
            ApproveJoinCommand::new(approval_context, authorization_digest),
            CandidateMembership::NotMember,
            2_100,
        )
        .await?;
    let commit = vec![0x55; 48];
    let approved = MlsCommitCommand::new_v3_approved_identity_join(
        request("0190f2a5-7b1c-7abc-8def-0123456789a9"),
        scope(),
        owner(),
        owner_device,
        candidate,
        candidate_device,
        candidate_key_package_digest,
        digest(0x63),
        1,
        bootstrap_receipt.receipt().head_digest(),
        commit.clone(),
        mls_opaque_commit_digest(&commit),
        digest(0x64),
        approval_id,
        authorization_digest,
        join_request_digest,
        approval_request_digest,
    )?;
    let accepted = MlsCommitSequencerRepository
        .submit(
            &store,
            tenant(),
            &approved,
            2_200,
            public,
            |_| Ok(()),
            |_| Ok(()),
            |input| Ok(sign(&signer, input)),
        )
        .await?;
    assert_eq!(accepted.receipt().protocol_version(), 3);
    assert_eq!(
        accepted.receipt().candidate_key_package_digest(),
        candidate_key_package_digest
    );
    assert_eq!(
        accepted.receipt().join_request_digest(),
        Some(join_request_digest)
    );
    assert_eq!(
        accepted.receipt().approval_request_digest(),
        Some(approval_request_digest)
    );
    let second_commit = vec![0x56; 48];
    let duplicate_approval = MlsCommitCommand::new_v3_approved_identity_join(
        request("0190f2a5-7b1c-7abc-8def-0123456789b4"),
        scope(),
        owner(),
        owner_device,
        candidate,
        candidate_device,
        candidate_key_package_digest,
        digest(0x73),
        2,
        accepted.receipt().head_digest(),
        second_commit.clone(),
        mls_opaque_commit_digest(&second_commit),
        digest(0x74),
        approval_id,
        authorization_digest,
        join_request_digest,
        approval_request_digest,
    )?;
    assert!(matches!(
        MlsCommitSequencerRepository
            .submit(
                &store,
                tenant(),
                &duplicate_approval,
                2_250,
                public,
                |_| Ok(()),
                |_| Ok(()),
                |input| Ok(sign(&signer, input)),
            )
            .await,
        Err(GroupPersistenceError::MlsAuthorizationRejected)
    ));
    let unsigned = MlsDeviceJoinConfirmation {
        submission_id: approved.submission_id(),
        identity_id: candidate,
        device_id: candidate_device,
        receipt_digest: accepted.receipt().receipt_digest(),
        head_digest: accepted.receipt().head_digest(),
        signature: Ed25519Signature::from_bytes([0; 64]),
    };
    let confirmation = MlsDeviceJoinConfirmation {
        signature: sign(
            &signer,
            &mls_device_confirmation_signature_input(&unsigned)?,
        ),
        ..unsigned
    };
    MlsCommitSequencerRepository
        .confirm(&store, tenant(), confirmation, 2_300, public)
        .await?;
    assert!(
        !MlsCommitSequencerRepository
            .is_device_active(&store, tenant(), scope(), candidate, candidate_device)
            .await?,
        "pending GM1 identity workflow must block Router eligibility"
    );
    Ok(())
}
