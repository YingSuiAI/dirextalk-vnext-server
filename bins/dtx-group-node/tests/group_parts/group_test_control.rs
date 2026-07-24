#[tokio::test]
#[allow(clippy::too_many_lines)] // The coupled concurrent-create and five-admin invariants are clearest as one persistence scenario.
async fn group_control_persists_a_hard_five_admin_limit_under_serialized_writes()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    for privilege in ["SELECT", "INSERT"] {
        let granted: bool = sqlx::query_scalar(
            "SELECT has_table_privilege(current_user, 'groups.control_commands', $1)",
        )
        .bind(privilege)
        .fetch_one(harness.group_runtime_pool())
        .await?;
        assert!(
            granted,
            "group runtime is missing {privilege} on control receipts"
        );
    }
    let tenant_id = TenantId::new();
    let repository = GroupControlRepository;
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let first_owner = identity_from_seed(31)?;
    let competing_owner = identity_from_seed(32)?;
    let (first_create, competing_create) = tokio::join!(
        repository.execute(
            &store,
            tenant_id,
            control_command(
                first_owner,
                DeviceId::new(),
                GroupControlOperation::CreateGroup {
                    scope,
                    owner_identity_id: first_owner,
                },
                b"create-first-owner",
            ),
            NOW,
        ),
        repository.execute(
            &store,
            tenant_id,
            control_command(
                competing_owner,
                DeviceId::new(),
                GroupControlOperation::CreateGroup {
                    scope,
                    owner_identity_id: competing_owner,
                },
                b"create-competing-owner",
            ),
            NOW,
        )
    );
    let first_create = first_create?;
    let competing_create = competing_create?;
    let owner = match (first_create.disposition(), competing_create.disposition()) {
        (
            GroupControlDisposition::Applied { .. },
            GroupControlDisposition::Rejected(GroupControlRejection::GroupExists),
        ) => first_owner,
        (
            GroupControlDisposition::Rejected(GroupControlRejection::GroupExists),
            GroupControlDisposition::Applied { .. },
        ) => competing_owner,
        (left, right) => panic!(
            "competing group creation must yield one owner and one stable rejection: {left:?}, {right:?}"
        ),
    };

    for (index, administrator_identity_id) in (0_u8..5).map(identity_from_seed).enumerate() {
        let administrator_identity_id = administrator_identity_id?;
        let command_seed = u8::try_from(index)?;
        let receipt = repository
            .execute(
                &store,
                tenant_id,
                control_command(
                    owner,
                    DeviceId::new(),
                    GroupControlOperation::GrantAdmin {
                        scope,
                        expected_revision: Revision::new(u64::try_from(index + 1)?)?,
                        administrator_identity_id,
                    },
                    &[command_seed],
                ),
                NOW,
            )
            .await?;
        assert!(matches!(
            receipt.disposition(),
            GroupControlDisposition::Applied { .. }
        ));
    }

    let sixth = identity_from_seed(41)?;
    let seventh = identity_from_seed(42)?;
    let expected_revision = Revision::new(6)?;
    let (left, right) = tokio::join!(
        repository.execute(
            &store,
            tenant_id,
            control_command(
                owner,
                DeviceId::new(),
                GroupControlOperation::GrantAdmin {
                    scope,
                    expected_revision,
                    administrator_identity_id: sixth,
                },
                b"sixth",
            ),
            NOW,
        ),
        repository.execute(
            &store,
            tenant_id,
            control_command(
                owner,
                DeviceId::new(),
                GroupControlOperation::GrantAdmin {
                    scope,
                    expected_revision,
                    administrator_identity_id: seventh,
                },
                b"seventh",
            ),
            NOW,
        )
    );
    for receipt in [left?, right?] {
        assert_eq!(
            receipt.disposition(),
            GroupControlDisposition::Rejected(GroupControlRejection::AdminLimitReached)
        );
    }
    assert_eq!(
        GroupMembershipRepository
            .load_policy(&store, tenant_id, scope)
            .await?
            .admin_count(),
        5
    );
    Ok(())
}
