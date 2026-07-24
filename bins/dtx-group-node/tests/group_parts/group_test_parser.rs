#[tokio::test]
async fn v5_parser_rejects_add_remove_nullability_matrix_without_rows() -> Result<(), Box<dyn Error>>
{
    let harness = support::PostgresHarness::start().await?;
    let identity_store = IdentityPgStore::connect(harness.identity_runtime_options(), 4).await?;
    let group_store = GroupPgStore::connect(harness.group_runtime_options(), 4).await?;
    let owner = enroll_active_device(&identity_store, 144, 145, 146, [147; 32]).await?;
    let target = synthetic_same_identity_device(&owner, 148);
    let tenant_id = TenantId::new();
    let app = group_router_with_state(
        GroupNodeState::with_clock(group_store, tenant_id, Arc::new(FixedClock(NOW)))
            .with_mls_sequencer_signing_key(SigningKey::from_bytes(&[149; 32]))
            .with_public_origin_and_allowed_http_identity_origins(
                AUDIENCE,
                std::iter::empty::<String>(),
            )?,
    );
    let scope = GroupScope::PrivateConversation(ConversationId::new());
    let scope_path = scope_path(scope);
    let nonzero = Sha256Digest::from_bytes([0x55; 32]);

    for (index, (recovery_add, field, replacement)) in [
        (true, 8_u64, CanonicalValue::Null),
        (true, 14_u64, CanonicalValue::Null),
        (false, 8_u64, nonzero.to_canonical_value()),
        (false, 14_u64, nonzero.to_canonical_value()),
    ]
    .into_iter()
    .enumerate()
    {
        let submission_id = RequestId::new();
        let path = format!("{scope_path}/mls-commits/{submission_id}");
        let idempotency_key = format!("v5-parser-nullability-{index:04}");
        let valid_body = if recovery_add {
            mls_recovery_add_body_v5(
                &owner,
                &target,
                scope,
                submission_id,
                &idempotency_key,
                0,
                Sha256Digest::from_bytes([0; 32]),
                vec![0xd1; 48],
                Sha256Digest::from_bytes([0x44; 32]),
                DeviceEnrollmentChallengeId::new(),
                Sha256Digest::from_bytes([0x45; 32]),
            )?
        } else {
            mls_device_remove_body_v5(
                &owner,
                &target,
                scope,
                submission_id,
                &idempotency_key,
                0,
                Sha256Digest::from_bytes([0; 32]),
                vec![0xd2; 48],
                Sha256Digest::from_bytes([0x46; 32]),
            )?
        };
        let response = send_mutation(
            app.clone(),
            "POST",
            &path,
            MLS_COMMIT_V5_CONTENT_TYPE,
            &idempotency_key,
            &owner,
            replace_numbered_map_field(&valid_body, field, replacement)?,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_safe_group_error(response, "GROUP_REQUEST_INVALID").await?;
        assert_eq!(v5_intent_count(harness.admin_pool(), tenant_id).await?, 0);
    }
    Ok(())
}
