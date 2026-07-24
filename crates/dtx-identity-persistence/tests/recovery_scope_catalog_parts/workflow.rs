#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one PostgreSQL workflow proves the coupled V41 fences"
)]
async fn postgres_catalog_preparation_and_provider_workflow_is_fenced_and_replay_safe()
-> Result<(), Box<dyn Error>> {
    let harness = support::PostgresHarness::start().await?;
    let store = IdentityPgStore::connect(harness.identity_runtime_options(), 8).await?;
    let identity_repository = IdentityLogRepository::new();
    let catalog_repository = RecoveryScopeCatalogRepository;
    let enrollment_repository = DeviceEnrollmentRepository;

    let root = key(1);
    let recovery = key(2);
    let authority = key(3);
    let provider = key(4);
    let candidate = key(5);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let head1 = committed(
        identity_repository
            .append(&store, &append_command(1, None, &genesis)?, at(1_001))
            .await?,
    )?;
    let authority_device = DeviceId::from_str(AUTHORITY_DEVICE)?;
    let authority_add = device_add(
        &root,
        identity_id,
        authority_device,
        &authority,
        33,
        2,
        head1.hash(),
        1_010,
    );
    let head2 = committed(
        identity_repository
            .append(
                &store,
                &append_command(2, Some(head1), &authority_add)?,
                at(1_011),
            )
            .await?,
    )?;
    let provider_device = DeviceId::from_str(PROVIDER_DEVICE)?;
    let provider_add = device_add(
        &root,
        identity_id,
        provider_device,
        &provider,
        44,
        3,
        head2.hash(),
        1_020,
    );
    let head3 = committed(
        identity_repository
            .append(
                &store,
                &append_command(3, Some(head2), &provider_add)?,
                at(1_021),
            )
            .await?,
    )?;

    let authority_credential = session(
        &store,
        identity_id,
        authority_device,
        &authority,
        11,
        at(2_000),
    )
    .await?;
    let provider_credential = session(
        &store,
        identity_id,
        provider_device,
        &provider,
        12,
        at(2_000),
    )
    .await?;

    let catalog = catalog_command(
        identity_id,
        head3,
        &authority,
        Sha256Digest::from_bytes([21; 32]),
        safe(1),
        None,
        [31; 32],
    )?;
    let (first, second) = tokio::time::timeout(
        Duration::from_secs(5),
        async {
            tokio::join!(
                catalog_repository.publish(&store, &catalog, &authority_credential, at(3_000)),
                catalog_repository.publish(&store, &catalog, &authority_credential, at(3_000)),
            )
        },
    )
    .await
    .map_err(|_| "concurrent first catalog publish deadlocked")?;
    let first = first?;
    let second = second?;
    assert_ne!(first.created, second.created);
    assert_eq!(first.exact_head_bytes, second.exact_head_bytes);
    assert_eq!(catalog_rows(&harness, identity_id).await?, 1);

    // V1 preparation/provider shapes are rejected explicitly; no disabled
    // legacy branch is allowed to stand in for the frozen V2 contract.
    let v1_preparation = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(
            2,
            CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-0123456789b1".to_owned()),
        ),
    ]))?;
    assert!(CatalogPreparationCommand::parse_v2(
        Sha256Digest::from_bytes([38; 32]),
        v1_preparation,
        DeviceEnrollmentCapability::new([35; 32])?,
        &RecoveryResponseCapability::new([37; 32])?,
    )
    .is_err());
    let v1_provider = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        field(1, CanonicalValue::Unsigned(1)),
        field(
            2,
            CanonicalValue::Text("0190f2a5-7b1c-7abc-8def-0123456789b1".to_owned()),
        ),
    ]))?;
    assert!(CatalogProviderResponseCommand::parse_v2(
        Sha256Digest::from_bytes([39; 32]),
        "0190f2a5-7b1c-7abc-8def-0123456789b1".parse()?,
        v1_provider,
    )
    .is_err());

    let changed_same_key = catalog_command(
        identity_id,
        head3,
        &authority,
        catalog.idempotency_key_hash,
        safe(1),
        None,
        [32; 32],
    )?;
    assert!(matches!(
        catalog_repository
            .publish(&store, &changed_same_key, &authority_credential, at(3_001))
            .await,
        Err(IdentityPersistenceError::IdempotencyConflict)
    ));
    let gap = catalog_command(
        identity_id,
        head3,
        &authority,
        Sha256Digest::from_bytes([22; 32]),
        safe(3),
        Some(catalog.head_digest),
        [33; 32],
    )?;
    assert!(matches!(
        catalog_repository
            .publish(&store, &gap, &authority_credential, at(3_001))
            .await,
        Err(IdentityPersistenceError::RecoveryCatalogConflict)
    ));
    assert_eq!(catalog_rows(&harness, identity_id).await?, 1);

    let candidate_device = DeviceId::from_str(CANDIDATE_DEVICE)?;
    let enrollment_capability_bytes = [41; 32];
    let challenge = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([42; 32]),
                identity_id,
                candidate_device,
                public(&candidate),
                DeviceEncryptionPublicKey::try_from([55; 32])?,
                DeviceEnrollmentCapability::new(enrollment_capability_bytes)?,
            )?,
            at(4_000),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(challenge) = challenge else {
        return Err("new ordinary enrollment challenge must be created".into());
    };

    let response_capability_bytes = [61; 32];
    let response_capability = RecoveryResponseCapability::new(response_capability_bytes)?;
    let prep_key = Sha256Digest::from_bytes([62; 32]);
    let exact_preparation_bytes = preparation_bytes(
        challenge.challenge_id(),
        identity_id,
        candidate_device,
        &candidate,
        [55; 32],
        head3,
        response_capability_bytes,
        &catalog,
        prep_key,
    )?;
    let prepare_a = CatalogPreparationCommand::parse_v2(
        prep_key,
        exact_preparation_bytes.clone(),
        DeviceEnrollmentCapability::new(enrollment_capability_bytes)?,
        &response_capability,
    )?;
    let prepare_b = CatalogPreparationCommand::parse_v2(
        prep_key,
        exact_preparation_bytes,
        DeviceEnrollmentCapability::new(enrollment_capability_bytes)?,
        &response_capability,
    )?;
    let (prepare_first, prepare_second) = tokio::join!(
        catalog_repository.prepare(&store, &prepare_a, at(5_000)),
        catalog_repository.prepare(&store, &prepare_b, at(5_000)),
    );
    assert_ne!(prepare_first?.0, prepare_second?.0);
    assert_eq!(preparation_rows(&harness, identity_id).await?, 1);
    assert_eq!(
        catalog_repository
            .status(
                &store,
                challenge.challenge_id(),
                &response_capability,
                at(5_001)
            )
            .await?
            .status,
        CatalogStatus::Pending,
    );

    // Status and an idempotent prepare replay contend on the same durable
    // identity/challenge/preparation lock chain.  They must complete without
    // deadlock, and only the original prepare remains the CAS winner.
    let (prepare_replay, concurrent_status) = tokio::time::timeout(
        Duration::from_secs(5),
        async {
            tokio::join!(
                catalog_repository.prepare(&store, &prepare_a, at(5_002)),
                catalog_repository.status(
                    &store,
                    challenge.challenge_id(),
                    &response_capability,
                    at(5_002),
                ),
            )
        },
    )
    .await
    .map_err(|_| "concurrent prepare/status deadlocked")?;
    assert!(!prepare_replay?.0);
    assert_eq!(concurrent_status?.status, CatalogStatus::Pending);

    let wrong_capability = RecoveryResponseCapability::new([62; 32])?;
    assert!(matches!(
        catalog_repository
            .status(
                &store,
                challenge.challenge_id(),
                &wrong_capability,
                at(5_001)
            )
            .await,
        Err(IdentityPersistenceError::RecoveryResponseCapabilityRejected)
    ));

    let invalid_provider = provider_command(
        challenge.challenge_id(),
        catalog.head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [55; 32],
        Sha256Digest::from_bytes([70; 32]),
        identity_id,
        catalog.catalog_id,
        catalog.generation,
        prepare_a.digest,
        head3,
        IdentityLogHead::observed(identity_id, safe(4), Sha256Digest::from_bytes([99; 32]))?,
        candidate_device,
        &candidate,
        &device_add(&root, identity_id, candidate_device, &candidate, 55, 4, head3.hash(), 7_101).to_deterministic_cbor()?,
    )?;
    assert!(matches!(
        catalog_repository
            .put_provider_response(&store, &invalid_provider, &provider_credential, at(5_100))
            .await,
        Err(IdentityPersistenceError::RecoveryPreparationRevoked)
            | Err(IdentityPersistenceError::RecoveryPreparationInvalidated)
    ));
    assert_eq!(provider_response_rows(&harness, identity_id).await?, 0);

    let approval_credential = session(
        &store,
        identity_id,
        provider_device,
        &provider,
        13,
        at(7_100),
    )
    .await?;

    let candidate_add = device_add(
        &root,
        identity_id,
        candidate_device,
        &candidate,
        55,
        4,
        head3.hash(),
        7_101,
    );
    let approval = DeviceEnrollmentApprovalCommand::new(
        Sha256Digest::from_bytes([71; 32]),
        challenge.challenge_id(),
        DeviceEnrollmentCapability::new(enrollment_capability_bytes)?,
        head3.hash(),
        candidate_add.to_deterministic_cbor()?,
    )?;
    let head4 = committed(
        enrollment_repository
            .approve(&store, approval, approval_credential, at(7_102))
            .await?,
    )?;
    assert_eq!(head4.sequence().get(), head3.sequence().get() + 1);
    assert_eq!(
        catalog_repository
            .status(
                &store,
                challenge.challenge_id(),
                &response_capability,
                at(7_103)
            )
            .await?
            .status,
        CatalogStatus::Pending,
    );
    let replay_after_h1 = catalog_repository
        .publish(&store, &catalog, &authority_credential, at(7_104))
        .await?;
    assert!(!replay_after_h1.created);

    let provider_response = provider_command(
        challenge.challenge_id(),
        catalog.head_digest,
        provider_device,
        &provider,
        Sha256Digest::hash_domain(
            CURRENT_HISTORY_AUTHORITY_HASH_DOMAIN,
            public(&authority).as_bytes(),
        ),
        [55; 32],
        Sha256Digest::from_bytes([72; 32]),
        identity_id,
        catalog.catalog_id,
        catalog.generation,
        prepare_a.digest,
        head3,
        head4,
        candidate_device,
        &candidate,
        &candidate_add.to_deterministic_cbor()?,
    )?;
    let (ready, replay) = tokio::join!(
        catalog_repository.put_provider_response(
            &store,
            &provider_response,
            &provider_credential,
            at(7_200),
        ),
        catalog_repository.put_provider_response(
            &store,
            &provider_response,
            &provider_credential,
            at(7_200),
        ),
    );
    let ready = ready?;
    let replay = replay?;
    assert_eq!(ready.status, CatalogStatus::ResponseAvailable);
    assert_eq!(
        ready.provider_response.as_deref(),
        Some(provider_response.exact_bytes.as_slice())
    );
    assert_eq!(replay.provider_response, ready.provider_response);
    assert_eq!(provider_response_rows(&harness, identity_id).await?, 1);

    let rotated = catalog_command(
        identity_id,
        head4,
        &authority,
        Sha256Digest::from_bytes([73; 32]),
        safe(2),
        Some(catalog.head_digest),
        [34; 32],
    )?;
    catalog_repository
        .publish(&store, &rotated, &authority_credential, at(7_300))
        .await?;
    let invalidated = catalog_repository
        .status(
            &store,
            challenge.challenge_id(),
            &response_capability,
            at(7_301),
        )
        .await?;
    assert_eq!(
        invalidated.status,
        CatalogStatus::Invalidated(CatalogStatusInvalidation::Catalog)
    );
    assert_eq!(invalidated.observed_at, at(7_300));
    let invalidated_exact = invalidated.exact_bytes()?;
    assert!(invalidated.provider_response.is_none());

    // A preparation bound to generation N+1 sees a successor and an identity
    // event at the same timestamp below; enum numeric priority must choose
    // Identity (1) over Catalog (2).
    let candidate_two = key(6);
    let challenge_two = enrollment_repository
        .create_challenge(
            &store,
            CreateDeviceEnrollmentChallengeCommand::new(
                Sha256Digest::from_bytes([43; 32]),
                identity_id,
                DeviceId::from_str(SECOND_CANDIDATE_DEVICE)?,
                public(&candidate_two),
                DeviceEncryptionPublicKey::try_from([56; 32])?,
                DeviceEnrollmentCapability::new([44; 32])?,
            )?,
            at(7_301),
        )
        .await?;
    let DeviceEnrollmentChallengeOutcome::Created(challenge_two) = challenge_two else {
        return Err("second ordinary enrollment challenge must be created".into());
    };
    let response_capability_two = RecoveryResponseCapability::new([63; 32])?;
    let prep_two = CatalogPreparationCommand::parse_v2(
        Sha256Digest::from_bytes([64; 32]),
        preparation_bytes(
            challenge_two.challenge_id(),
            identity_id,
            DeviceId::from_str(SECOND_CANDIDATE_DEVICE)?,
            &candidate_two,
            [56; 32],
            head4,
            [63; 32],
            &rotated,
            Sha256Digest::from_bytes([64; 32]),
        )?,
        DeviceEnrollmentCapability::new([44; 32])?,
        &response_capability_two,
    )?;
    assert!(catalog_repository.prepare(&store, &prep_two, at(7_302)).await?.0);

    let rotated_again = catalog_command(
        identity_id,
        committed(
            identity_repository
                .append(
                    &store,
                    &append_command(
                        7,
                        Some(head4),
                        &relay_event(
                            &root,
                            identity_id,
                            5,
                            head4.hash(),
                            "equal-terminal-time",
                            7_400,
                        ),
                    )?,
                    at(7_400),
                )
                .await?,
        )?,
        &authority,
        Sha256Digest::from_bytes([74; 32]),
        safe(3),
        Some(rotated.head_digest),
        [35; 32],
    )?;
    catalog_repository
        .publish(&store, &rotated_again, &authority_credential, at(7_400))
        .await?;
    let invalidated_after_multiple_successors = catalog_repository
        .status(
            &store,
            challenge.challenge_id(),
            &response_capability,
            at(7_401),
        )
        .await?;
    assert_eq!(
        invalidated_after_multiple_successors.status,
        CatalogStatus::Invalidated(CatalogStatusInvalidation::Catalog)
    );
    assert_eq!(invalidated_after_multiple_successors.observed_at, at(7_300));
    let simultaneous = catalog_repository
        .status(
            &store,
            challenge_two.challenge_id(),
            &response_capability_two,
            at(7_401),
        )
        .await?;
    assert_eq!(
        simultaneous.status,
        CatalogStatus::Invalidated(CatalogStatusInvalidation::Identity)
    );
    assert_eq!(simultaneous.observed_at, at(7_400));

    // V2 rejects a provider descriptor that reuses the candidate identity or
    // signing key; the old disabled second-candidate block did not exercise
    // this invariant with a valid response shape.
    let candidate_provider = provider_command(
        challenge.challenge_id(),
        catalog.head_digest,
        candidate_device,
        &candidate,
        Sha256Digest::from_bytes([90; 32]),
        [55; 32],
        Sha256Digest::from_bytes([91; 32]),
        identity_id,
        catalog.catalog_id,
        catalog.generation,
        prepare_a.digest,
        head3,
        head4,
        candidate_device,
        &candidate,
        &candidate_add.to_deterministic_cbor()?,
    );
    assert!(candidate_provider.is_err());

    let expired = catalog_repository
        .status(
            &store,
            challenge.challenge_id(),
            &response_capability,
            at(200_000),
        )
        .await?;
    // The catalog successor invalidated this preparation before its own
    // expiry.  That earliest terminal event remains immutable after the
    // preparation expiry and must replay byte-identically.
    assert_eq!(
        expired.status,
        CatalogStatus::Invalidated(CatalogStatusInvalidation::Catalog)
    );
    assert_eq!(expired.observed_at, at(7_300));
    assert_eq!(expired.exact_bytes()?, invalidated_exact);
    assert!(expired.provider_response.is_none());

    let no_plaintext_columns: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(
             SELECT 1 FROM information_schema.columns
              WHERE table_schema='identity'
                AND table_name IN ('recovery_scope_catalogs','recovery_scope_catalog_preparations')
                AND column_name ~ '(scope|leaf|plaintext|receipt)'
                AND column_name <> 'leaf_count')",
    )
    .fetch_one(harness.admin_pool())
    .await?;
    assert!(no_plaintext_columns);
    Ok(())
}
