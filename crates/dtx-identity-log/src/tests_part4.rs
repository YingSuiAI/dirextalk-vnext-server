#[test]
#[allow(clippy::too_many_lines)]
fn root_recovery_rotation_and_restore_fence_old_authorities() {
    let root = signing_key(1);
    let recovery = signing_key(2);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let mut log = IdentityLogV1::bootstrap(&genesis).unwrap();

    let first_device = signing_key(3);
    let first_certificate = device_certificate(
        &root,
        identity_id,
        &first_device,
        device_id(DEVICE_A),
        31,
        1_050,
    );
    let add = signed_event(
        &root,
        identity_id,
        2,
        Some(log.head_hash()),
        1_100,
        IdentityLogEventPayloadV1::DeviceAdd {
            certificate: first_certificate,
        },
    );
    log.append(&add).unwrap();

    let device_key_as_root = signed_event(
        &root,
        identity_id,
        3,
        Some(log.head_hash()),
        1_150,
        IdentityLogEventPayloadV1::RootRotate {
            new_root_signing_key: public_key(&first_device),
            acceptance_signature: signature(
                &first_device,
                &key_rotation_acceptance_input(
                    identity_id,
                    safe(3),
                    Some(log.head_hash()),
                    KeyAcceptancePurposeV1::RootRotate,
                    public_key(&first_device),
                )
                .unwrap(),
            ),
        },
    );
    assert_eq!(
        log.append(&device_key_as_root),
        Err(IdentityLogError::InvalidRotation)
    );

    let next_root = signing_key(4);
    let wrong_purpose_rotation = signed_event(
        &root,
        identity_id,
        3,
        Some(log.head_hash()),
        1_175,
        IdentityLogEventPayloadV1::RootRotate {
            new_root_signing_key: public_key(&next_root),
            acceptance_signature: signature(
                &next_root,
                &key_rotation_acceptance_input(
                    identity_id,
                    safe(3),
                    Some(log.head_hash()),
                    KeyAcceptancePurposeV1::RecoveryRestoreRoot,
                    public_key(&next_root),
                )
                .unwrap(),
            ),
        },
    );
    assert_eq!(
        log.append(&wrong_purpose_rotation),
        Err(IdentityLogError::InvalidRotation)
    );

    let root_rotation = signed_event(
        &root,
        identity_id,
        3,
        Some(log.head_hash()),
        1_200,
        IdentityLogEventPayloadV1::RootRotate {
            new_root_signing_key: public_key(&next_root),
            acceptance_signature: signature(
                &next_root,
                &key_rotation_acceptance_input(
                    identity_id,
                    safe(3),
                    Some(log.head_hash()),
                    KeyAcceptancePurposeV1::RootRotate,
                    public_key(&next_root),
                )
                .unwrap(),
            ),
        },
    );
    log.append(&root_rotation).unwrap();
    assert_eq!(log.current_root_key(), public_key(&next_root));

    let old_root_update = signed_event(
        &root,
        identity_id,
        4,
        Some(log.head_hash()),
        1_250,
        IdentityLogEventPayloadV1::RelayDescriptor {
            descriptor: descriptor(2_500),
        },
    );
    assert_eq!(
        log.append(&old_root_update),
        Err(IdentityLogError::UnauthorizedSigner)
    );

    let next_recovery = signing_key(5);
    let recovery_successor_acceptance_signature = signature(
        &next_recovery,
        &key_rotation_acceptance_input(
            identity_id,
            safe(4),
            Some(log.head_hash()),
            KeyAcceptancePurposeV1::RecoveryRotate,
            public_key(&next_recovery),
        )
        .unwrap(),
    );
    let old_root_recovery_rotation = signed_event(
        &root,
        identity_id,
        4,
        Some(log.head_hash()),
        1_300,
        IdentityLogEventPayloadV1::RecoveryRotate {
            new_recovery_signing_key: public_key(&next_recovery),
            acceptance_signature: recovery_successor_acceptance_signature,
            recovery_authorization_signature: Some(signature(
                &recovery,
                &recovery_rotation_authorization_input(
                    IDENTITY_LOG_WIRE_VERSION,
                    identity_id,
                    safe(4),
                    Some(log.head_hash()),
                    timestamp(1_300),
                    public_key(&root),
                    public_key(&next_recovery),
                    recovery_successor_acceptance_signature,
                )
                .unwrap(),
            )),
        },
    );
    assert_eq!(
        log.append(&old_root_recovery_rotation),
        Err(IdentityLogError::UnauthorizedSigner)
    );
    assert_eq!(log.current_recovery_key(), public_key(&recovery));

    let recovery_rotation = signed_event(
        &next_root,
        identity_id,
        4,
        Some(log.head_hash()),
        1_300,
        IdentityLogEventPayloadV1::RecoveryRotate {
            new_recovery_signing_key: public_key(&next_recovery),
            acceptance_signature: recovery_successor_acceptance_signature,
            recovery_authorization_signature: Some(signature(
                &recovery,
                &recovery_rotation_authorization_input(
                    IDENTITY_LOG_WIRE_VERSION,
                    identity_id,
                    safe(4),
                    Some(log.head_hash()),
                    timestamp(1_300),
                    public_key(&next_root),
                    public_key(&next_recovery),
                    recovery_successor_acceptance_signature,
                )
                .unwrap(),
            )),
        },
    );
    log.append(&recovery_rotation).unwrap();
    assert_eq!(log.current_recovery_key(), public_key(&next_recovery));

    let restored_root = signing_key(6);
    let restored_recovery = signing_key(7);
    let recovery_restore = signed_event(
        &next_recovery,
        identity_id,
        5,
        Some(log.head_hash()),
        1_400,
        IdentityLogEventPayloadV1::RecoveryRestore {
            new_root_signing_key: public_key(&restored_root),
            new_recovery_signing_key: public_key(&restored_recovery),
            root_acceptance_signature: signature(
                &restored_root,
                &key_rotation_acceptance_input(
                    identity_id,
                    safe(5),
                    Some(log.head_hash()),
                    KeyAcceptancePurposeV1::RecoveryRestoreRoot,
                    public_key(&restored_root),
                )
                .unwrap(),
            ),
            recovery_acceptance_signature: signature(
                &restored_recovery,
                &key_rotation_acceptance_input(
                    identity_id,
                    safe(5),
                    Some(log.head_hash()),
                    KeyAcceptancePurposeV1::RecoveryRestoreRecovery,
                    public_key(&restored_recovery),
                )
                .unwrap(),
            ),
        },
    );
    log.append(&recovery_restore).unwrap();
    assert_eq!(log.current_root_key(), public_key(&restored_root));
    assert_eq!(log.current_recovery_key(), public_key(&restored_recovery));
    assert_eq!(
        log.device_status(device_id(DEVICE_A)),
        Some(DeviceStatusV1::Revoked)
    );

    let new_device = signing_key(8);
    let new_certificate = device_certificate(
        &restored_root,
        identity_id,
        &new_device,
        device_id(DEVICE_C),
        81,
        1_450,
    );
    let revoked_device_attempt = signed_event(
        &first_device,
        identity_id,
        6,
        Some(log.head_hash()),
        1_500,
        IdentityLogEventPayloadV1::DeviceAdd {
            certificate: new_certificate.clone(),
        },
    );
    assert_eq!(
        log.append(&revoked_device_attempt),
        Err(IdentityLogError::UnauthorizedSigner)
    );

    let root_device_add = signed_event(
        &restored_root,
        identity_id,
        6,
        Some(log.head_hash()),
        1_500,
        IdentityLogEventPayloadV1::DeviceAdd {
            certificate: new_certificate,
        },
    );
    log.append(&root_device_add).unwrap();
    assert_eq!(
        log.device_status(device_id(DEVICE_C)),
        Some(DeviceStatusV1::Active)
    );
}

#[test]
fn identity_log_page_binds_a_contiguous_exact_chain_to_its_advertised_head() {
    let root = signing_key(1);
    let recovery = signing_key(2);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let relay = signed_event(
        &root,
        identity_id,
        2,
        Some(genesis.entry_hash().expect("genesis hash")),
        1_100,
        IdentityLogEventPayloadV1::RelayDescriptor {
            descriptor: descriptor(2_000),
        },
    );
    let genesis_bytes = genesis
        .to_deterministic_cbor()
        .expect("exact genesis bytes");
    let relay_bytes = relay.to_deterministic_cbor().expect("exact relay bytes");
    let head_hash = relay.entry_hash().expect("relay hash");

    let page = IdentityLogPageV1::new(
        identity_id,
        safe(2),
        head_hash,
        0,
        vec![genesis_bytes, relay_bytes],
        2,
        false,
    )
    .expect("contiguous page");
    let exact = page.to_deterministic_cbor().expect("canonical page bytes");

    assert_eq!(IdentityLogPageV1::decode_and_verify(&exact), Ok(page));
}

#[test]
fn identity_log_page_rejects_a_terminal_head_that_does_not_match_the_exact_events() {
    let root = signing_key(1);
    let recovery = signing_key(2);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let relay = signed_event(
        &root,
        identity_id,
        2,
        Some(genesis.entry_hash().expect("genesis hash")),
        1_100,
        IdentityLogEventPayloadV1::RelayDescriptor {
            descriptor: descriptor(2_000),
        },
    );

    assert_eq!(
        IdentityLogPageV1::new(
            identity_id,
            safe(2),
            Sha256Digest::from_bytes([0x55; 32]),
            0,
            vec![
                genesis
                    .to_deterministic_cbor()
                    .expect("exact genesis bytes"),
                relay.to_deterministic_cbor().expect("exact relay bytes"),
            ],
            2,
            false,
        ),
        Err(IdentityLogPageError::AdvertisedHeadMismatch)
    );
}
