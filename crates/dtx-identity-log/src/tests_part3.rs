#[test]
fn replay_fork_and_tampering_fail_without_advancing_state() {
    let root = signing_key(1);
    let recovery = signing_key(2);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let mut log = IdentityLogV1::bootstrap(&genesis).unwrap();

    let update = signed_event(
        &root,
        identity_id,
        2,
        Some(log.head_hash()),
        1_100,
        IdentityLogEventPayloadV1::RelayDescriptor {
            descriptor: descriptor(2_000),
        },
    );
    log.append(&update).unwrap();
    let head_before = (log.head_sequence(), log.head_hash());

    let skipped_sequence = signed_event(
        &root,
        identity_id,
        4,
        Some(log.head_hash()),
        1_200,
        IdentityLogEventPayloadV1::RelayDescriptor {
            descriptor: descriptor(2_100),
        },
    );
    let fork = signed_event(
        &root,
        identity_id,
        3,
        Some(Sha256Digest::from_bytes([9; 32])),
        1_200,
        IdentityLogEventPayloadV1::RelayDescriptor {
            descriptor: descriptor(2_100),
        },
    );
    for (candidate, expected_error) in [
        (update.clone(), IdentityLogError::Replay),
        (skipped_sequence, IdentityLogError::SequenceMismatch),
        (fork, IdentityLogError::PreviousHashMismatch),
    ] {
        assert_eq!(log.append(&candidate), Err(expected_error));
        assert_eq!((log.head_sequence(), log.head_hash()), head_before);
    }

    let signed_bytes = update.to_deterministic_cbor().unwrap();
    let mut tampered = signed_bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let mut trailing = signed_bytes;
    trailing.push(0);
    for (bytes, expected_error) in [
        (tampered, IdentityLogError::InvalidSignature),
        (trailing, IdentityLogError::InvalidCanonical),
    ] {
        assert_eq!(
            IdentityLogEventV1::decode_and_verify(&bytes),
            Err(expected_error)
        );
    }
}

#[test]
fn recovery_rotation_rejects_a_root_only_authorization() {
    let root = signing_key(1);
    let recovery = signing_key(2);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let mut log = IdentityLogV1::bootstrap(&genesis).unwrap();
    let successor = signing_key(3);
    let root_only_rotation = UnsignedIdentityLogEventV1::new(
        IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        safe(2),
        Some(log.head_hash()),
        timestamp(1_100),
        IdentityLogEventPayloadV1::RecoveryRotate {
            new_recovery_signing_key: public_key(&successor),
            acceptance_signature: signature(
                &successor,
                &key_rotation_acceptance_input(
                    identity_id,
                    safe(2),
                    Some(log.head_hash()),
                    KeyAcceptancePurposeV1::RecoveryRotate,
                    public_key(&successor),
                )
                .unwrap(),
            ),
            recovery_authorization_signature: None,
        },
        public_key(&root),
    );

    assert_eq!(root_only_rotation, Err(IdentityLogError::InvalidRotation));

    let successor_acceptance_signature = signature(
        &successor,
        &key_rotation_acceptance_input(
            identity_id,
            safe(2),
            Some(log.head_hash()),
            KeyAcceptancePurposeV1::RecoveryRotate,
            public_key(&successor),
        )
        .unwrap(),
    );
    let forged_recovery_authorization = signed_event(
        &root,
        identity_id,
        2,
        Some(log.head_hash()),
        1_100,
        IdentityLogEventPayloadV1::RecoveryRotate {
            new_recovery_signing_key: public_key(&successor),
            acceptance_signature: successor_acceptance_signature,
            recovery_authorization_signature: Some(signature(
                &root,
                &recovery_rotation_authorization_input(
                    IDENTITY_LOG_WIRE_VERSION,
                    identity_id,
                    safe(2),
                    Some(log.head_hash()),
                    timestamp(1_100),
                    public_key(&root),
                    public_key(&successor),
                    successor_acceptance_signature,
                )
                .unwrap(),
            )),
        },
    );
    assert_eq!(
        log.append(&forged_recovery_authorization),
        Err(IdentityLogError::InvalidRotation)
    );
    assert_eq!(log.current_recovery_key(), public_key(&recovery));
}

#[test]
fn current_write_entry_rejects_v1_0_root_only_recovery_chain() {
    let (legacy_genesis, current_genesis, rotation) = frozen_v1_0_root_only_recovery_chain();

    rotation.verify().unwrap();
    assert!(matches!(
        IdentityLogV1::bootstrap(&legacy_genesis),
        Err(IdentityLogError::InvalidWireVersion)
    ));

    let mut current_log = IdentityLogV1::bootstrap(&current_genesis).unwrap();
    assert_eq!(
        current_log.append(&rotation),
        Err(IdentityLogError::InvalidWireVersion)
    );
}

#[test]
fn historical_v1_0_chain_is_verified_without_current_append_access() {
    let (legacy_genesis, _, rotation) = frozen_v1_0_root_only_recovery_chain();
    let expected_recovery = match rotation.payload() {
        IdentityLogEventPayloadV1::RecoveryRotate {
            new_recovery_signing_key,
            ..
        } => *new_recovery_signing_key,
        _ => unreachable!("fixture contains a recovery rotation"),
    };
    let historical = HistoricalIdentityLogV1::import_v1_0(&[legacy_genesis, rotation]).unwrap();

    assert_eq!(historical.wire(), IDENTITY_LOG_V1_0_WIRE_VERSION);
    assert_eq!(historical.head_sequence(), safe(2));
    assert_eq!(historical.current_recovery_key(), expected_recovery);
}

#[test]
fn relay_history_replays_but_active_lookup_uses_trusted_now() {
    let root = signing_key(1);
    let recovery = signing_key(2);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let mut log = IdentityLogV1::bootstrap(&genesis).unwrap();

    let backdated_descriptor = signed_event(
        &root,
        identity_id,
        2,
        Some(log.head_hash()),
        1_050,
        IdentityLogEventPayloadV1::RelayDescriptor {
            descriptor: descriptor(1_100),
        },
    );
    log.append(&backdated_descriptor).unwrap();
    assert!(log.latest_relay_descriptor().is_some());
    assert!(log.active_relay_descriptor(timestamp(1_099)).is_some());
    assert!(log.active_relay_descriptor(timestamp(1_100)).is_none());
    assert!(log.active_relay_descriptor(timestamp(1_500)).is_none());

    let already_expired_at_event_time = UnsignedIdentityLogEventV1::new(
        IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        safe(3),
        Some(log.head_hash()),
        timestamp(1_200),
        IdentityLogEventPayloadV1::RelayDescriptor {
            descriptor: descriptor(1_100),
        },
        public_key(&root),
    );
    assert_eq!(
        already_expired_at_event_time,
        Err(IdentityLogError::InvalidRelayDescriptor)
    );
}

#[test]
fn current_wire_rejects_legacy_embedded_contracts() {
    let root = signing_key(1);
    let recovery = signing_key(2);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let legacy_device = signing_key(3);
    let legacy_certificate_unsigned = UnsignedDeviceCertificateV1::new(
        IDENTITY_LOG_V1_0_WIRE_VERSION,
        identity_id,
        device_id(DEVICE_A),
        public_key(&legacy_device),
        DeviceEncryptionPublicKey::try_from([31; 32]).unwrap(),
        public_key(&root),
        timestamp(1_050),
    )
    .unwrap();
    let legacy_certificate = DeviceCertificateV1::signed(
        legacy_certificate_unsigned.clone(),
        signature(
            &root,
            &device_certificate_signature_input(
                legacy_certificate_unsigned.signing_digest().unwrap(),
            ),
        ),
    )
    .unwrap();

    let device_add = UnsignedIdentityLogEventV1::new(
        IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        safe(2),
        Some(genesis.entry_hash().unwrap()),
        timestamp(1_100),
        IdentityLogEventPayloadV1::DeviceAdd {
            certificate: legacy_certificate,
        },
        public_key(&root),
    );
    assert_eq!(device_add, Err(IdentityLogError::InvalidWireVersion));

    let relay_update = UnsignedIdentityLogEventV1::new(
        IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        safe(2),
        Some(genesis.entry_hash().unwrap()),
        timestamp(1_100),
        IdentityLogEventPayloadV1::RelayDescriptor {
            descriptor: RelayDescriptorV1::new(
                IDENTITY_LOG_V1_0_WIRE_VERSION,
                vec!["https://relay-a.example/v1".to_owned()],
                timestamp(2_000),
            )
            .unwrap(),
        },
        public_key(&root),
    );
    assert_eq!(relay_update, Err(IdentityLogError::InvalidWireVersion));
}
