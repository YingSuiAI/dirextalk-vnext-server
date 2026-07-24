fn render_current_v1_1_vector() -> String {
    let events = current_v1_1_chain();
    let identity_id = events[0].1.identity_id().to_string();
    let events = events
        .into_iter()
        .map(|(event, value)| {
            json!({
                "event": event,
                "canonical_cbor_hex": encode_hex(&value.to_deterministic_cbor().unwrap()),
                "entry_hash": value.entry_hash().unwrap().to_string(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string_pretty(&json!({
        "version": 1,
        "wire_version": "1.1",
        "identity_id": identity_id,
        "events": events,
    }))
    .unwrap()
        + "\n"
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

fn encode_hex(value: &[u8]) -> String {
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn vector() -> IdentityLogVector {
    serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/identity-log/v1/identity-log-v1.json"
    ))
    .unwrap()
}

fn current_v1_1_vector() -> IdentityLogV1_1Vector {
    serde_json::from_str(include_str!(
        "../../../protocol/test-vectors/identity-log/v1_1/identity-log-v1_1.json"
    ))
    .unwrap()
}

#[test]
fn canonical_genesis_vector_is_exact_and_independently_verifiable() {
    let vector = vector();
    assert_eq!(vector.version, 1);
    let root = signing_key(1);
    let recovery = signing_key(2);
    let expected = genesis_with_wire(IDENTITY_LOG_V1_0_WIRE_VERSION, &root, &recovery);
    assert_eq!(expected.identity_id().to_string(), vector.identity_id);
    assert_eq!(
        encode_hex(&expected.to_deterministic_cbor().unwrap()),
        vector.canonical_cbor_hex
    );
    assert_eq!(
        expected.entry_hash().unwrap().to_string(),
        vector.entry_hash
    );

    let bytes = decode_hex(&vector.canonical_cbor_hex);
    let decoded = IdentityLogEventV1::decode_and_verify(&bytes).unwrap();
    assert_eq!(decoded, expected);
    assert_eq!(decoded.to_deterministic_cbor().unwrap(), bytes);
}

#[test]
fn canonical_v1_1_vector_is_full_replayable_contract() {
    let vector = current_v1_1_vector();
    let expected = current_v1_1_chain();
    let expected_event_names = [
        "genesis",
        "device_add",
        "relay_descriptor",
        "root_rotate",
        "recovery_rotate",
        "device_revoke",
        "recovery_restore",
    ];

    assert_eq!(vector.version, 1);
    assert_eq!(vector.wire_version, "1.1");
    assert_eq!(
        vector
            .events
            .iter()
            .map(|event| event.event.as_str())
            .collect::<Vec<_>>(),
        expected_event_names
    );
    assert_eq!(expected.len(), expected_event_names.len());
    assert_eq!(vector.identity_id, expected[0].1.identity_id().to_string());
    assert_eq!(
        render_current_v1_1_vector(),
        include_str!("../../../protocol/test-vectors/identity-log/v1_1/identity-log-v1_1.json")
    );

    let decoded = vector
        .events
        .iter()
        .zip(expected.iter())
        .map(|(fixture, (expected_name, expected_event))| {
            assert_eq!(fixture.event, *expected_name);
            let bytes = decode_hex(&fixture.canonical_cbor_hex);
            let decoded = IdentityLogEventV1::decode_and_verify(&bytes).unwrap();
            assert_eq!(&decoded, expected_event);
            assert_eq!(decoded.to_deterministic_cbor().unwrap(), bytes);
            assert_eq!(
                decoded.entry_hash().unwrap().to_string(),
                fixture.entry_hash
            );
            decoded
        })
        .collect::<Vec<_>>();

    let mut log = IdentityLogV1::bootstrap(&decoded[0]).unwrap();
    assert_eq!(log.wire(), IDENTITY_LOG_WIRE_VERSION);
    for event in decoded.iter().skip(1) {
        log.append(event).unwrap();
    }
    assert_eq!(log.head_sequence(), safe(7));
    assert_eq!(
        log.device_status(device_id(DEVICE_A)),
        Some(DeviceStatusV1::Revoked)
    );
    assert!(log.active_relay_descriptor(timestamp(1_999)).is_some());
    assert!(log.active_relay_descriptor(timestamp(2_000)).is_none());
}

#[test]
fn root_and_active_device_can_enroll_then_root_can_revoke_devices() {
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
    let first_add = signed_event(
        &root,
        identity_id,
        2,
        Some(log.head_hash()),
        1_100,
        IdentityLogEventPayloadV1::DeviceAdd {
            certificate: first_certificate,
        },
    );
    log.append(&first_add).unwrap();
    assert_eq!(
        log.device_status(device_id(DEVICE_A)),
        Some(DeviceStatusV1::Active)
    );

    let second_device = signing_key(4);
    let second_certificate = device_certificate(
        &root,
        identity_id,
        &second_device,
        device_id(DEVICE_B),
        41,
        1_150,
    );
    let second_add = signed_event(
        &first_device,
        identity_id,
        3,
        Some(log.head_hash()),
        1_200,
        IdentityLogEventPayloadV1::DeviceAdd {
            certificate: second_certificate,
        },
    );
    log.append(&second_add).unwrap();

    let relay_update = signed_event(
        &root,
        identity_id,
        4,
        Some(log.head_hash()),
        1_300,
        IdentityLogEventPayloadV1::RelayDescriptor {
            descriptor: descriptor(2_000),
        },
    );
    log.append(&relay_update).unwrap();
    assert_eq!(
        log.latest_relay_descriptor().unwrap().relay_urls(),
        ["https://relay-a.example/v1", "https://relay-b.example/v1"]
    );

    let revoke = signed_event(
        &root,
        identity_id,
        5,
        Some(log.head_hash()),
        1_400,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: device_id(DEVICE_A),
        },
    );
    log.append(&revoke).unwrap();
    assert_eq!(
        log.device_status(device_id(DEVICE_A)),
        Some(DeviceStatusV1::Revoked)
    );
    assert_eq!(
        log.device_status(device_id(DEVICE_B)),
        Some(DeviceStatusV1::Active)
    );
}
