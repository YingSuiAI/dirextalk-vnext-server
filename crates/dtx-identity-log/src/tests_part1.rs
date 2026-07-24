use std::{fmt::Write as _, str::FromStr};

use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use serde_json::json;

use super::*;

const DEVICE_A: &str = "0190f2a5-7b1c-7abc-8def-0123456789ab";
const DEVICE_B: &str = "0190f2a5-7b1c-7abc-8def-0123456789ac";
const DEVICE_C: &str = "0190f2a5-7b1c-7abc-8def-0123456789ad";

#[derive(Deserialize)]
struct IdentityLogVector {
    version: u16,
    identity_id: String,
    canonical_cbor_hex: String,
    entry_hash: String,
}

#[derive(Deserialize)]
struct IdentityLogV1_1Vector {
    version: u16,
    wire_version: String,
    identity_id: String,
    events: Vec<IdentityLogVectorEvent>,
}

#[derive(Deserialize)]
struct IdentityLogVectorEvent {
    event: String,
    canonical_cbor_hex: String,
    entry_hash: String,
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_key(key: &SigningKey) -> SigningPublicKey {
    SigningPublicKey::try_from(key.verifying_key().to_bytes()).unwrap()
}

fn signature(key: &SigningKey, input: &[u8]) -> Ed25519Signature {
    Ed25519Signature::from_bytes(key.sign(input).to_bytes())
}

fn safe(value: u64) -> SafeUint {
    SafeUint::new(value).unwrap()
}

fn timestamp(value: i64) -> UtcMillis {
    UtcMillis::new(value).unwrap()
}

fn device_id(value: &str) -> DeviceId {
    DeviceId::from_str(value).unwrap()
}

fn signed_event(
    signer: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous_event_hash: Option<Sha256Digest>,
    occurred_at: i64,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    signed_event_with_wire(
        IDENTITY_LOG_WIRE_VERSION,
        signer,
        identity_id,
        sequence,
        previous_event_hash,
        occurred_at,
        payload,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_event_with_wire(
    wire: WireVersion,
    signer: &SigningKey,
    identity_id: IdentityId,
    sequence: u64,
    previous_event_hash: Option<Sha256Digest>,
    occurred_at: i64,
    payload: IdentityLogEventPayloadV1,
) -> IdentityLogEventV1 {
    let unsigned = UnsignedIdentityLogEventV1::new(
        wire,
        identity_id,
        safe(sequence),
        previous_event_hash,
        timestamp(occurred_at),
        payload,
        public_key(signer),
    )
    .unwrap();
    IdentityLogEventV1::signed(
        unsigned.clone(),
        signature(
            signer,
            &identity_log_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap()
}

fn genesis(root: &SigningKey, recovery: &SigningKey) -> IdentityLogEventV1 {
    genesis_with_wire(IDENTITY_LOG_WIRE_VERSION, root, recovery)
}

fn genesis_with_wire(
    wire: WireVersion,
    root: &SigningKey,
    recovery: &SigningKey,
) -> IdentityLogEventV1 {
    let root_key = public_key(root);
    let recovery_key = public_key(recovery);
    let identity_id = IdentityId::derive(root_key.as_domain_key());
    let recovery_acceptance_signature = signature(
        recovery,
        &genesis_recovery_acceptance_input(identity_id, root_key, recovery_key).unwrap(),
    );
    signed_event_with_wire(
        wire,
        root,
        identity_id,
        1,
        None,
        1_000,
        IdentityLogEventPayloadV1::Genesis {
            root_signing_key: root_key,
            recovery_signing_key: recovery_key,
            recovery_acceptance_signature,
        },
    )
}

fn device_certificate(
    root: &SigningKey,
    identity_id: IdentityId,
    device: &SigningKey,
    device_id: DeviceId,
    encryption_seed: u8,
    issued_at: i64,
) -> DeviceCertificateV1 {
    let unsigned = UnsignedDeviceCertificateV1::new(
        IDENTITY_LOG_WIRE_VERSION,
        identity_id,
        device_id,
        public_key(device),
        DeviceEncryptionPublicKey::try_from([encryption_seed; 32]).unwrap(),
        public_key(root),
        timestamp(issued_at),
    )
    .unwrap();
    DeviceCertificateV1::signed(
        unsigned.clone(),
        signature(
            root,
            &device_certificate_signature_input(unsigned.signing_digest().unwrap()),
        ),
    )
    .unwrap()
}

fn descriptor(expires_at: i64) -> RelayDescriptorV1 {
    RelayDescriptorV1::new(
        IDENTITY_LOG_WIRE_VERSION,
        vec![
            "https://relay-a.example/v1".to_owned(),
            "https://relay-b.example/v1".to_owned(),
        ],
        timestamp(expires_at),
    )
    .unwrap()
}

fn frozen_v1_0_root_only_recovery_chain()
-> (IdentityLogEventV1, IdentityLogEventV1, IdentityLogEventV1) {
    let root = signing_key(1);
    let recovery = signing_key(2);
    let legacy_genesis = genesis_with_wire(IDENTITY_LOG_V1_0_WIRE_VERSION, &root, &recovery);
    let identity_id = legacy_genesis.identity_id();
    let legacy_head = legacy_genesis.entry_hash().unwrap();
    let successor = signing_key(3);
    let rotation = signed_event_with_wire(
        IDENTITY_LOG_V1_0_WIRE_VERSION,
        &root,
        identity_id,
        2,
        Some(legacy_head),
        1_100,
        IdentityLogEventPayloadV1::RecoveryRotate {
            new_recovery_signing_key: public_key(&successor),
            acceptance_signature: signature(
                &successor,
                &key_rotation_acceptance_input(
                    identity_id,
                    safe(2),
                    Some(legacy_head),
                    KeyAcceptancePurposeV1::RecoveryRotate,
                    public_key(&successor),
                )
                .unwrap(),
            ),
            recovery_authorization_signature: None,
        },
    );
    (legacy_genesis, genesis(&root, &recovery), rotation)
}

#[allow(clippy::too_many_lines)]
fn current_v1_1_chain() -> Vec<(&'static str, IdentityLogEventV1)> {
    let root = signing_key(1);
    let recovery = signing_key(2);
    let genesis = genesis(&root, &recovery);
    let identity_id = genesis.identity_id();
    let mut log = IdentityLogV1::bootstrap(&genesis).unwrap();
    let mut events = vec![("genesis", genesis)];

    let first_device = signing_key(3);
    let first_certificate = device_certificate(
        &root,
        identity_id,
        &first_device,
        device_id(DEVICE_A),
        31,
        1_050,
    );
    let device_add = signed_event(
        &root,
        identity_id,
        2,
        Some(log.head_hash()),
        1_100,
        IdentityLogEventPayloadV1::DeviceAdd {
            certificate: first_certificate,
        },
    );
    log.append(&device_add).unwrap();
    events.push(("device_add", device_add));

    let relay_descriptor = signed_event(
        &root,
        identity_id,
        3,
        Some(log.head_hash()),
        1_200,
        IdentityLogEventPayloadV1::RelayDescriptor {
            descriptor: descriptor(2_000),
        },
    );
    log.append(&relay_descriptor).unwrap();
    events.push(("relay_descriptor", relay_descriptor));

    let next_root = signing_key(4);
    let root_acceptance_signature = signature(
        &next_root,
        &key_rotation_acceptance_input(
            identity_id,
            safe(4),
            Some(log.head_hash()),
            KeyAcceptancePurposeV1::RootRotate,
            public_key(&next_root),
        )
        .unwrap(),
    );
    let root_rotate = signed_event(
        &root,
        identity_id,
        4,
        Some(log.head_hash()),
        1_300,
        IdentityLogEventPayloadV1::RootRotate {
            new_root_signing_key: public_key(&next_root),
            acceptance_signature: root_acceptance_signature,
        },
    );
    log.append(&root_rotate).unwrap();
    events.push(("root_rotate", root_rotate));

    let next_recovery = signing_key(5);
    let recovery_acceptance_signature = signature(
        &next_recovery,
        &key_rotation_acceptance_input(
            identity_id,
            safe(5),
            Some(log.head_hash()),
            KeyAcceptancePurposeV1::RecoveryRotate,
            public_key(&next_recovery),
        )
        .unwrap(),
    );
    let recovery_rotation_authorization_signature = signature(
        &recovery,
        &recovery_rotation_authorization_input(
            IDENTITY_LOG_WIRE_VERSION,
            identity_id,
            safe(5),
            Some(log.head_hash()),
            timestamp(1_400),
            public_key(&next_root),
            public_key(&next_recovery),
            recovery_acceptance_signature,
        )
        .unwrap(),
    );
    let recovery_rotate = signed_event(
        &next_root,
        identity_id,
        5,
        Some(log.head_hash()),
        1_400,
        IdentityLogEventPayloadV1::RecoveryRotate {
            new_recovery_signing_key: public_key(&next_recovery),
            acceptance_signature: recovery_acceptance_signature,
            recovery_authorization_signature: Some(recovery_rotation_authorization_signature),
        },
    );
    log.append(&recovery_rotate).unwrap();
    events.push(("recovery_rotate", recovery_rotate));

    let device_revoke = signed_event(
        &next_root,
        identity_id,
        6,
        Some(log.head_hash()),
        1_500,
        IdentityLogEventPayloadV1::DeviceRevoke {
            device_id: device_id(DEVICE_A),
        },
    );
    log.append(&device_revoke).unwrap();
    events.push(("device_revoke", device_revoke));

    let restored_root = signing_key(6);
    let restored_recovery = signing_key(7);
    let recovery_restore = signed_event(
        &next_recovery,
        identity_id,
        7,
        Some(log.head_hash()),
        1_600,
        IdentityLogEventPayloadV1::RecoveryRestore {
            new_root_signing_key: public_key(&restored_root),
            new_recovery_signing_key: public_key(&restored_recovery),
            root_acceptance_signature: signature(
                &restored_root,
                &key_rotation_acceptance_input(
                    identity_id,
                    safe(7),
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
                    safe(7),
                    Some(log.head_hash()),
                    KeyAcceptancePurposeV1::RecoveryRestoreRecovery,
                    public_key(&restored_recovery),
                )
                .unwrap(),
            ),
        },
    );
    log.append(&recovery_restore).unwrap();
    events.push(("recovery_restore", recovery_restore));
    events
}
