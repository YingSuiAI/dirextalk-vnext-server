#![forbid(unsafe_code)]

use std::{env, net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use axum_server::tls_rustls::RustlsConfig;
use base64ct::{Base64UrlUnpadded, Encoding};
use dtx_domain::{Clock, DeviceSessionId, IdentityId, SystemClock};
use dtx_identity_persistence::DeviceSessionCredential;
use dtx_realtime_sync::{
    HEARTBEAT_INTERVAL_MILLIS, Invalidation, InvalidationKind, Lease, OutboxNotification,
    RealtimeSyncStore, ReplayPage,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, SafeUint, UtcMillis, decode_deterministic_cbor,
    encode_deterministic_cbor,
};
use futures_util::StreamExt;
use sqlx::postgres::PgConnectOptions;
use tokio::sync::broadcast;
use uuid::Uuid;

const SUBPROTOCOL: &str = "dirextalk.realtime-sync.v1";
const SYNC_PATH: &str = "/v1/realtime-sync";
const SESSION_SCHEME: &str = "DTX-Device-Session";
const OUTBOX_POLL_INTERVAL: Duration = Duration::from_millis(100);
const SAFETY_REPLAY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_FRAME_BYTES: usize = 16_384;
const MAX_EPHEMERAL_TTL_MILLIS: u64 = 10_000;

#[derive(Clone)]
struct AppState {
    store: RealtimeSyncStore,
    clock: Arc<dyn Clock>,
    ephemeral: broadcast::Sender<EphemeralSignal>,
    durable: broadcast::Sender<OutboxNotification>,
}

#[derive(Clone, Copy, Debug)]
struct EphemeralSignal {
    identity_id: IdentityId,
    kind: u64,
    scope_digest: [u8; 32],
    expires_at_ms: i64,
}

enum ClientFrame {
    Hello {
        cursor: SafeUint,
    },
    Heartbeat {
        lease_id: Uuid,
        fence: SafeUint,
    },
    Ack {
        lease_id: Uuid,
        fence: SafeUint,
        cursor: SafeUint,
    },
    Ephemeral {
        kind: u64,
        scope_digest: [u8; 32],
        ttl_ms: u64,
        presence_opt_in: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = env::var("DTX_REALTIME_SYNC_DATABASE_URL")?;
    let bind = env::var("DTX_REALTIME_SYNC_BIND")
        .unwrap_or_else(|_| "0.0.0.0:9444".to_owned())
        .parse::<SocketAddr>()?;
    let certificate = PathBuf::from(env::var("DTX_REALTIME_SYNC_TLS_CERTIFICATE_FILE")?);
    let private_key = PathBuf::from(env::var("DTX_REALTIME_SYNC_TLS_PRIVATE_KEY_FILE")?);
    let store = RealtimeSyncStore::connect(PgConnectOptions::from_str(&database_url)?, 16).await?;
    let (ephemeral, _) = broadcast::channel(256);
    let (durable, _) = broadcast::channel(1_024);
    let state = AppState {
        store: store.clone(),
        clock: Arc::new(SystemClock),
        ephemeral,
        durable: durable.clone(),
    };
    tokio::spawn(publish_outbox(store, durable, Uuid::now_v7()));
    let router = Router::new()
        .route(SYNC_PATH, get(upgrade))
        .with_state(state);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = RustlsConfig::from_pem_file(certificate, private_key).await?;
    axum_server::bind_rustls(bind, tls)
        .serve(router.into_make_service())
        .await?;
    Ok(())
}

async fn upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    websocket: WebSocketUpgrade,
) -> Response {
    if !offers_exact_subprotocol(&headers) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Ok(credential) = parse_credential(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    websocket
        .protocols([SUBPROTOCOL])
        .on_upgrade(move |socket| serve_socket(state, credential, socket))
}

async fn serve_socket(state: AppState, credential: DeviceSessionCredential, mut socket: WebSocket) {
    let Some(Ok(Message::Binary(first))) = socket.next().await else {
        close(&mut socket, 1002, "binary hello required").await;
        return;
    };
    let Ok(ClientFrame::Hello { cursor }) = decode_client_frame(&first) else {
        close(&mut socket, 1002, "invalid hello").await;
        return;
    };
    let Ok(initial_now) = now(&state) else { return };
    let Ok(mut lease) = state.store.acquire(&credential, cursor, initial_now).await else {
        close(&mut socket, 1008, "authentication rejected").await;
        return;
    };
    if send_binary(&mut socket, encode_hello_ack(lease))
        .await
        .is_err()
    {
        return;
    }

    let mut next_cursor = cursor;
    let mut poll = tokio::time::interval(SAFETY_REPLAY_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ephemeral_rx = state.ephemeral.subscribe();
    let mut durable_rx = state.durable.subscribe();
    loop {
        tokio::select! {
            _ = poll.tick() => {
                let Ok(current_now) = now(&state) else { break };
                if !push_replay(&state, &credential, lease, &mut next_cursor, current_now, &mut socket).await { return; }
            }
            notification = durable_rx.recv() => {
                let should_replay = match notification {
                    Ok(notification) => notification.identity_id == lease.identity_id,
                    Err(broadcast::error::RecvError::Lagged(_)) => true,
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                if should_replay {
                    let Ok(current_now) = now(&state) else { break };
                    if !push_replay(&state, &credential, lease, &mut next_cursor, current_now, &mut socket).await { return; }
                }
            }
            signal = ephemeral_rx.recv() => {
                let Ok(current_now) = now(&state) else { break };
                if let Ok(signal) = signal
                    && ephemeral_is_visible(signal, lease.identity_id, current_now)
                    && send_binary(&mut socket, encode_ephemeral(signal)).await.is_err()
                {
                    return;
                }
            }
            incoming = socket.next() => {
                let Some(Ok(message)) = incoming else { return; };
                let Message::Binary(bytes) = message else {
                    if matches!(message, Message::Close(_)) { return; }
                    close(&mut socket, 1003, "binary frames only").await;
                    return;
                };
                let Ok(frame) = decode_client_frame(&bytes) else {
                    close(&mut socket, 1002, "invalid frame").await;
                    return;
                };
                let Ok(current_now) = now(&state) else { return; };
                match frame {
                    ClientFrame::Heartbeat { lease_id, fence } if matches_lease(lease, lease_id, fence) => {
                        if let Ok(updated) = state.store.heartbeat(&credential, lease, current_now).await {
                            lease = updated;
                            if send_binary(&mut socket, encode_heartbeat_ack(lease)).await.is_err() { return; }
                        } else {
                            close(&mut socket, 1008, "stale lease").await;
                            return;
                        }
                    }
                    ClientFrame::Ack { lease_id, fence, cursor } if matches_lease(lease, lease_id, fence) => {
                        if state.store.acknowledge(&credential, lease, cursor, current_now).await.is_err() {
                            close(&mut socket, 1008, "ack rejected").await;
                            return;
                        }
                        if send_binary(&mut socket, encode_ack_ok(cursor)).await.is_err() { return; }
                    }
                    ClientFrame::Ephemeral { kind, scope_digest, ttl_ms, presence_opt_in } => {
                        if kind == 3 && !presence_opt_in {
                            close(&mut socket, 1008, "presence requires opt in").await;
                            return;
                        }
                        let expires_at_ms = current_now.get().saturating_add(i64::try_from(ttl_ms).unwrap_or(i64::MAX));
                        let _ = state.ephemeral.send(EphemeralSignal { identity_id: lease.identity_id, kind, scope_digest, expires_at_ms });
                    }
                    _ => { close(&mut socket, 1008, "frame fence rejected").await; return; }
                }
            }
        }
    }
}

async fn publish_outbox(
    store: RealtimeSyncStore,
    durable: broadcast::Sender<OutboxNotification>,
    worker_id: Uuid,
) {
    let mut poll = tokio::time::interval(OUTBOX_POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let clock = SystemClock;
    let mut compaction_tick = 0_u16;
    let mut failures = 0_u8;
    loop {
        poll.tick().await;
        let Ok(now_ms) = clock.now_utc_millis() else {
            continue;
        };
        let Ok(now) = UtcMillis::new(now_ms) else {
            continue;
        };
        let claim = if let Ok(claim) = store.claim_outbox(worker_id, now).await {
            failures = 0;
            claim
        } else {
            failures = failures.saturating_add(1).min(5);
            tokio::time::sleep(Duration::from_millis(100_u64 << u32::from(failures))).await;
            continue;
        };
        for notification in &claim.notifications {
            let _ = durable.send(*notification);
        }
        if !claim.notifications.is_empty() {
            let _ = store.mark_outbox_published(&claim, now).await;
        }
        compaction_tick = compaction_tick.wrapping_add(1);
        if compaction_tick >= 300 {
            let _ = store.compact_expired(now).await;
            compaction_tick = 0;
        }
    }
}

async fn push_replay(
    state: &AppState,
    credential: &DeviceSessionCredential,
    lease: Lease,
    next_cursor: &mut SafeUint,
    now: UtcMillis,
    socket: &mut WebSocket,
) -> bool {
    match state
        .store
        .replay(credential, lease, *next_cursor, now)
        .await
    {
        Ok(ReplayPage::Events { events, .. }) => {
            for event in events {
                *next_cursor = event.cursor;
                if send_binary(socket, encode_invalidation(event))
                    .await
                    .is_err()
                {
                    return false;
                }
            }
            true
        }
        Ok(ReplayPage::CatchUpRequired { highwater }) => {
            let _ = send_binary(socket, encode_catch_up(highwater)).await;
            close(socket, 1008, "durable catch-up required").await;
            false
        }
        Err(_) => {
            close(socket, 1008, "lease or session rejected").await;
            false
        }
    }
}

fn decode_client_frame(bytes: &[u8]) -> Result<ClientFrame, ()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(());
    }
    let value = decode_deterministic_cbor(bytes).map_err(|_| ())?;
    let CanonicalValue::Map(fields) = value else {
        return Err(());
    };
    let get = |key: u64| {
        fields
            .iter()
            .find_map(|(candidate, value)| {
                (candidate == &CanonicalValue::Unsigned(key)).then_some(value)
            })
            .ok_or(())
    };
    if get(1)? != &CanonicalValue::Unsigned(1) {
        return Err(());
    }
    let CanonicalValue::Unsigned(kind) = get(2)? else {
        return Err(());
    };
    match *kind {
        1 if fields.len() == 3 => Ok(ClientFrame::Hello {
            cursor: unsigned_safe(get(3)?)?,
        }),
        2 if fields.len() == 4 => Ok(ClientFrame::Heartbeat {
            lease_id: uuid_text(get(3)?)?,
            fence: unsigned_safe(get(4)?)?,
        }),
        3 if fields.len() == 5 => Ok(ClientFrame::Ack {
            lease_id: uuid_text(get(3)?)?,
            fence: unsigned_safe(get(4)?)?,
            cursor: unsigned_safe(get(5)?)?,
        }),
        4 if fields.len() == 6 => {
            let CanonicalValue::Unsigned(signal_kind @ 1..=3) = get(3)? else {
                return Err(());
            };
            let CanonicalValue::Bytes(scope) = get(4)? else {
                return Err(());
            };
            let scope_digest = scope.as_slice().try_into().map_err(|_| ())?;
            let CanonicalValue::Unsigned(ttl_ms @ 1..=MAX_EPHEMERAL_TTL_MILLIS) = get(5)? else {
                return Err(());
            };
            let CanonicalValue::Bool(presence_opt_in) = get(6)? else {
                return Err(());
            };
            Ok(ClientFrame::Ephemeral {
                kind: *signal_kind,
                scope_digest,
                ttl_ms: *ttl_ms,
                presence_opt_in: *presence_opt_in,
            })
        }
        _ => Err(()),
    }
}

fn encode_hello_ack(lease: Lease) -> Vec<u8> {
    encode_map(vec![
        (1, CanonicalValue::Unsigned(1)),
        (2, CanonicalValue::Unsigned(1)),
        (3, CanonicalValue::Text(lease.lease_id.to_string())),
        (4, CanonicalValue::Unsigned(lease.fence.get())),
        (5, CanonicalValue::Unsigned(lease.journal_floor.get())),
        (6, CanonicalValue::Unsigned(lease.highwater.get())),
        (
            7,
            CanonicalValue::Unsigned(u64::try_from(HEARTBEAT_INTERVAL_MILLIS).unwrap_or(15_000)),
        ),
        (8, CanonicalValue::Unsigned(45_000)),
    ])
}

fn encode_invalidation(event: Invalidation) -> Vec<u8> {
    let kind = match event.kind {
        InvalidationKind::MailboxDelivery => 1,
        InvalidationKind::ConversationRead => 2,
        InvalidationKind::DurableInvalidation => 3,
    };
    encode_map(vec![
        (1, CanonicalValue::Unsigned(1)),
        (2, CanonicalValue::Unsigned(2)),
        (3, CanonicalValue::Unsigned(event.cursor.get())),
        (4, CanonicalValue::Unsigned(kind)),
        (
            5,
            CanonicalValue::Bytes(event.subject_digest.as_bytes().to_vec()),
        ),
    ])
}

fn encode_catch_up(highwater: SafeUint) -> Vec<u8> {
    encode_map(vec![
        (1, CanonicalValue::Unsigned(1)),
        (2, CanonicalValue::Unsigned(3)),
        (3, CanonicalValue::Unsigned(highwater.get())),
    ])
}

fn encode_heartbeat_ack(lease: Lease) -> Vec<u8> {
    encode_map(vec![
        (1, CanonicalValue::Unsigned(1)),
        (2, CanonicalValue::Unsigned(4)),
        (3, CanonicalValue::Text(lease.lease_id.to_string())),
        (4, CanonicalValue::Unsigned(lease.fence.get())),
        (5, lease.expires_at.to_canonical_value()),
    ])
}

fn encode_ack_ok(cursor: SafeUint) -> Vec<u8> {
    encode_map(vec![
        (1, CanonicalValue::Unsigned(1)),
        (2, CanonicalValue::Unsigned(5)),
        (3, CanonicalValue::Unsigned(cursor.get())),
    ])
}

fn encode_ephemeral(signal: EphemeralSignal) -> Vec<u8> {
    encode_map(vec![
        (1, CanonicalValue::Unsigned(1)),
        (2, CanonicalValue::Unsigned(6)),
        (3, CanonicalValue::Unsigned(signal.kind)),
        (4, CanonicalValue::Bytes(signal.scope_digest.to_vec())),
        (
            5,
            UtcMillis::new(signal.expires_at_ms).map_or(CanonicalValue::Unsigned(0), |value| {
                value.to_canonical_value()
            }),
        ),
    ])
}

fn encode_map(fields: Vec<(u64, CanonicalValue)>) -> Vec<u8> {
    encode_deterministic_cbor(&CanonicalValue::Map(
        fields
            .into_iter()
            .map(|(key, value)| (CanonicalValue::Unsigned(key), value))
            .collect(),
    ))
    .unwrap_or_default()
}

fn matches_lease(lease: Lease, lease_id: Uuid, fence: SafeUint) -> bool {
    lease.lease_id == lease_id && lease.fence == fence
}

fn ephemeral_is_visible(signal: EphemeralSignal, identity_id: IdentityId, now: UtcMillis) -> bool {
    signal.identity_id == identity_id && signal.expires_at_ms > now.get()
}

fn unsigned_safe(value: &CanonicalValue) -> Result<SafeUint, ()> {
    let CanonicalValue::Unsigned(value) = value else {
        return Err(());
    };
    SafeUint::new(*value).map_err(|_| ())
}

fn uuid_text(value: &CanonicalValue) -> Result<Uuid, ()> {
    let CanonicalValue::Text(value) = value else {
        return Err(());
    };
    let uuid = Uuid::parse_str(value).map_err(|_| ())?;
    if uuid.get_version_num() != 7 || uuid.to_string() != *value {
        return Err(());
    }
    Ok(uuid)
}

fn now(state: &AppState) -> Result<UtcMillis, ()> {
    UtcMillis::new(state.clock.now_utc_millis().map_err(|_| ())?).map_err(|_| ())
}

fn offers_exact_subprotocol(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(|value| value == SUBPROTOCOL)
}

fn parse_credential(headers: &HeaderMap) -> Result<DeviceSessionCredential, ()> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(())?.to_str().map_err(|_| ())?;
    if values.next().is_some() {
        return Err(());
    }
    let value = value
        .strip_prefix(&format!("{SESSION_SCHEME} "))
        .ok_or(())?;
    let (session_id, secret) = value.split_once('.').ok_or(())?;
    if secret.contains('.') || secret.len() != 43 {
        return Err(());
    }
    let mut bytes = [0_u8; 32];
    let decoded = Base64UrlUnpadded::decode(secret, &mut bytes).map_err(|_| ())?;
    if decoded.len() != 32 {
        return Err(());
    }
    DeviceSessionCredential::new(
        session_id.parse::<DeviceSessionId>().map_err(|_| ())?,
        bytes,
    )
    .map_err(|_| ())
}

async fn send_binary(socket: &mut WebSocket, bytes: Vec<u8>) -> Result<(), axum::Error> {
    socket.send(Message::Binary(bytes.into())).await
}

async fn close(socket: &mut WebSocket, code: u16, reason: &'static str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })))
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_textual_or_capability_bearing_frames() {
        let invalid = encode_map(vec![
            (1, CanonicalValue::Unsigned(1)),
            (2, CanonicalValue::Unsigned(2)),
            (3, CanonicalValue::Text("plaintext-room-name".to_owned())),
            (4, CanonicalValue::Unsigned(1)),
        ]);
        assert!(decode_client_frame(&invalid).is_err());
    }

    #[test]
    fn ephemeral_requires_bounded_typed_signal() {
        let frame = encode_map(vec![
            (1, CanonicalValue::Unsigned(1)),
            (2, CanonicalValue::Unsigned(4)),
            (3, CanonicalValue::Unsigned(1)),
            (4, CanonicalValue::Bytes(vec![7; 32])),
            (5, CanonicalValue::Unsigned(10_000)),
            (6, CanonicalValue::Bool(false)),
        ]);
        assert!(matches!(
            decode_client_frame(&frame),
            Ok(ClientFrame::Ephemeral { kind: 1, .. })
        ));
    }

    #[test]
    fn ephemeral_expiry_is_strict() {
        let identity_id = "dtxi1l7a4yw7wcc5nlo6p74d3oorsb5fgkpvrphihkgqxexrisc5h43ka"
            .parse::<IdentityId>()
            .expect("valid test identity");
        let signal = EphemeralSignal {
            identity_id,
            kind: 1,
            scope_digest: [7; 32],
            expires_at_ms: 10_000,
        };
        assert!(ephemeral_is_visible(
            signal,
            identity_id,
            UtcMillis::new(9_999).expect("valid test time")
        ));
        assert!(!ephemeral_is_visible(
            signal,
            identity_id,
            UtcMillis::new(10_000).expect("valid test time")
        ));
    }
}
