#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    env, fs,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    extract::{
        ConnectInfo, State, WebSocketUpgrade,
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
    HEARTBEAT_INTERVAL_MILLIS, Invalidation, InvalidationKind, Lease, LeaseOperation,
    OutboxNotification, RealtimeSyncStore, ReplayPage,
};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, SafeUint, Sha256Digest, UtcMillis, decode_deterministic_cbor,
    encode_deterministic_cbor,
};
use futures_util::StreamExt;
use sqlx::postgres::PgConnectOptions;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast};
use uuid::Uuid;

const SUBPROTOCOL_V1: &str = "dirextalk.realtime-sync.v1";
const SUBPROTOCOL_V2: &str = "dirextalk.realtime-sync.v2";
const SYNC_PATH: &str = "/v1/realtime-sync";
const SESSION_SCHEME: &str = "DTX-Device-Session";
const OUTBOX_POLL_INTERVAL: Duration = Duration::from_millis(100);
const SAFETY_REPLAY_INTERVAL: Duration = Duration::from_secs(1);
const MAX_FRAME_BYTES: usize = 16_384;
const MAX_EPHEMERAL_TTL_MILLIS: u64 = 10_000;
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const LEASE_OPERATION_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(1);
const SOCKET_SIDE_EFFECT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_GLOBAL_CONNECTIONS: usize = 4_096;
const MAX_CONNECTIONS_PER_SOURCE: usize = 32;
const MAX_SCOPES_PER_CONNECTION: usize = 32;
const MAX_GLOBAL_SCOPE_SUBSCRIPTIONS: usize = 8_192;
const EPHEMERAL_ACTOR_DIGEST_DOMAIN: &[u8] = b"dirextalk.realtime-ephemeral-actor.v2\0";
const DATABASE_URL_ENV: &str = "DTX_REALTIME_SYNC_DATABASE_URL";
const DATABASE_URL_FILE_ENV: &str = "DTX_REALTIME_SYNC_DATABASE_URL_FILE";
const MAX_DATABASE_URL_BYTES: u64 = 8_192;

#[derive(Clone)]
struct AppState {
    store: RealtimeSyncStore,
    clock: Arc<dyn Clock>,
    ephemeral: broadcast::Sender<EphemeralSignal>,
    durable: broadcast::Sender<OutboxNotification>,
    admission: Arc<AdmissionGate>,
    scopes: Arc<EphemeralRegistry>,
}

struct AdmissionGate {
    global: Arc<Semaphore>,
    per_source_limit: usize,
    per_source: Mutex<HashMap<IpAddr, usize>>,
}

impl AdmissionGate {
    fn new(global_limit: usize, per_source_limit: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global_limit)),
            per_source_limit,
            per_source: Mutex::new(HashMap::new()),
        }
    }

    fn try_acquire(self: &Arc<Self>, source: IpAddr) -> Option<AdmissionPermit> {
        let global = self.global.clone().try_acquire_owned().ok()?;
        let mut per_source = self.per_source.lock().ok()?;
        let current = per_source.entry(source).or_default();
        if *current >= self.per_source_limit {
            return None;
        }
        *current += 1;
        drop(per_source);
        Some(AdmissionPermit {
            gate: self.clone(),
            source,
            _global: global,
        })
    }
}

struct AdmissionPermit {
    gate: Arc<AdmissionGate>,
    source: IpAddr,
    _global: OwnedSemaphorePermit,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        if let Ok(mut per_source) = self.gate.per_source.lock()
            && let Some(current) = per_source.get_mut(&self.source)
        {
            *current = current.saturating_sub(1);
            if *current == 0 {
                per_source.remove(&self.source);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ScopeSubscription {
    identity_id: IdentityId,
    expires_at_ms: i64,
    presence_opt_in: bool,
}

#[derive(Default)]
struct EphemeralRegistry {
    subscriptions: Mutex<HashMap<Uuid, HashMap<[u8; 32], ScopeSubscription>>>,
}

impl EphemeralRegistry {
    fn subscribe(
        &self,
        connection_id: Uuid,
        identity_id: IdentityId,
        scope_digest: [u8; 32],
        expires_at_ms: i64,
        presence_opt_in: bool,
        now: UtcMillis,
    ) -> bool {
        let Ok(mut subscriptions) = self.subscriptions.lock() else {
            return false;
        };
        prune_expired_subscriptions(&mut subscriptions, now);
        let total: usize = subscriptions.values().map(HashMap::len).sum();
        let connection = subscriptions.entry(connection_id).or_default();
        let replacing = connection.contains_key(&scope_digest);
        if !replacing
            && (connection.len() >= MAX_SCOPES_PER_CONNECTION
                || total >= MAX_GLOBAL_SCOPE_SUBSCRIPTIONS)
        {
            return false;
        }
        connection.insert(
            scope_digest,
            ScopeSubscription {
                identity_id,
                expires_at_ms,
                presence_opt_in,
            },
        );
        true
    }

    fn is_visible(
        &self,
        signal: EphemeralSignal,
        connection_id: Uuid,
        identity_id: IdentityId,
        now: UtcMillis,
    ) -> bool {
        if signal.expires_at_ms <= now.get()
            || signal.source_connection_id == connection_id
            || signal.source_identity_id == identity_id
        {
            return false;
        }
        let Ok(mut subscriptions) = self.subscriptions.lock() else {
            return false;
        };
        prune_expired_subscriptions(&mut subscriptions, now);
        subscriptions
            .get(&connection_id)
            .and_then(|scopes| scopes.get(&signal.scope_digest))
            .is_some_and(|subscription| {
                subscription.identity_id == identity_id
                    && subscription.expires_at_ms > now.get()
                    && (signal.kind != 3 || subscription.presence_opt_in)
            })
    }

    fn has_subscription(
        &self,
        connection_id: Uuid,
        identity_id: IdentityId,
        scope_digest: [u8; 32],
        require_presence_opt_in: bool,
        now: UtcMillis,
    ) -> bool {
        let Ok(mut subscriptions) = self.subscriptions.lock() else {
            return false;
        };
        prune_expired_subscriptions(&mut subscriptions, now);
        subscriptions
            .get(&connection_id)
            .and_then(|scopes| scopes.get(&scope_digest))
            .is_some_and(|subscription| {
                subscription.identity_id == identity_id
                    && (!require_presence_opt_in || subscription.presence_opt_in)
            })
    }

    fn remove(&self, connection_id: Uuid) {
        if let Ok(mut subscriptions) = self.subscriptions.lock() {
            subscriptions.remove(&connection_id);
        }
    }
}

fn prune_expired_subscriptions(
    subscriptions: &mut HashMap<Uuid, HashMap<[u8; 32], ScopeSubscription>>,
    now: UtcMillis,
) {
    subscriptions.retain(|_, scopes| {
        scopes.retain(|_, subscription| subscription.expires_at_ms > now.get());
        !scopes.is_empty()
    });
}

struct ScopeRegistration {
    registry: Arc<EphemeralRegistry>,
    connection_id: Uuid,
}

impl ScopeRegistration {
    fn new(registry: Arc<EphemeralRegistry>, connection_id: Uuid) -> Self {
        Self {
            registry,
            connection_id,
        }
    }
}

impl Drop for ScopeRegistration {
    fn drop(&mut self) {
        self.registry.remove(self.connection_id);
    }
}

#[derive(Clone, Copy, Debug)]
struct EphemeralSignal {
    source_connection_id: Uuid,
    source_identity_id: IdentityId,
    source_actor_digest: Sha256Digest,
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
    ScopeSubscribe {
        scope_digest: [u8; 32],
        ttl_ms: u64,
        presence_opt_in: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WireLine {
    V1,
    V2,
}

impl WireLine {
    const fn version(self) -> u64 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = load_database_url()?;
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
        admission: Arc::new(AdmissionGate::new(
            MAX_GLOBAL_CONNECTIONS,
            MAX_CONNECTIONS_PER_SOURCE,
        )),
        scopes: Arc::new(EphemeralRegistry::default()),
    };
    tokio::spawn(publish_outbox(store, durable, Uuid::now_v7()));
    let router = Router::new()
        .route(SYNC_PATH, get(upgrade))
        .with_state(state);
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = RustlsConfig::from_pem_file(certificate, private_key).await?;
    axum_server::bind_rustls(bind, tls)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

fn load_database_url() -> Result<String, std::io::Error> {
    let direct = env::var_os(DATABASE_URL_ENV);
    let file = env::var_os(DATABASE_URL_FILE_ENV);
    match (direct, file) {
        (Some(_), Some(_)) | (None, None) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "configure exactly one realtime database source",
        )),
        (Some(value), None) => value.into_string().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "realtime database URL is not UTF-8",
            )
        }),
        (None, Some(path)) => {
            let path = PathBuf::from(path);
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() == 0
                || metadata.len() > MAX_DATABASE_URL_BYTES
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "realtime database credential file rejected",
                ));
            }
            let bytes = fs::read(path)?;
            let value = std::str::from_utf8(&bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "realtime database credential is not UTF-8",
                )
            })?;
            let value = value.strip_suffix('\n').unwrap_or(value);
            let value = value.strip_suffix('\r').unwrap_or(value);
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "realtime database credential shape rejected",
                ));
            }
            Ok(value.to_owned())
        }
    }
}

async fn upgrade(
    State(state): State<AppState>,
    ConnectInfo(source): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    websocket: WebSocketUpgrade,
) -> Response {
    let Some(wire) = negotiated_wire(&headers) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(credential) = parse_credential(&headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(admission) = state.admission.try_acquire(source.ip()) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    websocket
        .protocols([match wire {
            WireLine::V1 => SUBPROTOCOL_V1,
            WireLine::V2 => SUBPROTOCOL_V2,
        }])
        .on_upgrade(move |socket| serve_socket(state, credential, socket, wire, admission))
}

#[allow(
    clippy::too_many_lines,
    reason = "one socket state machine keeps lease fencing, replay, ACK, and ephemeral scope lifecycle coherent"
)]
async fn serve_socket(
    state: AppState,
    credential: DeviceSessionCredential,
    mut socket: WebSocket,
    wire: WireLine,
    _admission: AdmissionPermit,
) {
    let connection_id = Uuid::now_v7();
    let _scope_registration = ScopeRegistration::new(state.scopes.clone(), connection_id);
    let Ok(Some(Ok(Message::Binary(first)))) =
        tokio::time::timeout(HELLO_TIMEOUT, socket.next()).await
    else {
        close(&mut socket, 1002, "binary hello required").await;
        return;
    };
    let Ok(ClientFrame::Hello { cursor }) = decode_client_frame(&first, wire) else {
        close(&mut socket, 1002, "invalid hello").await;
        return;
    };
    let Ok(initial_now) = now(&state) else { return };
    let Ok(mut lease) = state.store.acquire(&credential, cursor, initial_now).await else {
        close(&mut socket, 1008, "authentication rejected").await;
        return;
    };
    if !send_binary_fenced(
        &state,
        &credential,
        lease,
        initial_now,
        &mut socket,
        encode_hello_ack(lease, wire),
    )
    .await
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
                if !push_replay(&state, &credential, lease, &mut next_cursor, current_now, &mut socket, wire).await { return; }
            }
            notification = durable_rx.recv() => {
                let should_replay = match notification {
                    Ok(notification) => notification.identity_id == lease.identity_id,
                    Err(broadcast::error::RecvError::Lagged(_)) => true,
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                if should_replay {
                    let Ok(current_now) = now(&state) else { break };
                    if !push_replay(&state, &credential, lease, &mut next_cursor, current_now, &mut socket, wire).await { return; }
                }
            }
            signal = ephemeral_rx.recv() => {
                let Ok(current_now) = now(&state) else { break };
                let signal = match signal {
                    Ok(signal) => signal,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                };
                if state.scopes.is_visible(signal, connection_id, lease.identity_id, current_now) {
                    let Ok(operation) = begin_gateway_operation(
                        &state, &credential, lease, current_now,
                    ).await else {
                        close(&mut socket, 1008, "lease or session rejected").await;
                        return;
                    };
                    let Some(edge_now) = operation_side_effect_now(&state, lease) else {
                        drop(operation);
                        return;
                    };
                    if !state.scopes.is_visible(
                        signal, connection_id, lease.identity_id, edge_now,
                    ) {
                        if !finish_gateway_operation(operation).await {
                            return;
                        }
                        continue;
                    }
                    if !send_binary_in_operation(
                        &state,
                        operation,
                        lease,
                        &mut socket,
                        encode_ephemeral(signal, wire),
                    ).await { return; }
                }
            }
            incoming = socket.next() => {
                let Some(Ok(message)) = incoming else { return; };
                let Message::Binary(bytes) = message else {
                    if matches!(message, Message::Close(_)) { return; }
                    close(&mut socket, 1003, "binary frames only").await;
                    return;
                };
                let Ok(frame) = decode_client_frame(&bytes, wire) else {
                    close(&mut socket, 1002, "invalid frame").await;
                    return;
                };
                let Ok(current_now) = now(&state) else { return; };
                match frame {
                    ClientFrame::Heartbeat { lease_id, fence } if matches_lease(lease, lease_id, fence) => {
                        if let Ok(updated) = state.store.heartbeat(&credential, lease, current_now).await {
                            lease = updated;
                            if !send_binary_fenced(
                                &state,
                                &credential,
                                lease,
                                current_now,
                                &mut socket,
                                encode_heartbeat_ack(lease, wire),
                            ).await { return; }
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
                        if !send_binary_fenced(
                            &state,
                            &credential,
                            lease,
                            current_now,
                            &mut socket,
                            encode_ack_ok(cursor, wire),
                        ).await { return; }
                    }
                    ClientFrame::Ephemeral { kind, scope_digest, ttl_ms, presence_opt_in } => {
                        let Ok(operation) = begin_gateway_operation(
                            &state, &credential, lease, current_now,
                        ).await else {
                            close(&mut socket, 1008, "lease or session rejected").await;
                            return;
                        };
                        let Some(edge_now) = operation_side_effect_now(&state, lease) else {
                            drop(operation);
                            return;
                        };
                        if kind == 3 && !presence_opt_in {
                            let _ = finish_gateway_operation(operation).await;
                            close(&mut socket, 1008, "presence requires opt in").await;
                            return;
                        }
                        let scope_admitted = if wire == WireLine::V1 {
                            state.scopes.subscribe(
                                connection_id,
                                lease.identity_id,
                                scope_digest,
                                edge_now.get().saturating_add(i64::try_from(ttl_ms).unwrap_or(i64::MAX)),
                                presence_opt_in,
                                edge_now,
                            )
                        } else {
                            state.scopes.has_subscription(
                                connection_id,
                                lease.identity_id,
                                scope_digest,
                                kind == 3,
                                edge_now,
                            )
                        };
                        if !scope_admitted {
                            let _ = finish_gateway_operation(operation).await;
                            close(&mut socket, 1008, "scope admission rejected").await;
                            return;
                        }
                        let expires_at_ms = edge_now.get().saturating_add(i64::try_from(ttl_ms).unwrap_or(i64::MAX));
                        let _ = state.ephemeral.send(EphemeralSignal {
                            source_connection_id: connection_id,
                            source_identity_id: lease.identity_id,
                            source_actor_digest: Sha256Digest::hash_domain(
                                EPHEMERAL_ACTOR_DIGEST_DOMAIN,
                                lease.identity_id.to_string().as_bytes(),
                            ),
                            kind,
                            scope_digest,
                            expires_at_ms,
                        });
                        if !finish_gateway_operation(operation).await {
                            return;
                        }
                    }
                    ClientFrame::ScopeSubscribe { scope_digest, ttl_ms, presence_opt_in }
                        if wire == WireLine::V2 => {
                        let Ok(operation) = begin_gateway_operation(
                            &state, &credential, lease, current_now,
                        ).await else {
                            close(&mut socket, 1008, "lease or session rejected").await;
                            return;
                        };
                        let Some(edge_now) = operation_side_effect_now(&state, lease) else {
                            drop(operation);
                            return;
                        };
                        let expires_at_ms = edge_now.get().saturating_add(i64::try_from(ttl_ms).unwrap_or(i64::MAX));
                        if !state.scopes.subscribe(
                            connection_id,
                            lease.identity_id,
                            scope_digest,
                            expires_at_ms,
                            presence_opt_in,
                            edge_now,
                        ) {
                            let _ = finish_gateway_operation(operation).await;
                            close(&mut socket, 1008, "scope admission rejected").await;
                            return;
                        }
                        if !finish_gateway_operation(operation).await {
                            return;
                        }
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
    wire: WireLine,
) -> bool {
    let Ok(mut operation) = begin_gateway_operation(state, credential, lease, now).await else {
        close(socket, 1008, "lease or session rejected").await;
        return false;
    };
    let Some(replay_now) = operation_side_effect_now(state, lease) else {
        drop(operation);
        return false;
    };
    let Ok(page) = operation.replay(*next_cursor, replay_now).await else {
        drop(operation);
        close(socket, 1008, "lease or session rejected").await;
        return false;
    };
    match page {
        ReplayPage::Events { events, .. } => {
            let Some(edge_now) = operation_side_effect_now(state, lease) else {
                drop(operation);
                return false;
            };
            let Some(timeout) = socket_side_effect_timeout(lease, edge_now) else {
                drop(operation);
                return false;
            };
            let sent = tokio::time::timeout(timeout, async {
                for event in events {
                    send_binary(socket, encode_invalidation(event, wire))
                        .await
                        .map_err(|_| ())?;
                    *next_cursor = event.cursor;
                }
                Ok::<(), ()>(())
            })
            .await
            .is_ok_and(|result| result.is_ok());
            let finished = finish_gateway_operation(operation).await;
            sent && finished
        }
        ReplayPage::CatchUpRequired { highwater } => {
            let Some(edge_now) = operation_side_effect_now(state, lease) else {
                drop(operation);
                return false;
            };
            let Some(timeout) = socket_side_effect_timeout(lease, edge_now) else {
                drop(operation);
                return false;
            };
            let _ = tokio::time::timeout(timeout, async {
                let _ = send_binary(socket, encode_catch_up(highwater, wire)).await;
                close(socket, 1008, "durable catch-up required").await;
            })
            .await;
            let _ = finish_gateway_operation(operation).await;
            false
        }
    }
}

async fn begin_gateway_operation(
    state: &AppState,
    credential: &DeviceSessionCredential,
    lease: Lease,
    now: UtcMillis,
) -> Result<LeaseOperation, ()> {
    tokio::time::timeout(
        LEASE_OPERATION_ACQUIRE_TIMEOUT,
        state.store.begin_lease_operation(credential, lease, now),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())
}

async fn finish_gateway_operation(operation: LeaseOperation) -> bool {
    tokio::time::timeout(LEASE_OPERATION_ACQUIRE_TIMEOUT, operation.finish())
        .await
        .is_ok_and(|result| result.is_ok())
}

async fn send_binary_fenced(
    state: &AppState,
    credential: &DeviceSessionCredential,
    lease: Lease,
    now: UtcMillis,
    socket: &mut WebSocket,
    bytes: Vec<u8>,
) -> bool {
    let Ok(operation) = begin_gateway_operation(state, credential, lease, now).await else {
        return false;
    };
    send_binary_in_operation(state, operation, lease, socket, bytes).await
}

async fn send_binary_in_operation(
    state: &AppState,
    operation: LeaseOperation,
    lease: Lease,
    socket: &mut WebSocket,
    bytes: Vec<u8>,
) -> bool {
    let Some(edge_now) = operation_side_effect_now(state, lease) else {
        drop(operation);
        return false;
    };
    let Some(timeout) = socket_side_effect_timeout(lease, edge_now) else {
        drop(operation);
        return false;
    };
    let sent = tokio::time::timeout(timeout, send_binary(socket, bytes))
        .await
        .is_ok_and(|result| result.is_ok());
    let finished = finish_gateway_operation(operation).await;
    sent && finished
}

fn operation_side_effect_now(state: &AppState, lease: Lease) -> Option<UtcMillis> {
    let edge_now = now(state).ok()?;
    (edge_now < lease.expires_at).then_some(edge_now)
}

fn socket_side_effect_timeout(lease: Lease, now: UtcMillis) -> Option<Duration> {
    let remaining = lease.expires_at.get().checked_sub(now.get())?;
    if remaining == 0 {
        return None;
    }
    let remaining = Duration::from_millis(u64::try_from(remaining).ok()?);
    Some(SOCKET_SIDE_EFFECT_TIMEOUT.min(remaining))
}

fn decode_client_frame(bytes: &[u8], wire: WireLine) -> Result<ClientFrame, ()> {
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
    if get(1)? != &CanonicalValue::Unsigned(wire.version()) {
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
        5 if wire == WireLine::V2 && fields.len() == 5 => {
            let CanonicalValue::Bytes(scope) = get(3)? else {
                return Err(());
            };
            let scope_digest = scope.as_slice().try_into().map_err(|_| ())?;
            let CanonicalValue::Unsigned(ttl_ms @ 1..=MAX_EPHEMERAL_TTL_MILLIS) = get(4)? else {
                return Err(());
            };
            let CanonicalValue::Bool(presence_opt_in) = get(5)? else {
                return Err(());
            };
            Ok(ClientFrame::ScopeSubscribe {
                scope_digest,
                ttl_ms: *ttl_ms,
                presence_opt_in: *presence_opt_in,
            })
        }
        _ => Err(()),
    }
}

fn encode_hello_ack(lease: Lease, wire: WireLine) -> Vec<u8> {
    encode_map(vec![
        (1, CanonicalValue::Unsigned(wire.version())),
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

fn encode_invalidation(event: Invalidation, wire: WireLine) -> Vec<u8> {
    let kind = match (wire, event.kind) {
        (_, InvalidationKind::MailboxDelivery) => 1,
        (_, InvalidationKind::ConversationRead) => 2,
        (
            WireLine::V1,
            InvalidationKind::IdentityHeadChanged
            | InvalidationKind::DeviceRevoked
            | InvalidationKind::KeyAuthorizationChanged,
        )
        | (_, InvalidationKind::DurableInvalidation) => 3,
        (WireLine::V2, InvalidationKind::IdentityHeadChanged) => 4,
        (WireLine::V2, InvalidationKind::DeviceRevoked) => 5,
        (WireLine::V2, InvalidationKind::KeyAuthorizationChanged) => 6,
    };
    encode_map(vec![
        (1, CanonicalValue::Unsigned(wire.version())),
        (2, CanonicalValue::Unsigned(2)),
        (3, CanonicalValue::Unsigned(event.cursor.get())),
        (4, CanonicalValue::Unsigned(kind)),
        (
            5,
            CanonicalValue::Bytes(event.subject_digest.as_bytes().to_vec()),
        ),
    ])
}

fn encode_catch_up(highwater: SafeUint, wire: WireLine) -> Vec<u8> {
    encode_map(vec![
        (1, CanonicalValue::Unsigned(wire.version())),
        (2, CanonicalValue::Unsigned(3)),
        (3, CanonicalValue::Unsigned(highwater.get())),
    ])
}

fn encode_heartbeat_ack(lease: Lease, wire: WireLine) -> Vec<u8> {
    encode_map(vec![
        (1, CanonicalValue::Unsigned(wire.version())),
        (2, CanonicalValue::Unsigned(4)),
        (3, CanonicalValue::Text(lease.lease_id.to_string())),
        (4, CanonicalValue::Unsigned(lease.fence.get())),
        (5, lease.expires_at.to_canonical_value()),
    ])
}

fn encode_ack_ok(cursor: SafeUint, wire: WireLine) -> Vec<u8> {
    encode_map(vec![
        (1, CanonicalValue::Unsigned(wire.version())),
        (2, CanonicalValue::Unsigned(5)),
        (3, CanonicalValue::Unsigned(cursor.get())),
    ])
}

fn encode_ephemeral(signal: EphemeralSignal, wire: WireLine) -> Vec<u8> {
    let mut fields = vec![
        (1, CanonicalValue::Unsigned(wire.version())),
        (2, CanonicalValue::Unsigned(6)),
        (3, CanonicalValue::Unsigned(signal.kind)),
        (4, CanonicalValue::Bytes(signal.scope_digest.to_vec())),
        (
            5,
            UtcMillis::new(signal.expires_at_ms).map_or(CanonicalValue::Unsigned(0), |value| {
                value.to_canonical_value()
            }),
        ),
    ];
    if wire == WireLine::V2 {
        fields.push((
            6,
            CanonicalValue::Bytes(signal.source_actor_digest.as_bytes().to_vec()),
        ));
    }
    encode_map(fields)
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

fn negotiated_wire(headers: &HeaderMap) -> Option<WireLine> {
    let offered = headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .collect::<Vec<_>>();
    if offered.contains(&SUBPROTOCOL_V2) {
        Some(WireLine::V2)
    } else if offered.contains(&SUBPROTOCOL_V1) {
        Some(WireLine::V1)
    } else {
        None
    }
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
        assert!(decode_client_frame(&invalid, WireLine::V1).is_err());
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
            decode_client_frame(&frame, WireLine::V1),
            Ok(ClientFrame::Ephemeral { kind: 1, .. })
        ));
    }

    #[test]
    fn ephemeral_expiry_is_strict() {
        let source_identity = "dtxi1l7a4yw7wcc5nlo6p74d3oorsb5fgkpvrphihkgqxexrisc5h43ka"
            .parse::<IdentityId>()
            .expect("valid test identity");
        let target_identity = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la"
            .parse::<IdentityId>()
            .expect("valid target identity");
        let source_connection_id = Uuid::now_v7();
        let target_connection_id = Uuid::now_v7();
        let registry = EphemeralRegistry::default();
        assert!(registry.subscribe(
            target_connection_id,
            target_identity,
            [7; 32],
            10_000,
            true,
            UtcMillis::new(9_000).expect("valid test time"),
        ));
        let signal = EphemeralSignal {
            source_connection_id,
            source_identity_id: source_identity,
            source_actor_digest: Sha256Digest::from_bytes([8; 32]),
            kind: 1,
            scope_digest: [7; 32],
            expires_at_ms: 10_000,
        };
        assert!(registry.is_visible(
            signal,
            target_connection_id,
            target_identity,
            UtcMillis::new(9_999).expect("valid test time")
        ));
        assert!(!registry.is_visible(
            signal,
            target_connection_id,
            target_identity,
            UtcMillis::new(10_000).expect("valid test time")
        ));
    }

    #[test]
    fn v2_scope_subscription_routes_only_to_intended_active_peer() {
        let source_identity = "dtxi1l7a4yw7wcc5nlo6p74d3oorsb5fgkpvrphihkgqxexrisc5h43ka"
            .parse::<IdentityId>()
            .expect("valid source identity");
        let target_identity = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la"
            .parse::<IdentityId>()
            .expect("valid target identity");
        let source_connection_id = Uuid::now_v7();
        let target_connection_id = Uuid::now_v7();
        let outsider_connection_id = Uuid::now_v7();
        let now = UtcMillis::new(1_000).expect("valid now");
        let registry = EphemeralRegistry::default();
        assert!(registry.subscribe(
            source_connection_id,
            source_identity,
            [9; 32],
            2_000,
            true,
            now,
        ));
        assert!(registry.subscribe(
            target_connection_id,
            target_identity,
            [9; 32],
            2_000,
            true,
            now,
        ));
        assert!(registry.subscribe(
            outsider_connection_id,
            target_identity,
            [10; 32],
            2_000,
            true,
            now,
        ));
        let signal = EphemeralSignal {
            source_connection_id,
            source_identity_id: source_identity,
            source_actor_digest: Sha256Digest::from_bytes([11; 32]),
            kind: 1,
            scope_digest: [9; 32],
            expires_at_ms: 1_500,
        };
        assert!(registry.is_visible(signal, target_connection_id, target_identity, now));
        assert!(!registry.is_visible(signal, source_connection_id, source_identity, now));
        assert!(!registry.is_visible(signal, outsider_connection_id, target_identity, now));
    }

    #[test]
    fn admission_is_globally_and_per_source_bounded_and_released() {
        let gate = Arc::new(AdmissionGate::new(2, 1));
        let first_source: IpAddr = "192.0.2.1".parse().expect("valid source");
        let second_source: IpAddr = "192.0.2.2".parse().expect("valid source");
        let first = gate.try_acquire(first_source).expect("first admitted");
        assert!(gate.try_acquire(first_source).is_none());
        let second = gate.try_acquire(second_source).expect("second admitted");
        assert!(
            gate.try_acquire("192.0.2.3".parse().expect("valid source"))
                .is_none()
        );
        drop(first);
        assert!(gate.try_acquire(first_source).is_some());
        drop(second);
    }

    #[test]
    fn v2_is_preferred_and_hello_deadline_is_five_seconds() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            format!("{SUBPROTOCOL_V1}, {SUBPROTOCOL_V2}")
                .parse()
                .expect("valid header"),
        );
        assert_eq!(negotiated_wire(&headers), Some(WireLine::V2));
        assert_eq!(HELLO_TIMEOUT, Duration::from_secs(5));
    }
}
