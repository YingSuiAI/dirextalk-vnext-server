use dtx_domain::IdentityId;
use dtx_identity_log::{
    IDENTITY_LOG_WIRE_VERSION, IdentityLogEventPayloadV1, IdentityLogEventV1, IdentityLogPageV1,
    IdentityLogV1, MAX_IDENTITY_LOG_PAGE_EVENTS,
};
use dtx_wire::{SafeUint, Sha256Digest, UtcMillis, WireVersion};
use sqlx::{PgConnection, Row};

use crate::types::request_digest;
use crate::{
    DeviceRevokeCommand, DeviceSessionCredential, DeviceSessionRepository, IdentityAppendCommand,
    IdentityAppendOutcome, IdentityAppendReceipt, IdentityCommandPhase, IdentityForkEvidence,
    IdentityLogHead, IdentityLogSnapshot, IdentityPersistenceError, IdentityPgStore,
};

const ACTIVE_LOG_STATE: &str = "active";
const TOMBSTONED_LOG_STATE: &str = "tombstoned";
const FORKED_LOG_STATE: &str = "forked";
const COMMITTED_RECEIPT_STATE: &str = "committed";
const FORKED_RECEIPT_STATE: &str = "forked";
const REALTIME_DEVICE_SUBJECT_DOMAIN: &[u8] = b"dirextalk.realtime-device-subject.v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LogState {
    Active,
    Tombstoned,
    Forked,
}

impl LogState {
    fn parse(value: &str) -> Result<Self, IdentityPersistenceError> {
        match value {
            ACTIVE_LOG_STATE => Ok(Self::Active),
            TOMBSTONED_LOG_STATE => Ok(Self::Tombstoned),
            FORKED_LOG_STATE => Ok(Self::Forked),
            _ => Err(IdentityPersistenceError::CorruptData("identity log state")),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct StoredHead {
    head: IdentityLogHead,
    state: LogState,
}

enum CommandClaim {
    Execute,
    Replay(IdentityAppendReceipt),
    Forked(IdentityAppendReceipt),
}

enum AppendDecision {
    Appended(IdentityLogHead),
    Forked(IdentityForkEvidence),
}

/// Public outcome of a bounded read-only identity-log page request.
///
/// Not-found, inactive, and ahead-of-source are intentionally distinct only
/// for the HTTP boundary's documented status mapping; no durable state is
/// mutated by a read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentityLogPageReadOutcome {
    /// The requested active log produced one exact canonical page.
    Page(IdentityLogPageV1),
    /// No identity log exists for the requested self-certifying ID.
    NotFound,
    /// The durable log is tombstoned or has fork evidence.
    Inactive,
    /// The caller's cursor is newer than the source's committed head.
    CursorAhead,
}

/// Durable repository for the exact current identity-log wire line.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdentityLogRepository;

impl IdentityLogRepository {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Validates, reduces, and appends one exact signed event in a single
    /// transaction with its CAS head, durable idempotency receipt, and relay
    /// replication outbox row.
    ///
    /// A caller must pass trusted server time; signer-provided event time never
    /// becomes the command commit timestamp.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for invalid exact bytes, authorization or
    /// reducer rejection, stale heads, idempotency conflicts, storage faults,
    /// or an incomplete transaction.
    pub async fn append(
        self,
        store: &IdentityPgStore,
        command: &IdentityAppendCommand,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        let (event, identity_id, request_digest) = prepare_append_command(command)?;
        let mut session = store.begin().await?;
        let outcome = self
            .append_verified_in_transaction(
                session.connection(),
                command,
                &event,
                identity_id,
                request_digest,
                committed_at,
            )
            .await;
        match outcome {
            Ok(outcome) => {
                session.commit().await?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Appends a self-authenticated genesis event with a bootstrap-only,
    /// globally scoped idempotency claim in the same transaction as the
    /// identity head, receipt, and outbox row.
    ///
    /// Ordinary identity-log appends deliberately retain their established
    /// per-identity idempotency scope; only the anonymous bootstrap transport
    /// needs to prevent a response-loss retry from creating a second identity.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error when the command is not an exact V1.1
    /// genesis, its bootstrap key was reused for a different body or identity,
    /// or the atomic append cannot complete.
    pub async fn append_bootstrap(
        self,
        store: &IdentityPgStore,
        command: &IdentityAppendCommand,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        let (event, identity_id, request_digest) = prepare_append_command(command)?;
        validate_bootstrap_shape(command, &event)?;

        let mut session = store.begin().await?;
        let outcome = async {
            claim_bootstrap_command(
                session.connection(),
                identity_id,
                command.idempotency_key_hash(),
                request_digest,
                committed_at,
            )
            .await?;
            self.append_verified_in_transaction(
                session.connection(),
                command,
                &event,
                identity_id,
                request_digest,
                committed_at,
            )
            .await
        }
        .await;
        match outcome {
            Ok(outcome) => {
                session.commit().await?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Appends the root-authorized first device after genesis.
    ///
    /// The first device is the only device enrollment that can be authorized
    /// directly by the root log event: bootstrap deliberately creates no
    /// `DeviceCertificate`, so there is no active device session yet. Later
    /// QR enrollment must use a separately authenticated active-device session.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error unless the exact event is sequence two,
    /// references the supplied genesis hash, and reduces from a device-empty
    /// active identity log using the existing root authorization rules.
    pub async fn append_initial_device(
        self,
        store: &IdentityPgStore,
        idempotency_key_hash: Sha256Digest,
        expected_genesis_hash: Sha256Digest,
        exact_event_bytes: Vec<u8>,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        let event = IdentityLogEventV1::decode_and_verify(&exact_event_bytes)?;
        validate_initial_device_shape(&event, expected_genesis_hash)?;
        let expected_head = IdentityLogHead::new(
            event.identity_id(),
            IDENTITY_LOG_WIRE_VERSION,
            SafeUint::new(1)
                .map_err(|_| IdentityPersistenceError::CorruptData("identity genesis sequence"))?,
            expected_genesis_hash,
        );
        let command = IdentityAppendCommand::new(
            idempotency_key_hash,
            Some(expected_head),
            exact_event_bytes,
        )?;
        self.append(store, &command, committed_at).await
    }

    /// Atomically revokes another device using an active device session and
    /// one exact root-signed V1.1 `DeviceRevoke` event.
    ///
    /// A byte-identical durable replay is recovered before session
    /// reauthentication. This lets a caller recover the original receipt after
    /// response loss even when either the initiator or target was subsequently
    /// revoked. A new or changed request still requires an active session.
    ///
    /// # Errors
    ///
    /// Rejects path/body/head mismatch, non-revoke or non-V1.1 events,
    /// inactive sessions, self-revoke by the current session, stale heads,
    /// reused idempotency keys with different requests, and storage failures.
    pub async fn revoke_device(
        self,
        store: &IdentityPgStore,
        command: &DeviceRevokeCommand,
        credential: &DeviceSessionCredential,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        let event = IdentityLogEventV1::decode_and_verify(command.exact_event_bytes())?;
        validate_device_revoke_shape(command, &event)?;
        let previous_sequence = event
            .sequence()
            .get()
            .checked_sub(1)
            .filter(|sequence| *sequence > 0)
            .ok_or(IdentityPersistenceError::InvalidCommand(
                "device revoke predecessor sequence",
            ))?;
        let previous_hash =
            event
                .previous_event_hash()
                .ok_or(IdentityPersistenceError::InvalidCommand(
                    "device revoke predecessor hash",
                ))?;
        let expected_head = IdentityLogHead::new(
            command.identity_id(),
            event.wire(),
            SafeUint::new(previous_sequence).map_err(|_| {
                IdentityPersistenceError::InvalidCommand("device revoke predecessor sequence")
            })?,
            previous_hash,
        );
        let append = IdentityAppendCommand::new(
            command.idempotency_key_hash(),
            Some(expected_head),
            command.exact_event_bytes().to_vec(),
        )?;
        let request_digest = request_digest(&append, command.identity_id())?;

        let mut session = store.begin().await?;
        let result = async {
            if let Some(replay) = existing_command_outcome(
                session.connection(),
                command.identity_id(),
                command.idempotency_key_hash(),
                request_digest,
            )
            .await?
            {
                return Ok(replay);
            }

            let authenticated = DeviceSessionRepository::authenticate_in_transaction(
                session.connection(),
                credential,
                committed_at,
            )
            .await?;
            if authenticated.identity_id() != command.identity_id() {
                return Err(IdentityPersistenceError::DeviceAuthenticationRejected);
            }
            if authenticated.device_id() == command.target_device_id() {
                return Err(IdentityPersistenceError::CurrentSessionDeviceRevokeForbidden);
            }

            self.append_verified_in_transaction(
                session.connection(),
                &append,
                &event,
                command.identity_id(),
                request_digest,
                committed_at,
            )
            .await
        }
        .await;
        match result {
            Ok(outcome) => {
                session.commit().await?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Rehydrates the exact public head and pure reducer projection after a
    /// process restart. A malformed row is never treated as authorization fact.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed error for an inactive identity, database failure,
    /// or any row that cannot reproduce the exact verified projection.
    pub async fn load(
        self,
        store: &IdentityPgStore,
        identity_id: IdentityId,
    ) -> Result<Option<IdentityLogSnapshot>, IdentityPersistenceError> {
        let mut session = store.begin().await?;
        let result = async {
            lock_identity(session.connection(), identity_id).await?;
            let Some(stored) = load_stored_head(session.connection(), identity_id).await? else {
                return Ok(None);
            };
            if stored.state != LogState::Active {
                return Err(IdentityPersistenceError::IdentityInactive);
            }
            load_snapshot_for_head(session.connection(), stored)
                .await
                .map(Some)
        }
        .await;
        match result {
            Ok(snapshot) => {
                session.commit().await?;
                Ok(snapshot)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    /// Reads one bounded immutable prefix of an active identity log.
    ///
    /// The identity advisory lock holds the head and returned event range
    /// stable for this transaction. Exact rows are re-verified before they are
    /// emitted so a corrupt persistence row never becomes a remote trust fact.
    ///
    /// # Errors
    ///
    /// Returns a storage or corruption error. Semantic read outcomes are
    /// represented explicitly so the transport can return its stable public
    /// statuses without treating a missing log as a database failure.
    #[allow(
        clippy::too_many_lines,
        reason = "one transaction keeps head locking, durable-row validation, and bounded page construction auditable together"
    )]
    pub async fn read_page(
        self,
        store: &IdentityPgStore,
        identity_id: IdentityId,
        after_sequence: u64,
        limit: usize,
    ) -> Result<IdentityLogPageReadOutcome, IdentityPersistenceError> {
        if SafeUint::new(after_sequence).is_err()
            || limit == 0
            || limit > MAX_IDENTITY_LOG_PAGE_EVENTS
        {
            return Err(IdentityPersistenceError::InvalidCommand(
                "identity log page range",
            ));
        }

        let mut session = store.begin().await?;
        let result = async {
            lock_identity(session.connection(), identity_id).await?;
            let Some(stored) = load_stored_head(session.connection(), identity_id).await? else {
                return Ok(IdentityLogPageReadOutcome::NotFound);
            };
            if stored.state != LogState::Active {
                return Ok(IdentityLogPageReadOutcome::Inactive);
            }
            if after_sequence > stored.head.sequence().get() {
                return Ok(IdentityLogPageReadOutcome::CursorAhead);
            }

            // The advertised head is itself a remote trust fact, including
            // for an empty terminal page. Rehydrate its exact row before
            // emitting it so a stale/corrupt head projection fails closed.
            let stored_head_entry =
                load_entry_by_sequence(session.connection(), identity_id, stored.head.sequence())
                    .await?
                    .ok_or(IdentityPersistenceError::CorruptData(
                        "identity log page head entry",
                    ))?;
            if stored_head_entry.entry_hash != stored.head.hash() {
                return Err(IdentityPersistenceError::CorruptData(
                    "identity log page head hash",
                ));
            }

            // `IdentityLogPageV1` can validate the links within a page, but
            // it deliberately has no hidden predecessor input. Validate the
            // persisted cursor row here so the first returned event cannot
            // cross a corrupted page boundary.
            let mut previous_entry_hash = if after_sequence == 0 {
                None
            } else if after_sequence == stored.head.sequence().get() {
                Some(stored_head_entry.entry_hash)
            } else {
                let cursor = SafeUint::new(after_sequence).map_err(|_| {
                    IdentityPersistenceError::InvalidCommand("identity log page cursor")
                })?;
                let predecessor = load_entry_by_sequence(session.connection(), identity_id, cursor)
                    .await?
                    .ok_or(IdentityPersistenceError::CorruptData(
                        "identity log page predecessor entry",
                    ))?;
                Some(predecessor.entry_hash)
            };

            let rows =
                sqlx::query(
                    "SELECT sequence, entry_hash, previous_hash,
                        protocol_major, protocol_minor,
                        minimum_reader_major, minimum_reader_minor,
                        event_bytes
                   FROM identity.log_entries
                  WHERE identity_id=$1
                    AND sequence > $2
                    AND sequence <= $3
                  ORDER BY sequence ASC
                  LIMIT $4",
                )
                .bind(identity_id.to_string())
                .bind(to_i64(SafeUint::new(after_sequence).map_err(|_| {
                    IdentityPersistenceError::InvalidCommand("identity log page cursor")
                })?)?)
                .bind(to_i64(stored.head.sequence())?)
                .bind(i64::try_from(limit).map_err(|_| {
                    IdentityPersistenceError::InvalidCommand("identity log page limit")
                })?)
                .fetch_all(&mut *session.connection())
                .await?;

            if rows.is_empty() && after_sequence < stored.head.sequence().get() {
                return Err(IdentityPersistenceError::CorruptData(
                    "identity log page entries",
                ));
            }

            let mut exact_events = Vec::with_capacity(rows.len());
            let mut page = None;
            for row in rows {
                let entry = decode_entry_row(&row, identity_id)?;
                if let Some(expected_previous_hash) = previous_entry_hash
                    && entry.event.previous_event_hash() != Some(expected_previous_hash)
                {
                    return Err(IdentityPersistenceError::CorruptData(
                        "identity log page predecessor link",
                    ));
                }
                previous_entry_hash = Some(entry.entry_hash);
                exact_events.push(entry.exact_bytes);
                let next_after_sequence = after_sequence
                    .checked_add(u64::try_from(exact_events.len()).map_err(|_| {
                        IdentityPersistenceError::CorruptData("identity log page event count")
                    })?)
                    .ok_or(IdentityPersistenceError::CorruptData(
                        "identity log page next cursor",
                    ))?;
                let has_more = next_after_sequence < stored.head.sequence().get();
                match IdentityLogPageV1::new(
                    identity_id,
                    stored.head.sequence(),
                    stored.head.hash(),
                    after_sequence,
                    exact_events.clone(),
                    next_after_sequence,
                    has_more,
                ) {
                    Ok(candidate) => page = Some(candidate),
                    Err(dtx_identity_log::IdentityLogPageError::PageTooLarge) => {
                        let _ = exact_events.pop();
                        break;
                    }
                    Err(_) => {
                        return Err(IdentityPersistenceError::CorruptData(
                            "identity log page projection",
                        ));
                    }
                }
            }

            let page = match page {
                Some(page) => page,
                None if after_sequence == stored.head.sequence().get() => IdentityLogPageV1::new(
                    identity_id,
                    stored.head.sequence(),
                    stored.head.hash(),
                    after_sequence,
                    Vec::new(),
                    after_sequence,
                    false,
                )
                .map_err(|_| IdentityPersistenceError::CorruptData("identity log empty page"))?,
                None => {
                    return Err(IdentityPersistenceError::CorruptData(
                        "identity log page size",
                    ));
                }
            };
            Ok(IdentityLogPageReadOutcome::Page(page))
        }
        .await;
        match result {
            Ok(outcome) => {
                session.commit().await?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = session.rollback().await;
                Err(error)
            }
        }
    }

    async fn append_verified_in_transaction(
        self,
        connection: &mut PgConnection,
        command: &IdentityAppendCommand,
        event: &IdentityLogEventV1,
        identity_id: IdentityId,
        request_digest: Sha256Digest,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        lock_identity(connection, identity_id).await?;
        match claim_command(
            connection,
            identity_id,
            command.idempotency_key_hash(),
            request_digest,
            committed_at,
        )
        .await?
        {
            CommandClaim::Replay(receipt) => return Ok(IdentityAppendOutcome::Replayed(receipt)),
            CommandClaim::Forked(receipt) => {
                let evidence = load_fork_evidence_for_command(
                    connection,
                    identity_id,
                    command.idempotency_key_hash(),
                )
                .await?;
                if receipt.head() != evidence.observed_head()
                    || receipt.phase() != IdentityCommandPhase::Reconciling
                {
                    return Err(IdentityPersistenceError::CorruptData(
                        "forked receipt evidence",
                    ));
                }
                return Ok(IdentityAppendOutcome::Forked { receipt, evidence });
            }
            CommandClaim::Execute => {}
        }

        let decision = match load_stored_head(connection, identity_id).await? {
            None => AppendDecision::Appended(
                bootstrap_identity(connection, event, command.exact_event_bytes(), committed_at)
                    .await?,
            ),
            Some(stored) => {
                append_existing_identity(
                    connection,
                    command,
                    event,
                    command.exact_event_bytes(),
                    stored,
                    committed_at,
                )
                .await?
            }
        };

        append_realtime_identity_invalidation(connection, event, &decision).await?;

        resolve_append_decision(connection, command, request_digest, committed_at, decision).await
    }

    /// Runs the normal exact identity append inside a caller-owned validated
    /// identity transaction.
    ///
    /// This is intentionally crate-private: higher-level durable workflows
    /// (such as QR device enrollment) must retain their own authorization,
    /// capability, state transition, append receipt, and outbox work in one
    /// `PostgreSQL` transaction. HTTP callers continue to use [`Self::append`]
    /// and never construct an [`IdentityLogHead`] themselves.
    pub(crate) async fn append_in_transaction(
        self,
        connection: &mut PgConnection,
        command: &IdentityAppendCommand,
        committed_at: UtcMillis,
    ) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
        let (event, identity_id, request_digest) = prepare_append_command(command)?;
        self.append_verified_in_transaction(
            connection,
            command,
            &event,
            identity_id,
            request_digest,
            committed_at,
        )
        .await
    }
}

async fn append_realtime_identity_invalidation(
    connection: &mut PgConnection,
    event: &IdentityLogEventV1,
    decision: &AppendDecision,
) -> Result<(), IdentityPersistenceError> {
    let (event_kind, subject_digest) = match decision {
        AppendDecision::Forked(evidence) => {
            ("identity_head_changed", evidence.observed_head().hash())
        }
        AppendDecision::Appended(head) => match event.payload() {
            IdentityLogEventPayloadV1::DeviceRevoke { device_id } => (
                "device_revoked",
                Sha256Digest::hash_domain(
                    REALTIME_DEVICE_SUBJECT_DOMAIN,
                    device_id.as_uuid().as_bytes(),
                ),
            ),
            IdentityLogEventPayloadV1::RootRotate { .. }
            | IdentityLogEventPayloadV1::RecoveryRotate { .. }
            | IdentityLogEventPayloadV1::RecoveryRestore { .. } => {
                ("key_authorization_changed", head.hash())
            }
            IdentityLogEventPayloadV1::Genesis { .. }
            | IdentityLogEventPayloadV1::DeviceAdd { .. }
            | IdentityLogEventPayloadV1::RelayDescriptor { .. } => {
                ("identity_head_changed", head.hash())
            }
        },
    };
    let _: i64 = sqlx::query_scalar("SELECT realtime.append_identity_invalidation($1,$2,$3)")
        .bind(event.identity_id().to_string())
        .bind(event_kind)
        .bind(subject_digest.as_bytes().as_slice())
        .fetch_one(&mut *connection)
        .await?;
    Ok(())
}

fn validate_device_revoke_shape(
    command: &DeviceRevokeCommand,
    event: &IdentityLogEventV1,
) -> Result<(), IdentityPersistenceError> {
    if event.wire() != IDENTITY_LOG_WIRE_VERSION
        || event.identity_id() != command.identity_id()
        || event.previous_event_hash() != Some(command.expected_head_hash())
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "device revoke event binding",
        ));
    }
    match event.payload() {
        IdentityLogEventPayloadV1::DeviceRevoke { device_id }
            if *device_id == command.target_device_id() =>
        {
            Ok(())
        }
        IdentityLogEventPayloadV1::DeviceRevoke { .. } => Err(
            IdentityPersistenceError::InvalidCommand("device revoke target binding"),
        ),
        _ => Err(IdentityPersistenceError::InvalidCommand(
            "device revoke event kind",
        )),
    }
}

async fn resolve_append_decision(
    connection: &mut PgConnection,
    command: &IdentityAppendCommand,
    request_digest: Sha256Digest,
    committed_at: UtcMillis,
    decision: AppendDecision,
) -> Result<IdentityAppendOutcome, IdentityPersistenceError> {
    match decision {
        AppendDecision::Appended(head) => {
            insert_outbox(connection, head, committed_at).await?;
            let receipt = IdentityAppendReceipt::new(
                head,
                request_digest,
                IdentityCommandPhase::Committed,
                committed_at,
            )?;
            complete_command(
                connection,
                head.identity_id(),
                command.idempotency_key_hash(),
                &receipt,
                COMMITTED_RECEIPT_STATE,
            )
            .await?;
            Ok(IdentityAppendOutcome::Committed(receipt))
        }
        AppendDecision::Forked(evidence) => {
            let receipt = IdentityAppendReceipt::new(
                evidence.observed_head(),
                request_digest,
                IdentityCommandPhase::Reconciling,
                committed_at,
            )?;
            complete_command(
                connection,
                evidence.observed_head().identity_id(),
                command.idempotency_key_hash(),
                &receipt,
                FORKED_RECEIPT_STATE,
            )
            .await?;
            Ok(IdentityAppendOutcome::Forked { receipt, evidence })
        }
    }
}

async fn bootstrap_identity(
    connection: &mut PgConnection,
    event: &IdentityLogEventV1,
    exact_event_bytes: &[u8],
    committed_at: UtcMillis,
) -> Result<IdentityLogHead, IdentityPersistenceError> {
    let projection = IdentityLogV1::bootstrap(event)?;
    let head = head_from_projection(&projection);
    insert_head(connection, head, committed_at).await?;
    insert_entry(connection, event, exact_event_bytes, committed_at).await?;
    Ok(head)
}

async fn append_existing_identity(
    connection: &mut PgConnection,
    command: &IdentityAppendCommand,
    event: &IdentityLogEventV1,
    exact_event_bytes: &[u8],
    stored: StoredHead,
    committed_at: UtcMillis,
) -> Result<AppendDecision, IdentityPersistenceError> {
    if stored.state != LogState::Active {
        return Err(IdentityPersistenceError::IdentityInactive);
    }
    let snapshot = load_snapshot_for_head(connection, stored).await?;
    if is_verified_divergence(&snapshot, event)? {
        let evidence = insert_fork_evidence(
            connection,
            command,
            snapshot.head(),
            event,
            exact_event_bytes,
            committed_at,
        )
        .await?;
        mark_log_forked(connection, snapshot.head()).await?;
        return Ok(AppendDecision::Forked(evidence));
    }
    if event.sequence().get() == 1 {
        return Err(IdentityPersistenceError::GenesisConflict);
    }
    let expected = command
        .expected_head()
        .ok_or(IdentityPersistenceError::InvalidCommand(
            "non-genesis identity append needs expected head",
        ))?;
    if expected != snapshot.head() {
        return Err(IdentityPersistenceError::HeadConflict {
            current: Some(snapshot.head()),
        });
    }
    let mut projection = snapshot.projection().clone();
    projection.append(event)?;
    let proposed = head_from_projection(&projection);
    insert_entry(connection, event, exact_event_bytes, committed_at).await?;
    let updated = sqlx::query(
        "UPDATE identity.log_heads
            SET head_sequence=$2, head_hash=$3, updated_at_ms=$4
          WHERE identity_id=$1
            AND state='active'
            AND head_sequence=$5
            AND head_hash=$6",
    )
    .bind(event.identity_id().to_string())
    .bind(to_i64(proposed.sequence())?)
    .bind(proposed.hash().as_bytes().as_slice())
    .bind(committed_at.get())
    .bind(to_i64(snapshot.head().sequence())?)
    .bind(snapshot.head().hash().as_bytes().as_slice())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated != 1 {
        return Err(current_head_conflict(connection, event.identity_id()).await?);
    }
    Ok(AppendDecision::Appended(proposed))
}

fn is_verified_divergence(
    snapshot: &IdentityLogSnapshot,
    candidate: &IdentityLogEventV1,
) -> Result<bool, IdentityPersistenceError> {
    if candidate.sequence().get() > snapshot.head().sequence().get() {
        return Ok(false);
    }
    let index = sequence_index(candidate.sequence())?;
    let canonical_bytes =
        snapshot
            .exact_events()
            .get(index)
            .ok_or(IdentityPersistenceError::CorruptData(
                "identity fork canonical entry",
            ))?;
    let canonical = IdentityLogEventV1::decode_and_verify(canonical_bytes)
        .map_err(|_| IdentityPersistenceError::CorruptData("identity fork canonical entry"))?;
    if canonical.entry_hash()? == candidate.entry_hash()? {
        return Ok(false);
    }
    if candidate.sequence().get() == 1 {
        return Ok(IdentityLogV1::bootstrap(candidate).is_ok());
    }
    let mut predecessor = projection_before_sequence(snapshot, candidate.sequence())?;
    Ok(predecessor.append(candidate).is_ok())
}

fn projection_before_sequence(
    snapshot: &IdentityLogSnapshot,
    sequence: SafeUint,
) -> Result<IdentityLogV1, IdentityPersistenceError> {
    let predecessor_count = sequence_index(sequence)?;
    let predecessor_bytes = snapshot.exact_events().get(..predecessor_count).ok_or(
        IdentityPersistenceError::CorruptData("identity fork predecessor entries"),
    )?;
    let (genesis_bytes, following) =
        predecessor_bytes
            .split_first()
            .ok_or(IdentityPersistenceError::CorruptData(
                "identity fork predecessor genesis",
            ))?;
    let genesis = IdentityLogEventV1::decode_and_verify(genesis_bytes)
        .map_err(|_| IdentityPersistenceError::CorruptData("identity fork predecessor genesis"))?;
    let mut projection = IdentityLogV1::bootstrap(&genesis)
        .map_err(|_| IdentityPersistenceError::CorruptData("identity fork predecessor genesis"))?;
    for exact_bytes in following {
        let event = IdentityLogEventV1::decode_and_verify(exact_bytes).map_err(|_| {
            IdentityPersistenceError::CorruptData("identity fork predecessor entry")
        })?;
        projection.append(&event).map_err(|_| {
            IdentityPersistenceError::CorruptData("identity fork predecessor entry")
        })?;
    }
    Ok(projection)
}

async fn insert_fork_evidence(
    connection: &mut PgConnection,
    command: &IdentityAppendCommand,
    observed_head: IdentityLogHead,
    candidate: &IdentityLogEventV1,
    exact_candidate_bytes: &[u8],
    recorded_at: UtcMillis,
) -> Result<IdentityForkEvidence, IdentityPersistenceError> {
    let candidate_head = IdentityLogHead::new(
        candidate.identity_id(),
        candidate.wire(),
        candidate.sequence(),
        candidate.entry_hash()?,
    );
    let wire = candidate_head.wire();
    sqlx::query(
        "INSERT INTO identity.fork_evidence (
             identity_id, candidate_entry_hash, candidate_sequence, candidate_previous_hash,
             candidate_protocol_major, candidate_protocol_minor,
             candidate_minimum_reader_major, candidate_minimum_reader_minor,
             observed_head_sequence, observed_head_hash, idempotency_key_hash,
             event_bytes, recorded_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(candidate_head.identity_id().to_string())
    .bind(candidate_head.hash().as_bytes().as_slice())
    .bind(to_i64(candidate_head.sequence())?)
    .bind(
        candidate
            .previous_event_hash()
            .map(|hash| hash.as_bytes().to_vec()),
    )
    .bind(i16::try_from(wire.protocol.major()).expect("identity wire major fits smallint"))
    .bind(i16::try_from(wire.protocol.minor()).expect("identity wire minor fits smallint"))
    .bind(
        i16::try_from(wire.minimum_reader.major())
            .expect("identity minimum reader major fits smallint"),
    )
    .bind(
        i16::try_from(wire.minimum_reader.minor())
            .expect("identity minimum reader minor fits smallint"),
    )
    .bind(to_i64(observed_head.sequence())?)
    .bind(observed_head.hash().as_bytes().as_slice())
    .bind(command.idempotency_key_hash().as_bytes().as_slice())
    .bind(exact_candidate_bytes)
    .bind(recorded_at.get())
    .execute(&mut *connection)
    .await?;
    Ok(IdentityForkEvidence::new(
        observed_head,
        candidate_head,
        exact_candidate_bytes.to_vec(),
    ))
}

async fn mark_log_forked(
    connection: &mut PgConnection,
    observed_head: IdentityLogHead,
) -> Result<(), IdentityPersistenceError> {
    let updated = sqlx::query(
        "UPDATE identity.log_heads
            SET state='forked'
          WHERE identity_id=$1
            AND state='active'
            AND head_sequence=$2
            AND head_hash=$3",
    )
    .bind(observed_head.identity_id().to_string())
    .bind(to_i64(observed_head.sequence())?)
    .bind(observed_head.hash().as_bytes().as_slice())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(current_head_conflict(connection, observed_head.identity_id()).await?)
    }
}

fn prepare_append_command(
    command: &IdentityAppendCommand,
) -> Result<(IdentityLogEventV1, IdentityId, Sha256Digest), IdentityPersistenceError> {
    let event = IdentityLogEventV1::decode_and_verify(command.exact_event_bytes())?;
    if event.wire() != IDENTITY_LOG_WIRE_VERSION {
        return Err(IdentityPersistenceError::IdentityLog(
            dtx_identity_log::IdentityLogError::InvalidWireVersion,
        ));
    }
    validate_expected_shape(command, &event)?;
    let identity_id = event.identity_id();
    let request_digest = request_digest(command, identity_id)?;
    Ok((event, identity_id, request_digest))
}

fn validate_bootstrap_shape(
    command: &IdentityAppendCommand,
    event: &IdentityLogEventV1,
) -> Result<(), IdentityPersistenceError> {
    if command.expected_head().is_some()
        || event.sequence().get() != 1
        || event.previous_event_hash().is_some()
        || !matches!(event.payload(), IdentityLogEventPayloadV1::Genesis { .. })
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "identity bootstrap must be an exact genesis",
        ));
    }
    Ok(())
}

fn validate_initial_device_shape(
    event: &IdentityLogEventV1,
    expected_genesis_hash: Sha256Digest,
) -> Result<(), IdentityPersistenceError> {
    if event.wire() != IDENTITY_LOG_WIRE_VERSION
        || event.sequence().get() != 2
        || event.previous_event_hash() != Some(expected_genesis_hash)
        || !matches!(event.payload(), IdentityLogEventPayloadV1::DeviceAdd { .. })
    {
        return Err(IdentityPersistenceError::InvalidCommand(
            "initial device must be an exact sequence-two device add",
        ));
    }
    Ok(())
}

fn validate_expected_shape(
    command: &IdentityAppendCommand,
    event: &IdentityLogEventV1,
) -> Result<(), IdentityPersistenceError> {
    match (event.sequence().get(), command.expected_head()) {
        (1, None) => Ok(()),
        (1, Some(_)) => Err(IdentityPersistenceError::InvalidCommand(
            "genesis identity append cannot have expected head",
        )),
        (_, None) => Err(IdentityPersistenceError::InvalidCommand(
            "non-genesis identity append needs expected head",
        )),
        (_, Some(expected))
            if expected.identity_id() != event.identity_id()
                || expected.wire() != IDENTITY_LOG_WIRE_VERSION =>
        {
            Err(IdentityPersistenceError::InvalidCommand(
                "identity append expected head belongs to another wire or identity",
            ))
        }
        (_, Some(_)) => Ok(()),
    }
}

pub(crate) async fn lock_identity(
    connection: &mut PgConnection,
    identity_id: IdentityId,
) -> Result<(), IdentityPersistenceError> {
    let bytes = identity_id.digest_bytes();
    let key = i64::from_be_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| IdentityPersistenceError::CorruptData("identity advisory lock"))?,
    );
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

/// Locks and fully rehydrates one active identity log inside an existing
/// identity-only transaction. Authentication callers use this exact helper so
/// a device's active status cannot be read in one transaction and consumed in
/// a second transaction after a concurrent revoke or recovery restore.
/// Locks and reconstructs one active identity log at its exact committed head.
///
/// # Errors
///
/// Returns a persistence error for a missing, inactive, or corrupt identity log.
pub async fn lock_and_load_active_snapshot(
    connection: &mut PgConnection,
    identity_id: IdentityId,
) -> Result<IdentityLogSnapshot, IdentityPersistenceError> {
    lock_identity(connection, identity_id).await?;
    let stored = load_stored_head(connection, identity_id)
        .await?
        .ok_or(IdentityPersistenceError::IdentityInactive)?;
    if stored.state != LogState::Active {
        return Err(IdentityPersistenceError::IdentityInactive);
    }
    load_snapshot_for_head(connection, stored).await
}

/// Rehydrates one active identity log from the caller's already-established
/// read-only snapshot. Unlike [`lock_and_load_active_snapshot`], this never
/// acquires an advisory or row lock.
///
/// # Errors
///
/// Returns a persistence error for a missing, inactive, or corrupt identity log.
pub async fn load_active_snapshot_readonly(
    connection: &mut PgConnection,
    identity_id: IdentityId,
) -> Result<IdentityLogSnapshot, IdentityPersistenceError> {
    let stored = load_stored_head(connection, identity_id)
        .await?
        .ok_or(IdentityPersistenceError::IdentityInactive)?;
    if stored.state != LogState::Active {
        return Err(IdentityPersistenceError::IdentityInactive);
    }
    load_snapshot_for_head(connection, stored).await
}

async fn claim_bootstrap_command(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    idempotency_key_hash: Sha256Digest,
    request_digest: Sha256Digest,
    created_at: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.bootstrap_idempotency_claims (
             idempotency_key_hash, identity_id, request_digest, created_at_ms
         ) VALUES ($1,$2,$3,$4)
         ON CONFLICT DO NOTHING",
    )
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .bind(identity_id.to_string())
    .bind(request_digest.as_bytes().as_slice())
    .bind(created_at.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(());
    }

    // `INSERT .. ON CONFLICT DO NOTHING` has already waited for the unique
    // claim transaction. At read committed the durable conflicting row is now
    // visible, so an immutable claim needs no `FOR UPDATE` lock or UPDATE grant.
    let row = sqlx::query(
        "SELECT identity_id, request_digest
           FROM identity.bootstrap_idempotency_claims
          WHERE idempotency_key_hash=$1",
    )
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .fetch_one(&mut *connection)
    .await?;
    let stored_identity: String = row.try_get("identity_id")?;
    let stored_request = digest(
        &row.try_get::<Vec<u8>, _>("request_digest")?,
        "bootstrap claim request digest",
    )?;
    if stored_identity != identity_id.to_string() || stored_request != request_digest {
        return Err(IdentityPersistenceError::IdempotencyConflict);
    }
    Ok(())
}

async fn claim_command(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    idempotency_key_hash: Sha256Digest,
    request_digest: Sha256Digest,
    created_at: UtcMillis,
) -> Result<CommandClaim, IdentityPersistenceError> {
    let inserted = sqlx::query(
        "INSERT INTO identity.command_receipts (
             identity_id, idempotency_key_hash, request_digest, state, created_at_ms
         ) VALUES ($1,$2,$3,'pending',$4)
         ON CONFLICT DO NOTHING",
    )
    .bind(identity_id.to_string())
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .bind(request_digest.as_bytes().as_slice())
    .bind(created_at.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        return Ok(CommandClaim::Execute);
    }

    load_existing_command_claim(
        connection,
        identity_id,
        idempotency_key_hash,
        request_digest,
    )
    .await?
    .ok_or(IdentityPersistenceError::IncompleteCommand)
}

async fn existing_command_outcome(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    idempotency_key_hash: Sha256Digest,
    request_digest: Sha256Digest,
) -> Result<Option<IdentityAppendOutcome>, IdentityPersistenceError> {
    let Some(claim) = load_existing_command_claim(
        connection,
        identity_id,
        idempotency_key_hash,
        request_digest,
    )
    .await?
    else {
        return Ok(None);
    };
    match claim {
        CommandClaim::Replay(receipt) => Ok(Some(IdentityAppendOutcome::Replayed(receipt))),
        CommandClaim::Forked(receipt) => {
            let evidence =
                load_fork_evidence_for_command(connection, identity_id, idempotency_key_hash)
                    .await?;
            if receipt.head() != evidence.observed_head()
                || receipt.phase() != IdentityCommandPhase::Reconciling
            {
                return Err(IdentityPersistenceError::CorruptData(
                    "forked receipt evidence",
                ));
            }
            Ok(Some(IdentityAppendOutcome::Forked { receipt, evidence }))
        }
        CommandClaim::Execute => Err(IdentityPersistenceError::CorruptData(
            "stored identity command execution state",
        )),
    }
}

async fn load_existing_command_claim(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    idempotency_key_hash: Sha256Digest,
    request_digest: Sha256Digest,
) -> Result<Option<CommandClaim>, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT request_digest, state,
                receipt_protocol_major, receipt_protocol_minor,
                receipt_minimum_reader_major, receipt_minimum_reader_minor,
                receipt_sequence, receipt_head_hash, receipt_bytes,
                receipt_digest, committed_at_ms
           FROM identity.command_receipts
          WHERE identity_id=$1 AND idempotency_key_hash=$2
          FOR UPDATE",
    )
    .bind(identity_id.to_string())
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored_request = digest(
        &row.try_get::<Vec<u8>, _>("request_digest")?,
        "receipt request digest",
    )?;
    if stored_request != request_digest {
        return Err(IdentityPersistenceError::IdempotencyConflict);
    }
    let state: String = row.try_get("state")?;
    let phase = match state.as_str() {
        COMMITTED_RECEIPT_STATE => IdentityCommandPhase::Committed,
        FORKED_RECEIPT_STATE => IdentityCommandPhase::Reconciling,
        "pending" => return Err(IdentityPersistenceError::IncompleteCommand),
        _ => {
            return Err(IdentityPersistenceError::CorruptData(
                "identity command receipt state",
            ));
        }
    };
    let wire = parse_wire(
        row.try_get("receipt_protocol_major")?,
        row.try_get("receipt_protocol_minor")?,
        row.try_get("receipt_minimum_reader_major")?,
        row.try_get("receipt_minimum_reader_minor")?,
    )?;
    let sequence = safe_uint(row.try_get("receipt_sequence")?, "receipt sequence")?;
    let hash = digest(
        &row.try_get::<Vec<u8>, _>("receipt_head_hash")?,
        "receipt head hash",
    )?;
    let committed_at = utc_millis(row.try_get("committed_at_ms")?, "receipt committed time")?;
    let receipt = IdentityAppendReceipt::new(
        IdentityLogHead::new(identity_id, wire, sequence, hash),
        stored_request,
        phase,
        committed_at,
    )?;
    let stored_bytes: Vec<u8> = row.try_get("receipt_bytes")?;
    let stored_digest = digest(
        &row.try_get::<Vec<u8>, _>("receipt_digest")?,
        "receipt digest",
    )?;
    receipt.verify_exact_bytes(&stored_bytes, stored_digest)?;
    match phase {
        IdentityCommandPhase::Committed => Ok(Some(CommandClaim::Replay(receipt))),
        IdentityCommandPhase::Reconciling => Ok(Some(CommandClaim::Forked(receipt))),
        IdentityCommandPhase::Pending => Err(IdentityPersistenceError::CorruptData(
            "identity command receipt phase",
        )),
    }
}

async fn load_fork_evidence_for_command(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    idempotency_key_hash: Sha256Digest,
) -> Result<IdentityForkEvidence, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT candidate_entry_hash, candidate_sequence, candidate_previous_hash,
                candidate_protocol_major, candidate_protocol_minor,
                candidate_minimum_reader_major, candidate_minimum_reader_minor,
                observed_head_sequence, observed_head_hash, event_bytes
           FROM identity.fork_evidence
          WHERE identity_id=$1 AND idempotency_key_hash=$2",
    )
    .bind(identity_id.to_string())
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .fetch_optional(&mut *connection)
    .await?
    .ok_or(IdentityPersistenceError::CorruptData(
        "forked receipt evidence",
    ))?;
    let candidate_wire = parse_wire(
        row.try_get("candidate_protocol_major")?,
        row.try_get("candidate_protocol_minor")?,
        row.try_get("candidate_minimum_reader_major")?,
        row.try_get("candidate_minimum_reader_minor")?,
    )?;
    let candidate_sequence = safe_uint(
        row.try_get("candidate_sequence")?,
        "fork candidate sequence",
    )?;
    let candidate_hash = digest(
        &row.try_get::<Vec<u8>, _>("candidate_entry_hash")?,
        "fork candidate hash",
    )?;
    let candidate_previous = row
        .try_get::<Option<Vec<u8>>, _>("candidate_previous_hash")?
        .as_deref()
        .map(|value| digest(value, "fork candidate previous hash"))
        .transpose()?;
    let observed_sequence = safe_uint(
        row.try_get("observed_head_sequence")?,
        "fork observed head sequence",
    )?;
    let observed_hash = digest(
        &row.try_get::<Vec<u8>, _>("observed_head_hash")?,
        "fork observed head hash",
    )?;
    let exact_candidate_bytes: Vec<u8> = row.try_get("event_bytes")?;
    let event = IdentityLogEventV1::decode_and_verify(&exact_candidate_bytes)
        .map_err(|_| IdentityPersistenceError::CorruptData("fork candidate event"))?;
    if event.identity_id() != identity_id
        || event.wire() != candidate_wire
        || event.sequence() != candidate_sequence
        || event.previous_event_hash() != candidate_previous
        || event.entry_hash()? != candidate_hash
        || event.to_deterministic_cbor()? != exact_candidate_bytes
    {
        return Err(IdentityPersistenceError::CorruptData(
            "fork candidate evidence",
        ));
    }
    Ok(IdentityForkEvidence::new(
        IdentityLogHead::new(
            identity_id,
            IDENTITY_LOG_WIRE_VERSION,
            observed_sequence,
            observed_hash,
        ),
        IdentityLogHead::new(
            identity_id,
            candidate_wire,
            candidate_sequence,
            candidate_hash,
        ),
        exact_candidate_bytes,
    ))
}

async fn complete_command(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    idempotency_key_hash: Sha256Digest,
    receipt: &IdentityAppendReceipt,
    state: &'static str,
) -> Result<(), IdentityPersistenceError> {
    let head = receipt.head();
    let wire = head.wire();
    let updated = sqlx::query(
        "UPDATE identity.command_receipts
            SET state=$3,
                receipt_protocol_major=$4,
                receipt_protocol_minor=$5,
                receipt_minimum_reader_major=$6,
                receipt_minimum_reader_minor=$7,
                receipt_sequence=$8,
                receipt_head_hash=$9,
                receipt_bytes=$10,
                receipt_digest=$11,
                committed_at_ms=$12
          WHERE identity_id=$1 AND idempotency_key_hash=$2 AND state='pending'",
    )
    .bind(identity_id.to_string())
    .bind(idempotency_key_hash.as_bytes().as_slice())
    .bind(state)
    .bind(i16::try_from(wire.protocol.major()).expect("identity wire major fits smallint"))
    .bind(i16::try_from(wire.protocol.minor()).expect("identity wire minor fits smallint"))
    .bind(
        i16::try_from(wire.minimum_reader.major())
            .expect("identity minimum reader major fits smallint"),
    )
    .bind(
        i16::try_from(wire.minimum_reader.minor())
            .expect("identity minimum reader minor fits smallint"),
    )
    .bind(to_i64(head.sequence())?)
    .bind(head.hash().as_bytes().as_slice())
    .bind(receipt.exact_bytes())
    .bind(receipt.receipt_digest().as_bytes().as_slice())
    .bind(receipt.committed_at().get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if updated == 1 {
        Ok(())
    } else {
        Err(IdentityPersistenceError::IncompleteCommand)
    }
}

async fn insert_head(
    connection: &mut PgConnection,
    head: IdentityLogHead,
    recorded_at: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let wire = head.wire();
    let inserted = sqlx::query(
        "INSERT INTO identity.log_heads (
             identity_id, protocol_major, protocol_minor,
             minimum_reader_major, minimum_reader_minor,
             head_sequence, head_hash, state, created_at_ms, updated_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8,$8)
         ON CONFLICT DO NOTHING",
    )
    .bind(head.identity_id().to_string())
    .bind(i16::try_from(wire.protocol.major()).expect("identity wire major fits smallint"))
    .bind(i16::try_from(wire.protocol.minor()).expect("identity wire minor fits smallint"))
    .bind(
        i16::try_from(wire.minimum_reader.major())
            .expect("identity minimum reader major fits smallint"),
    )
    .bind(
        i16::try_from(wire.minimum_reader.minor())
            .expect("identity minimum reader minor fits smallint"),
    )
    .bind(to_i64(head.sequence())?)
    .bind(head.hash().as_bytes().as_slice())
    .bind(recorded_at.get())
    .execute(&mut *connection)
    .await?
    .rows_affected();
    if inserted == 1 {
        Ok(())
    } else {
        Err(IdentityPersistenceError::GenesisConflict)
    }
}

async fn insert_entry(
    connection: &mut PgConnection,
    event: &IdentityLogEventV1,
    exact_event_bytes: &[u8],
    recorded_at: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    let entry_hash = event.entry_hash()?;
    let wire = event.wire();
    sqlx::query(
        "INSERT INTO identity.log_entries (
             identity_id, sequence, entry_hash, previous_hash,
             protocol_major, protocol_minor, minimum_reader_major, minimum_reader_minor,
             event_bytes, recorded_at_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(event.identity_id().to_string())
    .bind(to_i64(event.sequence())?)
    .bind(entry_hash.as_bytes().as_slice())
    .bind(
        event
            .previous_event_hash()
            .map(|hash| hash.as_bytes().to_vec()),
    )
    .bind(i16::try_from(wire.protocol.major()).expect("identity wire major fits smallint"))
    .bind(i16::try_from(wire.protocol.minor()).expect("identity wire minor fits smallint"))
    .bind(
        i16::try_from(wire.minimum_reader.major())
            .expect("identity minimum reader major fits smallint"),
    )
    .bind(
        i16::try_from(wire.minimum_reader.minor())
            .expect("identity minimum reader minor fits smallint"),
    )
    .bind(exact_event_bytes)
    .bind(recorded_at.get())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn insert_outbox(
    connection: &mut PgConnection,
    head: IdentityLogHead,
    available_at: UtcMillis,
) -> Result<(), IdentityPersistenceError> {
    sqlx::query(
        "INSERT INTO identity.log_outbox (
             identity_id, entry_hash, topic, available_at_ms, attempt_count
         ) VALUES ($1,$2,'identity_log_append',$3,0)",
    )
    .bind(head.identity_id().to_string())
    .bind(head.hash().as_bytes().as_slice())
    .bind(available_at.get())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn load_stored_head(
    connection: &mut PgConnection,
    identity_id: IdentityId,
) -> Result<Option<StoredHead>, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT protocol_major, protocol_minor,
                minimum_reader_major, minimum_reader_minor,
                head_sequence, head_hash, state
           FROM identity.log_heads
          WHERE identity_id=$1",
    )
    .bind(identity_id.to_string())
    .fetch_optional(&mut *connection)
    .await?;
    row.map(|row| {
        let wire = parse_wire(
            row.try_get("protocol_major")?,
            row.try_get("protocol_minor")?,
            row.try_get("minimum_reader_major")?,
            row.try_get("minimum_reader_minor")?,
        )?;
        let sequence = safe_uint(row.try_get("head_sequence")?, "head sequence")?;
        let hash = digest(&row.try_get::<Vec<u8>, _>("head_hash")?, "head hash")?;
        Ok(StoredHead {
            head: IdentityLogHead::new(identity_id, wire, sequence, hash),
            state: LogState::parse(row.try_get("state")?)?,
        })
    })
    .transpose()
}

async fn load_snapshot_for_head(
    connection: &mut PgConnection,
    stored: StoredHead,
) -> Result<IdentityLogSnapshot, IdentityPersistenceError> {
    let rows = sqlx::query(
        "SELECT sequence, entry_hash, previous_hash,
                protocol_major, protocol_minor,
                minimum_reader_major, minimum_reader_minor,
                event_bytes
           FROM identity.log_entries
          WHERE identity_id=$1
          ORDER BY sequence ASC",
    )
    .bind(stored.head.identity_id().to_string())
    .fetch_all(&mut *connection)
    .await?;
    let (first, rest) = rows
        .split_first()
        .ok_or(IdentityPersistenceError::CorruptData(
            "identity log entries",
        ))?;
    let first_event = decode_entry_row(first, stored.head.identity_id())?;
    let mut projection = IdentityLogV1::bootstrap(&first_event.event)?;
    let mut exact_events = vec![first_event.exact_bytes];
    for row in rest {
        let entry = decode_entry_row(row, stored.head.identity_id())?;
        projection.append(&entry.event)?;
        exact_events.push(entry.exact_bytes);
    }
    let actual = head_from_projection(&projection);
    if actual != stored.head {
        return Err(IdentityPersistenceError::CorruptData(
            "identity log head projection",
        ));
    }
    Ok(IdentityLogSnapshot::new(
        stored.head,
        projection,
        exact_events,
    ))
}

struct DecodedEntry {
    event: IdentityLogEventV1,
    exact_bytes: Vec<u8>,
    entry_hash: Sha256Digest,
}

async fn load_entry_by_sequence(
    connection: &mut PgConnection,
    identity_id: IdentityId,
    sequence: SafeUint,
) -> Result<Option<DecodedEntry>, IdentityPersistenceError> {
    let row = sqlx::query(
        "SELECT sequence, entry_hash, previous_hash,
                protocol_major, protocol_minor,
                minimum_reader_major, minimum_reader_minor,
                event_bytes
           FROM identity.log_entries
          WHERE identity_id=$1 AND sequence=$2",
    )
    .bind(identity_id.to_string())
    .bind(to_i64(sequence)?)
    .fetch_optional(&mut *connection)
    .await?;
    row.map(|row| decode_entry_row(&row, identity_id))
        .transpose()
}

fn decode_entry_row(
    row: &sqlx::postgres::PgRow,
    expected_identity_id: IdentityId,
) -> Result<DecodedEntry, IdentityPersistenceError> {
    let sequence = safe_uint(row.try_get("sequence")?, "entry sequence")?;
    let stored_hash = digest(&row.try_get::<Vec<u8>, _>("entry_hash")?, "entry hash")?;
    let stored_previous: Option<Vec<u8>> = row.try_get("previous_hash")?;
    let stored_previous = stored_previous
        .as_deref()
        .map(|value| digest(value, "entry previous hash"))
        .transpose()?;
    let wire = parse_wire(
        row.try_get("protocol_major")?,
        row.try_get("protocol_minor")?,
        row.try_get("minimum_reader_major")?,
        row.try_get("minimum_reader_minor")?,
    )?;
    let exact_bytes: Vec<u8> = row.try_get("event_bytes")?;
    let event = IdentityLogEventV1::decode_and_verify(&exact_bytes)?;
    if event.identity_id() != expected_identity_id
        || event.wire() != wire
        || event.sequence() != sequence
        || event.previous_event_hash() != stored_previous
        || event.entry_hash()? != stored_hash
        || event.to_deterministic_cbor()? != exact_bytes
    {
        return Err(IdentityPersistenceError::CorruptData(
            "identity log entry projection",
        ));
    }
    Ok(DecodedEntry {
        event,
        exact_bytes,
        entry_hash: stored_hash,
    })
}

async fn current_head_conflict(
    connection: &mut PgConnection,
    identity_id: IdentityId,
) -> Result<IdentityPersistenceError, IdentityPersistenceError> {
    match load_stored_head(connection, identity_id).await? {
        Some(stored) if stored.state == LogState::Active => {
            Ok(IdentityPersistenceError::HeadConflict {
                current: Some(stored.head),
            })
        }
        Some(_) => Ok(IdentityPersistenceError::IdentityInactive),
        None => Ok(IdentityPersistenceError::HeadConflict { current: None }),
    }
}

fn head_from_projection(projection: &IdentityLogV1) -> IdentityLogHead {
    IdentityLogHead::new(
        projection.identity_id(),
        projection.wire(),
        projection.head_sequence(),
        projection.head_hash(),
    )
}

fn parse_wire(
    protocol_major: Option<i16>,
    protocol_minor: Option<i16>,
    minimum_reader_major: Option<i16>,
    minimum_reader_minor: Option<i16>,
) -> Result<WireVersion, IdentityPersistenceError> {
    let protocol_major = u16::try_from(protocol_major.ok_or(
        IdentityPersistenceError::CorruptData("identity wire protocol major"),
    )?)
    .map_err(|_| IdentityPersistenceError::CorruptData("identity wire protocol major"))?;
    let protocol_minor = u16::try_from(protocol_minor.ok_or(
        IdentityPersistenceError::CorruptData("identity wire protocol minor"),
    )?)
    .map_err(|_| IdentityPersistenceError::CorruptData("identity wire protocol minor"))?;
    let minimum_reader_major = u16::try_from(minimum_reader_major.ok_or(
        IdentityPersistenceError::CorruptData("identity wire minimum reader major"),
    )?)
    .map_err(|_| IdentityPersistenceError::CorruptData("identity wire minimum reader major"))?;
    let minimum_reader_minor = u16::try_from(minimum_reader_minor.ok_or(
        IdentityPersistenceError::CorruptData("identity wire minimum reader minor"),
    )?)
    .map_err(|_| IdentityPersistenceError::CorruptData("identity wire minimum reader minor"))?;
    let wire = WireVersion::new(
        dtx_wire::ProtocolVersion::new(protocol_major, protocol_minor),
        dtx_wire::ProtocolVersion::new(minimum_reader_major, minimum_reader_minor),
    );
    if wire != IDENTITY_LOG_WIRE_VERSION {
        return Err(IdentityPersistenceError::CorruptData(
            "identity wire version",
        ));
    }
    Ok(wire)
}

fn safe_uint(value: i64, label: &'static str) -> Result<SafeUint, IdentityPersistenceError> {
    let value = u64::try_from(value).map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    SafeUint::new(value).map_err(|_| IdentityPersistenceError::CorruptData(label))
}

fn utc_millis(value: i64, label: &'static str) -> Result<UtcMillis, IdentityPersistenceError> {
    UtcMillis::new(value).map_err(|_| IdentityPersistenceError::CorruptData(label))
}

fn digest(value: &[u8], label: &'static str) -> Result<Sha256Digest, IdentityPersistenceError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| IdentityPersistenceError::CorruptData(label))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn to_i64(value: SafeUint) -> Result<i64, IdentityPersistenceError> {
    i64::try_from(value.get())
        .map_err(|_| IdentityPersistenceError::CorruptData("identity safe sequence"))
}

fn sequence_index(sequence: SafeUint) -> Result<usize, IdentityPersistenceError> {
    let zero_based = sequence
        .get()
        .checked_sub(1)
        .ok_or(IdentityPersistenceError::CorruptData("identity sequence"))?;
    usize::try_from(zero_based)
        .map_err(|_| IdentityPersistenceError::CorruptData("identity sequence"))
}
