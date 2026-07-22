use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use dtx_connect_registry::AdapterKind;
use dtx_domain::{ConnectorId, HostId, RequestId, Revision, TenantId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::InstallStateJournal;
use crate::supervisor::validate_durable_command_precondition;
use crate::types::InstallProof;
use crate::{
    BootstrapCredentialFacts, CatalogRelease, CommandDigest, CommandDisposition, CommandOutcome,
    ConfigDigest, ConnectorLifecycleFacts, ConnectorLifecycleOperationId, ConnectorTarget,
    CredentialArtifactRef, DurableHostCommand, FinalizedReceiptDigest, HandoffDigest,
    HostOperationId, HostRevisionFence, Journal, JournalRecord, ManagedConnectorDesiredState,
    ManagedConnectorSnapshot, MaterialDigest, McpBearerRef, OperationIntent, OperationReceipt,
    PlanDigest, PlatformTarget, PortError, PortErrorKind, PreparedReceiptDigest,
    ProcessObservation, ReleaseDigest, ResourceProfile, SupervisorSnapshot, TrustDigest,
};

const PRODUCTION_ROOT: &str = "/var/lib/dirextalk/host-supervisor/journals";
const JOURNAL_FILE: &str = "journal.json";
const LOCK_FILE: &str = "journal.lock";
const SCHEMA: &str = "dirextalk.host-supervisor.operation-journal";
const VERSION: u32 = 4;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;

/// Durable, Host-scoped operation journal backed by one fixed local file.
pub struct FileJournal {
    host_id: HostId,
    directory: PathBuf,
    journal_path: PathBuf,
    lock_path: PathBuf,
}

impl FileJournal {
    /// Opens the fixed production journal for `host_id`.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn for_host(host_id: HostId) -> Self {
        Self::under_root(Path::new(PRODUCTION_ROOT), host_id)
    }

    #[cfg(test)]
    pub(crate) fn for_test_root(root: &Path, host_id: HostId) -> Self {
        Self::under_root(root, host_id)
    }

    fn under_root(root: &Path, host_id: HostId) -> Self {
        let directory = root.join(host_id.to_string());
        Self {
            host_id,
            journal_path: directory.join(JOURNAL_FILE),
            lock_path: directory.join(LOCK_FILE),
            directory,
        }
    }

    fn mutate(
        &self,
        mutation: impl FnOnce(&mut JournalFile) -> Result<bool, PortError>,
    ) -> Result<(), PortError> {
        self.with_lock(|journal| {
            let expected = journal.clone();
            if !mutation(journal)? {
                return Ok(());
            }
            journal.generation = journal
                .generation
                .checked_add(1)
                .filter(|generation| *generation <= Revision::MAX)
                .ok_or_else(conflict)?;
            journal.chain_tip = journal.computed_chain_tip().map_err(|()| invalid())?;
            journal.validate(self.host_id).map_err(|()| invalid())?;
            self.write_cas(&expected, journal)
        })
    }

    fn with_lock<T>(
        &self,
        operation: impl FnOnce(&mut JournalFile) -> Result<T, PortError>,
    ) -> Result<T, PortError> {
        self.prepare_directory()?;
        let lock = open_lock_file(&self.lock_path)?;
        lock.lock().map_err(|_| unavailable())?;
        let mut journal = self.read()?;
        let result = operation(&mut journal);
        let unlock = lock.unlock().map_err(|_| unavailable());
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    fn prepare_directory(&self) -> Result<(), PortError> {
        #[cfg(all(target_os = "linux", not(test)))]
        {
            prepare_production_directory(&self.directory)
        }
        #[cfg(any(not(target_os = "linux"), test))]
        {
            fs::create_dir_all(&self.directory).map_err(|_| unavailable())?;
            let metadata = fs::symlink_metadata(&self.directory).map_err(|_| unavailable())?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(invalid());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))
                    .map_err(|_| unavailable())?;
            }
            Ok(())
        }
    }

    fn read(&self) -> Result<JournalFile, PortError> {
        if !self.journal_path.try_exists().map_err(|_| unavailable())? {
            return Ok(JournalFile::empty(self.host_id));
        }
        ensure_secure_file(&self.journal_path)?;
        let mut file = File::open(&self.journal_path).map_err(|_| unavailable())?;
        ensure_secure_open_file(&file)?;
        let length = file.metadata().map_err(|_| unavailable())?.len();
        if length == 0 || length > MAX_JOURNAL_BYTES {
            return Err(invalid());
        }
        let mut bytes = Vec::with_capacity(usize::try_from(length).map_err(|_| invalid())?);
        file.read_to_end(&mut bytes).map_err(|_| unavailable())?;
        if u64::try_from(bytes.len()).map_err(|_| invalid())? != length {
            return Err(invalid());
        }
        let journal: JournalFile = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        journal.validate(self.host_id).map_err(|()| invalid())?;
        Ok(journal)
    }

    fn write_cas(&self, expected: &JournalFile, next: &JournalFile) -> Result<(), PortError> {
        if &self.read()? != expected {
            return Err(conflict());
        }
        let bytes = serde_json::to_vec(next).map_err(|_| invalid())?;
        if bytes.len() > usize::try_from(MAX_JOURNAL_BYTES).map_err(|_| invalid())? {
            return Err(invalid());
        }
        let temp_path = self
            .directory
            .join(format!("journal.{}.tmp", Uuid::now_v7().hyphenated()));
        let mut temporary = secure_create_new(&temp_path)?;
        let write_result = (|| {
            temporary.write_all(&bytes).map_err(|_| unavailable())?;
            temporary.sync_all().map_err(|_| unavailable())?;
            ensure_secure_open_file(&temporary)?;
            replace_file(&temp_path, &self.journal_path)?;
            ensure_secure_file(&self.journal_path)?;
            sync_directory(&self.directory)
        })();
        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result
    }
}

impl Journal for FileJournal {
    fn load_snapshot(&mut self, host_id: HostId) -> Result<Option<SupervisorSnapshot>, PortError> {
        if host_id != self.host_id {
            return Err(conflict());
        }
        self.with_lock(|journal| {
            journal
                .snapshot
                .as_ref()
                .map(SnapshotWire::rehydrate)
                .transpose()
                .map_err(|()| invalid())
        })
    }

    fn lookup(
        &mut self,
        host_id: HostId,
        operation_id: HostOperationId,
    ) -> Result<Option<JournalRecord>, PortError> {
        if host_id != self.host_id {
            return Err(conflict());
        }
        self.with_lock(|journal| {
            journal
                .records
                .iter()
                .find(|record| record.operation_id() == operation_id)
                .map(Record::rehydrate)
                .transpose()
                .map_err(|()| invalid())
        })
    }

    fn persist_intent(
        &mut self,
        intent: OperationIntent,
        predecessor: &SupervisorSnapshot,
    ) -> Result<(), PortError> {
        if intent.host_id() != self.host_id {
            return Err(conflict());
        }
        let predecessor = SnapshotWire::from_snapshot(predecessor);
        let predecessor_snapshot_digest =
            snapshot_wire_digest(&predecessor).map_err(|()| invalid())?;
        let predecessor_snapshot = predecessor.rehydrate().map_err(|()| invalid())?;
        if predecessor_snapshot.host_id != self.host_id
            || predecessor_snapshot.tenant_id != intent.tenant_id()
            || snapshot_fence(&predecessor_snapshot) != Some(intent.expected())
        {
            return Err(conflict());
        }
        validate_predecessor_command(&predecessor_snapshot, &intent).map_err(|()| conflict())?;
        self.mutate(|journal| {
            if let Some(existing_record) = journal
                .records
                .iter()
                .find(|record| record.operation_id() == intent.operation_id())
            {
                let exact = match existing_record.rehydrate().map_err(|()| invalid())? {
                    JournalRecord::Pending(existing_intent) => {
                        existing_intent == intent && journal.snapshot.as_ref() == Some(&predecessor)
                    }
                    JournalRecord::Completed {
                        intent: existing_intent,
                        ..
                    } => {
                        existing_intent == intent
                            && existing_record.predecessor_snapshot() == &predecessor
                    }
                };
                return if exact { Ok(false) } else { Err(conflict()) };
            }
            if journal.records.iter().any(Record::is_pending) {
                return Err(conflict());
            }
            if journal
                .snapshot
                .as_ref()
                .is_some_and(|current| current != &predecessor)
                || (!journal.records.is_empty() && journal.snapshot.is_none())
            {
                return Err(conflict());
            }
            journal.snapshot = Some(predecessor.clone());
            let sequence = journal.next_record_sequence().map_err(|()| invalid())?;
            journal.records.push(Record::Pending {
                sequence,
                previous_record_digest: journal.chain_tip,
                intent: IntentWire::from_intent(&intent),
                predecessor_snapshot: predecessor.clone(),
                predecessor_snapshot_digest,
            });
            Ok(true)
        })
    }

    fn complete(
        &mut self,
        receipt: OperationReceipt,
        resulting: &SupervisorSnapshot,
    ) -> Result<(), PortError> {
        let resulting = SnapshotWire::from_snapshot(resulting);
        let resulting_snapshot_digest = snapshot_wire_digest(&resulting).map_err(|()| invalid())?;
        let resulting_snapshot = resulting.rehydrate().map_err(|()| invalid())?;
        if resulting_snapshot.host_id != self.host_id {
            return Err(conflict());
        }
        self.mutate(|journal| {
            let record_index = journal
                .records
                .iter()
                .position(|record| record.operation_id() == receipt.operation_id())
                .ok_or_else(conflict)?;
            let record = journal.records[record_index].clone();
            match record.rehydrate().map_err(|()| invalid())? {
                JournalRecord::Pending(intent) => {
                    if receipt.command_digest() != intent.command_digest()
                        || OperationReceipt::rehydrate(
                            &intent,
                            receipt.operation_id(),
                            receipt.command_digest(),
                            receipt.outcome(),
                            receipt.install_proof(),
                        )
                        .is_err()
                    {
                        return Err(conflict());
                    }
                    let predecessor_wire = record.predecessor_snapshot();
                    if journal.snapshot.as_ref() != Some(predecessor_wire) {
                        return Err(invalid());
                    }
                    let predecessor = predecessor_wire.rehydrate().map_err(|()| invalid())?;
                    validate_snapshot_transition(
                        &predecessor,
                        &resulting_snapshot,
                        &intent,
                        receipt,
                    )
                    .map_err(|()| conflict())?;
                    journal.records[record_index] = Record::Completed {
                        sequence: record.sequence(),
                        previous_record_digest: record.previous_record_digest(),
                        intent: IntentWire::from_intent(&intent),
                        receipt: ReceiptWire::from_receipt(receipt),
                        predecessor_snapshot: predecessor_wire.clone(),
                        predecessor_snapshot_digest: record.predecessor_snapshot_digest(),
                        resulting_snapshot: Box::new(resulting.clone()),
                        resulting_snapshot_digest,
                    };
                    journal.snapshot = Some(resulting.clone());
                    Ok(true)
                }
                JournalRecord::Completed {
                    receipt: existing, ..
                } if existing == receipt && journal.snapshot.as_ref() == Some(&resulting) => {
                    Ok(false)
                }
                JournalRecord::Completed { .. } => Err(conflict()),
            }
        })
    }

    fn pending(&mut self, host_id: HostId) -> Result<Vec<OperationIntent>, PortError> {
        if host_id != self.host_id {
            return Err(conflict());
        }
        self.with_lock(|journal| {
            journal
                .records
                .iter()
                .filter_map(|record| match record {
                    Record::Pending { .. } => Some(record.rehydrate()),
                    Record::Completed { .. } => None,
                })
                .map(|record| match record.map_err(|()| invalid())? {
                    JournalRecord::Pending(intent) => Ok(intent),
                    JournalRecord::Completed { .. } => Err(invalid()),
                })
                .collect()
        })
    }
}

impl InstallStateJournal for FileJournal {
    fn load_install_state(
        &mut self,
        host_id: HostId,
        connector_id: ConnectorId,
    ) -> Result<Option<crate::InstallState>, PortError> {
        if host_id != self.host_id {
            return Err(conflict());
        }
        self.with_lock(|journal| {
            let mut state = None;
            for record in &journal.records {
                let JournalRecord::Completed { receipt, .. } =
                    record.rehydrate().map_err(|()| invalid())?
                else {
                    continue;
                };
                let Some(proof) = receipt.install_proof() else {
                    continue;
                };
                match proof {
                    InstallProof::Prepared {
                        facts,
                        prepared_receipt,
                        credentials,
                        observation,
                    } if facts.connector_id() == connector_id => {
                        state = Some(crate::InstallState::Prepared {
                            facts,
                            prepared_receipt,
                            credentials,
                            observation,
                        });
                    }
                    InstallProof::Finalized {
                        facts,
                        prepared_receipt,
                        finalized_receipt,
                        credentials,
                        observation,
                    } if facts.connector_id() == connector_id => {
                        state = Some(crate::InstallState::Finalized {
                            facts,
                            prepared_receipt,
                            finalized_receipt,
                            credentials,
                            observation,
                        });
                    }
                    _ => {}
                }
            }
            Ok(state)
        })
    }
}

// The production file and its directory are root-owned. This unkeyed SHA-256
// chain detects stale or incomplete truncation, reordering, renumbering, and
// partial rewrites that do not also rebuild the chain. Without an external
// monotonic anchor it cannot distinguish a self-consistent rollback to an
// earlier valid whole-file image. It is deliberately not an authenticity
// boundary against an active root attacker, who can rewrite the file and
// recompute every digest; those threats require an externally held anchor/key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalFile {
    schema: String,
    version: u32,
    host_id: HostId,
    generation: u64,
    genesis_anchor: [u8; 32],
    chain_tip: [u8; 32],
    snapshot: Option<SnapshotWire>,
    records: Vec<Record>,
}

#[allow(clippy::too_many_lines)]
impl JournalFile {
    fn empty(host_id: HostId) -> Self {
        let genesis_anchor = journal_genesis_anchor(host_id);
        Self {
            schema: SCHEMA.to_owned(),
            version: VERSION,
            host_id,
            generation: 0,
            genesis_anchor,
            chain_tip: genesis_anchor,
            snapshot: None,
            records: Vec::new(),
        }
    }

    fn next_record_sequence(&self) -> Result<u64, ()> {
        u64::try_from(self.records.len())
            .map_err(|_| ())?
            .checked_add(1)
            .filter(|sequence| *sequence <= Revision::MAX)
            .ok_or(())
    }

    fn computed_chain_tip(&self) -> Result<[u8; 32], ()> {
        self.records
            .last()
            .map(record_digest)
            .transpose()
            .map(|tip| tip.unwrap_or(self.genesis_anchor))
    }

    fn validate(&self, expected_host: HostId) -> Result<(), ()> {
        if self.schema != SCHEMA
            || self.version != VERSION
            || self.host_id != expected_host
            || self.generation > Revision::MAX
            || self.genesis_anchor != journal_genesis_anchor(expected_host)
        {
            return Err(());
        }
        let snapshot_wire = self.snapshot.as_ref();
        let snapshot = snapshot_wire.map(SnapshotWire::rehydrate).transpose()?;
        if self.records.is_empty() != snapshot.is_none() {
            return Err(());
        }
        let completed = self
            .records
            .iter()
            .filter(|record| matches!(record, Record::Completed { .. }))
            .count();
        let expected_generation = self.records.len().checked_add(completed).ok_or(())?;
        if self.generation != u64::try_from(expected_generation).map_err(|_| ())? {
            return Err(());
        }
        let mut operation_ids = BTreeSet::new();
        let mut tenant_id = None;
        let mut pending_seen = false;
        let mut prior_resulting = None;
        let mut prior_resulting_snapshot = None;
        let mut prepared_credentials = std::collections::BTreeMap::new();
        let mut expected_previous_record_digest = self.genesis_anchor;
        for (index, record) in self.records.iter().enumerate() {
            let expected_sequence = record_sequence(index)?;
            if record.sequence() != expected_sequence
                || record.previous_record_digest() != expected_previous_record_digest
            {
                return Err(());
            }
            let rehydrated = record.rehydrate()?;
            let intent = match &rehydrated {
                JournalRecord::Pending(intent) | JournalRecord::Completed { intent, .. } => intent,
            };
            if intent.host_id() != expected_host
                || !operation_ids.insert(intent.operation_id())
                || tenant_id.is_some_and(|tenant| tenant != intent.tenant_id())
                || prior_resulting.is_some_and(|prior| prior != intent.expected())
            {
                return Err(());
            }
            tenant_id = Some(intent.tenant_id());
            let predecessor_wire = record.predecessor_snapshot();
            if snapshot_wire_digest(predecessor_wire)? != record.predecessor_snapshot_digest()
                || prior_resulting_snapshot
                    .as_ref()
                    .is_some_and(|prior| prior != predecessor_wire)
            {
                return Err(());
            }
            let predecessor = predecessor_wire.rehydrate()?;
            if predecessor.host_id != expected_host
                || predecessor.tenant_id != intent.tenant_id()
                || snapshot_fence(&predecessor) != Some(intent.expected())
            {
                return Err(());
            }
            validate_predecessor_command(&predecessor, intent)?;
            match &rehydrated {
                JournalRecord::Pending(_) => {
                    if pending_seen
                        || index + 1 != self.records.len()
                        || record.resulting_snapshot().is_some()
                        || record.resulting_snapshot_digest().is_some()
                    {
                        return Err(());
                    }
                    pending_seen = true;
                    prior_resulting_snapshot = Some(predecessor_wire.clone());
                }
                JournalRecord::Completed { receipt, .. } => {
                    let resulting_wire = record.resulting_snapshot().ok_or(())?;
                    if snapshot_wire_digest(resulting_wire)?
                        != record.resulting_snapshot_digest().ok_or(())?
                    {
                        return Err(());
                    }
                    let resulting = resulting_wire.rehydrate()?;
                    validate_snapshot_transition(&predecessor, &resulting, intent, *receipt)?;
                    match receipt.install_proof() {
                        Some(InstallProof::Prepared {
                            facts, credentials, ..
                        }) => {
                            if !matches!(
                                intent.command(),
                                DurableHostCommand::PrepareConnectorMaterial { .. }
                            ) {
                                return Err(());
                            }
                            if let InstallProof::Prepared {
                                prepared_receipt, ..
                            } = receipt.install_proof().ok_or(())?
                            {
                                prepared_credentials.insert(
                                    facts.connector_id(),
                                    (facts, prepared_receipt, credentials),
                                );
                            }
                        }
                        Some(InstallProof::Finalized {
                            facts,
                            prepared_receipt,
                            credentials,
                            ..
                        }) => {
                            let Some((prepared_facts, prepared_receipt_digest, prepared)) =
                                prepared_credentials.get(&facts.connector_id())
                            else {
                                return Err(());
                            };
                            if !matches!(
                                intent.command(),
                                DurableHostCommand::FinalizeConnectorMaterial { .. }
                            ) || *prepared_facts != facts
                                || *prepared != credentials
                                || *prepared_receipt_digest != prepared_receipt
                            {
                                return Err(());
                            }
                        }
                        None => {
                            if matches!(
                                intent.command(),
                                DurableHostCommand::PrepareConnectorMaterial { .. }
                                    | DurableHostCommand::FinalizeConnectorMaterial { .. }
                            ) && receipt.outcome().disposition
                                != CommandDisposition::ExpiredUnclaimed
                            {
                                return Err(());
                            }
                        }
                    }
                    prior_resulting_snapshot = Some(resulting_wire.clone());
                }
            }
            // A completed ExpiredUnclaimed prepare is intentionally a durable
            // no-effect receipt: its intent reserves the next fence, but its
            // receipt and resulting snapshot remain at the predecessor fence.
            // Chain the following intent from the actual completed outcome,
            // while pending and all effectful records retain intent.resulting.
            prior_resulting = Some(match &rehydrated {
                JournalRecord::Completed { receipt, .. }
                    if receipt.outcome().disposition == CommandDisposition::ExpiredUnclaimed =>
                {
                    receipt.outcome().revisions
                }
                _ => intent.resulting(),
            });
            expected_previous_record_digest = record_digest(record)?;
        }
        if snapshot_wire != prior_resulting_snapshot.as_ref()
            || self.chain_tip != expected_previous_record_digest
            || snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.host_id != expected_host)
        {
            return Err(());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
enum Record {
    Pending {
        sequence: u64,
        previous_record_digest: [u8; 32],
        intent: IntentWire,
        predecessor_snapshot: SnapshotWire,
        predecessor_snapshot_digest: [u8; 32],
    },
    Completed {
        sequence: u64,
        previous_record_digest: [u8; 32],
        intent: IntentWire,
        receipt: ReceiptWire,
        predecessor_snapshot: SnapshotWire,
        predecessor_snapshot_digest: [u8; 32],
        resulting_snapshot: Box<SnapshotWire>,
        resulting_snapshot_digest: [u8; 32],
    },
}

impl Record {
    const fn sequence(&self) -> u64 {
        match self {
            Self::Pending { sequence, .. } | Self::Completed { sequence, .. } => *sequence,
        }
    }

    const fn previous_record_digest(&self) -> [u8; 32] {
        match self {
            Self::Pending {
                previous_record_digest,
                ..
            }
            | Self::Completed {
                previous_record_digest,
                ..
            } => *previous_record_digest,
        }
    }

    fn operation_id(&self) -> HostOperationId {
        match self {
            Self::Pending { intent, .. } | Self::Completed { intent, .. } => {
                HostOperationId::from_request_id(intent.operation_id)
            }
        }
    }

    const fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }

    const fn predecessor_snapshot(&self) -> &SnapshotWire {
        match self {
            Self::Pending {
                predecessor_snapshot,
                ..
            }
            | Self::Completed {
                predecessor_snapshot,
                ..
            } => predecessor_snapshot,
        }
    }

    const fn predecessor_snapshot_digest(&self) -> [u8; 32] {
        match self {
            Self::Pending {
                predecessor_snapshot_digest,
                ..
            }
            | Self::Completed {
                predecessor_snapshot_digest,
                ..
            } => *predecessor_snapshot_digest,
        }
    }

    const fn resulting_snapshot(&self) -> Option<&SnapshotWire> {
        match self {
            Self::Pending { .. } => None,
            Self::Completed {
                resulting_snapshot, ..
            } => Some(resulting_snapshot),
        }
    }

    const fn resulting_snapshot_digest(&self) -> Option<[u8; 32]> {
        match self {
            Self::Pending { .. } => None,
            Self::Completed {
                resulting_snapshot_digest,
                ..
            } => Some(*resulting_snapshot_digest),
        }
    }

    fn rehydrate(&self) -> Result<JournalRecord, ()> {
        match self {
            Self::Pending { intent, .. } => Ok(JournalRecord::Pending(intent.rehydrate()?)),
            Self::Completed {
                intent, receipt, ..
            } => {
                let intent = intent.rehydrate()?;
                let receipt = receipt.rehydrate(&intent)?;
                Ok(JournalRecord::Completed { intent, receipt })
            }
        }
    }
}

fn journal_genesis_anchor(host_id: HostId) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"dirextalk.host-supervisor.operation-journal.v4.genesis\0");
    digest.update(Uuid::from(host_id).as_bytes());
    digest.finalize().into()
}

fn record_sequence(index: usize) -> Result<u64, ()> {
    u64::try_from(index)
        .map_err(|_| ())?
        .checked_add(1)
        .ok_or(())
}

fn record_digest(record: &Record) -> Result<[u8; 32], ()> {
    let bytes = serde_json::to_vec(record).map_err(|_| ())?;
    let mut digest = Sha256::new();
    digest.update(b"dirextalk.host-supervisor.operation-journal.v4.record\0");
    digest.update(bytes);
    Ok(digest.finalize().into())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct IntentWire {
    operation_id: RequestId,
    tenant_id: TenantId,
    host_id: HostId,
    command_digest: [u8; 32],
    expected: FenceWire,
    resulting: FenceWire,
    command: CommandWire,
}

impl IntentWire {
    fn from_intent(intent: &OperationIntent) -> Self {
        Self {
            operation_id: intent.operation_id().as_request_id(),
            tenant_id: intent.tenant_id(),
            host_id: intent.host_id(),
            command_digest: intent.command_digest().as_bytes(),
            expected: FenceWire::from_fence(intent.expected()),
            resulting: FenceWire::from_fence(intent.resulting()),
            command: CommandWire::from_command(intent.command()),
        }
    }

    fn rehydrate(&self) -> Result<OperationIntent, ()> {
        OperationIntent::rehydrate(
            HostOperationId::from_request_id(self.operation_id),
            self.tenant_id,
            self.host_id,
            CommandDigest::from_bytes(self.command_digest),
            self.expected.rehydrate()?,
            self.resulting.rehydrate()?,
            self.command.rehydrate()?,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FenceWire {
    desired: u64,
    observed: Option<u64>,
}

impl FenceWire {
    const fn from_fence(fence: HostRevisionFence) -> Self {
        Self {
            desired: fence.desired().get(),
            observed: match fence.observed() {
                Some(revision) => Some(revision.get()),
                None => None,
            },
        }
    }

    fn rehydrate(self) -> Result<HostRevisionFence, ()> {
        HostRevisionFence::new(self.desired, self.observed).map_err(|_| ())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum CommandWire {
    Ensure {
        target: TargetWire,
        release: ReleaseWire,
    },
    Start {
        target: TargetWire,
        release: ReleaseWire,
        credential_ref: [u8; 32],
        credential_operation_id: RequestId,
    },
    Stop {
        target: TargetWire,
    },
    Restart {
        target: TargetWire,
        release: ReleaseWire,
        credential_ref: [u8; 32],
        credential_operation_id: RequestId,
    },
    RotateCredential {
        target: TargetWire,
        release: ReleaseWire,
        credential_ref: [u8; 32],
        resulting_generation: u64,
    },
    RemoveRetainingData {
        target: TargetWire,
    },
    PrepareConnectorMaterial {
        facts: LifecycleFactsWire,
    },
    FinalizeConnectorMaterial {
        facts: LifecycleFactsWire,
        prepared_receipt: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LifecycleFactsWire {
    lifecycle_operation_id: RequestId,
    platform_target: PlatformWire,
    adapter_kind: AdapterWire,
    release_digest: [u8; 32],
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
    expiry_millis: u64,
    plan_digest: [u8; 32],
    handoff_digest: [u8; 32],
    config_digest: [u8; 32],
    trust_digest: [u8; 32],
    material_digest: [u8; 32],
}

#[allow(clippy::large_types_passed_by_value, clippy::unnecessary_wraps)]
impl LifecycleFactsWire {
    const fn from_facts(f: ConnectorLifecycleFacts) -> Self {
        Self {
            lifecycle_operation_id: f.lifecycle_operation_id().as_request_id(),
            platform_target: PlatformWire::from_target(f.platform_target()),
            adapter_kind: AdapterWire::from_adapter(f.adapter_kind()),
            release_digest: f.release_digest().as_bytes(),
            tenant_id: f.tenant_id(),
            host_id: f.host_id(),
            connector_id: f.connector_id(),
            expiry_millis: f.expiry_millis(),
            plan_digest: f.plan_digest().as_bytes(),
            handoff_digest: f.handoff_digest().as_bytes(),
            config_digest: f.config_digest().as_bytes(),
            trust_digest: f.trust_digest().as_bytes(),
            material_digest: f.material_digest().as_bytes(),
        }
    }
    fn rehydrate(self) -> Result<ConnectorLifecycleFacts, ()> {
        Ok(ConnectorLifecycleFacts::new(
            ConnectorLifecycleOperationId::from_request_id(self.lifecycle_operation_id),
            self.platform_target.into_target(),
            self.adapter_kind.into_adapter(),
            ReleaseDigest::from_bytes(self.release_digest),
            self.tenant_id,
            self.host_id,
            self.connector_id,
            self.expiry_millis,
            PlanDigest::from_bytes(self.plan_digest),
            HandoffDigest::from_bytes(self.handoff_digest),
            ConfigDigest::from_bytes(self.config_digest),
            TrustDigest::from_bytes(self.trust_digest),
            MaterialDigest::from_bytes(self.material_digest),
        ))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PlatformWire {
    LinuxAmd64,
    LinuxArm64,
}
impl PlatformWire {
    const fn from_target(v: PlatformTarget) -> Self {
        match v {
            PlatformTarget::LinuxAmd64 => Self::LinuxAmd64,
            PlatformTarget::LinuxArm64 => Self::LinuxArm64,
        }
    }
    const fn into_target(self) -> PlatformTarget {
        match self {
            Self::LinuxAmd64 => PlatformTarget::LinuxAmd64,
            Self::LinuxArm64 => PlatformTarget::LinuxArm64,
        }
    }
}

#[allow(clippy::large_types_passed_by_value)]
impl CommandWire {
    fn from_command(command: DurableHostCommand) -> Self {
        match command {
            DurableHostCommand::Ensure { target, release } => Self::Ensure {
                target: TargetWire::from_target(target),
                release: ReleaseWire::from_release(release),
            },
            DurableHostCommand::Start {
                target,
                release,
                credential_ref,
                credential_operation_id,
            } => Self::Start {
                target: TargetWire::from_target(target),
                release: ReleaseWire::from_release(release),
                credential_ref: credential_ref.as_bytes(),
                credential_operation_id: credential_operation_id.as_request_id(),
            },
            DurableHostCommand::Stop { target } => Self::Stop {
                target: TargetWire::from_target(target),
            },
            DurableHostCommand::Restart {
                target,
                release,
                credential_ref,
                credential_operation_id,
            } => Self::Restart {
                target: TargetWire::from_target(target),
                release: ReleaseWire::from_release(release),
                credential_ref: credential_ref.as_bytes(),
                credential_operation_id: credential_operation_id.as_request_id(),
            },
            DurableHostCommand::RotateCredential {
                target,
                release,
                credential_ref,
                resulting_generation,
            } => Self::RotateCredential {
                target: TargetWire::from_target(target),
                release: ReleaseWire::from_release(release),
                credential_ref: credential_ref.as_bytes(),
                resulting_generation,
            },
            DurableHostCommand::RemoveRetainingData { target } => Self::RemoveRetainingData {
                target: TargetWire::from_target(target),
            },
            DurableHostCommand::PrepareConnectorMaterial { facts } => {
                Self::PrepareConnectorMaterial {
                    facts: LifecycleFactsWire::from_facts(facts),
                }
            }
            DurableHostCommand::FinalizeConnectorMaterial {
                facts,
                prepared_receipt,
            } => Self::FinalizeConnectorMaterial {
                facts: LifecycleFactsWire::from_facts(facts),
                prepared_receipt: prepared_receipt.as_bytes(),
            },
        }
    }

    fn rehydrate(&self) -> Result<DurableHostCommand, ()> {
        Ok(match self {
            Self::Ensure { target, release } => DurableHostCommand::Ensure {
                target: target.rehydrate(),
                release: release.rehydrate()?,
            },
            Self::Start {
                target,
                release,
                credential_ref,
                credential_operation_id,
            } => DurableHostCommand::Start {
                target: target.rehydrate(),
                release: release.rehydrate()?,
                credential_ref: CredentialArtifactRef::from_bytes(*credential_ref),
                credential_operation_id: HostOperationId::from_request_id(*credential_operation_id),
            },
            Self::Stop { target } => DurableHostCommand::Stop {
                target: target.rehydrate(),
            },
            Self::Restart {
                target,
                release,
                credential_ref,
                credential_operation_id,
            } => DurableHostCommand::Restart {
                target: target.rehydrate(),
                release: release.rehydrate()?,
                credential_ref: CredentialArtifactRef::from_bytes(*credential_ref),
                credential_operation_id: HostOperationId::from_request_id(*credential_operation_id),
            },
            Self::RotateCredential {
                target,
                release,
                credential_ref,
                resulting_generation,
            } => DurableHostCommand::RotateCredential {
                target: target.rehydrate(),
                release: release.rehydrate()?,
                credential_ref: CredentialArtifactRef::from_bytes(*credential_ref),
                resulting_generation: *resulting_generation,
            },
            Self::RemoveRetainingData { target } => DurableHostCommand::RemoveRetainingData {
                target: target.rehydrate(),
            },
            Self::PrepareConnectorMaterial { facts } => {
                DurableHostCommand::PrepareConnectorMaterial {
                    facts: facts.rehydrate()?,
                }
            }
            Self::FinalizeConnectorMaterial {
                facts,
                prepared_receipt,
            } => DurableHostCommand::FinalizeConnectorMaterial {
                facts: facts.rehydrate()?,
                prepared_receipt: PreparedReceiptDigest::from_bytes(*prepared_receipt),
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetWire {
    tenant_id: TenantId,
    host_id: HostId,
    connector_id: ConnectorId,
    adapter_kind: AdapterWire,
}

impl TargetWire {
    const fn from_target(target: ConnectorTarget) -> Self {
        Self {
            tenant_id: target.tenant_id(),
            host_id: target.host_id(),
            connector_id: target.connector_id(),
            adapter_kind: AdapterWire::from_adapter(target.adapter_kind()),
        }
    }

    const fn rehydrate(self) -> ConnectorTarget {
        ConnectorTarget::new(
            self.tenant_id,
            self.host_id,
            self.connector_id,
            self.adapter_kind.into_adapter(),
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReleaseWire {
    adapter_kind: AdapterWire,
    digest: [u8; 32],
    resource_profile: ResourceProfileWire,
    catalog_revision: u64,
}

impl ReleaseWire {
    const fn from_release(release: CatalogRelease) -> Self {
        Self {
            adapter_kind: AdapterWire::from_adapter(release.adapter_kind()),
            digest: release.digest().as_bytes(),
            resource_profile: ResourceProfileWire::from_profile(release.resource_profile()),
            catalog_revision: release.catalog_revision().get(),
        }
    }

    fn rehydrate(self) -> Result<CatalogRelease, ()> {
        Ok(CatalogRelease::approved(
            self.adapter_kind.into_adapter(),
            ReleaseDigest::from_bytes(self.digest),
            self.resource_profile.into_profile(),
            Revision::new(self.catalog_revision).map_err(|_| ())?,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotWire {
    tenant_id: TenantId,
    host_id: HostId,
    desired_revision: u64,
    observed_revision: Option<u64>,
    instances: Vec<InstanceWire>,
}

impl SnapshotWire {
    fn from_snapshot(snapshot: &SupervisorSnapshot) -> Self {
        let mut instances: Vec<_> = snapshot
            .instances
            .iter()
            .copied()
            .map(InstanceWire::from_instance)
            .collect();
        instances.sort_by_key(|instance| instance.connector_id);
        Self {
            tenant_id: snapshot.tenant_id,
            host_id: snapshot.host_id,
            desired_revision: snapshot.desired_revision.get(),
            observed_revision: snapshot.observed_revision.map(Revision::get),
            instances,
        }
    }

    fn rehydrate(&self) -> Result<SupervisorSnapshot, ()> {
        let fence = HostRevisionFence::new(self.desired_revision, self.observed_revision)
            .map_err(|_| ())?;
        let mut connector_ids = BTreeSet::new();
        let instances: Vec<_> = self
            .instances
            .iter()
            .copied()
            .map(InstanceWire::rehydrate)
            .collect::<Result<_, _>>()?;
        if !instances
            .iter()
            .all(|instance| connector_ids.insert(instance.connector_id))
            || (!instances.is_empty()
                && (fence.desired() == Revision::INITIAL
                    || fence.observed() != Some(fence.desired())))
        {
            return Err(());
        }
        Ok(SupervisorSnapshot {
            tenant_id: self.tenant_id,
            host_id: self.host_id,
            desired_revision: fence.desired(),
            observed_revision: fence.observed(),
            instances,
        })
    }
}

fn snapshot_wire_digest(snapshot: &SnapshotWire) -> Result<[u8; 32], ()> {
    let bytes = serde_json::to_vec(snapshot).map_err(|_| ())?;
    Ok(Sha256::digest(bytes).into())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InstanceWire {
    connector_id: ConnectorId,
    adapter_kind: AdapterWire,
    release: ReleaseWire,
    desired_state: DesiredStateWire,
    observation: ObservationWire,
    credential_generation: u64,
    credential_ref: Option<[u8; 32]>,
    credential_operation_id: Option<RequestId>,
}

impl InstanceWire {
    fn from_instance(instance: ManagedConnectorSnapshot) -> Self {
        Self {
            connector_id: instance.connector_id,
            adapter_kind: AdapterWire::from_adapter(instance.adapter_kind),
            release: ReleaseWire::from_release(instance.release),
            desired_state: DesiredStateWire::from_state(instance.desired_state),
            observation: ObservationWire::from_observation(instance.observation),
            credential_generation: instance.credential_generation,
            credential_ref: instance.credential_ref.map(CredentialArtifactRef::as_bytes),
            credential_operation_id: instance
                .credential_operation_id
                .map(HostOperationId::as_request_id),
        }
    }

    fn rehydrate(self) -> Result<ManagedConnectorSnapshot, ()> {
        let release = self.release.rehydrate()?;
        let adapter_kind = self.adapter_kind.into_adapter();
        let desired_state = self.desired_state.into_state();
        let observation = self.observation.into_observation();
        if release.adapter_kind() != adapter_kind
            || self.credential_generation > Revision::MAX
            || (self.credential_generation == 0) != self.credential_ref.is_none()
            || self.credential_ref.is_none() != self.credential_operation_id.is_none()
            || !snapshot_observation_is_valid(desired_state, observation)
        {
            return Err(());
        }
        Ok(ManagedConnectorSnapshot {
            connector_id: self.connector_id,
            adapter_kind,
            release,
            desired_state,
            observation,
            credential_generation: self.credential_generation,
            credential_ref: self.credential_ref.map(CredentialArtifactRef::from_bytes),
            credential_operation_id: self
                .credential_operation_id
                .map(HostOperationId::from_request_id),
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AdapterWire {
    Codex,
    OpenClawAcp,
    Eino,
    Rig,
    ClaudeCode,
    CustomAcp,
    HermesAcp,
}

impl AdapterWire {
    const fn from_adapter(value: AdapterKind) -> Self {
        match value {
            AdapterKind::Codex => Self::Codex,
            AdapterKind::OpenClawAcp => Self::OpenClawAcp,
            AdapterKind::Eino => Self::Eino,
            AdapterKind::Rig => Self::Rig,
            AdapterKind::ClaudeCode => Self::ClaudeCode,
            AdapterKind::CustomAcp => Self::CustomAcp,
            AdapterKind::HermesAcp => Self::HermesAcp,
        }
    }

    const fn into_adapter(self) -> AdapterKind {
        match self {
            Self::Codex => AdapterKind::Codex,
            Self::OpenClawAcp => AdapterKind::OpenClawAcp,
            Self::Eino => AdapterKind::Eino,
            Self::Rig => AdapterKind::Rig,
            Self::ClaudeCode => AdapterKind::ClaudeCode,
            Self::CustomAcp => AdapterKind::CustomAcp,
            Self::HermesAcp => AdapterKind::HermesAcp,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ResourceProfileWire {
    Standard,
    Compute,
    LowLatency,
}

impl ResourceProfileWire {
    const fn from_profile(value: ResourceProfile) -> Self {
        match value {
            ResourceProfile::Standard => Self::Standard,
            ResourceProfile::Compute => Self::Compute,
            ResourceProfile::LowLatency => Self::LowLatency,
        }
    }

    const fn into_profile(self) -> ResourceProfile {
        match self {
            Self::Standard => ResourceProfile::Standard,
            Self::Compute => ResourceProfile::Compute,
            Self::LowLatency => ResourceProfile::LowLatency,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReceiptWire {
    operation_id: RequestId,
    command_digest: [u8; 32],
    outcome: OutcomeWire,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    install_proof: Option<InstallProofWire>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum InstallProofWire {
    Prepared {
        facts: LifecycleFactsWire,
        prepared_receipt: [u8; 32],
        credentials: CredentialFactsWire,
        observation: ObservationWire,
    },
    Finalized {
        facts: LifecycleFactsWire,
        prepared_receipt: [u8; 32],
        finalized_receipt: [u8; 32],
        credentials: CredentialFactsWire,
        observation: ObservationWire,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CredentialFactsWire {
    generation: u64,
    revision: u64,
    credential_ref: [u8; 32],
    mcp_bearer_ref: [u8; 32],
}

impl CredentialFactsWire {
    fn from_facts(v: BootstrapCredentialFacts) -> Self {
        Self {
            generation: v.generation,
            revision: v.revision.get(),
            credential_ref: v.credential_ref.as_bytes(),
            mcp_bearer_ref: v.mcp_bearer_ref.as_bytes(),
        }
    }
    fn rehydrate(self) -> Result<BootstrapCredentialFacts, ()> {
        Ok(BootstrapCredentialFacts {
            generation: self.generation,
            revision: Revision::new(self.revision).map_err(|_| ())?,
            credential_ref: CredentialArtifactRef::from_bytes(self.credential_ref),
            mcp_bearer_ref: McpBearerRef::from_bytes(self.mcp_bearer_ref),
        })
    }
}

#[allow(clippy::large_types_passed_by_value)]
impl ReceiptWire {
    fn from_receipt(receipt: OperationReceipt) -> Self {
        Self {
            operation_id: receipt.operation_id().as_request_id(),
            command_digest: receipt.command_digest().as_bytes(),
            outcome: OutcomeWire::from_outcome(receipt.outcome()),
            install_proof: receipt.install_proof().map(InstallProofWire::from_proof),
        }
    }

    fn rehydrate(self, intent: &OperationIntent) -> Result<OperationReceipt, ()> {
        OperationReceipt::rehydrate(
            intent,
            HostOperationId::from_request_id(self.operation_id),
            CommandDigest::from_bytes(self.command_digest),
            self.outcome.rehydrate()?,
            self.install_proof
                .as_ref()
                .map(InstallProofWire::rehydrate)
                .transpose()?,
        )
    }
}

#[allow(clippy::large_types_passed_by_value)]
impl InstallProofWire {
    fn from_proof(v: InstallProof) -> Self {
        match v {
            InstallProof::Prepared {
                facts,
                prepared_receipt,
                credentials,
                observation,
            } => Self::Prepared {
                facts: LifecycleFactsWire::from_facts(facts),
                prepared_receipt: prepared_receipt.as_bytes(),
                credentials: CredentialFactsWire::from_facts(credentials),
                observation: ObservationWire::from_observation(observation),
            },
            InstallProof::Finalized {
                facts,
                prepared_receipt,
                finalized_receipt,
                credentials,
                observation,
            } => Self::Finalized {
                facts: LifecycleFactsWire::from_facts(facts),
                prepared_receipt: prepared_receipt.as_bytes(),
                finalized_receipt: finalized_receipt.as_bytes(),
                credentials: CredentialFactsWire::from_facts(credentials),
                observation: ObservationWire::from_observation(observation),
            },
        }
    }
    fn rehydrate(&self) -> Result<InstallProof, ()> {
        Ok(match self {
            Self::Prepared {
                facts,
                prepared_receipt,
                credentials,
                observation,
            } => InstallProof::Prepared {
                facts: facts.rehydrate()?,
                prepared_receipt: PreparedReceiptDigest::from_bytes(*prepared_receipt),
                credentials: credentials.rehydrate()?,
                observation: observation.into_observation(),
            },
            Self::Finalized {
                facts,
                prepared_receipt,
                finalized_receipt,
                credentials,
                observation,
            } => InstallProof::Finalized {
                facts: facts.rehydrate()?,
                prepared_receipt: PreparedReceiptDigest::from_bytes(*prepared_receipt),
                finalized_receipt: FinalizedReceiptDigest::from_bytes(*finalized_receipt),
                credentials: credentials.rehydrate()?,
                observation: observation.into_observation(),
            },
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OutcomeWire {
    connector_id: ConnectorId,
    revisions: FenceWire,
    disposition: DispositionWire,
    desired_state: DesiredStateWire,
    observation: ObservationWire,
    credential_generation: u64,
}

impl OutcomeWire {
    const fn from_outcome(outcome: CommandOutcome) -> Self {
        Self {
            connector_id: outcome.connector_id,
            revisions: FenceWire::from_fence(outcome.revisions),
            disposition: DispositionWire::from_disposition(outcome.disposition),
            desired_state: DesiredStateWire::from_state(outcome.desired_state),
            observation: ObservationWire::from_observation(outcome.observation),
            credential_generation: outcome.credential_generation,
        }
    }

    fn rehydrate(self) -> Result<CommandOutcome, ()> {
        Ok(CommandOutcome {
            connector_id: self.connector_id,
            revisions: self.revisions.rehydrate()?,
            disposition: self.disposition.into_disposition(),
            desired_state: self.desired_state.into_state(),
            observation: self.observation.into_observation(),
            credential_generation: self.credential_generation,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DispositionWire {
    Applied,
    PolicyBlocked,
    ExpiredUnclaimed,
}

impl DispositionWire {
    const fn from_disposition(value: CommandDisposition) -> Self {
        match value {
            CommandDisposition::Applied => Self::Applied,
            CommandDisposition::PolicyBlocked => Self::PolicyBlocked,
            CommandDisposition::ExpiredUnclaimed => Self::ExpiredUnclaimed,
        }
    }

    const fn into_disposition(self) -> CommandDisposition {
        match self {
            Self::Applied => CommandDisposition::Applied,
            Self::PolicyBlocked => CommandDisposition::PolicyBlocked,
            Self::ExpiredUnclaimed => CommandDisposition::ExpiredUnclaimed,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DesiredStateWire {
    EnsuredStopped,
    Running,
    Stopped,
    RemovedRetainingData,
}

impl DesiredStateWire {
    const fn from_state(value: ManagedConnectorDesiredState) -> Self {
        match value {
            ManagedConnectorDesiredState::EnsuredStopped => Self::EnsuredStopped,
            ManagedConnectorDesiredState::Running => Self::Running,
            ManagedConnectorDesiredState::Stopped => Self::Stopped,
            ManagedConnectorDesiredState::RemovedRetainingData => Self::RemovedRetainingData,
        }
    }

    const fn into_state(self) -> ManagedConnectorDesiredState {
        match self {
            Self::EnsuredStopped => ManagedConnectorDesiredState::EnsuredStopped,
            Self::Running => ManagedConnectorDesiredState::Running,
            Self::Stopped => ManagedConnectorDesiredState::Stopped,
            Self::RemovedRetainingData => ManagedConnectorDesiredState::RemovedRetainingData,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ObservationWire {
    Absent,
    Starting,
    Running,
    Stopped,
    Failed,
}

impl ObservationWire {
    const fn from_observation(value: ProcessObservation) -> Self {
        match value {
            ProcessObservation::Absent => Self::Absent,
            ProcessObservation::Starting => Self::Starting,
            ProcessObservation::Running => Self::Running,
            ProcessObservation::Stopped => Self::Stopped,
            ProcessObservation::Failed => Self::Failed,
        }
    }

    const fn into_observation(self) -> ProcessObservation {
        match self {
            Self::Absent => ProcessObservation::Absent,
            Self::Starting => ProcessObservation::Starting,
            Self::Running => ProcessObservation::Running,
            Self::Stopped => ProcessObservation::Stopped,
            Self::Failed => ProcessObservation::Failed,
        }
    }
}

fn snapshot_fence(snapshot: &SupervisorSnapshot) -> Option<HostRevisionFence> {
    HostRevisionFence::from_revisions(snapshot.desired_revision, snapshot.observed_revision).ok()
}

fn validate_predecessor_command(
    predecessor: &SupervisorSnapshot,
    intent: &OperationIntent,
) -> Result<(), ()> {
    if matches!(
        intent.command(),
        DurableHostCommand::PrepareConnectorMaterial { .. }
            | DurableHostCommand::FinalizeConnectorMaterial { .. }
    ) {
        return Ok(());
    }
    let target = intent.command().target();
    let existing = predecessor
        .instances
        .iter()
        .find(|instance| instance.connector_id == target.connector_id());
    validate_durable_command_precondition(existing, intent.command()).map_err(|_| ())
}

#[allow(clippy::large_types_passed_by_value, clippy::too_many_lines)]
fn validate_snapshot_transition(
    predecessor: &SupervisorSnapshot,
    resulting: &SupervisorSnapshot,
    intent: &OperationIntent,
    receipt: OperationReceipt,
) -> Result<(), ()> {
    if predecessor.tenant_id != resulting.tenant_id
        || predecessor.host_id != resulting.host_id
        || predecessor.tenant_id != intent.tenant_id()
        || predecessor.host_id != intent.host_id()
        || snapshot_fence(predecessor) != Some(intent.expected())
        || (receipt.outcome().disposition != CommandDisposition::ExpiredUnclaimed
            && snapshot_fence(resulting) != Some(intent.resulting()))
    {
        return Err(());
    }
    let target = intent.command().target();
    if receipt.outcome().disposition == CommandDisposition::ExpiredUnclaimed {
        if !matches!(
            intent.command(),
            DurableHostCommand::PrepareConnectorMaterial { .. }
        ) || receipt.outcome().revisions != intent.expected()
            || predecessor != resulting
        {
            return Err(());
        }
        return Ok(());
    }
    let before = predecessor
        .instances
        .iter()
        .find(|instance| instance.connector_id == target.connector_id());
    let after = resulting
        .instances
        .iter()
        .find(|instance| instance.connector_id == target.connector_id())
        .ok_or(())?;
    if after.adapter_kind != target.adapter_kind() {
        return Err(());
    }
    let disposition = receipt.outcome().disposition;
    validate_lifecycle_transition(before, after, intent.command(), disposition)?;
    validate_completed_snapshot_projection(resulting, intent, receipt)?;
    validate_unchanged_siblings(
        predecessor,
        resulting,
        target.connector_id(),
        before.is_none(),
    )?;
    match intent.command() {
        DurableHostCommand::Ensure { release, .. } => {
            if after.release != release
                || after.credential_generation
                    != before.map_or(0, |value| value.credential_generation)
                || after.credential_ref != before.and_then(|value| value.credential_ref)
                || after.credential_operation_id
                    != before.and_then(|value| value.credential_operation_id)
            {
                return Err(());
            }
        }
        DurableHostCommand::Start {
            release,
            credential_ref,
            credential_operation_id,
            ..
        }
        | DurableHostCommand::Restart {
            release,
            credential_ref,
            credential_operation_id,
            ..
        } => {
            let before = before.ok_or(())?;
            if before.adapter_kind != after.adapter_kind
                || before.release != release
                || after.release != release
                || before.credential_generation != after.credential_generation
                || before.credential_ref != Some(credential_ref)
                || after.credential_ref != Some(credential_ref)
                || before.credential_operation_id != after.credential_operation_id
                || before.credential_operation_id != Some(credential_operation_id)
            {
                return Err(());
            }
        }
        DurableHostCommand::Stop { .. } | DurableHostCommand::RemoveRetainingData { .. } => {
            let before = before.ok_or(())?;
            if before.adapter_kind != after.adapter_kind
                || before.release != after.release
                || before.credential_generation != after.credential_generation
                || before.credential_ref != after.credential_ref
                || before.credential_operation_id != after.credential_operation_id
            {
                return Err(());
            }
        }
        DurableHostCommand::RotateCredential {
            release,
            credential_ref,
            resulting_generation,
            ..
        } => {
            let before = before.ok_or(())?;
            if before.adapter_kind != after.adapter_kind
                || before.release != release
                || after.release != release
                || before.credential_generation.checked_add(1) != Some(resulting_generation)
                || after.credential_generation != resulting_generation
                || after.credential_ref != Some(credential_ref)
                || after.credential_operation_id != Some(intent.operation_id())
            {
                return Err(());
            }
        }
        DurableHostCommand::PrepareConnectorMaterial { .. }
        | DurableHostCommand::FinalizeConnectorMaterial { .. } => {}
    }
    Ok(())
}

#[allow(clippy::large_types_passed_by_value, clippy::match_same_arms)]
fn validate_lifecycle_transition(
    before: Option<&ManagedConnectorSnapshot>,
    after: &ManagedConnectorSnapshot,
    command: DurableHostCommand,
    disposition: CommandDisposition,
) -> Result<(), ()> {
    validate_durable_command_precondition(before, command).map_err(|_| ())?;

    let expected_desired_state = match (command, disposition) {
        (
            DurableHostCommand::Start { .. } | DurableHostCommand::Restart { .. },
            CommandDisposition::PolicyBlocked,
        ) => ManagedConnectorDesiredState::Stopped,
        (_, CommandDisposition::PolicyBlocked) => return Err(()),
        (DurableHostCommand::Ensure { .. }, CommandDisposition::Applied) => {
            ManagedConnectorDesiredState::EnsuredStopped
        }
        (
            DurableHostCommand::Start { .. } | DurableHostCommand::Restart { .. },
            CommandDisposition::Applied,
        ) => ManagedConnectorDesiredState::Running,
        (DurableHostCommand::Stop { .. }, CommandDisposition::Applied) => {
            ManagedConnectorDesiredState::Stopped
        }
        (DurableHostCommand::RotateCredential { .. }, CommandDisposition::Applied) => {
            before.ok_or(())?.desired_state
        }
        (DurableHostCommand::RemoveRetainingData { .. }, CommandDisposition::Applied) => {
            ManagedConnectorDesiredState::RemovedRetainingData
        }
        (DurableHostCommand::PrepareConnectorMaterial { .. }, CommandDisposition::Applied) => {
            ManagedConnectorDesiredState::EnsuredStopped
        }
        (DurableHostCommand::FinalizeConnectorMaterial { .. }, CommandDisposition::Applied) => {
            ManagedConnectorDesiredState::Running
        }
        (
            DurableHostCommand::PrepareConnectorMaterial { .. },
            CommandDisposition::ExpiredUnclaimed,
        ) => return Ok(()),
        (_, CommandDisposition::ExpiredUnclaimed) => return Err(()),
    };
    if after.desired_state != expected_desired_state {
        return Err(());
    }
    Ok(())
}

fn validate_unchanged_siblings(
    predecessor: &SupervisorSnapshot,
    resulting: &SupervisorSnapshot,
    target: ConnectorId,
    target_is_new: bool,
) -> Result<(), ()> {
    for sibling in predecessor
        .instances
        .iter()
        .filter(|instance| instance.connector_id != target)
    {
        if resulting
            .instances
            .iter()
            .find(|candidate| candidate.connector_id == sibling.connector_id)
            != Some(sibling)
        {
            return Err(());
        }
    }
    if resulting.instances.len() != predecessor.instances.len() + usize::from(target_is_new) {
        return Err(());
    }
    Ok(())
}

#[allow(clippy::large_types_passed_by_value)]
fn validate_completed_snapshot_projection(
    snapshot: &SupervisorSnapshot,
    intent: &OperationIntent,
    receipt: OperationReceipt,
) -> Result<(), ()> {
    validate_snapshot_outcome(snapshot, receipt)?;
    let target = intent.command().target();
    let instance = snapshot
        .instances
        .iter()
        .find(|instance| instance.connector_id == target.connector_id())
        .ok_or(())?;
    if instance.adapter_kind != target.adapter_kind() {
        return Err(());
    }
    match intent.command() {
        DurableHostCommand::Ensure { release, .. } => {
            if instance.release != release {
                return Err(());
            }
        }
        DurableHostCommand::Start {
            release,
            credential_ref,
            credential_operation_id,
            ..
        }
        | DurableHostCommand::Restart {
            release,
            credential_ref,
            credential_operation_id,
            ..
        } => {
            if instance.release != release
                || instance.credential_ref != Some(credential_ref)
                || instance.credential_operation_id != Some(credential_operation_id)
            {
                return Err(());
            }
        }
        DurableHostCommand::RotateCredential {
            release,
            credential_ref,
            resulting_generation,
            ..
        } => {
            if instance.release != release
                || instance.credential_ref != Some(credential_ref)
                || instance.credential_generation != resulting_generation
                || instance.credential_operation_id != Some(intent.operation_id())
            {
                return Err(());
            }
        }
        DurableHostCommand::Stop { .. }
        | DurableHostCommand::RemoveRetainingData { .. }
        | DurableHostCommand::PrepareConnectorMaterial { .. }
        | DurableHostCommand::FinalizeConnectorMaterial { .. } => {}
    }
    Ok(())
}

#[allow(clippy::large_types_passed_by_value)]
fn validate_snapshot_outcome(
    snapshot: &SupervisorSnapshot,
    receipt: OperationReceipt,
) -> Result<(), ()> {
    let outcome = receipt.outcome();
    let instance = snapshot
        .instances
        .iter()
        .find(|instance| instance.connector_id == outcome.connector_id)
        .ok_or(())?;
    if snapshot_fence(snapshot) != Some(outcome.revisions)
        || instance.desired_state != outcome.desired_state
        || instance.observation != outcome.observation
        || instance.credential_generation != outcome.credential_generation
    {
        return Err(());
    }
    Ok(())
}

const fn snapshot_observation_is_valid(
    desired: ManagedConnectorDesiredState,
    observation: ProcessObservation,
) -> bool {
    matches!(
        (desired, observation),
        (
            ManagedConnectorDesiredState::EnsuredStopped | ManagedConnectorDesiredState::Stopped,
            ProcessObservation::Stopped
        ) | (
            ManagedConnectorDesiredState::Running,
            ProcessObservation::Running | ProcessObservation::Failed
        ) | (
            ManagedConnectorDesiredState::RemovedRetainingData,
            ProcessObservation::Absent
        )
    )
}

fn open_lock_file(path: &Path) -> Result<File, PortError> {
    if path.try_exists().map_err(|_| unavailable())? {
        ensure_secure_file(path)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|_| unavailable())?;
    ensure_secure_open_file(&file)?;
    ensure_secure_file(path)?;
    Ok(file)
}

fn secure_create_new(path: &Path) -> Result<File, PortError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|_| unavailable())?;
    ensure_secure_open_file(&file)?;
    Ok(file)
}

fn ensure_secure_file(path: &Path) -> Result<(), PortError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid());
    }
    ensure_secure_metadata(&metadata)
}

fn ensure_secure_open_file(file: &File) -> Result<(), PortError> {
    let metadata = file.metadata().map_err(|_| unavailable())?;
    if !metadata.is_file() {
        return Err(invalid());
    }
    ensure_secure_metadata(&metadata)
}

#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn ensure_secure_metadata(metadata: &fs::Metadata) -> Result<(), PortError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(invalid());
        }
    }
    #[cfg(all(target_os = "linux", not(test)))]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.uid() != 0 {
            return Err(invalid());
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    Ok(())
}

#[cfg(all(target_os = "linux", not(test)))]
fn prepare_production_directory(directory: &Path) -> Result<(), PortError> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

    if directory.parent() != Some(Path::new(PRODUCTION_ROOT)) {
        return Err(invalid());
    }
    let paths = [
        (Path::new("/var/lib"), None),
        (Path::new("/var/lib/dirextalk"), Some(0o755)),
        (Path::new("/var/lib/dirextalk/host-supervisor"), Some(0o755)),
        (Path::new(PRODUCTION_ROOT), Some(0o755)),
        (directory, Some(0o700)),
    ];
    for (path, create_mode) in paths {
        match fs::symlink_metadata(path) {
            Ok(metadata) => validate_production_directory(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mode = create_mode.ok_or_else(invalid)?;
                match fs::DirBuilder::new().mode(mode).create(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(_) => return Err(unavailable()),
                }
                let metadata = fs::symlink_metadata(path).map_err(|_| unavailable())?;
                validate_production_directory(&metadata)?;
            }
            Err(_) => return Err(unavailable()),
        }
    }
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(|_| unavailable())?;
    let metadata = fs::symlink_metadata(directory).map_err(|_| unavailable())?;
    validate_production_directory(&metadata)?;
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(test)))]
fn validate_production_directory(metadata: &fs::Metadata) -> Result<(), PortError> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(unix)]
fn replace_file(source: &Path, destination: &Path) -> Result<(), PortError> {
    fs::rename(source, destination).map_err(|_| unavailable())
}

#[cfg(not(unix))]
fn replace_file(source: &Path, destination: &Path) -> Result<(), PortError> {
    if destination.try_exists().map_err(|_| unavailable())? {
        fs::remove_file(destination).map_err(|_| unavailable())?;
    }
    fs::rename(source, destination).map_err(|_| unavailable())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), PortError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| unavailable())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_directory(_directory: &Path) -> Result<(), PortError> {
    Ok(())
}

const fn unavailable() -> PortError {
    PortError::new(PortErrorKind::Unavailable)
}

const fn conflict() -> PortError {
    PortError::new(PortErrorKind::Conflict)
}

const fn invalid() -> PortError {
    PortError::new(PortErrorKind::InvalidArtifact)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::{Arc, Barrier},
        thread,
    };

    use dtx_connect_registry::AdapterKind;
    use dtx_domain::{ConnectorId, HostId, Revision, TenantId};
    use serde_json::Value;

    use super::{FileJournal, JOURNAL_FILE, JournalFile, VERSION, validate_snapshot_transition};
    use crate::{
        CatalogRelease, CommandDisposition, CommandOutcome, ConfigDigest, ConnectorLifecycleFacts,
        ConnectorLifecycleOperationId, ConnectorTarget, CredentialArtifactRef, DurableHostCommand,
        HandoffDigest, HostCommand, HostCommandEnvelope, HostOperationId, HostRevisionFence,
        Journal, JournalRecord, ManagedConnectorDesiredState, ManagedConnectorSnapshot,
        MaterialDigest, OperationIntent, OperationReceipt, PlanDigest, PlatformTarget,
        PortErrorKind, ProcessObservation, ReleaseDigest, RemovalPolicy, ResourceProfile,
        SupervisorSnapshot, TrustDigest,
    };

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "dirextalk-file-journal-{}",
                uuid::Uuid::now_v7().hyphenated()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn journal_path(&self, host_id: HostId) -> PathBuf {
            self.0.join(host_id.to_string()).join(JOURNAL_FILE)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Case {
        Ensure,
        Start,
        Stop,
        Restart,
        Rotate,
        Remove,
    }

    #[test]
    fn pre_install_proof_v4_records_retain_their_exact_hash_input() {
        for fixture in [
            include_bytes!("fixtures/pre_install_proof_v4_completed.json").as_slice(),
            include_bytes!("fixtures/pre_install_proof_v4_completed_pending.json").as_slice(),
        ] {
            // `apply_patch` terminates text fixtures; the base v4 writer did
            // not.  Compare the exact writer bytes, not that source newline.
            let fixture = fixture.strip_suffix(b"\n").unwrap_or(fixture);
            let decoded: JournalFile = serde_json::from_slice(fixture).unwrap();
            let host_id = decoded.host_id;
            let operation_id = decoded.records[0].operation_id();
            assert_eq!(serde_json::to_vec(&decoded).unwrap(), fixture);

            let root = TempRoot::new();
            let path = root.journal_path(host_id);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, fixture).unwrap();
            #[cfg(unix)]
            fs::set_permissions(&path, {
                use std::os::unix::fs::PermissionsExt as _;
                fs::Permissions::from_mode(0o600)
            })
            .unwrap();
            let mut journal = FileJournal::for_test_root(root.path(), host_id);
            assert!(journal.load_snapshot(host_id).unwrap().is_some());
            assert!(matches!(
                journal.lookup(host_id, operation_id).unwrap(),
                Some(JournalRecord::Completed { .. })
            ));
            assert_eq!(fs::read(path).unwrap(), fixture);
        }
    }

    #[test]
    fn record_chain_rejects_incomplete_truncation_and_renumbering_with_stale_chain_metadata() {
        let root = TempRoot::new();
        let tenant_id = TenantId::new();
        let host_id = HostId::new();
        let connector_id = ConnectorId::new();
        let mut journal = FileJournal::for_test_root(root.path(), host_id);
        let mut current = initial_snapshot(tenant_id, host_id);
        for case in [Case::Ensure, Case::Rotate, Case::Start] {
            let (intent, receipt, resulting) = operation(&current, connector_id, case);
            journal.persist_intent(intent, &current).unwrap();
            journal.complete(receipt, &resulting).unwrap();
            current = resulting;
        }

        let path = root.journal_path(host_id);
        let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

        let mut prefix_removed = original.clone();
        prefix_removed["records"].as_array_mut().unwrap().remove(0);
        for (index, record) in prefix_removed["records"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            record["sequence"] = Value::from(u64::try_from(index + 1).unwrap());
        }
        prefix_removed["generation"] = Value::from(4_u64);
        fs::write(&path, serde_json::to_vec(&prefix_removed).unwrap()).unwrap();
        assert_eq!(
            journal.load_snapshot(host_id).unwrap_err().kind(),
            PortErrorKind::InvalidArtifact
        );

        let mut suffix_removed = original.clone();
        suffix_removed["records"].as_array_mut().unwrap().pop();
        suffix_removed["generation"] = Value::from(4_u64);
        suffix_removed["snapshot"] = suffix_removed["records"][1]["resulting_snapshot"].clone();
        fs::write(&path, serde_json::to_vec(&suffix_removed).unwrap()).unwrap();
        assert_eq!(
            journal.load_snapshot(host_id).unwrap_err().kind(),
            PortErrorKind::InvalidArtifact
        );

        let mut renumbered = original;
        renumbered["records"][1]["sequence"] = Value::from(99_u64);
        fs::write(&path, serde_json::to_vec(&renumbered).unwrap()).unwrap();
        assert_eq!(
            journal.load_snapshot(host_id).unwrap_err().kind(),
            PortErrorKind::InvalidArtifact
        );
    }

    #[test]
    fn completing_the_tail_preserves_its_sequence_and_advances_the_chain_tip() {
        let root = TempRoot::new();
        let tenant_id = TenantId::new();
        let host_id = HostId::new();
        let predecessor = initial_snapshot(tenant_id, host_id);
        let (intent, receipt, resulting) =
            operation(&predecessor, ConnectorId::new(), Case::Ensure);
        let mut journal = FileJournal::for_test_root(root.path(), host_id);
        journal.persist_intent(intent, &predecessor).unwrap();
        let path = root.journal_path(host_id);
        let pending: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let pending_sequence = pending["records"][0]["sequence"].clone();
        let pending_predecessor = pending["records"][0]["previous_record_digest"].clone();
        let pending_tip = pending["chain_tip"].clone();

        journal.complete(receipt, &resulting).unwrap();
        let completed: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(completed["records"][0]["sequence"], pending_sequence);
        assert_eq!(
            completed["records"][0]["previous_record_digest"],
            pending_predecessor
        );
        assert_ne!(completed["chain_tip"], pending_tip);
    }

    #[test]
    fn sequential_expired_unclaimed_prepares_chain_at_the_unchanged_fence_and_rehydrate() {
        let root = TempRoot::new();
        let tenant_id = TenantId::new();
        let host_id = HostId::new();
        let predecessor = initial_snapshot(tenant_id, host_id);
        let (first_intent, first_receipt) =
            expired_unclaimed_prepare(&predecessor, ConnectorId::new());
        let (second_intent, second_receipt) =
            expired_unclaimed_prepare(&predecessor, ConnectorId::new());
        let mut journal = FileJournal::for_test_root(root.path(), host_id);

        journal
            .persist_intent(first_intent.clone(), &predecessor)
            .unwrap();
        journal.complete(first_receipt, &predecessor).unwrap();
        journal
            .persist_intent(second_intent.clone(), &predecessor)
            .unwrap();
        journal.complete(second_receipt, &predecessor).unwrap();

        assert_eq!(
            journal.load_snapshot(host_id).unwrap(),
            Some(predecessor.clone())
        );
        assert!(matches!(
            journal
                .lookup(host_id, first_intent.operation_id())
                .unwrap(),
            Some(JournalRecord::Completed { .. })
        ));
        assert!(matches!(
            journal
                .lookup(host_id, second_intent.operation_id())
                .unwrap(),
            Some(JournalRecord::Completed { .. })
        ));

        let path = root.journal_path(host_id);
        let mut tampered: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        tampered["records"][1]["resulting_snapshot"]["desired_revision"] = Value::from(2_u64);
        fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert_eq!(
            journal.load_snapshot(host_id).unwrap_err().kind(),
            PortErrorKind::InvalidArtifact
        );
    }

    #[test]
    fn lifecycle_preconditions_and_rotate_state_preservation_fail_closed() {
        let tenant_id = TenantId::new();
        let host_id = HostId::new();
        let connector_id = ConnectorId::new();
        let initial = initial_snapshot(tenant_id, host_id);
        let ensured = apply_valid_operation(&initial, connector_id, Case::Ensure);
        let rotated = apply_valid_operation(&ensured, connector_id, Case::Rotate);
        let running = apply_valid_operation(&rotated, connector_id, Case::Start);
        let stopped = apply_valid_operation(&running, connector_id, Case::Stop);
        let removed = apply_valid_operation(&stopped, connector_id, Case::Remove);

        for (label, predecessor, case) in [
            ("ensure from running", &running, Case::Ensure),
            ("ensure from removed", &removed, Case::Ensure),
            ("start from removed", &removed, Case::Start),
            ("stop from removed", &removed, Case::Stop),
            ("restart from removed", &removed, Case::Restart),
            ("rotate from removed", &removed, Case::Rotate),
            ("remove from removed", &removed, Case::Remove),
        ] {
            let (intent, receipt, resulting) = operation(predecessor, connector_id, case);
            assert!(
                validate_snapshot_transition(predecessor, &resulting, &intent, receipt).is_err(),
                "{label} must be rejected"
            );
        }

        let (intent, _, mut forged_running) = operation(&stopped, connector_id, Case::Rotate);
        let forged_instance = forged_running
            .instances
            .iter_mut()
            .find(|instance| instance.connector_id == connector_id)
            .unwrap();
        forged_instance.desired_state = ManagedConnectorDesiredState::Running;
        forged_instance.observation = ProcessObservation::Running;
        let forged_receipt = OperationReceipt::new(
            intent.operation_id(),
            intent.command_digest(),
            CommandOutcome {
                connector_id,
                revisions: intent.resulting(),
                disposition: CommandDisposition::Applied,
                desired_state: ManagedConnectorDesiredState::Running,
                observation: ProcessObservation::Running,
                credential_generation: forged_instance.credential_generation,
            },
        );
        assert!(
            validate_snapshot_transition(&stopped, &forged_running, &intent, forged_receipt)
                .is_err(),
            "rotation must preserve the predecessor desired state"
        );
    }

    #[test]
    fn full_pending_and_completed_records_round_trip_exactly() {
        let root = TempRoot::new();
        let tenant_id = TenantId::new();
        let host_id = HostId::new();
        let mut journal = FileJournal::for_test_root(root.path(), host_id);
        let connector_id = ConnectorId::new();
        let mut current = initial_snapshot(tenant_id, host_id);
        let cases = [
            Case::Ensure,
            Case::Rotate,
            Case::Start,
            Case::Stop,
            Case::Restart,
            Case::Rotate,
            Case::Remove,
        ];
        let mut expected = Vec::new();

        for case in cases {
            let (intent, receipt, resulting) = operation(&current, connector_id, case);
            journal.persist_intent(intent.clone(), &current).unwrap();
            journal.persist_intent(intent.clone(), &current).unwrap();
            assert_eq!(
                journal.load_snapshot(host_id).unwrap(),
                Some(current.clone())
            );
            assert_eq!(
                journal.lookup(host_id, intent.operation_id()).unwrap(),
                Some(JournalRecord::Pending(intent.clone()))
            );
            assert_eq!(journal.pending(host_id).unwrap(), vec![intent.clone()]);
            journal.complete(receipt, &resulting).unwrap();
            journal.complete(receipt, &resulting).unwrap();
            assert_eq!(
                journal.load_snapshot(host_id).unwrap(),
                Some(resulting.clone())
            );
            let completed = JournalRecord::Completed {
                intent: intent.clone(),
                receipt,
            };
            assert_eq!(
                journal.lookup(host_id, intent.operation_id()).unwrap(),
                Some(completed.clone())
            );
            expected.push((intent.operation_id(), completed));
            current = resulting;
        }

        assert!(journal.pending(host_id).unwrap().is_empty());
        let mut reopened = FileJournal::for_test_root(root.path(), host_id);
        for (operation_id, record) in expected {
            assert_eq!(
                reopened.lookup(host_id, operation_id).unwrap(),
                Some(record)
            );
        }
        assert_eq!(reopened.load_snapshot(host_id).unwrap(), Some(current));
        assert!(
            fs::read_dir(root.path().join(host_id.to_string()))
                .unwrap()
                .all(|entry| !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp"))
        );

        let path = root.journal_path(host_id);
        let original: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let mut tampered_receipt = original.clone();
        tampered_receipt["records"][0]["receipt"]["outcome"]["credential_generation"] =
            Value::from(7_u64);
        fs::write(&path, serde_json::to_vec(&tampered_receipt).unwrap()).unwrap();
        assert_eq!(
            reopened.load_snapshot(host_id).unwrap_err().kind(),
            PortErrorKind::InvalidArtifact
        );

        let mut reordered = original;
        reordered["records"].as_array_mut().unwrap().swap(0, 1);
        fs::write(&path, serde_json::to_vec(&reordered).unwrap()).unwrap();
        assert_eq!(
            reopened.load_snapshot(host_id).unwrap_err().kind(),
            PortErrorKind::InvalidArtifact
        );
    }

    #[test]
    fn policy_blocked_start_and_restart_round_trip_as_stopped_compensations() {
        for blocked_case in [Case::Start, Case::Restart] {
            let root = TempRoot::new();
            let tenant_id = TenantId::new();
            let host_id = HostId::new();
            let connector_id = ConnectorId::new();
            let mut journal = FileJournal::for_test_root(root.path(), host_id);
            let mut current = initial_snapshot(tenant_id, host_id);
            let preparation: &[Case] = match blocked_case {
                Case::Start => &[Case::Ensure, Case::Rotate],
                Case::Restart => &[Case::Ensure, Case::Rotate, Case::Start],
                Case::Ensure | Case::Stop | Case::Rotate | Case::Remove => unreachable!(),
            };

            for case in preparation {
                let (intent, receipt, resulting) = operation(&current, connector_id, *case);
                journal.persist_intent(intent, &current).unwrap();
                journal.complete(receipt, &resulting).unwrap();
                current = resulting;
            }

            let (intent, _applied_receipt, mut resulting) =
                operation(&current, connector_id, blocked_case);
            let instance = resulting
                .instances
                .iter_mut()
                .find(|instance| instance.connector_id == connector_id)
                .unwrap();
            instance.desired_state = ManagedConnectorDesiredState::Stopped;
            instance.observation = ProcessObservation::Stopped;
            let receipt = OperationReceipt::new(
                intent.operation_id(),
                intent.command_digest(),
                CommandOutcome {
                    connector_id,
                    revisions: intent.resulting(),
                    disposition: CommandDisposition::PolicyBlocked,
                    desired_state: ManagedConnectorDesiredState::Stopped,
                    observation: ProcessObservation::Stopped,
                    credential_generation: instance.credential_generation,
                },
            );
            journal.persist_intent(intent.clone(), &current).unwrap();
            journal.complete(receipt, &resulting).unwrap();

            let mut reopened = FileJournal::for_test_root(root.path(), host_id);
            assert_eq!(
                reopened.lookup(host_id, intent.operation_id()).unwrap(),
                Some(JournalRecord::Completed { intent, receipt })
            );
            assert_eq!(reopened.load_snapshot(host_id).unwrap(), Some(resulting));
        }
    }

    #[test]
    fn exact_retries_are_idempotent_and_a_second_pending_operation_is_rejected() {
        let root = TempRoot::new();
        let tenant_id = TenantId::new();
        let host_id = HostId::new();
        let mut journal = FileJournal::for_test_root(root.path(), host_id);
        let predecessor = initial_snapshot(tenant_id, host_id);
        let (first, receipt, resulting) = operation(&predecessor, ConnectorId::new(), Case::Ensure);
        let (second, _, _) = operation(&predecessor, ConnectorId::new(), Case::Ensure);
        journal.persist_intent(first.clone(), &predecessor).unwrap();
        journal.persist_intent(first, &predecessor).unwrap();
        assert_eq!(
            journal
                .persist_intent(second, &predecessor)
                .unwrap_err()
                .kind(),
            PortErrorKind::Conflict
        );

        let (_, unknown_receipt, unknown_resulting) =
            operation(&predecessor, ConnectorId::new(), Case::Ensure);
        assert_eq!(
            journal
                .complete(unknown_receipt, &unknown_resulting)
                .unwrap_err()
                .kind(),
            PortErrorKind::Conflict
        );
        journal.complete(receipt, &resulting).unwrap();
        journal.complete(receipt, &resulting).unwrap();
        let mut divergent = resulting;
        let next = divergent.desired_revision.checked_next().unwrap();
        divergent.desired_revision = next;
        divergent.observed_revision = Some(next);
        assert_eq!(
            journal.complete(receipt, &divergent).unwrap_err().kind(),
            PortErrorKind::Conflict
        );
    }

    #[test]
    fn pending_intents_reject_adapter_switch_same_credential_and_running_ensure() {
        let root = TempRoot::new();
        let tenant_id = TenantId::new();
        let host_id = HostId::new();
        let connector_id = ConnectorId::new();
        let initial = initial_snapshot(tenant_id, host_id);
        let ensured = apply_valid_operation(&initial, connector_id, Case::Ensure);
        let stopped = apply_valid_operation(&ensured, connector_id, Case::Rotate);
        let mut journal = FileJournal::for_test_root(root.path(), host_id);

        let switched_release = CatalogRelease::approved(
            AdapterKind::OpenClawAcp,
            ReleaseDigest::from_bytes([41; 32]),
            ResourceProfile::Standard,
            Revision::INITIAL,
        );
        let switched_target =
            ConnectorTarget::new(tenant_id, host_id, connector_id, AdapterKind::OpenClawAcp);
        let adapter_switch = intent_for(
            &stopped,
            HostCommand::Ensure {
                connector_id,
                adapter_kind: AdapterKind::OpenClawAcp,
                release_digest: switched_release.digest(),
            },
            DurableHostCommand::Ensure {
                target: switched_target,
                release: switched_release,
            },
        );

        let instance = stopped
            .instances
            .iter()
            .find(|instance| instance.connector_id == connector_id)
            .unwrap();
        let same_ref = instance.credential_ref.unwrap();
        let same_credential = intent_for(
            &stopped,
            HostCommand::RotateCredential {
                connector_id,
                credential_ref: same_ref,
            },
            DurableHostCommand::RotateCredential {
                target: ConnectorTarget::new(
                    tenant_id,
                    host_id,
                    connector_id,
                    instance.adapter_kind,
                ),
                release: instance.release,
                credential_ref: same_ref,
                resulting_generation: instance.credential_generation + 1,
            },
        );

        let running = apply_valid_operation(&stopped, connector_id, Case::Start);
        let (running_ensure, _, _) = operation(&running, connector_id, Case::Ensure);
        for (label, intent, predecessor) in [
            ("adapter switch", adapter_switch, &stopped),
            ("same credential", same_credential, &stopped),
            ("running ensure", running_ensure, &running),
        ] {
            assert_eq!(
                journal
                    .persist_intent(intent, predecessor)
                    .unwrap_err()
                    .kind(),
                PortErrorKind::Conflict,
                "{label}"
            );
        }
        assert!(journal.pending(host_id).unwrap().is_empty());
        assert_eq!(journal.load_snapshot(host_id).unwrap(), None);
    }

    #[test]
    fn completed_intent_retry_requires_the_recorded_predecessor_snapshot() {
        let root = TempRoot::new();
        let tenant_id = TenantId::new();
        let host_id = HostId::new();
        let connector_id = ConnectorId::new();
        let mut journal = FileJournal::for_test_root(root.path(), host_id);
        let initial = initial_snapshot(tenant_id, host_id);
        let (ensure, ensure_receipt, ensured) = operation(&initial, connector_id, Case::Ensure);
        journal.persist_intent(ensure, &initial).unwrap();
        journal.complete(ensure_receipt, &ensured).unwrap();

        let (rotate, rotate_receipt, rotated) = operation(&ensured, connector_id, Case::Rotate);
        journal.persist_intent(rotate.clone(), &ensured).unwrap();
        journal.complete(rotate_receipt, &rotated).unwrap();
        journal.persist_intent(rotate.clone(), &ensured).unwrap();

        let mut divergent = ensured;
        divergent.instances[0].release = CatalogRelease::approved(
            AdapterKind::Codex,
            ReleaseDigest::from_bytes([42; 32]),
            ResourceProfile::Compute,
            Revision::INITIAL,
        );
        assert_eq!(
            journal
                .persist_intent(rotate, &divergent)
                .unwrap_err()
                .kind(),
            PortErrorKind::Conflict
        );
    }

    #[test]
    fn file_lock_serializes_competing_writers() {
        let root = TempRoot::new();
        let tenant_id = TenantId::new();
        let host_id = HostId::new();
        let predecessor = initial_snapshot(tenant_id, host_id);
        let (first, _, _) = operation(&predecessor, ConnectorId::new(), Case::Ensure);
        let (second, _, _) = operation(&predecessor, ConnectorId::new(), Case::Ensure);
        let barrier = Arc::new(Barrier::new(3));
        let handles = [first, second].map(|intent| {
            let barrier = Arc::clone(&barrier);
            let root = root.path().to_owned();
            let predecessor = predecessor.clone();
            thread::spawn(move || {
                let mut journal = FileJournal::for_test_root(&root, host_id);
                barrier.wait();
                journal.persist_intent(intent, &predecessor)
            })
        });
        barrier.wait();
        let results = handles.map(|handle| handle.join().unwrap());
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| result
                    .as_ref()
                    .is_err_and(|error| { error.kind() == PortErrorKind::Conflict }))
                .count(),
            1
        );
        assert_eq!(
            FileJournal::for_test_root(root.path(), host_id)
                .pending(host_id)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn malformed_schema_generation_host_and_truncation_fail_closed() {
        let root = TempRoot::new();
        let tenant_id = TenantId::new();
        let host_id = HostId::new();
        let predecessor = initial_snapshot(tenant_id, host_id);
        let (intent, receipt, resulting) =
            operation(&predecessor, ConnectorId::new(), Case::Ensure);
        let mut journal = FileJournal::for_test_root(root.path(), host_id);
        journal
            .persist_intent(intent.clone(), &predecessor)
            .unwrap();
        journal.complete(receipt, &resulting).unwrap();
        let path = root.journal_path(host_id);
        let original = fs::read(&path).unwrap();

        for mutation in [
            "schema",
            "version",
            "generation",
            "genesis_anchor",
            "chain_tip",
            "host",
            "snapshot_host",
            "unknown",
        ] {
            let mut value: Value = serde_json::from_slice(&original).unwrap();
            match mutation {
                "schema" => value["schema"] = Value::from("unrecognized"),
                "version" => value["version"] = Value::from(VERSION + 1),
                "generation" => value["generation"] = Value::from(1),
                "genesis_anchor" => {
                    let byte = value["genesis_anchor"][0].as_u64().unwrap();
                    value["genesis_anchor"][0] = Value::from(if byte == 255 { 0 } else { 255 });
                }
                "chain_tip" => {
                    let byte = value["chain_tip"][0].as_u64().unwrap();
                    value["chain_tip"][0] = Value::from(if byte == 255 { 0 } else { 255 });
                }
                "host" => value["host_id"] = Value::from(HostId::new().to_string()),
                "snapshot_host" => {
                    value["snapshot"]["host_id"] = Value::from(HostId::new().to_string());
                }
                "unknown" => {
                    value["unexpected"] = Value::Bool(true);
                }
                _ => unreachable!(),
            }
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(
                journal
                    .lookup(host_id, intent.operation_id())
                    .unwrap_err()
                    .kind(),
                PortErrorKind::InvalidArtifact
            );
            fs::write(&path, &original).unwrap();
        }

        fs::write(&path, b"{\"schema\":").unwrap();
        assert_eq!(
            journal
                .lookup(host_id, intent.operation_id())
                .unwrap_err()
                .kind(),
            PortErrorKind::InvalidArtifact
        );
    }

    #[test]
    fn cold_read_rejects_snapshot_credential_that_diverges_from_last_intent() {
        let root = TempRoot::new();
        let tenant_id = TenantId::new();
        let host_id = HostId::new();
        let connector_id = ConnectorId::new();
        let mut journal = FileJournal::for_test_root(root.path(), host_id);
        let mut current = initial_snapshot(tenant_id, host_id);
        let mut last_operation = None;
        for case in [Case::Ensure, Case::Rotate, Case::Start] {
            let (intent, receipt, resulting) = operation(&current, connector_id, case);
            journal.persist_intent(intent.clone(), &current).unwrap();
            journal.complete(receipt, &resulting).unwrap();
            last_operation = Some(intent.operation_id());
            current = resulting;
        }

        let path = root.journal_path(host_id);
        let original = fs::read(&path).unwrap();
        for field in ["credential_ref", "credential_operation_id"] {
            let mut value: Value = serde_json::from_slice(&original).unwrap();
            value["snapshot"]["instances"][0][field] = match field {
                "credential_ref" => serde_json::to_value([99_u8; 32]).unwrap(),
                "credential_operation_id" => {
                    serde_json::to_value(HostOperationId::new().as_request_id()).unwrap()
                }
                _ => unreachable!(),
            };
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(
                journal
                    .lookup(host_id, last_operation.unwrap())
                    .unwrap_err()
                    .kind(),
                PortErrorKind::InvalidArtifact
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn journal_rejects_insecure_permissions_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = TempRoot::new();
        let tenant_id = TenantId::new();
        let host_id = HostId::new();
        let predecessor = initial_snapshot(tenant_id, host_id);
        let (intent, _, _) = operation(&predecessor, ConnectorId::new(), Case::Ensure);
        let mut journal = FileJournal::for_test_root(root.path(), host_id);
        journal
            .persist_intent(intent.clone(), &predecessor)
            .unwrap();
        let path = root.journal_path(host_id);
        let lock_path = path.with_file_name(super::LOCK_FILE);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            journal
                .lookup(host_id, intent.operation_id())
                .unwrap_err()
                .kind(),
            PortErrorKind::InvalidArtifact
        );
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            journal
                .lookup(host_id, intent.operation_id())
                .unwrap_err()
                .kind(),
            PortErrorKind::InvalidArtifact
        );

        fs::remove_file(&path).unwrap();
        let target = root.path().join("target.json");
        fs::write(&target, b"{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &path).unwrap();
        assert_eq!(
            journal
                .lookup(host_id, intent.operation_id())
                .unwrap_err()
                .kind(),
            PortErrorKind::InvalidArtifact
        );
    }

    fn initial_snapshot(tenant_id: TenantId, host_id: HostId) -> SupervisorSnapshot {
        SupervisorSnapshot {
            tenant_id,
            host_id,
            desired_revision: Revision::INITIAL,
            observed_revision: Some(Revision::INITIAL),
            instances: Vec::new(),
        }
    }

    fn expired_unclaimed_prepare(
        predecessor: &SupervisorSnapshot,
        connector_id: ConnectorId,
    ) -> (OperationIntent, OperationReceipt) {
        let expected = HostRevisionFence::from_revisions(
            predecessor.desired_revision,
            predecessor.observed_revision,
        )
        .unwrap();
        let release = ReleaseDigest::from_bytes([7; 32]);
        let facts = ConnectorLifecycleFacts::new(
            ConnectorLifecycleOperationId::new(),
            PlatformTarget::LinuxAmd64,
            AdapterKind::Codex,
            release,
            predecessor.tenant_id,
            predecessor.host_id,
            connector_id,
            1,
            PlanDigest::from_bytes([1; 32]),
            HandoffDigest::from_bytes([2; 32]),
            ConfigDigest::from_bytes([3; 32]),
            TrustDigest::from_bytes([4; 32]),
            MaterialDigest::from_bytes([5; 32]),
        );
        let envelope = HostCommandEnvelope::new(
            predecessor.tenant_id,
            predecessor.host_id,
            HostOperationId::new(),
            expected,
            HostCommand::PrepareConnectorMaterial { facts },
        );
        let intent = OperationIntent::new(
            envelope,
            expected.advance_and_acknowledge().unwrap(),
            DurableHostCommand::PrepareConnectorMaterial { facts },
        );
        let receipt = OperationReceipt::new(
            intent.operation_id(),
            intent.command_digest(),
            CommandOutcome {
                connector_id,
                revisions: expected,
                disposition: CommandDisposition::ExpiredUnclaimed,
                desired_state: ManagedConnectorDesiredState::EnsuredStopped,
                observation: ProcessObservation::Absent,
                credential_generation: 0,
            },
        );
        (intent, receipt)
    }

    fn apply_valid_operation(
        predecessor: &SupervisorSnapshot,
        connector_id: ConnectorId,
        case: Case,
    ) -> SupervisorSnapshot {
        let (intent, receipt, resulting) = operation(predecessor, connector_id, case);
        validate_snapshot_transition(predecessor, &resulting, &intent, receipt).unwrap();
        resulting
    }

    #[allow(clippy::large_types_passed_by_value)]
    fn intent_for(
        predecessor: &SupervisorSnapshot,
        requested: HostCommand,
        durable: DurableHostCommand,
    ) -> OperationIntent {
        let expected = HostRevisionFence::from_revisions(
            predecessor.desired_revision,
            predecessor.observed_revision,
        )
        .unwrap();
        let resulting = expected.advance_and_acknowledge().unwrap();
        let envelope = HostCommandEnvelope::new(
            predecessor.tenant_id,
            predecessor.host_id,
            HostOperationId::new(),
            expected,
            requested,
        );
        OperationIntent::new(envelope, resulting, durable)
    }

    #[allow(clippy::too_many_lines)]
    fn operation(
        predecessor: &SupervisorSnapshot,
        connector_id: ConnectorId,
        case: Case,
    ) -> (OperationIntent, OperationReceipt, SupervisorSnapshot) {
        let tenant_id = predecessor.tenant_id;
        let host_id = predecessor.host_id;
        let operation_id = HostOperationId::new();
        let expected = HostRevisionFence::from_revisions(
            predecessor.desired_revision,
            predecessor.observed_revision,
        )
        .unwrap();
        let next_revision = predecessor.desired_revision.checked_next().unwrap();
        let resulting =
            HostRevisionFence::from_revisions(next_revision, Some(next_revision)).unwrap();
        let adapter_kind = AdapterKind::Codex;
        let digest = ReleaseDigest::from_bytes([7; 32]);
        let release = CatalogRelease::approved(
            adapter_kind,
            digest,
            ResourceProfile::Standard,
            Revision::INITIAL,
        );
        let target = ConnectorTarget::new(tenant_id, host_id, connector_id, adapter_kind);
        let current_instance = predecessor
            .instances
            .iter()
            .find(|instance| instance.connector_id == connector_id);
        let current_generation =
            current_instance.map_or(0, |instance| instance.credential_generation);
        let current_credential_ref = current_instance.and_then(|instance| instance.credential_ref);
        let current_credential_operation_id =
            current_instance.and_then(|instance| instance.credential_operation_id);
        let credential_ref =
            CredentialArtifactRef::from_bytes([u8::try_from(9 + current_generation).unwrap(); 32]);
        let (
            requested,
            durable,
            desired_state,
            observation,
            credential_generation,
            resulting_credential_ref,
            resulting_credential_operation_id,
        ) = match case {
            Case::Ensure => (
                HostCommand::Ensure {
                    connector_id,
                    adapter_kind,
                    release_digest: digest,
                },
                DurableHostCommand::Ensure { target, release },
                ManagedConnectorDesiredState::EnsuredStopped,
                ProcessObservation::Stopped,
                current_generation,
                current_credential_ref,
                current_credential_operation_id,
            ),
            Case::Start => (
                HostCommand::Start { connector_id },
                DurableHostCommand::Start {
                    target,
                    release,
                    credential_ref: current_credential_ref.unwrap(),
                    credential_operation_id: current_credential_operation_id.unwrap(),
                },
                ManagedConnectorDesiredState::Running,
                ProcessObservation::Running,
                current_generation,
                current_credential_ref,
                current_credential_operation_id,
            ),
            Case::Stop => (
                HostCommand::Stop { connector_id },
                DurableHostCommand::Stop { target },
                ManagedConnectorDesiredState::Stopped,
                ProcessObservation::Stopped,
                current_generation,
                current_credential_ref,
                current_credential_operation_id,
            ),
            Case::Restart => (
                HostCommand::Restart { connector_id },
                DurableHostCommand::Restart {
                    target,
                    release,
                    credential_ref: current_credential_ref.unwrap(),
                    credential_operation_id: current_credential_operation_id.unwrap(),
                },
                ManagedConnectorDesiredState::Running,
                ProcessObservation::Running,
                current_generation,
                current_credential_ref,
                current_credential_operation_id,
            ),
            Case::Rotate => (
                HostCommand::RotateCredential {
                    connector_id,
                    credential_ref,
                },
                DurableHostCommand::RotateCredential {
                    target,
                    release,
                    credential_ref,
                    resulting_generation: current_generation + 1,
                },
                current_instance.unwrap().desired_state,
                current_instance.unwrap().observation,
                current_generation + 1,
                Some(credential_ref),
                Some(operation_id),
            ),
            Case::Remove => (
                HostCommand::Remove {
                    connector_id,
                    policy: RemovalPolicy::RetainData,
                },
                DurableHostCommand::RemoveRetainingData { target },
                ManagedConnectorDesiredState::RemovedRetainingData,
                ProcessObservation::Absent,
                current_generation,
                current_credential_ref,
                current_credential_operation_id,
            ),
        };
        let envelope =
            HostCommandEnvelope::new(tenant_id, host_id, operation_id, expected, requested);
        let intent = OperationIntent::new(envelope, resulting, durable);
        let receipt = OperationReceipt::new(
            operation_id,
            envelope.command_digest(),
            CommandOutcome {
                connector_id,
                revisions: resulting,
                disposition: CommandDisposition::Applied,
                desired_state,
                observation,
                credential_generation,
            },
        );
        let mut resulting_snapshot = predecessor.clone();
        resulting_snapshot.desired_revision = next_revision;
        resulting_snapshot.observed_revision = Some(next_revision);
        let instance = ManagedConnectorSnapshot {
            connector_id,
            adapter_kind,
            release,
            desired_state,
            observation,
            credential_generation,
            credential_ref: resulting_credential_ref,
            credential_operation_id: resulting_credential_operation_id,
        };
        if let Some(existing) = resulting_snapshot
            .instances
            .iter_mut()
            .find(|existing| existing.connector_id == connector_id)
        {
            *existing = instance;
        } else {
            resulting_snapshot.instances.push(instance);
        }
        (intent, receipt, resulting_snapshot)
    }
}
