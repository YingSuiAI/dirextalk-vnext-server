impl MlsCommitReceipt {
    /// Frozen protocol version of the stored receipt.
    #[must_use]
    pub const fn protocol_version(&self) -> u8 {
        self.protocol_version
    }
    /// Stable submission ID used to query after response loss.
    #[must_use]
    pub const fn submission_id(&self) -> RequestId {
        self.submission_id
    }
    /// Exact request digest retained for conflict detection.
    #[must_use]
    pub const fn request_digest(&self) -> Sha256Digest {
        self.request_digest
    }
    /// Epoch admitted by the single-node sequencer.
    #[must_use]
    pub const fn admitted_epoch(&self) -> u64 {
        self.admitted_epoch
    }
    /// New canonical conversation head.
    #[must_use]
    pub const fn head_digest(&self) -> Sha256Digest {
        self.head_digest
    }
    /// Opaque commit digest.
    #[must_use]
    pub const fn commit_digest(&self) -> Sha256Digest {
        self.commit_digest
    }
    /// Opaque Welcome digest.
    #[must_use]
    pub const fn welcome_digest(&self) -> Sha256Digest {
        self.welcome_digest
    }
    /// Exact candidate `KeyPackage` admitted by this receipt.
    #[must_use]
    pub const fn candidate_key_package_digest(&self) -> Sha256Digest {
        self.candidate_key_package_digest
    }
    /// Candidate-authored V2 join request digest for V3 receipts.
    #[must_use]
    pub const fn join_request_digest(&self) -> Option<Sha256Digest> {
        self.join_request_digest
    }
    /// Owner/Admin V2 approval request digest for V3 receipts.
    #[must_use]
    pub const fn approval_request_digest(&self) -> Option<Sha256Digest> {
        self.approval_request_digest
    }
    /// Expected and resulting product-policy revisions for a V4 removal.
    #[must_use]
    pub const fn removal_policy_revisions(&self) -> Option<(Revision, Revision)> {
        self.removal_policy_revisions
    }
    /// Canonical unsigned receipt bytes signed by the server.
    #[must_use]
    pub fn canonical_cbor(&self) -> &[u8] {
        &self.canonical_cbor
    }
    /// Digest bound by device join confirmation.
    #[must_use]
    pub const fn receipt_digest(&self) -> Sha256Digest {
        self.receipt_digest
    }
    /// Server receipt verification key.
    #[must_use]
    pub const fn signing_public_key(&self) -> SigningPublicKey {
        self.signing_public_key
    }
    /// Server receipt signature.
    #[must_use]
    pub const fn signature(&self) -> Ed25519Signature {
        self.signature
    }
}

/// Submit outcome distinguishing a first response from exact replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsCommitExecution {
    receipt: MlsCommitReceipt,
    replayed: bool,
}

/// One immutable V30 commit-feed item. The signed receipt and opaque commit
/// bytes are loaded from the same durable sequencer intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsCommitFeedItem {
    receipt: MlsCommitReceipt,
    commit_bytes: Vec<u8>,
}

impl MlsCommitFeedItem {
    /// Exact signed receipt facts for the admitted commit.
    #[must_use]
    pub fn receipt(&self) -> &MlsCommitReceipt {
        &self.receipt
    }

    /// Exact opaque MLS Commit bytes submitted for this epoch.
    #[must_use]
    pub fn commit_bytes(&self) -> &[u8] {
        &self.commit_bytes
    }
}

/// Bounded keyset page of consecutive V30 commits after one known epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsCommitFeedPage {
    after_epoch: u64,
    items: Vec<MlsCommitFeedItem>,
}

impl MlsCommitFeedPage {
    /// Epoch supplied by the caller.
    #[must_use]
    pub const fn after_epoch(&self) -> u64 {
        self.after_epoch
    }

    /// Consecutive V30 commits ordered by admitted epoch.
    #[must_use]
    pub fn items(&self) -> &[MlsCommitFeedItem] {
        &self.items
    }
}

impl MlsCommitExecution {
    /// Immutable receipt.
    #[must_use]
    pub fn receipt(&self) -> &MlsCommitReceipt {
        &self.receipt
    }
    /// Whether a durable response was replayed.
    #[must_use]
    pub const fn replayed(&self) -> bool {
        self.replayed
    }
}

/// Exact state of an identity/device MLS leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlsDeviceMemberState {
    PendingConfirmation,
    Active,
    Removed,
}

/// Candidate-signed confirmation of the accepted receipt and current head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlsDeviceJoinConfirmation {
    pub submission_id: RequestId,
    pub identity_id: IdentityId,
    pub device_id: DeviceId,
    pub receipt_digest: Sha256Digest,
    pub head_digest: Sha256Digest,
    pub signature: Ed25519Signature,
}

/// Durable single-node sequencer repository.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlsCommitSequencerRepository;
