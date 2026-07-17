#![forbid(unsafe_code)]

//! Pure verification and state types for independently operated public Indexers.

use std::{
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use base64ct::{Base64UrlUnpadded, Encoding as _};
use dtx_domain::{DirectoryRegistrationId, IndexerId, PublicSubjectId, TenantId};
use dtx_public_descriptor::{DescriptorHeadV1, SignedPublicDescriptorV1};
use dtx_public_feed::{PublicFeedHeadV1, PublicFeedPayloadV1, SignedPublicFeedEventV1};
use dtx_wire::{
    CanonicalEncode, CanonicalValue, ProtocolVersion, SafeUint, Sha256Digest, UtcMillis,
    WireVersion, decode_deterministic_cbor, encode_deterministic_cbor,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const MAX_RESOLVED_ADDRESSES: usize = 16;
const MAX_FEED_PAGES: usize = 64;
const MAX_FEED_ENTRIES: usize = 4_096;
const MAX_SEARCH_QUERY_BYTES: usize = 256;
const MAX_SEARCH_PAGE_SIZE: u16 = 50;
const MAX_SEARCH_OFFSET: u64 = 10_000;
const MAX_SEARCH_CURSOR_CHARS: usize = 512;
const SEARCH_CURSOR_BINDING_DOMAIN: &[u8] = b"dirextalk.public-search-cursor.v1\0";

/// Durable per-Indexer registration projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i16)]
pub enum RegistrationStatusV1 {
    Pending = 1,
    Published = 2,
    Rejected = 3,
    Stale = 4,
    Revoked = 5,
}
impl RegistrationStatusV1 {
    #[must_use]
    pub const fn code(self) -> i16 {
        self as i16
    }

    #[must_use]
    pub const fn wire_code(self) -> u64 {
        match self {
            Self::Pending => 1,
            Self::Published => 2,
            Self::Rejected => 3,
            Self::Stale => 4,
            Self::Revoked => 5,
        }
    }
}

/// Stable verification failures persisted without untrusted provider detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexerError {
    InvalidOrigin,
    UnsafeAddress,
    TooManyAddresses,
    InvalidDescriptor,
    DescriptorMismatch,
    DescriptorExpired,
    Downgrade,
    InvalidFeed,
    FeedTooLarge,
    InvalidCursor,
}
impl fmt::Display for IndexerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidOrigin => "invalid public feed origin",
            Self::UnsafeAddress => "public feed origin resolved to a forbidden address",
            Self::TooManyAddresses => "public feed origin resolved to too many addresses",
            Self::InvalidDescriptor => "invalid signed public descriptor",
            Self::DescriptorMismatch => "fetched descriptor does not match the registered proof",
            Self::DescriptorExpired => "public descriptor is expired or not yet active",
            Self::Downgrade => "public descriptor would downgrade accepted state",
            Self::InvalidFeed => "invalid signed public feed proof",
            Self::FeedTooLarge => "public feed proof exceeds indexing bounds",
            Self::InvalidCursor => "invalid public search cursor",
        })
    }
}

/// Returns the one canonical query representation used by SQL, cache keys,
/// and cursor bindings. Oversized or whitespace-only input is rejected before
/// allocating an unbounded normalized value.
#[must_use]
pub fn normalize_public_search_query(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > MAX_SEARCH_QUERY_BYTES {
        return None;
    }
    let normalized = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    (!normalized.is_empty() && normalized.len() <= MAX_SEARCH_QUERY_BYTES).then_some(normalized)
}

/// Opaque continuation for one durable Indexer search generation.
///
/// The cursor carries no authority. Its binding digest prevents accidental or
/// partial field substitution, while the HTTP boundary also compares its
/// generation with the current persistent projection and bounds the offset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicSearchCursorV1 {
    binding_digest: Sha256Digest,
    generation: SafeUint,
    offset: SafeUint,
    limit: u16,
}

impl PublicSearchCursorV1 {
    /// Creates a query/filter/limit/generation-bound continuation.
    ///
    /// # Errors
    /// Returns `InvalidCursor` for noncanonical input or unsafe bounds.
    pub fn new(
        tenant: TenantId,
        indexer: IndexerId,
        normalized_query: &str,
        kind: Option<u8>,
        generation: u64,
        offset: u64,
        limit: u16,
    ) -> Result<Self, IndexerError> {
        if normalize_public_search_query(normalized_query).as_deref() != Some(normalized_query)
            || !matches!(kind, None | Some(1 | 2))
            || generation == 0
            || offset == 0
            || offset > MAX_SEARCH_OFFSET
            || !(1..=MAX_SEARCH_PAGE_SIZE).contains(&limit)
            || !offset.is_multiple_of(u64::from(limit))
        {
            return Err(IndexerError::InvalidCursor);
        }
        let generation = SafeUint::new(generation).map_err(|_| IndexerError::InvalidCursor)?;
        let offset = SafeUint::new(offset).map_err(|_| IndexerError::InvalidCursor)?;
        let binding_digest = public_search_scope_digest(
            tenant,
            indexer,
            normalized_query,
            kind,
            generation.get(),
            offset.get(),
            limit,
        )?;
        Ok(Self {
            binding_digest,
            generation,
            offset,
            limit,
        })
    }

    /// Decodes exact canonical CBOR from unpadded base64url and validates the
    /// current durable generation plus every canonical query dimension.
    ///
    /// An omitted requested limit adopts the cursor's bound limit. A supplied
    /// limit must match exactly.
    ///
    /// # Errors
    /// Returns `InvalidCursor` for malformed, stale, cross-query, cross-tenant,
    /// cross-Indexer, or limit-substituted cursors.
    pub fn decode_for(
        value: &str,
        tenant: TenantId,
        indexer: IndexerId,
        normalized_query: &str,
        kind: Option<u8>,
        current_generation: u64,
        requested_limit: Option<u16>,
    ) -> Result<Self, IndexerError> {
        if value.len() > MAX_SEARCH_CURSOR_CHARS {
            return Err(IndexerError::InvalidCursor);
        }
        let bytes =
            Base64UrlUnpadded::decode_vec(value).map_err(|_| IndexerError::InvalidCursor)?;
        let root = decode_deterministic_cbor(&bytes).map_err(|_| IndexerError::InvalidCursor)?;
        let fields = map(&root, 5).map_err(|_| IndexerError::InvalidCursor)?;
        wire(field(fields, 1).map_err(|_| IndexerError::InvalidCursor)?)
            .map_err(|_| IndexerError::InvalidCursor)?;
        let binding_digest = Sha256Digest::from_bytes(
            bytes32(field(fields, 2).map_err(|_| IndexerError::InvalidCursor)?)
                .map_err(|_| IndexerError::InvalidCursor)?,
        );
        let generation = unsigned(field(fields, 3).map_err(|_| IndexerError::InvalidCursor)?)
            .map_err(|_| IndexerError::InvalidCursor)?;
        let offset = unsigned(field(fields, 4).map_err(|_| IndexerError::InvalidCursor)?)
            .map_err(|_| IndexerError::InvalidCursor)?;
        let limit = u16::try_from(
            unsigned(field(fields, 5).map_err(|_| IndexerError::InvalidCursor)?)
                .map_err(|_| IndexerError::InvalidCursor)?,
        )
        .map_err(|_| IndexerError::InvalidCursor)?;
        if current_generation != generation || requested_limit.is_some_and(|v| v != limit) {
            return Err(IndexerError::InvalidCursor);
        }
        let decoded = Self::new(
            tenant,
            indexer,
            normalized_query,
            kind,
            generation,
            offset,
            limit,
        )?;
        if decoded.binding_digest != binding_digest || decoded.encode()? != value {
            return Err(IndexerError::InvalidCursor);
        }
        Ok(decoded)
    }

    /// Encodes exact canonical CBOR as unpadded base64url.
    ///
    /// # Errors
    /// Returns `InvalidCursor` if deterministic encoding fails.
    pub fn encode(&self) -> Result<String, IndexerError> {
        Ok(Base64UrlUnpadded::encode_string(
            &encode_deterministic_cbor(self).map_err(|_| IndexerError::InvalidCursor)?,
        ))
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation.get()
    }

    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset.get()
    }

    #[must_use]
    pub const fn limit(&self) -> u16 {
        self.limit
    }
}

impl CanonicalEncode for PublicSearchCursorV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                WireVersion::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 0))
                    .to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(2),
                self.binding_digest.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(3),
                self.generation.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(4),
                self.offset.to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(5),
                CanonicalValue::Unsigned(u64::from(self.limit)),
            ),
        ])
    }
}

/// Computes the collision-safe canonical digest used by cache keys and cursor
/// bindings. Generation zero is valid only for an empty pre-publication root
/// search; continuation constructors enforce a positive durable generation.
///
/// # Errors
/// Returns `InvalidCursor` for a noncanonical query/filter or unsafe bounds.
pub fn public_search_scope_digest(
    tenant: TenantId,
    indexer: IndexerId,
    normalized_query: &str,
    kind: Option<u8>,
    generation: u64,
    offset: u64,
    limit: u16,
) -> Result<Sha256Digest, IndexerError> {
    if normalize_public_search_query(normalized_query).as_deref() != Some(normalized_query)
        || !matches!(kind, None | Some(1 | 2))
        || generation > SafeUint::MAX
        || offset > MAX_SEARCH_OFFSET
        || !(1..=MAX_SEARCH_PAGE_SIZE).contains(&limit)
    {
        return Err(IndexerError::InvalidCursor);
    }
    let exact = encode_deterministic_cbor(&CanonicalValue::Map(vec![
        (
            CanonicalValue::Unsigned(1),
            CanonicalValue::Bytes(tenant.as_uuid().as_bytes().to_vec()),
        ),
        (
            CanonicalValue::Unsigned(2),
            CanonicalValue::Bytes(indexer.as_uuid().as_bytes().to_vec()),
        ),
        (
            CanonicalValue::Unsigned(3),
            CanonicalValue::Text(normalized_query.to_owned()),
        ),
        (
            CanonicalValue::Unsigned(4),
            kind.map_or(CanonicalValue::Null, |v| {
                CanonicalValue::Unsigned(u64::from(v))
            }),
        ),
        (
            CanonicalValue::Unsigned(5),
            CanonicalValue::Unsigned(generation),
        ),
        (
            CanonicalValue::Unsigned(6),
            CanonicalValue::Unsigned(offset),
        ),
        (
            CanonicalValue::Unsigned(7),
            CanonicalValue::Unsigned(u64::from(limit)),
        ),
    ]))
    .map_err(|_| IndexerError::InvalidCursor)?;
    let mut hash = Sha256::new();
    hash.update(SEARCH_CURSOR_BINDING_DOMAIN);
    hash.update(exact);
    Ok(Sha256Digest::from_bytes(hash.finalize().into()))
}
impl Error for IndexerError {}

/// Owner request to publish one exact signed descriptor at one logical Indexer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexRegistrationRequestV1 {
    registration_id: DirectoryRegistrationId,
    indexer_id: IndexerId,
    descriptor_bytes: Vec<u8>,
}
impl IndexRegistrationRequestV1 {
    /// Creates a bounded request after authenticating its descriptor proof.
    ///
    /// # Errors
    /// Returns `InvalidDescriptor` for invalid or oversized exact bytes.
    pub fn new(
        registration_id: DirectoryRegistrationId,
        indexer_id: IndexerId,
        descriptor_bytes: Vec<u8>,
    ) -> Result<Self, IndexerError> {
        if descriptor_bytes.is_empty()
            || descriptor_bytes.len() > 65_536
            || SignedPublicDescriptorV1::decode_and_verify(&descriptor_bytes).is_err()
        {
            return Err(IndexerError::InvalidDescriptor);
        }
        Ok(Self {
            registration_id,
            indexer_id,
            descriptor_bytes,
        })
    }
    /// Decodes exact canonical CBOR.
    ///
    /// # Errors
    /// Returns an error for malformed IDs, fields, version, or descriptor proof.
    pub fn decode(bytes: &[u8]) -> Result<Self, IndexerError> {
        let root = decode_deterministic_cbor(bytes).map_err(|_| IndexerError::InvalidDescriptor)?;
        let f = map(&root, 4)?;
        wire(field(f, 1)?)?;
        let registration_id = uuid_id::<DirectoryRegistrationId>(field(f, 2)?)?;
        let indexer_id = uuid_id::<IndexerId>(field(f, 3)?)?;
        let descriptor_bytes = match field(f, 4)? {
            CanonicalValue::Bytes(v) => v.clone(),
            _ => return Err(IndexerError::InvalidDescriptor),
        };
        let value = Self::new(registration_id, indexer_id, descriptor_bytes)?;
        if value.encode()? != bytes {
            return Err(IndexerError::InvalidDescriptor);
        }
        Ok(value)
    }
    /// Encodes exact canonical CBOR.
    ///
    /// # Errors
    /// Returns an error if the bounded canonical encoder fails.
    pub fn encode(&self) -> Result<Vec<u8>, IndexerError> {
        encode_deterministic_cbor(self).map_err(|_| IndexerError::InvalidDescriptor)
    }
    #[must_use]
    pub const fn registration_id(&self) -> DirectoryRegistrationId {
        self.registration_id
    }
    #[must_use]
    pub const fn indexer_id(&self) -> IndexerId {
        self.indexer_id
    }
    #[must_use]
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor_bytes
    }
}
impl CanonicalEncode for IndexRegistrationRequestV1 {
    fn to_canonical_value(&self) -> CanonicalValue {
        CanonicalValue::Map(vec![
            (
                CanonicalValue::Unsigned(1),
                WireVersion::new(ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 0))
                    .to_canonical_value(),
            ),
            (
                CanonicalValue::Unsigned(2),
                CanonicalValue::Bytes(self.registration_id.as_uuid().as_bytes().to_vec()),
            ),
            (
                CanonicalValue::Unsigned(3),
                CanonicalValue::Bytes(self.indexer_id.as_uuid().as_bytes().to_vec()),
            ),
            (
                CanonicalValue::Unsigned(4),
                CanonicalValue::Bytes(self.descriptor_bytes.clone()),
            ),
        ])
    }
}

/// One DNS resolution result whose complete address set passed egress policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedOriginV1 {
    host: String,
    port: u16,
    addresses: Vec<IpAddr>,
}
impl PinnedOriginV1 {
    /// Validates a canonical PD1 origin and every resolution result.
    ///
    /// # Errors
    /// Returns an error for malformed origins, empty/oversized answers, or any non-public address.
    pub fn new(origin: &str, addresses: Vec<IpAddr>) -> Result<Self, IndexerError> {
        let without_scheme = origin
            .strip_prefix("https://")
            .ok_or(IndexerError::InvalidOrigin)?;
        let authority = without_scheme.strip_suffix('/').unwrap_or(without_scheme);
        if authority.is_empty() || authority.contains(['@', '/', '?', '#', '\\', '[', ']']) {
            return Err(IndexerError::InvalidOrigin);
        }
        let (host, port) = if let Some((host, port)) = authority.rsplit_once(':') {
            (
                host,
                port.parse::<u16>()
                    .ok()
                    .filter(|v| *v != 0)
                    .ok_or(IndexerError::InvalidOrigin)?,
            )
        } else {
            (authority, 443)
        };
        if host.is_empty() || port == 0 || host.parse::<IpAddr>().is_ok() {
            return Err(IndexerError::InvalidOrigin);
        }
        if addresses.is_empty() || addresses.len() > MAX_RESOLVED_ADDRESSES {
            return Err(IndexerError::TooManyAddresses);
        }
        if addresses.iter().any(|address| !is_public_address(*address)) {
            return Err(IndexerError::UnsafeAddress);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
            addresses,
        })
    }
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
    #[must_use]
    pub fn pinned_socket(&self) -> SocketAddr {
        SocketAddr::new(self.addresses[0], self.port)
    }
}

/// Fully revalidated descriptor/feed snapshot ready for one Indexer transaction.
#[derive(Clone, Debug)]
pub struct VerifiedPublicBundleV1 {
    descriptor: SignedPublicDescriptorV1,
    descriptor_bytes: Vec<u8>,
    entries: Vec<Vec<u8>>,
    feed_sequence: Option<SafeUint>,
    feed_hash: Option<Sha256Digest>,
    search_text: String,
    revoked: bool,
}

fn verify_descriptor_transition(
    candidate: &SignedPublicDescriptorV1,
    accepted_exact: Option<&[u8]>,
    now: UtcMillis,
) -> Result<(), IndexerError> {
    let Some(accepted_exact) = accepted_exact else {
        return DescriptorHeadV1::bootstrap_at(candidate, now)
            .map(|_| ())
            .map_err(|_| IndexerError::DescriptorExpired);
    };
    let accepted = SignedPublicDescriptorV1::decode_and_verify(accepted_exact)
        .map_err(|_| IndexerError::InvalidDescriptor)?;
    if accepted.is_tombstone() {
        return Err(IndexerError::Downgrade);
    }
    if candidate.kind() != accepted.kind()
        || candidate.subject_id() != accepted.subject_id()
        || candidate.subject_genesis_signing_key() != accepted.subject_genesis_signing_key()
        || candidate.publisher_identity_id() != accepted.publisher_identity_id()
        || candidate.publisher_identity_genesis_signing_key()
            != accepted.publisher_identity_genesis_signing_key()
    {
        return Err(IndexerError::InvalidDescriptor);
    }
    let expected = accepted
        .sequence()
        .get()
        .checked_add(1)
        .ok_or(IndexerError::InvalidDescriptor)?;
    if candidate.sequence().get() < expected {
        return Err(IndexerError::Downgrade);
    }
    if candidate.sequence().get() != expected
        || candidate.previous_descriptor_hash()
            != Some(
                accepted
                    .entry_hash()
                    .map_err(|_| IndexerError::InvalidDescriptor)?,
            )
    {
        return Err(IndexerError::InvalidDescriptor);
    }
    if candidate.issued_at() > now || (!candidate.is_tombstone() && candidate.expires_at() <= now) {
        Err(IndexerError::DescriptorExpired)
    } else {
        Ok(())
    }
}

impl VerifiedPublicBundleV1 {
    /// Verifies an exact registration proof and all stable-snapshot feed pages.
    ///
    /// # Errors
    /// Returns an error for signature, subject, time, snapshot, chain, or bound violations.
    #[allow(clippy::too_many_lines)] // One verification pass keeps descriptor, pages, and feed head atomic.
    pub fn verify(
        registered_descriptor: &[u8],
        fetched_descriptor: &[u8],
        pages: &[Vec<u8>],
        now: UtcMillis,
        accepted_descriptor: Option<&[u8]>,
    ) -> Result<Self, IndexerError> {
        let registered = SignedPublicDescriptorV1::decode_and_verify(registered_descriptor)
            .map_err(|_| IndexerError::InvalidDescriptor)?;
        let fetched = SignedPublicDescriptorV1::decode_and_verify(fetched_descriptor)
            .map_err(|_| IndexerError::InvalidDescriptor)?;
        if registered_descriptor != fetched_descriptor
            || registered
                .entry_hash()
                .map_err(|_| IndexerError::InvalidDescriptor)?
                != fetched
                    .entry_hash()
                    .map_err(|_| IndexerError::InvalidDescriptor)?
        {
            return Err(IndexerError::DescriptorMismatch);
        }
        verify_descriptor_transition(&fetched, accepted_descriptor, now)?;
        if fetched.is_tombstone() {
            return Ok(Self {
                descriptor: fetched,
                descriptor_bytes: fetched_descriptor.to_vec(),
                entries: vec![],
                feed_sequence: None,
                feed_hash: None,
                search_text: String::new(),
                revoked: true,
            });
        }
        if pages.len() > MAX_FEED_PAGES {
            return Err(IndexerError::FeedTooLarge);
        }
        let mut all_entries = Vec::new();
        let mut head = None;
        let mut snapshot = None;
        let mut expected_after = 0_u64;
        let mut search = String::new();
        for exact_page in pages {
            let page = decode_page(exact_page)?;
            if page.subject_id != fetched.subject_id() || page.after_sequence != expected_after {
                return Err(IndexerError::InvalidFeed);
            }
            if snapshot.is_some_and(|value| value != (page.snapshot_sequence, page.snapshot_hash)) {
                return Err(IndexerError::InvalidFeed);
            }
            snapshot = Some((page.snapshot_sequence, page.snapshot_hash));
            for exact in page.entries {
                if all_entries.len() >= MAX_FEED_ENTRIES {
                    return Err(IndexerError::FeedTooLarge);
                }
                let event = SignedPublicFeedEventV1::decode_and_verify(&exact)
                    .map_err(|_| IndexerError::InvalidFeed)?;
                if event.subject_id() != fetched.subject_id()
                    || event.publisher_identity_id() != fetched.publisher_identity_id()
                    || event.publisher_key() != fetched.publisher_identity_genesis_signing_key()
                {
                    return Err(IndexerError::InvalidFeed);
                }
                match head.as_mut() {
                    None => {
                        head = Some(
                            PublicFeedHeadV1::bootstrap(&event)
                                .map_err(|_| IndexerError::InvalidFeed)?,
                        );
                    }
                    Some(value) => value
                        .append(&event)
                        .map_err(|_| IndexerError::InvalidFeed)?,
                }
                if let PublicFeedPayloadV1::Post { body, .. } = event.payload() {
                    if !search.is_empty() {
                        search.push(' ');
                    }
                    search.push_str(body);
                }
                expected_after = event.sequence().get();
                all_entries.push(exact);
            }
            if page.next_after.is_none() {
                break;
            }
            if page.next_after != Some(expected_after) {
                return Err(IndexerError::InvalidFeed);
            }
        }
        let (feed_sequence, feed_hash, revoked) = match (head, snapshot) {
            (Some(head), Some((sequence, hash)))
                if head.sequence() == sequence && head.hash() == hash =>
            {
                (Some(sequence), Some(hash), head.is_tombstoned())
            }
            _ => return Err(IndexerError::InvalidFeed),
        };
        Ok(Self {
            descriptor: fetched,
            descriptor_bytes: fetched_descriptor.to_vec(),
            entries: all_entries,
            feed_sequence,
            feed_hash,
            search_text: search,
            revoked,
        })
    }
    #[must_use]
    pub const fn subject_id(&self) -> PublicSubjectId {
        self.descriptor.subject_id()
    }
    #[must_use]
    pub fn descriptor(&self) -> &SignedPublicDescriptorV1 {
        &self.descriptor
    }
    #[must_use]
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor_bytes
    }
    #[must_use]
    pub fn entries(&self) -> &[Vec<u8>] {
        &self.entries
    }
    #[must_use]
    pub const fn feed_sequence(&self) -> Option<SafeUint> {
        self.feed_sequence
    }
    #[must_use]
    pub const fn feed_hash(&self) -> Option<Sha256Digest> {
        self.feed_hash
    }
    #[must_use]
    pub fn search_text(&self) -> &str {
        &self.search_text
    }
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked
    }
}

struct DecodedPage {
    subject_id: PublicSubjectId,
    after_sequence: u64,
    entries: Vec<Vec<u8>>,
    next_after: Option<u64>,
    snapshot_sequence: SafeUint,
    snapshot_hash: Sha256Digest,
}
fn decode_page(bytes: &[u8]) -> Result<DecodedPage, IndexerError> {
    let root = decode_deterministic_cbor(bytes).map_err(|_| IndexerError::InvalidFeed)?;
    let fields = map(&root, 6)?;
    wire(field(fields, 1)?)?;
    let subject_id = text(field(fields, 2)?)?
        .parse()
        .map_err(|_| IndexerError::InvalidFeed)?;
    let entries = match field(fields, 3)? {
        CanonicalValue::Array(values) => values
            .iter()
            .map(|v| match v {
                CanonicalValue::Bytes(v) => Ok(v.clone()),
                _ => Err(IndexerError::InvalidFeed),
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => return Err(IndexerError::InvalidFeed),
    };
    let next = match field(fields, 4)? {
        CanonicalValue::Null => None,
        CanonicalValue::Text(value) => {
            let cursor = dtx_public_feed::PublicFeedCursorV1::decode(value)
                .map_err(|_| IndexerError::InvalidFeed)?;
            if cursor.subject_id() != subject_id {
                return Err(IndexerError::InvalidFeed);
            }
            Some(cursor.after_sequence().get())
        }
        _ => return Err(IndexerError::InvalidFeed),
    };
    let snapshot_sequence =
        SafeUint::new(unsigned(field(fields, 5)?)?).map_err(|_| IndexerError::InvalidFeed)?;
    let snapshot_hash = Sha256Digest::from_bytes(bytes32(field(fields, 6)?)?);
    let after = entries.first().map_or(0, |exact| {
        SignedPublicFeedEventV1::decode_and_verify(exact)
            .map_or(u64::MAX, |event| event.sequence().get() - 1)
    });
    Ok(DecodedPage {
        subject_id,
        after_sequence: after,
        entries,
        next_after: next,
        snapshot_sequence,
        snapshot_hash,
    })
}
fn is_public_address(value: IpAddr) -> bool {
    match value {
        IpAddr::V4(v) => public_v4(v),
        IpAddr::V6(v) => public_v6(v),
    }
}
fn public_v4(v: Ipv4Addr) -> bool {
    let n = u32::from(v);
    ![
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc058_6300, 24),
        (0xc0a8_0000, 16),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xe000_0000, 4),
        (0xf000_0000, 4),
    ]
    .iter()
    .any(|(network, prefix)| n >> (32 - prefix) == network >> (32 - prefix))
}
fn public_v6(v: Ipv6Addr) -> bool {
    let n = u128::from(v);
    if v.to_ipv4_mapped().is_some() {
        return false;
    }
    // Fail closed to ordinary global-unicast space, then remove IANA
    // special-purpose translation/tunneling allocations inside that space.
    n >> 125 == 0b001
        && ![
            (0x2001_u128 << 112, 23),     // IETF protocol assignments, including Teredo.
            (0x2001_0db8_u128 << 96, 32), // Documentation.
            (0x2002_u128 << 112, 16),     // 6to4 embeds an arbitrary IPv4 target.
        ]
        .iter()
        .any(|(network, prefix)| n >> (128 - prefix) == network >> (128 - prefix))
}
fn map(
    v: &CanonicalValue,
    len: usize,
) -> Result<&[(CanonicalValue, CanonicalValue)], IndexerError> {
    match v {
        CanonicalValue::Map(v) if v.len() == len => Ok(v),
        _ => Err(IndexerError::InvalidFeed),
    }
}
fn field(
    v: &[(CanonicalValue, CanonicalValue)],
    key: u64,
) -> Result<&CanonicalValue, IndexerError> {
    v.iter()
        .find_map(|(k, v)| (*k == CanonicalValue::Unsigned(key)).then_some(v))
        .ok_or(IndexerError::InvalidFeed)
}
fn unsigned(v: &CanonicalValue) -> Result<u64, IndexerError> {
    if let CanonicalValue::Unsigned(v) = v {
        Ok(*v)
    } else {
        Err(IndexerError::InvalidFeed)
    }
}
fn text(v: &CanonicalValue) -> Result<&str, IndexerError> {
    if let CanonicalValue::Text(v) = v {
        Ok(v)
    } else {
        Err(IndexerError::InvalidFeed)
    }
}
fn bytes32(v: &CanonicalValue) -> Result<[u8; 32], IndexerError> {
    if let CanonicalValue::Bytes(v) = v {
        v.as_slice()
            .try_into()
            .map_err(|_| IndexerError::InvalidFeed)
    } else {
        Err(IndexerError::InvalidFeed)
    }
}
fn wire(v: &CanonicalValue) -> Result<(), IndexerError> {
    let f = map(v, 2)?;
    for key in [1, 2] {
        let version = map(field(f, key)?, 2)?;
        if unsigned(field(version, 1)?)? != 1 || unsigned(field(version, 2)?)? != 0 {
            return Err(IndexerError::InvalidFeed);
        }
    }
    Ok(())
}
fn uuid_id<T: std::str::FromStr>(v: &CanonicalValue) -> Result<T, IndexerError> {
    let bytes = match v {
        CanonicalValue::Bytes(v) => v
            .as_slice()
            .try_into()
            .map_err(|_| IndexerError::InvalidDescriptor)?,
        _ => return Err(IndexerError::InvalidDescriptor),
    };
    Uuid::from_bytes(bytes)
        .hyphenated()
        .to_string()
        .parse()
        .map_err(|_| IndexerError::InvalidDescriptor)
}
