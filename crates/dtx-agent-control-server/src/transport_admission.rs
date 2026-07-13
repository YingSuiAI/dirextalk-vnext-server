use std::{
    collections::HashMap,
    error::Error,
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use dtx_security::{AuthenticatedConnectorPeer, ConnectorWorkloadIdentity};
use tonic::Request;

const MAX_CONFIGURED_LIMIT: usize = 1_000_000;
const MAX_CONFIGURED_BURST: u32 = 1_000_000;

/// Per-key concurrency and token-bucket limits for admitted transport work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportAdmissionDimensionConfig {
    max_concurrent: usize,
    burst: u32,
    refill_interval: Duration,
}

impl TransportAdmissionDimensionConfig {
    /// Builds one bounded dimension policy.
    ///
    /// # Errors
    ///
    /// Rejects zero or impractically large limits and a zero refill interval.
    pub fn new(
        max_concurrent: usize,
        burst: u32,
        refill_interval: Duration,
    ) -> Result<Self, ConnectorTransportAdmissionConfigError> {
        if max_concurrent == 0
            || max_concurrent > MAX_CONFIGURED_LIMIT
            || burst == 0
            || burst > MAX_CONFIGURED_BURST
        {
            return Err(ConnectorTransportAdmissionConfigError::InvalidLimit);
        }
        if refill_interval.is_zero() {
            return Err(ConnectorTransportAdmissionConfigError::InvalidDuration);
        }
        Ok(Self {
            max_concurrent,
            burst,
            refill_interval,
        })
    }
}

/// Validated global and direct-source admission policy for anonymous transport work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceTransportAdmissionConfig {
    global: TransportAdmissionDimensionConfig,
    source: TransportAdmissionDimensionConfig,
    idle_entry_ttl: Duration,
    max_source_entries: usize,
}

impl SourceTransportAdmissionConfig {
    /// Builds a bounded global and direct-source concurrency/rate policy.
    ///
    /// # Errors
    ///
    /// Rejects excessive limits, source concurrency above the global ceiling,
    /// or an entry TTL shorter than the source refill interval.
    pub fn new(
        global: TransportAdmissionDimensionConfig,
        source: TransportAdmissionDimensionConfig,
        idle_entry_ttl: Duration,
        max_source_entries: usize,
    ) -> Result<Self, ConnectorTransportAdmissionConfigError> {
        if max_source_entries == 0 || max_source_entries > MAX_CONFIGURED_LIMIT {
            return Err(ConnectorTransportAdmissionConfigError::InvalidLimit);
        }
        if source.max_concurrent > global.max_concurrent {
            return Err(ConnectorTransportAdmissionConfigError::PerKeyConcurrencyExceedsGlobal);
        }
        if idle_entry_ttl.is_zero() {
            return Err(ConnectorTransportAdmissionConfigError::InvalidDuration);
        }
        if idle_entry_ttl < source.refill_interval {
            return Err(ConnectorTransportAdmissionConfigError::IdleTtlTooShort);
        }
        Ok(Self {
            global,
            source,
            idle_entry_ttl,
            max_source_entries,
        })
    }
}

impl Default for SourceTransportAdmissionConfig {
    fn default() -> Self {
        Self {
            global: TransportAdmissionDimensionConfig {
                max_concurrent: 128,
                burst: 256,
                refill_interval: Duration::from_millis(10),
            },
            source: TransportAdmissionDimensionConfig {
                max_concurrent: 8,
                burst: 16,
                refill_interval: Duration::from_millis(100),
            },
            idle_entry_ttl: Duration::from_mins(10),
            max_source_entries: 4_096,
        }
    }
}

/// Fully validated authenticated first-`Hello` admission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorTransportAdmissionConfig {
    max_concurrent: usize,
    source: TransportAdmissionDimensionConfig,
    identity: TransportAdmissionDimensionConfig,
    idle_entry_ttl: Duration,
    max_source_entries: usize,
    max_identity_entries: usize,
}

impl ConnectorTransportAdmissionConfig {
    /// Builds a bounded pending-`Hello` policy by global, source, and identity.
    ///
    /// # Errors
    ///
    /// Rejects zero or excessive limits, per-key concurrency above the global
    /// ceiling, and an entry TTL shorter than either bucket refill interval.
    pub fn new(
        max_concurrent: usize,
        source: TransportAdmissionDimensionConfig,
        identity: TransportAdmissionDimensionConfig,
        idle_entry_ttl: Duration,
        max_source_entries: usize,
        max_identity_entries: usize,
    ) -> Result<Self, ConnectorTransportAdmissionConfigError> {
        if max_concurrent == 0
            || max_concurrent > MAX_CONFIGURED_LIMIT
            || max_source_entries == 0
            || max_source_entries > MAX_CONFIGURED_LIMIT
            || max_identity_entries == 0
            || max_identity_entries > MAX_CONFIGURED_LIMIT
        {
            return Err(ConnectorTransportAdmissionConfigError::InvalidLimit);
        }
        if source.max_concurrent > max_concurrent || identity.max_concurrent > max_concurrent {
            return Err(ConnectorTransportAdmissionConfigError::PerKeyConcurrencyExceedsGlobal);
        }
        if idle_entry_ttl.is_zero() {
            return Err(ConnectorTransportAdmissionConfigError::InvalidDuration);
        }
        if idle_entry_ttl < source.refill_interval || idle_entry_ttl < identity.refill_interval {
            return Err(ConnectorTransportAdmissionConfigError::IdleTtlTooShort);
        }
        Ok(Self {
            max_concurrent,
            source,
            identity,
            idle_entry_ttl,
            max_source_entries,
            max_identity_entries,
        })
    }
}

impl Default for ConnectorTransportAdmissionConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 256,
            source: TransportAdmissionDimensionConfig {
                max_concurrent: 32,
                burst: 64,
                refill_interval: Duration::from_millis(100),
            },
            identity: TransportAdmissionDimensionConfig {
                max_concurrent: 2,
                burst: 4,
                refill_interval: Duration::from_secs(1),
            },
            idle_entry_ttl: Duration::from_mins(10),
            max_source_entries: 4_096,
            max_identity_entries: 32_768,
        }
    }
}

/// Stable startup configuration failure with no peer-specific material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorTransportAdmissionConfigError {
    InvalidLimit,
    InvalidDuration,
    PerKeyConcurrencyExceedsGlobal,
    IdleTtlTooShort,
}

impl fmt::Display for ConnectorTransportAdmissionConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLimit => "Connector transport admission limit is invalid",
            Self::InvalidDuration => "Connector transport admission duration is invalid",
            Self::PerKeyConcurrencyExceedsGlobal => {
                "Connector transport per-key concurrency exceeds the global limit"
            }
            Self::IdleTtlTooShort => {
                "Connector transport admission entry TTL is shorter than its refill interval"
            }
        })
    }
}

impl Error for ConnectorTransportAdmissionConfigError {}

/// In-memory admission guard for work that has only a direct transport source.
///
/// Clones share the same bounded counters and token buckets.
#[derive(Clone)]
pub struct SourceTransportAdmission {
    inner: Arc<SourceAdmissionInner>,
}

impl SourceTransportAdmission {
    #[must_use]
    pub fn new(config: SourceTransportAdmissionConfig) -> Self {
        Self::with_clock_inner(config, Arc::new(SystemAdmissionClock::new()))
    }

    /// Atomically acquires global and canonical direct-source capacity.
    ///
    /// A missing direct transport address skips only the source dimension and
    /// remains subject to the global concurrency and token-bucket limits.
    ///
    /// # Errors
    ///
    /// Returns one opaque overload result for every admission rejection.
    pub fn try_acquire(
        &self,
        source_ip: Option<IpAddr>,
    ) -> Result<SourceTransportAdmissionPermit, ConnectorTransportAdmissionError> {
        let source_ip = source_ip.map(canonical_source_ip);
        let now = self.inner.clock.now();
        let mut state = lock_source_state(&self.inner.state);
        state.try_acquire(self.inner.config, source_ip, now)?;
        drop(state);
        Ok(SourceTransportAdmissionPermit {
            inner: Arc::clone(&self.inner),
            source_ip,
        })
    }

    /// Acquires capacity using tonic's direct transport address.
    ///
    /// Forwarding headers are deliberately ignored.
    ///
    /// # Errors
    ///
    /// Returns one opaque overload result for every admission rejection.
    pub fn try_acquire_request<T>(
        &self,
        request: &Request<T>,
    ) -> Result<SourceTransportAdmissionPermit, ConnectorTransportAdmissionError> {
        self.try_acquire(request.remote_addr().map(|address| address.ip()))
    }

    #[cfg(test)]
    fn with_clock(config: SourceTransportAdmissionConfig, clock: Arc<dyn AdmissionClock>) -> Self {
        Self::with_clock_inner(config, clock)
    }

    fn with_clock_inner(
        config: SourceTransportAdmissionConfig,
        clock: Arc<dyn AdmissionClock>,
    ) -> Self {
        Self {
            inner: Arc::new(SourceAdmissionInner {
                state: Mutex::new(SourceAdmissionState::new(config)),
                config,
                clock,
            }),
        }
    }
}

impl fmt::Debug for SourceTransportAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceTransportAdmission")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

/// Non-cloneable RAII ownership of one global/direct-source admission.
pub struct SourceTransportAdmissionPermit {
    inner: Arc<SourceAdmissionInner>,
    source_ip: Option<IpAddr>,
}

impl fmt::Debug for SourceTransportAdmissionPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceTransportAdmissionPermit")
            .field("source", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SourceTransportAdmissionPermit {
    fn drop(&mut self) {
        lock_source_state(&self.inner.state).release(self.source_ip);
    }
}

struct SourceAdmissionInner {
    config: SourceTransportAdmissionConfig,
    clock: Arc<dyn AdmissionClock>,
    state: Mutex<SourceAdmissionState>,
}

struct SourceAdmissionState {
    global: AdmissionEntry,
    sources: HashMap<IpAddr, AdmissionEntry>,
    last_observed_now: Duration,
    next_cleanup: Duration,
}

impl SourceAdmissionState {
    fn new(config: SourceTransportAdmissionConfig) -> Self {
        Self {
            global: AdmissionEntry::new(config.global, Duration::ZERO),
            sources: HashMap::new(),
            last_observed_now: Duration::ZERO,
            next_cleanup: config.idle_entry_ttl,
        }
    }

    fn try_acquire(
        &mut self,
        config: SourceTransportAdmissionConfig,
        source_ip: Option<IpAddr>,
        now: Duration,
    ) -> Result<(), ConnectorTransportAdmissionError> {
        if now < self.last_observed_now {
            return Err(ConnectorTransportAdmissionError);
        }
        self.last_observed_now = now;
        self.cleanup_if_due(now, config.idle_entry_ttl);
        if source_ip.is_some_and(|source| {
            !self.sources.contains_key(&source) && self.sources.len() >= config.max_source_entries
        }) {
            return Err(ConnectorTransportAdmissionError);
        }

        let global_candidate = AdmissionEntry::candidate(Some(&self.global), config.global, now)?;
        let source_candidate = source_ip
            .map(|source| AdmissionEntry::candidate(self.sources.get(&source), config.source, now))
            .transpose()?;

        self.global = global_candidate;
        if let (Some(source), Some(candidate)) = (source_ip, source_candidate) {
            self.sources.insert(source, candidate);
        }
        Ok(())
    }

    fn cleanup_if_due(&mut self, now: Duration, idle_entry_ttl: Duration) {
        if now < self.next_cleanup {
            return;
        }
        self.sources
            .retain(|_, entry| !entry.is_expired(now, idle_entry_ttl));
        self.next_cleanup = now.saturating_add(idle_entry_ttl);
    }

    fn release(&mut self, source_ip: Option<IpAddr>) {
        self.global.in_flight = self.global.in_flight.saturating_sub(1);
        if let Some(source_ip) = source_ip
            && let Some(entry) = self.sources.get_mut(&source_ip)
        {
            entry.in_flight = entry.in_flight.saturating_sub(1);
        }
    }
}

/// In-memory admission guard for bounded authenticated first-`Hello` work.
#[derive(Clone)]
pub struct ConnectorTransportAdmission {
    inner: Arc<AdmissionInner>,
}

impl ConnectorTransportAdmission {
    #[must_use]
    pub fn new(config: ConnectorTransportAdmissionConfig) -> Self {
        Self::with_clock_inner(config, Arc::new(SystemAdmissionClock::new()))
    }

    /// Atomically acquires global, direct-source, and canonical SAN identity capacity.
    ///
    /// `source_ip` must come from tonic's direct transport `remote_addr`, never a
    /// caller-controlled forwarding header. A missing transport address skips
    /// only the source dimension; global and identity limits still apply.
    ///
    /// # Errors
    ///
    /// Returns one indistinguishable overload result for every concurrency,
    /// rate, clock, or key-cardinality rejection.
    fn try_acquire_control_stream(
        &self,
        source_ip: Option<IpAddr>,
        identity: ConnectorWorkloadIdentity,
    ) -> Result<ConnectorHelloAdmissionPermit, ConnectorTransportAdmissionError> {
        let source_ip = source_ip.map(canonical_source_ip);
        let now = self.inner.clock.now();
        let mut state = lock_state(&self.inner.state);
        state.try_acquire(self.inner.config, source_ip, identity, now)?;
        drop(state);
        Ok(ConnectorHelloAdmissionPermit {
            inner: Arc::clone(&self.inner),
            source_ip,
            identity,
        })
    }

    /// Acquires control-stream capacity from tonic's direct peer address and the
    /// canonical identity retained from the cryptographically authenticated leaf.
    ///
    /// This is the preferred gRPC integration seam because neither key comes
    /// from a forwarding header or the untrusted `Hello` body.
    ///
    /// # Errors
    ///
    /// Returns the same opaque overload error for every admission rejection.
    pub fn try_acquire_control_request<T>(
        &self,
        request: &Request<T>,
        peer: AuthenticatedConnectorPeer,
    ) -> Result<ConnectorHelloAdmissionPermit, ConnectorTransportAdmissionError> {
        self.try_acquire_control_stream(
            request.remote_addr().map(|address| address.ip()),
            peer.identity(),
        )
    }

    #[cfg(test)]
    fn with_clock(
        config: ConnectorTransportAdmissionConfig,
        clock: Arc<dyn AdmissionClock>,
    ) -> Self {
        Self::with_clock_inner(config, clock)
    }

    fn with_clock_inner(
        config: ConnectorTransportAdmissionConfig,
        clock: Arc<dyn AdmissionClock>,
    ) -> Self {
        Self {
            inner: Arc::new(AdmissionInner {
                state: Mutex::new(AdmissionState::new(config.idle_entry_ttl)),
                config,
                clock,
            }),
        }
    }
}

impl fmt::Debug for ConnectorTransportAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorTransportAdmission")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

/// Non-cloneable RAII ownership of one pending first-`Hello` window.
pub struct ConnectorHelloAdmissionPermit {
    inner: Arc<AdmissionInner>,
    source_ip: Option<IpAddr>,
    identity: ConnectorWorkloadIdentity,
}

impl fmt::Debug for ConnectorHelloAdmissionPermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectorHelloAdmissionPermit")
            .field("source", &"[REDACTED]")
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ConnectorHelloAdmissionPermit {
    fn drop(&mut self) {
        lock_state(&self.inner.state).release(self.source_ip, self.identity);
    }
}

/// Deliberately indistinguishable pre-authorization overload response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectorTransportAdmissionError;

impl fmt::Display for ConnectorTransportAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Connector transport admission is temporarily unavailable")
    }
}

impl Error for ConnectorTransportAdmissionError {}

struct AdmissionInner {
    config: ConnectorTransportAdmissionConfig,
    clock: Arc<dyn AdmissionClock>,
    state: Mutex<AdmissionState>,
}

struct AdmissionState {
    total_in_flight: usize,
    sources: HashMap<IpAddr, AdmissionEntry>,
    identities: HashMap<ConnectorWorkloadIdentity, AdmissionEntry>,
    last_observed_now: Duration,
    next_cleanup: Duration,
}

impl AdmissionState {
    fn new(idle_entry_ttl: Duration) -> Self {
        Self {
            total_in_flight: 0,
            sources: HashMap::new(),
            identities: HashMap::new(),
            last_observed_now: Duration::ZERO,
            next_cleanup: idle_entry_ttl,
        }
    }

    fn try_acquire(
        &mut self,
        config: ConnectorTransportAdmissionConfig,
        source_ip: Option<IpAddr>,
        identity: ConnectorWorkloadIdentity,
        now: Duration,
    ) -> Result<(), ConnectorTransportAdmissionError> {
        if now < self.last_observed_now {
            return Err(ConnectorTransportAdmissionError);
        }
        self.last_observed_now = now;
        self.cleanup_if_due(now, config.idle_entry_ttl);
        if self.total_in_flight >= config.max_concurrent
            || source_ip.is_some_and(|source| {
                !self.sources.contains_key(&source)
                    && self.sources.len() >= config.max_source_entries
            })
            || (!self.identities.contains_key(&identity)
                && self.identities.len() >= config.max_identity_entries)
        {
            return Err(ConnectorTransportAdmissionError);
        }

        let source_candidate = source_ip
            .map(|source| AdmissionEntry::candidate(self.sources.get(&source), config.source, now))
            .transpose()?;
        let identity_candidate =
            AdmissionEntry::candidate(self.identities.get(&identity), config.identity, now)?;

        if let (Some(source), Some(candidate)) = (source_ip, source_candidate) {
            self.sources.insert(source, candidate);
        }
        self.identities.insert(identity, identity_candidate);
        self.total_in_flight += 1;
        Ok(())
    }

    fn cleanup_if_due(&mut self, now: Duration, idle_entry_ttl: Duration) {
        if now < self.next_cleanup {
            return;
        }
        self.sources
            .retain(|_, entry| !entry.is_expired(now, idle_entry_ttl));
        self.identities
            .retain(|_, entry| !entry.is_expired(now, idle_entry_ttl));
        self.next_cleanup = now.saturating_add(idle_entry_ttl);
    }

    fn release(&mut self, source_ip: Option<IpAddr>, identity: ConnectorWorkloadIdentity) {
        self.total_in_flight = self.total_in_flight.saturating_sub(1);
        if let Some(source_ip) = source_ip
            && let Some(entry) = self.sources.get_mut(&source_ip)
        {
            entry.in_flight = entry.in_flight.saturating_sub(1);
        }
        if let Some(entry) = self.identities.get_mut(&identity) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
        }
    }
}

#[derive(Clone, Copy)]
struct AdmissionEntry {
    tokens: u32,
    last_refill: Duration,
    last_seen: Duration,
    in_flight: usize,
}

impl AdmissionEntry {
    const fn new(policy: TransportAdmissionDimensionConfig, now: Duration) -> Self {
        Self {
            tokens: policy.burst,
            last_refill: now,
            last_seen: now,
            in_flight: 0,
        }
    }

    fn candidate(
        current: Option<&Self>,
        policy: TransportAdmissionDimensionConfig,
        now: Duration,
    ) -> Result<Self, ConnectorTransportAdmissionError> {
        let mut candidate = current.copied().unwrap_or_else(|| Self::new(policy, now));
        candidate.refill(policy, now)?;
        if candidate.in_flight >= policy.max_concurrent || candidate.tokens == 0 {
            return Err(ConnectorTransportAdmissionError);
        }
        if candidate.tokens == policy.burst {
            candidate.last_refill = now;
        }
        candidate.tokens -= 1;
        candidate.in_flight += 1;
        candidate.last_seen = now;
        Ok(candidate)
    }

    fn refill(
        &mut self,
        policy: TransportAdmissionDimensionConfig,
        now: Duration,
    ) -> Result<(), ConnectorTransportAdmissionError> {
        let elapsed = now
            .checked_sub(self.last_refill)
            .ok_or(ConnectorTransportAdmissionError)?;
        let intervals = elapsed.as_nanos() / policy.refill_interval.as_nanos();
        if intervals == 0 || self.tokens == policy.burst {
            return Ok(());
        }
        let missing = policy.burst - self.tokens;
        let added = u32::try_from(intervals.min(u128::from(missing)))
            .map_err(|_| ConnectorTransportAdmissionError)?;
        self.tokens += added;
        self.last_refill = if self.tokens == policy.burst {
            now
        } else {
            self.last_refill
                .saturating_add(policy.refill_interval.saturating_mul(added))
        };
        Ok(())
    }

    fn is_expired(self, now: Duration, idle_entry_ttl: Duration) -> bool {
        self.in_flight == 0
            && now
                .checked_sub(self.last_seen)
                .is_some_and(|idle| idle >= idle_entry_ttl)
    }
}

fn lock_state(state: &Mutex<AdmissionState>) -> MutexGuard<'_, AdmissionState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_source_state(state: &Mutex<SourceAdmissionState>) -> MutexGuard<'_, SourceAdmissionState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn canonical_source_ip(source_ip: IpAddr) -> IpAddr {
    match source_ip {
        IpAddr::V6(source) => source
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(source), IpAddr::V4),
        IpAddr::V4(source) => IpAddr::V4(source),
    }
}

trait AdmissionClock: Send + Sync {
    fn now(&self) -> Duration;
}

struct SystemAdmissionClock {
    origin: Instant,
}

impl SystemAdmissionClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl AdmissionClock for SystemAdmissionClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
        time::Duration,
    };

    use dtx_domain::{ConnectorId, TenantId};
    use dtx_security::ConnectorWorkloadIdentity;

    use super::{
        AdmissionClock, ConnectorTransportAdmission, ConnectorTransportAdmissionConfig,
        ConnectorTransportAdmissionConfigError, ConnectorTransportAdmissionError,
        SourceTransportAdmission, SourceTransportAdmissionConfig,
        TransportAdmissionDimensionConfig,
    };

    #[test]
    fn source_admission_enforces_raii_global_source_and_rate_limits() {
        let clock = Arc::new(FakeClock::default());
        let config = SourceTransportAdmissionConfig::new(
            TransportAdmissionDimensionConfig::new(2, 8, Duration::from_millis(100))
                .expect("global policy is valid"),
            TransportAdmissionDimensionConfig::new(1, 2, Duration::from_secs(1))
                .expect("source policy is valid"),
            Duration::from_secs(30),
            8,
        )
        .expect("source admission config is valid");
        let admission = SourceTransportAdmission::with_clock(config, clock.clone());
        let source = ip(1);
        let first = admission
            .try_acquire(Some(source))
            .expect("first source request is admitted");

        assert!(matches!(
            admission.try_acquire(Some(source)),
            Err(ConnectorTransportAdmissionError)
        ));
        let unknown_source = admission
            .try_acquire(None)
            .expect("missing source still receives global admission");
        assert!(matches!(
            admission.try_acquire(Some(ip(2))),
            Err(ConnectorTransportAdmissionError)
        ));

        drop(first);
        drop(unknown_source);
        drop(
            admission
                .try_acquire(Some(source))
                .expect("dropping the permit releases source concurrency"),
        );
        assert!(matches!(
            admission.try_acquire(Some(source)),
            Err(ConnectorTransportAdmissionError)
        ));
        clock.advance(Duration::from_secs(1));
        admission
            .try_acquire(Some(source))
            .expect("the injected clock refills one source token");
    }

    #[test]
    fn source_admission_map_is_bounded_canonical_and_ttl_evicted() {
        let clock = Arc::new(FakeClock::default());
        let config = SourceTransportAdmissionConfig::new(
            TransportAdmissionDimensionConfig::new(8, 16, Duration::from_millis(100))
                .expect("global policy is valid"),
            TransportAdmissionDimensionConfig::new(8, 8, Duration::from_secs(1))
                .expect("source policy is valid"),
            Duration::from_secs(30),
            1,
        )
        .expect("source admission config is valid");
        let admission = SourceTransportAdmission::with_clock(config, clock.clone());
        let source = Ipv4Addr::new(192, 0, 2, 2);
        let permit = admission
            .try_acquire(Some(IpAddr::V4(source)))
            .expect("first canonical source is admitted");
        admission
            .try_acquire(Some(IpAddr::V6(source.to_ipv6_mapped())))
            .expect("mapped IPv6 reuses the existing canonical source entry");
        assert!(matches!(
            admission.try_acquire(Some(ip(3))),
            Err(ConnectorTransportAdmissionError)
        ));

        drop(permit);
        clock.advance(Duration::from_secs(30));
        admission
            .try_acquire(Some(ip(3)))
            .expect("expired idle source entry is evicted before insertion");
    }

    #[test]
    fn raii_release_and_dual_key_concurrency_are_atomic() {
        let admission = admission(test_config(3, 1, 1, 8, Duration::from_secs(1), 8, 8));
        let source = ip(10);
        let first_identity = identity();
        let second_identity = identity();
        let first = admission
            .try_acquire_control_stream(Some(source), first_identity)
            .expect("the first pending Hello is admitted");

        assert!(
            matches!(
                admission.try_acquire_control_stream(Some(source), second_identity),
                Err(ConnectorTransportAdmissionError)
            ),
            "the source concurrency ceiling applies across identities"
        );
        assert!(
            matches!(
                admission.try_acquire_control_stream(Some(ip(11)), first_identity),
                Err(ConnectorTransportAdmissionError)
            ),
            "the identity concurrency ceiling applies across sources"
        );

        drop(first);
        admission
            .try_acquire_control_stream(Some(source), second_identity)
            .expect("dropping the RAII permit releases both dimensions");
    }

    #[test]
    fn token_buckets_refill_from_an_injected_monotonic_clock() {
        let clock = Arc::new(FakeClock::default());
        let config = test_config(4, 4, 4, 2, Duration::from_secs(1), 8, 8);
        let admission = ConnectorTransportAdmission::with_clock(config, clock.clone());
        let source = ip(20);
        let identity = identity();
        clock.advance(Duration::from_secs(10));

        drop(
            admission
                .try_acquire_control_stream(Some(source), identity)
                .expect("first burst token is available"),
        );
        drop(
            admission
                .try_acquire_control_stream(Some(source), identity)
                .expect("second burst token is available"),
        );
        assert!(matches!(
            admission.try_acquire_control_stream(Some(source), identity),
            Err(ConnectorTransportAdmissionError)
        ));

        clock.advance(Duration::from_millis(999));
        assert!(matches!(
            admission.try_acquire_control_stream(Some(source), identity),
            Err(ConnectorTransportAdmissionError)
        ));
        clock.advance(Duration::from_millis(1));
        admission
            .try_acquire_control_stream(Some(source), identity)
            .expect("one exact refill interval restores one token");
    }

    #[test]
    fn ipv4_and_ipv4_mapped_ipv6_share_the_same_source_limit() {
        let admission = admission(test_config(2, 1, 2, 8, Duration::from_secs(1), 2, 2));
        let source = Ipv4Addr::new(192, 0, 2, 60);
        let permit = admission
            .try_acquire_control_stream(Some(IpAddr::V4(source)), identity())
            .expect("canonical IPv4 source is admitted");

        assert!(matches!(
            admission
                .try_acquire_control_stream(Some(IpAddr::V6(source.to_ipv6_mapped())), identity(),),
            Err(ConnectorTransportAdmissionError)
        ));
        drop(permit);
    }

    #[test]
    fn tracked_keys_are_bounded_and_expire_without_sleeping() {
        let clock = Arc::new(FakeClock::default());
        let config = test_config(8, 8, 8, 8, Duration::from_secs(1), 2, 2);
        let admission = ConnectorTransportAdmission::with_clock(config, clock.clone());
        for suffix in [30, 31] {
            drop(
                admission
                    .try_acquire_control_stream(Some(ip(suffix)), identity())
                    .expect("bounded slot is initially available"),
            );
        }
        assert!(
            matches!(
                admission.try_acquire_control_stream(Some(ip(32)), identity()),
                Err(ConnectorTransportAdmissionError)
            ),
            "a new source and identity cannot grow either map beyond its cap"
        );

        clock.advance(Duration::from_mins(1));
        admission
            .try_acquire_control_stream(Some(ip(32)), identity())
            .expect("expired idle keys are evicted before bounded insertion");
    }

    #[test]
    fn active_permits_survive_ttl_cleanup_and_global_capacity_is_bounded() {
        let clock = Arc::new(FakeClock::default());
        let config = test_config(1, 1, 1, 8, Duration::from_secs(1), 1, 1);
        let admission = ConnectorTransportAdmission::with_clock(config, clock.clone());
        let permit = admission
            .try_acquire_control_stream(Some(ip(40)), identity())
            .expect("global slot is available");
        clock.advance(Duration::from_mins(1));
        assert!(
            matches!(
                admission.try_acquire_control_stream(Some(ip(41)), identity()),
                Err(ConnectorTransportAdmissionError)
            ),
            "TTL cleanup must not evict an in-flight permit"
        );
        drop(permit);
    }

    #[test]
    fn configuration_and_debug_surfaces_are_fail_closed_and_redacted() {
        let dimension = TransportAdmissionDimensionConfig::new(1, 1, Duration::from_secs(1))
            .expect("dimension is valid");
        assert_eq!(
            TransportAdmissionDimensionConfig::new(0, 1, Duration::from_secs(1)),
            Err(ConnectorTransportAdmissionConfigError::InvalidLimit)
        );
        assert_eq!(
            ConnectorTransportAdmissionConfig::new(
                1,
                dimension,
                dimension,
                Duration::from_millis(999),
                1,
                1,
            ),
            Err(ConnectorTransportAdmissionConfigError::IdleTtlTooShort)
        );

        let admission = admission(test_config(1, 1, 1, 1, Duration::from_secs(1), 1, 1));
        let identity = identity();
        let identity_text = identity.to_string();
        let source = ip(50);
        let permit = admission
            .try_acquire_control_stream(Some(source), identity)
            .expect("permit is admitted");
        let debug = format!("{admission:?} {permit:?}");
        assert!(!debug.contains(&identity_text));
        assert!(!debug.contains(&source.to_string()));
    }

    fn admission(config: ConnectorTransportAdmissionConfig) -> ConnectorTransportAdmission {
        ConnectorTransportAdmission::with_clock(config, Arc::new(FakeClock::default()))
    }

    fn test_config(
        global: usize,
        source_concurrent: usize,
        identity_concurrent: usize,
        burst: u32,
        refill: Duration,
        source_entries: usize,
        identity_entries: usize,
    ) -> ConnectorTransportAdmissionConfig {
        ConnectorTransportAdmissionConfig::new(
            global,
            TransportAdmissionDimensionConfig::new(source_concurrent, burst, refill)
                .expect("source policy is valid"),
            TransportAdmissionDimensionConfig::new(identity_concurrent, burst, refill)
                .expect("identity policy is valid"),
            Duration::from_secs(30),
            source_entries,
            identity_entries,
        )
        .expect("test admission config is valid")
    }

    fn identity() -> ConnectorWorkloadIdentity {
        ConnectorWorkloadIdentity::new(TenantId::new(), ConnectorId::new())
    }

    const fn ip(suffix: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, suffix))
    }

    #[derive(Default)]
    struct FakeClock {
        nanos: AtomicU64,
    }

    impl FakeClock {
        fn advance(&self, duration: Duration) {
            let nanos = u64::try_from(duration.as_nanos()).expect("test duration fits u64");
            self.nanos.fetch_add(nanos, Ordering::SeqCst);
        }
    }

    impl AdmissionClock for FakeClock {
        fn now(&self) -> Duration {
            Duration::from_nanos(self.nanos.load(Ordering::SeqCst))
        }
    }
}
