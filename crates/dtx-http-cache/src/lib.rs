#![forbid(unsafe_code)]

//! Small bounded response cache with per-key miss coalescing.

use sha2::{Digest as _, Sha256};
use std::{
    collections::HashMap,
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct CachedBody {
    bytes: Arc<[u8]>,
    etag: Arc<str>,
}
impl CachedBody {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    #[must_use]
    pub fn etag(&self) -> &str {
        &self.etag
    }
}

#[derive(Clone)]
pub struct ResponseCache {
    inner: Arc<Mutex<CacheState>>,
    capacity: usize,
    max_bytes: usize,
}
struct CacheState {
    entries: HashMap<String, CacheEntry>,
    flights: HashMap<String, Arc<Mutex<()>>>,
    clock: u64,
    bytes: usize,
}
struct CacheEntry {
    body: CachedBody,
    expires: Instant,
    touched: u64,
}
impl ResponseCache {
    #[must_use]
    pub fn new(capacity: usize, max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CacheState {
                entries: HashMap::new(),
                flights: HashMap::new(),
                clock: 0,
                bytes: 0,
            })),
            capacity: capacity.max(1),
            max_bytes: max_bytes.max(1),
        }
    }

    /// Loads a fresh cached body or coalesces concurrent misses for the same key.
    ///
    /// # Errors
    /// Returns the loader error without caching it.
    pub async fn load<E, F, Fut>(
        &self,
        key: String,
        ttl: Duration,
        loader: F,
    ) -> Result<CachedBody, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Vec<u8>, E>>,
    {
        if let Some(value) = self.fresh(&key).await {
            return Ok(value);
        }
        let gate = {
            let mut state = self.inner.lock().await;
            if let Some(gate) = state.flights.get(&key) {
                Some(Arc::clone(gate))
            } else if state.flights.len() < self.capacity {
                let gate = Arc::new(Mutex::new(()));
                state.flights.insert(key.clone(), Arc::clone(&gate));
                Some(gate)
            } else {
                None
            }
        };
        let Some(gate) = gate else {
            return loader().await.map(cached_body);
        };
        let _guard = gate.lock().await;
        let mut cleanup =
            FlightCleanup::new(Arc::clone(&self.inner), key.clone(), Arc::clone(&gate));
        if let Some(value) = self.fresh(&key).await {
            cleanup.finish().await;
            return Ok(value);
        }
        let bytes = match loader().await {
            Ok(value) => value,
            Err(error) => {
                cleanup.finish().await;
                return Err(error);
            }
        };
        let body = cached_body(bytes);
        let mut state = self.inner.lock().await;
        if body.bytes.len() > self.max_bytes {
            state.flights.remove(&key);
            cleanup.disarm();
            return Ok(body);
        }
        state.clock = state.clock.wrapping_add(1);
        let touched = state.clock;
        while state.entries.len() >= self.capacity
            || state.bytes.saturating_add(body.bytes.len()) > self.max_bytes
        {
            let Some(oldest) = state
                .entries
                .iter()
                .min_by_key(|(_, value)| value.touched)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(removed) = state.entries.remove(&oldest) {
                state.bytes = state.bytes.saturating_sub(removed.body.bytes.len());
            }
        }
        state.bytes = state.bytes.saturating_add(body.bytes.len());
        state.entries.insert(
            key.clone(),
            CacheEntry {
                body: body.clone(),
                expires: Instant::now() + ttl,
                touched,
            },
        );
        state.flights.remove(&key);
        cleanup.disarm();
        Ok(body)
    }

    pub async fn invalidate_prefix(&self, prefix: &str) {
        let mut state = self.inner.lock().await;
        let removed = state
            .entries
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(_, value)| value.body.bytes.len())
            .sum::<usize>();
        state.entries.retain(|key, _| !key.starts_with(prefix));
        state.bytes = state.bytes.saturating_sub(removed);
    }

    async fn fresh(&self, key: &str) -> Option<CachedBody> {
        let mut state = self.inner.lock().await;
        let now = Instant::now();
        let value = state
            .entries
            .get(key)
            .filter(|value| value.expires > now)
            .map(|value| value.body.clone());
        if value.is_some() {
            state.clock = state.clock.wrapping_add(1);
            let touched = state.clock;
            if let Some(entry) = state.entries.get_mut(key) {
                entry.touched = touched;
            }
        } else if let Some(removed) = state.entries.remove(key) {
            state.bytes = state.bytes.saturating_sub(removed.body.bytes.len());
        }
        value
    }

    #[cfg(test)]
    async fn counts(&self) -> (usize, usize, usize) {
        let state = self.inner.lock().await;
        (state.entries.len(), state.bytes, state.flights.len())
    }
}

struct FlightCleanup {
    state: Arc<Mutex<CacheState>>,
    key: Option<String>,
    gate: Arc<Mutex<()>>,
}
impl FlightCleanup {
    fn new(state: Arc<Mutex<CacheState>>, key: String, gate: Arc<Mutex<()>>) -> Self {
        Self {
            state,
            key: Some(key),
            gate,
        }
    }
    async fn finish(&mut self) {
        if let Some(key) = self.key.take() {
            let mut state = self.state.lock().await;
            remove_matching_flight(&mut state, &key, &self.gate);
        }
    }
    fn disarm(&mut self) {
        self.key = None;
    }
}
impl Drop for FlightCleanup {
    fn drop(&mut self) {
        if let Some(key) = self.key.take()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            let state = Arc::clone(&self.state);
            let gate = Arc::clone(&self.gate);
            handle.spawn(async move {
                let mut state = state.lock().await;
                remove_matching_flight(&mut state, &key, &gate);
            });
        }
    }
}
fn remove_matching_flight(state: &mut CacheState, key: &str, gate: &Arc<Mutex<()>>) {
    if state
        .flights
        .get(key)
        .is_some_and(|current| Arc::ptr_eq(current, gate))
    {
        state.flights.remove(key);
    }
}

fn strong_etag(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let mut value = String::with_capacity(70);
    value.push_str("\"dtx-");
    for byte in digest {
        use std::fmt::Write as _;
        write!(value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value.push('"');
    value
}
fn cached_body(bytes: Vec<u8>) -> CachedBody {
    CachedBody {
        etag: Arc::from(strong_etag(&bytes)),
        bytes: Arc::from(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::ResponseCache;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    #[tokio::test]
    async fn concurrent_misses_run_one_loader() {
        let cache = ResponseCache::new(4, 1024);
        let loads = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..16 {
            let cache = cache.clone();
            let loads = Arc::clone(&loads);
            tasks.push(tokio::spawn(async move {
                cache
                    .load("one".to_owned(), Duration::from_secs(1), || async move {
                        loads.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        Ok::<_, ()>(b"body".to_vec())
                    })
                    .await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.expect("join").expect("load").bytes(), b"body");
        }
        assert_eq!(loads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failures_leave_no_flights_and_bytes_stay_bounded() {
        let cache = ResponseCache::new(3, 5);
        for index in 0..32 {
            assert!(
                cache
                    .load(format!("bad-{index}"), Duration::from_secs(1), || async {
                        Err::<Vec<u8>, _>(())
                    })
                    .await
                    .is_err()
            );
        }
        assert_eq!(cache.counts().await.2, 0);
        for index in 0..8 {
            cache
                .load(format!("ok-{index}"), Duration::from_secs(1), || async {
                    Ok::<_, ()>(vec![u8::try_from(index).expect("small"); 3])
                })
                .await
                .expect("load");
        }
        let (entries, bytes, flights) = cache.counts().await;
        assert!(entries <= 3);
        assert!(bytes <= 5);
        assert_eq!(flights, 0);
        cache
            .load("oversize".to_owned(), Duration::from_secs(1), || async {
                Ok::<_, ()>(vec![0; 6])
            })
            .await
            .expect("oversize response still returned");
        assert!(cache.counts().await.1 <= 5);
    }

    #[tokio::test]
    async fn cancelled_loader_releases_its_flight() {
        let cache = ResponseCache::new(2, 16);
        let task_cache = cache.clone();
        let task = tokio::spawn(async move {
            task_cache
                .load("cancel".to_owned(), Duration::from_secs(1), || async {
                    std::future::pending::<Result<Vec<u8>, ()>>().await
                })
                .await
        });
        while cache.counts().await.2 == 0 {
            tokio::task::yield_now().await;
        }
        task.abort();
        let _ = task.await;
        for _ in 0..16 {
            if cache.counts().await.2 == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(cache.counts().await.2, 0);
    }

    #[tokio::test]
    async fn concurrent_unique_loads_cannot_grow_the_flight_map_past_capacity() {
        let cache = ResponseCache::new(2, 16);
        let mut tasks = Vec::new();
        for index in 0..16 {
            let cache = cache.clone();
            tasks.push(tokio::spawn(async move {
                cache
                    .load(
                        format!("pending-{index}"),
                        Duration::from_secs(1),
                        || async { std::future::pending::<Result<Vec<u8>, ()>>().await },
                    )
                    .await
            }));
        }
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(cache.counts().await.2 <= 2);
        for task in tasks {
            task.abort();
        }
    }
}
