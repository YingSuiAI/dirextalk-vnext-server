use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub struct AdmissionGate {
    global: Arc<Semaphore>,
    per_source_limit: usize,
    per_source: Mutex<HashMap<IpAddr, usize>>,
}
impl AdmissionGate {
    pub fn new(global_limit: usize, per_source_limit: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global_limit)),
            per_source_limit,
            per_source: Mutex::new(HashMap::new()),
        }
    }
    pub fn try_acquire(self: &Arc<Self>, source: IpAddr) -> Option<AdmissionPermit> {
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
pub struct AdmissionPermit {
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
