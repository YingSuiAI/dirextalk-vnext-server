use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use dtx_domain::{Clock, SystemClock};
use dtx_realtime_sync::{OutboxNotification, RealtimeSyncStore};
use dtx_wire::UtcMillis;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::health::OutboxHealth;

const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub async fn publish(
    store: RealtimeSyncStore,
    durable: broadcast::Sender<OutboxNotification>,
    worker_id: Uuid,
    health: Arc<Mutex<OutboxHealth>>,
) {
    let mut poll = tokio::time::interval(POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let clock = SystemClock;
    let mut compaction_tick = 0_u16;
    let mut failures = 0_u8;
    loop {
        poll.tick().await;
        let cycle = async {
            let now = UtcMillis::new(clock.now_utc_millis().map_err(|_| ())?).map_err(|_| ())?;
            let claim = store.claim_outbox(worker_id, now).await.map_err(|_| ())?;
            for notification in &claim.notifications {
                let _ = durable.send(*notification);
            }
            if !claim.notifications.is_empty() {
                store
                    .mark_outbox_published(&claim, now)
                    .await
                    .map_err(|_| ())?;
            }
            compaction_tick = compaction_tick.wrapping_add(1);
            if compaction_tick >= 300 {
                store.compact_expired(now).await.map_err(|_| ())?;
                compaction_tick = 0;
            }
            Ok::<(), ()>(())
        }
        .await;
        if cycle.is_err() {
            failures = failures.saturating_add(1).min(5);
            if let Ok(mut health) = health.lock() {
                health.failed();
            }
            tokio::time::sleep(Duration::from_millis(100_u64 << u32::from(failures))).await;
        } else {
            failures = 0;
            if let Ok(mut health) = health.lock() {
                health.succeeded(Instant::now());
            }
        }
    }
}
