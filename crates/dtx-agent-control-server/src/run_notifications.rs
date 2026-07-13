use std::{
    collections::HashMap,
    fmt,
    future::pending,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use dtx_agent_persistence::{
    AGENT_RUN_OFFER_NOTIFY_CHANNEL, parse_agent_run_offer_notification_payload,
};
use dtx_domain::{ConnectorId, TenantId};
use dtx_storage::PgStore;
use tokio::sync::watch;

const LISTENER_RETRY_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RunOfferNotificationKey {
    tenant_id: TenantId,
    connector_id: ConnectorId,
}

/// Race-free, lossy wakeup subscription for one Connector's durable Run offers.
pub struct RunOfferNotificationSubscription {
    receiver: Option<watch::Receiver<u64>>,
    notifications: Weak<ConnectorRunOfferNotifications>,
    key: Option<RunOfferNotificationKey>,
}

impl RunOfferNotificationSubscription {
    pub(crate) const fn never() -> Self {
        Self {
            receiver: None,
            notifications: Weak::new(),
            key: None,
        }
    }

    pub(crate) async fn changed(&mut self) {
        let Some(receiver) = self.receiver.as_mut() else {
            pending::<()>().await;
            return;
        };
        if receiver.changed().await.is_err() {
            pending::<()>().await;
        }
    }
}

impl Drop for RunOfferNotificationSubscription {
    fn drop(&mut self) {
        self.receiver.take();
        let (Some(notifications), Some(key)) = (self.notifications.upgrade(), self.key) else {
            return;
        };
        let Ok(mut channels) = notifications.channels.lock() else {
            return;
        };
        if channels
            .get(&key)
            .is_some_and(|sender| sender.receiver_count() == 0)
        {
            channels.remove(&key);
        }
    }
}

impl fmt::Debug for RunOfferNotificationSubscription {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RunOfferNotificationSubscription")
            .field("connected", &self.receiver.is_some())
            .finish_non_exhaustive()
    }
}

/// Per-process fanout backed by one cross-replica `PostgreSQL` listener.
#[derive(Debug)]
pub(crate) struct ConnectorRunOfferNotifications {
    channels: Mutex<HashMap<RunOfferNotificationKey, watch::Sender<u64>>>,
    listener_started: AtomicBool,
    shutdown: watch::Sender<()>,
}

impl ConnectorRunOfferNotifications {
    pub(crate) fn new() -> Arc<Self> {
        let (shutdown, _) = watch::channel(());
        Arc::new(Self {
            channels: Mutex::new(HashMap::new()),
            listener_started: AtomicBool::new(false),
            shutdown,
        })
    }

    pub(crate) fn subscribe(
        self: &Arc<Self>,
        store: &PgStore,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> RunOfferNotificationSubscription {
        self.ensure_postgres_listener(store.clone());
        self.subscribe_local(tenant_id, connector_id)
    }

    fn subscribe_local(
        self: &Arc<Self>,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> RunOfferNotificationSubscription {
        let Ok(mut channels) = self.channels.lock() else {
            return RunOfferNotificationSubscription::never();
        };
        let key = RunOfferNotificationKey {
            tenant_id,
            connector_id,
        };
        let sender = channels.entry(key).or_insert_with(|| watch::channel(0).0);
        RunOfferNotificationSubscription {
            receiver: Some(sender.subscribe()),
            notifications: Arc::downgrade(self),
            key: Some(key),
        }
    }

    pub(crate) fn publish(&self, tenant_id: TenantId, connector_id: ConnectorId) {
        let key = RunOfferNotificationKey {
            tenant_id,
            connector_id,
        };
        let sender = self
            .channels
            .lock()
            .ok()
            .and_then(|channels| channels.get(&key).cloned());
        if let Some(sender) = sender {
            sender.send_modify(|version| *version = version.wrapping_add(1));
        }
    }

    fn ensure_postgres_listener(self: &Arc<Self>, store: PgStore) {
        if self
            .listener_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let notifications = Arc::downgrade(self);
        let shutdown = self.shutdown.subscribe();
        tokio::spawn(async move {
            listen_for_postgres_notifications(store, notifications, shutdown).await;
        });
    }
}

async fn listen_for_postgres_notifications(
    store: PgStore,
    notifications: Weak<ConnectorRunOfferNotifications>,
    mut shutdown: watch::Receiver<()>,
) {
    loop {
        if notifications.upgrade().is_none() {
            return;
        }
        let listener = tokio::select! {
            listener = store.connect_listener() => listener,
            _ = shutdown.changed() => return,
        };
        let Ok(mut listener) = listener else {
            if wait_for_listener_retry(&mut shutdown).await {
                return;
            }
            continue;
        };
        let listening = tokio::select! {
            result = listener.listen(AGENT_RUN_OFFER_NOTIFY_CHANNEL) => result,
            _ = shutdown.changed() => return,
        };
        if listening.is_err() {
            if wait_for_listener_retry(&mut shutdown).await {
                return;
            }
            continue;
        }
        loop {
            let notification = tokio::select! {
                notification = listener.recv() => notification,
                _ = shutdown.changed() => return,
            };
            let Ok(notification) = notification else {
                break;
            };
            let Some((tenant_id, connector_id)) =
                parse_agent_run_offer_notification_payload(notification.payload())
            else {
                continue;
            };
            let Some(notifications) = notifications.upgrade() else {
                return;
            };
            notifications.publish(tenant_id, connector_id);
        }
        if wait_for_listener_retry(&mut shutdown).await {
            return;
        }
    }
}

async fn wait_for_listener_retry(shutdown: &mut watch::Receiver<()>) -> bool {
    tokio::select! {
        () = tokio::time::sleep(LISTENER_RETRY_INTERVAL) => false,
        _ = shutdown.changed() => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_offer_wakeup_is_connector_scoped() {
        let notifications = ConnectorRunOfferNotifications::new();
        let tenant_id = TenantId::new();
        let connector_id = ConnectorId::new();
        let mut subscription = notifications.subscribe_local(tenant_id, connector_id);
        notifications.publish(tenant_id, connector_id);
        tokio::time::timeout(Duration::from_millis(50), subscription.changed())
            .await
            .expect("matching Connector is woken");
    }
}
