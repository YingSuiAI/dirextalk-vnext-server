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
    CONNECTOR_COMMAND_NOTIFY_CHANNEL, parse_connector_command_notification_payload,
};
use dtx_domain::{ConnectorId, TenantId};
use dtx_storage::PgStore;
use tokio::sync::watch;

const LISTENER_RETRY_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CommandNotificationKey {
    tenant_id: TenantId,
    connector_id: ConnectorId,
}

impl CommandNotificationKey {
    const fn new(tenant_id: TenantId, connector_id: ConnectorId) -> Self {
        Self {
            tenant_id,
            connector_id,
        }
    }
}

/// Race-free subscription to command availability for one tenant-scoped Connector.
///
/// Notifications are deliberately lossy/coalesced. Callers must subscribe first,
/// then query the durable command suffix, and only then wait for `changed()`.
pub struct CommandNotificationSubscription {
    receiver: Option<watch::Receiver<u64>>,
    notifications: Weak<ConnectorCommandNotifications>,
    key: Option<CommandNotificationKey>,
}

impl CommandNotificationSubscription {
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

impl Drop for CommandNotificationSubscription {
    fn drop(&mut self) {
        // Drop our receiver before counting. A concurrent subscription either
        // increments the same sender under the map lock or creates a fresh entry
        // after this one is removed; neither can be deleted accidentally.
        self.receiver.take();
        let (Some(notifications), Some(key)) = (self.notifications.upgrade(), self.key) else {
            return;
        };
        let Ok(mut channels) = notifications.channels.lock() else {
            return;
        };
        let remove = channels
            .get(&key)
            .is_some_and(|sender| sender.receiver_count() == 0);
        if remove {
            channels.remove(&key);
        }
    }
}

impl fmt::Debug for CommandNotificationSubscription {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandNotificationSubscription")
            .field("connected", &self.receiver.is_some())
            .finish_non_exhaustive()
    }
}

/// Per-process fanout fed by direct post-commit publication and one `PostgreSQL`
/// LISTEN connection for cross-instance wakeups.
#[derive(Debug)]
pub(crate) struct ConnectorCommandNotifications {
    channels: Mutex<HashMap<CommandNotificationKey, watch::Sender<u64>>>,
    listener_started: AtomicBool,
    shutdown: watch::Sender<()>,
}

impl ConnectorCommandNotifications {
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
    ) -> CommandNotificationSubscription {
        self.ensure_postgres_listener(store.clone());
        self.subscribe_local(tenant_id, connector_id)
    }

    fn subscribe_local(
        self: &Arc<Self>,
        tenant_id: TenantId,
        connector_id: ConnectorId,
    ) -> CommandNotificationSubscription {
        let Ok(mut channels) = self.channels.lock() else {
            return CommandNotificationSubscription::never();
        };
        let key = CommandNotificationKey::new(tenant_id, connector_id);
        let sender = channels.entry(key).or_insert_with(|| watch::channel(0).0);
        CommandNotificationSubscription {
            receiver: Some(sender.subscribe()),
            notifications: Arc::downgrade(self),
            key: Some(key),
        }
    }

    pub(crate) fn publish(&self, tenant_id: TenantId, connector_id: ConnectorId) {
        let key = CommandNotificationKey::new(tenant_id, connector_id);
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
    notifications: Weak<ConnectorCommandNotifications>,
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
            result = listener.listen(CONNECTOR_COMMAND_NOTIFY_CHANNEL) => result,
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
                parse_connector_command_notification_payload(notification.payload())
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
    async fn in_process_notifications_are_scoped_and_close_the_subscribe_wait_race() {
        let notifications = ConnectorCommandNotifications::new();
        let tenant_id = TenantId::new();
        let first_connector = ConnectorId::new();
        let second_connector = ConnectorId::new();
        let mut first = notifications.subscribe_local(tenant_id, first_connector);
        let mut second = notifications.subscribe_local(tenant_id, second_connector);

        // Publication between subscribe and the caller's durable replay remains
        // observed when the caller eventually begins waiting.
        notifications.publish(tenant_id, first_connector);
        tokio::time::timeout(Duration::from_millis(50), first.changed())
            .await
            .expect("subscribed Connector is woken");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), second.changed())
                .await
                .is_err(),
            "another Connector is not spuriously woken",
        );
    }

    #[test]
    fn subscriptions_remove_idle_keys_without_deleting_concurrent_receivers() {
        let notifications = ConnectorCommandNotifications::new();
        let tenant_id = TenantId::new();
        for _ in 0..1_000 {
            let subscription = notifications.subscribe_local(tenant_id, ConnectorId::new());
            drop(subscription);
        }
        assert!(
            notifications.channels.lock().unwrap().is_empty(),
            "short-lived Connector streams do not retain routing keys",
        );

        let connector_id = ConnectorId::new();
        let first = notifications.subscribe_local(tenant_id, connector_id);
        let second = notifications.subscribe_local(tenant_id, connector_id);
        drop(first);
        assert_eq!(notifications.channels.lock().unwrap().len(), 1);
        drop(second);
        assert!(notifications.channels.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dropping_the_notification_hub_stops_its_listener_lifetime() {
        let notifications = ConnectorCommandNotifications::new();
        let mut shutdown = notifications.shutdown.subscribe();

        drop(notifications);

        assert!(shutdown.changed().await.is_err());
    }
}
