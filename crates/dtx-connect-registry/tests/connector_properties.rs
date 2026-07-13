mod support;

use dtx_connect_registry::{AdapterKind, Connector, ConnectorError};
use dtx_domain::{BootId, ConnectorId, LeaseId, TenantId};
use proptest::prelude::*;
use support::registered_connector;

const NOW: i64 = 1_800_000_000_000;

fn connector(tenant_id: TenantId, connector_id: ConnectorId) -> Connector {
    registered_connector(tenant_id, connector_id, AdapterKind::Codex, 2)
}

proptest! {
    #[test]
    fn lease_epochs_never_regress_and_old_fences_never_revive(restarts in 1_usize..32) {
        let mut connector = connector(TenantId::new(), ConnectorId::new());
        let mut prior = Vec::new();

        for step in 0..restarts {
            let now = NOW + i64::try_from(step).unwrap() * 100;
            let boot_id = BootId::new();
            connector.begin_boot(boot_id, now).unwrap();
            let fence = connector
                .issue_lease(LeaseId::new(), boot_id, now, now + 15_000)
                .unwrap();
            prop_assert_eq!(fence.lease_epoch().get(), u64::try_from(step + 1).unwrap());
            for stale in &prior {
                prop_assert_eq!(
                    connector.validate_fence(stale, now + 1),
                    Err(ConnectorError::StaleLease)
                );
            }
            connector.validate_fence(&fence, now + 1).unwrap();
            prior.push(fence);
        }
    }

    #[test]
    fn foreign_tenant_fences_never_authorize_the_same_connector_id(
        foreign_count in 1_usize..32,
    ) {
        let connector_id = ConnectorId::new();
        let current = connector(TenantId::new(), connector_id);
        for step in 0..foreign_count {
            let mut foreign = connector(TenantId::new(), connector_id);
            let boot_id = BootId::new();
            let now = NOW + i64::try_from(step).unwrap();
            foreign.begin_boot(boot_id, now).unwrap();
            let fence = foreign
                .issue_lease(LeaseId::new(), boot_id, now, now + 15_000)
                .unwrap();

            prop_assert_eq!(
                current.validate_fence(&fence, now + 1),
                Err(ConnectorError::WrongTenant)
            );
        }
    }
}
