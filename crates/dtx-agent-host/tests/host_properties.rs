use std::str::FromStr;

use dtx_agent_host::{AgentHost, EffectiveHostState, HostLifecycle, ReportedHealth};
use dtx_domain::{HostCredentialId, HostId, IdentityId, Revision, TenantId};
use proptest::prelude::*;

const NOW: i64 = 1_800_000_000_000;
const OWNER: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

#[derive(Clone, Copy, Debug)]
enum Operation {
    AdvanceDesired,
    Heartbeat {
        acknowledge_desired: bool,
        degraded: bool,
        tick: u16,
    },
    RotateCredential,
    Quarantine,
    ClearQuarantine,
    Revoke,
    StaleMutation,
}

fn operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        Just(Operation::AdvanceDesired),
        (any::<bool>(), any::<bool>(), any::<u16>()).prop_map(
            |(acknowledge_desired, degraded, tick)| Operation::Heartbeat {
                acknowledge_desired,
                degraded,
                tick,
            }
        ),
        Just(Operation::RotateCredential),
        Just(Operation::Quarantine),
        Just(Operation::ClearQuarantine),
        Just(Operation::Revoke),
        Just(Operation::StaleMutation),
    ]
}

fn owner() -> IdentityId {
    IdentityId::from_str(OWNER).unwrap()
}

proptest! {
    #[test]
    fn random_transitions_preserve_host_invariants(operations in prop::collection::vec(operation(), 0..128)) {
        let mut host = AgentHost::register(TenantId::new(), HostId::new(), owner());
        let first_credential = HostCredentialId::new();
        host.enroll(host.revision(), first_credential).unwrap();
        let mut credential = first_credential;
        let mut previous_desired = host.desired_revision();
        let mut previous_observed = host.observed_revision();
        let tenant_id = host.tenant_id();
        let owner_id = host.owner_id();
        let host_id = host.host_id();

        for operation in operations {
            let before = host.clone();
            let before_revision = host.revision();
            let result = match operation {
                Operation::AdvanceDesired => host.advance_desired_revision(before_revision).map(|_| ()),
                Operation::Heartbeat { acknowledge_desired, degraded, tick } => {
                    let acknowledged = if acknowledge_desired {
                        host.desired_revision()
                    } else {
                        Revision::INITIAL
                    };
                    let health = if degraded {
                        ReportedHealth::Degraded
                    } else {
                        ReportedHealth::Healthy
                    };
                    host.record_heartbeat(
                        before_revision,
                        credential,
                        acknowledged,
                        health,
                        NOW + i64::from(tick),
                        90_000,
                    ).map(|_| ())
                }
                Operation::RotateCredential => {
                    let next = HostCredentialId::new();
                    let result = host.rotate_credential(before_revision, next).map(|_| ());
                    if result.is_ok() {
                        credential = next;
                    }
                    result
                }
                Operation::Quarantine => host.quarantine(before_revision),
                Operation::ClearQuarantine => host.clear_quarantine(before_revision),
                Operation::Revoke => host.revoke(before_revision),
                Operation::StaleMutation => host.advance_desired_revision(Revision::INITIAL).map(|_| ()),
            };

            prop_assert_eq!(host.tenant_id(), tenant_id);
            prop_assert_eq!(host.owner_id(), owner_id);
            prop_assert_eq!(host.host_id(), host_id);
            prop_assert!(host.desired_revision() >= previous_desired);
            if let Some(observed) = host.observed_revision() {
                prop_assert!(observed <= host.desired_revision());
                if let Some(previous) = previous_observed {
                    prop_assert!(observed >= previous);
                }
            }
            if result.is_ok() {
                prop_assert_eq!(host.revision(), before_revision.checked_next().unwrap());
            } else {
                prop_assert_eq!(&host, &before);
            }
            if before.lifecycle() == HostLifecycle::Revoked {
                prop_assert_eq!(host.lifecycle(), HostLifecycle::Revoked);
                prop_assert_eq!(host.effective_state(i64::MAX), EffectiveHostState::Revoked);
            }

            previous_desired = host.desired_revision();
            previous_observed = host.observed_revision();
        }
    }
}
