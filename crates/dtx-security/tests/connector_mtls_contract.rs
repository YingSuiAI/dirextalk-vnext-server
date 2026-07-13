use std::str::FromStr;

use dtx_domain::{ConnectorId, HostId, TenantId};
use dtx_security::{ConnectorWorkloadIdentity, HostWorkloadIdentity, WorkloadIdentity};

const TENANT: &str = "01890f00-0000-7000-8000-000000000201";
const CONNECTOR: &str = "01890f00-0000-7000-8000-000000000202";
const HOST: &str = "01890f00-0000-7000-8000-000000000203";

#[test]
fn connector_workload_uri_round_trips_only_the_canonical_shape() {
    let tenant_id = TenantId::from_str(TENANT).expect("valid tenant fixture");
    let connector_id = ConnectorId::from_str(CONNECTOR).expect("valid Connector fixture");
    let identity = ConnectorWorkloadIdentity::new(tenant_id, connector_id);
    let expected =
        format!("spiffe://dirextalk.internal/v1/tenants/{TENANT}/connectors/{CONNECTOR}");

    assert_eq!(identity.uri(), expected);
    assert_eq!(ConnectorWorkloadIdentity::from_str(&expected), Ok(identity));
    assert_eq!(WorkloadIdentity::from_str(&expected), Ok(identity.into()));

    for malformed in [
        expected.to_uppercase(),
        format!("{expected}/"),
        format!("{expected}?scope=connector"),
        format!("{expected}#connector"),
        expected.replace("/connectors/", "/connectors%2f"),
        expected.replace("/v1/", "/v01/"),
        expected.replace("/connectors/", "/connector/"),
        expected.replace("spiffe://", "SPIFFE://"),
        expected.replace("dirextalk.internal", "dirextalk.internal:443"),
        expected.replace("dirextalk.internal", "dirextalk.internal@evil.example"),
    ] {
        assert!(
            ConnectorWorkloadIdentity::from_str(&malformed).is_err(),
            "non-canonical Connector URI must fail"
        );
    }

    let host = HostWorkloadIdentity::new(
        tenant_id,
        HostId::from_str(HOST).expect("valid Host fixture"),
    );
    assert!(ConnectorWorkloadIdentity::from_str(&host.uri()).is_err());
}
