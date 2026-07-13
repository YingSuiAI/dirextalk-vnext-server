use std::str::FromStr;

use dtx_agent_registry::{
    AgentDefinitionAdmission, AgentDefinitionError, AgentDefinitionRegistry, DescriptorDigest,
    VerifiedAgentDefinition,
};
use dtx_domain::{AgentId, IdentityId, Revision};

const AGENT_ID: &str = "dtxa17sv7zwzpr7aduy467sdm3pkmxe6if34eoarhaxdnau44fjwfseda";
const PUBLISHER_ID: &str = "dtxi1eci4tbb6kk5wk4vwv5ckekifwqtxy7bdd5vbmd7vac45r5xwu4la";

fn definition(version: u64, hash_byte: u8, expires_at_ms: i64) -> VerifiedAgentDefinition {
    VerifiedAgentDefinition::new(
        AgentId::from_str(AGENT_ID).unwrap(),
        IdentityId::from_str(PUBLISHER_ID).unwrap(),
        Revision::new(version).unwrap(),
        DescriptorDigest::from_bytes([hash_byte; 32]),
        expires_at_ms,
    )
}

#[test]
fn admits_only_fresh_monotonic_verified_definition_versions() {
    let mut registry = AgentDefinitionRegistry::new();

    let first = registry.admit(definition(1, 1, 2_000), 1_000).unwrap();
    assert!(matches!(first, AgentDefinitionAdmission::Advanced { .. }));
    assert_eq!(
        registry
            .head(AgentId::from_str(AGENT_ID).unwrap())
            .unwrap()
            .version()
            .get(),
        1
    );

    let duplicate = registry.admit(definition(1, 1, 2_000), 1_001).unwrap();
    assert!(matches!(
        duplicate,
        AgentDefinitionAdmission::Duplicate { .. }
    ));

    assert_eq!(
        registry.admit(definition(1, 2, 2_000), 1_001),
        Err(AgentDefinitionError::VersionContentConflict)
    );
    registry.admit(definition(3, 3, 3_000), 1_002).unwrap();
    assert_eq!(
        registry.admit(definition(2, 2, 3_000), 1_003),
        Err(AgentDefinitionError::VersionRegressed {
            current: Revision::new(3).unwrap(),
            proposed: Revision::new(2).unwrap(),
        })
    );
    assert_eq!(
        registry.admit(definition(4, 4, 1_003), 1_003),
        Err(AgentDefinitionError::DescriptorExpired)
    );
}

#[test]
fn admitted_versions_are_append_only_and_exact_retries_survive_expiry() {
    let agent_id = AgentId::from_str(AGENT_ID).unwrap();
    let mut registry = AgentDefinitionRegistry::new();
    registry.admit(definition(1, 1, 2_000), 1_000).unwrap();
    registry.admit(definition(2, 2, 3_000), 1_001).unwrap();

    assert_eq!(
        registry
            .version(agent_id, Revision::new(1).unwrap())
            .expect("version one remains durable")
            .descriptor_hash(),
        DescriptorDigest::from_bytes([1; 32])
    );
    assert!(matches!(
        registry.admit(definition(1, 1, 2_000), 4_000).unwrap(),
        AgentDefinitionAdmission::Duplicate { .. }
    ));
    assert_eq!(
        registry.admit(definition(1, 9, 2_000), 4_000),
        Err(AgentDefinitionError::VersionContentConflict)
    );
    assert_eq!(registry.version_count(agent_id), 2);
}
