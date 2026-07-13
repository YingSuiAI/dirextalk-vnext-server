use std::{collections::BTreeMap, error::Error, fmt};

use dtx_domain::{AgentId, IdentityId, Revision};

/// SHA-256 digest of one canonical, signature-verified Agent descriptor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DescriptorDigest([u8; 32]);

impl DescriptorDigest {
    /// Creates a digest from its exact bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Descriptor facts admitted only after signature and canonical-payload verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAgentDefinition {
    agent_id: AgentId,
    publisher_id: IdentityId,
    version: Revision,
    descriptor_hash: DescriptorDigest,
    expires_at_ms: i64,
}

impl VerifiedAgentDefinition {
    /// Builds the value returned by the descriptor verification boundary.
    ///
    /// The caller must have verified the publisher signature, the subject-key
    /// binding of `agent_id`, and the canonical descriptor digest. This registry
    /// deliberately never admits an unsigned descriptor candidate.
    #[must_use]
    pub const fn new(
        agent_id: AgentId,
        publisher_id: IdentityId,
        version: Revision,
        descriptor_hash: DescriptorDigest,
        expires_at_ms: i64,
    ) -> Self {
        Self {
            agent_id,
            publisher_id,
            version,
            descriptor_hash,
            expires_at_ms,
        }
    }

    /// Returns the stable public Agent ID.
    #[must_use]
    pub const fn agent_id(&self) -> AgentId {
        self.agent_id
    }

    /// Returns the publisher identity that verified this version.
    #[must_use]
    pub const fn publisher_id(&self) -> IdentityId {
        self.publisher_id
    }

    /// Returns the monotonic descriptor version.
    #[must_use]
    pub const fn version(&self) -> Revision {
        self.version
    }

    /// Returns the verified canonical descriptor digest.
    #[must_use]
    pub const fn descriptor_hash(&self) -> DescriptorDigest {
        self.descriptor_hash
    }

    /// Returns the exclusive expiry boundary as UTC epoch milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }
}

/// In-memory pure registry used to decide immutable definition-version admission.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentDefinitionRegistry {
    heads: BTreeMap<AgentId, Revision>,
    versions: BTreeMap<(AgentId, Revision), VerifiedAgentDefinition>,
}

impl AgentDefinitionRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            heads: BTreeMap::new(),
            versions: BTreeMap::new(),
        }
    }

    /// Returns the latest admitted definition for an Agent.
    #[must_use]
    pub fn head(&self, agent_id: AgentId) -> Option<&VerifiedAgentDefinition> {
        let version = self.heads.get(&agent_id)?;
        self.versions.get(&(agent_id, *version))
    }

    /// Returns one immutable admitted definition version.
    #[must_use]
    pub fn version(
        &self,
        agent_id: AgentId,
        version: Revision,
    ) -> Option<&VerifiedAgentDefinition> {
        self.versions.get(&(agent_id, version))
    }

    /// Returns the number of immutable versions retained for an Agent.
    #[must_use]
    pub fn version_count(&self, agent_id: AgentId) -> usize {
        self.versions
            .keys()
            .filter(|(candidate, _)| *candidate == agent_id)
            .count()
    }

    /// Admits a fresh verified version or recognizes an exact retry.
    ///
    /// # Errors
    ///
    /// Rejects expired descriptors, publisher changes, version rollback, and
    /// equivocation at an already admitted version.
    pub fn admit(
        &mut self,
        definition: VerifiedAgentDefinition,
        now_ms: i64,
    ) -> Result<AgentDefinitionAdmission, AgentDefinitionError> {
        let version_key = (definition.agent_id, definition.version);
        if let Some(existing) = self.versions.get(&version_key) {
            if existing == &definition {
                return Ok(AgentDefinitionAdmission::Duplicate {
                    current: existing.clone(),
                });
            }
            return Err(AgentDefinitionError::VersionContentConflict);
        }

        if definition.expires_at_ms <= now_ms {
            return Err(AgentDefinitionError::DescriptorExpired);
        }

        let previous = self.head(definition.agent_id);
        if let Some(previous) = previous {
            if previous.publisher_id != definition.publisher_id {
                return Err(AgentDefinitionError::PublisherChanged);
            }
            if definition.version < previous.version {
                return Err(AgentDefinitionError::VersionRegressed {
                    current: previous.version,
                    proposed: definition.version,
                });
            }
        }

        let previous_version = previous.map(VerifiedAgentDefinition::version);
        self.heads.insert(definition.agent_id, definition.version);
        self.versions.insert(version_key, definition.clone());
        Ok(AgentDefinitionAdmission::Advanced {
            previous_version,
            current: definition,
        })
    }
}

/// Result of definition admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentDefinitionAdmission {
    /// A newer verified version became the Agent head.
    Advanced {
        /// Previous head version, absent on first admission.
        previous_version: Option<Revision>,
        /// Newly admitted head.
        current: VerifiedAgentDefinition,
    },
    /// An exact version and digest was already the head.
    Duplicate {
        /// Existing head retained without mutation.
        current: VerifiedAgentDefinition,
    },
}

/// Stable definition registry rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentDefinitionError {
    /// The descriptor is expired at the admission boundary.
    DescriptorExpired,
    /// An Agent ID attempted to switch publisher without an explicit delegation.
    PublisherChanged,
    /// A lower version attempted to replace the current head.
    VersionRegressed {
        /// Current admitted version.
        current: Revision,
        /// Rejected older version.
        proposed: Revision,
    },
    /// The same version was presented with different canonical content.
    VersionContentConflict,
}

impl fmt::Display for AgentDefinitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DescriptorExpired => "Agent descriptor is expired",
            Self::PublisherChanged => "Agent descriptor publisher changed",
            Self::VersionRegressed { .. } => "Agent descriptor version regressed",
            Self::VersionContentConflict => "Agent descriptor version content conflicts",
        })
    }
}

impl Error for AgentDefinitionError {}
