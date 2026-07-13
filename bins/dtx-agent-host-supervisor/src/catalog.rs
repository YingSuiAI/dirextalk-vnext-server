use dtx_agent_host_supervisor::{
    CatalogRelease, PortError, PortErrorKind, ReleaseCatalog, ReleaseDigest, ResourceProfile,
};
use dtx_connect_registry::AdapterKind;
use dtx_domain::Revision;
use serde::Deserialize;

use crate::wire::{AdapterWire, OperatorFailure, decode_sha256};

const MAX_RELEASES: usize = 128;

pub struct StaticReleaseCatalog {
    releases: Vec<CatalogRecord>,
}

#[derive(Clone, Copy)]
struct CatalogRecord {
    release: CatalogRelease,
    runnable: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFileWire {
    schema_version: u32,
    releases: Vec<CatalogEntryWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntryWire {
    adapter_kind: AdapterWire,
    release_sha256: String,
    resource_profile: ResourceProfileWire,
    catalog_revision: u64,
    runnable: bool,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResourceProfileWire {
    Standard,
    Compute,
    LowLatency,
}

impl StaticReleaseCatalog {
    pub fn from_slice(input: &[u8]) -> Result<Self, OperatorFailure> {
        let wire: CatalogFileWire = serde_json::from_slice(input)
            .map_err(|_| OperatorFailure::new("INVALID_RELEASE_CATALOG"))?;
        if wire.schema_version != 1
            || wire.releases.is_empty()
            || wire.releases.len() > MAX_RELEASES
        {
            return Err(OperatorFailure::new("INVALID_RELEASE_CATALOG"));
        }
        let mut releases = Vec::with_capacity(wire.releases.len());
        for entry in wire.releases {
            let adapter_kind = entry.adapter_kind.into_domain();
            let digest = ReleaseDigest::from_bytes(
                decode_sha256(&entry.release_sha256)
                    .map_err(|_| OperatorFailure::new("INVALID_RELEASE_CATALOG"))?,
            );
            let resource_profile = entry.resource_profile.into_domain();
            let catalog_revision = Revision::new(entry.catalog_revision)
                .map_err(|_| OperatorFailure::new("INVALID_RELEASE_CATALOG"))?;
            if releases.iter().any(|existing: &CatalogRecord| {
                existing.release.adapter_kind() == adapter_kind
                    && existing.release.digest() == digest
            }) {
                return Err(OperatorFailure::new("INVALID_RELEASE_CATALOG"));
            }
            releases.push(CatalogRecord {
                release: CatalogRelease::approved(
                    adapter_kind,
                    digest,
                    resource_profile,
                    catalog_revision,
                ),
                runnable: entry.runnable,
            });
        }
        Ok(Self { releases })
    }

    fn find(
        &self,
        adapter_kind: AdapterKind,
        digest: ReleaseDigest,
    ) -> Result<CatalogRecord, PortError> {
        self.releases
            .iter()
            .copied()
            .find(|record| {
                record.release.adapter_kind() == adapter_kind && record.release.digest() == digest
            })
            .ok_or_else(|| PortError::new(PortErrorKind::NotApproved))
    }
}

impl ReleaseCatalog for StaticReleaseCatalog {
    fn resolve_known(
        &mut self,
        adapter_kind: AdapterKind,
        digest: ReleaseDigest,
    ) -> Result<CatalogRelease, PortError> {
        self.find(adapter_kind, digest).map(|record| record.release)
    }

    fn resolve_runnable(
        &mut self,
        adapter_kind: AdapterKind,
        digest: ReleaseDigest,
    ) -> Result<CatalogRelease, PortError> {
        let record = self.find(adapter_kind, digest)?;
        if record.runnable {
            Ok(record.release)
        } else {
            Err(PortError::new(PortErrorKind::NotApproved))
        }
    }
}

impl AdapterWire {
    #[must_use]
    pub const fn into_domain(self) -> AdapterKind {
        match self {
            Self::Codex => AdapterKind::Codex,
            Self::OpenclawAcp => AdapterKind::OpenClawAcp,
            Self::Eino => AdapterKind::Eino,
            Self::Rig => AdapterKind::Rig,
            Self::ClaudeCode => AdapterKind::ClaudeCode,
            Self::CustomAcp => AdapterKind::CustomAcp,
        }
    }
}

impl ResourceProfileWire {
    const fn into_domain(self) -> ResourceProfile {
        match self {
            Self::Standard => ResourceProfile::Standard,
            Self::Compute => ResourceProfile::Compute,
            Self::LowLatency => ResourceProfile::LowLatency,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_distinguishes_known_from_runnable() {
        let input = br#"{
          "schema_version": 1,
          "releases": [
            {
              "adapter_kind": "codex",
              "release_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
              "resource_profile": "standard",
              "catalog_revision": 1,
              "runnable": false
            }
          ]
        }"#;
        let mut catalog = StaticReleaseCatalog::from_slice(input).expect("catalog parses");
        let digest = ReleaseDigest::from_bytes([0x11; 32]);
        assert!(catalog.resolve_known(AdapterKind::Codex, digest).is_ok());
        assert_eq!(
            catalog
                .resolve_runnable(AdapterKind::Codex, digest)
                .expect_err("revoked release is not runnable")
                .kind(),
            PortErrorKind::NotApproved
        );
    }

    #[test]
    fn catalog_rejects_duplicate_release_identity() {
        let entry = r#"{
          "adapter_kind":"codex",
          "release_sha256":"1111111111111111111111111111111111111111111111111111111111111111",
          "resource_profile":"standard",
          "catalog_revision":1,
          "runnable":true
        }"#;
        let input = format!(r#"{{"schema_version":1,"releases":[{entry},{entry}]}}"#);
        let Err(error) = StaticReleaseCatalog::from_slice(input.as_bytes()) else {
            panic!("duplicate unexpectedly succeeded");
        };
        assert_eq!(error.code, "INVALID_RELEASE_CATALOG");
    }
}
