use std::{fmt, fs, io::Read, path::PathBuf};

use sha2::{Digest, Sha256};

use crate::{ConnectorTarget, CredentialArtifactRef, HostOperationId, PortError, PortErrorKind};

use super::layout::ConnectorLayout;

pub(super) const MAX_CREDENTIAL_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct CredentialFileProof {
    digest: [u8; 32],
    length: u64,
}

impl CredentialFileProof {
    pub(super) const fn new(digest: [u8; 32], length: u64) -> Self {
        Self { digest, length }
    }

    pub(super) const fn digest(self) -> [u8; 32] {
        self.digest
    }

    pub(super) const fn length(self) -> u64 {
        self.length
    }
}

/// Opaque proof that a trusted provider placed one credential at the exact
/// staged path for this Connector and operation. It never contains secret data.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct LinuxCredentialArtifact {
    operation_id: HostOperationId,
    target: ConnectorTarget,
    reference: CredentialArtifactRef,
    proof: CredentialFileProof,
}

impl LinuxCredentialArtifact {
    /// Returns the only Linux path at which a trusted provider may stage this
    /// operation's credential.
    #[must_use]
    pub fn staged_path(operation_id: HostOperationId, target: ConnectorTarget) -> PathBuf {
        ConnectorLayout::production(target).staged_credential(operation_id)
    }

    /// Verifies an already-staged bounded regular `0600` file and binds its
    /// internal proof to the provider's opaque reference. The reference is not
    /// interpreted as a content digest.
    ///
    /// # Errors
    ///
    /// Rejects a missing, linked, non-regular, incorrectly permissioned, or
    /// digest-mismatched staged artifact.
    pub fn verify_staged(
        operation_id: HostOperationId,
        target: ConnectorTarget,
        reference: CredentialArtifactRef,
    ) -> Result<Self, PortError> {
        Self::verify_staged_in(
            &ConnectorLayout::production(target),
            operation_id,
            reference,
        )
    }

    pub(super) fn verify_staged_in(
        layout: &ConnectorLayout,
        operation_id: HostOperationId,
        reference: CredentialArtifactRef,
    ) -> Result<Self, PortError> {
        let proof = hash_staged_credential(&layout.staged_credential(operation_id))?;
        Ok(Self {
            operation_id,
            target: layout.target(),
            reference,
            proof,
        })
    }

    pub(super) const fn operation_id(&self) -> HostOperationId {
        self.operation_id
    }

    pub(super) const fn target(&self) -> ConnectorTarget {
        self.target
    }

    pub(super) const fn reference(&self) -> CredentialArtifactRef {
        self.reference
    }

    pub(super) const fn proof(&self) -> CredentialFileProof {
        self.proof
    }
}

impl fmt::Debug for LinuxCredentialArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LinuxCredentialArtifact([redacted])")
    }
}

pub(super) fn hash_staged_credential(
    path: &std::path::Path,
) -> Result<CredentialFileProof, PortError> {
    hash_credential_file(path, 0o600, Some((0, 0)))
}

pub(super) fn hash_active_credential(
    path: &std::path::Path,
    connector_gid: u32,
) -> Result<CredentialFileProof, PortError> {
    hash_credential_file(path, 0o440, Some((0, connector_gid)))
}

pub(super) fn hash_ready_credential(
    path: &std::path::Path,
    connector_gid: u32,
) -> Result<CredentialFileProof, PortError> {
    let metadata = secure_file_metadata(path)?;
    #[cfg(unix)]
    {
        #[cfg(all(target_os = "linux", not(test)))]
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        if !matches!(metadata.permissions().mode() & 0o777, 0o600 | 0o440) {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        #[cfg(all(target_os = "linux", not(test)))]
        if metadata.uid() != 0 || (metadata.gid() != 0 && metadata.gid() != connector_gid) {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        #[cfg(not(all(target_os = "linux", not(test))))]
        let _ = connector_gid;
    }
    #[cfg(not(unix))]
    let _ = connector_gid;
    hash_open_credential(path, &metadata)
}

fn hash_credential_file(
    path: &std::path::Path,
    expected_mode: u32,
    expected_owner: Option<(u32, u32)>,
) -> Result<CredentialFileProof, PortError> {
    let metadata = secure_file_metadata(path)?;
    #[cfg(unix)]
    {
        #[cfg(all(target_os = "linux", not(test)))]
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o777 != expected_mode {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        #[cfg(all(target_os = "linux", not(test)))]
        if expected_owner.is_some_and(|(uid, gid)| metadata.uid() != uid || metadata.gid() != gid) {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
        #[cfg(not(all(target_os = "linux", not(test))))]
        let _ = expected_owner;
    }
    #[cfg(not(unix))]
    let _ = (expected_mode, expected_owner);
    hash_open_credential(path, &metadata)
}

fn secure_file_metadata(path: &std::path::Path) -> Result<fs::Metadata, PortError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_CREDENTIAL_BYTES
    {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(PortError::new(PortErrorKind::InvalidArtifact));
        }
    }
    Ok(metadata)
}

fn hash_open_credential(
    path: &std::path::Path,
    path_metadata: &fs::Metadata,
) -> Result<CredentialFileProof, PortError> {
    let mut file =
        fs::File::open(path).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    let before = file
        .metadata()
        .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if !same_open_file(path_metadata, &before) {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8192];
    let mut length = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(
                u64::try_from(read).map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?,
            )
            .filter(|length| *length <= MAX_CREDENTIAL_BYTES)
            .ok_or_else(|| PortError::new(PortErrorKind::InvalidArtifact))?;
        digest.update(&buffer[..read]);
    }
    let after = file
        .metadata()
        .map_err(|_| PortError::new(PortErrorKind::InvalidArtifact))?;
    if length != before.len() || !same_open_file(&before, &after) {
        return Err(PortError::new(PortErrorKind::InvalidArtifact));
    }
    Ok(CredentialFileProof::new(digest.finalize().into(), length))
}

fn same_open_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    if !left.file_type().is_file() || !right.file_type().is_file() || left.len() != right.len() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "dtx-credential-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn staged_credentials_are_bounded_and_hardlinks_fail_closed() {
        let oversized = temp_path("oversized");
        fs::write(
            &oversized,
            vec![0_u8; usize::try_from(MAX_CREDENTIAL_BYTES + 1).unwrap()],
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            hash_staged_credential(&oversized),
            Err(PortError::new(PortErrorKind::InvalidArtifact))
        );
        fs::remove_file(&oversized).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let source = temp_path("linked");
            let alias = source.with_extension("alias");
            fs::write(&source, b"bounded credential").unwrap();
            fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).unwrap();
            fs::hard_link(&source, &alias).unwrap();
            assert_eq!(
                hash_staged_credential(&source),
                Err(PortError::new(PortErrorKind::InvalidArtifact))
            );
            fs::remove_file(alias).unwrap();
            fs::remove_file(source).unwrap();
        }
    }
}
