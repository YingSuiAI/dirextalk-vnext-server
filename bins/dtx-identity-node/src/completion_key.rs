use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use ed25519_dalek::SigningKey;
#[cfg(unix)]
use std::fs;
use zeroize::Zeroize;

/// Loads the externally provisioned Completion V2 signing seed from a pinned,
/// owner-only file. No fallback or ephemeral key is permitted.
pub fn load_completion_signing_key(path: &Path) -> Result<SigningKey, io::Error> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "completion key path must be absolute",
        ));
    }
    validate_secure_ancestors(path)?;
    let mut file = open_completion_key(path)?;
    validate_secure_ancestors(path)?;
    read_completion_signing_key(&mut file)
}

#[cfg(unix)]
fn open_completion_key(path: &Path) -> Result<File, io::Error> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt;
    let file = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(io::Error::from)?;
    if file.metadata()?.nlink() != 1
        || file.metadata()?.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "completion key file must have exactly one link",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn open_completion_key(_path: &Path) -> Result<File, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "secure completion key loading is disabled on Windows",
    ))
}

#[cfg(not(any(unix, windows)))]
fn open_completion_key(_path: &Path) -> Result<File, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure completion key loading is unsupported",
    ))
}

fn read_completion_signing_key(file: &mut File) -> Result<SigningKey, io::Error> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "completion key must be an exact 32-byte regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "completion key file must be private",
            ));
        }
    }
    let mut seed = [0_u8; 32];
    file.read_exact(&mut seed)?;
    let mut trailing = [0_u8; 1];
    if file.read(&mut trailing)? != 0 {
        seed.zeroize();
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid completion key length",
        ));
    }
    let key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(key)
}

#[cfg(unix)]
fn validate_secure_ancestors(path: &Path) -> Result<(), io::Error> {
    use std::os::unix::fs::PermissionsExt;
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        let metadata = fs::symlink_metadata(directory)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "completion key ancestors must be private directories",
            ));
        }
        ancestor = directory.parent();
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_secure_ancestors(_path: &Path) -> Result<(), io::Error> {
    Ok(())
}
