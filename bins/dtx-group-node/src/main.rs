#![forbid(unsafe_code)]

use std::{
    env,
    fs::File,
    io::{self, Read},
    net::SocketAddr,
    path::Path,
    str::FromStr,
};

#[cfg(unix)]
use std::fs;

use dtx_domain::TenantId;
use dtx_group_persistence::GroupPgStore;
use ed25519_dalek::SigningKey;
use sqlx::postgres::PgConnectOptions;
use zeroize::Zeroize;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = env::var("DTX_DATABASE_URL")?;
    let tenant_id = env::var("DTX_GROUP_TENANT_ID")?.parse::<TenantId>()?;
    let bind_address = env::var("DTX_GROUP_BIND")
        .unwrap_or_else(|_| "127.0.0.1:4814".to_owned())
        .parse::<SocketAddr>()?;
    let options = PgConnectOptions::from_str(&database_url)?;
    let store = GroupPgStore::connect(options, 8).await?;
    let sequencer_signing_key =
        load_sequencer_signing_key(Path::new(&env::var("DTX_GROUP_MLS_SEQUENCER_KEY_FILE")?))?;
    let allowed_http_identity_origins = env::var("DTX_GROUP_DEV_HTTP_IDENTITY_ORIGINS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|origin| !origin.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let state = dtx_group_node::GroupNodeState::new(store, tenant_id)
        .with_mls_sequencer_signing_key(sequencer_signing_key)
        .with_allowed_http_identity_origins(allowed_http_identity_origins)?;
    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    axum::serve(listener, dtx_group_node::group_router_with_state(state)).await?;
    Ok(())
}

fn load_sequencer_signing_key(path: &Path) -> Result<SigningKey, io::Error> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "MLS sequencer key path must be absolute",
        ));
    }
    validate_secure_ancestors(path)?;
    let mut file = open_sequencer_key(path)?;
    validate_secure_ancestors(path)?;
    read_sequencer_signing_key(&mut file)
}

#[cfg(unix)]
fn open_sequencer_key(path: &Path) -> Result<File, io::Error> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt;

    let file = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(io::Error::from)?;
    if file.metadata()?.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "MLS sequencer key file must have exactly one link",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn open_sequencer_key(_path: &Path) -> Result<File, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "MLS sequencer key loading is disabled on Windows until reparse-point and ACL validation is available",
    ))
}

#[cfg(not(any(unix, windows)))]
fn open_sequencer_key(_path: &Path) -> Result<File, io::Error> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure MLS sequencer key loading is unsupported on this platform",
    ))
}

fn read_sequencer_signing_key(file: &mut File) -> Result<SigningKey, io::Error> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "MLS sequencer key must be an exact 32-byte regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "MLS sequencer key file must be private",
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
            "invalid MLS key length",
        ));
    }
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    Ok(signing_key)
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
                "MLS sequencer key ancestors must be real directories and not group/world writable",
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn secure_test_directory(case: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_nanos();
        let path = env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .expect("HOME is required for secure key tests")
            .join(".cache")
            .join(format!("secure-key-{case}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).expect("create secure test directory");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .expect("secure test directory permissions");
        path
    }

    fn write_key(path: &Path, seed: [u8; 32]) {
        fs::write(path, seed).expect("write key");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("secure key permissions");
    }

    #[test]
    fn opened_handle_is_pinned_when_path_is_replaced() {
        let directory = secure_test_directory("swap");
        let path = directory.join("sequencer.key");
        let replacement = directory.join("replacement.key");
        write_key(&path, [7; 32]);
        write_key(&replacement, [9; 32]);

        let mut opened = open_sequencer_key(&path).expect("open original key");
        fs::rename(&replacement, &path).expect("replace key path");
        let loaded = read_sequencer_signing_key(&mut opened).expect("read pinned handle");

        assert_eq!(
            loaded.to_bytes(),
            SigningKey::from_bytes(&[7; 32]).to_bytes()
        );
        fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn rejects_symlink_key_path() {
        let directory = secure_test_directory("symlink");
        let target = directory.join("target.key");
        let path = directory.join("sequencer.key");
        write_key(&target, [7; 32]);
        symlink(&target, &path).expect("create key symlink");

        load_sequencer_signing_key(&path).expect_err("symlink must fail");
        fs::remove_dir_all(directory).expect("remove test directory");
    }

    #[test]
    fn rejects_writable_parent_and_public_key_permissions() {
        let directory = secure_test_directory("permissions");
        let path = directory.join("sequencer.key");
        write_key(&path, [7; 32]);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
            .expect("public key permissions");
        assert_eq!(
            load_sequencer_signing_key(&path)
                .expect_err("public key must fail")
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("private key permissions");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o770))
            .expect("writable parent permissions");
        assert_eq!(
            load_sequencer_signing_key(&path)
                .expect_err("writable parent must fail")
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("restore directory permissions");
        fs::remove_dir_all(directory).expect("remove test directory");
    }
}
