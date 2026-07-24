use std::{env, fs, path::PathBuf};

const DATABASE_URL_ENV: &str = "DTX_REALTIME_SYNC_DATABASE_URL";
const DATABASE_URL_FILE_ENV: &str = "DTX_REALTIME_SYNC_DATABASE_URL_FILE";
const MAX_DATABASE_URL_BYTES: u64 = 8_192;

pub fn pool_size(name: &str, default: u32, maximum: u32) -> Result<u32, std::io::Error> {
    match env::var(name) {
        Err(env::VarError::NotPresent) => Ok(default),
        Ok(value) => value
            .parse::<u32>()
            .ok()
            .filter(|size| (1..=maximum).contains(size))
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "realtime pool size rejected",
                )
            }),
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "realtime pool size rejected",
        )),
    }
}

pub fn database_url() -> Result<String, std::io::Error> {
    match (
        env::var_os(DATABASE_URL_ENV),
        env::var_os(DATABASE_URL_FILE_ENV),
    ) {
        (Some(_), Some(_)) | (None, None) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "configure exactly one realtime database source",
        )),
        (Some(value), None) => value.into_string().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "realtime database URL is not UTF-8",
            )
        }),
        (None, Some(path)) => {
            let path = PathBuf::from(path);
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() == 0
                || metadata.len() > MAX_DATABASE_URL_BYTES
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "realtime database credential file rejected",
                ));
            }
            let bytes = fs::read(path)?;
            let value = std::str::from_utf8(&bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "realtime database credential is not UTF-8",
                )
            })?;
            let value = value
                .strip_suffix('\n')
                .unwrap_or(value)
                .strip_suffix('\r')
                .unwrap_or(value);
            if value.is_empty() || value.chars().any(char::is_control) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "realtime database credential shape rejected",
                ));
            }
            Ok(value.to_owned())
        }
    }
}
